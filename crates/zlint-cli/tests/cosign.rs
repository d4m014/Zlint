use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn zlint(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_zlint"))
        .args(args)
        .current_dir(root())
        .output()
        .unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zlint-cosign-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn init_share(dir: &PathBuf) -> PathBuf {
    let path = dir.join("share.json");
    let output = zlint(&["share", "init", "--path", path.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    path
}

fn cosign(db: &str, policy: &str, proposal: &str, share: &str) -> std::process::Output {
    zlint(&[
        "cosign",
        "--policy",
        policy,
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        proposal,
        "--db",
        db,
        "--share",
        share,
    ])
}

#[test]
fn accept_contributes_a_simulated_share_and_reject_does_not() {
    let dir = scratch("verdicts");
    let db = dir.join("zlint.db");
    let db_arg = db.to_str().unwrap();
    let share = init_share(&dir);
    let share_arg = share.to_str().unwrap();

    let accepted = cosign(
        db_arg,
        "config/policy.example.yaml",
        "fixtures/proposals/clean_accept.json",
        share_arg,
    );
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let accepted_json = json(&accepted);
    assert_eq!(accepted_json["decision"]["verdict"], "accept");
    assert_eq!(accepted_json["decision"]["score"], 100);
    assert_eq!(accepted_json["awaiting_confirmation"], false);
    assert_eq!(accepted_json["already_signed"], false);
    let share = &accepted_json["signature_share"];
    assert_eq!(share["signer"], "simulated");
    assert!(share["share"].as_str().unwrap().starts_with("simulated:"));
    assert_eq!(
        share["statement"],
        "Simulated share. This is not a Zcash signature."
    );
    let err = String::from_utf8(accepted.stderr).unwrap();
    assert!(err.contains("not a Zcash signature"));
    assert!(err.to_ascii_lowercase().contains("simulated"));

    let again = cosign(
        db_arg,
        "config/policy.example.yaml",
        "fixtures/proposals/clean_accept.json",
        share_arg,
    );
    assert!(again.status.success());
    let again_json = json(&again);
    assert!(again_json["signature_share"].is_null());
    assert_eq!(again_json["already_signed"], true);
    assert!(String::from_utf8(again.stderr)
        .unwrap()
        .contains("no second share"));

    let rejected = cosign(
        db_arg,
        "config/policy.example.yaml",
        "fixtures/proposals/timing_reject.json",
        share_arg,
    );
    assert!(rejected.status.success());
    let rejected_json = json(&rejected);
    assert_eq!(rejected_json["decision"]["verdict"], "reject");
    assert!(rejected_json["signature_share"].is_null());
    assert_eq!(rejected_json["awaiting_confirmation"], false);
    let reject_err = String::from_utf8(rejected.stderr).unwrap();
    assert!(reject_err.contains("no share contributed"));
    assert!(!reject_err.contains("not a Zcash signature"));

    let hard = zlint(&[
        "cosign",
        "--policy",
        "config/policy.demo.yaml",
        "--activity",
        "fixtures/cap_activity.json",
        "--proposal",
        "fixtures/proposals/daily_cap_reject.json",
        "--db",
        db_arg,
        "--share",
        share_arg,
    ]);
    assert!(hard.status.success());
    let hard_json = json(&hard);
    assert_eq!(hard_json["decision"]["verdict"], "reject");
    assert_eq!(
        hard_json["decision"]["hard_rule_failures"][0]["code"],
        "daily_cap"
    );
    assert!(hard_json["signature_share"].is_null());
}

#[test]
fn warn_signs_only_after_confirm_and_then_counts_toward_the_cap() {
    let dir = scratch("warn");
    let db = dir.join("zlint.db");
    let db_arg = db.to_str().unwrap();
    let share = init_share(&dir);
    let share_arg = share.to_str().unwrap();
    let proposal = "fixtures/proposals/shield_warn.json";

    let warned = cosign(db_arg, "config/policy.example.yaml", proposal, share_arg);
    assert!(warned.status.success());
    let warned_json = json(&warned);
    assert_eq!(warned_json["decision"]["verdict"], "warn");
    assert_eq!(warned_json["decision"]["score"], 65);
    assert!(warned_json["signature_share"].is_null());
    assert_eq!(warned_json["awaiting_confirmation"], true);
    let warn_err = String::from_utf8(warned.stderr).unwrap();
    assert!(warn_err.contains("no share contributed"));
    assert!(warn_err.contains("zlint confirm"));
    assert!(!warn_err.contains("not a Zcash signature"));

    let early = zlint(&[
        "confirm",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/clean_accept.json",
        "--db",
        db_arg,
        "--share",
        share_arg,
    ]);
    assert_eq!(early.status.code(), Some(2));
    assert!(String::from_utf8(early.stderr)
        .unwrap()
        .contains("no warning is waiting"));

    let confirmed = zlint(&[
        "confirm",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        proposal,
        "--db",
        db_arg,
        "--share",
        share_arg,
    ]);
    assert!(
        confirmed.status.success(),
        "{}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    let confirmed_json = json(&confirmed);
    assert_eq!(confirmed_json["decision"]["verdict"], "warn");
    assert_eq!(confirmed_json["signature_share"]["signer"], "simulated");
    assert_eq!(confirmed_json["awaiting_confirmation"], false);
    assert!(String::from_utf8(confirmed.stderr.clone())
        .unwrap()
        .contains("not a Zcash signature"));

    let second = zlint(&[
        "confirm",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        proposal,
        "--db",
        db_arg,
        "--share",
        share_arg,
    ]);
    assert_eq!(second.status.code(), Some(2));
    assert!(String::from_utf8(second.stderr)
        .unwrap()
        .contains("already signed"));

    let policy = dir.join("cap.yaml");
    std::fs::write(
        &policy,
        "\
version: 1
limits:
  daily_cap_zatoshis: 13700000
  max_tx_zatoshis: 50000000
  allowlist: []
  max_spends_per_hour: 5
privacy:
  reject_below: 60
  warn_below: 75
linter:
  timing_lookback_ms: 600000
  amount_similarity: 0.20
  round_modulus_zatoshis: 1000000
  flag_exact_recent_amount: true
  shield_lookback_ms: 600000
  change_fraction: 0.95
",
    )
    .unwrap();
    let over = cosign(
        db_arg,
        policy.to_str().unwrap(),
        "fixtures/proposals/clean_accept.json",
        share_arg,
    );
    assert!(over.status.success());
    let over_json = json(&over);
    assert_eq!(over_json["decision"]["verdict"], "reject");
    assert_eq!(
        over_json["decision"]["hard_rule_failures"][0]["code"],
        "daily_cap"
    );
    assert!(over_json["signature_share"].is_null());
}

#[test]
fn an_unconfirmed_warning_does_not_spend_the_cap() {
    let dir = scratch("uncounted");
    let db = dir.join("zlint.db");
    let db_arg = db.to_str().unwrap();
    let share = init_share(&dir);
    let share_arg = share.to_str().unwrap();
    let policy = dir.join("cap.yaml");
    std::fs::write(
        &policy,
        "\
version: 1
limits:
  daily_cap_zatoshis: 13700000
  max_tx_zatoshis: 50000000
  allowlist: []
  max_spends_per_hour: 5
privacy:
  reject_below: 60
  warn_below: 75
linter:
  timing_lookback_ms: 600000
  amount_similarity: 0.20
  round_modulus_zatoshis: 1000000
  flag_exact_recent_amount: true
  shield_lookback_ms: 600000
  change_fraction: 0.95
",
    )
    .unwrap();
    let policy_arg = policy.to_str().unwrap();

    let warned = cosign(
        db_arg,
        policy_arg,
        "fixtures/proposals/shield_warn.json",
        share_arg,
    );
    assert!(warned.status.success());
    assert_eq!(json(&warned)["decision"]["verdict"], "warn");
    assert!(json(&warned)["signature_share"].is_null());

    let accepted = cosign(
        db_arg,
        policy_arg,
        "fixtures/proposals/clean_accept.json",
        share_arg,
    );
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let accepted_json = json(&accepted);
    assert_eq!(accepted_json["decision"]["verdict"], "accept");
    assert_eq!(accepted_json["signature_share"]["signer"], "simulated");
}
