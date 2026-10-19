use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn zlint(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_zlint");
    Command::new(bin)
        .args(args)
        .current_dir(root())
        .output()
        .expect("run zlint")
}

fn decide(policy: &str, activity: &str, proposal: &str) -> (i32, Value) {
    let output = zlint(&[
        "decide",
        "--policy",
        policy,
        "--activity",
        activity,
        "--proposal",
        proposal,
    ]);
    let code = output.status.code().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        code == 0,
        "exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (code, serde_json::from_str(&stdout).unwrap())
}

fn round_trip(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    let typed: Value = match path.file_name().and_then(|n| n.to_str()).unwrap() {
        "demo_activity.json" | "cap_activity.json" => {
            let activity: zlint_types::Activity = serde_json::from_value(value.clone()).unwrap();
            activity.validate().unwrap();
            serde_json::to_value(activity).unwrap()
        }
        _ => {
            let proposal: zlint_types::SpendProposal =
                serde_json::from_value(value.clone()).unwrap();
            proposal.validate().unwrap();
            serde_json::to_value(proposal).unwrap()
        }
    };
    assert_eq!(typed, value, "{}", path.display());
}

#[test]
fn fixtures_round_trip() {
    let root = root();
    for rel in [
        "fixtures/demo_activity.json",
        "fixtures/cap_activity.json",
        "fixtures/proposals/clean_accept.json",
        "fixtures/proposals/timing_reject.json",
        "fixtures/proposals/daily_cap_reject.json",
        "fixtures/proposals/shield_warn.json",
    ] {
        round_trip(&root.join(rel));
    }
}

#[test]
fn acceptance_cases() {
    let (_, clean) = decide(
        "config/policy.example.yaml",
        "fixtures/demo_activity.json",
        "fixtures/proposals/clean_accept.json",
    );
    assert_eq!(clean["verdict"], "accept");
    assert_eq!(clean["score"], 100);
    assert_eq!(clean["flags"], serde_json::json!([]));
    assert_eq!(clean["hard_rule_failures"], serde_json::json!([]));

    let (_, timing) = decide(
        "config/policy.example.yaml",
        "fixtures/demo_activity.json",
        "fixtures/proposals/timing_reject.json",
    );
    assert_eq!(timing["verdict"], "reject");
    assert_eq!(timing["score"], 45);
    assert_eq!(timing["hard_rule_failures"], serde_json::json!([]));
    assert_eq!(timing["flags"][0]["code"], "timing_correlation",);
    assert_eq!(timing["flags"][0]["weight"], 40);
    assert_eq!(
        timing["flags"][0]["explanation"],
        "Spend of 0.5 ZEC is 4 min after a 0.5 ZEC receive — timing link risk"
    );
    assert_eq!(timing["flags"][1]["code"], "round_or_distinctive_amount",);
    assert_eq!(timing["flags"][1]["weight"], 15);
    assert!(!timing["flags"][1]["explanation"]
        .as_str()
        .unwrap()
        .is_empty());

    let (_, cap) = decide(
        "config/policy.demo.yaml",
        "fixtures/cap_activity.json",
        "fixtures/proposals/daily_cap_reject.json",
    );
    assert_eq!(cap["verdict"], "reject");
    assert_eq!(cap["score"], 100);
    assert_eq!(cap["flags"], serde_json::json!([]));
    assert_eq!(cap["hard_rule_failures"][0]["code"], "daily_cap");
    assert_eq!(
        cap["hard_rule_failures"][0]["explanation"],
        "Daily cap exceeded: 0.8 ZEC already accepted plus 0.401 ZEC is 1.201 ZEC, cap is 1 ZEC."
    );
    assert_eq!(cap["hard_rule_failures"].as_array().unwrap().len(), 1);

    let (_, warn) = decide(
        "config/policy.example.yaml",
        "fixtures/demo_activity.json",
        "fixtures/proposals/shield_warn.json",
    );
    assert_eq!(warn["verdict"], "warn");
    assert_eq!(warn["score"], 65);
    assert_eq!(warn["flags"][0]["code"], "shield_after_receive");
    assert_eq!(warn["flags"][0]["weight"], 35);
    assert_eq!(
        warn["flags"][0]["explanation"],
        "Shielded 0.2 ZEC 2 min ago, now spending — turnstile linkage risk"
    );
    assert_eq!(warn["flags"].as_array().unwrap().len(), 1);

    let (_, shield_demo) = decide(
        "config/policy.demo.yaml",
        "fixtures/demo_activity.json",
        "fixtures/proposals/shield_warn.json",
    );
    assert_eq!(shield_demo["verdict"], "reject");
    assert_eq!(shield_demo["score"], 65);
}

#[test]
fn policy_show_and_usage_errors() {
    let show = zlint(&["policy", "show", "--policy", "config/policy.demo.yaml"]);
    assert!(show.status.success());
    let text = String::from_utf8(show.stdout).unwrap();
    assert!(text.contains("daily cap: 1 ZEC"));
    assert!(text.contains("max tx: 0.5 ZEC"));
    assert!(text.contains("reject below: 70"));

    let missing = zlint(&[
        "decide",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/missing.json",
    ]);
    assert_eq!(missing.status.code(), Some(2));
}

#[test]
fn reject_still_exits_zero() {
    let output = zlint(&[
        "decide",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/timing_reject.json",
    ]);
    assert!(output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("reject  score 45\n"));
    assert!(stderr.contains("timing_correlation:"));
}
