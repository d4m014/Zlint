use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    let dir = std::env::temp_dir().join(format!("zlint-m3-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn report_file_matches_decide_stdout() {
    let dir = scratch("report");
    let report = dir.join("decision.json");
    let output = zlint(&[
        "decide",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/timing_reject.json",
        "--report",
        report.to_str().unwrap(),
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let file = std::fs::read_to_string(&report).unwrap();
    assert_eq!(stdout.trim(), file.trim());
    let decision: Value = serde_json::from_str(&file).unwrap();
    assert_eq!(decision["verdict"], "reject");
    assert_eq!(decision["score"], 45);
}

#[test]
fn history_is_newest_first_and_an_accept_is_counted() {
    let dir = scratch("history");
    let db = dir.join("zlint.db");
    let db_arg = db.to_str().unwrap();

    let accepted = zlint(&[
        "decide",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/clean_accept.json",
        "--db",
        db_arg,
    ]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let accepted_json: Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(accepted_json["verdict"], "accept");

    let warned = zlint(&[
        "decide",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/shield_warn.json",
        "--db",
        db_arg,
    ]);
    assert!(warned.status.success());
    let warned_json: Value = serde_json::from_slice(&warned.stdout).unwrap();
    assert_eq!(warned_json["verdict"], "warn");
    assert_eq!(warned_json["score"], 65);

    let listed = zlint(&["history", "--db", db_arg, "--limit", "1"]);
    assert!(listed.status.success());
    let text = String::from_utf8(listed.stdout).unwrap();
    assert!(text.starts_with("warn  score 65"));
    assert!(text.contains("shield_after_receive"));
    assert_eq!(
        text.lines()
            .filter(|line| !line.starts_with(' ') && !line.is_empty())
            .count(),
        1
    );

    let again = zlint(&[
        "decide",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/clean_accept.json",
        "--db",
        db_arg,
    ]);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let again_json: Value = serde_json::from_slice(&again.stdout).unwrap();
    assert_eq!(again_json["verdict"], "accept");
}

#[test]
fn mcp_propose_spend_matches_decide() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zlint"))
        .arg("mcp")
        .current_dir(root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let messages = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"propose_spend","arguments":{"policy_path":"config/policy.example.yaml","activity_path":"fixtures/demo_activity.json","proposal_path":"fixtures/proposals/timing_reject.json"}}}"#,
    ];
    for message in messages {
        writeln!(stdin, "{message}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let lines: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "zlint");
    assert_eq!(lines[0]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(lines[1]["result"]["tools"][0]["name"], "propose_spend");
    assert_eq!(lines[2]["result"]["isError"], false);
    let text = lines[2]["result"]["content"][0]["text"].as_str().unwrap();
    let decision: Value = serde_json::from_str(text).unwrap();
    assert_eq!(decision["verdict"], "reject");
    assert_eq!(decision["score"], 45);
    assert_eq!(decision["flags"][0]["code"], "timing_correlation");
    assert_eq!(decision["flags"][1]["code"], "round_or_distinctive_amount");
    assert!(decision.get("signer").is_none());
}
