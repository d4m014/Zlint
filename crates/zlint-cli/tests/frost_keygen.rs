use std::os::unix::fs::PermissionsExt;
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

#[test]
fn keygen_writes_owner_only_shares_and_cosign_refuses_them() {
    let dir = std::env::temp_dir().join(format!("zlint-frost-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let share1 = dir.join("share1.json");
    let share2 = dir.join("share2.json");
    let output = zlint(&[
        "frost",
        "keygen",
        "--share1",
        share1.to_str().unwrap(),
        "--share2",
        share2.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("trusted dealer"), "{stderr}");
    assert!(stderr.contains("does not broadcast"), "{stderr}");
    assert!(stderr.contains("share 2 stays"), "{stderr}");
    assert!(!stderr.contains("key_package"), "{stderr}");
    for path in [&share1, &share2] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let body = std::fs::read_to_string(path).unwrap();
        let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!stderr.contains(&id), "keygen printed a share id");
    }

    let db = dir.join("zlint.db");
    let proposal = root().join("fixtures/proposals/clean_accept.json");
    let policy = root().join("config/policy.example.yaml");
    let activity = root().join("fixtures/demo_activity.json");
    let cosign = zlint(&[
        "cosign",
        "--policy",
        policy.to_str().unwrap(),
        "--activity",
        activity.to_str().unwrap(),
        "--proposal",
        proposal.to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--share",
        share2.to_str().unwrap(),
    ]);
    assert_eq!(cosign.status.code(), Some(2));
    assert!(cosign.stdout.is_empty());
    let err = String::from_utf8_lossy(&cosign.stderr);
    assert!(err.contains("PCZT"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
