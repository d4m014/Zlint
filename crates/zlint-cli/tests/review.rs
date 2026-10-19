use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn review_rejects_a_file_that_is_not_a_transaction() {
    let path = std::env::temp_dir().join("zlint-not-a-pczt.bin");
    std::fs::write(&path, b"not a transaction").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_zlint"))
        .args([
            "review",
            "--policy",
            "config/policy.example.yaml",
            "--activity",
            "fixtures/demo_activity.json",
            "--pczt",
            path.to_str().unwrap(),
            "--at",
            "1760003600000",
        ])
        .current_dir(root())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("could not read the transaction"),
        "{stderr}"
    );
}
