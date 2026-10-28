use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

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

struct Server {
    child: std::process::Child,
    socket: PathBuf,
    share_id: String,
}

impl Server {
    fn start(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("zlint-serve-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let share = dir.join("share.json");
        let init = zlint(&["share", "init", "--path", share.to_str().unwrap()]);
        assert!(
            init.status.success(),
            "{}",
            String::from_utf8_lossy(&init.stderr)
        );
        let share_body: Value =
            serde_json::from_str(&std::fs::read_to_string(&share).unwrap()).unwrap();
        let share_id = share_body["id"].as_str().unwrap().to_string();
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&init.stdout),
            String::from_utf8_lossy(&init.stderr)
        );
        assert!(!shown.contains(&share_id));

        let socket = dir.join("z.sock");
        let mut child = Command::new(env!("CARGO_BIN_EXE_zlint"))
            .args([
                "serve",
                "--socket",
                socket.to_str().unwrap(),
                "--policy",
                "config/policy.example.yaml",
                "--activity",
                "fixtures/demo_activity.json",
                "--db",
                dir.join("zlint.db").to_str().unwrap(),
                "--share",
                share.to_str().unwrap(),
            ])
            .current_dir(root())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = false;
        for _ in 0..50 {
            if socket.exists() {
                let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
                if mode == 0o600 {
                    ready = true;
                    break;
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                let mut err = String::new();
                if let Some(stderr) = child.stderr.as_mut() {
                    use std::io::Read;
                    let _ = stderr.read_to_string(&mut err);
                }
                panic!("server exited {status}: {err}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(ready, "socket was not owner-only");
        Self {
            child,
            socket,
            share_id,
        }
    }

    fn request(&self, body: &Value) -> Value {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(format!("{body}\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let text = line.trim();
        assert!(!text.contains(&self.share_id), "{text}");
        serde_json::from_str(text).unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn proposal(name: &str) -> Value {
    let path = root().join("fixtures/proposals").join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn the_socket_cosigns_without_giving_the_agent_the_share() {
    let server = Server::start("agent");
    let ignored = server.request(&serde_json::json!({
        "method": "cosign",
        "proposal": proposal("clean_accept.json"),
        "activity": {"receives": [], "shields": [], "accepted_spends": []}
    }));
    assert!(ignored.get("error").is_some(), "{ignored}");
    assert!(ignored.get("signature_share").is_none());

    let accepted = server.request(&serde_json::json!({
        "method": "cosign",
        "proposal": proposal("clean_accept.json")
    }));
    assert_eq!(accepted["decision"]["verdict"], "accept");
    assert_eq!(accepted["signature_share"]["signer"], "simulated");
    assert_eq!(accepted["already_signed"], false);
    assert!(accepted["signature_share"]["statement"]
        .as_str()
        .unwrap()
        .contains("not a Zcash signature"));

    let proposed = zlint(&[
        "propose",
        "--socket",
        server.socket.to_str().unwrap(),
        "--proposal",
        "fixtures/proposals/timing_reject.json",
    ]);
    assert!(
        proposed.status.success(),
        "{}",
        String::from_utf8_lossy(&proposed.stderr)
    );
    let proposed_json: Value = serde_json::from_slice(&proposed.stdout).unwrap();
    assert_eq!(proposed_json["decision"]["verdict"], "reject");
    assert!(proposed_json["signature_share"].is_null());
    let shown =
        String::from_utf8(proposed.stdout).unwrap() + &String::from_utf8(proposed.stderr).unwrap();
    assert!(!shown.contains(&server.share_id));

    let warned = server.request(&serde_json::json!({
        "method": "cosign",
        "proposal": proposal("shield_warn.json")
    }));
    assert_eq!(warned["decision"]["verdict"], "warn");
    assert!(warned["signature_share"].is_null());
    assert_eq!(warned["awaiting_confirmation"], true);

    let remote_confirm = server.request(&serde_json::json!({
        "method": "confirm",
        "proposal": proposal("shield_warn.json")
    }));
    let err = remote_confirm["error"].as_str().unwrap();
    assert!(err.contains("confirm"), "{err}");
    assert!(!err.contains(&server.share_id));

    let confirmed = zlint(&[
        "confirm",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/shield_warn.json",
        "--db",
        server
            .socket
            .parent()
            .unwrap()
            .join("zlint.db")
            .to_str()
            .unwrap(),
        "--share",
        server
            .socket
            .parent()
            .unwrap()
            .join("share.json")
            .to_str()
            .unwrap(),
    ]);
    assert!(
        confirmed.status.success(),
        "{}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    let confirmed_json: Value = serde_json::from_slice(&confirmed.stdout).unwrap();
    assert_eq!(confirmed_json["signature_share"]["signer"], "simulated");
    let shown = String::from_utf8(confirmed.stdout).unwrap()
        + &String::from_utf8(confirmed.stderr).unwrap();
    assert!(!shown.contains(&server.share_id));
}

#[test]
fn advise_does_not_open_the_share_file() {
    let dir = std::env::temp_dir().join(format!("zlint-advise-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let share = dir.join("share.json");
    let init = zlint(&["share", "init", "--path", share.to_str().unwrap()]);
    assert!(init.status.success());
    std::fs::set_permissions(&share, std::fs::Permissions::from_mode(0o644)).unwrap();

    let decided = zlint(&[
        "decide",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/clean_accept.json",
    ]);
    assert!(decided.status.success());
    let decision: Value = serde_json::from_slice(&decided.stdout).unwrap();
    assert_eq!(decision["verdict"], "accept");
    assert!(decision.get("signature_share").is_none());

    let refused = zlint(&[
        "cosign",
        "--policy",
        "config/policy.example.yaml",
        "--activity",
        "fixtures/demo_activity.json",
        "--proposal",
        "fixtures/proposals/clean_accept.json",
        "--db",
        dir.join("zlint.db").to_str().unwrap(),
        "--share",
        share.to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(2));
    let err = String::from_utf8(refused.stderr).unwrap();
    assert!(err.contains("600"), "{err}");
    assert!(refused.stdout.is_empty());
}
