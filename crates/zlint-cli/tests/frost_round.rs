//! Host-local PCZT round.
//! Share 1 prepares on this side of the socket. Share 2 commits and signs over the socket.
//! The two signature shares are aggregated in the test. One share does not aggregate.

use std::convert::Infallible;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use incrementalmerkletree::Retention;
use orchard::tree::MerkleHashOrchard;
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::redactor::Redactor;
use pczt::roles::verifier::Verifier;
use pczt::Pczt;
use rand::rngs::OsRng;
use serde_json::Value;
use shardtree::store::memory::MemoryShardStore;
use shardtree::ShardTree;
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::value::Zatoshis;
use zlint_policy::Policy;
use zlint_signer::{
    aggregate_shares, group_verifying_key, orchard_ask_bytes, randomize_verifying_key,
    save_frost_share, split_ask, verify_spend_auth, FrostSignatureShare, PublicCommit,
};
use zlint_tx::apply_orchard_spend_auth;

const AT: u64 = 1_760_086_400_000;

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
    stderr: Arc<Mutex<String>>,
    reader: Option<JoinHandle<()>>,
}

impl Server {
    fn start(dir: &Path, policy: &Path, db: &Path, share: &Path, nonce: &Path) -> Self {
        let socket = dir.join("z.sock");
        let _ = std::fs::remove_file(&socket);
        let mut child = Command::new(env!("CARGO_BIN_EXE_zlint"))
            .args([
                "frost",
                "serve",
                "--socket",
                socket.to_str().unwrap(),
                "--policy",
                policy.to_str().unwrap(),
                "--activity",
                root().join("fixtures/demo_activity.json").to_str().unwrap(),
                "--db",
                db.to_str().unwrap(),
                "--share",
                share.to_str().unwrap(),
                "--nonce",
                nonce.to_str().unwrap(),
            ])
            .current_dir(root())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let log = Arc::new(Mutex::new(String::new()));
        let stored = log.clone();
        let reader = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                stored.lock().unwrap().push_str(&line);
                stored.lock().unwrap().push('\n');
            }
        });
        for _ in 0..50 {
            if socket.exists() {
                let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
                if mode == 0o600 {
                    return Self {
                        child,
                        socket,
                        stderr: log,
                        reader: Some(reader),
                    };
                }
            }
            if let Some(status) = child.try_wait().unwrap() {
                thread::sleep(Duration::from_millis(50));
                panic!("frost serve exited {status}: {}", log.lock().unwrap());
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("socket was not owner-only: {}", log.lock().unwrap());
    }

    fn request(&self, body: &Value) -> Value {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream.write_all(format!("{body}\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).expect(&line)
    }

    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.stderr.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn the_co_signer_signs_one_orchard_spend_and_refuses_the_rest() {
    let dir = std::env::temp_dir().join(format!("zlint-frost-round-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let spending_key_bytes = [0u8; 32];
    let spending_key = orchard::keys::SpendingKey::from_bytes(spending_key_bytes).unwrap();
    let ask = orchard_ask_bytes(&spending_key_bytes).unwrap();
    let frost = split_ask(ask).unwrap();
    let (pczt, _) = orchard_spend_pczt(&spending_key);
    let pczt = redact_change(pczt);
    let bytes = pczt.clone().serialize().unwrap();
    let pczt_path = dir.join("spend.pczt");
    std::fs::write(&pczt_path, &bytes).unwrap();

    let share1 = dir.join("share1.json");
    let share2 = dir.join("share2.json");
    save_frost_share(&share1, "share1", &frost.share1, &frost.group).unwrap();
    save_frost_share(&share2, "share2", &frost.share2, &frost.group).unwrap();
    let share_ids = [share_id(&share1), share_id(&share2)];

    let policy = Policy::load(&root().join("config/policy.example.yaml")).unwrap();
    let activity: zlint_types::Activity = serde_json::from_str(
        &std::fs::read_to_string(root().join("fixtures/demo_activity.json")).unwrap(),
    )
    .unwrap();
    let review = zlint_tx::review_pczt(&policy, &activity, &bytes, AT).unwrap();
    assert_eq!(
        review.decision.verdict,
        zlint_types::Verdict::Accept,
        "{:?}",
        review.decision
    );
    assert_eq!(review.payment.amount_zatoshis, 100_000);
    assert_eq!(review.payment.change_zatoshis, 890_000);

    let parsed = zlint_tx::orchard_sighash(&bytes).unwrap();
    let group_key = group_verifying_key(&frost.group).unwrap();
    let matched: Vec<_> = parsed
        .actions
        .iter()
        .filter(|action| randomize_verifying_key(group_key, &action.alpha).unwrap() == action.rk)
        .collect();
    assert_eq!(matched.len(), 1, "the spend must match one action");
    let index = matched[0].index;
    let alpha = matched[0].alpha;

    let policy_path = dir.join("policy.yaml");
    let example = std::fs::read_to_string(root().join("config/policy.example.yaml")).unwrap();
    std::fs::write(&policy_path, &example).unwrap();
    let db = dir.join("zlint.db");
    let server_nonce = dir.join("share2.nonce");
    let server = Server::start(&dir, &policy_path, &db, &share2, &server_nonce);

    let remote_confirm = server.request(&serde_json::json!({
        "method": "confirm",
        "pczt": hex::encode(&bytes),
        "at": AT,
    }));
    assert!(
        remote_confirm["error"]
            .as_str()
            .unwrap()
            .contains("confirm"),
        "{remote_confirm}"
    );
    let extra = server.request(&serde_json::json!({
        "method": "commit",
        "pczt": hex::encode(&bytes),
        "at": AT,
        "activity": {"receives": [], "shields": [], "accepted_spends": []},
    }));
    assert!(extra.get("error").is_some(), "{extra}");
    assert!(!server_nonce.exists());

    let agent_nonce = dir.join("share1.nonce");
    let prepared = zlint(&[
        "frost",
        "prepare",
        "--share",
        share1.to_str().unwrap(),
        "--nonce",
        agent_nonce.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
    ]);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let agent_commit: PublicCommit = serde_json::from_slice(&prepared.stdout).unwrap();
    let agent_commit_path = dir.join("agent.commit.json");
    std::fs::write(&agent_commit_path, &prepared.stdout).unwrap();
    assert_eq!(
        std::fs::metadata(&agent_nonce)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let committed = zlint(&[
        "frost",
        "commit",
        "--socket",
        server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert!(
        committed.status.success(),
        "{}",
        String::from_utf8_lossy(&committed.stderr)
    );
    let server_commit: PublicCommit = serde_json::from_slice(&committed.stdout).unwrap();
    assert!(committed.stdout.windows(12).all(|w| w != b"key_package"));
    let nonce_bytes = std::fs::read(&server_nonce).unwrap();
    let secrets = secret_nonces(&server_nonce);
    assert_eq!(
        std::fs::metadata(&server_nonce)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let committed_again = zlint(&[
        "frost",
        "commit",
        "--socket",
        server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert!(committed_again.status.success());
    let again: PublicCommit = serde_json::from_slice(&committed_again.stdout).unwrap();
    assert_eq!(again, server_commit);
    assert_eq!(std::fs::read(&server_nonce).unwrap(), nonce_bytes);

    let server_commit_path = dir.join("server.commit.json");
    std::fs::write(&server_commit_path, &committed.stdout).unwrap();
    let signed = zlint(&[
        "frost",
        "sign",
        "--socket",
        server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
        "--commitment",
        agent_commit_path.to_str().unwrap(),
    ]);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    assert!(
        !server_nonce.exists(),
        "sign deletes the nonce before it signs"
    );
    let server_share: FrostSignatureShare = serde_json::from_slice(&signed.stdout).unwrap();

    let contributed = zlint(&[
        "frost",
        "contribute",
        "--share",
        share1.to_str().unwrap(),
        "--nonce",
        agent_nonce.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--theirs",
        server_commit_path.to_str().unwrap(),
    ]);
    assert!(
        contributed.status.success(),
        "{}",
        String::from_utf8_lossy(&contributed.stderr)
    );
    assert!(!agent_nonce.exists());
    let agent_share: FrostSignatureShare = serde_json::from_slice(&contributed.stdout).unwrap();

    let mut commitments = std::collections::BTreeMap::new();
    commitments.insert(agent_commit.identifier, agent_commit.commitment);
    commitments.insert(server_commit.identifier, server_commit.commitment);
    let mut one = std::collections::BTreeMap::new();
    one.insert(agent_commit.identifier, agent_share);
    assert!(aggregate_shares(&commitments, &parsed.sighash, &one, &frost.group, &alpha).is_err());
    let mut both = one;
    both.insert(server_commit.identifier, server_share);
    let signature =
        aggregate_shares(&commitments, &parsed.sighash, &both, &frost.group, &alpha).unwrap();
    let signed_pczt = apply_orchard_spend_auth(&bytes, index, signature).unwrap();
    verify_spend_auth(matched[0].rk, &parsed.sighash, signature).unwrap();
    let signed_parsed = zlint_tx::orchard_sighash(&signed_pczt).unwrap();
    assert_eq!(signed_parsed.sighash, parsed.sighash);

    let second = zlint(&[
        "frost",
        "commit",
        "--socket",
        server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_json: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second_json["already_signed"], true);
    assert!(!server_nonce.exists());

    let shown = shown_outputs(&[
        &prepared,
        &committed,
        &committed_again,
        &signed,
        &contributed,
        &second,
    ]);
    let accept_log = server.stop();
    assert_hidden(&(shown + &accept_log), &share_ids, &secrets);
    // Reject and warn use a fresh log and the same share.
    std::fs::write(
        &policy_path,
        example.replace("max_tx_zatoshis: 50000000", "max_tx_zatoshis: 1"),
    )
    .unwrap();
    let _ = std::fs::remove_file(&db);
    let reject_server = Server::start(&dir, &policy_path, &db, &share2, &server_nonce);
    let rejected = zlint(&[
        "frost",
        "commit",
        "--socket",
        reject_server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    let reject_err = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        reject_err.contains("reject") || reject_err.contains("no share"),
        "{reject_err}"
    );
    assert!(!server_nonce.exists());
    let reject_log = reject_server.stop();
    assert_hidden(&reject_log, &share_ids, &[]);
    assert_hidden(&reject_err, &share_ids, &[]);

    std::fs::write(
        &policy_path,
        example.replace("warn_below: 75", "warn_below: 101"),
    )
    .unwrap();
    let _ = std::fs::remove_file(&db);
    let warn_server = Server::start(&dir, &policy_path, &db, &share2, &server_nonce);
    let warned = zlint(&[
        "frost",
        "commit",
        "--socket",
        warn_server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert!(
        warned.status.success(),
        "{}",
        String::from_utf8_lossy(&warned.stderr)
    );
    let warned_json: Value = serde_json::from_slice(&warned.stdout).unwrap();
    assert_eq!(warned_json["awaiting_confirmation"], true);
    assert!(warned_json.get("commitment").is_none());
    assert!(!server_nonce.exists());

    let missing_pczt = zlint(&[
        "confirm",
        "--policy",
        policy_path.to_str().unwrap(),
        "--activity",
        root().join("fixtures/demo_activity.json").to_str().unwrap(),
        "--proposal",
        root()
            .join("fixtures/proposals/shield_warn.json")
            .to_str()
            .unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--share",
        share2.to_str().unwrap(),
    ]);
    assert_eq!(missing_pczt.status.code(), Some(2));
    assert!(missing_pczt.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing_pczt.stderr).contains("PCZT"));

    let confirmed = zlint(&[
        "confirm",
        "--policy",
        policy_path.to_str().unwrap(),
        "--activity",
        root().join("fixtures/demo_activity.json").to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--share",
        share2.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert!(
        confirmed.status.success(),
        "{}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    let confirmed_json: Value = serde_json::from_slice(&confirmed.stdout).unwrap();
    assert_eq!(confirmed_json["confirmed"], true);
    assert!(confirmed_json["signature_share"].is_null());
    assert!(String::from_utf8_lossy(&confirmed.stderr).contains("no signature share"));
    assert!(!server_nonce.exists());

    let unlocked = zlint(&[
        "frost",
        "commit",
        "--socket",
        warn_server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert!(
        unlocked.status.success(),
        "{}",
        String::from_utf8_lossy(&unlocked.stderr)
    );
    let unlocked_json: Value = serde_json::from_slice(&unlocked.stdout).unwrap();
    assert!(unlocked_json.get("commitment").is_some(), "{unlocked_json}");
    assert_eq!(
        std::fs::metadata(&server_nonce)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let warn_secrets = secret_nonces(&server_nonce);

    std::fs::write(
        &policy_path,
        example.replace("max_tx_zatoshis: 50000000", "max_tx_zatoshis: 1"),
    )
    .unwrap();
    let refused = zlint(&[
        "frost",
        "sign",
        "--socket",
        warn_server.socket.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
        "--commitment",
        agent_commit_path.to_str().unwrap(),
    ]);
    assert_eq!(
        refused.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(refused.stdout.is_empty());
    assert!(!server_nonce.exists(), "a reject deletes the nonce");
    let warn_log = warn_server.stop();
    let warn_shown = shown_outputs(&[&warned, &confirmed, &unlocked, &refused]) + &warn_log;
    assert_hidden(&warn_shown, &share_ids, &warn_secrets);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn advice_mcp_has_no_cosign_and_frost_mcp_signs_the_spend() {
    let dir = std::env::temp_dir().join(format!("zlint-frost-mcp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let simulated = dir.join("simulated.json");
    let init = zlint(&["share", "init", "--path", simulated.to_str().unwrap()]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let refused = zlint(&[
        "frost",
        "mcp",
        "--policy",
        root().join("config/policy.example.yaml").to_str().unwrap(),
        "--activity",
        root().join("fixtures/demo_activity.json").to_str().unwrap(),
        "--db",
        dir.join("unused.db").to_str().unwrap(),
        "--share",
        simulated.to_str().unwrap(),
        "--nonce",
        dir.join("unused.nonce").to_str().unwrap(),
    ]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("FROST"));

    let spending_key = orchard::keys::SpendingKey::from_bytes([0u8; 32]).unwrap();
    let ask = orchard_ask_bytes(&[0u8; 32]).unwrap();
    let frost = split_ask(ask).unwrap();
    let (pczt, _) = orchard_spend_pczt(&spending_key);
    let bytes = redact_change(pczt).serialize().unwrap();
    let pczt_path = dir.join("spend.pczt");
    std::fs::write(&pczt_path, &bytes).unwrap();
    let share1 = dir.join("share1.json");
    let share2 = dir.join("share2.json");
    save_frost_share(&share1, "share1", &frost.share1, &frost.group).unwrap();
    save_frost_share(&share2, "share2", &frost.share2, &frost.group).unwrap();
    let share_ids = [share_id(&share1), share_id(&share2)];

    let example = std::fs::read_to_string(root().join("config/policy.example.yaml")).unwrap();
    let policy_path = dir.join("policy.yaml");
    std::fs::write(
        &policy_path,
        example.replace("max_tx_zatoshis: 50000000", "max_tx_zatoshis: 1"),
    )
    .unwrap();
    let db = dir.join("zlint.db");
    let nonce = dir.join("share2.nonce");
    let mut mcp = Mcp::start(&dir, &policy_path, &db, &share2, &nonce);

    let listed = mcp.call(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list"
    }));
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["cosign_pczt"]);

    let remote_confirm = mcp.call(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "confirm", "arguments": {}}
    }));
    assert_eq!(remote_confirm["result"]["isError"], true);
    assert!(tool_text(&remote_confirm).contains("confirm"));

    let overridden = mcp.call(&cosign_call(3, &pczt_path, None, Some("policy_path")));
    assert_eq!(overridden["result"]["isError"], true);
    assert!(tool_text(&overridden).contains("not accepted"));
    assert!(!nonce.exists());

    let rejected = mcp.call(&cosign_call(4, &pczt_path, None, None));
    assert_eq!(rejected["result"]["isError"], false);
    let rejected_body: Value = serde_json::from_str(tool_text(&rejected)).unwrap();
    assert_eq!(rejected_body["decision"]["verdict"], "reject");
    assert!(rejected_body.get("commitment").is_none());
    assert!(rejected_body.get("signature_share").is_none());
    assert!(!nonce.exists());

    std::fs::write(
        &policy_path,
        example.replace("warn_below: 75", "warn_below: 101"),
    )
    .unwrap();
    let warned = mcp.call(&cosign_call(5, &pczt_path, None, None));
    let warned_body: Value = serde_json::from_str(tool_text(&warned)).unwrap();
    assert_eq!(warned_body["awaiting_confirmation"], true);
    assert!(warned_body.get("commitment").is_none());
    assert!(!nonce.exists());

    let confirmed = zlint(&[
        "confirm",
        "--policy",
        policy_path.to_str().unwrap(),
        "--activity",
        root().join("fixtures/demo_activity.json").to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
        "--share",
        share2.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--at",
        &AT.to_string(),
    ]);
    assert!(
        confirmed.status.success(),
        "{}",
        String::from_utf8_lossy(&confirmed.stderr)
    );
    assert!(
        serde_json::from_slice::<Value>(&confirmed.stdout).unwrap()["signature_share"].is_null()
    );

    let unlocked = mcp.call(&cosign_call(6, &pczt_path, None, None));
    let unlocked_body: Value = serde_json::from_str(tool_text(&unlocked)).unwrap();
    assert!(unlocked_body.get("commitment").is_some(), "{unlocked_body}");
    assert!(unlocked_body.get("signature_share").is_none());
    assert_eq!(
        std::fs::metadata(&nonce).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let secrets = secret_nonces(&nonce);
    let server_commit: PublicCommit =
        serde_json::from_value(unlocked_body["commitment"].clone()).unwrap();

    let agent_nonce = dir.join("share1.nonce");
    let prepared = zlint(&[
        "frost",
        "prepare",
        "--share",
        share1.to_str().unwrap(),
        "--nonce",
        agent_nonce.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
    ]);
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let agent_commit: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    let signed = mcp.call(&cosign_call(7, &pczt_path, Some(&agent_commit), None));
    assert_eq!(signed["result"]["isError"], false, "{signed}");
    let signed_body: Value = serde_json::from_str(tool_text(&signed)).unwrap();
    assert!(
        signed_body.get("signature_share").is_some(),
        "{signed_body}"
    );
    assert!(!nonce.exists());
    let server_share: FrostSignatureShare =
        serde_json::from_value(signed_body["signature_share"].clone()).unwrap();
    let agent_public: PublicCommit = serde_json::from_value(agent_commit).unwrap();

    let server_commit_path = dir.join("server.commit.json");
    std::fs::write(
        &server_commit_path,
        serde_json::to_vec_pretty(&server_commit).unwrap(),
    )
    .unwrap();
    let contributed = zlint(&[
        "frost",
        "contribute",
        "--share",
        share1.to_str().unwrap(),
        "--nonce",
        agent_nonce.to_str().unwrap(),
        "--pczt",
        pczt_path.to_str().unwrap(),
        "--theirs",
        server_commit_path.to_str().unwrap(),
    ]);
    assert!(
        contributed.status.success(),
        "{}",
        String::from_utf8_lossy(&contributed.stderr)
    );
    let agent_share: FrostSignatureShare = serde_json::from_slice(&contributed.stdout).unwrap();
    let parsed = zlint_tx::orchard_sighash(&bytes).unwrap();
    let group_key = group_verifying_key(&frost.group).unwrap();
    let action = parsed
        .actions
        .iter()
        .find(|action| randomize_verifying_key(group_key, &action.alpha).unwrap() == action.rk)
        .unwrap();
    let mut commitments = std::collections::BTreeMap::new();
    commitments.insert(agent_public.identifier, agent_public.commitment);
    commitments.insert(server_commit.identifier, server_commit.commitment);
    let mut shares = std::collections::BTreeMap::new();
    shares.insert(server_commit.identifier, server_share);
    assert!(aggregate_shares(
        &commitments,
        &parsed.sighash,
        &shares,
        &frost.group,
        &action.alpha
    )
    .is_err());
    shares.insert(agent_public.identifier, agent_share);
    let signature = aggregate_shares(
        &commitments,
        &parsed.sighash,
        &shares,
        &frost.group,
        &action.alpha,
    )
    .unwrap();
    apply_orchard_spend_auth(&bytes, action.index, signature).unwrap();

    let log = mcp.stop();
    let shown = format!(
        "{listed}{remote_confirm}{overridden}{rejected}{warned}{unlocked}{signed}{log}{}",
        String::from_utf8_lossy(&confirmed.stdout),
    );
    assert_hidden(&shown, &share_ids, &secrets);
    let _ = std::fs::remove_dir_all(&dir);
}

struct Mcp {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
    stderr: Arc<Mutex<String>>,
    reader: Option<JoinHandle<()>>,
}

impl Mcp {
    fn start(dir: &Path, policy: &Path, db: &Path, share: &Path, nonce: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zlint"))
            .args([
                "frost",
                "mcp",
                "--policy",
                policy.to_str().unwrap(),
                "--activity",
                root().join("fixtures/demo_activity.json").to_str().unwrap(),
                "--db",
                db.to_str().unwrap(),
                "--share",
                share.to_str().unwrap(),
                "--nonce",
                nonce.to_str().unwrap(),
            ])
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let stderr = child.stderr.take().unwrap();
        let log = Arc::new(Mutex::new(String::new()));
        let stored = log.clone();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                stored.lock().unwrap().push_str(&line);
                stored.lock().unwrap().push('\n');
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr: log,
            reader: Some(reader),
        }
    }

    fn call(&mut self, message: &Value) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        if line.trim().is_empty() {
            panic!("mcp closed: {}", self.stderr.lock().unwrap());
        }
        serde_json::from_str(line.trim()).unwrap()
    }

    fn stop(mut self) -> String {
        self.stdin.take();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        self.stderr.lock().unwrap().clone()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn cosign_call(id: u64, pczt: &Path, commitment: Option<&Value>, extra: Option<&str>) -> Value {
    let mut arguments = serde_json::json!({
        "pczt_path": pczt.to_str().unwrap(),
        "proposed_at_ms": AT,
    });
    if let Some(commitment) = commitment {
        arguments["commitment"] = commitment.clone();
    }
    if let Some(extra) = extra {
        arguments[extra] = serde_json::json!("ignored");
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "cosign_pczt", "arguments": arguments}
    })
}

fn tool_text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
}

fn shown_outputs(outputs: &[&std::process::Output]) -> String {
    outputs
        .iter()
        .map(|output| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .collect()
}

fn assert_hidden(shown: &str, share_ids: &[String], secrets: &[String]) {
    assert!(!shown.contains("key_package"), "{shown}");
    for id in share_ids {
        assert!(!shown.contains(id), "output contained a share id");
    }
    for secret in secrets {
        assert!(
            !shown.contains(secret.as_str()),
            "output contained a secret nonce"
        );
    }
}

fn share_id(path: &Path) -> String {
    let body: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    body["id"].as_str().unwrap().to_string()
}

fn secret_nonces(path: &Path) -> Vec<String> {
    let body: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    vec![
        body["nonces"]["hiding"]
            .as_str()
            .expect("hiding nonce hex")
            .to_string(),
        body["nonces"]["binding"]
            .as_str()
            .expect("binding nonce hex")
            .to_string(),
    ]
}

fn redact_change(pczt: Pczt) -> Pczt {
    let mut indexes = Vec::new();
    Verifier::new(pczt.clone())
        .with_orchard::<Infallible, _>(|bundle| {
            for (index, action) in bundle.actions().iter().enumerate() {
                if *action.output().value() == Some(orchard::value::NoteValue::from_raw(890_000)) {
                    indexes.push(index);
                }
            }
            Ok(())
        })
        .unwrap();
    assert!(!indexes.is_empty(), "change output was not found");
    let mut redactor = Redactor::new(pczt);
    for index in indexes {
        redactor = redactor.redact_orchard_with(|mut orchard| {
            orchard.redact_action(index, |mut action| {
                action.clear_output_recipient();
                action.clear_output_user_address();
            });
        });
    }
    redactor.finish()
}

fn orchard_spend_pczt(spending_key: &orchard::keys::SpendingKey) -> (Pczt, usize) {
    let mut rng = OsRng;
    let fvk = orchard::keys::FullViewingKey::from(spending_key);
    let ivk = fvk.to_ivk(orchard::keys::Scope::External);
    let external_ovk = fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::bundle::BundleVersion::orchard_v2(),
            orchard::bundle::BundleVersion::orchard_v2().default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &ivk.prepare(), action).unwrap();
        note
    };

    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, Retention::Marked).unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let merkle_path = tree
            .witness_at_checkpoint_depth(0.into(), 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    let mut builder = Builder::new(
        pre_nu6_3_test_network(),
        BlockHeight::from_u32(10_000_000),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(external_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
            fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(890_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let result = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();
    let index = result.orchard_meta.spend_action_index(0).unwrap();
    let pczt = Creator::build_from_parts(result.pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    (pczt, index)
}

fn pre_nu6_3_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
    zcash_protocol::local_consensus::LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(2)),
        blossom: Some(BlockHeight::from_u32(3)),
        heartwood: Some(BlockHeight::from_u32(4)),
        canopy: Some(BlockHeight::from_u32(5)),
        nu5: Some(BlockHeight::from_u32(6)),
        nu6: Some(BlockHeight::from_u32(7)),
        nu6_1: Some(BlockHeight::from_u32(8)),
        nu6_2: Some(BlockHeight::from_u32(9)),
        nu6_3: None,
    }
}
