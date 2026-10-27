//! Unix socket for an agent.
//! The agent sends a proposal. Policy, activity, the decision log, and the share file
//! stay in this process. `confirm` is not a method on this socket.

use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zlint_signer::CosignReport;
use zlint_types::SpendProposal;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    method: String,
    proposal: SpendProposal,
}

struct RemoveSocket(PathBuf);

impl Drop for RemoveSocket {
    fn drop(&mut self) {
        if self.0.exists() {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

pub fn listen(
    socket: &Path,
    policy: &Path,
    activity: &Path,
    db: &Path,
    share: &Path,
) -> Result<(), String> {
    zlint_signer::require_simulated_share(share)?;
    if socket.exists() {
        let meta = std::fs::metadata(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
        if meta.file_type().is_socket() {
            std::fs::remove_file(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
        } else {
            return Err(format!("{} exists and is not a socket", socket.display()));
        }
    }
    if let Some(parent) = socket.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
    }
    let listener = UnixListener::bind(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    let _cleanup = RemoveSocket(socket.to_path_buf());
    eprintln!(
        "listening on {}. the share file stays in this process.",
        socket.display()
    );
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("zlint: {err}");
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        match handle(&mut stream, policy, activity, db, share) {
            Ok(report) => {
                eprintln!("{}", super::summary(&report.decision));
                eprintln!("{}", super::share_status(&report));
                let line = serde_json::to_string(&report).map_err(|e| e.to_string())?;
                let _ = write_line(&mut stream, &line);
            }
            Err(err) => {
                eprintln!("zlint: {err}");
                let line = serde_json::json!({"error": err}).to_string();
                let _ = write_line(&mut stream, &line);
            }
        }
    }
    Ok(())
}

fn handle(
    stream: &mut UnixStream,
    policy: &Path,
    activity: &Path,
    db: &Path,
    share: &Path,
) -> Result<CosignReport, String> {
    let mut reader = BufReader::new(stream.take(64 * 1024));
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read proposal: {e}"))?;
    if line.trim().is_empty() {
        return Err("empty proposal".into());
    }
    let request: Request =
        serde_json::from_str(&line).map_err(|e| format!("proposal was not understood: {e}"))?;
    if request.method != "cosign" {
        return Err(format!(
            "{} is not available on this socket. confirm stays on this machine.",
            request.method
        ));
    }
    super::cosign_loaded(policy, activity, request.proposal, db, share)
}

fn write_line(stream: &mut UnixStream, line: &str) -> Result<(), String> {
    stream
        .write_all(line.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(())
}

pub fn propose(socket: &Path, proposal_path: &Path) -> Result<CosignReport, String> {
    let proposal_text = std::fs::read_to_string(proposal_path)
        .map_err(|e| format!("{}: {e}", proposal_path.display()))?;
    let proposal: serde_json::Value = serde_json::from_str(&proposal_text)
        .map_err(|e| format!("{}: {e}", proposal_path.display()))?;
    let request = serde_json::json!({
        "method": "cosign",
        "proposal": proposal,
    });
    let mut stream =
        UnixStream::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    write_line(&mut stream, &request.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().is_empty() {
        return Err("co-signer closed the socket".into());
    }
    let value: serde_json::Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    if let Some(err) = value.get("error").and_then(|err| err.as_str()) {
        return Err(err.to_string());
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}
