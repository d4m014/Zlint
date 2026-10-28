//! Unix socket for a PCZT signing round.
//! Methods are `commit` and `sign`. `confirm` stays on this machine.
//! The response is a public commitment or a signature share.

use serde::Deserialize;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use zlint_signer::PublicCommit;

use crate::frost_round::{self, awaiting_message, CommitOutcome, SignOutcome};
use crate::summary;

const MAX_REQUEST: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitRequest {
    method: String,
    pczt: String,
    at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignRequest {
    method: String,
    pczt: String,
    at: u64,
    commitment: PublicCommit,
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
    nonce: &Path,
) -> Result<(), String> {
    let loaded = zlint_signer::load_frost_share(share)?;
    if loaded.role != "share2" {
        return Err(format!("{} is not share 2", share.display()));
    }
    bind(socket)?;
    let _cleanup = RemoveSocket(socket.to_path_buf());
    let listener = UnixListener::bind(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    eprintln!(
        "listening on {}. share 2 stays in this process.",
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
        match handle(&mut stream, policy, activity, db, share, nonce) {
            Ok(line) => {
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

fn bind(socket: &Path) -> Result<(), String> {
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
    Ok(())
}

fn handle(
    stream: &mut UnixStream,
    policy: &Path,
    activity: &Path,
    db: &Path,
    share: &Path,
    nonce: &Path,
) -> Result<String, String> {
    let mut reader = BufReader::new(stream.take(MAX_REQUEST));
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read request: {e}"))?;
    if line.len() as u64 >= MAX_REQUEST && !line.ends_with('\n') {
        return Err("request is too large".into());
    }
    if line.trim().is_empty() {
        return Err("empty request".into());
    }
    let value: Value = serde_json::from_str(&line).map_err(|_| "request was not understood")?;
    let method = value
        .get("method")
        .and_then(|method| method.as_str())
        .unwrap_or("");
    if method == "confirm" {
        return Err("confirm stays on this machine".into());
    }
    if method.is_empty() {
        return Err("request was not understood".into());
    }
    match method {
        "commit" => {
            let request: CommitRequest = serde_json::from_value(value)
                .map_err(|_| "request was not understood".to_string())?;
            if request.method != "commit" {
                return Err(format!(
                    "{} is not available on this socket. confirm stays on this machine.",
                    request.method
                ));
            }
            let pczt = decode_pczt(&request.pczt)?;
            match frost_round::server_commit(policy, activity, db, share, nonce, &pczt, request.at)?
            {
                CommitOutcome::Commitment { public, .. } => {
                    eprintln!("contributed a commitment. the nonce file stays on this machine.");
                    serde_json::to_string(&public).map_err(|e| e.to_string())
                }
                CommitOutcome::Refused(decision) => {
                    Err(format!("no share contributed\n{}", summary(&decision)))
                }
                CommitOutcome::Awaiting(decision) => {
                    eprintln!("no share contributed. confirm this warning with `zlint confirm`.");
                    eprintln!("{}", summary(&decision));
                    Ok(serde_json::json!({
                        "awaiting_confirmation": true,
                        "decision": decision,
                    })
                    .to_string())
                }
                CommitOutcome::AlreadySigned(decision) => {
                    eprintln!("already signed. no second share contributed.");
                    Ok(serde_json::json!({
                        "already_signed": true,
                        "decision": decision,
                    })
                    .to_string())
                }
            }
        }
        "sign" => {
            let request: SignRequest = serde_json::from_value(value)
                .map_err(|_| "request was not understood".to_string())?;
            if request.method != "sign" {
                return Err(format!(
                    "{} is not available on this socket. confirm stays on this machine.",
                    request.method
                ));
            }
            let pczt = decode_pczt(&request.pczt)?;
            match frost_round::server_sign(
                policy,
                activity,
                db,
                share,
                nonce,
                &pczt,
                request.at,
                &request.commitment,
            )? {
                SignOutcome::Share { signature, .. } => {
                    eprintln!("contributed a signature share.");
                    serde_json::to_string(&signature).map_err(|e| e.to_string())
                }
                SignOutcome::Awaiting(decision) => Err(awaiting_message(&decision)),
                SignOutcome::Refused(decision) => {
                    Err(format!("no share contributed\n{}", summary(&decision)))
                }
                SignOutcome::AlreadySigned(decision) => {
                    eprintln!("already signed. no second share contributed.");
                    Ok(serde_json::json!({
                        "already_signed": true,
                        "decision": decision,
                    })
                    .to_string())
                }
            }
        }
        other => Err(format!(
            "{other} is not available on this socket. confirm stays on this machine."
        )),
    }
}

fn decode_pczt(hex_text: &str) -> Result<Vec<u8>, String> {
    hex::decode(hex_text.trim()).map_err(|_| "pczt was not understood".to_string())
}

fn write_line(stream: &mut UnixStream, line: &str) -> Result<(), String> {
    stream
        .write_all(line.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(())
}

pub fn round_request(socket: &Path, request: &Value) -> Result<Value, String> {
    let mut stream =
        UnixStream::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    write_line(&mut stream, &request.to_string())?;
    let mut reader = BufReader::new(stream.take(MAX_REQUEST));
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().is_empty() {
        return Err("co-signer closed the socket".into());
    }
    let value: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    if let Some(err) = value.get("error").and_then(|err| err.as_str()) {
        return Err(err.to_string());
    }
    Ok(value)
}

pub fn commit(socket: &Path, pczt: &Path, at: u64) -> Result<Value, String> {
    let bytes = std::fs::read(pczt).map_err(|e| format!("{}: {e}", pczt.display()))?;
    round_request(
        socket,
        &serde_json::json!({
            "method": "commit",
            "pczt": hex::encode(bytes),
            "at": at,
        }),
    )
}

pub fn sign(socket: &Path, pczt: &Path, at: u64, commitment: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(pczt).map_err(|e| format!("{}: {e}", pczt.display()))?;
    let text = std::fs::read_to_string(commitment)
        .map_err(|e| format!("{}: {e}", commitment.display()))?;
    let commitment: Value =
        serde_json::from_str(&text).map_err(|_| "commitment was not understood".to_string())?;
    round_request(
        socket,
        &serde_json::json!({
            "method": "sign",
            "pczt": hex::encode(bytes),
            "at": at,
            "commitment": commitment,
        }),
    )
}
