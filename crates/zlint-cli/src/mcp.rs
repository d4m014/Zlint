//! Stdio MCP server.
//! `zlint mcp` answers `propose_spend` and `review_pczt`. Neither tool signs.
//! `zlint frost mcp` is the enforce server. Its only tool is `cosign_pczt`.
//! Confirm is not a tool on either server.

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use zlint_policy::Policy;
use zlint_signer::PublicCommit;
use zlint_types::{Activity, Decision, SpendProposal};

use crate::frost_round::{self, CommitOutcome, SignOutcome};

struct Enforce {
    policy: PathBuf,
    activity: PathBuf,
    db: PathBuf,
    share: PathBuf,
    nonce: PathBuf,
}

pub fn serve() -> Result<(), String> {
    listen(None)
}

/// Enforce server. Share 2 and the nonce stay in this process. Confirm is not a tool.
pub fn serve_enforce(
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
    listen(Some(Enforce {
        policy: policy.to_path_buf(),
        activity: activity.to_path_buf(),
        db: db.to_path_buf(),
        share: share.to_path_buf(),
        nonce: nonce.to_path_buf(),
    }))
}

fn listen(enforce: Option<Enforce>) -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(err) => {
                write_message(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32700, "message": err.to_string()}
                    }),
                )?;
                continue;
            }
        };
        let method = message["method"].as_str().unwrap_or("");
        if message.get("id").is_none() || method.starts_with("notifications/") {
            continue;
        }
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => Ok(initialize(&message["params"])),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(tools(enforce.is_some())),
            "tools/call" => call_tool(&message["params"], enforce.as_ref()),
            _ => Err(json!({"code": -32601, "message": format!("method not found: {method}")})),
        };
        let response = match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
        };
        write_message(&mut stdout, &response)?;
    }
    Ok(())
}

fn initialize(params: &Value) -> Value {
    let version = params["protocolVersion"].as_str().unwrap_or("2024-11-05");
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "zlint", "version": "0.1.0"}
    })
}

fn tools(enforce: bool) -> Value {
    if enforce {
        return json!({
            "tools": [{
                "name": "cosign_pczt",
                "description": "Ask this co-signer for a FROST commitment or signature share on a PCZT. Omit commitment for round 1. Pass the other signer's public commitment for round 2. Does not broadcast. Confirm is not a tool.",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["proposed_at_ms"],
                    "properties": {
                        "pczt_path": {"type": "string"},
                        "pczt_hex": {"type": "string"},
                        "proposed_at_ms": {"type": "integer", "minimum": 0},
                        "commitment": {
                            "type": "object",
                            "description": "The other signer's public commitment. Omit this on round 1."
                        }
                    }
                }
            }]
        });
    }
    json!({
        "tools": [{
            "name": "propose_spend",
            "description": "Check a shielded spend. Returns the same decision object as `zlint decide`. Does not sign.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["policy_path", "activity_path"],
                "properties": {
                    "policy_path": {"type": "string"},
                    "activity_path": {"type": "string"},
                    "proposal_path": {"type": "string"},
                    "proposal": {
                        "type": "object",
                        "description": "Inline spend proposal. Use this or proposal_path."
                    }
                }
            }
        }, {
            "name": "review_pczt",
            "description": "Check a partially built Zcash transaction (PCZT). Returns the same kind of decision as `zlint decide`. Does not sign.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["policy_path", "activity_path", "pczt_path", "proposed_at_ms"],
                "properties": {
                    "policy_path": {"type": "string"},
                    "activity_path": {"type": "string"},
                    "pczt_path": {"type": "string"},
                    "proposed_at_ms": {"type": "integer", "minimum": 0}
                }
            }
        }]
    })
}

fn call_tool(params: &Value, enforce: Option<&Enforce>) -> Result<Value, Value> {
    let name = params["name"].as_str().unwrap_or("");
    let arguments = &params["arguments"];
    if name == "confirm" {
        return Ok(json!({
            "content": [{"type": "text", "text": "confirm stays on this machine"}],
            "isError": true
        }));
    }
    let outcome = match (name, enforce) {
        ("propose_spend", None) => propose(arguments),
        ("review_pczt", None) => review(arguments),
        ("cosign_pczt", Some(enforce)) => cosign_pczt(enforce, arguments),
        _ => return Err(json!({"code": -32602, "message": format!("unknown tool {name}")})),
    };
    match outcome {
        Ok(decision) => Ok(json!({
            "content": [{"type": "text", "text": decision}],
            "isError": false
        })),
        Err(err) => Ok(json!({
            "content": [{"type": "text", "text": err}],
            "isError": true
        })),
    }
}

fn propose(arguments: &Value) -> Result<String, String> {
    let policy_path = arguments["policy_path"]
        .as_str()
        .ok_or("policy_path is required")?;
    let activity_path = arguments["activity_path"]
        .as_str()
        .ok_or("activity_path is required")?;
    let policy = Policy::load(PathBuf::from(policy_path).as_path())?;
    let activity: Activity = read_json(activity_path)?;
    activity.validate()?;
    let proposal = if let Some(path) = arguments["proposal_path"].as_str() {
        read_json(path)?
    } else if arguments.get("proposal").is_some() && !arguments["proposal"].is_null() {
        serde_json::from_value(arguments["proposal"].clone()).map_err(|e| e.to_string())?
    } else {
        return Err("proposal_path or proposal is required".into());
    };
    let proposal: SpendProposal = proposal;
    proposal.validate()?;
    let decision = zlint_linter::decide(&policy, &activity, &proposal);
    serde_json::to_string_pretty(&decision).map_err(|e| e.to_string())
}

fn review(arguments: &Value) -> Result<String, String> {
    let policy_path = arguments["policy_path"]
        .as_str()
        .ok_or("policy_path is required")?;
    let activity_path = arguments["activity_path"]
        .as_str()
        .ok_or("activity_path is required")?;
    let pczt_path = arguments["pczt_path"]
        .as_str()
        .ok_or("pczt_path is required")?;
    let proposed_at_ms = arguments["proposed_at_ms"]
        .as_u64()
        .ok_or("proposed_at_ms is required")?;
    let policy = Policy::load(PathBuf::from(policy_path).as_path())?;
    let activity: Activity = read_json(activity_path)?;
    activity.validate()?;
    let bytes = std::fs::read(pczt_path).map_err(|e| format!("{pczt_path}: {e}"))?;
    let review = zlint_tx::review_pczt(&policy, &activity, &bytes, proposed_at_ms)?;
    serde_json::to_string_pretty(&review.decision).map_err(|e| e.to_string())
}

fn cosign_pczt(enforce: &Enforce, arguments: &Value) -> Result<String, String> {
    let object = arguments
        .as_object()
        .ok_or("cosign_pczt arguments must be an object")?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "pczt_path" | "pczt_hex" | "proposed_at_ms" | "commitment"
        ) {
            return Err(format!(
                "{key} is not accepted. policy and activity stay on this machine."
            ));
        }
    }
    let at = arguments["proposed_at_ms"]
        .as_u64()
        .ok_or("proposed_at_ms is required")?;
    let pczt = pczt_bytes(arguments)?;
    let has_commitment = arguments
        .get("commitment")
        .is_some_and(|value| !value.is_null());
    if has_commitment {
        let commitment: PublicCommit = serde_json::from_value(arguments["commitment"].clone())
            .map_err(|_| "commitment was not understood".to_string())?;
        match frost_round::server_sign(
            &enforce.policy,
            &enforce.activity,
            &enforce.db,
            &enforce.share,
            &enforce.nonce,
            &pczt,
            at,
            &commitment,
        )? {
            SignOutcome::Share {
                decision,
                signature,
            } => {
                eprintln!("contributed a signature share.");
                report(&decision, None, Some(&signature), false, false)
            }
            SignOutcome::Awaiting(decision) => report(&decision, None, None, true, false),
            SignOutcome::Refused(decision) => report(&decision, None, None, false, false),
            SignOutcome::AlreadySigned(decision) => report(&decision, None, None, false, true),
        }
    } else {
        match frost_round::server_commit(
            &enforce.policy,
            &enforce.activity,
            &enforce.db,
            &enforce.share,
            &enforce.nonce,
            &pczt,
            at,
        )? {
            CommitOutcome::Commitment { decision, public } => {
                eprintln!("contributed a commitment. the nonce file stays on this machine.");
                report(&decision, Some(&public), None, false, false)
            }
            CommitOutcome::Awaiting(decision) => {
                eprintln!("no share contributed. confirm this warning with `zlint confirm`.");
                report(&decision, None, None, true, false)
            }
            CommitOutcome::Refused(decision) => report(&decision, None, None, false, false),
            CommitOutcome::AlreadySigned(decision) => {
                eprintln!("already signed. no second share contributed.");
                report(&decision, None, None, false, true)
            }
        }
    }
}

fn report(
    decision: &Decision,
    commitment: Option<&PublicCommit>,
    signature: Option<&zlint_signer::FrostSignatureShare>,
    awaiting: bool,
    already_signed: bool,
) -> Result<String, String> {
    let mut body = json!({
        "decision": decision,
        "awaiting_confirmation": awaiting,
        "already_signed": already_signed,
    });
    if let Some(commitment) = commitment {
        body["commitment"] = serde_json::to_value(commitment).map_err(|e| e.to_string())?;
    }
    if let Some(signature) = signature {
        body["signature_share"] = serde_json::to_value(signature).map_err(|e| e.to_string())?;
    }
    serde_json::to_string_pretty(&body).map_err(|e| e.to_string())
}

fn pczt_bytes(arguments: &Value) -> Result<Vec<u8>, String> {
    let path = arguments["pczt_path"].as_str();
    let hex_text = arguments["pczt_hex"].as_str();
    match (path, hex_text) {
        (Some(_), Some(_)) => Err("pass pczt_path or pczt_hex".into()),
        (Some(path), None) => std::fs::read(path).map_err(|e| format!("{path}: {e}")),
        (None, Some(text)) => {
            hex::decode(text.trim()).map_err(|_| "pczt was not understood".to_string())
        }
        (None, None) => Err("pczt_path or pczt_hex is required".into()),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

fn write_message(stdout: &mut impl Write, message: &Value) -> Result<(), String> {
    writeln!(stdout, "{message}").map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())
}
