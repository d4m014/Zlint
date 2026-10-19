//! Stdio MCP server.
//! `propose_spend` returns the same decision JSON as `zlint decide`.
//! `review_pczt` checks a partially built Zcash transaction.
//! Neither tool signs, and neither writes the decision log.

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use zlint_policy::Policy;
use zlint_types::{Activity, SpendProposal};

pub fn serve() -> Result<(), String> {
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
            "tools/list" => Ok(tools()),
            "tools/call" => call_tool(&message["params"]),
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

fn tools() -> Value {
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

fn call_tool(params: &Value) -> Result<Value, Value> {
    let name = params["name"].as_str().unwrap_or("");
    let arguments = &params["arguments"];
    let outcome = match name {
        "propose_spend" => propose(arguments),
        "review_pczt" => review(arguments),
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

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
}

fn write_message(stdout: &mut impl Write, message: &Value) -> Result<(), String> {
    writeln!(stdout, "{message}").map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())
}
