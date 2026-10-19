mod mcp;

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zlint_policy::Policy;
use zlint_store::Store;
use zlint_types::{Activity, Decision, SpendProposal, Verdict};

#[derive(Parser)]
#[command(
    name = "zlint",
    about = "Check a shielded ZEC spend against limits and privacy rules. Does not sign."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print one JSON decision. Exit 0 for accept, reject, and warn.
    Decide {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        activity: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
        /// Remember this decision. An accept is also counted toward the cap and the rate limit.
        #[arg(long)]
        db: Option<PathBuf>,
        /// Also write the decision JSON to this file.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Print the caps and privacy thresholds.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Print the newest logged decisions. Scores are the privacy history.
    History {
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Speak MCP on stdin/stdout. The tools are `propose_spend` and `review_pczt`.
    Mcp,
    /// Check a partially built Zcash transaction. Does not sign it.
    Review {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        activity: PathBuf,
        /// PCZT bytes, the transaction a wallet or agent built.
        #[arg(long)]
        pczt: PathBuf,
        /// When the spend is being proposed, in Unix milliseconds.
        #[arg(long)]
        at: u64,
        /// Also write the decision JSON to this file.
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum PolicyCommand {
    Show {
        #[arg(long)]
        policy: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Decide {
            policy,
            activity,
            proposal,
            db,
            report,
        } => match run_decide(&policy, &activity, &proposal, db.as_deref()) {
            Ok(decision) => finish_decision(&decision, report.as_deref()),
            Err(err) => fail(err),
        },
        Command::Policy {
            command: PolicyCommand::Show { policy },
        } => match Policy::load(&policy) {
            Ok(policy) => {
                print!("{}", policy.show());
                ExitCode::SUCCESS
            }
            Err(err) => fail(err),
        },
        Command::History { db, limit } => match history_cmd(&db, limit) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(err) => fail(err),
        },
        Command::Mcp => match mcp::serve() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => fail(err),
        },
        Command::Review {
            policy,
            activity,
            pczt,
            at,
            report,
        } => match review_cmd(&policy, &activity, &pczt, at) {
            Ok(review) => {
                eprintln!("checked the transaction. does not sign.");
                finish_decision(&review.decision, report.as_deref())
            }
            Err(err) => fail(err),
        },
    }
}

fn fail(err: String) -> ExitCode {
    eprintln!("zlint: {err}");
    ExitCode::from(2)
}

fn finish_decision(decision: &Decision, report: Option<&Path>) -> ExitCode {
    let json = serde_json::to_string_pretty(decision).unwrap();
    if let Some(path) = report {
        if let Err(err) = write_report(path, &json) {
            return fail(err);
        }
    }
    eprintln!("{}", summary(decision));
    println!("{json}");
    ExitCode::SUCCESS
}

fn review_cmd(
    policy: &Path,
    activity: &Path,
    pczt: &Path,
    at: u64,
) -> Result<zlint_tx::Review, String> {
    let policy = Policy::load(policy)?;
    let activity = read_json::<Activity>(activity)?;
    activity.validate()?;
    let bytes = std::fs::read(pczt).map_err(|e| format!("{}: {e}", pczt.display()))?;
    zlint_tx::review_pczt(&policy, &activity, &bytes, at)
}

fn run_decide(
    policy: &Path,
    activity: &Path,
    proposal: &Path,
    db: Option<&Path>,
) -> Result<Decision, String> {
    let policy = Policy::load(policy)?;
    let mut activity = read_json::<Activity>(activity)?;
    activity.validate()?;
    let proposal = read_json::<SpendProposal>(proposal)?;
    proposal.validate()?;
    let store = db.map(Store::open).transpose()?;
    if let Some(store) = &store {
        activity.accepted_spends.extend(store.accepted_spends()?);
    }
    let decision = zlint_linter::decide(&policy, &activity, &proposal);
    if let Some(store) = &store {
        let hash = proposal_hash(&proposal)?;
        store.record_decision(&hash, proposal.proposed_at_ms, &decision)?;
        if decision.verdict == Verdict::Accept && !store.has_accepted(&hash)? {
            store.record_accept(&hash, proposal.amount_zatoshis, proposal.proposed_at_ms)?;
        }
    }
    Ok(decision)
}

fn proposal_hash(proposal: &SpendProposal) -> Result<String, String> {
    let bytes = serde_json::to_vec(proposal).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn history_cmd(db: &Path, limit: u32) -> Result<String, String> {
    let store = Store::open(db)?;
    let rows = store.recent_decisions(limit)?;
    if rows.is_empty() {
        return Ok("no decisions\n".into());
    }
    let mut lines = Vec::new();
    for row in rows {
        lines.push(format!(
            "{}  score {:<3}  proposed {}  {}",
            row.verdict, row.score, row.proposed_at_ms, row.proposal_hash
        ));
        if let Ok(flags) = serde_json::from_str::<Vec<zlint_types::Flag>>(&row.flags_json) {
            for flag in flags {
                lines.push(format!("  {}: {}", flag.code.as_str(), flag.explanation));
            }
        }
    }
    lines.push(String::new());
    Ok(lines.join("\n"))
}

fn write_report(path: &Path, json: &str) -> Result<(), String> {
    std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
}

fn summary(decision: &Decision) -> String {
    let verdict = match decision.verdict {
        Verdict::Accept => "accept",
        Verdict::Reject => "reject",
        Verdict::Warn => "warn",
    };
    let mut lines = vec![format!("{verdict}  score {}", decision.score)];
    for failure in &decision.hard_rule_failures {
        lines.push(format!(
            "- {}: {}",
            failure.code.as_str(),
            failure.explanation
        ));
    }
    for flag in &decision.flags {
        lines.push(format!("- {}: {}", flag.code.as_str(), flag.explanation));
    }
    lines.join("\n")
}
