mod frost_round;
mod frost_serve;
mod mcp;
mod serve;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zlint_policy::Policy;
use zlint_signer::{
    contribute, create_frost_shares, create_share, proposal_hash, require_simulated_share,
    CosignReport, SimulatedSigner,
};
use zlint_store::Store;
use zlint_types::{Activity, Decision, SpendProposal, Verdict};

#[derive(Parser)]
#[command(
    name = "zlint",
    about = "Check a shielded ZEC spend against limits and privacy rules."
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
    /// Speak MCP on stdin/stdout. The tools are `propose_spend` and `review_pczt`. Does not sign.
    Mcp,
    /// Contribute a simulated share when the check accepts.
    /// The share is not a Zcash signature. A warning contributes nothing until `confirm`.
    Cosign {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        activity: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
        /// Decision log. An accept is counted only when a share is contributed.
        #[arg(long)]
        db: PathBuf,
        /// Simulated share file. Mode must be 0600. This is not a Zcash key.
        #[arg(long)]
        share: PathBuf,
        /// Also write the cosign JSON to this file.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Confirm a warning from this machine.
    /// A simulated share contributes a dummy share. A FROST share records the confirmation and does not sign here.
    Confirm {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        activity: PathBuf,
        /// JSON proposal. Required for a simulated share.
        #[arg(long)]
        proposal: Option<PathBuf>,
        #[arg(long)]
        db: PathBuf,
        /// Share file. Mode must be 0600.
        #[arg(long)]
        share: PathBuf,
        /// PCZT bytes. Required for a FROST share, refused for a simulated share.
        #[arg(long)]
        pczt: Option<PathBuf>,
        /// When the spend is being proposed, in Unix milliseconds. Required with `--pczt`.
        #[arg(long)]
        at: Option<u64>,
        /// Also write the cosign JSON to this file.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Write a simulated share file for this co-signer. This is not a Zcash key.
    Share {
        #[command(subcommand)]
        command: ShareCommand,
    },
    /// Trusted-dealer RedPallas 2-of-2 key. This process sees both shares.
    Frost {
        #[command(subcommand)]
        command: FrostCommand,
    },
    /// Listen on a Unix socket. The agent sends a proposal. The share file stays here.
    Serve {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        activity: PathBuf,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        share: PathBuf,
    },
    /// Send a proposal to `zlint serve`. Does not open a share file.
    Propose {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
    },
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

#[derive(Subcommand)]
enum ShareCommand {
    /// Create a new share file. Refuses to replace one that already exists.
    Init {
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum FrostCommand {
    /// Write share 1 and share 2. Does not broadcast.
    Keygen {
        /// Share 1, for the agent. Mode 0600.
        #[arg(long)]
        share1: PathBuf,
        /// Share 2, for this co-signer. Mode 0600.
        #[arg(long)]
        share2: PathBuf,
    },
    /// Speak MCP for a PCZT signing round. The tool is `cosign_pczt`. Confirm is not a tool.
    Mcp {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        activity: PathBuf,
        #[arg(long)]
        db: PathBuf,
        /// FROST share 2. Mode must be 0600.
        #[arg(long)]
        share: PathBuf,
        /// Nonce file for share 2. Mode 0600. Deleted before a signature share is written.
        #[arg(long)]
        nonce: PathBuf,
    },
    /// Listen for a PCZT signing round. Share 2 and the nonce stay here.
    Serve {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        activity: PathBuf,
        #[arg(long)]
        db: PathBuf,
        /// FROST share 2. Mode must be 0600.
        #[arg(long)]
        share: PathBuf,
        /// Nonce file for share 2. Mode 0600. Deleted before a signature share is written.
        #[arg(long)]
        nonce: PathBuf,
    },
    /// Write share 1's round-1 commitment. Prints the public commitment.
    Prepare {
        /// FROST share 1. Mode must be 0600.
        #[arg(long)]
        share: PathBuf,
        #[arg(long)]
        nonce: PathBuf,
        #[arg(long)]
        pczt: PathBuf,
    },
    /// Ask the co-signer for its round-1 commitment.
    Commit {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        pczt: PathBuf,
        /// When the spend is being proposed, in Unix milliseconds.
        #[arg(long)]
        at: u64,
    },
    /// Ask the co-signer for its signature share.
    Sign {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        pczt: PathBuf,
        #[arg(long)]
        at: u64,
        /// The other signer's public commitment.
        #[arg(long)]
        commitment: PathBuf,
    },
    /// Write share 1's signature share and delete its nonce file.
    Contribute {
        /// FROST share 1. Mode must be 0600.
        #[arg(long)]
        share: PathBuf,
        #[arg(long)]
        nonce: PathBuf,
        #[arg(long)]
        pczt: PathBuf,
        /// The co-signer's public commitment.
        #[arg(long)]
        theirs: PathBuf,
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
        Command::Cosign {
            policy,
            activity,
            proposal,
            db,
            share,
            report,
        } => match run_cosign(&policy, &activity, &proposal, &db, &share) {
            Ok(report_body) => finish_cosign(&report_body, report.as_deref()),
            Err(err) => fail(err),
        },
        Command::Confirm {
            policy,
            activity,
            proposal,
            db,
            share,
            pczt,
            at,
            report,
        } => match run_confirm(
            &policy,
            &activity,
            proposal.as_deref(),
            &db,
            &share,
            pczt.as_deref(),
            at,
        ) {
            Ok(ConfirmOutcome::Simulated(report_body)) => {
                finish_cosign(&report_body, report.as_deref())
            }
            Ok(ConfirmOutcome::Frost { decision }) => {
                finish_frost_confirm(&decision, report.as_deref())
            }
            Err(err) => fail(err),
        },
        Command::Share {
            command: ShareCommand::Init { path },
        } => match create_share(&path) {
            Ok(()) => {
                eprintln!(
                    "wrote {}. simulated share file. this is not a Zcash key.",
                    path.display()
                );
                ExitCode::SUCCESS
            }
            Err(err) => fail(err),
        },
        Command::Frost { command } => run_frost(command),
        Command::Serve {
            socket,
            policy,
            activity,
            db,
            share,
        } => match serve::listen(&socket, &policy, &activity, &db, &share) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => fail(err),
        },
        Command::Propose { socket, proposal } => match serve::propose(&socket, &proposal) {
            Ok(report_body) => finish_cosign(&report_body, None),
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

fn run_frost(command: FrostCommand) -> ExitCode {
    match command {
        FrostCommand::Keygen { share1, share2 } => match create_frost_shares(&share1, &share2) {
            Ok(()) => {
                eprintln!(
                    "this process saw both shares. share 1 is for the agent. share 2 stays on this machine. this is a trusted dealer, not distributed key generation. this does not broadcast."
                );
                eprintln!("wrote {}", share1.display());
                eprintln!("wrote {}", share2.display());
                ExitCode::SUCCESS
            }
            Err(err) => fail(err),
        },
        FrostCommand::Mcp {
            policy,
            activity,
            db,
            share,
            nonce,
        } => match mcp::serve_enforce(&policy, &activity, &db, &share, &nonce) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => fail(err),
        },
        FrostCommand::Serve {
            socket,
            policy,
            activity,
            db,
            share,
            nonce,
        } => match frost_serve::listen(&socket, &policy, &activity, &db, &share, &nonce) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => fail(err),
        },
        FrostCommand::Prepare { share, nonce, pczt } => {
            match frost_round::prepare(&share, &nonce, &pczt) {
                Ok(public) => {
                    eprintln!("commitment is ready. the nonce file stays on this machine.");
                    print_json(&public)
                }
                Err(err) => fail(err),
            }
        }
        FrostCommand::Commit { socket, pczt, at } => {
            match frost_serve::commit(&socket, &pczt, at) {
                Ok(value) => {
                    eprintln!("received a co-signer response.");
                    print_json(&value)
                }
                Err(err) => fail(err),
            }
        }
        FrostCommand::Sign {
            socket,
            pczt,
            at,
            commitment,
        } => match frost_serve::sign(&socket, &pczt, at, &commitment) {
            Ok(value) => {
                eprintln!("received a co-signer response.");
                print_json(&value)
            }
            Err(err) => fail(err),
        },
        FrostCommand::Contribute {
            share,
            nonce,
            pczt,
            theirs,
        } => match frost_round::contribute(&share, &nonce, &pczt, &theirs) {
            Ok(signature) => {
                eprintln!("wrote a signature share. the nonce file was deleted.");
                print_json(&signature)
            }
            Err(err) => fail(err),
        },
    }
}

fn print_json(value: &impl serde::Serialize) -> ExitCode {
    match serde_json::to_string_pretty(value) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => fail(err.to_string()),
    }
}

fn finish_frost_confirm(decision: &Decision, report: Option<&Path>) -> ExitCode {
    let body = serde_json::json!({
        "decision": decision,
        "signature_share": null,
        "confirmed": true,
    });
    let json = serde_json::to_string_pretty(&body).unwrap();
    if let Some(path) = report {
        if let Err(err) = write_report(path, &json) {
            return fail(err);
        }
    }
    eprintln!("{}", summary(decision));
    eprintln!("confirmed. no signature share was written.");
    println!("{json}");
    ExitCode::SUCCESS
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

fn finish_cosign(report: &CosignReport, path: Option<&Path>) -> ExitCode {
    let json = serde_json::to_string_pretty(report).unwrap();
    if let Some(path) = path {
        if let Err(err) = write_report(path, &json) {
            return fail(err);
        }
    }
    eprintln!("{}", summary(&report.decision));
    eprintln!("{}", share_status(report));
    println!("{json}");
    ExitCode::SUCCESS
}

pub(crate) fn share_status(report: &CosignReport) -> String {
    if report.already_signed {
        return "already signed. no second share contributed.".into();
    }
    if let Some(share) = &report.signature_share {
        return share.statement.clone();
    }
    if report.awaiting_confirmation {
        return "no share contributed. confirm this warning with `zlint confirm`.".into();
    }
    "no share contributed.".into()
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
    let store = db.map(Store::open).transpose()?;
    let (policy, activity, proposal) = prepare(policy, activity, proposal, store.as_ref())?;
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

fn run_cosign(
    policy: &Path,
    activity: &Path,
    proposal_path: &Path,
    db: &Path,
    share: &Path,
) -> Result<CosignReport, String> {
    let proposal = read_json::<SpendProposal>(proposal_path)?;
    cosign_loaded(policy, activity, proposal, db, share)
}

pub(crate) fn cosign_loaded(
    policy: &Path,
    activity: &Path,
    proposal: SpendProposal,
    db: &Path,
    share: &Path,
) -> Result<CosignReport, String> {
    require_simulated_share(share)?;
    proposal.validate()?;
    let store = Store::open(db)?;
    let policy = Policy::load(policy)?;
    let mut activity = read_json::<Activity>(activity)?;
    activity.validate()?;
    activity.accepted_spends.extend(store.accepted_spends()?);
    let decision = zlint_linter::decide(&policy, &activity, &proposal);
    let hash = proposal_hash(&proposal)?;
    store.record_decision(&hash, proposal.proposed_at_ms, &decision)?;
    if store.has_accepted(&hash)? {
        return Ok(CosignReport {
            decision,
            signature_share: None,
            awaiting_confirmation: false,
            already_signed: true,
        });
    }
    apply_contribution(&store, &proposal, &hash, &decision, false)
}

enum ConfirmOutcome {
    Simulated(CosignReport),
    Frost { decision: Decision },
}

fn run_confirm(
    policy: &Path,
    activity: &Path,
    proposal_path: Option<&Path>,
    db: &Path,
    share: &Path,
    pczt: Option<&Path>,
    at: Option<u64>,
) -> Result<ConfirmOutcome, String> {
    match zlint_signer::require_share(share)? {
        zlint_signer::ShareKind::Simulated => {
            if pczt.is_some() || at.is_some() {
                return Err("a simulated share does not sign a transaction".into());
            }
            let Some(proposal_path) = proposal_path else {
                return Err("a proposal is required".into());
            };
            Ok(ConfirmOutcome::Simulated(confirm_simulated(
                policy,
                activity,
                proposal_path,
                db,
                share,
            )?))
        }
        zlint_signer::ShareKind::Frost => {
            if proposal_path.is_some() || pczt.is_none() || at.is_none() {
                return Err(
                    "this share signs a PCZT sighash. confirm it with --pczt and --at".into(),
                );
            }
            let decision = frost_round::confirm_warning(
                policy,
                activity,
                db,
                share,
                pczt.expect("pczt"),
                at.expect("at"),
            )?;
            Ok(ConfirmOutcome::Frost { decision })
        }
    }
}

fn confirm_simulated(
    policy: &Path,
    activity: &Path,
    proposal_path: &Path,
    db: &Path,
    share: &Path,
) -> Result<CosignReport, String> {
    require_simulated_share(share)?;
    let store = Store::open(db)?;
    let (policy, activity, proposal) = prepare(policy, activity, proposal_path, Some(&store))?;
    let hash = proposal_hash(&proposal)?;
    if store.has_accepted(&hash)? {
        store.remove_pending(&hash)?;
        return Err("this proposal was already signed".into());
    }
    let Some(pending) = store.pending(&hash)? else {
        return Err("no warning is waiting for confirmation".into());
    };
    if pending.amount_zatoshis != proposal.amount_zatoshis
        || pending.proposed_at_ms != proposal.proposed_at_ms
    {
        return Err("pending warning does not match this proposal".into());
    }
    let decision = zlint_linter::decide(&policy, &activity, &proposal);
    apply_contribution(&store, &proposal, &hash, &decision, true)
}

fn apply_contribution(
    store: &Store,
    proposal: &SpendProposal,
    hash: &str,
    decision: &Decision,
    confirmed: bool,
) -> Result<CosignReport, String> {
    let contribution = contribute(decision.verdict, confirmed, &SimulatedSigner, hash);
    if let Some(share) = contribution.share {
        store.record_accept(hash, proposal.amount_zatoshis, proposal.proposed_at_ms)?;
        store.remove_pending(hash)?;
        return Ok(CosignReport {
            decision: decision.clone(),
            signature_share: Some(share),
            awaiting_confirmation: false,
            already_signed: false,
        });
    }
    if contribution.awaiting_confirmation {
        store.record_pending(hash, proposal.amount_zatoshis, proposal.proposed_at_ms)?;
    } else if confirmed {
        return Err(format!(
            "confirmation refused because the check rejects this spend\n{}",
            summary(decision)
        ));
    } else {
        store.remove_pending(hash)?;
    }
    Ok(CosignReport {
        decision: decision.clone(),
        signature_share: None,
        awaiting_confirmation: contribution.awaiting_confirmation,
        already_signed: false,
    })
}

fn prepare(
    policy: &Path,
    activity: &Path,
    proposal: &Path,
    store: Option<&Store>,
) -> Result<(Policy, Activity, SpendProposal), String> {
    let policy = Policy::load(policy)?;
    let mut activity = read_json::<Activity>(activity)?;
    activity.validate()?;
    let proposal = read_json::<SpendProposal>(proposal)?;
    proposal.validate()?;
    if let Some(store) = store {
        activity.accepted_spends.extend(store.accepted_spends()?);
    }
    Ok((policy, activity, proposal))
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

pub(crate) fn summary(decision: &Decision) -> String {
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
