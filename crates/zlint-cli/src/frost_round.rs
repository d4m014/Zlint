//! One PCZT signing round.
//! The check runs on the transaction bytes. A warning contributes nothing until
//! `zlint confirm` on this machine. The nonce file is deleted before the share is produced.

use std::path::Path;
use zlint_policy::Policy;
use zlint_signer::{
    commit, discard_matching_round, load_frost_share, sign_with_round1, store_round1,
    LoadedFrostShare, PublicCommit,
};
use zlint_store::Store;
use zlint_tx::{OrchardSighash, Review};
use zlint_types::{Activity, Decision, Verdict};

use crate::summary;

pub enum CommitOutcome {
    Commitment {
        decision: Decision,
        public: PublicCommit,
    },
    Awaiting(Decision),
    AlreadySigned(Decision),
    Refused(Decision),
}

pub enum SignOutcome {
    Share {
        decision: Decision,
        signature: zlint_signer::FrostSignatureShare,
    },
    AlreadySigned(Decision),
    Awaiting(Decision),
    Refused(Decision),
}

struct Checked {
    sighash: [u8; 32],
    hash: String,
    alpha: [u8; 32],
    action_index: u32,
    at: u64,
    review: Review,
}

pub fn prepare(share: &Path, nonce: &Path, pczt: &Path) -> Result<PublicCommit, String> {
    let loaded = load_share(share, "share1")?;
    let bytes = read_pczt(pczt)?;
    let parsed = zlint_tx::orchard_sighash(&bytes)?;
    let (alpha, action_index) = match_action(&loaded, &parsed)?;
    let round = commit(&loaded.key);
    store_round1(nonce, round, parsed.sighash, alpha, action_index)
}

pub fn contribute(
    share: &Path,
    nonce: &Path,
    pczt: &Path,
    theirs: &Path,
) -> Result<zlint_signer::FrostSignatureShare, String> {
    let loaded = load_share(share, "share1")?;
    let bytes = read_pczt(pczt)?;
    let parsed = zlint_tx::orchard_sighash(&bytes)?;
    let (alpha, action_index) = match_action(&loaded, &parsed)?;
    let theirs = read_commit(theirs)?;
    sign_with_round1(
        nonce,
        &loaded.key,
        &loaded.group,
        &theirs,
        &parsed.sighash,
        &alpha,
        action_index,
    )
}

pub fn server_commit(
    policy: &Path,
    activity: &Path,
    db: &Path,
    share: &Path,
    nonce: &Path,
    pczt: &[u8],
    at: u64,
) -> Result<CommitOutcome, String> {
    let loaded = load_share(share, "share2")?;
    let store = Store::open(db)?;
    let checked = check(policy, activity, &store, &loaded, pczt, at)?;
    store.record_decision(&checked.hash, at, &checked.review.decision)?;
    if store.has_accepted(&checked.hash)? {
        discard_matching_round(nonce, &checked.sighash)?;
        return Ok(CommitOutcome::AlreadySigned(checked.review.decision));
    }
    if !may_contribute(&store, &checked)? {
        discard_matching_round(nonce, &checked.sighash)?;
        return held_back(&store, &checked);
    }
    let round = commit(&loaded.key);
    let public = store_round1(
        nonce,
        round,
        checked.sighash,
        checked.alpha,
        checked.action_index,
    )?;
    Ok(CommitOutcome::Commitment {
        decision: checked.review.decision,
        public,
    })
}

pub fn server_sign(
    policy: &Path,
    activity: &Path,
    db: &Path,
    share: &Path,
    nonce: &Path,
    pczt: &[u8],
    at: u64,
    theirs: &PublicCommit,
) -> Result<SignOutcome, String> {
    let loaded = load_share(share, "share2")?;
    let store = Store::open(db)?;
    let checked = check(policy, activity, &store, &loaded, pczt, at)?;
    store.record_decision(&checked.hash, at, &checked.review.decision)?;
    if store.has_accepted(&checked.hash)? {
        discard_matching_round(nonce, &checked.sighash)?;
        return Ok(SignOutcome::AlreadySigned(checked.review.decision));
    }
    if !may_contribute(&store, &checked)? {
        discard_matching_round(nonce, &checked.sighash)?;
        return match held_back(&store, &checked)? {
            CommitOutcome::Awaiting(decision) => Ok(SignOutcome::Awaiting(decision)),
            CommitOutcome::AlreadySigned(decision) => Ok(SignOutcome::AlreadySigned(decision)),
            CommitOutcome::Refused(decision) => Ok(SignOutcome::Refused(decision)),
            CommitOutcome::Commitment { .. } => Err("no share contributed".into()),
        };
    }
    let signature = sign_with_round1(
        nonce,
        &loaded.key,
        &loaded.group,
        theirs,
        &checked.sighash,
        &checked.alpha,
        checked.action_index,
    )?;
    let decision = checked.review.decision.clone();
    store.record_accept(&checked.hash, checked.review.payment.amount_zatoshis, at)?;
    store.remove_pending(&checked.hash)?;
    store.remove_confirmed(&checked.hash)?;
    Ok(SignOutcome::Share {
        decision,
        signature,
    })
}

pub fn confirm_warning(
    policy: &Path,
    activity: &Path,
    db: &Path,
    share: &Path,
    pczt: &Path,
    at: u64,
) -> Result<Decision, String> {
    let loaded = load_share(share, "share2")?;
    let bytes = read_pczt(pczt)?;
    let store = Store::open(db)?;
    let checked = check(policy, activity, &store, &loaded, &bytes, at)?;
    if store.has_accepted(&checked.hash)? {
        store.remove_pending(&checked.hash)?;
        return Err("this transaction was already signed".into());
    }
    let Some(pending) = store.pending(&checked.hash)? else {
        return Err("no warning is waiting for confirmation".into());
    };
    let amount = checked.review.payment.amount_zatoshis;
    if pending.amount_zatoshis != amount || pending.proposed_at_ms != at {
        return Err("pending warning does not match this transaction".into());
    }
    match checked.review.decision.verdict {
        Verdict::Warn => {}
        Verdict::Reject => {
            return Err(format!(
                "confirmation refused because the check rejects this spend\n{}",
                summary(&checked.review.decision)
            ));
        }
        Verdict::Accept => return Err("this spend is not a warning".into()),
    }
    store.record_confirmed(&checked.hash, amount, at)?;
    Ok(checked.review.decision)
}

fn held_back(store: &Store, checked: &Checked) -> Result<CommitOutcome, String> {
    match checked.review.decision.verdict {
        Verdict::Warn => {
            store.record_pending(
                &checked.hash,
                checked.review.payment.amount_zatoshis,
                checked.at,
            )?;
            Ok(CommitOutcome::Awaiting(checked.review.decision.clone()))
        }
        Verdict::Reject => {
            store.remove_pending(&checked.hash)?;
            store.remove_confirmed(&checked.hash)?;
            Ok(CommitOutcome::Refused(checked.review.decision.clone()))
        }
        Verdict::Accept => Err("no share contributed".into()),
    }
}

fn may_contribute(store: &Store, checked: &Checked) -> Result<bool, String> {
    match checked.review.decision.verdict {
        Verdict::Accept => Ok(true),
        Verdict::Reject => Ok(false),
        Verdict::Warn => {
            let Some(confirmed) = store.confirmed(&checked.hash)? else {
                return Ok(false);
            };
            Ok(
                confirmed.amount_zatoshis == checked.review.payment.amount_zatoshis
                    && confirmed.proposed_at_ms == checked.at,
            )
        }
    }
}

pub(crate) fn awaiting_message(decision: &Decision) -> String {
    format!(
        "no share contributed. confirm this warning with `zlint confirm`.\n{}",
        summary(decision)
    )
}

fn check(
    policy: &Path,
    activity: &Path,
    store: &Store,
    share: &LoadedFrostShare,
    pczt: &[u8],
    at: u64,
) -> Result<Checked, String> {
    let policy = Policy::load(policy)?;
    let mut activity = read_activity(activity)?;
    activity.accepted_spends.extend(store.accepted_spends()?);
    let review = zlint_tx::review_pczt(&policy, &activity, pczt, at)?;
    let parsed = zlint_tx::orchard_sighash(pczt)?;
    let (alpha, action_index) = match_action(share, &parsed)?;
    Ok(Checked {
        hash: hex::encode(parsed.sighash),
        sighash: parsed.sighash,
        alpha,
        action_index,
        at,
        review,
    })
}

fn match_action(
    share: &LoadedFrostShare,
    parsed: &OrchardSighash,
) -> Result<([u8; 32], u32), String> {
    let group_key = zlint_signer::group_verifying_key(&share.group)?;
    let mut matched = Vec::new();
    for action in &parsed.actions {
        let rk = zlint_signer::randomize_verifying_key(group_key, &action.alpha)?;
        if rk == action.rk {
            matched.push(action);
        }
    }
    let action = match matched.len() {
        0 => return Err("this transaction does not spend this key".into()),
        1 => matched[0],
        _ => return Err("more than one action spends this key".into()),
    };
    let action_index =
        u32::try_from(action.index).map_err(|_| "action index does not fit".to_string())?;
    Ok((action.alpha, action_index))
}

fn load_share(path: &Path, role: &str) -> Result<LoadedFrostShare, String> {
    let loaded = load_frost_share(path)?;
    if loaded.role != role {
        let label = if role == "share1" {
            "share 1"
        } else {
            "share 2"
        };
        return Err(format!("{} is not {label}", path.display()));
    }
    Ok(loaded)
}

fn read_pczt(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_activity(path: &Path) -> Result<Activity, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let activity: Activity =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    activity.validate()?;
    Ok(activity)
}

pub fn read_commit(path: &Path) -> Result<PublicCommit, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|_| "commitment was not understood".to_string())
}
