//! Privacy checks and the accept / reject / warn combiner.
//! Checks: timing, round-or-distinctive amount, shield-after-receive,
//! and change / note selection when the proposal carries input and change.

use zlint_policy::{hard_rules, Policy};
use zlint_types::{
    format_gap, format_zec, in_lookback, Activity, Decision, Flag, FlagCode, SpendProposal, Verdict,
};

pub const WEIGHT_TIMING: u8 = 40;
pub const WEIGHT_ROUND: u8 = 15;
pub const WEIGHT_SHIELD: u8 = 35;
pub const WEIGHT_CHANGE: u8 = 25;

pub fn decide(policy: &Policy, activity: &Activity, proposal: &SpendProposal) -> Decision {
    let hard_rule_failures = hard_rules(policy, activity, proposal);
    let flags = flags(policy, activity, proposal);
    let score = score_of(&flags);
    let verdict = verdict(score, policy, !hard_rule_failures.is_empty());
    Decision {
        verdict,
        score,
        flags,
        hard_rule_failures,
    }
}

pub fn verdict(score: u8, policy: &Policy, hard_failed: bool) -> Verdict {
    if hard_failed || score < policy.reject_below {
        Verdict::Reject
    } else if score < policy.warn_below {
        Verdict::Warn
    } else {
        Verdict::Accept
    }
}

fn score_of(flags: &[Flag]) -> u8 {
    let penalty: u16 = flags.iter().map(|f| u16::from(f.weight)).sum();
    100u16.saturating_sub(penalty).min(100) as u8
}

fn flags(policy: &Policy, activity: &Activity, proposal: &SpendProposal) -> Vec<Flag> {
    let mut out = Vec::new();
    if let Some(flag) = timing_flag(policy, activity, proposal) {
        out.push(flag);
    }
    if let Some(flag) = round_flag(policy, activity, proposal) {
        out.push(flag);
    }
    if let Some(flag) = shield_flag(policy, activity, proposal) {
        out.push(flag);
    }
    if let Some(flag) = change_flag(policy, proposal) {
        out.push(flag);
    }
    out
}

fn timing_flag(policy: &Policy, activity: &Activity, proposal: &SpendProposal) -> Option<Flag> {
    let match_note = activity
        .receives
        .iter()
        .filter(|note| {
            in_lookback(
                note.at_ms,
                proposal.proposed_at_ms,
                policy.timing_lookback_ms,
            ) && similar(
                note.amount_zatoshis,
                proposal.amount_zatoshis,
                policy.amount_similarity,
            )
        })
        .min_by_key(|note| proposal.proposed_at_ms - note.at_ms)?;
    let gap = proposal.proposed_at_ms - match_note.at_ms;
    Some(Flag {
        code: FlagCode::TimingCorrelation,
        weight: WEIGHT_TIMING,
        explanation: format!(
            "Spend of {} is {} after a {} receive — timing link risk",
            format_zec(proposal.amount_zatoshis),
            format_gap(gap),
            format_zec(match_note.amount_zatoshis)
        ),
    })
}

fn round_flag(policy: &Policy, activity: &Activity, proposal: &SpendProposal) -> Option<Flag> {
    let round = policy.round_modulus_zatoshis > 0
        && proposal.amount_zatoshis % policy.round_modulus_zatoshis == 0;
    let matched = if policy.flag_exact_recent_amount {
        activity.receives.iter().find(|note| {
            note.amount_zatoshis == proposal.amount_zatoshis
                && in_lookback(
                    note.at_ms,
                    proposal.proposed_at_ms,
                    policy.timing_lookback_ms,
                )
        })
    } else {
        None
    };
    if !round && matched.is_none() {
        return None;
    }
    let explanation = match (round, matched) {
        (true, Some(note)) => format!(
            "{} is a round amount and matches a receive of {}",
            format_zec(proposal.amount_zatoshis),
            format_zec(note.amount_zatoshis)
        ),
        (true, None) => format!(
            "{} is a round amount that stands out",
            format_zec(proposal.amount_zatoshis)
        ),
        (false, Some(note)) => format!(
            "{} matches a receive of {} in the lookback window",
            format_zec(proposal.amount_zatoshis),
            format_zec(note.amount_zatoshis)
        ),
        (false, None) => unreachable!("flag is only built when a reason exists"),
    };
    Some(Flag {
        code: FlagCode::RoundOrDistinctiveAmount,
        weight: WEIGHT_ROUND,
        explanation,
    })
}

fn shield_flag(policy: &Policy, activity: &Activity, proposal: &SpendProposal) -> Option<Flag> {
    let shield = activity
        .shields
        .iter()
        .filter(|shield| {
            in_lookback(
                shield.at_ms,
                proposal.proposed_at_ms,
                policy.shield_lookback_ms,
            )
        })
        .min_by_key(|shield| proposal.proposed_at_ms - shield.at_ms)?;
    let gap = proposal.proposed_at_ms - shield.at_ms;
    Some(Flag {
        code: FlagCode::ShieldAfterReceive,
        weight: WEIGHT_SHIELD,
        explanation: format!(
            "Shielded {} {} ago, now spending — turnstile linkage risk",
            format_zec(shield.amount_zatoshis),
            format_gap(gap)
        ),
    })
}

/// Fires only when both input and change are present and change/input is at least
/// `change_fraction`. A missing amount skips the check rather than guessing.
fn change_flag(policy: &Policy, proposal: &SpendProposal) -> Option<Flag> {
    let (input, change) = match (proposal.input_zatoshis, proposal.change_zatoshis) {
        (Some(input), Some(change)) if input > 0 => (input, change),
        _ => return None,
    };
    if !fraction_at_least(change, input, policy.change_fraction) {
        return None;
    }
    let pct = u128::from(change) * 100 / u128::from(input);
    Some(Flag {
        code: FlagCode::ChangeNoteSelection,
        weight: WEIGHT_CHANGE,
        explanation: format!(
            "Change of {} is {pct}% of the {} input — distinctive note selection",
            format_zec(change),
            format_zec(input)
        ),
    })
}

/// `|receive - spend| / spend <= similarity`, compared in integers.
/// A similarity of 0.20 uses a scale of 1_000_000 so 0.20 is exact.
fn similar(receive: u64, spend: u64, similarity: f64) -> bool {
    if spend == 0 {
        return false;
    }
    let scale: u128 = 1_000_000;
    let sim = (similarity * scale as f64).round() as u128;
    let diff = u128::from(receive.abs_diff(spend));
    diff * scale <= u128::from(spend) * sim
}

fn fraction_at_least(part: u64, whole: u64, fraction: f64) -> bool {
    if whole == 0 {
        return false;
    }
    let scale: u128 = 1_000_000;
    let scaled = (fraction * scale as f64).round() as u128;
    u128::from(part) * scale >= u128::from(whole) * scaled
}

#[cfg(test)]
mod tests {
    use super::*;
    use zlint_types::{Pool, Receive, Shield};

    fn policy() -> Policy {
        Policy {
            daily_cap_zatoshis: 200_000_000,
            max_tx_zatoshis: 50_000_000,
            allowlist: vec![],
            max_spends_per_hour: 5,
            reject_below: 60,
            warn_below: 75,
            timing_lookback_ms: 600_000,
            amount_similarity: 0.20,
            round_modulus_zatoshis: 1_000_000,
            flag_exact_recent_amount: true,
            shield_lookback_ms: 600_000,
            change_fraction: 0.95,
        }
    }

    fn bare(amount: u64, at: u64) -> SpendProposal {
        SpendProposal {
            destination: "u1test".into(),
            amount_zatoshis: amount,
            proposed_at_ms: at,
            memo: None,
            input_zatoshis: None,
            change_zatoshis: None,
        }
    }

    fn empty() -> Activity {
        Activity {
            receives: vec![],
            shields: vec![],
            accepted_spends: vec![],
        }
    }

    fn receive(amount: u64, at: u64) -> Activity {
        Activity {
            receives: vec![Receive {
                amount_zatoshis: amount,
                at_ms: at,
                pool: Some(Pool::Orchard),
            }],
            shields: vec![],
            accepted_spends: vec![],
        }
    }

    #[test]
    fn score_table() {
        let policy = policy();
        let at = 10_000_000u64;

        // Timing only: odd amount, similar receive, inside the window. 100 - 40 = 60.
        let timing_only = decide(
            &policy,
            &receive(12_100_000, at - 60_000),
            &bare(10_100_000, at),
        );
        assert_eq!(timing_only.score, 60);
        assert_eq!(timing_only.flags.len(), 1);
        assert_eq!(timing_only.flags[0].code, FlagCode::TimingCorrelation);
        assert_eq!(timing_only.verdict, Verdict::Warn);

        // Round only. 100 - 15 = 85. Product warn-below is 75, so this accepts.
        let round_only = decide(&policy, &empty(), &bare(10_000_000, at));
        assert_eq!(round_only.score, 85);
        assert_eq!(round_only.flags[0].code, FlagCode::RoundOrDistinctiveAmount);
        assert_eq!(round_only.verdict, Verdict::Accept);

        // Shield only. 100 - 35 = 65. Warn under product defaults.
        let mut shielded = empty();
        shielded.shields.push(Shield {
            amount_zatoshis: 20_000_000,
            at_ms: at - 120_000,
        });
        let shield_only = decide(&policy, &shielded, &bare(13_700_000, at));
        assert_eq!(shield_only.score, 65);
        assert_eq!(shield_only.flags[0].code, FlagCode::ShieldAfterReceive);
        assert_eq!(shield_only.verdict, Verdict::Warn);

        // Timing plus round. 100 - 40 - 15 = 45.
        let timing_round = decide(
            &policy,
            &receive(50_000_000, at - 240_000),
            &bare(50_000_000, at),
        );
        assert_eq!(timing_round.score, 45);
        assert_eq!(timing_round.verdict, Verdict::Reject);

        // Timing plus shield. Odd similar amount so the round check stays quiet. 100 - 40 - 35 = 25.
        let mut both = receive(12_100_000, at - 60_000);
        both.shields.push(Shield {
            amount_zatoshis: 3_000_001,
            at_ms: at - 60_000,
        });
        let timing_shield = decide(&policy, &both, &bare(10_100_000, at));
        assert_eq!(timing_shield.score, 25);
        assert_eq!(timing_shield.verdict, Verdict::Reject);
        assert!(timing_shield
            .flags
            .iter()
            .all(|f| !f.explanation.is_empty()));
    }

    #[test]
    fn demo_threshold_rejects_timing_only_and_shield_only() {
        let mut policy = policy();
        policy.reject_below = 70;
        policy.warn_below = 85;
        let at = 10_000_000u64;
        let timing = decide(
            &policy,
            &receive(12_100_000, at - 60_000),
            &bare(10_100_000, at),
        );
        assert_eq!(timing.score, 60);
        assert_eq!(timing.verdict, Verdict::Reject);

        let mut shielded = empty();
        shielded.shields.push(Shield {
            amount_zatoshis: 20_000_000,
            at_ms: at - 120_000,
        });
        let shield = decide(&policy, &shielded, &bare(13_700_000, at));
        assert_eq!(shield.score, 65);
        assert_eq!(shield.verdict, Verdict::Reject);
    }

    #[test]
    fn change_check_fires_only_when_both_amounts_are_present() {
        let policy = policy();
        let at = 10_000_000u64;
        let mut proposal = bare(13_700_000, at);
        proposal.input_zatoshis = Some(100);
        proposal.change_zatoshis = Some(95);
        let on_edge = decide(&policy, &empty(), &proposal);
        assert_eq!(on_edge.score, 75);
        assert_eq!(on_edge.flags[0].code, FlagCode::ChangeNoteSelection);
        assert_eq!(on_edge.flags[0].weight, 25);
        assert_eq!(on_edge.verdict, Verdict::Accept);

        proposal.change_zatoshis = Some(94);
        let under = decide(&policy, &empty(), &proposal);
        assert!(under.flags.is_empty());
        assert_eq!(under.score, 100);

        proposal.change_zatoshis = Some(95);
        proposal.input_zatoshis = None;
        assert!(decide(&policy, &empty(), &proposal).flags.is_empty());

        let mut demo = policy;
        demo.reject_below = 70;
        demo.warn_below = 85;
        proposal.input_zatoshis = Some(100);
        proposal.change_zatoshis = Some(95);
        let warned = decide(&demo, &empty(), &proposal);
        assert_eq!(warned.score, 75);
        assert_eq!(warned.verdict, Verdict::Warn);
    }

    #[test]
    fn similarity_band_is_inclusive_at_20_percent() {
        assert!(similar(120, 100, 0.20));
        assert!(!similar(121, 100, 0.20));
    }

    #[test]
    fn exact_amount_outside_lookback_does_not_flag_when_not_round() {
        let policy = policy();
        let at = 10_000_000u64;
        let decision = decide(
            &policy,
            &receive(10_100_000, at - 600_001),
            &bare(10_100_000, at),
        );
        assert!(decision.flags.is_empty());
        assert_eq!(decision.score, 100);
    }
}
