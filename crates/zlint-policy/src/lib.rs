//! YAML policy load and hard rules.
//! Milestone 1: max transaction size and daily cap.
//! Milestone 2: address allowlist and hourly rate limit.

use serde::Deserialize;
use std::fs;
use std::path::Path;
use zlint_types::{
    format_zec, in_lookback, Activity, HardRuleCode, HardRuleFailure, SpendProposal, DAY_MS,
    HOUR_MS,
};

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub daily_cap_zatoshis: u64,
    pub max_tx_zatoshis: u64,
    pub allowlist: Vec<String>,
    pub max_spends_per_hour: u32,
    pub reject_below: u8,
    pub warn_below: u8,
    pub timing_lookback_ms: u64,
    pub amount_similarity: f64,
    pub round_modulus_zatoshis: u64,
    pub flag_exact_recent_amount: bool,
    pub shield_lookback_ms: u64,
    pub change_fraction: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    limits: LimitsFile,
    privacy: PrivacyFile,
    linter: LinterFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    daily_cap_zatoshis: u64,
    max_tx_zatoshis: u64,
    #[serde(default)]
    allowlist: Vec<String>,
    max_spends_per_hour: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyFile {
    reject_below: u8,
    warn_below: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinterFile {
    timing_lookback_ms: u64,
    amount_similarity: f64,
    round_modulus_zatoshis: u64,
    flag_exact_recent_amount: bool,
    shield_lookback_ms: u64,
    change_fraction: f64,
}

impl Policy {
    pub fn from_yaml_str(text: &str) -> Result<Self, String> {
        let file: PolicyFile = serde_yaml::from_str(text).map_err(|e| e.to_string())?;
        if file.version != 1 {
            return Err(format!("unsupported policy version {}", file.version));
        }
        if file.limits.daily_cap_zatoshis == 0 || file.limits.max_tx_zatoshis == 0 {
            return Err("caps must be at least 1 zatoshi".into());
        }
        if file.privacy.reject_below > file.privacy.warn_below {
            return Err("reject_below cannot be greater than warn_below".into());
        }
        if !(0.0..=1.0).contains(&file.linter.amount_similarity) {
            return Err("amount_similarity must be between 0 and 1".into());
        }
        if !(0.0..=1.0).contains(&file.linter.change_fraction) {
            return Err("change_fraction must be between 0 and 1".into());
        }
        Ok(Policy {
            daily_cap_zatoshis: file.limits.daily_cap_zatoshis,
            max_tx_zatoshis: file.limits.max_tx_zatoshis,
            allowlist: file.limits.allowlist,
            max_spends_per_hour: file.limits.max_spends_per_hour,
            reject_below: file.privacy.reject_below,
            warn_below: file.privacy.warn_below,
            timing_lookback_ms: file.linter.timing_lookback_ms,
            amount_similarity: file.linter.amount_similarity,
            round_modulus_zatoshis: file.linter.round_modulus_zatoshis,
            flag_exact_recent_amount: file.linter.flag_exact_recent_amount,
            shield_lookback_ms: file.linter.shield_lookback_ms,
            change_fraction: file.linter.change_fraction,
        })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml_str(&text)
    }

    /// Lines the demo script shows before any spend.
    pub fn show(&self) -> String {
        format!(
            "daily cap: {}\nmax tx: {}\nreject below: {}\nwarn below: {}\n",
            format_zec(self.daily_cap_zatoshis),
            format_zec(self.max_tx_zatoshis),
            self.reject_below,
            self.warn_below,
        )
    }
}

/// Every failing hard rule, in order: max tx, daily cap, allowlist, rate limit.
/// A spend that lands on the cap is allowed. One zatoshi over is not.
/// Accepted spends count only inside the window ending at the proposal,
/// including a spend exactly on the window edge. Later spends do not count.
/// An empty allowlist allows any destination. A non-empty list is an exact match.
/// The rate limit counts prior accepts in the rolling hour. The new spend is
/// rejected when that count is already at the maximum.
pub fn hard_rules(
    policy: &Policy,
    activity: &Activity,
    proposal: &SpendProposal,
) -> Vec<HardRuleFailure> {
    let mut failures = Vec::new();
    if proposal.amount_zatoshis > policy.max_tx_zatoshis {
        failures.push(HardRuleFailure {
            code: HardRuleCode::MaxTx,
            explanation: format!(
                "Transaction is {}, above the {} maximum.",
                format_zec(proposal.amount_zatoshis),
                format_zec(policy.max_tx_zatoshis)
            ),
        });
    }

    let mut prior: u128 = 0;
    for spend in &activity.accepted_spends {
        if in_lookback(spend.at_ms, proposal.proposed_at_ms, DAY_MS) {
            prior += u128::from(spend.amount_zatoshis);
        }
    }
    let total = prior + u128::from(proposal.amount_zatoshis);
    if total > u128::from(policy.daily_cap_zatoshis) {
        failures.push(HardRuleFailure {
            code: HardRuleCode::DailyCap,
            explanation: format!(
                "Daily cap exceeded: {} already accepted plus {} is {}, cap is {}.",
                format_zec(prior.min(u128::from(u64::MAX)) as u64),
                format_zec(proposal.amount_zatoshis),
                format_zec_u128(total),
                format_zec(policy.daily_cap_zatoshis)
            ),
        });
    }

    if !policy.allowlist.is_empty()
        && !policy
            .allowlist
            .iter()
            .any(|allowed| allowed == &proposal.destination)
    {
        failures.push(HardRuleFailure {
            code: HardRuleCode::Allowlist,
            explanation: "Destination is not on the allowlist.".into(),
        });
    }

    let in_hour = activity
        .accepted_spends
        .iter()
        .filter(|spend| in_lookback(spend.at_ms, proposal.proposed_at_ms, HOUR_MS))
        .count();
    if in_hour >= usize::try_from(policy.max_spends_per_hour).unwrap_or(usize::MAX) {
        failures.push(HardRuleFailure {
            code: HardRuleCode::RateLimit,
            explanation: format!(
                "Rate limit exceeded: {in_hour} spends already accepted in the last hour, max is {}.",
                policy.max_spends_per_hour
            ),
        });
    }
    failures
}

fn format_zec_u128(zatoshis: u128) -> String {
    if zatoshis > u128::from(u64::MAX) {
        return format!("{zatoshis} zatoshis");
    }
    format_zec(zatoshis as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zlint_types::AcceptedSpend;

    fn policy(cap: u64, max_tx: u64) -> Policy {
        Policy {
            daily_cap_zatoshis: cap,
            max_tx_zatoshis: max_tx,
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

    fn proposal(amount: u64, at: u64) -> SpendProposal {
        SpendProposal {
            destination: "u1test".into(),
            amount_zatoshis: amount,
            proposed_at_ms: at,
            memo: None,
            input_zatoshis: None,
            change_zatoshis: None,
        }
    }

    fn activity_with(prior: u64, at: u64) -> Activity {
        Activity {
            receives: vec![],
            shields: vec![],
            accepted_spends: vec![AcceptedSpend {
                amount_zatoshis: prior,
                at_ms: at,
            }],
        }
    }

    #[test]
    fn exact_cap_is_accepted_and_one_zatoshi_over_is_rejected() {
        let policy = policy(100_000_000, 100_000_000);
        let at = 1_000_000_000u64;
        let on_cap = hard_rules(
            &policy,
            &activity_with(50_000_000, at - 1_000),
            &proposal(50_000_000, at),
        );
        assert!(on_cap.is_empty());

        let over = hard_rules(
            &policy,
            &activity_with(50_000_000, at - 1_000),
            &proposal(50_000_001, at),
        );
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].code, HardRuleCode::DailyCap);
        assert!(!over[0].explanation.is_empty());
    }

    #[test]
    fn daily_window_includes_exactly_24h_and_excludes_older_and_future() {
        let policy = policy(100, 1_000);
        let at = DAY_MS + 50;
        let edge = hard_rules(&policy, &activity_with(40, at - DAY_MS), &proposal(60, at));
        assert!(edge.is_empty(), "exactly 24h still counts toward the cap");

        let older = hard_rules(
            &policy,
            &activity_with(40, at - DAY_MS - 1),
            &proposal(60, at),
        );
        assert!(older.is_empty(), "older than 24h must not count");

        let future = hard_rules(&policy, &activity_with(40, at + 1), &proposal(60, at));
        assert!(future.is_empty(), "a later accept must not count");
    }

    #[test]
    fn max_tx_boundary() {
        let policy = policy(1_000, 50);
        let at = 10_000u64;
        let empty = Activity {
            receives: vec![],
            shields: vec![],
            accepted_spends: vec![],
        };
        assert!(hard_rules(&policy, &empty, &proposal(50, at)).is_empty());
        let over = hard_rules(&policy, &empty, &proposal(51, at));
        assert_eq!(over[0].code, HardRuleCode::MaxTx);
    }

    #[test]
    fn both_hard_rules_are_reported() {
        let policy = policy(10, 5);
        let failures = hard_rules(&policy, &activity_with(8, 1_000), &proposal(6, 2_000));
        assert_eq!(
            failures.iter().map(|f| f.code).collect::<Vec<_>>(),
            vec![HardRuleCode::MaxTx, HardRuleCode::DailyCap]
        );
    }

    #[test]
    fn empty_allowlist_permits_and_nonempty_is_exact() {
        let mut policy = policy(1_000, 1_000);
        let at = 5_000u64;
        let empty = Activity {
            receives: vec![],
            shields: vec![],
            accepted_spends: vec![],
        };
        assert!(hard_rules(&policy, &empty, &proposal(10, at)).is_empty());
        policy.allowlist = vec!["u1other".into()];
        let denied = hard_rules(&policy, &empty, &proposal(10, at));
        assert_eq!(denied[0].code, HardRuleCode::Allowlist);
        policy.allowlist = vec!["u1test".into()];
        assert!(hard_rules(&policy, &empty, &proposal(10, at)).is_empty());
    }

    #[test]
    fn rate_limit_counts_the_hour_window_only() {
        let mut policy = policy(1_000_000, 1_000);
        policy.max_spends_per_hour = 2;
        let at = HOUR_MS + 10;
        let mut activity = Activity {
            receives: vec![],
            shields: vec![],
            accepted_spends: vec![
                AcceptedSpend {
                    amount_zatoshis: 1,
                    at_ms: at - HOUR_MS,
                },
                AcceptedSpend {
                    amount_zatoshis: 1,
                    at_ms: at - 1,
                },
            ],
        };
        let at_max = hard_rules(&policy, &activity, &proposal(1, at));
        assert_eq!(at_max[0].code, HardRuleCode::RateLimit);

        activity.accepted_spends[0].at_ms = at - HOUR_MS - 1;
        assert!(
            hard_rules(&policy, &activity, &proposal(1, at)).is_empty(),
            "a spend older than one hour does not count"
        );
    }

    #[test]
    fn loads_example_policy() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/policy.example.yaml");
        let policy = Policy::load(&path).unwrap();
        assert_eq!(policy.daily_cap_zatoshis, 200_000_000);
        assert_eq!(policy.max_tx_zatoshis, 50_000_000);
        assert_eq!(policy.reject_below, 60);
        assert_eq!(policy.warn_below, 75);
        assert!(policy.allowlist.is_empty());
    }
}
