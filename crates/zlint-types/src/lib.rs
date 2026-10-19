//! Wire types for a spend proposal, an activity window, and a decision.
//! Field names match `schemas/*.schema.json`.

use serde::{Deserialize, Serialize};

pub const ZATOSHIS_PER_ZEC: u64 = 100_000_000;
pub const DAY_MS: u64 = 24 * 60 * 60 * 1000;
pub const HOUR_MS: u64 = 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendProposal {
    pub destination: String,
    pub amount_zatoshis: u64,
    pub proposed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_zatoshis: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_zatoshis: Option<u64>,
}

impl SpendProposal {
    pub fn validate(&self) -> Result<(), String> {
        if self.destination.is_empty() {
            return Err("destination is empty".into());
        }
        if self.amount_zatoshis == 0 {
            return Err("amount_zatoshis must be at least 1".into());
        }
        if self.input_zatoshis == Some(0) {
            return Err("input_zatoshis must be at least 1 when set".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pool {
    Orchard,
    Sapling,
    Transparent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receive {
    pub amount_zatoshis: u64,
    pub at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<Pool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Shield {
    pub amount_zatoshis: u64,
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedSpend {
    pub amount_zatoshis: u64,
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub receives: Vec<Receive>,
    pub shields: Vec<Shield>,
    pub accepted_spends: Vec<AcceptedSpend>,
}

impl Activity {
    pub fn validate(&self) -> Result<(), String> {
        for (i, note) in self.receives.iter().enumerate() {
            if note.amount_zatoshis == 0 {
                return Err(format!("receives[{i}].amount_zatoshis must be at least 1"));
            }
        }
        for (i, shield) in self.shields.iter().enumerate() {
            if shield.amount_zatoshis == 0 {
                return Err(format!("shields[{i}].amount_zatoshis must be at least 1"));
            }
        }
        for (i, spend) in self.accepted_spends.iter().enumerate() {
            if spend.amount_zatoshis == 0 {
                return Err(format!(
                    "accepted_spends[{i}].amount_zatoshis must be at least 1"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accept,
    Reject,
    Warn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagCode {
    TimingCorrelation,
    RoundOrDistinctiveAmount,
    ShieldAfterReceive,
    ChangeNoteSelection,
}

impl FlagCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TimingCorrelation => "timing_correlation",
            Self::RoundOrDistinctiveAmount => "round_or_distinctive_amount",
            Self::ShieldAfterReceive => "shield_after_receive",
            Self::ChangeNoteSelection => "change_note_selection",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flag {
    pub code: FlagCode,
    pub weight: u8,
    pub explanation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardRuleCode {
    DailyCap,
    MaxTx,
    Allowlist,
    RateLimit,
}

impl HardRuleCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DailyCap => "daily_cap",
            Self::MaxTx => "max_tx",
            Self::Allowlist => "allowlist",
            Self::RateLimit => "rate_limit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardRuleFailure {
    pub code: HardRuleCode,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub verdict: Verdict,
    pub score: u8,
    pub flags: Vec<Flag>,
    pub hard_rule_failures: Vec<HardRuleFailure>,
}

/// `50000000` → `0.5 ZEC`. Trailing zeros in the fractional part are dropped.
pub fn format_zec(zatoshis: u64) -> String {
    let whole = zatoshis / ZATOSHIS_PER_ZEC;
    let frac = zatoshis % ZATOSHIS_PER_ZEC;
    if frac == 0 {
        return format!("{whole} ZEC");
    }
    let mut frac_s = format!("{frac:08}");
    while frac_s.ends_with('0') {
        frac_s.pop();
    }
    format!("{whole}.{frac_s} ZEC")
}

/// Whole minutes when the gap lands on a minute, otherwise minutes and seconds.
pub fn format_gap(ms: u64) -> String {
    if ms % 60_000 == 0 {
        format!("{} min", ms / 60_000)
    } else if ms < 60_000 {
        format!("{} sec", ms / 1000)
    } else {
        format!("{} min {} sec", ms / 60_000, (ms % 60_000) / 1000)
    }
}

/// `at` is inside the lookback when it is not after `proposed_at` and the gap
/// is at most `lookback_ms`. The edge (`gap == lookback`) is inside.
pub fn in_lookback(at_ms: u64, proposed_at_ms: u64, lookback_ms: u64) -> bool {
    at_ms <= proposed_at_ms && proposed_at_ms.saturating_sub(at_ms) <= lookback_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_zec_and_gaps() {
        assert_eq!(format_zec(100_000_000), "1 ZEC");
        assert_eq!(format_zec(50_000_000), "0.5 ZEC");
        assert_eq!(format_zec(13_700_000), "0.137 ZEC");
        assert_eq!(format_zec(40_100_000), "0.401 ZEC");
        assert_eq!(format_zec(120_100_000), "1.201 ZEC");
        assert_eq!(format_gap(240_000), "4 min");
        assert_eq!(format_gap(120_000), "2 min");
        assert_eq!(format_gap(90_000), "1 min 30 sec");
    }

    #[test]
    fn lookback_is_inclusive_on_the_edge() {
        assert!(in_lookback(400, 1000, 600));
        assert!(!in_lookback(399, 1000, 600));
        assert!(!in_lookback(1001, 1000, 600));
    }
}
