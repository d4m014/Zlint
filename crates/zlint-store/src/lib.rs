//! Local decision log, accepted-spend history, and warnings waiting for a person.
//! The daily cap and the rate limit count rows in `accepted_spends`.
//! A warning stays out of that table until a signature share is contributed.

use rusqlite::{params, Connection};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zlint_types::{AcceptedSpend, Decision};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedDecision {
    pub proposal_hash: String,
    pub verdict: String,
    pub score: u8,
    pub flags_json: String,
    pub proposed_at_ms: u64,
    pub recorded_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWarn {
    pub proposal_hash: String,
    pub amount_zatoshis: u64,
    pub proposed_at_ms: u64,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_hash TEXT NOT NULL,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                flags_json TEXT NOT NULL,
                proposed_at_ms INTEGER NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accepted_spends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_hash TEXT NOT NULL UNIQUE,
                amount_zatoshis INTEGER NOT NULL,
                at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_warnings (
                proposal_hash TEXT PRIMARY KEY,
                amount_zatoshis INTEGER NOT NULL,
                proposed_at_ms INTEGER NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS confirmed_warnings (
                proposal_hash TEXT PRIMARY KEY,
                amount_zatoshis INTEGER NOT NULL,
                proposed_at_ms INTEGER NOT NULL,
                recorded_at_ms INTEGER NOT NULL
            );
            ",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    pub fn has_accepted(&self, proposal_hash: &str) -> Result<bool, String> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM accepted_spends WHERE proposal_hash = ?1",
                params![proposal_hash],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        Ok(count > 0)
    }

    pub fn record_decision(
        &self,
        proposal_hash: &str,
        proposal_at_ms: u64,
        decision: &Decision,
    ) -> Result<(), String> {
        let flags = serde_json::to_string(&decision.flags).map_err(|e| e.to_string())?;
        let verdict = match decision.verdict {
            zlint_types::Verdict::Accept => "accept",
            zlint_types::Verdict::Reject => "reject",
            zlint_types::Verdict::Warn => "warn",
        };
        self.conn
            .execute(
                "INSERT INTO decisions
                    (proposal_hash, verdict, score, flags_json, proposed_at_ms, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    proposal_hash,
                    verdict,
                    i64::from(decision.score),
                    flags,
                    i64_ms(proposal_at_ms)?,
                    i64_ms(now_ms())?,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn record_accept(
        &self,
        proposal_hash: &str,
        amount_zatoshis: u64,
        at_ms: u64,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO accepted_spends (proposal_hash, amount_zatoshis, at_ms)
                 VALUES (?1, ?2, ?3)",
                params![proposal_hash, i64_ms(amount_zatoshis)?, i64_ms(at_ms)?],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn recent_decisions(&self, limit: u32) -> Result<Vec<LoggedDecision>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT proposal_hash, verdict, score, flags_json, proposed_at_ms, recorded_at_ms
                 FROM decisions
                 ORDER BY id DESC
                 LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![limit], |row| {
                let score: i64 = row.get(2)?;
                Ok(LoggedDecision {
                    proposal_hash: row.get(0)?,
                    verdict: row.get(1)?,
                    score: u8::try_from(score).unwrap_or(0),
                    flags_json: row.get(3)?,
                    proposed_at_ms: u64_ms(row.get(4)?)?,
                    recorded_at_ms: u64_ms(row.get(5)?)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn record_pending(
        &self,
        proposal_hash: &str,
        amount_zatoshis: u64,
        proposed_at_ms: u64,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO pending_warnings
                    (proposal_hash, amount_zatoshis, proposed_at_ms, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(proposal_hash) DO UPDATE SET
                    amount_zatoshis = excluded.amount_zatoshis,
                    proposed_at_ms = excluded.proposed_at_ms,
                    recorded_at_ms = excluded.recorded_at_ms",
                params![
                    proposal_hash,
                    i64_ms(amount_zatoshis)?,
                    i64_ms(proposed_at_ms)?,
                    i64_ms(now_ms())?,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn pending(&self, proposal_hash: &str) -> Result<Option<PendingWarn>, String> {
        let row = self.conn.query_row(
            "SELECT proposal_hash, amount_zatoshis, proposed_at_ms
                 FROM pending_warnings WHERE proposal_hash = ?1",
            params![proposal_hash],
            |row| {
                Ok(PendingWarn {
                    proposal_hash: row.get(0)?,
                    amount_zatoshis: u64_ms(row.get(1)?)?,
                    proposed_at_ms: u64_ms(row.get(2)?)?,
                })
            },
        );
        match row {
            Ok(pending) => Ok(Some(pending)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn record_confirmed(
        &self,
        proposal_hash: &str,
        amount_zatoshis: u64,
        proposed_at_ms: u64,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO confirmed_warnings
                    (proposal_hash, amount_zatoshis, proposed_at_ms, recorded_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(proposal_hash) DO UPDATE SET
                    amount_zatoshis = excluded.amount_zatoshis,
                    proposed_at_ms = excluded.proposed_at_ms,
                    recorded_at_ms = excluded.recorded_at_ms",
                params![
                    proposal_hash,
                    i64_ms(amount_zatoshis)?,
                    i64_ms(proposed_at_ms)?,
                    i64_ms(now_ms())?,
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn confirmed(&self, proposal_hash: &str) -> Result<Option<PendingWarn>, String> {
        let row = self.conn.query_row(
            "SELECT proposal_hash, amount_zatoshis, proposed_at_ms
                 FROM confirmed_warnings WHERE proposal_hash = ?1",
            params![proposal_hash],
            |row| {
                Ok(PendingWarn {
                    proposal_hash: row.get(0)?,
                    amount_zatoshis: u64_ms(row.get(1)?)?,
                    proposed_at_ms: u64_ms(row.get(2)?)?,
                })
            },
        );
        match row {
            Ok(confirmed) => Ok(Some(confirmed)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.to_string()),
        }
    }

    pub fn remove_confirmed(&self, proposal_hash: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM confirmed_warnings WHERE proposal_hash = ?1",
                params![proposal_hash],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn remove_pending(&self, proposal_hash: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM pending_warnings WHERE proposal_hash = ?1",
                params![proposal_hash],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn accepted_spends(&self) -> Result<Vec<AcceptedSpend>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT amount_zatoshis, at_ms FROM accepted_spends ORDER BY at_ms, id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AcceptedSpend {
                    amount_zatoshis: u64_ms(row.get(0)?)?,
                    at_ms: u64_ms(row.get(1)?)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn i64_ms(value: u64) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{value} does not fit in a sqlite integer"))
}

fn u64_ms(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Integer, Box::new(e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zlint_types::{Flag, FlagCode, Verdict};

    fn decision(verdict: Verdict) -> Decision {
        Decision {
            verdict,
            score: 100,
            flags: vec![Flag {
                code: FlagCode::TimingCorrelation,
                weight: 40,
                explanation: "example".into(),
            }],
            hard_rule_failures: vec![],
        }
    }

    #[test]
    fn accepts_are_counted_and_rejects_are_not() {
        let path = std::env::temp_dir().join(format!("zlint-store-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        store
            .record_decision("reject-hash", 10, &decision(Verdict::Reject))
            .unwrap();
        store
            .record_decision("accept-hash", 20, &decision(Verdict::Accept))
            .unwrap();
        store.record_accept("accept-hash", 5, 20).unwrap();
        let spends = store.accepted_spends().unwrap();
        assert_eq!(spends.len(), 1);
        assert_eq!(spends[0].amount_zatoshis, 5);
        assert!(store.has_accepted("accept-hash").unwrap());
        assert!(!store.has_accepted("reject-hash").unwrap());
        let again = store.record_accept("accept-hash", 5, 20);
        assert!(again.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_pending_warning_is_replaced_and_then_removed() {
        let path = std::env::temp_dir().join(format!("zlint-pending-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path).unwrap();
        store.record_pending("warn-hash", 10, 30).unwrap();
        store.record_pending("warn-hash", 11, 31).unwrap();
        let pending = store.pending("warn-hash").unwrap().unwrap();
        assert_eq!(pending.amount_zatoshis, 11);
        assert_eq!(pending.proposed_at_ms, 31);
        assert!(store.pending("missing").unwrap().is_none());
        store.remove_pending("warn-hash").unwrap();
        assert!(store.pending("warn-hash").unwrap().is_none());
        store.record_confirmed("warn-hash", 11, 31).unwrap();
        store.record_confirmed("warn-hash", 12, 32).unwrap();
        let confirmed = store.confirmed("warn-hash").unwrap().unwrap();
        assert_eq!(confirmed.amount_zatoshis, 12);
        assert_eq!(confirmed.proposed_at_ms, 32);
        store.remove_confirmed("warn-hash").unwrap();
        assert!(store.confirmed("warn-hash").unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }
}
