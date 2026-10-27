//! Co-signer control plane.
//! A share is contributed only for an accept, or for a warning a person has confirmed.
//! A reject never contributes a share. The simulated share is not a Zcash signature.
//! A FROST share signs an Orchard sighash. It is not used for a JSON proposal.

mod frost;
mod nonce;
mod share;

pub use frost::SignatureShare as FrostSignatureShare;
pub use frost::{
    aggregate_shares, commit, deal_two_of_two, group_verifying_key, orchard_ask_bytes,
    other_identifier, randomize_verifying_key, sign_share, split_ask, verify_spend_auth, FrostKey,
    Identifier, KeyPackage, PublicKeyPackage, Round1, SigningCommitments,
};
pub use nonce::{discard_matching_round, sign_with_round1, store_round1, PublicCommit};
pub use share::{
    create_frost_shares, create_share, load_frost_share, require_share, require_simulated_share,
    save_frost_share, LoadedFrostShare, ShareKind,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zlint_types::{SpendProposal, Verdict};

pub const SIMULATED_STATEMENT: &str = "Simulated share. This is not a Zcash signature.";

pub trait Signer {
    fn contribute(&self, proposal_hash: &str) -> SignatureShare;
}

/// Labels a dummy share. It holds no key material.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulatedSigner;

impl Signer for SimulatedSigner {
    fn contribute(&self, proposal_hash: &str) -> SignatureShare {
        SignatureShare {
            signer: "simulated".into(),
            proposal_hash: proposal_hash.to_string(),
            share: format!("simulated:{proposal_hash}"),
            statement: SIMULATED_STATEMENT.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureShare {
    pub signer: String,
    pub proposal_hash: String,
    pub share: String,
    pub statement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    pub share: Option<SignatureShare>,
    pub awaiting_confirmation: bool,
}

/// `confirmed` is ignored unless the verdict is a warning.
/// A reject does not call the signer, even when `confirmed` is set.
pub fn contribute(
    verdict: Verdict,
    confirmed: bool,
    signer: &impl Signer,
    proposal_hash: &str,
) -> Contribution {
    match verdict {
        Verdict::Accept => Contribution {
            share: Some(signer.contribute(proposal_hash)),
            awaiting_confirmation: false,
        },
        Verdict::Warn if confirmed => Contribution {
            share: Some(signer.contribute(proposal_hash)),
            awaiting_confirmation: false,
        },
        Verdict::Warn => Contribution {
            share: None,
            awaiting_confirmation: true,
        },
        Verdict::Reject => Contribution {
            share: None,
            awaiting_confirmation: false,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CosignReport {
    pub decision: zlint_types::Decision,
    pub signature_share: Option<SignatureShare>,
    pub awaiting_confirmation: bool,
    pub already_signed: bool,
}

pub fn proposal_hash(proposal: &SpendProposal) -> Result<String, String> {
    let bytes = serde_json::to_vec(proposal).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Spy {
        calls: Cell<u32>,
    }

    impl Signer for Spy {
        fn contribute(&self, proposal_hash: &str) -> SignatureShare {
            self.calls.set(self.calls.get() + 1);
            SimulatedSigner.contribute(proposal_hash)
        }
    }

    fn gate(verdict: Verdict, confirmed: bool) -> (Contribution, u32) {
        let spy = Spy {
            calls: Cell::new(0),
        };
        let contribution = contribute(verdict, confirmed, &spy, "abc");
        (contribution, spy.calls.get())
    }

    #[test]
    fn accept_contributes_one_simulated_share() {
        let (contribution, calls) = gate(Verdict::Accept, false);
        let share = contribution.share.expect("share");
        assert_eq!(calls, 1);
        assert!(!contribution.awaiting_confirmation);
        assert_eq!(share.signer, "simulated");
        assert_eq!(share.share, "simulated:abc");
        assert_eq!(share.statement, SIMULATED_STATEMENT);
        assert!(share.statement.contains("not a Zcash signature"));
    }

    #[test]
    fn reject_contributes_nothing_even_when_confirmed() {
        let (contribution, calls) = gate(Verdict::Reject, true);
        assert_eq!(calls, 0);
        assert!(contribution.share.is_none());
        assert!(!contribution.awaiting_confirmation);
    }

    #[test]
    fn warn_waits_until_a_person_confirms() {
        let (waiting, calls) = gate(Verdict::Warn, false);
        assert_eq!(calls, 0);
        assert!(waiting.share.is_none());
        assert!(waiting.awaiting_confirmation);

        let (confirmed, calls) = gate(Verdict::Warn, true);
        assert_eq!(calls, 1);
        let share = confirmed.share.expect("share");
        assert!(!confirmed.awaiting_confirmation);
        assert_eq!(share.statement, SIMULATED_STATEMENT);
    }
}
