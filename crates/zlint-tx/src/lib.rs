//! Read a partially built Zcash transaction and run the spend check on it.
//!
//! A wallet or an agent passes the PCZT bytes. Zlint reads shielded outputs that still
//! show an address and an amount. It does not scan the chain and it does not sign.

use std::collections::BTreeMap;

use pczt::Pczt;
use zlint_policy::Policy;
use zlint_types::{Activity, Decision, SpendProposal};

/// One shielded payment found in the transaction, plus change that has an amount but no address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldedPayment {
    pub destination: String,
    pub amount_zatoshis: u64,
    pub change_zatoshis: u64,
    pub input_zatoshis: u64,
}

/// The payment read from the transaction, and the decision for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Review {
    pub payment: ShieldedPayment,
    pub decision: Decision,
}

pub fn review_pczt(
    policy: &Policy,
    activity: &Activity,
    pczt_bytes: &[u8],
    proposed_at_ms: u64,
) -> Result<Review, String> {
    let payment = shielded_payment(pczt_bytes)?;
    let proposal = SpendProposal {
        destination: payment.destination.clone(),
        amount_zatoshis: payment.amount_zatoshis,
        proposed_at_ms,
        memo: None,
        input_zatoshis: Some(payment.input_zatoshis),
        change_zatoshis: Some(payment.change_zatoshis),
    };
    proposal.validate()?;
    let decision = zlint_linter::decide(policy, activity, &proposal);
    Ok(Review { payment, decision })
}

pub fn shielded_payment(pczt_bytes: &[u8]) -> Result<ShieldedPayment, String> {
    let pczt =
        Pczt::parse(pczt_bytes).map_err(|e| format!("could not read the transaction: {e}"))?;
    let mut payments: BTreeMap<String, u64> = BTreeMap::new();
    let mut change: u64 = 0;

    for bundle in [pczt.orchard(), pczt.ironwood()] {
        for action in bundle.actions() {
            take_output(
                *action.output().value(),
                payment_address(
                    action.output().user_address(),
                    action.output().recipient().as_ref(),
                )
                .as_deref(),
                &mut payments,
                &mut change,
            )?;
        }
    }
    for output in pczt.sapling().outputs() {
        take_output(
            *output.value(),
            output.user_address().as_deref(),
            &mut payments,
            &mut change,
        )?;
    }

    if payments.is_empty() {
        return Err(
            "no shielded payment with an address and an amount. The wallet has to leave those fields visible, and Zlint does not read transparent payments."
                .into(),
        );
    }
    if payments.len() != 1 {
        return Err(format!(
            "this transaction pays {} different addresses. Zlint reviews one payment at a time.",
            payments.len()
        ));
    }
    let (destination, amount_zatoshis) = payments.into_iter().next().unwrap();
    let input_zatoshis = amount_zatoshis
        .checked_add(change)
        .ok_or("payment plus change overflowed")?;
    Ok(ShieldedPayment {
        destination,
        amount_zatoshis,
        change_zatoshis: change,
        input_zatoshis,
    })
}

/// `user_address` is the string a wallet sets for the allowlist. The raw recipient is what
/// the constructor always writes, so a PCZT is still checkable when that string was left unset.
fn payment_address(user_address: &Option<String>, recipient: Option<&[u8; 43]>) -> Option<String> {
    let written = user_address
        .as_deref()
        .map(str::trim)
        .filter(|address| !address.is_empty());
    if let Some(address) = written {
        return Some(address.to_string());
    }
    recipient.map(hex::encode)
}

fn take_output(
    value: Option<u64>,
    user_address: Option<&str>,
    payments: &mut BTreeMap<String, u64>,
    change: &mut u64,
) -> Result<(), String> {
    let address = user_address.map(str::trim).filter(|s| !s.is_empty());
    match (value, address) {
        (None | Some(0), None) => Ok(()),
        (None, Some(_)) => Err(
            "a shielded output has an address but no amount. The wallet redacted the value, so Zlint cannot check it."
                .into(),
        ),
        (Some(0), Some(_)) => Ok(()),
        (Some(amount), None) => {
            *change = change
                .checked_add(amount)
                .ok_or("change overflowed")?;
            Ok(())
        }
        (Some(amount), Some(address)) => {
            let entry = payments.entry(address.to_string()).or_insert(0);
            *entry = entry.checked_add(amount).ok_or("payment overflowed")?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pczt::roles::creator::Creator;
    use zcash_protocol::consensus::BranchId;

    #[test]
    fn empty_transaction_is_not_a_payment() {
        let branch = u32::from(BranchId::Nu6_1);
        let pczt = Creator::new(branch, 1, 133, None, Some([0u8; 32]))
            .unwrap()
            .build()
            .unwrap();
        let bytes = pczt.serialize().unwrap();
        let err = shielded_payment(&bytes).unwrap_err();
        assert!(err.contains("no shielded payment"), "{err}");
    }

    #[test]
    fn garbage_is_rejected() {
        let err = shielded_payment(b"not a transaction").unwrap_err();
        assert!(err.contains("could not read the transaction"), "{err}");
    }
}
