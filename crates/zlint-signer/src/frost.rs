//! Trusted-dealer 2-of-2 RedPallas FROST.
//!
//! The dealer sees both shares. This is not distributed key generation.
//! A signature share is over an Orchard shielded sighash. One share does not aggregate.
//! Nonces are used once. Reusing them leaks the signing key.

use std::collections::BTreeMap;

use pasta_curves::group::ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::pallas;
use rand::rngs::OsRng;
use reddsa::frost::redpallas::keys::{self, IdentifierList, SecretShare};
use reddsa::frost::redpallas::rerandomized::{self, Randomizer};
use reddsa::frost::redpallas::{self, round1, SigningPackage};
use reddsa::orchard::SpendAuth;

pub use reddsa::frost::redpallas::keys::{KeyPackage, PublicKeyPackage};
pub use reddsa::frost::redpallas::round1::{SigningCommitments, SigningNonces};
pub use reddsa::frost::redpallas::round2::SignatureShare;
pub use reddsa::frost::redpallas::Identifier;

/// Both secret shares and the public group key from one dealer run.
/// The dealer that built this value saw both shares.
pub struct FrostKey {
    pub share1: KeyPackage,
    pub share2: KeyPackage,
    pub group: PublicKeyPackage,
}

/// Round-1 output for one share. `nonces` are secret and must be used once.
pub struct Round1 {
    pub id: Identifier,
    pub nonces: SigningNonces,
    pub commitment: SigningCommitments,
}

/// Fresh 2-of-2 key. The group verifying key has even Y, as Orchard requires.
pub fn deal_two_of_two() -> Result<FrostKey, String> {
    let (shares, group) = keys::generate_with_dealer(2, 2, IdentifierList::Default, OsRng)
        .map_err(|_| "could not deal a 2-of-2 key".to_string())?;
    finish_deal(shares, group)
}

/// Split an existing Orchard spend-authorizing key into a 2-of-2 FROST key.
/// `ask` is the 32-byte scalar. The group key must stay equal to that scalar's verifying key.
pub fn split_ask(ask: [u8; 32]) -> Result<FrostKey, String> {
    let signing_key = redpallas::SigningKey::deserialize(&ask)
        .map_err(|_| "ask is not a signing key".to_string())?;
    let (shares, group) = keys::split(&signing_key, 2, 2, IdentifierList::Default, &mut OsRng)
        .map_err(|_| "could not split the spend authorizing key".to_string())?;
    let dealt = finish_deal(shares, group)?;
    let group_key = group_verifying_key(&dealt.group)?;
    if group_key != reddsa_verifying_key(ask)? {
        return Err("group key does not match the spend authorizing key".into());
    }
    Ok(dealt)
}

/// Orchard `ask` from a 32-byte spending key, with the even-Y negation Orchard applies.
pub fn orchard_ask_bytes(spending_key: &[u8; 32]) -> Result<[u8; 32], String> {
    let expanded = zcash_spec::PrfExpand::ORCHARD_ASK.with(spending_key);
    let ask = pallas::Scalar::from_uniform_bytes(&expanded);
    if bool::from(ask.is_zero()) {
        return Err("ask is zero".into());
    }
    let bytes = scalar_bytes(ask);
    let verifying_key = reddsa_verifying_key(bytes)?;
    if verifying_key[31] & 0x80 == 1 {
        Ok(scalar_bytes(-ask))
    } else {
        Ok(bytes)
    }
}

pub fn group_verifying_key(group: &PublicKeyPackage) -> Result<[u8; 32], String> {
    let bytes = group
        .verifying_key()
        .serialize()
        .map_err(|_| "could not encode the group key".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "group key is not 32 bytes".to_string())
}

/// `rk = ak + alpha * G`, the Orchard randomized verifying key.
pub fn randomize_verifying_key(
    verifying_key: [u8; 32],
    randomizer: &[u8; 32],
) -> Result<[u8; 32], String> {
    let vk = reddsa::VerificationKey::<SpendAuth>::try_from(verifying_key)
        .map_err(|_| "verifying key is not a RedPallas key".to_string())?;
    let alpha = scalar_from_bytes(randomizer)?;
    let randomized: [u8; 32] = vk.randomize(&alpha).into();
    Ok(randomized)
}

pub fn verify_spend_auth(
    verifying_key: [u8; 32],
    message: &[u8],
    signature: [u8; 64],
) -> Result<(), String> {
    let vk = reddsa::VerificationKey::<SpendAuth>::try_from(verifying_key)
        .map_err(|_| "verifying key is not a RedPallas key".to_string())?;
    let signature = reddsa::Signature::<SpendAuth>::from(signature);
    vk.verify(message, &signature)
        .map_err(|_| "signature did not verify".to_string())
}

/// The other participant in a 2-of-2 group. This is not this share's own identifier.
pub fn other_identifier(key: &KeyPackage, group: &PublicKeyPackage) -> Result<Identifier, String> {
    let mine = *key.identifier();
    let mut others: Vec<Identifier> = group
        .verifying_shares()
        .keys()
        .copied()
        .filter(|identifier| *identifier != mine)
        .collect();
    if others.len() != 1 || others[0] == mine {
        return Err("group key does not have one other share".into());
    }
    Ok(others.pop().expect("one other share"))
}

pub fn commit(key: &KeyPackage) -> Round1 {
    let (nonces, commitment) = round1::commit(key.signing_share(), &mut OsRng);
    Round1 {
        id: *key.identifier(),
        nonces,
        commitment,
    }
}

/// Produce one signature share. `nonces` are consumed. Do not commit them again.
pub fn sign_share(
    key: &KeyPackage,
    nonces: SigningNonces,
    commitments: &BTreeMap<Identifier, SigningCommitments>,
    message: &[u8],
    randomizer: &[u8; 32],
) -> Result<SignatureShare, String> {
    if commitments.len() < 2 || !commitments.contains_key(key.identifier()) {
        return Err("2-of-2 signing needs both commitments".into());
    }
    let package = SigningPackage::new(commitments.clone(), message);
    let randomizer = Randomizer::deserialize(randomizer)
        .map_err(|_| "randomizer is not a scalar".to_string())?;
    #[allow(deprecated)]
    frost_rerandomized::sign(&package, &nonces, key, randomizer)
        .map_err(|_| "could not produce a signature share".to_string())
}

/// Aggregate two shares into a 64-byte RedPallas signature.
/// One share is refused here, before aggregation.
pub fn aggregate_shares(
    commitments: &BTreeMap<Identifier, SigningCommitments>,
    message: &[u8],
    shares: &BTreeMap<Identifier, SignatureShare>,
    group: &PublicKeyPackage,
    randomizer: &[u8; 32],
) -> Result<[u8; 64], String> {
    if shares.len() < 2 {
        return Err("missing a signature share".into());
    }
    let package = SigningPackage::new(commitments.clone(), message);
    let randomizer = Randomizer::deserialize(randomizer)
        .map_err(|_| "randomizer is not a scalar".to_string())?;
    let params = rerandomized::RandomizedParams::from_randomizer(group.verifying_key(), randomizer);
    let signature = rerandomized::aggregate(&package, shares, group, &params)
        .map_err(|_| "could not aggregate the signature shares".to_string())?;
    let bytes = signature
        .serialize()
        .map_err(|_| "could not encode the signature".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "signature is not 64 bytes".to_string())
}

pub(crate) fn decode_key_package(value: &serde_json::Value) -> Result<KeyPackage, String> {
    serde_json::from_value(value.clone())
        .map_err(|_| "share file has a bad key package".to_string())
}

pub(crate) fn decode_group_package(value: &serde_json::Value) -> Result<PublicKeyPackage, String> {
    serde_json::from_value(value.clone()).map_err(|_| "share file has a bad group key".to_string())
}

pub(crate) fn check_share_matches_group(
    key: &KeyPackage,
    group: &PublicKeyPackage,
) -> Result<(), String> {
    if *key.min_signers() != 2 || group.min_signers() != Some(2) {
        return Err("share is not a 2-of-2 key".into());
    }
    if group_verifying_key(group)? != group_verifying_key_of(key)? {
        return Err("share does not match its group key".into());
    }
    Ok(())
}

fn finish_deal(
    shares: BTreeMap<Identifier, SecretShare>,
    group: PublicKeyPackage,
) -> Result<FrostKey, String> {
    if shares.len() != 2 {
        return Err("dealer did not produce two shares".into());
    }
    let mut packages = Vec::with_capacity(2);
    for share in shares.into_values() {
        let package = KeyPackage::try_from(share)
            .map_err(|_| "dealer share failed verification".to_string())?;
        packages.push(package);
    }
    packages.sort_by_key(|package| *package.identifier());
    let share2 = packages.pop().expect("two shares");
    let share1 = packages.pop().expect("two shares");
    if share1.identifier() == share2.identifier() {
        return Err("dealer produced two shares with one id".into());
    }
    check_share_matches_group(&share1, &group)?;
    check_share_matches_group(&share2, &group)?;
    Ok(FrostKey {
        share1,
        share2,
        group,
    })
}

fn group_verifying_key_of(key: &KeyPackage) -> Result<[u8; 32], String> {
    let bytes = key
        .verifying_key()
        .serialize()
        .map_err(|_| "could not encode the group key".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "group key is not 32 bytes".to_string())
}

fn reddsa_verifying_key(ask: [u8; 32]) -> Result<[u8; 32], String> {
    let signing_key = reddsa::SigningKey::<SpendAuth>::try_from(ask)
        .map_err(|_| "ask is not a RedPallas signing key".to_string())?;
    Ok(reddsa::VerificationKey::from(&signing_key).into())
}

fn scalar_bytes(scalar: pallas::Scalar) -> [u8; 32] {
    let repr = scalar.to_repr();
    let bytes: &[u8] = repr.as_ref();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<pallas::Scalar, String> {
    let mut repr = pallas::Scalar::from(0u64).to_repr();
    repr.as_mut().copy_from_slice(bytes);
    Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(repr))
        .ok_or_else(|| "randomizer is not a scalar".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitments_of(first: &Round1, second: &Round1) -> BTreeMap<Identifier, SigningCommitments> {
        let mut commitments = BTreeMap::new();
        commitments.insert(first.id, first.commitment);
        commitments.insert(second.id, second.commitment);
        commitments
    }

    fn sign_message(key: &FrostKey, message: &[u8], randomizer: &[u8; 32]) -> [u8; 64] {
        let first = commit(&key.share1);
        let second = commit(&key.share2);
        let commitments = commitments_of(&first, &second);
        let share1 = sign_share(&key.share1, first.nonces, &commitments, message, randomizer)
            .expect("share 1");
        let share2 = sign_share(
            &key.share2,
            second.nonces,
            &commitments,
            message,
            randomizer,
        )
        .expect("share 2");
        let mut one = BTreeMap::new();
        one.insert(first.id, share1.clone());
        let missing = aggregate_shares(&commitments, message, &one, &key.group, randomizer);
        assert!(missing.is_err(), "one share must not aggregate");
        let mut both = one;
        both.insert(second.id, share2);
        aggregate_shares(&commitments, message, &both, &key.group, randomizer).expect("aggregate")
    }

    #[test]
    fn split_orchard_ask_verifies_only_with_both_shares() {
        let ask = orchard_ask_bytes(&[0u8; 32]).unwrap();
        let key = split_ask(ask).unwrap();
        let vk = reddsa_verifying_key(ask).unwrap();
        assert_eq!(vk[31] & 0x80, 0);
        assert_eq!(group_verifying_key(&key.group).unwrap(), vk);
        let message = b"orchard-sighash-stand-in";
        let randomizer = [7u8; 32];
        let signature = sign_message(&key, message, &randomizer);
        let rk = randomize_verifying_key(vk, &randomizer).unwrap();
        verify_spend_auth(rk, message, signature).unwrap();
        let mut broken = signature;
        broken[0] ^= 1;
        assert!(verify_spend_auth(rk, message, broken).is_err());
        assert!(verify_spend_auth(vk, message, signature).is_err());
    }

    #[test]
    fn dealer_key_also_needs_both_shares() {
        let key = deal_two_of_two().unwrap();
        let vk = group_verifying_key(&key.group).unwrap();
        assert_eq!(vk[31] & 0x80, 0);
        let message = b"dealer";
        let randomizer = [9u8; 32];
        let signature = sign_message(&key, message, &randomizer);
        let rk = randomize_verifying_key(vk, &randomizer).unwrap();
        verify_spend_auth(rk, message, signature).unwrap();
    }
}
