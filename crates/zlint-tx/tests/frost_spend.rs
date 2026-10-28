//! A regtest Orchard PCZT, stopped before the prover.
//! Share 2 missing: aggregation fails and the action has no spend authorization.
//! Both shares: the aggregate verifies, and the PCZT signer role stores it.

use std::collections::BTreeMap;
use std::convert::Infallible;

use incrementalmerkletree::Retention;
use orchard::tree::MerkleHashOrchard;
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::signer::Signer;
use pczt::roles::verifier::Verifier;
use pczt::Pczt;
use rand::rngs::OsRng;
use shardtree::store::memory::MemoryShardStore;
use shardtree::ShardTree;
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::value::Zatoshis;
use zlint_signer::{
    aggregate_shares, commit, group_verifying_key, orchard_ask_bytes, randomize_verifying_key,
    sign_share, split_ask, FrostSignatureShare, Identifier,
};
use zlint_tx::apply_orchard_spend_auth;

#[test]
fn both_shares_authorize_the_spend_and_one_share_does_not() {
    let spending_key_bytes = [0u8; 32];
    let spending_key = orchard::keys::SpendingKey::from_bytes(spending_key_bytes).unwrap();
    let ask = orchard_ask_bytes(&spending_key_bytes).unwrap();
    let frost = split_ask(ask).unwrap();
    let group_key = group_verifying_key(&frost.group).unwrap();
    assert_eq!(group_key[31] & 0x80, 0);

    let (pczt, index) = orchard_spend_pczt(&spending_key);
    let bytes = pczt.clone().serialize().unwrap();
    assert!(action_signature(&pczt, index).is_none());

    let sighash = Signer::new(pczt.clone()).unwrap().shielded_sighash();
    let alpha = action_alpha(&pczt, index);
    let rk = action_rk(&pczt, index);
    assert_eq!(randomize_verifying_key(group_key, &alpha).unwrap(), rk);
    let extracted = zlint_tx::orchard_sighash(&bytes).unwrap();
    assert_eq!(extracted.sighash, sighash);
    assert!(extracted
        .actions
        .iter()
        .any(|action| { action.index == index && action.alpha == alpha && action.rk == rk }));

    let first = commit(&frost.share1);
    let second = commit(&frost.share2);
    let mut commitments = BTreeMap::new();
    commitments.insert(first.id, first.commitment);
    commitments.insert(second.id, second.commitment);
    let share1 = sign_share(&frost.share1, first.nonces, &commitments, &sighash, &alpha).unwrap();
    let share2 = sign_share(&frost.share2, second.nonces, &commitments, &sighash, &alpha).unwrap();

    let mut one = BTreeMap::new();
    one.insert(first.id, share1);
    let missing = aggregate_shares(&commitments, &sighash, &one, &frost.group, &alpha);
    assert!(
        missing.is_err(),
        "a PCZT missing share 2 must not get a signature"
    );
    assert!(action_signature(&Pczt::parse(&bytes).unwrap(), index).is_none());

    let mut both: BTreeMap<Identifier, FrostSignatureShare> = one;
    both.insert(second.id, share2);
    let signature = aggregate_shares(&commitments, &sighash, &both, &frost.group, &alpha).unwrap();

    let rejected = apply_orchard_spend_auth(&bytes, index, [0u8; 64]);
    assert!(rejected.is_err(), "an empty signature must be rejected");

    let signed = apply_orchard_spend_auth(&bytes, index, signature).unwrap();
    let signed_pczt = Pczt::parse(&signed).unwrap();
    assert_eq!(action_signature(&signed_pczt, index), Some(signature));
    let signed_sighash = Signer::new(signed_pczt).unwrap().shielded_sighash();
    assert_eq!(signed_sighash, sighash);
    zlint_signer::verify_spend_auth(rk, &sighash, signature).unwrap();
}

fn orchard_spend_pczt(spending_key: &orchard::keys::SpendingKey) -> (Pczt, usize) {
    let mut rng = OsRng;
    let fvk = orchard::keys::FullViewingKey::from(spending_key);
    let ivk = fvk.to_ivk(orchard::keys::Scope::External);
    let external_ovk = fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = fvk.address_at(0u32, orchard::keys::Scope::External);
    let value = orchard::value::NoteValue::from_raw(1_000_000);
    let note = {
        let mut builder = orchard::builder::Builder::new(
            orchard::builder::BundleType::DEFAULT,
            orchard::bundle::BundleVersion::orchard_v2(),
            orchard::bundle::BundleVersion::orchard_v2().default_flags(),
            orchard::Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(None, recipient, value, Memo::Empty.encode().into_bytes())
            .unwrap();
        let (bundle, meta) = builder.build::<i64>(&mut rng).unwrap().unwrap();
        let action = bundle
            .actions()
            .get(meta.output_action_index(0).unwrap())
            .unwrap();
        let domain = orchard::note_encryption::OrchardDomain::for_action(action);
        let (note, _, _) = try_note_decryption(&domain, &ivk.prepare(), action).unwrap();
        note
    };

    let (anchor, merkle_path) = {
        let cmx: orchard::note::ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree =
            ShardTree::<_, 32, 16>::new(MemoryShardStore::<MerkleHashOrchard, u32>::empty(), 100);
        tree.append(leaf, Retention::Marked).unwrap();
        tree.checkpoint(9_999_999).unwrap();
        let merkle_path = tree
            .witness_at_checkpoint_depth(0.into(), 0)
            .unwrap()
            .unwrap();
        let anchor = merkle_path.root(leaf);
        (anchor.into(), merkle_path.into())
    };

    let mut builder = Builder::new(
        pre_nu6_3_test_network(),
        BlockHeight::from_u32(10_000_000),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: Some(anchor),
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_orchard_spend::<zip317::FeeRule>(fvk.clone(), note, merkle_path)
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(external_ovk),
            recipient,
            Zatoshis::const_from_u64(100_000),
            MemoBytes::empty(),
        )
        .unwrap();
    builder
        .add_orchard_output::<zip317::FeeRule>(
            Some(fvk.to_ovk(orchard::keys::Scope::Internal)),
            fvk.address_at(0u32, orchard::keys::Scope::Internal),
            Zatoshis::const_from_u64(890_000),
            MemoBytes::empty(),
        )
        .unwrap();
    let result = builder
        .build_for_pczt(OsRng, &zip317::FeeRule::standard())
        .unwrap();
    let index = result.orchard_meta.spend_action_index(0).unwrap();
    let pczt = Creator::build_from_parts(result.pczt_parts).unwrap();
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
    (pczt, index)
}

fn action_alpha(pczt: &Pczt, index: usize) -> [u8; 32] {
    with_spend(pczt, index, |spend| {
        let alpha = spend.alpha().as_ref().expect("alpha is set");
        scalar_bytes(*alpha)
    })
}

fn action_rk(pczt: &Pczt, index: usize) -> [u8; 32] {
    with_spend(pczt, index, |spend| spend.rk().clone().into())
}

fn action_signature(pczt: &Pczt, index: usize) -> Option<[u8; 64]> {
    with_spend(pczt, index, |spend| {
        spend
            .spend_auth_sig()
            .as_ref()
            .map(|signature| <[u8; 64]>::from(signature))
    })
}

fn with_spend<T>(pczt: &Pczt, index: usize, read: impl FnOnce(&orchard::pczt::Spend) -> T) -> T {
    let mut found = None;
    Verifier::new(pczt.clone())
        .with_orchard::<Infallible, _>(|bundle| {
            found = Some(read(bundle.actions()[index].spend()));
            Ok(())
        })
        .expect("orchard bundle parses");
    found.expect("closure ran")
}

fn scalar_bytes(scalar: pallas::Scalar) -> [u8; 32] {
    let repr = scalar.to_repr();
    let bytes: &[u8] = repr.as_ref();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

fn pre_nu6_3_test_network() -> zcash_protocol::local_consensus::LocalNetwork {
    zcash_protocol::local_consensus::LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(2)),
        blossom: Some(BlockHeight::from_u32(3)),
        heartwood: Some(BlockHeight::from_u32(4)),
        canopy: Some(BlockHeight::from_u32(5)),
        nu5: Some(BlockHeight::from_u32(6)),
        nu6: Some(BlockHeight::from_u32(7)),
        nu6_1: Some(BlockHeight::from_u32(8)),
        nu6_2: Some(BlockHeight::from_u32(9)),
        nu6_3: None,
    }
}
