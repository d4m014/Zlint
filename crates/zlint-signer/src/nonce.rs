//! Round-1 nonce file for one FROST share.
//! The file is mode 0600. It is deleted before the signature share is produced.
//! A commitment for the same sighash is reused. A different sighash is refused.

use crate::frost::{self, KeyPackage, PublicKeyPackage, Round1, SigningCommitments, SigningNonces};
use crate::Identifier;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const REQUIRED_MODE: u32 = 0o600;
const MAX_BYTES: u64 = 64 * 1024;

/// Public round-1 output. This is what the other signer needs. It holds no nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCommit {
    pub identifier: Identifier,
    pub commitment: SigningCommitments,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceBody {
    version: u32,
    role: String,
    sighash: String,
    alpha: String,
    action_index: u32,
    identifier: Identifier,
    commitment: SigningCommitments,
    nonces: SigningNonces,
}

struct LoadedNonce {
    sighash: [u8; 32],
    alpha: [u8; 32],
    action_index: u32,
    identifier: Identifier,
    commitment: SigningCommitments,
    nonces: SigningNonces,
}

/// Store a fresh round-1 commitment.
/// The same sighash returns the commitment already on disk and drops `round`.
/// A different sighash is left untouched.
pub fn store_round1(
    path: &Path,
    round: Round1,
    sighash: [u8; 32],
    alpha: [u8; 32],
    action_index: u32,
) -> Result<PublicCommit, String> {
    if path.exists() {
        let loaded = read_nonce(path)?;
        if loaded.sighash != sighash
            || loaded.alpha != alpha
            || loaded.action_index != action_index
            || loaded.identifier != round.id
        {
            return Err(mismatch_message(&loaded, sighash));
        }
        return Ok(PublicCommit {
            identifier: loaded.identifier,
            commitment: loaded.commitment,
        });
    }
    write_nonce(
        path,
        &NonceBody {
            version: 1,
            role: "nonce".into(),
            sighash: hex::encode(sighash),
            alpha: hex::encode(alpha),
            action_index,
            identifier: round.id,
            commitment: round.commitment,
            nonces: round.nonces,
        },
    )?;
    Ok(PublicCommit {
        identifier: round.id,
        commitment: round.commitment,
    })
}

/// Delete a nonce file when its sighash is `sighash`. A different sighash is left in place.
/// A missing file is not an error.
pub fn discard_matching_round(path: &Path, sighash: &[u8; 32]) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let loaded = read_nonce(path)?;
    if loaded.sighash != *sighash {
        return Ok(());
    }
    remove_nonce(path)
}

/// Delete the nonce file, then sign. The nonce is gone before `sign` runs.
pub fn sign_with_round1(
    path: &Path,
    key: &KeyPackage,
    group: &PublicKeyPackage,
    theirs: &PublicCommit,
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    action_index: u32,
) -> Result<frost::SignatureShare, String> {
    let other = frost::other_identifier(key, group)?;
    if theirs.identifier != other || theirs.identifier == *key.identifier() {
        return Err("the other commitment must be the other share".into());
    }
    if !path.exists() {
        return Err("no commitment is waiting for this transaction".into());
    }
    let stored = take_round1(path, sighash, alpha, action_index, *key.identifier())?;
    let mut commitments = std::collections::BTreeMap::new();
    commitments.insert(stored.identifier, stored.commitment);
    commitments.insert(theirs.identifier, theirs.commitment);
    frost::sign_share(key, stored.nonces, &commitments, sighash, alpha)
}

fn mismatch_message(loaded: &LoadedNonce, sighash: [u8; 32]) -> String {
    if loaded.sighash != sighash {
        "a nonce file for a different transaction already exists".into()
    } else {
        "nonce file does not match this transaction".into()
    }
}

fn take_round1(
    path: &Path,
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    action_index: u32,
    identifier: Identifier,
) -> Result<LoadedNonce, String> {
    let loaded = read_nonce(path)?;
    if loaded.sighash != *sighash
        || loaded.alpha != *alpha
        || loaded.action_index != action_index
        || loaded.identifier != identifier
    {
        return Err(mismatch_message(&loaded, *sighash));
    }
    remove_nonce(path)?;
    Ok(loaded)
}

fn remove_nonce(path: &Path) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_nonce(path: &Path) -> Result<LoadedNonce, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != REQUIRED_MODE {
        return Err(format!("nonce file mode is {mode:o}, required mode is 600"));
    }
    if meta.len() > MAX_BYTES {
        return Err(format!("{} is too large", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let body: NonceBody =
        serde_json::from_str(&text).map_err(|_| "nonce file was not understood".to_string())?;
    if body.version != 1 {
        return Err("nonce file has an unsupported version".into());
    }
    if body.role != "nonce" {
        return Err("nonce file has a bad role".into());
    }
    Ok(LoadedNonce {
        sighash: decode_32(&body.sighash)?,
        alpha: decode_32(&body.alpha)?,
        action_index: body.action_index,
        identifier: body.identifier,
        commitment: body.commitment,
        nonces: body.nonces,
    })
}

fn decode_32(hex_text: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_text).map_err(|_| "nonce file was not understood".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "nonce file was not understood".to_string())
}

fn write_nonce(path: &Path, body: &NonceBody) -> Result<(), String> {
    let json = serde_json::to_string(body).map_err(|_| "could not encode the nonce file")?;
    if json.len() as u64 > MAX_BYTES {
        return Err("nonce file would be too large".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(REQUIRED_MODE)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(json.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(b"\n")
        .map_err(|e| format!("{}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(REQUIRED_MODE))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{
        aggregate_shares, commit, group_verifying_key, randomize_verifying_key, verify_spend_auth,
    };
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_same_sighash_is_reused_and_signing_deletes_the_file() {
        let dir = std::env::temp_dir().join(format!("zlint-nonce-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dealt = crate::frost::deal_two_of_two().unwrap();
        let sighash = [9u8; 32];
        let alpha = [3u8; 32];
        let first_path = dir.join("share1.nonce");
        let second_path = dir.join("share2.nonce");

        let first_round = commit(&dealt.share1);
        let first_commit = first_round.commitment;
        let stored = store_round1(first_path.as_path(), first_round, sighash, alpha, 0).unwrap();
        assert_eq!(stored.commitment, first_commit);
        let mode = std::fs::metadata(&first_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let bytes = std::fs::read(&first_path).unwrap();
        let again = store_round1(
            first_path.as_path(),
            commit(&dealt.share1),
            sighash,
            alpha,
            0,
        )
        .unwrap();
        assert_eq!(again, stored);
        assert_eq!(std::fs::read(&first_path).unwrap(), bytes);

        let other = store_round1(
            first_path.as_path(),
            commit(&dealt.share1),
            [1u8; 32],
            alpha,
            0,
        );
        assert!(other.is_err());
        assert!(other.unwrap_err().contains("different transaction"));
        assert_eq!(std::fs::read(&first_path).unwrap(), bytes);

        std::fs::set_permissions(&first_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loose = store_round1(
            first_path.as_path(),
            commit(&dealt.share1),
            sighash,
            alpha,
            0,
        );
        assert!(loose.unwrap_err().contains("600"));
        std::fs::set_permissions(&first_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let second_round = commit(&dealt.share2);
        let second = store_round1(second_path.as_path(), second_round, sighash, alpha, 0).unwrap();
        let share1 = sign_with_round1(
            &first_path,
            &dealt.share1,
            &dealt.group,
            &second,
            &sighash,
            &alpha,
            0,
        )
        .unwrap();
        assert!(!first_path.exists());
        let share2 = sign_with_round1(
            &second_path,
            &dealt.share2,
            &dealt.group,
            &stored,
            &sighash,
            &alpha,
            0,
        )
        .unwrap();
        assert!(!second_path.exists());

        let mut commitments = BTreeMap::new();
        commitments.insert(stored.identifier, stored.commitment);
        commitments.insert(second.identifier, second.commitment);
        let mut shares = BTreeMap::new();
        shares.insert(stored.identifier, share1);
        let missing = aggregate_shares(&commitments, &sighash, &shares, &dealt.group, &alpha);
        assert!(missing.is_err());
        shares.insert(second.identifier, share2);
        let signature =
            aggregate_shares(&commitments, &sighash, &shares, &dealt.group, &alpha).unwrap();
        let group_key = group_verifying_key(&dealt.group).unwrap();
        let rk = randomize_verifying_key(group_key, &alpha).unwrap();
        verify_spend_auth(rk, &sighash, signature).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
