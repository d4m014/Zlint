//! Share file for the co-signer process.
//! A simulated file is not a Zcash key.
//! A FROST file holds share 2 of a trusted-dealer RedPallas key.
//! Callers check that the mode is `0600`. The id is not returned.

use crate::frost::{self, FrostKey, KeyPackage, PublicKeyPackage};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const REQUIRED_MODE: u32 = 0o600;
const MAX_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareKind {
    Simulated,
    Frost,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareBody {
    version: u32,
    role: String,
    signer: String,
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_package: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_package: Option<serde_json::Value>,
}

/// A FROST share read from disk. The id is dropped.
pub struct LoadedFrostShare {
    pub role: String,
    pub key: KeyPackage,
    pub group: PublicKeyPackage,
}

/// Read a share file and reject it unless only the owner can read it.
/// The parsed id is dropped here so a caller cannot print it by accident.
pub fn require_share(path: &Path) -> Result<ShareKind, String> {
    let parsed = read_share(path)?;
    if parsed.role != "share2" {
        return Err(format!("{} is not share 2", path.display()));
    }
    Ok(parsed.kind)
}

/// The JSON co-signer accepts a simulated share only.
/// A FROST share signs a PCZT sighash, not a proposal.
pub fn require_simulated_share(path: &Path) -> Result<(), String> {
    match require_share(path)? {
        ShareKind::Simulated => Ok(()),
        ShareKind::Frost => Err("this share signs a PCZT sighash, not a proposal".into()),
    }
}

/// Read a FROST share. Accepts share 1 or share 2. The id is dropped.
pub fn load_frost_share(path: &Path) -> Result<LoadedFrostShare, String> {
    let parsed = read_share(path)?;
    if parsed.kind != ShareKind::Frost {
        return Err(format!("{} is not a FROST share", path.display()));
    }
    let (key, group) = parsed.frost.expect("frost share has packages");
    Ok(LoadedFrostShare {
        role: parsed.role,
        key,
        group,
    })
}

/// Create a new simulated share file. Refuses to replace an existing one.
pub fn create_share(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    write_body(path, simulated_body("share2")?)?;
    match require_share(path)? {
        ShareKind::Simulated => Ok(()),
        ShareKind::Frost => Err("simulated share file was saved as frost".into()),
    }
}

/// Write one FROST share that the caller already holds. Refuses to replace a file.
pub fn save_frost_share(
    path: &Path,
    role: &str,
    key: &KeyPackage,
    group: &PublicKeyPackage,
) -> Result<(), String> {
    if role != "share1" && role != "share2" {
        return Err("role must be share 1 or share 2".into());
    }
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    frost::check_share_matches_group(key, group)?;
    write_body(path, frost_body(role, key, group)?)
}

/// Write share 1 and share 2 from a fresh trusted dealer.
/// This process sees both shares. Refuses to replace an existing file.
pub fn create_frost_shares(share1: &Path, share2: &Path) -> Result<(), String> {
    if share1 == share2 {
        return Err("share 1 and share 2 are the same path".into());
    }
    if share1.exists() {
        return Err(format!("{} already exists", share1.display()));
    }
    if share2.exists() {
        return Err(format!("{} already exists", share2.display()));
    }
    let dealt = frost::deal_two_of_two()?;
    if let Err(err) = write_frost_pair(share1, share2, &dealt) {
        let _ = std::fs::remove_file(share1);
        let _ = std::fs::remove_file(share2);
        return Err(err);
    }
    Ok(())
}

struct ParsedShare {
    kind: ShareKind,
    role: String,
    frost: Option<(KeyPackage, PublicKeyPackage)>,
}

fn read_share(path: &Path) -> Result<ParsedShare, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode != REQUIRED_MODE {
        return Err(format!("share file mode is {mode:o}, required mode is 600"));
    }
    if meta.len() > MAX_BYTES {
        return Err(format!("{} is too large", path.display()));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let body: ShareBody = serde_json::from_str(&text)
        .map_err(|_| format!("{} is not a share file", path.display()))?;
    if body.version != 1 {
        return Err(format!("{} has unsupported version", path.display()));
    }
    if body.role != "share1" && body.role != "share2" {
        return Err(format!("{} has a bad role", path.display()));
    }
    if body.id.len() != 32 || !body.id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{} has a bad share id", path.display()));
    }
    match body.signer.as_str() {
        "simulated" => {
            if body.key_package.is_some() || body.group_package.is_some() {
                return Err("simulated share file has key material".into());
            }
            Ok(ParsedShare {
                kind: ShareKind::Simulated,
                role: body.role,
                frost: None,
            })
        }
        "frost" => {
            let key_package = body
                .key_package
                .as_ref()
                .ok_or_else(|| format!("{} is missing its key package", path.display()))?;
            let group_package = body
                .group_package
                .as_ref()
                .ok_or_else(|| format!("{} is missing its group key", path.display()))?;
            let key = frost::decode_key_package(key_package)?;
            let group = frost::decode_group_package(group_package)?;
            frost::check_share_matches_group(&key, &group)?;
            Ok(ParsedShare {
                kind: ShareKind::Frost,
                role: body.role,
                frost: Some((key, group)),
            })
        }
        _ => Err(format!("{} signer is not supported", path.display())),
    }
}

fn write_frost_pair(share1: &Path, share2: &Path, dealt: &FrostKey) -> Result<(), String> {
    write_body(share1, frost_body("share1", &dealt.share1, &dealt.group)?)?;
    if let Err(err) = write_body(share2, frost_body("share2", &dealt.share2, &dealt.group)?) {
        let _ = std::fs::remove_file(share1);
        return Err(err);
    }
    match require_share(share2)? {
        ShareKind::Frost => {}
        ShareKind::Simulated => return Err("frost share file was saved as simulated".into()),
    }
    let err = match require_share(share1) {
        Err(err) => err,
        Ok(_) => return Err(format!("{} was accepted as share 2", share1.display())),
    };
    if !err.contains("share 2") {
        return Err(err);
    }
    load_frost_share(share1).map(|_| ())
}

fn simulated_body(role: &str) -> Result<ShareBody, String> {
    Ok(ShareBody {
        version: 1,
        role: role.into(),
        signer: "simulated".into(),
        id: random_id()?,
        key_package: None,
        group_package: None,
    })
}

fn frost_body(role: &str, key: &KeyPackage, group: &PublicKeyPackage) -> Result<ShareBody, String> {
    Ok(ShareBody {
        version: 1,
        role: role.into(),
        signer: "frost".into(),
        id: random_id()?,
        key_package: Some(
            serde_json::to_value(key).map_err(|_| "could not encode the key package")?,
        ),
        group_package: Some(
            serde_json::to_value(group).map_err(|_| "could not encode the group key")?,
        ),
    })
}

fn write_body(path: &Path, body: ShareBody) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(&body).map_err(|_| "could not encode the share file")?;
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

fn random_id() -> Result<String, String> {
    let mut id_bytes = [0u8; 16];
    let mut random =
        std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
    std::io::Read::read_exact(&mut random, &mut id_bytes).map_err(|e| e.to_string())?;
    Ok(hex::encode(id_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frost::{
        aggregate_shares, commit, group_verifying_key, randomize_verifying_key, sign_share,
        verify_spend_auth,
    };
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    fn dir(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "zlint-share-{name}-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn create_is_owner_only_and_refuses_to_replace() {
        let dir = dir("create");
        let path = dir.join("share.json");
        create_share(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let again = create_share(&path);
        assert!(again.is_err());
        assert_eq!(require_share(&path).unwrap(), ShareKind::Simulated);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_group_readable_file_is_refused() {
        let dir = dir("loose");
        let path = dir.join("share.json");
        create_share(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = require_share(&path).unwrap_err();
        assert!(err.contains("600"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_not_share_2_is_refused() {
        let dir = dir("role");
        let path = dir.join("share.json");
        std::fs::write(&path, "{\"version\":1,\"role\":\"share1\",\"signer\":\"simulated\",\"id\":\"0123456789abcdef0123456789abcdef\"}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = require_share(&path).unwrap_err();
        assert!(err.contains("share 2"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn frost_share_round_trips_and_is_refused_for_a_proposal() {
        let dir = dir("frost");
        let share1 = dir.join("share1.json");
        let share2 = dir.join("share2.json");
        create_frost_shares(&share1, &share2).unwrap();
        for path in [&share1, &share2] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(require_share(&share2).unwrap(), ShareKind::Frost);
        let err = require_share(&share1).unwrap_err();
        assert!(err.contains("share 2"), "{err}");
        let err = require_simulated_share(&share2).unwrap_err();
        assert!(err.contains("PCZT"), "{err}");
        let id =
            serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&share2).unwrap())
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string();
        assert!(!err.contains(&id), "error included the share id");

        let loaded1 = load_frost_share(&share1).unwrap();
        let loaded2 = load_frost_share(&share2).unwrap();
        assert_eq!(loaded1.role, "share1");
        assert_eq!(loaded2.role, "share2");
        let message = b"from-disk";
        let randomizer = [3u8; 32];
        let first = commit(&loaded1.key);
        let second = commit(&loaded2.key);
        let mut commitments = BTreeMap::new();
        commitments.insert(first.id, first.commitment);
        commitments.insert(second.id, second.commitment);
        let part1 = sign_share(
            &loaded1.key,
            first.nonces,
            &commitments,
            message,
            &randomizer,
        )
        .unwrap();
        let part2 = sign_share(
            &loaded2.key,
            second.nonces,
            &commitments,
            message,
            &randomizer,
        )
        .unwrap();
        let mut shares = BTreeMap::new();
        shares.insert(first.id, part1);
        assert!(
            aggregate_shares(&commitments, message, &shares, &loaded2.group, &randomizer).is_err()
        );
        shares.insert(second.id, part2);
        let signature =
            aggregate_shares(&commitments, message, &shares, &loaded2.group, &randomizer).unwrap();
        let vk = group_verifying_key(&loaded2.group).unwrap();
        let rk = randomize_verifying_key(vk, &randomizer).unwrap();
        verify_spend_auth(rk, message, signature).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
