// SPDX-License-Identifier: MIT OR Apache-2.0
//! Row 5: a COPY of the data directory must give no fast offline check of a
//! guessed value. The masks file used to hold each secret's length and
//! `SHA-256(salt ‖ value)` in the clear, so a copied file let anyone test
//! billions of guesses a second without the vault, DPAPI or Hello.
//!
//! The copier is modelled as someone holding the files' bytes but not the
//! protector's key: every file that parses as masks is tried against the
//! true value, which is the strongest guess there is.

use chrono::Utc;
use with_secret::mask::{mask_with_hashes, masks_json, HashMask};
use with_secret::vault::{Access, Protector, Secret, Vault, VaultStore};

const VALUE: &str = "postgres://owner:Sup3rS3cretValue@db/tj";

/// Keyed and reversible; the copier does not hold the key. Not security -
/// DPAPI is the real one, tested below on Windows.
struct XorProtector(u8);
impl Protector for XorProtector {
    fn protect(&self, p: &[u8]) -> Result<Vec<u8>, String> {
        Ok(p.iter().map(|b| b ^ self.0).collect())
    }
    fn unprotect(&self, b: &[u8]) -> Result<Vec<u8>, String> {
        Ok(b.iter().map(|x| x ^ self.0).collect())
    }
}

fn vault() -> Vault {
    let mut v = Vault::default();
    v.secrets.insert(
        "TJ_DB".into(),
        Secret {
            value: VALUE.into(),
            env_var: "DATABASE_URL".into(),
            access: Access::Read,
            created_at: Utc::now(),
            rotate_by: None,
        },
    );
    v
}

/// Every offline hit a copier gets from the directory's bytes alone.
fn offline_hits(dir: &std::path::Path, expected_files: usize) -> usize {
    let mut files = 0;
    let mut hits = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        files += 1;
        if let Ok(masks) = serde_json::from_slice::<Vec<HashMask>>(&bytes) {
            hits += mask_with_hashes(VALUE, &masks).1;
        }
    }
    // Positive control: every file the store should have left was read.
    assert_eq!(files, expected_files, "unexpected file count in {dir:?}");
    hits
}

fn copied_store_gives_no_offline_check<P: Protector>(protector: P) {
    let dir = tempfile::tempdir().unwrap();
    let store = VaultStore {
        dir: dir.path().into(),
        protector,
    };
    let v = vault();
    store.save(&v, masks_json(&v).unwrap()).unwrap();
    assert_eq!(
        offline_hits(dir.path(), 2),
        0,
        "a copied file checks a guess"
    );
}

#[test]
fn a_copied_masks_file_gives_no_offline_check() {
    copied_store_gives_no_offline_check(XorProtector(0x5a));
}

#[cfg(windows)]
#[test]
fn a_copied_dpapi_masks_file_gives_no_offline_check() {
    copied_store_gives_no_offline_check(with_secret::dpapi::DpapiProtector);
}

/// A 0.6 install left plaintext masks.json, and a crashed 0.6 write left
/// plaintext masks.tmp. After the hook's migration, a copy checks nothing.
fn copied_store_after_migration_gives_no_offline_check<P: Protector>(protector: P) {
    let dir = tempfile::tempdir().unwrap();
    let plain = masks_json(&vault()).unwrap();
    std::fs::write(dir.path().join("masks.json"), &plain).unwrap();
    std::fs::write(dir.path().join("masks.tmp"), &plain).unwrap();
    assert_eq!(
        offline_hits(dir.path(), 2),
        2,
        "control: legacy files check a guess"
    );
    let store = VaultStore {
        dir: dir.path().into(),
        protector,
    };
    store.migrate_legacy_masks().unwrap();
    assert_eq!(
        offline_hits(dir.path(), 1),
        0,
        "a copied file checks a guess"
    );
    // ...and the hook still has the masks.
    assert_eq!(store.load_masks().unwrap(), Some(plain));
}

#[test]
fn a_copied_store_after_migration_gives_no_offline_check() {
    copied_store_after_migration_gives_no_offline_check(XorProtector(0x5a));
}

#[cfg(windows)]
#[test]
fn a_copied_dpapi_store_after_migration_gives_no_offline_check() {
    copied_store_after_migration_gives_no_offline_check(with_secret::dpapi::DpapiProtector);
}

/// The control for the copied-store tests above: the same query DOES find the value
/// in a plaintext masks list, so a zero there is not a broken query.
#[test]
fn control_a_plaintext_masks_list_is_an_offline_check() {
    let masks: Vec<HashMask> = serde_json::from_slice(&masks_json(&vault()).unwrap()).unwrap();
    assert_eq!(mask_with_hashes(VALUE, &masks).1, 1);
}
