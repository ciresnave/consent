// SPDX-License-Identifier: MIT OR Apache-2.0
//! The vault model. ⚠️ `Secret::value` is the only plaintext in this crate's
//! data model; it never appears in `Debug`, argv, logs or any environment
//! except the one child `with-secret` starts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Masking a short value would rewrite ordinary words in command output, and a
/// short secret is weak anyway.
pub const MIN_VALUE_LEN: usize = 12;

pub fn validate_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let ok = name.len() >= 2
        && name.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "secret names are UPPER_SNAKE, 2-64 chars, starting with a letter; got {name:?}"
        ))
    }
}

pub fn validate_value(value: &str) -> Result<(), String> {
    if value.chars().count() < MIN_VALUE_LEN {
        return Err(format!(
            "a secret must be at least {MIN_VALUE_LEN} characters"
        ));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err("a secret must be one line".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Secret {
    pub value: String,
    /// The variable name the child sees, e.g. `DATABASE_URL`.
    pub env_var: String,
    pub access: Access,
    pub created_at: DateTime<Utc>,
    /// Least privilege (e): a write credential should be short-lived. Nothing
    /// enforces rotation; `vault list` flags a secret past this date.
    pub rotate_by: Option<NaiveDate>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("value", &"<redacted>")
            .field("env_var", &self.env_var)
            .field("access", &self.access)
            .field("created_at", &self.created_at)
            .field("rotate_by", &self.rotate_by)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Vault {
    pub secrets: BTreeMap<String, Secret>,
}

/// Encrypt and decrypt bytes at rest. ⚠️ The real one is DPAPI at user scope
/// (`dpapi.rs`): it protects against copies of the disk, NOT against another
/// process running as the same user (design §3).
pub trait Protector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String>;
}

pub const VAULT_FILE: &str = "vault.bin";
/// The hook's masks, protected like the vault. ⚠️ Row 5: they used to sit in
/// `masks.json` as plain salted SHA-256, so a COPY of that file was a fast
/// offline check of guessed values. A slow KDF was not an option: the hook
/// hashes every window of every tool output.
pub const MASKS_FILE: &str = "masks.bin";
/// The pre-0.7 plaintext masks file. Read only to migrate it, then deleted.
pub const LEGACY_MASKS_FILE: &str = "masks.json";
/// Where a pre-0.7 write of `masks.json` staged its PLAINTEXT; a crash could
/// leave it behind.
pub const LEGACY_MASKS_TMP: &str = "masks.tmp";
// `approvals.key` and `approvals.json` are no longer read: approvals live in
// the user-request store since #2b, so an old copy put back grants nothing.
pub const AUDIT_FILE: &str = "access.log";
/// A `write_atomic` temp file this old is a leftover, not a write in flight.
pub const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

pub fn default_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(base).join("OverMind").join("with-secret"))
}

/// Write via a sibling temp file and rename, so a crash never leaves a
/// half-written vault - which `load` would then refuse. ⚠️ The temp name is
/// unique per write: hooks run concurrently, and with one fixed name a second
/// writer could truncate the file the first had just renamed into place.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| format!("random temp name: {e}"))?;
    let tmp = path.with_extension(format!(
        "{}.{:016x}.tmp",
        std::process::id(),
        u64::from_le_bytes(nonce)
    ));
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
}

pub struct VaultStore<P: Protector> {
    pub dir: PathBuf,
    pub protector: P,
}

impl<P: Protector> VaultStore<P> {
    pub fn load(&self) -> Result<Vault, String> {
        let path = self.dir.join(VAULT_FILE);
        let blob = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vault::default()),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let plain = self
            .protector
            .unprotect(&blob)
            .map_err(|e| format!("the vault exists but cannot be decrypted: {e}"))?;
        serde_json::from_slice(&plain)
            .map_err(|e| format!("the vault decrypted but is not valid: {e}"))
    }

    /// `masks` is the already-serialised masks list (`mask::masks_json`), so
    /// this module never depends on `mask.rs`. It is stored protected.
    pub fn save(&self, vault: &Vault, masks: Vec<u8>) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("create {}: {e}", self.dir.display()))?;
        let plain = serde_json::to_vec(vault).map_err(|e| e.to_string())?;
        let blob = self.protector.protect(&plain)?;
        write_atomic(&self.dir.join(VAULT_FILE), &blob)?;
        write_atomic(&self.dir.join(MASKS_FILE), &self.protector.protect(&masks)?)?;
        remove_if_present(&self.dir.join(LEGACY_MASKS_FILE))
    }

    /// Seal a legacy `masks.json` into `masks.bin` and delete it, along with
    /// the plaintext `masks.tmp` a crashed pre-0.7 write could leave. A
    /// `masks.json` that is not a JSON list is deleted WITHOUT replacing
    /// `masks.bin`. ⚠️ Its salts stay the same: renewing them needs the vault,
    /// which the hook never opens (design §2.4). The next `vault set` or
    /// `remove` renews them. Failing here never stops masking: `load_masks`
    /// still reads the legacy file while it exists.
    pub fn migrate_legacy_masks(&self) -> Result<(), String> {
        self.remove_stale_temp_files(STALE_TEMP_AGE);
        let legacy = self.dir.join(LEGACY_MASKS_FILE);
        if let Some(plain) = read_legacy(&legacy)? {
            write_atomic(&self.dir.join(MASKS_FILE), &self.protector.protect(&plain)?)?;
        }
        remove_if_present(&legacy)?;
        remove_if_present(&self.dir.join(LEGACY_MASKS_TMP))
    }

    /// Delete leftovers of a `write_atomic` whose rename failed: files named
    /// `masks.<pid>.<16 hex>.tmp` or `vault.<pid>.<16 hex>.tmp` and older than
    /// `max_age`. Best effort: nothing here may stop the hook.
    pub fn remove_stale_temp_files(&self, max_age: std::time::Duration) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.flatten() {
            let is_leftover = entry.file_name().to_str().is_some_and(is_write_atomic_temp);
            let age = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok());
            if is_leftover
                && age.is_some_and(|a| a >= max_age)
                && std::fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
        removed
    }

    /// The masks' plaintext (`mask::masks_json` bytes), or `None` if there are
    /// none. ⚠️ A valid legacy `masks.json` wins over `masks.bin`: only a
    /// pre-0.7 binary writes it, so it is newer (a rollback's `vault set`).
    pub fn load_masks(&self) -> Result<Option<Vec<u8>>, String> {
        let path = self.dir.join(MASKS_FILE);
        if let Some(plain) = read_legacy(&self.dir.join(LEGACY_MASKS_FILE))? {
            return Ok(Some(plain));
        }
        let blob = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        self.protector
            .unprotect(&blob)
            .map(Some)
            .map_err(|e| format!("{} cannot be decrypted: {e}", path.display()))
    }
}

/// `masks.<pid>.<16 hex>.tmp` or `vault.<pid>.<16 hex>.tmp`: the names
/// `write_atomic` gives its temp files. Anything else is not ours to delete.
fn is_write_atomic_temp(name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix("masks.")
        .or_else(|| name.strip_prefix("vault."))
    else {
        return false;
    };
    let Some(rest) = rest.strip_suffix(".tmp") else {
        return false;
    };
    let Some((pid, nonce)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && nonce.len() == 16
        && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The legacy file's bytes if it exists and is a JSON list.
fn read_legacy(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(b) if serde_json::from_slice::<Vec<serde_json::Value>>(&b).is_ok() => Ok(Some(b)),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Two hooks can migrate at once; the loser finds the file already gone.
fn remove_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(format!("remove {}: {e}", path.display()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn secret(value: &str) -> Secret {
        Secret {
            value: value.into(),
            env_var: "DATABASE_URL".into(),
            access: Access::Read,
            created_at: Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap(),
            rotate_by: None,
        }
    }

    #[test]
    fn names_are_upper_snake() {
        assert!(validate_name("TJ_PROD_DATABASE_URL").is_ok());
        for bad in [
            "",
            "A",
            "tj_prod",
            "1ABC",
            "AB-C",
            "vault",
            "hook",
            &"A".repeat(65),
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn short_values_are_refused_because_masking_them_would_garble_output() {
        assert!(validate_value("short").is_err());
        assert!(validate_value(&"x".repeat(MIN_VALUE_LEN)).is_ok());
    }

    #[test]
    fn values_with_newlines_are_refused() {
        assert!(validate_value("postgres://a:b@host/db\nsecond").is_err());
    }

    #[test]
    fn debug_never_prints_the_value() {
        let s = secret("postgres://owner:hunter2hunter2@host/db");
        let shown = format!(
            "{s:?} {:?}",
            Vault {
                secrets: [("X_Y".to_string(), s.clone())].into()
            }
        );
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("DATABASE_URL"));
    }

    #[test]
    fn vault_round_trips_through_json() {
        let mut v = Vault::default();
        v.secrets
            .insert("TJ_DB".into(), secret("postgres://x:yyyyyyyyyyyy@h/d"));
        let back: Vault = serde_json::from_slice(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(back.secrets["TJ_DB"].value, "postgres://x:yyyyyyyyyyyy@h/d");
        assert_eq!(back.secrets["TJ_DB"].access, Access::Read);
    }

    /// Reversible, keyed, and NOT identity - so a test can tell "stored
    /// protected" from "stored plain". Not security; DPAPI is the real one.
    struct XorProtector(u8);
    impl Protector for XorProtector {
        fn protect(&self, p: &[u8]) -> Result<Vec<u8>, String> {
            Ok(p.iter().map(|b| b ^ self.0).collect())
        }
        fn unprotect(&self, b: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b.iter().map(|x| x ^ self.0).collect())
        }
    }
    struct FailingProtector;
    impl Protector for FailingProtector {
        fn protect(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("no".into())
        }
        fn unprotect(&self, _: &[u8]) -> Result<Vec<u8>, String> {
            Err("cannot decrypt".into())
        }
    }

    #[test]
    fn missing_vault_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore {
            dir: dir.path().into(),
            protector: XorProtector(0x5a),
        };
        assert!(store.load().unwrap().secrets.is_empty());
    }

    #[test]
    fn save_then_load_round_trips_and_the_file_is_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore {
            dir: dir.path().into(),
            protector: XorProtector(0x5a),
        };
        let mut v = Vault::default();
        v.secrets
            .insert("TJ_DB".into(), secret("postgres://x:supersecretvalue@h/d"));
        store.save(&v, b"[]".to_vec()).unwrap();
        let raw = std::fs::read(dir.path().join("vault.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("supersecretvalue"));
        assert_eq!(store.load().unwrap(), v);
        assert_eq!(store.load_masks().unwrap().as_deref(), Some(&b"[]"[..]));
    }

    fn xor_store(dir: &Path) -> VaultStore<XorProtector> {
        VaultStore {
            dir: dir.into(),
            protector: XorProtector(0x5a),
        }
    }

    #[test]
    fn save_stores_the_masks_protected_and_drops_a_legacy_masks_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_MASKS_FILE), b"[\"old\"]").unwrap();
        xor_store(dir.path())
            .save(&Vault::default(), b"[\"new\"]".to_vec())
            .unwrap();
        let raw = std::fs::read(dir.path().join(MASKS_FILE)).unwrap();
        assert_eq!(raw, XorProtector(0x5a).protect(b"[\"new\"]").unwrap());
        assert!(!dir.path().join(LEGACY_MASKS_FILE).exists());
    }

    /// A leftover temp file as `write_atomic` names it, last written `age` ago.
    fn leftover(dir: &Path, name: &str, age: std::time::Duration) {
        let path = dir.join(name);
        std::fs::write(&path, b"sealed bytes").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - age)
            .unwrap();
    }

    const DAY2: std::time::Duration = std::time::Duration::from_secs(2 * 24 * 60 * 60);
    const HOUR: std::time::Duration = std::time::Duration::from_secs(60 * 60);

    #[test]
    fn stale_write_atomic_leftovers_are_removed_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        leftover(d, "masks.54596.d8905001dd337276.tmp", DAY2);
        leftover(d, "vault.1.0000000000000001.tmp", DAY2);
        leftover(d, "masks.54596.d8905001dd337277.tmp", HOUR); // a write in flight
        leftover(d, "masks.bin", DAY2); // the real file, however old
        leftover(d, "vault.bin", DAY2);
        leftover(d, "access.log", DAY2);
        leftover(d, "notes.tmp", DAY2); // not our naming
        leftover(d, "masks.abc.d8905001dd337276.tmp", DAY2); // pid not digits
        leftover(d, "masks.1.d8905001dd33727.tmp", DAY2); // 15 hex, not 16
        leftover(d, "masks.1.zzzzzzzzzzzzzzzz.tmp", DAY2); // 16 chars, not hex
        leftover(d, "masks.1.d8905001dd337276.tmp.bak", DAY2);
        let removed = xor_store(d).remove_stale_temp_files(STALE_TEMP_AGE);
        assert_eq!(removed, 2);
        let mut left: Vec<String> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "access.log",
                "masks.1.d8905001dd33727.tmp",
                "masks.1.d8905001dd337276.tmp.bak",
                "masks.1.zzzzzzzzzzzzzzzz.tmp",
                "masks.54596.d8905001dd337277.tmp",
                "masks.abc.d8905001dd337276.tmp",
                "masks.bin",
                "notes.tmp",
                "vault.bin",
            ]
        );
    }

    #[test]
    fn a_missing_directory_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("nope");
        assert_eq!(xor_store(&gone).remove_stale_temp_files(STALE_TEMP_AGE), 0);
    }

    #[test]
    fn migrating_cleans_stale_leftovers_even_when_the_seal_fails() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(d.join(LEGACY_MASKS_FILE), b"[\"old\"]").unwrap();
        std::fs::create_dir(d.join(MASKS_FILE)).unwrap(); // the rename cannot replace a directory
        leftover(d, "masks.9.00000000000000aa.tmp", DAY2);
        assert!(xor_store(d).migrate_legacy_masks().is_err());
        assert!(!d.join("masks.9.00000000000000aa.tmp").exists());
        assert!(d.join(LEGACY_MASKS_FILE).exists(), "masking source kept");
    }

    #[test]
    fn no_masks_file_is_none_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(xor_store(dir.path()).load_masks().unwrap(), None);
    }

    #[test]
    fn a_legacy_masks_json_is_sealed_then_deleted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_MASKS_FILE), b"[\"old\"]").unwrap();
        let store = xor_store(dir.path());
        store.migrate_legacy_masks().unwrap();
        assert!(!dir.path().join(LEGACY_MASKS_FILE).exists());
        let raw = std::fs::read(dir.path().join(MASKS_FILE)).unwrap();
        assert_eq!(raw, XorProtector(0x5a).protect(b"[\"old\"]").unwrap());
        assert_eq!(
            store.load_masks().unwrap().as_deref(),
            Some(&b"[\"old\"]"[..])
        );
    }

    #[test]
    fn a_masks_json_written_after_masks_bin_wins() {
        // Rolled back to 0.6, `vault set` writes masks.json with the new
        // secret; masks.bin is now stale and must not hide that secret.
        let dir = tempfile::tempdir().unwrap();
        let store = xor_store(dir.path());
        store
            .save(&Vault::default(), b"[\"stale\"]".to_vec())
            .unwrap();
        std::fs::write(dir.path().join(LEGACY_MASKS_FILE), b"[\"rollback\"]").unwrap();
        assert_eq!(
            store.load_masks().unwrap().as_deref(),
            Some(&b"[\"rollback\"]"[..])
        );
        store.migrate_legacy_masks().unwrap();
        assert!(!dir.path().join(LEGACY_MASKS_FILE).exists());
        assert_eq!(
            store.load_masks().unwrap().as_deref(),
            Some(&b"[\"rollback\"]"[..])
        );
    }

    #[test]
    fn a_failed_seal_still_masks_from_the_legacy_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_MASKS_FILE), b"[\"old\"]").unwrap();
        let store = VaultStore {
            dir: dir.path().into(),
            protector: FailingProtector,
        };
        assert!(store.migrate_legacy_masks().is_err());
        assert!(dir.path().join(LEGACY_MASKS_FILE).exists());
        assert_eq!(
            store.load_masks().unwrap().as_deref(),
            Some(&b"[\"old\"]"[..])
        );
    }

    #[test]
    fn a_garbage_masks_json_never_replaces_masks_bin() {
        let dir = tempfile::tempdir().unwrap();
        let store = xor_store(dir.path());
        store
            .save(&Vault::default(), b"[\"good\"]".to_vec())
            .unwrap();
        std::fs::write(dir.path().join(LEGACY_MASKS_FILE), b"").unwrap();
        assert_eq!(
            store.load_masks().unwrap().as_deref(),
            Some(&b"[\"good\"]"[..])
        );
        store.migrate_legacy_masks().unwrap();
        assert!(!dir.path().join(LEGACY_MASKS_FILE).exists());
        assert_eq!(
            store.load_masks().unwrap().as_deref(),
            Some(&b"[\"good\"]"[..])
        );
    }

    #[test]
    fn migration_deletes_a_plaintext_masks_tmp() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_MASKS_TMP), b"[\"old\"]").unwrap();
        xor_store(dir.path()).migrate_legacy_masks().unwrap();
        assert!(!dir.path().join(LEGACY_MASKS_TMP).exists());
    }

    #[test]
    fn writes_never_stage_through_a_fixed_temp_name() {
        // Concurrent hooks sharing one temp name could truncate a file
        // another had just renamed into place. A directory squatting on the
        // old fixed names makes any write through them fail.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("masks.tmp")).unwrap();
        std::fs::create_dir(dir.path().join("vault.tmp")).unwrap();
        let store = xor_store(dir.path());
        store
            .save(&Vault::default(), b"[\"new\"]".to_vec())
            .unwrap();
        assert_eq!(
            store.load_masks().unwrap().as_deref(),
            Some(&b"[\"new\"]"[..])
        );
    }

    #[test]
    fn an_undecryptable_masks_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MASKS_FILE), b"garbage").unwrap();
        let store = VaultStore {
            dir: dir.path().into(),
            protector: FailingProtector,
        };
        assert!(store.load_masks().is_err());
    }

    #[test]
    fn an_undecryptable_vault_is_an_error_not_an_empty_vault() {
        // ⚠️ Treating it as empty would let `vault set` silently overwrite
        // every stored secret with a one-entry vault.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vault.bin"), b"garbage").unwrap();
        let store = VaultStore {
            dir: dir.path().into(),
            protector: FailingProtector,
        };
        assert!(store.load().is_err());
    }
}
