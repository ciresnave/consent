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
pub const MASKS_FILE: &str = "masks.json";
// `approvals.key` and `approvals.json` are no longer read: approvals live in
// the user-request store since #2b, so an old copy put back grants nothing.
pub const AUDIT_FILE: &str = "access.log";

pub fn default_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(base).join("OverMind").join("with-secret"))
}

/// Write via a sibling temp file and rename, so a crash never leaves a
/// half-written vault - which `load` would then refuse.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
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

    /// `masks` is the already-serialised `masks.json` (`mask::masks_json`), so
    /// this module never depends on `mask.rs`.
    pub fn save(&self, vault: &Vault, masks: Vec<u8>) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("create {}: {e}", self.dir.display()))?;
        let plain = serde_json::to_vec(vault).map_err(|e| e.to_string())?;
        let blob = self.protector.protect(&plain)?;
        write_atomic(&self.dir.join(VAULT_FILE), &blob)?;
        write_atomic(&self.dir.join(MASKS_FILE), &masks)
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
        assert_eq!(std::fs::read(dir.path().join("masks.json")).unwrap(), b"[]");
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
