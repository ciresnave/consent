// SPDX-License-Identifier: MIT OR Apache-2.0
//! The store key at rest where there is no DPAPI: a tiered `Protector`
//! (docs/LINUX-PORT-DESIGN.md section 2).
//!
//! Every blob names the tier that wrote it (`UR1\0<tag>\0<tier blob>`), and
//! only that tier may open it: a blob whose tier is missing is an error that
//! names the tier, never a silent re-wrap by another one.
//!
//! ⚠️ The `keyfile` tier is WEAKER than DPAPI user scope. Its key is a file in
//! the same state tree as the store, so a copy or backup of the tree carries
//! both, and any process running as this user can read it. It keeps other
//! users out by file permission and nothing more. It is shown by `list`.

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::store::{KeyError, Protector};

/// Starts every blob this module writes. A blob without it is not ours.
pub const MAGIC: &[u8] = b"UR1\0";

/// What `store.key` says about how the key is protected.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyTier {
    /// No key yet: nothing has been stored.
    Missing,
    /// `store.key` exists and cannot be read right now.
    Unreadable,
    /// A tiered blob, protected by this tier.
    Tier(String),
    /// An unprefixed blob on Windows: DPAPI user scope.
    LegacyDpapi,
    /// An unprefixed blob where only tiered blobs are written.
    Foreign,
}

impl KeyTier {
    /// The line `list` prints, always, including when the store cannot be
    /// trusted.
    pub fn describe(&self) -> String {
        match self {
            KeyTier::Missing => "key: none yet".into(),
            KeyTier::Unreadable => "key protected by: UNKNOWN (store.key cannot be read)".into(),
            KeyTier::LegacyDpapi => "key protected by: dpapi".into(),
            KeyTier::Foreign => {
                "key protected by: UNKNOWN (store.key is not a blob this build writes)".into()
            }
            KeyTier::Tier(t) if t == KeyFile::TAG => format!(
                "key protected by: {t}\n\
                 weakest tier: the key sits beside the store, readable by any process running as \
                 this user and carried by any copy or backup of that directory; it only keeps \
                 other users out"
            ),
            KeyTier::Tier(t) => format!("key protected by: {t}"),
        }
    }
}

/// Reads only the prefix of `<dir>/store.key`: it needs no protector, so it
/// works for an untrusted or unreadable store.
pub fn key_tier(dir: &Path) -> KeyTier {
    match std::fs::read(dir.join("store.key")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => KeyTier::Missing,
        Err(_) => KeyTier::Unreadable,
        Ok(blob) => match parse(&blob) {
            Some((tag, _)) => KeyTier::Tier(tag.to_string()),
            None if cfg!(windows) => KeyTier::LegacyDpapi,
            None => KeyTier::Foreign,
        },
    }
}

/// `(tag, tier blob)` of a tiered blob, or `None` if it is not one.
fn parse(blob: &[u8]) -> Option<(&str, &[u8])> {
    let rest = blob.strip_prefix(MAGIC)?;
    let end = rest.iter().position(|&b| b == 0)?;
    let tag = std::str::from_utf8(&rest[..end]).ok()?;
    if tag.is_empty() {
        return None;
    }
    Some((tag, &rest[end + 1..]))
}

/// One way of keeping the key at rest.
pub trait Tier {
    fn tag(&self) -> &'static str;
    /// Whether this tier can be used right now, and why not if it cannot.
    fn available(&self) -> Result<(), String>;
    /// `aad` binds the tier and the tool (purpose) to the blob.
    fn protect(&self, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, KeyError>;
}

/// The first available tier writes; the blob's own tag chooses on every read.
pub struct TieredProtector {
    /// Which tool's key this is (`user-request`, `with-secret`): bound into
    /// the blob so one tool's key does not open in the other.
    purpose: &'static str,
    tiers: Vec<Box<dyn Tier>>,
}

impl TieredProtector {
    pub fn new(purpose: &'static str, tiers: Vec<Box<dyn Tier>>) -> Self {
        Self { purpose, tiers }
    }

    /// The tiers this build has, best first. Only `keyfile` exists in this
    /// slice; `secret-service` and `tpm2` are opt-in features that add
    /// themselves ahead of it (design section 2).
    pub fn standard(purpose: &'static str, kek: PathBuf) -> Self {
        Self::new(purpose, vec![Box::new(KeyFile::new(kek))])
    }

    fn aad(&self, tag: &str) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(self.purpose.as_bytes());
        a.push(0);
        a.extend_from_slice(tag.as_bytes());
        a
    }
}

impl Protector for TieredProtector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        let mut why = Vec::new();
        for t in &self.tiers {
            match t.available() {
                Ok(()) => {
                    let body = t.protect(plain, &self.aad(t.tag()))?;
                    let mut out = MAGIC.to_vec();
                    out.extend_from_slice(t.tag().as_bytes());
                    out.push(0);
                    out.extend_from_slice(&body);
                    return Ok(out);
                }
                Err(e) => why.push(format!("{}: {e}", t.tag())),
            }
        }
        Err(format!(
            "no key protection tier is available ({})",
            why.join("; ")
        ))
    }

    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        self.unprotect_typed(blob).map_err(|e| match e {
            KeyError::Unavailable(s) | KeyError::Corrupt(s) => s,
        })
    }

    fn unprotect_typed(&self, blob: &[u8]) -> Result<Vec<u8>, KeyError> {
        let Some((tag, body)) = parse(blob) else {
            return Err(KeyError::Corrupt(
                "store.key is not a blob this build writes (no tier prefix)".into(),
            ));
        };
        // only the tier named in the blob may open it; there is no fallback
        let Some(tier) = self.tiers.iter().find(|t| t.tag() == tag) else {
            return Err(KeyError::Unavailable(format!(
                "the key was protected by tier '{tag}', which this build does not have; \
                 it is not re-wrapped by another tier"
            )));
        };
        tier.available().map_err(|e| {
            KeyError::Unavailable(format!("the key's tier '{tag}' is not available: {e}"))
        })?;
        tier.unprotect(body, &self.aad(tag))
    }

    fn tier(&self, blob: &[u8]) -> Option<String> {
        parse(blob).map(|(t, _)| t.to_string())
    }
}

/// A 32-byte key-encrypting key in a file in the state tree, mode 0600.
pub struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    pub const TAG: &'static str = "keyfile";

    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The KEK, created on first use. A file with the wrong mode, or that is
    /// not the length of a key, is refused, never repaired in place.
    fn kek(&self, create: bool) -> Result<[u8; 32], KeyError> {
        use std::io::ErrorKind::{AlreadyExists, NotFound};
        for _ in 0..50 {
            match std::fs::read(&self.path) {
                Ok(b) => {
                    self.check_mode()?;
                    if let Ok(k) = <[u8; 32]>::try_from(b.as_slice()) {
                        return Ok(k);
                    }
                    // another process may be between create and write
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) if e.kind() == NotFound && create => {
                    let mut k = [0u8; 32];
                    getrandom::fill(&mut k)
                        .map_err(|e| KeyError::Unavailable(format!("random key: {e}")))?;
                    match self.create_exclusive(&k) {
                        Ok(()) => return Ok(k),
                        Err(e) if e.kind() == AlreadyExists => continue,
                        Err(e) => {
                            return Err(KeyError::Unavailable(format!(
                                "{} cannot be created: {e}",
                                self.path.display()
                            )))
                        }
                    }
                }
                Err(e) if e.kind() == NotFound => {
                    let dir_present = self.path.parent().is_some_and(|p| p.is_dir());
                    let why = format!(
                        "{} is missing: the key it protected cannot be opened",
                        self.path.display()
                    );
                    // the state directory is there and the file is not: the key is
                    // lost, which waiting will not fix, so `repair` is offered
                    // (it revokes every grant, as for any lost key). If the
                    // directory itself is missing (an unmounted volume) it may
                    // come back, so that is a retry.
                    return Err(if dir_present {
                        KeyError::Corrupt(why)
                    } else {
                        KeyError::Unavailable(why)
                    });
                }
                Err(e) => {
                    return Err(KeyError::Unavailable(format!(
                        "{} cannot be read: {e}",
                        self.path.display()
                    )))
                }
            }
        }
        Err(KeyError::Corrupt(format!(
            "{} is not a 32-byte key",
            self.path.display()
        )))
    }

    fn create_exclusive(&self, k: &[u8; 32]) -> std::io::Result<()> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&self.path)?;
        f.write_all(k)?;
        f.sync_all()
    }

    #[cfg(unix)]
    fn check_mode(&self) -> Result<(), KeyError> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&self.path)
            .map_err(|e| KeyError::Unavailable(format!("{}: {e}", self.path.display())))?;
        if m.mode() & 0o077 != 0 {
            return Err(KeyError::Unavailable(format!(
                "{} is readable by other users (mode {:o}); refusing to use it. \
                 `chmod 600` it if you made it, or investigate if you did not",
                self.path.display(),
                m.mode() & 0o777
            )));
        }
        // the parent directory's owner made it; a key anyone else owns is not ours
        if let Some(parent) = self.path.parent() {
            if let Ok(p) = std::fs::metadata(parent) {
                if p.uid() != m.uid() {
                    return Err(KeyError::Unavailable(format!(
                        "{} is owned by another user than its directory; refusing to use it",
                        self.path.display()
                    )));
                }
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_mode(&self) -> Result<(), KeyError> {
        Ok(())
    }
}

impl Tier for KeyFile {
    fn tag(&self) -> &'static str {
        Self::TAG
    }

    fn available(&self) -> Result<(), String> {
        Ok(())
    }

    fn protect(&self, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let kek = self.kek(true).map_err(|e| match e {
            KeyError::Unavailable(s) | KeyError::Corrupt(s) => s,
        })?;
        let cipher = XChaCha20Poly1305::new((&kek).into());
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|e| format!("random nonce: {e}"))?;
        let ct = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: plain, aad })
            .map_err(|_| "keyfile: encryption failed".to_string())?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unprotect(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, KeyError> {
        if blob.len() < 24 + 16 {
            return Err(KeyError::Corrupt("keyfile blob is too short".into()));
        }
        let kek = self.kek(false)?;
        let (nonce, ct) = blob.split_at(24);
        let nonce: [u8; 24] = nonce.try_into().expect("split at 24");
        XChaCha20Poly1305::new((&kek).into())
            .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad })
            .map_err(|_| {
                KeyError::Corrupt(
                    "keyfile blob did not authenticate (altered, or another tool's key)".into(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn kf(dir: &Path) -> TieredProtector {
        TieredProtector::standard("user-request", dir.join("kek"))
    }

    #[test]
    fn a_round_trip_names_its_tier_in_the_blob() {
        let d = tempfile::tempdir().unwrap();
        let p = kf(d.path());
        let blob = p.protect(b"the store key").unwrap();
        assert!(blob.starts_with(b"UR1\0keyfile\0"), "{blob:?}");
        assert_eq!(p.tier(&blob).as_deref(), Some("keyfile"));
        assert_eq!(p.unprotect(&blob).unwrap(), b"the store key");
        assert_ne!(
            blob.windows(13).position(|w| w == b"the store key"),
            Some(0)
        );
    }

    /// A fresh nonce every time: the same key protected twice differs.
    #[test]
    fn two_protections_of_the_same_key_differ() {
        let d = tempfile::tempdir().unwrap();
        let p = kf(d.path());
        assert_ne!(p.protect(b"k").unwrap(), p.protect(b"k").unwrap());
    }

    #[test]
    fn an_altered_blob_is_corrupt_not_unavailable() {
        let d = tempfile::tempdir().unwrap();
        let p = kf(d.path());
        let mut blob = p.protect(b"k").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(matches!(
            p.unprotect_typed(&blob),
            Err(KeyError::Corrupt(_))
        ));
        assert!(matches!(
            p.unprotect_typed(b"no magic at all"),
            Err(KeyError::Corrupt(_))
        ));
    }

    /// One tool's key does not open in the other, though they share a KEK file.
    #[test]
    fn another_purpose_cannot_open_the_blob() {
        let d = tempfile::tempdir().unwrap();
        let a = TieredProtector::standard("user-request", d.path().join("kek"));
        let b = TieredProtector::standard("with-secret", d.path().join("kek"));
        let blob = a.protect(b"k").unwrap();
        assert!(matches!(
            b.unprotect_typed(&blob),
            Err(KeyError::Corrupt(_))
        ));
    }

    struct Fake {
        tag: &'static str,
        up: Cell<bool>,
    }
    impl Tier for Fake {
        fn tag(&self) -> &'static str {
            self.tag
        }
        fn available(&self) -> Result<(), String> {
            if self.up.get() {
                Ok(())
            } else {
                Err("locked".into())
            }
        }
        fn protect(&self, plain: &[u8], _: &[u8]) -> Result<Vec<u8>, String> {
            Ok(plain.iter().map(|b| b ^ 0x5a).collect())
        }
        fn unprotect(&self, blob: &[u8], _: &[u8]) -> Result<Vec<u8>, KeyError> {
            Ok(blob.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    /// U3 acceptance: a blob written by one tier is refused, not silently
    /// re-wrapped, by another.
    #[test]
    fn a_blob_is_never_opened_or_rewrapped_by_another_tier() {
        let d = tempfile::tempdir().unwrap();
        let best = TieredProtector::new(
            "user-request",
            vec![
                Box::new(Fake {
                    tag: "fake",
                    up: Cell::new(true),
                }),
                Box::new(KeyFile::new(d.path().join("kek"))),
            ],
        );
        let blob = best.protect(b"k").unwrap();
        assert!(blob.starts_with(b"UR1\0fake\0"));

        // the better tier is locked: the keyfile tier must NOT open its blob
        let locked = TieredProtector::new(
            "user-request",
            vec![
                Box::new(Fake {
                    tag: "fake",
                    up: Cell::new(false),
                }),
                Box::new(KeyFile::new(d.path().join("kek"))),
            ],
        );
        match locked.unprotect_typed(&blob) {
            Err(KeyError::Unavailable(w)) => assert!(w.contains("'fake'"), "{w}"),
            o => panic!("{o:?}"),
        }
        // and a build without that tier at all says so, naming it
        let without = kf(d.path());
        match without.unprotect_typed(&blob) {
            Err(KeyError::Unavailable(w)) => assert!(w.contains("'fake'"), "{w}"),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn the_first_available_tier_writes() {
        let d = tempfile::tempdir().unwrap();
        let p = TieredProtector::new(
            "user-request",
            vec![
                Box::new(Fake {
                    tag: "down",
                    up: Cell::new(false),
                }),
                Box::new(KeyFile::new(d.path().join("kek"))),
            ],
        );
        assert!(p.protect(b"k").unwrap().starts_with(b"UR1\0keyfile\0"));
        let none = TieredProtector::new(
            "user-request",
            vec![Box::new(Fake {
                tag: "down",
                up: Cell::new(false),
            })],
        );
        let e = none.protect(b"k").unwrap_err();
        assert!(e.contains("down: locked"), "{e}");
    }

    #[test]
    fn key_tier_reads_the_prefix_without_a_protector() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(key_tier(d.path()), KeyTier::Missing);
        let p = kf(d.path());
        std::fs::write(d.path().join("store.key"), p.protect(b"k").unwrap()).unwrap();
        assert_eq!(key_tier(d.path()), KeyTier::Tier("keyfile".into()));
        std::fs::write(d.path().join("store.key"), b"raw blob").unwrap();
        let want = if cfg!(windows) {
            KeyTier::LegacyDpapi
        } else {
            KeyTier::Foreign
        };
        assert_eq!(key_tier(d.path()), want);
    }

    #[test]
    fn the_keyfile_tier_is_never_shown_without_its_warning() {
        let t = KeyTier::Tier("keyfile".into()).describe();
        assert!(t.starts_with("key protected by: keyfile\n"), "{t}");
        assert!(
            t.contains("weakest tier") && t.contains("copy or backup"),
            "{t}"
        );
        assert_eq!(KeyTier::LegacyDpapi.describe(), "key protected by: dpapi");
    }

    #[cfg(unix)]
    #[test]
    fn the_kek_is_mode_0600_and_a_loose_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = kf(d.path());
        let blob = p.protect(b"k").unwrap();
        let mode = std::fs::metadata(d.path().join("kek"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::set_permissions(d.path().join("kek"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(matches!(
            p.unprotect_typed(&blob),
            Err(KeyError::Unavailable(w)) if w.contains("readable by other users")
        ));
    }

    #[test]
    fn a_lost_kek_is_corrupt_never_regenerated_on_read() {
        let d = tempfile::tempdir().unwrap();
        let p = kf(d.path());
        let blob = p.protect(b"k").unwrap();
        std::fs::remove_file(d.path().join("kek")).unwrap();
        // the directory is there, the key is not: lost, so repairable
        assert!(matches!(
            p.unprotect_typed(&blob),
            Err(KeyError::Corrupt(_))
        ));
        assert!(!d.path().join("kek").exists(), "a read created a new key");
        // the whole state directory missing may come back: a retry
        let gone = kf(&d.path().join("not-mounted"));
        assert!(matches!(
            gone.unprotect_typed(&blob),
            Err(KeyError::Unavailable(_))
        ));
    }
}
