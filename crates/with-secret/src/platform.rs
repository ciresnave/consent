// SPDX-License-Identifier: MIT OR Apache-2.0
//! What differs by operating system (docs/LINUX-PORT-DESIGN.md section 5):
//! where the vault lives and how its key is protected at rest.
//!
//! Windows is unchanged: `%LOCALAPPDATA%\OverMind\with-secret` and DPAPI user
//! scope with this tool's entropy. Elsewhere the vault is under the XDG state
//! directory and its key goes through the same tiers as the approvals store
//! (`user_request::tiered`), with the purpose label `with-secret` so one
//! tool's blob does not open in the other.
//!
//! ⚠️ The `keyfile` tier is weaker than DPAPI: its key sits in the same state
//! tree as the vault, so a copy of the tree carries both (design section 6).

use std::path::PathBuf;

use user_request::locate::Env;

use crate::vault::Protector;

/// The vault directory for `env`. Pure, so every OS's answer is testable on
/// any host.
pub fn try_default_dir(env: &Env) -> Result<PathBuf, String> {
    let tail = |base: PathBuf| base.join("OverMind").join("with-secret");
    if env.windows {
        return env
            .local_app_data
            .clone()
            .map(tail)
            .ok_or_else(|| "LOCALAPPDATA is not set".to_string());
    }
    if let Some(x) = env
        .xdg_state_home
        .as_ref()
        .filter(|x| x.to_string_lossy().starts_with('/'))
    {
        return Ok(tail(x.clone()));
    }
    let home = env
        .home
        .as_ref()
        .ok_or("neither XDG_STATE_HOME nor HOME is set")?;
    Ok(tail(home.join(".local").join("state")))
}

/// This platform's vault protector. `kek` is set only by `for_dir`.
pub struct SelectedProtector {
    #[cfg_attr(windows, allow(dead_code))]
    kek: Option<PathBuf>,
}

impl SelectedProtector {
    /// The production protector: its key file, off Windows, is beside the
    /// vault directory (inside it when the directory is the test override).
    pub fn new() -> Self {
        Self { kek: None }
    }

    /// For a test that opens a vault in `dir` itself.
    pub fn for_dir(dir: &std::path::Path) -> Self {
        Self {
            kek: Some(dir.join("kek")),
        }
    }
}

impl Default for SelectedProtector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl Protector for SelectedProtector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        crate::dpapi::DpapiProtector.protect(plain)
    }
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        crate::dpapi::DpapiProtector.unprotect(blob)
    }
}

/// Where the key-encrypting key lives for a vault in `dir`: beside it, in the
/// same state tree; inside it when `dir` is the `WITH_SECRET_DIR` override
/// (a test or a deliberate location owns its directory, and a shared parent
/// such as `/tmp` is not its to write to).
pub fn kek_path_for(dir: &std::path::Path, overridden: bool) -> PathBuf {
    if overridden {
        dir.join("kek")
    } else {
        dir.with_file_name("with-secret-kek")
    }
}

#[cfg(not(windows))]
impl SelectedProtector {
    fn tiered(&self) -> Result<user_request::tiered::TieredProtector, String> {
        let kek = match &self.kek {
            Some(k) => k.clone(),
            None => match std::env::var_os("WITH_SECRET_DIR") {
                // the override names the directory, so no home is needed
                Some(d) => kek_path_for(&PathBuf::from(d), true),
                None => kek_path_for(&crate::vault::default_dir()?, false),
            },
        };
        Ok(user_request::tiered::TieredProtector::standard(
            "with-secret",
            kek,
        ))
    }
}

#[cfg(not(windows))]
impl Protector for SelectedProtector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        use user_request::store::Protector as _;
        self.tiered()?.protect(plain)
    }
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        use user_request::store::Protector as _;
        self.tiered()?.unprotect(blob)
    }
}

/// What `with-secret check` calls the protection it just exercised.
pub const PROTECTION_NAME: &str = if cfg!(windows) {
    "DPAPI"
} else {
    "tiered key protector (keyfile tier: weaker than DPAPI)"
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn env(windows: bool, lad: Option<&str>, xdg: Option<&str>, home: Option<&str>) -> Env {
        let p = |s: &str| PathBuf::from(s);
        Env {
            windows,
            local_app_data: lad.map(p),
            xdg_state_home: xdg.map(p),
            home: home.map(p),
        }
    }

    fn norm(p: PathBuf) -> String {
        p.to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn windows_keeps_localappdata() {
        let e = env(
            true,
            Some("C:/Users/x/AppData/Local"),
            Some("/xdg"),
            Some("/home/x"),
        );
        assert_eq!(
            norm(try_default_dir(&e).unwrap()),
            "C:/Users/x/AppData/Local/OverMind/with-secret"
        );
        assert_eq!(
            try_default_dir(&env(true, None, Some("/xdg"), Some("/home/x"))),
            Err("LOCALAPPDATA is not set".into())
        );
    }

    #[test]
    fn linux_uses_xdg_then_home_and_ignores_a_relative_xdg() {
        let x = env(false, None, Some("/xdg"), Some("/home/x"));
        assert_eq!(
            norm(try_default_dir(&x).unwrap()),
            "/xdg/OverMind/with-secret"
        );
        let h = env(false, None, None, Some("/home/x"));
        assert_eq!(
            norm(try_default_dir(&h).unwrap()),
            "/home/x/.local/state/OverMind/with-secret"
        );
        let r = env(false, None, Some("rel"), Some("/home/x"));
        assert_eq!(
            norm(try_default_dir(&r).unwrap()),
            "/home/x/.local/state/OverMind/with-secret"
        );
        assert!(try_default_dir(&env(false, Some("C:/x"), None, None)).is_err());
    }

    /// The vault key goes through the platform protector and back.
    #[test]
    fn the_kek_is_beside_the_vault_or_inside_an_override() {
        let d = PathBuf::from("/state/OverMind/with-secret");
        assert_eq!(
            norm(kek_path_for(&d, false)),
            "/state/OverMind/with-secret-kek"
        );
        assert_eq!(
            norm(kek_path_for(&d, true)),
            "/state/OverMind/with-secret/kek"
        );
        // never the approvals store's file
        assert_ne!(
            norm(kek_path_for(&d, false)),
            "/state/OverMind/user-request-kek"
        );
    }

    #[test]
    fn the_selected_protector_round_trips_in_its_own_directory() {
        let d = tempfile::tempdir().unwrap();
        let p = SelectedProtector::for_dir(d.path());
        let blob = p.protect(b"vault bytes").unwrap();
        assert_ne!(blob, b"vault bytes");
        assert_eq!(p.unprotect(&blob).unwrap(), b"vault bytes");
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_blob_names_its_tier_and_this_tool() {
        let d = tempfile::tempdir().unwrap();
        let p = SelectedProtector::for_dir(d.path());
        let blob = p.protect(b"v").unwrap();
        assert!(blob.starts_with(b"UR1\0keyfile\0"), "{blob:?}");
        // user-request's store key, protected under ITS purpose with the same
        // key file, does not open as a vault blob
        use user_request::store::Protector as _;
        let theirs =
            user_request::tiered::TieredProtector::standard("user-request", d.path().join("kek"));
        assert!(theirs.unprotect(&blob).is_err());
    }
}
