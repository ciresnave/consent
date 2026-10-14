// SPDX-License-Identifier: MIT OR Apache-2.0
//! Where the production store lives, shared by every binary that opens it
//! (`user-request`, and with-secret since #2b), so all of them open the
//! SAME store, and `revoke --all` covers every kind.

use std::path::PathBuf;

use crate::dpapi::Dpapi;

/// The store key's DPAPI entropy.
pub const ENTROPY: &[u8] = b"overmind.user-request.v1";
pub const PROTECTOR: Dpapi = Dpapi { entropy: ENTROPY };

/// ⚠️ The overrides exist for tests and only in debug builds (review M4): a
/// leaked variable must never point the panic button, or a secret's
/// approvals, at another store.
pub fn env_override(name: &str) -> Option<PathBuf> {
    if cfg!(debug_assertions) {
        std::env::var_os(name).map(PathBuf::from)
    } else {
        None
    }
}

/// The environment `dir` reads, as a value so every platform's answer can be
/// tested on any host.
#[derive(Clone, Debug, Default)]
pub struct Env {
    pub windows: bool,
    pub local_app_data: Option<PathBuf>,
    pub xdg_state_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

impl Env {
    pub fn current() -> Self {
        let var = |n: &str| {
            std::env::var_os(n)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Self {
            windows: cfg!(windows),
            local_app_data: var("LOCALAPPDATA"),
            xdg_state_home: var("XDG_STATE_HOME"),
            home: var("HOME"),
        }
    }
}

/// Windows: `%LOCALAPPDATA%\OverMind\user-request`. Elsewhere: the XDG state
/// directory, `$XDG_STATE_HOME/OverMind/user-request`, else
/// `~/.local/state/OverMind/user-request`. A relative `XDG_STATE_HOME` is
/// ignored, as the XDG specification says.
pub fn try_dir(env: &Env) -> Result<PathBuf, String> {
    let tail = |base: PathBuf| base.join("OverMind").join("user-request");
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

/// The store directory, or `USER_REQUEST_DIR` in a debug build.
pub fn dir() -> Result<PathBuf, String> {
    if let Some(d) = env_override("USER_REQUEST_DIR") {
        return Ok(d);
    }
    try_dir(&Env::current())
}

/// The second place the audit chain's head is written, or
/// `USER_REQUEST_HEAD` in a debug build.
pub fn head_copy() -> PathBuf {
    env_override("USER_REQUEST_HEAD")
        .unwrap_or_else(|| PathBuf::from("C:/Projects/.lane-state/user-request-audit.head"))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// U1: Windows is unchanged, and XDG variables never move it.
    #[test]
    fn windows_keeps_localappdata_whatever_xdg_says() {
        let e = env(
            true,
            Some("C:/Users/x/AppData/Local"),
            Some("/xdg"),
            Some("/home/x"),
        );
        assert_eq!(
            norm(try_dir(&e).unwrap()),
            "C:/Users/x/AppData/Local/OverMind/user-request"
        );
        let none = env(true, None, Some("/xdg"), Some("/home/x"));
        assert_eq!(try_dir(&none), Err("LOCALAPPDATA is not set".into()));
    }

    #[test]
    fn linux_uses_xdg_state_home_then_home() {
        let x = env(false, None, Some("/xdg"), Some("/home/x"));
        assert_eq!(norm(try_dir(&x).unwrap()), "/xdg/OverMind/user-request");
        let h = env(false, None, None, Some("/home/x"));
        assert_eq!(
            norm(try_dir(&h).unwrap()),
            "/home/x/.local/state/OverMind/user-request"
        );
    }

    /// The XDG specification: a relative value is invalid and ignored.
    #[test]
    fn linux_ignores_a_relative_xdg_state_home() {
        let e = env(false, None, Some("relative/state"), Some("/home/x"));
        assert_eq!(
            norm(try_dir(&e).unwrap()),
            "/home/x/.local/state/OverMind/user-request"
        );
    }

    #[test]
    fn linux_without_xdg_or_home_is_an_error_not_a_relative_path() {
        let e = env(false, None, None, None);
        assert!(try_dir(&e).is_err());
        // Windows' variable is not a Linux fallback
        let w = env(false, Some("C:/x"), None, None);
        assert!(try_dir(&w).is_err());
    }
}
