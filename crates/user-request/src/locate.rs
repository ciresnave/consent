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

/// `%LOCALAPPDATA%\OverMind\user-request`, or `USER_REQUEST_DIR` in a debug
/// build.
pub fn dir() -> Result<PathBuf, String> {
    if let Some(d) = env_override("USER_REQUEST_DIR") {
        return Ok(d);
    }
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(base).join("OverMind").join("user-request"))
}

/// The second place the audit chain's head is written, or
/// `USER_REQUEST_HEAD` in a debug build.
pub fn head_copy() -> PathBuf {
    env_override("USER_REQUEST_HEAD")
        .unwrap_or_else(|| PathBuf::from("C:/Projects/.lane-state/user-request-audit.head"))
}
