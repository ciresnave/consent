// SPDX-License-Identifier: MIT OR Apache-2.0
//! Values that look like a NON-secret. ⚠️ Incident 2026-10-23: a Cloudflare
//! account id (32 hex) was stored under an API-token entry; nothing noticed
//! until output masking rewrote the id in a command's output under the wrong
//! entry's name. These rules only WARN: a real token can be 32 hex.
//!
//! ⚠️ Every string returned names a rule, an env var or an entry, never a
//! value: `vault check` prints them and `vault set` prints them to a terminal.

use crate::vault::{Vault, MIN_VALUE_LEN};

/// Names whose value is an identifier or a place, not a credential.
const EXACT: &[&str] = &[
    "AWS_ACCOUNT_ID",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "CF_ACCOUNT_ID",
    "CLOUDFLARE_ACCOUNT_ID",
    "COMPUTERNAME",
    "GCLOUD_PROJECT",
    "GITHUB_ACTOR",
    "GITHUB_REPOSITORY",
    "GOOGLE_CLOUD_PROJECT",
    "HOSTNAME",
    "LOGNAME",
    "USERNAME",
];
const SUFFIXES: &[&str] = &[
    "_ACCOUNT_ID",
    "_CLIENT_ID",
    "_HOSTNAME",
    "_PROJECT_ID",
    "_REGION",
    "_TENANT_ID",
    "_USERNAME",
    "_ZONE_ID",
];
/// A name containing one of these is treated as a credential even if it
/// ends like an id: it is how `with-secret` hands a real value to a child.
const CREDENTIAL_WORDS: &[&str] = &["TOKEN", "SECRET", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL"];

pub fn is_non_secret_env_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    if CREDENTIAL_WORDS.iter().any(|w| n.contains(w)) {
        return false;
    }
    EXACT.contains(&n.as_str()) || SUFFIXES.iter().any(|s| n.ends_with(s))
}

fn is_32_hex(v: &str) -> bool {
    v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Rules that fire for `value`. `env` is the process environment (passed in
/// so a test needs no global state).
pub fn audit_value(value: &str, env: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    if is_32_hex(value) {
        out.push(
            "exactly 32 hex characters: the shape of an account or zone id, not of most tokens"
                .to_string(),
        );
    }
    if value.chars().count() >= MIN_VALUE_LEN {
        for (k, v) in env {
            if v.trim() == value && is_non_secret_env_name(k) {
                out.push(format!("equals the value of the non-secret env var {k}"));
            }
        }
    }
    out
}

/// Every entry with at least one rule, in name order. Includes "same value as
/// another entry": masking then labels the value with whichever name sorts
/// first, which is the mislabel this module exists to catch.
pub fn audit_vault(vault: &Vault, env: &[(String, String)]) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for (name, s) in &vault.secrets {
        let mut rules = audit_value(&s.value, env);
        for (other, o) in &vault.secrets {
            if other != name && o.value == s.value {
                rules.push(format!("has the same value as entry {other}"));
            }
        }
        if !rules.is_empty() {
            out.push((name.clone(), rules));
        }
    }
    out
}
