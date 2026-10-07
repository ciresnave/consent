// SPDX-License-Identifier: MIT OR Apache-2.0
//! The seam for asking. Item 81 (c): "every access asks YOU first, naming
//! the secret, the requesting lane, the command and the reason".
//!
//! Since #2b the access prompt is the user-request store's
//! (`user_request::channel::prompt_text`): Who, Grant (to the second, and
//! loud past today) and Covers first and never clipped, then the secret,
//! the command and the reason, cleaned and clipped.

pub use user_request::consent::{Consent, ConsentOutcome};

/// The prompt for changing the vault itself (`vault set`, `vault remove`).
pub fn store_prompt_text(action: &str, secret: &str) -> String {
    format!("with-secret: {action} secret {secret} in the vault?")
}
