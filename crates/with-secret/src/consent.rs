// SPDX-License-Identifier: MIT OR Apache-2.0
//! The seam for asking. Item 81 (c) asked for a prompt "naming the secret,
//! the requesting lane, the command and the reason"; board 134 (CireSnave,
//! 2026-10-07) replaced it with three things: who, which secret, and how
//! long.
//!
//! The access prompt is the user-request store's
//! (`user_request::channel::prompt_text`): Who, Wants and Duration (to the
//! second, and loud past today). The command and the reason go to the
//! access log, not the prompt.

pub use user_request::consent::{Consent, ConsentOutcome};

/// The prompt for changing the vault itself (`vault set`, `vault remove`).
pub fn store_prompt_text(action: &str, secret: &str) -> String {
    format!("with-secret: {action} secret {secret} in the vault?")
}
