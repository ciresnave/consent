// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one primitive every channel's person-facing side reduces to: show a
//! text, get a yes, a no, a timeout, or "cannot ask". Moved unchanged from
//! with-secret's `consent.rs`, which re-exports it.

#[derive(Debug, PartialEq)]
pub enum ConsentOutcome {
    Approved,
    Denied,
    TimedOut,
    Unavailable(String),
}

pub trait Consent {
    fn ask(&self, prompt: &str, wait: std::time::Duration) -> ConsentOutcome;
}
