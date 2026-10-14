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

    /// `ask`, with a 32-byte `binding` the channel derived from the request
    /// (and fresh random bytes), for a provider that can bind its proof to
    /// it (a security key's assertion). The default ignores the binding, so
    /// every existing implementor keeps its behaviour.
    fn ask_bound(
        &self,
        prompt: &str,
        binding: &[u8; 32],
        wait: std::time::Duration,
    ) -> ConsentOutcome {
        let _ = binding;
        self.ask(prompt, wait)
    }
}
