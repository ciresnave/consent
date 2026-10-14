// SPDX-License-Identifier: MIT OR Apache-2.0
//! Approval by physical presence where there is no Windows Hello
//! (docs/LINUX-PORT-DESIGN.md section 3): a security key's touch first, a
//! fingerprint second, else `Unavailable`.
//!
//! This module is the seam and the policy; the providers that talk to
//! hardware (FIDO2, fprintd) are separate slices behind features. There is
//! deliberately NO provider that asks on a terminal: see
//! `tests/no_terminal_channel.rs`.

use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::consent::{Consent, ConsentOutcome};

/// What one provider reports for one ask.
#[derive(Debug, PartialEq, Eq)]
pub enum Presence {
    /// A person was present and approved; the provider verified its proof.
    Verified,
    /// A person was present and refused, or cancelled.
    Cancelled,
    TimedOut,
    /// This provider cannot ask right now (no device, no enrolled
    /// credential). Only this lets the next provider try.
    Unavailable(String),
}

/// One way of proving presence.
pub trait PresenceProvider {
    fn name(&self) -> &'static str;
    /// Ask. `challenge` is `SHA-256("user-request.v1" || binding ||
    /// prompt)`; a provider that signs must sign exactly it and must verify
    /// the signature itself before it returns `Verified`.
    fn ask(&self, challenge: &[u8; 32], prompt: &str, wait: Duration) -> Presence;
}

/// The challenge a provider signs: bound to the request, the shown text and
/// the fresh bytes in `binding`.
pub fn challenge(binding: &[u8; 32], prompt: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"user-request.v1");
    h.update(binding);
    h.update(prompt.as_bytes());
    h.finalize().into()
}

/// Providers in order. The first that is available answers; a Cancelled or
/// TimedOut ends the ask, it is never retried on a weaker provider.
pub struct PresenceConsent {
    providers: Vec<Box<dyn PresenceProvider>>,
}

impl PresenceConsent {
    pub fn new(providers: Vec<Box<dyn PresenceProvider>>) -> Self {
        Self { providers }
    }
}

impl Consent for PresenceConsent {
    /// Unbound: there is nothing to bind a proof to, so this never approves.
    fn ask(&self, _: &str, _: Duration) -> ConsentOutcome {
        ConsentOutcome::Unavailable(
            "physical-presence approval needs a request to bind to; asked without one".into(),
        )
    }

    fn ask_bound(&self, prompt: &str, binding: &[u8; 32], wait: Duration) -> ConsentOutcome {
        let c = challenge(binding, prompt);
        let mut why = Vec::new();
        for p in &self.providers {
            match p.ask(&c, prompt, wait) {
                Presence::Verified => return ConsentOutcome::Approved,
                Presence::Cancelled => return ConsentOutcome::Denied,
                Presence::TimedOut => return ConsentOutcome::TimedOut,
                Presence::Unavailable(w) => why.push(format!("{}: {w}", p.name())),
            }
        }
        ConsentOutcome::Unavailable(if why.is_empty() {
            "no physical-presence provider is configured".into()
        } else {
            format!(
                "no physical-presence provider is available ({})",
                why.join("; ")
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Seen = Rc<RefCell<Vec<[u8; 32]>>>;

    /// A scripted authenticator that records what it was asked.
    struct Fake {
        name: &'static str,
        answer: fn() -> Presence,
        seen: Seen,
    }
    impl PresenceProvider for Fake {
        fn name(&self) -> &'static str {
            self.name
        }
        fn ask(&self, c: &[u8; 32], _: &str, _: Duration) -> Presence {
            self.seen.borrow_mut().push(*c);
            (self.answer)()
        }
    }

    fn fake(name: &'static str, answer: fn() -> Presence) -> (Box<Fake>, Seen) {
        let seen = Rc::new(RefCell::new(Vec::new()));
        (
            Box::new(Fake {
                name,
                answer,
                seen: seen.clone(),
            }),
            seen,
        )
    }

    const W: Duration = Duration::from_secs(1);
    const B: [u8; 32] = [7; 32];

    #[test]
    fn approved_only_when_a_provider_verified() {
        let (a, _) = fake("key", || Presence::Verified);
        let c = PresenceConsent::new(vec![a]);
        assert_eq!(c.ask_bound("p", &B, W), ConsentOutcome::Approved);
    }

    #[test]
    fn cancel_is_denied_and_deadline_is_timed_out() {
        for (answer, want) in [
            (
                (|| Presence::Cancelled) as fn() -> Presence,
                ConsentOutcome::Denied,
            ),
            (|| Presence::TimedOut, ConsentOutcome::TimedOut),
        ] {
            let (a, _) = fake("key", answer);
            let c = PresenceConsent::new(vec![a]);
            assert_eq!(c.ask_bound("p", &B, W), want);
        }
    }

    /// A "no" is never retried on the next provider.
    #[test]
    fn no_fallthrough_after_a_denial_or_a_timeout() {
        for answer in [(|| Presence::Cancelled) as fn() -> Presence, || {
            Presence::TimedOut
        }] {
            let (first, _) = fake("key", answer);
            let (second, second_seen) = fake("finger", || Presence::Verified);
            let c = PresenceConsent::new(vec![first, second]);
            assert_ne!(c.ask_bound("p", &B, W), ConsentOutcome::Approved);
            assert!(
                second_seen.borrow().is_empty(),
                "the second provider was asked"
            );
        }
    }

    #[test]
    fn an_unavailable_provider_lets_the_next_one_answer() {
        let (a, _) = fake("key", || Presence::Unavailable("no device".into()));
        let (b, b_seen) = fake("finger", || Presence::Verified);
        let c = PresenceConsent::new(vec![a, b]);
        assert_eq!(c.ask_bound("p", &B, W), ConsentOutcome::Approved);
        assert_eq!(b_seen.borrow().len(), 1);
    }

    #[test]
    fn nothing_available_or_configured_is_unavailable_never_approved() {
        let none = PresenceConsent::new(vec![]);
        assert!(matches!(
            none.ask_bound("p", &B, W),
            ConsentOutcome::Unavailable(_)
        ));
        let (a, _) = fake("key", || Presence::Unavailable("no device".into()));
        let (b, _) = fake("finger", || Presence::Unavailable("no reader".into()));
        let c = PresenceConsent::new(vec![a, b]);
        match c.ask_bound("p", &B, W) {
            ConsentOutcome::Unavailable(w) => {
                assert!(
                    w.contains("key: no device") && w.contains("finger: no reader"),
                    "{w}"
                )
            }
            o => panic!("{o:?}"),
        }
    }

    /// An unbound ask has nothing to bind a proof to, so it cannot approve,
    /// even with a provider that would say yes.
    #[test]
    fn a_plain_ask_never_approves() {
        let (a, seen) = fake("key", || Presence::Verified);
        let c = PresenceConsent::new(vec![a]);
        assert!(matches!(c.ask("p", W), ConsentOutcome::Unavailable(_)));
        assert!(seen.borrow().is_empty());
    }

    /// The provider is handed exactly SHA-256("user-request.v1" || binding ||
    /// prompt), and a different prompt or binding is a different challenge.
    #[test]
    fn the_challenge_binds_the_binding_and_the_shown_text() {
        let (a, seen) = fake("key", || Presence::Verified);
        let c = PresenceConsent::new(vec![a]);
        c.ask_bound("text one", &B, W);
        c.ask_bound("text two", &B, W);
        c.ask_bound("text one", &[8; 32], W);
        let seen = seen.borrow();
        assert_eq!(seen[0], challenge(&B, "text one"));
        assert_ne!(seen[0], seen[1]);
        assert_ne!(seen[0], seen[2]);
        let mut h = Sha256::new();
        h.update(b"user-request.v1");
        h.update(B);
        h.update(b"text one");
        assert_eq!(seen[0], <[u8; 32]>::from(h.finalize()));
    }
}
