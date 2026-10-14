// SPDX-License-Identifier: MIT OR Apache-2.0
//! The approval channel this operating system has, chosen in one place so
//! every consumer (`with-secret`, `lane-restart`, `agentlife`) asks the same
//! way (docs/LINUX-PORT-DESIGN.md sections 1 and 5).
//!
//! Windows: Windows Hello. Elsewhere: physical presence (`presence`), with a
//! security key when the `fido2` feature is on, and `Unavailable` otherwise.
//! There is NO terminal-prompt channel (`tests/no_terminal_channel.rs`).

use std::time::Duration;

use crate::consent::{Consent, ConsentOutcome};

/// Windows Hello, or physical presence.
pub enum PlatformConsent {
    Hello(crate::hello::HelloConsent),
    Presence(crate::presence::PresenceConsent),
}

impl Consent for PlatformConsent {
    fn ask(&self, prompt: &str, wait: Duration) -> ConsentOutcome {
        match self {
            PlatformConsent::Hello(c) => c.ask(prompt, wait),
            PlatformConsent::Presence(c) => c.ask(prompt, wait),
        }
    }

    fn ask_bound(&self, prompt: &str, binding: &[u8; 32], wait: Duration) -> ConsentOutcome {
        match self {
            PlatformConsent::Hello(c) => c.ask_bound(prompt, binding, wait),
            PlatformConsent::Presence(c) => c.ask_bound(prompt, binding, wait),
        }
    }
}

/// This platform's consent. Off Windows the providers are, in order, the
/// security key when built with `fido2` and enrolled; with none, every ask is
/// `Unavailable` and consent fails closed.
pub fn platform_consent() -> PlatformConsent {
    #[cfg(windows)]
    {
        PlatformConsent::Hello(crate::hello::HelloConsent::default())
    }
    #[cfg(not(windows))]
    {
        #[allow(unused_mut)]
        let mut providers: Vec<Box<dyn crate::presence::PresenceProvider>> = Vec::new();
        #[cfg(feature = "fido2")]
        if let Ok(d) = crate::locate::dir() {
            providers.push(Box::new(crate::fido2::Fido2Provider::new(
                crate::fido2::HidAuthenticator,
                d.join("fido2-credential.json"),
            )));
        }
        PlatformConsent::Presence(crate::presence::PresenceConsent::new(providers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn off_windows_without_a_provider_every_ask_is_unavailable() {
        // the default build has no hardware provider, so this must never approve
        let c = PlatformConsent::Presence(crate::presence::PresenceConsent::new(vec![]));
        let w = Duration::from_secs(1);
        assert!(matches!(c.ask("p", w), ConsentOutcome::Unavailable(_)));
        assert!(matches!(
            c.ask_bound("p", &[0; 32], w),
            ConsentOutcome::Unavailable(_)
        ));
    }

    #[test]
    fn the_platform_consent_is_the_documented_variant() {
        let c = platform_consent();
        assert_eq!(
            matches!(c, PlatformConsent::Hello(_)),
            cfg!(windows),
            "Hello exactly on Windows"
        );
    }
}
