// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows Hello consent - design §2.2. Moved to the `user-request` crate
//! (board item 121); re-exported here so with-secret is unchanged.

pub use user_request::hello::{HelloConsent, Owner};

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::consent::{Consent, ConsentOutcome};
    use std::time::Duration;

    /// ⚠️ LIVE: shows a real prompt. Run only with CireSnave at the desktop:
    /// `cargo test -p with-secret -- --ignored live_hello`
    #[test]
    #[ignore]
    fn live_hello_cancel_is_denied() {
        let o = HelloConsent::default().ask(
            "with-secret LIVE TEST: press Cancel.",
            Duration::from_secs(120),
        );
        assert_eq!(o, ConsentOutcome::Denied);
    }
}
