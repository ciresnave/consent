// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows Hello consent - design §2.2. ⚠️ The ONE approval channel no agent
//! can answer: it needs CireSnave's PIN or biometric at the desktop.

use std::time::Duration;

use crate::consent::{Consent, ConsentOutcome};

#[derive(Clone, Copy, Debug, Default)]
pub enum Owner {
    // ⚠️ Set from Task 0's measurement (WITH-SECRET-DESIGN.md §4): both owners
    // showed the dialog, but from a lane's Bash tool GetConsoleWindow is null.
    #[default]
    Foreground,
    Console,
}

#[derive(Default)]
pub struct HelloConsent {
    pub owner: Owner,
}

#[cfg(windows)]
impl Consent for HelloConsent {
    fn ask(&self, prompt: &str, wait: Duration) -> ConsentOutcome {
        match ask_windows(self.owner, prompt, wait) {
            Ok(o) => o,
            Err(e) => ConsentOutcome::Unavailable(format!("Windows Hello failed: {e}")),
        }
    }
}

#[cfg(windows)]
fn ask_windows(
    owner: Owner,
    prompt: &str,
    wait: Duration,
) -> windows::core::Result<ConsentOutcome> {
    use std::time::Instant;
    use windows::core::{factory, Interface, HSTRING};
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult as R, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    // windows 0.62: the async types live in windows-future (design §4).
    use windows_future::{AsyncStatus, IAsyncInfo, IAsyncOperation};

    let avail = UserConsentVerifier::CheckAvailabilityAsync()?.join()?;
    if avail != UserConsentVerifierAvailability::Available {
        return Ok(ConsentOutcome::Unavailable(format!(
            "Windows Hello is {avail:?}"
        )));
    }
    let hwnd = unsafe {
        match owner {
            Owner::Foreground => GetForegroundWindow(),
            Owner::Console => GetConsoleWindow(),
        }
    };
    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let op: IAsyncOperation<R> =
        unsafe { interop.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(prompt))? };
    let info = op.cast::<IAsyncInfo>()?;
    let deadline = Instant::now() + wait;
    while info.Status()? == AsyncStatus::Started {
        if Instant::now() >= deadline {
            let _ = info.Cancel();
            return Ok(ConsentOutcome::TimedOut);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(match op.GetResults()? {
        R::Verified => ConsentOutcome::Approved,
        R::Canceled | R::RetriesExhausted => ConsentOutcome::Denied,
        other => ConsentOutcome::Unavailable(format!("Windows Hello returned {other:?}")),
    })
}

#[cfg(not(windows))]
impl Consent for HelloConsent {
    fn ask(&self, _: &str, _: Duration) -> ConsentOutcome {
        ConsentOutcome::Unavailable("Windows Hello exists only on Windows".into())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
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
