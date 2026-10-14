// SPDX-License-Identifier: MIT OR Apache-2.0
//! The FIDO2 / security-key presence provider (docs/LINUX-PORT-DESIGN.md
//! section 3, slice S3). Behind the `fido2` feature.
//!
//! One-time `enroll` makes a credential on the person's key and stores its id
//! and public key. Each ask sends a `getAssertion` whose challenge is the
//! section 3 challenge, user presence required, and `Verified` only when the
//! signature verifies against the enrolled key, the relying-party hash matches,
//! the user-present flag is set and the signature counter did not go back.
//!
//! ⚠️ A key proves a person TOUCHED it, not that they read the text (design
//! section 6; CireSnave accepted this, board 208). ⚠️ The credential file is
//! as trustworthy as the store directory: like the rest of this crate it
//! stops accidents, not a same-user process that rewrites files.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use ctap_hid_fido2::public_key::{PublicKey, PublicKeyType};
use sha2::{Digest, Sha256};

use crate::presence::{Presence, PresenceProvider};

/// The relying-party id every credential is made for. Fixed: a signature for
/// another id does not verify.
pub const RPID: &str = "user-request.local";

/// The enrolled credential, as stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    /// Hex of the credential id.
    pub id: String,
    /// Hex of the public key (an uncompressed P-256 point).
    pub public_key: String,
    /// The highest signature counter seen; a lower one is a cloned key.
    /// Authenticators that always report 0 are never checked.
    pub counter: u32,
}

impl Credential {
    fn id_bytes(&self) -> Result<Vec<u8>, String> {
        unhex(&self.id)
    }

    fn key(&self) -> Result<PublicKey, String> {
        Ok(PublicKey::with_der(
            &unhex(&self.public_key)?,
            PublicKeyType::Ecdsa256,
        ))
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) || !b.iter().all(u8::is_ascii_hexdigit) {
        return Err("not lowercase or uppercase hex".into());
    }
    Ok(b.chunks(2)
        .map(|p| {
            let d = |c: u8| (c as char).to_digit(16).expect("checked") as u8;
            d(p[0]) << 4 | d(p[1])
        })
        .collect())
}

/// What an authenticator returned for an assertion, before verification.
#[derive(Debug, Clone)]
pub struct RawAssertion {
    pub rpid_hash: Vec<u8>,
    pub user_present: bool,
    pub sign_count: u32,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// No device, or more than one.
    NoDevice(String),
    Cancelled,
    TimedOut,
    Other(String),
}

/// A security key, or a fake of one.
pub trait Authenticator: Send + Sync {
    fn assert(
        &self,
        rpid: &str,
        challenge: &[u8; 32],
        credential_id: &[u8],
    ) -> Result<RawAssertion, AuthError>;
}

/// The provider. `path` is where the credential is kept; it is re-read on
/// every ask so an enrolment made by another process is seen.
pub struct Fido2Provider<A: Authenticator + 'static> {
    auth: std::sync::Arc<A>,
    path: PathBuf,
}

impl<A: Authenticator + 'static> Fido2Provider<A> {
    pub fn new(auth: A, path: impl Into<PathBuf>) -> Self {
        Self {
            auth: std::sync::Arc::new(auth),
            path: path.into(),
        }
    }

    fn load(&self) -> Result<Credential, String> {
        let t = std::fs::read_to_string(&self.path).map_err(|e| {
            format!(
                "no enrolled credential ({}: {e}); run `user-request enroll`",
                self.path.display()
            )
        })?;
        serde_json::from_str(&t)
            .map_err(|e| format!("{} is not a credential: {e}", self.path.display()))
    }

    fn save(&self, c: &Credential) -> Result<(), String> {
        write_credential(&self.path, c)
    }
}

/// Atomic write, mode 0600 where that exists.
pub fn write_credential(path: &Path, c: &Credential) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Verifies one assertion against the credential. Pure, so every refusal is
/// testable without a device.
pub fn verify(
    rpid: &str,
    cred: &Credential,
    challenge: &[u8; 32],
    a: &RawAssertion,
) -> Result<u32, String> {
    // everything is read from the signed authenticator data: the fields of
    // `RawAssertion` are the authenticator's own report and are not trusted
    // where they could disagree with what was signed
    let ad = &a.auth_data;
    if ad.len() < 37 {
        return Err("authenticator data is too short".into());
    }
    let want: [u8; 32] = Sha256::digest(rpid.as_bytes()).into();
    if ad[..32] != want || a.rpid_hash != want {
        return Err("the assertion is for another relying party".into());
    }
    if ad[32] & 0x01 == 0 || !a.user_present {
        return Err("the authenticator did not report a person present".into());
    }
    let signed_count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    if signed_count != a.sign_count {
        return Err("the reported signature counter is not the signed one".into());
    }
    let key = cred.key()?;
    let assertion = ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Assertion {
        rpid_hash: a.rpid_hash.clone(),
        auth_data: a.auth_data.clone(),
        signature: a.signature.clone(),
        ..Default::default()
    };
    if !ctap_hid_fido2::verifier::verify_assertion(rpid, &key, challenge, &assertion) {
        return Err("the signature does not verify for this challenge and credential".into());
    }
    // a counter that never moves (many keys report 0) is not checked; one that
    // has moved must not go back, or the key was cloned
    if (cred.counter != 0 || a.sign_count != 0) && a.sign_count <= cred.counter {
        return Err(format!(
            "the signature counter went from {} to {}: a cloned key, or a replay",
            cred.counter, a.sign_count
        ));
    }
    Ok(a.sign_count)
}

impl<A: Authenticator + 'static> PresenceProvider for Fido2Provider<A> {
    fn name(&self) -> &'static str {
        "fido2"
    }

    fn ask(&self, challenge: &[u8; 32], _prompt: &str, wait: Duration) -> Presence {
        let cred = match self.load() {
            Ok(c) => c,
            Err(e) => return Presence::Unavailable(e),
        };
        let id = match cred.id_bytes() {
            Ok(i) => i,
            Err(e) => return Presence::Unavailable(format!("credential id: {e}")),
        };
        // the device call blocks until a touch; bound it by `wait`
        let (tx, rx) = mpsc::channel();
        let auth = self.auth.clone();
        let ch = *challenge;
        std::thread::spawn(move || {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                auth.assert(RPID, &ch, &id)
            }))
            .unwrap_or_else(|_| Err(AuthError::Other("the authenticator code panicked".into())));
            let _ = tx.send(r);
        });
        match rx.recv_timeout(wait) {
            Err(_) => Presence::TimedOut,
            Ok(Err(AuthError::NoDevice(w))) => Presence::Unavailable(w),
            Ok(Err(AuthError::Cancelled)) => Presence::Cancelled,
            Ok(Err(AuthError::TimedOut)) => Presence::TimedOut,
            Ok(Err(AuthError::Other(w))) => Presence::Unavailable(w),
            Ok(Ok(a)) => match verify(RPID, &cred, challenge, &a) {
                Ok(count) => {
                    let mut c = cred;
                    c.counter = count;
                    // best effort: a failed write only loses the clone check
                    let _ = self.save(&c);
                    Presence::Verified
                }
                // a response that does not verify is a refusal, never an approval
                Err(w) => Presence::Unavailable(format!("fido2 response rejected: {w}")),
            },
        }
    }
}

/// The real key, over USB/NFC HID.
pub struct HidAuthenticator;

fn classify<E: std::fmt::Display>(e: &E) -> AuthError {
    let s = format!("{e:#}");
    if s.contains("FIDO device not found") || s.contains("Multiple FIDO devices") {
        AuthError::NoDevice(s)
    } else if s.contains("CTAP2_ERR_USER_ACTION_TIMEOUT")
        || s.contains("CTAP2_ERR_ACTION_TIMEOUT")
        || s.contains("CTAP1_ERR_TIMEOUT")
    {
        AuthError::TimedOut
    } else if s.contains("CTAP2_ERR_KEEPALIVE_CANCEL")
        || s.contains("CTAP2_ERR_OPERATION_DENIED")
        || s.contains("CTAP2_ERR_USER_ACTION_PENDING")
    {
        AuthError::Cancelled
    } else {
        AuthError::Other(s)
    }
}

impl Authenticator for HidAuthenticator {
    fn assert(
        &self,
        rpid: &str,
        challenge: &[u8; 32],
        credential_id: &[u8],
    ) -> Result<RawAssertion, AuthError> {
        use ctap_hid_fido2::fidokey::GetAssertionArgsBuilder;
        use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};
        let key = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| classify(&e))?;
        let args = GetAssertionArgsBuilder::new(rpid, challenge)
            .credential_id(credential_id)
            .without_pin_and_uv()
            .build();
        let mut v = key
            .get_assertion_with_args(&args)
            .map_err(|e| classify(&e))?;
        let a = v
            .pop()
            .ok_or_else(|| AuthError::Other("the key returned no assertion".into()))?;
        Ok(RawAssertion {
            rpid_hash: a.rpid_hash,
            user_present: a.flags.user_present_result,
            sign_count: a.sign_count,
            auth_data: a.auth_data,
            signature: a.signature,
        })
    }
}

/// One-time enrolment on the real key: makes a credential for `RPID`, checks
/// its attestation and writes it to `path`. `pin` is the key's PIN when it
/// has one set.
pub fn enroll_hid(path: &Path, pin: Option<&str>) -> Result<Credential, String> {
    use ctap_hid_fido2::fidokey::MakeCredentialArgsBuilder;
    use ctap_hid_fido2::{verifier, Cfg, FidoKeyHidFactory};
    if path.exists() {
        return Err(format!(
            "{} already holds a credential; remove it first if you mean to replace it",
            path.display()
        ));
    }
    let key = FidoKeyHidFactory::create(&Cfg::init()).map_err(|e| format!("{e:#}"))?;
    let challenge = verifier::create_challenge();
    let b = MakeCredentialArgsBuilder::new(RPID, &challenge);
    let args = match pin {
        Some(p) => b.pin(p).build(),
        None => b.without_pin_and_uv().build(),
    };
    let att = key
        .make_credential_with_args(&args)
        .map_err(|e| format!("{e:#}"))?;
    let r = verifier::verify_attestation(RPID, &challenge, &att);
    if !r.is_success {
        return Err("the key's attestation did not verify".into());
    }
    let c = Credential {
        id: hex(&r.credential_id),
        public_key: hex(&r.credential_public_key.der),
        counter: 0,
    };
    write_credential(path, &c)?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    /// A software authenticator: signs authData || SHA-256(challenge) like a key.
    struct Soft {
        pair: EcdsaKeyPair,
        counter: std::sync::Mutex<u32>,
        behaviour: fn() -> Behaviour,
    }
    #[derive(Clone, Copy)]
    enum Behaviour {
        Sign,
        SignWithoutPresence,
        WrongRp,
        Cancel,
        Timeout,
        NoDevice,
        FixedCounter(u32),
    }

    impl Soft {
        fn new(behaviour: fn() -> Behaviour) -> (Self, Credential) {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let cred = Credential {
                id: hex(b"credential-1"),
                public_key: hex(pair.public_key().as_ref()),
                counter: 0,
            };
            (
                Self {
                    pair,
                    counter: std::sync::Mutex::new(0),
                    behaviour,
                },
                cred,
            )
        }
    }

    impl Authenticator for Soft {
        fn assert(
            &self,
            rpid: &str,
            challenge: &[u8; 32],
            _: &[u8],
        ) -> Result<RawAssertion, AuthError> {
            let b = (self.behaviour)();
            match b {
                Behaviour::Cancel => return Err(AuthError::Cancelled),
                Behaviour::Timeout => return Err(AuthError::TimedOut),
                Behaviour::NoDevice => return Err(AuthError::NoDevice("no key".into())),
                _ => {}
            }
            let rp = if matches!(b, Behaviour::WrongRp) {
                "evil.example"
            } else {
                rpid
            };
            let rpid_hash: Vec<u8> = Sha256::digest(rp.as_bytes()).to_vec();
            let count = match b {
                Behaviour::FixedCounter(n) => n,
                _ => {
                    let mut c = self.counter.lock().unwrap();
                    *c += 1;
                    *c
                }
            };
            let up = !matches!(b, Behaviour::SignWithoutPresence);
            let mut auth_data = rpid_hash.clone();
            auth_data.push(if up { 0x01 } else { 0x00 });
            auth_data.extend_from_slice(&count.to_be_bytes());
            let mut msg = auth_data.clone();
            // ctap-hid-fido2 hashes the "challenge" bytes it is given
            msg.extend_from_slice(&Sha256::digest(challenge));
            let sig = self.pair.sign(&SystemRandom::new(), &msg).unwrap();
            Ok(RawAssertion {
                rpid_hash,
                user_present: up,
                sign_count: count,
                auth_data,
                signature: sig.as_ref().to_vec(),
            })
        }
    }

    const W: Duration = Duration::from_secs(5);
    const C: [u8; 32] = [9; 32];

    fn provider(b: fn() -> Behaviour) -> (Fido2Provider<Soft>, tempfile::TempDir) {
        let (soft, cred) = Soft::new(b);
        let d = tempfile::tempdir().unwrap();
        let p = Fido2Provider::new(soft, d.path().join("fido2.json"));
        write_credential(&p.path, &cred).unwrap();
        (p, d)
    }

    #[test]
    fn a_valid_assertion_is_verified_and_the_counter_is_kept() {
        let (p, _d) = provider(|| Behaviour::Sign);
        assert_eq!(p.ask(&C, "t", W), Presence::Verified);
        assert_eq!(p.load().unwrap().counter, 1);
        assert_eq!(p.ask(&C, "t", W), Presence::Verified);
        assert_eq!(p.load().unwrap().counter, 2);
    }

    #[test]
    fn cancel_and_deadline_and_missing_device_map_as_designed() {
        let (p, _d) = provider(|| Behaviour::Cancel);
        assert_eq!(p.ask(&C, "t", W), Presence::Cancelled);
        let (p, _d) = provider(|| Behaviour::Timeout);
        assert_eq!(p.ask(&C, "t", W), Presence::TimedOut);
        let (p, _d) = provider(|| Behaviour::NoDevice);
        assert!(matches!(p.ask(&C, "t", W), Presence::Unavailable(_)));
    }

    /// Each of these must NOT approve.
    #[test]
    fn a_bad_response_is_never_approved() {
        for (name, b) in [
            (
                "no presence flag",
                (|| Behaviour::SignWithoutPresence) as fn() -> Behaviour,
            ),
            ("another relying party", || Behaviour::WrongRp),
        ] {
            let (p, _d) = provider(b);
            assert!(
                matches!(p.ask(&C, "t", W), Presence::Unavailable(_)),
                "{name}"
            );
        }
    }

    #[test]
    fn a_signature_over_another_challenge_is_rejected() {
        let (soft, cred) = Soft::new(|| Behaviour::Sign);
        let a = soft.assert(RPID, &[1; 32], b"id").unwrap();
        // verified against a different challenge than the one signed
        assert!(verify(RPID, &cred, &[2; 32], &a).is_err());
        assert!(verify(RPID, &cred, &[1; 32], &a).is_ok());
    }

    #[test]
    fn a_signature_by_another_key_is_rejected() {
        let (soft, _) = Soft::new(|| Behaviour::Sign);
        let (_, other_cred) = Soft::new(|| Behaviour::Sign);
        let a = soft.assert(RPID, &C, b"id").unwrap();
        assert!(verify(RPID, &other_cred, &C, &a).is_err());
    }

    #[test]
    fn a_counter_that_goes_back_is_a_clone_or_a_replay() {
        let (soft, mut cred) = Soft::new(|| Behaviour::Sign);
        let a = soft.assert(RPID, &C, b"id").unwrap(); // counter 1
        cred.counter = 5;
        assert!(verify(RPID, &cred, &C, &a).unwrap_err().contains("counter"));
        // a key that always reports 0 is not subject to the check
        let (zero, cred0) = Soft::new(|| Behaviour::FixedCounter(0));
        let z = zero.assert(RPID, &C, b"id").unwrap();
        assert!(verify(RPID, &cred0, &C, &z).is_ok());
    }

    /// Review of S3: fields the authenticator reports must agree with what
    /// it SIGNED; each mismatch is rejected.
    #[test]
    fn fields_that_disagree_with_the_signed_data_are_rejected() {
        let (soft, cred) = Soft::new(|| Behaviour::Sign);
        let good = soft.assert(RPID, &C, b"id").unwrap();
        assert!(verify(RPID, &cred, &C, &good).is_ok());
        // signed UP=0, but reported present
        let (nopres, _) = Soft::new(|| Behaviour::SignWithoutPresence);
        let mut a = nopres.assert(RPID, &C, b"id").unwrap();
        a.user_present = true;
        let (_, c2) = (
            0,
            Credential {
                public_key: hex(nopres.pair.public_key().as_ref()),
                ..cred.clone()
            },
        );
        assert!(verify(RPID, &c2, &C, &a)
            .unwrap_err()
            .contains("person present"));
        // signed rp hash of another site, reported correct
        let (wrong, _) = Soft::new(|| Behaviour::WrongRp);
        let mut a = wrong.assert(RPID, &C, b"id").unwrap();
        a.rpid_hash = Sha256::digest(RPID.as_bytes()).to_vec();
        let c3 = Credential {
            public_key: hex(wrong.pair.public_key().as_ref()),
            ..cred.clone()
        };
        assert!(verify(RPID, &c3, &C, &a)
            .unwrap_err()
            .contains("relying party"));
        // signed counter 1, reported 99 (a replayed assertion passing a
        // counter rule)
        let mut a = good.clone();
        a.sign_count = 99;
        assert!(verify(RPID, &cred, &C, &a)
            .unwrap_err()
            .contains("signed one"));
        // authenticator data too short to hold the fixed header
        let mut a = good;
        a.auth_data.truncate(20);
        assert!(verify(RPID, &cred, &C, &a)
            .unwrap_err()
            .contains("too short"));
    }

    #[test]
    fn the_counter_rule_by_case() {
        let (zero, _) = Soft::new(|| Behaviour::FixedCounter(0));
        let (five, _) = Soft::new(|| Behaviour::FixedCounter(5));
        let (six, _) = Soft::new(|| Behaviour::FixedCounter(6));
        for (stored, soft, ok) in [
            (0, &zero, true),
            (0, &five, true),
            (5, &five, false),
            (5, &zero, false),
            (5, &six, true),
        ] {
            let a = soft.assert(RPID, &C, b"id").unwrap();
            let cred = Credential {
                id: hex(b"x"),
                public_key: hex(soft.pair.public_key().as_ref()),
                counter: stored,
            };
            assert_eq!(verify(RPID, &cred, &C, &a).is_ok(), ok, "stored {stored}");
        }
    }

    /// Our own deadline, not one the authenticator reports.
    #[test]
    fn a_device_that_never_answers_times_out_never_approves() {
        struct Hang;
        impl Authenticator for Hang {
            fn assert(&self, _: &str, _: &[u8; 32], _: &[u8]) -> Result<RawAssertion, AuthError> {
                std::thread::sleep(Duration::from_secs(5));
                Err(AuthError::Cancelled)
            }
        }
        let (_, cred) = Soft::new(|| Behaviour::Sign);
        let d = tempfile::tempdir().unwrap();
        let p = Fido2Provider::new(Hang, d.path().join("f.json"));
        write_credential(&p.path, &cred).unwrap();
        assert_eq!(
            p.ask(&C, "t", Duration::from_millis(100)),
            Presence::TimedOut
        );
    }

    #[test]
    fn a_panicking_authenticator_is_unavailable_not_a_timeout() {
        struct Boom;
        impl Authenticator for Boom {
            fn assert(&self, _: &str, _: &[u8; 32], _: &[u8]) -> Result<RawAssertion, AuthError> {
                panic!("boom")
            }
        }
        let (_, cred) = Soft::new(|| Behaviour::Sign);
        let d = tempfile::tempdir().unwrap();
        let p = Fido2Provider::new(Boom, d.path().join("f.json"));
        write_credential(&p.path, &cred).unwrap();
        assert!(matches!(p.ask(&C, "t", W), Presence::Unavailable(_)));
    }

    #[test]
    fn a_corrupt_credential_file_is_unavailable_and_never_panics() {
        for body in [
            r#"{"id":"a\u00e9b","public_key":"00","counter":0}"#,
            r#"{"id":"+f","public_key":"00","counter":0}"#,
            r#"{"id":"zz","public_key":"00","counter":0}"#,
            r#"{"id":"0","public_key":"00","counter":0}"#,
            "not json",
        ] {
            let (soft, _) = Soft::new(|| Behaviour::Sign);
            let d = tempfile::tempdir().unwrap();
            let p = Fido2Provider::new(soft, d.path().join("f.json"));
            std::fs::write(&p.path, body).unwrap();
            assert!(
                matches!(p.ask(&C, "t", W), Presence::Unavailable(_)),
                "{body}"
            );
        }
    }

    #[test]
    fn classify_matches_the_library_names_not_substrings() {
        let e = |s: &str| anyhow_like(s);
        assert_eq!(
            classify(&e("0x2F CTAP2_ERR_USER_ACTION_TIMEOUT x")),
            AuthError::TimedOut
        );
        assert_eq!(
            classify(&e("0x27 CTAP2_ERR_OPERATION_DENIED")),
            AuthError::Cancelled
        );
        assert!(matches!(
            classify(&e("FIDO device not found.")),
            AuthError::NoDevice(_)
        ));
        // a path or length that merely contains a code is not one
        assert!(matches!(
            classify(&e("device path /dev/hidraw0x2f")),
            AuthError::Other(_)
        ));
        assert!(matches!(
            classify(&e("invalid length 0x27xx")),
            AuthError::Other(_)
        ));
        assert!(matches!(
            classify(&e("credential not found on this key")),
            AuthError::Other(_)
        ));
    }

    fn anyhow_like(s: &str) -> impl std::fmt::Display {
        s.to_string()
    }

    #[test]
    fn no_enrolled_credential_is_unavailable() {
        let (soft, _) = Soft::new(|| Behaviour::Sign);
        let d = tempfile::tempdir().unwrap();
        let p = Fido2Provider::new(soft, d.path().join("none.json"));
        match p.ask(&C, "t", W) {
            Presence::Unavailable(w) => assert!(w.contains("enroll"), "{w}"),
            o => panic!("{o:?}"),
        }
    }

    /// ⚠️ LIVE: needs a security key and a touch. Run only with CireSnave at
    /// the desk: `cargo test -p user-request --features fido2 -- --ignored live_fido2`
    #[test]
    #[ignore]
    fn live_fido2_cancel_is_denied() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("fido2.json");
        enroll_hid(&path, None).expect("enrol: touch the key when it blinks");
        let p = Fido2Provider::new(HidAuthenticator, path);
        // when asked, do NOT touch the key: the deadline must be TimedOut
        assert_eq!(
            p.ask(
                &C,
                "user-request LIVE TEST: do not touch",
                Duration::from_secs(10)
            ),
            Presence::TimedOut
        );
    }
}
