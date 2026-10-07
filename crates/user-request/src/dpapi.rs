// SPDX-License-Identifier: MIT OR Apache-2.0
//! DPAPI at user scope, moved from with-secret. ⚠️ Protects files against
//! copies of the disk and backups; ANY process running as this Windows user
//! can decrypt them (WITH-SECRET-DESIGN.md §3).

use crate::store::Protector;

/// DPAPI with a per-tool entropy. The entropy binds a blob to the tool that
/// wrote it, so one tool's blob does not decrypt by accident in another; it
/// is not a secret. with-secret keeps `b"overmind.with-secret.v1"`, the value
/// its existing vault blobs were written with.
pub struct Dpapi {
    pub entropy: &'static [u8],
}

#[cfg(windows)]
impl Protector for Dpapi {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        call(plain, true, self.entropy)
    }
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        call(blob, false, self.entropy)
    }
}

#[cfg(windows)]
fn call(data: &[u8], protect: bool, entropy: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let ent = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        if protect {
            CryptProtectData(
                &input,
                None,
                Some(&ent),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptUnprotectData(
                &input,
                None,
                Some(&ent),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    }
    .map_err(|e| {
        format!(
            "DPAPI {}: {e}",
            if protect { "protect" } else { "unprotect" }
        )
    })?;
    let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.pbData as _)));
    }
    Ok(bytes)
}

#[cfg(not(windows))]
impl Protector for Dpapi {
    fn protect(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI is Windows-only".into())
    }
    fn unprotect(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI is Windows-only".into())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_round_trip_works_and_another_entropy_cannot_read_it() {
        let a = Dpapi { entropy: b"a" };
        let blob = a.protect(b"plain").unwrap();
        assert_ne!(blob, b"plain");
        assert_eq!(a.unprotect(&blob).unwrap(), b"plain");
        assert!(Dpapi { entropy: b"b" }.unprotect(&blob).is_err());
    }
}
