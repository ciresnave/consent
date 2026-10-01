// SPDX-License-Identifier: MIT OR Apache-2.0
//! DPAPI at user scope. ⚠️ Protects the vault against copies of the disk and
//! backups; ANY process running as this Windows user can decrypt it (design §3).

use crate::vault::Protector;

/// Bound to this tool, so a blob from another DPAPI user on the account
/// does not decrypt by accident. Not a secret - an accident guard.
#[cfg(windows)]
const ENTROPY: &[u8] = b"overmind.with-secret.v1";

pub struct DpapiProtector;

#[cfg(windows)]
impl Protector for DpapiProtector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String> {
        call(plain, true)
    }
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        call(blob, false)
    }
}

#[cfg(windows)]
fn call(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let ent = CRYPT_INTEGER_BLOB {
        cbData: ENTROPY.len() as u32,
        pbData: ENTROPY.as_ptr() as *mut u8,
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
impl Protector for DpapiProtector {
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
    fn round_trip_and_ciphertext_differs() {
        let p = DpapiProtector;
        let blob = p.protect(b"a-secret-value-123").unwrap();
        assert_ne!(blob, b"a-secret-value-123");
        assert_eq!(p.unprotect(&blob).unwrap(), b"a-secret-value-123");
    }
    #[test]
    fn tampered_blob_fails() {
        let p = DpapiProtector;
        let mut blob = p.protect(b"a-secret-value-123").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(p.unprotect(&blob).is_err());
    }
}
