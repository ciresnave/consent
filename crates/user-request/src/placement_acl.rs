// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows: refuse a placement target whose effective DACL grants access to
//! anyone but its owner, SYSTEM or Administrators.
//!
//! Fail closed: a missing DACL (everyone) or any API error is a refusal. Only
//! ACCESS_ALLOWED entries count; a deny entry never widens access.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// SAFETY: `sid` must point to a valid SID.
unsafe fn sid_string(sid: PSID) -> Result<String, String> {
    let mut out = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut out) }.map_err(|e| e.to_string())?;
    let s = unsafe { out.to_string() }.map_err(|e| e.to_string());
    unsafe { LocalFree(Some(HLOCAL(out.0 as _))) };
    s
}

/// The SID string of the user this process runs as.
fn current_user() -> Result<String, String> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).map_err(|e| e.to_string())?;
        let mut need = 0u32;
        let _ = GetTokenInformation(tok, TokenUser, None, 0, &mut need);
        let mut buf = vec![0u64; (need as usize).div_ceil(8).max(1)];
        let r = GetTokenInformation(
            tok,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            need,
            &mut need,
        );
        let _ = CloseHandle(tok);
        r.map_err(|e| e.to_string())?;
        sid_string((*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}

/// Ok when every allowed ACE of `path`'s DACL names the owner, the current
/// user, SYSTEM or Administrators; Err names the first other SID, or the failure.
pub fn require_owner_only(path: &Path) -> Result<(), String> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    };
    if rc.0 != 0 {
        return Err(format!("cannot read the ACL (error {})", rc.0));
    }
    let result = (|| {
        if dacl.is_null() {
            return Err("it has no DACL, so everyone has access".to_string());
        }
        let owner_s = unsafe { sid_string(owner) }?;
        let me = current_user()?;
        let count = unsafe { (*dacl).AceCount };
        for i in 0..u32::from(count) {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            unsafe { GetAce(dacl, i, &mut ace) }.map_err(|e| e.to_string())?;
            let hdr = ace as *const ACCESS_ALLOWED_ACE;
            if unsafe { (*hdr).Header.AceType } != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            let sid = PSID(unsafe { std::ptr::addr_of!((*hdr).SidStart) } as *mut _);
            let s = unsafe { sid_string(sid) }?;
            if s != owner_s && s != me && s != SYSTEM && s != ADMINISTRATORS {
                return Err(format!("it grants access to {s}"));
            }
        }
        Ok(())
    })();
    unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    result
}

/// Test helper: drops inherited entries (a CI or sandbox temp dir may grant a
/// group) and leaves exactly the current user.
#[cfg(test)]
pub(crate) fn lock_to_current_user(f: &Path) {
    let me = current_user().unwrap();
    let st = std::process::Command::new("icacls")
        .arg(f)
        .args(["/inheritance:r", "/grant:r", &format!("*{me}:F")])
        .output()
        .unwrap();
    assert!(st.status.success(), "{st:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn a_locked_down_file_passes() {
        let d = tempdir().unwrap();
        let f = d.path().join("a.env");
        std::fs::write(&f, b"x").unwrap();
        lock_to_current_user(&f);
        assert_eq!(require_owner_only(&f), Ok(()));
    }

    #[test]
    fn a_file_granted_to_everyone_is_refused() {
        let d = tempdir().unwrap();
        let f = d.path().join("a.env");
        std::fs::write(&f, b"x").unwrap();
        let st = std::process::Command::new("icacls")
            .arg(&f)
            .args(["/grant", "*S-1-1-0:R"])
            .output()
            .unwrap();
        assert!(st.status.success(), "{st:?}");
        let e = require_owner_only(&f).unwrap_err();
        assert!(e.contains("S-1-1-0"), "{e}");
    }

    #[test]
    fn a_missing_file_fails_closed() {
        let d = tempdir().unwrap();
        assert!(require_owner_only(&d.path().join("none")).is_err());
    }
}
