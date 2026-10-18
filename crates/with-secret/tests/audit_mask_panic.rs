// SPDX-License-Identifier: MIT OR Apache-2.0
//! Audit finding 6 (2026-10-18): `unhex` slices a &str by byte offset.
use with_secret::mask::{mask_with_hashes, HashMask};

#[test]
fn a_non_ascii_salt_does_not_panic() {
    // "a€" is 4 bytes; bytes 0..2 end inside the euro sign
    let m = HashMask {
        name: "X".into(),
        len: 3,
        salt_hex: "a€".into(),
        digest_hex: "00".into(),
    };
    let _ = mask_with_hashes("abcdef", &[m]);
}
