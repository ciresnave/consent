// SPDX-License-Identifier: MIT OR Apache-2.0
//! Masking. ⚠️ EXACT MATCHES ONLY: a URL-encoded, base64-encoded or split
//! value passes through (design §3).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::Vault;

pub fn label(name: &str) -> String {
    format!("[with-secret:{name}]")
}

/// Masks known plaintext values in a byte stream that arrives in chunks.
/// ⚠️ A value split across two reads must still be caught: the unmatched tail
/// that could be the START of a value is held back until the next chunk.
pub struct StreamMasker {
    needles: Vec<(Vec<u8>, Vec<u8>)>, // (value, label), longest value first
    carry: Vec<u8>,
}

impl StreamMasker {
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        let mut needles: Vec<(Vec<u8>, Vec<u8>)> = pairs
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(n, v)| (v.as_bytes().to_vec(), label(n).into_bytes()))
            .collect();
        needles.sort_by_key(|n| std::cmp::Reverse(n.0.len()));
        Self {
            needles,
            carry: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.carry.extend_from_slice(chunk);
        self.process(false)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.process(true)
    }

    fn process(&mut self, finish: bool) -> Vec<u8> {
        let buf = std::mem::take(&mut self.carry);
        let mut out = Vec::with_capacity(buf.len());
        let mut i = 0;
        'scan: while i < buf.len() {
            for (needle, lab) in &self.needles {
                if buf[i..].starts_with(needle) {
                    out.extend_from_slice(lab);
                    i += needle.len();
                    continue 'scan;
                }
            }
            let rest = &buf[i..];
            if !finish
                && self
                    .needles
                    .iter()
                    .any(|(n, _)| n.len() > rest.len() && n.starts_with(rest))
            {
                self.carry = rest.to_vec();
                return out;
            }
            out.push(buf[i]);
            i += 1;
        }
        out
    }
}

/// What the HOOK knows about a secret: its length and a salted hash. ⚠️ The
/// hook never decrypts the vault (design §2.4). This leaks each value's
/// length - accepted, and one reason for MIN_VALUE_LEN.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HashMask {
    pub name: String,
    pub len: usize,
    pub salt_hex: String,
    pub digest_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn salted(salt: &[u8], value: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(value);
    hex(&h.finalize())
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

impl HashMask {
    pub fn new(name: &str, value: &str) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| format!("random salt: {e}"))?;
        Ok(Self {
            name: name.into(),
            len: value.len(),
            salt_hex: hex(&salt),
            digest_hex: salted(&salt, value.as_bytes()),
        })
    }
}

pub fn masks_json(vault: &Vault) -> Result<Vec<u8>, String> {
    let masks: Result<Vec<HashMask>, String> = vault
        .secrets
        .iter()
        .map(|(n, s)| HashMask::new(n, &s.value))
        .collect();
    serde_json::to_vec_pretty(&masks?).map_err(|e| e.to_string())
}

/// Replace every window of `text` whose salted hash matches a mask. Cost is
/// one SHA-256 per (position, mask); fine for tool output sizes.
pub fn mask_with_hashes(text: &str, masks: &[HashMask]) -> (String, usize) {
    let mut sorted: Vec<(&HashMask, Vec<u8>)> = masks
        .iter()
        .filter(|m| m.len > 0)
        .map(|m| (m, unhex(&m.salt_hex)))
        .collect();
    sorted.sort_by_key(|m| std::cmp::Reverse(m.0.len));
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut hits = 0;
    let mut i = 0;
    'scan: while i < bytes.len() {
        for (m, salt) in &sorted {
            if i + m.len <= bytes.len() && salted(salt, &bytes[i..i + m.len]) == m.digest_hex {
                out.extend_from_slice(label(&m.name).as_bytes());
                i += m.len;
                hits += 1;
                continue 'scan;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // A match of a valid-UTF-8 value inside valid UTF-8 starts and ends on
    // char boundaries, so this never actually substitutes.
    (String::from_utf8_lossy(&out).into_owned(), hits)
}

pub fn mask_json(value: &serde_json::Value, masks: &[HashMask]) -> (serde_json::Value, usize) {
    use serde_json::Value;
    match value {
        Value::String(s) => {
            let (m, n) = mask_with_hashes(s, masks);
            (Value::String(m), n)
        }
        Value::Array(items) => {
            let mut n = 0;
            let out = items
                .iter()
                .map(|v| {
                    let (m, k) = mask_json(v, masks);
                    n += k;
                    m
                })
                .collect();
            (Value::Array(out), n)
        }
        Value::Object(map) => {
            let mut n = 0;
            let out = map
                .iter()
                .map(|(k, v)| {
                    let (m, c) = mask_json(v, masks);
                    n += c;
                    (k.clone(), m)
                })
                .collect();
            (Value::Object(out), n)
        }
        other => (other.clone(), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "postgres://owner:Sup3rS3cret@db.example/tj";

    fn run(m: &mut StreamMasker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for c in chunks {
            out.extend(m.push(c));
        }
        out.extend(m.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn value_in_one_chunk_is_masked() {
        let mut m = StreamMasker::new(&[("TJ_DB", V)]);
        assert_eq!(
            run(&mut m, &[format!("url={V} ok\n").as_bytes()]),
            "url=[with-secret:TJ_DB] ok\n"
        );
    }

    #[test]
    fn test_value_split_across_chunks_is_masked() {
        let text = format!("a {V} b");
        let bytes = text.as_bytes();
        for cut in 1..bytes.len() {
            let mut m = StreamMasker::new(&[("TJ_DB", V)]);
            let got = run(&mut m, &[&bytes[..cut], &bytes[cut..]]);
            assert_eq!(got, "a [with-secret:TJ_DB] b", "cut at {cut}");
        }
    }

    #[test]
    fn a_partial_prefix_at_the_end_is_released_on_finish() {
        let mut m = StreamMasker::new(&[("TJ_DB", V)]);
        assert_eq!(
            run(&mut m, &[b"tail postgres://own"]),
            "tail postgres://own"
        );
    }

    #[test]
    fn longest_value_wins_when_one_contains_another() {
        let mut m = StreamMasker::new(&[("SHORT", "Sup3rS3cret!!"), ("LONG", "xxSup3rS3cret!!yy")]);
        assert_eq!(
            run(&mut m, &[b"[xxSup3rS3cret!!yy]"]),
            "[[with-secret:LONG]]"
        );
    }

    #[test]
    fn output_without_secrets_is_byte_identical() {
        let mut m = StreamMasker::new(&[("TJ_DB", V)]);
        let text = "nothing to see\r\nhere \u{1F600}\n";
        assert_eq!(run(&mut m, &[text.as_bytes()]), text);
    }

    #[test]
    fn hash_masker_finds_the_value_without_holding_it() {
        let hm = HashMask::new("TJ_DB", V).unwrap();
        let shown = serde_json::to_string(&hm).unwrap();
        assert!(!shown.contains("Sup3rS3cret"), "{shown}");
        let (out, n) = mask_with_hashes(&format!("x {V} y {V}"), &[hm]);
        assert_eq!(out, "x [with-secret:TJ_DB] y [with-secret:TJ_DB]");
        assert_eq!(n, 2);
    }

    #[test]
    fn hash_masker_leaves_other_text_alone() {
        let hm = HashMask::new("TJ_DB", V).unwrap();
        let (out, n) = mask_with_hashes("postgres://owner:WRONG@db.example/tj", &[hm]);
        assert_eq!(n, 0);
        assert_eq!(out, "postgres://owner:WRONG@db.example/tj");
    }

    #[test]
    fn salts_differ_so_equal_values_do_not_hash_alike() {
        let a = HashMask::new("A_A", V).unwrap();
        let b = HashMask::new("B_B", V).unwrap();
        assert_ne!(a.digest_hex, b.digest_hex);
    }

    #[test]
    fn mask_json_masks_every_string_and_keeps_shape() {
        let hm = HashMask::new("TJ_DB", V).unwrap();
        let v = serde_json::json!({"stdout": format!("conn {V}"), "stderr": "", "code": 0,
                                   "nested": [V]});
        let (out, n) = mask_json(&v, &[hm]);
        assert_eq!(n, 2);
        assert_eq!(out["stdout"], "conn [with-secret:TJ_DB]");
        assert_eq!(out["nested"][0], "[with-secret:TJ_DB]");
        assert_eq!(out["code"], 0);
    }
}
