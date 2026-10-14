// SPDX-License-Identifier: MIT OR Apache-2.0
//! U6 (docs/LINUX-PORT-DESIGN.md section 4): no approval channel reads a
//! terminal, behind no flag and no environment variable. A same-user process
//! can type into a pty, so a terminal `y/n` would turn "a person approved"
//! into "something on this machine answered".
//!
//! Two rules over `crates/*/src/**/*.rs`, enumerated with `git ls-files`
//! (never a disk walk; when git cannot answer the test FAILS, it never scans
//! nothing), with `//` and `/* */` comments and string literals stripped:
//! 1. a file that implements `Consent` or `Channel` mentions none of the
//!    terminal-reading tokens;
//! 2. only the files in `STDIN_READERS` mention stdin at all.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The only files that touch stdin, each with its reason. A new reader fails
/// the test until a reviewer adds it here.
const STDIN_READERS: &[(&str, &str)] = &[(
    "crates/with-secret/src/main.rs",
    "`hook` reads the hook JSON; the child inherits stdin; `read_hidden` reads a \
     secret VALUE the person types (not an approval)",
)];

/// Tokens that read a terminal or open one.
const TERMINAL_TOKENS: &[&str] = &[
    "stdin",
    "read_line",
    "IsTerminal",
    "is_terminal",
    "rpassword",
    "File::open",
    "OpenOptions",
];

/// `src` with comments and string/char literals blanked.
fn strip(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == 'r' && raw_start(&b, i) {
            let mut j = i + 1;
            let mut hashes = 0;
            while b.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            j += 1; // the opening quote
            while j < b.len() {
                if b[j] == '"' && (0..hashes).all(|k| b.get(j + 1 + k) == Some(&'#')) {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            out.push_str("\"\"");
            i = j;
        } else if c == '\'' && next == Some('\\') {
            // an escaped char literal: '\"', '\n', '\u{..}'
            i += 2;
            while i < b.len() && b[i] != '\'' {
                i += 1;
            }
            i += 1;
            out.push_str("''");
        } else if c == '\'' && b.get(i + 2) == Some(&'\'') {
            // a one-character literal such as '"'; a lifetime has no closing quote
            i += 3;
            out.push_str("''");
        } else if c == '"' {
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            out.push_str("\"\"");
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// True when the `r` at `i` begins a raw string, not an identifier ending in r.
fn raw_start(b: &[char], i: usize) -> bool {
    // a `b` or `c` immediately before is a literal prefix (br#".."#, cr".."),
    // not part of an identifier, unless something alphanumeric precedes it
    let mut k = i;
    if k > 0 && (b[k - 1] == 'b' || b[k - 1] == 'c') {
        k -= 1;
    }
    if k > 0 && (b[k - 1].is_alphanumeric() || b[k - 1] == '_') {
        return false;
    }
    let mut j = i + 1;
    while b.get(j) == Some(&'#') {
        j += 1;
    }
    b.get(j) == Some(&'"')
}

/// Any `... Consent for X` or `... Channel for X`, however the path is
/// written or spaced.
fn implements_channel(code: &str) -> bool {
    let flat = code.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.contains("Consent for ") || flat.contains("Channel for ")
}

/// Case-insensitive, so `Stdin` and `STDIN_FILENO` count.
fn hits(code: &str, tokens: &[&str]) -> Vec<String> {
    let low = code.to_lowercase();
    tokens
        .iter()
        .filter(|t| low.contains(&t.to_lowercase()))
        .map(|t| t.to_string())
        .collect()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/user-request has a repo root two levels up")
        .to_path_buf()
}

/// The tracked source files, from the index.
fn sources(root: &Path) -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "ls-files",
            "--",
            "crates/*/src/*.rs",
            "crates/*/src/**/*.rs",
        ])
        .output()
        .expect("git must run: this test enumerates the index and never walks the disk");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let files: Vec<String> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    assert!(
        files.len() > 10,
        "git ls-files returned {} files: the scan would be vacuous",
        files.len()
    );
    files
}

fn is_reader(path: &str) -> bool {
    STDIN_READERS.iter().any(|(p, _)| *p == path)
}

/// Violations over `(path, source)` pairs.
fn violations(files: &[(String, String)]) -> Vec<String> {
    let mut v = Vec::new();
    for (path, src) in files {
        let code = strip(src);
        if implements_channel(&code) {
            let h = hits(&code, TERMINAL_TOKENS);
            if !h.is_empty() {
                v.push(format!(
                    "{path}: implements Consent/Channel and mentions {h:?}"
                ));
            }
        }
        if code.to_lowercase().contains("stdin") && !is_reader(path) {
            v.push(format!(
                "{path}: mentions stdin but is not in STDIN_READERS (add it, with a reason, \
                 only if it is not an approval)"
            ));
        }
    }
    v
}

#[test]
fn no_approval_channel_reads_a_terminal() {
    let root = repo_root();
    let files: Vec<(String, String)> = sources(&root)
        .into_iter()
        .map(|p| {
            let s = std::fs::read_to_string(root.join(&p)).unwrap_or_else(|e| panic!("{p}: {e}"));
            (p, s)
        })
        .collect();
    // the scan sees the files it is meant to
    for must in [
        "crates/user-request/src/channel.rs",
        "crates/user-request/src/hello.rs",
        "crates/with-secret/src/main.rs",
    ] {
        assert!(files.iter().any(|(p, _)| p == must), "{must} not scanned");
    }
    let v = violations(&files);
    assert!(
        v.is_empty(),
        "terminal-reading code near an approval channel:\n{}",
        v.join("\n")
    );
}

#[test]
fn the_allowlist_is_not_stale() {
    let root = repo_root();
    for (p, _) in STDIN_READERS {
        let s = std::fs::read_to_string(root.join(p)).expect("an allowlisted file exists");
        assert!(
            strip(&s).contains("stdin"),
            "{p} no longer reads stdin: remove it"
        );
    }
}

// positive controls: the scan flags what it is meant to flag

#[test]
fn control_an_impl_consent_that_reads_stdin_is_flagged() {
    let planted = (
        "crates/x/src/evil.rs".to_string(),
        "impl Consent for Evil { fn ask(&self) { std::io::stdin().read_line(&mut s); } }"
            .to_string(),
    );
    assert!(!violations(&[planted]).is_empty());
}

#[test]
fn control_opening_dev_tty_in_a_channel_is_flagged() {
    let planted = (
        "crates/x/src/evil.rs".to_string(),
        "impl Channel for Evil { fn present() { std::fs::File::open(\"/dev/tty\"); } }".to_string(),
    );
    assert!(!violations(&[planted]).is_empty());
}

#[test]
fn control_a_stdin_reader_outside_the_allowlist_is_flagged() {
    let planted = (
        "crates/x/src/helper.rs".to_string(),
        "fn f() { let _ = std::io::stdin(); }".to_string(),
    );
    assert!(!violations(&[planted]).is_empty());
}

/// Review of S2: literals that used to blind the stripper.
#[test]
fn control_a_char_literal_quote_does_not_hide_a_later_stdin_read() {
    for hiding in [
        "let q = '\"'; std::io::stdin(); let s = \"x\";",
        "let q = '\\\"'; std::io::stdin(); let s = \"x\";",
        "let b = br#\"a\"b\"#; std::io::stdin(); let s = \"x\";",
        "let b = b\"x\"; std::io::stdin(); let s = \"y\";",
        "let c = cr#\"a\"b\"#; std::io::stdin(); let s = \"x\";",
    ] {
        let src = format!("impl Consent for Evil {{ fn ask(&self) {{ {hiding} }} }}");
        assert!(
            !violations(&[("crates/x/src/evil.rs".to_string(), src)]).is_empty(),
            "{hiding}"
        );
    }
}

#[test]
fn control_a_path_qualified_impl_and_odd_case_are_still_checked() {
    let src =
        "impl  user_request::consent::Consent   for Evil { fn f() { let _ = STDIN_FILENO; } }";
    assert!(!violations(&[("crates/x/src/evil.rs".to_string(), src.into())]).is_empty());
}

#[test]
fn control_lifetimes_do_not_start_a_literal() {
    let ok = "impl<'a> Consent for Fine<'a> { fn ask(&self, p: &'a str) {} }".to_string();
    assert!(violations(&[("crates/x/src/fine.rs".to_string(), ok)]).is_empty());
    let bad = "impl<'a> Consent for Evil<'a> { fn ask(&self, p: &'a str) { std::io::stdin(); } }";
    assert!(!violations(&[("crates/x/src/evil.rs".to_string(), bad.into())]).is_empty());
}

#[test]
fn control_mentions_in_comments_and_strings_are_not_hits() {
    let ok = (
        "crates/x/src/fine.rs".to_string(),
        "impl Consent for Fine { /* stdin */ fn ask(&self) { // reads stdin? no\n \
         let _ = \"stdin\"; let _ = r#\"is_terminal\"#; } }"
            .to_string(),
    );
    assert!(violations(&[ok]).is_empty());
}
