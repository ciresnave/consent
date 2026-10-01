# `with-secret` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Rust tool, `with-secret`. It stores secrets in a vault encrypted with DPAPI (Windows' built-in per-user encryption), and puts one secret into one child process only after CireSnave has approved it with a Windows Hello prompt. One approval covers one lane and one secret until local midnight at the latest, and ends early if the lane restarts. The tool also ships Claude Code hooks that block environment dumps and mask known secret values in tool output.

**Architecture:** A new workspace crate, `crates/with-secret`, alongside `lane-restart`. It reuses `lane-restart`'s process table and lane-state reader to identify which lane is asking. Pure logic is unit-tested against fakes:
- vault model;
- maskers;
- identity resolution;
- approval cache and its expiry;
- dump-command classifier;
- authorisation flow.

Two Windows-only adapters sit behind traits. `DpapiProtector` encrypts the vault and `HelloConsent` shows the approval prompt. Task 0 proves both on this machine before anything else is built. There is no resident process: each invocation decrypts, checks, asks if needed, runs the child and exits (design §2.3).

**Tech Stack:** Rust 2021, a workspace member, with these crates:
- `windows`: Windows Hello and DPAPI;
- `windows-sys`: console echo control, already a `lane-restart` dependency;
- `serde`/`serde_json`, `chrono`, `sha2`, `hmac` and `getrandom`;
- `lane-restart` as a path dependency.

**Spec:** `WITH-SECRET-DESIGN.md` (committed with this plan). Its source is board item 81 in `C:\Projects\CIRESNAVE-DECISIONS.md`, plus the PM's approval of 2026-10-01.

## Global Constraints

- **Approval rule** (CireSnave, 2026-09-28, quoted exactly): *"Approve once per lane per secret with a timeout so that an approval now isn't still valid tomorrow."* What it means for the code:
  - one approval covers ONE lane and ONE secret;
  - it expires at local midnight at the latest, and `--window-mins` can make it shorter, never longer;
  - it is void when the lane restarts, because the session id and Claude process identity change.
- **Every access asks CireSnave** through Windows Hello (`UserConsentVerifier`). The prompt names the secret, the lane, the command and the reason. Never route approval through GitHub, claude-peers or the PM (design §2.2).
- **Secrets never sit in any process's environment except the one child `with-secret` starts.** Never in argv, never in a log, never in `Debug` output.
- **The honest limit is stated exactly as design §3 states it**, in code comments, CLI help and docs: this stops accidental exposure, not deliberate misuse by a same-user process. Never claim more.
- **Use the newest version of every dependency.** CireSnave: *"I want all of my projects' dependencies on their most recent versions at all times."* Add them with `cargo add` and no version, so the newest published version is recorded.
- **One version number for the whole project.** The crate uses `version.workspace = true`. Do not bump the version in a PR: the PM allocates it at gate time.
- **Every new `.rs` file starts with** `// SPDX-License-Identifier: MIT OR Apache-2.0`, or CI's `spdx_gate.py` fails.
- **Fail closed on authorisation; fail open, with a stderr warning, in the hooks.**
  - Any error in identity, the vault, the cache or consent means no secret is released.
  - A hook that errors exits 0 and warns. A buggy hook must not brick every lane, and the hooks are defence in depth, not the gate.
- **Windows is the deployment platform.** `cfg(windows)` adapters, plus a non-Windows stub that returns `Unavailable` so `cargo test` still runs on CI's ubuntu runner.

## Review Focus

1. **A secret value split across two reads of the child's output.** A masker that only checks each chunk on its own prints the value in two halves. Pinned in Task 3: `test_value_split_across_chunks_is_masked`.
2. **The lane restarts mid-day.** The Claude process and session are new, so the old approval must not cover them, even for the same role and secret before midnight. Pinned in Task 5: `test_restart_voids_approval`.
3. **A secret is approved at 23:50 local time.** It expires at 00:00, not 23:50 tomorrow. A configured window longer than the time left until midnight is clamped. Pinned in Task 5: `test_late_grant_expires_at_midnight`.
4. **A tampered or hand-written approval entry** (wrong MAC, or edited fields) is ignored, never honoured. Pinned in Task 5: `test_tampered_entry_is_ignored`.
5. **`with-secret NAME -- env`, or a child that would dump its own environment.** It is refused before any consent is requested. Pinned in Task 7: `test_dump_child_refused_before_consent`.

---

## File structure

| File | Responsibility |
|---|---|
| `Cargo.toml` (root) | add `crates/with-secret` to `members` |
| `crates/with-secret/Cargo.toml` | the crate manifest |
| `crates/with-secret/src/lib.rs` | module list |
| `crates/with-secret/src/vault.rs` | `Secret`, `Vault`, name and value rules, `Protector` trait, `VaultStore` (vault file, masks file, approval key) |
| `crates/with-secret/src/dpapi.rs` | `DpapiProtector` (Windows), with a stub elsewhere |
| `crates/with-secret/src/mask.rs` | `StreamMasker` (plaintext, streaming), `HashMask` and `mask_with_hashes` (for the hook), `mask_json` |
| `crates/with-secret/src/identity.rs` | `Requester`, `resolve` (process table plus lane-state, to find which lane is asking) |
| `crates/with-secret/src/approval.rs` | `Approval`, `expiry`, `ApprovalCache` (HMAC-signed entries) |
| `crates/with-secret/src/consent.rs` | `ConsentRequest`, `ConsentOutcome`, `Consent` trait, `prompt_text` |
| `crates/with-secret/src/hello.rs` | `HelloConsent` (Windows), with a stub elsewhere |
| `crates/with-secret/src/dumpcheck.rs` | `dump_reason`: is this command or file read an environment dump |
| `crates/with-secret/src/audit.rs` | an append-only JSON-lines access log that never contains a value |
| `crates/with-secret/src/run.rs` | `RunArgs`, `parse_run`, `authorize`: the decision, with no I/O |
| `crates/with-secret/src/main.rs` | CLI: `with-secret NAME --reason R -- cmd…`, `vault {list,set,remove,check}`, `hook {pre-tool-use,post-tool-use}` |
| `WITH-SECRET-DESIGN.md` | spec (committed with this plan); Task 0 appends its findings |
| `docs/WITH-SECRET-RUNBOOK.md` | install, adding a secret, wiring the hooks, least privilege, migrating `TJ_PROD_DATABASE_URL` |

Data directory: `%LOCALAPPDATA%\OverMind\with-secret\`, holding:
- `vault.bin`, DPAPI-encrypted;
- `masks.json`, salted hashes only;
- `approvals.key`, DPAPI-encrypted;
- `approvals.json`, HMAC-signed;
- `access.log`.

---

### Task 0: Spike — prove Windows Hello, DPAPI and the hook protocol on THIS machine

The rest of the plan rests on four facts that have not been measured here. Measure them first. If any one fails, **stop and report to the PM**. Do not adapt the design yourself.

**Files:**
- Create: `crates/with-secret/` with the manifest below and a throwaway `src/bin/spike.rs` (deleted at the end of this task)
- Modify: `Cargo.toml` (root `members`)
- Modify: `WITH-SECRET-DESIGN.md` (append §4, "Measured 2026-10-xx")

- [ ] **Step 1: Scaffold the crate.** In the root `Cargo.toml`, change `members = ["crates/lane-restart"]` to `members = ["crates/lane-restart", "crates/with-secret"]`. Create `crates/with-secret/Cargo.toml`:

```toml
[package]
name = "with-secret"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "Runs one command with one secret, after its owner approves via Windows Hello. Stops accidental exposure, not deliberate misuse - see WITH-SECRET-DESIGN.md section 3."

[dependencies]

[dev-dependencies]
```

Then run from `crates/with-secret`:

```bash
cargo add serde --features derive
cargo add serde_json chrono sha2 hmac getrandom
cargo add chrono --features serde
cargo add lane-restart --path ../lane-restart
cargo add windows-sys --features Win32_Foundation,Win32_System_Console
cargo add windows --features Foundation,Security_Credentials_UI,Win32_Foundation,Win32_System_WinRT,Win32_UI_WindowsAndMessaging,Win32_Security_Cryptography,Win32_System_Memory
cargo add --dev tempfile
```

`hmac` and `sha2` must use the same `digest` major version. If `cargo build` reports a `digest` trait mismatch between them, run `cargo tree -i digest`. Pick the newest `hmac` whose `digest` matches the newest `sha2`, and record which in the commit message.

Create `crates/with-secret/src/lib.rs`, containing only `// SPDX-License-Identifier: MIT OR Apache-2.0`, for now.

- [ ] **Step 2: Write the spike binary.** Create `crates/with-secret/src/bin/spike.rs`:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! THROWAWAY (deleted at the end of Task 0). Measures what the plan assumes.
use windows::core::{factory, Interface, HSTRING};
use windows::Foundation::{AsyncStatus, IAsyncInfo, IAsyncOperation};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

fn main() -> windows::core::Result<()> {
    let which = std::env::args().nth(1).unwrap_or_default();
    let avail = UserConsentVerifier::CheckAvailabilityAsync()?.get()?;
    println!("availability: {avail:?} (Available = {:?})", UserConsentVerifierAvailability::Available);
    if which == "dpapi" {
        return dpapi_roundtrip();
    }
    let hwnd: HWND = match which.as_str() {
        "console" => unsafe { GetConsoleWindow() },
        _ => unsafe { GetForegroundWindow() },
    };
    println!("owner hwnd ({which}): {:?}", hwnd);
    let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
    let op: IAsyncOperation<UserConsentVerificationResult> = unsafe {
        interop.RequestVerificationForWindowAsync(hwnd, &HSTRING::from(
            "SPIKE: with-secret test prompt. Approve or cancel - nothing is released."))?
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while op.cast::<IAsyncInfo>()?.Status()? == AsyncStatus::Started {
        if std::time::Instant::now() > deadline {
            op.cast::<IAsyncInfo>()?.Cancel()?;
            println!("timed out, cancelled");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    println!("result: {:?}", op.GetResults()?);
    Ok(())
}

fn dpapi_roundtrip() -> windows::core::Result<()> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let plain = b"spike-value-123456";
    let entropy = b"overmind.with-secret.v1";
    let mut out = CRYPT_INTEGER_BLOB::default();
    let input = CRYPT_INTEGER_BLOB { cbData: plain.len() as u32, pbData: plain.as_ptr() as *mut u8 };
    let ent = CRYPT_INTEGER_BLOB { cbData: entropy.len() as u32, pbData: entropy.as_ptr() as *mut u8 };
    unsafe { CryptProtectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)? };
    let blob = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { let _ = LocalFree(Some(HLOCAL(out.pbData as _))); }
    let mut back = CRYPT_INTEGER_BLOB::default();
    let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
    unsafe { CryptUnprotectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut back)? };
    let got = unsafe { std::slice::from_raw_parts(back.pbData, back.cbData as usize).to_vec() };
    unsafe { let _ = LocalFree(Some(HLOCAL(back.pbData as _))); }
    println!("dpapi roundtrip equal: {}  blob != plain: {}", got == plain, blob != plain);
    Ok(())
}
```

The `windows` crate's API names shift between releases: `LocalFree`'s signature, `HWND`'s representation, and where `.get()` lives. If this does not compile against the version `cargo add` chose, fix it against that version's docs (docs.rs/windows) and **record each change in the §4 findings**. Tasks 2 and 6 reuse this exact code, so they inherit the fixes.

- [ ] **Step 3: Measure (CireSnave must be at the desktop for 3b and 3c — ask the PM to arrange it).**

Run each command from a lane's own Bash tool, which is the real calling context:

- (3a) `cargo run -p with-secret --bin spike -- dpapi`. Expected: `availability: Available` and `dpapi roundtrip equal: true  blob != plain: true`.
- (3b) `cargo run -p with-secret --bin spike -- foreground`. Expected: a Windows Hello dialog with the spike text appears **on CireSnave's screen**. He approves and the result is `Verified`. Run it a second time; he cancels, and the result is `Canceled`.
- (3c) `cargo run -p with-secret --bin spike -- console`. Same as 3b. Record which owner window makes the dialog appear in front and accept input: `foreground`, `console`, or both. If **neither** does, STOP and report to the PM.
- (3d) Hook protocol, in a scratch directory **outside** every repo. Do not touch any lane's settings.
  1. Create `.claude/settings.json` with one `PostToolUse` hook (matcher `Bash`) that runs a script. The script reads stdin, appends it to `hook-in.json`, then prints `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":"REPLACED"}}`.
  2. Add one `PreToolUse` hook that prints `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"spike deny"}}` whenever the command contains `spikedeny`.
  3. Start `claude` there and ask it to run `echo hello` and then `echo spikedeny`.
  4. Record:
     - **(i)** whether Claude saw `REPLACED` instead of `hello`;
     - **(ii)** the exact field name and JSON shape of the tool's result in `hook-in.json`. The plan assumes `tool_response`, an object with string fields such as `stdout` and `stderr`;
     - **(iii)** whether `updatedToolOutput` must be a string or may be an object of the same shape (repeat with the object form);
     - **(iv)** whether the deny blocked the call and Claude saw `spike deny`.

  If (i) is false, output masking via the hook is impossible. Record that, and Task 8's `post-tool-use` is dropped from scope, with the gap stated in the runbook. It is not a reason to stop, because `with-secret`'s own masking (Task 7) is unaffected.

- [ ] **Step 4: Record the findings.** Append to `WITH-SECRET-DESIGN.md`:

```markdown
## 4. Measured 2026-10-xx (Task 0 spike, on CireSnave's machine)

- `windows` crate version: X. API changes from the plan's code: (list, or "none").
- DPAPI round trip: (result).
- Hello availability: (result). Owner window that works: foreground | console | both.
- Hook: updatedToolOutput replaces Bash output: yes/no. Result field: `<name>`, shape: (...).
  updatedToolOutput accepts: string | object | both. PreToolUse JSON deny: works yes/no.
```

- [ ] **Step 5: Delete the spike, then commit.**

```bash
git rm -q --cached crates/with-secret/src/bin/spike.rs 2>/dev/null; rm -rf crates/with-secret/src/bin
git add Cargo.toml Cargo.lock crates/with-secret WITH-SECRET-DESIGN.md
git commit -m "with-secret: crate scaffold; spike measurements of Hello, DPAPI and the hook protocol"
```

---

### Task 1: Vault model, naming rules, and a `Debug` that cannot leak

**Files:**
- Create: `crates/with-secret/src/vault.rs`
- Modify: `crates/with-secret/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub const MIN_VALUE_LEN: usize = 12`.
  - `pub fn validate_name(&str) -> Result<(), String>`. Names must match `^[A-Z][A-Z0-9_]{1,63}$`; being uppercase keeps them clear of the lowercase subcommands.
  - `pub fn validate_value(&str) -> Result<(), String>`.
  - `pub enum Access { Read, Write }`, serialised as `"read"`/`"write"`.
  - `pub struct Secret { value, env_var, access, created_at: DateTime<Utc>, rotate_by: Option<NaiveDate> }`, with a hand-written `Debug` that redacts `value`.
  - `#[derive(Default)] pub struct Vault { pub secrets: BTreeMap<String, Secret> }`.
  - `pub trait Protector { fn protect(&self, &[u8]) -> Result<Vec<u8>, String>; fn unprotect(&self, &[u8]) -> Result<Vec<u8>, String>; }`.

- [ ] **Step 1: Write the failing tests.** Create `crates/with-secret/src/vault.rs` containing only the test module for now:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn secret(value: &str) -> Secret {
        Secret { value: value.into(), env_var: "DATABASE_URL".into(), access: Access::Read,
                 created_at: Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap(), rotate_by: None }
    }

    #[test]
    fn names_are_upper_snake() {
        assert!(validate_name("TJ_PROD_DATABASE_URL").is_ok());
        for bad in ["", "A", "tj_prod", "1ABC", "AB-C", "vault", "hook", &"A".repeat(65)] {
            assert!(validate_name(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn short_values_are_refused_because_masking_them_would_garble_output() {
        assert!(validate_value("short").is_err());
        assert!(validate_value(&"x".repeat(MIN_VALUE_LEN)).is_ok());
    }

    #[test]
    fn values_with_newlines_are_refused() {
        assert!(validate_value("postgres://a:b@host/db\nsecond").is_err());
    }

    #[test]
    fn debug_never_prints_the_value() {
        let s = secret("postgres://owner:hunter2hunter2@host/db");
        let shown = format!("{s:?} {:?}", Vault { secrets: [("X_Y".to_string(), s.clone())].into() });
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(shown.contains("DATABASE_URL"));
    }

    #[test]
    fn vault_round_trips_through_json() {
        let mut v = Vault::default();
        v.secrets.insert("TJ_DB".into(), secret("postgres://x:yyyyyyyyyyyy@h/d"));
        let back: Vault = serde_json::from_slice(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(back.secrets["TJ_DB"].value, "postgres://x:yyyyyyyyyyyy@h/d");
        assert_eq!(back.secrets["TJ_DB"].access, Access::Read);
    }
}
```

Set `lib.rs` to:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `with-secret` - WITH-SECRET-DESIGN.md. ⚠️ Stops ACCIDENTAL exposure only (§3).

pub mod vault;
```

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret`. Expected: compile errors such as `cannot find function validate_name`.

- [ ] **Step 3: Implement.** Insert above the test module in `vault.rs`:

```rust
//! The vault model. ⚠️ `Secret::value` is the only plaintext in this crate's
//! data model; it never appears in `Debug`, argv, logs or any environment
//! except the one child `with-secret` starts.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Masking a short value would rewrite ordinary words in command output, and a
/// short secret is weak anyway.
pub const MIN_VALUE_LEN: usize = 12;

pub fn validate_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let ok = name.len() >= 2
        && name.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(()) } else {
        Err(format!("secret names are UPPER_SNAKE, 2-64 chars, starting with a letter; got {name:?}"))
    }
}

pub fn validate_value(value: &str) -> Result<(), String> {
    if value.chars().count() < MIN_VALUE_LEN {
        return Err(format!("a secret must be at least {MIN_VALUE_LEN} characters"));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err("a secret must be one line".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access { Read, Write }

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct Secret {
    pub value: String,
    /// The variable name the child sees, e.g. `DATABASE_URL`.
    pub env_var: String,
    pub access: Access,
    pub created_at: DateTime<Utc>,
    /// Least privilege (e): a write credential should be short-lived. Nothing
    /// enforces rotation; `vault list` flags a secret past this date.
    pub rotate_by: Option<NaiveDate>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("value", &"<redacted>")
            .field("env_var", &self.env_var)
            .field("access", &self.access)
            .field("created_at", &self.created_at)
            .field("rotate_by", &self.rotate_by)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Vault {
    pub secrets: BTreeMap<String, Secret>,
}

/// Encrypt and decrypt bytes at rest. ⚠️ The real one is DPAPI at user scope
/// (`dpapi.rs`): it protects against copies of the disk, NOT against another
/// process running as the same user (design §3).
pub trait Protector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String>;
}
```

- [ ] **Step 4: Run the tests.** Run `cargo test -p with-secret`. Expected: 5 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/with-secret/src
git commit -m "with-secret: vault model, naming and value rules, redacting Debug"
```

---

### Task 2: `VaultStore` and `DpapiProtector`

**Files:**
- Modify: `crates/with-secret/src/vault.rs`
- Create: `crates/with-secret/src/dpapi.rs`
- Modify: `crates/with-secret/src/lib.rs` (add `pub mod dpapi;`)

**Interfaces:**
- Consumes: `Vault`, `Protector` (Task 1).
- `save` takes the already-serialised `masks.json` bytes as an argument, so this module never depends on `mask.rs`, which arrives in Task 3. `main.rs` (Task 8) passes `mask::masks_json(&vault)?`.
- Produces:
  - `pub struct VaultStore<P: Protector> { pub dir: PathBuf, pub protector: P }`.
  - `fn load(&self) -> Result<Vault, String>`. A missing file gives an empty vault; a present but undecryptable file is an `Err`.
  - `fn save(&self, &Vault, masks: Vec<u8>) -> Result<(), String>`, which writes `vault.bin` and `masks.json` atomically.
  - `fn approval_key(&self) -> Result<Vec<u8>, String>`, which gets or creates 32 random bytes, stored protected in `approvals.key`.
  - `pub fn default_dir() -> Result<PathBuf, String>`, which gives `%LOCALAPPDATA%\OverMind\with-secret`.
  - `dpapi::DpapiProtector` (Windows), and on other targets a stub that returns `Err`.

- [ ] **Step 1: Write the failing tests.** Append to the `tests` module in `vault.rs`:

```rust
    /// Reversible, keyed, and NOT identity - so a test can tell "stored
    /// protected" from "stored plain". Not security; DPAPI is the real one.
    struct XorProtector(u8);
    impl Protector for XorProtector {
        fn protect(&self, p: &[u8]) -> Result<Vec<u8>, String> { Ok(p.iter().map(|b| b ^ self.0).collect()) }
        fn unprotect(&self, b: &[u8]) -> Result<Vec<u8>, String> { Ok(b.iter().map(|x| x ^ self.0).collect()) }
    }
    struct FailingProtector;
    impl Protector for FailingProtector {
        fn protect(&self, _: &[u8]) -> Result<Vec<u8>, String> { Err("no".into()) }
        fn unprotect(&self, _: &[u8]) -> Result<Vec<u8>, String> { Err("cannot decrypt".into()) }
    }

    #[test]
    fn missing_vault_is_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore { dir: dir.path().into(), protector: XorProtector(0x5a) };
        assert!(store.load().unwrap().secrets.is_empty());
    }

    #[test]
    fn save_then_load_round_trips_and_the_file_is_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore { dir: dir.path().into(), protector: XorProtector(0x5a) };
        let mut v = Vault::default();
        v.secrets.insert("TJ_DB".into(), secret("postgres://x:supersecretvalue@h/d"));
        store.save(&v, b"[]".to_vec()).unwrap();
        let raw = std::fs::read(dir.path().join("vault.bin")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("supersecretvalue"));
        assert_eq!(store.load().unwrap(), v);
        assert_eq!(std::fs::read(dir.path().join("masks.json")).unwrap(), b"[]");
    }

    #[test]
    fn an_undecryptable_vault_is_an_error_not_an_empty_vault() {
        // ⚠️ Treating it as empty would let `vault set` silently overwrite
        // every stored secret with a one-entry vault.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("vault.bin"), b"garbage").unwrap();
        let store = VaultStore { dir: dir.path().into(), protector: FailingProtector };
        assert!(store.load().is_err());
    }

    #[test]
    fn approval_key_is_created_once_and_stored_protected() {
        let dir = tempfile::tempdir().unwrap();
        let store = VaultStore { dir: dir.path().into(), protector: XorProtector(0x5a) };
        let k1 = store.approval_key().unwrap();
        let k2 = store.approval_key().unwrap();
        assert_eq!(k1.len(), 32);
        assert_eq!(k1, k2);
        assert_ne!(std::fs::read(dir.path().join("approvals.key")).unwrap(), k1);
    }
```

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret`. Expected: `cannot find struct VaultStore`.

- [ ] **Step 3: Implement.** Append to `vault.rs`, above the tests:

```rust
use std::path::{Path, PathBuf};

pub const VAULT_FILE: &str = "vault.bin";
pub const MASKS_FILE: &str = "masks.json";
pub const KEY_FILE: &str = "approvals.key";
pub const APPROVALS_FILE: &str = "approvals.json";
pub const AUDIT_FILE: &str = "access.log";

pub fn default_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    Ok(PathBuf::from(base).join("OverMind").join("with-secret"))
}

/// Write via a sibling temp file and rename, so a crash never leaves a
/// half-written vault - which `load` would then refuse.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
}

pub struct VaultStore<P: Protector> {
    pub dir: PathBuf,
    pub protector: P,
}

impl<P: Protector> VaultStore<P> {
    pub fn load(&self) -> Result<Vault, String> {
        let path = self.dir.join(VAULT_FILE);
        let blob = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vault::default()),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let plain = self.protector.unprotect(&blob)
            .map_err(|e| format!("the vault exists but cannot be decrypted: {e}"))?;
        serde_json::from_slice(&plain).map_err(|e| format!("the vault decrypted but is not valid: {e}"))
    }

    pub fn save(&self, vault: &Vault, masks: Vec<u8>) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("create {}: {e}", self.dir.display()))?;
        let plain = serde_json::to_vec(vault).map_err(|e| e.to_string())?;
        let blob = self.protector.protect(&plain)?;
        write_atomic(&self.dir.join(VAULT_FILE), &blob)?;
        write_atomic(&self.dir.join(MASKS_FILE), &masks)
    }

    pub fn approval_key(&self) -> Result<Vec<u8>, String> {
        let path = self.dir.join(KEY_FILE);
        match std::fs::read(&path) {
            Ok(blob) => self.protector.unprotect(&blob),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
                let mut key = vec![0u8; 32];
                getrandom::fill(&mut key).map_err(|e| format!("random key: {e}"))?;
                write_atomic(&path, &self.protector.protect(&key)?)?;
                Ok(key)
            }
            Err(e) => Err(format!("read {}: {e}", path.display())),
        }
    }
}
```

`getrandom::fill` is the 0.3+ API. If `cargo add` chose an older `getrandom`, the function is `getrandom::getrandom`. Use whichever the chosen version provides.

Create `crates/with-secret/src/dpapi.rs`. Use the DPAPI code proven in Task 0, with that task's recorded fixes:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! DPAPI at user scope. ⚠️ Protects the vault against copies of the disk and
//! backups; ANY process running as this Windows user can decrypt it (design §3).

use crate::vault::Protector;

/// Bound to this tool, so a blob from another DPAPI user on the account
/// does not decrypt by accident. Not a secret - an accident guard.
const ENTROPY: &[u8] = b"overmind.with-secret.v1";

pub struct DpapiProtector;

#[cfg(windows)]
impl Protector for DpapiProtector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String> { call(plain, true) }
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String> { call(blob, false) }
}

#[cfg(windows)]
fn call(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let ent = CRYPT_INTEGER_BLOB { cbData: ENTROPY.len() as u32, pbData: ENTROPY.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB::default();
    unsafe {
        if protect {
            CryptProtectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        } else {
            CryptUnprotectData(&input, None, Some(&ent), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        }
    }
    .map_err(|e| format!("DPAPI {}: {e}", if protect { "protect" } else { "unprotect" }))?;
    let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { let _ = LocalFree(Some(HLOCAL(out.pbData as _))); }
    Ok(bytes)
}

#[cfg(not(windows))]
impl Protector for DpapiProtector {
    fn protect(&self, _: &[u8]) -> Result<Vec<u8>, String> { Err("DPAPI is Windows-only".into()) }
    fn unprotect(&self, _: &[u8]) -> Result<Vec<u8>, String> { Err("DPAPI is Windows-only".into()) }
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
```

Add `pub mod dpapi;` to `lib.rs`.

- [ ] **Step 4: Run the tests.** Run `cargo test -p with-secret`. Expected on Windows: 9 + 2 passed. On Linux, 9 passed and the DPAPI tests are compiled out.

- [ ] **Step 5: Commit.**

```bash
git add crates/with-secret/src
git commit -m "with-secret: VaultStore with atomic writes and a protected approval key; DPAPI protector"
```

---

### Task 3: Masking — streaming plaintext masker and salted-hash masker

**Files:**
- Create: `crates/with-secret/src/mask.rs`
- Modify: `crates/with-secret/src/lib.rs` (`pub mod mask;`)

**Interfaces:**
- Produces:
  - `pub fn label(name: &str) -> String`, which gives `"[with-secret:NAME]"`.
  - `pub struct StreamMasker`, with `new(&[(&str, &str)])` (name, value), `push(&mut self, &[u8]) -> Vec<u8>` and `finish(&mut self) -> Vec<u8>`.
  - `#[derive(Serialize, Deserialize, Clone)] pub struct HashMask { pub name, pub len, pub salt_hex, pub digest_hex }`, with `HashMask::new(name, value) -> Result<Self, String>` (random salt).
  - `pub fn masks_json(&Vault) -> Result<Vec<u8>, String>`.
  - `pub fn mask_with_hashes(&str, &[HashMask]) -> (String, usize)`.
  - `pub fn mask_json(&serde_json::Value, &[HashMask]) -> (serde_json::Value, usize)`.

- [ ] **Step 1: Write the failing tests.** Create `crates/with-secret/src/mask.rs`:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "postgres://owner:Sup3rS3cret@db.example/tj";

    fn run(m: &mut StreamMasker, chunks: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for c in chunks { out.extend(m.push(c)); }
        out.extend(m.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn value_in_one_chunk_is_masked() {
        let mut m = StreamMasker::new(&[("TJ_DB", V)]);
        assert_eq!(run(&mut m, &[format!("url={V} ok\n").as_bytes()]),
                   "url=[with-secret:TJ_DB] ok\n");
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
        assert_eq!(run(&mut m, &[b"tail postgres://own"]), "tail postgres://own");
    }

    #[test]
    fn longest_value_wins_when_one_contains_another() {
        let mut m = StreamMasker::new(&[("SHORT", "Sup3rS3cret!!"), ("LONG", "xxSup3rS3cret!!yy")]);
        assert_eq!(run(&mut m, &[b"[xxSup3rS3cret!!yy]"]), "[[with-secret:LONG]]");
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
```

Add `pub mod mask;` to `lib.rs`.

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret mask`. Expected: compile errors.

- [ ] **Step 3: Implement.** Insert above the tests:

```rust
//! Masking. ⚠️ EXACT MATCHES ONLY: a URL-encoded, base64-encoded or split
//! value passes through (design §3).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vault::Vault;

pub fn label(name: &str) -> String { format!("[with-secret:{name}]") }

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
        needles.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self { needles, carry: Vec::new() }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.carry.extend_from_slice(chunk);
        self.process(false)
    }

    pub fn finish(&mut self) -> Vec<u8> { self.process(true) }

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
            if !finish && self.needles.iter().any(|(n, _)| n.len() > rest.len() && n.starts_with(rest)) {
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

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn salted(salt: &[u8], value: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(value);
    hex(&h.finalize())
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

impl HashMask {
    pub fn new(name: &str, value: &str) -> Result<Self, String> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|e| format!("random salt: {e}"))?;
        Ok(Self { name: name.into(), len: value.len(), salt_hex: hex(&salt),
                  digest_hex: salted(&salt, value.as_bytes()) })
    }
}

pub fn masks_json(vault: &Vault) -> Result<Vec<u8>, String> {
    let masks: Result<Vec<HashMask>, String> =
        vault.secrets.iter().map(|(n, s)| HashMask::new(n, &s.value)).collect();
    serde_json::to_vec_pretty(&masks?).map_err(|e| e.to_string())
}

/// Replace every window of `text` whose salted hash matches a mask. Cost is
/// one SHA-256 per (position, mask); fine for tool output sizes.
pub fn mask_with_hashes(text: &str, masks: &[HashMask]) -> (String, usize) {
    let mut sorted: Vec<(&HashMask, Vec<u8>)> =
        masks.iter().filter(|m| m.len > 0).map(|m| (m, unhex(&m.salt_hex))).collect();
    sorted.sort_by(|a, b| b.0.len.cmp(&a.0.len));
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
            let out = items.iter().map(|v| { let (m, k) = mask_json(v, masks); n += k; m }).collect();
            (Value::Array(out), n)
        }
        Value::Object(map) => {
            let mut n = 0;
            let out = map.iter().map(|(k, v)| { let (m, c) = mask_json(v, masks); n += c; (k.clone(), m) }).collect();
            (Value::Object(out), n)
        }
        other => (other.clone(), 0),
    }
}
```

Apply the same `getrandom` API note as in Task 2.

- [ ] **Step 4: Run the tests.** Run `cargo test -p with-secret mask`. Expected: 9 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/with-secret/src
git commit -m "with-secret: streaming plaintext masker and salted-hash masker for the hook"
```

---

### Task 4: Who is asking — `identity::resolve`

**Files:**
- Create: `crates/with-secret/src/identity.rs`
- Modify: `crates/with-secret/src/lib.rs` (`pub mod identity;`)

**Interfaces:**
- Consumes: `lane_restart::facts::ProcEntry { pid, parent, name, start_time_secs, exe }`, `lane_restart::state::LaneState { role, session_id, pid, .. }`.
- Produces:
  - `#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)] pub struct Requester { pub role: String, pub session_id: String, pub claude_pid: u32, pub claude_start_secs: u64, pub managed: bool }`.
  - `pub fn resolve(table: &[ProcEntry], self_pid: u32, states: &[LaneState]) -> Result<Requester, String>`.
  - `pub fn load_states(dir: &Path) -> Vec<LaneState>`, which reads every `*.json` through `lane_restart::state::load` and skips unreadable files.

**Rules:**
- Walk parents from `self_pid`. A parent whose `start_time_secs` is later than its child's is a reused pid, so the walk stops there; this mirrors `tab_close.rs`.
- The first ancestor whose lowercased image name is `claude.exe` or `claude` is the requester's Claude process.
- If a lane-state has that `pid`, the requester is `managed`, with that state's `role` and `session_id`.
- With no matching state, `role` is `"unmanaged-claude"` and `session_id` is `""`.
- With no Claude ancestor at all (CireSnave's own shell), `role` is `"outside-claude"`, keyed on the immediate parent's pid and start time.
- If `self_pid` is not in the table at all, return `Err`: fail closed.

- [ ] **Step 1: Write the failing tests.** Create `identity.rs`:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use lane_restart::facts::ProcEntry;
    use lane_restart::state::LaneState;

    fn p(pid: u32, parent: Option<u32>, name: &str, start: u64) -> ProcEntry {
        ProcEntry { pid, parent, name: name.into(), start_time_secs: start, exe: None }
    }

    fn state(role: &str, pid: u32, session: &str) -> LaneState {
        serde_json::from_value(serde_json::json!({
            "role": role, "session_id": session, "pid": pid, "cwd": "C:\\Projects\\X",
            "remote_control": false, "busy": false, "subagents_running": 0,
            "updated_at": "2026-10-01T00:00:00Z", "updated_by_event": "test"
        })).unwrap()
    }

    // claude(10) -> bash(20) -> with-secret(30)
    fn table() -> Vec<ProcEntry> {
        vec![p(1, None, "explorer.exe", 1), p(10, Some(1), "claude.exe", 100),
             p(20, Some(10), "bash.exe", 200), p(30, Some(20), "with-secret.exe", 300)]
    }

    #[test]
    fn a_lane_is_identified_by_its_claude_ancestor_and_state() {
        let r = resolve(&table(), 30, &[state("humboldt", 10, "s-1")]).unwrap();
        assert_eq!(r, Requester { role: "humboldt".into(), session_id: "s-1".into(),
                                  claude_pid: 10, claude_start_secs: 100, managed: true });
    }

    #[test]
    fn a_claude_with_no_state_is_unmanaged() {
        let r = resolve(&table(), 30, &[state("other", 999, "s-9")]).unwrap();
        assert_eq!(r.role, "unmanaged-claude");
        assert!(!r.managed);
        assert_eq!(r.claude_pid, 10);
    }

    #[test]
    fn no_claude_ancestor_is_outside_claude_keyed_on_the_parent() {
        let t = vec![p(1, None, "explorer.exe", 1), p(20, Some(1), "pwsh.exe", 200),
                     p(30, Some(20), "with-secret.exe", 300)];
        let r = resolve(&t, 30, &[]).unwrap();
        assert_eq!(r.role, "outside-claude");
        assert_eq!((r.claude_pid, r.claude_start_secs), (20, 200));
    }

    #[test]
    fn a_reused_parent_pid_stops_the_walk() {
        // pid 10 was reused by a claude that started AFTER its "child".
        let t = vec![p(10, None, "claude.exe", 500), p(20, Some(10), "bash.exe", 200),
                     p(30, Some(20), "with-secret.exe", 300)];
        let r = resolve(&t, 30, &[state("humboldt", 10, "s-1")]).unwrap();
        assert_eq!(r.role, "outside-claude", "trusted a reused pid");
    }

    #[test]
    fn self_missing_from_the_table_fails_closed() {
        assert!(resolve(&table(), 77, &[]).is_err());
    }

    #[test]
    fn a_restarted_lane_is_a_different_requester() {
        let before = resolve(&table(), 30, &[state("humboldt", 10, "s-1")]).unwrap();
        let mut t = table();
        t[1] = p(11, Some(1), "claude.exe", 900);
        t[2] = p(20, Some(11), "bash.exe", 950);
        t[3] = p(30, Some(20), "with-secret.exe", 960);
        let after = resolve(&t, 30, &[state("humboldt", 11, "s-2")]).unwrap();
        assert_eq!(before.role, after.role);
        assert_ne!(before, after);
    }
}
```

The JSON in `state()` must match `LaneState`'s real required fields at implementation time. If deserialisation fails, read `crates/lane-restart/src/state.rs`'s `sample_json()` test helper and copy its field set.

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret identity`. Expected: compile errors.

- [ ] **Step 3: Implement.** Insert above the tests:

```rust
//! Who is asking. ⚠️ Taken from the OS process table and lane-state files,
//! never from an argument - a lane cannot name itself into another lane's
//! approval. (A deliberate same-user process could forge a lane-state file;
//! design §3.)

use std::path::Path;

use lane_restart::facts::ProcEntry;
use lane_restart::state::LaneState;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requester {
    pub role: String,
    pub session_id: String,
    pub claude_pid: u32,
    pub claude_start_secs: u64,
    pub managed: bool,
}

fn is_claude(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "claude.exe" || n == "claude"
}

pub fn resolve(table: &[ProcEntry], self_pid: u32, states: &[LaneState]) -> Result<Requester, String> {
    let find = |pid: u32| table.iter().find(|e| e.pid == pid);
    let me = find(self_pid).ok_or_else(|| format!("pid {self_pid} is not in the process table"))?;
    let first_parent = me.parent.and_then(find).filter(|p| p.start_time_secs <= me.start_time_secs);

    let mut child = me;
    for _ in 0..64 {
        let Some(parent) = child.parent.and_then(find) else { break };
        if parent.start_time_secs > child.start_time_secs { break } // reused pid
        if is_claude(&parent.name) {
            return Ok(match states.iter().find(|s| s.pid == parent.pid) {
                Some(s) => Requester { role: s.role.clone(), session_id: s.session_id.clone(),
                                       claude_pid: parent.pid, claude_start_secs: parent.start_time_secs,
                                       managed: true },
                None => Requester { role: "unmanaged-claude".into(), session_id: String::new(),
                                    claude_pid: parent.pid, claude_start_secs: parent.start_time_secs,
                                    managed: false },
            });
        }
        child = parent;
    }
    let anchor = first_parent.unwrap_or(me);
    Ok(Requester { role: "outside-claude".into(), session_id: String::new(),
                   claude_pid: anchor.pid, claude_start_secs: anchor.start_time_secs, managed: false })
}

pub fn load_states(dir: &Path) -> Vec<LaneState> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            (path.extension()? == "json").then(|| path.file_stem()?.to_str().map(String::from))?
        })
        .filter_map(|role| lane_restart::state::load(dir, &role).ok())
        .collect()
}
```

- [ ] **Step 4: Run the tests.** Run `cargo test -p with-secret identity`. Expected: 6 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/with-secret/src
git commit -m "with-secret: identify the requesting lane from the process table and lane-state"
```

---

### Task 5: Approvals — expiry, restart-void, HMAC-signed cache

**Files:**
- Create: `crates/with-secret/src/approval.rs`
- Modify: `crates/with-secret/src/lib.rs` (`pub mod approval;`)

**Interfaces:**
- Consumes: `Requester`, `write_atomic`.
- Produces:
  - `#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)] pub struct Approval { pub secret: String, pub requester: Requester, pub granted_at: DateTime<Utc>, pub expires_at: DateTime<Utc> }`.
  - `pub fn expiry(granted: DateTime<Local>, window: Option<chrono::Duration>) -> DateTime<Utc>`.
  - `impl Approval { pub fn covers(&self, secret: &str, who: &Requester, now: DateTime<Utc>) -> bool }`.
  - `pub struct ApprovalCache { key: Vec<u8>, entries: Vec<Approval> }`, with `load(path, key) -> (Self, usize /*rejected*/)`, `find(&self, secret, who, now) -> Option<&Approval>`, `add(&mut self, Approval)` and `save(&self, path, now: DateTime<Utc>) -> Result<(), String>`.
  - `save` takes `now` explicitly, never `Utc::now()`. Otherwise these tests, whose approvals expire on 2026-10-02, would start failing on any later date.

- [ ] **Step 1: Write the failing tests.** Create `approval.rs`:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Local, TimeZone};

    fn who(pid: u32, session: &str) -> Requester {
        Requester { role: "humboldt".into(), session_id: session.into(), claude_pid: pid,
                    claude_start_secs: 100, managed: true }
    }
    fn local(h: u32, m: u32) -> chrono::DateTime<Local> {
        Local.with_ymd_and_hms(2026, 10, 1, h, m, 0).single().unwrap()
    }
    fn approval(at: chrono::DateTime<Local>, window: Option<Duration>) -> Approval {
        Approval { secret: "TJ_DB".into(), requester: who(10, "s-1"),
                   granted_at: at.with_timezone(&Utc), expires_at: expiry(at, window) }
    }

    #[test]
    fn expires_at_local_midnight_by_default() {
        assert_eq!(expiry(local(9, 0), None),
                   Local.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).single().unwrap().with_timezone(&Utc));
    }

    #[test]
    fn test_late_grant_expires_at_midnight() {
        let e = expiry(local(23, 50), Some(Duration::hours(4)));
        assert_eq!(e, Local.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).single().unwrap().with_timezone(&Utc));
    }

    #[test]
    fn a_shorter_window_wins() {
        assert_eq!(expiry(local(9, 0), Some(Duration::minutes(30))),
                   (local(9, 0) + Duration::minutes(30)).with_timezone(&Utc));
    }

    #[test]
    fn covers_only_its_own_secret_and_requester_and_time() {
        let a = approval(local(9, 0), None);
        let now = local(12, 0).with_timezone(&Utc);
        assert!(a.covers("TJ_DB", &who(10, "s-1"), now));
        assert!(!a.covers("OTHER", &who(10, "s-1"), now), "another secret");
        let mut other_lane = who(10, "s-1");
        other_lane.role = "fuel".into();
        assert!(!a.covers("TJ_DB", &other_lane, now), "another lane");
        assert!(!a.covers("TJ_DB", &who(10, "s-1"), local(9, 0).with_timezone(&Utc) + Duration::days(1)),
                "tomorrow");
        assert!(!a.covers("TJ_DB", &who(10, "s-1"), local(8, 0).with_timezone(&Utc)),
                "before it was granted - a clock moved backwards");
    }

    #[test]
    fn test_restart_voids_approval() {
        let a = approval(local(9, 0), None);
        let now = local(12, 0).with_timezone(&Utc);
        assert!(!a.covers("TJ_DB", &who(11, "s-1"), now), "new claude pid");
        assert!(!a.covers("TJ_DB", &who(10, "s-2"), now), "new session");
        let mut restarted = who(10, "s-1");
        restarted.claude_start_secs = 999;
        assert!(!a.covers("TJ_DB", &restarted, now), "same pid, new process");
    }

    #[test]
    fn cache_round_trips_and_finds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.json");
        let mut c = ApprovalCache::load(&path, b"k".repeat(32)).0;
        c.add(approval(local(9, 0), None));
        c.save(&path, local(10, 0).with_timezone(&Utc)).unwrap();
        let (back, rejected) = ApprovalCache::load(&path, b"k".repeat(32));
        assert_eq!(rejected, 0);
        assert!(back.find("TJ_DB", &who(10, "s-1"), local(10, 0).with_timezone(&Utc)).is_some());
    }

    #[test]
    fn test_tampered_entry_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.json");
        let mut c = ApprovalCache::load(&path, b"k".repeat(32)).0;
        c.add(approval(local(9, 0), None));
        c.save(&path, local(10, 0).with_timezone(&Utc)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap().replace("humboldt", "fuel");
        std::fs::write(&path, text).unwrap();
        let (back, rejected) = ApprovalCache::load(&path, b"k".repeat(32));
        assert_eq!(rejected, 1);
        let mut fuel = who(10, "s-1");
        fuel.role = "fuel".into();
        assert!(back.find("TJ_DB", &fuel, local(10, 0).with_timezone(&Utc)).is_none());
    }

    #[test]
    fn a_different_key_rejects_everything() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.json");
        let mut c = ApprovalCache::load(&path, b"k".repeat(32)).0;
        c.add(approval(local(9, 0), None));
        c.save(&path, local(10, 0).with_timezone(&Utc)).unwrap();
        assert_eq!(ApprovalCache::load(&path, b"j".repeat(32)).1, 1);
    }

    #[test]
    fn expired_entries_are_dropped_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.json");
        let mut c = ApprovalCache::load(&path, b"k".repeat(32)).0;
        let now = local(12, 0).with_timezone(&Utc);
        let mut old = approval(local(9, 0), None);
        old.expires_at = now - Duration::hours(1);
        c.add(old);
        c.save(&path, now).unwrap();
        assert!(ApprovalCache::load(&path, b"k".repeat(32)).0.entries.is_empty());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret approval`. Expected: compile errors.

- [ ] **Step 3: Implement.** Insert above the tests:

```rust
//! Approvals - CireSnave 2026-09-28: "Approve once per lane per secret with a
//! timeout so that an approval now isn't still valid tomorrow."
//!
//! ⚠️ The cache is HMAC-signed with a DPAPI-protected key, so an entry that a
//! lane writes BY ACCIDENT (or a hand edit) is ignored. A deliberate same-user
//! process can read the key and forge one (design §3).

use std::path::Path;

use chrono::{DateTime, Duration, Local, TimeZone, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::identity::Requester;
use crate::vault::write_atomic;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Approval {
    pub secret: String,
    pub requester: Requester,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The earlier of local midnight after `granted` and `granted + window`.
pub fn expiry(granted: DateTime<Local>, window: Option<Duration>) -> DateTime<Utc> {
    let next_midnight = (granted.date_naive() + Duration::days(1)).and_hms_opt(0, 0, 0).unwrap();
    // ⚠️ If local midnight does not exist (a DST gap), fall back SHORT - one
    // hour - never long.
    let midnight = Local.from_local_datetime(&next_midnight).earliest()
        .unwrap_or(granted + Duration::hours(1));
    let end = match window { Some(w) if granted + w < midnight => granted + w, _ => midnight };
    end.with_timezone(&Utc)
}

impl Approval {
    pub fn covers(&self, secret: &str, who: &Requester, now: DateTime<Utc>) -> bool {
        self.secret == secret
            && &self.requester == who      // role, session, claude pid AND its start time
            && self.granted_at <= now
            && now < self.expires_at
    }
}

#[derive(Serialize, Deserialize)]
struct Signed { approval: Approval, mac: String }

pub struct ApprovalCache {
    key: Vec<u8>,
    pub entries: Vec<Approval>,
}

fn mac(key: &[u8], a: &Approval) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(&serde_json::to_vec(a).expect("Approval serialises"));
    m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

impl ApprovalCache {
    /// Returns the cache and how many entries were REJECTED (bad MAC or
    /// unreadable). A missing or corrupt file is an empty cache: the cost is
    /// one more consent prompt, never a wrongly-honoured approval.
    pub fn load(path: &Path, key: Vec<u8>) -> (Self, usize) {
        let signed: Vec<Signed> = std::fs::read(path).ok()
            .and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let total = signed.len();
        let entries: Vec<Approval> = signed.into_iter()
            .filter(|s| mac(&key, &s.approval) == s.mac).map(|s| s.approval).collect();
        let rejected = total - entries.len();
        (Self { key, entries }, rejected)
    }

    pub fn find(&self, secret: &str, who: &Requester, now: DateTime<Utc>) -> Option<&Approval> {
        self.entries.iter().find(|a| a.covers(secret, who, now))
    }

    pub fn add(&mut self, a: Approval) { self.entries.push(a); }

    pub fn save(&self, path: &Path, now: DateTime<Utc>) -> Result<(), String> {
        let signed: Vec<Signed> = self.entries.iter().filter(|a| a.expires_at > now)
            .map(|a| Signed { approval: a.clone(), mac: mac(&self.key, a) }).collect();
        write_atomic(path, &serde_json::to_vec_pretty(&signed).map_err(|e| e.to_string())?)
    }
}
```

`hmac` 0.13 or later may rename `new_from_slice`. If so, use the chosen version's keyed constructor.

- [ ] **Step 4: Run the tests.** Run `cargo test -p with-secret approval`. Expected: 9 passed.

- [ ] **Step 5: Commit.**

```bash
git add crates/with-secret/src
git commit -m "with-secret: approvals expire by local midnight, die with the lane, and are HMAC-signed"
```

---

### Task 6: Consent — the prompt text, the trait, and Windows Hello

**Files:**
- Create: `crates/with-secret/src/consent.rs`, `crates/with-secret/src/hello.rs`
- Modify: `crates/with-secret/src/lib.rs` (`pub mod consent; pub mod hello;`)

**Interfaces:**
- Produces:
  - `pub struct ConsentRequest { pub secret: String, pub requester: Requester, pub command: String, pub reason: String, pub expires_at: DateTime<Utc> }`.
  - `#[derive(Debug, PartialEq)] pub enum ConsentOutcome { Approved, Denied, TimedOut, Unavailable(String) }`.
  - `pub trait Consent { fn ask(&self, prompt: &str, wait: std::time::Duration) -> ConsentOutcome; }`.
  - `pub fn prompt_text(&ConsentRequest) -> String`.
  - `pub fn store_prompt_text(action: &str, secret: &str) -> String`.
  - `hello::HelloConsent { pub owner: Owner }`, where `Owner` is `Foreground` or `Console`. **Use the owner window Task 0 recorded as working as the `Default` value.**

- [ ] **Step 1: Write the failing tests.** Create `consent.rs`:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn req(cmd: &str) -> ConsentRequest {
        ConsentRequest {
            secret: "TJ_PROD_DATABASE_URL".into(),
            requester: Requester { role: "humboldt".into(), session_id: "s-1".into(),
                                   claude_pid: 10, claude_start_secs: 100, managed: true },
            command: cmd.into(),
            reason: "run the seed migration against prod".into(),
            expires_at: Utc.with_ymd_and_hms(2026, 10, 2, 7, 0, 0).unwrap(),
        }
    }

    #[test]
    fn prompt_names_secret_lane_command_reason_and_expiry() {
        let t = prompt_text(&req("psql -f seed.sql"));
        for part in ["TJ_PROD_DATABASE_URL", "humboldt", "psql -f seed.sql",
                     "run the seed migration against prod", "until"] {
            assert!(t.contains(part), "missing {part:?} in {t}");
        }
    }

    #[test]
    fn an_unmanaged_requester_is_flagged() {
        let mut r = req("x");
        r.requester.managed = false;
        r.requester.role = "unmanaged-claude".into();
        assert!(prompt_text(&r).contains("NOT a registered lane"));
    }

    #[test]
    fn a_long_command_is_truncated_visibly() {
        let t = prompt_text(&req(&"a".repeat(1000)));
        assert!(t.contains('…'));
        assert!(t.chars().count() < 700);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret consent`. Expected: compile errors.

- [ ] **Step 3: Implement `consent.rs`.**

```rust
//! What CireSnave is asked, and the seam for asking. Item 81 (c): "every
//! access asks YOU first, naming the secret, the requesting lane, the command
//! and the reason".

use chrono::{DateTime, Local, Utc};

use crate::identity::Requester;

pub struct ConsentRequest {
    pub secret: String,
    pub requester: Requester,
    pub command: String,
    pub reason: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, PartialEq)]
pub enum ConsentOutcome { Approved, Denied, TimedOut, Unavailable(String) }

pub trait Consent {
    fn ask(&self, prompt: &str, wait: std::time::Duration) -> ConsentOutcome;
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { format!("{}…", s.chars().take(max).collect::<String>()) }
}

pub fn prompt_text(r: &ConsentRequest) -> String {
    let who = if r.requester.managed {
        format!("lane '{}'", r.requester.role)
    } else {
        format!("{} (pid {}) - NOT a registered lane", r.requester.role, r.requester.claude_pid)
    };
    format!(
        "with-secret: {who} asks to use secret {}.\nCommand: {}\nReason: {}\n\
         Approving covers this lane and this secret until {} (or the lane restarts).",
        r.secret, clip(&r.command, 200), clip(&r.reason, 200),
        r.expires_at.with_timezone(&Local).format("%H:%M today"),
    )
}

pub fn store_prompt_text(action: &str, secret: &str) -> String {
    format!("with-secret: {action} secret {secret} in the vault?")
}
```

- [ ] **Step 4: Implement `hello.rs`.** Use Task 0's proven code and its recorded fixes:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Windows Hello consent - design §2.2. ⚠️ The ONE approval channel no agent
//! can answer: it needs CireSnave's PIN or biometric at the desktop.

use std::time::{Duration, Instant};

use crate::consent::{Consent, ConsentOutcome};

#[derive(Clone, Copy, Debug)]
pub enum Owner { Foreground, Console }

impl Default for Owner {
    // ⚠️ Set from Task 0's measurement (WITH-SECRET-DESIGN.md §4).
    fn default() -> Self { Owner::Foreground }
}

#[derive(Default)]
pub struct HelloConsent { pub owner: Owner }

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
fn ask_windows(owner: Owner, prompt: &str, wait: Duration) -> windows::core::Result<ConsentOutcome> {
    use windows::core::{factory, Interface, HSTRING};
    use windows::Foundation::{AsyncStatus, IAsyncInfo, IAsyncOperation};
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult as R, UserConsentVerifier, UserConsentVerifierAvailability,
    };
    use windows::Win32::System::Console::GetConsoleWindow;
    use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
    use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

    let avail = UserConsentVerifier::CheckAvailabilityAsync()?.get()?;
    if avail != UserConsentVerifierAvailability::Available {
        return Ok(ConsentOutcome::Unavailable(format!("Windows Hello is {avail:?}")));
    }
    let hwnd = unsafe { match owner { Owner::Foreground => GetForegroundWindow(), Owner::Console => GetConsoleWindow() } };
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
        let o = HelloConsent::default().ask("with-secret LIVE TEST: press Cancel.", Duration::from_secs(120));
        assert_eq!(o, ConsentOutcome::Denied);
    }
}
```

- [ ] **Step 5: Run the tests.** Run `cargo test -p with-secret`. Expected: all pass, with the live test ignored. Then, with CireSnave present, run `cargo test -p with-secret -- --ignored live_hello`. Expected: the dialog appears on his screen; he presses Cancel, and the test passes.

- [ ] **Step 6: Commit.**

```bash
git add crates/with-secret/src
git commit -m "with-secret: consent prompt text and the Windows Hello adapter"
```

---

### Task 7: `dump_reason`, the audit log, and `authorize` — the whole decision, with no I/O

**Files:**
- Create: `crates/with-secret/src/dumpcheck.rs`, `crates/with-secret/src/audit.rs`, `crates/with-secret/src/run.rs`
- Modify: `crates/with-secret/src/lib.rs` (`pub mod dumpcheck; pub mod audit; pub mod run;`)

**Interfaces:**
- Produces:
  - `dumpcheck::dump_reason(tool_name: &str, tool_input: &serde_json::Value) -> Option<String>`.
  - `dumpcheck::command_dump_reason(cmd: &str) -> Option<String>`.
  - `audit::Event { at, event, secret, role, session_id, claude_pid, command, reason }`, plus `audit::append(path, &Event)`.
  - `run::RunArgs { secret, reason, argv: Vec<String>, wait: Duration, window: Option<chrono::Duration> }`.
  - `run::parse_run(&[String]) -> Result<RunArgs, String>`.
  - `run::Released { secret: Secret, approval: Approval, newly_granted: bool }`.
  - `run::authorize(args: &RunArgs, vault: &Vault, cache: &mut ApprovalCache, who: &Requester, consent: &dyn Consent, now: DateTime<Local>, log: &mut Vec<audit::Event>) -> Result<Released, String>`.

- [ ] **Step 1: Write the failing tests for `dumpcheck`.** Create `dumpcheck.rs`:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bash(c: &str) -> Option<String> { dump_reason("Bash", &json!({"command": c})) }
    fn ps(c: &str) -> Option<String> { dump_reason("PowerShell", &json!({"command": c})) }

    #[test]
    fn env_dumps_are_blocked() {
        for c in ["env", "env | sort", "cd x && env", "printenv", "printenv PATH", "set",
                  "export", "export -p", "declare -x", "/usr/bin/env", "cmd /c set",
                  "bash -c \"env\"", "npm run check; env", "cmd /c echo hi; env"] {
            assert!(bash(c).is_some(), "{c:?} was allowed");
        }
        for c in ["Get-ChildItem env:", "gci Env:\\", "ls env:*", "dir env:",
                  "Get-Item env:*", "[Environment]::GetEnvironmentVariables()",
                  "pwsh -Command \"Get-ChildItem env:\""] {
            assert!(ps(c).is_some(), "{c:?} was allowed");
        }
    }

    #[test]
    fn ordinary_commands_pass() {
        for c in ["env FOO=1 cargo test", "env -u HOME ls", "cargo test", "git status",
                  "echo $PATH", "set -o pipefail && cargo test", "grep -n env src/main.rs",
                  "cat README.md", "cat .env.example"] {
            assert!(bash(c).is_none(), "{c:?} was blocked");
        }
        for c in ["$env:PATH", "Get-ChildItem src", "Get-Content README.md"] {
            assert!(ps(c).is_none(), "{c:?} was blocked");
        }
    }

    #[test]
    fn dotenv_reads_are_blocked() {
        assert!(bash("cat .env").is_some());
        assert!(bash("cat apps/api/.env.local").is_some());
        assert!(ps("Get-Content .env").is_some());
        assert!(ps("type C:\\x\\.env.production").is_some());
        assert!(dump_reason("Read", &json!({"file_path": "C:\\Projects\\X\\.env"})).is_some());
        assert!(dump_reason("Read", &json!({"file_path": "C:\\Projects\\X\\.env.sample"})).is_none());
        assert!(dump_reason("Read", &json!({"file_path": "C:\\Projects\\X\\src\\env.rs"})).is_none());
    }

    #[test]
    fn other_tools_and_bad_input_pass() {
        assert!(dump_reason("Write", &json!({"file_path": ".env"})).is_none());
        assert!(dump_reason("Bash", &json!({})).is_none());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret dumpcheck`. Expected: compile errors.

- [ ] **Step 3: Implement `dumpcheck.rs`.**

```rust
//! Is this an environment dump? Item 81 (d). ⚠️ A pattern check for ACCIDENTS -
//! the 2026-09-28 incident was a bare `env`. It is trivially bypassed on
//! purpose (`python -c ...`), and is not the gate; the vault is.

const DOTENV_SAFE_SUFFIXES: [&str; 3] = [".example", ".sample", ".template"];

fn is_dotenv(path: &str) -> bool {
    let base = path.rsplit(['/', '\\']).next().unwrap_or(path).trim_matches(['"', '\'']);
    (base == ".env" || base.starts_with(".env."))
        && !DOTENV_SAFE_SUFFIXES.iter().any(|s| base.ends_with(s))
}

fn image(token: &str) -> String {
    let base = token.rsplit(['/', '\\']).next().unwrap_or(token).to_ascii_lowercase();
    base.strip_suffix(".exe").unwrap_or(&base).to_string()
}

fn segments(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
        if two == "&&" || two == "||" { out.push(std::mem::take(&mut cur)); i += 2; continue; }
        if c == '|' || c == ';' || c == '\n' { out.push(std::mem::take(&mut cur)); i += 1; continue; }
        cur.push(c);
        i += 1;
    }
    out.push(cur);
    out.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

pub fn command_dump_reason(cmd: &str) -> Option<String> {
    if cmd.to_ascii_lowercase().contains("[environment]::getenvironmentvariables") {
        return Some("lists every environment variable".into());
    }
    for seg in segments(cmd) {
        let toks: Vec<&str> = seg.split_whitespace().collect();
        let Some(first) = toks.first() else { continue };
        let rest = &toks[1..];
        let name = image(first);
        let blocked = match name.as_str() {
            "env" => !rest.iter().any(|t| !t.starts_with('-') && !t.contains('=')),
            "printenv" => true,
            "set" | "export" | "declare" | "typeset" =>
                rest.is_empty() || rest.iter().all(|t| *t == "-p" || *t == "-x"),
            "get-childitem" | "gci" | "ls" | "dir" | "get-item" | "gi" =>
                rest.iter().any(|t| t.trim_matches(['"', '\'']).to_ascii_lowercase().starts_with("env:")),
            "cat" | "type" | "gc" | "get-content" | "more" | "less" | "head" | "tail" | "bat" =>
                rest.iter().any(|t| is_dotenv(t)),
            "cmd" if rest.first().is_some_and(|f| f.eq_ignore_ascii_case("/c") || f.eq_ignore_ascii_case("/k")) => {
                if let Some(r) = command_dump_reason(&rest[1..].join(" ")) { return Some(r) }
                false
            }
            "bash" | "sh" | "pwsh" | "powershell" if rest.first().is_some_and(|f| {
                let f = f.to_ascii_lowercase();
                f == "-c" || f == "-command"
            }) => {
                let inner = rest[1..].join(" ");
                if let Some(r) = command_dump_reason(inner.trim_matches(['"', '\''])) { return Some(r) }
                false
            }
            _ => false,
        };
        if blocked {
            return Some(format!("`{seg}` would print environment variables or a .env file"));
        }
    }
    None
}

pub fn dump_reason(tool_name: &str, input: &serde_json::Value) -> Option<String> {
    match tool_name {
        "Bash" | "PowerShell" => command_dump_reason(input.get("command")?.as_str()?),
        "Read" => {
            let p = input.get("file_path")?.as_str()?;
            is_dotenv(p).then(|| format!("{p} is a .env file"))
        }
        _ => None,
    }
    .map(|why| format!("with-secret hook: blocked - {why}. Secrets are not read from the \
                        environment here; use `with-secret NAME --reason ... -- <command>`."))
}
```

`"set -o pipefail && cargo test"` must pass: `set` with `-o pipefail` is not all `-p`/`-x`, so it is not blocked. `"cmd /c set"` reclassifies `set` with no arguments, which is blocked. When `cmd /c` or `bash -c` recurse, they return only a *positive* inner verdict. A harmless inner command falls through to the later segments, so `cmd /c echo hi; env` is still caught (it is in the test list).

Edge case for the implementer: in `"cd x && env"`, the `env` segment has no `rest`, so `!rest.iter().any(...)` is `true`, which is blocked, correctly. In `env FOO=1 cargo test`, `cargo` is a token without `=` and not starting with `-`, so it is a command, and the line is allowed.

- [ ] **Step 4: Write the failing tests for `audit` and `run`.** Create `audit.rs`:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every access attempt, as JSON lines. ⚠️ NEVER the value. CireSnave on the
//! auditor's kill-log, same spirit: the record is what makes it reviewable.

use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub at: DateTime<Utc>,
    pub event: String, // granted | used | denied | timed-out | unavailable | refused
    pub secret: String,
    pub role: String,
    pub session_id: String,
    pub claude_pid: u32,
    pub command: String,
    pub reason: String,
}

pub fn append(path: &Path, e: &Event) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)
        .map_err(|err| format!("open {}: {err}", path.display()))?;
    writeln!(f, "{}", serde_json::to_string(e).map_err(|err| err.to_string())?)
        .map_err(|err| err.to_string())
}
```

Create `run.rs` with the tests first:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Local, TimeZone};
    use std::cell::RefCell;

    struct FakeConsent { answer: ConsentOutcome, asked: RefCell<Vec<String>> }
    impl FakeConsent {
        fn new(answer: ConsentOutcome) -> Self { Self { answer, asked: RefCell::new(vec![]) } }
    }
    impl Consent for FakeConsent {
        fn ask(&self, prompt: &str, _: std::time::Duration) -> ConsentOutcome {
            self.asked.borrow_mut().push(prompt.to_string());
            match &self.answer {
                ConsentOutcome::Approved => ConsentOutcome::Approved,
                ConsentOutcome::Denied => ConsentOutcome::Denied,
                ConsentOutcome::TimedOut => ConsentOutcome::TimedOut,
                ConsentOutcome::Unavailable(s) => ConsentOutcome::Unavailable(s.clone()),
            }
        }
    }

    const VALUE: &str = "postgres://owner:Sup3rS3cret@db/tj";

    fn vault() -> Vault {
        let mut v = Vault::default();
        v.secrets.insert("TJ_DB".into(), Secret { value: VALUE.into(), env_var: "DATABASE_URL".into(),
            access: Access::Read, created_at: Utc::now(), rotate_by: None });
        v
    }
    fn who() -> Requester {
        Requester { role: "humboldt".into(), session_id: "s-1".into(), claude_pid: 10,
                    claude_start_secs: 100, managed: true }
    }
    fn args(argv: &[&str]) -> RunArgs {
        let mut all = vec!["TJ_DB", "--reason", "seed the prod db", "--"];
        all.extend_from_slice(argv);
        parse_run(&all.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }
    fn cache() -> ApprovalCache {
        ApprovalCache::load(std::path::Path::new("does-not-exist.json"), b"k".repeat(32)).0
    }
    fn now() -> chrono::DateTime<Local> { Local.with_ymd_and_hms(2026, 10, 1, 9, 0, 0).single().unwrap() }

    #[test]
    fn parse_requires_a_reason_and_a_command() {
        let p = |v: &[&str]| parse_run(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(p(&["TJ_DB", "--", "psql"]).is_err(), "no reason");
        assert!(p(&["TJ_DB", "--reason", "short", "--", "psql"]).is_err(), "reason too short");
        assert!(p(&["TJ_DB", "--reason", "seed the prod db", "--"]).is_err(), "no command");
        assert!(p(&["tj_db", "--reason", "seed the prod db", "--", "psql"]).is_err(), "bad name");
        let ok = p(&["TJ_DB", "--reason", "seed the prod db", "--window-mins", "30", "--", "psql", "-f", "x"]).unwrap();
        assert_eq!(ok.argv, vec!["psql", "-f", "x"]);
        assert_eq!(ok.window, Some(chrono::Duration::minutes(30)));
    }

    #[test]
    fn first_use_asks_and_caches() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut c = cache();
        let mut log = vec![];
        let r = authorize(&args(&["psql"]), &vault(), &mut c, &who(), &consent, now(), &mut log).unwrap();
        assert!(r.newly_granted);
        assert_eq!(r.secret.value, VALUE);
        assert_eq!(consent.asked.borrow().len(), 1);
        assert_eq!(c.entries.len(), 1);
        assert_eq!(log.iter().map(|e| e.event.as_str()).collect::<Vec<_>>(), ["granted", "used"]);
    }

    #[test]
    fn second_use_same_day_does_not_ask() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut c = cache();
        let mut log = vec![];
        authorize(&args(&["psql"]), &vault(), &mut c, &who(), &consent, now(), &mut log).unwrap();
        let r = authorize(&args(&["psql", "-c", "select 1"]), &vault(), &mut c, &who(), &consent,
                          now() + chrono::Duration::hours(2), &mut log).unwrap();
        assert!(!r.newly_granted);
        assert_eq!(consent.asked.borrow().len(), 1);
    }

    #[test]
    fn denied_timed_out_and_unavailable_release_nothing() {
        for answer in [ConsentOutcome::Denied, ConsentOutcome::TimedOut,
                       ConsentOutcome::Unavailable("no hello".into())] {
            let mut c = cache();
            let mut log = vec![];
            let err = authorize(&args(&["psql"]), &vault(), &mut c, &who(),
                                &FakeConsent::new(answer), now(), &mut log).unwrap_err();
            assert!(!err.contains(VALUE));
            assert!(c.entries.is_empty());
            assert_eq!(log.len(), 1);
        }
    }

    #[test]
    fn test_dump_child_refused_before_consent() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut log = vec![];
        for argv in [&["env"][..], &["printenv"], &["cmd", "/c", "set"]] {
            let err = authorize(&args(argv), &vault(), &mut cache(), &who(), &consent, now(), &mut log)
                .unwrap_err();
            assert!(err.contains("blocked"), "{err}");
        }
        assert!(consent.asked.borrow().is_empty(), "consent was requested for a dump");
    }

    #[test]
    fn unknown_secret_is_refused_without_asking() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut a = args(&["psql"]);
        a.secret = "NOPE_NOPE".into();
        assert!(authorize(&a, &vault(), &mut cache(), &who(), &consent, now(), &mut vec![]).is_err());
        assert!(consent.asked.borrow().is_empty());
    }

    #[test]
    fn the_log_never_contains_the_value() {
        let mut log = vec![];
        authorize(&args(&["psql"]), &vault(), &mut cache(), &who(),
                  &FakeConsent::new(ConsentOutcome::Approved), now(), &mut log).unwrap();
        assert!(!serde_json::to_string(&log).unwrap().contains("Sup3rS3cret"));
    }
}
```

- [ ] **Step 5: Run the tests to verify they fail.** Run `cargo test -p with-secret run`. Expected: compile errors.

- [ ] **Step 6: Implement `run.rs`.** Insert above the tests:

```rust
//! The decision: may THIS requester use THIS secret for THIS command now.
//! No I/O - `main.rs` loads, spawns and saves. ⚠️ Every refusal path releases
//! nothing, and consent is asked only after every cheap refusal has passed.

use std::time::Duration;

use chrono::{DateTime, Local, Utc};

use crate::approval::{expiry, Approval, ApprovalCache};
use crate::audit::Event;
use crate::consent::{prompt_text, Consent, ConsentOutcome, ConsentRequest};
use crate::dumpcheck::command_dump_reason;
use crate::identity::Requester;
use crate::vault::{validate_name, Secret, Vault};

pub const MIN_REASON_CHARS: usize = 10;
/// Under the 10-minute ceiling of a lane's Bash tool call; a lane calling
/// `with-secret` should pass `timeout: 600000`.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(540);

pub struct RunArgs {
    pub secret: String,
    pub reason: String,
    pub argv: Vec<String>,
    pub wait: Duration,
    pub window: Option<chrono::Duration>,
}

pub fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let sep = args.iter().position(|a| a == "--").ok_or("missing `--` before the command")?;
    let (opts, argv) = (&args[..sep], &args[sep + 1..]);
    let secret = opts.first().ok_or("missing secret NAME")?.clone();
    validate_name(&secret)?;
    let (mut reason, mut wait, mut window) = (None, DEFAULT_WAIT, None);
    let mut i = 1;
    while i < opts.len() {
        let val = opts.get(i + 1).ok_or_else(|| format!("{} needs a value", opts[i]))?;
        match opts[i].as_str() {
            "--reason" => reason = Some(val.clone()),
            "--wait-secs" => wait = Duration::from_secs(val.parse().map_err(|_| "--wait-secs: not a number")?),
            "--window-mins" => window = Some(chrono::Duration::minutes(
                val.parse().map_err(|_| "--window-mins: not a number")?)),
            other => return Err(format!("unknown option {other}")),
        }
        i += 2;
    }
    let reason = reason.ok_or("--reason is required: CireSnave is shown it")?;
    if reason.trim().chars().count() < MIN_REASON_CHARS {
        return Err(format!("--reason must be at least {MIN_REASON_CHARS} characters"));
    }
    if argv.is_empty() {
        return Err("no command after `--`".into());
    }
    Ok(RunArgs { secret, reason, argv: argv.to_vec(), wait, window })
}

pub struct Released {
    pub secret: Secret,
    pub approval: Approval,
    pub newly_granted: bool,
}

fn event(kind: &str, a: &RunArgs, who: &Requester, now: DateTime<Utc>) -> Event {
    Event { at: now, event: kind.into(), secret: a.secret.clone(), role: who.role.clone(),
            session_id: who.session_id.clone(), claude_pid: who.claude_pid,
            command: a.argv.join(" "), reason: a.reason.clone() }
}

pub fn authorize(a: &RunArgs, vault: &Vault, cache: &mut ApprovalCache, who: &Requester,
                 consent: &dyn Consent, now: DateTime<Local>, log: &mut Vec<Event>)
                 -> Result<Released, String> {
    let utc = now.with_timezone(&Utc);
    let command = a.argv.join(" ");
    if let Some(why) = command_dump_reason(&command) {
        log.push(event("refused", a, who, utc));
        return Err(format!("with-secret: blocked - {why}; a secret is never handed to an env dump"));
    }
    let Some(secret) = vault.secrets.get(&a.secret) else {
        log.push(event("refused", a, who, utc));
        return Err(format!("no secret named {} in the vault (`with-secret vault list`)", a.secret));
    };
    if let Some(found) = cache.find(&a.secret, who, utc) {
        log.push(event("used", a, who, utc));
        return Ok(Released { secret: secret.clone(), approval: found.clone(), newly_granted: false });
    }
    let expires_at = expiry(now, a.window);
    let prompt = prompt_text(&ConsentRequest {
        secret: a.secret.clone(), requester: who.clone(), command, reason: a.reason.clone(), expires_at });
    let refusal = match consent.ask(&prompt, a.wait) {
        ConsentOutcome::Approved => None,
        ConsentOutcome::Denied => Some(("denied", "CireSnave declined".to_string())),
        ConsentOutcome::TimedOut => Some(("timed-out", "no answer before the wait ran out".to_string())),
        ConsentOutcome::Unavailable(why) => Some(("unavailable", why)),
    };
    if let Some((kind, why)) = refusal {
        log.push(event(kind, a, who, utc));
        return Err(format!("with-secret: {} not released - {why}", a.secret));
    }
    let approval = Approval { secret: a.secret.clone(), requester: who.clone(), granted_at: utc, expires_at };
    cache.add(approval.clone());
    log.push(event("granted", a, who, utc));
    log.push(event("used", a, who, utc));
    Ok(Released { secret: secret.clone(), approval, newly_granted: true })
}
```

The tests module needs `Access`, which the module itself does not import. Add `use crate::vault::Access;` as the second line of `mod tests`, under `use super::*;`. Everything else the tests use is imported at module level and arrives through `super::*`.

- [ ] **Step 7: Run all the tests.** Run `cargo test -p with-secret`. Expected: all pass.

- [ ] **Step 8: Commit.**

```bash
git add crates/with-secret/src
git commit -m "with-secret: env-dump classifier, audit log, and the authorise decision"
```

---

### Task 8: `main.rs` — the CLI, child spawn with masking, vault commands, hooks

**Files:**
- Create: `crates/with-secret/src/main.rs`
- Test: `crates/with-secret/tests/cli.rs` (integration tests; they spawn the built binary)

**Interfaces:**
- Consumes: everything above.
- Produces the `with-secret` binary:
  - `with-secret NAME --reason R [--wait-secs N] [--window-mins M] -- cmd args…`, which exits with the child's code, or with 2 on any refusal;
  - `with-secret vault list | set NAME --env VAR --access read|write [--rotate-by YYYY-MM-DD] | remove NAME | check`;
  - `with-secret hook pre-tool-use | post-tool-use`, which reads hook JSON on stdin.
- The environment variable `WITH_SECRET_DIR` overrides the data directory. It is **for tests only**, and documented as such: a lane that set it would only point the tool at an empty vault.

- [ ] **Step 1: Write the failing integration tests.** Create `crates/with-secret/tests/cli.rs`. These tests touch only paths that need neither Hello nor DPAPI:

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! The binary's no-consent paths. Consent and DPAPI are covered by unit tests
//! and the ignored live test; these prove the wiring and the hooks.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_with-secret"));
    c.env("WITH_SECRET_DIR", tempfile::tempdir().unwrap().keep());
    c
}

fn hook(kind: &str, input: serde_json::Value) -> (i32, String) {
    let mut child = bin().args(["hook", kind]).stdin(Stdio::piped()).stdout(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap())
}

#[test]
fn pre_tool_use_denies_an_env_dump() {
    let (code, out) = hook("pre-tool-use", serde_json::json!({
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "env"}}));
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn pre_tool_use_is_silent_for_ordinary_commands() {
    let (code, out) = hook("pre-tool-use", serde_json::json!({
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cargo test"}}));
    assert_eq!((code, out.as_str()), (0, ""));
}

#[test]
fn a_hook_given_garbage_fails_open() {
    let mut child = bin().args(["hook", "pre-tool-use"]).stdin(Stdio::piped())
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"not json").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("with-secret hook"));
}

#[test]
fn post_tool_use_without_masks_is_silent() {
    let (code, out) = hook("post-tool-use", serde_json::json!({
        "hook_event_name": "PostToolUse", "tool_name": "Bash",
        "tool_response": {"stdout": "hello", "stderr": ""}}));
    assert_eq!((code, out.as_str()), (0, ""));
}

#[test]
fn run_with_an_unknown_secret_is_refused_with_code_2() {
    let out = bin().args(["NOPE_NOPE", "--reason", "testing the refusal", "--", "cmd", "/c", "echo", "hi"])
        .output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn run_refuses_a_dump_child() {
    let out = bin().args(["TJ_DB", "--reason", "testing the refusal", "--", "env"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("blocked"));
}
```

`run_with_an_unknown_secret_is_refused_with_code_2` hits the vault load first. With an empty `WITH_SECRET_DIR` there is no `vault.bin`, so the vault is empty, the name is unknown, and the exit code is 2. DPAPI is never called.

The masks-present case of `post-tool-use` needs a `masks.json`, which is plain JSON and needs no DPAPI. Add this test:

```rust
#[test]
fn post_tool_use_masks_a_known_value() {
    let dir = tempfile::tempdir().unwrap().keep();
    let v = "postgres://owner:Sup3rS3cret@db/tj";
    std::fs::write(dir.join("masks.json"),
        serde_json::to_vec(&vec![with_secret::mask::HashMask::new("TJ_DB", v).unwrap()]).unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_with-secret")).env("WITH_SECRET_DIR", &dir)
        .args(["hook", "post-tool-use"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(serde_json::json!({
        "hook_event_name": "PostToolUse", "tool_name": "Bash",
        "tool_response": {"stdout": format!("url {v}"), "stderr": ""}}).to_string().as_bytes()).unwrap();
    let out = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    assert!(!out.contains("Sup3rS3cret"), "{out}");
    assert!(out.contains("[with-secret:TJ_DB]"));
}
```

If Task 0 found that the result field is not named `tool_response`, use the recorded name in these tests and in `main.rs`. If it found that `updatedToolOutput` must be a string, assert on the string form.

- [ ] **Step 2: Run the tests to verify they fail.** Run `cargo test -p with-secret --test cli`. Expected: compile error, because the `with-secret` binary has no `main.rs`.

- [ ] **Step 3: Implement `main.rs`.**

```rust
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `with-secret` - WITH-SECRET-DESIGN.md. ⚠️ STOPS ACCIDENTAL EXPOSURE, NOT
//! DELIBERATE MISUSE (§3): a process that is given a secret can print it, and
//! any process running as this Windows user can decrypt the vault.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use chrono::{Local, NaiveDate, Utc};
use lane_restart::facts::{SysinfoFacts, SystemFacts};
use with_secret::approval::ApprovalCache;
use with_secret::consent::{store_prompt_text, Consent, ConsentOutcome};
use with_secret::dpapi::DpapiProtector;
use with_secret::hello::HelloConsent;
use with_secret::mask::{mask_json, masks_json, HashMask, StreamMasker};
use with_secret::run::{authorize, parse_run, DEFAULT_WAIT};
use with_secret::vault::*;
use with_secret::{audit, dumpcheck, identity};

const LANE_STATE_DIR: &str = "C:/Projects/.lane-state";

fn data_dir() -> Result<PathBuf, String> {
    // ⚠️ TEST-ONLY override. Pointing it elsewhere reaches an EMPTY vault, not
    // anyone else's secrets.
    match std::env::var_os("WITH_SECRET_DIR") { Some(d) => Ok(d.into()), None => default_dir() }
}

fn store() -> Result<VaultStore<DpapiProtector>, String> {
    Ok(VaultStore { dir: data_dir()?, protector: DpapiProtector })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("hook") => return hook(args.get(1).map(String::as_str)),
        Some("vault") => vault_cmd(&args[1..]),
        Some("--help") | Some("-h") | None => { print!("{HELP}"); Ok(0) }
        Some(_) => run(&args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => { eprintln!("{e}"); ExitCode::from(2) }
    }
}

const HELP: &str = "\
with-secret NAME --reason \"why\" [--wait-secs N] [--window-mins M] -- <command> [args...]
    Runs <command> with secret NAME in its environment (and nowhere else), after
    CireSnave approves via Windows Hello. One approval: one lane, one secret,
    until local midnight at the latest, void on lane restart.
    Call it from a lane's Bash tool with timeout 600000: the prompt waits up to 9 min.
with-secret vault list | set NAME --env VAR --access read|write [--rotate-by YYYY-MM-DD]
                | remove NAME | check
with-secret hook pre-tool-use | post-tool-use     (Claude Code hooks; JSON on stdin)

This stops ACCIDENTAL exposure. It does not stop a process that has a secret from
printing it, nor a same-user process from decrypting the vault. WITH-SECRET-DESIGN.md §3.
";

fn run(args: &[String]) -> Result<u8, String> {
    let a = parse_run(args)?;
    let store = store()?;
    let vault = store.load()?;
    let table = SysinfoFacts::new(PathBuf::new()).process_table().map_err(|e| format!("{e:?}"))?;
    let who = identity::resolve(&table, std::process::id(), &identity::load_states(Path::new(LANE_STATE_DIR)))?;
    let approvals_path = store.dir.join(APPROVALS_FILE);
    let key = if vault.secrets.contains_key(&a.secret) { store.approval_key()? } else { vec![0; 32] };
    let (mut cache, rejected) = ApprovalCache::load(&approvals_path, key);
    if rejected > 0 {
        eprintln!("with-secret: ignored {rejected} approval entr(y/ies) with a bad signature");
    }
    let mut log = Vec::new();
    let decided = authorize(&a, &vault, &mut cache, &who, &HelloConsent::default(), Local::now(), &mut log);
    let audit_path = store.dir.join(AUDIT_FILE);
    for e in &log {
        if let Err(err) = audit::append(&audit_path, e) { eprintln!("with-secret: audit log: {err}"); }
    }
    let released = decided?;
    if released.newly_granted {
        cache.save(&approvals_path, Utc::now())?;
    }
    spawn_masked(&a.argv, &a.secret, &released.secret)
}

/// ⚠️ The ONLY place a value enters an environment: this child's. stdout and
/// stderr are piped through a StreamMasker each, so the child's own output
/// cannot print the value verbatim. Grandchildren inherit the variable -
/// design §3.
fn spawn_masked(argv: &[String], name: &str, secret: &Secret) -> Result<u8, String> {
    let mut child = Command::new(&argv[0]).args(&argv[1..])
        .env(&secret.env_var, &secret.value)
        .stdin(Stdio::inherit()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|e| format!("could not start {}: {e}", argv[0]))?;
    let pump = |mut src: Box<dyn Read + Send>, mut dst: Box<dyn Write + Send>, value: String, name: String| {
        std::thread::spawn(move || {
            let mut m = StreamMasker::new(&[(name.as_str(), value.as_str())]);
            let mut buf = [0u8; 8192];
            loop {
                match src.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { let _ = dst.write_all(&m.push(&buf[..n])); let _ = dst.flush(); }
                }
            }
            let _ = dst.write_all(&m.finish());
            let _ = dst.flush();
        })
    };
    let out = pump(Box::new(child.stdout.take().unwrap()), Box::new(std::io::stdout()),
                   secret.value.clone(), name.to_string());
    let err = pump(Box::new(child.stderr.take().unwrap()), Box::new(std::io::stderr()),
                   secret.value.clone(), name.to_string());
    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = out.join();
    let _ = err.join();
    Ok(status.code().map(|c| c.clamp(0, 255) as u8).unwrap_or(1))
}

fn require_hello(action: &str, name: &str) -> Result<(), String> {
    match HelloConsent::default().ask(&store_prompt_text(action, name), DEFAULT_WAIT) {
        ConsentOutcome::Approved => Ok(()),
        other => Err(format!("not {action}d: {other:?}")),
    }
}

fn vault_cmd(args: &[String]) -> Result<u8, String> {
    let store = store()?;
    match args.first().map(String::as_str) {
        Some("list") => {
            let today = Local::now().date_naive();
            for (name, s) in &store.load()?.secrets {
                let overdue = s.rotate_by.is_some_and(|d| d < today);
                println!("{name}  env={}  access={:?}  created={}  rotate_by={}{}", s.env_var, s.access,
                         s.created_at.format("%Y-%m-%d"),
                         s.rotate_by.map(|d| d.to_string()).unwrap_or("-".into()),
                         if overdue { "  ⚠️ PAST ROTATE-BY" } else { "" });
            }
            Ok(0)
        }
        Some("set") => {
            let name = args.get(1).ok_or("vault set NAME --env VAR --access read|write")?;
            validate_name(name)?;
            let opt = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
            let env_var = opt("--env").ok_or("--env VAR is required")?;
            let access = match opt("--access").as_deref() {
                Some("read") => Access::Read, Some("write") => Access::Write,
                _ => return Err("--access read|write is required".into()),
            };
            let rotate_by = opt("--rotate-by").map(|d| NaiveDate::parse_from_str(&d, "%Y-%m-%d")
                .map_err(|e| format!("--rotate-by: {e}"))).transpose()?;
            let value = read_value_from_console()?;
            validate_value(&value)?;
            require_hello("store", name)?;
            let mut vault = store.load()?;
            vault.secrets.insert(name.clone(), Secret { value, env_var, access,
                created_at: Utc::now(), rotate_by });
            store.save(&vault, masks_json(&vault)?)?;
            println!("stored {name}");
            Ok(0)
        }
        Some("remove") => {
            let name = args.get(1).ok_or("vault remove NAME")?;
            require_hello("remove", name)?;
            let mut vault = store.load()?;
            vault.secrets.remove(name).ok_or_else(|| format!("no secret named {name}"))?;
            store.save(&vault, masks_json(&vault)?)?;
            println!("removed {name}");
            Ok(0)
        }
        Some("check") => {
            let p = DpapiProtector;
            let ok = p.protect(b"with-secret-check").and_then(|b| p.unprotect(&b))
                .map(|b| b == b"with-secret-check").unwrap_or(false);
            println!("DPAPI round trip: {}", if ok { "ok" } else { "FAILED" });
            println!("Windows Hello: run `with-secret vault set` to see the prompt; `check` never prompts.");
            Ok(if ok { 0 } else { 1 })
        }
        _ => Err("vault list | set | remove | check".into()),
    }
}

/// ⚠️ Typed at a console, never argv or stdin-from-a-pipe: a value in argv is
/// in the process table, and a piped value is in some transcript.
fn read_value_from_console() -> Result<String, String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err("vault set must be run by a person at a console; the value is typed, not piped".into());
    }
    let first = read_hidden("Value (not echoed): ")?;
    let second = read_hidden("Again: ")?;
    if first != second { return Err("the two entries differ".into()); }
    Ok(first)
}

#[cfg(windows)]
fn read_hidden(prompt: &str) -> Result<String, String> {
    use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleMode,
        ENABLE_ECHO_INPUT, STD_INPUT_HANDLE};
    eprint!("{prompt}");
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    unsafe { GetConsoleMode(h, &mut mode) };
    unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) };
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    unsafe { SetConsoleMode(h, mode) };
    eprintln!();
    r.map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(not(windows))]
fn read_hidden(_: &str) -> Result<String, String> { Err("vault set is Windows-only".into()) }

/// ⚠️ FAILS OPEN: any error exits 0 with a warning. A hook bug must not block
/// every tool call in every lane; the hooks are defence in depth, not the gate.
fn hook(kind: Option<&str>) -> ExitCode {
    let mut input = String::new();
    let parsed: Result<serde_json::Value, String> = std::io::stdin().read_to_string(&mut input)
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_str(&input).map_err(|e| e.to_string()));
    let v = match parsed {
        Ok(v) => v,
        Err(e) => { eprintln!("with-secret hook: unreadable input ({e}); allowing"); return ExitCode::SUCCESS }
    };
    let tool = v["tool_name"].as_str().unwrap_or("");
    match kind {
        Some("pre-tool-use") => {
            if let Some(why) = dumpcheck::dump_reason(tool, &v["tool_input"]) {
                println!("{}", serde_json::json!({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse", "permissionDecision": "deny",
                    "permissionDecisionReason": why}}));
            }
        }
        Some("post-tool-use") => {
            let masks: Vec<HashMask> = match data_dir().map(|d| d.join(MASKS_FILE)) {
                Ok(p) => match std::fs::read(&p) {
                    Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                        eprintln!("with-secret hook: {} unreadable ({e}); not masking", p.display());
                        Vec::new()
                    }),
                    Err(_) => Vec::new(),
                },
                Err(e) => { eprintln!("with-secret hook: {e}"); Vec::new() }
            };
            let (masked, hits) = mask_json(&v["tool_response"], &masks);
            if hits > 0 {
                println!("{}", serde_json::json!({"hookSpecificOutput": {
                    "hookEventName": "PostToolUse", "updatedToolOutput": masked}}));
            }
        }
        _ => eprintln!("with-secret hook: unknown hook kind {kind:?}; allowing"),
    }
    ExitCode::SUCCESS
}
```

Notes the implementer needs:
- **Approval-key order.** `run` only loads `approval_key()` when the secret exists. For an unknown name, `authorize` refuses before the cache is consulted, so the dummy key is harmless and DPAPI is never touched. That is what keeps `run_with_an_unknown_secret_is_refused_with_code_2` free of Windows dependencies.
- **Task 0's recorded shape.** If Task 0 recorded that `updatedToolOutput` must be a string, change `"updatedToolOutput": masked` to `"updatedToolOutput": masked.to_string()`.
- **`process_table`.** `SysinfoFacts::new` takes the Claude config directory, which `process_table` does not use, so `PathBuf::new()` is passed. Confirm in `facts.rs` that `process_table` ignores it.

- [ ] **Step 4: Run the tests.**

Run: `cargo test -p with-secret`
Expected: all unit and integration tests pass, with the live test ignored.

Run: `cargo clippy -p with-secret -- -D warnings`
Expected: clean, if CI runs clippy. Check `.github/workflows/ci.yml` and match what CI runs.

- [ ] **Step 5: Live check with CireSnave (the PM arranges it). Every value used here is a throwaway test secret, never a real one.**
  1. `with-secret vault set TEST_THROWAWAY --env TEST_VAR --access read`. Type a 20-character random string twice, then approve the Hello prompt. Expected: `stored TEST_THROWAWAY`.
  2. From a lane's Bash tool (timeout 600000): `with-secret TEST_THROWAWAY --reason "live check of the approval prompt" -- cmd /c echo %TEST_VAR%`. Expected: a Hello prompt naming that lane, the secret, the command and the reason. Approve. The output shows `[with-secret:TEST_THROWAWAY]`, not the value.
  3. Repeat step 2. Expected: no prompt (approved for the day); masked output again.
  4. Run the same command from a **different** lane. Expected: a prompt, because approvals are per lane.
  5. `with-secret vault remove TEST_THROWAWAY`, then approve.
  6. Read `access.log`. It holds granted/used entries and no value.

  Record each result in the PR body.

- [ ] **Step 6: Commit.**

```bash
git add crates/with-secret Cargo.lock
git commit -m "with-secret: CLI - run with masking, vault set/list/remove/check, hooks"
```

---

### Task 9: Runbook, hook wiring, least privilege, and the TJ migration

**Files:**
- Create: `docs/WITH-SECRET-RUNBOOK.md`
- Modify: `README.md` (one line where it lists tools, if it has such a list)

The runbook covers, in this order:

1. **The honest limit, first and in full,** copied from design §3.
2. **Install.**
   - Build with `cargo build --release -p with-secret`.
   - The PM installs the binary at `C:\Projects\.claude-hooks\with-secret.exe`, the same way `lane-restart.exe` is installed: by full path, keeping the previous binary under a versioned name.
   - Then run `with-secret vault check`.
3. **Adding a secret.** CireSnave runs `with-secret vault set NAME --env VAR --access read|write --rotate-by YYYY-MM-DD` at his own console. A lane never can, because the value is typed at a console and the Hello prompt needs his PIN.
4. **Using a secret from a lane.** `with-secret NAME --reason "…" -- <command>`, called with the Bash tool's `timeout: 600000`. Explain the prompt, the approval lasting the rest of the day, and that a restart voids it.
5. **Hook wiring.** Give the exact JSON block to add to `C:\Projects\.claude\settings.json`: a `PreToolUse` hook with matcher `Bash|PowerShell|Read`, plus a `PostToolUse` hook with matcher `Bash|PowerShell|Read`, both pointing at the full path of `with-secret.exe` with `hook pre-tool-use` or `hook post-tool-use`.
   - **⚠️ Applying it is CireSnave's or the PM's step.** It is shared configuration that every lane loads; never have a lane apply it.
   - If Task 0 found `updatedToolOutput` does not work, say that the post hook is omitted and why.
6. **Least privilege (e), a procedure no tool enforces.**
   - For each credential, prefer a read-only role for checks (for Neon: `CREATE ROLE … LOGIN` plus `GRANT SELECT`), stored as an `--access read` secret.
   - Write credentials are separate secrets with a `--rotate-by` date at most 7 days out. `vault list` flags one that is overdue.
   - Rotation itself is done by hand in the provider's console.
7. **Migrating `TJ_PROD_DATABASE_URL`** (item 81's cleanup is CireSnave's):
   - after rotating the `neondb_owner` password, store the new string with `vault set TJ_PROD_DATABASE_URL --env DATABASE_URL --access write --rotate-by …`;
   - also create and store a read-only role as `TJ_PROD_DATABASE_URL_RO`;
   - confirm the old User-scope variable is gone: `[Environment]::GetEnvironmentVariable('TJ_PROD_DATABASE_URL','User')` returns nothing. As a control, the same call for `PATH` returns a value.

- [ ] **Step 1: Write `docs/WITH-SECRET-RUNBOOK.md`** with the seven sections above. The hook JSON must use the real binary path and the real subcommand names from Task 8, and the field names Task 0 confirmed.
- [ ] **Step 2: Update the design doc's status line** to: `**Status: BUILT (crates/with-secret). Hooks wired: <yes/no, by whom, when>.**`
- [ ] **Step 3: Run the full workspace checks:** `cargo test --workspace`, then `python .github/spdx_gate.py --self-test`, then `python .github/spdx_gate.py`. Expected: all pass.
- [ ] **Step 4: Commit.**

```bash
git add docs/WITH-SECRET-RUNBOOK.md WITH-SECRET-DESIGN.md README.md
git commit -m "docs: with-secret runbook - install, hooks, least privilege, TJ migration, honest limit"
```

---

## After the plan

- One PR. Report it to the PM with `[READY]`, including the Task 0 and Task 8 live results. The version number is the PM's to allocate.
- **Not in scope:**
  - wiring the hooks into shared settings (CireSnave or the PM, per the runbook);
  - rotating or migrating the real TJ credential (CireSnave, per item 81);
  - masking transformed encodings;
  - any protection against deliberate same-user misuse (design §3).
