// SPDX-License-Identifier: MIT OR Apache-2.0
//! The binary's no-consent paths. Consent and DPAPI are covered by unit tests
//! and the ignored live test; these prove the wiring and the hooks.

use std::io::Write;
use std::process::{Command, Stdio};

/// A scratch vault AND a scratch approvals store: never the person's real
/// ones (#2b).
fn bin() -> Command {
    let scratch = tempfile::tempdir().unwrap().keep();
    let mut c = Command::new(env!("CARGO_BIN_EXE_with-secret"));
    c.env("WITH_SECRET_DIR", scratch.join("vault"))
        .env("USER_REQUEST_DIR", scratch.join("user-request"))
        .env("USER_REQUEST_HEAD", scratch.join("head"));
    c
}

fn hook(kind: &str, input: serde_json::Value) -> (i32, String) {
    let mut child = bin()
        .args(["hook", kind])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
    )
}

#[test]
fn pre_tool_use_denies_an_env_dump() {
    let (code, out) = hook(
        "pre-tool-use",
        serde_json::json!({
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "env"}}),
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn pre_tool_use_is_silent_for_ordinary_commands() {
    let (code, out) = hook(
        "pre-tool-use",
        serde_json::json!({
        "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cargo test"}}),
    );
    assert_eq!((code, out.as_str()), (0, ""));
}

#[test]
fn a_hook_given_garbage_fails_open() {
    let mut child = bin()
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"not json").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("with-secret hook"));
}

#[test]
fn post_tool_use_without_masks_is_silent() {
    let (code, out) = hook(
        "post-tool-use",
        serde_json::json!({
        "hook_event_name": "PostToolUse", "tool_name": "Bash",
        "tool_response": {"stdout": "hello", "stderr": ""}}),
    );
    assert_eq!((code, out.as_str()), (0, ""));
}

// the scratch-store overrides are debug-only (second review of #2b, 8)
#[cfg(debug_assertions)]
#[test]
fn run_with_an_unknown_secret_is_refused_with_code_2() {
    let out = bin()
        .args([
            "NOPE_NOPE",
            "--reason",
            "testing the refusal",
            "--",
            "cmd",
            "/c",
            "echo",
            "hi",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

// the scratch-store overrides are debug-only (second review of #2b, 8)
#[cfg(debug_assertions)]
#[test]
fn run_refuses_a_dump_child() {
    let out = bin()
        .args(["TJ_DB", "--reason", "testing the refusal", "--", "env"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("blocked"));
}

#[cfg(windows)]
const V: &str = "postgres://owner:Sup3rS3cret@db/tj";

#[cfg(windows)]
fn masks_list() -> Vec<u8> {
    serde_json::to_vec(&vec![with_secret::mask::HashMask::new("TJ_DB", V).unwrap()]).unwrap()
}

/// Row 5: the masks live in DPAPI-protected `masks.bin`, so the hook needs
/// DPAPI (Windows) to read them.
#[cfg(windows)]
#[test]
fn post_tool_use_masks_a_known_value() {
    let dir = tempfile::tempdir().unwrap().keep();
    with_secret::vault::VaultStore {
        dir: dir.clone(),
        protector: with_secret::dpapi::DpapiProtector,
    }
    .save(&Default::default(), masks_list())
    .unwrap();
    assert_masked(&post_tool_use_in(&dir));
}

/// A 0.6 install left a plaintext `masks.json`. The first hook run seals it
/// into `masks.bin` and deletes it, and masking carries on with no gap.
#[cfg(windows)]
#[test]
fn post_tool_use_seals_a_legacy_masks_json() {
    let dir = tempfile::tempdir().unwrap().keep();
    std::fs::write(dir.join("masks.json"), masks_list()).unwrap();
    assert_masked(&post_tool_use_in(&dir));
    assert!(!dir.join("masks.json").exists(), "legacy file left behind");
    let sealed = std::fs::read(dir.join("masks.bin")).unwrap();
    assert!(
        serde_json::from_slice::<serde_json::Value>(&sealed).is_err(),
        "masks.bin is plaintext JSON"
    );
    // ...and the sealed file is what the next run reads.
    assert_masked(&post_tool_use_in(&dir));
}

#[cfg(windows)]
fn assert_masked(out: &str) {
    assert!(!out.contains("Sup3rS3cret"), "{out}");
    assert!(out.contains("[with-secret:TJ_DB]"), "{out}");
    // Design §4 (3d): Claude Code silently ignores a STRING updatedToolOutput
    // for Bash; only the object form replaces the output.
    let parsed: serde_json::Value = serde_json::from_str(out).unwrap();
    assert!(
        parsed["hookSpecificOutput"]["updatedToolOutput"]["stdout"].is_string(),
        "updatedToolOutput must be an object with a string stdout: {out}"
    );
}

#[cfg(windows)]
fn post_tool_use_in(dir: &std::path::Path) -> String {
    let v = V;
    let mut child = Command::new(env!("CARGO_BIN_EXE_with-secret"))
        .env("WITH_SECRET_DIR", dir)
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::json!({
            "hook_event_name": "PostToolUse", "tool_name": "Bash",
            "tool_response": {"stdout": format!("url {v}"), "stderr": ""}})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
}

/// Board 134: approvals can now outlive today, so they can be ended at any
/// time, with no Hello (it only removes privilege). With no store yet there
/// is nothing to revoke. The scratch-store overrides are debug-only.
#[cfg(debug_assertions)]
#[test]
fn revoke_ends_approvals_and_checks_its_arguments() {
    let out = bin().args(["revoke", "--all"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "revoked 0 approval(s)"
    );
    assert_eq!(
        bin()
            .args(["revoke", "TJ_DB"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(0)
    );
    for bad in [&["revoke"][..], &["revoke", "tj_db"], &["revoke", "A", "B"]] {
        assert_eq!(
            bin().args(bad).output().unwrap().status.code(),
            Some(2),
            "{bad:?}"
        );
    }
}

/// Second review of #2b, finding 5: `with-secret revoke NAME | --all`
/// against a store that HOLDS grants: it revokes that secret's grants for
/// every lane (then every secret's), and leaves other kinds alone. The
/// store's key is DPAPI-protected, so this is Windows-only.
#[cfg(all(windows, debug_assertions))]
#[test]
fn revoke_ends_secrets_grants_in_the_store_and_nothing_else() {
    use user_request::channel::Outcome;
    use user_request::locate::PROTECTOR;
    use user_request::request::{Approval, KindId, Requester};
    use user_request::store::{AuditOnly, Store};

    let scratch = tempfile::tempdir().unwrap().keep();
    let (dir, head) = (scratch.join("user-request"), scratch.join("head"));
    let lane = |role: &str| Requester {
        role: role.into(),
        session_id: "s".into(),
        claude_pid: 1,
        claude_start_secs: 1,
        managed: true,
    };
    let grant = |kind: KindId, subject: &str, who: &Requester| {
        let mut s = Store::open(&dir, &PROTECTOR, Some(head.clone())).unwrap();
        let r = s.may_ask(who, kind, subject, &AuditOnly).unwrap();
        let ap = Approval {
            kind,
            subject: subject.into(),
            requester: who.clone(),
            approved_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        };
        s.resolve(&r, &Outcome::Approved(ap), &AuditOnly)
            .unwrap()
            .unwrap()
    };
    grant(KindId::Secret, "TJ_DB", &lane("humboldt"));
    grant(KindId::Secret, "TJ_DB", &lane("fuel"));
    grant(KindId::Secret, "OTHER", &lane("humboldt"));
    let bypass = grant(KindId::LaneDialogBypass, "TJ_DB", &lane("pm"));
    let with_secret = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_with-secret"))
            .env("WITH_SECRET_DIR", scratch.join("vault"))
            .env("USER_REQUEST_DIR", &dir)
            .env("USER_REQUEST_HEAD", &head)
            .args(args)
            .output()
            .unwrap()
    };
    let active = || {
        let s = Store::open(&dir, &PROTECTOR, Some(head.clone())).unwrap();
        assert_eq!(s.untrusted(), None);
        s.active()
            .into_iter()
            .map(|g| (g.approval.kind, g.approval.subject.clone()))
            .collect::<Vec<_>>()
    };
    let out = with_secret(&["revoke", "TJ_DB"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "revoked 2 approval(s)"
    );
    let left = active();
    assert_eq!(left.len(), 2, "{left:?}");
    assert!(left.contains(&(KindId::Secret, "OTHER".into())));
    assert!(left.contains(&(KindId::LaneDialogBypass, "TJ_DB".into())));
    let out = with_secret(&["revoke", "--all"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "revoked 1 approval(s)"
    );
    assert_eq!(active(), vec![(KindId::LaneDialogBypass, "TJ_DB".into())]);
    let s = Store::open(&dir, &PROTECTOR, Some(head.clone())).unwrap();
    assert_eq!(s.active()[0].id, bypass);
}

/// #2b and its second review, findings 1 and 6: a scratch vault with the
/// REAL approvals store, or the real audit head copy, is refused, so a test
/// can never revoke the person's approvals or untrust their store. Every
/// path here points at scratch, so a broken guard still cannot reach the
/// real store. Control: with both overrides, the same command succeeds.
#[cfg(debug_assertions)]
#[test]
fn a_scratch_vault_never_reaches_the_real_approvals() {
    let scratch = tempfile::tempdir().unwrap().keep();
    let cmd = || {
        let mut c = Command::new(env!("CARGO_BIN_EXE_with-secret"));
        c.env("WITH_SECRET_DIR", scratch.join("vault"))
            .env("LOCALAPPDATA", scratch.join("appdata"))
            .args(["revoke", "--all"]);
        c
    };
    let no_dir = cmd()
        .env_remove("USER_REQUEST_DIR")
        .env("USER_REQUEST_HEAD", scratch.join("head"))
        .output()
        .unwrap();
    let no_head = cmd()
        .env("USER_REQUEST_DIR", scratch.join("user-request"))
        .env_remove("USER_REQUEST_HEAD")
        .output()
        .unwrap();
    for out in [no_dir, no_head] {
        assert_eq!(out.status.code(), Some(2), "{out:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("USER_REQUEST_HEAD"));
    }
    let out = cmd()
        .env("USER_REQUEST_DIR", scratch.join("user-request"))
        .env("USER_REQUEST_HEAD", scratch.join("head"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}
