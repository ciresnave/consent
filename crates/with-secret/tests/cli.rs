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

#[test]
fn run_refuses_a_dump_child() {
    let out = bin()
        .args(["TJ_DB", "--reason", "testing the refusal", "--", "env"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("blocked"));
}

#[test]
fn post_tool_use_masks_a_known_value() {
    let dir = tempfile::tempdir().unwrap().keep();
    let v = "postgres://owner:Sup3rS3cret@db/tj";
    std::fs::write(
        dir.join("masks.json"),
        serde_json::to_vec(&vec![with_secret::mask::HashMask::new("TJ_DB", v).unwrap()]).unwrap(),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_with-secret"))
        .env("WITH_SECRET_DIR", &dir)
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
    let out = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
    assert!(!out.contains("Sup3rS3cret"), "{out}");
    assert!(out.contains("[with-secret:TJ_DB]"));
    // Design §4 (3d): Claude Code silently ignores a STRING updatedToolOutput
    // for Bash; only the object form replaces the output.
    let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        parsed["hookSpecificOutput"]["updatedToolOutput"]["stdout"].is_string(),
        "updatedToolOutput must be an object with a string stdout: {out}"
    );
}
