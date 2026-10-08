// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `user-request` binary against a throwaway store. Windows-only: the
//! binary's store is DPAPI-protected. Debug builds only (review I-E): a
//! release binary ignores the overrides and would act on the REAL store.
#![cfg(all(windows, debug_assertions))]

use std::path::Path;
use std::process::Command;

use chrono::{Duration, Utc};
use user_request::dpapi::Dpapi;
use user_request::request::{next_local_midnight, Approval, KindId, Requester};
use user_request::store::{AuditOnly, Store};
use user_request::Outcome;

const ENTROPY: &[u8] = b"overmind.user-request.v1";

fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_user-request"))
        .args(args)
        .env("USER_REQUEST_DIR", dir)
        .env("USER_REQUEST_HEAD", dir.join("head.copy"))
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn seed(dir: &Path) -> (String, String) {
    let mut s = Store::open(
        dir,
        &Dpapi { entropy: ENTROPY },
        Some(dir.join("head.copy")),
    )
    .unwrap();
    let who = Requester {
        role: "overmind".into(),
        session_id: "s".into(),
        claude_pid: 1,
        claude_start_secs: 1,
        managed: true,
    };
    let now = Utc::now();
    let mk = |kind, subject: &str, expires_at| Approval {
        kind,
        subject: subject.into(),
        requester: who.clone(),
        approved_at: now,
        expires_at,
    };
    // the only way in: a reservation the channel approved
    let mut grant = |mut ap: Approval| {
        let r = s.may_ask(&who, ap.kind, &ap.subject, &AuditOnly).unwrap();
        // given after the reservation, as a channel would
        ap.approved_at = Utc::now();
        s.resolve(&r, &Outcome::Approved(ap), &AuditOnly)
            .unwrap()
            .unwrap()
    };
    let forever = grant(mk(
        KindId::LaneDialogBypass,
        &user_request::request::lane_dialog_subject("fuel", "trust-dialog").unwrap(),
        None,
    ));
    // a Secret may not outlive local midnight
    let soon = (now + Duration::minutes(5)).min(next_local_midnight(now));
    let timed = grant(mk(KindId::Secret, "db", Some(soon)));
    (forever, timed)
}

#[test]
fn list_shows_forever_grants_first_and_loudly() {
    let d = tempfile::tempdir().unwrap();
    let (forever, timed) = seed(d.path());
    let (code, out, _) = run(d.path(), &["list"]);
    assert_eq!(code, 0);
    let (f, t) = (out.find(&forever).unwrap(), out.find(&timed).unwrap());
    assert!(out.starts_with("*** FOREVER GRANTS"), "{out}");
    assert!(f < t, "{out}");
}

#[test]
fn revoke_removes_one_and_the_audit_chain_records_it() {
    let d = tempfile::tempdir().unwrap();
    let (forever, timed) = seed(d.path());
    assert_eq!(run(d.path(), &["revoke", &forever]).0, 0);
    let (_, out, _) = run(d.path(), &["list"]);
    assert!(!out.contains(&forever) && out.contains(&timed), "{out}");
    let (code, out, err) = run(d.path(), &["audit", "verify"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("audit chain intact"), "{out}");
    let log = std::fs::read_to_string(d.path().join("audit.jsonl")).unwrap();
    assert!(
        log.contains(&format!("\"detail\":\"id={forever}\"")) && log.contains("\"revoked\""),
        "{log}"
    );
}

#[test]
fn revoke_all_is_the_panic_button() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    let (code, out, _) = run(d.path(), &["revoke", "--all"]);
    assert_eq!((code, out.trim()), (0, "revoked 2 grant(s)"));
    assert!(run(d.path(), &["list"]).1.contains("no active grants"));
    let log = std::fs::read_to_string(d.path().join("audit.jsonl")).unwrap();
    assert!(log.contains("\"revoked-all\""), "{log}");
}

#[test]
fn an_unknown_id_and_bad_usage_fail() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    assert_eq!(run(d.path(), &["revoke", "nope"]).0, 1);
    assert_eq!(run(d.path(), &["frobnicate"]).0, 1);
}

#[test]
fn a_truncated_audit_log_fails_verify() {
    let d = tempfile::tempdir().unwrap();
    let (forever, timed) = seed(d.path());
    run(d.path(), &["revoke", &forever]);
    run(d.path(), &["revoke", &timed]);
    let p = d.path().join("audit.jsonl");
    let first = std::fs::read_to_string(&p)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    std::fs::write(&p, first + "\n").unwrap();
    let (code, _, err) = run(d.path(), &["audit", "verify"]);
    assert_eq!(code, 1);
    assert!(err.contains("head copy"), "{err}");
}

#[test]
fn read_only_commands_never_create_a_store() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("none");
    let (code, out, err) = run(&dir, &["list"]);
    assert_eq!(code, 0);
    assert!(
        out.contains("no store yet") && err.contains("store "),
        "{out} {err}"
    );
    assert_eq!(run(&dir, &["audit", "verify"]).0, 0);
    // the panic button succeeds when there is nothing to stop
    assert_eq!(run(&dir, &["revoke", "--all"]).0, 0);
    assert_eq!(run(&dir, &["revoke", "some-id"]).0, 1);
    assert!(!dir.exists());
}

#[test]
fn repair_restores_a_damaged_store_by_revoking_everything() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    std::fs::remove_file(d.path().join("attempts.json")).unwrap();
    let (code, out, err) = run(d.path(), &["list"]);
    assert_eq!(code, 1, "{out} {err}");
    assert!(out.contains("CANNOT BE TRUSTED"), "{out}");
    let (code, out, err) = run(d.path(), &["repair"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("revoked 2 grant(s)"), "{out}");
    let (code, out, _) = run(d.path(), &["list"]);
    assert_eq!((code, out.trim()), (0, "no active grants"));
    let (code, out, err) = run(d.path(), &["audit", "verify"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("audit chain intact"), "{out}");
}

#[test]
fn a_lost_key_lists_as_unknown_not_as_nothing_granted() {
    let d = tempfile::tempdir().unwrap();
    seed(d.path());
    std::fs::remove_file(d.path().join("store.key")).unwrap();
    let (code, out, _) = run(d.path(), &["list"]);
    assert_eq!(code, 1);
    assert!(out.contains("GRANTS UNKNOWN"), "{out}");
    assert_eq!(run(d.path(), &["audit", "verify"]).0, 1);
    assert_eq!(run(d.path(), &["revoke", "--all"]).0, 1);
    assert_eq!(run(d.path(), &["repair"]).0, 0);
    assert_eq!(run(d.path(), &["list"]).1.trim(), "no active grants");
}
