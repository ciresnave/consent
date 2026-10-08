// SPDX-License-Identifier: MIT OR Apache-2.0
//! The store, the gate and the audit chain. Each `review` note names the
//! finding of the review of ea50f85 the test pins.

use super::*;
use crate::channel::Outcome;
use chrono::TimeZone;
use std::cell::RefCell;
use tempfile::tempdir;

/// Reversible and keyed, so "another key" is testable.
struct Xor(u8);
impl Protector for Xor {
    fn protect(&self, p: &[u8]) -> Result<Vec<u8>, String> {
        Ok(p.iter().map(|b| b ^ self.0).collect())
    }
    fn unprotect(&self, b: &[u8]) -> Result<Vec<u8>, String> {
        Ok(b.iter().map(|x| x ^ self.0).collect())
    }
}

/// A protector whose decryption fails outright (a DPAPI error).
struct Broken;
impl Protector for Broken {
    fn protect(&self, p: &[u8]) -> Result<Vec<u8>, String> {
        Ok(p.to_vec())
    }
    fn unprotect(&self, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("DPAPI said no".into())
    }
}

#[derive(Default)]
struct Alerts(RefCell<Vec<String>>);
impl Alert for Alerts {
    fn alert(&self, what: &str) {
        self.0.borrow_mut().push(what.to_string());
    }
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 7, 16, 0, 0).unwrap()
}

fn mins(m: i64) -> DateTime<Utc> {
    t0() + Duration::minutes(m)
}

/// A lane-bound subject (user-request #5): the dialog named `d`, on lane fuel.
fn lane_subject(d: &str) -> String {
    crate::request::lane_dialog_subject("fuel", d).unwrap()
}

fn who(role: &str, session: &str) -> Requester {
    Requester {
        role: role.into(),
        session_id: session.into(),
        claude_pid: 42,
        claude_start_secs: 1,
        managed: true,
    }
}

fn approval(
    kind: KindId,
    subject: &str,
    r: &Requester,
    expires: Option<DateTime<Utc>>,
) -> Approval {
    Approval {
        kind,
        subject: subject.into(),
        requester: r.clone(),
        approved_at: t0(),
        expires_at: expires,
    }
}

/// A grant as `resolve` makes one: added, then saved.
fn add(s: &mut Store, a: Approval) -> String {
    let id = s.add(a, t0()).unwrap();
    s.save(t0()).unwrap();
    id
}

/// What the channel answered, for the `prompt` helper.
fn answer(outcome: &str, r: &Requester, subject: &str) -> Outcome {
    match outcome {
        "approved" => Outcome::Approved(approval(KindId::Secret, subject, r, Some(mins(60)))),
        "denied" => Outcome::Denied,
        "timed-out" => Outcome::TimedOut,
        other => panic!("{other}"),
    }
}

fn open(dir: &Path) -> Store {
    Store::open(dir, &Xor(7), Some(dir.join("head.copy"))).unwrap()
}

/// One full prompt through the gate: reserve, drop the store (the lock),
/// answer, resolve.
fn prompt(
    dir: &Path,
    r: &Requester,
    subject: &str,
    outcome: &str,
    at: DateTime<Utc>,
) -> Result<(), String> {
    let mut s = open(dir);
    let res = s.may_ask_at(r, KindId::Secret, subject, at, &AuditOnly)?;
    drop(s);
    let mut s = open(dir);
    s.resolve_at(&res, &answer(outcome, r, subject), at, &AuditOnly)
        .unwrap();
    Ok(())
}

fn audit_text(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("audit.jsonl")).unwrap_or_default()
}

// -- grants -----------------------------------------------------------------

#[test]
fn a_grant_is_found_by_kind_subject_and_scope_until_it_expires() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("overmind", "s1");
    add(&mut s, approval(KindId::Secret, "DB", &a, Some(mins(60))));
    assert!(s.find_at(KindId::Secret, "DB", &a, t0()).is_some());
    assert!(s.find_at(KindId::Secret, "OTHER", &a, t0()).is_none());
    assert!(
        s.find_at(KindId::Secret, "DB", &who("overmind", "s2"), t0())
            .is_none(),
        "a restart voids it"
    );
    assert!(s
        .find_at(KindId::Secret, "DB", &who("fuel", "s1"), t0())
        .is_none());
    assert!(
        s.find_at(KindId::Secret, "DB", &a, mins(60)).is_none(),
        "expired"
    );
}

#[test]
fn an_any_requester_grant_covers_every_lane_and_forever_never_expires() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("pm", "s"),
            None,
        ),
    );
    let later = t0() + Duration::days(3650);
    assert!(s
        .find_at(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("fuel", "x"),
            later
        )
        .is_some());
}

#[test]
fn grants_survive_a_save_and_expired_ones_are_dropped() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s");
    add(&mut s, approval(KindId::Secret, "LIVE", &a, Some(mins(60))));
    add(&mut s, approval(KindId::Secret, "OLD", &a, Some(mins(1))));
    s.save(mins(2)).unwrap();
    drop(s);
    let s = open(d.path());
    assert_eq!(s.untrusted, None);
    let subjects: Vec<_> = s
        .grants
        .iter()
        .map(|g| g.approval.subject.as_str())
        .collect();
    assert_eq!(subjects, vec!["LIVE"]);
}

#[test]
fn ids_are_128_random_bits() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s");
    let x = add(&mut s, approval(KindId::Secret, "A", &a, Some(mins(60))));
    let y = add(&mut s, approval(KindId::Secret, "A", &a, Some(mins(60))));
    assert_eq!(x.len(), 32);
    assert!(x.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(x, y);
}

#[test]
fn revoke_and_revoke_all_persist_as_tombstones() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s");
    let x = add(&mut s, approval(KindId::Secret, "A", &a, Some(mins(60))));
    add(&mut s, approval(KindId::Secret, "B", &a, Some(mins(60))));
    add(&mut s, approval(KindId::Secret, "C", &a, Some(mins(60))));
    assert!(s.revoke_at(&x, t0()).unwrap());
    assert!(!s.revoke_at(&x, t0()).unwrap(), "already revoked");
    s.save(t0()).unwrap();
    drop(s);
    let mut s = open(d.path());
    assert_eq!(s.active_at(t0()).len(), 2);
    assert!(s.revoked.contains(&x));
    assert_eq!(s.revoke_all_at(t0()).unwrap(), 2);
    s.save(t0()).unwrap();
    drop(s);
    assert!(open(d.path()).active_at(t0()).is_empty());
}

// -- integrity: the audit chain anchors the files ----------------------------

/// Review C2: a revocation cannot come back, even from a process that had
/// the store open before it (the lock serialises them), nor from an old
/// copy of the file put back (review I4).
#[test]
fn a_revoked_grant_never_comes_back() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let g = add(
        &mut s,
        approval(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("pm", "s"),
            None,
        ),
    );
    s.save(t0()).unwrap();
    drop(s);
    let before = std::fs::read(d.path().join("grants.json")).unwrap();
    let mut s = open(d.path());
    s.revoke_all_at(t0()).unwrap();
    s.save(t0()).unwrap();
    drop(s);
    // a lane that records an attempt afterwards does not resurrect it
    prompt(d.path(), &who("fuel", "x"), "S", "approved", t0()).unwrap();
    assert!(open(d.path())
        .find_at(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("o", "s"),
            t0()
        )
        .is_none());
    // nor does putting the old, validly signed file back
    std::fs::write(d.path().join("grants.json"), before).unwrap();
    let s = open(d.path());
    assert!(
        matches!(s.untrusted, Some(Untrusted::Files(_))),
        "{:?}",
        s.untrusted
    );
    assert!(
        s.find_at(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("o", "s"),
            t0()
        )
        .is_none(),
        "{g}"
    );
}

#[test]
fn a_tampered_file_is_quarantined_and_the_store_fails_closed() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    s.save(t0()).unwrap();
    drop(s);
    let p = d.path().join("grants.json");
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("\"DB\"", "\"PROD\"");
    std::fs::write(&p, text).unwrap();
    let mut s = open(d.path());
    assert!(matches!(s.untrusted, Some(Untrusted::Files(_))));
    assert!(s
        .find_at(KindId::Secret, "PROD", &who("o", "s"), t0())
        .is_none());
    assert!(
        s.may_ask_at(&who("o", "s"), KindId::Secret, "X", t0(), &AuditOnly)
            .is_err(),
        "gate fails open"
    );
    let kept = std::fs::read_dir(d.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains("rejected"));
    assert!(kept, "the bad file was dropped instead of kept");
}

/// Review I3: deleting the attempts file (or rolling it back) must not reset
/// the gate.
#[test]
fn a_deleted_attempts_file_makes_the_gate_fail_closed() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    prompt(d.path(), &a, "DB", "denied", t0()).unwrap();
    std::fs::remove_file(d.path().join("attempts.json")).unwrap();
    let mut s = open(d.path());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "OTHER", mins(1), &AuditOnly)
        .is_err());
}

/// Review C-B: an untrustworthy store can still revoke, but no save
/// restores trust - only a repair, which revokes everything.
#[test]
fn an_untrustworthy_store_revokes_but_only_a_repair_restores_trust() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    let keep = add(
        &mut s,
        approval(KindId::Secret, "KEEP", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    std::fs::remove_file(d.path().join("attempts.json")).unwrap();
    let mut s = open(d.path());
    assert!(s.untrusted.is_some());
    assert!(s.revoke_at(&keep, t0()).unwrap());
    drop(s);
    let mut s = open(d.path());
    assert!(
        matches!(s.untrusted, Some(Untrusted::Files(_))),
        "a save laundered it: {:?}",
        s.untrusted
    );
    assert!(s.revoked.contains(&keep), "the revocation did not land");
    assert_eq!(s.repair_at(t0(), &Xor(7)).unwrap().revoked, 1);
    assert_eq!(s.untrusted, None);
    drop(s);
    let s = open(d.path());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    assert!(s.active_at(t0()).is_empty());
}

// -- the key -----------------------------------------------------------------

#[test]
fn a_key_that_decrypts_to_the_wrong_bytes_trusts_nothing_and_saves_nothing() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    s.save(t0()).unwrap();
    drop(s);
    let mut wrong = Store::open(d.path(), &Xor(9), None).unwrap();
    assert!(matches!(wrong.untrusted, Some(Untrusted::Key(_))));
    assert!(wrong
        .find_at(KindId::Secret, "DB", &who("o", "s"), t0())
        .is_none());
    assert!(wrong.save(t0()).is_err());
    drop(wrong);
    assert_eq!(
        open(d.path()).grants.len(),
        1,
        "the real grants were overwritten"
    );
}

/// Review I3: a DPAPI failure keeps its reason and fails closed.
#[test]
fn a_key_that_does_not_decrypt_says_why_and_fails_closed() {
    let d = tempdir().unwrap();
    drop(open(d.path()));
    let mut s = Store::open(d.path(), &Broken, None).unwrap();
    match &s.untrusted {
        Some(Untrusted::Key(why)) => assert!(why.contains("DPAPI said no"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(s
        .may_ask_at(&who("o", "s"), KindId::Secret, "X", t0(), &AuditOnly)
        .is_err());
}

/// Review I2: a missing check file is rebuilt when the files prove the key.
#[test]
fn a_missing_key_check_is_rebuilt_when_the_files_verify() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let g = add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    s.save(t0()).unwrap();
    drop(s);
    std::fs::remove_file(d.path().join("store.key.check")).unwrap();
    let mut s = open(d.path());
    assert_eq!(s.untrusted, None);
    assert!(s.revoke_at(&g, t0()).unwrap());
    s.save(t0()).unwrap();
    assert!(d.path().join("store.key.check").exists());
}

/// Review I2, the other half: a missing check file is NOT rebuilt under a
/// key the files do not verify under - that key would quarantine the real
/// files and anchor itself.
#[test]
fn a_missing_key_check_is_not_rebuilt_under_the_wrong_key() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    s.save(t0()).unwrap();
    drop(s);
    std::fs::remove_file(d.path().join("store.key.check")).unwrap();
    let wrong = Store::open(d.path(), &Xor(9), None).unwrap();
    assert!(
        matches!(wrong.untrusted, Some(Untrusted::Key(_))),
        "{:?}",
        wrong.untrusted
    );
    drop(wrong);
    assert!(!d.path().join("store.key.check").exists());
    let s = open(d.path());
    assert_eq!(s.untrusted, None, "the real files were touched");
    assert_eq!(s.grants.len(), 1);
}

/// Files that verify but that no save in the audit log recorded (the log
/// was deleted, or the files were copied in) are not trusted.
#[test]
fn files_no_save_recorded_are_not_trusted() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    s.save(t0()).unwrap();
    drop(s);
    std::fs::remove_file(d.path().join("audit.jsonl")).unwrap();
    std::fs::remove_file(d.path().join("head.copy")).unwrap();
    let s = open(d.path());
    match &s.untrusted {
        Some(Untrusted::Files(why)) => assert!(why.contains("no save recorded"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(s
        .find_at(KindId::Secret, "DB", &who("o", "s"), t0())
        .is_none());
}

/// The MAC covers the sequence number: an edited header fails its
/// signature (and is quarantined), not just the hash check.
#[test]
fn an_edited_sequence_number_fails_the_signature() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    s.save(t0()).unwrap();
    s.save(t0()).unwrap();
    drop(s);
    let p = d.path().join("grants.json");
    let text = std::fs::read_to_string(&p).unwrap();
    assert_eq!(text.matches("{\"seq\":2,").count(), 1, "{text}");
    std::fs::write(&p, text.replace("{\"seq\":2,", "{\"seq\":9,")).unwrap();
    let s = open(d.path());
    match &s.untrusted {
        Some(Untrusted::Files(why)) => assert!(why.contains("failed its signature"), "{why}"),
        other => panic!("{other:?}"),
    }
}

/// Review M2: only a key that does not exist is created; a read-only open
/// never creates a store.
#[test]
fn a_read_only_open_never_creates_a_store() {
    let d = tempdir().unwrap();
    let dir = d.path().join("none");
    assert!(Store::open_existing(&dir, &Xor(7), None).unwrap().is_none());
    assert!(!dir.exists());
}

// -- the gate (audit row 1) ---------------------------------------------------

#[test]
fn after_a_denial_the_same_role_and_subject_cool_down() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    prompt(d.path(), &a, "DB", "denied", t0()).unwrap();
    let mut s = open(d.path());
    let restarted = who("o", "s2");
    assert!(
        s.may_ask_at(&restarted, KindId::Secret, " db ", mins(9), &AuditOnly)
            .is_err(),
        "restart or case reset it"
    );
    assert!(s
        .may_ask_at(&a, KindId::Secret, "OTHER", mins(1), &AuditOnly)
        .is_ok());
    assert!(s
        .may_ask_at(&who("fuel", "x"), KindId::Secret, "DB", mins(1), &AuditOnly)
        .is_ok());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "DB", t0() + DENIAL_COOLDOWN, &AuditOnly)
        .is_ok());
}

#[test]
fn a_timeout_cools_down_too_but_an_approval_does_not() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    prompt(d.path(), &a, "X", "timed-out", t0()).unwrap();
    prompt(d.path(), &a, "Y", "approved", t0()).unwrap();
    let mut s = open(d.path());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "X", mins(1), &AuditOnly)
        .is_err());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "Y", mins(1), &AuditOnly)
        .is_ok());
}

/// Review C3: a pending prompt counts, so parallel asks cannot overrun.
#[test]
fn pending_prompts_count_toward_the_cap() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s1");
    for i in 0..PROMPTS_PER_HOUR {
        s.may_ask_at(&a, KindId::Secret, &format!("S{i}"), t0(), &AuditOnly)
            .unwrap();
    }
    assert!(s
        .may_ask_at(&a, KindId::Secret, "NEW", t0(), &AuditOnly)
        .is_err());
}

#[test]
fn a_role_is_capped_per_rolling_hour_and_alerted_once() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s1");
    for i in 0..PROMPTS_PER_HOUR {
        s.may_ask_at(
            &a,
            KindId::Secret,
            &format!("S{i}"),
            mins(i as i64),
            &AuditOnly,
        )
        .unwrap();
    }
    let alerts = Alerts::default();
    for m in 30..35 {
        assert!(s
            .may_ask_at(&a, KindId::Secret, "NEW", mins(m), &alerts)
            .is_err());
    }
    assert_eq!(
        alerts.0.borrow().len(),
        1,
        "review M1: one alert, not one per refusal"
    );
    assert!(s
        .may_ask_at(
            &who("fuel", "x"),
            KindId::Secret,
            "NEW",
            mins(30),
            &AuditOnly
        )
        .is_ok());
    assert!(
        s.may_ask_at(&a, KindId::Secret, "NEW", mins(60), &AuditOnly)
            .is_ok(),
        "the first one aged out"
    );
}

/// Review I9: the cap protects a person, not just each role.
#[test]
fn the_person_is_capped_across_every_role() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    for i in 0..PROMPTS_PER_HOUR_FOR_THE_PERSON {
        s.may_ask_at(
            &who(&format!("lane{i}"), "s"),
            KindId::Secret,
            "S",
            t0(),
            &AuditOnly,
        )
        .unwrap();
    }
    assert!(s
        .may_ask_at(&who("fresh", "s"), KindId::Secret, "S", t0(), &AuditOnly)
        .is_err());
}

#[test]
fn repeated_refusals_alert_once_within_the_hour() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s1");
    let alerts = Alerts::default();
    for i in 0..DENIALS_BEFORE_ALERT + 1 {
        let r = s
            .may_ask_at(
                &a,
                KindId::Secret,
                &format!("S{i}"),
                mins(i as i64),
                &AuditOnly,
            )
            .unwrap();
        s.resolve_at(&r, &Outcome::Denied, mins(i as i64), &alerts)
            .unwrap();
        let want = usize::from(i + 1 >= DENIALS_BEFORE_ALERT);
        assert_eq!(alerts.0.borrow().len(), want, "after {} refusals", i + 1);
    }
}

/// Once the first alert's hour has passed, refusals still piling up alert
/// again, even past the threshold (4 in the window, not exactly 3).
#[test]
fn a_role_still_being_refused_is_alerted_again_an_hour_later() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s1");
    let alerts = Alerts::default();
    for (i, m) in [0, 1, 2, 30, 40, 50, 63].into_iter().enumerate() {
        let r = s
            .may_ask_at(&a, KindId::Secret, &format!("S{i}"), mins(m), &AuditOnly)
            .unwrap();
        s.resolve_at(&r, &Outcome::Denied, mins(m), &alerts)
            .unwrap();
    }
    // at minute 63 the window holds 30, 40, 50 and 63: four refusals
    assert_eq!(alerts.0.borrow().len(), 2, "{:?}", alerts.0.borrow());
}

#[test]
fn refusals_older_than_an_hour_do_not_count_toward_the_alert() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = who("o", "s1");
    let alerts = Alerts::default();
    for (i, m) in [0, 1, 70].into_iter().enumerate() {
        let r = s
            .may_ask_at(&a, KindId::Secret, &format!("S{i}"), mins(m), &AuditOnly)
            .unwrap();
        s.resolve_at(&r, &Outcome::Denied, mins(m), &alerts)
            .unwrap();
    }
    assert!(alerts.0.borrow().is_empty());
}

/// Review I7: every gate decision and alert is in the audit log.
#[test]
fn gate_decisions_and_alerts_are_audited() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    prompt(d.path(), &a, "DB", "denied", t0()).unwrap();
    let mut s = open(d.path());
    let _ = s.may_ask_at(&a, KindId::Secret, "DB", mins(1), &AuditOnly);
    for i in 0..3 {
        let r = s
            .may_ask_at(&a, KindId::Secret, &format!("Z{i}"), mins(2), &AuditOnly)
            .unwrap();
        s.resolve_at(&r, &Outcome::Denied, mins(2), &AuditOnly)
            .unwrap();
    }
    let log = audit_text(d.path());
    for want in [
        "\"gate-allowed\"",
        "\"gate-refused\"",
        "outcome=denied",
        "\"ALERT\"",
    ] {
        assert!(log.contains(want), "{want} missing from:\n{log}");
    }
}

// -- concurrency (review C2, C3, I1, I5) ---------------------------------------

#[test]
fn parallel_writers_lose_nothing_and_the_chain_holds() {
    let d = tempdir().unwrap();
    drop(open(d.path()));
    let dir = d.path().to_path_buf();
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let dir = dir.clone();
            std::thread::spawn(move || {
                prompt(&dir, &who(&format!("lane{i}"), "s"), "S", "approved", t0())
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap().unwrap();
    }
    let s = open(&dir);
    assert_eq!(s.untrusted, None);
    assert_eq!(
        s.attempts
            .iter()
            .filter(|a| a.outcome == Ended::Approved)
            .count(),
        8
    );
    assert!(s.verify_audit().is_ok(), "{:?}", s.verify_audit());
}

#[test]
fn parallel_first_opens_agree_on_one_key() {
    let d = tempdir().unwrap();
    let dir = d.path().join("new");
    let threads: Vec<_> = (0..6)
        .map(|_| {
            let dir = dir.clone();
            std::thread::spawn(move || {
                let mut s = Store::open(&dir, &Xor(7), Some(dir.join("head.copy"))).unwrap();
                assert_eq!(s.untrusted, None);
                add(
                    &mut s,
                    approval(KindId::Secret, "S", &who("o", "s"), Some(mins(60))),
                );
                s.save(t0()).unwrap();
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let s = open(&dir);
    assert_eq!(s.untrusted, None);
    assert_eq!(s.grants.len(), 6);
}

// -- the audit chain (row 13, PM condition (d)) -------------------------------

fn three_events(d: &Path) -> Store {
    let mut s = open(d);
    for (i, e) in ["granted", "denied", "revoked"].iter().enumerate() {
        s.audit(mins(i as i64), e, &format!("detail {i}")).unwrap();
    }
    s
}

#[test]
fn an_intact_chain_verifies_and_a_fresh_store_has_nothing_to_report() {
    let d = tempdir().unwrap();
    assert_eq!(open(d.path()).verify_audit().map(|r| r.lines), Ok(0));
    let e = tempdir().unwrap();
    assert_eq!(
        three_events(e.path()).verify_audit().map(|r| r.lines),
        Ok(3)
    );
}

#[test]
fn an_edited_line_breaks_the_chain() {
    let d = tempdir().unwrap();
    let s = three_events(d.path());
    let p = d.path().join("audit.jsonl");
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("detail 1", "detail X");
    std::fs::write(&p, text).unwrap();
    assert!(s.verify_audit().unwrap_err().contains("line 3"));
}

/// Review C1: truncation, deletion and a torn line stay visible after the
/// next append.
#[test]
fn a_truncated_deleted_or_torn_log_stays_visible_after_the_next_append() {
    for damage in ["truncate", "delete", "tear", "newline"] {
        let d = tempdir().unwrap();
        let mut s = three_events(d.path());
        let p = d.path().join("audit.jsonl");
        let text = std::fs::read_to_string(&p).unwrap();
        match damage {
            "truncate" => {
                std::fs::write(&p, text.lines().next().unwrap().to_string() + "\n").unwrap()
            }
            "delete" => std::fs::remove_file(&p).unwrap(),
            // the last line whole but its newline lost: the next line must
            // not be glued onto it
            "newline" => std::fs::write(&p, &text[..text.len() - 1]).unwrap(),
            _ => std::fs::write(&p, &text[..text.len() - 10]).unwrap(),
        }
        s.audit(mins(9), "revoked", "after the damage").unwrap();
        let err = s.verify_audit().unwrap_err();
        assert!(err.contains("reset"), "{damage}: {err}");
        // and the chain keeps working
        s.audit(mins(10), "granted", "later").unwrap();
        assert!(s.verify_audit().unwrap_err().contains("reset"), "{damage}");
    }
}

#[test]
fn a_missing_head_copy_is_reported() {
    let d = tempdir().unwrap();
    let s = three_events(d.path());
    std::fs::remove_file(d.path().join("head.copy")).unwrap();
    assert!(s.verify_audit().unwrap_err().contains("head copy"));
}

#[test]
fn every_save_is_anchored_in_the_chain() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    s.save(t0()).unwrap();
    s.save(t0()).unwrap();
    assert_eq!(audit_text(d.path()).matches("\"saved\"").count(), 2);
    assert!(s.verify_audit().is_ok());
}

// -- round 2 (the review of 5e67bcc) -------------------------------------------

fn snapshot(d: &Path) -> Vec<(&'static str, Vec<u8>)> {
    DATA_FILES
        .iter()
        .map(|n| (*n, std::fs::read(d.join(n)).unwrap()))
        .collect()
}

fn put_back(d: &Path, snap: &[(&'static str, Vec<u8>)]) {
    for (n, b) in snap {
        std::fs::write(d.join(n), b).unwrap();
    }
}

/// Review C-A: putting back a copy of the whole directory (files and log
/// together) is caught by the head copy, and stays caught after a save.
#[test]
fn a_whole_directory_rollback_is_untrusted() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let g = add(
        &mut s,
        approval(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("pm", "s"),
            None,
        ),
    );
    drop(s);
    let old = snapshot(d.path());
    let mut s = open(d.path());
    s.revoke_at(&g, t0()).unwrap();
    drop(s);
    prompt(d.path(), &who("o", "s"), "DB", "denied", t0()).unwrap();
    put_back(d.path(), &old);
    let mut s = open(d.path());
    assert!(
        matches!(s.untrusted, Some(Untrusted::Files(_))),
        "{:?}",
        s.untrusted
    );
    assert!(s
        .find_at(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("x", "y"),
            t0()
        )
        .is_none());
    assert!(s
        .may_ask_at(&who("o", "s"), KindId::Secret, "DB", mins(1), &AuditOnly)
        .is_err());
    drop(s);
    assert!(open(d.path()).untrusted.is_some(), "a save laundered it");
}

/// Review C-A: deleting the data files (the gate's memory) is caught.
#[test]
fn wiping_the_data_files_is_untrusted() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    prompt(d.path(), &a, "DB", "denied", t0()).unwrap();
    for n in DATA_FILES {
        std::fs::remove_file(d.path().join(n)).unwrap();
    }
    let mut s = open(d.path());
    assert!(s.untrusted.is_some());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "DB", mins(1), &AuditOnly)
        .is_err());
}

/// Review C-B: a rolled-back grants file is not laundered by an unrelated
/// revocation, and a repair revokes what it brought back.
#[test]
fn a_rolled_back_grant_is_not_laundered_by_a_later_revoke() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let a = add(
        &mut s,
        approval(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("pm", "s"),
            None,
        ),
    );
    let b = add(
        &mut s,
        approval(
            KindId::LaneDialogBypass,
            &lane_subject("other"),
            &who("pm", "s"),
            None,
        ),
    );
    drop(s);
    let old = std::fs::read(d.path().join("grants.json")).unwrap();
    let mut s = open(d.path());
    assert!(s.revoke_at(&a, t0()).unwrap());
    drop(s);
    std::fs::write(d.path().join("grants.json"), old).unwrap();
    let mut s = open(d.path());
    assert!(s.revoke_at(&b, t0()).unwrap());
    drop(s);
    let mut s = open(d.path());
    assert!(s.untrusted.is_some(), "the revoke re-anchored the rollback");
    assert!(s
        .find_at(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("x", "y"),
            t0()
        )
        .is_none());
    s.repair_at(t0(), &Xor(7)).unwrap();
    assert!(s
        .find_at(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("x", "y"),
            t0()
        )
        .is_none());
}

/// Review C-B, I3: deleting the attempts file and then saving does not
/// reset the gate.
#[test]
fn a_deleted_attempts_file_stays_untrusted_after_a_save() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    prompt(d.path(), &a, "DB", "denied", t0()).unwrap();
    std::fs::remove_file(d.path().join("attempts.json")).unwrap();
    let mut s = open(d.path());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "OTHER", mins(1), &AuditOnly)
        .is_err());
    s.save(mins(1)).unwrap();
    drop(s);
    let mut s = open(d.path());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "DB", mins(2), &AuditOnly)
        .is_err());
}

/// Review I-C: an attempt ends once; a second answer cannot erase a denial.
#[test]
fn an_attempt_is_resolved_once() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    let mut s = open(d.path());
    let r = s
        .may_ask_at(&a, KindId::Secret, "DB", t0(), &AuditOnly)
        .unwrap();
    s.resolve_at(&r, &Outcome::Denied, t0(), &AuditOnly)
        .unwrap();
    let again = s.resolve_at(&r, &answer("approved", &a, "DB"), t0(), &AuditOnly);
    assert!(again.unwrap_err().contains("already ended"));
    assert!(s
        .may_ask_at(&a, KindId::Secret, "DB", mins(1), &AuditOnly)
        .is_err());
    assert!(s
        .resolve_at(
            &Reservation {
                attempt_id: "nope".into()
            },
            &Outcome::Denied,
            t0(),
            &AuditOnly
        )
        .is_err());
}

/// An approval is stored as a grant in the same step, and must be for what
/// was reserved.
#[test]
fn an_approval_must_match_its_reservation_and_becomes_a_grant() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    let mut s = open(d.path());
    let r = s
        .may_ask_at(&a, KindId::Secret, " DB ", t0(), &AuditOnly)
        .unwrap();
    for wrong in [
        answer("approved", &a, "PROD"),
        answer("approved", &who("other", "s1"), "DB"),
    ] {
        assert!(s.resolve_at(&r, &wrong, t0(), &AuditOnly).is_err());
    }
    let id = s
        .resolve_at(&r, &answer("approved", &a, "db"), t0(), &AuditOnly)
        .unwrap()
        .unwrap();
    drop(s);
    let s = open(d.path());
    assert_eq!(
        s.find_at(KindId::Secret, "db", &a, t0())
            .map(|g| g.id.clone()),
        Some(id)
    );
    assert_eq!(s.attempts[0].outcome, Ended::Approved);
}

/// Review I-B: the gate's memory does not depend on the caller saving.
#[test]
fn the_gate_remembers_without_the_caller_saving() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    {
        let mut s = open(d.path());
        s.may_ask_at(&a, KindId::Secret, "X", t0(), &AuditOnly)
            .unwrap();
    }
    assert_eq!(open(d.path()).attempts.len(), 1, "the reservation was lost");
    for i in 1..PROMPTS_PER_HOUR {
        prompt(d.path(), &a, &format!("S{i}"), "approved", t0()).unwrap();
    }
    let alerts = Alerts::default();
    for _ in 0..3 {
        let mut s = open(d.path());
        assert!(s
            .may_ask_at(&a, KindId::Secret, "Z", mins(1), &alerts)
            .is_err());
    }
    assert_eq!(alerts.0.borrow().len(), 1, "one alert across three opens");
}

/// Review I-F: a lost key is not a fresh install.
#[test]
fn a_lost_key_is_not_a_fresh_install() {
    let d = tempdir().unwrap();
    let a = who("o", "s1");
    let mut s = open(d.path());
    let g = add(&mut s, approval(KindId::Secret, "DB", &a, Some(mins(60))));
    drop(s);
    prompt(d.path(), &a, "DB2", "denied", t0()).unwrap();
    std::fs::remove_file(d.path().join("store.key")).unwrap();
    let head = Some(d.path().join("head.copy"));
    let s = Store::open_existing(d.path(), &Xor(7), head).unwrap();
    assert!(matches!(
        s.as_ref().map(|s| &s.untrusted),
        Some(Some(Untrusted::Key(_)))
    ));
    drop(s);
    let mut s = open(d.path());
    assert!(matches!(s.untrusted, Some(Untrusted::Key(_))));
    assert!(!d.path().join("store.key").exists(), "a key was made");
    assert!(s.revoke_at(&g, t0()).is_err());
    assert!(s
        .may_ask_at(&a, KindId::Secret, "DB2", mins(1), &AuditOnly)
        .is_err());
}

/// A repair after a lost key starts a new key, sets the old files aside
/// and closes the gate.
#[test]
fn a_repair_after_a_lost_key_starts_over_with_the_gate_closed() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    std::fs::remove_file(d.path().join("store.key")).unwrap();
    let mut s = open(d.path());
    s.repair_at(t0(), &Xor(7)).unwrap();
    drop(s);
    let mut s = open(d.path());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    assert!(s.grants.is_empty());
    assert!(std::fs::read_dir(d.path()).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("rejected")));
    assert!(s
        .may_ask_at(&who("o", "s"), KindId::Secret, "X", mins(59), &AuditOnly)
        .unwrap_err()
        .contains("repaired"));
    assert!(s
        .may_ask_at(&who("o", "s"), KindId::Secret, "X", mins(60), &AuditOnly)
        .is_ok());
}

/// A repair is recorded, and `audit verify` counts the resets it
/// acknowledged instead of failing forever (review M-f).
#[test]
fn a_repair_acknowledges_earlier_chain_resets() {
    let d = tempdir().unwrap();
    let s = three_events(d.path());
    drop(s);
    std::fs::remove_file(d.path().join("audit.jsonl")).unwrap();
    let mut s = open(d.path());
    assert!(s.untrusted.is_some());
    assert!(s.verify_audit().unwrap_err().contains("reset"));
    s.repair_at(t0(), &Xor(7)).unwrap();
    let report = s.verify_audit().unwrap();
    assert_eq!(report.repaired_resets, 1);
    assert!(audit_text(d.path()).contains("\"repaired\""));
    drop(s);
    assert_eq!(open(d.path()).untrusted, None);
}

/// Review I-A: the lock is the OS's, held for the store's lifetime however
/// old its file looks, and never removed from under another holder.
#[test]
fn the_lock_is_held_for_the_stores_lifetime() {
    let d = tempdir().unwrap();
    let first = open(d.path());
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(d.path().join("store.lock"))
        .unwrap();
    f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
    drop(f);
    let dir = d.path().to_path_buf();
    let second = std::thread::spawn(move || {
        let s = open(&dir);
        drop(s);
        Instant::now()
    });
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(
        !second.is_finished(),
        "a second store opened beside the first"
    );
    let released = Instant::now();
    drop(first);
    assert!(second.join().unwrap() >= released);
}

/// Review I-H: a signed body that does not parse is set aside; open still
/// works and so does revoking.
#[test]
fn a_body_that_does_not_parse_is_set_aside() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "DB", &who("o", "s"), Some(mins(60))),
    );
    let key = s.key.clone();
    drop(s);
    let body = br#"{"grants":[{"id":"x","approval":{"kind":"FutureKind"}}],"revoked":[]}"#;
    write_signed(&d.path().join("grants.json"), &key, 99, body).unwrap();
    let mut s = open(d.path());
    match &s.untrusted {
        Some(Untrusted::Files(why)) => assert!(why.contains("did not parse"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.revoke_all_at(t0()).unwrap(), 0);
}

/// Review I-D: a head copy whose folder does not exist is created; one that
/// cannot be written never blocks a revocation.
#[test]
fn the_head_copy_never_blocks_a_revocation() {
    let d = tempdir().unwrap();
    let nested = d.path().join("lane-state").join("head");
    let mut s = Store::open(d.path(), &Xor(7), Some(nested.clone())).unwrap();
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    assert!(nested.exists());
    drop(s);
    let e = tempdir().unwrap();
    let mut s = open(e.path());
    let g = add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    // a head copy that cannot be read (here: a folder) decides nothing: the
    // open asks for a retry (review 4, I-A)
    let blocked = e.path().join("a-folder");
    std::fs::create_dir(&blocked).unwrap();
    let before = audit_text(e.path());
    let err = Store::open(e.path(), &Xor(7), Some(blocked)).err().unwrap();
    assert!(err.contains("try again"), "{err}");
    assert_eq!(audit_text(e.path()), before);
    assert!(
        open(e.path())
            .find_at(KindId::Secret, "A", &who("o", "s"), t0())
            .is_some(),
        "{g}"
    );
}

/// Review I-G: grants and revocations are audited by the store itself.
#[test]
fn grants_and_revocations_are_audited() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let g = add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    s.revoke_at(&g, t0()).unwrap();
    s.revoke_all_at(t0()).unwrap();
    let log = audit_text(d.path());
    for want in [
        format!("\"granted\",\"detail\":\"id={g} "),
        format!("\"revoked\",\"detail\":\"id={g}\""),
        "\"revoked-all\",\"detail\":\"n=0".to_string(),
    ] {
        assert!(log.contains(&want), "{want} missing from:\n{log}");
    }
}

#[test]
fn an_untrustworthy_store_takes_no_new_grants() {
    let d = tempdir().unwrap();
    drop(open(d.path()));
    std::fs::write(d.path().join("attempts.json"), "junk").unwrap();
    let mut s = open(d.path());
    assert!(s
        .add(
            approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
            t0()
        )
        .is_err());
    assert!(s.grants.is_empty());
}

/// Review M-a: a change that was audited but did not save says so.
#[test]
fn a_failed_save_is_audited() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    std::fs::remove_file(d.path().join("grants.json")).unwrap();
    std::fs::create_dir(d.path().join("grants.json")).unwrap();
    assert!(s.revoke_all_at(t0()).is_err());
    let log = audit_text(d.path());
    let (revoked, failed) = (log.find("\"revoked-all\""), log.find("\"save-failed\""));
    assert!(revoked.is_some() && failed > revoked, "{log}");
}

// -- round 3 (the review of d27837a) -------------------------------------------

/// A reservation for `subject`, as a lane would make it.
fn reserve(s: &mut Store, r: &Requester, subject: &str, at: DateTime<Utc>) -> Reservation {
    s.may_ask_at(r, KindId::Secret, subject, at, &AuditOnly)
        .unwrap()
}

/// Review 3, C1: a repair whose save fails restores nothing; the grants
/// stay unhonoured and the store stays untrusted.
#[test]
fn a_repair_whose_save_fails_leaves_the_store_untrusted() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("pm", "s"),
            None,
        ),
    );
    drop(s);
    std::fs::remove_file(d.path().join("head.copy")).unwrap();
    let mut s = open(d.path());
    assert!(s.untrusted.is_some());
    let g = d.path().join("grants.json");
    let saved = std::fs::read(&g).unwrap();
    std::fs::remove_file(&g).unwrap();
    std::fs::create_dir(&g).unwrap();
    assert!(s.repair_at(t0(), &Xor(7)).is_err());
    assert!(s.untrusted.is_some(), "a failed repair cleared the flag");
    drop(s);
    std::fs::remove_dir(&g).unwrap();
    std::fs::write(&g, saved).unwrap();
    let s = open(d.path());
    assert!(s.untrusted.is_some(), "{:?}", s.verify_audit());
    assert!(s
        .find_at(
            KindId::LaneDialogBypass,
            &lane_subject("trust"),
            &who("x", "y"),
            t0()
        )
        .is_none());
}

/// Review 3, I2: a save cut short between the two files is still
/// recognised as ours, so a crash or a held file does not cost the grants.
#[test]
fn a_save_cut_short_between_the_files_is_still_ours() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let g = add(&mut s, approval(KindId::Secret, "A", &a, Some(mins(60))));
    let p = d.path().join("grants.json");
    let old_grants = std::fs::read(&p).unwrap();
    std::fs::remove_file(&p).unwrap();
    std::fs::create_dir(&p).unwrap();
    // attempts.json is written, grants.json cannot be
    assert!(s.revoke_at(&g, t0()).is_err());
    drop(s);
    std::fs::remove_dir(&p).unwrap();
    std::fs::write(&p, old_grants).unwrap();
    let s = open(d.path());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    // the caller was told it failed, and it did
    assert!(!s.revoked.contains(&g));
}

/// Review 3, I3: a repair or `revoke_all` ends every pending reservation,
/// so an approval still in flight never becomes a grant.
#[test]
fn repair_and_revoke_all_end_pending_reservations() {
    let a = who("o", "s");
    for how in ["repair", "revoke-all"] {
        let d = tempdir().unwrap();
        let mut s = open(d.path());
        let r = reserve(&mut s, &a, "DB", t0());
        match how {
            "repair" => {
                s.repair_at(t0(), &Xor(7)).unwrap();
            }
            _ => {
                s.revoke_all_at(t0()).unwrap();
            }
        }
        let late = s.resolve_at(&r, &answer("approved", &a, "DB"), mins(1), &AuditOnly);
        assert!(late.unwrap_err().contains("already ended"), "{how}");
        assert!(s.active_at(mins(1)).is_empty(), "{how}");
    }
}

/// Review 3, I3: no channel waits longer than the reservation lives.
#[test]
fn an_old_reservation_cannot_be_resolved() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = reserve(&mut s, &a, "DB", t0());
    let at = t0() + RESERVATION_TTL;
    let late = s.resolve_at(&r, &answer("approved", &a, "DB"), at, &AuditOnly);
    assert!(late.unwrap_err().contains("minutes ago"));
    let r = reserve(&mut s, &a, "DB2", t0());
    let just = t0() + RESERVATION_TTL - Duration::seconds(1);
    assert!(s
        .resolve_at(&r, &answer("approved", &a, "DB2"), just, &AuditOnly)
        .unwrap()
        .is_some());
}

/// Review 3, I4: an approval longer than its kind allows never becomes a
/// grant, even when the channel returned it.
#[test]
fn an_approval_longer_than_its_kind_allows_is_refused() {
    // a secret may be any finite length, never forever (PM ruling on #115
    // M4); nor may any approval end before it is given
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = reserve(&mut s, &a, "DB", t0());
    let forever = Outcome::Approved(approval(KindId::Secret, "DB", &a, None));
    assert!(s.resolve_at(&r, &forever, t0(), &AuditOnly).is_err());
    let ended = Outcome::Approved(approval(KindId::Secret, "DB", &a, Some(t0())));
    assert!(s.resolve_at(&r, &ended, t0(), &AuditOnly).is_err());
    assert!(s.grants.is_empty());
    // and the attempt is still pending: a valid answer can still land, and a
    // long one is a valid answer now (board 134)
    let month = Outcome::Approved(approval(
        KindId::Secret,
        "DB",
        &a,
        Some(t0() + Duration::days(30)),
    ));
    assert!(s
        .resolve_at(&r, &month, t0(), &AuditOnly)
        .unwrap()
        .is_some());
}

/// Review 3, I5: a chain found broken mid-session untrusts the store at
/// once, not only from the next open.
#[test]
fn a_chain_reset_mid_session_untrusts_at_once() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    add(&mut s, approval(KindId::Secret, "DB", &a, Some(mins(60))));
    std::fs::remove_file(d.path().join("head.copy")).unwrap();
    assert!(s
        .may_ask_at(&a, KindId::Secret, "X", t0(), &AuditOnly)
        .is_err());
    assert!(matches!(s.untrusted, Some(Untrusted::Files(_))));
    assert!(s.find_at(KindId::Secret, "DB", &a, t0()).is_none());
}

/// Review 3, I2: an untrusted store disables everything, so the gate
/// alerts, once per role per hour.
#[test]
fn an_untrusted_store_alerts_once() {
    let d = tempdir().unwrap();
    drop(open(d.path()));
    std::fs::write(d.path().join("attempts.json"), "junk").unwrap();
    let alerts = Alerts::default();
    for m in 0..3 {
        let mut s = open(d.path());
        assert!(s
            .may_ask_at(&who("o", "s"), KindId::Secret, "X", mins(m), &alerts)
            .is_err());
    }
    assert_eq!(alerts.0.borrow().len(), 1, "{:?}", alerts.0.borrow());
    assert!(audit_text(d.path()).contains("became untrustworthy"));
}

/// Review 3, M1: a repair says when it could not count the grants.
#[test]
fn a_repair_says_when_the_grants_were_unknown() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    std::fs::remove_file(d.path().join("store.key")).unwrap();
    let mut s = open(d.path());
    let r = s.repair_at(t0(), &Xor(7)).unwrap();
    assert!(!r.grants_known);
    assert!(r.set_aside.iter().any(|f| f.contains("grants")), "{r:?}");
    let e = tempdir().unwrap();
    let mut s = open(e.path());
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    let r = s.repair_at(t0(), &Xor(7)).unwrap();
    assert!(r.grants_known && r.revoked == 1, "{r:?}");
}

/// Review 3, M4: looking never writes, moves or records anything.
#[test]
fn inspect_writes_nothing() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    let p = d.path().join("grants.json");
    let tampered = std::fs::read_to_string(&p)
        .unwrap()
        .replace("\"A\"", "\"B\"");
    std::fs::write(&p, &tampered).unwrap();
    std::fs::remove_file(d.path().join("store.key.check")).unwrap();
    let before = audit_text(d.path());
    let head = Some(d.path().join("head.copy"));
    let mut s = Store::inspect(d.path(), &Xor(7), head).unwrap().unwrap();
    assert!(s.untrusted.is_some());
    assert!(!s.grants_known());
    assert!(s.revoke_all_at(t0()).is_err(), "a read-only store changed");
    drop(s);
    assert_eq!(audit_text(d.path()), before);
    assert_eq!(std::fs::read_to_string(&p).unwrap(), tampered);
    assert!(!d.path().join("store.key.check").exists());
}

/// Review 3, I1: on Windows the lock file cannot be deleted while it is
/// held, so no second holder can appear beside the first.
#[cfg(windows)]
#[test]
fn the_lock_file_cannot_be_deleted_while_held() {
    let d = tempdir().unwrap();
    let s = open(d.path());
    assert!(std::fs::remove_file(d.path().join("store.lock")).is_err());
    drop(s);
    assert!(std::fs::remove_file(d.path().join("store.lock")).is_ok());
}

/// Holds `path` open with no sharing (an antivirus scan) for `ms`.
#[cfg(windows)]
fn hold(path: PathBuf, ms: u64) -> std::thread::JoinHandle<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(ms));
        drop(f);
    })
}

/// Review 3, I2: a file held for a moment is retried; one held longer
/// fails the open and records nothing, and the store is trusted after.
#[cfg(windows)]
#[test]
fn a_held_file_is_retried_and_never_recorded_as_damage() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    let g = d.path().join("grants.json");
    let t = hold(g.clone(), 300);
    assert_eq!(open(d.path()).untrusted, None, "a brief hold was damage");
    t.join().unwrap();
    let before = audit_text(d.path());
    let t = hold(g, (RETRY_FOR.as_millis() + 1500) as u64);
    let err = Store::open(d.path(), &Xor(7), Some(d.path().join("head.copy")))
        .err()
        .unwrap();
    assert!(err.contains("try again"), "{err}");
    t.join().unwrap();
    assert_eq!(audit_text(d.path()), before, "a held file was recorded");
    assert_eq!(open(d.path()).untrusted, None);
}

/// Review 3, I2: a save onto a file someone holds for a moment is retried.
#[cfg(windows)]
#[test]
fn a_save_onto_a_briefly_held_file_is_retried() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let g = add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    let t = hold(d.path().join("attempts.json"), 300);
    assert!(s.revoke_at(&g, t0()).unwrap());
    t.join().unwrap();
    drop(s);
    let s = open(d.path());
    assert_eq!(s.untrusted, None);
    assert!(s.revoked.contains(&g));
}

/// Review 3, I5: `find` checks the chain itself, so a lookup with no
/// change before it still sees a chain broken since `open`.
#[test]
fn find_alone_sees_a_chain_broken_since_open() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    add(&mut s, approval(KindId::Secret, "DB", &a, Some(mins(60))));
    assert!(s.find_at(KindId::Secret, "DB", &a, t0()).is_some());
    std::fs::remove_file(d.path().join("head.copy")).unwrap();
    assert!(s.find_at(KindId::Secret, "DB", &a, t0()).is_none());
}

/// Review 3, I5: the change that writes a chain reset untrusts the store
/// at once, though the chain checks clean again after the reset line.
#[test]
fn the_change_that_resets_the_chain_untrusts_the_store() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    add(&mut s, approval(KindId::Secret, "KEEP", &a, Some(mins(60))));
    let other = add(&mut s, approval(KindId::Secret, "GO", &a, Some(mins(60))));
    std::fs::remove_file(d.path().join("head.copy")).unwrap();
    assert!(s.revoke_at(&other, t0()).unwrap());
    assert!(matches!(s.untrusted, Some(Untrusted::Files(_))));
    assert!(s.find_at(KindId::Secret, "KEEP", &a, t0()).is_none());
}

/// Review 3, I2: a key check that cannot be read is not "missing": open
/// asks for a retry and decides nothing.
#[cfg(windows)]
#[test]
fn an_unreadable_key_check_fails_the_open_and_decides_nothing() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    let check = d.path().join("store.key.check");
    let before = std::fs::read(&check).unwrap();
    let t = hold(check.clone(), (RETRY_FOR.as_millis() + 1500) as u64);
    let err = Store::open(d.path(), &Xor(7), Some(d.path().join("head.copy")))
        .err()
        .unwrap();
    assert!(err.contains("try again"), "{err}");
    t.join().unwrap();
    assert_eq!(std::fs::read(&check).unwrap(), before);
    assert_eq!(open(d.path()).untrusted, None);
}

// -- round 4 (the review of d83648a) -------------------------------------------

/// Review 4, I-B: an approval's time must lie between its reservation and
/// now, so a future `approved_at` cannot stretch the kind's maximum.
#[test]
fn an_approval_dated_outside_its_reservation_is_refused() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = reserve(&mut s, &a, "DB", mins(10));
    for at in [
        mins(10) - Duration::seconds(1),
        mins(11) + Duration::days(30),
    ] {
        let mut ap = approval(KindId::Secret, "DB", &a, Some(at + Duration::minutes(30)));
        ap.approved_at = at;
        let err = s
            .resolve_at(&r, &Outcome::Approved(ap), mins(11), &AuditOnly)
            .unwrap_err();
        assert!(err.contains("outside its reservation"), "{err}");
    }
    assert!(s.grants.is_empty());
}

/// Review 4, I-B: the public API reads the clock itself; the real clock
/// is what a grant and every gate window are judged at.
#[test]
fn the_public_api_uses_the_real_clock() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = s.may_ask(&a, KindId::Secret, "DB", &AuditOnly).unwrap();
    let at = s.attempts.last().unwrap().at;
    assert!((Utc::now() - at).num_seconds().abs() < 60, "{at}");
    let mut ap = approval(KindId::Secret, "DB", &a, None);
    ap.approved_at = Utc::now();
    ap.expires_at = Some(ap.approved_at + Duration::minutes(1));
    let g = s
        .resolve(&r, &Outcome::Approved(ap), &AuditOnly)
        .unwrap()
        .unwrap();
    assert_eq!(
        s.find(KindId::Secret, "db", &a).map(|x| x.id.clone()),
        Some(g.clone())
    );
    assert_eq!(s.active().len(), 1);
    assert!(s.revoke(&g).unwrap());
    assert!(s.find(KindId::Secret, "db", &a).is_none());
    assert_eq!(s.revoke_all().unwrap(), 0);
    assert_eq!(s.repair(&Xor(7)).unwrap().revoked, 0);
    assert!(s
        .may_ask(&a, KindId::Secret, "X", &AuditOnly)
        .unwrap_err()
        .contains("repaired"));
}

/// Review 4, M-a: a resolve that fails leaves no grant behind, in memory or
/// for a later save to keep.
#[test]
fn a_failed_resolve_leaves_no_grant() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = reserve(&mut s, &a, "DB", t0());
    let p = d.path().join("attempts.json");
    let old = std::fs::read(&p).unwrap();
    std::fs::remove_file(&p).unwrap();
    std::fs::create_dir(&p).unwrap();
    assert!(s
        .resolve_at(&r, &answer("approved", &a, "DB"), t0(), &AuditOnly)
        .is_err());
    assert!(s.find_at(KindId::Secret, "db", &a, t0()).is_none());
    assert!(s.grants.is_empty());
    assert_eq!(s.attempts.last().unwrap().outcome, Ended::Pending);
    // the lane exits with nothing saved after the failure (review 5, I-1)
    drop(s);
    std::fs::remove_dir(&p).unwrap();
    std::fs::write(&p, old).unwrap();
    let s = open(d.path());
    assert!(s.grants.is_empty());
    assert!(s.find_at(KindId::Secret, "db", &a, t0()).is_none());
}

/// Review 5, I-1: when the grant cannot be written after its attempt was,
/// the lane is told it failed, no grant is honoured, and the reservation is
/// ended, so it cannot make a grant later.
#[test]
fn a_resolve_cut_short_before_the_grant_never_honours_it() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = reserve(&mut s, &a, "DB", t0());
    let p = d.path().join("grants.json");
    let old = std::fs::read(&p).unwrap();
    std::fs::remove_file(&p).unwrap();
    std::fs::create_dir(&p).unwrap();
    assert!(s
        .resolve_at(&r, &answer("approved", &a, "DB"), t0(), &AuditOnly)
        .is_err());
    drop(s);
    std::fs::remove_dir(&p).unwrap();
    std::fs::write(&p, old).unwrap();
    let mut s = open(d.path());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    assert!(s.find_at(KindId::Secret, "db", &a, t0()).is_none());
    let again = s.resolve_at(&r, &answer("approved", &a, "DB"), t0(), &AuditOnly);
    assert!(again.unwrap_err().contains("already ended"));
    assert!(s.grants.is_empty());
}

/// Review 4, I-A: a head copy held by a backup or sync tool fails the open
/// with "try again" and records nothing; after it is released the store is
/// trusted.
#[cfg(windows)]
#[test]
fn a_held_head_copy_is_never_recorded_as_damage() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    drop(s);
    let before = audit_text(d.path());
    let t = hold(
        d.path().join("head.copy"),
        (RETRY_FOR.as_millis() + 1500) as u64,
    );
    let err = Store::open(d.path(), &Xor(7), Some(d.path().join("head.copy")))
        .err()
        .unwrap();
    assert!(err.contains("try again"), "{err}");
    t.join().unwrap();
    assert_eq!(audit_text(d.path()), before);
    assert_eq!(open(d.path()).untrusted, None);
}

/// Review 4, M-d: a lock file another program holds open for a moment is
/// waited for, like another holder of the lock.
#[cfg(windows)]
#[test]
fn a_lock_file_held_by_another_program_is_waited_for() {
    let d = tempdir().unwrap();
    drop(open(d.path()));
    let t = hold(d.path().join("store.lock"), 300);
    assert!(Store::open(d.path(), &Xor(7), Some(d.path().join("head.copy"))).is_ok());
    t.join().unwrap();
}

/// Review 4, I-B: the public `find` judges expiry at the real clock.
#[test]
fn the_public_find_drops_a_grant_that_expired_in_real_time() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = s.may_ask(&a, KindId::Secret, "DB", &AuditOnly).unwrap();
    let mut ap = approval(KindId::Secret, "DB", &a, None);
    ap.approved_at = Utc::now();
    let end = ap.approved_at + Duration::seconds(1);
    ap.expires_at = Some(end);
    s.resolve(&r, &Outcome::Approved(ap), &AuditOnly).unwrap();
    // on a loaded machine the resolve itself can outlast the grant
    if Utc::now() < end - Duration::milliseconds(100) {
        assert!(s.find(KindId::Secret, "DB", &a).is_some());
    }
    while Utc::now() <= end + Duration::milliseconds(50) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(s.find(KindId::Secret, "DB", &a).is_none());
}

/// Review 4, M-a: an append onto a log someone holds against writing (it
/// can still be read) is retried.
#[cfg(windows)]
#[test]
fn an_append_onto_a_briefly_write_locked_log_is_retried() {
    use std::os::windows::fs::OpenOptionsExt;
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let g = add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    // FILE_SHARE_READ only: readers pass, writers wait
    let f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1)
        .open(d.path().join("audit.jsonl"))
        .unwrap();
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        drop(f);
    });
    assert!(s.revoke_at(&g, t0()).unwrap());
    t.join().unwrap();
}

// -- round 5 (the review of 75daefb) -------------------------------------------

/// Review 5, I-2: a head copy that failed to update lags the log and agrees
/// with it at its own line; that is not damage. Lagging further than
/// `HEAD_COPY_LAG`, or disagreeing, still is.
#[test]
fn a_head_copy_that_lags_a_little_is_not_damage() {
    let d = tempdir().unwrap();
    let mut s = three_events(d.path());
    let head = d.path().join("head.copy");
    let stale = std::fs::read(&head).unwrap();
    s.audit(mins(5), "granted", "after the copy failed")
        .unwrap();
    s.audit(mins(6), "granted", "and again").unwrap();
    drop(s);
    std::fs::write(&head, &stale).unwrap();
    assert_eq!(open(d.path()).untrusted, None);

    let e = tempdir().unwrap();
    let mut s = three_events(e.path());
    let head = e.path().join("head.copy");
    let stale = std::fs::read(&head).unwrap();
    for i in 0..=HEAD_COPY_LAG {
        s.audit(mins(10), "granted", &format!("line {i}")).unwrap();
    }
    drop(s);
    std::fs::write(&head, &stale).unwrap();
    assert!(
        open(e.path()).untrusted.is_some(),
        "a copy far behind passed"
    );

    let f = tempdir().unwrap();
    let mut s = three_events(f.path());
    s.audit(mins(5), "granted", "x").unwrap();
    drop(s);
    let head = f.path().join("head.copy");
    let text = std::fs::read_to_string(&head).unwrap();
    let (n, _) = text.trim().split_once(' ').unwrap();
    std::fs::write(
        &head,
        format!("{} {}\n", n.parse::<usize>().unwrap() - 1, "0".repeat(64)),
    )
    .unwrap();
    assert!(
        open(f.path()).untrusted.is_some(),
        "a copy that disagrees passed"
    );
}

/// Review 5, I-2: a head copy a backup tool holds against replacement (it
/// can still be read) during a write is caught up later, never damage.
#[cfg(windows)]
#[test]
fn a_head_copy_held_during_a_write_is_not_damage() {
    use std::os::windows::fs::OpenOptionsExt;
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let g = add(
        &mut s,
        approval(KindId::Secret, "A", &who("o", "s"), Some(mins(60))),
    );
    // FILE_SHARE_READ | FILE_SHARE_WRITE: readable, not replaceable
    let f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(d.path().join("head.copy"))
        .unwrap();
    let t = std::thread::spawn(move || {
        std::thread::sleep(RETRY_FOR + std::time::Duration::from_millis(1500));
        drop(f);
    });
    assert!(s.revoke_at(&g, t0()).unwrap());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    t.join().unwrap();
    drop(s);
    assert_eq!(open(d.path()).untrusted, None);
}

/// Review 5, M-3: subjects fold ASCII only, so no two distinct names fold
/// together.
#[test]
fn subjects_fold_ascii_only() {
    assert_eq!(normal_subject(" Db_Token "), "db_token");
    assert_ne!(normal_subject("\u{212A}_TOKEN"), normal_subject("k_token"));
}

/// Review 5, M-2: a reservation that could not be recorded is not kept.
#[test]
fn a_reservation_that_was_not_recorded_is_not_kept() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let p = d.path().join("attempts.json");
    std::fs::create_dir(&p).unwrap();
    assert!(s
        .may_ask_at(&a, KindId::Secret, "DB", t0(), &AuditOnly)
        .is_err());
    assert!(s.attempts.is_empty());
}

/// Review 5, M-4: a resolve that is undone keeps the alert it raised, so
/// the alert is not raised again.
#[test]
fn an_undone_resolve_keeps_its_alert() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    for i in 0..DENIALS_BEFORE_ALERT - 1 {
        let r = reserve(&mut s, &a, &format!("S{i}"), t0());
        s.resolve_at(&r, &Outcome::Denied, t0(), &AuditOnly)
            .unwrap();
    }
    let r = reserve(&mut s, &a, "LAST", t0());
    let p = d.path().join("grants.json");
    std::fs::remove_file(&p).unwrap();
    std::fs::create_dir(&p).unwrap();
    let alerts = Alerts::default();
    assert!(s.resolve_at(&r, &Outcome::Denied, t0(), &alerts).is_err());
    assert_eq!(alerts.0.borrow().len(), 1);
    assert!(s
        .attempts
        .iter()
        .any(|x| x.outcome == Ended::Alerted && x.requester.role == "o"));
}

// -- round 6 (the review of 18ea704) -------------------------------------------

/// Review 6, m-1: an approval given before a revocation cannot make a
/// grant for a later reservation.
#[test]
fn an_earlier_approval_cannot_bring_back_a_revoked_grant() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r1 = reserve(&mut s, &a, "DB", t0());
    let first = answer("approved", &a, "DB");
    let g = s
        .resolve_at(&r1, &first, t0(), &AuditOnly)
        .unwrap()
        .unwrap();
    s.revoke_at(&g, mins(1)).unwrap();
    let r2 = reserve(&mut s, &a, "DB", mins(1));
    assert!(s.resolve_at(&r2, &first, mins(1), &AuditOnly).is_err());
    assert!(s.find_at(KindId::Secret, "db", &a, mins(1)).is_none());
}

/// Review 6, m-3: a revocation lands even when the prompts file cannot be
/// written.
#[test]
fn a_revocation_lands_when_the_prompts_file_cannot_be_written() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let g = add(&mut s, approval(KindId::Secret, "A", &a, Some(mins(60))));
    let p = d.path().join("attempts.json");
    let old = std::fs::read(&p).unwrap();
    std::fs::remove_file(&p).unwrap();
    std::fs::create_dir(&p).unwrap();
    assert!(
        s.revoke_at(&g, t0()).is_err(),
        "the failure is still reported"
    );
    drop(s);
    std::fs::remove_dir(&p).unwrap();
    std::fs::write(&p, old).unwrap();
    let s = open(d.path());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    assert!(
        s.find_at(KindId::Secret, "A", &a, t0()).is_none(),
        "the revocation did not land"
    );
}

/// Review 6, m-4: once both files landed, a closing line that fails does
/// not make the caller believe the grant failed (and resolve it again).
#[test]
fn a_grant_that_landed_is_reported_as_landed() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = reserve(&mut s, &a, "DB", t0());
    fault::FAIL_SAVED_LINE.with(|f| f.set(true));
    let got = s.resolve_at(&r, &answer("approved", &a, "DB"), t0(), &AuditOnly);
    fault::FAIL_SAVED_LINE.with(|f| f.set(false));
    let g = got.unwrap().unwrap();
    assert!(audit_text(d.path()).contains("saved line: injected"));
    drop(s);
    let s = open(d.path());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    assert_eq!(
        s.find_at(KindId::Secret, "db", &a, t0())
            .map(|x| x.id.clone()),
        Some(g)
    );
}

// -- #2b: with-secret on the store ---------------------------------------------

/// #2b: `with-secret revoke NAME | --all` revokes one kind's grants (one
/// subject, or all of them) for every requester, as tombstones, and ends
/// the matching pending prompts so an approval in flight never lands.
/// Other kinds and subjects are untouched.
#[test]
fn revoke_matching_ends_one_kinds_grants_and_pending_prompts() {
    let d = tempdir().unwrap();
    let (a, b) = (who("o", "s"), who("fuel", "t"));
    let mut s = open(d.path());
    add(&mut s, approval(KindId::Secret, "DB", &a, Some(mins(60))));
    add(&mut s, approval(KindId::Secret, "db ", &b, Some(mins(60))));
    add(
        &mut s,
        approval(KindId::Secret, "OTHER", &a, Some(mins(60))),
    );
    let bypass = add(
        &mut s,
        approval(KindId::LaneDialogBypass, &lane_subject("DB"), &a, None),
    );
    let in_flight = reserve(&mut s, &a, "DB", t0());
    let other_flight = reserve(&mut s, &a, "OTHER", t0());
    assert_eq!(
        s.revoke_matching_at(KindId::Secret, Some("Db"), t0())
            .unwrap(),
        2
    );
    drop(s);
    let mut s = open(d.path());
    assert_eq!(s.untrusted, None, "{:?}", s.untrusted);
    assert!(s.find_at(KindId::Secret, "DB", &a, t0()).is_none());
    assert!(s.find_at(KindId::Secret, "DB", &b, t0()).is_none());
    assert!(s.find_at(KindId::Secret, "OTHER", &a, t0()).is_some());
    assert!(s.active_at(t0()).iter().any(|g| g.id == bypass));
    let late = s.resolve_at(
        &in_flight,
        &answer("approved", &a, "DB"),
        mins(1),
        &AuditOnly,
    );
    assert!(late.unwrap_err().contains("already ended"));
    assert!(s
        .resolve_at(
            &other_flight,
            &answer("approved", &a, "OTHER"),
            mins(1),
            &AuditOnly
        )
        .unwrap()
        .is_some());
    // every subject of the kind
    assert_eq!(
        s.revoke_matching_at(KindId::Secret, None, mins(2)).unwrap(),
        2
    );
    assert!(s
        .active_at(mins(2))
        .iter()
        .all(|g| g.approval.kind == KindId::LaneDialogBypass));
    assert!(audit_text(d.path()).contains("revoked-matching"));
}

/// #2b: a revocation can never be undone by an old grants file put back.
#[test]
fn a_matching_revocation_survives_an_old_file_put_back() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    add(&mut s, approval(KindId::Secret, "DB", &a, Some(mins(60))));
    drop(s);
    let before = std::fs::read(d.path().join("grants.json")).unwrap();
    let mut s = open(d.path());
    assert_eq!(s.revoke_matching_at(KindId::Secret, None, t0()).unwrap(), 1);
    drop(s);
    std::fs::write(d.path().join("grants.json"), before).unwrap();
    assert!(open(d.path())
        .find_at(KindId::Secret, "DB", &a, t0())
        .is_none());
}

/// #2b: like `revoke`, it works on a store untrusted for its files, and is
/// refused when the key is the problem (the grants are unknown); a
/// read-only store refuses it.
#[test]
fn revoke_matching_follows_revokes_trust_rules() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    add(&mut s, approval(KindId::Secret, "DB", &a, Some(mins(60))));
    drop(s);
    std::fs::remove_file(d.path().join("head.copy")).unwrap();
    let mut s = open(d.path());
    assert!(matches!(s.untrusted, Some(Untrusted::Files(_))));
    assert_eq!(s.revoke_matching_at(KindId::Secret, None, t0()).unwrap(), 1);
    drop(s);
    let mut ro = Store::inspect(d.path(), &Xor(7), Some(d.path().join("head.copy")))
        .unwrap()
        .unwrap();
    assert!(ro.revoke_matching_at(KindId::Secret, None, t0()).is_err());
    drop(ro);
    let mut wrong = Store::open(d.path(), &Xor(9), Some(d.path().join("head.copy"))).unwrap();
    assert!(matches!(wrong.untrusted, Some(Untrusted::Key(_))));
    assert!(wrong
        .revoke_matching_at(KindId::Secret, None, t0())
        .is_err());
}

/// Second review of #2b, finding 4: a revocation whose prompts file was
/// never written (a crash, a held file) still ends the prompt in flight,
/// because the ended ids travel with the tombstones, in the file written
/// first.
#[test]
fn a_revocation_cut_short_still_ends_the_prompt_in_flight() {
    for how in ["matching", "all"] {
        let d = tempdir().unwrap();
        let a = who("o", "s");
        let mut s = open(d.path());
        let r = reserve(&mut s, &a, "DB", t0());
        let p = d.path().join("attempts.json");
        let old = std::fs::read(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        let cut = match how {
            "matching" => s.revoke_matching_at(KindId::Secret, Some("DB"), t0()),
            _ => s.revoke_all_at(t0()),
        };
        assert!(cut.is_err(), "{how}: the prompts file was written");
        drop(s);
        std::fs::remove_dir(&p).unwrap();
        std::fs::write(&p, old).unwrap();
        let mut s = open(d.path());
        assert_eq!(s.untrusted, None, "{how}: {:?}", s.untrusted);
        let late = s.resolve_at(&r, &answer("approved", &a, "DB"), mins(1), &AuditOnly);
        assert!(late.unwrap_err().contains("already ended"), "{how}");
        assert!(
            s.find_at(KindId::Secret, "DB", &a, mins(1)).is_none(),
            "{how}"
        );
    }
}

/// Second review of #2b, finding 2: a grant is never honoured before the
/// moment it was approved (a clock that was wrong ahead, then corrected).
#[test]
fn a_grant_is_not_honoured_before_it_was_approved() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let mut ap = approval(KindId::Secret, "DB", &a, Some(mins(60)));
    ap.approved_at = mins(1);
    add(&mut s, ap);
    assert!(s.find_at(KindId::Secret, "DB", &a, mins(1)).is_some());
    assert!(s.find_at(KindId::Secret, "DB", &a, t0()).is_none());
    assert!(s
        .find_at(KindId::Secret, "DB", &a, t0() - Duration::days(30))
        .is_none());
}

/// Second review of #2b, finding 3: an approval whose shown end passed
/// before it could be recorded makes no grant.
#[test]
fn an_approval_that_ended_before_it_was_recorded_grants_nothing() {
    let d = tempdir().unwrap();
    let a = who("o", "s");
    let mut s = open(d.path());
    let r = reserve(&mut s, &a, "DB", t0());
    let mut ap = approval(KindId::Secret, "DB", &a, Some(mins(5)));
    ap.approved_at = mins(4);
    let late = s.resolve_at(&r, &Outcome::Approved(ap.clone()), mins(6), &AuditOnly);
    assert!(late.unwrap_err().contains("before it could be recorded"));
    assert!(s.active_at(mins(4)).is_empty());
    // control: the same approval, recorded before its end, lands
    let r = reserve(&mut s, &a, "DB2", t0());
    ap.subject = "DB2".into();
    assert!(s
        .resolve_at(&r, &Outcome::Approved(ap), mins(4), &AuditOnly)
        .unwrap()
        .is_some());
}

/// Review 6, m-5: `audit verify` says when the head copy lags.
#[test]
fn verify_reports_a_lagging_head_copy() {
    let d = tempdir().unwrap();
    let mut s = three_events(d.path());
    assert_eq!(s.verify_audit().unwrap().head_behind, 0);
    let head = d.path().join("head.copy");
    let stale = std::fs::read(&head).unwrap();
    s.audit(mins(5), "granted", "x").unwrap();
    s.audit(mins(6), "granted", "y").unwrap();
    std::fs::write(&head, stale).unwrap();
    assert_eq!(s.verify_audit().unwrap().head_behind, 2);
}

fn fuel_trust() -> String {
    crate::request::lane_dialog_subject("fuel", "trust").unwrap()
}

/// user-request #5: a grant for lane X never answers lane Y's dialog.
#[test]
fn a_lane_dialog_grant_for_one_lane_never_answers_another_lane() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    add(
        &mut s,
        approval(
            KindId::LaneDialogBypass,
            &fuel_trust(),
            &who("pm", "s"),
            None,
        ),
    );
    let other = crate::request::lane_dialog_subject("overmind", "trust").unwrap();
    assert!(s
        .find_at(
            KindId::LaneDialogBypass,
            &fuel_trust(),
            &who("pm", "s"),
            t0()
        )
        .is_some());
    assert!(s
        .find_at(KindId::LaneDialogBypass, &other, &who("pm", "s"), t0())
        .is_none());
}

/// user-request #5: a handler-id-only subject (the pre-#5 shape) names no
/// lane, so it is neither stored nor matched.
#[test]
fn an_unbound_lane_dialog_approval_is_refused_and_never_matches() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let bare = approval(KindId::LaneDialogBypass, "trust", &who("pm", "s"), None);
    assert!(s.add(bare, t0()).is_err());
    assert!(s
        .find_at(KindId::LaneDialogBypass, "trust", &who("fuel", "x"), t0())
        .is_none());
}
