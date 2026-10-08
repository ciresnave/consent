// SPDX-License-Identifier: MIT OR Apache-2.0
//! Durable pending requests (user-request #4). Every test names the case it
//! pins; each fails on the stubbed API, which answers "not built yet".
//!
//! CireSnave, 2026-10-07 (board 134, verbatim): "The message in the Windows
//! Hello prompt can be three things: 1) Who is making the request.  2) What
//! secret they are requesting.  3) What duration they want access to that
//! secret for.  Then I either approve the Windows Hello prompt or cancel it."

use super::*;
use crate::channel::{Channel, HelloChannel};
use crate::consent::{Consent, ConsentOutcome};
use chrono::TimeZone;
use std::cell::RefCell;
use tempfile::tempdir;

struct Xor(u8);
impl Protector for Xor {
    fn protect(&self, p: &[u8]) -> Result<Vec<u8>, String> {
        Ok(p.iter().map(|b| b ^ self.0).collect())
    }
    fn unprotect(&self, b: &[u8]) -> Result<Vec<u8>, String> {
        Ok(b.iter().map(|x| x ^ self.0).collect())
    }
}

#[derive(Default)]
struct Alerts(RefCell<Vec<String>>);
impl Alert for Alerts {
    fn alert(&self, what: &str) {
        self.0.borrow_mut().push(what.to_string());
    }
}

/// The Hello prompt: answers as told, and keeps every text it was shown.
struct Hello {
    answer: fn() -> ConsentOutcome,
    shown: RefCell<Vec<String>>,
}
impl Consent for Hello {
    fn ask(&self, prompt: &str, _: std::time::Duration) -> ConsentOutcome {
        self.shown.borrow_mut().push(prompt.to_string());
        (self.answer)()
    }
}

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 7, 16, 0, 0).unwrap()
}

fn mins(m: i64) -> DateTime<Utc> {
    t0() + Duration::minutes(m)
}

fn who(role: &str) -> Requester {
    Requester {
        role: role.into(),
        session_id: "s1".into(),
        claude_pid: 42,
        claude_start_secs: 1,
        managed: true,
    }
}

fn req(role: &str, subject: &str) -> Request {
    Request {
        kind: KindId::Secret,
        subject: subject.into(),
        summary: "run: psql -f seed.sql".into(),
        requester: who(role),
        reason: "seed the db".into(),
    }
}

fn hour() -> Grant {
    Grant::for_duration(Duration::hours(1))
}

fn open(dir: &Path) -> Store {
    Store::open(dir, &Xor(7), Some(dir.join("head.copy"))).unwrap()
}

/// Hello, with the clock stopped at `now`.
fn hello(answer: fn() -> ConsentOutcome, now: DateTime<Utc>) -> HelloChannel<Hello> {
    HelloChannel {
        consent: Hello {
            answer,
            shown: RefCell::new(Vec::new()),
        },
        clock: Box::new(move || now),
    }
}

fn approve() -> ConsentOutcome {
    ConsentOutcome::Approved
}
fn cancel() -> ConsentOutcome {
    ConsentOutcome::Denied
}
fn nobody_there() -> ConsentOutcome {
    ConsentOutcome::TimedOut
}

const WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// One whole answer, as a consumer does it: begin, drop the store (the
/// lock), show the prompt, reopen, resolve.
fn answer_via(
    dir: &Path,
    id: &str,
    bound_hash: &str,
    ch: &HelloChannel<Hello>,
    now: DateTime<Utc>,
) -> Result<Option<String>, String> {
    let mut s = open(dir);
    let asking = s.begin_answer_at(id, bound_hash, now, &AuditOnly)?;
    drop(s);
    let out = ch.present(&asking.request, &asking.grant, WAIT);
    let mut s = open(dir);
    s.resolve_at(&asking.reservation, &out, now, &AuditOnly)
}

fn submit(dir: &Path, role: &str, subject: &str, hash: &str) -> String {
    let mut s = open(dir);
    s.submit_at(&req(role, subject), &hour(), hash, t0())
        .unwrap()
}

// -- what survives a restart ------------------------------------------------

#[test]
fn a_pending_request_survives_a_restart_and_grants_nothing() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let s = open(d.path());
    assert_eq!(s.untrusted, None);
    assert_eq!(s.pending().len(), 1);
    let p = &s.pending()[0];
    assert_eq!(p.id, id);
    assert_eq!(p.request, req("overmind", "TJ_DB"));
    assert_eq!(p.grant, hour());
    assert_eq!(p.bound_hash, "plan-1");
    // a record that someone asked is not an approval
    assert!(s.grants().is_empty());
    assert!(s
        .find_at(KindId::Secret, "TJ_DB", &who("overmind"), t0())
        .is_none());
    assert!(s.attempts().is_empty(), "nobody was prompted");
}

/// "No timeout": the request is still there, and still answerable, days
/// later; the grant then runs from the moment it is shown.
#[test]
fn a_pending_request_has_no_timeout() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let later = t0() + Duration::days(3);
    let ch = hello(approve, later);
    let granted = answer_via(d.path(), &id, "plan-1", &ch, later).unwrap();
    assert!(granted.is_some());
    let s = open(d.path());
    assert_eq!(
        s.grants()[0].approval.expires_at,
        Some(later + Duration::hours(1))
    );
}

// -- a restored request re-prompts, never approves by itself -----------------

#[test]
fn a_restored_request_prompts_the_person_again() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let ch = hello(approve, t0());
    let granted = answer_via(d.path(), &id, "plan-1", &ch, t0()).unwrap();
    assert!(granted.is_some());
    let shown = ch.consent.shown.borrow();
    assert_eq!(shown.len(), 1, "the person was asked exactly once");
    // board 134: exactly who, what, how long
    assert_eq!(
        shown[0],
        format!(
            "Who: lane 'overmind'\nWants: use a secret: TJ_DB\nDuration: {}",
            hour().describe(t0())
        )
    );
}

/// Approve grants exactly the requested duration (board 134).
#[test]
fn approving_grants_exactly_the_requested_duration() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    answer_via(d.path(), &id, "plan-1", &hello(approve, t0()), t0()).unwrap();
    let s = open(d.path());
    assert_eq!(s.grants().len(), 1);
    let a = &s.grants()[0].approval;
    assert_eq!(a.expires_at, Some(t0() + Duration::hours(1)));
    assert_eq!(a.requester, who("overmind"));
    assert!(s.pending().is_empty(), "the request is spent");
}

/// An approval for a different length than was requested is not for what
/// was asked; it makes no grant, and the request stays answerable.
#[test]
fn an_approval_for_another_duration_is_refused() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let mut s = open(d.path());
    let asking = s.begin_answer_at(&id, "plan-1", t0(), &AuditOnly).unwrap();
    let longer = Outcome::Approved(Approval {
        kind: KindId::Secret,
        subject: "TJ_DB".into(),
        requester: who("overmind"),
        approved_at: t0(),
        expires_at: Some(t0() + Duration::hours(100)),
    });
    let err = s
        .resolve_at(&asking.reservation, &longer, t0(), &AuditOnly)
        .unwrap_err();
    assert!(err.contains("requested"), "{err}");
    assert!(s.grants().is_empty());
    assert_eq!(s.pending().len(), 1);
    // control: the length that was asked for lands
    let right = Outcome::Approved(Approval {
        kind: KindId::Secret,
        subject: "TJ_DB".into(),
        requester: who("overmind"),
        approved_at: t0(),
        expires_at: Some(t0() + Duration::hours(1)),
    });
    s.resolve_at(&asking.reservation, &right, t0(), &AuditOnly)
        .unwrap();
    assert_eq!(s.grants().len(), 1);
}

/// Cancel refuses (board 134): no grant, the request is closed, and the
/// gate's cooldown starts.
#[test]
fn cancel_refuses_and_closes_the_request() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let granted = answer_via(d.path(), &id, "plan-1", &hello(cancel, t0()), t0()).unwrap();
    assert_eq!(granted, None);
    let s = open(d.path());
    assert!(s.grants().is_empty());
    assert!(s.pending().is_empty());
    assert_eq!(s.attempts().last().unwrap().outcome, Ended::Denied);
    // the same lane asking again is in the cooldown
    drop(s);
    let again = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let err = answer_via(
        d.path(),
        &again,
        "plan-1",
        &hello(approve, mins(1)),
        mins(1),
    )
    .unwrap_err();
    assert!(err.contains("refused"), "{err}");
    assert_eq!(open(d.path()).pending().len(), 1, "kept for later");
}

/// Nobody at the desk is not a refusal: the request stays pending.
#[test]
fn an_unanswered_prompt_leaves_the_request_pending() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let granted = answer_via(d.path(), &id, "plan-1", &hello(nobody_there, t0()), t0()).unwrap();
    assert_eq!(granted, None);
    let s = open(d.path());
    assert_eq!(s.pending().len(), 1);
    assert!(s.grants().is_empty());
    drop(s);
    // and a later prompt can still be approved (past the timeout cooldown)
    let ch = hello(approve, mins(11));
    assert!(answer_via(d.path(), &id, "plan-1", &ch, mins(11))
        .unwrap()
        .is_some());
}

// -- over the maximum -------------------------------------------------------

#[test]
fn a_request_over_the_kinds_maximum_is_refused_before_any_prompt() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    // a secret is never forever (PM ruling on #115 M4)
    let err = s
        .submit_at(&req("overmind", "TJ_DB"), &Grant::Forever, "plan-1", t0())
        .unwrap_err();
    assert!(err.contains("maximum"), "{err}");
    assert!(s.pending().is_empty(), "stored anyway");
    assert!(s.attempts().is_empty(), "prompted anyway");
    // never clamped: nothing was stored in its place
    drop(s);
    assert!(open(d.path()).pending().is_empty());
    // control: a finite length is accepted
    assert!(open(d.path())
        .submit_at(&req("overmind", "TJ_DB"), &hour(), "plan-1", t0())
        .is_ok());
}

// -- duplicate --------------------------------------------------------------

#[test]
fn submitting_the_same_request_twice_keeps_one() {
    let d = tempdir().unwrap();
    let a = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let b = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    assert_eq!(a, b);
    assert_eq!(open(d.path()).pending().len(), 1);
    // a different binding is a different request
    let c = submit(d.path(), "overmind", "TJ_DB", "plan-2");
    assert_ne!(a, c);
    assert_eq!(open(d.path()).pending().len(), 2);
}

/// A request is answered once: the same id again finds nothing, and a
/// reservation cannot be resolved twice.
#[test]
fn an_answered_request_cannot_be_answered_again() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    answer_via(d.path(), &id, "plan-1", &hello(approve, t0()), t0()).unwrap();
    let ch = hello(approve, mins(1));
    let err = answer_via(d.path(), &id, "plan-1", &ch, mins(1)).unwrap_err();
    assert!(err.contains("no such pending"), "{err}");
    assert!(
        ch.consent.shown.borrow().is_empty(),
        "prompted for a replay"
    );
    assert_eq!(open(d.path()).grants().len(), 1);
}

// -- stale ------------------------------------------------------------------

/// The artifact changed since the request was made (agentlife: the plan
/// hash): the request is void and the person is never asked about it.
#[test]
fn a_changed_bound_hash_voids_the_request_without_a_prompt() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let ch = hello(approve, t0());
    let err = answer_via(d.path(), &id, "plan-2", &ch, t0()).unwrap_err();
    assert!(err.contains("bound_hash"), "{err}");
    assert!(ch.consent.shown.borrow().is_empty(), "prompted anyway");
    let s = open(d.path());
    assert!(s.pending().is_empty(), "a stale request must not linger");
    assert!(s.grants().is_empty());
    assert!(s.attempts().is_empty(), "no prompt was reserved");
}

#[test]
fn a_request_for_a_moment_that_has_passed_is_stale() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let until = Grant::Until(mins(10));
    let id = s
        .submit_at(&req("overmind", "TJ_DB"), &until, "plan-1", t0())
        .unwrap();
    drop(s);
    let ch = hello(approve, mins(11));
    let err = answer_via(d.path(), &id, "plan-1", &ch, mins(11)).unwrap_err();
    assert!(err.contains("ended") || err.contains("maximum"), "{err}");
    assert!(ch.consent.shown.borrow().is_empty());
    assert!(open(d.path()).pending().is_empty());
}

// -- tampered ---------------------------------------------------------------

/// A record altered after it was made fails closed at the answer, whichever
/// field was changed, and the person is never shown the altered text.
#[test]
fn an_altered_pending_request_fails_closed() {
    type Edit = fn(&mut PendingRequest);
    let edits: [(&str, Edit); 5] = [
        ("subject", |p| p.request.subject = "PROD_ROOT".into()),
        ("duration", |p| {
            p.grant = Grant::for_duration(Duration::hours(100))
        }),
        ("requester", |p| p.request.requester.role = "pm".into()),
        ("bound_hash", |p| p.bound_hash = "plan-evil".into()),
        ("seal", |p| p.seal = "0".repeat(64)),
    ];
    for (what, edit) in edits {
        let d = tempdir().unwrap();
        let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
        let mut s = open(d.path());
        edit(&mut s.pending[0]);
        s.save(t0()).unwrap();
        drop(s);
        // the consumer's own hash is the altered one where that is what
        // changed, so only the seal can catch it
        let current = if what == "bound_hash" {
            "plan-evil"
        } else {
            "plan-1"
        };
        let ch = hello(approve, t0());
        let alerts = Alerts::default();
        let mut s = open(d.path());
        let err = s
            .begin_answer_at(&id, current, t0(), &alerts)
            .map(|_| ())
            .unwrap_err();
        assert!(err.contains("altered"), "{what}: {err}");
        assert!(ch.consent.shown.borrow().is_empty(), "{what}: prompted");
        assert!(!alerts.0.borrow().is_empty(), "{what}: no alert");
        assert!(s.pending().is_empty(), "{what}: kept");
        assert!(s.grants().is_empty(), "{what}: granted");
        assert!(s.attempts().is_empty(), "{what}: reserved a prompt");
        assert!(
            std::fs::read_to_string(d.path().join("audit.jsonl"))
                .unwrap()
                .contains("pending-altered"),
            "{what}: not audited"
        );
    }
}

// -- in flight, caps, revocation, trust ---------------------------------------

/// The requester withdraws while the prompt is up: the approval that comes
/// back lands nowhere.
#[test]
fn a_withdrawn_request_cannot_be_approved_afterwards() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let mut s = open(d.path());
    let asking = s.begin_answer_at(&id, "plan-1", t0(), &AuditOnly).unwrap();
    drop(s);
    assert!(open(d.path()).withdraw_at(&id, t0()).unwrap());
    let out = hello(approve, t0()).present(&asking.request, &asking.grant, WAIT);
    let mut s = open(d.path());
    assert!(s
        .resolve_at(&asking.reservation, &out, t0(), &AuditOnly)
        .is_err());
    assert!(s.grants().is_empty());
    // and withdrawing what is not there says so
    assert!(!s.withdraw_at(&id, t0()).unwrap());
}

#[test]
fn a_role_cannot_fill_the_store_with_requests_that_never_expire() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    for n in 0..MAX_PENDING_PER_ROLE {
        s.submit_at(&req("overmind", &format!("S{n}")), &hour(), "h", t0())
            .unwrap();
    }
    let err = s
        .submit_at(&req("overmind", "ONE_TOO_MANY"), &hour(), "h", t0())
        .unwrap_err();
    assert!(err.contains("pending"), "{err}");
    // control: another lane is not locked out by it
    assert!(s.submit_at(&req("fuel", "S0"), &hour(), "h", t0()).is_ok());
}

#[test]
fn revoking_everything_ends_the_pending_requests_too() {
    let d = tempdir().unwrap();
    submit(d.path(), "overmind", "A", "h");
    submit(d.path(), "fuel", "B", "h");
    let mut s = open(d.path());
    s.revoke_all_at(mins(1)).unwrap();
    assert!(s.pending().is_empty());
    drop(s);
    assert!(open(d.path()).pending().is_empty());
}

#[test]
fn revoking_a_secret_ends_only_that_secrets_pending_requests() {
    let d = tempdir().unwrap();
    submit(d.path(), "overmind", "A", "h");
    submit(d.path(), "overmind", "B", "h");
    let mut s = open(d.path());
    s.revoke_matching_at(KindId::Secret, Some("a"), mins(1))
        .unwrap();
    let left: Vec<_> = s
        .pending()
        .iter()
        .map(|p| p.request.subject.as_str())
        .collect();
    assert_eq!(left, ["B"]);
}

#[test]
fn an_untrustworthy_store_takes_no_request() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    s.untrusted = Some(Untrusted::Files("test".into()));
    let err = s
        .submit_at(&req("overmind", "TJ_DB"), &hour(), "h", t0())
        .unwrap_err();
    assert!(err.contains("cannot be trusted"), "{err}");
    assert!(s.pending().is_empty());
}

#[test]
fn a_bound_hash_must_be_a_short_plain_string() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    for bad in ["", "a\nb", &"x".repeat(MAX_BOUND_HASH_CHARS + 1)] {
        assert!(
            s.submit_at(&req("overmind", "TJ_DB"), &hour(), bad, t0())
                .is_err(),
            "{bad:?}"
        );
    }
    assert!(s.pending().is_empty());
    // control: a plain hash of the usual length is accepted
    assert!(s
        .submit_at(&req("overmind", "TJ_DB"), &hour(), &"a".repeat(64), t0())
        .is_ok());
}

/// Two prompts for one request could each be approved: the second is not
/// started while the first is up, and a second reservation that slipped in
/// anyway cannot land once the first has spent the request.
#[test]
fn a_request_is_answered_by_one_prompt_at_a_time() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let mut s = open(d.path());
    let first = s.begin_answer_at(&id, "plan-1", t0(), &AuditOnly).unwrap();
    let err = s
        .begin_answer_at(&id, "plan-1", mins(1), &AuditOnly)
        .map(|_| ())
        .unwrap_err();
    assert!(err.contains("already being answered"), "{err}");
    // the first is approved and spends the request
    let ok = hello(approve, t0()).present(&first.request, &first.grant, WAIT);
    s.resolve_at(&first.reservation, &ok, t0(), &AuditOnly)
        .unwrap();
    // a reservation for the same request made some other way cannot land
    let stray = s
        .reserve(
            &who("overmind"),
            KindId::Secret,
            "TJ_DB",
            mins(2),
            &AuditOnly,
            Some(id.clone()),
        )
        .unwrap();
    let again = hello(approve, mins(2)).present(&first.request, &first.grant, WAIT);
    let err = s
        .resolve_at(&stray, &again, mins(2), &AuditOnly)
        .unwrap_err();
    assert!(err.contains("no longer pending"), "{err}");
    assert_eq!(s.grants().len(), 1);
}

/// `id` and `created_at` are sealed too, so one record's body cannot be filed
/// under another's id, nor a record be given a later birth.
#[test]
fn the_seal_covers_the_id_and_the_creation_time() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let mut s = open(d.path());
    s.pending[0].created_at = mins(5);
    let err = s
        .begin_answer_at(&id, "plan-1", t0(), &AuditOnly)
        .map(|_| ())
        .unwrap_err();
    assert!(err.contains("altered"), "{err}");
    drop(s);
    let d = tempdir().unwrap();
    submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let mut s = open(d.path());
    s.pending[0].id = "someone-elses".into();
    let err = s
        .begin_answer_at("someone-elses", "plan-1", t0(), &AuditOnly)
        .map(|_| ())
        .unwrap_err();
    assert!(err.contains("altered"), "{err}");
}

#[test]
fn a_prompt_the_channel_could_not_show_leaves_the_request_pending() {
    let d = tempdir().unwrap();
    let id = submit(d.path(), "overmind", "TJ_DB", "plan-1");
    let ch = hello(|| ConsentOutcome::Unavailable("no Hello".into()), t0());
    assert_eq!(
        answer_via(d.path(), &id, "plan-1", &ch, t0()).unwrap(),
        None
    );
    assert_eq!(open(d.path()).pending().len(), 1);
}

#[test]
fn a_request_cannot_carry_unbounded_text() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let mut r = req("overmind", "TJ_DB");
    r.summary = "x".repeat(MAX_TEXT_CHARS + 1);
    assert!(s.submit_at(&r, &hour(), "h", t0()).is_err());
    let mut r = req("overmind", "TJ_DB");
    r.reason = "x".repeat(MAX_TEXT_CHARS + 1);
    assert!(s.submit_at(&r, &hour(), "h", t0()).is_err());
    let r = req("overmind", &"s".repeat(MAX_SUBJECT_CHARS + 1));
    assert!(s.submit_at(&r, &hour(), "h", t0()).is_err());
    assert!(s.pending().is_empty());
    let r = req("overmind", &"s".repeat(MAX_SUBJECT_CHARS));
    assert!(s.submit_at(&r, &hour(), "h", t0()).is_ok());
}

/// user-request #5: two lanes' dialog requests are two pending requests, and
/// one that names no lane is refused before anything is stored.
#[test]
fn pending_lane_dialog_requests_are_per_lane() {
    let d = tempdir().unwrap();
    let mut s = open(d.path());
    let lane = |l: &str| Request {
        kind: KindId::LaneDialogBypass,
        ..req(
            "pm",
            &crate::request::lane_dialog_subject(l, "trust").unwrap(),
        )
    };
    let a = s
        .submit_at(&lane("fuel"), &Grant::Forever, "h", t0())
        .unwrap();
    let b = s
        .submit_at(&lane("overmind"), &Grant::Forever, "h", t0())
        .unwrap();
    assert_ne!(a, b);
    let bare = Request {
        kind: KindId::LaneDialogBypass,
        ..req("pm", "trust")
    };
    assert!(s.submit_at(&bare, &Grant::Forever, "h", t0()).is_err());
    assert_eq!(s.pending().len(), 2);
}
