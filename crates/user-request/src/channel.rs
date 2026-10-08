// SPDX-License-Identifier: MIT OR Apache-2.0
//! How a request reaches a person. Every channel answers the same way, so
//! callers can use them interchangeably.
//!
//! The requester states how long it wants, and the message the person
//! approves or cancels names that duration and its absolute end (board 134,
//! CireSnave 2026-10-07: approve it or cancel it; nothing is typed). Hello
//! proves the person was present and approved that text; it does not prove
//! they read it.

use std::time::Duration;

use chrono::{DateTime, Local, Utc};

use crate::consent::{Consent, ConsentOutcome};
use crate::request::{Approval, Grant, Request};

#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum Outcome {
    /// Approved, for exactly the end the person was shown.
    Approved(Approval),
    Denied,
    TimedOut,
    /// The channel cannot ask right now (no Hello, not implemented, ...).
    Unavailable(String),
    /// Not asked, or not honoured: over the kind's maximum, a malformed
    /// request, or a grant that ended while the person was deciding.
    Refused(String),
}

pub trait Channel {
    /// Ask the person to approve `req` for exactly `grant`.
    fn present(&self, req: &Request, grant: &Grant, wait: Duration) -> Outcome;
}

/// A requester role longer than this is refused, never clipped: the
/// requester line must be shown whole (PM condition (f)).
pub const MAX_ROLE_CHARS: usize = 64;

/// Requester-supplied text with every control and invisible formatting
/// character (newlines, bidi overrides, zero-width marks) replaced by a
/// space, so it cannot forge or reorder the prompt's own lines (review I2).
/// with-secret's prompt uses it too.
pub fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            let hidden = c.is_control()
                || matches!(c,
                    '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{FEFF}'
                    | '\u{200B}'..='\u{200F}'
                    | '\u{2028}'..='\u{202E}'
                    | '\u{2060}'..='\u{206F}');
            if hidden {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// The text the person approves: exactly who asks, what for, and for how
/// long (board 134, CireSnave 2026-10-07: "three things"). The reason and
/// the command are not in it; the caller logs them. Who and Duration are
/// never clipped; the subject is cleaned and clipped (review I2).
pub fn prompt_text(req: &Request, grant: &Grant, now: DateTime<Utc>) -> String {
    let r = &req.requester;
    let role = clean(&r.role);
    let who = if r.managed {
        format!("lane '{role}'")
    } else {
        format!("{role} (pid {}) - NOT a registered lane", r.claude_pid)
    };
    format!(
        "Who: {who}\nWants: {}: {}\nDuration: {}",
        req.kind.name(),
        clip(&clean(&req.subject), 200),
        grant.describe(now),
    )
}

/// Windows Hello, through any `Consent` (the real one is `hello::HelloConsent`).
pub struct HelloChannel<C: Consent> {
    pub consent: C,
    /// The clock; injectable so a test can make time pass while the person
    /// decides.
    pub clock: Box<dyn Fn() -> DateTime<Utc>>,
}

impl<C: Consent> HelloChannel<C> {
    pub fn new(consent: C) -> Self {
        Self {
            consent,
            clock: Box::new(Utc::now),
        }
    }
}

impl<C: Consent> Channel for HelloChannel<C> {
    fn present(&self, req: &Request, grant: &Grant, wait: Duration) -> Outcome {
        if req.requester.role.chars().count() > MAX_ROLE_CHARS {
            return Outcome::Refused(format!(
                "requester role is longer than {MAX_ROLE_CHARS} characters"
            ));
        }
        if let Err(e) = req.check_subject() {
            return Outcome::Refused(e);
        }
        let shown_at = (self.clock)();
        if !grant.within(req.kind.max(), shown_at.with_timezone(&Local)) {
            return Outcome::Refused(format!(
                "{} is over the maximum for {:?}",
                grant.describe(shown_at),
                req.kind
            ));
        }
        // `within` passed, so the end is representable
        let Ok(expires_at) = grant.end_at(shown_at) else {
            return Outcome::Refused("an impossible duration".into());
        };
        match self.consent.ask(&prompt_text(req, grant, shown_at), wait) {
            ConsentOutcome::Approved => {
                let approved_at = (self.clock)();
                // the person approved the END they were shown; if it passed
                // while they decided, there is nothing left to grant
                if expires_at.is_some_and(|e| e <= approved_at) {
                    return Outcome::Refused("the grant ended while waiting for approval".into());
                }
                Outcome::Approved(Approval {
                    kind: req.kind,
                    subject: req.subject.clone(),
                    requester: req.requester.clone(),
                    approved_at,
                    expires_at,
                })
            }
            ConsentOutcome::Denied => Outcome::Denied,
            ConsentOutcome::TimedOut => Outcome::TimedOut,
            ConsentOutcome::Unavailable(why) => Outcome::Unavailable(why),
        }
    }
}

/// Designed for, not built. An SMS or push answer arrives LATER and from
/// another device, so it must carry proof bound to the request (a one-time
/// code or a signature over the request id) and land through the pending
/// store (plan step #4). Until then it cannot ask.
pub struct SmsChannel;
pub struct PushChannel;

impl Channel for SmsChannel {
    fn present(&self, _: &Request, _: &Grant, _: Duration) -> Outcome {
        Outcome::Unavailable("SMS requests are designed for but not built yet".into())
    }
}

impl Channel for PushChannel {
    fn present(&self, _: &Request, _: &Grant, _: Duration) -> Outcome {
        Outcome::Unavailable("push requests are designed for but not built yet".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{KindId, Requester};
    use chrono::{Duration as Span, TimeZone};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    struct FakeConsent {
        answer: fn() -> ConsentOutcome,
        asked: RefCell<Vec<String>>,
    }
    impl FakeConsent {
        fn new(answer: fn() -> ConsentOutcome) -> Self {
            Self {
                answer,
                asked: RefCell::new(Vec::new()),
            }
        }
    }
    impl Consent for FakeConsent {
        fn ask(&self, prompt: &str, _: Duration) -> ConsentOutcome {
            self.asked.borrow_mut().push(prompt.to_string());
            (self.answer)()
        }
    }

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 7, 16, 0, 0).unwrap()
    }

    /// A clock that reads `t0`, then `t0 + later` on every later reading:
    /// time passes while the person decides.
    fn channel(answer: fn() -> ConsentOutcome, later: Span) -> HelloChannel<FakeConsent> {
        let reads = Rc::new(Cell::new(0));
        HelloChannel {
            consent: FakeConsent::new(answer),
            clock: Box::new(move || {
                let n = reads.get();
                reads.set(n + 1);
                if n == 0 {
                    t0()
                } else {
                    t0() + later
                }
            }),
        }
    }

    fn req(kind: KindId, role: &str, subject: &str, text: &str, managed: bool) -> Request {
        Request {
            kind,
            subject: subject.into(),
            summary: text.into(),
            requester: Requester {
                role: role.into(),
                session_id: "s".into(),
                claude_pid: 42,
                claude_start_secs: 1,
                managed,
            },
            reason: text.into(),
        }
    }

    fn bypass() -> Request {
        req(
            KindId::LaneDialogBypass,
            "overmind",
            "lane 'fuel', dialog 'trust'",
            "because",
            true,
        )
    }

    const WAIT: Duration = Duration::from_secs(1);

    #[test]
    fn an_approval_keeps_the_end_that_was_shown_not_one_from_the_approval() {
        let ch = channel(|| ConsentOutcome::Approved, Span::minutes(1));
        let g = Grant::for_duration(Span::hours(1));
        match ch.present(&bypass(), &g, WAIT) {
            Outcome::Approved(a) => {
                assert_eq!(a.approved_at, t0() + Span::minutes(1));
                assert_eq!(
                    a.expires_at,
                    Some(t0() + Span::hours(1)),
                    "stretched by the wait"
                );
                assert_eq!(
                    (a.kind, a.subject.as_str()),
                    (KindId::LaneDialogBypass, "lane 'fuel', dialog 'trust'")
                );
            }
            o => panic!("{o:?}"),
        }
        assert!(ch.consent.asked.borrow()[0].contains(&g.describe(t0())));
    }

    #[test]
    fn a_grant_that_ends_while_the_person_decides_is_refused() {
        let ch = channel(|| ConsentOutcome::Approved, Span::minutes(10));
        let g = Grant::Until(t0() + Span::minutes(5));
        assert!(matches!(
            ch.present(&bypass(), &g, WAIT),
            Outcome::Refused(_)
        ));
    }

    #[test]
    fn a_forever_approval_has_no_end() {
        let ch = channel(|| ConsentOutcome::Approved, Span::days(3));
        match ch.present(&bypass(), &Grant::Forever, WAIT) {
            Outcome::Approved(a) => assert_eq!(a.expires_at, None),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn every_other_answer_maps_through() {
        for (answer, want) in [
            (
                (|| ConsentOutcome::Denied) as fn() -> ConsentOutcome,
                Outcome::Denied,
            ),
            (|| ConsentOutcome::TimedOut, Outcome::TimedOut),
            (
                || ConsentOutcome::Unavailable("x".into()),
                Outcome::Unavailable("x".into()),
            ),
        ] {
            let ch = channel(answer, Span::zero());
            assert_eq!(ch.present(&bypass(), &Grant::Forever, WAIT), want);
        }
    }

    /// A secret may not be granted forever (PM ruling on #115 M4), and the
    /// person is not even asked.
    #[test]
    fn a_grant_over_the_kinds_maximum_is_refused_without_asking() {
        let ch = channel(|| ConsentOutcome::Approved, Span::zero());
        let r = req(
            KindId::Secret,
            "overmind",
            "TJ_PROD_DATABASE_URL",
            "migration",
            true,
        );
        assert!(matches!(
            ch.present(&r, &Grant::Forever, WAIT),
            Outcome::Refused(_)
        ));
        assert!(
            ch.consent.asked.borrow().is_empty(),
            "the person was asked anyway"
        );
    }

    #[test]
    fn an_over_long_role_is_refused_without_asking_never_clipped() {
        let ch = channel(|| ConsentOutcome::Approved, Span::zero());
        let r = req(
            KindId::LaneDialogBypass,
            &"r".repeat(MAX_ROLE_CHARS + 1),
            "d",
            "x",
            true,
        );
        assert!(matches!(
            ch.present(&r, &Grant::Forever, WAIT),
            Outcome::Refused(_)
        ));
        assert!(ch.consent.asked.borrow().is_empty());
        let ok = req(
            KindId::LaneDialogBypass,
            &"r".repeat(MAX_ROLE_CHARS),
            "d",
            "x",
            true,
        );
        assert!(prompt_text(&ok, &Grant::Forever, t0()).contains(&"r".repeat(MAX_ROLE_CHARS)));
    }

    /// Review I2: a subject, summary, reason or role cannot forge or reorder
    /// the prompt's own lines.
    #[test]
    fn requester_text_cannot_forge_the_who_or_grant_line() {
        let forged = "dialog\nWho: lane 'pm'\nGrant: for 0h 05m, until today";
        let r = req(
            KindId::LaneDialogBypass,
            "evil\nGrant: 5m\u{202E}x",
            forged,
            forged,
            true,
        );
        let text = prompt_text(&r, &Grant::Forever, t0());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].starts_with("Who: lane 'evil"), "{text}");
        assert!(lines[1].starts_with("Wants: "), "{text}");
        assert!(lines[2].starts_with("Duration: *** FOREVER"), "{text}");
        assert!(!text.contains('\u{202E}'), "a bidi override survived");
    }

    #[test]
    fn a_long_subject_is_clipped_and_the_duration_never_is() {
        let long = "x".repeat(5000);
        let r = req(KindId::LaneDialogBypass, "overmind", &long, &long, true);
        let text = prompt_text(&r, &Grant::Forever, t0());
        assert!(text.starts_with("Who: lane 'overmind'\nWants: "), "{text}");
        assert!(
            text.ends_with("\nDuration: *** FOREVER (until revoked) ***"),
            "{text}"
        );
        assert!(text.len() < 500, "not clipped: {}", text.len());
        assert!(text.contains('…'));
    }

    /// Board 134, CireSnave 2026-10-07 (verbatim): "The message in the
    /// Windows Hello prompt can be three things: 1) Who is making the
    /// request.  2) What secret they are requesting.  3) What duration they
    /// want access to that secret for."
    #[test]
    fn the_prompt_is_exactly_who_what_and_how_long() {
        let r = req(KindId::Secret, "overmind", "TJ_DB", "run: psql", true);
        let g = Grant::for_duration(Span::hours(1));
        assert_eq!(
            prompt_text(&r, &g, t0()),
            format!(
                "Who: lane 'overmind'\nWants: use a secret: TJ_DB\nDuration: {}",
                g.describe(t0())
            )
        );
        assert!(g.describe(t0()).starts_with("for 1h 00m 00s, until "));
    }

    /// FOREVER stays loud and distinct, in the duration line itself.
    #[test]
    fn a_forever_prompt_says_so_loudly() {
        assert_eq!(
            prompt_text(&bypass(), &Grant::Forever, t0()),
            "Who: lane 'overmind'\n\
             Wants: auto-answer a lane startup dialog: lane 'fuel', dialog 'trust'\n\
             Duration: *** FOREVER (until revoked) ***"
        );
    }

    /// He asked for three things only: the reason and the command go to the
    /// audit log, not the prompt.
    #[test]
    fn the_prompt_carries_no_reason_or_summary() {
        let mut r = req(KindId::Secret, "overmind", "S", "x", true);
        r.summary = "run: psql -f seed.sql".into();
        r.reason = "seed the prod db".into();
        let text = prompt_text(&r, &Grant::for_duration(Span::minutes(5)), t0());
        assert!(!text.contains("psql") && !text.contains("seed"), "{text}");
    }

    #[test]
    fn an_unregistered_requester_is_named_as_such() {
        let r = req(KindId::LaneDialogBypass, "overmind", "d", "r", false);
        let text = prompt_text(&r, &Grant::Forever, t0());
        assert!(
            text.contains("pid 42") && text.contains("NOT a registered lane"),
            "{text}"
        );
    }

    #[test]
    fn the_prompt_names_the_kind_and_the_subject() {
        let r = req(KindId::Secret, "overmind", "subject", "x", true);
        let text = prompt_text(&r, &Grant::for_duration(Span::minutes(5)), t0());
        assert!(
            text.contains(KindId::Secret.name()) && text.contains("subject"),
            "{text}"
        );
    }

    #[test]
    fn sms_and_push_are_designed_for_but_cannot_ask_yet() {
        for ch in [&SmsChannel as &dyn Channel, &PushChannel] {
            assert!(matches!(
                ch.present(&bypass(), &Grant::Forever, WAIT),
                Outcome::Unavailable(_)
            ));
        }
    }

    /// user-request #5: the lane being answered is in what the person sees,
    /// and a request that names none is refused before any prompt.
    #[test]
    fn a_lane_dialog_prompt_names_the_lane_and_an_unbound_one_is_refused() {
        let subject = crate::request::lane_dialog_subject("fuel", "trust").unwrap();
        let bound = req(KindId::LaneDialogBypass, "pm", &subject, "r", true);
        let g = Grant::Forever;
        assert!(prompt_text(&bound, &g, t0()).contains("lane 'fuel', dialog 'trust'"));
        let ch = channel(|| ConsentOutcome::Approved, Span::minutes(1));
        assert!(matches!(ch.present(&bound, &g, WAIT), Outcome::Approved(_)));
        let bare = req(KindId::LaneDialogBypass, "pm", "trust", "r", true);
        assert!(matches!(ch.present(&bare, &g, WAIT), Outcome::Refused(_)));
    }
}
