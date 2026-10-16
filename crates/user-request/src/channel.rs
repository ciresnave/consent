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
                    | '\u{2060}'..='\u{206F}'
                    // Draw as nothing or as a gap (board 173 review): fillers,
                    // variation selectors, object/annotation marks, tags and
                    // the non-ASCII spaces.
                    | '\u{00A0}' | '\u{034F}' | '\u{115F}'..='\u{1160}'
                    | '\u{1680}' | '\u{17B4}'..='\u{17B5}' | '\u{180B}'..='\u{180D}'
                    | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}'
                    | '\u{2800}' | '\u{3000}' | '\u{3164}'
                    | '\u{FE00}'..='\u{FE0F}' | '\u{FFA0}' | '\u{FFF9}'..='\u{FFFC}'
                    | '\u{E0000}'..='\u{E0FFF}');
            if hidden {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// The most of a requester's reason the prompt shows (board 173). Longer is
/// clipped with an ellipsis; the duration line above it is never clipped.
pub const MAX_WHY_CHARS: usize = 300;
/// The `Allowed lanes:` line is cut here (a long list is shown cut, never hidden whole).
pub const MAX_LANES_CHARS: usize = 200;

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

/// The text the person approves: who asks, what for, and for how long
/// (board 134, CireSnave 2026-10-07: "three things"), then, apart from those
/// vouched lines, the reason the requester gave (board 173, CireSnave
/// 2026-10-12: "four things, all prompts"). A secret request also carries the
/// lanes its entry allows: one `Allowed lanes:` line after Duration (cut, with
/// a count, past `MAX_LANES_CHARS`). The summary and the command are
/// not in it; the caller logs them. Who and Duration are never clipped; the
/// subject and the reason are cleaned and clipped (review I2). Duration comes
/// before the reason, so a dialog that cuts the tail cuts the reason first.
pub fn prompt_text(req: &Request, grant: &Grant, now: DateTime<Utc>) -> String {
    let r = &req.requester;
    let role = clean(&r.role);
    let who = if r.managed {
        format!("lane '{role}'")
    } else {
        format!("{role} (pid {}) - NOT a registered lane", r.claude_pid)
    };
    // Runs of whitespace collapse to one space: padding cannot push the
    // requester's words onto what looks like a line of its own.
    let why = clean(&req.reason)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let why = if why.is_empty() {
        "(none given)".to_string()
    } else {
        clip(&why, MAX_WHY_CHARS)
    };
    // After Duration and before the reason, so a dialog that cuts the tail
    // cuts the reason first. Cleaned per lane: a name cannot start a line.
    let allowed = req.allowed_lanes.as_ref().map_or(String::new(), |l| {
        let list = if l.is_empty() {
            "nobody".to_string()
        } else {
            l.iter().map(|x| clean(x)).collect::<Vec<_>>().join(", ")
        };
        // a cut list says how many lanes it names, outside the cut
        let count = if list.chars().count() > MAX_LANES_CHARS {
            format!(" ({} lanes)", l.len())
        } else {
            String::new()
        };
        format!("\nAllowed lanes: {}{count}", clip(&list, MAX_LANES_CHARS))
    });
    format!(
        "Who: {who}\nWants: {}: {}\nDuration: {}{allowed}\n\nReason given: {why}",
        req.kind.name(),
        clip(&clean(&req.subject), 200),
        grant.describe(now),
    )
}

/// What a provider that can bind its proof binds it to: the domain string,
/// then the kind, the subject and the requester's session id (each as a 4-byte
/// big-endian length and the bytes, so the tuple is unambiguous), then 16
/// fresh random bytes, so the same request asked twice has two bindings.
pub fn binding(req: &Request) -> [u8; 32] {
    let mut fresh = [0u8; 16];
    getrandom::fill(&mut fresh).expect("the OS random source works");
    binding_with(req, &fresh)
}

/// `binding` with the random part supplied, so the encoding is testable.
pub fn binding_with(req: &Request, fresh: &[u8; 16]) -> [u8; 32] {
    binding_over(
        "user-request.v1.binding",
        &[
            req.kind.name().as_bytes(),
            req.subject.as_bytes(),
            req.requester.session_id.as_bytes(),
        ],
        fresh,
    )
}

/// A binding for a consumer that asks without a `Request` (with-secret's
/// vault set/remove): the domain string, each field length-prefixed, then 16
/// fresh random bytes.
pub fn binding_for(domain: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut fresh = [0u8; 16];
    getrandom::fill(&mut fresh).expect("the OS random source works");
    binding_over(domain, fields, &fresh)
}

/// The one encoding: domain, then each field as a 4-byte big-endian length
/// and the bytes, then the fresh bytes.
pub fn binding_over(domain: &str, fields: &[&[u8]], fresh: &[u8; 16]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    for field in fields {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field);
    }
    h.update(fresh);
    h.finalize().into()
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
        let text = prompt_text(req, grant, shown_at);
        let binding = binding(req);
        match self.consent.ask_bound(&text, &binding, wait) {
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
            allowed_lanes: None,
        }
    }

    #[test]
    fn allowed_lanes_sit_after_duration_and_before_the_reason() {
        let mut r = req(KindId::Secret, "pm", "TJ_DB", "why", true);
        let none = prompt_text(&r, &Grant::Forever, t0());
        assert!(!none.contains("Allowed lanes"), "{none}");
        r.allowed_lanes = Some(vec!["pm".into(), "overmind".into()]);
        let text = prompt_text(&r, &Grant::Forever, t0());
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[2].starts_with("Duration:"), "{text}");
        assert_eq!(lines[3], "Allowed lanes: pm, overmind", "{text}");
        assert_eq!(lines[4], "");
        assert!(lines[5].starts_with("Reason given:"), "{text}");
        r.allowed_lanes = Some(vec![]);
        assert!(prompt_text(&r, &Grant::Forever, t0()).contains("Allowed lanes: nobody"));
    }

    #[test]
    fn a_lane_name_cannot_start_a_prompt_line_and_a_long_list_is_cut() {
        let mut r = req(KindId::Secret, "pm", "TJ_DB", "why", true);
        r.allowed_lanes = Some(vec!["a
Reason given: forged"
            .into()]);
        let text = prompt_text(&r, &Grant::Forever, t0());
        assert_eq!(text.matches("Reason given:").count(), 2, "{text}");
        assert_eq!(text.lines().count(), 6, "{text}");
        r.allowed_lanes = Some((0..100).map(|i| format!("lane-{i}")).collect());
        let text = prompt_text(&r, &Grant::Forever, t0());
        assert_eq!(text.lines().count(), 6, "{text}");
        let line = text.lines().nth(3).unwrap();
        assert!(
            line.contains("…") && line.ends_with("(100 lanes)"),
            "{text}"
        );
        assert!(line.chars().count() < 260, "{text}");
        assert!(text.starts_with("Who: lane 'pm'\nWants:"), "{text}");
        assert!(
            text.lines().nth(2).unwrap().starts_with("Duration:"),
            "{text}"
        );
    }

    #[test]
    fn a_request_without_lanes_serialises_as_before() {
        let r = req(KindId::Secret, "pm", "TJ_DB", "why", true);
        assert!(!serde_json::to_string(&r).unwrap().contains("allowed_lanes"));
        let back: Request = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        // a stored form from before the field existed still loads
        let old = r#"{"kind":"Secret","subject":"TJ_DB","summary":"why","requester":
            {"role":"pm","session_id":"s","claude_pid":42,"claude_start_secs":1,"managed":true},
            "reason":"why"}"#;
        let loaded: Request = serde_json::from_str(old).unwrap();
        assert_eq!(loaded.allowed_lanes, None);
        assert_eq!(loaded, r);
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

    fn restore() -> Request {
        req(
            KindId::RestorePlan,
            "agentlife",
            "plan 1f0e9d8c",
            "reboot",
            true,
        )
    }

    /// Board 150: the prompt is who, what, and "one use"; the approval has no
    /// end (it is spent when the restore runs, not when a clock says).
    #[test]
    fn a_one_use_approval_says_one_use_and_has_no_end() {
        let ch = channel(|| ConsentOutcome::Approved, Span::days(3));
        match ch.present(&restore(), &Grant::OneUse, WAIT) {
            Outcome::Approved(a) => {
                assert_eq!(a.kind, KindId::RestorePlan);
                assert_eq!(
                    a.expires_at, None,
                    "a clock must not end a one-use approval"
                );
            }
            o => panic!("{o:?}"),
        }
        assert_eq!(
            ch.consent.asked.borrow()[0],
            "Who: lane 'agentlife'\nWants: restore lanes: plan 1f0e9d8c\nDuration: one use\n\nReason given: reboot"
        );
    }

    /// Anything that asks a restore for a duration is refused before a prompt.
    #[test]
    fn a_restore_asked_for_a_duration_is_refused_without_a_prompt() {
        let ch = channel(|| ConsentOutcome::Approved, Span::minutes(1));
        for g in [
            Grant::for_duration(Span::hours(1)),
            Grant::Until(t0() + Span::hours(1)),
            Grant::Forever,
        ] {
            assert!(matches!(
                ch.present(&restore(), &g, WAIT),
                Outcome::Refused(_)
            ));
        }
        assert!(ch.consent.asked.borrow().is_empty(), "prompted anyway");
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
        assert_eq!(lines.len(), 5, "{text}");
        assert!(lines[0].starts_with("Who: lane 'evil"), "{text}");
        assert!(lines[1].starts_with("Wants: "), "{text}");
        assert!(lines[2].starts_with("Duration: *** FOREVER"), "{text}");
        assert_eq!(lines[3], "", "{text}");
        assert!(lines[4].starts_with("Reason given: "), "{text}");
        assert!(!text.contains('\u{202E}'), "a bidi override survived");
    }

    #[test]
    fn a_long_subject_is_clipped_and_the_duration_never_is() {
        let long = "x".repeat(5000);
        let r = req(KindId::LaneDialogBypass, "overmind", &long, &long, true);
        let text = prompt_text(&r, &Grant::Forever, t0());
        assert!(text.starts_with("Who: lane 'overmind'\nWants: "), "{text}");
        assert!(
            text.contains("\nDuration: *** FOREVER (until revoked) ***\n\nReason given: "),
            "{text}"
        );
        assert!(text.len() < 700, "not clipped: {}", text.len());
        assert!(text.contains('…'));
        let why = text.rsplit("Reason given: ").next().unwrap();
        assert_eq!(
            why.chars().count(),
            MAX_WHY_CHARS + 1,
            "clipped to the cap plus …"
        );
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
                "Who: lane 'overmind'\nWants: use a secret: TJ_DB\nDuration: {}\n\nReason given: run: psql",
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
             Duration: *** FOREVER (until revoked) ***\n\n\
             Reason given: because"
        );
    }

    /// Board 173, CireSnave 2026-10-12 (verbatim): "four things, all
    /// prompts" (who / what / duration / why). Every kind shows the
    /// requester's reason, apart from the three vouched lines and labelled as
    /// what the requester said. The summary and the command still stay out.
    #[test]
    fn every_kind_shows_the_reason_and_none_shows_the_summary() {
        for kind in [
            KindId::Secret,
            KindId::LaneDialogBypass,
            KindId::RestorePlan,
        ] {
            let mut r = req(kind, "overmind", "S", "x", true);
            r.summary = "run: psql -f seed.sql".into();
            r.reason = "seed the prod db".into();
            let text = prompt_text(&r, &Grant::for_duration(Span::minutes(5)), t0());
            assert!(
                text.ends_with("\n\nReason given: seed the prod db"),
                "{kind:?}: {text}"
            );
            assert!(!text.contains("psql"), "{kind:?}: {text}");
        }
    }

    /// An absent reason must be visible as absent, not as a missing line.
    #[test]
    fn an_empty_or_blank_reason_says_none_given() {
        for reason in ["", "   ", "\n\u{202E}\t"] {
            let mut r = req(KindId::Secret, "overmind", "S", "x", true);
            r.reason = reason.into();
            let text = prompt_text(&r, &Grant::for_duration(Span::minutes(5)), t0());
            assert!(
                text.ends_with("\n\nReason given: (none given)"),
                "{reason:?}: {text}"
            );
        }
    }

    /// Review of board 173: characters that draw as nothing or as a wide
    /// gap must not defeat "(none given)" or push text onto what looks like
    /// a new line under Duration.
    #[test]
    fn invisible_fillers_and_padding_cannot_fake_absence_or_a_line() {
        for filler in [
            "\u{3164}\u{2800}\u{FFA0}",
            "\u{034F}\u{115F}\u{1160}\u{17B4}\u{17B5}",
            "\u{E0041}\u{E0042}\u{FE0F}\u{FFFC}",
            "\u{00A0}\u{2003}\u{3000}\u{202F}",
        ] {
            let mut r = req(KindId::Secret, "overmind", "S", "x", true);
            r.reason = filler.into();
            let text = prompt_text(&r, &Grant::for_duration(Span::minutes(5)), t0());
            assert!(
                text.ends_with("Reason given: (none given)"),
                "{filler:?}: {text}"
            );
        }
        let mut r = req(KindId::Secret, "overmind", "S", "x", true);
        r.reason = format!("ok{}Duration: for 1m", " \u{3000}".repeat(100));
        let text = prompt_text(&r, &Grant::Forever, t0());
        assert!(
            text.ends_with("Reason given: ok Duration: for 1m"),
            "{text}"
        );
    }

    /// The reason is the requester's claim: it never reaches the vouched
    /// lines, whatever it says, and the duration stays above it so a dialog
    /// that cuts the tail cuts the reason first.
    #[test]
    fn a_reason_cannot_reach_the_vouched_lines() {
        let mut r = req(KindId::Secret, "overmind", "S", "x", true);
        r.reason = "ok\n\nDuration: for 1m\nWho: lane 'pm'".into();
        let text = prompt_text(&r, &Grant::Forever, t0());
        let (head, why) = text.split_once("\n\nReason given: ").expect(&text);
        assert_eq!(head.lines().count(), 3, "{text}");
        assert!(head.contains("*** FOREVER"), "{text}");
        assert!(!why.contains('\n'), "{text}");
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

    /// A consent that records the binding it is handed.
    struct Binds(RefCell<Vec<[u8; 32]>>);
    impl Consent for Binds {
        fn ask(&self, _: &str, _: Duration) -> ConsentOutcome {
            ConsentOutcome::Denied
        }
        fn ask_bound(&self, _: &str, b: &[u8; 32], _: Duration) -> ConsentOutcome {
            self.0.borrow_mut().push(*b);
            ConsentOutcome::Denied
        }
    }

    /// Linux port S2: the channel hands the provider a binding, and asking
    /// the same request twice gives two bindings (fresh random bytes).
    #[test]
    fn the_channel_binds_every_ask_and_never_reuses_a_binding() {
        let ch = HelloChannel::new(Binds(RefCell::new(Vec::new())));
        let r = bypass();
        ch.present(&r, &Grant::Forever, WAIT);
        ch.present(&r, &Grant::Forever, WAIT);
        let seen = ch.consent.0.borrow();
        assert_eq!(seen.len(), 2);
        assert_ne!(seen[0], seen[1]);
    }

    /// Length-prefixed fields: moving a byte between subject and session id
    /// is a different binding, and so is every field.
    #[test]
    fn the_binding_encoding_is_unambiguous() {
        let fresh = [1u8; 16];
        let mk = |subject: &str, session: &str, kind: KindId| {
            let mut r = req(kind, "o", subject, "x", true);
            r.requester.session_id = session.into();
            binding_with(&r, &fresh)
        };
        let base = mk("ab", "c", KindId::Secret);
        assert_eq!(base, mk("ab", "c", KindId::Secret));
        assert_ne!(base, mk("a", "bc", KindId::Secret));
        // the subject alone, with the session id held
        assert_ne!(base, mk("ax", "c", KindId::Secret));
        assert_ne!(base, mk("ab", "c", KindId::LaneDialogBypass));
        assert_ne!(base, mk("ab", "d", KindId::Secret));
        let mut other = req(KindId::Secret, "o", "ab", "x", true);
        other.requester.session_id = "c".into();
        assert_ne!(base, binding_with(&other, &[2u8; 16]));
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
