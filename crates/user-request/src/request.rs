// SPDX-License-Identifier: MIT OR Apache-2.0
//! What is asked, by whom, and for how long it may be granted.
//!
//! ⚠️ PM condition (a), 2026-10-04: the kinds are COMPILED IN. `KindId` is a
//! closed enum, and each kind's maximum grant is decided here, so no lane can
//! define a kind with a larger maximum. The kinds that can be granted
//! FOREVER are listed in the crate README; a test keeps the two in step.

use chrono::{DateTime, Duration, Local, TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// Who is asking. ⚠️ The caller takes it from the OS process table and
/// lane-state files, never from an argument (with-secret's `identity.rs`).
/// Moved unchanged from with-secret, which re-exports it: its approval cache
/// signs this exact serialised shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requester {
    pub role: String,
    pub session_id: String,
    pub claude_pid: u32,
    pub claude_start_secs: u64,
    pub managed: bool,
}

/// The longest grant a kind allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaxGrant {
    /// No later than the next local midnight (with-secret's ruling for
    /// secrets: "an approval now isn't still valid tomorrow").
    UntilLocalMidnight,
    /// No longer than this from the moment it is shown.
    For(Duration),
    /// Any stated end, however far, but never forever.
    Finite,
    /// Anything, including forever.
    Forever,
    /// One use, spent when the approved action runs: no length at all.
    OneUse,
}

/// Whether an approval belongs to the asking process only, or to anyone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// One requester (role, session, process); a lane restart voids it.
    ThisRequester,
    /// Any requester.
    AnyRequester,
}

/// The closed set of request kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KindId {
    /// with-secret: release one secret to one command.
    Secret,
    /// lane-restart: auto-answer a lane's startup dialog without asking.
    LaneDialogBypass,
    /// agentlife: restore the fleet from ONE frozen plan, once (board 150,
    /// CireSnave 2026-10-08: "One-shot."). Spent when the restore runs.
    RestorePlan,
}

impl KindId {
    /// Every kind, for checks that must cover all of them.
    pub const ALL: [KindId; 3] = [
        KindId::Secret,
        KindId::LaneDialogBypass,
        KindId::RestorePlan,
    ];

    pub fn name(self) -> &'static str {
        match self {
            KindId::Secret => "use a secret",
            KindId::LaneDialogBypass => "auto-answer a lane startup dialog",
            KindId::RestorePlan => "restore lanes",
        }
    }

    pub fn max(self) -> MaxGrant {
        match self {
            // board 134 (CireSnave, 2026-10-07): the requester states how
            // long, the person sees the end (loudly when past today) and may
            // refuse. A stated length, never forever (PM ruling on #115 M4)
            KindId::Secret => MaxGrant::Finite,
            KindId::LaneDialogBypass => MaxGrant::Forever,
            KindId::RestorePlan => MaxGrant::OneUse,
        }
    }

    pub fn scope(self) -> Scope {
        match self {
            KindId::Secret => Scope::ThisRequester,
            KindId::LaneDialogBypass => Scope::AnyRequester,
            // The plan hash is the binding, not the process: a restore after a
            // reboot is asked for by a NEW agentlife process, and that is the
            // case this kind exists for.
            KindId::RestorePlan => Scope::AnyRequester,
        }
    }
}

/// The longest a lane name or dialog id in a lane-dialog subject may be.
pub const MAX_LANE_DIALOG_PART_CHARS: usize = 64;

fn plain_part(p: &str) -> bool {
    !p.is_empty()
        && p.chars().count() <= MAX_LANE_DIALOG_PART_CHARS
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The subject of a `LaneDialogBypass` request: ONE lane's ONE dialog (PM
/// ruling on user-request #5, 2026-10-08: a FOREVER grant is the narrowest
/// thing that works, so it never covers every lane). The person is shown it
/// whole. Both parts are plain (no quote or comma), so neither can forge the
/// other.
pub fn lane_dialog_subject(lane: &str, dialog: &str) -> Result<String, String> {
    if !plain_part(lane) || !plain_part(dialog) {
        return Err(format!(
            "lane and dialog must each be 1 to {MAX_LANE_DIALOG_PART_CHARS} characters of letters, digits, '-', '_' or '.'"
        ));
    }
    Ok(format!("lane '{lane}', dialog '{dialog}'"))
}

/// The (lane, dialog) a subject names, if it is exactly the shape
/// `lane_dialog_subject` makes.
pub fn parse_lane_dialog_subject(subject: &str) -> Option<(&str, &str)> {
    let rest = subject.strip_prefix("lane '")?.strip_suffix("'")?;
    let (lane, dialog) = rest.split_once("', dialog '")?;
    (plain_part(lane) && plain_part(dialog)).then_some((lane, dialog))
}

/// The longest a plan hash in a restore-plan subject may be (a SHA-256 in hex
/// is 64; room is left for a longer digest).
pub const MAX_PLAN_HASH_CHARS: usize = 128;

/// Lowercase only: the store compares subjects case-folded, so two hashes that
/// differ only by case would otherwise be the same plan to `find` and `spend`
/// but different to `bound_hash`.
fn plain_hash(h: &str) -> bool {
    !h.is_empty()
        && h.chars().count() <= MAX_PLAN_HASH_CHARS
        && h.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'))
}

/// The subject of a `RestorePlan` request: the hash of ONE frozen plan (each
/// agent's id/name, cwd and rebuilt argv, permission mode included). The
/// person is shown it whole, and the pending request's `bound_hash` must be
/// the same string, so a plan that changed afterwards voids the request.
pub fn restore_plan_subject(plan_hash: &str) -> Result<String, String> {
    if !plain_hash(plan_hash) {
        return Err(format!(
            "a plan hash is 1 to {MAX_PLAN_HASH_CHARS} characters of lowercase letters, digits, '-', '_' or '.'"
        ));
    }
    Ok(format!("plan {plan_hash}"))
}

/// The plan hash a subject names, if it is exactly the shape
/// `restore_plan_subject` makes.
pub fn parse_restore_plan_subject(subject: &str) -> Option<&str> {
    subject.strip_prefix("plan ").filter(|h| plain_hash(h))
}

/// What the approver grants. A request-side choice: once approved, what is
/// kept is the ABSOLUTE end the person was shown (`Approval::expires_at`),
/// never this relative form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grant {
    /// For this long (seconds) from the moment it is shown.
    For { secs: i64 },
    /// Until this moment.
    Until(DateTime<Utc>),
    /// Until revoked.
    Forever,
    /// Once: spent when the approved action runs. Not a length.
    OneUse,
}

/// A grant whose end cannot be represented (a `For` that overflows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unrepresentable;

impl Grant {
    /// Whole seconds; a sub-second remainder is dropped.
    pub fn for_duration(d: Duration) -> Self {
        Grant::For {
            secs: d.num_seconds(),
        }
    }

    /// When it ends if shown at `now`: `Ok(None)` for NO END, which is both
    /// `Forever` and `OneUse` (a one-use grant is spent, not timed out): tell
    /// them apart by the variant, or by `KindId::max()`, never by `None`
    /// alone. Checked: a
    /// `For` too large to add is `Err`, never a panic.
    pub fn end_at(&self, now: DateTime<Utc>) -> Result<Option<DateTime<Utc>>, Unrepresentable> {
        match self {
            Grant::For { secs } => Duration::try_seconds(*secs)
                .and_then(|d| now.checked_add_signed(d))
                .map(Some)
                .ok_or(Unrepresentable),
            Grant::Until(t) => Ok(Some(*t)),
            Grant::Forever | Grant::OneUse => Ok(None),
        }
    }

    /// Is it within `max`, shown at `now` (`now`'s time zone decides
    /// midnight)? A grant that ends before it starts, or whose end cannot
    /// be represented, is never within.
    pub fn within<Tz: TimeZone>(&self, max: MaxGrant, now: DateTime<Tz>) -> bool {
        // One use has no end to compare: it fits a one-use kind and nothing
        // else, and a one-use kind takes nothing but one use (a length, a date
        // or forever is refused, never clamped).
        if matches!(self, Grant::OneUse) || max == MaxGrant::OneUse {
            return matches!(self, Grant::OneUse) && max == MaxGrant::OneUse;
        }
        let utc = now.with_timezone(&Utc);
        let Ok(end) = self.end_at(utc) else {
            return false;
        };
        if end.is_some_and(|e| e <= utc) {
            return false;
        }
        match (max, end) {
            (MaxGrant::Forever, _) => true,
            // handled above; a length is never one use
            (MaxGrant::OneUse, _) => false,
            (MaxGrant::Finite, end) => end.is_some(),
            (_, None) => false,
            (MaxGrant::For(d), Some(e)) => utc.checked_add_signed(d).is_some_and(|m| e <= m),
            (MaxGrant::UntilLocalMidnight, Some(e)) => e <= next_local_midnight(now),
        }
    }

    /// One line for the person, never clipped, naming the absolute end.
    /// FOREVER is loud on purpose (PM condition: Forever grants are shown in
    /// a distinct, loud form).
    pub fn describe(&self, now: DateTime<Utc>) -> String {
        if matches!(self, Grant::OneUse) {
            return "one use".to_string();
        }
        let local = |t: DateTime<Utc>| {
            t.with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        };
        let text = match (self, self.end_at(now)) {
            (_, Err(_)) => "an impossible duration (refused)".to_string(),
            (_, Ok(None)) => "*** FOREVER (until revoked) ***".to_string(),
            (Grant::For { secs }, Ok(Some(end))) => {
                let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
                format!("for {h}h {m:02}m {s:02}s, until {}", local(end))
            }
            (_, Ok(Some(end))) => format!("until {}", local(end)),
        };
        // board 134: an end past today is never approved by habit
        match self.end_at(now) {
            Ok(Some(end)) if end > next_local_midnight(now.with_timezone(&Local)) => {
                format!("*** LONGER THAN TODAY: {text} ***")
            }
            _ => text,
        }
    }
}

/// The next local midnight after `now`, in UTC.
///
/// ⚠️ On a day whose midnight does not exist locally (a DST gap at midnight,
/// e.g. Beirut, Santiago), this is the first valid instant after it, found
/// within three hours; failing that, `now + 1h` - SHORT, never long, the
/// same direction as with-secret's `approval::expiry` (review of #1: an
/// earlier fallback read local midnight as UTC and could run 3h late).
pub fn next_local_midnight<Tz: TimeZone>(now: DateTime<Tz>) -> DateTime<Utc> {
    let tz = now.timezone();
    let midnight = now
        .date_naive()
        .succ_opt()
        .expect("a date after today exists")
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists");
    (0..=180)
        .find_map(|m| {
            tz.from_local_datetime(&(midnight + Duration::minutes(m)))
                .earliest()
        })
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(|| now.with_timezone(&Utc) + Duration::hours(1))
}

/// One request to one person.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub kind: KindId,
    /// What it is about: a secret's name, a dialog handler's id, a plan hash.
    pub subject: String,
    /// What the person is shown about it (cleaned and clipped in the prompt).
    pub summary: String,
    pub requester: Requester,
    /// Why, in the requester's words (cleaned and clipped in the prompt).
    pub reason: String,
}

impl Request {
    /// Is the subject one this kind accepts? A `LaneDialogBypass` must name a
    /// lane, a `RestorePlan` one plan; other kinds take any subject.
    pub fn check_subject(&self) -> Result<(), String> {
        match self.kind {
            KindId::LaneDialogBypass if parse_lane_dialog_subject(&self.subject).is_none() => {
                Err("a lane dialog request must name one lane and one dialog".into())
            }
            KindId::RestorePlan if parse_restore_plan_subject(&self.subject).is_none() => {
                Err("a restore request must name one plan (subject 'plan <hash>')".into())
            }
            _ => Ok(()),
        }
    }
}

/// What an approval grants, with the ABSOLUTE end the person was shown, so
/// a later wait (or a store) can never stretch it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub kind: KindId,
    pub subject: String,
    pub requester: Requester,
    pub approved_at: DateTime<Utc>,
    /// `None` for forever.
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    /// 2026-10-07 h:m in Phoenix (UTC-7, no DST), host time zone irrelevant.
    fn at(h: u32, m: u32) -> DateTime<FixedOffset> {
        FixedOffset::west_opt(7 * 3600)
            .unwrap()
            .with_ymd_and_hms(2026, 10, 7, h, m, 0)
            .unwrap()
    }

    #[test]
    fn next_local_midnight_is_in_the_given_time_zone() {
        assert_eq!(
            next_local_midnight(at(18, 0)),
            Utc.with_ymd_and_hms(2026, 10, 8, 7, 0, 0).unwrap()
        );
    }

    /// Review C1: midnight does not exist in Beirut on 2026-03-29 (clocks go
    /// 00:00 EET -> 01:00 EEST). The day starts at 22:00Z, not 3h later.
    #[test]
    fn a_dst_gap_midnight_is_the_first_real_instant_of_the_day() {
        use chrono_tz::Asia::Beirut;
        let now = Beirut.with_ymd_and_hms(2026, 3, 28, 20, 0, 0).unwrap();
        assert_eq!(
            next_local_midnight(now),
            Utc.with_ymd_and_hms(2026, 3, 28, 22, 0, 0).unwrap()
        );
        // and a midnight maximum cannot outlive it
        let max = MaxGrant::UntilLocalMidnight;
        assert!(Grant::for_duration(Duration::hours(4)).within(max, now));
        assert!(!Grant::for_duration(Duration::hours(4) + Duration::seconds(1)).within(max, now));
    }

    /// Review C1, the western case: Santiago's 2026-09-06 midnight is a gap
    /// too (00:00 -04 -> 01:00 -03). The old fallback made it 20:00 local
    /// the evening before.
    #[test]
    fn a_dst_gap_west_of_utc_is_not_hours_early() {
        use chrono_tz::America::Santiago;
        let now = Santiago.with_ymd_and_hms(2026, 9, 5, 18, 0, 0).unwrap();
        assert_eq!(
            next_local_midnight(now),
            Utc.with_ymd_and_hms(2026, 9, 6, 4, 0, 0).unwrap()
        );
    }

    /// Board 134 (CireSnave, 2026-10-07): the requester states how long, the
    /// person sees it and may refuse; a secret has no compiled cap.
    #[test]
    fn a_secret_may_be_any_finite_length_but_never_forever() {
        // PM ruling on #115 M4 (2026-10-07): "as long of a time as it wants"
        // is a stated length; FOREVER is something CireSnave did not choose
        let now = at(18, 0);
        let max = KindId::Secret.max();
        assert_eq!(max, MaxGrant::Finite);
        assert!(Grant::Until(now.with_timezone(&Utc) + Duration::days(3650)).within(max, now));
        assert!(Grant::for_duration(Duration::days(30)).within(max, now));
        assert!(!Grant::Forever.within(max, now));
        // control: the dialog bypass still may be forever
        assert!(Grant::Forever.within(KindId::LaneDialogBypass.max(), now));
    }

    /// The midnight maximum still works for any kind that uses it.
    #[test]
    fn an_until_midnight_maximum_stops_at_midnight() {
        let now = at(18, 0);
        let max = MaxGrant::UntilLocalMidnight;
        let midnight = Utc.with_ymd_and_hms(2026, 10, 8, 7, 0, 0).unwrap();
        assert!(Grant::Until(midnight).within(max, now));
        assert!(!Grant::Until(midnight + Duration::seconds(1)).within(max, now));
        assert!(!Grant::Forever.within(max, now));
    }

    #[test]
    fn a_dialog_bypass_may_be_granted_forever() {
        assert!(Grant::Forever.within(KindId::LaneDialogBypass.max(), at(9, 0)));
    }

    #[test]
    fn a_for_maximum_is_measured_from_the_moment_of_showing() {
        let now = at(9, 0);
        let max = MaxGrant::For(Duration::hours(1));
        let utc = now.with_timezone(&Utc);
        assert!(Grant::for_duration(Duration::hours(1)).within(max, now));
        assert!(!Grant::for_duration(Duration::hours(1) + Duration::seconds(1)).within(max, now));
        assert!(Grant::Until(utc + Duration::hours(1)).within(max, now));
        assert!(!Grant::Until(utc + Duration::hours(2)).within(max, now));
        assert!(!Grant::Forever.within(max, now));
    }

    #[test]
    fn a_grant_that_ends_before_it_starts_is_never_within() {
        let now = at(9, 0);
        let past = now.with_timezone(&Utc) - Duration::minutes(1);
        assert!(!Grant::Until(past).within(MaxGrant::Forever, now));
        assert!(!Grant::For { secs: 0 }.within(MaxGrant::Forever, now));
        assert!(!Grant::For { secs: -60 }.within(MaxGrant::Forever, now));
    }

    /// Review I1: these panicked before.
    #[test]
    fn an_unrepresentable_grant_is_refused_not_a_panic() {
        let now = at(9, 0);
        for secs in [i64::MAX, 9_000_000_000_000, i64::MIN] {
            let g = Grant::For { secs };
            assert_eq!(g.end_at(now.with_timezone(&Utc)), Err(Unrepresentable));
            assert!(!g.within(MaxGrant::Forever, now), "{secs}");
            assert!(g.describe(now.with_timezone(&Utc)).contains("impossible"));
        }
    }

    #[test]
    fn end_of_each_grant() {
        let now = at(9, 0).with_timezone(&Utc);
        assert_eq!(
            Grant::for_duration(Duration::hours(1)).end_at(now),
            Ok(Some(now + Duration::hours(1)))
        );
        assert_eq!(Grant::Until(now).end_at(now), Ok(Some(now)));
        assert_eq!(Grant::Forever.end_at(now), Ok(None));
    }

    #[test]
    fn forever_is_described_loudly_and_nothing_else_is() {
        let now = at(9, 0).with_timezone(&Utc);
        assert!(Grant::Forever.describe(now).contains("FOREVER"));
        for g in [
            Grant::for_duration(Duration::hours(1)),
            Grant::Until(now + Duration::days(400)),
        ] {
            let d = g.describe(now);
            assert!(d.contains("until") && !d.contains("FOREVER"), "{d}");
        }
    }

    /// Board 134: an end after the next local midnight is described in a
    /// loud, distinct form; one within today is not.
    #[test]
    fn an_end_after_today_is_described_loudly() {
        let now = at(9, 0).with_timezone(&Utc);
        for g in [
            Grant::for_duration(Duration::hours(20)),
            Grant::Until(now + Duration::days(3)),
        ] {
            assert!(
                g.describe(now).contains("*** LONGER THAN TODAY"),
                "{}",
                g.describe(now)
            );
        }
        for g in [
            Grant::for_duration(Duration::hours(1)),
            Grant::Until(now + Duration::hours(2)),
        ] {
            assert!(
                !g.describe(now).contains("LONGER THAN TODAY"),
                "{}",
                g.describe(now)
            );
        }
        assert!(!Grant::Forever.describe(now).contains("LONGER THAN TODAY"));
    }

    #[test]
    fn short_grants_show_their_seconds() {
        let now = at(9, 0).with_timezone(&Utc);
        assert!(Grant::For { secs: 59 }.describe(now).contains("0h 00m 59s"));
    }

    /// PM condition (a): the README lists exactly the kinds that can be
    /// granted forever.
    #[test]
    fn the_readme_lists_exactly_the_forever_kinds() {
        let readme = include_str!("../README.md");
        let section = readme
            .split("### Kinds that can be granted forever")
            .nth(1)
            .expect("README section")
            .split("\n## ")
            .next()
            .unwrap();
        for k in KindId::ALL {
            let listed = section.contains(&format!("`{k:?}`"));
            assert_eq!(listed, k.max() == MaxGrant::Forever, "{k:?}");
        }
    }

    // -- RestorePlan (board 150, CireSnave 2026-10-08: "One-shot.") ----------

    /// A one-shot kind has no length: not a duration, not a date, never forever.
    #[test]
    fn a_restore_plan_is_one_use_and_nothing_longer() {
        let now = at(9, 0);
        let max = KindId::RestorePlan.max();
        assert_eq!(max, MaxGrant::OneUse);
        assert!(Grant::OneUse.within(max, now));
        assert!(!Grant::Forever.within(max, now));
        assert!(!Grant::for_duration(Duration::seconds(1)).within(max, now));
        assert!(!Grant::Until(now.with_timezone(&Utc) + Duration::hours(1)).within(max, now));
    }

    /// And a one-use grant is within no kind that is about a length: it must
    /// not slip past a `Finite` or `Forever` maximum as "no end".
    #[test]
    fn a_one_use_grant_is_not_within_any_other_kinds_maximum() {
        let now = at(9, 0);
        for max in [
            MaxGrant::Finite,
            MaxGrant::Forever,
            MaxGrant::UntilLocalMidnight,
            MaxGrant::For(Duration::hours(1)),
        ] {
            assert!(!Grant::OneUse.within(max, now), "{max:?}");
        }
        for k in KindId::ALL
            .into_iter()
            .filter(|k| *k != KindId::RestorePlan)
        {
            assert!(!Grant::OneUse.within(k.max(), now), "{k:?}");
        }
    }

    /// The person is shown "one use", never a time, and never FOREVER.
    #[test]
    fn a_one_use_grant_is_described_as_one_use() {
        let now = at(9, 0).with_timezone(&Utc);
        assert_eq!(Grant::OneUse.describe(now), "one use");
        assert_eq!(Grant::OneUse.end_at(now), Ok(None));
        // control: forever still shouts
        assert!(Grant::Forever.describe(now).contains("FOREVER"));
    }

    #[test]
    fn a_restore_plan_kind_is_listed_and_is_not_a_forever_kind() {
        assert!(KindId::ALL.contains(&KindId::RestorePlan));
        assert_ne!(KindId::RestorePlan.max(), MaxGrant::Forever);
        // the README test above keeps the forever list in step; RestorePlan
        // must not be on it
        let readme = include_str!("../README.md");
        let section = readme
            .split("### Kinds that can be granted forever")
            .nth(1)
            .unwrap()
            .split(
                "
## ",
            )
            .next()
            .unwrap();
        assert!(!section.contains("`RestorePlan`"));
    }

    /// The subject names the plan hash and nothing else, so the person sees
    /// exactly what was frozen and it can be compared with `bound_hash`.
    #[test]
    fn a_restore_plan_subject_names_one_plan_hash() {
        let h = "a".repeat(64);
        let s = restore_plan_subject(&h).unwrap();
        assert_eq!(s, format!("plan {h}"));
        assert_eq!(parse_restore_plan_subject(&s), Some(h.as_str()));
        for bad in ["", "has space", "quo'te", "comma,", "../x", "AbC", "ABC123"] {
            assert!(restore_plan_subject(bad).is_err(), "{bad:?}");
        }
        assert!(restore_plan_subject(&"a".repeat(MAX_PLAN_HASH_CHARS + 1)).is_err());
        assert!(restore_plan_subject(&"a".repeat(MAX_PLAN_HASH_CHARS)).is_ok());
        // a bare hash, or a forged second plan, is not a plan subject
        assert_eq!(parse_restore_plan_subject(&h), None);
        assert_eq!(
            parse_restore_plan_subject(&format!("plan {h} plan {h}")),
            None
        );
        assert_eq!(parse_restore_plan_subject("plan "), None);
    }

    #[test]
    fn a_restore_plan_request_must_name_a_plan() {
        let r = |subject: &str| Request {
            kind: KindId::RestorePlan,
            subject: subject.into(),
            summary: String::new(),
            requester: Requester {
                role: "agentlife".into(),
                session_id: "s".into(),
                claude_pid: 1,
                claude_start_secs: 1,
                managed: false,
            },
            reason: String::new(),
        };
        assert!(r("everything").check_subject().is_err());
        assert!(r("plan abc123").check_subject().is_ok());
    }

    /// PM ruling on user-request #5 (2026-10-08): a LaneDialogBypass grant is
    /// for ONE lane. The lane is part of the subject the person is shown.
    #[test]
    fn a_lane_dialog_subject_names_the_lane_and_the_dialog() {
        let s = lane_dialog_subject("fuel", "trust").unwrap();
        assert_eq!(s, "lane 'fuel', dialog 'trust'");
        assert_eq!(parse_lane_dialog_subject(&s), Some(("fuel", "trust")));
    }

    #[test]
    fn a_lane_dialog_subject_cannot_forge_another_lane_or_omit_it() {
        assert!(lane_dialog_subject("fuel', dialog 'x", "trust").is_err());
        assert!(lane_dialog_subject("", "trust").is_err());
        assert!(lane_dialog_subject("fuel", "").is_err());
        assert!(lane_dialog_subject(&"a".repeat(65), "trust").is_err());
        // a bare handler id (the pre-#5 subject) names no lane
        assert_eq!(parse_lane_dialog_subject("trust"), None);
        assert_eq!(
            parse_lane_dialog_subject("lane 'a', dialog 'b', dialog 'c'"),
            None
        );
    }

    #[test]
    fn only_a_lane_dialog_request_must_name_a_lane() {
        let r = |kind, subject: &str| Request {
            kind,
            subject: subject.into(),
            summary: String::new(),
            requester: Requester {
                role: "pm".into(),
                session_id: "s".into(),
                claude_pid: 1,
                claude_start_secs: 1,
                managed: true,
            },
            reason: String::new(),
        };
        assert!(r(KindId::LaneDialogBypass, "trust")
            .check_subject()
            .is_err());
        assert!(r(KindId::LaneDialogBypass, "lane 'fuel', dialog 'trust'")
            .check_subject()
            .is_ok());
        assert!(r(KindId::Secret, "TJ_DB").check_subject().is_ok());
    }
}
