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
}

impl KindId {
    /// Every kind, for checks that must cover all of them.
    pub const ALL: [KindId; 2] = [KindId::Secret, KindId::LaneDialogBypass];

    pub fn name(self) -> &'static str {
        match self {
            KindId::Secret => "use a secret",
            KindId::LaneDialogBypass => "auto-answer a lane startup dialog",
        }
    }

    pub fn max(self) -> MaxGrant {
        match self {
            // board 134 (CireSnave, 2026-10-07): the requester states how
            // long, the person sees the end (loudly when past today) and may
            // refuse. A stated length, never forever (PM ruling on #115 M4)
            KindId::Secret => MaxGrant::Finite,
            KindId::LaneDialogBypass => MaxGrant::Forever,
        }
    }

    pub fn scope(self) -> Scope {
        match self {
            KindId::Secret => Scope::ThisRequester,
            KindId::LaneDialogBypass => Scope::AnyRequester,
        }
    }
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

    /// When it ends if shown at `now`: `Ok(None)` for forever. Checked: a
    /// `For` too large to add is `Err`, never a panic.
    pub fn end_at(&self, now: DateTime<Utc>) -> Result<Option<DateTime<Utc>>, Unrepresentable> {
        match self {
            Grant::For { secs } => Duration::try_seconds(*secs)
                .and_then(|d| now.checked_add_signed(d))
                .map(Some)
                .ok_or(Unrepresentable),
            Grant::Until(t) => Ok(Some(*t)),
            Grant::Forever => Ok(None),
        }
    }

    /// Is it within `max`, shown at `now` (`now`'s time zone decides
    /// midnight)? A grant that ends before it starts, or whose end cannot
    /// be represented, is never within.
    pub fn within<Tz: TimeZone>(&self, max: MaxGrant, now: DateTime<Tz>) -> bool {
        let utc = now.with_timezone(&Utc);
        let Ok(end) = self.end_at(utc) else {
            return false;
        };
        if end.is_some_and(|e| e <= utc) {
            return false;
        }
        match (max, end) {
            (MaxGrant::Forever, _) => true,
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
}
