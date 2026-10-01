// SPDX-License-Identifier: MIT OR Apache-2.0
//! Approvals - CireSnave 2026-09-28: "Approve once per lane per secret with a
//! timeout so that an approval now isn't still valid tomorrow."
//!
//! ⚠️ The cache is HMAC-signed with a DPAPI-protected key, so an entry that a
//! lane writes BY ACCIDENT (or a hand edit) is ignored. A deliberate same-user
//! process can read the key and forge one (design §3).

use std::path::Path;

use chrono::{DateTime, Duration, Local, TimeZone, Utc};
use hmac::{Hmac, KeyInit, Mac};
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
    let next_midnight = (granted.date_naive() + Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .unwrap();
    // ⚠️ If local midnight does not exist (a DST gap), fall back SHORT - one
    // hour - never long.
    let midnight = Local
        .from_local_datetime(&next_midnight)
        .earliest()
        .unwrap_or(granted + Duration::hours(1));
    let end = match window {
        Some(w) if granted + w < midnight => granted + w,
        _ => midnight,
    };
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
struct Signed {
    approval: Approval,
    mac: String,
}

pub struct ApprovalCache {
    key: Vec<u8>,
    pub entries: Vec<Approval>,
}

fn mac(key: &[u8], a: &Approval) -> String {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(&serde_json::to_vec(a).expect("Approval serialises"));
    m.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl ApprovalCache {
    /// Returns the cache and how many entries were REJECTED (bad MAC or
    /// unreadable). A missing or corrupt file is an empty cache: the cost is
    /// one more consent prompt, never a wrongly-honoured approval.
    pub fn load(path: &Path, key: Vec<u8>) -> (Self, usize) {
        let signed: Vec<Signed> = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let total = signed.len();
        let entries: Vec<Approval> = signed
            .into_iter()
            .filter(|s| mac(&key, &s.approval) == s.mac)
            .map(|s| s.approval)
            .collect();
        let rejected = total - entries.len();
        (Self { key, entries }, rejected)
    }

    pub fn find(&self, secret: &str, who: &Requester, now: DateTime<Utc>) -> Option<&Approval> {
        self.entries.iter().find(|a| a.covers(secret, who, now))
    }

    pub fn add(&mut self, a: Approval) {
        self.entries.push(a);
    }

    pub fn save(&self, path: &Path, now: DateTime<Utc>) -> Result<(), String> {
        let signed: Vec<Signed> = self
            .entries
            .iter()
            .filter(|a| a.expires_at > now)
            .map(|a| Signed {
                approval: a.clone(),
                mac: mac(&self.key, a),
            })
            .collect();
        write_atomic(
            path,
            &serde_json::to_vec_pretty(&signed).map_err(|e| e.to_string())?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Local, TimeZone};

    fn who(pid: u32, session: &str) -> Requester {
        Requester {
            role: "humboldt".into(),
            session_id: session.into(),
            claude_pid: pid,
            claude_start_secs: 100,
            managed: true,
        }
    }
    fn local(h: u32, m: u32) -> chrono::DateTime<Local> {
        Local
            .with_ymd_and_hms(2026, 10, 1, h, m, 0)
            .single()
            .unwrap()
    }
    fn approval(at: chrono::DateTime<Local>, window: Option<Duration>) -> Approval {
        Approval {
            secret: "TJ_DB".into(),
            requester: who(10, "s-1"),
            granted_at: at.with_timezone(&Utc),
            expires_at: expiry(at, window),
        }
    }

    #[test]
    fn expires_at_local_midnight_by_default() {
        assert_eq!(
            expiry(local(9, 0), None),
            Local
                .with_ymd_and_hms(2026, 10, 2, 0, 0, 0)
                .single()
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn test_late_grant_expires_at_midnight() {
        let e = expiry(local(23, 50), Some(Duration::hours(4)));
        assert_eq!(
            e,
            Local
                .with_ymd_and_hms(2026, 10, 2, 0, 0, 0)
                .single()
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn a_shorter_window_wins() {
        assert_eq!(
            expiry(local(9, 0), Some(Duration::minutes(30))),
            (local(9, 0) + Duration::minutes(30)).with_timezone(&Utc)
        );
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
        assert!(
            !a.covers(
                "TJ_DB",
                &who(10, "s-1"),
                local(9, 0).with_timezone(&Utc) + Duration::days(1)
            ),
            "tomorrow"
        );
        assert!(
            !a.covers("TJ_DB", &who(10, "s-1"), local(8, 0).with_timezone(&Utc)),
            "before it was granted - a clock moved backwards"
        );
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
        assert!(back
            .find("TJ_DB", &who(10, "s-1"), local(10, 0).with_timezone(&Utc))
            .is_some());
    }

    #[test]
    fn test_tampered_entry_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("approvals.json");
        let mut c = ApprovalCache::load(&path, b"k".repeat(32)).0;
        c.add(approval(local(9, 0), None));
        c.save(&path, local(10, 0).with_timezone(&Utc)).unwrap();
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("humboldt", "fuel");
        std::fs::write(&path, text).unwrap();
        let (back, rejected) = ApprovalCache::load(&path, b"k".repeat(32));
        assert_eq!(rejected, 1);
        let mut fuel = who(10, "s-1");
        fuel.role = "fuel".into();
        assert!(back
            .find("TJ_DB", &fuel, local(10, 0).with_timezone(&Utc))
            .is_none());
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
        assert!(ApprovalCache::load(&path, b"k".repeat(32))
            .0
            .entries
            .is_empty());
    }
}
