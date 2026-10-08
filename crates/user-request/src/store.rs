// SPDX-License-Identifier: MIT OR Apache-2.0
//! The approvals store (plan step #2) and the prompt gate (the brute-force
//! audit, row 1: "approval fatigue").
//!
//! In one directory (by default `%LOCALAPPDATA%\OverMind\user-request`):
//! - `store.key`, `store.key.check`: the HMAC key, DPAPI-protected, and a
//!   value that tells the right key from a wrong one;
//! - `grants.json`: approvals and revocation tombstones;
//! - `attempts.json`: recent prompts and how they ended (or that they are
//!   still pending);
//! - `audit.jsonl`: every save, grant, revocation, gate decision, alert and
//!   integrity finding, hash-chained, with the chain's head ALSO written to a
//!   second file (PM condition (d));
//! - `store.lock`: an OS file lock, held from `open` until the `Store` is
//!   dropped, so one process at a time reads, changes and writes.
//!
//! A grant is made only by `resolve`, from the channel's approval of a
//! reservation, and only within its kind's maximum (review I4). Every
//! public method that changes something saves before it returns (review
//! I-B). ⚠️ Drop the `Store` before showing a prompt: holding it holds the
//! lock.
//!
//! ⚠️ The audit chain is the store's integrity anchor. On `open`:
//! - the chain must be intact and agree with its head copy;
//! - each file must be one a save recorded (the last one, or one written
//!   since by a save that did not finish);
//! - no integrity problem may be on record since the last repair.
//!
//! Anything else makes the store UNTRUSTWORTHY, and it fails CLOSED: no
//! grant is honoured and the gate refuses. The finding is written to the
//! audit log, so no later save can launder it (review C-B): revoking still
//! works, but only `repair` restores trust, and repair REVOKES EVERY GRANT
//! and closes the gate for an hour. It only removes privilege, so it needs
//! no Hello. A file that is only briefly unreadable (an antivirus scan, a
//! backup) is retried, and if it stays unreadable `open` fails and asks for
//! a retry, recording nothing (review 3, I2).
//!
//! ⚠️ Honest limit (WITH-SECRET-DESIGN.md §3): a process running as the same
//! Windows user can read the DPAPI key and rewrite the files, the chain and
//! its head copy consistently. All of this catches accidents, buggy lanes
//! and naive edits, not that.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{DateTime, Duration, Local, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::channel::Outcome;
use crate::request::{Approval, Grant, KindId, Request, Requester, Scope};

/// Encrypts the store's key at rest (`dpapi::Dpapi` in production).
pub trait Protector {
    fn protect(&self, plain: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, blob: &[u8]) -> Result<Vec<u8>, String>;
}

/// Tells a person something needs their attention. ⚠️ DELIVERY is not built:
/// where alerts go waits on board item 131 (SECURITY_ALERT_EMAIL does not
/// exist yet). Every alert is ALSO written to the audit log by the store,
/// whatever the sink does (except under an untrusted key, when nothing is
/// written).
pub trait Alert {
    fn alert(&self, what: &str);
}

/// No delivery; the audit log is the only record.
pub struct AuditOnly;
impl Alert for AuditOnly {
    fn alert(&self, _: &str) {}
}

/// After a denial or a timeout, the same role may not ask about the same
/// subject again for this long.
pub const DENIAL_COOLDOWN: Duration = Duration::minutes(10);
/// At most this many prompts per role per rolling hour.
pub const PROMPTS_PER_HOUR: usize = 6;
/// At most this many prompts per rolling hour in front of the person, from
/// every role together (review I9: the cap protects a person, not a role).
pub const PROMPTS_PER_HOUR_FOR_THE_PERSON: usize = 20;
/// This many denials or timeouts for one role in an hour raise an alert.
pub const DENIALS_BEFORE_ALERT: usize = 3;
/// After a repair, the gate refuses every prompt for this long.
pub const GATE_CLOSED_AFTER_REPAIR: Duration = Duration::hours(1);
/// A reservation older than this can no longer be resolved: no channel
/// waits that long (Hello waits at most 9 minutes).
pub const RESERVATION_TTL: Duration = Duration::minutes(15);
/// How long `open` waits for another process's lock before giving up.
pub const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(15);
/// How long a read or rename that fails (a file briefly held by an
/// antivirus scan or a backup) is retried.
const RETRY_FOR: std::time::Duration = std::time::Duration::from_secs(2);

// A repair that drops the gate's memory (a lost key) must not shorten any
// of its windows (review 3, M5).
const _: () = assert!(DENIAL_COOLDOWN.num_seconds() <= GATE_CLOSED_AFTER_REPAIR.num_seconds());
const _: () = assert!(3600 <= GATE_CLOSED_AFTER_REPAIR.num_seconds());

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGrant {
    /// 128 random bits, hex.
    pub id: String,
    pub approval: Approval,
}

/// How a prompt ended. A closed set (review I-C): no caller can invent an
/// outcome the gate does not count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ended {
    /// The person has not answered yet.
    Pending,
    Approved,
    Denied,
    TimedOut,
    /// The channel could not ask.
    Unavailable,
    /// Not asked, or no longer answerable: the channel refused to ask, or a
    /// repair or `revoke_all` ended the reservation.
    NotAsked,
    /// Not a prompt: an alert was raised (one per role and reason per hour).
    Alerted,
    /// Not a prompt: the store was repaired, which closes the gate.
    Repaired,
}

impl Ended {
    fn name(self) -> &'static str {
        match self {
            Ended::Pending => "pending",
            Ended::Approved => "approved",
            Ended::Denied => "denied",
            Ended::TimedOut => "timed-out",
            Ended::Unavailable => "unavailable",
            Ended::NotAsked => "not-asked",
            Ended::Alerted => "alerted",
            Ended::Repaired => "repaired",
        }
    }

    /// The person said no, or did not answer.
    fn is_refusal(self) -> bool {
        matches!(self, Ended::Denied | Ended::TimedOut)
    }

    /// Counts toward the hourly caps.
    fn is_prompt(self) -> bool {
        !matches!(self, Ended::Alerted | Ended::Repaired)
    }
}

/// One prompt, from the gate's reservation to its answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// 128 random bits, hex.
    pub id: String,
    pub at: DateTime<Utc>,
    pub requester: Requester,
    pub kind: KindId,
    /// Normalised (`normal_subject`), so `DB`, `db` and `DB ` share a cooldown.
    pub subject: String,
    pub outcome: Ended,
    /// The durable pending request this prompt answers, if any (`pending.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<String>,
}

/// What `may_ask` hands back: the pending attempt to resolve once the person
/// has answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub attempt_id: String,
}

/// What `verify_audit` found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReport {
    /// Lines in the log.
    pub lines: usize,
    /// Lines checked: those from the last chain reset on.
    pub checked: usize,
    /// Chain resets that a later repair acknowledged.
    pub repaired_resets: usize,
    /// How many lines the head copy is behind the log (0: it agrees).
    pub head_behind: usize,
}

/// What `repair` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairReport {
    /// Grants it revoked.
    pub revoked: usize,
    /// False when some grants could not be read (a lost key, a file set
    /// aside): those are gone, and were never counted (review 3, M1).
    pub grants_known: bool,
    /// Files moved aside, now or when the store was opened.
    pub set_aside: Vec<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct GrantsFile {
    grants: Vec<StoredGrant>,
    /// Ids revoked; kept so an old copy of a grant cannot come back.
    revoked: BTreeSet<String>,
    /// Pending prompts a revocation ended, with their reservation time.
    /// Written with the tombstones, in the file written FIRST, so a
    /// revocation whose prompts file was never written still ends them
    /// (second review of #2b, finding 4). Absent in older files.
    #[serde(default)]
    ended: BTreeMap<String, DateTime<Utc>>,
    /// Requests nobody has answered yet; they outlive the process, the
    /// reboot and the day (`pending.rs`). Absent in older files.
    #[serde(default)]
    pending: Vec<PendingRequest>,
}

#[derive(Serialize, Deserialize)]
struct Header {
    seq: u64,
    mac: String,
}

#[derive(Serialize, Deserialize)]
struct AuditLine {
    prev: String,
    at: DateTime<Utc>,
    event: String,
    detail: String,
}

/// Why the store cannot be trusted right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Untrusted {
    /// The key is missing, did not decrypt, or decrypted to the wrong bytes.
    Key(String),
    /// A file or the audit chain is not what it should be, now or at some
    /// point since the last repair.
    Files(String),
}

/// Why the chain could not be confirmed.
enum ChainError {
    /// It is broken, truncated, torn or disagrees with its head copy.
    Broken(String),
    /// It could not be read right now; nothing should be concluded.
    Io(String),
}

/// The store. Its state is read through methods only (review 3, I4): no
/// caller can clear a tombstone or the untrusted flag and then save.
pub struct Store {
    dir: PathBuf,
    key: Vec<u8>,
    head_copy: Option<PathBuf>,
    seq: u64,
    grants: Vec<StoredGrant>,
    revoked: BTreeSet<String>,
    ended: BTreeMap<String, DateTime<Utc>>,
    pending: Vec<PendingRequest>,
    attempts: Vec<Attempt>,
    untrusted: Option<Untrusted>,
    /// `grants.json` was there but could not be read under this key.
    grants_unreadable: bool,
    set_aside: Vec<String>,
    /// Opened by `inspect`: nothing is written, not even a finding.
    read_only: bool,
    _lock: StoreLock,
}

/// The files whose presence means a store exists.
const DATA_FILES: [&str; 3] = ["grants.json", "attempts.json", "audit.jsonl"];

impl Store {
    /// Opens the store in `dir`, creating it if it does not exist, and holds
    /// its lock until the `Store` is dropped. `head_copy` is the second
    /// place the audit chain's head is written.
    pub fn open(
        dir: &Path,
        protector: &dyn Protector,
        head_copy: Option<PathBuf>,
    ) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        Self::open_in(dir, protector, head_copy, false)
    }

    /// Like `open`, but `None` when there is no store yet, which it never
    /// creates (review M2, M5). A store whose key is gone but whose data is
    /// not still exists (review I-F).
    pub fn open_existing(
        dir: &Path,
        protector: &dyn Protector,
        head_copy: Option<PathBuf>,
    ) -> Result<Option<Self>, String> {
        if !exists(dir) {
            return Ok(None);
        }
        Self::open_in(dir, protector, head_copy, false).map(Some)
    }

    /// Opens an existing store to look at it: nothing is written, moved or
    /// recorded, so an older binary never sets aside a newer one's files
    /// (review 3, M4). Every change is refused. The one exception is
    /// `store.lock`, created if it is missing.
    pub fn inspect(
        dir: &Path,
        protector: &dyn Protector,
        head_copy: Option<PathBuf>,
    ) -> Result<Option<Self>, String> {
        if !exists(dir) {
            return Ok(None);
        }
        Self::open_in(dir, protector, head_copy, true).map(Some)
    }

    fn open_in(
        dir: &Path,
        protector: &dyn Protector,
        head_copy: Option<PathBuf>,
        read_only: bool,
    ) -> Result<Self, String> {
        let lock = StoreLock::acquire(&dir.join("store.lock"))?;
        let key_path = dir.join("store.key");
        let check_path = dir.join("store.key.check");
        let mut untrusted = None;
        let key = match read_retry(&key_path) {
            Ok(blob) => match protector.unprotect(&blob) {
                Ok(k) => k,
                Err(e) => {
                    untrusted = Some(Untrusted::Key(format!("the key did not decrypt: {e}")));
                    Vec::new()
                }
            },
            // a key is created only for a store that has nothing yet (review
            // M2, I-F): a lost key must never look like a fresh install
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if DATA_FILES.iter().any(|n| dir.join(n).exists()) || read_only {
                    untrusted = Some(Untrusted::Key(
                        "store.key is missing but the store has data".into(),
                    ));
                    Vec::new()
                } else {
                    new_key(dir, protector)?
                }
            }
            Err(e) => {
                return Err(format!(
                    "{} cannot be read right now ({e}); try again",
                    key_path.display()
                ))
            }
        };
        let mut store = Self {
            dir: dir.to_path_buf(),
            key,
            head_copy,
            seq: 0,
            grants: Vec::new(),
            revoked: BTreeSet::new(),
            ended: BTreeMap::new(),
            pending: Vec::new(),
            attempts: Vec::new(),
            untrusted,
            grants_unreadable: false,
            set_aside: Vec::new(),
            read_only,
            _lock: lock,
        };
        if store.untrusted.is_none() {
            store.load(&check_path, Utc::now())?;
        }
        Ok(store)
    }

    fn load(&mut self, check_path: &Path, now: DateTime<Utc>) -> Result<(), String> {
        let grants = read_signed(&self.dir.join("grants.json"), &self.key)?;
        let attempts = read_signed(&self.dir.join("attempts.json"), &self.key)?;
        // the key check: a match, or (missing check, review I2) files that
        // verify under this key, which proves it is the right one
        // every read retries a file held for a moment (an antivirus scan);
        // one held longer fails the open, and nothing is concluded or
        // recorded from it (review 3, I2)
        let check = match read_retry(check_path) {
            Ok(b) => Some(String::from_utf8_lossy(&b).into_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(format!(
                    "{} cannot be read right now ({e}); try again",
                    check_path.display()
                ))
            }
        };
        let verified_any =
            matches!(grants, Signed::Good { .. }) || matches!(attempts, Signed::Good { .. });
        let nothing_yet = grants == Signed::Missing && attempts == Signed::Missing;
        match check {
            Some(c) if c == mac(&self.key, KEY_CHECK.as_bytes()) => {}
            Some(_) => {
                self.untrusted = Some(Untrusted::Key(
                    "the key decrypted to bytes that are not this store's key".into(),
                ));
                return Ok(());
            }
            None if verified_any || nothing_yet => {
                if !self.read_only {
                    write_atomic(check_path, mac(&self.key, KEY_CHECK.as_bytes()).as_bytes())?;
                }
            }
            None => {
                self.untrusted = Some(Untrusted::Key(
                    "the key check is missing and nothing verifies".into(),
                ));
                return Ok(());
            }
        }
        let mut problems = Vec::new();
        // the chain and its head copy first (review C-A): a whole-directory
        // rollback or wipe leaves files that match their own log
        match self.check_chain() {
            Ok(_) => {}
            Err(ChainError::Broken(why)) => problems.push(why),
            Err(ChainError::Io(why)) => return Err(format!("{why}; try again")),
        }
        // read once, so a log that turns unreadable between two reads cannot
        // look like "no save recorded" (review 4, M-g)
        let log = match read_retry(&self.dir.join("audit.jsonl")) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(format!(
                    "the audit log cannot be read right now ({e}); try again"
                ))
            }
        };
        let expected = recorded_hashes(&log);
        for (name, file) in [("grants.json", &grants), ("attempts.json", &attempts)] {
            let want = expected.as_ref().and_then(|e| e.get(name));
            match (file, want) {
                (Signed::Bad, _) => {
                    let to = self.set_aside(name);
                    problems.push(format!("{name} failed its signature ({to})"));
                }
                (Signed::Good { sha, .. }, Some(want)) if !want.contains(sha) => {
                    problems.push(format!("{name} is not a file a save recorded"))
                }
                (Signed::Good { .. }, None) => {
                    problems.push(format!("{name} has no save recorded in the audit log"))
                }
                (Signed::Missing, Some(_)) => problems.push(format!("{name} is missing")),
                _ => {}
            }
        }
        if grants == Signed::Bad {
            self.grants_unreadable = true;
        }
        // a body that verifies but does not parse (a newer or older schema)
        // is set aside, never a reason open fails: revoking must always work
        // (review I-H)
        if let Signed::Good { seq, body, .. } = grants {
            match serde_json::from_slice::<GrantsFile>(&body) {
                Ok(g) => {
                    self.grants = g.grants;
                    self.revoked = g.revoked;
                    self.ended = g.ended;
                    self.pending = g.pending;
                    self.seq = seq;
                }
                Err(e) => {
                    self.grants_unreadable = true;
                    let to = self.set_aside("grants.json");
                    problems.push(format!("grants.json did not parse: {e} ({to})"));
                }
            }
        }
        if let Signed::Good { seq, body, .. } = attempts {
            match serde_json::from_slice::<Vec<Attempt>>(&body) {
                Ok(a) => {
                    self.attempts = a;
                    self.seq = self.seq.max(seq);
                }
                Err(e) => {
                    let to = self.set_aside("attempts.json");
                    problems.push(format!("attempts.json did not parse: {e} ({to})"));
                }
            }
        }
        let on_record = unrepaired_finding(&log);
        if problems.is_empty() && on_record.is_none() {
            return Ok(());
        }
        let mut why = problems.join("; ");
        if !problems.is_empty() && on_record.is_none() && !self.read_only {
            // recorded, so no later save can launder it (review C-B), and
            // alerted once in the log; best effort: the store is untrusted in
            // memory either way
            let _ = self.audit(now, "untrusted", &why);
            let _ = self.audit(
                now,
                "ALERT",
                &format!("the store became untrustworthy: {why}"),
            );
        }
        if let Some(earlier) = on_record {
            if !why.is_empty() {
                why.push_str("; ");
            }
            why.push_str(&format!("not repaired since {earlier}"));
        }
        self.untrusted = Some(Untrusted::Files(why));
        Ok(())
    }

    /// Moves a file aside (unless read-only) and says where it went.
    fn set_aside(&mut self, name: &str) -> String {
        if self.read_only {
            return "left in place: opened read-only".into();
        }
        let to = quarantine(&self.dir.join(name));
        self.set_aside.push(to.clone());
        format!("kept as {to}")
    }

    /// Why the store cannot be trusted, or `None` when it can.
    pub fn untrusted(&self) -> Option<&Untrusted> {
        self.untrusted.as_ref()
    }

    /// `Ok` when grants may be honoured and the gate trusted.
    pub fn trustworthy(&self) -> Result<(), String> {
        match &self.untrusted {
            None => Ok(()),
            Some(Untrusted::Key(why)) | Some(Untrusted::Files(why)) => Err(format!(
                "the store cannot be trusted: {why} (`user-request repair` revokes every \
                 grant and restores it)"
            )),
        }
    }

    /// False when some grants could not be read: under an untrusted key, or
    /// from a grants file that failed its check.
    pub fn grants_known(&self) -> bool {
        !matches!(self.untrusted, Some(Untrusted::Key(_))) && !self.grants_unreadable
    }

    /// Files moved aside since this store was opened.
    pub fn files_set_aside(&self) -> &[String] {
        &self.set_aside
    }

    /// Every stored grant, revoked and expired ones included.
    pub fn grants(&self) -> &[StoredGrant] {
        &self.grants
    }

    /// The ids of revoked grants.
    pub fn revoked(&self) -> &BTreeSet<String> {
        &self.revoked
    }

    /// Recent prompts, alerts and repairs.
    pub fn attempts(&self) -> &[Attempt] {
        &self.attempts
    }

    fn writable(&self) -> Result<(), String> {
        if self.read_only {
            return Err("the store was opened read-only".into());
        }
        Ok(())
    }

    /// Writes grants and attempts (expired grants and attempts older than a
    /// day are dropped). The hashes are recorded first (`saving`) and the
    /// completion after (`saved`), so a save cut short between the two
    /// files is recognised as ours. Refused when the key is untrusted, so
    /// the real store is never overwritten. A store whose FILES are
    /// untrusted may save (that is how a revocation lands) but stays
    /// untrusted: only `repair` restores trust.
    pub(crate) fn save(&mut self, now: DateTime<Utc>) -> Result<(), String> {
        self.save_ordered(now, false)
    }

    /// `save`, with the files written in the order that keeps a save cut
    /// short between them safe for this operation (review 6, m-3): grants
    /// first where privilege is REMOVED (a revocation lands even if the
    /// prompts file cannot be written), prompts first where it is ADDED (an
    /// approval never leaves a grant whose prompt is still open, review 5,
    /// I-1).
    fn save_ordered(&mut self, now: DateTime<Utc>, attempts_first: bool) -> Result<(), String> {
        self.writable()?;
        if let Some(Untrusted::Key(why)) = &self.untrusted {
            return Err(format!("refusing to save: {why}"));
        }
        self.seq += 1;
        let grants = GrantsFile {
            grants: self
                .grants
                .iter()
                .filter(|g| live(g, now))
                .cloned()
                .collect(),
            revoked: self.revoked.clone(),
            // kept as long as the attempts themselves are
            ended: self
                .ended
                .iter()
                .filter(|(_, at)| **at > now - Duration::days(1))
                .map(|(id, at)| (id.clone(), *at))
                .collect(),
            pending: self.pending.clone(),
        };
        let attempts: Vec<&Attempt> = self
            .attempts
            .iter()
            .filter(|a| a.at > now - Duration::days(1))
            .collect();
        let gbytes = signed_file(
            &self.key,
            self.seq,
            &serde_json::to_vec(&grants).map_err(|e| e.to_string())?,
        )?;
        let abytes = signed_file(
            &self.key,
            self.seq,
            &serde_json::to_vec(&attempts).map_err(|e| e.to_string())?,
        )?;
        let hashes = format!(
            "seq={} grants.json={} attempts.json={}",
            self.seq,
            sha(&gbytes),
            sha(&abytes)
        );
        self.audit(now, "saving", &hashes)?;
        let (g, a) = (self.dir.join("grants.json"), self.dir.join("attempts.json"));
        let written = if attempts_first {
            write_atomic(&a, &abytes).and_then(|()| write_atomic(&g, &gbytes))
        } else {
            write_atomic(&g, &gbytes).and_then(|()| write_atomic(&a, &abytes))
        };
        match written {
            // both files landed, and the `saving` line already anchors
            // them: a closing line that cannot be written does not make the
            // caller believe it failed (review 6, m-4)
            Ok(()) => {
                let closed = if fault::fail_saved_line() {
                    Err("injected".to_string())
                } else {
                    self.audit(now, "saved", &hashes)
                };
                if let Err(e) = closed {
                    let _ = self.audit(now, "save-failed", &format!("saved line: {e}"));
                }
                Ok(())
            }
            Err(e) => {
                // so an audited change that did not land says so (review M-a)
                let _ = self.audit(now, "save-failed", &e);
                Err(e)
            }
        }
    }

    /// Stores an approval the channel returned, within its kind's maximum
    /// (review 3, I4). Only `resolve` calls it. The caller saves.
    fn add(&mut self, approval: Approval, now: DateTime<Utc>) -> Result<String, String> {
        self.trustworthy()?;
        let grant = approval.expires_at.map_or(Grant::Forever, Grant::Until);
        if !grant.within(
            approval.kind.max(),
            approval.approved_at.with_timezone(&Local),
        ) {
            return Err(format!(
                "the approval is longer than {:?} allows ({:?})",
                approval.kind,
                approval.kind.max()
            ));
        }
        let id = random_id();
        let expires = approval
            .expires_at
            .map_or("FOREVER".to_string(), |e| e.to_rfc3339());
        self.audit(
            now,
            "granted",
            &format!(
                "id={id} kind={:?} subject={} role={} expires={expires}",
                approval.kind, approval.subject, approval.requester.role
            ),
        )?;
        self.grants.push(StoredGrant {
            id: id.clone(),
            approval,
        });
        Ok(id)
    }

    /// A live grant covering this request: same kind and subject, not
    /// expired, not revoked, the same requester when the kind's scope is one
    /// requester - and never from an untrustworthy store. The store reads
    /// the clock itself (review 4, I-B): no caller can pick the time a grant
    /// or a gate window is judged at.
    pub fn find(&self, kind: KindId, subject: &str, requester: &Requester) -> Option<&StoredGrant> {
        self.find_at(kind, subject, requester, Utc::now())
    }

    pub(crate) fn find_at(
        &self,
        kind: KindId,
        subject: &str,
        requester: &Requester,
        now: DateTime<Utc>,
    ) -> Option<&StoredGrant> {
        // the chain is checked here too, so a reset since `open` is seen at
        // once (review 3, I5)
        if self.trustworthy().is_err() || matches!(self.check_chain(), Err(ChainError::Broken(_))) {
            return None;
        }
        self.active_at(now).into_iter().find(|g| {
            let a = &g.approval;
            // never before it was approved: a clock that was wrong ahead
            // when the person approved must not stretch the grant once it
            // is corrected (second review of #2b, finding 2)
            a.approved_at <= now
                && a.kind == kind
                && normal_subject(&a.subject) == normal_subject(subject)
                && match kind.scope() {
                    Scope::ThisRequester => a.requester == *requester,
                    Scope::AnyRequester => true,
                }
        })
    }

    /// Every grant that has not expired or been revoked.
    pub fn active(&self) -> Vec<&StoredGrant> {
        self.active_at(Utc::now())
    }

    pub(crate) fn active_at(&self, now: DateTime<Utc>) -> Vec<&StoredGrant> {
        self.grants
            .iter()
            .filter(|g| live(g, now) && !self.revoked.contains(&g.id))
            .collect()
    }

    /// Revokes one grant; `false` when there is no such active grant. Works
    /// on an untrustworthy store unless its key is the problem (then its
    /// grants are unknown, and only `repair` helps).
    pub fn revoke(&mut self, id: &str) -> Result<bool, String> {
        self.revoke_at(id, Utc::now())
    }

    pub(crate) fn revoke_at(&mut self, id: &str, now: DateTime<Utc>) -> Result<bool, String> {
        self.writable()?;
        self.key_known()?;
        let known = self.grants.iter().any(|g| g.id == id) && !self.revoked.contains(id);
        if !known {
            return Ok(false);
        }
        self.audit(now, "revoked", &format!("id={id}"))?;
        self.revoked.insert(id.to_string());
        self.save(now)?;
        Ok(true)
    }

    /// The panic button: revokes every grant, and ends every pending
    /// prompt so no approval still in flight becomes a grant (review 3,
    /// I3). Returns how many grants it revoked.
    pub fn revoke_all(&mut self) -> Result<usize, String> {
        self.revoke_all_at(Utc::now())
    }

    pub(crate) fn revoke_all_at(&mut self, now: DateTime<Utc>) -> Result<usize, String> {
        self.writable()?;
        self.key_known()?;
        let n = self.revoke_everything(now)?;
        self.save(now)?;
        Ok(n)
    }

    /// Revokes every grant of `kind` (about `subject` only, when given),
    /// whoever holds it, and ends the matching pending prompts so an
    /// approval still in flight never becomes a grant (#2b: `with-secret
    /// revoke NAME | --all`). Returns how many grants it revoked. The same
    /// trust rules as `revoke`.
    pub fn revoke_matching(
        &mut self,
        kind: KindId,
        subject: Option<&str>,
    ) -> Result<usize, String> {
        self.revoke_matching_at(kind, subject, Utc::now())
    }

    pub(crate) fn revoke_matching_at(
        &mut self,
        kind: KindId,
        subject: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<usize, String> {
        self.writable()?;
        self.key_known()?;
        let subject = subject.map(normal_subject);
        let matches = |k: KindId, s: &str| {
            k == kind
                && subject
                    .as_ref()
                    .is_none_or(|want| normal_subject(s) == *want)
        };
        let ids: Vec<String> = self
            .grants
            .iter()
            .filter(|g| !self.revoked.contains(&g.id))
            .filter(|g| matches(g.approval.kind, &g.approval.subject))
            .map(|g| g.id.clone())
            .collect();
        let pending: Vec<String> = self
            .attempts
            .iter()
            .filter(|a| a.outcome == Ended::Pending && matches(a.kind, &a.subject))
            .map(|a| a.id.clone())
            .collect();
        let requests: Vec<String> = self
            .pending
            .iter()
            .filter(|p| matches(p.request.kind, &p.request.subject))
            .map(|p| p.id.clone())
            .collect();
        self.audit(
            now,
            "revoked-matching",
            &format!(
                "kind={kind:?} subject={} n={} ids={} pending-ended={} requests-dropped={}",
                subject.as_deref().unwrap_or("*"),
                ids.len(),
                ids.join(","),
                pending.join(","),
                requests.join(",")
            ),
        )?;
        let n = ids.len();
        self.pending.retain(|p| !requests.contains(&p.id));
        self.revoked.extend(ids);
        for a in self.attempts.iter_mut().filter(|a| pending.contains(&a.id)) {
            a.outcome = Ended::NotAsked;
            self.ended.insert(a.id.clone(), a.at);
        }
        // tombstones first, like every revocation (the README's write order)
        self.save(now)?;
        Ok(n)
    }

    fn revoke_everything(&mut self, now: DateTime<Utc>) -> Result<usize, String> {
        let ids: Vec<String> = self
            .grants
            .iter()
            .map(|g| g.id.clone())
            .filter(|id| !self.revoked.contains(id))
            .collect();
        let n = ids.len();
        let pending: Vec<String> = self
            .attempts
            .iter()
            .filter(|a| a.outcome == Ended::Pending)
            .map(|a| a.id.clone())
            .collect();
        let requests: Vec<String> = self.pending.iter().map(|p| p.id.clone()).collect();
        self.audit(
            now,
            "revoked-all",
            &format!(
                "n={n} ids={} pending-ended={} requests-dropped={}",
                ids.join(","),
                pending.join(","),
                requests.join(",")
            ),
        )?;
        self.pending.clear();
        self.revoked.extend(ids);
        for a in self
            .attempts
            .iter_mut()
            .filter(|a| a.outcome == Ended::Pending)
        {
            a.outcome = Ended::NotAsked;
            self.ended.insert(a.id.clone(), a.at);
        }
        Ok(n)
    }

    fn key_known(&self) -> Result<(), String> {
        match &self.untrusted {
            Some(Untrusted::Key(why)) => Err(format!(
                "the store's key cannot be trusted ({why}), so its grants are unknown; \
                 `user-request repair` revokes every grant"
            )),
            _ => Ok(()),
        }
    }

    /// Restores trust by REVOKING EVERY GRANT, ending every pending prompt
    /// and closing the gate for `GATE_CLOSED_AFTER_REPAIR`. A store whose
    /// key is the problem gets a new key, and its old files are set aside.
    /// Removes privilege only, so it needs no Hello; on a trusted store it
    /// does the same, which is a way to stop everything for an hour.
    ///
    /// Trust returns only once the revocations are SAVED (review 3, C1): a
    /// repair whose save fails leaves the store untrusted.
    pub fn repair(&mut self, protector: &dyn Protector) -> Result<RepairReport, String> {
        self.repair_at(Utc::now(), protector)
    }

    pub(crate) fn repair_at(
        &mut self,
        now: DateTime<Utc>,
        protector: &dyn Protector,
    ) -> Result<RepairReport, String> {
        self.writable()?;
        let was = match &self.untrusted {
            None => "nothing (the store was trusted)".to_string(),
            Some(Untrusted::Key(w)) | Some(Untrusted::Files(w)) => w.clone(),
        };
        let grants_known = self.grants_known();
        if matches!(self.untrusted, Some(Untrusted::Key(_))) {
            for name in ["store.key", "grants.json", "attempts.json"] {
                if self.dir.join(name).exists() {
                    let to = quarantine(&self.dir.join(name));
                    self.set_aside.push(to);
                }
            }
            self.key = new_key(&self.dir, protector)?;
            self.grants.clear();
            self.revoked.clear();
            self.ended.clear();
            self.pending.clear();
            self.attempts.clear();
            self.seq = 0;
            self.untrusted = Some(Untrusted::Files(was.clone()));
        }
        let revoked = self.revoke_everything(now)?;
        self.attempts.push(Attempt {
            id: random_id(),
            at: now,
            requester: nobody("*"),
            kind: KindId::Secret,
            subject: "repair".into(),
            outcome: Ended::Repaired,
            pending: None,
        });
        self.save(now)?;
        self.audit(
            now,
            "repaired",
            &format!(
                "revoked={revoked} grants-known={grants_known} gate-closed-until={} was: {was}",
                (now + GATE_CLOSED_AFTER_REPAIR).to_rfc3339()
            ),
        )?;
        self.untrusted = None;
        self.grants_unreadable = false;
        Ok(RepairReport {
            revoked,
            grants_known,
            set_aside: self.set_aside.clone(),
        })
    }

    /// May `requester` put a prompt about `subject` in front of the person
    /// now? On yes, a PENDING attempt is recorded and saved, and it counts
    /// toward every limit until resolved (review C3). Refused when the store
    /// is untrustworthy (fail closed, and alerted), for an hour after a
    /// repair, in the cooldown after a denial or timeout of the same role
    /// and subject, or past the role's or the person's hourly cap. Keyed by
    /// ROLE, so a restart resets nothing. Every decision is audited and
    /// saved, except under an untrusted key, when nothing can be.
    pub fn may_ask(
        &mut self,
        requester: &Requester,
        kind: KindId,
        subject: &str,
        alert: &dyn Alert,
    ) -> Result<Reservation, String> {
        self.may_ask_at(requester, kind, subject, Utc::now(), alert)
    }

    pub(crate) fn may_ask_at(
        &mut self,
        requester: &Requester,
        kind: KindId,
        subject: &str,
        now: DateTime<Utc>,
        alert: &dyn Alert,
    ) -> Result<Reservation, String> {
        self.reserve(requester, kind, subject, now, alert, None)
    }

    /// `may_ask_at`, for a prompt that answers durable pending request
    /// `pending` (the attempt remembers which, so an answer ends that request
    /// in the same save as the grant).
    pub(super) fn reserve(
        &mut self,
        requester: &Requester,
        kind: KindId,
        subject: &str,
        now: DateTime<Utc>,
        alert: &dyn Alert,
        pending: Option<String>,
    ) -> Result<Reservation, String> {
        self.writable()?;
        let subject = normal_subject(subject);
        let role = requester.role.clone();
        // a chain broken since `open` untrusts the store before anything is
        // decided (review 3, I5)
        if self.untrusted.is_none() {
            if let Err(ChainError::Broken(why)) = self.check_chain() {
                self.untrusted = Some(Untrusted::Files(format!("chain found broken: {why}")));
            }
        }
        if let Some(Untrusted::Key(_)) = self.untrusted {
            // nothing can be recorded under this key (review 3, M9)
            let why = self.trustworthy().unwrap_err();
            alert.alert(&why);
            return Err(why);
        }
        if let Err(why) = self.gate(&role, &subject, now, alert) {
            let recorded = self
                .audit(
                    now,
                    "gate-refused",
                    &format!("role={role} subject={subject}: {why}"),
                )
                .and_then(|()| self.save(now));
            return Err(match recorded {
                Ok(()) => why,
                Err(e) => format!("{why} (and recording it failed: {e})"),
            });
        }
        let id = random_id();
        self.attempts.push(Attempt {
            id: id.clone(),
            at: now,
            requester: requester.clone(),
            kind,
            subject: subject.clone(),
            outcome: Ended::Pending,
            pending,
        });
        let recorded = self
            .audit(
                now,
                "gate-allowed",
                &format!("role={role} subject={subject} attempt={id}"),
            )
            .and_then(|()| self.save(now));
        if let Err(e) = recorded {
            // not recorded, so not kept (review 5, M-2)
            self.attempts.retain(|a| a.id != id);
            return Err(e);
        }
        Ok(Reservation { attempt_id: id })
    }

    fn gate(
        &mut self,
        role: &str,
        subject: &str,
        now: DateTime<Utc>,
        alert: &dyn Alert,
    ) -> Result<(), String> {
        if let Err(why) = self.trustworthy() {
            // an untrusted store disables everything, so it is not silent
            // (review 3, I2)
            self.alert_once(role, "untrusted", &why, now, alert)?;
            return Err(why);
        }
        let within = |a: &Attempt, d: Duration| now < a.at + d;
        if let Some(r) = self
            .attempts
            .iter()
            .filter(|a| a.outcome == Ended::Repaired && within(a, GATE_CLOSED_AFTER_REPAIR))
            .map(|a| a.at)
            .max()
        {
            return Err(format!(
                "the store was repaired at {r}; prompts resume at {}",
                r + GATE_CLOSED_AFTER_REPAIR
            ));
        }
        if self.attempts.iter().any(|a| {
            a.requester.role == role
                && a.subject == subject
                && a.outcome.is_refusal()
                && within(a, DENIAL_COOLDOWN)
        }) {
            return Err(format!(
                "'{role}' was refused about '{subject}' less than {} minutes ago",
                DENIAL_COOLDOWN.num_minutes()
            ));
        }
        let prompts = |only: Option<&str>| {
            self.attempts
                .iter()
                .filter(|a| a.outcome.is_prompt() && within(a, Duration::hours(1)))
                .filter(|a| only.is_none_or(|r| a.requester.role == r))
                .count()
        };
        let (mine, everyone) = (prompts(Some(role)), prompts(None));
        let why = if mine >= PROMPTS_PER_HOUR {
            format!("'{role}' has asked {mine} times in the last hour (cap {PROMPTS_PER_HOUR})")
        } else if everyone >= PROMPTS_PER_HOUR_FOR_THE_PERSON {
            format!(
                "{everyone} prompts reached the person in the last hour \
                 (cap {PROMPTS_PER_HOUR_FOR_THE_PERSON})"
            )
        } else {
            return Ok(());
        };
        self.alert_once(role, "cap", &why, now, alert)?;
        Err(why)
    }

    /// Records how a reserved prompt ended, once (review I-C), and saves.
    /// An approval must be for what was reserved and within its kind's
    /// maximum, and becomes a grant in the same save; its id is returned.
    /// A reservation that a repair or `revoke_all` ended, or that is older
    /// than `RESERVATION_TTL`, can no longer be resolved (review 3, I3).
    /// Repeated refusals alert once.
    pub fn resolve(
        &mut self,
        reservation: &Reservation,
        outcome: &Outcome,
        alert: &dyn Alert,
    ) -> Result<Option<String>, String> {
        self.resolve_at(reservation, outcome, Utc::now(), alert)
    }

    /// `resolve`, undone in memory on any error (review 4, M-a): a grant
    /// that did not land must not be honoured, nor saved by a later,
    /// unrelated save.
    pub(crate) fn resolve_at(
        &mut self,
        reservation: &Reservation,
        outcome: &Outcome,
        now: DateTime<Utc>,
        alert: &dyn Alert,
    ) -> Result<Option<String>, String> {
        let before = (
            self.grants.clone(),
            self.revoked.clone(),
            self.attempts.clone(),
            self.pending.clone(),
        );
        let result = self.resolve_once(reservation, outcome, now, alert);
        if result.is_err() {
            let alerted: Vec<Attempt> = self
                .attempts
                .iter()
                .filter(|a| a.outcome == Ended::Alerted && !before.2.contains(a))
                .cloned()
                .collect();
            (self.grants, self.revoked, self.attempts, self.pending) = before;
            // the alert was delivered and audited: keep its record (review 5,
            // M-4)
            self.attempts.extend(alerted);
        }
        result
    }

    fn resolve_once(
        &mut self,
        reservation: &Reservation,
        outcome: &Outcome,
        now: DateTime<Utc>,
        alert: &dyn Alert,
    ) -> Result<Option<String>, String> {
        self.writable()?;
        let a = self
            .attempts
            .iter()
            .find(|a| a.id == reservation.attempt_id)
            .ok_or("no such attempt")?;
        if a.outcome != Ended::Pending {
            return Err(format!(
                "attempt {} already ended: {}",
                a.id,
                a.outcome.name()
            ));
        }
        // ended by a revocation whose prompts file was never written
        // (second review of #2b, finding 4)
        if self.ended.contains_key(&a.id) {
            return Err(format!("attempt {} already ended: revoked", a.id));
        }
        if now >= a.at + RESERVATION_TTL {
            return Err(format!(
                "attempt {} was reserved at {}, more than {} minutes ago",
                a.id,
                a.at,
                RESERVATION_TTL.num_minutes()
            ));
        }
        let (role, subject) = (a.requester.role.clone(), a.subject.clone());
        // a prompt that answers a durable pending request needs the request
        // to be still there (a second prompt for it, or a withdrawal, must not
        // land) and, when approved, to be for the length that was asked
        let (pending_id, reserved_at) = (a.pending.clone(), a.at);
        let asked = match &pending_id {
            Some(pid) => Some(
                self.pending
                    .iter()
                    .find(|p| p.id == *pid)
                    .map(|p| p.grant.clone())
                    .ok_or_else(|| {
                        format!(
                            "pending request {pid} is no longer pending (answered or withdrawn)"
                        )
                    })?,
            ),
            None => None,
        };
        let ended = match outcome {
            Outcome::Approved(ap) => {
                if ap.kind != a.kind
                    || normal_subject(&ap.subject) != a.subject
                    || ap.requester != a.requester
                {
                    return Err("the approval is not for what was reserved".into());
                }
                // the kind's maximum is judged from `approved_at`, so it must
                // be a time between the reservation and now (review 4, I-B)
                // no allowance for a clock stepped back (review 6, m-1): it
                // would let an approval given before a revocation make a
                // grant after it; a stepped-back clock costs one more prompt
                if ap.approved_at < a.at || ap.approved_at > now {
                    return Err(format!(
                        "the approval says it was given at {}, outside its reservation \
                         ({} to {now})",
                        ap.approved_at, a.at
                    ));
                }
                // the end the person was shown has passed: nothing is left
                // to grant (second review of #2b, finding 3)
                if ap.expires_at.is_some_and(|e| e <= now) {
                    return Err(format!(
                        "the approval ended at {} before it could be recorded",
                        ap.expires_at.map(|e| e.to_rfc3339()).unwrap_or_default()
                    ));
                }
                if let Some(asked) = &asked {
                    if !pending::is_what_was_requested(asked, ap, reserved_at) {
                        return Err(
                            "the approval is not for the duration that was requested".into()
                        );
                    }
                }
                Ended::Approved
            }
            Outcome::Denied => Ended::Denied,
            Outcome::TimedOut => Ended::TimedOut,
            Outcome::Unavailable(_) => Ended::Unavailable,
            Outcome::Refused(_) => Ended::NotAsked,
        };
        let mut grant = None;
        if let Outcome::Approved(ap) = outcome {
            // checked before anything is recorded; nothing is saved twice,
            // so the caller is never told "failed" for a grant that landed
            // (review 3, M6)
            grant = Some(self.add(ap.clone(), now)?);
        }
        // an answer spends its request in the same save as the grant; a prompt
        // nobody answered leaves it pending
        let spent = pending_id.filter(|_| !matches!(ended, Ended::TimedOut | Ended::Unavailable));
        if let Some(pid) = &spent {
            self.pending.retain(|p| p.id != *pid);
        }
        self.audit(
            now,
            "resolved",
            &format!(
                "outcome={} role={role} subject={subject} attempt={}{}",
                ended.name(),
                reservation.attempt_id,
                spent
                    .map(|p| format!(" pending-spent={p}"))
                    .unwrap_or_default()
            ),
        )?;
        if let Some(a) = self
            .attempts
            .iter_mut()
            .find(|a| a.id == reservation.attempt_id)
        {
            a.outcome = ended;
        }
        if ended.is_refusal() {
            let refusals = self
                .attempts
                .iter()
                .filter(|a| {
                    a.requester.role == role
                        && a.outcome.is_refusal()
                        && now < a.at + Duration::hours(1)
                })
                .count();
            if refusals >= DENIALS_BEFORE_ALERT {
                let what = format!("'{role}' was refused {refusals} times within an hour");
                self.alert_once(&role, "refusals", &what, now, alert)?;
            }
        }
        self.save_ordered(now, true)?;
        Ok(grant)
    }

    /// One alert per role and reason per rolling hour (review M1), always
    /// audited, whatever the sink does. The caller saves.
    fn alert_once(
        &mut self,
        role: &str,
        reason: &str,
        what: &str,
        now: DateTime<Utc>,
        alert: &dyn Alert,
    ) -> Result<(), String> {
        let tag = format!("alert:{reason}");
        let recent = self.attempts.iter().any(|a| {
            a.outcome == Ended::Alerted
                && a.requester.role == role
                && a.subject == tag
                && now < a.at + Duration::hours(1)
        });
        if recent {
            return Ok(());
        }
        self.attempts.push(Attempt {
            id: random_id(),
            at: now,
            requester: nobody(role),
            kind: KindId::Secret,
            subject: tag,
            outcome: Ended::Alerted,
            pending: None,
        });
        self.audit(now, "ALERT", what)?;
        alert.alert(what);
        Ok(())
    }

    /// Appends one line to the hash-chained audit log and rewrites the head
    /// copy. The chain is checked first (review C1, I5, I6): a chain that is
    /// broken, or shorter than its head copy says (truncated, deleted, a torn
    /// last line), gets an explicit `chain-reset` line naming why, and the
    /// store is untrusted from that moment, not only from the next open
    /// (review 3, I5). A chain that cannot be READ right now is an error,
    /// never a reset.
    fn audit(&mut self, at: DateTime<Utc>, event: &str, detail: &str) -> Result<(), String> {
        self.writable()?;
        let path = self.dir.join("audit.jsonl");
        let (count, prev) = match self.check_chain() {
            Ok(head) => head,
            Err(ChainError::Io(why)) => return Err(why),
            Err(ChainError::Broken(why)) => {
                let reset = AuditLine {
                    prev: GENESIS.to_string(),
                    at,
                    event: "chain-reset".into(),
                    detail: why.clone(),
                };
                let text = read_text(&path);
                let line = serde_json::to_string(&reset).map_err(|e| e.to_string())?;
                let sep = if text.is_empty() || text.ends_with('\n') {
                    ""
                } else {
                    "\n"
                };
                append(&path, &format!("{sep}{line}\n"))?;
                if self.untrusted.is_none() {
                    self.untrusted = Some(Untrusted::Files(format!("chain reset: {why}")));
                }
                (read_text(&path).lines().count(), sha(line.as_bytes()))
            }
        };
        let line = serde_json::to_string(&AuditLine {
            prev,
            at,
            event: event.to_string(),
            detail: detail.to_string(),
        })
        .map_err(|e| e.to_string())?;
        append(&path, &format!("{line}\n"))?;
        if let Some(copy) = &self.head_copy {
            // best effort (review I-D): a revocation must land even where the
            // copy cannot be written; the next open then finds the copy wrong
            // and the store untrusted, which fails closed
            if let Some(parent) = copy.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = write_atomic(
                copy,
                format!("{} {}\n", count + 1, sha(line.as_bytes())).as_bytes(),
            );
        }
        Ok(())
    }

    /// The chain's (length, last hash) if every link and the head copy
    /// agree. A `chain-reset` line starts a new chain.
    fn check_chain(&self) -> Result<(usize, String), ChainError> {
        let path = self.dir.join("audit.jsonl");
        let bytes = match read_retry(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(ChainError::Io(format!("the audit log cannot be read: {e}"))),
        };
        let text = String::from_utf8(bytes)
            .map_err(|_| ChainError::Broken("audit log is not UTF-8".into()))?;
        if !text.is_empty() && !text.ends_with('\n') {
            return Err(ChainError::Broken(
                "the audit log's last line is torn".into(),
            ));
        }
        let lines: Vec<&str> = text.lines().collect();
        let start = chain_start(&lines);
        let mut prev = GENESIS.to_string();
        let hashes: Vec<String> = lines.iter().map(|l| sha(l.as_bytes())).collect();
        for (i, l) in lines.iter().enumerate().skip(start) {
            let line: AuditLine = serde_json::from_str(l).map_err(|e| {
                ChainError::Broken(format!("audit line {}: unreadable: {e}", i + 1))
            })?;
            if line.prev != prev && !(i == start && line.event == "chain-reset") {
                return Err(ChainError::Broken(format!(
                    "audit chain broken at line {}",
                    i + 1
                )));
            }
            prev = sha(l.as_bytes());
        }
        let count = lines.len();
        if let Some(copy) = &self.head_copy {
            match read_retry(copy) {
                Ok(head) if String::from_utf8_lossy(&head).trim() == format!("{count} {prev}") => {}
                // a copy a backup or sync tool held during a write lags the
                // log, and agrees with it at its own line (review 5, I-2);
                // truncation or rollback leaves the log shorter than the copy
                // or different at that line. The next append rewrites it.
                Ok(head) if lags_by_a_few(&String::from_utf8_lossy(&head), &hashes) => {}
                Ok(head) => {
                    return Err(ChainError::Broken(format!(
                        "audit head copy says '{}', the chain ends at '{count} {prev}': \
                         truncated, rolled back or rewritten",
                        String::from_utf8_lossy(&head).trim()
                    )))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if count > 0 {
                        return Err(ChainError::Broken(format!(
                            "audit head copy {} is missing",
                            copy.display()
                        )));
                    }
                }
                // held by a backup or sync tool: decide nothing (review 4, I-A)
                Err(e) => {
                    return Err(ChainError::Io(format!(
                        "audit head copy {} cannot be read right now: {e}",
                        copy.display()
                    )))
                }
            }
        }
        Ok((count, prev))
    }

    /// Checks the chain from its last reset on, and the head copy. A
    /// `chain-reset` since the last repair is an error: it is evidence the
    /// chain was found broken. Resets that a repair acknowledged are counted,
    /// not failed (review M-f); the lines before the last reset are the
    /// damage it reported, and are not re-checked.
    pub fn verify_audit(&self) -> Result<AuditReport, String> {
        let (lines, _) = self.check_chain().map_err(|e| match e {
            ChainError::Broken(w) | ChainError::Io(w) => w,
        })?;
        let text = read_text(&self.dir.join("audit.jsonl"));
        let all: Vec<&str> = text.lines().collect();
        let checked = lines - chain_start(&all);
        let parsed: Vec<(usize, AuditLine)> = all
            .iter()
            .enumerate()
            .filter_map(|(i, l)| serde_json::from_str::<AuditLine>(l).ok().map(|a| (i, a)))
            .collect();
        let after_repair = parsed
            .iter()
            .rposition(|(_, a)| a.event == "repaired")
            .map_or(0, |i| i + 1);
        let mut repaired_resets = 0;
        for (n, (i, a)) in parsed.iter().enumerate() {
            if a.event != "chain-reset" {
                continue;
            }
            if n < after_repair {
                repaired_resets += 1;
            } else {
                return Err(format!(
                    "the chain was reset at line {}: {}",
                    i + 1,
                    a.detail
                ));
            }
        }
        let head_behind = self
            .head_copy
            .as_ref()
            .and_then(|c| read_retry(c).ok())
            .and_then(|b| {
                let text = String::from_utf8_lossy(&b).into_owned();
                text.split_whitespace().next()?.parse::<usize>().ok()
            })
            .map_or(0, |n| lines.saturating_sub(n));
        Ok(AuditReport {
            lines,
            checked,
            repaired_resets,
            head_behind,
        })
    }
}

/// The first integrity finding on record since the last repair.
fn unrepaired_finding(text: &str) -> Option<String> {
    let lines: Vec<AuditLine> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<AuditLine>(l).ok())
        .collect();
    let start = lines
        .iter()
        .rposition(|a| a.event == "repaired")
        .map_or(0, |i| i + 1);
    lines
        .into_iter()
        .skip(start)
        .find(|a| a.event == "untrusted" || a.event == "chain-reset")
        .map(|a| format!("{} at {}: {}", a.event, a.at, a.detail))
}

/// For each file, the hashes a save recorded for it: the last completed
/// save's, plus any written since by a save that did not finish (a crash
/// or a failed rename between the two files, review M-g, 3 I2). An older
/// copy matches neither.
fn recorded_hashes(text: &str) -> Option<HashMap<String, HashSet<String>>> {
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    let mut any = false;
    for l in text.lines().rev() {
        let Ok(a) = serde_json::from_str::<AuditLine>(l) else {
            continue;
        };
        if a.event != "saved" && a.event != "saving" {
            continue;
        }
        any = true;
        for (k, v) in a
            .detail
            .split_whitespace()
            .filter_map(|kv| kv.split_once('='))
        {
            out.entry(k.to_string()).or_default().insert(v.to_string());
        }
        if a.event == "saved" {
            break;
        }
    }
    any.then_some(out)
}

/// A head copy may lag the log by this many lines, when it failed to
/// update (it is written best effort) and agrees with the log at its line.
pub const HEAD_COPY_LAG: usize = 32;

/// Does the head copy `n hash` name a line of the log, at most
/// `HEAD_COPY_LAG` lines from its end, with that line's hash?
fn lags_by_a_few(head: &str, hashes: &[String]) -> bool {
    let Some((n, hash)) = head.trim().split_once(' ') else {
        return false;
    };
    let Ok(n) = n.parse::<usize>() else {
        return false;
    };
    n > 0 && n <= hashes.len() && hashes.len() - n <= HEAD_COPY_LAG && hashes[n - 1] == hash
}

/// Where the current chain starts: the last `chain-reset` line, or 0.
fn chain_start(lines: &[&str]) -> usize {
    lines
        .iter()
        .rposition(|l| serde_json::from_str::<AuditLine>(l).is_ok_and(|a| a.event == "chain-reset"))
        .unwrap_or(0)
}

fn exists(dir: &Path) -> bool {
    dir.join("store.key").exists() || DATA_FILES.iter().any(|n| dir.join(n).exists())
}

/// A store-wide OS file lock (review I-A): the OS releases it when the
/// handle closes, including when the process dies, so there is no staleness
/// to guess and no other holder's lock to delete. On Windows the file is
/// opened WITHOUT delete sharing, so it cannot be deleted while held and a
/// second holder cannot appear beside the first (review 3, I1). The file
/// itself stays.
struct StoreLock {
    _file: std::fs::File,
}

impl StoreLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ | FILE_SHARE_WRITE: no FILE_SHARE_DELETE
            options.share_mode(0x1 | 0x2);
        }
        let deadline = Instant::now() + LOCK_WAIT;
        // another program holding the file open (review 4, M-d) is waited
        // for, like another holder of the lock
        let file = loop {
            match options.open(path) {
                Ok(f) => break f,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => return Err(format!("lock {}: {e}", path.display())),
            }
        };
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(format!(
                            "the store is in use by another process ({}); it is released \
                             when that process finishes or exits - do not delete the file",
                            path.display()
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(format!("lock {}: {e}", path.display()))
                }
            }
        }
    }
}

fn new_key(dir: &Path, protector: &dyn Protector) -> Result<Vec<u8>, String> {
    let mut k = vec![0u8; 32];
    getrandom::fill(&mut k).map_err(|e| format!("random key: {e}"))?;
    write_atomic(&dir.join("store.key"), &protector.protect(&k)?)?;
    write_atomic(
        &dir.join("store.key.check"),
        mac(&k, KEY_CHECK.as_bytes()).as_bytes(),
    )?;
    Ok(k)
}

/// The requester recorded on a store-made attempt (an alert, a repair).
fn nobody(role: &str) -> Requester {
    Requester {
        role: role.to_string(),
        session_id: String::new(),
        claude_pid: 0,
        claude_start_secs: 0,
        managed: false,
    }
}

fn live(g: &StoredGrant, now: DateTime<Utc>) -> bool {
    g.approval.expires_at.is_none_or(|e| e > now)
}

/// Subjects are compared trimmed and case-folded (review I9).
pub fn normal_subject(s: &str) -> String {
    // ASCII only (review 5, M-3): Unicode folding would make the Kelvin sign
    // in "\u{212A}_TOKEN" the same subject as "k_token"
    s.trim().to_ascii_lowercase()
}

fn random_id() -> String {
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).expect("the OS random source works");
    hex(&id)
}

/// What `store.key.check` signs, to tell the right key from a wrong one.
const KEY_CHECK: &str = "user-request store key check";

/// The `prev` of the first audit line.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, PartialEq)]
enum Signed {
    Missing,
    Bad,
    Good {
        seq: u64,
        body: Vec<u8>,
        sha: String,
    },
}

/// Reads a file, retrying for `RETRY_FOR` while it fails for any reason
/// but not existing (review 3, I2).
fn read_retry(path: &Path) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + RETRY_FOR;
    loop {
        match std::fs::read(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            other => return other,
        }
    }
}

/// A text file, or "" when it does not exist. Only used after `open` has
/// confirmed every file is readable.
fn read_text(path: &Path) -> String {
    read_retry(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// A signed file: a header line `{"seq":N,"mac":"..."}`, a newline, and the
/// body. The MAC covers the sequence number and the body's EXACT bytes, so
/// no re-serialisation can change what was signed (review I8). A file that
/// cannot be read right now is an error, not "missing".
fn read_signed(path: &Path, key: &[u8]) -> Result<Signed, String> {
    let bytes = match read_retry(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Signed::Missing),
        Err(e) => {
            return Err(format!(
                "{} cannot be read right now ({e}); try again",
                path.display()
            ))
        }
    };
    let Some(nl) = bytes.iter().position(|&b| b == b'\n') else {
        return Ok(Signed::Bad);
    };
    let (head, body) = (&bytes[..nl], &bytes[nl + 1..]);
    let Ok(h) = serde_json::from_slice::<Header>(head) else {
        return Ok(Signed::Bad);
    };
    if key.is_empty() || mac(key, &signed_bytes(h.seq, body)) != h.mac {
        return Ok(Signed::Bad);
    }
    Ok(Signed::Good {
        seq: h.seq,
        body: body.to_vec(),
        sha: sha(&bytes),
    })
}

/// The bytes of a signed file.
fn signed_file(key: &[u8], seq: u64, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(&Header {
        seq,
        mac: mac(key, &signed_bytes(seq, body)),
    })
    .map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    bytes.extend_from_slice(body);
    Ok(bytes)
}

#[cfg(test)]
fn write_signed(path: &Path, key: &[u8], seq: u64, body: &[u8]) -> Result<String, String> {
    let bytes = signed_file(key, seq, body)?;
    write_atomic(path, &bytes)?;
    Ok(sha(&bytes))
}

fn signed_bytes(seq: u64, body: &[u8]) -> Vec<u8> {
    let mut v = format!("seq:{seq}\n").into_bytes();
    v.extend_from_slice(body);
    v
}

/// Moves a file aside instead of dropping it (review I8); returns its new
/// name, which is unique, so two files set aside in the same millisecond
/// never overwrite each other.
fn quarantine(path: &Path) -> String {
    let to = path.with_extension(format!(
        "rejected-{}-{}",
        Utc::now().format("%Y%m%dT%H%M%S%.3f"),
        &random_id()[..8]
    ));
    let _ = std::fs::rename(path, &to);
    to.display().to_string()
}

/// Appends, retrying a log someone holds for a moment (review 4, M-a).
fn append(path: &Path, text: &str) -> Result<(), String> {
    let deadline = Instant::now() + RETRY_FOR;
    loop {
        let opened = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);
        match opened {
            Ok(mut f) => return f.write_all(text.as_bytes()).map_err(|e| e.to_string()),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => return Err(format!("open {}: {e}", path.display())),
        }
    }
}

/// A uniquely named temp file and a rename, so neither a reader nor another
/// writer ever sees half a file (review I1: shared temp names collided). A
/// rename onto a file someone briefly holds is retried (review 3, I2).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp-{}", random_id()));
    std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    let deadline = Instant::now() + RETRY_FOR;
    loop {
        match std::fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(format!("rename to {}: {e}", path.display()));
            }
        }
    }
}

fn mac(key: &[u8], bytes: &[u8]) -> String {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(bytes);
    hex(&m.finalize().into_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// A fault the tests inject where nothing outside can reach: the closing
/// `saved` line failing after both files landed. Per thread, so tests
/// running in parallel never see each other's.
mod fault {
    #[cfg(test)]
    thread_local! {
        pub(super) static FAIL_SAVED_LINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    pub(super) fn fail_saved_line() -> bool {
        #[cfg(test)]
        return FAIL_SAVED_LINE.with(|f| f.get());
        #[cfg(not(test))]
        false
    }
}

mod pending;
pub use pending::{Asking, PendingRequest, MAX_PENDING, MAX_PENDING_PER_ROLE};

#[cfg(test)]
mod tests;
