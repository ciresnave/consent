// SPDX-License-Identifier: MIT OR Apache-2.0
//! The decision: may THIS requester use THIS secret for THIS command now.
//! `main.rs` loads the vault and spawns; the approvals live in the
//! user-request store (#2b), so every prompt passes its gate, and
//! `user-request revoke --all` covers secrets, with tombstones.
//!
//! ⚠️ Every refusal path releases nothing, and consent is asked only after
//! every cheap refusal has passed. The store is NOT held while the person
//! decides (holding it holds its lock); the answer is recorded against the
//! store as it is then, so a revocation made meanwhile wins.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Local, Utc};
use user_request::channel::{Channel, Outcome};
use user_request::request::{next_local_midnight, Grant, KindId, Request};
use user_request::store::{Alert, Protector, Store, RESERVATION_TTL};

use crate::audit::Event;
use crate::dumpcheck::command_dump_reason;
use crate::identity::Requester;
use crate::vault::{validate_name, Secret, Vault};

pub const MIN_REASON_CHARS: usize = 10;
/// Under the 10-minute ceiling of a lane's Bash tool call; a lane calling
/// `with-secret` should pass `timeout: 600000`.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(540);
/// The longest wait: a minute inside the store's reservation, so an answer
/// given in time can always be recorded.
pub const MAX_WAIT: Duration = Duration::from_secs(14 * 60);
const _: () = assert!(MAX_WAIT.as_secs() < RESERVATION_TTL.num_seconds() as u64);

pub struct RunArgs {
    pub secret: String,
    pub reason: String,
    pub argv: Vec<String>,
    pub wait: Duration,
    pub window: Option<chrono::Duration>,
}

pub fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or("missing `--` before the command")?;
    let (opts, argv) = (&args[..sep], &args[sep + 1..]);
    let secret = opts.first().ok_or("missing secret NAME")?.clone();
    validate_name(&secret)?;
    let (mut reason, mut wait, mut window) = (None, DEFAULT_WAIT, None);
    let mut i = 1;
    while i < opts.len() {
        let val = opts
            .get(i + 1)
            .ok_or_else(|| format!("{} needs a value", opts[i]))?;
        match opts[i].as_str() {
            "--reason" => reason = Some(val.clone()),
            "--wait-secs" => {
                let secs: u64 = val.parse().map_err(|_| "--wait-secs: not a number")?;
                // an answer after the reservation expires is refused, so a
                // longer wait could only waste the person's approval (second
                // review of #2b, finding 7)
                if secs > MAX_WAIT.as_secs() {
                    return Err(format!(
                        "--wait-secs: at most {} (a prompt's reservation lasts {} minutes)",
                        MAX_WAIT.as_secs(),
                        RESERVATION_TTL.num_minutes()
                    ));
                }
                wait = Duration::from_secs(secs)
            }
            "--window-mins" => {
                let mins: i64 = val.parse().map_err(|_| "--window-mins: not a number")?;
                // a window that is not positive, or too long to represent,
                // is refused (it used to panic)
                window = Some(
                    chrono::Duration::try_minutes(mins)
                        .filter(|d| *d > chrono::Duration::zero())
                        .ok_or("--window-mins: must be a positive number of minutes")?,
                )
            }
            other => return Err(format!("unknown option {other}")),
        }
        i += 2;
    }
    let reason = reason.ok_or("--reason is required: CireSnave is shown it")?;
    if reason.trim().chars().count() < MIN_REASON_CHARS {
        return Err(format!(
            "--reason must be at least {MIN_REASON_CHARS} characters"
        ));
    }
    if argv.is_empty() {
        return Err("no command after `--`".into());
    }
    Ok(RunArgs {
        secret,
        reason,
        argv: argv.to_vec(),
        wait,
        window,
    })
}

/// What is asked for: `--window-mins` from the moment it is shown, however
/// long (board 134), else until the next local midnight - the same midnight
/// the prompt's "longer than today" check uses. A secret is never granted
/// forever (`KindId::Secret.max()`).
pub fn grant_for(window: Option<chrono::Duration>, now: DateTime<Local>) -> Grant {
    match window {
        Some(w) => Grant::for_duration(w),
        None => Grant::Until(next_local_midnight(now)),
    }
}

/// The store and the channel a decision uses (`main.rs` passes the
/// production ones: `user_request::locate`, Windows Hello).
pub struct Approver<'a> {
    pub dir: PathBuf,
    pub protector: &'a dyn Protector,
    pub head_copy: Option<PathBuf>,
    pub channel: &'a dyn Channel,
    pub alert: &'a dyn Alert,
}

impl Approver<'_> {
    fn open(&self) -> Result<Store, String> {
        Store::open(&self.dir, self.protector, self.head_copy.clone())
    }
}

#[derive(Debug)]
pub struct Released {
    pub secret: Secret,
    /// The store's id for the grant (`user-request revoke <id>`).
    pub grant_id: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub newly_granted: bool,
}

fn event(kind: &str, a: &RunArgs, who: &Requester) -> Event {
    Event {
        at: Utc::now(),
        event: kind.into(),
        secret: a.secret.clone(),
        role: who.role.clone(),
        session_id: who.session_id.clone(),
        claude_pid: who.claude_pid,
        command: a.argv.join(" "),
        reason: a.reason.clone(),
    }
}

pub fn authorize(
    a: &RunArgs,
    vault: &Vault,
    who: &Requester,
    approver: &Approver,
    log: &mut Vec<Event>,
) -> Result<Released, String> {
    let command = a.argv.join(" ");
    if let Some(why) = command_dump_reason(&command) {
        log.push(event("refused", a, who));
        return Err(format!(
            "with-secret: blocked - {why}; a secret is never handed to an env dump"
        ));
    }
    let Some(secret) = vault.secrets.get(&a.secret) else {
        log.push(event("refused", a, who));
        return Err(format!(
            "no secret named {} in the vault (`with-secret vault list`)",
            a.secret
        ));
    };
    let not_released = |why: &str| format!("with-secret: {} not released - {why}", a.secret);
    // a grant over the kind's maximum, or that cannot be represented, never
    // reaches the store or the person
    let grant = grant_for(a.window, Local::now());
    if !grant.within(KindId::Secret.max(), Local::now()) {
        log.push(event("refused", a, who));
        return Err(not_released(&format!(
            "{} is over the maximum for a secret",
            grant.describe(Utc::now())
        )));
    }
    let reservation = {
        let mut store = approver
            .open()
            .inspect_err(|_| log.push(event("refused", a, who)))?;
        if let Some(g) = store.find(KindId::Secret, &a.secret, who) {
            log.push(event("used", a, who));
            return Ok(Released {
                secret: secret.clone(),
                grant_id: g.id.clone(),
                expires_at: g.approval.expires_at,
                newly_granted: false,
            });
        }
        match store.may_ask(who, KindId::Secret, &a.secret, approver.alert) {
            Ok(r) => r,
            Err(why) => {
                log.push(event("gate-refused", a, who));
                return Err(not_released(&why));
            }
        }
        // the store, and its lock, are dropped here: never held while the
        // person decides
    };
    let req = Request {
        kind: KindId::Secret,
        subject: a.secret.clone(),
        summary: format!("run: {command}"),
        requester: who.clone(),
        reason: a.reason.clone(),
    };
    let outcome = approver.channel.present(&req, &grant, a.wait);
    // against the store as it is NOW: a revocation (or a repair) made while
    // the person was deciding ended this prompt, so the approval is refused
    let recorded = approver
        .open()
        .and_then(|mut s| s.resolve(&reservation, &outcome, approver.alert));
    let refusal = match (&outcome, recorded) {
        (Outcome::Approved(ap), Ok(Some(id))) => {
            log.push(event("granted", a, who));
            log.push(event("used", a, who));
            return Ok(Released {
                secret: secret.clone(),
                grant_id: id,
                expires_at: ap.expires_at,
                newly_granted: true,
            });
        }
        (Outcome::Approved(_), Ok(None)) => ("refused", "the approval made no grant".to_string()),
        (Outcome::Approved(_), Err(e)) => ("refused", format!("approved, but not recorded: {e}")),
        (other, recorded) => {
            let (kind, why) = match other {
                Outcome::Denied => ("denied", "CireSnave declined".to_string()),
                Outcome::TimedOut => ("timed-out", "no answer before the wait ran out".to_string()),
                Outcome::Unavailable(why) => ("unavailable", why.clone()),
                Outcome::Refused(why) => ("refused", why.clone()),
                o => ("refused", format!("{o:?}")),
            };
            match recorded {
                Ok(_) => (kind, why),
                Err(e) => (kind, format!("{why} (and recording it failed: {e})")),
            }
        }
    };
    log.push(event(refusal.0, a, who));
    Err(not_released(&refusal.1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::{Consent, ConsentOutcome};
    use crate::vault::Access;
    use std::cell::RefCell;
    use user_request::channel::HelloChannel;
    use user_request::store::AuditOnly;

    /// Reversible and keyed, like the store's own test protector.
    struct Xor;
    impl Protector for Xor {
        fn protect(&self, p: &[u8]) -> Result<Vec<u8>, String> {
            Ok(p.iter().map(|b| b ^ 7).collect())
        }
        fn unprotect(&self, b: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b.iter().map(|x| x ^ 7).collect())
        }
    }

    /// Answers `answer`, after running `during` - what happens while the
    /// person decides.
    struct FakeConsent {
        answer: ConsentOutcome,
        asked: RefCell<Vec<String>>,
        during: Box<dyn Fn()>,
    }
    impl Consent for FakeConsent {
        fn ask(&self, prompt: &str, _: std::time::Duration) -> ConsentOutcome {
            self.asked.borrow_mut().push(prompt.to_string());
            (self.during)();
            match &self.answer {
                ConsentOutcome::Approved => ConsentOutcome::Approved,
                ConsentOutcome::Denied => ConsentOutcome::Denied,
                ConsentOutcome::TimedOut => ConsentOutcome::TimedOut,
                ConsentOutcome::Unavailable(s) => ConsentOutcome::Unavailable(s.clone()),
            }
        }
    }

    fn hello(answer: ConsentOutcome) -> HelloChannel<FakeConsent> {
        hello_while(answer, || {})
    }
    fn hello_while(
        answer: ConsentOutcome,
        during: impl Fn() + 'static,
    ) -> HelloChannel<FakeConsent> {
        HelloChannel::new(FakeConsent {
            answer,
            asked: RefCell::new(vec![]),
            during: Box::new(during),
        })
    }
    fn asked(ch: &HelloChannel<FakeConsent>) -> Vec<String> {
        ch.consent.asked.borrow().clone()
    }

    /// A store directory that does not exist yet.
    fn store_dir() -> PathBuf {
        tempfile::tempdir().unwrap().keep().join("user-request")
    }
    fn approver<'a>(dir: &std::path::Path, channel: &'a dyn Channel) -> Approver<'a> {
        Approver {
            dir: dir.to_path_buf(),
            protector: &Xor,
            head_copy: Some(dir.with_extension("head")),
            channel,
            alert: &AuditOnly,
        }
    }
    fn open(dir: &std::path::Path) -> Store {
        Store::open(dir, &Xor, Some(dir.with_extension("head"))).unwrap()
    }

    const VALUE: &str = "postgres://owner:Sup3rS3cret@db/tj";

    fn vault() -> Vault {
        let mut v = Vault::default();
        v.secrets.insert(
            "TJ_DB".into(),
            Secret {
                value: VALUE.into(),
                env_var: "DATABASE_URL".into(),
                access: Access::Read,
                created_at: Utc::now(),
                rotate_by: None,
            },
        );
        v
    }
    fn who() -> Requester {
        Requester {
            role: "humboldt".into(),
            session_id: "s-1".into(),
            claude_pid: 10,
            claude_start_secs: 100,
            managed: true,
        }
    }
    fn args(argv: &[&str]) -> RunArgs {
        let mut all = vec![
            "TJ_DB",
            "--reason",
            "seed the prod db",
            "--window-mins",
            "60",
            "--",
        ];
        all.extend_from_slice(argv);
        parse_run(&all.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }
    fn run(
        dir: &std::path::Path,
        ch: &dyn Channel,
        a: &RunArgs,
        log: &mut Vec<Event>,
    ) -> Result<Released, String> {
        authorize(a, &vault(), &who(), &approver(dir, ch), log)
    }
    fn kinds(log: &[Event]) -> Vec<&str> {
        log.iter().map(|e| e.event.as_str()).collect()
    }

    #[test]
    fn parse_requires_a_reason_and_a_command() {
        let p = |v: &[&str]| parse_run(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(p(&["TJ_DB", "--", "psql"]).is_err(), "no reason");
        assert!(
            p(&["TJ_DB", "--reason", "short", "--", "psql"]).is_err(),
            "reason too short"
        );
        assert!(
            p(&["TJ_DB", "--reason", "seed the prod db", "--"]).is_err(),
            "no command"
        );
        assert!(
            p(&["tj_db", "--reason", "seed the prod db", "--", "psql"]).is_err(),
            "bad name"
        );
        let ok = p(&[
            "TJ_DB",
            "--reason",
            "seed the prod db",
            "--window-mins",
            "30",
            "--",
            "psql",
            "-f",
            "x",
        ])
        .unwrap();
        assert_eq!(ok.argv, vec!["psql", "-f", "x"]);
        assert_eq!(ok.window, Some(chrono::Duration::minutes(30)));
    }

    /// Board 134: a window that is not positive or cannot be represented is
    /// refused at parse, never a panic.
    #[test]
    fn a_window_must_be_positive_and_representable() {
        let p = |w: &str| {
            parse_run(
                &[
                    "TJ_DB",
                    "--reason",
                    "seed the prod db",
                    "--window-mins",
                    w,
                    "--",
                    "psql",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            )
        };
        assert!(p("0").is_err());
        assert!(p("-5").is_err());
        // second review of #2b, finding 7: no wait outlives its reservation
        let w = |s: &str| {
            parse_run(
                &[
                    "TJ_DB",
                    "--reason",
                    "seed the prod db",
                    "--wait-secs",
                    s,
                    "--",
                    "psql",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
            )
        };
        assert!(w("841").is_err());
        assert!(w("3600").is_err());
        assert_eq!(w("840").unwrap().wait, MAX_WAIT);
        assert!(p("9223372036854775807").is_err());
        assert_eq!(p("2880").unwrap().window, Some(chrono::Duration::days(2)));
    }

    /// The default grant ends at the next local midnight, the same one the
    /// prompt's "longer than today" check uses; a window is kept as asked.
    #[test]
    fn the_grant_asked_for() {
        use chrono::TimeZone;
        let at = Local
            .with_ymd_and_hms(2026, 10, 1, 9, 0, 0)
            .single()
            .unwrap();
        assert_eq!(grant_for(None, at), Grant::Until(next_local_midnight(at)));
        assert_eq!(
            grant_for(Some(chrono::Duration::days(30)), at),
            Grant::for_duration(chrono::Duration::days(30))
        );
    }

    #[test]
    fn first_use_asks_and_stores_the_grant() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        let mut log = vec![];
        let r = run(&d, &ch, &args(&["psql"]), &mut log).unwrap();
        assert!(r.newly_granted);
        assert_eq!(r.secret.value, VALUE);
        assert_eq!(asked(&ch).len(), 1);
        assert_eq!(kinds(&log), ["granted", "used"]);
        let s = open(&d);
        let g = s.find(KindId::Secret, "TJ_DB", &who()).expect("stored");
        assert_eq!(g.id, r.grant_id);
        assert_eq!(g.approval.expires_at, r.expires_at);
    }

    #[test]
    fn a_second_use_does_not_ask() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        let first = run(&d, &ch, &args(&["psql"]), &mut vec![]).unwrap();
        let mut log = vec![];
        let r = run(&d, &ch, &args(&["psql", "-c", "select 1"]), &mut log).unwrap();
        assert!(!r.newly_granted);
        assert_eq!(r.grant_id, first.grant_id);
        assert_eq!(asked(&ch).len(), 1);
        assert_eq!(kinds(&log), ["used"]);
    }

    /// A lane restart (a new claude process) voids the approval.
    #[test]
    fn a_restarted_lane_is_asked_again() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        run(&d, &ch, &args(&["psql"]), &mut vec![]).unwrap();
        let mut restarted = who();
        restarted.claude_start_secs = 999;
        let r = authorize(
            &args(&["psql"]),
            &vault(),
            &restarted,
            &approver(&d, &ch),
            &mut vec![],
        )
        .unwrap();
        assert!(r.newly_granted);
        assert_eq!(asked(&ch).len(), 2);
    }

    /// Board 134: the end the person is shown is exactly the end stored,
    /// including one past midnight, which is shown loudly.
    #[test]
    fn the_end_shown_is_the_end_stored() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        let mut a = args(&["psql"]);
        a.window = Some(chrono::Duration::hours(30));
        let r = run(&d, &ch, &a, &mut vec![]).unwrap();
        let stored = open(&d)
            .find(KindId::Secret, "TJ_DB", &who())
            .unwrap()
            .approval
            .expires_at
            .unwrap();
        assert_eq!(r.expires_at, Some(stored));
        let prompt = &asked(&ch)[0];
        let shown = stored
            .with_timezone(&Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        assert!(prompt.contains(&shown), "{prompt}");
        assert!(prompt.contains("LONGER THAN TODAY"), "{prompt}");
    }

    /// Board 134 (CireSnave, 2026-10-07): the prompt is who, which secret
    /// and how long. The command and the reason are in the access log.
    #[test]
    fn the_command_and_reason_go_to_the_log_not_the_prompt() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        let mut log = vec![];
        run(&d, &ch, &args(&["psql"]), &mut log).unwrap();
        let prompt = &asked(&ch)[0];
        assert_eq!(prompt.lines().count(), 3, "{prompt}");
        assert!(prompt.contains("Wants: use a secret: TJ_DB"), "{prompt}");
        assert!(!prompt.contains("psql"), "{prompt}");
        assert!(!prompt.contains("seed the prod db"), "{prompt}");
        assert!(
            log.iter()
                .all(|e| e.command == "psql" && e.reason == "seed the prod db"),
            "{log:?}"
        );
    }

    #[test]
    fn denied_timed_out_and_unavailable_release_nothing() {
        for answer in [
            ConsentOutcome::Denied,
            ConsentOutcome::TimedOut,
            ConsentOutcome::Unavailable("no hello".into()),
        ] {
            let d = store_dir();
            let ch = hello(answer);
            let mut log = vec![];
            let err = run(&d, &ch, &args(&["psql"]), &mut log).unwrap_err();
            assert!(!err.contains(VALUE));
            assert!(open(&d).active().is_empty());
            assert_eq!(log.len(), 1);
        }
    }

    /// #2b, the reason for the move: a secret's prompts pass the store's
    /// gate. After a denial the same lane may not ask about the same secret
    /// again for 10 minutes, and the person is not asked.
    #[test]
    fn a_secrets_prompts_pass_the_gate() {
        let d = store_dir();
        let no = hello(ConsentOutcome::Denied);
        run(&d, &no, &args(&["psql"]), &mut vec![]).unwrap_err();
        let yes = hello(ConsentOutcome::Approved);
        let mut log = vec![];
        let err = run(&d, &yes, &args(&["psql"]), &mut log).unwrap_err();
        assert!(err.contains("minutes ago"), "{err}");
        assert!(asked(&yes).is_empty(), "the person was asked again");
        assert_eq!(kinds(&log), ["gate-refused"]);
    }

    /// #2b: `with-secret revoke NAME` (and `user-request revoke --all`) made
    /// while the person is deciding ends the prompt: the approval that
    /// follows never becomes a grant, and nothing is released. Also proves
    /// the store is not held while the person decides: the revoke opens it.
    #[test]
    fn a_revocation_while_the_person_decides_wins() {
        for how in ["revoke-name", "revoke-all"] {
            let d = store_dir();
            let dd = d.clone();
            let ch = hello_while(ConsentOutcome::Approved, move || {
                let mut s = open(&dd);
                match how {
                    "revoke-name" => s.revoke_matching(KindId::Secret, Some("TJ_DB")).map(|_| ()),
                    _ => s.revoke_all().map(|_| ()),
                }
                .unwrap()
            });
            let mut log = vec![];
            let err = run(&d, &ch, &args(&["psql"]), &mut log).unwrap_err();
            assert!(err.contains("already ended"), "{how}: {err}");
            assert!(!err.contains(VALUE));
            assert_eq!(kinds(&log), ["refused"], "{how}");
            assert!(open(&d).active().is_empty(), "{how}: a grant landed");
        }
    }

    /// #2b: a revoked approval is not honoured, and an old copy of the
    /// grants file put back does not bring it back (the limit #115 named).
    #[test]
    fn a_revoked_approval_stays_revoked_even_from_an_old_file() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        run(&d, &ch, &args(&["psql"]), &mut vec![]).unwrap();
        let old = std::fs::read(d.join("grants.json")).unwrap();
        assert_eq!(
            open(&d)
                .revoke_matching(KindId::Secret, Some("TJ_DB"))
                .unwrap(),
            1
        );
        // revoked: the next use asks again rather than reusing it
        let no = hello(ConsentOutcome::Denied);
        assert!(run(&d, &no, &args(&["psql"]), &mut vec![]).is_err());
        assert_eq!(asked(&no).len(), 1, "it reused a revoked approval");
        // the old file put back: the store sees the rollback and fails
        // closed - nothing released, nobody asked
        std::fs::write(d.join("grants.json"), old).unwrap();
        assert!(open(&d).trustworthy().is_err());
        let yes = hello(ConsentOutcome::Approved);
        let err = run(&d, &yes, &args(&["psql"]), &mut vec![]).unwrap_err();
        assert!(!err.contains(VALUE));
        assert!(asked(&yes).is_empty());
    }

    /// An untrustworthy store fails closed: no grant is honoured and the
    /// person is not asked.
    #[test]
    fn an_untrustworthy_store_releases_nothing_and_asks_nobody() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        run(&d, &ch, &args(&["psql"]), &mut vec![]).unwrap();
        std::fs::remove_file(d.with_extension("head")).unwrap();
        let mut log = vec![];
        let err = run(&d, &ch, &args(&["psql"]), &mut log).unwrap_err();
        assert!(!err.contains(VALUE));
        assert_eq!(asked(&ch).len(), 1, "asked on an untrusted store");
        assert_eq!(kinds(&log), ["gate-refused"]);
    }

    /// A secret is never granted forever, and an end that cannot be
    /// represented is refused without asking.
    #[test]
    fn an_impossible_window_is_refused_without_asking() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        let mut a = args(&["psql"]);
        a.window = Some(chrono::Duration::MAX);
        let err = run(&d, &ch, &a, &mut vec![]).unwrap_err();
        assert!(!err.contains(VALUE), "{err}");
        assert!(asked(&ch).is_empty());
        assert!(!d.exists(), "a prompt was reserved");
    }

    #[test]
    fn a_dump_child_is_refused_before_the_store_or_consent() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        for argv in [&["env"][..], &["printenv"], &["cmd", "/c", "set"]] {
            let err = run(&d, &ch, &args(argv), &mut vec![]).unwrap_err();
            assert!(err.contains("blocked"), "{err}");
        }
        assert!(asked(&ch).is_empty(), "consent was requested for a dump");
        assert!(!d.exists(), "the store was touched");
    }

    #[test]
    fn an_unknown_secret_is_refused_before_the_store_or_consent() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        let mut a = args(&["psql"]);
        a.secret = "NOPE_NOPE".into();
        assert!(run(&d, &ch, &a, &mut vec![]).is_err());
        assert!(asked(&ch).is_empty());
        assert!(!d.exists(), "the store was touched");
    }

    #[test]
    fn the_log_never_contains_the_value() {
        let d = store_dir();
        let ch = hello(ConsentOutcome::Approved);
        let mut log = vec![];
        run(&d, &ch, &args(&["psql"]), &mut log).unwrap();
        assert!(!serde_json::to_string(&log).unwrap().contains("Sup3rS3cret"));
        assert!(!std::fs::read_to_string(d.join("audit.jsonl"))
            .unwrap()
            .contains("Sup3rS3cret"));
    }
}
