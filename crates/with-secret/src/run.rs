// SPDX-License-Identifier: MIT OR Apache-2.0
//! The decision: may THIS requester use THIS secret for THIS command now.
//! No I/O - `main.rs` loads, spawns and saves. ⚠️ Every refusal path releases
//! nothing, and consent is asked only after every cheap refusal has passed.

use std::time::Duration;

use chrono::{DateTime, Local, Utc};

use crate::approval::{expiry, Approval, ApprovalCache};
use crate::audit::Event;
use crate::consent::{prompt_text, Consent, ConsentOutcome, ConsentRequest};
use crate::dumpcheck::command_dump_reason;
use crate::identity::Requester;
use crate::vault::{validate_name, Secret, Vault};

pub const MIN_REASON_CHARS: usize = 10;
/// Under the 10-minute ceiling of a lane's Bash tool call; a lane calling
/// `with-secret` should pass `timeout: 600000`.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(540);

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
                wait = Duration::from_secs(val.parse().map_err(|_| "--wait-secs: not a number")?)
            }
            "--window-mins" => {
                window = Some(chrono::Duration::minutes(
                    val.parse().map_err(|_| "--window-mins: not a number")?,
                ))
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

#[derive(Debug)]
pub struct Released {
    pub secret: Secret,
    pub approval: Approval,
    pub newly_granted: bool,
}

fn event(kind: &str, a: &RunArgs, who: &Requester, now: DateTime<Utc>) -> Event {
    Event {
        at: now,
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
    cache: &mut ApprovalCache,
    who: &Requester,
    consent: &dyn Consent,
    now: DateTime<Local>,
    log: &mut Vec<Event>,
) -> Result<Released, String> {
    let utc = now.with_timezone(&Utc);
    let command = a.argv.join(" ");
    if let Some(why) = command_dump_reason(&command) {
        log.push(event("refused", a, who, utc));
        return Err(format!(
            "with-secret: blocked - {why}; a secret is never handed to an env dump"
        ));
    }
    let Some(secret) = vault.secrets.get(&a.secret) else {
        log.push(event("refused", a, who, utc));
        return Err(format!(
            "no secret named {} in the vault (`with-secret vault list`)",
            a.secret
        ));
    };
    if let Some(found) = cache.find(&a.secret, who, utc) {
        log.push(event("used", a, who, utc));
        return Ok(Released {
            secret: secret.clone(),
            approval: found.clone(),
            newly_granted: false,
        });
    }
    let expires_at = expiry(now, a.window);
    let prompt = prompt_text(&ConsentRequest {
        secret: a.secret.clone(),
        requester: who.clone(),
        command,
        reason: a.reason.clone(),
        expires_at,
    });
    let refusal = match consent.ask(&prompt, a.wait) {
        ConsentOutcome::Approved => None,
        ConsentOutcome::Denied => Some(("denied", "CireSnave declined".to_string())),
        ConsentOutcome::TimedOut => {
            Some(("timed-out", "no answer before the wait ran out".to_string()))
        }
        ConsentOutcome::Unavailable(why) => Some(("unavailable", why)),
    };
    if let Some((kind, why)) = refusal {
        log.push(event(kind, a, who, utc));
        return Err(format!("with-secret: {} not released - {why}", a.secret));
    }
    let approval = Approval {
        secret: a.secret.clone(),
        requester: who.clone(),
        granted_at: utc,
        expires_at,
    };
    cache.add(approval.clone());
    log.push(event("granted", a, who, utc));
    log.push(event("used", a, who, utc));
    Ok(Released {
        secret: secret.clone(),
        approval,
        newly_granted: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Access;
    use chrono::{Local, TimeZone};
    use std::cell::RefCell;

    struct FakeConsent {
        answer: ConsentOutcome,
        asked: RefCell<Vec<String>>,
    }
    impl FakeConsent {
        fn new(answer: ConsentOutcome) -> Self {
            Self {
                answer,
                asked: RefCell::new(vec![]),
            }
        }
    }
    impl Consent for FakeConsent {
        fn ask(&self, prompt: &str, _: std::time::Duration) -> ConsentOutcome {
            self.asked.borrow_mut().push(prompt.to_string());
            match &self.answer {
                ConsentOutcome::Approved => ConsentOutcome::Approved,
                ConsentOutcome::Denied => ConsentOutcome::Denied,
                ConsentOutcome::TimedOut => ConsentOutcome::TimedOut,
                ConsentOutcome::Unavailable(s) => ConsentOutcome::Unavailable(s.clone()),
            }
        }
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
        let mut all = vec!["TJ_DB", "--reason", "seed the prod db", "--"];
        all.extend_from_slice(argv);
        parse_run(&all.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }
    fn cache() -> ApprovalCache {
        ApprovalCache::load(std::path::Path::new("does-not-exist.json"), b"k".repeat(32)).0
    }
    fn now() -> chrono::DateTime<Local> {
        Local
            .with_ymd_and_hms(2026, 10, 1, 9, 0, 0)
            .single()
            .unwrap()
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

    #[test]
    fn first_use_asks_and_caches() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut c = cache();
        let mut log = vec![];
        let r = authorize(
            &args(&["psql"]),
            &vault(),
            &mut c,
            &who(),
            &consent,
            now(),
            &mut log,
        )
        .unwrap();
        assert!(r.newly_granted);
        assert_eq!(r.secret.value, VALUE);
        assert_eq!(consent.asked.borrow().len(), 1);
        assert_eq!(c.entries.len(), 1);
        assert_eq!(
            log.iter().map(|e| e.event.as_str()).collect::<Vec<_>>(),
            ["granted", "used"]
        );
    }

    #[test]
    fn second_use_same_day_does_not_ask() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut c = cache();
        let mut log = vec![];
        authorize(
            &args(&["psql"]),
            &vault(),
            &mut c,
            &who(),
            &consent,
            now(),
            &mut log,
        )
        .unwrap();
        let r = authorize(
            &args(&["psql", "-c", "select 1"]),
            &vault(),
            &mut c,
            &who(),
            &consent,
            now() + chrono::Duration::hours(2),
            &mut log,
        )
        .unwrap();
        assert!(!r.newly_granted);
        assert_eq!(consent.asked.borrow().len(), 1);
    }

    #[test]
    fn denied_timed_out_and_unavailable_release_nothing() {
        for answer in [
            ConsentOutcome::Denied,
            ConsentOutcome::TimedOut,
            ConsentOutcome::Unavailable("no hello".into()),
        ] {
            let mut c = cache();
            let mut log = vec![];
            let err = authorize(
                &args(&["psql"]),
                &vault(),
                &mut c,
                &who(),
                &FakeConsent::new(answer),
                now(),
                &mut log,
            )
            .unwrap_err();
            assert!(!err.contains(VALUE));
            assert!(c.entries.is_empty());
            assert_eq!(log.len(), 1);
        }
    }

    #[test]
    fn test_dump_child_refused_before_consent() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut log = vec![];
        for argv in [&["env"][..], &["printenv"], &["cmd", "/c", "set"]] {
            let err = authorize(
                &args(argv),
                &vault(),
                &mut cache(),
                &who(),
                &consent,
                now(),
                &mut log,
            )
            .unwrap_err();
            assert!(err.contains("blocked"), "{err}");
        }
        assert!(
            consent.asked.borrow().is_empty(),
            "consent was requested for a dump"
        );
    }

    #[test]
    fn unknown_secret_is_refused_without_asking() {
        let consent = FakeConsent::new(ConsentOutcome::Approved);
        let mut a = args(&["psql"]);
        a.secret = "NOPE_NOPE".into();
        assert!(authorize(
            &a,
            &vault(),
            &mut cache(),
            &who(),
            &consent,
            now(),
            &mut vec![]
        )
        .is_err());
        assert!(consent.asked.borrow().is_empty());
    }

    #[test]
    fn the_log_never_contains_the_value() {
        let mut log = vec![];
        authorize(
            &args(&["psql"]),
            &vault(),
            &mut cache(),
            &who(),
            &FakeConsent::new(ConsentOutcome::Approved),
            now(),
            &mut log,
        )
        .unwrap();
        assert!(!serde_json::to_string(&log).unwrap().contains("Sup3rS3cret"));
    }
}
