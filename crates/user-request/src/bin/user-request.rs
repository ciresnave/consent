// SPDX-License-Identifier: MIT OR Apache-2.0
//! `user-request list | revoke <id> | revoke --all | repair | audit verify`.
//!
//! Revoking and repairing need no Windows Hello: they only remove privilege
//! (PM condition (c)). Every change is audited by the store before it is
//! saved.

use std::process::ExitCode;

use chrono::{Local, Utc};
use user_request::locate::{dir, head_copy, PROTECTOR};
use user_request::store::{Store, Untrusted, GATE_CLOSED_AFTER_REPAIR};

/// The store, or `None` when there is none yet. Says which store it is and
/// whether it can be trusted. A read-only open writes nothing (review 3,
/// M4).
fn open(read_only: bool) -> Result<Option<Store>, String> {
    let dir = dir()?;
    eprintln!("user-request: store {}", dir.display());
    let s = if read_only {
        Store::inspect(&dir, &PROTECTOR, Some(head_copy()))?
    } else {
        Store::open_existing(&dir, &PROTECTOR, Some(head_copy()))?
    };
    if let Some(Err(why)) = s.as_ref().map(Store::trustworthy) {
        eprintln!("user-request: ⚠️ {why}");
    }
    Ok(s)
}

fn list() -> Result<u8, String> {
    let Some(s) = open(true)? else {
        println!("no store yet: nothing has been granted");
        return Ok(0);
    };
    // review M-b, 3 M2: grants that could not be read are unknown, which is
    // not the same as none
    if let Some(Untrusted::Key(_)) = s.untrusted() {
        println!("*** GRANTS UNKNOWN: the store's key cannot be trusted ***");
        println!("`user-request repair` revokes every grant and restores the store");
        return Ok(1);
    }
    let untrusted = s.trustworthy().is_err();
    let active = s.active();
    if untrusted {
        println!("*** THE STORE CANNOT BE TRUSTED: none of these is honoured until it is ***");
    }
    if !s.grants_known() {
        println!("*** SOME GRANTS ARE UNKNOWN: the grants file failed its check ***");
    }
    if active.is_empty() {
        println!(
            "no active grants{}",
            if s.grants_known() {
                ""
            } else {
                " that can be read"
            }
        );
        return Ok(u8::from(untrusted));
    }
    // FOREVER grants first, loud (PM condition (a))
    let (forever, timed): (Vec<_>, Vec<_>) = active
        .into_iter()
        .partition(|g| g.approval.expires_at.is_none());
    if !forever.is_empty() {
        println!("*** FOREVER GRANTS (until revoked) ***");
        for g in &forever {
            let a = &g.approval;
            println!(
                "  {}  {:?}  {}  by '{}'",
                g.id, a.kind, a.subject, a.requester.role
            );
        }
    }
    for g in &timed {
        let a = &g.approval;
        let until = a
            .expires_at
            .map(|e| {
                e.with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M %Z")
                    .to_string()
            })
            .unwrap_or_default();
        println!(
            "  {}  {:?}  {}  by '{}'  until {until}",
            g.id, a.kind, a.subject, a.requester.role
        );
    }
    Ok(u8::from(untrusted))
}

fn revoke(target: &str) -> Result<u8, String> {
    let Some(mut s) = open(false)? else {
        if target == "--all" {
            // the panic button succeeds when there is nothing to stop
            println!("no store yet: nothing to revoke");
            return Ok(0);
        }
        return Err("no store yet: nothing to revoke".into());
    };
    if target == "--all" {
        let n = s.revoke_all()?;
        println!("revoked {n} grant(s)");
        return Ok(0);
    }
    if !s.revoke(target)? {
        return Err(format!("no active grant with id {target}"));
    }
    println!("revoked {target}");
    Ok(0)
}

fn repair() -> Result<u8, String> {
    let now = Utc::now();
    let Some(mut s) = open(false)? else {
        println!("no store yet: nothing to repair");
        return Ok(0);
    };
    let r = s.repair(&PROTECTOR)?;
    let resume = (now + GATE_CLOSED_AFTER_REPAIR)
        .with_timezone(&Local)
        .format("%H:%M %Z");
    // review 3, M1: grants that could not be read were not counted
    let unknown = if r.grants_known {
        String::new()
    } else {
        " and every grant it could not read".to_string()
    };
    println!(
        "repaired: revoked {} grant(s){unknown}; prompts are refused until {resume}",
        r.revoked
    );
    for f in &r.set_aside {
        println!("  set aside: {f}");
    }
    Ok(0)
}

fn verify() -> Result<u8, String> {
    let Some(s) = open(true)? else {
        println!("no store yet: no audit log to verify");
        return Ok(0);
    };
    let report = s.verify_audit()?;
    s.trustworthy()?;
    let head = match report.head_behind {
        0 => "head copy agrees".to_string(),
        n => format!(
            "head copy {n} line(s) behind (it could not be updated; the next change catches it up)"
        ),
    };
    println!(
        "audit chain intact: {} line(s) checked of {}, {head}",
        report.checked, report.lines
    );
    if report.repaired_resets > 0 {
        println!(
            "({} earlier chain reset(s), acknowledged by a repair)",
            report.repaired_resets
        );
    }
    Ok(0)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["list"] => list(),
        ["revoke", target] => revoke(target),
        ["repair"] => repair(),
        ["audit", "verify"] => verify(),
        _ => Err(
            "usage: user-request list | revoke <id> | revoke --all | repair | audit verify".into(),
        ),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("user-request: {e}");
            ExitCode::from(1)
        }
    }
}
