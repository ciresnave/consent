// SPDX-License-Identifier: MIT OR Apache-2.0
//! `with-secret` - WITH-SECRET-DESIGN.md. ⚠️ STOPS ACCIDENTAL EXPOSURE, NOT
//! DELIBERATE MISUSE (§3): a process that is given a secret can print it, and
//! any process running as this Windows user can decrypt the vault.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use chrono::{Local, NaiveDate, Utc};
use lane_state::facts::{SysinfoFacts, SystemFacts};
use user_request::channel::HelloChannel;
use user_request::locate;
use user_request::request::KindId;
use user_request::store::{AuditOnly, Store};
use with_secret::consent::{store_prompt_text, Consent, ConsentOutcome};
use with_secret::mask::{mask_json, masks_json, HashMask, StreamMasker};
use with_secret::platform::SelectedProtector;
use with_secret::run::{authorize, parse_run, Approver, DEFAULT_WAIT};
use with_secret::vault::*;
use with_secret::{allow, audit, dumpcheck, identity};

fn data_dir() -> Result<PathBuf, String> {
    // ⚠️ TEST-ONLY override. Pointing it elsewhere reaches an EMPTY vault, not
    // anyone else's secrets.
    match std::env::var_os("WITH_SECRET_DIR") {
        Some(d) => Ok(d.into()),
        None => default_dir(),
    }
}

/// The user-request store, where approvals live since #2b. ⚠️ A test that
/// points WITH_SECRET_DIR at a scratch vault must point the approvals at a
/// scratch store AND a scratch head copy too (`USER_REQUEST_DIR`,
/// `USER_REQUEST_HEAD`, honoured in debug builds only): otherwise its
/// `revoke --all` would end the person's real approvals, or its audit head
/// would overwrite the real store's and untrust it (second review of #2b,
/// finding 1).
fn approvals_dir() -> Result<PathBuf, String> {
    if std::env::var_os("WITH_SECRET_DIR").is_some()
        && (locate::env_override("USER_REQUEST_DIR").is_none()
            || locate::env_override("USER_REQUEST_HEAD").is_none())
    {
        return Err(
            "WITH_SECRET_DIR points at a test vault, but the approvals would be the \
             real ones: set USER_REQUEST_DIR and USER_REQUEST_HEAD too (debug builds only)"
                .into(),
        );
    }
    locate::dir()
}

fn store() -> Result<VaultStore<SelectedProtector>, String> {
    Ok(VaultStore {
        dir: data_dir()?,
        protector: SelectedProtector::new(),
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("hook") => return hook(args.get(1).map(String::as_str)),
        Some("vault") => vault_cmd(&args[1..]),
        Some("revoke") => revoke_cmd(&args[1..]),
        Some("--help") | Some("-h") | None => {
            print!("{HELP}");
            Ok(0)
        }
        Some(_) => run(&args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}

const HELP: &str = "\
with-secret NAME --reason \"why\" [--wait-secs N] [--window-mins M] -- <command> [args...]
    Runs <command> with secret NAME in its environment (and nowhere else), after
    CireSnave approves via Windows Hello. One approval: one lane, one secret,
    void on lane restart, until the end the prompt shows: --window-mins M from
    now if given (however long; past today it is shown LOUDLY), else midnight.
    Call it from a lane's Bash tool with timeout 600000: the prompt waits up to 9 min.
    The prompt names the lane, the secret and the duration; the command and the
    reason go to the access log. Cancel denies.
    Approvals live in the user-request store; prompts pass its gate (no re-asking
    within 10 min of a refusal, at most 6 prompts per lane per hour).
with-secret vault list | set NAME --env VAR --access read|write [--lanes a,b|none] [--rotate-by YYYY-MM-DD]
                | allow NAME (--lanes a,b|none | --add a,b | --remove a,b) | allow --file lanes.json
                | remove NAME | check
with-secret revoke NAME | --all     end approvals now (no Hello: it only removes privilege)
with-secret hook pre-tool-use | post-tool-use     (Claude Code hooks; JSON on stdin)

This stops ACCIDENTAL exposure. It does not stop a process that has a secret from
printing it, nor a same-user process from decrypting the vault. WITH-SECRET-DESIGN.md §3.
";

fn run(args: &[String]) -> Result<u8, String> {
    let a = parse_run(args)?;
    let store = store()?;
    let vault = store.load()?;
    let table = SysinfoFacts::new(PathBuf::new())
        .process_table()
        .map_err(|e| format!("{e:?}"))?;
    let who = identity::resolve(
        &table,
        std::process::id(),
        &identity::load_states(&lane_state::platform::state_dir()),
    )?;
    let channel = HelloChannel::new(user_request::platform::platform_consent());
    let approver = Approver {
        dir: approvals_dir()?,
        protector: &locate::PROTECTOR,
        head_copy: Some(locate::head_copy()),
        channel: &channel,
        alert: &AuditOnly,
    };
    let mut log = Vec::new();
    let decided = authorize(&a, &vault, &who, &approver, &mut log);
    let audit_path = store.dir.join(AUDIT_FILE);
    for e in &log {
        if let Err(err) = audit::append(&audit_path, e) {
            eprintln!("with-secret: audit log: {err}");
        }
    }
    let released = decided?;
    spawn_masked(&a.argv, &a.secret, &released.secret)
}

/// ⚠️ The ONLY place a value enters an environment: this child's. stdout and
/// stderr are piped through a StreamMasker each, so the child's own output
/// cannot print the value verbatim. Grandchildren inherit the variable -
/// design §3.
fn spawn_masked(argv: &[String], name: &str, secret: &Secret) -> Result<u8, String> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .env(&secret.env_var, &secret.value)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", argv[0]))?;
    let pump = |mut src: Box<dyn Read + Send>,
                mut dst: Box<dyn Write + Send>,
                value: String,
                name: String| {
        std::thread::spawn(move || {
            let mut m = StreamMasker::new(&[(name.as_str(), value.as_str())]);
            let mut buf = [0u8; 8192];
            loop {
                match src.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = dst.write_all(&m.push(&buf[..n]));
                        let _ = dst.flush();
                    }
                }
            }
            let _ = dst.write_all(&m.finish());
            let _ = dst.flush();
        })
    };
    let out = pump(
        Box::new(child.stdout.take().unwrap()),
        Box::new(std::io::stdout()),
        secret.value.clone(),
        name.to_string(),
    );
    let err = pump(
        Box::new(child.stderr.take().unwrap()),
        Box::new(std::io::stderr()),
        secret.value.clone(),
        name.to_string(),
    );
    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = out.join();
    let _ = err.join();
    Ok(status.code().map(|c| c.clamp(0, 255) as u8).unwrap_or(1))
}

fn require_hello(action: &str, name: &str) -> Result<(), String> {
    // bound to the action and the secret's name, so a provider that signs
    // (a security key) signs this ask and no other
    let binding = user_request::channel::binding_for(
        "with-secret.v1.binding",
        &[action.as_bytes(), name.as_bytes()],
    );
    let consent = user_request::platform::platform_consent();
    match consent.ask_bound(&store_prompt_text(action, name), &binding, DEFAULT_WAIT) {
        ConsentOutcome::Approved => Ok(()),
        other => Err(format!("not {action}d: {other:?}")),
    }
}

/// `with-secret revoke NAME | --all`: ends secrets' approvals now, for
/// every lane, and any prompt for them still awaiting an answer. No Hello:
/// it only removes privilege. Revocations are tombstones in the
/// user-request store, so an old file put back cannot undo them.
/// (`user-request revoke --all` ends every kind of grant.)
fn revoke_cmd(args: &[String]) -> Result<u8, String> {
    let which = match args {
        [all] if all == "--all" => None,
        [name] => {
            validate_name(name)?;
            Some(name.as_str())
        }
        _ => return Err("usage: with-secret revoke NAME | --all".into()),
    };
    let dir = approvals_dir()?;
    let Some(mut s) = Store::open_existing(&dir, &locate::PROTECTOR, Some(locate::head_copy()))?
    else {
        println!("revoked 0 approval(s)");
        return Ok(0);
    };
    let n = s.revoke_matching(KindId::Secret, which)?;
    println!("revoked {n} approval(s)");
    Ok(0)
}

fn vault_cmd(args: &[String]) -> Result<u8, String> {
    let store = store()?;
    match args.first().map(String::as_str) {
        Some("list") => {
            let today = Local::now().date_naive();
            for (name, s) in &store.load()?.secrets {
                let overdue = s.rotate_by.is_some_and(|d| d < today);
                println!(
                    "{name}  env={}  access={:?}  created={}  rotate_by={}  lanes={}{}",
                    s.env_var,
                    s.access,
                    s.created_at.format("%Y-%m-%d"),
                    s.rotate_by.map(|d| d.to_string()).unwrap_or("-".into()),
                    if s.lanes.is_empty() {
                        "none".to_string()
                    } else {
                        s.lanes.join(",")
                    },
                    if overdue {
                        "  ⚠️ PAST ROTATE-BY"
                    } else {
                        ""
                    }
                );
            }
            Ok(0)
        }
        Some("set") => {
            let name = args
                .get(1)
                .ok_or("vault set NAME --env VAR --access read|write")?;
            validate_name(name)?;
            let opt = |flag: &str| {
                args.iter()
                    .position(|a| a == flag)
                    .and_then(|i| args.get(i + 1))
                    .cloned()
            };
            let env_var = opt("--env").ok_or("--env VAR is required")?;
            let access = match opt("--access").as_deref() {
                Some("read") => Access::Read,
                Some("write") => Access::Write,
                _ => return Err("--access read|write is required".into()),
            };
            let rotate_by = opt("--rotate-by")
                .map(|d| {
                    NaiveDate::parse_from_str(&d, "%Y-%m-%d")
                        .map_err(|e| format!("--rotate-by: {e}"))
                })
                .transpose()?;
            // fail before the person types the secret or answers Hello; the
            // list actually stored is re-derived below from the vault as it is
            lanes_for_set(opt("--lanes").as_deref(), store.load()?.secrets.get(name))?;
            let value = read_value_from_console()?;
            validate_value(&value)?;
            require_hello("store", name)?;
            let mut vault = store.load()?;
            let lanes = lanes_for_set(opt("--lanes").as_deref(), vault.secrets.get(name))?;
            vault.secrets.insert(
                name.clone(),
                Secret {
                    value,
                    env_var,
                    access,
                    created_at: Utc::now(),
                    rotate_by,
                    lanes,
                },
            );
            store.save(&vault, masks_json(&vault)?)?;
            println!("stored {name}");
            Ok(0)
        }
        Some("allow") => allow_cmd(&store, &args[1..]),
        Some("remove") => {
            let name = args.get(1).ok_or("vault remove NAME")?;
            require_hello("remove", name)?;
            let mut vault = store.load()?;
            vault
                .secrets
                .remove(name)
                .ok_or_else(|| format!("no secret named {name}"))?;
            store.save(&vault, masks_json(&vault)?)?;
            println!("removed {name}");
            Ok(0)
        }
        Some("check") => {
            let p = SelectedProtector::new();
            let ok = p
                .protect(b"with-secret-check")
                .and_then(|b| p.unprotect(&b))
                .map(|b| b == b"with-secret-check")
                .unwrap_or(false);
            println!(
                "{} round trip: {}",
                with_secret::platform::PROTECTION_NAME,
                if ok { "ok" } else { "FAILED" }
            );
            println!("Windows Hello: run `with-secret vault set` to see the prompt; `check` never prompts.");
            Ok(if ok { 0 } else { 1 })
        }
        _ => Err("vault list | set | allow | remove | check".into()),
    }
}

/// `vault allow`: change who may request entries, without the values. A
/// person at a console only: a managed lane is refused, and the Hello text
/// shows every entry (counted past eight) with its new list.
fn allow_cmd(store: &VaultStore<SelectedProtector>, args: &[String]) -> Result<u8, String> {
    use std::io::IsTerminal;
    let changes = allow::parse_args(args, |f| {
        std::fs::read_to_string(f).map_err(|e| format!("--file {f}: {e}"))
    })?;
    if !std::io::stdin().is_terminal() {
        return Err("vault allow must be run by a person at a console".into());
    }
    let table = SysinfoFacts::new(PathBuf::new())
        .process_table()
        .map_err(|e| format!("{e:?}"))?;
    let states = identity::load_states(&lane_state::platform::state_dir());
    let who = identity::resolve(&table, std::process::id(), &states)?;
    if who.managed {
        return Err(format!(
            "vault allow is refused for a lane ({}): ask the PM, who asks CireSnave",
            who.role
        ));
    }
    let vault = store.load()?;
    let plan = allow::plan(&vault, &changes)?;
    let roles: Vec<String> = states.iter().map(|s| s.role.clone()).collect();
    for w in allow::warnings(&plan, &roles) {
        eprintln!("warning: {w}");
    }
    let parts = allow::binding_parts(&plan);
    let part_refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let binding = user_request::channel::binding_for("with-secret.v1.binding", &part_refs);
    let consent = user_request::platform::platform_consent();
    match consent.ask_bound(&allow::prompt_text(&plan), &binding, DEFAULT_WAIT) {
        ConsentOutcome::Approved => {}
        other => return Err(format!("not changed: {other:?}")),
    }
    // reload: the vault may have changed while the person decided
    let mut vault = store.load()?;
    let plan = allow::plan(&vault, &changes)?;
    allow::commit(&mut vault, &plan);
    store.save_vault_only(&vault)?;
    for p in &plan {
        let l = if p.new.is_empty() {
            "none".to_string()
        } else {
            p.new.join(",")
        };
        println!("{}: lanes={l}", p.name);
    }
    Ok(0)
}

/// ⚠️ Typed at a console, never argv or stdin-from-a-pipe: a value in argv is
/// in the process table, and a piped value is in some transcript.
fn read_value_from_console() -> Result<String, String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(
            "vault set must be run by a person at a console; the value is typed, not piped".into(),
        );
    }
    let first = read_hidden("Value (not echoed): ")?;
    let second = read_hidden("Again: ")?;
    if first != second {
        return Err("the two entries differ".into());
    }
    Ok(first)
}

#[cfg(windows)]
fn read_hidden(prompt: &str) -> Result<String, String> {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };
    eprint!("{prompt}");
    let h = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    unsafe { GetConsoleMode(h, &mut mode) };
    unsafe { SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) };
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    unsafe { SetConsoleMode(h, mode) };
    eprintln!();
    r.map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Unix: echo off on the controlling terminal, restored afterwards. The
/// person types a secret VALUE here; it is not an approval (see the stdin
/// allowlist in `user-request/tests/no_terminal_channel.rs`).
#[cfg(unix)]
fn read_hidden(prompt: &str) -> Result<String, String> {
    /// Puts the saved terminal mode back when dropped, so an error or a panic
    /// cannot leave echo off. (A fatal signal still can: no handler is set.)
    struct Restore(Option<libc::termios>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(t) = &self.0 {
                unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, t) };
            }
        }
    }
    eprint!("{prompt}");
    let fd = libc::STDIN_FILENO;
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    let have = unsafe { libc::tcgetattr(fd, &mut saved) } == 0;
    let _restore = Restore(have.then_some(saved));
    if have {
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let r = std::io::stdin().read_line(&mut line);
    drop(_restore);
    eprintln!();
    r.map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(not(any(windows, unix)))]
fn read_hidden(_: &str) -> Result<String, String> {
    Err("vault set is not supported on this platform".into())
}

/// ⚠️ FAILS OPEN: any error exits 0 with a warning. A hook bug must not block
/// every tool call in every lane; the hooks are defence in depth, not the gate.
fn hook(kind: Option<&str>) -> ExitCode {
    let mut input = String::new();
    let parsed: Result<serde_json::Value, String> = std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| e.to_string())
        .and_then(|_| serde_json::from_str(&input).map_err(|e| e.to_string()));
    let v = match parsed {
        Ok(v) => v,
        Err(e) => {
            eprintln!("with-secret hook: unreadable input ({e}); allowing");
            return ExitCode::SUCCESS;
        }
    };
    let tool = v["tool_name"].as_str().unwrap_or("");
    match kind {
        Some("pre-tool-use") => {
            if let Some(why) = dumpcheck::dump_reason(tool, &v["tool_input"]) {
                println!(
                    "{}",
                    serde_json::json!({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse", "permissionDecision": "deny",
                    "permissionDecisionReason": why}})
                );
            }
        }
        Some("post-tool-use") => {
            // Fails open, like every hook here: an unreadable masks file
            // means no masking for this call, never a blocked tool.
            let masks: Vec<HashMask> = match store().and_then(|s| {
                if let Err(e) = s.migrate_legacy_masks() {
                    eprintln!("with-secret hook: sealing the legacy masks failed ({e}); masking from them anyway");
                }
                s.load_masks()
            }) {
                Ok(Some(b)) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                    eprintln!("with-secret hook: {MASKS_FILE} is not valid ({e}); not masking");
                    Vec::new()
                }),
                Ok(None) => Vec::new(),
                Err(e) => {
                    eprintln!("with-secret hook: {e}; not masking");
                    Vec::new()
                }
            };
            let (masked, hits) = mask_json(&v["tool_response"], &masks);
            if hits > 0 {
                println!(
                    "{}",
                    serde_json::json!({"hookSpecificOutput": {
                    "hookEventName": "PostToolUse", "updatedToolOutput": masked}})
                );
            }
        }
        _ => eprintln!("with-secret hook: unknown hook kind {kind:?}; allowing"),
    }
    ExitCode::SUCCESS
}
