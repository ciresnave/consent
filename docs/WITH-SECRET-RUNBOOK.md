# with-secret runbook

`with-secret` runs ONE command with ONE secret in its environment, after CireSnave approves via
Windows Hello. Design and decisions: `WITH-SECRET-DESIGN.md`. Build plan:
`docs/superpowers/plans/2026-10-01-with-secret.md`.

## 1. The honest limit (read this first)

Copied in full from `WITH-SECRET-DESIGN.md` §3:

**This stops ACCIDENTAL exposure** like the 2026-09-28 incident:
- no secret sits in any environment that a dump could print;
- reading one needs CireSnave's PIN, once per lane, per secret, per day;
- dump commands are refused;
- known values are masked in tool output.

**It does not stop deliberate misuse.**
- A process that has been granted a secret can print it, send it elsewhere, or pass it on to
  its own children. An environment variable is inherited by grandchildren.
- Any process running as this Windows user can call DPAPI to decrypt the vault file. It can read
  `with-secret`'s memory while that is running, forge an approval-cache entry by first taking
  the DPAPI-protected HMAC key, or send keystrokes to the desktop.
- DPAPI at user scope protects the vault against copies of the disk and backups. It does not
  protect against other processes running as this same user.
- Masking finds exact matches only. A value that has been transformed in any way (URL-encoded,
  split, base64-encoded) passes through.
- An approval covers its secret for the whole window, not one command. Until the window ends,
  the approved requester can run other commands with the same secret. Per-command scoping was
  considered and declined by the PM on 2026-10-01; the Hello prompt and a short `--window-mins`
  are the controls. This is an accepted limit.
  - ⚠️ Since board 134 (2026-10-07) the prompt names who, which secret and how long, but **not the
    command or the reason** (CireSnave asked for those three things only). They are in the access
    log. So the person approves the secret for a duration, not a command.

Least privilege (e) limits how much damage a leaked secret can do. It is a procedure for
CireSnave and the PM when they provision each credential, and no tool can enforce it.

## 2. Install

1. Build: `cargo build --release -p with-secret`.
2. **The PM installs it** at `C:\Projects\.claude-hooks\with-secret.exe`, the same way
   `lane-restart.exe` is installed: by full path, keeping any previous binary under a versioned
   name (`with-secret.<version>.exe`). It is not on `PATH`; always call it by full path. Record
   its SHA-256 beside it in `C:\Projects\.claude-hooks\with-secret.sha256`, as
   `lane-restart.sha256` is (RESTART-TOOL-DESIGN.md §12.9).
3. Check it: `C:/Projects/.claude-hooks/with-secret.exe vault check`. Expected:
   `DPAPI round trip: ok`. `check` never shows a Hello prompt.

Data lives in `%LOCALAPPDATA%\OverMind\with-secret\`: `vault.bin` (DPAPI-protected),
`masks.bin` (salted hashes, no values; DPAPI-protected since 0.7, and the hook seals a leftover
`masks.json` into it), `access.log` (no values). `WITH_SECRET_DIR` overrides
this **for tests only**; a lane that set it would just reach an empty vault.

Approvals live in the user-request store, `%LOCALAPPDATA%\OverMind\user-request\`
(crates/user-request/README.md), since #2b. An `approvals.key` or `approvals.json` left in the
with-secret folder by an older version is no longer read, so putting an old copy back grants
nothing; it can be deleted. A binary given `WITH_SECRET_DIR` refuses to touch approvals unless
`USER_REQUEST_DIR` and `USER_REQUEST_HEAD` (debug builds only) point at a scratch store and a
scratch head copy too.

## 3. Adding a secret (CireSnave only)

At his own console:

```
C:/Projects/.claude-hooks/with-secret.exe vault set NAME --env VAR --access read|write [--rotate-by YYYY-MM-DD]
```

The value is typed twice, not echoed, and never accepted from argv or a pipe; then a Hello prompt
confirms the store. A lane can never do this: it has no console to type at, and the prompt needs
CireSnave's PIN or biometric. `vault list` shows names, env vars, access and rotate-by dates (never
values); `vault remove NAME` deletes one, also behind a Hello prompt.

## 4. Using a secret from a lane

```
C:/Projects/.claude-hooks/with-secret.exe NAME --reason "why, in at least 10 characters" [--window-mins M] -- <command> [args...]
```

- Call it from the Bash tool with `timeout: 600000`: the Hello prompt waits up to 9 minutes.
  `--wait-secs` may not exceed 840 (14 minutes): a prompt's reservation lasts 15, and an answer after
  it could not be recorded.
- ⚠️ From Git Bash, prefix `MSYS_NO_PATHCONV=1` when the command has slash flags such as
  `cmd /c`. Otherwise MSYS rewrites `/c` to `C:/`, cmd starts interactively and does nothing, and
  CireSnave approves a command that is not the one you meant (measured on spike day, 2026-10-01).
- The Windows Hello prompt on CireSnave's screen says three things: who asks (the lane), which
  secret, and for how long, with the end time. He approves or cancels; nothing is released until he
  approves. The command and the reason are written to the access log, not shown in the prompt.
- The secret is set as `VAR` in that one child's environment and nowhere else. The child's stdout
  and stderr are masked: the value prints as `[with-secret:NAME]`.
- One approval covers **one lane, one secret**.
  - With `--window-mins M` it lasts M minutes from now, however long.
  - Without it, it lasts until local midnight.
  - The prompt shows the end. One that runs past today is shown as `*** LONGER THAN TODAY ***`, so
    it is never approved by habit (board 134, CireSnave 2026-10-07: "if I or some other user
    disagrees, we simply don't aprove it").
  - Later calls in the window need no prompt.
- A lane restart voids it: a new session is a new requester.
- Prompts pass the user-request prompt gate: after a denial or timeout the same lane may not ask
  about the same secret for 10 minutes, and a lane may put at most 6 prompts an hour in front of
  CireSnave (20 for all lanes together). A refusal by the gate shows no prompt.
- `with-secret revoke NAME` or `with-secret revoke --all` ends secrets' approvals at once, for
  every lane, with no Hello prompt, because it only removes privilege. It also ends any prompt for
  them still awaiting an answer, so an approval given meanwhile never takes effect.
  `user-request revoke --all` ends every grant of every kind, secrets included, and
  `user-request list` shows them.
- A command that would dump the environment (`env`, `printenv`, `set`, `Get-ChildItem env:`, ...)
  and a read of a `.env` file are refused outright, exit code 2.
- The PM can request a secret the same way, for a bounded task (e.g. a hand-run migration with a
  short `--window-mins`).

## 5. Hook wiring

The hooks are defence in depth, not the gate: `pre-tool-use` refuses environment dumps in any
lane, and `post-tool-use` masks every stored value in tool output. Both **fail open**: a hook
error allows the call and prints a warning, so a hook bug can never block every lane.

Add these entries to the `PreToolUse` and `PostToolUse` arrays in the **user-level**
`C:\Users\cires\.claude\settings.json`, beside the existing `lane-restart.exe` entries (that is
where every lane's hooks already live; the plan named `C:\Projects\.claude\settings.json`, which
holds no hooks):

```json
"PreToolUse": [
  {
    "matcher": "Bash|PowerShell|Read",
    "hooks": [
      {
        "type": "command",
        "command": "C:/Projects/.claude-hooks/with-secret.exe hook pre-tool-use 2>>C:/Projects/.lane-state/hook-errors.log"
      }
    ]
  }
],
"PostToolUse": [
  {
    "matcher": "Bash|PowerShell|Read",
    "hooks": [
      {
        "type": "command",
        "command": "C:/Projects/.claude-hooks/with-secret.exe hook post-tool-use 2>>C:/Projects/.lane-state/hook-errors.log"
      }
    ]
  }
]
```

⚠️ **Applying this is CireSnave's or the PM's step.** It is shared configuration that every lane
loads; a lane never applies it.

**Applied** by the PM on 2026-10-02 at about 23:27Z (the settings.json mtime). On 2026-10-03 a
lane saw `pre-tool-use` deny one of its own Bash calls in a session that had started before the
change, so Claude Code loads the change without a restart. `post-tool-use` masking was checked
on the installed binary, with `WITH_SECRET_DIR` pointed at a scratch dir. It has not yet been
seen in a live session, which needs a stored value (§3).

How `pre-tool-use` reads a command (0.5.4):
- It parses the command as the tool's own shell would: POSIX (bash 5.3) rules for Bash, and
  PowerShell 7 rules for PowerShell. That covers quotes, escapes, `$'...'`, line continuations,
  `#` comments, PowerShell `<# #>` comments and here-strings. A `|` or `;` inside quotes is not a
  separator, so `git grep -E 'a|printenv|b'` is allowed.
- Nested code is checked as commands of its own: `$(...)`, `(...)`, POSIX backticks, bash 5.3
  `${ ...; }` and PowerShell `{ ... }` blocks, even inside double quotes. Its text also stays in
  the command around it, whose argument it may be (`ls $(echo env:)`).
- The commands this parse finds are always checked. On top of that, the pre-0.5.4 check, which
  ignores quotes and splits at every `|`, `;`, `&&`, `||` and newline, also applies unless the
  quotes can be trusted. They are trusted only when every command word is a fixed program name
  that runs no string itself (`.`, `source`, `trap`), no word names a program that runs a string
  as code (`bash`/`sh -c`, `eval`, `iex`, `xargs`, `sudo`, `env`, `ssh`, `parallel`, ...), and no
  option does (`-exec`, `--exec`, `*pager*`, `*editor*`, git's `-c`/`-x`/`-O`). The commands are
  also checked with their quotes and escapes removed (`pr\intenv` runs `printenv`). The old check
  also applies whenever the parse gives up: an unterminated quote, an unmatched bracket, a bash
  heredoc (`<<`), PowerShell's `--%`, `${...}` or smart quotes, or a comment or here-string start
  it cannot place for sure. Where a comment starts was checked against bash 5.3 and pwsh 7.6.
- The aim: deny everything the pre-0.5.4 check denied, except where the real shell does not run a
  dump (a dump word inside quotes, a comment or a here-string, words joined by a continuation, a
  `&` putting a command in the background, a syntax error). How that was tested is in the PR
  that made the change.
- Limit: a quoted string that some other program runs itself (an `awk` `system()` call, a
  `python -c` script) is not inspected, and the old check did not catch those either. This check
  is for accidents (§1), not the gate.
- `with-secret run` keeps the quote-unaware check, because its child's argv, joined with spaces,
  has already lost its quoting.

Measured on Claude Code 2.1.287 (design §4, and this build's own binary as the hook). ⚠️ Not
re-measured on 2.1.288 (installed by 2026-10-03): the object-form `updatedToolOutput` claim below
is unverified there.

- `updatedToolOutput` replaces a tool's output **only as an object** in the tool's own result
  shape (`{stdout, stderr, interrupted, isImage}` for Bash and PowerShell; `{type, file:{...}}` for
  Read). A string is silently ignored. `post-tool-use` copies `tool_response` and masks its
  strings, so the shape is kept.
- With it, a stored value was masked for Bash, PowerShell and Read, in both the model's result
  and the transcript's `toolUseResult`, and ordinary output passed through unchanged.
- `pre-tool-use` denied `printenv`, and the model saw the reason.
- ⚠️ The hook's own stdin carries the raw output. `with-secret` never logs it; nothing else
  should be pointed at that stream.

## 6. Least privilege (a procedure; no tool enforces it)

- For each credential, prefer a **read-only role for checks** (Neon: `CREATE ROLE ... LOGIN`, then
  `GRANT SELECT`), stored as an `--access read` secret.
- **Write credentials are separate secrets** with `--rotate-by` at most 7 days out. `vault list`
  flags one that is overdue.
- For a one-off task, store a credential made for that task, never the owner credential.
- Rotation is done by hand in the provider's console.

## 7. Migrating `TJ_PROD_DATABASE_URL` (item 81; CireSnave's step)

1. Rotate the `neondb_owner` password in Neon's console.
2. Store the new string:
   `with-secret vault set TJ_PROD_DATABASE_URL --env DATABASE_URL --access write --rotate-by <date>`.
3. Create a read-only role and store it as `TJ_PROD_DATABASE_URL_RO` (`--access read`).
4. Confirm the old User-scope variable is gone. In PowerShell,
   `[Environment]::GetEnvironmentVariable('TJ_PROD_DATABASE_URL','User')` must return nothing.
   As a control, the same call for `PATH` returns a value.
