# `with-secret` — secret storage with per-use owner approval: design

**Status: BUILT (crates/with-secret). The live Hello checks (T0 3b/3c, T8 step 5) were run with
CireSnave at the desktop on 2026-10-01 and passed (§4 and the #102 body). `with-secret.exe` 0.5.1 is
installed at `C:/Projects/.claude-hooks/` (the PM, 2026-10-02). Hooks wired: no. Wiring them edits the user
settings.json, which only CireSnave can do (runbook §5).** Design approved by the PM 2026-10-01. Implementation plan:
`docs/superpowers/plans/2026-10-01-with-secret.md`. Source: board item 81 in
`C:\Projects\CIRESNAVE-DECISIONS.md`.

## 0. Why this exists (the incident, from item 81)

At 2026-09-28 05:58:17Z, the Humboldt lane ran a check that ended in a bare `env`. That printed
`TJ_PROD_DATABASE_URL` into the lane's transcript. The variable held the full-owner credential
for ThinkersJournal's production database, and it had been set at Windows **User** scope, so
every process inherited it, all ten lanes included. Nothing was done with it; it was exposed,
not used.

## 1. Requirements, quoted exactly

- CireSnave, 2026-09-28: *"Secret access requests should probably require approval by a user.
  If I had seen a request for access to TJ's database URL, I would have questioned why anyone
  needed it before it became exposed."*
- CireSnave, 2026-09-28, ruling: *"Approve once per lane per secret with a timeout so that an
  approval now isn't still valid tomorrow."* Item 81 turns that into three rules:
  - an approval covers ONE lane and ONE secret;
  - it expires by the end of the same local day at the latest, and a shorter window can be
    configured;
  - it is void if the lane restarts, because a new session is a new requester.
- From the PM's proposal on item 81:
  - **(a)** secrets live in an encrypted vault, never in environment variables;
  - **(b)** `with-secret NAME -- cmd` puts the value into ONE child process only;
  - **(c)** every access asks CireSnave first, naming the secret, the lane, the command and the
    reason;
  - **(d)** a hook blocks environment dumps and masks known secret values in command output;
  - **(e)** least privilege: read-only roles for checks, short-lived credentials for writes.

## 2. Decisions (PM-approved 2026-10-01), and why

**2.1 Not PowerShell SecretManagement/SecretStore.** Neither module is installed here. Measured
2026-10-01: `Get-Module -ListAvailable` finds 0 of the two, and as a control it finds
`Microsoft.PowerShell.Utility`. Installing them would be easy, but they are a bad fit for two
reasons from Microsoft's own page ("Use the SecretStore in automation", updated 2026-06-22):

- The modules are archived: *"feature complete and will no longer be actively developed … The
  code repository has been archived."*
- For scripted use, Microsoft's documented pattern keeps the vault password in a DPAPI-encrypted
  file, then calls `Unlock-SecretStore`. Any process running as this Windows user can decrypt
  that file, and every lane runs as this user. So any lane could call `Get-Secret` directly and
  never meet the approval step. The vault would enforce nothing of (c).

**2.2 The approval channel is a Windows Hello consent prompt** (`UserConsentVerifier`), shown on
CireSnave's desktop and answered with his PIN or biometric. lane-restart's approval channel is
not reused here, and the reason matters:

- lane-restart's channel is a merge into the owner's approvals repo, plus an `[ASK]` sent to the
  PM.
- The PM is authorised to act as `ciresnave` on GitHub (`C:\Projects\CLAUDE.md` §0).
- So that channel cannot prove that CireSnave *himself* said yes, and (c) requires that he did.

A PIN or biometric prompt is the one channel here that no agent can answer, the PM included.
If he is away, the request times out and the command fails, saying why.

**2.3 There is no long-running broker process.** The PM approved "a broker". This design does the
broker's job inside each `with-secret` invocation instead:

- it decrypts the vault;
- it checks an integrity-protected approval cache;
- it asks for consent when no approval covers the request;
- it runs the child and exits.

That gives one fewer process to keep alive, secure and restart. Nothing the PM approved depends
on a resident process.

**2.4 Masking uses salted hashes, not plaintext.** The output-masking hook (d) is a separate
process that runs after every tool call. It never decrypts the vault. It reads `masks.json`,
which holds each secret's length and `SHA-256(salt ‖ value)`, and it replaces any window of
output whose hash matches. `with-secret` itself masks its own child's output using the
plaintext it already holds.

## 3. Threat model — the honest limit (state it this way, never more strongly)

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
  considered and declined by the PM on 2026-10-01; the Hello prompt (naming the command and
  reason) and a short `--window-mins` are the controls. This is an accepted limit.

Least privilege (e) limits how much damage a leaked secret can do. It is a procedure for
CireSnave and the PM when they provision each credential, and no tool can enforce it.

## 4. Measured 2026-10-01 (Task 0 spike, on CireSnave's machine)

Run from the OverMind lane's Bash tool. 3b and 3c ran with CireSnave at the desktop.

- `windows` crate version: 0.62.2. API changes from the plan's code:
  - `AsyncStatus`, `IAsyncInfo` and `IAsyncOperation` moved out of `windows::Foundation` into the
    `windows-future` crate, which `windows` does not re-export. Added `windows-future = "0.3.2"`
    as a direct dependency; it must stay the version `windows` itself uses, or the types differ.
  - The blocking wait is `.join()`, not `.get()`.
  - `GetConsoleWindow` needs the `windows` feature `Win32_System_Console` (missing from the plan's
    `cargo add` list).
  - `LocalFree`, `HLOCAL`, `HWND`, `factory` and `CryptProtectData`: no change.
- DPAPI round trip (3a): `dpapi roundtrip equal: true  blob != plain: true`.
- Hello availability: `Available` (`UserConsentVerifierAvailability(0)`).
- Owner window (3b/3c), run from the lane's Bash tool:
  - 3b `GetForegroundWindow`: a non-null HWND; the dialog appeared; CireSnave approved it, and the
    result was `Verified` (0).
  - 3c `GetConsoleWindow`: **null HWND (0x0)**, because the Bash tool has no console window. The
    dialog still appeared (CireSnave confirmed it); he cancelled it, and the result was `Canceled` (6).
  - Both work on this machine. **Default: `Foreground`**, because it hands Hello a real owner,
    while `Console` works only by Hello's tolerance of a null owner.
  - `cargo test -p with-secret -- --ignored live_hello` (default owner): dialog shown, cancelled,
    `Denied`: pass.
- Hook protocol (3d), Claude Code 2.1.287, headless `claude -p` in a scratch dir outside every
  repo; each result read from the session transcript, not from the model's account:
  - (i) `updatedToolOutput` replaces Bash output: **yes, but only in object form.** The string
    form (`"REPLACED"`) was ignored: the hook ran, and the tool result stayed `hello`.
  - (ii) Result field: `tool_response`, an object:
    `{"stdout":"hello","stderr":"","interrupted":false,"isImage":false,"noOutputExpected":false}`.
  - (iii) `updatedToolOutput` accepts: **object only** for Bash, in the shape
    `{"stdout":..,"stderr":..,"interrupted":..,"isImage":..}`. With it, the model's tool result
    AND the transcript's `toolUseResult` both held the replacement. The raw value did not appear
    in that transcript (control: the same search finds it in the string-form run's transcript).
  - (iv) PreToolUse JSON deny: works. The call was blocked, and the model saw
    `PreToolUse:Bash hook error: spike deny`.
  - Consequence for Task 8: `post-tool-use` must emit the object form, copying `tool_response`
    and masking `stdout` and `stderr`. The hook's own stdin carries the raw output, so the hook
    must never log its input.
