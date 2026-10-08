# user-request

Ask a person to approve something, through a channel that can be swapped, and get back a grant the
**approver** chose. CireSnave asked for it on 2026-10-04 (board item 121): *"a separate
"user-request" crate? That way it can implement Windows Hello, SMS requests, push requests, etc. and
code requesting something from a user could use them interchangeably"*.

## What is in it now

- `Request`: what is asked (`kind`, `subject`, `summary`), who asks (`Requester`, taken from the OS
  process table and lane-state files, never from an argument), and why.
- `KindId`: the **closed** set of request kinds. Each kind's maximum grant and scope is compiled in,
  so no lane can define a kind with a larger maximum.
- `Grant`: for a duration, until a date and time, or forever. `Grant::within` checks a grant against
  its kind's maximum. A grant over the maximum is **refused, never clamped**.
- `Channel`: one way to ask. `HelloChannel` (Windows Hello) is built; `SmsChannel` and `PushChannel`
  are designed for and answer `Unavailable` until built.
- `prompt_text`: the text the person approves: three lines, who asks, what for, and for how long.
  The requester line and the duration line are never clipped; the subject is.

## Kinds

| kind | maximum grant | scope |
|---|---|---|
| `Secret` (with-secret) | any **finite** length: the requester states it, the person sees the end (loudly past today) and may refuse (board 134); never forever (PM ruling) | this requester only; a lane restart voids it |
| `LaneDialogBypass` (lane-restart) | **FOREVER** | any requester |

### Kinds that can be granted forever

Every kind whose maximum is `Forever` must be listed here, and nowhere else may one be added:

- `LaneDialogBypass`: auto-answering a lane's startup dialog.

A forever grant is described in the prompt as `*** FOREVER (until revoked) ***`. A grant that ends
after the next local midnight is described as `*** LONGER THAN TODAY: ... ***`.

## How a duration is approved

The requester states the duration it wants. The Windows Hello prompt names it, and the person approves
it or cancels. CireSnave, 2026-10-07 (board 134, verbatim): *"The message in the Windows Hello prompt can be three things: 1) Who is making the request.  2) What secret they are requesting.  3) What duration they want access to that secret for.  Then I either approve the Windows Hello prompt or cancel it."*

The prompt is exactly three lines:

```
Who: lane 'overmind'
Wants: use a secret: TJ_DB
Duration: for 1h 00m 00s, until 2026-10-07 18:38:32 -07:00
```

- **Approve** grants exactly that duration. **Cancel** is a denial: no grant, and the gate's
  10-minute cooldown starts.
- Nothing is typed, and there is no other window.
- FOREVER and an end past local midnight are loud and distinct in the duration line.
- A duration over the kind's maximum is refused before any prompt, never clamped.
- The reason and the command are not in the prompt: the caller logs them (with-secret: its access log).
- Hello proves the person was present and approved that text; it does not prove they read it.

## Who uses it

- **with-secret** (since #2b): every secret approval is a `Secret` grant here, and every secret
  prompt passes the prompt gate below. `user-request revoke --all` ends secrets too.
  `with-secret revoke NAME | --all` revokes only secrets (`Store::revoke_matching`), as tombstones,
  and ends their pending prompts.
- `user_request::locate` names the production store, so every binary opens the same one.

## The store

Everything lives in `%LOCALAPPDATA%\OverMind\user-request\`:

- `store.lock`: an OS file lock, held by one process at a time from opening the store to closing
  it, and released by the OS if that process dies.
  - On Windows the file cannot be deleted while it is held, so a second holder can never appear.
  - Drop the store before showing a prompt: holding it holds the lock.
- `store.key` and `store.key.check`: the HMAC key, DPAPI-protected, and a value that tells the right
  key from a wrong one.
  - A store whose key does not check out trusts nothing and refuses to save, so it can never
    overwrite the real grants.
  - A missing key, when the store has data, is treated the same way, never as a fresh install.
- `grants.json`: approvals, plus the ids of revoked ones (tombstones), so an old copy cannot bring a
  revoked grant back, and the durable pending requests (below).
- `attempts.json`: recent prompts, including ones still pending, and how they ended.
- Both files are HMAC-signed over their exact bytes. A file that fails its signature, or that
  verifies but does not parse, is moved aside (`*.rejected-<time>-<id>`), never deleted.
- `audit.jsonl`: every save, grant, revocation, gate decision, alert, integrity finding and repair,
  append-only. Each line carries the SHA-256 of the line before it. The chain's head is also written
  to `C:\Projects\.lane-state\user-request-audit.head`.

Every call that changes the store saves before it returns.

- A grant is made only by resolving a reservation with an approval for it, and only within its
  kind's maximum. In production the approval is the channel's.
  - The approval's time must lie between its reservation and now. A clock stepped back costs one
    more prompt. Allowing it would let an approval given before a revocation make a grant after
    it.
  - No caller can add a grant, clear a tombstone or clear the untrusted flag directly.
  - ⚠️ `Approval` has public fields, so code inside a process can build one itself and skip the
    person. The gate, the maximum and the reservation still apply. That is the deliberate-process
    limit below.
- The store reads the clock itself. No caller can choose the time at which a grant expires or a
  gate window is judged.
- Each save records the files' hashes before writing them, and records its completion after. A save
  cut short between the two files (a crash, a held file) is still recognised.
- The write order depends on the operation, so a save cut short between the two files is safe:
  - **Approving:** the prompts file is written first. A cut-short approval ends the prompt with no
    grant, and the person is asked again. It never leaves a grant whose prompt is still open.
  - **Revoking or repairing:** the grants file is written first, so a revocation lands even if the
    prompts file cannot be written.
- A file that is briefly unreadable (an antivirus scan, a backup) is retried for 2 seconds. If it
  stays unreadable, opening fails with "try again", and nothing is concluded or recorded from it.
  That includes the head copy, which a backup or sync tool may hold.

### Integrity: the audit chain is the anchor

- When the store is opened, three checks run:
  - the audit chain must be intact and agree with its head copy;
  - the files must be the ones the last save recorded;
  - no integrity problem may be on record since the last repair.
- These checks catch a file that was deleted, rolled back, edited or copied in, and a whole folder
  put back from a backup. ⚠️ While the head copy lags (see below), a folder put back to a point
  after the copy's line is not caught. Any of these findings makes the store **untrustworthy**, and the gate raises an
  alert, once per role per hour. Under an untrusted key nothing can be recorded, so that alert
  goes to the sink on every refused prompt.
- A chain found broken while the store is open untrusts it at once.
- An untrustworthy store fails **closed**:
  - no grant is honoured;
  - the prompt gate refuses;
  - no new grant is taken;
  - revoking still works, unless the key is the problem.
- The finding is written to the audit log, so no later save can clear it.
- Only `user-request repair` restores trust, and only once its revocations are saved. It does so by:
  - **revoking every grant**;
  - ending every pending prompt;
  - refusing every prompt for an hour.

  A store whose key was the problem gets a new key, and its old files are set aside. Repair only
  removes privilege, so it needs no Hello. Run on a trusted store, it does the same: a way to stop
  everything for an hour.
- Before every append, the chain itself is checked against its head copy. A chain found truncated,
  deleted, torn or edited gets an explicit `chain-reset` line naming why. That keeps the store
  untrusted until a repair. `audit verify` then counts the reset as acknowledged.
- The head copy is written on a best-effort basis, so a revocation always lands. A copy that could
  not be replaced (a backup tool held it) lags the log. If it lags by at most 32 lines, and agrees
  with the log at its own line, it is accepted and caught up at the next write. A copy further
  behind, or one that disagrees, fails closed.

### Durable pending requests

A requester that cannot wait (agentlife, waking an agent while nobody is at the desk) records a request
and goes away. The request is only a record that someone asked: it holds no privilege and expires on no
clock.

```
submit(request, grant, bound_hash) -> id     record it; refused over the kind's maximum, never clamped
begin_answer(id, bound_hash)       -> Asking  void it, or reserve a prompt through the gate
  ... drop the store, show Asking.request with Asking.grant through a channel, reopen ...
resolve(reservation, outcome)                 an approval makes the grant and spends the request
withdraw(id)                                  the requester gives up (a prompt already up cannot land)
```

- **The person sees what they always saw** (board 134): the Hello prompt alone, three lines, who, which
  secret, how long. Nothing is typed. **Approve** grants exactly the requested length. **Cancel** refuses:
  no grant, the request is closed, and the gate's 10-minute cooldown starts.
- **What survives a restart:** every pending request, with its exact contents. It is in `grants.json`, so
  it is signed, anchored in the audit chain and covered by the integrity checks like a grant.
- **A restored request re-prompts and never approves by itself.** `begin_answer` reserves a NEW prompt
  through the gate (cooldown and caps apply), and only the channel's approval makes a grant. A prompt
  nobody answered (`TimedOut`, `Unavailable`) leaves the request pending for the next try. Both still count
  as prompts toward the hourly caps, and a `TimedOut` starts the same 10-minute cooldown as a Cancel, so the
  next try is at least 10 minutes later.
- **`bound_hash` binds the request to the consumer's artifact** (agentlife: the frozen plan hash). The
  consumer passes the hash it holds now to `begin_answer`; any difference **voids** the request (audited
  `pending-stale`) and the person is never asked.
- **A tampered request fails closed.** Each record carries a seal: an HMAC, under the store key, over its
  id, time, request, grant and `bound_hash`. A record whose seal does not match is voided, alerted and
  audited (`pending-altered`) before any prompt, so an altered subject, length, requester or hash is never
  shown. The seal catches an edit of a record. It cannot stop a process that holds the key (see the limits).
- A request whose `bound_hash` no longer matches is voided for good; the consumer submits a new one.
- A subject over 200 characters, or a summary or reason over 1024, is refused at `submit`.
- **Stale** also means the requested end has passed, or the grant is no longer within the kind's maximum.
- **Duplicate:** submitting the exact same request and `bound_hash` again returns the existing id. A
  different `bound_hash` is a different request.
- **Single use:** one prompt at a time per request, and an approval is for the requested length only. The
  grant and the spent request are written together, so a crash cannot leave both.
- **Caps** (a request never expires, so the count is the limit): 20 per role, 100 in all.
- `revoke --all` and `repair` drop every pending request; `revoke_matching` drops those of that kind (and
  subject). Each is audited (`requests-dropped=`).

### The prompt gate

These limits answer "approval fatigue": a lane re-asking until a mis-click approves it.

- After a denial or a timeout, the same role may not ask about the same subject again for 10
  minutes. Subjects are compared trimmed and case-folded.
- A role may put at most 6 prompts per rolling hour in front of the person.
- All roles together may put at most 20 per rolling hour in front of the person.
- A prompt that is still pending counts toward both caps, so parallel requests cannot get past them.
- A prompt is resolved exactly once, with an outcome from a closed set, and within 15 minutes of
  its reservation.
- An approval must be for what was reserved, and it becomes a grant in the same step.
- `revoke --all` and `repair` end every pending prompt, so an approval still in flight never becomes
  a grant. The ended prompts are recorded with the tombstones, in the file written first, so this
  holds even when the prompts file could not be written.
- An approval whose shown end has passed by the time it is recorded makes no grant, and a grant is
  never honoured before the moment it was approved (a clock that was wrong ahead, then corrected).
- Reaching a cap, or 3 refusals within an hour, raises an **alert**, once per role and reason per
  hour.
- The limits are keyed by role, so restarting a lane resets neither.
- Every gate decision and every alert is written to the audit log.
- ⚠️ Alert **delivery** is not built yet. Where alerts go waits on board item 131; until then the
  audit log is the only record.

### Commands

```
user-request list            active grants, FOREVER ones first and loudly
user-request revoke <id>     revoke one grant (no Hello needed: it only removes privilege)
user-request revoke --all    the panic button
user-request repair          restore trust: revoke everything, refuse prompts for an hour
user-request audit verify    check the audit chain since its last reset, and its head copy
```

- Each command prints which store it used.
- `list` and `audit verify` only look: they never create a store, move a file or write to the log.
  The only exception is `store.lock`, which they create if it is missing.
- `list` says when grants are unknown (an untrusted key, a grants file that failed its check),
  rather than reporting none.
- Exit codes:
  - `0`: done, or there is nothing to do (`revoke --all` with no store);
  - `1`: an error, an untrustworthy store (`list`, `audit verify`), or an unknown id.

## Honest limits

- Like with-secret (WITH-SECRET-DESIGN.md §3), this stops **accidents**, not a deliberate process
  running as the same Windows user. Such a process can read the DPAPI key and forge entries.
- The audit chain is plain SHA-256 with no key, so rewriting the chain and its head copy
  consistently needs no key at all. The chain catches accidents and naive edits, not forgery.
- The audit log is never rotated, and every append reads it whole.
- Coming next, per the approved plan:
  - grants for lane-launch dialog bypasses.
