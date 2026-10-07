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
- `prompt_text`: the text the person approves. Summary and reason are clipped; the requester line
  and the grant line never are.

## Kinds

| kind | maximum grant | scope |
|---|---|---|
| `Secret` (with-secret) | until the next local midnight | this requester only; a lane restart voids it |
| `LaneDialogBypass` (lane-restart) | **FOREVER** | any requester |

### Kinds that can be granted forever

Every kind whose maximum is `Forever` must be listed here, and nowhere else may one be added:

- `LaneDialogBypass`: auto-answering a lane's startup dialog.

A forever grant is described in the prompt as `*** FOREVER (until revoked) ***`.

## How a duration is chosen

Windows Hello is a yes/no dialog with a message: it cannot ask "for how long". So the grant is
chosen **first**, and the message the person approves names it. Hello proves the person was present
and approved that text; it does not prove they read it.

## Honest limits

- Like with-secret (WITH-SECRET-DESIGN.md §3), this stops **accidents**, not a deliberate process
  running as the same Windows user, which can drive the same APIs.
- Coming next, per the approved plan:
  - a signed grant store with list, revoke and an audit chain;
  - an approver-side chooser where FOREVER, or a date over 30 days away, must be typed;
  - durable pending requests with no timeout;
  - grants for lane-launch dialog bypasses.
