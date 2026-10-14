# Linux port of user-request and with-secret: U3, U5, U6, U8

Status: design, 2026-10-14 (revised after an independent audit the same day). Source of the asks:
agentlife `docs/PORT-LINUX-PLAN.md` section 5.
Ruled by CireSnave (board 205, relayed by the PM; his words verbatim: *"I agree with the lane's
recommendation"*, where the recommendation is agentlife's plan section 5): FIDO2 touch first, fingerprint
second, else `Unavailable`; key tier TPM2 > Secret Service > `0600` key file, the tier shown and never silent;
**no terminal-prompt channel** (U6 is a standing NO: no channel, no flag). Also his idea, relayed by the PM:
this repo is the cross-platform approval project, Windows Hello is one provider among several, and a
Termux/Android biometric provider may come later (unverified; only the seam is left for it).

U1, U2, U4, U7 are merged (0.14.0). This document covers what is left.

## 1. Shape: two provider seams per crate, one new additive method

| Seam | Trait (today) | Windows provider | New providers |
|---|---|---|---|
| Approvals store key at rest | `user_request::store::Protector` | `dpapi::Dpapi` | `TieredProtector` over `KeyFile`, `SecretService`, `Tpm2` |
| with-secret vault key at rest | `with_secret::vault::Protector` (a **separate** trait) | `DpapiProtector` | the same tiers (section 5) |
| Approval | `consent::Consent`, wrapped by `HelloChannel` | `hello::HelloConsent` | `PresenceConsent` over `Fido2`, `Fprintd` |

A third approval provider (Android/Termux) is a new `PresenceProvider` plus one entry in the ordered list;
nothing in `Store`, `Request`, `Grant` or `prompt_text` changes. `HelloChannel` keeps its name; a generic alias
`type ConsentChannel<C> = HelloChannel<C>` is added so new code does not say "Hello" for a fingerprint.

**The one trait change (additive, not Breaking).** `Consent::ask(&self, prompt, wait)` carries no request
identity, so a provider cannot bind its proof to the request. `Consent` gains

```rust
fn ask_bound(&self, prompt: &str, binding: &[u8; 32], wait: Duration) -> ConsentOutcome {
    let _ = binding;
    self.ask(prompt, wait)
}
```

`HelloChannel::present` calls `ask_bound` with `binding = SHA-256` over the domain string
`user-request.v1.binding` followed by each of kind, subject and requester session id as a 4-byte
big-endian length then the bytes, then 16 fresh random bytes (length prefixes: plain concatenation would be
ambiguous). Existing implementors (Hello, test fakes, with-secret's
`FakeConsent`) keep compiling and keep their behaviour. A provider that can bind (FIDO2) overrides it.

## 2. U3: tiered `Protector`

`TieredProtector { tiers: Vec<Box<dyn Tier>> }`; each `Tier` has a `tag` (`tpm2`, `secret-service`,
`keyfile`), `available() -> Result<(), String>`, `protect`, `unprotect`.

- **Blob format (non-Windows only).** `protect` writes `UR1\0<tag>\0<tier blob>`. `unprotect` reads the tag
  and **only** that tier may open it; a blob whose tier is missing or unavailable is an error naming the tier,
  never a silent re-wrap by another tier (the U3 acceptance). **Windows is unchanged**: it keeps writing the
  raw, unprefixed DPAPI blob, so no existing store changes and an older binary still reads it. A blob without
  the `UR1\0` magic is handed to `Dpapi` on Windows and is an error elsewhere.
- **Where entropy goes.** `Dpapi`'s per-tool entropy (`overmind.user-request.v1` vs with-secret's) stays a
  Windows-only DPAPI parameter. Off Windows, the same purpose label (`user-request` or `with-secret`) is bound
  as AEAD associated data together with the tag, so one tool's blob does not open in the other.
- **Selection.** On first write the first available tier in order TPM2, Secret Service, key file is chosen and
  its tag is written into the blob. Later opens use the tag, not the order, so installing a TPM later does not
  strand a store. Changing tiers is an explicit, audited `rewrap` subcommand, never automatic; its design
  (old tier available, new key written atomically, audit line) is written in its own slice PR.
- **Shown, never silent.** `Protector::tier(&self, blob: &[u8]) -> Option<String>` is added with a default of
  `None` (additive: the existing implementors are `Dpapi` and three test types, `Xor` twice and `Broken`, all keep compiling).
  `Store` keeps no protector (it is a parameter of `open*` and `repair`), so the tier is read by a free
  function `locate::key_tier(dir) -> KeyTier`, which reads `store.key` and parses only the prefix (it needs no
  protector), and returns
  `Tier(tag)`, `LegacyDpapi` (no `UR1\0` magic, on Windows; printed as `dpapi`, hard-coded because `Dpapi::tier` is the default `None`),
  `Foreign` (no magic, elsewhere: an error line) or
  `Missing` (no key yet: `list` prints `key: none yet`). `user-request list` calls it before `inspect` and
  prints it on **every** path, including the untrusted-key early return, calling `dir()` itself so it works
  before any store exists: `key protected by: <tag>`, and for `keyfile`
  `weakest tier: the key sits beside the store, readable by any process running as this user and carried by
  any copy or backup of that directory; it only keeps other users out`.
  There is no flag to hide it. with-secret's vault trait gets the same `tier` method and `with-secret list`
  prints it.
- **Typed unavailability.** `Protector::unprotect` keeps `Result<Vec<u8>, String>` for compatibility; a
  new default method `unprotect_typed(&self, blob) -> Result<Vec<u8>, KeyError>` with
  `KeyError::{Unavailable(String), Corrupt(String)}` is what `open_in` calls (the default maps the string
  error to `Corrupt`, so existing implementors behave as before). `open_in` maps `Unavailable` to a new
  `Untrusted::KeyUnavailable`, which `list` reports as retryable and which does **not** offer `repair`.
  `repair(&mut self, &dyn Protector, tier: Option<&str>)` takes the tier explicitly.
- **`repair` never silently re-tiers.** `repair` quarantines `store.key` and writes a new one through the
  selector. A transient condition (Secret Service locked, TPM busy) must not destroy every grant and then
  re-key under another tier. Only `Corrupt` reaches `repair`. The tag survives in the blob prefix when the
  AEAD body is corrupt; when even the prefix is unreadable the previous tier is unknown and `repair` requires
  `--tier <tag>` explicitly. It prints the tier it chose.
- **The selector.** `locate::PROTECTOR` is today `pub const PROTECTOR: Dpapi`. It becomes
  `pub fn protector() -> Selected` (an enum over `Dpapi` and `TieredProtector`): a **Breaking** change to
  that public name, in the same release that lands S1. Callers are `bin/user-request.rs` (three sites), with-secret's `main.rs` and its `tests/cli.rs`; `ENTROPY`
  stays public.
- **Tiers.**
  - `keyfile`: a 32-byte KEK in `<state>/OverMind/user-request-kek` (a distinct file for with-secret), mode
    `0600`, created with `O_EXCL`; the blob is XChaCha20-Poly1305 over the key, tag and purpose as associated
    data. Mode and owner are re-checked on every open and a wrong one is refused. Always available. The KEK
    lives in the state tree, so this tier does not defend against a copied or backed-up tree (section 6).
  - `secret-service`: the KEK is an item in the user's Secret Service collection. Unavailable when there is no
    session bus or the collection is locked (we never show an unlock prompt: a second consent surface).
  - `tpm2`: the KEK is sealed under the owner hierarchy; `/dev/tpmrm0` required. No PIN in this slice.
- **Features and dependencies.** The AEAD crate is an unconditional dependency under
  `[target.'cfg(not(windows))'.dependencies]` (Cargo has no per-target default features, and `keyfile` must
  work on a headless box). `secret-service`, `tpm2`, `fido2`, `fprintd` are opt-in features (`fido2` also brings a CBOR/COSE parser and
an ECDSA crate for the in-process verification). CI gains a `--all-features` clippy and test step on
`ubuntu-latest`, or the opt-in code is never compiled; `deny.toml` runs with `all-features = true`, so the
D-Bus, TPM and HID crates' licences and advisories are checked when they land (each slice says what it adds). U4's check stays
  `cargo tree --target x86_64-unknown-linux-gnu -e normal`: no D-Bus, TPM, HID or `windows*` crate. The new
  AEAD crate must pass `deny.toml` (CI runs it).

## 3. U5: `PresenceConsent`

`PresenceConsent { providers: Vec<Box<dyn PresenceProvider>> }` implements `Consent`. Its `ask_bound` does
the work; its plain `ask` (no binding) returns `Unavailable`, never `Approved`, so an unbound call cannot
produce an unbound assertion.
Providers are tried in order and the first **available** one is used for the whole ask. **No fallthrough
after a Denied or TimedOut**: that would turn a "no" into a second try on a weaker channel. (This policy is
this document's own; the plan's acceptance does not state it.)

- `Fido2`: a one-time, audited `enroll` makes a credential on the person's authenticator and stores its id
  and public key in the store (a store format-version bump; the migration is written in S3). Each ask sends a
  `getAssertion` with `challenge = SHA-256("user-request.v1" || binding || prompt_text)` and user presence
  required, with the relying-party id `user-request.local` fixed at enrolment and the signature counter
  checked to increase **only when the credential has ever returned a non-zero counter** (many
  authenticators always return 0); the highest counter seen is kept in the store with the credential. `Approved` only on a valid signature over that challenge by the enrolled key with the UP flag set,
  verified in-process, so a provider that merely returns "yes" is not enough. The fresh random bytes in
  `binding` make each challenge single-use. Cancel -> `Denied`; deadline -> `TimedOut`; no device or no
  enrolled credential -> `Unavailable`.
- `Fprintd`: `net.reactivated.Fprint` `VerifyStart` on the enrolled device; `verify-match` -> `Approved`;
  `verify-no-match` after the service's retries, or cancel -> `Denied`. **To be measured, not assumed:**
  fprintd's D-Bus API is reachable by any same-user process and whether a polkit policy restricts it differs
  by distribution (section 8). It is the second provider because CireSnave ruled it; the README states the
  measured level.
- **Never `Approved` by default.** An empty or all-unavailable list returns `Unavailable`; `Approved` has one
  constructor path per provider: the verified assertion or the verify-match.
- **Fakes.** `PresenceProvider` is a trait, so the acceptance tests run on any host with a fake authenticator
  that signs, cancels, times out, or returns a bad signature, a wrong challenge, a replayed challenge or a
  missing UP flag (each must not approve). Live tests are `#[ignore]` and Linux-only:
  `user-request::presence::fido2::live_fido2_cancel_is_denied` and `...::fprintd::live_fprintd_cancel_is_denied`
  (distinct from the two existing `live_hello_cancel_is_denied`, one per crate, Windows).
- **Where the person sees the text.** A security key has no screen, so the prompt text is shown by a
  display-only surface (a desktop notification). It reads nothing back, so it is not a terminal-prompt
  channel; the answer is only the touch. Section 6 states what this does and does not prove.

## 4. U6: no terminal-prompt channel

- `tests/no_terminal_channel.rs` enumerates `crates/*/src/**/*.rs` with `git ls-files` (never a disk walk; if
  `git` is unavailable the test **fails loudly** and says so, it never scans nothing). Two rules, on
  code with `//` comments and string literals stripped, so a mention in help text or test data is not a hit
  (`with-secret/src/dumpcheck.rs` is inside the scan root and passes only because of that):
  1. a file that has `impl Consent for` or `impl Channel for` may not contain `stdin`, `read_line`,
     `IsTerminal`, `is_terminal`, `rpassword`, `File::open`/`OpenOptions` (a terminal is opened as
     `/dev/tty`, a string, so the open call is the token), or a `read` on fd 0. Today none does (hello.rs, channel.rs, the test
     fakes and with-secret `run.rs` are clean).
  2. the files that touch stdin at all are an explicit allowlist, each with its reason: today only
     `with-secret/src/main.rs` (the `hook` command reads the hook JSON from stdin, the child inherits stdin,
     `read_hidden` reads a secret *value* the person types, which is not an approval). A new stdin reader
     fails until a reviewer adds it. `tests/` directories are out of the scan root.
  Positive controls in the same test: a planted `impl Consent` file with `io::stdin()` fails rule 1, and so does one with
  `File::open("/dev/tty")`; a
  planted stdin reader outside the allowlist fails rule 2.
- `README.md` gets a "Deliberate omissions" section: no terminal prompt, behind no flag or env var, because a
  same-user process can type into a pty and it would turn "a person approved" into "something on this
  machine answered".
- Lands in the same PR as the first new `Consent` implementation (S2), as the PM agreed.

## 5. U8: with-secret

with-secret shares the **approvals** store, so approvals and `revoke --all` consume U1-U3 unchanged. It does
**not** share the vault: `vault.bin` and `masks.bin` go through its own `vault::Protector` and
`DpapiProtector`, and `read_hidden` says "vault set is Windows-only" off Windows. U8 therefore also needs:

- the vault's `Protector` implemented by the same tiers (purpose label `with-secret`; its own KEK file,
  `<state>/OverMind/with-secret-kek`, and one Secret Service / TPM item per purpose), `tier()` shown in
  `with-secret list`, and `main.rs` stops naming `DpapiProtector` as a concrete type (a `Selected`-style
  choice, as for the store);
- `vault::default_dir()` reads only `LOCALAPPDATA`: it gets the same XDG resolution as U1;
- `main.rs` builds `HelloChannel::new(HelloConsent::default())` and calls `HelloConsent::default().ask(..)`
  directly for `vault set` and `vault remove`. Both go through the platform's `Consent` selector, and the
  direct call becomes an `ask_bound` whose binding covers the same fields (kind `vault set`/`vault remove`,
  the secret name, the session id, fresh random bytes); left as plain `ask`, `PresenceConsent` answers
  `Unavailable` forever and Linux could never approve them;
- its own README states its Linux support level (the plan's U8 acceptance);
- a unix `read_hidden` (echo off on the controlling terminal); it is on the section 4 allowlist because the
  person types a secret value, which is not approval;
- the process-identity check on Linux: `identity.rs` accepts only `claude.exe` or `claude` by name and uses
  `start_time_secs`; both need measuring on Linux (agentlife plan section 2.2 flags the same drift);
- a test that `revoke --all` covers every kind on the `keyfile` tier (the existing portable revoke tests,
  run with the key-file protector in place of the XOR test one).

## 6. What this does not claim

- The `keyfile` tier is **weaker than DPAPI user scope**: its KEK is a file in the same state tree as the
  store, so a copy or backup of the tree carries both, and any same-user process can read it. It separates
  users by file permission and nothing more (the agentlife plan's "parity with DPAPI" wording is corrected
  here). It is the tier of last resort, shown on every `list`, never hidden. Secret Service and TPM2 keep the
  KEK out of the copied tree; a same-user process can still ask them to unseal it.
- **A security key proves a person touched it, not that they read the text.** Windows Hello shows the prompt
  in a system dialog. A key has no screen, so the text is shown on a surface an agent running as the same
  user may be able to influence; the signature binds the request, the text hash and a fresh nonce to the
  touch, which defeats replay, not misdirection. That is weaker than Hello; CireSnave accepted it (board
  208, section 9). A key with a display, a TPM PIN typed on a path the agent cannot read, or a second device
  (section 10) would close it; none is in S1-S6.
- No TPM PIN (`authValue`).
- The comment in `with-secret/src/vault.rs` that DPAPI protects "against copies of the disk" is made
  tier-neutral in S1/S6: the `keyfile` tier sits behind the same trait and does not.

## 7. Slices (each a PR, tests first, independent review, version allocated by the PM)

The Linux CI leg already exists (`ci.yml`: `ubuntu-latest` and `windows-latest` run fmt, clippy and
`cargo test --workspace`), so Linux-only tests run in CI today.

| Slice | Content | Needs |
|---|---|---|
| S1 | `Tier`, `TieredProtector`, blob format, `keyfile` tier, `Protector::tier`, free function `locate::key_tier`, a typed unavailable-vs-corrupt split in `unprotect`/`open_in`/`repair`, shown in `list`, `locate::protector()` (Breaking), refusal tests | nothing external |
| S2 | `Consent::ask_bound` (additive), `PresenceConsent`, `PresenceProvider`, fake authenticator, U6 test + README | nothing external |
| S3 | `Fido2` provider, `enroll`, store format bump. Unblocked by the section 9 answer (board 208) | a FIDO2 key for the live test |
| S4 | `Fprintd` provider after measurement 1 | a reader + enrolled finger |
| S5 | `secret-service` and `tpm2` tiers | desktop session / TPM for live tests |
| S6 | with-secret on Linux: vault tiers, vault dir, Consent selector in `main.rs`, `read_hidden`, identity check, README, `revoke --all` test (U8) | S1, S2 |

## 8. Measurements owed before the README makes a claim

1. Can a same-user process answer `net.reactivated.Fprint` verification without a person present, on the
   target distributions (polkit policy)? Result goes in the README with distribution and version.
2. Can a pty-less lane Bash tool reach `/dev/hidraw*` of a FIDO2 key (udev ACL)? An agent driving the HID
   endpoint still cannot touch the key but may cancel it: a denial of service, not an approval.
3. Does the Claude process on Linux appear as `claude` (or `node`) in the process table, and how far does
   `start_time_secs` drift between reads (S6)?

## 9. Ruled: the FIDO2 text surface (board 208)

CireSnave ruled, verbatim: *"208: accept"* (relayed by the PM 2026-10-14), accepting that for the FIDO2
provider "a touch proves presence and the signature binds the request, but the text is shown on a surface
an agent could influence". The limitation is stated plainly in the README and the tier in use is shown at
approval time; the `keyfile` key tier is named the weakest. S3 is unblocked. His follow-up question, a
second device, is section 10 (design only; building it waits on his decision about a relay service).

## 10. Second-device approval (board 208, CireSnave's question)

*The question:* should approval happen on a **different device** (a phone), so the agent cannot influence
the text the person sees? Design only; nothing here is built. An independent audit of the first draft of
this section found its central argument unsound (a consumer cannot recompute the prompt text, and the
trust anchor sat in a same-user-writable store); this is the corrected version.

### What a second device buys, and what it cannot

The threat is a process running as the same user as the person, which can read and write every file the
person's tools write, including the store and its HMAC key (the crate's own header says it "stops
accidents"). Against that threat:

- A second device **can** give a display and an approve action that nothing on the host can overdraw,
  synthesise or answer, and a private key that never leaves the phone's hardware-backed store, gated by its
  biometric.
- A second device **cannot**, by itself, make an approval *record* on the host trustworthy: a record the
  agent can write is not evidence. Evidence is a **signature** the consumer verifies against a key the
  agent cannot replace (below).
- It **cannot** fix what the requester says. `Secret` subjects and every `reason` are requester-supplied
  and stay labelled "Reason given:", apart from the vouched lines.
- It **does not bind the command**: the prompt, by design, excludes the command and summary (they go to the
  access log), so the person approves a secret name and a duration, not a command line.

### The signed statement (replaces "the consumer recomputes the text")

A consumer cannot recompute `prompt_text`: it does not hold the requester's `reason`, the `shown_at` the
channel read (the displayed end depends on it), the grant's form (`For` or `Until`), or, for
`AnyRequester` kinds, the asker. So the second-device provider signs a **structured statement**, not a
rendered string:

`statement = {kind, subject, requester{role, session_id, claude_pid, claude_start_secs}, grant_form,
asked_at, expires_at, approved_at, binding, nonce (issued by the phone), reason_sha256}`

- **Encoding** (not left open: ambiguity here is a forgery vector): each field in the order above as a
  4-byte big-endian length then its UTF-8 bytes (times as RFC 3339 UTC to the second; an absent
  `expires_at` as the zero-length field), under the one domain string `user-request.v1.statement`
  (the statement's own version is that string; there is no separate `v` field). The three domain strings in
  this document (`user-request.v1` for the section 3 challenge, `.binding`, `.statement`) are each hashed
  as a length-prefixed first field in the new code, so none is a prefix of another's input.
- **Who fixes the end:** the host, at ask time (`asked_at`, `expires_at` are computed from the grant and
  shown to the phone, which signs them). The phone adds only `approved_at` from its own clock; a
  consumer rejects an `approved_at` before `asked_at` or after its own now plus a small skew. A delayed
  relayed approval is therefore bounded by the end the person was shown.

The phone shows the same human text as today (`prompt_text`) and signs `SHA-256("user-request.v1.statement"
|| canonical(statement))`. The signature and the statement are stored with the approval
(`Approval.proof`). A consumer that is about to act checks, on its own:

1. the signature verifies against the **pinned phone key** (next section);
2. `kind` and `subject` equal the action it is about to perform (for `with-secret`, the secret name; for
   `RestorePlan`, the plan hash it holds);
3. for `ThisRequester` kinds (`Secret`), `requester` equals the consumer's own identity from the process
   table; for `AnyRequester` kinds (`LaneDialogBypass`, `RestorePlan`) the requester is **advisory**: its
   `role` is requester-supplied text, shown on the phone as a claim;
4. the statement's grant is within the kind's maximum (`Grant::within`, re-run on the signed values, not
   trusted from the record), `expires_at` has not passed, and `approved_at` is plausible (above);
5. `nonce` is not in the spent-nonce set, and the nonce was issued by the phone for this ask: only the
   provider that talked to the phone can know that at ask time, so the provider rejects a response whose
   nonce it did not hand out, and the consumer's check is uniqueness only.

It does not claim that the displayed text equals a recomputation, and it does not check `reason`
(requester-supplied, shown and labelled, hashed only so the person's screen and the record agree).

**Why the nonce is the phone's:** the 16 random bytes in the section 1 `binding` are chosen by the host, so
a same-user agent could present an old (binding, signature) pair again. A nonce the phone issues per
ask and signs, plus the consumer's spent set, closes that. (`binding` still ties the ask to the request.)

### Limits that remain (read these before deciding)

An independent re-audit found these, and the design does not hide them:

1. **Replay of a stored statement is not prevented against an agent that rewrites the store.** The spent
   set and a `OneUse` spend live in the store, which a same-user agent can rewrite and re-seal with the key
   it can read. It can then re-present an old valid (statement, signature) for the *same kind and subject*.
   That can only reuse something the person approved earlier, but for `Forever` and `OneUse` grants there
   is no time bound. **The mode that closes this is a consumer-issued challenge:** at use time the
   consumer generates a fresh nonce, the phone signs a statement containing it, and nothing stored is
   reusable. It needs the phone online at each use, so it suits `OneUse` and `Forever` kinds
   (`RestorePlan`, `LaneDialogBypass`), and stored statements are accepted only for finite grants.
2. **The verifier must not be steerable.** The key path is a compile-time constant with no environment
   variable, flag or XDG override (the repo's own debug overrides, `WITH_SECRET_DIR` and
   `USER_REQUEST_DIR`, are deliberately **not** extended to it, and a test greps for any new such knob).
3. **A root-owned key checked by a user-writable binary protects nothing against a same-user agent that
   replaces the binary.** The check is only as strong as the install location of the consumer: a
   root-owned install path (`/usr/local/lib/user-request/`, `%ProgramFiles%`) is part of the elevated
   enrolment, or the honest statement is that the second device then raises the bar from "the agent can
   inject an approval or overdraw the prompt" to "the agent must replace the consumer binary", and no
   further. The same bound applies to Windows Hello today.
4. **The signed approval gates consumers that honour it, not the data.** The vault key is a same-user
   KEK file or a keyring item a same-user process can ask for; an agent that reads the secret directly
   never needs an approval. This design protects the *approval*, not the secret at rest (section 6).
5. **Which kinds require the second device is itself a policy that must be root-owned**: it is stored in
   the same elevated file as the pinned key, not in the store or any user config, or the agent switches
   "required" off.

### The trust anchor must not be same-user-writable

The phone's public key cannot be "pinned in the store": the agent can rewrite the store (or unseal its key
through a same-user Secret Service/TPM call) and pin its own key. The pinned key therefore lives where the
agent cannot write:

- **Linux:** `/etc/user-request/phone.pub`, root-owned, mode 0644, written by `sudo user-request
  enroll-phone` (the person, at a terminal, with the phone's QR/fingerprint shown on the phone).
- **Windows:** a file under `%ProgramData%` whose ACL grants write to Administrators only, written by an
  elevated `enroll-phone`.
- A consumer refuses proof-less approvals for the kinds where the second device is **required**
  (configurable per kind; today's Hello approvals stay accepted for the others). Without that, a forged
  proof-less record still passes, and the second device would add nothing.

If elevation is not available on a box (a shared CI runner, a container), second-device approval is simply
not offered there; that is `Unavailable`, not a weaker mode.

### Options

| # | Option | Arbitrary text on the second device | Needs | Verdict |
|---|---|---|---|---|
| A | **Own phone app, push through a relay** (self-hosted ntfy/WebSocket, or FCM): the app shows the text and Approve/Deny and signs the statement with a hardware-backed, biometric-gated key | yes (our app renders it) | a phone app (new project), a relay, an elevated enrolment | the only option that gives the signed statement above |
| B | **FIDO2 key on the host + text on the phone**: the person reads the phone and touches the key | yes, but the key proves only presence | relay for the text, plus section 3 | weaker than A: presence and text arrive on two surfaces, and the key signs no statement |
| C | **WebAuthn hybrid** (phone as the authenticator, formerly caBLE) | **no**: the transaction-text extension `txAuthSimple` was removed from WebAuthn Level 2 in 2020 as unimplemented (w3c/webauthn issue 1386; it survives in Level 1 and the IANA registry), and its revised proposal (PR 2020) was closed unmerged in 2025 over the risk of untrusted text in trusted UI. Secure Payment Confirmation shows payee name and origin (optional), total, and an instrument name and icon, in a browser, for payments | a browser on the host, no relay | not viable for arbitrary text; at most presence, like B |
| D | **Third-party chat bot** (Telegram/Signal/Slack inline buttons) | yes | an account at a third party, a bot token on the host | the callback is authenticated by the third party, not by a key we hold; no signed statement; privacy cost |
| E | **Direct, no relay** (phone app reached over LAN, USB or BLE) | yes | the app, same network or cable | no relay service; only when the phone is near. A Termux/Android provider running **on the same machine** gains no trust boundary (it shares the user); only a separate device does |

(Option C: the txAuthSimple history and PR 2020 were checked against the w3c/webauthn issue tracker and the
W3C SPC specification on 2026-10-14. That the phone's OS, not the relying party, renders the hybrid
authenticator's UI is the authenticator's design and was **not** verified on a device.)

### Threats this adds

- **A stolen or compromised phone** approves anything it is shown: the biometric gate and revocation (the
  person removes `/etc/user-request/phone.pub`) are the only controls. A lost phone must be revocable from
  the host without the phone.
- **A relay that drops or delays** messages is denial of service and fails closed (`Unavailable` or
  `TimedOut`); a delayed approval is bounded by the statement's own `expires_at` and the phone's clock.
- The relay sees metadata (that something was asked, when); the payload is end-to-end encrypted to the
  phone's key.

### Shape in this repo (not additive everywhere; stated plainly)

- A second-device provider is one more `PresenceProvider` (section 3) that sends the request to the phone
  and returns the verified statement.
- `Consent::ask_bound` returns a unit-variant `ConsentOutcome` and cannot carry a signature. A new method
  (`ask_proved`, default-bodied, returning `Outcome` plus an optional `Proof`) carries it; this is a new
  trait method, not a change to `ask_bound`.
- `Approval` is a plain public struct built by literal in this workspace; adding `proof:
  Option<Proof>` is **source-breaking** for those literals (minor bump pre-1.0). Serialised stores stay
  readable (`#[serde(default, skip_serializing_if = "Option::is_none")]`); an older binary reading a newer
  store ignores the field, which is a silent loss of the proof and is stated in the changelog.
- A new store file (the spent-nonce set), a new CLI command (`enroll-phone`), and a relay protocol are new
  public concepts; none of this is "no new concept". Enrolment is `enroll-phone`, matching section 3's
  spelling.

### Recommendation

Do **not** build C (it cannot show the text) or D (no signature we hold). Build **A over a self-hosted
relay, with E as the no-relay path**, only after CireSnave rules on three things: whether to run a relay
at all, whether a phone app is in scope (and in which repo), and whether elevated enrolment is acceptable.
Until then S1 and S2 stand alone, and S3 (FIDO2) is a valid, weaker provider whose limits section 6
states; this section is the plan if he wants the stronger property, and the limits above are what it
still does not give him.
