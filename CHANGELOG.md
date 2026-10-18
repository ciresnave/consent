# Changelog

Version numbers continue OverMind's. The entries below 0.12.0 are the part of OverMind's
`CHANGELOG.md` that concerns these two crates, kept so the history travels with the code.

## Unreleased (compile-time audit, OverMind 2026-10-18; version allocated by the PM)

- **BREAKING: `Approval` is `#[non_exhaustive]`.** Code outside `user-request` can no longer write an `Approval` literal and hand it to `Store::resolve` as if a person had approved (it used to mint a grant with no `Consent`); a `compile_fail` doctest pins it. Tests that need one enable the new `test-support` feature and call `Approval::for_test`. Deserialising one by hand is still possible (the store reads its own file through serde).
- **with-secret hook: a mistyped hook kind (`pre_tool_use`) now exits 2** instead of printing "allowing" and silently disabling the env-dump check. Runtime trouble (unreadable input, masks file) still fails open, as documented.
- **with-secret: `mask::unhex` no longer panics** on a non-ASCII character in a corrupt `salt_hex` (it sliced a `&str` by byte offset).

## 0.15.9 (CI hardening, no code change)

- CI: `--locked` on the cargo clippy/test/doc/check steps, and a CODEOWNERS file (`* @ciresnave`). No behaviour change.

## 0.15.8 (allowlist step 4: the prompt names the allowed lanes)

- **Approval prompt gains an `Allowed lanes:` line** for with-secret requests (optional `Request.allowed_lanes`; other request kinds keep their shape), so the person approving sees which lanes an entry admits (OverMind consent#15). The mechanism is complete; no entry is restricted until board 225 is ruled.

## 0.15.7 (allowlist step 3: `vault allow`)

- **with-secret: `vault allow`** changes who may request an entry without re-entering the value. Each change leaves an audit line per entry (`allow-changed`, with "old -> new" in the reason; `allow-refused`); the plan is re-checked against what was approved, newly allowed lanes are printed, lane names are validated, and `outside-claude` can only be changed from the console (OverMind consent#14). Mechanism only: no entry is restricted until a ruling on board 225 sets lanes.

## 0.15.6 (allowlist step 2; mechanism only, no entry is restricted until lanes are set)

- **with-secret: per-entry requester allowlist.** A vault entry gains an optional `lanes` field and an authorize check before the approval prompt; a bad `--lanes` is rejected before the secret is typed, and `none` or a flag is not a lane name. The list is a filter before the prompt, not a security boundary (OverMind consent#13, step 2 of the requester-allowlist order).

## 0.15.5 (allowlist step 1; no behaviour change outside the tie-break)

- **Identity: shared-pid tie-break.** When two lane records share a pid, the newest `updated_at` wins; ties go to the alphabetically first role (OverMind consent#12, step 1 of the requester-allowlist order).

## 0.15.4 (S6 of docs/LINUX-PORT-DESIGN.md / U8; additive, Windows behaviour unchanged)

- **with-secret on Linux.** `platform` module: the vault directory resolves under the XDG state directory (Windows keeps `%LOCALAPPDATA%`); the vault key goes through the same tiered protector as the approvals store (purpose label `with-secret`, its own key file; `keyfile` tier, weaker than DPAPI and said so by `check` and the README); `vault set` has hidden input on Unix (termios); `main.rs` no longer names DPAPI or Hello concretely.
- **`user_request::platform::platform_consent()`**: Windows Hello on Windows, physical presence elsewhere (the security key when built with `fido2`; none: `Unavailable`). One place every consumer asks the same way. `with-secret` forwards the `fido2` feature.
- `vault set` / `vault remove` approvals are now bound (`ask_bound`, `channel::binding_for`) to the action and secret name, so a provider that signs signs that ask and no other.
- Tests: `revoke --all` covers every kind on the keyfile tier; vault dir resolution per OS; protector round trip; blobs name their tier and do not open across tools; the platform consent is Hello on Windows only and never approves without a provider.
- Not done: Secret Service / TPM2 tiers (S5), fprintd (S4), and the Linux process-table identity measurement (design measurement 3).

## 0.15.3 (S3 of docs/LINUX-PORT-DESIGN.md; additive, behind the opt-in `fido2` feature)

- **`fido2` feature** (off by default; needs `pkg-config` and `libudev-dev` on Linux): `fido2::Fido2Provider`, a `PresenceProvider` over a security key (`ctap-hid-fido2` 3.6.0). `enroll` (also `user-request enroll`, PIN from `USER_REQUEST_FIDO2_PIN` if the key has one) makes a credential for the fixed relying-party id `user-request.local` and stores its id and public key. Each ask sends a `getAssertion` with the section 3 challenge; `Verified` only when the signature verifies against the enrolled key, the RP hash matches, the user-present flag is set and the signature counter did not go back (a counter that never moves is not checked). A cancel is `Cancelled`, the key's or our deadline `TimedOut`, no device or enrolment `Unavailable`; anything that fails verification is `Unavailable`, never `Approved`.
- A key proves a person touched it, not that they read the text (design section 6; CireSnave accepted this, board 208).
- Tests use a software authenticator that signs like a key (valid; wrong RP; no presence; another challenge; another key; counter back; cancel; timeout; no device). `live_fido2_cancel_is_denied` is `#[ignore]` and needs a key.
- CI: a `fido2 feature` job on ubuntu and windows (clippy `-D warnings` and tests with the feature).

## 0.15.2 (S2 of docs/LINUX-PORT-DESIGN.md; additive, not Breaking)

- **`Consent::ask_bound`** (default-bodied: every existing implementor is unchanged). `HelloChannel` now hands the provider a 32-byte binding: SHA-256 over `user-request.v1.binding`, then kind, subject and session id each length-prefixed, then 16 fresh random bytes (`channel::binding`, `binding_with`), so the same request asked twice has two bindings.
- **`presence` module:** `PresenceProvider`, `PresenceConsent` (providers in order; the first available answers; a cancel or a timeout is never retried on the next provider; plain `ask` is `Unavailable`; nothing available is `Unavailable`, never `Approved`), and the challenge `SHA-256("user-request.v1" || binding || prompt)`. No hardware provider yet (FIDO2 is S3, fprintd S4).
- **U6:** `tests/no_terminal_channel.rs`: a file that implements `Consent` or `Channel` may not mention stdin, `read_line`, `IsTerminal`, `rpassword`, `File::open` or `OpenOptions`; only listed files may mention stdin at all (today `with-secret/src/main.rs`). Enumerated from `git ls-files`, fails loudly without git, with positive controls. README: a terminal prompt is a deliberate omission.

## 0.15.1 (docs only)

- `docs/LINUX-PORT-DESIGN.md`: section 9 records CireSnave's ruling on the FIDO2 text surface (board 208: "208: accept"; S3 unblocked) and section 10 adds second-device approval: what a second device buys and cannot, the signed-statement design, the limits that remain, five options, and what it needs from CireSnave (relay, phone app, elevated enrolment). Design only; two independent audit rounds, the last revision not re-audited.

## 0.15.0 (S1 of docs/LINUX-PORT-DESIGN.md; `locate::PROTECTOR` changes type)

- **U3, the key tier layer.** New `tiered` module: `TieredProtector` over `Tier`s, blob `UR1\0<tag>\0<tier blob>`, and the `keyfile` tier (XChaCha20-Poly1305 under a 32-byte key in `<state>/OverMind/user-request-kek`, mode 0600, owner and mode re-checked on every open). Only the tier named in a blob may open it; a missing or locked tier is an error that names it and nothing is re-wrapped. Windows is unchanged: DPAPI, raw unprefixed blobs.
- **The keyfile tier is weaker than DPAPI user scope** (its key sits in the same state tree, so a copy or backup of the tree carries both); `user-request list` and `repair` print `key protected by: <tag>` with that warning on stderr, on every path, trusted or not.
- `store::Protector` gains two default methods, `unprotect_typed` and `tier` (additive); new `store::KeyError::{Unavailable, Corrupt}`. A key that is **unavailable** (locked or missing tier) now fails the open with a "try again; nothing was changed" error and is never marked untrusted, so `repair` is never offered and no grant is revoked for it. A key-encrypting key file that is gone while its directory is present is a lost key (`Corrupt`, `repair` is offered and revokes every grant, as for any lost key); a missing directory (an unmounted volume) is a retry.
- `locate::PROTECTOR` is now a `Selected` (DPAPI on Windows, tiered elsewhere); every call site `&PROTECTOR` is unchanged. `Selected::for_dir(dir)` is for tests that open a store themselves. New dependency: `chacha20poly1305` 0.11.0 (unconditional, pure Rust, MIT OR Apache-2.0).

## 0.14.1 (docs only)

- `docs/LINUX-PORT-DESIGN.md`: the design for the Linux port of the key protector (U3), the approval providers (U5), the no-terminal-channel test (U6) and with-secret (U8). Three independent audit rounds; no code.

## 0.14.0 (Breaking for non-Windows builds)

Linux port, upstream asks U1, U2, U4, U7 (agentlife `docs/PORT-LINUX-PLAN.md` section 5). U3 and U5 wait on CireSnave; U6 is a standing NO.

- **U2:** `locate::head_copy()` is `lane_state::platform::state_dir()` joined with `user-request-audit.head` (new `locate::head_copy_in`, `HEAD_COPY_NAME`): the Windows value is the same literal as before (`C:/Projects/.lane-state/...`); elsewhere it is an absolute path under the XDG state directory, outside the store directory. `lane-state` is now a dependency of `user-request` and is raised to 0.14.27 (`ProcEntry` gained `cmd`; with-secret's test fixture follows). `USER_REQUEST_HEAD` stays debug-only. with-secret reads lane states from the same `lane_state::platform::state_dir()` (it had its own `C:/Projects/.lane-state` literal; Windows value unchanged).

- **U1:** `locate::dir()` is `$XDG_STATE_HOME/OverMind/user-request`, else `~/.local/state/OverMind/user-request` off Windows (a relative `XDG_STATE_HOME` is ignored, per the XDG specification); Windows is unchanged (`%LOCALAPPDATA%`). New `locate::Env` and `locate::try_dir(&Env)` let every platform's answer be tested on any host. `USER_REQUEST_DIR` stays debug-only. An empty `LOCALAPPDATA` (or `XDG_STATE_HOME`, `HOME`) is now treated as unset, so Windows gives the "LOCALAPPDATA is not set" error where it used to build a relative path (found in review).
- **U7 (Breaking off Windows):** `hello::Owner` and `HelloConsent::owner` exist only on Windows (a window handle is a Windows concept). `HelloChannel::new(HelloConsent::default())` is the same call site on every OS (tested). with-secret re-exports `Owner` only on Windows.
- **U4:** no new dependencies; `cargo tree --target x86_64-unknown-linux-gnu -e normal` for user-request lists no `windows*` crate, and the workspace checks clean for that target.

## 0.13.1

- CI only: every GitHub Action is pinned to a release commit SHA (PM pin patch 2026-10-14); `dtolnay/rust-toolchain@stable` also gets an explicit `toolchain: stable`. No code change.

## 0.13.0

- **The Windows Hello prompt gains a fourth line, for every kind** (board 173, CireSnave 2026-10-12, verbatim: *"four things, all prompts"*: who / what / duration / why). After the three vouched lines and a blank line it shows `Reason given: <Request.reason>`: cleaned (control and bidi characters become spaces), clipped at 300 characters with `…` (`channel::MAX_WHY_CHARS`), and `(none given)` when empty or blank. Duration stays above it, so a dialog that cuts the tail cuts the reason first. `Wants:` is unchanged (a restore still shows its plan hash). The summary and the command are still not shown.
- Behaviour change for anything that matched the old three-line prompt text exactly (tests in this repo did; agentlife must fill `Request.reason` with the restore reason and lane list). No API change: `Request.reason` already existed and was already logged.
- `channel::clean` (shared with with-secret's prompts) now also replaces characters that draw as nothing or as a wide gap (fillers U+3164/U+2800/U+FFA0 and the Hangul/Khmer/Mongolian ones, variation selectors, U+FFF9-FFFC, tags, non-ASCII spaces) with a space, and the reason's whitespace runs collapse to one space, so a reason of invisible characters reads `(none given)` and padding cannot fake a line under Duration (independent review, 2026-10-12).

## 0.12.0

- The code moved here from [`ciresnave/OverMind`](https://github.com/ciresnave/OverMind)
  (ARCHITECTURE-LAYERS-SPEC 5.4 step 6). Every source file is byte-identical to OverMind `main` at
  `57fae94` (0.12.0); the crate manifests differ only in `rust-version.workspace = true` and
  `with-secret`'s `user-request` dependency, which names the version as well as the path.
- `lane-state` is taken from crates.io at 0.12.15 (was 0.11.1): no path, no git dependency. It carries
  its own number, not this project's.
- The workspace now has the version number 0.12.0 (was 0.11.1 here at the import) so it equals
  OverMind's at the move.
- Checked: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo test --workspace` (user-request 166 + 9, with-secret 64 + 11 + 5; 2 `#[ignore]`d live
  Windows Hello tests not run), on Windows.

## 0.11.1

- `lane-state` is publish-ready; with-secret names it by version.

## 0.10.0

- user-request: a new request kind, `RestorePlan`, a one-use approval bound to exactly one frozen
  plan hash; spent by `Store::spend_one_use` before the restore runs. **Breaking:** `Grant` and
  `MaxGrant` gained `OneUse`; `KindId::ALL` is now `[KindId; 3]`.
- Store files are flushed to disk before the rename that publishes them (`write_atomic`).
- Install `user-request` and `with-secret` together: a binary built before `RestorePlan` cannot read a
  store that holds one.

## Earlier

See OverMind's `CHANGELOG.md` for 0.9.1 and before.
