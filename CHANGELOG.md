# Changelog

Version numbers continue OverMind's. The entries below 0.12.0 are the part of OverMind's
`CHANGELOG.md` that concerns these two crates, kept so the history travels with the code.

## Unreleased (version allocated by the PM at gate time; Breaking for non-Windows builds)

Linux port, upstream asks U1, U4, U7 (agentlife `docs/PORT-LINUX-PLAN.md` section 5). U2 waits on `lane-state` publishing `platform::state_dir`; U3, U5 wait on CireSnave; U6 is a standing NO.

- **U1:** `locate::dir()` is `$XDG_STATE_HOME/OverMind/user-request`, else `~/.local/state/OverMind/user-request` off Windows (a relative `XDG_STATE_HOME` is ignored, per the XDG specification); Windows is unchanged (`%LOCALAPPDATA%`). New `locate::Env` and `locate::try_dir(&Env)` let every platform's answer be tested on any host. `USER_REQUEST_DIR` stays debug-only.
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
