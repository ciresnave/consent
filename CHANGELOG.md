# Changelog

Version numbers continue OverMind's. The entries below 0.12.0 are the part of OverMind's
`CHANGELOG.md` that concerns these two crates, kept so the history travels with the code.

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
