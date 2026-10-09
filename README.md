# consent

Two crates for asking a person to approve something, and for handing a secret to a command only
after they have. Both are Windows-first: the approval channel that is built today is Windows Hello.

| crate | what it is |
|---|---|
| [`user-request`](crates/user-request/README.md) | Ask a person to approve something through an interchangeable channel, and get back a grant **the approver** chose. A closed set of request kinds, each with a compiled-in maximum grant. |
| `with-secret` | Run one command with one secret, after the secret's owner approves through `user-request`. Secrets live in a DPAPI-encrypted vault, not in environment variables. Design: [`WITH-SECRET-DESIGN.md`](WITH-SECRET-DESIGN.md); operations: [`docs/WITH-SECRET-RUNBOOK.md`](docs/WITH-SECRET-RUNBOOK.md). |

## Honest scope

- **Windows Hello is the only channel built.** The SMS and push channels in `user-request` are
  designed for and answer `Unavailable`. Both crates compile on Linux (CI builds there), but the
  approval and vault paths do real work only on Windows.
- **`with-secret` stops accidental exposure, not deliberate misuse.** A process that is given a
  secret can print it, and any process running as the same Windows user can decrypt the vault
  (design doc section 3).
- **Neither crate is published.** Nothing here goes to crates.io without the owner's per-crate
  approval.
- The live Windows Hello tests are `#[ignore]`d and need a person at the desktop; CI does not run them.

## History

This repository was split out of [`ciresnave/OverMind`](https://github.com/ciresnave/OverMind) with
`git filter-repo`, so the commits that touched these crates keep their history. Version numbers
continue OverMind's (0.11.1) so an installed binary still says which release it came from. Both
crates share one version.

## Development

```
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 .github/spdx_gate.py --self-test && python3 .github/spdx_gate.py
```

The minimum supported Rust version is in `Cargo.toml` (`rust-version`) and is checked in CI.

## Licence

MIT OR Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
