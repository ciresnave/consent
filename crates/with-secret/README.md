# with-secret

Releases a named secret to one command, only after a person approved it, and masks the value in
what the command prints. See `../../WITH-SECRET-DESIGN.md` and `../../docs/WITH-SECRET-RUNBOOK.md`.

## Platform support

| | Windows | Linux |
|---|---|---|
| Vault at rest | DPAPI user scope (this tool's entropy) | the tiered key protector, `keyfile` tier only so far |
| Vault directory | `%LOCALAPPDATA%\OverMind\with-secret` | `$XDG_STATE_HOME/OverMind/with-secret`, else `~/.local/state/OverMind/with-secret` |
| Approval | Windows Hello | physical presence: a security key (build with `--features fido2`; needs `pkg-config` and `libudev-dev`), else every ask is `Unavailable` and nothing is released |
| `vault set` input | hidden console input | hidden terminal input (echo off) |
| Terminal `y/n` | none | **none, ever**: no flag, no environment variable (`user-request/tests/no_terminal_channel.rs`) |

**Weaker on Linux, stated plainly.** The `keyfile` tier keeps its key-encrypting key in the same state tree as
the vault, so a copy or backup of that tree carries both, and any process running as the same user can read
it. It keeps other users out and nothing more. DPAPI at least keeps the key out of a copied directory.
`with-secret check` names the protection in use. Secret Service and TPM2 tiers
(`docs/LINUX-PORT-DESIGN.md`, S5) are not built.

**Not yet verified on Linux:** that the `claude` process is found by name and start time in the process
table (`identity.rs` accepts `claude` and `claude.exe`; measurement 3 of the design). Until then a lane on
Linux may be reported as "NOT a registered lane" in the prompt.

`with-secret revoke NAME | --all` needs no approval and works the same on both: it only removes privilege.
