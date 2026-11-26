# consent roadmap

## R1: leave `chrono` (deadline 2026-12-17)

**Do:** (1) replace `chrono` with `jiff` or `time` in `user-request` and `with-secret`; (2) bump
`lane-state` once agentlife publishes a chrono-free release; then delete the `RUSTSEC-2026-0543` entry
from `deny.toml`. Step 2 waits on agentlife with no date: pm-platform (2026-11-25) says the `lane-state`
swap is a planned workspace-wide migration (82 files, public trait). It is not small.

**Why it is ignored until then:** `chrono` is unmaintained (RUSTSEC-2026-0543, all versions, no safe
upgrade). `cargo deny` fails on it, and nothing here can upgrade past it. PM ruling 2026-11-24 (consent#21):
ignore that one advisory, with an expiry, and carry this row as the exit.

**What pulls it in:** agentlife's `lane-state`, a dependency of both crates, still depends on `chrono`, so
step 1 alone does not remove it from the tree. Then `user-request` (grants, expiry, `next_local_midnight`, the audit log's timestamps, the
store files) and `with-secret` (its own approval expiry and audit). Both serialise `chrono` types, so a swap
changes stored formats: check old store and audit files still load.

**Not ignored:** `chrono-tz` (RUSTSEC-2026-0555). It is no longer a dependency; the DST-gap tests use a
test-only zone in `request.rs`.

**After 2026-12-17:** renewing the ignore needs a new decision from the PM. It does not lapse silently:
`deny.toml` carries the date, and this row is the reminder.
