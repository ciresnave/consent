# `with-secret`: should the vault be divided by who requests? Design (NOT implementation)

**Status: draft for the PM, decisions of 2026-10-16 recorded in §5-§6. No code written.** The PM's view to test: not two vaults, but ONE store with a
per-entry requester allowlist. This document tests it against the code as it is, and answers the PM's
three questions: how a lane's identity is established today, what an allowlist adds on top of the
per-approval prompt, and how the 17 existing entries migrate.

**Refs.** `consent@57c84ce` (`origin/main`, crates `with-secret` and `user-request`) and
`agentlife@2d4cc51` (`lane-restart`, `lane-state`), read from `origin/main` blobs on 2026-10-16. Machine
facts (ACLs, `vault list`, `access.log`) were read on this box the same day. Where something was read in
code but not executed, the text says so.

## 1. Answer in short

1. **Yes to one store with an allowlist; no to two vaults.** A second vault would be a second DPAPI blob under
   the same Windows user, so it separates nothing an agent can reach (§3.3), and it doubles the
   `vault set`/mask/rotation surface.
2. **The allowlist is a filter before the prompt, not a security boundary.** A lane that is not on the list never
   reaches Windows Hello. That is a real gain (fewer prompts, and a confused lane cannot even ask for another
   project's secret). It does not stop a deliberate same-user process, because a lane's name can be forged
   (§2) and the vault can be decrypted by any process of the same user (`WITH-SECRET-DESIGN.md` §3). Say it
   that way in the docs, never stronger.
3. **The real boundary is the Windows account.** `gh-runner` must be, and stays, a different Windows user.
   Today that account does not exist yet, and two things would let it round the vault anyway: a runner
   that runs as `cires`, and the fact that `with-secret.exe` is writable by every local account (§3.2).

## 2. How a lane's identity is established today

`with-secret` never takes a name from an argument. In `main.rs:108` it calls `identity::resolve`
(`identity.rs:20`) with its own pid, the OS process table and every lane-state file in
`C:/Projects/.lane-state` (`lane-state` `platform.rs:68`):

1. Walk up from `with-secret`'s pid to the **nearest `claude`/`claude.exe` ancestor** (`identity.rs:35-60`; a
   parent that started after its child is a reused pid and stops the walk).
2. Find the lane-state file whose `pid` equals that ancestor's pid (`identity.rs:41`, `states.iter().find`:
   first match, directory order). Its **`role` field** (not the file name) becomes the requester's role, with the
   file's `session_id`. Requester = role + session + claude pid + claude start time, `managed: true`.
3. A `claude` with no such file is role `unmanaged-claude`; no `claude` ancestor is `outside-claude`. Both are
   `managed: false`, and the prompt then says "NOT a registered lane" (`channel.rs:97`).

How a state file gets its `role` (`lane_state_writer.rs:95-124` `hook_role`, using `:28` `resolve_role`), in
order: the `LANE_ROLE` environment variable of the hook process, returned **verbatim**; else the file that
already records this session id **and** this claude pid; else the nearest cwd ancestor whose project-directory
encoding matches the transcript path; else the **lower-cased leaf of the working directory**. The PM's own
lane needs `LANE_ROLE=pm`, because its cwd leaf is `Projects`.

**Can a lane forge another's name? Yes, by three routes, none of which needs more than the lane's own Windows
user.** I read each in code; I did **not** run any of them, because two would overwrite a real lane's state
file.

| route | why it works | ref |
|---|---|---|
| Start a nested `claude` with `LANE_ROLE=<other>` | The nested `claude`'s hooks write a state file with that role, and `with-secret` called from inside it resolves to that role. | `lane_state_writer.rs:95-100` |
| Write a state file by hand | `C:/Projects/.lane-state` grants **`Authenticated Users: Modify`** (`icacls`, 2026-10-16, inherited from `C:/Projects`). `resolve` trusts the file's `pid` and `role` fields; nothing signs them. | `identity.rs:41-47`, `icacls` |
| Start `claude` in a directory named like the role, with `LANE_ROLE` unset | Role falls back to the cwd leaf. | `lane_state_writer.rs:95-124` |

So the identity is good against **accident** (a lane cannot name itself into another lane's approval from the
command line, which is what `identity.rs:1-5` claims) and bad against **intent**. The same limit is already
accepted for the Hello prompt: `identity.rs:4` says so, and `WITH-SECRET-DESIGN.md` §3 states it.

Also observed (listing `C:/Projects/.lane-state`, 2026-10-16): the role names are the state-file names, e.g.
`agentlife`, `auth-framework`, `baracuda`, `coderipper`, `fuel`, `humboldt`, `humboldtunifiedkidtracker`, `kiss`,
`lightbulb`, `mlmf`, `overmind`, `persistant`, `pm`, `safeimage`, `synapse`, `thinkersfoundation`,
`thinkersjournal-community`, `unisql`, `unpopped`. Some lanes have only a `<role>.launch.json` right now
(`restarttest`), and the directory also holds leftovers that are just a worktree's directory name (`api`, `web`,
`worker`, `shared`, `frontend`, `routes`, `hf-config`, `version-0.5.5`, `mlmf-gguf`, `model-policy`,
`synapse-restarttest-lane`). The cwd-leaf fallback mints such accidental roles. An allowlist must use the
exact strings, and a list may name a lane that is not running (hence a warning, not an error, in §4). The
PM's example `community` is not a role; `thinkersjournal-community` is.

**A hazard that exists today: several state files carry the same pid.** Measured (parsing every `*.json`
there, 2026-10-16): pid 18736 is recorded by both `overmind` (updated today) and `synapse-restarttest-lane`
(updated 2026-10-09); pid 4216 by `api`, `shared`, `web`; pid 41632 by `frontend`,
`humboldtunifiedkidtracker`, `routes`, `worker`; pid 57564 by `hf-config`, `version-0.5.5`. In every case the
`role` field equals the file stem. `identity.rs:41` takes the **first** match of `states.iter().find(...)`,
in `read_dir` order (I assumed alphabetical on NTFS; not tested). For pid 18736 that happens to give
`overmind`; a lane whose stale twin sorted earlier would resolve to the wrong role, and an allowlist would then
deny a legitimate lane or allow it under a stray name. `lane_state_writer.rs` copes with twins only partly:
`assert-idle` takes the most recently updated file (`:146`, `max_by_key(updated_at)`), but `hook_role` step 2
takes the shortest recorded cwd, then the alphabetically first role (`:107`), so it too could pick a stale
twin. **The design therefore requires** that `resolve`
choose, among files with the claude pid, the one with the newest `updated_at` (ties: the stem equal to
`role`), and that a pid shared by two files is logged. This is a change to `identity.rs` and should land first.

## 3. Storage: what the OS actually separates

### 3.1 How `with-secret` stores entries (facts)

- One file, `vault.bin`, is the whole vault: `Vault { secrets: BTreeMap<String, Secret> }` serialised to JSON
  and encrypted as **one** DPAPI blob (`vault.rs:51-77,89,132-160`). A `Secret` is `value`, `env_var`, `access`
  (read/write), `created_at`, `rotate_by` (`vault.rs:51-62`). There is no per-entry blob and no owner field.
- Protection is `CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN` only and the fixed entropy
  `overmind.with-secret.v1` (`dpapi.rs:10,47`). **No `CRYPTPROTECT_LOCAL_MACHINE`**, so it is per-user scope:
  the key derives from the Windows user's own credentials, not from the machine. The entropy is "an accident
  guard", per the comment, not a secret.
- Location: `%LOCALAPPDATA%\OverMind\with-secret` (`platform.rs:22-23`). ACL on this box: `SYSTEM`,
  `BUILTIN\Administrators` and `cires`, all Full, inherited from the profile; no `Users` or
  `Authenticated Users` entry (`icacls`, 2026-10-16).
- `masks.bin` (salted hashes for the output-masking hook) is protected the same way; `access.log` is plain JSON
  lines (`audit.rs:12`: time, event, secret, role, session, claude pid, command, reason; never the value).
- Approvals are NOT in the vault: they live in the `user-request` store (`run.rs:189`, `store.find`), keyed by
  kind + secret + requester.

### 3.2 `gh-runner` must have no access: what holds today

- **The account does not exist yet.** `net user` on this box (2026-10-16) lists `Administrator, cires,
  DefaultAccount, Guest, james, kims2, waemi, WDAGUtilityAccount`; the runner script has not been applied.
  Everything below is therefore reasoned from the ACL and the DPAPI scope, **not measured as `gh-runner`**.
- As a standard user, `gh-runner` cannot read `C:\Users\cires\AppData\Local\OverMind\with-secret` (the ACL above),
  and a copy of `vault.bin` would not decrypt under its credentials because the scope is per-user. That is
  documented DPAPI behaviour; I did not test it, because there is no second account to test with.
- `RUNNER-SETUP.md` already requires "a restricted Windows account, not CireSnave's" (`:10`) and "no secrets
  reachable by the account" (`:43`). Two gaps:
  1. `RUNNER-SETUP.md` already says "not CireSnave's" account (`:10`), and its §5 fallback (`:76-79`) is still
     `gh-runner`; the "as CireSnave's account" in §5 is a driver check (`nvidia-smi`, `vulkaninfo`), not a runner
     setup. So this is not a gap in the text, but the rule is worth stating where it cannot be misread: **a
     runner never runs as `cires`**, because a process under the owner's account reaches the vault by DPAPI
     with no prompt (`WITH-SECRET-DESIGN.md` §3).
  2. **Everything under `C:/Projects` is writable by every local account.** `icacls` (2026-10-16): `C:/Projects`,
     `C:/Projects/.lane-state`, `C:/Projects/.claude-hooks` and `C:/Projects/.claude-hooks/with-secret.exe` each
     carry `NT AUTHORITY\Authenticated Users:(M)` (Modify), inherited from the drive root, and `BUILTIN\Users:(RX)`.
     `net localgroup Administrators` lists only `Administrator` and `cires`, so `james`, `kims2` and `waemi` are
     standard users who **already hold this Modify right today**; it is not only a future `gh-runner` risk.
     Two consequences for any such account:
     - **It can replace `with-secret.exe`** (and `lane-restart.exe`, `user-request.exe`) in `.claude-hooks`.
       The next lane that runs it runs the job's code as `cires`, with DPAPI access to the vault. This
       bypasses the whole separation in §3.2, and it is the most important finding of this document. It
       needs no vault access at all.
     - It can write state files in `.lane-state`, and `identity.rs:41` would then mislabel whatever `claude`
       has the pid it names (approvals, `lane-restart`).

     **Recommend: an ACL of SYSTEM, Administrators and `cires` only (Modify for `cires`; remove `Users:(RX)` and `Authenticated Users:(M)`)
     on `C:/Projects/.claude-hooks` and `C:/Projects/.lane-state`, applied before the runner account exists.**
     `C:/Projects` itself holds the repos the runner is meant to check out; its ACL is the PM's call. This
     needs an elevated shell, so it is a PM/CireSnave action. (`C:/Projects/.agentlife` does not exist on
     this box yet; the same rule applies to it when it does.)

### 3.3 Why a second vault does not help

Both vaults would be DPAPI blobs readable by the same `cires` user, which every lane runs as
(`WITH-SECRET-DESIGN.md` §2.1 and §3). Splitting by requester at the file level adds nothing a lane cannot undo;
splitting by Windows user (one account per lane) would, but is a different and much larger project (an
interactive session and a Hello prompt per account, plus the lanes' tools and credentials). Not proposed.

## 4. What an allowlist adds on top of the per-approval prompt

**The flow today** (`run.rs:153-250`): dump check, vault lookup (`:167`), grant maximum, **`store.find`**
(`:189`: an existing grant for this requester is used without any prompt), the store's gate `may_ask`
(`:198`: 10 minutes after a refusal, 6 prompts per lane per hour, 20 per hour for the person;
`store.rs:101-106`), then Hello (`:215`). The prompt shows Who, Wants, Duration and the reason
(`channel.rs:91-115`).

**What the allowlist changes, with the check placed where it must go:**

| | today | with an allowlist |
|---|---|---|
| A lane asks for another project's secret | A Hello prompt appears. CireSnave must know that this lane should not have it and say no (and the 10-minute cooldown applies per lane). | Refused in `authorize` before `store.find`/`may_ask`/Hello. No prompt, an audit line `not-allowed`. |
| Prompt fatigue | Bounded by the gate (6/lane/hour), but each wrong ask is still a prompt. | Wrong asks cost nothing. The prompt is for a lane that is allowed to ask. |
| Removing a lane from an entry | Needs `with-secret revoke` as well, or its existing grant keeps working until it expires. | If the check runs **before** `store.find` (place it right after `run.rs:167`), removal takes effect at once. |
| Who decides which lane may hold which secret | CireSnave, in his head, at each prompt. | CireSnave once, in a Hello-approved change; the log records every refusal. |
| A confused or compromised lane probing secrets | Looks like ordinary prompts. | Repeated `not-allowed` events for one role are a clear signal (new audit kind; the PM can alert on a count). |

**What it does not add:**

- No protection from a deliberate same-user process: it can forge a role (§2), edit `access` via DPAPI, or read
  the vault directly. The allowlist is only enforced by `with-secret.exe` itself.
- A forged role does not make the Hello prompt more trustworthy. It already says `Who: lane 'synapse'` for a
  forged `synapse`. With an allowlist the forger also becomes *eligible* to ask, so the approver's check is
  unchanged but the forger is no longer stopped early. The approver is still the only barrier to a forged
  identity, as now.
- The prompt line "Allowed lanes: …" is informational. It lets the approver notice an over-wide list; it
  does not prove the requester is who it says.

**Design, concretely**

- **Data:** `Secret.lanes: Vec<String>` with `#[serde(default)]` (`vault.rs:51`). Stored inside the same DPAPI
  blob, so a list change is one atomic `vault.bin` write. Role strings are matched exactly and case-sensitively: only the cwd-leaf fallback is lower-cased, a `LANE_ROLE` value is kept as written (`lane_state_writer.rs:29-31`), so `vault allow` warns about a role that is not lower-case. `unmanaged-claude` and `outside-claude` are **never** matched by default; a list
  may name them explicitly, and `vault list` prints them in a warning colour.
- **Check:** in `authorize`, after the vault lookup: not on the list → log `not-allowed` (role, secret, claude
  pid) and return a message naming the entry and "ask the PM to add the lane". No store access, so no
  prompt and no gate slot spent.
- **Default deny** for new entries: `vault set` of a **new** name without `--lanes` is refused; `--lanes none`
  makes an entry nobody can request (parked). `vault set` replaces the whole `Secret` (`main.rs:272-281`) and
  is also the rotation path, so for an **existing** name it must **keep the stored list** unless `--lanes` is
  given; otherwise every rotation would restate (or silently lose) the list. Absent `lanes` in a legacy entry
  means "none" after cutover (§5). Every `Secret { .. }` literal needs the new field (`main.rs:274`,
  `run.rs:332`, `vault.rs:268`, `tests/masks_at_rest.rs:33`).
- **CLI:** `vault set NAME --env VAR --access read|write --lanes a,b,c`; **and** `vault allow NAME --lanes a,b,c`
  (replace) / `--add` / `--remove`, because changing the list through `vault set` means re-entering the
  secret (`main.rs:268`, `read_value_from_console`) and renews the mask salts. A role that matches no state
  file under `.lane-state` is a warning ("typo? currently no such lane"), not an error.
  `vault allow` is **not** free with today's code, and needs four things:
  1. **A vault-only save.** `VaultStore::save` always writes `vault.bin` **and** `masks.bin` and rebuilds the
     masks from the vault (`vault.rs:149-157`; callers pass `masks_json(&vault)`: `main.rs:282,294`). Reusing it
     would renew the mask salts, which `vault allow` is meant to avoid.
  2. **Its own Hello text.** `require_hello` builds `"with-secret: {action} secret {name} in the vault?"` and
     fails with `"not {action}d"` (`consent.rs:16-18`, `main.rs:184-194`), which reads "not allowd" and does
     not show the list. The prompt must show the entry and the **new list**; a batch must show every name and
     list (clipped, with a count). Approving a list the approver cannot see would defeat the point.
  3. **A binding for several secrets.** `require_hello` binds one (action, name); a `--file` call needs a binding
     over the whole set.
  4. **A TTY and a rate limit.** `vault set` is out of a lane's reach only because it reads the value from the
     console. `vault allow` has no such need, and `require_hello` has no gate or cooldown, so a lane could spam
     Hello prompts. Require an interactive console for `vault allow` and refuse it for a managed lane
     (`Requester.managed`).
- **Prompt:** one added line, `Allowed lanes: a, b, c`, **after Duration and before the reason**, because
  `channel.rs:86-90` puts Duration before the reason so that a dialog that cuts the tail cuts the reason first.
  This is more than a line in `channel.rs:91`: `prompt_text` is shared by every request kind in the
  `user-request` crate and `Request` (`run.rs:208-214`) has no lanes field, so the change adds an optional
  field to `Request` that only secrets fill. The test at `run.rs:553` pins five lines and becomes six.
  Who and Duration are never clipped; Wants is (`channel.rs:113`, 200 chars, harmless for a 64-char name).
- **Audit:** `Event` already records requester and entry (`audit.rs:12`). Add the kind `not-allowed` to the
  existing set (`granted | used | denied | timed-out | unavailable | refused | gate-refused`).
- **Version skew:** `Secret` has no `deny_unknown_fields`, so an older `with-secret.exe` that rewrites the vault
  (`vault set`/`remove`) drops `lanes`. The `.prev` binaries in `C:\Projects\.claude-hooks` would do that. After
  cutover, such an entry reads as "none": fail-closed, loud, recoverable with `vault allow`.

## 5. Migration of the 17 existing entries

`with-secret vault list` (2026-10-16; names and metadata only) shows 17 entries, all created 2026-10-15,
none with `rotate_by`, 16 `Write` and one `Read`. `access.log` has 34 rows between 2026-10-01 and 2026-10-16
and only three roles in it (`overmind`, `pm`, `outside-claude`), so **13 of the 17 entries have no logged use at
all**.

**PM ruling (2026-10-16, on #149):** an entry with no logged use starts **`pm`-only**, not with a guessed lane. A
lane is added later by one Hello-approved `vault allow` change when it actually asks (its refusal is in the log
as `not-allowed`, which is the trigger). An entry with logged use keeps the roles in the log.

| entry | access | starting lanes | basis |
|---|---|---|---|
| `GROQ_CLOUD_API_TOKEN` | write | `overmind` | log: overmind granted+used |
| `LLAMA_DESKTOP_API_KEY` | write | `overmind`, `pm` | log: both granted+used |
| `TJ_PROD_DATABASE_URL` | write | `pm` | log: pm granted+used (12 uses); `outside-claude` also granted+used (see below) |
| `TJ_PROD_DATABASE_URL_RO` | **read** | `pm` | log: pm only |
| `GOOGLE_AI_STUDIO_API_TOKEN` | write | `pm` | no use logged |
| `MISTRAL_API_TOKEN` | write | `pm` | no use logged |
| `NVIDIA_NIM_API_TOKEN` | write | `pm` | no use logged |
| `OPENROUTER_API_TOKEN` | write | `pm` | no use logged |
| `HUGGINGFACE_API_TOKEN` | write | `pm` | no use logged |
| `CLOUDFLARE_WORKERS_AI_API_TOKEN` | write | `pm` | no use logged |
| `CIVITAI_API_TOKEN` | write | `pm` | no use logged |
| `CLOUDFLARE_BUILDS_API_TOKEN` | write | `pm` | no use logged |
| `CACHE_PURGE_TOKEN` | write | `pm` | no use logged |
| `R2_ACCESS_KEY_ID` | write | `pm` | no use logged |
| `R2_SECRET_ACCESS_KEY` | write | `pm` | no use logged; must always have the same list as the line above |
| `CODECOV_TOKEN` | write | `pm` | no use logged |
| `FLY_API_TOKEN` | write | `pm` | no use logged |

Notes:

- **Expect `overmind` to be refused for the provider tokens** (`GOOGLE_AI_STUDIO_API_TOKEN`, `MISTRAL_API_TOKEN`,
  `NVIDIA_NIM_API_TOKEN`, `OPENROUTER_API_TOKEN`, `HUGGINGFACE_API_TOKEN`, `CLOUDFLARE_WORKERS_AI_API_TOKEN`,
  `CIVITAI_API_TOKEN`) the first time it runs `probe/provider_probe.py`, because the log has no use of them. That
  is the intended trigger for the first `vault allow`, not a fault; the refusal message names the entry and says
  to ask the PM.
- **`outside-claude` used `TJ_PROD_DATABASE_URL` twice** (and `TEST_THROWAWAY`, since removed from the vault).
  Under the new rule that role is denied unless an entry names it. PM ruling: the question goes to CireSnave
  (board 225), the PM recommends deny. Until he answers, the entry's starting list is `pm` only.
- A pair such as `R2_ACCESS_KEY_ID`/`R2_SECRET_ACCESS_KEY` should have the same list; `vault allow` takes several
  names in one call (`vault allow --file lanes.json`) so they cannot drift.
- **Cutover, one prompt:** build the new `with-secret.exe`; keep the old binary at `*.prev`; run one
  `vault allow --file` (a single Hello prompt that shows the 17 names and lists, per §4) with the table above;
  then `vault list` shows each list. Between install and that call, every request is refused with a message
  that says why (fail-closed). With the log showing 34 events in 15 days, the gap costs little. The alternative
  (a transition release where an absent list means "any lane" and `vault list` warns) is fail-open while it
  lasts and I do not recommend it.

## 6. Decisions and open points

PM decisions on #149 (2026-10-16):

1. The wording "a filter before the prompt, not a boundary" is approved for the user-facing docs.
2. The table in §5 is accepted, with the change that entries with no logged use start `pm`-only.
3. The ACL on `.claude-hooks` and `.lane-state` is board 224, and "a runner never runs as `cires`" (except the
   Humboldt exception, board 223) is board 223: both are CireSnave's decisions. The `outside-claude` question is
   board 225.
4. The implementation goes in the `consent` repo (`with-secret`, `user-request`), design-first.

Open: the order of the implementation PRs. This document suggests the `identity.rs` tie-break (§2) first, then
the `lanes` field and the check in `authorize`, then `vault allow`, then the prompt line.

## 7. Not measured

- Any behaviour as `gh-runner` (no such account).
- The three forgery routes (read, not executed).
- Whether an Administrator on this box can recover `cires`'s DPAPI key. Administrators is only `Administrator`
  and `cires` (`net localgroup Administrators`, 2026-10-16), so `james`, `kims2` and `waemi` are standard users.
  Microsoft's documented behaviour is that an administrator cannot without the credentials; I did not test it.
- NTFS `read_dir` ordering (§2, the shared-pid hazard).
