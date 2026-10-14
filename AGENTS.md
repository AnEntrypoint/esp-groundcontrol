# AGENTS.md

How an agent works in this repository. Factual, and short on purpose. When this
file and a served instruction disagree, the served instruction wins and the
disagreement is reported in one line.

## Tools

Everything goes through the gm verbs. Two rules are not negotiable:

1. **Code search is the `codesearch` port.** Never Grep, Glob, `find`, `rg` or
   `grep`. The reason is blast radius, not style: `codesearch` is a cached
   incremental index, a shell search walks the filesystem uncached on every call.
   The only `Read`s that skip it are known exact paths, and gm spool runtime
   state (`.gm/exec-spool/out/*.json`, `.status.json`, `.turn-summary.json`).
2. **Code questions go to codeinsight before `Read`.** `callers {symbol}` before
   you read, edit or delete a function: who calls it and what must stay valid.
   `impact {symbol, max_depth}` for what it depends on. After any change,
   `callers` on every function you touched. An empty reply proves absence only
   when `codeinsight_index` says `complete: true`; otherwise confirm with a
   `codesearch` identifier query.

Never run raw `git`. Use the git verbs.

A scan you would repeat, or one with no `path`/`glob`, goes to a subagent that
returns located `path:line` citations and counts only. The orchestrator keeps the
locations, not the match text.

Every `Agent`/`Task` dispatch opens with: use the gm skill for this; code
questions go to codeinsight (`callers`/`impact`) first, then the code-search
port, and `Read` only a located path. A fresh subagent inherits none of this
file and defaults to Grep/Glob/raw git unless told.

## Main only

- Commit and push on `main`. Never a branch, never a worktree, never a stash to
  get around a collision. Isolation buys a clean HEAD and costs a merge;
  recovery is cheaper.
- A collision is recovered, never parked. Re-read the changed paths at current
  remote state, reapply the change on that state, `git_add`, commit the merge
  without `paths`, push, finish on `main`. Never edit a file while `.git/MERGE_HEAD`
  exists: merge resolution restores the pre-merge tree and discards the edit
  with no error.
- A change left uncommitted, or a commit left unpushed, is a residual. Deliver
  it before the turn ends.
- One commit author: lanmower. No `Co-Authored-By`, no `Signed-off-by`, no
  "Generated with" line, in commit bodies or PR descriptions.
- A delivery is witnessed by separate read dispatches: `git_show {rev}` for the
  pushed sha and `ci-status {sha}` for CI. `unknown` is reported as unknown, not
  as pass. The command that made the commit is not the witness.
- Builds and cascading updates run through GitHub Actions, never a local
  toolchain.

## No test files, ever

No test file is created in this repository, for the firmware or the controller.
Verification is live execution against the real system, or a CI job:

- firmware: `idf.py build`, then `idf.py -p PORT flash` and `monitor` on real
  hardware; destructive recovery cases follow [docs/BENCH.md](docs/BENCH.md)
- controller: run the real service and drive it with a real MQTT client
- both: the `.github/workflows` jobs, and `node tools/keycheck.mjs` for the
  crypto vectors

A behaviour you need to pin down is recorded by running it once and writing down
what it did, not by writing a test.

## No comments in source

Intent is expressed through names. A comment is a name that failed. Rationale
that cannot be expressed in code lives in this file or in `docs/`, not in a
comment. If you meet a comment, express it in code or move it here; if you move
it here, confirm it is still true first.

## Directory ownership

| Directory | Owns | Notes |
| --- | --- | --- |
| `main/` | the firmware, ESP32-S2FN4R2, ESP-IDF v5.x | one `.c` per module, header in `main/include/`. `main/CMakeLists.txt` lists sources in dependency order; a module builds only once everything above it exists |
| `controller/` | the central control service, TypeScript on node 20 | sole authority for allow, deny, strike count and unblock. Refuses to start with no pepper for a site |
| `tools/` | provisioning and decode helpers | `provision.mjs` writes secrets to NVS from a file outside the repository; `keycheck.mjs` recomputes the crypto vectors |
| `docs/` | prose | `REQUIREMENTS.md` is the source of truth and its numbering is stable; cite requirement numbers, never restate them |
| `.github/workflows/` | CI | `firmware.yml` builds for esp32s2 and fails when the app image outgrows its slot; `controller.yml` typechecks and builds; `secrets.yml` fails on anything that looks like a real secret |

Cross-cutting: `partitions.csv` and `sdkconfig.defaults` are shared by every
firmware build. One image serves all three sites; provisioning supplies the site
id.

## The one failure that is invisible in logs

If the device and the controller derive different keys for the same number, the
portal accepts the number, the controller answers `not_verified`, and every
client is soft blocked for 24 hours. Nothing errors. It looks like "the bot is
not working".

Both halves derive independently: `key = HMAC-SHA256(pepper, domain || message)`
truncated to 8 bytes, with the number stripped to digits before hashing.

- Vectors and domain bytes: [docs/TEST_VECTORS.md](docs/TEST_VECTORS.md)
- Controller check, in CI: `node tools/keycheck.mjs`, exits non-zero on any
  mismatch
- Device check: bench procedure, row 12 of [docs/BENCH.md](docs/BENCH.md)

Run both before the first field pilot and after any change to `main/gc_crypto.c`
or `controller/src/crypto.ts`. A change to the domain string, the truncation
length or the pepper size is a coordinated rollout, not an edit: it breaks every
deployed device against its controller.

## Legal note

This is a South African deployment serving a public network.

- **RICA** (Regulation of Interception of Communications Act 70/2002) restricts
  intercepting or monitoring communications.
- **POPIA** (Protection of Personal Information Act 4 of 2013) governs personal
  information. A MAC address, a phone number and a per-client usage log are all
  personal information.

Consequences that are not up for discussion:

- Do not add payload inspection. Nothing reads, buffers or logs packet payloads
  (1.6).
- Do not add destination logging. No destination addresses, hostnames, URLs or
  per-client browse history in any log (1.7).
- A phone number is stored only as the 8-byte HMAC under the site pepper. Never
  in the clear, never in a log, never in an event (2.7).
- Keep the device at the device level: gate access, count bytes, monitor modem
  health.

If a requirement seems to ask for either, stop and raise it rather than
implementing it.

## Secrets

No private key, pre-shared key, broker password, pepper or WireGuard private key
is in the repository (13.1). CI fails on a file that looks like one. New keys go
through `tools/provision.mjs` from a file outside the tree. A secret that reaches
a log, a commit or an event is a defect to fix in the same turn.

## Words

Use the words in [docs/GLOSSARY.md](docs/GLOSSARY.md) and no synonyms: device,
controller, site, client, number, contact, verification, verdict, allow list,
block, block key, mac key, strike, soft block, permanent block, unblock, uplink,
reserve, governor, ladder, beacon, tunnel, slot, trial boot, self-test, frame,
reading.

## Before you open a PR

- `codesearch` for every symbol you touched, `callers` on every function you
  changed.
- No comment added, no test file added.
- Requirement numbers cited where behaviour changed.
- `docs/` updated if the change moves a threshold, a frame layout or a recovery
  path.
- CI green: `firmware.yml` and `controller.yml`.
