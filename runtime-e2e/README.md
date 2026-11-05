# Isolated runtime acceptance harness

Runs digest-pinned, already-built artifacts in a private Docker network. The fixture contains
three matching nodes, three assets nodes, OMS, settlement bridge, market gateway, money-journal
projector and fresh PostgreSQL databases. No ports are published. It does not build engine jars.

Implemented scenarios:

* `harness-negative-controls`: separate-process proof validation, including zero work, failed
  children, no-op kill, missing genesis, external endpoint and missing/changed artifact rejection.
* `critical-path-smoke`: verified empty genesis, deposits, 12 crossing trade pairs, cancellation,
  one open hold, withdrawals and exact reconciliation of durable orders/executions, AE state and
  projected money journal. HTTP acceptance alone never counts as completed financial work.
* `false-ready`: detach an owned live follower from the private network, commit and settle new
  work on the remaining quorum, compare independent replication counters with follower readiness.
* `pruner-exception`: temporarily deny access to the fixture follower's recording metadata,
  complete a snapshot, restore the original permissions, complete another snapshot and check
  pruner recovery and exact money. No financial records are deleted by the injector.
* `offline-purge-rejoin`: SIGKILL an owned follower, process 900,000 logged read-only diagnostic
  requests, snapshot across the engine's fixed 64 MiB segment boundary, observe purge and restart
  the same member state. Recovery is bounded by the manifest budget; exact money is rechecked.
* `baseline-fault-reproduction`: run the three fault scenarios sequentially in fresh owned fixtures.
  Three verified baseline REDs are reported explicitly, with nonzero exit; never converted to product PASS.
* `benchmark-preflight`: 140 orders validate measurement instrumentation and the full money oracle;
  no performance quality acceptance is inferred.
* `benchmark-normal` / `benchmark-n-minus-one`: one declared open-loop repeat, measuring original
  intended arrival to observed durable PostgreSQL state and actual journal settlements. All intents,
  errors, dispatch lag and durable observations are retained. Three repeats per profile are required
  separately before accepting a baseline; one successful repeat is insufficient.

Fault scenarios need the separately compiled, hash-pinned `java/FixtureProbe.java` test helper.
Record its source, compiler, compile classpath and jar hashes in `test_helper`; the runner never
compiles it or changes engine jars. On the initial baseline the three faults are expected to
return FAIL with raw witnesses. This is not product acceptance. Other scenario names fail closed.
The measurement scenarios also require a separately compiled, hash-pinned `BenchmarkProbe.java`
in `benchmark_helper`. No engine code is rebuilt or replaced. Actual performance acceptance remains
incomplete until all declared repeats and financial/resource checks have evidence.
The single-host fixture proves process behavior only; it cannot establish host failure tolerance.

Requirements: Python 3, Docker, PostgreSQL 16 tools with TimescaleDB installed, a fixed local Linux
image digest containing Java 21 and Python 3, and the six frozen jars. An explicit manifest supplies
artifact hashes/source commits, RFC1918 internal /24 network, endpoints, resource bounds, CPU set,
seed, toolchains and predeclared quality budgets. The current frozen market gateway requires ME
base port 9000 and stride 100; the fixture validates this declared port profile before startup.

```bash
python3 -m unittest discover -s tools/runtime-e2e -p 'test_*.py' -v
python3 tools/runtime-e2e/build_probes.py --me-jar /absolute/frozen/match-cluster.jar \
  --oms-jar /absolute/frozen/oms.jar --output /absolute/path/new-probe-directory
tools/runtime-e2e/run.sh --manifest /absolute/path/manifest.json \
  --scenario critical-path-smoke --output /absolute/path/new-evidence-directory
```

Copy the two objects from `probe-manifest.json` into the fixture manifest. This preparation uses
the supplied frozen jars only as compiler inputs; it does not install Maven dependencies, modify
product jars or publish anything. Compiled sources are copied into the immutable probe directory.

Every active run requires a new `r01-<12 lowercase hex>` identity and fresh state root, exactly
`<manifest parent>/fixtures/<run identity>`. Existing state and evidence are never reset or reused.
Retain a copy of each manifest. Repetitions change only identity/state path, not artifacts, resource
profile, seed or budgets. The image is addressed by `sha256`, never a mutable tag.

Results distinguish `PASS`, `FAIL` and `INCONCLUSIVE`; only PASS returns zero. All subprocess exits
and outputs are retained. Synthetic negative proofs are explicitly labeled and cannot count as
cluster fault evidence. The runner records source hashes and preserves failed attempts.

Teardown verifies both the run label and an unpredictable ownership token for Docker objects,
and verifies the owned PostgreSQL process/data path. It removes only those processes and network;
state and logs remain. If interrupted by an uncatchable signal, resume cleanup with the same
manifest using `Fixture(manifest, attach=True).close()`. Never manually prune Docker or reset a DB.

The money oracle uses integer units (1e-8), fixed-price LIMIT orders, no fees or amendments, and
two equal observations after input closes. Missing genesis, pending state or an unmodeled movement
is inconclusive. Raw collections, barrier hashes, each accepted order ID and all funding events
are retained. Smoke request timings include orchestration and are not performance measurements.

## Core topology (fixture v2, RC2 S14)

Manifest `schema_version: 2`, `topology: core` (validated by `core_contracts.py`) runs the OMS + ledger
core instead of the legacy OMS path: `me0-2`, `ae0-2`, `fwd0`, `fwd1`, `bridge0`, `bridge1`,
`projector`, the reserved `shadow0` and `probe`. `oms`, `market` and the legacy `bridge` are refused.
PostgreSQL carries only the money-journal history projection.

* Credentials: every run mints fresh 32-byte secrets (`credentials.py`). Key tables are
  `keyId:CLASS:secretHex::users=*` entries joined by `;` (RC2 S6, A16: the users field is mandatory). The AE gets
  `ASSETS_AUTH_KEYS`, each client one `AE_AUTH_CREDENTIAL`; the ME gets the key table named by
  `credentials.me.keys_env` (classes FORWARDER, ADMIN). `credentials.me.mode` must say whether the ME
  artifact enforces it (`not_enforced_by_artifact` until RC2 S6). Evidence keeps key ids and classes;
  secrets are redacted from every retained command line, output, container log and probe state file
  (`tap.out`, `tap.err`, `tap.jsonl`) before teardown. `shadow0` gets no key until
  `SessionClass.REPLICA` exists (RC2 S1); RCS S9 fills that slot.
* Slots: `fwd0/1` and `bridge0/1` start a pinned binary named in `slot_artifacts` (artifacts
  `forwarder[_b]`, `bridge[_b]`, `driver: embedded | external` (S15: `java_media_driver` is retired), optional `libs`). A `null`
  slot is recorded `SKIPPED_ABSENT`, never faked. The environment follows rc2-forwarder.md 2.11 and
  rc2-bridge-cpp.md 2.11; the bridge must keep the `/health` `{halted, aeConnected}` contract.
* D20: `timeouts: production` is mandatory. Allowlists, not denylists: top-level manifest keys
  (`core_contracts.MANIFEST_KEYS`), environment names a fixture process may receive (`PROCESS_ENV`),
  and the pinned image's own `Config.Env` names (`IMAGE_ENV`, checked by `docker image inspect` at
  start, names recorded in `owner.json`); no value, Entrypoint or Cmd may carry a `-D...timeout`
  style override. Every engine member is pinned to its own disjoint cpuset.
  D18: the network is `--internal`; no archive control port leaves it.
* Probes (`build_core_probes.py`): `CoreProbe` (against the AE jar: money-journal, core-config, risk,
  gate, deposit/withdraw, create/cancel/amend, order-dump, money-dump, pending-dump, tap, unauth) and
  `JournalProbe` (against the ME jar: verbatim journal frame dump, OpenOrdersSnapshot). The journal is
  decoded in Python from the pinned schema XML (`schemas/`, `journal_decode.py`); RC2 S1's journal
  schema 4 drops in as `schemas/me-journal-schema-4.xml` plus its SHA-256 in
  `schemas/journal-profiles.json` (profile `me-journal-4`, active since S15). Unknown records stop loudly.
* Oracles: `core_oracle.py` (money M1-M14) and `order_oracle.py` (order O1-O12) judge one
  `core-sample-v2` document (format in `oracle_model.py`) per rule: FAIL > INCONCLUSIVE > PASS.
  `oracle_samples.py <new dir>` writes the clean synthetic samples for the Java mirror.
* Fault helpers: `CoreFixture.kill(role)`, `CoreFixture.partition(src, dst, kind, add|delete)` for
  client-to-engine UDP paths (G10), `metrics(role, port)`.

**H0 G2 RED witness, substituted (2026-10-26).** The spec asks for "a boot of a9a865d with today's
fixture fails on authentication". The v1 fixture cannot boot on the dev box: the host PostgreSQL 16
TimescaleDB packaging (library 2.31.0, scripts up to 2.28.2) fails `CREATE EXTENSION timescaledb`
before any engine starts, an environment fault that is left as is. The equivalent witness is in
`core-boot`: `CoreProbe unauth mode=legacy_none` connects with no credential, exactly what every
pre-RC1 client (and the v1 fixture) presents, and the RC1 core refuses it with
`AuthenticationException`; the refusal is recorded as `auth_controls.g2_legacy_witness`, and the
genesis is re-verified unchanged afterwards.

Scenarios: `core-boot` (genesis, four authentication refusals, one core authority refusal that
moves `assets_ingress_unauthorised_total`), `core-smoke` (H0: funding at GENESIS, gate OPEN, creates
reach DISPATCH_PENDING; without a forwarder O7/O10 must be INCONCLUSIVE, a PASS fails the smoke) and
`core-boots-N` (G15: N fresh boots, `ten_consecutive_boots.json` for N = 10).

The T2 nightly runs from a local systemd user timer (`systemd/`, `nightly.py`), not GitHub (D20).

## Docker drills A01 + A02 (RC2 S15, 2026-11-02)

Contract: `notebook/reports/runtime-handoff-execution/RC2-me-link/S15/contract.md`. Nine T2 drills, two REDs, four
non-vacuity controls, two embedded-driver repeats. Scenario names: `core-drill-<name>` (lostack, coreleader, meleader,
fwdrestart, partition, fwdpause, driverkill, lifecycle, lifecycle-faults), `core-control-<line>`, `core-red-1`,
`core-red-2`, `core-red-2-negctl`. Code: `core_drills.py` (drills, barrier, backfill, branch records), `core_fixture.py`
(genesis phases, fault helpers, `/ready`), `java/CoreProbe.java` (`story`, `tap`).

* Run state: manifests and state roots live in a run directory outside every repository (`$RUNS`, a sibling of the
  workspace), never under the notebook. `validate_core_manifest` forces `state_root` under the manifest directory, so a
  manifest inside `evidence/` would put staged nc binaries one `git add` from a commit. Only the sealed subset is copied.
* Binaries: bind-mounted host build of `cluster-tools` (ct-forwarder, ct-bridge, aeronmd and its two `.so` files), pinned by
  sha256 and `source_sha`; no image build. The nc builds (`forwarder_b`, `bridge_b`) are never published.
* Drivers: slot driver is `external` (a staged aeronmd started by the slot wrapper after `rm -rf` of the dir) or
  `embedded`. `T1MeDriver` and `T1CoreDriver` are compiled from `cluster-tools` sources (never copied) and used as genesis
  probes; they read `T1_LOCAL_HOST` for the egress host. D20: the only exempt timeout names are exactly
  `FWD_DRIVER_TIMEOUT_MS=5000` and `BRIDGE_DRIVER_TIMEOUT_MS=5000`.
* Story: `CoreProbe story script=a01-mix|a02-lifecycle|funding`. One GATEWAY session, open loop, paced by wall clock. A
  per-user cap of 256 retained requests per 15 minutes applies, so a01-mix needs at least 29 funded users (the plan uses 40).
  Every UNKNOWN reply is re-sent once with the same `requestId` after the heal (6.1); an unresolved one makes the run
  INCONCLUSIVE, never FAIL.
* Tap: `CoreProbe tap` re-registers on a leader change and reports density. The tap goes blind across an AE leader change,
  so the drill compares the tap's last seq with the core head and closes gaps by backfill from pending-dump and the ME
  journal. A gap that cannot be closed is INCONCLUSIVE.
* Pitfalls seen in real runs: restarting an AE member within about 12 s of a kill hangs the JVM ("active mark file");
  the in-container aeronmd pid is always 9, so driver identity is the `cnc.dat` mtime plus the container `StartedAt`;
  `/dev/shm` peaks were 1040 to 1047 MB per ME member and 927 to 948 MB per AE member (limit 1536 MB each), bridges 60 MB, forwarders 56 MB.

## Docker drills A03 + A04 + A05 + A06 (RC2 S16, 2026-11-04)

Contract: `notebook/reports/runtime-handoff-execution/RC2-me-link/S16/contract.md`. Scenario names follow S15 (`core-drill-<name>`, `core-control-<line>`, RED scenarios).

* Lifecycle helpers (`core_fixture.py`): `stop`, `replace_slot` (the only way a slot changes binaries; both shas in the witness),
  `wipe_engine` (refuses a running member; for an AE member it needs the core life's projection dump with the digest
  `reset_projection` recorded, no dump no wipe), `reset_projection` (dumps the life's money tables, then recreates the database),
  `regenesis`, `start_members`.
* Two-life runs: A04 judges one sample per life; the projection database is reset between lives; life-1 ME evidence is read
  before the wipe.
* Engine external profile: manifest kind `s16-ext` runs the Java engines with `TRANSPORT_DRIVER_MODE=external` on a staged
  aeronmd, the pinned production `driver.properties` plus a dev threading overlay (both pinned by sha256 in `engine_libs`).
  Every other drill keeps the engines embedded.
* `mk_manifests.py <kind> <tag>`: `s16`, `s16-ext`, `s16-embedded`, `s16-n1`, `s16-a03`, `s16-a03-embedded`, `s16-a05`,
  `s16-a05-embedded`, `s16-red-a03`, `s16-red-a04`, `s16-ctl-edk-cnctimeout`.
* Latency table: per command id, the dispatch's cluster ms to the ME's first record-3 `timestamp` (the mint ms; the tap's receive
  time is not used), RELEASE_ID rows excluded. Baseline and swap-window summaries (p50, p99, p99.9, max) are recorded per run.
* Cost matrix: N in {1, 2} x rate in {100, 160} commands/s x 60 s (`CoreProbe story` caps at about 166/s); counts only, no
  throughput or latency claim (G20 is RCS S9's).
* Settings (`core_drills.py` SETTINGS, recorded with every run, never acceptance limits): `A05_P999_SLACK_MS` 10,
  `A05_N1_HOLD_S` 5, `A04_HALT_PHASE_S` 60, `CNC_TIMEOUT_BOUND_S` 35 (measured from the engine's own driver-wait log line, not the
  container spawn), `A05_DUP_EDGE_SLACK` 10, `ENGINE_SHUTDOWN_TIMEOUT_S` 4 plus `ENGINE_STOP_SLACK_S` 1.

## R10 cut, cross-version runs, activation record, nightly plan (RC2 S17, 2026-11-05)

Contract: `notebook/reports/runtime-handoff-execution/RC2-me-link/S17/contract.md`. Rollout page:
`notebook/reports/runtime-handoff-execution/R10/rc2-rcs-rollout.md`. Run every tool with plain `python3` (not `-I`: they import
their module dir).

* `r10_cut.py check <cut manifest> --old-pins <old-artifacts.sha256>`: rules K1-K10 over the cut (`ACCEPTED <name>`, exit 0;
  else one `K<n>` line per refusal and `REFUSED`, exit 1). `--cut <cut>` checks a derived fixture manifest. `harness_commit` must
  equal `repos.tools`, every probe source its blob at that commit, the tree clean, so every tools commit takes a new cut id.
* `r10_cut.py audit`, `precheck`, `activation-record`, `activation-records`, `genesis-ids`: the runtime audit against the
  manifest, the wipe precheck of runbook step 1, the RC2 step 7 record of one run (`OK`, `INCOMPLETE`, `ABORTED`, `REFUSED`;
  `record_kind` final or intermediate; the CLI writes life 1, the harness later lives), the set check over final records, and
  the CoreConfig `genesisId` read from each AE member's log.
* `mk_manifests.py <kind> <tag> --cut <cut>`: the `s17*` kinds derived from the cut (19 kinds), refused when the checker
  refuses them.
* `xver.py`: the cross-version (new side), activation and rollback cases X-1a/b/c, X-3a/b (both driver modes), X-7, X-A1,
  X-A2a, X-A2b, X-A3, X-A4, X-A5, X-R and their controls; `legacy_tag.py` runs the v0.5.0-beta jars (timescaledb pin, log-marker
  readiness, `ClusterTool snapshot` seeds). Timing sizes are `XVER_*` settings (`XVER_BOUND_S` 150, `XVER_STAGGER_S` 5).
* `core_fixture.py`: `seed_state` with witnesses, `replace_slot(keep_state)`, member-aware `verify_funded`, partial genesis and
  `finish`; a core boot on the cut runs the ME genesis before the forwarders.
* `nightly.py --plan nightly-cut.json --tools-repo <tools> --ct-repo <cluster-tools>`: drill and manifest pairs from a git
  archive of the pinned tools commit, the non-blocking heavy lock (`SKIPPED_BUSY` exit 75), the preflight (`INTERRUPTED`),
  `NIGHTLY_BOUND_S` 5 h, the night seal written last; `systemd/` holds the service template, the timeout drop-in and the timer.
* Settings changed in S17: `A05_P999_SLACK_MS` default 20 (PO 2026-11-05: the replacement forwarder's session setup costs 16 to
  28 ms on the 1-CPU fixture ME), still a setting.
* Known: the order tap loses order events across an AE leader change (product behaviour, no replay by `eventSeq` before RC3's
  `RequestOrderEvents`); the order oracle reads that as O5 INCONCLUSIVE (`tap_loss`), never FAIL.

