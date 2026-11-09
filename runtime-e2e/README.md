# runtime-e2e

Isolated runtime acceptance harness. It runs already-built, sha256-pinned artifacts in a private Docker network, drives them with Java probes, injects faults, and judges the resulting money and order state with oracles. It never builds or changes engine jars.

The single-host fixture proves process behaviour only. It cannot establish host-failure tolerance.

## Topologies

The manifest's `schema_version` selects the topology. `core-*` scenarios need a version 2 manifest and only they accept one.

- Core topology (`schema_version: 2`, `topology: core`, validated by `core_contracts.py`): the v1 layout. Roles are exactly `me0-2` (matching engine), `ae0-2` (order and ledger core), `fwd0`, `fwd1` (C++ ME forwarders), `bridge0`, `bridge1` (C++ settlement bridges), `projector`, `shadow0` (reserved) and `probe`. The v0.5 roles `oms`, `market`, `bridge` and `xprojector` are refused. PostgreSQL carries only the money-journal history projection.
- v0.5 topology (`schema_version: 1`, validated by `contracts.py`): three matching nodes, three assets nodes, OMS, settlement bridge, market gateway, money-journal projector and fresh PostgreSQL databases with TimescaleDB.

## Requirements

Python 3, Docker, PostgreSQL 16 binaries (`initdb`, `pg_ctl`, `psql`; TimescaleDB for the v0.5 topology), a Linux image addressed by `sha256` digest containing Java 21 and Python 3, and the pinned artifacts. Core slots run C++ binaries from `cluster-tools` (forwarder, bridge, `aeronmd` and its libraries), bind-mounted and pinned by sha256 and source commit.

Run the tools with plain `python3`, not `python3 -I`: they import modules from their own directory.

## Commands

```bash
# unit tests, no Docker needed
python3 -m unittest discover -s runtime-e2e -p 'test_*.py'

# probes for the v0.5 topology (compiled against the supplied jars, never changes them)
python3 runtime-e2e/build_probes.py --me-jar /abs/match-cluster.jar --oms-jar /abs/oms.jar \
  --output /abs/new-probe-dir

# probes for the core topology (CoreProbe against the AE jar, JournalProbe against the ME jar)
python3 runtime-e2e/build_core_probes.py --ae-jar /abs/assets-cluster.jar --me-jar /abs/match-cluster.jar \
  [--ct-dir /abs/cluster-tools] --output /abs/new-probe-dir

# one scenario
runtime-e2e/run.sh --manifest /abs/manifest.json --scenario core-smoke --output /abs/new-evidence-dir
```

Copy the program entries from the probe directory's `probe-manifest.json` into the fixture manifest.

Helper tools (each prints its own usage):

- `mk_manifests.py <kind> <tag>`: builds a core manifest of a named kind; every manifest of one kind differs only in `run_id` and `state_root`.
- `release_cut.py check | audit | precheck | activation-record | genesis-ids | record-builds`: checks a release cut manifest and derived fixture manifests against the artifact rules (pinned sha256, clean source commit, no test builds in product kinds, matching schema identities), audits a live state root, and writes activation records.
- `oracle_samples.py <new dir>`: writes clean synthetic oracle samples.
- `nightly.py`: the nightly runner (see below).

## Scenarios

Unknown scenario names fail closed.

Core topology:

- `core-boot`: genesis, authentication refusals and a core authority refusal.
- `core-smoke`: funding at genesis, gate open, creates reach dispatch.
- `core-boots-N`: N fresh boots (1 to 20).
- `core-drill-<name>`: fault drills such as `lostack`, `coreleader`, `meleader`, `fwdrestart`, `partition`, `fwdpause`, `driverkill`, `lifecycle`, `lifecycle-faults`. `core-control-<name>` are non-vacuity controls and `core-red-<name>` run known-bad builds that must fail. The full list is the `DRILLS`, `CONTROLS` and `REDS` tables in `core_drills.py`.
- `core-xver-*`, `core-act-*`, `core-rollback-*`: cross-version, activation and rollback cases against v0.5.0-beta state (`xver.py`, `legacy_tag.py`; the case table is in the `xver.py` docstring).

v0.5 topology: `critical-path-smoke`, `harness-negative-controls`, `false-ready`, `false-ready-ae`, `pruner-exception`, `offline-purge-rejoin`, `baseline-fault-reproduction`, `readiness-me`, `readiness-ae`, `readiness-lag-election-idle`, `log-channel-me`, `log-channel-ae`, `journal-oms-restart`, `oms-recovery-admission`, `oms-durable-request-id`, `execution-projector-replay-crash`, `oms-hold-release-authority`, `benchmark-preflight`, `benchmark-normal`, `benchmark-n-minus-one`. Fault scenarios need the pinned `java/FixtureProbe.java` helper and benchmark scenarios the pinned `java/BenchmarkProbe.java`, recorded in the manifest's `test_helper` and `benchmark_helper`.

## Run rules

- Every run needs a new run id and a fresh state root at exactly `<manifest dir>/fixtures/<run id>`. The output directory must not exist. State and evidence are never reset or reused; keep a copy of each manifest.
- Images are addressed by `sha256`, never by tag. Repeats change only the run id and state path.
- Core manifests require `timeouts: production`. Environment names are allowlisted per process (`PROCESS_ENV`) and per image (`IMAGE_ENV`); no value may carry a `-D...timeout` style override. The only exempt names are `FWD_DRIVER_TIMEOUT_MS=5000` and `BRIDGE_DRIVER_TIMEOUT_MS=5000`. Every engine member gets its own disjoint cpuset; the network is `--internal`.
- Credentials are minted per run (`credentials.py`): the AE gets `ASSETS_AUTH_KEYS`, each client `AE_AUTH_CREDENTIAL`. Secrets are redacted from every retained command line, output, log and probe state file before teardown.
- Teardown removes only Docker objects carrying both the run label and the run's ownership token, and only the owned PostgreSQL process. After an uncatchable signal, finish cleanup with `Fixture(manifest, attach=True).close()` (or `CoreFixture`). Never prune Docker or reset a database by hand.
- Keep manifests and state roots in a run directory outside every repository: `state_root` lives under the manifest directory and holds staged binaries.

## Results and oracles

Results are `PASS`, `FAIL` or `INCONCLUSIVE`; only `PASS` exits zero. All subprocess exits and outputs are retained, and the runner copies the harness sources into the evidence directory with their hashes.

- v0.5 money oracle: integer units (1e-8), fixed-price LIMIT orders, no fees or amendments, two equal observations after input closes. Missing genesis, pending state or an unmodelled movement is INCONCLUSIVE.
- Core oracles: `core_oracle.py` (money rules M1 to M14) and `order_oracle.py` (order rules O1 to O12) judge one `core-sample-v2` document (format in `oracle_model.py`), FAIL over INCONCLUSIVE over PASS.
- The journal is decoded in Python from the pinned schema XML in `schemas/` (`journal_decode.py`, profiles and hashes in `schemas/journal-profiles.json`). Unknown records stop the decode.
- Smoke request timings include orchestration and are not performance measurements. A benchmark baseline needs all declared repeats; one repeat is not enough.

Known limits:

- The order tap loses order events across an AE leader change. Drills close the gap by backfill from the pending dump and the ME journal; a gap that cannot be closed is INCONCLUSIVE (`tap_loss`), never FAIL.
- Restarting an AE member shortly after a kill can hang the JVM on an active mark file. The drills wait before restarting.
- Inside a container the `aeronmd` pid is always the same, so driver identity is the `cnc.dat` mtime plus the container start time.

## Nightly

`nightly.py --plan nightly-cut.json --evidence-root DIR --harness-commit SHA --tools-repo DIR --ct-repo DIR` runs a fixed plan of `{kind, scenario}` entries from a `git archive` of the pinned tools commit (a modified or extra file refuses the night). It takes a heavy-job lock without waiting (a held lock or foreign load ends the night `SKIPPED_BUSY`, exit 75), records stale earlier nights as `INTERRUPTED`, enforces `NIGHTLY_BOUND_S` (default 5 h) and writes `SHA256SUMS` last. Nothing is pushed or published.

Paths are settings, never machine defaults. A night reads them from the environment, and an entry whose path is unset ends `INCONCLUSIVE` with a message naming the variable:

| Variable | Used by | What it points at |
|---|---|---|
| `NIGHTLY_LOCK`, `NIGHTLY_CUT`, `NIGHTLY_CT_REPO` | `nightly.py` | heavy-job lock file, release cut manifest, cluster-tools checkout (falls back to `CUT_CT_REPO`) |
| `CUT_TOOLS_REPO`, `CUT_CT_REPO`, `CUT_OLD_PINS` | `release_cut.py` | tools and cluster-tools checkouts, previous pin set |
| `MK_RUNS`, `MK_BIN_A`, `MK_BUILD_B`, `MK_NC_DIR`, `MK_CUT_NC_DIR`, `MK_DRIVER_PROPERTIES`, `MK_AE_JAR`, `MK_ME_JAR`, `MK_PROJECTOR_JAR`, `MK_PROBE_MANIFEST`, `MK_NETFILTER_HELPER` | `mk_manifests.py` | run directory, C++ binaries and build trees, negative-control builds, external driver properties, engine and probe artifacts |
| `LEGACY_TEMPLATE`, `LEGACY_JARS` | `legacy_tag.py` | v0.5.0-beta manifest template and jars |
| `XVER_LEGACY_RUNS`, `XVER_SEEDS`, `XVER_CUT` | `xver.py` | cross-version run inputs |

Each module's docstring lists the exact meaning of its variables.

It runs from a local systemd user timer, not CI. `systemd/` holds the service, the timeout drop-in and the timer (daily at 03:17); install steps and the environment to edit are in the comments of `systemd/runtime-e2e-nightly.service`.
