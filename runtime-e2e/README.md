# runtime-e2e

Isolated runtime acceptance harness. It runs already-built, sha256-pinned artifacts in a private Docker network, drives them with Java probes, injects faults, and judges the resulting money and order state with oracles. It never builds or changes engine jars.

The single-host fixture proves process behaviour only. It cannot establish host-failure tolerance.

## Topologies

The manifest's `schema_version` selects the topology. `core-*` scenarios need a version 2 manifest and only they accept one.

- Core topology (`schema_version: 2`, `topology: core`, validated by `core_contracts.py`): the v1 layout. Roles are exactly `me0-2` (matching engine), `ae0-2` (order and ledger core), `fwd0`, `fwd1` (C++ ME forwarders), `bridge0`, `bridge1` (C++ settlement bridges), `projector`, `shadow0` (the shadow replica on the replica kinds, reserved on every other manifest) and `probe`. The v0.5 roles `oms`, `market`, `bridge` and `xprojector` are refused. PostgreSQL carries only the money-journal history projection.
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

# probes for the core topology (CoreProbe against the core jar, JournalProbe against the ME jar)
python3 runtime-e2e/build_core_probes.py --core-jar /abs/core-cluster.jar --me-jar /abs/match-cluster.jar \
  [--ct-dir /abs/cluster-tools] --output /abs/new-probe-dir

# one scenario
runtime-e2e/run.sh --manifest /abs/manifest.json --scenario core-smoke --output /abs/new-evidence-dir
```

Copy the program entries from the probe directory's `probe-manifest.json` into the fixture manifest.

Helper tools (each prints its own usage):

- `mk_manifests.py <kind> <tag>`: builds a core manifest of a named kind; every manifest of one kind differs only in `run_id` and `state_root`.
- `release_cut.py check | audit | precheck | activation-record | genesis-ids | record-builds`: checks a release cut manifest and derived fixture manifests against the artifact rules (pinned sha256, clean source commit, no test builds in product kinds, matching schema identities), audits a live state root, and writes activation records. Cut manifests are `rc2-cut/2` (repo key `core`); `rc2-cut/1` (repo key `assets`) is still read as written.
- `oracle_samples.py <new dir>`: writes clean synthetic oracle samples.
- `nightly.py`: the nightly runner (see below).

## Scenarios

Unknown scenario names fail closed.

Core topology:

- `core-boot`: genesis, authentication refusals and a core authority refusal.
- `core-smoke`: funding at genesis, gate open, creates reach dispatch.
- `core-boots-N`: N fresh boots (1 to 20).
- `core-drill-<name>`: fault drills such as `lostack`, `coreleader`, `meleader`, `fwdrestart`, `partition`, `fwdpause`, `driverkill`, `lifecycle`, `lifecycle-faults`. `core-control-<name>` are non-vacuity controls and `core-red-<name>` run known-bad builds that must fail. The full list is the `DRILLS`, `CONTROLS` and `REDS` tables in `core_drills.py`.
- `core-drill-<name>` on the replica kinds: the shadow replica and peer-loss drills (see "Shadow replica" below).
- `core-xver-*`, `core-act-*`, `core-rollback-*`: cross-version, activation and rollback cases against v0.5.0-beta state (`xver.py`, `legacy_tag.py`; the case table is in the `xver.py` docstring).

v0.5 topology: `critical-path-smoke`, `harness-negative-controls`, `false-ready`, `false-ready-ae`, `pruner-exception`, `offline-purge-rejoin`, `baseline-fault-reproduction`, `readiness-me`, `readiness-ae`, `readiness-lag-election-idle`, `log-channel-me`, `log-channel-ae`, `journal-oms-restart`, `oms-recovery-admission`, `oms-durable-request-id`, `execution-projector-replay-crash`, `oms-hold-release-authority`, `benchmark-preflight`, `benchmark-normal`, `benchmark-n-minus-one`. Fault scenarios need the pinned `java/FixtureProbe.java` helper and benchmark scenarios the pinned `java/BenchmarkProbe.java`, recorded in the manifest's `test_helper` and `benchmark_helper`.

## Run rules

- Every run needs a new run id and a fresh state root at exactly `<manifest dir>/fixtures/<run id>`. The output directory must not exist. State and evidence are never reset or reused; keep a copy of each manifest.
- Images are addressed by `sha256`, never by tag. Repeats change only the run id and state path.
- Core manifests require `timeouts: production`. Environment names are allowlisted per process (`PROCESS_ENV`) and per image (`IMAGE_ENV`); no value may carry a `-D...timeout` style override. The only exempt names are `FWD_DRIVER_TIMEOUT_MS=5000` and `BRIDGE_DRIVER_TIMEOUT_MS=5000`. Every engine member gets its own disjoint cpuset; the network is `--internal`.
- Credentials are minted per run (`credentials.py`): the core gets `CORE_AUTH_KEYS`, each client `CORE_AUTH_CREDENTIAL`. Secrets are redacted from every retained command line, output, log and probe state file before teardown.
- Teardown removes only Docker objects carrying both the run label and the run's ownership token, and only the owned PostgreSQL process. After an uncatchable signal, finish cleanup with `Fixture(manifest, attach=True).close()` (or `CoreFixture`). Never prune Docker or reset a database by hand.
- Keep manifests and state roots in a run directory outside every repository: `state_root` lives under the manifest directory and holds staged binaries.

## Results and oracles

Results are `PASS`, `FAIL` or `INCONCLUSIVE`; only `PASS` exits zero. All subprocess exits and outputs are retained, and the runner copies the harness sources into the evidence directory with their hashes.

- v0.5 money oracle: integer units (1e-8), fixed-price LIMIT orders, no fees or amendments, two equal observations after input closes. Missing genesis, pending state or an unmodelled movement is INCONCLUSIVE.
- Core oracles: `core_oracle.py` (money rules M1 to M14) and `order_oracle.py` (order rules O1 to O12) judge one `core-sample-v2` document (format in `oracle_model.py`), FAIL over INCONCLUSIVE over PASS.
- The journal is decoded in Python from the pinned schema XML in `schemas/` (`journal_decode.py`, profiles and hashes in `schemas/journal-profiles.json`). Unknown records stop the decode.
- Smoke request timings include orchestration and are not performance measurements. A benchmark baseline needs all declared repeats; one repeat is not enough.

Known limits:

- The order tap loses order events across a core leader change. Drills close the gap by backfill from the pending dump and the ME journal; a gap that cannot be closed is INCONCLUSIVE (`tap_loss`), never FAIL.
- Restarting a core member shortly after a kill can hang the JVM on an active mark file. The drills wait before restarting.
- Inside a container the `aeronmd` pid is always the same, so driver identity is the `cnc.dat` mtime plus the container start time.

## Shadow replica

The replica kinds fill the `shadow0` role with the core jar as `CORE_ROLE=replica` (one artifact: `artifacts.shadow` must be byte-equal to `artifacts.ae`) and run the AE members in `SNAPSHOT_MODE=shadow`. The role names keep the `ae*` spelling of the fixture; the processes are the core.

- The replica launches through the engines' launch shape, never the C++ slot wrapper: `java -jar` embedded, the engines' staged `aeronmd` wrapper (`engine_libs`, `AERON_DIR=/dev/shm/aeron-shadow0`) external. Its driver mode is the engines' (`engine_driver`).
- Replica env (`core_fixture.replica_env`): `CLUSTER_REPLICA_SLOT=3`, `CLUSTER_REPLICA_ADDRESS`, `REPLICA_BACKUP_SOURCE=FOLLOWER`, `CORE_NODE_PORT` = the profile's `shadow_metrics` (19703), `SHADOW_PULL_SOURCES` = the three members' archive control endpoints spelled as `CLUSTER_ADDRESSES` spells them, `REPLICA_CATCHUP_RCV_WND=512k`, `REPLICA_SHADOW_BUFFER_MB=64`, `SHADOW_RETAIN_N=3`, the fixture's `TRANSPORT_LOG_TERM_LENGTH`, `ARCHIVE_SEGMENT_LENGTH=1m` and the replica's own `REPLICA` key (minted only for a manifest that runs the replica). Readiness is `/ready` on 19703.
- Member shadow block (`engine_env`, AE members only): `SNAPSHOT_MODE=shadow`, `SHADOW_PULL_SOURCES` = the replica then the two peers, `SHADOW_PRODUCER_BUFFER_MB=64`, `SNAPSHOT_INTERVAL_MINUTES=1`, `SHADOW_WITNESS_ALARM_MS=120000`, `ARCHIVE_SEGMENT_LENGTH=1m`. No `TRANSPORT_LOG_RCV_WINDOW`: the member derives its window from the term and logs it at boot.
- Archive segments: the replica and full kinds set the core's `ARCHIVE_SEGMENT_LENGTH=1m` on the members and the replica, so a 120 s story (about 22 MB of log) purges whole 1 MiB segments and the drills that need a log starting above 0 (peer loss loud and its companion, replica wipe, re-bootstrap) reach their precondition. Only the followers purge: the leader never pulls a shadow, holds no floor witness and keeps its log, so replica wipe and re-bootstrap wait on the followers' log starts (the replica's backup sources with `REPLICA_BACKUP_SOURCE=FOLLOWER`) and record the leader's. The core never read `fixture.JAVA`'s `-Daeron.archive.segment.file.length` (it sets the length explicitly; the flag stays for older artifacts); the older kinds keep the core's 64 MiB default they were measured on. `archive_listing` takes the segment length of the log recording from the member's `archive.catalog` descriptor, never from a constant.
- Kinds (all derived from the cut, `mk_manifests.py <kind> <tag> --cut <cut>`): `shadow` (slots external, engines and replica embedded), `shadow-ext` (engines and replica on the staged aeronmd), `shadow-anyverified` (members `SHADOW_ANCHOR_RULE=any-verified`) and `shadow-anyverified-ext`, `shadow-cooldown30` (`REPLICA_BACKUP_COOLDOWN_MS=30000`), `shadow-detectoronly` (`SHADOW_REBOOTSTRAP_REPLAY_FAILURES=0`, members any-verified), `shadow-query` (`REPLICA_BACKUP_QUERY_INTERVAL_MS=13000`) and `shadow-query-ext`, and `full` (no replica, `SNAPSHOT_MODE` unset, the same 1-minute cadence). The env a kind adds is the `REPLICA_KINDS` table in `core_contracts.py`; a control's setting lives in its kind because env lives in manifests.
- Drills (`replica_drills.py`): `core-drill-member-kill9`, `-peerloss`, `-peerloss-loud`, `-shadow-catalog`, `-supplierloss`, `-leaderloss-promotion`, `-replica-restart`, `-replica-wipe`, `-replica-rebootstrap`; controls `core-control-kill9-fullmode` (`full`), `-peerloss-loud-unblocked`, `-supplierloss-cooldown30`, `-rebootstrap-detectoronly`, `-rebootstrap-nowitness`. Every drill runs in both driver modes: on `shadow` and `shadow-ext`, except the shadow catalog and leader loss on `shadow-query` and `shadow-query-ext` (13 s backup query) and re-bootstrap on `shadow-anyverified` and `shadow-anyverified-ext` (the members must purge below the stopped replica); a control runs in one mode on its own kind. A control passes when both oracles pass, its named line fails with its text and the lines it keeps hold.
- Supplier loss passes when, within `SUPPLIER_LOSS_RECOVERY_BOUND_S` of the kill, `shadow_replica_backup_state` read RESET_BACKUP or BACKUP_QUERY (the backup left BACKING_UP), a new supplier is named and the applied position passed the leader's `core_log_position` at the kill. The bound defaults to 30 s: the recovery is the supplier's liveness timeout (about 3 s), the backup's 12 s cool-down, one backup query and the catch-up of what was written meanwhile, measured at 16 to 28 s (a 20 s bound failed one run in four). `shadow_replica_backup_resets_total` and `shadow_replica_reader_reattach_total` are recorded, not required: on Aeron 1.53.1 a supplier stop moves neither (the resets count possible-failure events only, and the backup extends the same local log recording).
- Leader loss, state (i) (the supplier won the election): re-validated within two backup query intervals (the backup state left BACKING_UP, or it already named another supplier), then a follower supplier and the applied position past the leader's log position at the kill within the query interval plus the cool-down. Whether `shadow_replica_supplier_is_leader` ever read 1 is recorded: with the FOLLOWER source the next response already names a follower. The lag of an attempt is held to the term unless the backup went through RESET_BACKUP in it.
- The shadow catalog bound is `CATALOG_ALIGNED_BOUND_S` plus the kind's `REPLICA_BACKUP_QUERY_INTERVAL_MS` (18 s on the query kinds, observed to `OBSERVE_FACTOR` x the bound): the replica learns of a member snapshot only at its next backup query and holds the ALIGNED until it has retrieved it.
- The detector-only control (`SHADOW_REBOOTSTRAP_REPLAY_FAILURES=0`) passes when the replica counted at least 3 replay-below-start refusals and was still running `MISSED_OBSERVE_S` later (re-bootstrap missed); the kit never reports this setting as "not taken" (its `/ready` reads 503 unverified continuation).
- Peer loss (and its loud variant) kill the replica and both followers, so the cluster loses its quorum and the tap's session closes until quorum returns. The core keeps no egress history, so what it emitted meanwhile cannot be tapped late. The drill declares that window untappable (`declared.untappable`: the tap's dispatch and order-event gaps that start at a `session_closed` inside the recorded quorum-loss interval and end at a `reconnected`): the barrier backfill still rebuilds what it can, a dispatch shortfall inside the window and an order whose terminal falls in it are recorded with the verdict (`untappable`, O-F5 `untappable`), not judged. An ME outcome without a dispatch is still judged. Leader loss (the promotion drill) records each election window, from the leader kill to the new leader serving, and declares a gap the same way when it starts at a `session_closed` inside one and ends at a `reconnected`; a session that survived the election (`new_leader`) declares nothing. The drill verdict carries `untappable` with the reason, the orders recorded unjudged and their count; the money oracle is unchanged. Peer loss loud keeps the leader as the survivor and blocks its archive port; its unblocked companion's survivor is the other follower, which holds pulled copies (a leader neither pulls nor produces, so it has nothing to serve), and the leader is killed instead.
- Observation ends when the drill's last assertion is decided: after its fault steps, the story and the pre-barrier, the tap runs `TAP_SETTLE_S` (30 s) more and is stopped through its stop file (`CoreProbe tap stop=`, `core_fixture.stop_tap`). The tap's duration stays the summed worst-case bounds, so a step that waits to its bound only moves the stop later, and a tap that cannot stop early still ends there. `replica.json` records `tap_end` (decided, stopped, ended by `stop` or `duration`, seconds saved).
- Every bound and wait is a setting (`replica_drills.SETTINGS_SPEC`, overridden by an environment variable of the same name, range-checked) and is recorded with the run. A drill that cannot establish its precondition (a member snapshot, the pulls before a kill, a log that no longer starts at 0, a follower supplier) ends `INCONCLUSIVE` naming it. Every member a drill kills is restarted before the barrier, with `waited_after_kill_s` recorded; a replica restarted after a kill or an exit waits `SHADOW_RESTART_MIN_AFTER_KILL_S` (12.5 s) for its archive mark file, as an AE member does.
- Lag: `lag_sampler.py` runs once per drill inside the probe container (one process, never a process per sample) and writes `lag.tsv` and `summary.json`: `lag_bytes = core_log_position(leader) - shadow_replica_applied_position(replica)`, the leader's applied position (at most one duty cycle behind commit), with the replica's recorded-minus-applied alongside and the achieved sample rate. Time values here are functional guards of the fixture profile, never rate evidence.
- Faults go through the fixture's primitives only: `kill`, `pause`, `stop`, `restart` (`wait_ready=False` when the exit is the drill's to observe), `wipe_engine` (its replica branch needs no projection dump), `wipe_shadows` (an AE member's shadow recordings: the archive files its `recording.log` does not name) and the netfilter helper by port kind (`log_channel_fault.filter_arguments(..., port_kind='log'|'archive')`; an archive rule leaves loopback alone). The log start of a member is read from its archive listing on the host (`core_fixture.archive_listing`).

## Nightly

`nightly.py --plan nightly-cut.json --evidence-root DIR --harness-commit SHA --tools-repo DIR --ct-repo DIR` runs a fixed plan of `{kind, scenario}` entries from a `git archive` of the pinned tools commit (a modified or extra file refuses the night). It takes a heavy-job lock without waiting (a held lock or foreign load ends the night `SKIPPED_BUSY`, exit 75), records stale earlier nights as `INTERRUPTED`, enforces `NIGHTLY_BOUND_S` (default 5 h) and writes `SHA256SUMS` last. Nothing is pushed or published.

Paths are settings, never machine defaults. A night reads them from the environment, and an entry whose path is unset ends `INCONCLUSIVE` with a message naming the variable:

| Variable | Used by | What it points at |
|---|---|---|
| `NIGHTLY_LOCK`, `NIGHTLY_CUT`, `NIGHTLY_CT_REPO` | `nightly.py` | heavy-job lock file, release cut manifest, cluster-tools checkout (falls back to `CUT_CT_REPO`) |
| `CUT_TOOLS_REPO`, `CUT_CT_REPO`, `CUT_OLD_PINS` | `release_cut.py` | tools and cluster-tools checkouts, previous pin set |
| `MK_RUNS`, `MK_BIN_A`, `MK_BUILD_B`, `MK_NC_DIR`, `MK_CUT_NC_DIR`, `MK_DRIVER_PROPERTIES`, `MK_AE_JAR`, `MK_ME_JAR`, `MK_PROJECTOR_JAR`, `MK_PROBE_MANIFEST`, `MK_NETFILTER_HELPER` | `mk_manifests.py` | run directory, C++ binaries and build trees, negative-control builds, external driver properties, engine and probe artifacts |
| `CORE_PROBE_CORE_JAR` | `test_story.py` | the core jar the story tests compile and run against (unset: they skip) |
| `LEGACY_TEMPLATE`, `LEGACY_JARS` | `legacy_tag.py` | v0.5.0-beta manifest template and jars |
| `XVER_LEGACY_RUNS`, `XVER_SEEDS`, `XVER_CUT` | `xver.py` | cross-version run inputs |

Each module's docstring lists the exact meaning of its variables.

Two plan sets on alternating nights: `nightly.py --alternate nightly-cut-embedded.json nightly-cut-external.json ...` runs the embedded set on an even UTC day of the year and the external set on an odd one, so both driver modes run every 48 h while each night stays under the bound. The sets are balanced by measured walls: the embedded set is the default plan followed by five replica drills with the engines and replica embedded (peer loss loud, supplier loss, replica restart, replica wipe, re-bootstrap); the external set is the nine replica drills on the external kinds, the other four embedded replica drills (member kill -9, peer loss, the shadow catalog and leader loss) and the five controls (one mode each). Every drill runs in both modes every 48 h. `NIGHTLY_PLAN_SET=embedded|external` forces a set (a measured run of one set). The chosen set, the parity and whether it was forced are in the night's `summary.json` (`plan_set`). Both files must be the plans at the pinned commit.

Tools has no CI workflow: run the unit tests (`python3 -m unittest discover -s runtime-e2e -p 'test_*.py'`) locally before pinning a harness commit for the nightly.

It runs from a local systemd user timer, not CI. `systemd/` holds the service, the timeout drop-in and the timer (daily at 03:17); install steps and the environment to edit are in the comments of `systemd/runtime-e2e-nightly.service`.
