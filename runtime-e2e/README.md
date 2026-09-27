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
