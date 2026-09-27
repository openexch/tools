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

Other scenario names fail closed. Fault reproduction and performance acceptance are not complete.
The single-host fixture proves process behavior only; it cannot establish host failure tolerance.

Requirements: Python 3, Docker, PostgreSQL 16 tools with TimescaleDB installed, a fixed local Linux
image digest containing Java 21 and Python 3, and the six frozen jars. An explicit manifest supplies
artifact hashes/source commits, RFC1918 internal /24 network, endpoints, resource bounds, CPU set,
seed, toolchains and predeclared quality budgets. The current frozen market gateway requires ME
base port 9000 and stride 100; the fixture validates this declared port profile before startup.

```bash
python3 -m unittest discover -s tools/runtime-e2e -p 'test_*.py' -v
tools/runtime-e2e/run.sh --manifest /absolute/path/manifest.json \
  --scenario critical-path-smoke --output /absolute/path/new-evidence-directory
```

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
