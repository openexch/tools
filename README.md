# Open Exchange tools

Probe, simulation and test tooling for Open Exchange. Nothing here runs on the money path: these tools drive, observe or check the engines from the outside.

Status: nightly prerelease (v1.0.0-nightly.20261105). Not for production.

User documentation (architecture, configuration, operations): https://openexchange.dev/docs

## Where this fits

Open Exchange v1 is five repositories:

| Repo | Role |
|---|---|
| `match` | Matching engine, Aeron Raft cluster (Java) |
| `assets` | Order and ledger core: order lifecycle, risk, holds and ledger in one Aeron cluster (Java) |
| `cluster-kit` | Shared cluster machinery for both engines (Java) |
| `cluster-tools` | Cluster client, ME forwarder, settlement bridge, projectors (C++) |
| `tools` | This repo |

The previous v0.5 stack (`oms`, `admin-gateway`, `trading-ui`) still runs the demo. Some tools below target that stack; the table says which.

## Contents

| Directory | What it is | Target | Language |
|---|---|---|---|
| [`runtime-e2e/`](runtime-e2e/README.md) | Isolated Docker acceptance harness: runs pinned, already-built artifacts, injects faults, judges money and order state with oracles | v1 core topology and the v0.5 topology | Python, Java probes |
| [`market-sim/`](market-sim/README.md) | Agent-based market simulator and demo canary with a health endpoint | v0.5 OMS REST API | Go |
| [`money-check/`](money-check/README.md) | Read-only money invariant checker (conservation, locked equals open holds, non-negativity) | v0.5 Redis ledger or the Assets Engine via `AeDump` | Python |
| `tb-bench/` | TigerBeetle two-phase benchmark driver kept from the ledger evaluation | a TigerBeetle cluster | Java |

## Build and test

```bash
# Go tools (market-sim needs Go 1.23+, see each go.mod)
(cd market-sim && go build -o market-sim . && go test ./...)

# Python tools: standard library only
python3 -m unittest discover -s runtime-e2e -p 'test_*.py'
(cd money-check && python3 -m unittest test_money_check)

# TigerBeetle bench (Java 21, Maven); the client is pinned to TigerBeetle 0.17.9 in pom.xml
mvn -f tb-bench/pom.xml package
java -jar tb-bench/target/tb-bench.jar help
```

The `runtime-e2e` unit tests need no Docker; running scenarios does. See [runtime-e2e/README.md](runtime-e2e/README.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
