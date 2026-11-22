# obs-sampler

The read-only observation sampler of one Open Exchange host. It runs once per host and reads only that host: each local
service's `/metrics`, `/health` and `/ready` over HTTP, the supervisor's state, pid and start time per service, the pid's
CPU time and thread states from `/proc`, the use of each volume, the allocated bytes of each configured directory,
`/dev/shm` and its entries, and PostgreSQL sizes and progress values over a connection. Every `OBS_SAMPLE_S` it appends
one JSON line to its sample file. It writes nothing else and sends nothing anywhere.

A read that fails is written as a line with its error, never left out: the verdict must tell "the process did not answer"
from "no sample was taken". The verdict (`runtime-e2e/observation.py`, scenario `demo-observation-24h`) runs offline on a
copy of the sample files.

Go, standard library only, a static binary: `CGO_ENABLED=0`.

## Build and run

```bash
go build -o obs-sampler .
go test ./...
./obs-sampler --version                    # obs-sampler source <commit> (unknown for a plain build)
OBS_SAMPLER_CONFIG=/etc/obs/host.json ./obs-sampler
./obs-sampler liveness /var/lib/obs/samples-box.jsonl   # size and age of the last line
./obs-sampler verify /var/lib/obs/samples-box.jsonl     # the hash chain
```

The release binary is the linux/arm64 cross-build of `runtime-e2e/arm64_sibling.py go-build` (two reproducible builds from
`git archive <commit>`, the commit linked in as `main.sourceSha`).

## Settings

| Key | Default | Meaning |
|---|---|---|
| `OBS_SAMPLER_CONFIG` | none (required) | the host's configuration file; with it unset the sampler exits 78 naming it |
| `OBS_SAMPLE_S` | 60 | seconds between samples |
| `OBS_HTTP_TIMEOUT_MS` | 2000 | bound of one HTTP read |
| `OBS_PSQL_TIMEOUT_S` | 10 | bound of one PostgreSQL query |
| `OBS_MAX_SAMPLES` | 0 | stop after this many samples (0: until SIGTERM) |
| `OBS_MAX_GAP_S` | 180 | `liveness`: a last line older than this is reported (exit 1) |

A refused configuration exits 78 with the key's name; usage errors exit 64.

## Configuration file

```json
{"host": "box", "out": "/var/lib/obs/samples-box.jsonl", "supervisor": "systemd",
 "services": [{"name": "core/0", "kind": "core member", "unit": "oe-core@0",
               "metrics": "http://127.0.0.1:19700/metrics", "health": "http://127.0.0.1:19700/health",
               "ready": "http://127.0.0.1:19700/ready"}],
 "volumes": ["/"], "shm": ["/dev/shm"],
 "dirs": [{"name": "core/0 state", "path": "/var/lib/oe/core0", "model": "core_log", "service": "core/0"},
          {"name": "money history", "model": "money_db", "db": "oe_money", "rows": "money_rows", "size": "money_size"}],
 "pg": {"command": ["sudo", "-n", "-u", "postgres", "psql"], "databases": ["oe_money"], "wal_from": "postgres",
        "queries": [{"name": "money_rows", "db": "oe_money", "sql": "SELECT count(*) FROM money_journal"},
                    {"name": "money_size", "db": "oe_money", "sql": "SELECT pg_total_relation_size('money_journal')"}]}}
```

`supervisor` is `systemd` (each service names its `unit`), `docker` (`container`) or `pidfile` (`pidfile`). A service's
`kind` selects its row of the verdict's progress table (`observation.KINDS`). A directory's `model` is the verdict's disk
model (`observation.DISK_MODELS`); a directory without `path` is not walked (a database or the WAL, measured over
PostgreSQL). A password never goes in this file: psql reads it from its environment or a pgpass file. Unknown keys are
refused.

## Sample file

JSON lines: a `start` line (the whole configuration, its sha256, the settings, the clock tick rate), one `sample` line
per sample, a `stop` line. Every line carries `prev`, the hash of the line before it (64 zeros on the first line), and
ends with `,"hash":"<hex>"}`, the SHA-256 of the line without that last member. A changed, dropped or inserted line
breaks the chain; a restarted sampler continues the chain of the file it finds and refuses a file whose last line does
not verify.
