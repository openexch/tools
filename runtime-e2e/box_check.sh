#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The read-only box survey before a cutover and the arm64 self-check of the new binaries. Runs on the box with bash and
# coreutils only (the box has no Python guarantee). Changes nothing: it reads, and the self-check starts each binary
# twice, once to print its version and once with an empty environment, which every one of them must refuse before it
# binds, connects or writes anything.
#
# usage: box_check.sh selfcheck <scratch dir> <expect file>
#        box_check.sh survey
#
# selfcheck  <scratch dir> holds the binaries fetched for the check (nothing else runs from it); <expect file> is the
#            output of `arm64_sibling.py expect`: one `<name> <sha256> <source sha>` line per binary, from the accepted
#            arm64 sibling of the cut. Per binary:
#              1. the file's sha256 equals the expected one          else `sha256 differs from the sibling manifest: <name>`
#              2. it is an arm64 ELF (e_machine 183)                 else `not an arm64 ELF: <name>`
#              3. `<name> --version` prints `source <sha>`, the cut's  else `source sha differs from the cut: <name>`
#              4. with an empty environment it exits 78               else `bad config not refused with 78: <name>`
#              5. and the refusal names the expected key              else `refusal does not name <key>: <name>`
#            Prints one OK or FAIL line per binary (a FAIL line is the exact text; an indented detail line may
#            follow), then `SELFCHECK PASS` (exit 0) or `SELFCHECK FAIL` (exit 1).
#            BOX_ELF_MACHINE (default 183, EM_AARCH64) is the e_machine step 2 requires; `none` skips step 2, for the
#            unit test's stub binaries only.
# survey     the reads before the cutover, on stdout (the operator keeps it as the survey file): service list, disk size and use, RAM, PG
#            databases with sizes, login roles, tables with sizes, the PG WAL settings, the admin unit's KillMode, the
#            Python version, net.core.rmem_max and wmem_max, what listens on 8081, the v0.5 state directories, and the
#            headroom for the legacy dump and the tmpfs copy, computed from the measured sizes.
#            Env: BOX_ADMIN_UNIT (required: the console's systemd unit), BOX_PSQL (default `sudo -n -u postgres psql`),
#                 BOX_DUMP_DIR (default $HOME: where the legacy dump and the tmpfs copy are written),
#                 BOX_JOURNAL_GLOB (default $HOME/openexchange/journal/node*).
#
# Exit codes: 0 pass, 1 a check failed, 64 usage.
set -uo pipefail

# The key each binary's refusal of an empty environment must name (the first required setting of each).
expected_key() {
    case "$1" in
        oe-gateway) echo GATEWAY_DRIVER_MODE ;;
        oe-stream) echo STREAM_DRIVER_MODE ;;
        oe-projector) echo HISTORY_PROJECTOR_DRIVER_MODE ;;
        oe-marketdata) echo MD_DRIVER_MODE ;;
        market-sim) echo SIM_STREAM_URL ;;
        obs-sampler) echo OBS_SAMPLER_CONFIG ;;
        *) return 1 ;;
    esac
}

usage() {
    sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
    exit 64
}

selfcheck() {
    local dir=$1 expect=$2 machine=${BOX_ELF_MACHINE:-183}
    [ -d "$dir" ] || { echo "no scratch directory: $dir" >&2; exit 64; }
    [ -f "$expect" ] || { echo "no expect file: $expect" >&2; exit 64; }
    local failed=0 checked=0 name sha source rest
    while read -r name sha source rest; do
        case "$name" in ''|'#'*) continue ;; esac
        if [ -z "$sha" ] || [ -z "$source" ] || [ -n "$rest" ]; then
            echo "FAIL malformed expect line: $name $sha $source $rest"; failed=1; continue
        fi
        checked=$((checked + 1))
        local bin="$dir/$name" why="" key out rc got_source got_machine
        if ! key=$(expected_key "$name"); then
            echo "FAIL $name: no refusal key known for this binary"; failed=1; continue
        fi
        if [ ! -f "$bin" ]; then
            echo "FAIL missing from the scratch directory: $name"; failed=1; continue
        fi
        if [ "$(sha256sum "$bin" | cut -d' ' -f1)" != "$sha" ]; then
            echo "FAIL sha256 differs from the sibling manifest: $name"; failed=1; continue
        fi
        if [ "$machine" != none ]; then
            got_machine=$(od -An -tu2 -j18 -N2 "$bin" 2>/dev/null | tr -d ' ')
            if [ "$(head -c4 "$bin" | od -An -tx1 | tr -d ' ')" != 7f454c46 ] || [ "$got_machine" != "$machine" ]; then
                echo "FAIL not an arm64 ELF: $name"; echo "  e_machine ${got_machine:-none}, required $machine"
                failed=1; continue
            fi
        fi
        [ -x "$bin" ] || { echo "FAIL not executable: $name"; failed=1; continue; }
        out=$(cd "$dir" && env -i timeout 10 "./$name" --version 2>&1); rc=$?
        got_source=$(printf '%s\n' "$out" | sed -n 's/.* source \([0-9a-f]\{40\}\).*/\1/p' | head -n1)
        if [ "$rc" -ne 0 ] || [ "$got_source" != "$source" ]; then
            echo "FAIL source sha differs from the cut: $name"
            echo "  reported ${got_source:-nothing} (exit $rc), the cut names $source"
            failed=1; continue
        fi
        out=$(cd "$dir" && env -i timeout 10 "./$name" 2>&1); rc=$?
        if [ "$rc" -ne 78 ]; then
            echo "FAIL bad config not refused with 78: $name"; echo "  exit $rc"; failed=1; continue
        fi
        if ! printf '%s\n' "$out" | grep -qF "$key"; then
            echo "FAIL refusal does not name $key: $name"; failed=1; continue
        fi
        echo "OK $name sha256 $sha source $got_source; empty environment refused with 78 naming $key"
    done < "$expect"
    if [ "$checked" -eq 0 ]; then
        echo "FAIL the expect file lists no binary"; failed=1
    fi
    if [ "$failed" -ne 0 ]; then echo "SELFCHECK FAIL"; return 1; fi
    echo "SELFCHECK PASS ($checked binaries)"
}

section() { printf '\n== %s\n' "$*"; }

# A read that may fail (a missing tool, a permission) prints its error in the survey; it never stops the survey.
read_cmd() { "$@" 2>&1 || echo "(exit $?: $*)"; }

psql_q() { # <database> <query>: tab-separated rows
    # shellcheck disable=SC2086 # BOX_PSQL is a command line
    ${BOX_PSQL:-sudo -n -u postgres psql} -X -q -A -t -F $'\t' -v ON_ERROR_STOP=1 -d "$1" -c "$2"
}

bytes_of() { du -sb "$@" 2>/dev/null | awk '{s += $1} END {print s + 0}'; }

survey() {
    [ -n "${BOX_ADMIN_UNIT:-}" ] || { echo "BOX_ADMIN_UNIT is required: the console's systemd unit name" >&2; exit 64; }
    local dump_dir=${BOX_DUMP_DIR:-$HOME} journal_glob=${BOX_JOURNAL_GLOB:-$HOME/openexchange/journal/node*}
    echo "b1 survey $(date -u +%Y-%m-%dT%H:%M:%SZ) host $(hostname) arch $(uname -m) kernel $(uname -r)"
    section services; read_cmd systemctl list-units --type=service --all --no-pager --no-legend
    section disk; read_cmd df -B1 --output=source,fstype,size,used,avail,target
    section memory; read_cmd free -b
    section cpu; echo "nproc $(nproc)"
    section "pg databases (bytes)"; read_cmd psql_q postgres "SELECT datname, pg_database_size(datname) FROM pg_database WHERE NOT datistemplate ORDER BY 1"
    section "pg roles (name, can login)"; read_cmd psql_q postgres "SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname NOT LIKE 'pg\_%' ORDER BY 1"
    section "pg names"
    local db
    for db in marketdata; do
        [ "$(psql_q postgres "SELECT count(*) FROM pg_database WHERE datname = '$db'" 2>/dev/null)" = 1 ] \
            && echo "legacy database present: $db" || echo "legacy database ABSENT: $db"
    done
    [ "$(psql_q postgres "SELECT count(*) FROM pg_roles WHERE rolname = 'market'" 2>/dev/null)" = 1 ] \
        && echo "legacy role present: market" || echo "legacy role ABSENT: market"
    [ "$(psql_q postgres "SELECT count(*) FROM pg_database WHERE datname = 'oe_marketdata'" 2>/dev/null)" = 0 ] \
        && echo "name free: database oe_marketdata" || echo "NAME TAKEN OR UNREAD: database oe_marketdata"
    [ "$(psql_q postgres "SELECT count(*) FROM pg_roles WHERE rolname = 'oe_marketdata_writer'" 2>/dev/null)" = 0 ] \
        && echo "name free: role oe_marketdata_writer" || echo "NAME TAKEN OR UNREAD: role oe_marketdata_writer"
    section "pg tables (database, schema, table, bytes, live rows)"
    for db in $(psql_q postgres "SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY 1" 2>/dev/null); do
        psql_q "$db" "SELECT current_database(), schemaname, relname, pg_total_relation_size(relid), n_live_tup FROM pg_stat_user_tables ORDER BY 2, 3" 2>&1 \
            || echo "(unread: $db)"
    done
    section "pg wal settings"; read_cmd psql_q postgres "SELECT name, setting, coalesce(unit, '') FROM pg_settings WHERE name IN ('wal_level', 'max_wal_size', 'min_wal_size', 'wal_keep_size', 'max_slot_wal_keep_size', 'archive_mode', 'checkpoint_timeout') ORDER BY 1"
    section "admin unit $BOX_ADMIN_UNIT"; read_cmd systemctl show -p KillMode -p ActiveState -p MainPID -p FragmentPath -p DropInPaths "$BOX_ADMIN_UNIT"
    section python; if command -v python3 >/dev/null; then python3 --version 2>&1; else echo "python3 absent"; fi
    section sysctl; read_cmd sysctl net.core.rmem_max net.core.wmem_max
    section "listening on 8081"; read_cmd ss -ltnpH 'sport = :8081'
    section "v0.5 state directories (bytes)"
    local d
    for d in /dev/shm/aeron-cluster /dev/shm/aeron-assets $journal_glob; do
        [ -e "$d" ] && echo "$d $(bytes_of "$d")" || echo "$d absent"
    done
    section "/dev/shm"; read_cmd ls -la /dev/shm
    section headroom
    local avail pg_dump_upper tmpfs_copy
    avail=$(df -B1 --output=avail "$dump_dir" 2>/dev/null | tail -n1 | tr -d ' ')
    # the on-disk size of the two legacy databases bounds a `pg_dump -Fc` of them from above
    pg_dump_upper=$(psql_q postgres "SELECT coalesce(sum(pg_database_size(datname)), 0) FROM pg_database WHERE datname IN ('oms', 'marketdata')" 2>/dev/null)
    tmpfs_copy=$(bytes_of /dev/shm/aeron-cluster /dev/shm/aeron-assets)
    echo "dump dir $dump_dir available ${avail:-unread} bytes"
    echo "legacy dump upper bound ${pg_dump_upper:-unread} bytes (on-disk size of oms and marketdata)"
    echo "tmpfs copy $tmpfs_copy bytes (/dev/shm/aeron-cluster and /dev/shm/aeron-assets)"
    if [[ "$avail" =~ ^[0-9]+$ ]] && [[ "$pg_dump_upper" =~ ^[0-9]+$ ]]; then
        echo "headroom after the dump $((avail - pg_dump_upper)) bytes"
        echo "headroom after the dump and the tmpfs copy $((avail - pg_dump_upper - tmpfs_copy)) bytes"
        [ $((avail - pg_dump_upper - tmpfs_copy)) -gt 0 ] && echo "headroom for both: yes" || echo "headroom for both: NO"
    else
        echo "headroom: UNREAD (a size could not be measured)"
    fi
}

case "${1:-}" in
    selfcheck) [ $# -eq 3 ] || usage; selfcheck "$2" "$3" ;;
    survey) [ $# -eq 1 ] || usage; survey ;;
    *) usage ;;
esac
