# SPDX-License-Identifier: Apache-2.0
"""The canonical dump of a projection: one ``COPY (SELECT <fixed column list> FROM <table> ORDER BY <primary key>) TO
STDOUT`` per table, hashed with SHA-256 (never a CRC), and a ``SHA256SUMS`` file over the dumps.

Two projections of one journal are equal when every table's hash is equal. The column lists are fixed here, in this
order, and name only columns that are a function of the journal bytes: a wall-clock column (the money projection's
``ingested_at``, the projection state's ``beat_at``, ``lease_until`` and ``updated_at``) is never dumped. A table that
does not exist is reported as absent, never as empty.

Usage: projection_dump.py --psql <psql binary> --host H --port P --user U --database D --out DIR [--set history|money|all]
Writes ``DIR/<table>.copy`` and ``DIR/SHA256SUMS``; prints {"tables": {table: {"sha256", "rows", "bytes"}}} as JSON.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

# table -> (columns in dump order, primary key)
HISTORY_TABLES = {
    'oe_order_events': (['journal_seq', 'order_id', 'user_id', 'event', 'status', 'core_log_position', 'liquidity',
                         'me_epoch', 'me_journal_seq', 'me_log_position', 'me_timestamp_ms', 'trade_id', 'last_price',
                         'last_qty', 'hold_remaining', 'at_ms', 'payload'], ['journal_seq']),
    'oe_orders': (['order_id', 'user_id', 'client_order_id', 'market_id', 'side', 'type', 'time_in_force', 'price',
                   'stop_price', 'quantity', 'filled_quantity', 'remaining_quantity', 'status', 'reason', 'me_reason',
                   'me_order_id', 'hold_asset_id', 'hold_amount', 'hold_remaining', 'created_at_ms', 'updated_at_ms',
                   'last_event_seq', 'last_log_position'], ['order_id']),
    'oe_fills': (['trade_id', 'order_id', 'user_id', 'market_id', 'side', 'price', 'quantity', 'maker', 'executed_at_ms',
                  'event_seq', 'core_log_position', 'me_epoch', 'me_journal_seq', 'me_log_position', 'me_timestamp_ms'],
                 ['trade_id', 'order_id']),
}
# The money projection's two tables without ingested_at (its insert time, a wall clock)
MONEY_TABLES = {
    'money_journal': (['journal_seq', 'log_position', 'movement_type', 'cluster_time_ms', 'user_id', 'asset_id', 'amount', 'balance_after',
                       'trade_id', 'market_id', 'price', 'quantity', 'buyer_user_id', 'seller_user_id', 'taker_is_buy'],
                      ['journal_seq']),
    'money_journal_leg': (['journal_seq', 'leg_no', 'user_id', 'asset_id', 'asset_role', 'balance_after', 'delta'],
                          ['journal_seq', 'leg_no']),
}
SETS = {'history': HISTORY_TABLES, 'money': MONEY_TABLES, 'all': {**HISTORY_TABLES, **MONEY_TABLES}}


def copy_sql(table, tables=None):
    """The one COPY statement of ``table``: its fixed columns, ordered by its primary key."""
    columns, key = (tables or SETS['all'])[table]
    return f'COPY (SELECT {", ".join(columns)} FROM {table} ORDER BY {", ".join(key)}) TO STDOUT'


def exists_sql(table):
    return f"SELECT to_regclass('public.{table}') IS NOT NULL"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sums_text(results):
    """The SHA256SUMS lines (sha256sum format) of the dumped tables, sorted by table."""
    return ''.join(f'{r["sha256"]}  {t}.copy\n' for t, r in sorted(results.items()) if r.get('sha256'))


def dump(run, out_dir, tables):
    """``run(sql) -> bytes`` runs one statement and returns its raw standard output. Returns {table: result}."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {}
    for table in sorted(tables):
        present = run(exists_sql(table)).strip() == b't'
        if not present:
            results[table] = {'absent': True}
            continue
        data = run(copy_sql(table, tables))
        (out_dir / f'{table}.copy').write_bytes(data)
        results[table] = {'sha256': digest(data), 'rows': data.count(b'\n'), 'bytes': len(data)}
    (out_dir / 'SHA256SUMS').write_text(sums_text(results))
    return results


def equal(a, b):
    """The tables whose hashes differ between two dumps (absent on one side counts as a difference)."""
    return sorted(t for t in set(a) | set(b) if (a.get(t) or {}).get('sha256') != (b.get(t) or {}).get('sha256')
                  or (a.get(t) or {}).get('absent') or (b.get(t) or {}).get('absent'))


def psql_runner(psql, host, port, user, database):
    def run(sql):
        r = subprocess.run([str(psql), '-h', host, '-p', str(port), '-U', user, '-d', database, '-v', 'ON_ERROR_STOP=1',
                            '-X', '-q', '-tA', '-c', sql], capture_output=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError(f'psql exit {r.returncode}: {r.stderr.decode(errors="replace")[-300:]}')
        return r.stdout
    return run


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    for name in ('--psql', '--host', '--user', '--database', '--out'):
        p.add_argument(name, required=True)
    p.add_argument('--port', required=True, type=int)
    p.add_argument('--set', choices=sorted(SETS), default='history')
    a = p.parse_args(argv)
    results = dump(psql_runner(a.psql, a.host, a.port, a.user, a.database), a.out, SETS[a.set])
    print(json.dumps({'tables': results}, indent=1, sort_keys=True))


if __name__ == '__main__':
    sys.exit(main())
