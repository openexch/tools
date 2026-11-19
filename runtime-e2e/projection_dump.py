# SPDX-License-Identifier: Apache-2.0
"""The canonical dump of a projection: one ``COPY (SELECT <fixed column list> FROM <table> ORDER BY <primary key>) TO
STDOUT`` per table, hashed with SHA-256 (never a CRC), and a ``SHA256SUMS`` file over the dumps.

Two projections of one journal are equal when every table's hash is equal. The column lists are fixed here, in this
order, and name only columns that are a function of the journal bytes: a wall-clock column (the money projection's
``ingested_at``, the projection state's ``beat_at``, ``lease_until`` and ``updated_at``) is never dumped. A column a table
has beyond its fixed list (and not one of those known wall-clock columns) is dumped too, after the fixed ones in name
order and recorded as ``extra_columns``: a projection that grew a column never compares equal by leaving it out. Such a
table's fixed columns alone are hashed too (``sha256_fixed``), so a comparison can tell the extra columns from the rest.
A table that does not exist is reported as absent, never as empty.

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
# The wall-clock columns a dump never takes (the list above names none of them)
WALL_CLOCK_COLUMNS = {'ingested_at'}


def copy_sql(table, tables=None, extra=()):
    """The one COPY statement of ``table``: its fixed columns (then ``extra``), ordered by its primary key."""
    columns, key = (tables or SETS['all'])[table]
    return f'COPY (SELECT {", ".join(list(columns) + list(extra))} FROM {table} ORDER BY {", ".join(key)}) TO STDOUT'


def columns_sql(table):
    return ("SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' "
            f"AND table_name = '{table}' ORDER BY column_name")


def extra_columns(listing, table, tables=None):
    """The columns of ``listing`` (the output of columns_sql, one name per line) beyond the table's fixed list."""
    columns, _ = (tables or SETS['all'])[table]
    names = [n.strip() for n in (listing.decode() if isinstance(listing, bytes) else str(listing)).splitlines() if n.strip()]
    if any(not n.replace('_', '').isalnum() for n in names):
        raise ValueError(f'{table}: unexpected column name in {names}')
    return sorted(set(names) - set(columns) - WALL_CLOCK_COLUMNS)


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
        extra = extra_columns(run(columns_sql(table)), table, tables)
        data = run(copy_sql(table, tables, extra))
        (out_dir / f'{table}.copy').write_bytes(data)
        results[table] = {'sha256': digest(data), 'rows': data.count(b'\n'), 'bytes': len(data)}
        if extra:
            # the fixed columns alone hashed as well, so a comparison can tell the extra columns from the rest
            results[table]['extra_columns'] = extra
            results[table]['sha256_fixed'] = digest(run(copy_sql(table, tables)))
    (out_dir / 'SHA256SUMS').write_text(sums_text(results))
    return results


def equal(a, b, fixed=False):
    """The tables whose hashes differ between two dumps (absent on one side counts as a difference). ``fixed``: compare
    the fixed columns alone (``sha256_fixed`` where a table had extra columns, else its one hash)."""
    def h(d, t):
        r = d.get(t) or {}
        return r.get('sha256_fixed', r.get('sha256')) if fixed else r.get('sha256')
    return sorted(t for t in set(a) | set(b) if h(a, t) != h(b, t)
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
