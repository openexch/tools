# SPDX-License-Identifier: Apache-2.0
"""The PG-sourced order sample: the control "an oracle that reads PG orders cannot PASS" (control module only).

The product oracles take order truth from the core (core.live_orders from the core's order dump, core_events from the
tap). This module builds a variant of one core sample whose order truth comes from the order history projection instead:
``core.live_orders`` from ``oe_orders`` and ``core_events`` from ``oe_order_events``, through the explicit field map below.
Every other collection stays the core's. The variant is judged by the same order oracle; on a projection that provably
diverged from the core it must not PASS. No module on the core oracle path imports this one (the source scan of
test_red_proofs keeps it so).

Field map (sample field <- PG column; ``derived`` is computed from PG rows only; ``absent`` has no PG source):

  core.live_orders (the rows of oe_orders whose status is not terminal)
    order <- order_id            user <- user_id            market <- market_id        status <- status
    side <- side                 type <- type               tif <- time_in_force       price <- price (NULL: 0)
    stop_price <- stop_price (NULL: 0)                      quantity <- quantity       filled <- filled_quantity
    remaining <- remaining_quantity                         hold_asset <- hold_asset_id
    hold_amount <- hold_amount   me_order_id <- me_order_id (NULL: 0)
    absent: display_qty, expires_at_ms, hidden_qty, slice_seq, budget
  core_events (oe_order_events in journal_seq order)
    seq <- journal_seq           order <- order_id          kind <- event              status <- status
    trade <- trade_id            hold_remaining <- hold_remaining                      log_position <- core_log_position
    filled <- derived: the running sum of last_qty over the order's FILL records (trade_id > 0) up to this record
    absent: reason, quantity, remaining, leg, hold_amount

A PG row that lacks a mapped column ends the build INCONCLUSIVE ``pg sample incomplete: <field>``; a rule of the oracle
that reads an absent field gets the same text (the rows are ``StrictRow``s), never a KeyError, because a KeyError proves
nothing about staleness. The PG side is read twice, one second apart; the two reads must be equal (the PG half of the
two-sample barrier), and the variant's barrier digests for the two replaced collections are those of the settled read.
"""
import json
import time

from contracts import Inconclusive, fingerprint

TERMINAL = {'FILLED', 'CANCELLED', 'REJECTED', 'EXPIRED'}
INCOMPLETE = 'pg sample incomplete'
PASSED_TEXT = 'oracle passed from PG orders'
VACUOUS_TEXT = 'control vacuous: PG equals the core'
NAMED_RULES = ('O4', 'O5', 'O6')

LIVE_MAP = {'order': 'order_id', 'user': 'user_id', 'market': 'market_id', 'status': 'status', 'side': 'side',
            'type': 'type', 'tif': 'time_in_force', 'price': 'price', 'stop_price': 'stop_price', 'quantity': 'quantity',
            'filled': 'filled_quantity', 'remaining': 'remaining_quantity', 'hold_asset': 'hold_asset_id',
            'hold_amount': 'hold_amount', 'me_order_id': 'me_order_id'}
LIVE_NULL_ZERO = {'price', 'stop_price', 'me_order_id'}
LIVE_ABSENT = ('display_qty', 'expires_at_ms', 'hidden_qty', 'slice_seq', 'budget')
EVENT_MAP = {'seq': 'journal_seq', 'order': 'order_id', 'kind': 'event', 'status': 'status', 'trade': 'trade_id',
             'hold_remaining': 'hold_remaining', 'log_position': 'core_log_position'}
EVENT_DERIVED = {'filled': 'running sum of last_qty over the order FILL records'}
EVENT_ABSENT = ('reason', 'quantity', 'remaining', 'leg', 'hold_amount')
# The columns read (the map's sources plus what a derivation needs)
ORDER_COLUMNS = sorted(set(LIVE_MAP.values()))
EVENT_COLUMNS = sorted(set(EVENT_MAP.values()) | {'last_qty'})
FILL_COLUMNS = ['trade_id', 'order_id', 'user_id', 'market_id', 'side', 'price', 'quantity', 'maker', 'event_seq']


class StrictRow(dict):
    """A sample row built from PG: reading a field the map does not give is INCONCLUSIVE with the field's name."""

    def __missing__(self, key):
        raise Inconclusive(f'{INCOMPLETE}: {key}')

    def get(self, key, default=None):
        if key in self:
            return dict.__getitem__(self, key)
        raise Inconclusive(f'{INCOMPLETE}: {key}')


def read_sql():
    """One JSON value: the three relations, the columns the map reads, in key order."""
    def agg(table, columns, order):
        cols = ', '.join(columns)
        return f"(SELECT COALESCE(json_agg(t ORDER BY {order}), '[]'::json) FROM (SELECT {cols} FROM {table}) t)"
    return ("SELECT json_build_object('orders', " + agg('oe_orders', ORDER_COLUMNS, 'order_id') +
            ", 'events', " + agg('oe_order_events', EVENT_COLUMNS, 'journal_seq') +
            ", 'fills', " + agg('oe_fills', FILL_COLUMNS, 'trade_id, order_id') + ')')


def read_pg(psql, database, clock=time.monotonic, sleep=time.sleep, bound_s=30):
    """The PG side, read until two reads one second apart are equal (bound ``bound_s``)."""
    first = json.loads(psql(database, read_sql()))
    started = clock()
    while True:
        sleep(1)
        second = json.loads(psql(database, read_sql()))
        if fingerprint(first) == fingerprint(second):
            return second
        if clock() - started > bound_s:
            raise Inconclusive(f'pg sample did not settle: two reads 1 s apart differ for {bound_s} s')
        first = second


def _column(row, column, field):
    if column not in row:
        raise Inconclusive(f'{INCOMPLETE}: {field}')
    return row[column]


def live_orders(pg):
    out = []
    for row in pg['orders']:
        status = _column(row, 'status', 'status')
        if status in TERMINAL:
            continue
        live = StrictRow()
        for field, column in LIVE_MAP.items():
            value = _column(row, column, field)
            if value is None and field in LIVE_NULL_ZERO:
                value = 0
            if value is None:
                raise Inconclusive(f'{INCOMPLETE}: {field}')
            live[field] = value
        out.append(live)
    return out


def core_events(pg):
    out, filled = [], {}
    for row in sorted(pg['events'], key=lambda r: _column(r, 'journal_seq', 'seq')):
        event = StrictRow()
        for field, column in EVENT_MAP.items():
            event[field] = _column(row, column, field)
        order = event['order']
        if event['kind'] == 'FILL' and event['trade'] > 0:
            filled[order] = filled.get(order, 0) + _column(row, 'last_qty', 'filled')
        event['filled'] = filled.get(order, 0)
        out.append(event)
    return out


def pg_sample(sample, pg):
    """The core sample with its order truth from PG: core.live_orders and core_events replaced, every other collection
    the core's; the barrier digests of the two replaced collections are those of the settled PG read."""
    out = dict(sample)
    out['core'] = dict(sample['core'], live_orders=live_orders(pg))
    out['core_events'] = core_events(pg)
    barrier = dict(sample['barrier'])
    barrier['samples'] = [dict(s, core_digest=fingerprint(out['core']), core_events_digest=fingerprint(out['core_events']))
                          for s in sample['barrier']['samples']]
    out['barrier'] = barrier
    out['order_truth'] = 'pg: oe_orders, oe_order_events (control only)'
    return out


LIVE_COMPARED = ('order', 'status', 'filled', 'remaining', 'quantity', 'price', 'me_order_id')


def live_view(rows):
    return sorted(tuple(r[k] for k in LIVE_COMPARED) for r in rows)


def divergence(sample, pg):
    """What the PG-sourced oracle reads against the core's own dump: the live rows (the fields above) and the event
    sequence set. The control needs them to differ."""
    core_live, pg_live = live_view(sample['core']['live_orders']), live_view(live_orders(pg))
    core_seqs = sorted(e['seq'] for e in sample['core_events'])
    pg_seqs = sorted(r['journal_seq'] for r in pg['events'])
    live_only_core = [list(r) for r in core_live if r not in pg_live]
    live_only_pg = [list(r) for r in pg_live if r not in core_live]
    seq_missing = sorted(set(core_seqs) - set(pg_seqs))
    seq_extra = sorted(set(pg_seqs) - set(core_seqs))
    pg_orders = {r['order_id']: r['status'] for r in pg['orders']}
    differs = bool(live_only_core or live_only_pg or seq_missing or seq_extra)
    return differs, {'live_core_only': live_only_core[:10], 'live_pg_only': live_only_pg[:10],
                     'core_live': len(core_live), 'pg_live': len(pg_live), 'core_events': len(core_seqs),
                     'pg_events': len(pg_seqs), 'event_seqs_missing_in_pg': seq_missing[:20],
                     'event_seqs_only_in_pg': seq_extra[:20], 'pg_orders': len(pg_orders)}


def rule_names(verdict, status):
    return sorted(k for k, v in (verdict.get('rules') or {}).items() if v.get('status') == status)


def incomplete_fields(verdict):
    out = set()
    for v in (verdict.get('rules') or {}).values():
        detail = str(v.get('detail') or '')
        if INCOMPLETE + ':' in detail:
            out.add(detail.split(INCOMPLETE + ':', 1)[1].strip().split()[0])
    if INCOMPLETE + ':' in str(verdict.get('error') or ''):
        out.add(str(verdict['error']).split(INCOMPLETE + ':', 1)[1].strip().split()[0])
    return sorted(out)


def line(holds, detail, text, inconclusive=False):
    return {'holds': bool(holds), 'detail': detail, 'text': None if holds else text, 'inconclusive': bool(inconclusive)}


def control_lines(product_money, product_order, differs, detail, pg_verdict):
    """The control's lines (smoke_core.verdict shape): the product oracles PASS on the core sample; the divergence holds
    (else ``control vacuous: PG equals the core``, INCONCLUSIVE); the PG-sourced sample is complete (else ``pg sample
    incomplete: <field>``, INCONCLUSIVE); the PG-sourced oracle does not PASS (else ``oracle passed from PG orders``); and
    its failing rules include O4, O5 or O6 (judged only when the oracle did not pass)."""
    failing = rule_names(pg_verdict, 'FAIL')
    fields = incomplete_fields(pg_verdict)
    lines = {
        'product_money_oracle': line(product_money['status'] == 'PASS', {'status': product_money['status']},
                                     'money oracle not PASS', inconclusive=product_money['status'] == 'INCONCLUSIVE'),
        'product_order_oracle': line(product_order['status'] == 'PASS', {'status': product_order['status'],
                                                                          'failing': rule_names(product_order, 'FAIL')},
                                     'order oracle not PASS', inconclusive=product_order['status'] == 'INCONCLUSIVE'),
        'divergence': line(differs, detail, VACUOUS_TEXT, inconclusive=not differs),
        'pg_sample_complete': line(not fields, {'fields': fields},
                                   f'{INCOMPLETE}: {fields[0]}' if fields else None, inconclusive=bool(fields)),
        'pg_oracle_not_pass': line(pg_verdict['status'] != 'PASS',
                                   {'status': pg_verdict['status'], 'failing': failing,
                                    'inconclusive': rule_names(pg_verdict, 'INCONCLUSIVE'), 'error': pg_verdict.get('error'),
                                    'details': {k: v.get('detail') for k, v in (pg_verdict.get('rules') or {}).items()
                                                if v.get('status') != 'PASS'}},
                                   PASSED_TEXT),
    }
    named = sorted(set(failing) & set(NAMED_RULES))
    lines['pg_oracle_names_divergence'] = dict(line(bool(named), {'named': named, 'failing': failing},
                                                    'PG-sourced oracle did not fail on O4, O5 or O6'),
                                               consequence_of='pg_oracle_not_pass')
    return lines
