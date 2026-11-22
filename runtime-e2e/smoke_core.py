# SPDX-License-Identifier: Apache-2.0
"""The critical-path drills of the core topology: the whole user path through the product binaries, judged from the core.

Four scenario ids, dispatched by runner.py on a manifest of a critical-path kind (``core_contracts.MARKETDATA_KINDS``:
the projector binary kind plus the market-data slot md0):

* ``critical-path-smoke-core``: every request through gw0's REST API and every user event through st0's WebSocket,
  never through the probe's GATEWAY session. Funding by ``POST /balances/deposit`` on the treasury lane; N crossing
  LIMIT pairs at more than one price; one resting order partly filled by a smaller taker, amended, then cancelled; one
  more resting order per user, then a cancel-all per user; one create refused for funds and one create sent twice with
  one Idempotency-Key; two withdrawals, one accepted and one refused for funds. Input closed, the two-sample barrier,
  both core oracles (money and order, from the core sample: core dumps, the tap, the ME journal, the money history; no
  order history relation and no market history relation). It PASSes only when both oracles PASS, fills > 0, every
  part of the workload happened, and the REST client's request log equals the set the core decided. After the
  barrier: the order history (``GET /orders/history``, ``/orders/{id}/trail``, ``/fills``) and the stream frames of
  each user against the core's events (the core is the reference), and the public market data (the tape a subscribed
  client of md0 saw, ``md_trades``) against the ME journal's trades, plus the book's resting level until its cancel.
* ``core-control-smoke-nomatch``: the same workload on a kind with both forwarder slots empty (``cps-nofwd``): nothing
  reaches the ME, so the smoke must not PASS, and the order oracle must name O7 or O10. Run on a kind whose forwarders
  run, it ends INCONCLUSIVE ``control vacuous: orders matched``.
* ``core-gate-brake``: the global order-entry gate SUSPENDED and OPEN again, twice in one run: under SUSPENDED a create
  and an amend are refused GATE_CLOSED, a cancel, a deposit and a withdrawal are accepted, a fill already in flight
  settles, balances answer, gw0's ``/ready`` fails on ``gate_open`` and ``/ready/session`` stays ready; OPEN again, a
  create is accepted. Then the barrier and both oracles.
* ``core-history-loss``: the order history databases (the gateways' database pj0 writes and pj1's) taken down and
  returned twice while the workload runs: creates and fills continue, history routes answer 503 HISTORY_UNAVAILABLE,
  the projector catches up after each return inside the drill bound, both oracles PASS on the core sample. A database
  is taken down by refusing every new connection to it and ending every open one (core_fixture.history_databases_down):
  the money database and the market history database stay up.

Controls. A critical-path kind's ``smoke_control`` names the scenario it controls (``cps-nc-dropone``: the history line
on oe-projector built with PROJ_NC_DROP_ONE). The harness's own test builds are the setting ``CPS_CONTROL`` (CONTROLS:
one rule switched off or one input planted, recorded with the run). A control run passes only when a judged line fails
with exactly the control's text and no other judged line fails; an INCONCLUSIVE control (the database never taken
down) ends INCONCLUSIVE with its text. A line whose witness needs another line to hold names it in ``consequence_of``
and is judged only when that line holds.

Every size, bound and wait is a setting (SETTINGS, overridden by an environment variable of the same name), recorded.
"""
from collections import Counter
import json
import os
from pathlib import Path
import shutil
import time
import uuid

from contracts import FP, Inconclusive, Violation
import core_contracts
import core_drills
import gateway_probe
from gateway_scenarios import DRILL_RISK, GATE_AFTER, GatewayDrill, cancels_from, creates_from, line
from gateway_shim import request_id, units

SCENARIOS = ('critical-path-smoke-core', 'core-control-smoke-nomatch', 'core-gate-brake', 'core-history-loss')
SETTINGS = {
    # the smoke's workload: crossing pairs at SMOKE_PRICES prices
    'SMOKE_PAIRS': 12, 'SMOKE_PRICES': 3,
    # a keyed call is retried with its key until answered or this bound; a poll of an order, the book or the history
    # waits at most its bound (drill bounds, recorded; never limits of a binary)
    'SMOKE_CALL_BOUND_S': 60, 'SMOKE_FILL_WAIT_S': 20, 'SMOKE_BOOK_WAIT_S': 20, 'SMOKE_STREAM_SETTLE_S': 5,
    'SMOKE_HISTORY_CATCHUP_S': 90, 'SMOKE_TAPE_WAIT_S': 60, 'SMOKE_TAP_S': 3600, 'SMOKE_POLL_MS': 500,
    # the nomatch control waits for no fill: its polls end at this bound
    'NOMATCH_WAIT_S': 3,
    # core-gate-brake: cycles, and how long the gate stays SUSPENDED after the calls made under it
    'GATE_CYCLES': 2, 'GATE_HOLD_S': 2,
    # core-history-loss: outages, crossing pairs and history reads per outage, how long the databases stay down, and the
    # bound inside which the projector reaches the core's head after each return
    'HISTORY_LOSS_CYCLES': 2, 'HISTORY_DOWN_PAIRS': 4, 'HISTORY_DOWN_READS': 3, 'HISTORY_DOWN_S': 8,
    'HISTORY_CATCHUP_BOUND_S': 60,
}
# CPS_CONTROL -> (scenario, the text its line fails with, whether the run then ends INCONCLUSIVE). Each switches one rule
# of the harness off or plants one input; recorded with the run, never set by a nightly plan.
CONTROLS = {
    'skip-withdraw': ('critical-path-smoke-core', 'smoke workload incomplete: withdraw', False),
    'skip-partial-fill': ('critical-path-smoke-core', 'smoke workload incomplete: partial fill', False),
    'drop-request': ('critical-path-smoke-core', "request log differs from the core's decided set", False),
    'md-off': ('critical-path-smoke-core', 'no public trade for tradeId', False),
    'tape-extra-trade': ('critical-path-smoke-core', 'public tape differs from the journal: extra trade', False),
    'skip-gate': ('core-gate-brake', 'gate was never SUSPENDED', False),
    'one-cycle': ('core-gate-brake', 'gate cycle ran once', False),
    'funding-before-gate': ('core-gate-brake', 'no deposit or withdrawal was sent under a suspended gate', False),
    'never-down': ('core-history-loss', 'history database was never down', True),
    'one-stop': ('core-history-loss', 'history loss ran once', False),
    'history-500': ('core-history-loss', 'history fault surfaced with the wrong code', False),
}
CONTROL_SETTING = 'CPS_CONTROL'
VACUOUS_TEXT = 'control vacuous: orders matched'
HISTORY_MISSING_TEXT = 'history differs from the core: missing event'
REQUEST_LOG_TEXT = "request log differs from the core's decided set"
NO_TRADE_TEXT = 'no public trade for tradeId'
EXTRA_TRADE_TEXT = 'public tape differs from the journal: extra trade'
USER_BASE = {'critical-path-smoke-core': 91001, 'core-control-smoke-nomatch': 91101, 'core-gate-brake': 92001,
             'core-history-loss': 93001}
MARKET = 1
BASE_ASSET, QUOTE_ASSET, EMPTY_ASSET = 1, 0, 2       # market 1: base asset 1, quote asset 0; nobody holds asset 2
UNIT = FP // 1000
# Prices inside the ME band of market 1 (0.01 .. 100, tick 0.01) and the core's collar around the pairs' price
PAIR_PRICE = 90 * FP
REST_PRICE, AMEND_PRICE = 95 * FP, 96 * FP
LOW_BUY, HIGH_SELL = 80 * FP, 99 * FP
FUNDING = {QUOTE_ASSET: 1000 * FP, BASE_ASSET: 10 * FP}
# The gateways' faucet caps for these drills (each user funds itself on the treasury lane): every asset the workload
# deposits or withdraws has a cap (an asset without one is refused by the gateway before the core)
FAUCET_CAPS = {QUOTE_ASSET: '1000', BASE_ASSET: '100', EMPTY_ASSET: '1', 999: '1'}


def settings(environ=os.environ):
    out = {}
    for name, default in SETTINGS.items():
        value = environ.get(name)
        if value is None or value == '':
            out[name] = default
            continue
        if not value.isdigit() or int(value) < 1:
            raise Violation(f'{name} must be a positive integer, got {value!r}')
        out[name] = int(value)
    return out


def is_scenario(name):
    return name in SCENARIOS


def control_of(manifest, name, environ=os.environ):
    """(control name, text, inconclusive) of this run, or None. The kind's ``smoke_control`` (it runs only the scenario it
    controls) or the CPS_CONTROL setting (one of CONTROLS, for its own scenario only); both at once are refused."""
    spec = core_contracts.GATEWAY_KINDS.get(manifest.get('manifest_kind')) or {}
    setting = environ.get(CONTROL_SETTING) or None
    if spec.get('smoke_control'):
        if spec['smoke_control'] != name:
            raise Inconclusive(f'kind {manifest.get("manifest_kind")} is the control of {spec["smoke_control"]}, not of {name}')
        if setting:
            raise Inconclusive(f'{CONTROL_SETTING}={setting} on the control kind {manifest.get("manifest_kind")}: one control a run')
        return manifest.get('manifest_kind'), spec['control_text'], False
    if setting is None:
        return None
    if setting not in CONTROLS:
        raise Violation(f'{CONTROL_SETTING} is one of {", ".join(sorted(CONTROLS))}, got {setting!r}')
    scenario, text, inconclusive = CONTROLS[setting]
    if scenario != name:
        raise Inconclusive(f'{CONTROL_SETTING}={setting} is a control of {scenario}, not of {name}')
    return setting, text, inconclusive


def check_scenario(manifest, name, environ=os.environ):
    """Before any container starts: an unknown id is refused; the scenarios need a critical-path kind (gateway, stream,
    projector binary and market-data slots on the product binaries); a kind without forwarders runs only the nomatch
    control; a control kind runs only the scenario it controls. Returns the run's control or None."""
    if not is_scenario(name):
        raise Inconclusive('unknown critical-path scenario: ' + name)
    kind = manifest.get('manifest_kind')
    if kind not in core_contracts.MARKETDATA_KINDS or not core_contracts.marketdata_manifest(manifest):
        raise Inconclusive(f'{name} runs on a critical-path kind ({", ".join(sorted(core_contracts.MARKETDATA_KINDS))}); '
                           f'this manifest is {kind}')
    slots = manifest.get('slot_artifacts') or {}
    wanted = {'gw0': 'gateway', 'gw1': 'gateway', 'st0': 'stream', 'st1': 'stream', 'md0': 'marketdata'}
    wrong = {k: slots.get(k) for k, v in wanted.items() if slots.get(k) != v}
    if wrong or not {slots.get('pj0'), slots.get('pj1')} <= {'history_projector', 'history_projector_nc'}:
        raise Inconclusive(f'{name} runs on the product binaries in the user-facing slots; this kind stages '
                           + ', '.join(f'{k}={v}' for k, v in sorted(slots.items()) if k in wanted or k.startswith('pj')))
    forwarders = [slots.get('fwd0'), slots.get('fwd1')]
    if name != 'core-control-smoke-nomatch' and not any(forwarders):
        raise Inconclusive(f'{name} needs the forwarders; {kind} runs none (the nomatch control\'s kind)')
    return control_of(manifest, name, environ)


def scenario(fixture, name, out_dir):
    """runner.py entry for the critical-path scenario ids."""
    control = check_scenario(fixture.m, name)
    cls = {'critical-path-smoke-core': SmokeDrill, 'core-control-smoke-nomatch': NoMatchDrill,
           'core-gate-brake': GateBrakeDrill, 'core-history-loss': HistoryLossDrill}[name]
    result = cls(fixture, name, Path(out_dir) / 'drill', control).run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name} on {fixture.m.get("manifest_kind")} (engines {fixture.engine_driver()})')


# ------------------------------------------------------------------ the verdict (pure)

def text_matches(text, expected):
    """A line's text against a control's: equal, or the control's text followed by the id it names (`... tradeId <n>`)."""
    return bool(text) and (text == expected or text.startswith(expected + ' '))


def judged(lines):
    """The lines that are judged: a line whose ``consequence_of`` line does not hold is listed, not judged."""
    return {k: v for k, v in lines.items() if not v.get('consequence_of') or (lines.get(v['consequence_of']) or {}).get('holds')}


def verdict(lines, control=None):
    """(status, control block or None). A drill run: INCONCLUSIVE when a judged line's witness is missing, PASS when every
    judged line holds, else FAIL. A control run (``control`` = (name, text, inconclusive)): it holds when at least one
    judged line fails with the control's text and no judged line fails with another; then the run ends PASS, or
    INCONCLUSIVE for an INCONCLUSIVE control; else FAIL."""
    j = judged(lines)
    failing = {k: v for k, v in j.items() if not v['holds']}
    if control is None:
        if any(v.get('inconclusive') for v in j.values()):
            return 'INCONCLUSIVE', None
        return ('PASS' if not failing else 'FAIL'), None
    name, text, inconclusive = control
    matched = sorted(k for k, v in failing.items() if text_matches(v.get('text'), text))
    others = {k: v.get('text') for k, v in failing.items() if k not in matched}
    held = bool(matched) and not others
    status = ('INCONCLUSIVE' if inconclusive else 'PASS') if held else 'FAIL'
    return status, {'name': name, 'expected_text': text, 'expected_inconclusive': inconclusive, 'held': held,
                    'failed_lines': matched, 'other_failures': others}


def consequence(out, of):
    out['consequence_of'] = of
    return out


# ------------------------------------------------------------------ the request log as oracle rows (pure)

def attempt_records(log):
    """One record per attempt of every call (the shape gateway_scenarios.creates_from reads)."""
    out = []
    for call in log:
        for a in call.get('attempts') or [{'status': call['status'], 'reply': call['reply'], 'sent_ns': call['sent_ns'],
                                           'recv_ns': call['recv_ns']}]:
            out.append({'method': call['method'], 'path': call['path'].split('?')[0], 'user': call['user'], 'key': call.get('key'),
                        'body': call.get('body'), 'status': a['status'], 'reply': a.get('reply'), 'sent_ns': a['sent_ns'],
                        'recv_ns': a.get('recv_ns'), 'tag': call.get('tag')})
    return out


def _reply(row):
    return row.get('reply') if isinstance(row.get('reply'), dict) else {}


def gate_closed(row):
    """An answer the core's closed gate gave (GATE_CLOSED maps to 503 ADMISSION_CLOSED, never stored under its key)."""
    return row.get('status') == 503 and _reply(row).get('code') == 'ADMISSION_CLOSED'


def oracle_creates(log):
    """The oracle's create rows: every POST /orders key, its decisive answer first 2xx, else the first final reject."""
    return creates_from([r for r in attempt_records(log) if r['method'] == 'POST' and r['path'] == '/api/v2/orders'])


def oracle_cancels(log):
    """DELETE /orders/{id} rows (keyed or not) and every item of a bulk cancel (unkeyed: request 0/0)."""
    rows = cancels_from([r for r in attempt_records(log) if r['method'] == 'DELETE'])
    for call in log:
        if call['method'] != 'POST' or call['path'] != '/api/v2/orders/cancel' or call['status'] != 200:
            continue
        for item in _reply(call).get('results') or []:
            state = item.get('state')
            if state == 'CANCEL_PENDING':
                reply = {'outcome': 'ACK', 'order': int(item['orderId']), 'duplicate': False,
                         'reoffered': bool(item.get('reoffered'))}
            elif state in ('NOT_OPEN', 'NOT_FOUND'):
                reply = {'outcome': 'REJECT', 'reason': state, 'status': 200}
            else:
                reply = {'outcome': 'UNKNOWN'}
            rows.append({'request': [0, 0], 'user': call['user'], 'order': int(item['orderId']), 'reply': reply})
    return rows


def oracle_amends(log):
    """PUT /orders/{id} rows: ACK on 2xx, REJECT on a final refusal (GATE_CLOSED from the closed gate), else UNKNOWN."""
    rows = []
    for call in log:
        if call['method'] != 'PUT':
            continue
        rid = request_id(call.get('key'))
        body = call.get('body') or {}
        row = {'request': list(rid) if rid else [0, 0], 'user': call['user'], 'order': int(call['path'].rsplit('/', 1)[1]),
               'new_price': units(body.get('price')) or 0, 'new_quantity': units(body.get('quantity')) or 0}
        reply = _reply(call)
        if 200 <= call['status'] < 300:
            row['reply'] = {'outcome': 'ACK', 'order': row['order'], 'duplicate': bool(reply.get('duplicate'))}
        elif gate_closed(call):
            row['reply'] = {'outcome': 'REJECT', 'reason': 'GATE_CLOSED', 'status': 503}
        elif call['status'] not in gateway_probe.RETRY_STATUSES | {429}:
            row['reply'] = {'outcome': 'REJECT', 'reason': reply.get('reason'), 'status': call['status']}
        else:
            row['reply'] = {'outcome': 'UNKNOWN'}
        rows.append(row)
    return rows


def oracle_funding(log):
    """The deposits and withdrawals of the treasury lane as funding rows: ACK on 2xx, REJECT on a final refusal, UNKNOWN
    otherwise; ``gate`` is the tap's GLOBAL gate state the drill recorded on the call before it was sent."""
    rows = []
    for call in log:
        kind = {'/api/v2/balances/deposit': 'deposit', '/api/v2/balances/withdraw': 'withdraw'}.get(call['path'])
        if call['method'] != 'POST' or kind is None:
            continue
        rid = request_id(call.get('key'))
        body = call.get('body') or {}
        outcome = ('ACK' if 200 <= call['status'] < 300 else
                   'UNKNOWN' if call['status'] in gateway_probe.RETRY_STATUSES | {429} else 'REJECT')
        rows.append({'request': list(rid) if rid else [0, 0], 'kind': kind, 'user': call['user'],
                     'asset': int(body.get('assetId')), 'amount': units(body.get('amount')), 'outcome': outcome,
                     'gate': call.get('gate'), 'reply': _reply(call)})
    return rows


# ------------------------------------------------------------------ lines over the request log and the core sample (pure)

def decided_sets(log):
    """What the REST client's log says the core decided: created order ids, accepted amends and cancels per order, and the
    acknowledged deposits and withdrawals as a (kind, user, asset, amount) multiset."""
    created = set()
    for c in oracle_creates(log):
        if c['reply'].get('outcome') == 'ACK':
            created.add(c['reply']['order'])
    amends = Counter(r['order'] for r in oracle_amends(log) if r['reply'].get('outcome') == 'ACK'
                     and not r['reply'].get('duplicate'))
    cancels = Counter(r['order'] for r in oracle_cancels(log) if r['reply'].get('outcome') == 'ACK'
                      and not r['reply'].get('duplicate'))
    funding = Counter((r['kind'], r['user'], r['asset'], r['amount']) for r in oracle_funding(log) if r['outcome'] == 'ACK')
    return {'creates': created, 'amends': amends, 'cancels': cancels, 'funding': funding}


def core_decided(sample, users):
    """The same sets from the core: CREATE, AMEND and CANCEL dispatches of the users' orders (the tap with its
    backfill), and the money journal's deposits and withdrawals of the users."""
    users = set(users)
    rows = [r for r in sample.get('dispatch_tap') or [] if r.get('user') in users]
    created = {r['order'] for r in rows if r.get('kind') == 'CREATE'}
    amends = Counter(r['order'] for r in rows if r.get('kind') == 'AMEND')
    cancels = Counter(r['order'] for r in rows if r.get('kind') == 'CANCEL')
    funding = Counter((r['kind'], r['user'], r['asset'], r['amount']) for r in sample.get('money_journal') or []
                      if r.get('kind') in ('deposit', 'withdraw') and r.get('user') in users)
    return {'creates': created, 'amends': amends, 'cancels': cancels, 'funding': funding}


def request_log_line(log, sample, users):
    """The REST client's request log equals the set the core decided (creates, amends, cancels per order, funding)."""
    mine, core = decided_sets(log), core_decided(sample, users)
    diff = {}
    for name in ('creates', 'amends', 'cancels', 'funding'):
        a, b = mine[name], core[name]
        if a != b:
            if isinstance(a, set):
                diff[name] = {'log_only': sorted(a - b)[:10], 'core_only': sorted(b - a)[:10]}
            else:
                diff[name] = {'log_only': [list(k) if isinstance(k, tuple) else k for k in (a - b)][:10],
                              'core_only': [list(k) if isinstance(k, tuple) else k for k in (b - a)][:10]}
    detail = {'creates': len(mine['creates']), 'amends': sum(mine['amends'].values()), 'cancels': sum(mine['cancels'].values()),
              'funding': sum(mine['funding'].values()), 'differences': diff}
    return line(not diff and bool(mine['creates']), detail, REQUEST_LOG_TEXT, inconclusive=not mine['creates'])


def events_by_order(sample, orders):
    out = {}
    for e in sorted(sample.get('core_events') or [], key=lambda e: e['seq']):
        if e['order'] in orders:
            out.setdefault(e['order'], []).append(e)
    return out


def trades_of(sample):
    return [t for t in sample.get('me_journal') or [] if t.get('type') == 'trade']


def fills_line(sample):
    trades = trades_of(sample)
    return line(len(trades) > 0, {'trades': len(trades)}, 'no fill: no trade in the ME journal')


def holds_line(sample, users):
    """No hold remains for the smoke's users after their cancel-all (the core's holds at the barrier)."""
    left = [h for h in (sample.get('core') or {}).get('holds') or [] if h.get('user') in set(users) and h.get('remaining')]
    return line(not left, {'holds_left': left[:10]}, 'hold remains after cancel-all')


def oracle_lines(money, order):
    def failing(verdict, status):
        return sorted(k for k, v in (verdict.get('rules') or {}).items() if v.get('status') == status)
    return {
        'money_oracle': line(money['status'] == 'PASS', {'status': money['status'], 'failing': failing(money, 'FAIL'),
                                                         'inconclusive': failing(money, 'INCONCLUSIVE'),
                                                         'error': money.get('error')},
                             'money oracle not PASS', inconclusive=money['status'] == 'INCONCLUSIVE'),
        'order_oracle': line(order['status'] == 'PASS', {'status': order['status'], 'failing': failing(order, 'FAIL'),
                                                         'inconclusive': failing(order, 'INCONCLUSIVE'),
                                                         'error': order.get('error')},
                             'order oracle not PASS', inconclusive=order['status'] == 'INCONCLUSIVE'),
    }


# ------------------------------------------------------------------ order history and streams against the core (pure)

def history_line(sample, orders, history_rows, trails, fills):
    """GET /orders/history, /orders/{id}/trail and /fills of the users against the core's events of their orders: every
    order a row with the last event's status and filled quantity, every order's trail exactly its events (by eventSeq),
    every FILL event with a trade id a fill row. The core is the reference. ``history_rows``: {orderId: row};
    ``trails``: {orderId: [eventSeq, ...]}; ``fills``: {(tradeId, orderId)}."""
    events = events_by_order(sample, orders)
    missing_event, extra_event, status_diff, missing_rows, missing_fills = [], [], [], [], []
    for order, evs in sorted(events.items()):
        want = [e['seq'] for e in evs]
        have = trails.get(order)
        if have is None:
            missing_event.append({'order': order, 'trail': None})
        else:
            gone, extra = sorted(set(want) - set(have)), sorted(set(have) - set(want))
            if gone:
                missing_event.append({'order': order, 'event_seqs': gone[:5]})
            if extra:
                extra_event.append({'order': order, 'event_seqs': extra[:5]})
        row = history_rows.get(order)
        last = evs[-1]
        if row is None:
            missing_rows.append(order)
        elif row.get('status') != last['status'] or units(row.get('filledQuantity')) != last['filled']:
            status_diff.append({'order': order, 'history': [row.get('status'), row.get('filledQuantity')],
                                'core': [last['status'], last['filled']]})
        for e in evs:
            if e.get('kind') == 'FILL' and e.get('trade', 0) > 0 and (e['trade'], order) not in fills:
                missing_fills.append([e['trade'], order])
    detail = {'orders': len(events), 'missing_event': missing_event[:10], 'extra_event': extra_event[:10],
              'rows_missing': missing_rows[:10], 'status_differs': status_diff[:10], 'fills_missing': missing_fills[:10]}
    if missing_event or missing_fills:
        text = HISTORY_MISSING_TEXT
    elif extra_event:
        text = 'history differs from the core: extra event'
    elif missing_rows:
        text = 'history differs from the core: missing order'
    else:
        text = 'history differs from the core: status'
    ok = not (missing_event or extra_event or missing_rows or status_diff or missing_fills)
    return line(ok and bool(events), detail, text, inconclusive=not events)


def stream_line(sample, orders_by_user, frames_by_user):
    """The order and fill frames each user's st0 connection received against the core: every order's last status and
    every FILL event's trade (the core is the reference)."""
    diffs = []
    checked = 0
    for user, orders in sorted(orders_by_user.items()):
        frames = frames_by_user.get(user) or []
        last, fills = {}, set()
        for row in frames:
            frame = row.get('frame') or {}
            if frame.get('type') == 'order':
                o = frame.get('order') or {}
                last[str(o.get('orderId'))] = o.get('status')
            elif frame.get('type') == 'snapshot' and frame.get('channel') == 'orders':
                for o in frame.get('orders') or []:
                    last[str(o.get('orderId'))] = o.get('status')
            elif frame.get('type') == 'fill':
                f = frame.get('fill') or {}
                if f.get('tradeId') is not None:
                    fills.add((str(f.get('tradeId')), str(f.get('orderId'))))
        for order, evs in events_by_order(sample, orders).items():
            checked += 1
            if last.get(str(order)) != evs[-1]['status']:
                diffs.append({'user': user, 'order': order, 'stream': last.get(str(order)), 'core': evs[-1]['status']})
            for e in evs:
                if e.get('kind') == 'FILL' and e.get('trade', 0) > 0 and (str(e['trade']), str(order)) not in fills:
                    diffs.append({'user': user, 'order': order, 'fill_missing': e['trade']})
    return line(not diffs and checked > 0, {'orders': checked, 'differences': diffs[:10]},
                'stream differs from the core', inconclusive=checked == 0)


# ------------------------------------------------------------------ public market data against the ME journal (pure)

def tape_of(frames):
    """Every trade entry of the TRADES_BATCH frames a subscribed client received, in order: (tradeId, price, quantity,
    side, marketId), prices and quantities as int64 units."""
    out = []
    for row in frames:
        frame = row.get('frame') or {}
        if frame.get('type') != 'TRADES_BATCH':
            continue
        for t in frame.get('trades') or []:
            out.append({'trade_id': int(t['tradeId']), 'price': units(t.get('price')), 'quantity': units(t.get('quantity')),
                        'side': t.get('side'), 'market': frame.get('marketId'), 'recv_ns': row.get('recv_ns')})
    return out


def public_trades_line(trades, public, source, market=MARKET):
    """Each ME journal trade of ``market`` once in ``public`` (the tape, or md_trades rows in the same shape), with equal
    price, quantity and taker side; a public trade the journal does not hold is an extra trade. The journal is the
    reference."""
    want = {t['trade_id']: t for t in trades if t.get('market') == market}
    seen = Counter(p['trade_id'] for p in public)
    have = {p['trade_id']: p for p in public}
    missing = sorted(set(want) - set(have))
    extra = sorted(set(have) - set(want))
    twice = sorted(k for k, n in seen.items() if n > 1)
    wrong = []
    for tid, t in want.items():
        p = have.get(tid)
        if p is None:
            continue
        side = 'BUY' if t['taker_is_buy'] else 'SELL'
        if (p['price'], p['quantity'], p['side']) != (t['price'], t['quantity'], side):
            wrong.append({'trade': tid, 'public': [p['price'], p['quantity'], p['side']], 'journal': [t['price'], t['quantity'], side]})
    detail = {'source': source, 'journal_trades': len(want), 'public_trades': len(public), 'missing': missing[:10],
              'extra': extra[:10], 'twice': twice[:10], 'differs': wrong[:10]}
    if missing:
        text = f'{NO_TRADE_TEXT} {missing[0]}'
    elif extra or twice:
        text = EXTRA_TRADE_TEXT
    else:
        text = 'public tape differs from the journal: price, quantity or side'
    return line(not (missing or extra or twice or wrong) and bool(want), detail, text, inconclusive=not want)


def book_states(frames):
    """The ask and bid ladders a client holds after each book frame: [(recv_ns, {'asks': {price: qty}, 'bids': {...}})]."""
    book, out = {'asks': {}, 'bids': {}}, []
    for row in frames:
        frame = row.get('frame') or {}
        kind = frame.get('type')
        if kind == 'BOOK_SNAPSHOT':
            book = {side: {units(l['price']): units(l['quantity']) for l in frame.get(side) or []} for side in ('asks', 'bids')}
        elif kind == 'BOOK_DELTA':
            book = {side: dict(levels) for side, levels in book.items()}
            for c in frame.get('changes') or []:
                side = 'asks' if c.get('side') == 'ASK' else 'bids'
                price = units(c.get('price'))
                if c.get('updateType') == 'DELETE_LEVEL':
                    book[side].pop(price, None)
                else:
                    book[side][price] = units(c.get('quantity'))
        else:
            continue
        out.append((row.get('recv_ns') or 0, book))
    return out


def book_line(frames, price, quantity, after_ns, cancel_ns, side='asks'):
    """The book frames of the market show the resting order's level (``price`` with at least ``quantity``) after
    ``after_ns`` and before its cancel was sent (``cancel_ns``), and the level is gone from a book after the cancel."""
    states = book_states(frames)
    shown = [t for t, b in states if after_ns <= t <= cancel_ns and (b[side].get(price) or 0) >= quantity]
    later = [(t, b[side].get(price)) for t, b in states if t > cancel_ns]
    gone = any(q is None or q < quantity for _, q in later)
    detail = {'price': price, 'quantity': quantity, 'book_frames': len(states), 'shown_before_cancel': len(shown),
              'after_cancel': later[-3:], 'gone_after_cancel': gone}
    return line(bool(shown) and gone, detail, 'book did not show the resting level until its cancel', inconclusive=not states)


def plant_extra_trade(frames):
    """The tape-extra-trade control: a copy of the frames in which the first trade entry is committed twice, the second
    time under a new trade id (what a commit split looks like on the tape)."""
    out = [json.loads(json.dumps(r)) for r in frames]
    for row in out:
        frame = row.get('frame') or {}
        if frame.get('type') == 'TRADES_BATCH' and frame.get('trades'):
            t = dict(frame['trades'][0])
            t['tradeId'] = str(10 ** 12 + int(t['tradeId']))
            frame['trades'].append(t)
            return out, t['tradeId']
    return out, None


# ------------------------------------------------------------------ gate and history-loss lines (pure)

def gate_cycles(admission):
    """The GLOBAL gate's SUSPENDED (ADMIN) -> OPEN (ADMIN) cycles in the tap's admission rows."""
    cycles, suspended = 0, False
    for row in admission or []:
        if row.get('market') != 0:
            continue
        if row.get('state') == 'SUSPENDED' and row.get('reason') == 'ADMIN':
            suspended = True
        elif row.get('state') == 'OPEN' and suspended:
            cycles += 1
            suspended = False
    return cycles


def cycles_line(count, never_text, once_text, inconclusive_when_none=False):
    detail = {'cycles': count}
    if count == 0:
        return line(False, detail, never_text, inconclusive=inconclusive_when_none)
    return line(count >= 2, detail, once_text)


def history_503_line(outages):
    """Every history read made while the order history databases were down answered 503 HISTORY_UNAVAILABLE."""
    reads = [r for o in outages for r in o.get('reads') or []]
    wrong = [{'status': r['status'], 'code': _reply(r).get('code')} for r in reads
             if r['status'] != 503 or _reply(r).get('code') != 'HISTORY_UNAVAILABLE']
    return line(bool(reads) and not wrong, {'reads': len(reads), 'wrong': wrong[:10]},
                'history fault surfaced with the wrong code', inconclusive=not reads)


# ------------------------------------------------------------------ the drills

def new_key():
    return str(uuid.uuid4())


def order_call(user, side, price, quantity, tag, key=None, retry=True):
    return {'user': user, 'method': 'POST', 'path': '/api/v2/orders', 'key': key or new_key(), 'tag': tag, 'retry': retry,
            'body': gateway_probe.order_body(MARKET, side, 'LIMIT', 'GTC', price, quantity)}


def money_call(user, kind, asset, amount, tag):
    return {'user': user, 'method': 'POST', 'path': f'/api/v2/balances/{kind}', 'key': new_key(), 'tag': tag,
            'body': {'assetId': str(asset), 'amount': gateway_probe.money(amount)}}


class CriticalPathDrill(GatewayDrill):
    """The gateway drill base (probe, money oracle) plus the REST client's request log, the user streams on st0, the
    public market-data client on md0, and the history reads through gw0."""

    def __init__(self, fixture, name, out_dir, control):
        super().__init__(fixture, name, out_dir)
        self.p = settings()
        self.cps_control = control
        self.control_name = control[0] if control else None
        self.log, self.batches = [], 0
        self.record.update(cps_settings=self.p, cps_control=list(control) if control else None,
                           manifest_kind=fixture.m.get('manifest_kind'), engine_driver=fixture.engine_driver())

    # ---------------------------------------------------------------- boot and clients

    def users(self, n=3):
        base = USER_BASE[self.name]
        return list(range(base, base + n))

    def boot_cps(self, users):
        """The genesis with no funding (each user funds itself on the treasury lane), the gateways' faucet caps of these
        drills, and every slot of the kind; md0 left unstarted under the md-off control."""
        f = self.f
        f.gateway_user_ids = sorted(users)
        f.gateway_faucet_caps = dict(FAUCET_CAPS)
        if self.control_name == 'md-off':
            f.marketdata_deferred = True
        f.start({'users': sorted(users), 'markets': [1, 2, 3, 4, 5], 'funding': [], 'seed': f.m['seed'] & 0xFFFFFFFF,
                 'risk': DRILL_RISK, 'tap_ms': self.p['SMOKE_TAP_S'] * 1000})
        if self.control_name == 'md-off':
            f.slots['md0'] = {'state': 'NOT_STARTED', 'reason': 'control md-off: the market slot is not started'}
        self.mark('booted')
        shutil.copyfile(Path(__file__).with_name('gateway_probe.py'), self.probe_dir / 'gateway_probe.py')
        (self.probe_dir / 'gw-keys.json').write_text(json.dumps({str(u): k for u, k in f.keys.api_keys(sorted(users)).items()}))
        f.secret_values = f.keys.secrets() | getattr(f, 'marketdata_secrets', set())
        self.record['slots'] = {k: f.slots.get(k) for k in sorted(set(core_contracts.GATEWAY_SLOTS) | {'pj0', 'pj1', 'md0'})}
        self.record['core_behavior'] = f.registry.get('core_behavior')

    def calls(self, calls, tag=None):
        """One batch of REST calls through gw0, in order (gateway_probe calls); every call joins the request log with the
        tap's GLOBAL gate state read just before the batch was sent."""
        self.batches += 1
        name = f'calls-{self.batches:03d}'
        gate = self.f.tap_gate(0)
        plan = {'target': self.gw('gw0'), 'calls': calls, 'bound_s': self.p['SMOKE_CALL_BOUND_S']}
        rows = self.probe('calls', plan, name, timeout=len(calls) * (self.p['SMOKE_CALL_BOUND_S'] + 35) + 60)
        for row in rows:
            row['gate'] = gate['state'] if gate else None
            row['batch'] = name
        self.log.extend(rows)
        return rows

    def one(self, call):
        return self.calls([call])[0]

    def get(self, user, path, tag='read'):
        return self.one({'user': user, 'method': 'GET', 'path': path, 'tag': tag, 'retry': False})

    def start_user_streams(self, users):
        return self.start_streams([{'user': u, 'target': self.st('st0')} for u in users], name='user-streams',
                                  seconds=self.p['SMOKE_TAP_S'])

    def stream_frames(self, users):
        d = self.probe_dir / 'user-streams.frames'
        out = {}
        for u in users:
            path = d / f'{u}-{self.st("st0").replace(":", "_")}.jsonl'
            out[u] = [json.loads(l) for l in path.read_text().splitlines() if l.strip()] if path.exists() else []
        return out

    def md_target(self):
        return f'{self.f.m["nodes"]["md0"]}:{self.f.m["ports"]["md_public"]}'

    def start_mdfeed(self):
        plan = {'target': self.md_target(), 'market': MARKET, 'stop_file': '/data/md-feed.stop', 'seconds': self.p['SMOKE_TAP_S']}
        (self.probe_dir / 'md-feed-plan.json').write_text(json.dumps(plan))
        self.probe_bg(['python3', '-I', '/data/gateway_probe.py', 'mdfeed', '--plan', '/data/md-feed-plan.json', '--out',
                       '/data/md-feed.jsonl'], 'md-feed')

    def md_frames(self):
        path = self.probe_dir / 'md-feed.jsonl'
        rows = []
        if path.exists():
            for text in path.read_text().splitlines():
                try:
                    rows.append(json.loads(text))
                except ValueError:
                    continue
        return rows

    def stop_mdfeed(self):
        (self.probe_dir / 'md-feed.stop').write_text('stop\n')
        self.sleep(1.5)
        return self.md_frames()

    def wait_for(self, predicate, bound_s):
        """Poll ``predicate()`` every SMOKE_POLL_MS until it returns a truthy value or ``bound_s``; (value, waited_s)."""
        started = self.clock()
        while True:
            value = predicate()
            if value or self.clock() - started >= bound_s:
                return value, round(self.clock() - started, 3)
            self.sleep(self.p['SMOKE_POLL_MS'] / 1000)

    def order_state(self, user, order):
        r = self.get(user, f'/api/v2/orders/{order}', tag='poll')
        return _reply(r) if r['status'] == 200 else {}

    def book_level(self, price, side='asks'):
        states = book_states(self.md_frames())
        return states[-1][1][side].get(price) if states else None

    # ---------------------------------------------------------------- after the barrier

    def history_head(self):
        """The order history's applied event sequence (pj0's database), or None when unreadable."""
        try:
            text = self.f.psql('r01_gateway', 'SELECT applied_seq FROM oe_projection_state')
            return int(text) if text.strip().lstrip('-').isdigit() else None
        except (Inconclusive, Violation):
            return None

    def wait_history(self, head, bound_s):
        value, waited = self.wait_for(lambda: (self.history_head() or 0) >= head, bound_s)
        return {'caught_up': bool(value), 'head': head, 'applied': self.history_head(), 'waited_s': waited}

    def pages(self, user, path):
        """Every item of a history route, following nextCursor."""
        items, cursor, n = [], None, 0
        while True:
            sep = '&' if '?' in path else '?'
            r = self.get(user, path + (f'{sep}cursor={cursor}' if cursor else ''), tag='history')
            body = _reply(r)
            if r['status'] != 200:
                return None, r
            items.extend(body.get('items') or [])
            cursor, n = body.get('nextCursor'), n + 1
            if not cursor or n >= 50:
                return items, r

    def history_view(self, users, orders_by_user):
        rows, trails, fills, errors = {}, {}, set(), []
        for user in users:
            items, last = self.pages(user, '/api/v2/orders/history?limit=100')
            if items is None:
                errors.append({'user': user, 'route': 'orders/history', 'status': last['status']})
            for item in items or []:
                rows[int(item['orderId'])] = item
            items, last = self.pages(user, '/api/v2/fills?limit=100')
            if items is None:
                errors.append({'user': user, 'route': 'fills', 'status': last['status']})
            for item in items or []:
                fills.add((int(item['tradeId']), int(item['orderId'])))
            for order in sorted(orders_by_user.get(user) or []):
                items, last = self.pages(user, f'/api/v2/orders/{order}/trail?limit=100')
                if items is not None:
                    trails[order] = [int(i['eventSeq']) for i in items]
        return rows, trails, fills, errors

    def md_rows(self):
        """md_trades in journal order, or None while the relation does not exist (the service applies its schema at its
        first start; a slot never started has none): read without a failing child command."""
        try:
            if self.f.psql(core_contracts.MARKETDATA_DATABASE, "SELECT to_regclass('public.md_trades') IS NOT NULL") != 't':
                return None
            rows = json.loads(self.f.psql(core_contracts.MARKETDATA_DATABASE,
                                          "SELECT COALESCE(json_agg(t), '[]'::json) FROM (SELECT market_id, trade_id, price, "
                                          'quantity, taker_is_buy FROM md_trades ORDER BY journal_seq) t') or '[]')
        except (Inconclusive, Violation, ValueError):
            return None
        return [{'trade_id': r['trade_id'], 'price': r['price'], 'quantity': r['quantity'],
                 'side': 'BUY' if r['taker_is_buy'] else 'SELL', 'market': r['market_id']} for r in rows]

    def market_lines(self, trades, book):
        """The public market data: the tape a subscribed client saw and md_trades against the ME journal's trades (after waiting up to
        SMOKE_TAPE_WAIT_S for both to hold every trade), and the book's resting level."""
        want = {t['trade_id'] for t in trades if t.get('market') == MARKET}
        self.wait_for(lambda: want <= {t['trade_id'] for t in tape_of(self.md_frames())}
                      and want <= {r['trade_id'] for r in (self.md_rows() or [])}, self.p['SMOKE_TAPE_WAIT_S'])
        frames = self.stop_mdfeed()
        (self.out / 'md-feed.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in frames))
        planted = None
        if self.control_name == 'tape-extra-trade':
            frames, planted = plant_extra_trade(frames)
            self.record['planted_extra_trade'] = planted
        rows = self.md_rows()
        self.record['md_health'] = self.f.marketdata_health() if self.f.slots.get('md0', {}).get('state') == 'STARTED' else None
        lines = {'public_tape': public_trades_line(trades, tape_of(frames), 'tape (TRADES_BATCH frames of a subscribed client)'),
                 'market_history': public_trades_line(trades, rows or [], 'md_trades')}
        if book is not None:
            lines['book_resting_level'] = consequence(book_line(frames, *book), 'public_tape')
        return lines

    def finish(self, lines):
        status, control = verdict(lines, self.cps_control)
        result = {'status': status, 'lines': lines, 'record': self.record}
        if control:
            result['control'] = control
        failing = [v.get('text') or k for k, v in judged(lines).items() if not v['holds']]
        if status != 'PASS' or control:
            result['error'] = '; '.join(failing) if failing else None
        (self.out / 'drill.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        (self.out / 'requests.json').write_text(json.dumps(self.log, indent=1, default=str) + '\n')
        return result

    def oracle(self, gate_sequence=None):
        """Both core oracles over the barrier, with every create, amend, cancel and funding the log holds."""
        money, order = self.money(oracle_creates(self.log), oracle_cancels(self.log),
                                  gate_sequence or core_drills.GATE_SEQUENCE, amends=oracle_amends(self.log),
                                  funding=[{k: v for k, v in r.items() if k != 'reply'} for r in oracle_funding(self.log)])
        sample = json.loads((self.out / 'core-sample.json').read_text())
        return money, order, sample

    def orders_by_user(self):
        out = {}
        for c in oracle_creates(self.log):
            if c['reply'].get('outcome') == 'ACK':
                out.setdefault(c['user'], set()).add(c['reply']['order'])
        return out

    def fund(self, a, b):
        return self.calls([money_call(a, 'deposit', QUOTE_ASSET, FUNDING[QUOTE_ASSET], 'fund'),
                           money_call(b, 'deposit', BASE_ASSET, FUNDING[BASE_ASSET], 'fund')])

    def pairs(self, buyer, seller, n, prices, tag='pair', base_qty=10):
        calls = []
        for k in range(n):
            price = PAIR_PRICE + (k % max(1, prices)) * FP
            qty = (k + 1) * base_qty * UNIT
            calls.append(order_call(seller, 'SELL', price, qty, tag))
            calls.append(order_call(buyer, 'BUY', price, qty, tag))
        return self.calls(calls)

    def cancel_all(self, users):
        return self.calls([{'user': u, 'method': 'POST', 'path': '/api/v2/orders/cancel', 'body': {'all': True},
                            'tag': 'cancel-all', 'retry': False} for u in users])


def order_id_of(row):
    reply = _reply(row)
    return int(reply['orderId']) if 200 <= row['status'] < 300 and reply.get('orderId') is not None else None


class SmokeDrill(CriticalPathDrill):
    nomatch = False

    def run(self):
        f, p = self.f, self.p
        a, b, c = self.users()
        self.boot_cps([a, b, c])
        self.start_user_streams([a, b])
        if f.slots.get('md0', {}).get('state') == 'STARTED':
            self.start_mdfeed()
        wait_s = p['NOMATCH_WAIT_S'] if self.nomatch else None
        work = {}
        # 1. funding through the treasury lane
        work['fund'] = self.fund(a, b)
        # 2. crossing pairs at more than one price
        work['pairs'] = self.pairs(a, b, p['SMOKE_PAIRS'], p['SMOKE_PRICES'])
        # 3. a resting order, partly filled by a smaller taker, amended, cancelled
        rest = self.one(order_call(b, 'SELL', REST_PRICE, 50 * UNIT, 'rest'))
        rest_id = order_id_of(rest)
        partial = {'rest': rest_id}
        if self.control_name != 'skip-partial-fill' and rest_id:
            partial['taker'] = self.one(order_call(a, 'BUY', REST_PRICE, 20 * UNIT, 'partial-taker'))['status']
            state, partial['fill_wait_s'] = self.wait_for(
                lambda: (lambda s: s if units(s.get('filledQuantity')) else None)(self.order_state(b, rest_id)),
                wait_s or p['SMOKE_FILL_WAIT_S'])
            partial['state'] = state
        remaining = units((self.order_state(b, rest_id) if rest_id else {}).get('remainingQuantity')) or 50 * UNIT
        book = None
        if rest_id:
            shown_at = time.time_ns()
            _, partial['book_wait_s'] = self.wait_for(lambda: (self.book_level(REST_PRICE) or 0) >= remaining,
                                                      wait_s or p['SMOKE_BOOK_WAIT_S'])
            work['amend'] = self.one({'user': b, 'method': 'PUT', 'path': f'/api/v2/orders/{rest_id}', 'key': new_key(),
                                      'tag': 'amend', 'body': {'price': gateway_probe.money(AMEND_PRICE)}})
            amended_at = time.time_ns()
            _, partial['amend_wait_s'] = self.wait_for(
                lambda: units(self.order_state(b, rest_id).get('price')) == AMEND_PRICE
                and (self.book_level(AMEND_PRICE) or 0) >= remaining, wait_s or p['SMOKE_BOOK_WAIT_S'])
            cancel_at = time.time_ns()
            work['cancel'] = self.one({'user': b, 'method': 'DELETE', 'path': f'/api/v2/orders/{rest_id}', 'key': new_key(),
                                       'tag': 'cancel'})
            _, partial['cancel_wait_s'] = self.wait_for(lambda: self.book_level(AMEND_PRICE) is None,
                                                        wait_s or p['SMOKE_BOOK_WAIT_S'])
            book = (AMEND_PRICE, remaining, amended_at, cancel_at)
            partial['shown_at_ns'] = shown_at
        self.record['partial'] = partial
        # 5. a create refused for funds (c holds nothing) and a create sent twice with one key
        work['refused'] = self.one(order_call(c, 'BUY', PAIR_PRICE, 1 * UNIT, 'refused-funds'))
        replay = order_call(a, 'BUY', 70 * FP, 3 * UNIT, 'replay')
        work['replay'] = self.calls([replay, dict(replay, tag='replay-again')])
        # 4. one more resting order per user, then cancel-all for each user
        work['more'] = self.calls([order_call(a, 'BUY', LOW_BUY, 5 * UNIT, 'rest-a'),
                                   order_call(b, 'SELL', HIGH_SELL, 5 * UNIT, 'rest-b')])
        work['cancel_all'] = self.cancel_all([a, b])
        # 6. two withdrawals: one accepted, one refused for funds
        if self.control_name != 'skip-withdraw':
            work['withdraw'] = self.calls([money_call(a, 'withdraw', QUOTE_ASSET, 10 * FP, 'withdraw-ok'),
                                           money_call(c, 'withdraw', EMPTY_ASSET, 1 * FP, 'withdraw-refused')])
        # 7. input closed: the user streams settle, then the barrier and both oracles
        self.mark('input_closed')
        self.sleep(p['SMOKE_STREAM_SETTLE_S'])
        streams = self.stop_streams('user-streams')
        self.record['streams'] = streams
        money, order, sample = self.oracle()
        lines = oracle_lines(money, order)
        lines['fills'] = fills_line(sample)
        lines.update(workload_lines(self.log, sample, work, rest_id))
        lines['holds_after_cancel_all'] = holds_line(sample, [a, b])
        dropped = None
        log = self.log
        if self.control_name == 'drop-request':
            # the REST client drops one request from its log: the last acknowledged deposit
            idx = max(i for i, r in enumerate(log) if r['path'] == '/api/v2/balances/deposit' and 200 <= r['status'] < 300)
            dropped = {k: log[idx].get(k) for k in ('method', 'path', 'user', 'tag')}
            log = log[:idx] + log[idx + 1:]
            self.record['dropped_request'] = dropped
        lines['request_log'] = request_log_line(log, sample, [a, b, c])
        # history and streams against the core (the core is the reference)
        orders_by_user = self.orders_by_user()
        orders = set().union(*orders_by_user.values()) if orders_by_user else set()
        head = max((e['seq'] for e in sample.get('core_events') or []), default=0)
        self.record['history_catchup'] = self.wait_history(head, p['SMOKE_HISTORY_CATCHUP_S'])
        rows, trails, fills, errors = self.history_view([a, b, c], orders_by_user)
        self.record['history_errors'] = errors
        lines['history'] = history_line(sample, orders, rows, trails, fills)
        lines['stream'] = stream_line(sample, {u: orders_by_user.get(u) or set() for u in (a, b)}, self.stream_frames([a, b]))
        # the public market data against the ME journal
        lines.update(self.market_lines(trades_of(sample), book))
        return self.finish(self.verdict_lines(lines, sample))

    def verdict_lines(self, lines, sample):
        return lines


def workload_lines(log, sample, work, rest_id):
    """Every part of the smoke's workload happened, read from the core (events, journal) and the client's answers:
    funding, pairs that filled, the partial fill, the amend, the cancel, the cancel-all, the refused create, the replayed
    create, the accepted and the refused withdrawal. Text ``smoke workload incomplete: <part>``."""
    events = events_by_order(sample, {rest_id} if rest_id else set()).get(rest_id) or []
    statuses = [e['status'] for e in events]
    partial = any(0 < e.get('filled', 0) < e.get('quantity', 0) or e['status'] == 'PARTIALLY_FILLED' for e in events)
    amend = work.get('amend') or {}
    cancel = work.get('cancel') or {}
    refused = work.get('refused') or {}
    replay = work.get('replay') or []
    withdraw = work.get('withdraw') or []
    funds = json.dumps(refused.get('reply'))

    def part(name, ok, detail):
        return line(ok, detail, f'smoke workload incomplete: {name}')
    first, again = (replay + [{}, {}])[:2]
    return {
        'workload_funding': part('deposit', all(200 <= r['status'] < 300 for r in work.get('fund') or []) and bool(work.get('fund')),
                                 {'statuses': [r['status'] for r in work.get('fund') or []]}),
        'workload_pairs': part('pairs', bool(work.get('pairs')) and all(r['status'] in (200, 201) for r in work['pairs']),
                               {'statuses': Counter(r['status'] for r in work.get('pairs') or [])}),
        'workload_partial_fill': part('partial fill', partial, {'order': rest_id, 'statuses': statuses}),
        'workload_amend': part('amend', 200 <= amend.get('status', 0) < 300, {'status': amend.get('status'), 'reply': amend.get('reply')}),
        'workload_cancel': part('cancel', 200 <= cancel.get('status', 0) < 300 and (statuses[-1:] == ['CANCELLED']),
                                {'status': cancel.get('status'), 'last': statuses[-1:]}),
        'workload_cancel_all': part('cancel-all', bool(work.get('cancel_all')) and all(
            r['status'] == 200 and _reply(r).get('accepted', 0) >= 1 for r in work['cancel_all']),
            {'answers': [[r['status'], _reply(r).get('accepted')] for r in work.get('cancel_all') or []]}),
        'workload_refused_create': part('refused create', refused.get('status') == 422 and 'INSUFFICIENT_FUNDS' in funds,
                                        {'status': refused.get('status'), 'reply': refused.get('reply')}),
        'workload_replayed_create': part('replayed create', first.get('status') == 201 and again.get('status') == 200
                                         and _reply(again).get('duplicate') is True
                                         and _reply(again).get('orderId') == _reply(first).get('orderId'),
                                         {'statuses': [first.get('status'), again.get('status')],
                                          'duplicate': _reply(again).get('duplicate')}),
        'workload_withdraw': part('withdraw', len(withdraw) == 2 and 200 <= withdraw[0]['status'] < 300
                                  and withdraw[1]['status'] >= 400 and 'INSUFFICIENT_FUNDS' in json.dumps(withdraw[1].get('reply')),
                                  {'answers': [[r['status'], r.get('reply')] for r in withdraw]}),
    }


class NoMatchDrill(SmokeDrill):
    """The smoke's non-vacuity: the same workload with both forwarder slots empty. The smoke must not PASS and the order
    oracle must name O7 or O10; with any fill the control is vacuous (INCONCLUSIVE)."""
    nomatch = True

    def finish(self, lines):
        trades = (lines.get('fills') or {}).get('detail', {}).get('trades', 0)
        smoke_status, _ = verdict(lines)
        order = (lines.get('order_oracle') or {}).get('detail') or {}
        named = sorted(set(order.get('failing') or []) & {'O7', 'O10'}) + sorted(set(order.get('inconclusive') or []) & {'O7', 'O10'})
        held = smoke_status != 'PASS' and bool(named) and trades == 0
        control = {'name': 'nomatch', 'expected': 'not PASS; the order oracle names O7 or O10', 'held': held,
                   'smoke_status': smoke_status, 'named': named, 'fills': trades,
                   'forwarders': [self.f.m['slot_artifacts'].get(s) for s in ('fwd0', 'fwd1')]}
        if trades > 0:
            status, error = 'INCONCLUSIVE', VACUOUS_TEXT
        elif held:
            status, error = 'FAIL', 'order oracle not PASS: ' + ', '.join(named)
        else:
            status, error = 'FAIL', f'smoke {smoke_status} without an order oracle naming O7 or O10'
        result = {'status': status, 'lines': lines, 'record': self.record, 'control': control, 'error': error}
        (self.out / 'drill.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        (self.out / 'requests.json').write_text(json.dumps(self.log, indent=1, default=str) + '\n')
        return result


class GateBrakeDrill(CriticalPathDrill):
    def run(self):
        f, p = self.f, self.p
        a, b, _ = self.users()
        self.boot_cps([a, b])
        cycles = p['GATE_CYCLES'] if self.control_name != 'one-cycle' else 1
        self.fund(a, b)
        bid = order_id_of(self.one(order_call(a, 'BUY', LOW_BUY, 5 * UNIT, 'rest-bid')))
        rows = []
        for n in range(cycles):
            row = {'cycle': n + 1}
            ask = order_id_of(self.one(order_call(b, 'SELL', 97 * FP, 4 * UNIT, 'rest-ask')))
            if self.control_name == 'funding-before-gate':
                row['funding'] = self.calls([money_call(a, 'deposit', QUOTE_ASSET, 1 * FP, 'gate-deposit'),
                                             money_call(a, 'withdraw', QUOTE_ASSET, 1 * FP, 'gate-withdraw')])
            # a fill in flight: a crossing pair sent right before the gate closes
            qty = (n + 1) * 7 * UNIT
            row['in_flight'] = [order_id_of(r) for r in self.calls([order_call(b, 'SELL', PAIR_PRICE, qty, 'in-flight'),
                                                                   order_call(a, 'BUY', PAIR_PRICE, qty, 'in-flight')])]
            if self.control_name != 'skip-gate':
                meaning, _ = f.core('gate', 'probe-admin', market=0, state='SUSPENDED', reason='ADMIN')
                row['suspend'] = meaning
                row['suspend_seen_s'] = self.wait_gate('SUSPENDED')
            self.mark(f'cycle{n + 1}_suspended')
            refused = order_call(a, 'BUY', 85 * FP, 2 * UNIT, 'gate-create', retry=False)
            under = [refused,
                     {'user': a, 'method': 'PUT', 'path': f'/api/v2/orders/{bid}', 'key': new_key(), 'tag': 'gate-amend',
                      'retry': False, 'body': {'price': gateway_probe.money(81 * FP)}},
                     {'user': b, 'method': 'DELETE', 'path': f'/api/v2/orders/{ask}', 'key': new_key(), 'tag': 'gate-cancel'}]
            if self.control_name != 'funding-before-gate':
                under += [money_call(a, 'deposit', QUOTE_ASSET, 1 * FP, 'gate-deposit'),
                          money_call(a, 'withdraw', QUOTE_ASSET, 1 * FP, 'gate-withdraw')]
            under.append({'user': a, 'method': 'GET', 'path': '/api/v2/balances', 'tag': 'gate-balances', 'retry': False})
            row['under'] = self.calls(under)
            port = f.m['ports']['gateway_admin']
            row['ready'] = f.http('gw0', port, '/ready')
            row['ready_session'] = f.http('gw0', port, '/ready/session')
            self.sleep(p['GATE_HOLD_S'])
            if self.control_name != 'skip-gate':
                meaning, _ = f.core('gate', 'probe-admin', market=0, state='OPEN', reason='ADMIN')
                row['reopen'] = meaning
                row['open_seen_s'] = self.wait_gate('OPEN')
            self.mark(f'cycle{n + 1}_open')
            # the refused key sent again until decided (it was never stored), and a fresh create accepted
            refused_again = dict(refused, tag='gate-create-settle', retry=True)
            row['after'] = self.calls([refused_again, order_call(a, 'BUY', 82 * FP, 2 * UNIT, 'gate-open-create')])
            rows.append(row)
        self.record['cycles'] = rows
        self.cancel_all([a, b])
        self.mark('input_closed')
        observed = gate_cycles([r for r in self.tap_admission()])
        sequence = core_drills.GATE_SEQUENCE + GATE_AFTER * observed
        money, order, sample = self.oracle(sequence)
        lines = oracle_lines(money, order)
        lines.update(gate_lines(rows, sample, oracle_funding(self.log)))
        return self.finish(lines)

    def wait_gate(self, state):
        """Wait until the tap's last GLOBAL admission row has ``state`` (the gate verb's answer comes before the tap's row,
        and every call's gate state is read from the tap); the wait in seconds, or None at the bound."""
        seen, waited = self.wait_for(lambda: (self.f.tap_gate(0) or {}).get('state') == state, self.p['SMOKE_BOOK_WAIT_S'])
        return waited if seen else None

    def tap_admission(self):
        """The tap's admission rows so far (the GLOBAL gate's transitions), from the fixture's tap file."""
        path = Path(self.f.registry['tap']['path'])
        out = []
        for text in (path.read_text().splitlines() if path.exists() else []):
            try:
                entry = json.loads(text) if text.strip() else {}
            except ValueError:
                continue
            if entry.get('tap') == 'admission':
                out.append(entry['row'])
        return out


def gate_lines(rows, sample, funding):
    """The gate brake over the cycles that ran: the GLOBAL gate's SUSPENDED -> OPEN cycles in the tap (at least two); in each,
    under SUSPENDED: create and amend refused GATE_CLOSED, cancel accepted, balances answered, /ready failing on gate_open
    and /ready/session ready; a deposit and a withdrawal accepted with the gate SUSPENDED at send time; the fill in
    flight settled; OPEN again: a create accepted."""
    count = gate_cycles(sample.get('admission'))
    out = {'gate_suspended': line(count >= 1, {'cycles': count}, 'gate was never SUSPENDED'),
           'gate_cycles': consequence(line(count >= 2, {'cycles': count}, 'gate cycle ran once'), 'gate_suspended')}
    bad = []
    for row in rows:
        by = {r['tag']: r for r in row['under']}
        checks = {
            'create_refused': gate_closed(by.get('gate-create') or {}),
            'amend_refused': gate_closed(by.get('gate-amend') or {}),
            'cancel_accepted': (by.get('gate-cancel') or {}).get('status') == 200,
            'balances_answer': (by.get('gate-balances') or {}).get('status') == 200,
            'ready_gate_open_failing': row['ready'].get('status') == 503 and 'gate_open' in (row['ready'].get('body') or ''),
            'ready_session_ready': row['ready_session'].get('status') == 200,
            'create_after_open': all(200 <= r['status'] < 300 for r in row['after']),
        }
        failed = [k for k, v in checks.items() if not v]
        if failed:
            bad.append({'cycle': row['cycle'], 'failed': failed,
                        'answers': {r['tag']: [r['status'], _reply(r).get('code')] for r in row['under'] + row['after']},
                        'ready': [row['ready'].get('status'), (row['ready'].get('body') or '')[:160]],
                        'ready_session': row['ready_session'].get('status')})
    out['gate_rules'] = consequence(line(not bad and bool(rows), {'cycles_checked': len(rows), 'failed': bad},
                                         'gate rule broken under SUSPENDED'), 'gate_suspended')
    deposits = [r for r in funding if r['kind'] == 'deposit' and r['outcome'] == 'ACK' and r['gate'] == 'SUSPENDED']
    withdraws = [r for r in funding if r['kind'] == 'withdraw' and r['outcome'] == 'ACK' and r['gate'] == 'SUSPENDED']
    out['funding_under_suspended'] = consequence(line(bool(deposits) and bool(withdraws),
                                                      {'deposits': len(deposits), 'withdrawals': len(withdraws)},
                                                      'no deposit or withdrawal was sent under a suspended gate'),
                                                 'gate_suspended')
    settles = {(r.get('buyer'), r.get('seller'), r.get('trade')) for r in sample.get('money_journal') or [] if r.get('kind') == 'settle'}
    trades = {t['trade_id']: t for t in trades_of(sample)}
    unsettled = []
    for row in rows:
        sell, buy = row['in_flight']
        traded = [t for t in trades.values() if {t.get('taker_order'), t.get('maker_order')} == {sell, buy}]
        if not traded or not all(any(s[2] == t['trade_id'] for s in settles) for t in traded):
            unsettled.append({'cycle': row['cycle'], 'orders': [sell, buy], 'trades': [t['trade_id'] for t in traded]})
    out['in_flight_fill_settled'] = line(not unsettled and bool(rows), {'unsettled': unsettled}, 'fill in flight did not settle')
    return out


class HistoryLossDrill(CriticalPathDrill):
    def run(self):
        f, p = self.f, self.p
        a, b, _ = self.users()
        self.boot_cps([a, b])
        self.fund(a, b)
        self.pairs(a, b, 2, 1, tag='pair-before')
        cycles = 0 if self.control_name == 'never-down' else 1 if self.control_name == 'one-stop' else p['HISTORY_LOSS_CYCLES']
        outages = []
        for n in range(cycles):
            o = {'cycle': n + 1, 'down': f.history_databases_down(True)}
            self.mark(f'outage{n + 1}_down')
            o['pairs'] = [order_id_of(r) for r in self.pairs(a, b, p['HISTORY_DOWN_PAIRS'], 2, tag=f'pair-outage{n + 1}',
                                                             base_qty=3 + n)]
            o['reads'] = self.calls([{'user': a, 'method': 'GET', 'path': '/api/v2/orders/history?limit=5',
                                      'tag': 'history-down', 'retry': False} for _ in range(p['HISTORY_DOWN_READS'])])
            self.sleep(p['HISTORY_DOWN_S'])
            o['up'] = f.history_databases_down(False)
            self.mark(f'outage{n + 1}_up')
            o['projector'] = self.projector_back()
            head = self.core_head()
            o['catchup'] = self.wait_history(head or 0, p['HISTORY_CATCHUP_BOUND_S']) if head else {'caught_up': False, 'head': None}
            outages.append(o)
        if self.control_name == 'never-down':
            self.pairs(a, b, p['HISTORY_DOWN_PAIRS'], 2, tag='pair-no-outage', base_qty=3)
        self.record['outages'] = [{k: v for k, v in o.items() if k != 'reads'} for o in outages]
        judged_outages = outages
        if self.control_name == 'history-500':
            # a gateway that maps the history fault to 500 (a test copy of the recorded answers)
            judged_outages = [dict(o, reads=[dict(r, status=500 if r['status'] == 503 else r['status']) for r in o['reads']])
                              for o in outages]
        self.cancel_all([a, b])
        self.mark('input_closed')
        money, order, sample = self.oracle()
        lines = oracle_lines(money, order)
        lines['fills'] = fills_line(sample)
        lines.update(history_loss_lines(outages, judged_outages, sample, p['HISTORY_CATCHUP_BOUND_S']))
        orders_by_user = self.orders_by_user()
        orders = set().union(*orders_by_user.values()) if orders_by_user else set()
        head = max((e['seq'] for e in sample.get('core_events') or []), default=0)
        self.record['history_catchup'] = self.wait_history(head, p['SMOKE_HISTORY_CATCHUP_S'])
        rows, trails, fills, errors = self.history_view([a, b], orders_by_user)
        self.record['history_errors'] = errors
        lines['history'] = history_line(sample, orders, rows, trails, fills)
        return self.finish(lines)

    def core_head(self):
        meaning, reply = self.f.core('order-events', 'probe-admin', timeout=60, **{'from': 0, 'max': 0})
        return (reply or {}).get('last_seq') if meaning == 'ANSWERED' else None

    def projector_back(self):
        """The projection slots after a return: running, or exited and started again as their supervisor would (each
        exit code recorded; every exited slot is started before any is waited on)."""
        f = self.f
        out, started = {}, []
        for slot in ('pj0', 'pj1'):
            cid = f.registry['containers'].get(slot)
            if cid is None:
                continue
            state = f.inspect('container', cid)['State']
            out[slot] = {'running': state['Running']}
            if not state['Running']:
                out[slot].update(exit_code=state['ExitCode'], restarted=True)
                f.command(['docker', 'start', cid])
                f.record_fault({'kind': 'start', 'target': slot, 'container_id': cid, 'exit_code': state['ExitCode'],
                                'cause': 'order history database returned'})
                started.append(slot)
        for slot in started:
            f.wait_http(slot, f.m['ports']['projector_admin'], '/health', timeout=60)
        return out


def history_loss_lines(outages, judged_outages, sample, bound_s):
    """The history loss: the outages that ran (two; none is INCONCLUSIVE), history 503 HISTORY_UNAVAILABLE during each, creates and
    fills during each, and the projector at the core's head inside the bound after each return."""
    count = len(outages)
    out = {'history_outages': cycles_line(count, 'history database was never down', 'history loss ran once',
                                          inconclusive_when_none=True)}
    out['history_503'] = consequence(history_503_line(judged_outages), 'history_outages')
    trades = trades_of(sample)
    traded = {t.get('taker_order') for t in trades} | {t.get('maker_order') for t in trades}
    stopped = []
    for o in outages:
        orders = [x for x in o['pairs'] if x]
        if len(orders) != len(o['pairs']) or not orders or not all(x in traded for x in orders):
            stopped.append({'cycle': o['cycle'], 'orders': o['pairs'], 'filled': [x for x in orders if x in traded]})
    out['money_path_during_outage'] = consequence(line(not stopped and bool(outages), {'outages': count, 'stopped': stopped},
                                                       'creates or fills stopped while the history database was down'),
                                                  'history_outages')
    late = [{'cycle': o['cycle'], **{k: o['catchup'].get(k) for k in ('head', 'applied', 'waited_s')}}
            for o in outages if not o['catchup'].get('caught_up')]
    out['history_catchup'] = consequence(line(not late and bool(outages),
                                              {'bound_s': bound_s, 'late': late,
                                               'waited_s': [o['catchup'].get('waited_s') for o in outages]},
                                              'history did not catch up after the return'), 'history_outages')
    return out
