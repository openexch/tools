# SPDX-License-Identifier: Apache-2.0
"""The five gateway and stream drills on the product binaries (oe-gateway in gw0 and gw1, oe-stream in st0 and st1).

Every client runs in the probe container (gateway_probe.py, standard library only) and reaches the gateways and streams
over the fixture network; the fixture only starts, stops, freezes and kills containers and reads each role's own HTTP
endpoints. Each drill writes ``drill.json`` with its lines; a line that fails carries its text, a line whose witness is
missing makes the run INCONCLUSIVE, never PASS.

* ``gateway-kill-restart``: client load with keys across gw0 and gw1, streams on st0 and st1. gw0 is SIGKILLed mid-flight
  and restarted (external mode: only oe-gateway is killed; the driver in gw0's sidecar keeps running and the restarted
  gateway attaches to it); then the core leader is killed while unkeyed cancels of resting orders and armed stops are in flight;
  then the global gate is closed while stored keys are sent again. Every key ends with one order and its stored
  decision; gw1 is unaffected by gw0's kill; a stored acceptance is never answered ADMISSION_CLOSED; a re-offered cancel
  is never answered NOT_FOUND; the streams converge to the core; the money oracle is exact.
* ``stream-slow-consumer``: the a01 story under order flow with st0's inbound core egress thinned on the network (a slow
  consumer: its driver keeps sending status messages and its process keeps sending keepalives); the core's lowered
  egress ceiling closes that one session; the commit position keeps advancing; gw0, gw1 and st1 stay ready; with the
  throttle lifted st0 registers again and its clients converge.
* ``gateway-session-timeout``: oe-gateway in gw0 stopped with SIGSTOP under load (no keepalive; an embedded driver stops
  with it, the external driver in gw0's sidecar keeps running), then SIGCONT. The core closes the frozen session, never at the egress ceiling; apply is not paused; gw1 answers
  throughout; gw0 is ready again (reconnected, or exited 70 and restarted) and every key it held ends with one decision.
* ``fill-visibility-core``: n crossing pairs in a closed loop, on one gateway and stream and across two of each; the
  accept latency and the fill visibility are recorded as data, never as a pass criterion. Then fuzzed REST inputs (the
  treasury lane on, so a deposit of an unknown assetId meets the gateway's asset check): every one answered, the core's
  ingress decode counters unchanged. The money oracle runs after both, over every order the pairs and the fuzz made.
* ``tick-live-path``: a MARKET BUY with no budget and a stop order complete on the ME's ticks; with the forwarders
  stopped a MARKET BUY on the traded market must be answered 422 NO_REFERENCE_PRICE (INCONCLUSIVE while the core keeps
  its last tick with no age bound), and one on a market no tick ever priced is answered 422.

A control kind (``core_contracts.GATEWAY_KINDS[kind]['control']``) runs its drill with one rule switched off; the run
passes only when one line fails with the control's exact text.
"""
import json
import math
import os
from pathlib import Path
import shlex
import shutil
import time

from contracts import FP, Inconclusive, Violation, fingerprint
import core_contracts
import core_drills
import core_oracle
import core_scenarios
import gateway_probe
from gateway_shim import request_id, units
from oracle_model import BARRIER_COLLECTIONS
import order_oracle

STORED_TEXT = 'stored acceptance answered ADMISSION_CLOSED'
CANCEL_TEXT = 'successful cancel answered NOT_FOUND'
DECODE_TEXT = 'request unanswered: decode drop'
DECODE_COUNTERS = ['core_ingress_decode_rejects_total', 'core_ingress_schema_rejects_total',
                   'core_ingress_unknown_template_total', 'core_ingress_unhandled_template_total',
                   'core_ingress_apply_errors_total']
GATEWAY_SESSIONS = 'core_sessions{class="GATEWAY"}'
RESUMABLE_CLOSED = 'core_resumable_sessions_closed_total'
DISCARD_CLOSED = 'core_egress_discard_closes_total'
GATE_AFTER = [['SUSPENDED', 'ADMIN'], ['OPEN', 'ADMIN']]
# Prices of market 1 (BTC-USD, units of 10^-8): resting load BUYs far below the crossing pairs and the tick asks
REST_PRICE = 50 * FP
REOFFER_QUANTITY_BASE = 20              # the re-offered creates' quantities in UNITs: no other order of the side users has one
CUT_GATEWAYS = ('gw0', 'gw1')
PAIR_PRICE = 90 * FP
UNIT = FP // 1000
DRILL_RISK = {'per_sec': 1000, 'max_open': 5000, 'slippage_bps': 100, 'collar_bps': 5000}
USER_BASE = {'gateway-kill-restart': 82001, 'stream-slow-consumer': 83001, 'gateway-session-timeout': 85001,
             'fill-visibility-core': 86001, 'tick-live-path': 84001}


def control_of(manifest, name):
    """The control text of a control kind running ``name``, or None for a drill kind."""
    spec = core_contracts.GATEWAY_KINDS.get(manifest.get('manifest_kind')) or {}
    if spec.get('control') is None:
        return None
    if spec['control'] != name:
        raise Inconclusive(f'kind {manifest.get("manifest_kind")} is the control of {spec["control"]}, not of {name}')
    import gateway_drills
    return spec.get('control_text') or gateway_drills.CONTROL_TEXT[name]


def line(holds, detail, text=None, inconclusive=False):
    out = {'holds': bool(holds) and not inconclusive, 'detail': detail}
    if not out['holds'] and text:
        out['text'] = text
    if inconclusive:
        out['inconclusive'] = True
    return out


def percentiles(values):
    """n, min, p50, p90, p99, max of a list of numbers (nearest rank), or {'n': 0}."""
    v = sorted(x for x in values if x is not None)
    if not v:
        return {'n': 0}
    def rank(q):
        return v[min(len(v) - 1, max(0, math.ceil(q * len(v)) - 1))]
    return {'n': len(v), 'min': v[0], 'p50': rank(0.5), 'p90': rank(0.9), 'p99': rank(0.99), 'max': v[-1]}


def answer_code(row):
    reply = row.get('reply') if 'reply' in row else row.get('body')
    return reply.get('code') if isinstance(reply, dict) else None


# ------------------------------------------------------------------ the oracle sample from gateway answers

def create_row(key, user, body, answers):
    """One oracle create row per key (oracle_model): the decisive answer is the first 2xx (a duplicate one stands as a
    replay of the attempt whose ack was lost), else the first final reject, else UNKNOWN."""
    hi, lo = request_id(key)
    row = {'request': [hi, lo], 'user': user, 'market': int(body['marketId']), 'side': body['side'], 'type': body['type'],
           'tif': body['timeInForce'], 'price': units(body.get('price')) or 0, 'quantity': units(body['quantity']),
           'budget': units(body.get('budget')) or 0, 'stop_price': units(body.get('stopPrice')) or 0, 'display_qty': 0,
           'key': key}
    ok = [a for a in answers if 200 <= a['status'] < 300 and isinstance(a.get('reply'), dict)]
    final = [a for a in answers if a['status'] not in gateway_probe.RETRY_STATUSES and not 200 <= a['status'] < 300]
    if ok:
        r = ok[0]['reply']
        hold = r.get('hold') or {}
        reply = {'outcome': 'ACK', 'order': int(r['orderId']), 'duplicate': False,
                 'hold_asset': int(hold.get('assetId', 0)), 'hold_amount': units(hold.get('amount', '0')) or 0,
                 'status': r.get('status')}
        if r.get('duplicate'):
            reply['source'] = 'replay'
        row['reply'] = reply
    elif final:
        row['reply'] = {'outcome': 'REJECT', 'reason': (final[0].get('reply') or {}).get('reason')
                        if isinstance(final[0].get('reply'), dict) else None, 'status': final[0]['status']}
    else:
        row['reply'] = {'outcome': 'UNKNOWN'}
    return row


def creates_from(requests):
    """Oracle create rows from the probe's request records (POST /orders), one per key in first-send order."""
    by_key, order = {}, []
    for r in sorted(requests, key=lambda r: r['sent_ns']):
        if r.get('method', 'POST') != 'POST' or r.get('path', '/api/v2/orders') != '/api/v2/orders' or not r.get('key'):
            continue
        if not isinstance(r.get('body'), dict) or request_id(r['key']) is None:
            continue
        if r['key'] not in by_key:
            by_key[r['key']] = (r['user'], r['body'], [])
            order.append(r['key'])
        by_key[r['key']][2].append(r)
    return [create_row(k, *by_key[k]) for k in order]


def cancels_from(requests):
    """Oracle cancel rows from DELETE /orders/{id} records."""
    rows = []
    for r in sorted(requests, key=lambda r: r['sent_ns']):
        if r.get('method') != 'DELETE':
            continue
        oid = r['path'].rsplit('/', 1)[1]
        if not oid.isdigit():
            continue
        ids = request_id(r['key']) if r.get('key') else (0, 0)
        reply = r.get('reply') if isinstance(r.get('reply'), dict) else {}
        if r['status'] == 200:
            outcome = {'outcome': 'ACK', 'order': int(oid), 'duplicate': bool(reply.get('duplicate')),
                       'reoffered': bool(reply.get('reoffered'))}
        elif r['status'] in gateway_probe.RETRY_STATUSES:
            outcome = {'outcome': 'UNKNOWN'}
        else:
            outcome = {'outcome': 'REJECT', 'reason': reply.get('reason'), 'status': r['status']}
        rows.append({'request': list(ids), 'user': r['user'], 'order': int(oid), 'reply': outcome})
    return rows


def attempts_as_requests(attempts, rows):
    """The load's attempt lines in the request-record shape (method, path, body, reply)."""
    bodies = {r['key']: r['body'] for r in rows}
    return [{'method': 'POST', 'path': '/api/v2/orders', 'user': a['user'], 'key': a['key'], 'body': bodies.get(a['key']),
             'status': a['status'], 'reply': a.get('body'), 'sent_ns': a['sent_ns'], 'recv_ns': a['recv_ns'],
             'target': a.get('target')} for a in attempts]


# ------------------------------------------------------------------ the drill base

class GatewayDrill:
    sleep = staticmethod(time.sleep)
    clock = staticmethod(time.monotonic)

    def __init__(self, fixture, name, out_dir):
        import gateway_drills
        self.f, self.name, self.out = fixture, name, Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.spec = core_contracts.GATEWAY_KINDS.get(fixture.m.get('manifest_kind')) or {}
        self.s = gateway_drills.settings()
        # A control kind may set a drill size (recorded); an environment variable of the same name still wins
        for key, value in (self.spec.get('drill') or {}).items():
            if os.environ.get(key) in (None, ''):
                self.s[key] = value
        self.control = control_of(fixture.m, name)
        self.probe_dir = fixture.root / 'state' / 'probe'
        self.ledger = core_drills.Ledger()
        self.record = {'scenario': name, 'control': self.control, 'settings': self.s,
                       'manifest_kind': fixture.m.get('manifest_kind'), 'driver': self.driver(), 'phases': {}}

    def driver(self):
        name = self.f.m['slot_artifacts'].get('gw0') or self.f.m['slot_artifacts'].get('st0')
        return (self.f.m['artifacts'].get(name) or {}).get('driver')

    def mark(self, phase):
        self.record['phases'][phase] = time.time_ns()

    # ---------------------------------------------------------------- fixture and probe

    def boot(self, users, tap_s):
        f = self.f
        f.gateway_user_ids = sorted(users)
        f.start({'users': sorted(users), 'markets': [1, 2, 3, 4, 5], 'funding_for': 'a01-mix', 'seed': f.m['seed'] & 0xFFFFFFFF,
                 'risk': DRILL_RISK, 'tap_ms': tap_s * 1000})
        self.mark('booted')
        shutil.copyfile(Path(__file__).with_name('gateway_probe.py'), self.probe_dir / 'gateway_probe.py')
        (self.probe_dir / 'gw-keys.json').write_text(json.dumps({str(u): k for u, k in f.keys.api_keys(sorted(users)).items()}))
        f.secret_values = f.keys.secrets() | getattr(f, 'marketdata_secrets', set())
        self.record['slots'] = {k: f.slots.get(k) for k in sorted(core_contracts.GATEWAY_SLOTS)}
        self.record['status'] = self.status('gw1')
        self.record['core_behavior'] = f.registry.get('core_behavior')

    def gw(self, slot):
        return f'{self.f.m["nodes"][slot]}:{self.f.m["ports"]["gateway_http"]}'

    def st(self, slot):
        return f'{self.f.m["nodes"][slot]}:{self.f.m["ports"]["stream_ws"]}'

    def status(self, slot):
        response = self.f.http(slot, self.f.m['ports']['gateway_http'], '/api/v2/status')
        try:
            return json.loads(response.get('body') or 'null')
        except ValueError:
            return {'status': response.get('status'), 'body': response.get('body')}

    def ready(self, slot):
        port = self.f.m['ports']['gateway_admin' if slot.startswith('gw') else 'stream_admin']
        response = self.f.http(slot, port, '/ready')
        return response.get('status'), (response.get('body') or '')[:200]

    def probe(self, verb, plan, name, timeout):
        """One probe verb in the foreground (``docker exec``); returns its output file's JSON."""
        (self.probe_dir / f'{name}-plan.json').write_text(json.dumps(plan))
        out = self.probe_dir / f'{name}.json'
        argv = ['python3', '-I', '/data/gateway_probe.py', verb, '--plan', f'/data/{name}-plan.json', '--keys', '/data/gw-keys.json',
                '--out', f'/data/{name}.json']
        result = self.f.execute('probe', argv, timeout=timeout, check=False)
        if not out.exists():
            raise Inconclusive(f'probe {verb} wrote nothing (exit {result.returncode}): {(result.stderr or "")[-300:]}')
        return json.loads(out.read_text())

    def probe_bg(self, argv, name):
        cid = self.f.registry['containers']['probe']; self.f.inspect('container', cid)
        self.f.command(['docker', 'exec', '-d', cid, 'sh', '-c', shlex.join(argv) + f' > /data/{name}.out 2>&1'])

    def probe_with_go(self, verb, plan, name, ready_bound_s, done_bound_s, between=None):
        """One probe verb in the background that writes ``<name>.ready`` and waits for ``<name>.go`` (probe handshake);
        ``between(ready)`` runs in that gap. Returns (ready info, between's result, the output file's JSON)."""
        d = self.probe_dir
        for n in (f'{name}.ready', f'{name}.go', f'{name}.json'):
            (d / n).unlink(missing_ok=True)
        (d / f'{name}-plan.json').write_text(json.dumps(plan))
        self.probe_bg(['python3', '-I', '/data/gateway_probe.py', verb, '--plan', f'/data/{name}-plan.json', '--keys',
                       '/data/gw-keys.json', '--out', f'/data/{name}.json'], name)
        deadline = self.clock() + ready_bound_s
        while not (d / f'{name}.ready').exists():
            if self.clock() >= deadline:
                (d / f'{name}.go').write_text('go\n')
                raise Inconclusive(f'probe {verb} never got ready within {ready_bound_s} s: {self.probe_log(name)}')
            self.sleep(0.2)
        ready = json.loads((d / f'{name}.ready').read_text())
        try:
            extra = between(ready) if between else None
        finally:
            (d / f'{name}.go').write_text('go\n')
        out = d / f'{name}.json'
        deadline = self.clock() + done_bound_s
        while True:
            if out.exists():
                try:
                    return ready, extra, json.loads(out.read_text())
                except ValueError:
                    pass                         # still being written
            if self.clock() >= deadline:
                raise Inconclusive(f'probe {verb} wrote nothing within {done_bound_s} s: {self.probe_log(name)}')
            self.sleep(0.5)

    def probe_log(self, name):
        path = self.probe_dir / f'{name}.out'
        return path.read_text()[-300:] if path.exists() else ''

    def start_streams(self, conns, name='streams', seconds=1800):
        plan = {'conns': conns, 'stop_file': f'/data/{name}.stop', 'seconds': seconds}
        (self.probe_dir / f'{name}-plan.json').write_text(json.dumps(plan))
        self.probe_bg(['python3', '-I', '/data/gateway_probe.py', 'streams', '--plan', f'/data/{name}-plan.json', '--keys',
                       '/data/gw-keys.json', '--out', f'/data/{name}.json'], name)
        return name

    def stop_streams(self, name, bound_s=30):
        (self.probe_dir / f'{name}.stop').write_text('stop\n')
        out = self.probe_dir / f'{name}.json'
        deadline = self.clock() + bound_s
        while self.clock() < deadline:
            if out.exists():
                return json.loads(out.read_text())
            self.sleep(0.5)
        raise Inconclusive(f'the stream clients wrote no final state within {bound_s} s')

    def start_load(self, rows, targets, name, rate):
        s = self.s
        (self.probe_dir / f'{name}-story.json').write_text(json.dumps(rows))
        argv = ['python3', '-I', '/data/gateway_probe.py', 'load', '--targets', ','.join(targets), '--keys', '/data/gw-keys.json',
                '--story', f'/data/{name}-story.json', '--out', f'/data/{name}-attempts.jsonl', '--done-file',
                f'/data/{name}.done', '--concurrency', str(s['GW_CONCURRENCY']), '--retry-bound-s', str(s['GW_RETRY_BOUND_S']),
                '--attempt-s', str(s['GW_ATTEMPT_S']), '--rate', str(rate)]
        self.probe_bg(argv, name)
        return {'attempts': self.probe_dir / f'{name}-attempts.jsonl', 'done': self.probe_dir / f'{name}.done'}

    def wait_done(self, load, bound_s):
        deadline = self.clock() + bound_s
        while not load['done'].exists() and self.clock() < deadline:
            self.sleep(1)
        return load['done'].exists()

    def leader_metrics(self):
        snap = {}
        for i in range(3):
            try:
                snap[f'ae{i}'] = self.f.metrics(f'ae{i}', self.f.m['ports']['ae_metrics'])
            except Inconclusive as error:
                snap[f'ae{i}'] = {'error': str(error)}
        leader = next((r for r, v in snap.items() if v.get('core_cluster_role') == 2.0), None)
        return leader, (snap.get(leader) or {}) if leader else {}

    def sample(self, extra=()):
        leader, m = self.leader_metrics()
        row = {'at_ns': time.time_ns(), 'leader': leader, 'commit': m.get('core_log_position'),
               'gateway_sessions': m.get(GATEWAY_SESSIONS), 'resumable_closed': m.get(RESUMABLE_CLOSED),
               'discard_closed': m.get(DISCARD_CLOSED), 'egress_pending_bytes': m.get('core_egress_pending_bytes'),
               'egress_back_pressured': m.get('core_egress_back_pressured_total')}
        for slot in extra:
            row['ready_' + slot] = self.ready(slot)[0]
            row['epoch_' + slot] = self.session_epoch(slot)
        return row

    def session_epoch(self, slot):
        """The session epoch (sessions opened since start) on the role's own /health, or None."""
        port = self.f.m['ports']['gateway_admin' if slot.startswith('gw') else 'stream_admin']
        response = self.f.http(slot, port, '/health')
        try:
            return ((json.loads(response.get('body') or 'null') or {}).get('session') or {}).get('epoch')
        except (ValueError, AttributeError):
            return None

    def converge(self, name, expected_users, bound_s):
        """Wait until every stream client's open set equals the core's open orders of its user (order-dump), or the bound;
        then stop the clients. Returns the line (convergence())."""
        deadline = self.clock() + bound_s
        while True:
            core = self.core_open(expected_users)
            progress = self.probe_dir / f'{name}.progress.json'
            views = json.loads(progress.read_text()) if progress.exists() else []
            if views and not stream_diffs(views, core) or self.clock() >= deadline:
                break
            self.sleep(1)
        final = self.stop_streams(name)
        return convergence(final, self.core_open(expected_users))

    def core_open(self, users):
        meaning, dump = self.f.core('order-dump', 'probe-admin', timeout=180)
        if meaning != 'ANSWERED':
            raise Inconclusive('order-dump ' + meaning)
        out = {u: set() for u in users}
        for o in (dump or {}).get('orders') or []:
            if o.get('user') in out:
                out[o['user']].add(str(o['order']))
        return out

    # ---------------------------------------------------------------- the money oracle over the gateway's answers

    def money(self, creates, cancels, gate_sequence, amends=(), funding=()):
        """The core's money oracle (core_oracle) over a two-observation barrier, with the creates, cancels and amends
        rebuilt from what the gateways answered, and the funding the drill sent through the treasury lane (``funding``,
        after the genesis rows). Returns (money verdict, order verdict); the sample is kept."""
        f = self.f
        f.stop_tap()
        deadline = self.clock() + 60
        while True:
            try:
                tap_summary = f.read_tap_summary()
                break
            except Inconclusive:
                if self.clock() > deadline:
                    raise
                self.sleep(1)
        tap = core_scenarios.read_tap(Path(f.registry['tap']['path']))
        tap['order_event'], replay = core_drills.replay_event_gaps(f, tap['order_event'], tap_summary.get('transitions'))
        known = {c['reply']['order'] for c in creates if c['reply'].get('outcome') == 'ACK'}

        def observation():
            obs = core_scenarios.observe(f)
            rows, report = core_drills.backfill(tap['dispatch'], obs['pending']['entries'], obs['me_journal'], known,
                                                obs['core']['pending_dispatch']['head'])
            obs['dispatch_tap'] = tap['dispatch'] + rows
            obs['backfill'] = report
            return obs
        names = [n for n in BARRIER_COLLECTIONS if n != 'core_events']
        first = observation()
        deadline = self.clock() + 90
        while True:
            self.sleep(1)
            second = observation()
            if all(fingerprint(first[n]) == fingerprint(second[n]) for n in names):
                break
            if self.clock() > deadline:
                raise Inconclusive('barrier did not settle: two observations 1 s apart differ for 90 s')
            first = second
        sample = {'version': 'core-sample-v2', 'markets': {str(m): {'base': m, 'quote': 0} for m in range(1, 6)},
                  'risk': f.registry['risk'], 'genesis': f.registry['genesis_snapshot'], 'counters': second['counters'],
                  'funding': [{k: v for k, v in r.items() if k != 'reply'} for r in list(f.registry['funding']) + list(funding)],
                  'creates': [{k: v for k, v in c.items() if k != 'key'} for c in creates], 'amends': list(amends),
                  'cancels': cancels,
                  'core_events': tap['order_event'], 'admission': tap['admission'], 'dispatch_tap': second['dispatch_tap'],
                  **{k: second[k] for k in ['core', 'me_journal', 'me_journal_seq', 'me_open_legs', 'money_journal',
                                            'money_journal_legs']},
                  'faults': {'settle_fault': max(g['core_settle_faults_total'] for g in second['gauges'].values()),
                             'settle_rejected': max(g['core_settle_rejects_total'] for g in second['gauges'].values()),
                             'order_fault': len(tap['order_fault']),
                             'quarantined': sum(1 for e in tap['order_event'] if e['kind'] == 'QUARANTINED')},
                  'declared': core_drills.declared_block(self.ledger, int(f.genesis_id(1), 16), None, gate_sequence),
                  'tap_continuity': {'transitions': tap_summary['transitions'], 'summary': tap_summary['summary'],
                                     'line': tap_summary['line'], 'backfill': second['backfill'], 'event_replay': replay}}
        observations = []
        for obs in (first, second):
            view = dict(sample, **{k: obs[k] for k in ['core', 'me_journal', 'me_open_legs', 'money_journal',
                                                       'money_journal_legs', 'dispatch_tap']})
            observations.append({n + '_digest': fingerprint(view[n]) for n in BARRIER_COLLECTIONS})
        sample['barrier'] = {'input_closed': True, 'samples': observations}
        (self.out / 'core-sample.json').write_text(json.dumps(sample, indent=1, default=str) + '\n')
        money, order = core_oracle.judge(sample), order_oracle.judge(sample)
        (self.out / 'oracle.json').write_text(json.dumps({'money': money, 'order': order}, indent=1, default=str) + '\n')
        return money, order

    def money_line(self, money, order):
        failing = sorted(k for k, v in (money.get('rules') or {}).items() if v.get('status') == 'FAIL')
        open_ = sorted(k for k, v in (money.get('rules') or {}).items() if v.get('status') == 'INCONCLUSIVE')
        self.record['order_oracle'] = {'status': order.get('status'),
                                       'not_pass': {k: v.get('status') for k, v in (order.get('rules') or {}).items()
                                                    if v.get('status') != 'PASS'}}
        return line(money['status'] == 'PASS', {'status': money['status'], 'failing': failing, 'inconclusive': open_},
                    'money oracle not exact', inconclusive=money['status'] == 'INCONCLUSIVE')

    # ---------------------------------------------------------------- the verdict

    def finish(self, lines):
        if self.control is not None:
            failed = [k for k, v in lines.items() if not v['holds'] and v.get('text') == self.control]
            status = 'PASS' if failed else 'FAIL'
            control = {'expected_text': self.control, 'failed_lines': failed,
                       'observed': {k: v.get('text') for k, v in lines.items() if not v['holds']}}
        else:
            control = None
            if any(v.get('inconclusive') for v in lines.values()):
                status = 'INCONCLUSIVE'
            else:
                status = 'PASS' if all(v['holds'] for v in lines.values()) else 'FAIL'
        result = {'status': status, 'lines': lines, 'record': self.record}
        if control:
            result['control'] = control
        failing = [v.get('text') or k for k, v in lines.items() if not v['holds']]
        if status != 'PASS' or control:
            result['error'] = '; '.join(failing) if failing else None
        (self.out / 'drill.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        return result


def stream_diffs(views, core):
    """[(user, target, missing, extra)] where a client's open set differs from the core's open orders of its user."""
    out = []
    for v in views:
        want = core.get(v['user'])
        if want is None:
            continue
        have = set(v.get('open') or [])
        if have != want or v.get('awaiting_snapshot'):
            out.append({'user': v['user'], 'target': v['target'], 'missing': sorted(want - have)[:5],
                        'extra': sorted(have - want)[:5], 'awaiting_snapshot': v.get('awaiting_snapshot')})
    return out


CONVERGE_TEXT = 'client state differs from oracle'


def convergence(final, core):
    """The stream clients' final views against the core's open orders. Every user must hold at least one open order in
    the core, or equal sets prove nothing (INCONCLUSIVE)."""
    diffs = stream_diffs(final, core)
    empty = sorted(u for u, v in core.items() if not v)
    detail = {'connections': len(final), 'differing': diffs[:10], 'resyncs': sum(v['resyncs'] for v in final),
              'closes': sum(len(v['closes']) for v in final), 'snapshots': sum(v['snapshots'] for v in final),
              'core_open': {str(u): len(v) for u, v in core.items()}, 'users_without_open_orders': empty}
    return line(bool(final) and not diffs, detail, CONVERGE_TEXT, inconclusive=not diffs and (not final or bool(empty)))


def _jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    for text in p.read_text().splitlines():
        try:
            rows.append(json.loads(text))
        except ValueError:
            continue
    return rows


# ------------------------------------------------------------------ gateway-kill-restart

class KillRestart(GatewayDrill):
    def run(self):
        f, s = self.f, self.s
        if not f.m.get('netfilter_helper'):
            raise Inconclusive('the kill-restart drill cuts the leader\'s egress to gw1 on the network: it needs the netfilter helper')
        base = USER_BASE[self.name]
        users = list(range(base, base + s['GW_USERS']))
        side_users = [base + 100 + n for n in range(s['CANCEL_USERS'])]       # cancels and the gate witness
        self.boot(users + side_users, s['GW_TAP_S'])
        # One story: the paced load's rows, then the burst's (unpaced, first sent to gw0, so requests are in flight on gw0
        # when it is killed). Quantities stay unique per row, so (user, quantity) names one key across both.
        table = gateway_probe.story(s['GW_REQUESTS'] + s['GW_BURST_REQUESTS'], users, f.m['seed'], UNIT, REST_PRICE,
                                    resend_every=s['GW_RESEND_EVERY'])
        rows, burst = table[:s['GW_REQUESTS']], table[s['GW_REQUESTS']:]
        for k, row in enumerate(burst):
            row['i'] = 2 * (s['GW_REQUESTS'] + k)          # the load sends attempt n of row i to target (i + n) % 2: gw0 first
        stream_users = users[:s['GW_STREAM_USERS']]
        self.start_streams([{'user': u, 'target': self.st(st)} for u in stream_users for st in ('st0', 'st1')])
        load = self.start_load(rows, [self.gw('gw0'), self.gw('gw1')], 'load', s['GW_RATE'])
        started = self.clock()
        self.mark('load_started')
        kill = self.kill_gw0(load, started, burst)
        self.sleep(s['GW1_WINDOW_SLACK_S'])           # gw1's window after gw0's restart, before the leader kill
        leader = self.kill_leader(side_users)
        if kill.get('killed') and leader.get('killed_ns'):
            kill['window_end_ns'] = min(kill['ready_ns'] + int(s['GW1_WINDOW_SLACK_S'] * 1e9), leader['killed_ns'])
        gate = self.gate_phase(rows + burst, [load] + ([kill['burst']] if kill.get('burst') else []), side_users)
        done = self.wait_done(load, s['GW_LOAD_BOUND_S']) and (not kill.get('burst') or self.wait_done(kill['burst'], s['GW_LOAD_BOUND_S']))
        attempts = _jsonl(load['attempts']) + (_jsonl(kill['burst']['attempts']) if kill.get('burst') else [])
        rows = rows + burst
        kill.pop('burst', None)
        self.mark('load_done')
        lines = {}
        streams_line = self.converge('streams', stream_users, s['CONVERGE_BOUND_S'])
        resends = [a for a in gate.get('log', []) if a.get('tag') == 'stored']
        resend_attempts = [{'i': -1, 'key': a['key'], 'user': a['user'], 'quantity': units(a['body']['quantity']),
                            'attempt': 99, 'phase': 'resend', 'target': a['target'], 'status': a['status'],
                            'body': a['reply'], 'sent_ns': a['sent_ns'], 'recv_ns': a['recv_ns']} for a in resends]
        meaning, dump = f.core('order-dump', 'probe-admin', timeout=180)
        orders = (dump or {}).get('orders') or []
        result = gateway_probe.key_oracle(rows, attempts + resend_attempts, orders, nothing_fills=True)
        self.record['key_oracle'] = result
        self.record['kill_window'] = kill_report(kill, attempts, self.gw('gw0'))
        failures = result['failures']
        lines['key_oracle'] = line(result['verdict'] == 'PASS', {k: result[k] for k in ('verdict', 'keys', 'answered', 'failures',
                                                                                        'resends', 'retried_keys', 'not_live_keys')},
                                   failures[0] if failures else 'keys unanswered',
                                   inconclusive=result['verdict'] == 'INCONCLUSIVE')
        window = self.record['kill_window']
        lines['gw0_killed_mid_flight'] = line(window.get('in_flight_at_kill', 0) > 0 and
                                              window['in_flight_keys_answered'] == window['in_flight_at_kill'],
                                              {k: window.get(k) for k in ('in_flight_at_kill', 'in_flight_keys_answered',
                                                                         'in_flight_answers', 'in_flight_acks_lost')},
                                              'a request cut by the gw0 kill was never answered',
                                              inconclusive=not window.get('in_flight_at_kill'))
        lines['gw1_unaffected'] = self.gw1_line(kill, attempts)
        lines['gw0_ready_after_restart'] = line(kill.get('ready_s') is not None and kill['ready_s'] <= s['GW_READY_BOUND_S'],
                                                {k: kill.get(k) for k in ('ready_s', 'killed_at_attempts', 'down_s')},
                                                'gw0 not ready inside its bound after the restart',
                                                inconclusive=not kill.get('killed'))
        if kill.get('driver') is not None or self.driver() == 'external':
            lines['driver_survives_gw0_kill'] = driver_line(kill)
        lines['leader_changed'] = line(leader.get('new_leader') is not None,
                                       {k: leader.get(k) for k in ('old_leader', 'new_leader', 'election_s', 'gateways_ready_s')},
                                       'no new core leader', inconclusive=leader.get('new_leader') is None)
        lines['stored_acceptance_answered'] = stored_line(gate)
        lines.update(cancel_lines(leader.get('cancels') or {}, leader.get('egress_cut')))
        lines['create_reoffer_once'] = reoffer_create_line(leader.get('cancels') or {}, orders)
        lines['streams_converge'] = streams_line
        lines['load_finished'] = line(done, {'attempts': len(attempts), 'requests': len(rows)}, 'load did not finish inside its bound',
                                      inconclusive=not done)
        requests = (attempts_as_requests(attempts, rows) + [dict(a, body=a['body']) for a in gate.get('log', [])]
                    + gate.get('settle', []) + (leader.get('cancels') or {}).get('requests', []))
        settled_fresh = {r['key'] for r in gate.get('settle', []) if gateway_probe.settled(r['status'])}
        self.record['gate_settle'] = {'fresh_keys': len({r['key'] for r in gate.get('settle', [])}),
                                      'decided': len(settled_fresh),
                                      'answers': sorted({(r['status'], answer_code(r)) for r in gate.get('settle', [])}, key=str)}
        creates = creates_from(requests)
        cancels = cancels_from(requests)
        money, order = self.money(creates, cancels, core_drills.GATE_SEQUENCE + (GATE_AFTER if gate.get('closed') else []))
        lines['money_exact'] = self.money_line(money, order)
        (self.out / 'attempts.jsonl').write_text(''.join(json.dumps(a) + '\n' for a in attempts))
        (self.out / 'requests.json').write_text(json.dumps(requests) + '\n')
        return self.finish(lines)

    def kill_gw0(self, load, started, burst):
        """Once the paced load has sent GW_KILL_AFTER_ATTEMPTS attempts, start the burst (unpaced, gw0 first) and SIGKILL gw0
        after GW_BURST_KILL_AFTER of its attempts, with requests in flight on it; hold it down; restart; time its /ready."""
        f, s = self.f, self.s
        while self.clock() - started < s['GW_LOAD_BOUND_S'] and not load['done'].exists():
            if len(_jsonl(load['attempts'])) >= s['GW_KILL_AFTER_ATTEMPTS']:
                break
            self.sleep(0.2)
        if load['done'].exists():
            return {'killed': False, 'reason': 'the load finished before the kill point'}
        # External mode: the sidecar driver as seen before the burst (read here, so the kill still lands mid-flight)
        sidecar = f.driver_sidecar('gw0')
        driver = {'before': f.slot_driver('gw0')} if sidecar else None
        if sidecar:
            driver['gw0_pid1'] = f.execute('gw0', ['cat', '/proc/1/comm'], timeout=15, check=False).stdout.strip()
        quick = self.start_load(burst, [self.gw('gw0'), self.gw('gw1')], 'burst', 0)
        deadline = self.clock() + 60
        while len(_jsonl(quick['attempts'])) < s['GW_BURST_KILL_AFTER'] and not quick['done'].exists() and self.clock() < deadline:
            self.sleep(0.01)
        n = len(_jsonl(load['attempts'])) + len(_jsonl(quick['attempts']))
        killed_ns = time.time_ns()
        row = self.ledger.open('kill', 'gw0', f.kill('gw0'))
        kill_done_ns = time.time_ns()
        if sidecar:
            driver['while_down'] = f.slot_driver('gw0')
        self.sleep(s['GW_DOWN_S'])
        start = self.clock()
        restart = f.restart('gw0', ready_timeout=s['GW_READY_BOUND_S'])
        ready_s = round(self.clock() - start, 3)
        self.ledger.heal(row, 'restart', {'ready': True})
        f.close_fault('gw0')
        self.mark('gw0_ready')
        if sidecar:
            driver['after_restart'] = f.slot_driver('gw0')
            driver['restart_witness'] = restart.get('driver')
            try:
                health = json.loads(f.http('gw0', f.m['ports']['gateway_admin'], '/health').get('body') or 'null') or {}
            except ValueError:
                health = {}
            driver['gw0_health_driver'] = health.get('driver')
        return {'killed': True, 'burst': quick, 'killed_ns': killed_ns, 'kill_done_ns': kill_done_ns, 'killed_at_attempts': n, 'down_s': s['GW_DOWN_S'], 'ready_s': ready_s,
                'ready_ns': time.time_ns(), 'restart': {k: restart.get(k) for k in ('started_at',)}, 'driver': driver}

    def gw1_line(self, kill, attempts):
        """gw1's answers between gw0's kill and gw0's ready plus GW1_WINDOW_SLACK_S: no error, p99 inside its bound."""
        s = self.s
        if not kill.get('killed'):
            return line(False, kill, inconclusive=True)
        # From gw0's kill to gw0 ready plus the slack, never past the core leader kill (that window is the election's)
        lo, hi = kill['killed_ns'], kill.get('window_end_ns', kill['ready_ns'] + int(s['GW1_WINDOW_SLACK_S'] * 1e9))
        rows = [a for a in attempts if a['target'] == self.gw('gw1') and lo <= a['sent_ns'] <= hi]
        errors = [a for a in rows if a['status'] == 0 or a['status'] >= 500]
        lat = percentiles([(a['recv_ns'] - a['sent_ns']) / 1e6 for a in rows])
        detail = {'requests': len(rows), 'errors': len(errors), 'error_statuses': sorted({a['status'] for a in errors}),
                  'latency_ms': lat, 'p99_bound_ms': s['GW_P99_BOUND_MS']}
        if len(rows) < s['GW1_MIN_REQUESTS']:
            return line(False, detail, inconclusive=True)
        return line(not errors and lat['p99'] <= s['GW_P99_BOUND_MS'], detail, 'gw1 affected by the gw0 kill')

    def kill_leader(self, side_users):
        """Rest orders and arm stops for the side users through gw1; on the probe's signal, kill the core leader inside the
        window of unkeyed cancels; wait for the new leader and both gateways ready; restart the killed member."""
        f, s = self.f, self.s
        signals = self.probe_dir
        for name in ('cancels.ready', 'cancels.go'):
            (signals / name).unlink(missing_ok=True)
        plan = {'gw': self.gw('gw1'), 'users': side_users, 'market': 1, 'rest_price': REST_PRICE, 'stop_price': 200 * FP,
                'quantity': 10 * UNIT, 'per_user': s['CANCEL_PER_USER'], 'signal_dir': '/data', 'window_s': s['CANCEL_WINDOW_S'],
                'wait_go_s': 120, 'request_bound_s': 90, 'unknown_order': 9_000_000_000, 'reoffer_gw': self.gw('gw0'),
                'reoffer_creates': [{'user': u, 'quantity': (REOFFER_QUANTITY_BASE + n) * UNIT} for u in side_users
                                    for n in range(s['REOFFER_CREATES_PER_USER'])]}
        (self.probe_dir / 'cancels-plan.json').write_text(json.dumps(plan))
        self.probe_bg(['python3', '-I', '/data/gateway_probe.py', 'cancels', '--plan', '/data/cancels-plan.json', '--keys',
                       '/data/gw-keys.json', '--out', '/data/cancels.json'], 'cancels')
        deadline = self.clock() + 120
        while not (signals / 'cancels.ready').exists() and self.clock() < deadline:
            self.sleep(0.2)
        old, _ = self.leader_metrics()
        out = {'old_leader': old}
        if old is None or not (signals / 'cancels.ready').exists():
            out['error'] = 'no leader or the cancel phase never got ready'
            (signals / 'cancels.go').write_text('go\n')
            return out
        # The leader's egress to gw1 is cut before the cancels go (dropped as it arrives at gw1: a drop at the leader's
        # own output fails its sends, which the core treats as fatal): a cancel offered before the kill is committed and
        # applied, its answer never reaches gw1, and gw1 offers it again to the new leader, where it meets its own
        # effect. That re-offer is the case the cancel re-offer rule exists for. The rule names the old leader's
        # address, so the new leader's egress passes; it is deleted once the new leader is known.
        # The same cut at gw0, which sends keyed creates once each in the same window: a create committed before the kill
        # is offered again by gw0 to the new leader under its own request id, which must meet its stored decision.
        cut = ['-w', '2', '-{}', 'INPUT', '-p', 'udp', '-s', f.m['nodes'][old], '--dport', str(f.GATEWAY_RESPONSE_PORT),
               '-j', 'DROP']
        for g in CUT_GATEWAYS:
            f.netfilter(g, [a.replace('{}', 'A') if a == '-{}' else a for a in cut])
            f.record_fault({'kind': 'egress_cut', 'target': g, 'from': old})
        out['egress_cut'] = {'member': old, 'to': [f'{g} {f.m["nodes"][g]}:{f.GATEWAY_RESPONSE_PORT}' for g in CUT_GATEWAYS],
                             'at_ns': time.time_ns()}
        (signals / 'cancels.go').write_text('go\n')
        self.sleep(s['CANCEL_KILL_AT_S'])
        killed_ns = time.time_ns()
        row = self.ledger.open('kill', old, f.kill(old, heal_bound_s=600))
        started = self.clock()
        new, election = None, None
        while self.clock() - started < s['ELECTION_BOUND_S']:
            leader, _ = self.leader_metrics()
            if leader is not None and leader != old and f.ready_body(leader)[0] == 200:
                new, election = leader, round(self.clock() - started, 3)
                break
            self.sleep(0.2)
        out.update(killed_ns=killed_ns, new_leader=new, election_s=election)
        out['egress_cut']['rule_counters'] = {g: [l for l in f.netfilter(g, ['-w', '2', '-L', 'INPUT', '-v', '-n', '-x']).splitlines()
                                                  if 'DROP' in l][:2] for g in CUT_GATEWAYS}
        for g in CUT_GATEWAYS:
            f.netfilter(g, [a.replace('{}', 'D') if a == '-{}' else a for a in cut])
        out['egress_cut']['lifted_ns'] = time.time_ns()
        ready_at = None
        while self.clock() - started < s['ELECTION_BOUND_S'] + s['GW_READY_BOUND_S']:
            if all(self.ready(g)[0] == 200 for g in ('gw0', 'gw1')):
                ready_at = round(self.clock() - started, 3)
                break
            self.sleep(0.5)
        out['gateways_ready_s'] = ready_at
        result = self.probe_dir / 'cancels.json'
        deadline = self.clock() + 180
        while not result.exists() and self.clock() < deadline:
            self.sleep(0.5)
        out['cancels'] = json.loads(result.read_text()) if result.exists() else {}
        f.restart(old, ready_timeout=180)
        self.ledger.heal(row, 'restart', {'ready': True})
        f.close_fault(old)
        self.mark('leader_cycle_done')
        return out

    def gate_phase(self, rows, loads, side_users):
        """Close the global gate; send every key the load already had answered 2xx once more to both gateways (its stored
        acceptance must come back), plus fresh keys of the side users (the witness that the gate is closed); reopen."""
        f, s = self.f, self.s
        attempts = [a for load in loads for a in _jsonl(load['attempts'])]
        answered = {a['key'] for a in attempts if 200 <= a['status'] < 300}
        stored = [r for r in rows if r['key'] in answered][:s['GW_GATE_RESEND']]
        cut = [r for r in rows if r['key'] in {a['key'] for a in attempts if a['target'] == self.gw('gw0') and a['status'] == 0}
               and r['key'] in answered]
        chosen = {r['key']: r for r in cut + stored}
        rng = __import__('random').Random(f.m['seed'] + 7)
        fresh = [{'key': str(__import__('uuid').UUID(int=rng.getrandbits(128), version=4)), 'user': side_users[n % len(side_users)],
                  'body': gateway_probe.order_body(1, 'BUY', 'LIMIT', 'GTC', REST_PRICE, (n + 1) * UNIT)}
                 for n in range(s['GW_GATE_FRESH'])]
        meaning, reply = f.core('gate', 'probe-admin', market=0, state='SUSPENDED', reason='ADMIN')
        out = {'close': meaning, 'stored_keys': len(chosen), 'cut_keys': len(cut), 'closed': meaning == 'ANSWERED'}
        self.mark('gate_closed')
        try:
            log = self.probe('resend', {'rows': list(chosen.values()), 'targets': [self.gw('gw0'), self.gw('gw1')],
                                        'fresh': fresh}, 'resend', timeout=600)
        finally:
            self.sleep(s['GW_GATE_HOLD_S'])
            meaning, reply = f.core('gate', 'probe-admin', market=0, state='OPEN', reason='ADMIN')
            out['reopen'] = meaning
            self.mark('gate_open')
        out['log'] = log
        # The witness keys the closed gate refused are sent again with their key until decided, so no create of the run
        # stays of unknown outcome for the order oracle
        out['settle'] = self.probe('settle', {'rows': fresh, 'targets': [self.gw('gw0'), self.gw('gw1')],
                                              'bound_s': s['GW_GATE_SETTLE_BOUND_S']}, 'settle',
                                   timeout=len(fresh) * (s['GW_GATE_SETTLE_BOUND_S'] + 2 * s['GW_ATTEMPT_S']) + 120)
        return out


DRIVER_RUNNING = ('R', 'S', 'D')


def driver_line(kill):
    """External mode: the SIGKILL hit oe-gateway only. gw0's sidecar driver ran through the kill and the restart (same
    container, same StartedAt, no restart, its pid 1 an aeronmd running while gw0 was down; gw0's own pid 1 is not a
    driver), and the restarted gateway attached to it
    (the restart witness names the same driver; gw0's /health shows that driver dir connected)."""
    d = kill.get('driver')
    if not kill.get('killed') or not d:
        return line(False, {'killed': kill.get('killed'), 'driver': d}, inconclusive=True)
    seen = [d.get('before') or {}, d.get('while_down') or {}, d.get('after_restart') or {}]
    same = len({(x.get('container'), x.get('started_at'), x.get('restart_count')) for x in seen}) == 1
    running = all(x.get('running') and x.get('state') in DRIVER_RUNNING and x.get('comm') == 'aeronmd' for x in seen)
    running = running and d.get('gw0_pid1') not in (None, '', 'aeronmd')
    health = d.get('gw0_health_driver') or {}
    attached = (health.get('mode') == 'external' and health.get('connected') is True and health.get('dir') == '/dev/shm/aeron-gw0'
                and (d.get('restart_witness') or {}).get('reused') is True)
    detail = {'driver_container': seen[0].get('container'), 'driver_started_at': [x.get('started_at') for x in seen],
              'driver_state': [x.get('state') for x in seen], 'driver_comm': [x.get('comm') for x in seen], 'gw0_pid1': d.get('gw0_pid1'),
              'restart_witness': d.get('restart_witness'), 'gw0_health_driver': health}
    return line(same and running and attached, detail, 'gw0 driver did not survive the gateway kill or was not reused')


def kill_report(kill, attempts, gw0):
    if not kill.get('killed'):
        return kill
    # In flight: sent to gw0 before the kill had taken effect, no answer, cut at or after the kill was sent
    done = kill.get('kill_done_ns', kill['killed_ns'])
    cut = [a for a in attempts if a['target'] == gw0 and a['status'] == 0 and a['sent_ns'] <= done and a['recv_ns'] >= kill['killed_ns']]
    keys = {a['key'] for a in cut}
    final, replayed = {}, set()
    for a in sorted(attempts, key=lambda a: a['sent_ns']):
        if a['key'] in keys and gateway_probe.settled(a['status']) and a['key'] not in final:
            final[a['key']] = a['status']
            if isinstance(a.get('body'), dict) and a['body'].get('duplicate'):
                replayed.add(a['key'])       # the core had accepted the cut attempt: its ack was lost with gw0
    return dict(kill, in_flight_at_kill=len(cut), in_flight_keys_answered=len(final), in_flight_answers=sorted(set(final.values())),
                in_flight_acks_lost=len(replayed))


def stored_line(gate):
    """A key whose acceptance is stored, sent again while the global gate is closed, is answered 200 with its stored
    orderId, never ADMISSION_CLOSED; a fresh key in the same window is refused ADMISSION_CLOSED (the closure's witness)."""
    log = gate.get('log') or []
    stored = [r for r in log if r.get('tag') == 'stored']
    fresh = [r for r in log if r.get('tag') == 'fresh']
    closed = [r for r in stored if r['status'] == 503 and answer_code(r) == 'ADMISSION_CLOSED']
    other = [r for r in stored if r['status'] != 200 and r not in closed]
    witness = [r for r in fresh if r['status'] == 503 and answer_code(r) == 'ADMISSION_CLOSED']
    detail = {'gate_close': gate.get('close'), 'stored_sent': len(stored), 'admission_closed': len(closed),
              'not_200': sorted({(r['status'], answer_code(r)) for r in other}), 'fresh_sent': len(fresh),
              'fresh_refused_closed': len(witness), 'cut_keys': gate.get('cut_keys')}
    if closed:
        return line(False, detail, STORED_TEXT)
    if not stored or not witness:
        return line(False, detail, inconclusive=True)
    return line(not other, detail, 'stored acceptance not answered 200')


def reoffer_create_line(cancels, orders, market=1):
    """Keyed creates sent once each through gw0 across the leader kill, the old leader's egress to gw0 cut: one live order
    per key (a re-offer under a new request id makes a second order); every create answered; holds only when at least
    one re-offer met its own stored decision (an answer 200 ``duplicate``), else the rule was never exercised
    (INCONCLUSIVE)."""
    sent = [r for r in cancels.get('requests') or [] if r.get('tag') == 'reoffer-create']
    owned = {}
    for o in orders:
        if o.get('market') == market:
            owned.setdefault((o.get('user'), o.get('quantity')), []).append(o)
    counts = {r['key']: len(owned.get((r['user'], units(r['body']['quantity'])), [])) for r in sent}
    second = sorted(k for k, n in counts.items() if n > 1)
    unanswered = [r['key'] for r in sent if not gateway_probe.settled(r['status'])]
    accepted = [r for r in sent if 200 <= r['status'] < 300]
    not_live = [r['key'] for r in accepted if counts[r['key']] == 0]
    met = [r for r in accepted if isinstance(r.get('reply'), dict) and r['reply'].get('duplicate')]
    detail = {'sent': len(sent), 'statuses': sorted({r['status'] for r in sent}), 'duplicate_answers': len(met),
              'second_order_keys': len(second), 'unanswered': len(unanswered), 'not_live': len(not_live)}
    if second:
        return line(False, detail, gateway_probe.SECOND_ORDER)
    if unanswered or not_live:
        return line(False, detail, 'a re-offered create unanswered or without its order')
    return line(bool(met), detail, 'no re-offered create met its stored decision', inconclusive=not met)


def cancel_lines(cancels, egress_cut=None):
    """Unkeyed cancels of own resting orders and armed stops in flight across a leader kill, the leader's egress to the
    gateway cut first: never 404 (a re-offered cancel whose first offer took effect answers 200 reoffered with status
    NOT_OPEN); a keyed cancel's replay is PENDING_CANCEL; a first offer of an unknown id stays 404. The never-404 line
    holds only when at least one re-offer met its own first offer's effect (else the rule was never exercised:
    INCONCLUSIVE)."""
    log = cancels.get('requests') or []
    sent = [r for r in log if (r.get('tag') or '').startswith('cancel-')]
    not_found = [r for r in sent if r['status'] == 404]
    reoffered = [r for r in sent if r['status'] == 200 and isinstance(r.get('reply'), dict) and r['reply'].get('reoffered')]
    met_effect = [r for r in reoffered if r['reply'].get('status') == 'NOT_OPEN']
    statuses = {}
    for r in sent:
        reply = r.get('reply') if isinstance(r.get('reply'), dict) else {}
        key = f'{r["status"]} {reply.get("code") or reply.get("status")}'
        statuses[key] = statuses.get(key, 0) + 1
    keyed = [r for r in log if (r.get('tag') or '').startswith('keyed-')]
    unknown = [r for r in log if r.get('tag') == 'unknown']
    detail = {'targets': len(cancels.get('targets') or []), 'sent': len(sent), 'statuses': statuses,
              'reoffered': len(reoffered), 'reoffer_met_first_effect': len(met_effect), 'not_found': len(not_found),
              'egress_cut': egress_cut}
    out = {'cancel_never_not_found': line(sent and not not_found and met_effect, detail, CANCEL_TEXT,
                                          inconclusive=not sent or (not not_found and not met_effect))}
    replay = keyed[-1] if len(keyed) == 2 else None
    out['keyed_cancel_replays'] = line(replay is not None and replay['status'] == 200 and isinstance(replay.get('reply'), dict)
                                       and replay['reply'].get('status') == 'PENDING_CANCEL' and replay['reply'].get('duplicate'),
                                       {'answers': [(r['status'], r.get('reply')) for r in keyed]},
                                       'keyed cancel did not replay PENDING_CANCEL', inconclusive=replay is None)
    out['unknown_cancel_not_found'] = line(len(unknown) == 1 and unknown[0]['status'] == 404,
                                           {'answers': [(r['status'], answer_code(r)) for r in unknown]},
                                           'first-offer cancel of an unknown id not 404', inconclusive=not unknown)
    return out


# ------------------------------------------------------------------ stream-slow-consumer

class SlowConsumer(GatewayDrill):
    def run(self):
        f, s = self.f, self.s
        if not f.m.get('netfilter_helper'):
            raise Inconclusive('the slow-consumer drill thins st0 on the network: it needs the netfilter helper')
        import gateway_drills
        users = gateway_drills.SLOW_USERS
        self.boot(users, s['SLOW_STORY_S'] + s['SLOW_CLOSE_BOUND_S'] + 600)
        stream_users = users[:s['SLOW_STREAM_USERS']]
        self.start_streams([{'user': u, 'target': self.st(st)} for u in stream_users for st in ('st0', 'st1')])
        rested = self.rest_orders(stream_users)
        clean = ('gw0', 'gw1', 'st1')
        watched = clean + ('st0',)
        first = self.sample(watched)
        story = f.start_story({'script': 'a01-mix', 'seed': f.m['seed'] & 0xFFFFFFFF, 'seconds': s['SLOW_STORY_S'],
                               'rate': s['SLOW_STORY_RATE'], 'users': ','.join(map(str, users))}, name='story')
        self.sleep(s['SLOW_THROTTLE_AFTER_S'])
        rule = ['-w', '2', '-{}', 'INPUT', '-p', 'udp', '--dport', str(f.GATEWAY_RESPONSE_PORT), '-m', 'statistic', '--mode',
                'random', '--probability', '%.2f' % (s['SLOW_DROP_PERCENT'] / 100), '-j', 'DROP']
        f.netfilter('st0', [a.replace('{}', 'A') if a == '-{}' else a for a in rule])
        throttled_ns = time.time_ns()
        self.mark('throttled')
        f.record_fault({'kind': 'throttle', 'target': 'st0', 'drop_percent': s['SLOW_DROP_PERCENT']})
        samples, closed_at = [first], None
        deadline = self.clock() + s['SLOW_CLOSE_BOUND_S']
        while self.clock() < deadline:
            self.sleep(s['SAMPLE_S'])
            row = self.sample(watched)
            samples.append(row)
            if session_closes(first, row)['total']:
                closed_at = row['at_ns']
                break
        if closed_at is not None:
            # Still throttled: wait until st0 itself shows the close (not ready, or a new session epoch), so the closed
            # session is shown to be st0's and not inferred from the session count
            deadline = self.clock() + s['SLOW_ST0_CLOSE_SEEN_BOUND_S']
            while not st0_saw_close(samples, first, closed_at) and self.clock() < deadline:
                self.sleep(s['SAMPLE_S'])
                samples.append(self.sample(watched))
        counted = f.netfilter('st0', ['-w', '2', '-L', 'INPUT', '-v', '-n', '-x'])
        f.netfilter('st0', [a.replace('{}', 'D') if a == '-{}' else a for a in rule])
        lifted_ns = time.time_ns()
        self.mark('throttle_lifted')
        start = self.clock()
        st0_ready = None
        while self.clock() - start < s['SLOW_REREGISTER_BOUND_S']:
            samples.append(self.sample(watched))
            if samples[-1].get('ready_st0') == 200:
                st0_ready = round(self.clock() - start, 3)
                break
            self.sleep(s['SAMPLE_S'])
        story_exit = self.wait_file(story['exit'], s['SLOW_STORY_S'] + 180)
        samples.append(self.sample(watched))
        lines = {}
        closes = session_closes(first, samples[-1])
        delta = closes['total']
        self.record['throttle'] = {'started_ns': throttled_ns, 'closed_ns': closed_at, 'lifted_ns': lifted_ns,
                                   'close_s': None if closed_at is None else round((closed_at - throttled_ns) / 1e9, 3),
                                   'ceiling_bytes': (f.m.get('core_jvm_properties') or {}).get('core.egress.max.capacity.bytes',
                                                                                              'core default (16 MiB)'),
                                   'port': f.GATEWAY_RESPONSE_PORT, 'drop_percent': s['SLOW_DROP_PERCENT'],
                                   'rule_counters': counted.splitlines()[:6],
                                   'peak_pending_bytes': max((r.get('egress_pending_bytes') or 0) for r in samples)}
        lines['slow_session_closed'] = line(closed_at is not None and delta == 1,
                                            {'counters': [RESUMABLE_CLOSED, DISCARD_CLOSED], 'delta': delta,
                                             'resumable_closed_delta': closes['resumable_closed'],
                                             'discard_closed_delta': closes['discard_closed'], 'path': closes['path'],
                                             'close_s': self.record['throttle']['close_s'],
                                             'bound_s': s['SLOW_CLOSE_BOUND_S']}, 'slow session not closed within bound')
        lines['closed_session_is_st0'] = st0_close_line(samples, first, closed_at, lifted_ns, clean)
        commits = [r['commit'] for r in samples if r['commit'] is not None]
        flat = sum(1 for a, b in zip(commits, commits[1:]) if b <= a)
        lines['commit_advances'] = line(len(commits) >= 2 and commits[-1] > commits[0],
                                        {'samples': len(commits), 'flat_intervals': flat}, 'core commit position stalled')
        unclean = [(r['at_ns'], k, r[k]) for r in samples for k in r if k in {'ready_' + c for c in clean} and r[k] != 200]
        lines['others_clean'] = line(not unclean, {'samples': len(samples), 'not_ready': unclean[:10]},
                                     'gw0, gw1 or st1 not ready while st0 was slow')
        lines['st0_registers_again'] = line(st0_ready is not None, {'ready_s': st0_ready, 'bound_s': s['SLOW_REREGISTER_BOUND_S']},
                                            'throttled stream did not register again')
        lines['story_ran'] = line(story_exit == 0, {'exit': story_exit}, 'story did not finish', inconclusive=story_exit != 0)
        lines['clients_converge'] = self.converge('streams', stream_users, s['CONVERGE_BOUND_S'])
        lines['clients_converge']['detail']['rested'] = rested
        self.record['samples'] = samples
        return self.finish(lines)

    def rest_orders(self, stream_users):
        """SLOW_REST_PER_USER BUYs per stream user at REST_PRICE, below every price the a01 story trades at (its sells
        cross at 80.00), placed before the story through gw1: they stay open across st0's close, so the clients'
        convergence compares non-empty sets."""
        s = self.s
        rng = __import__('random').Random(self.f.m['seed'] + 11)
        rows = [{'key': str(__import__('uuid').UUID(int=rng.getrandbits(128), version=4)), 'user': u, 'tag': 'rest',
                 'body': gateway_probe.order_body(1, 'BUY', 'LIMIT', 'GTC', REST_PRICE, (n + 1) * UNIT)}
                for u in stream_users for n in range(s['SLOW_REST_PER_USER'])]
        log = self.probe('place', {'rows': rows, 'target': self.gw('gw1')}, 'rest', timeout=60 + 30 * len(rows))
        accepted = [r for r in log if 200 <= r['status'] < 300]
        if len(accepted) != len(rows):
            raise Inconclusive(f'resting orders of the stream users not accepted: {sorted({(r["status"], answer_code(r)) for r in log}, key=str)}')
        return {'orders': len(accepted), 'per_user': s['SLOW_REST_PER_USER'], 'price': REST_PRICE}

    def wait_file(self, path, bound_s):
        deadline = self.clock() + bound_s
        while self.clock() < deadline:
            if Path(path).exists():
                text = Path(path).read_text().strip()
                return int(text) if text.lstrip('-').isdigit() else text
            self.sleep(1)
        return None


CLOSE_PATHS = {'resumable_closed': 'ceiling (resumable session closed at the egress ceiling)',
               'discard_closed': 'not connected (egress offer failed after a delivery: discard close)'}


def session_closes(first, row):
    """The core's session closes between two samples, on either path: the egress ceiling (``resumable_closed``) or a
    failed offer after a delivery (``discard_closed``, the NOT_CONNECTED path). Each delta is None when the counter is
    unreadable in either sample; ``total`` sums the readable ones (None when neither is), ``path`` names those that
    moved."""
    out, total = {}, None
    for key in CLOSE_PATHS:
        a, b = first.get(key), row.get(key)
        out[key] = None if a is None or b is None else b - a
        if out[key] is not None:
            total = (total or 0) + out[key]
    out['total'] = total
    out['path'] = [CLOSE_PATHS[k] for k in CLOSE_PATHS if out[k]] or None
    return out


def st0_saw_close(samples, first, closed_at):
    """st0 itself shows a closed session after the core's close: /ready not 200, or its session epoch past the first."""
    for r in samples:
        if closed_at is None or r['at_ns'] < closed_at:
            continue
        if r.get('ready_st0') not in (None, 200):
            return True
        if first.get('epoch_st0') is not None and (r.get('epoch_st0') or 0) > first['epoch_st0']:
            return True
    return False


def st0_close_line(samples, first, closed_at, lifted_ns, clean):
    """The closed session is st0's: between the close and the lift st0 reads not ready or opens a new session, while the
    session epoch of gw0, gw1 and st1 never moves."""
    window = [r for r in samples if closed_at is not None and closed_at <= r['at_ns'] <= lifted_ns]
    moved = sorted({k for r in samples for k in ['epoch_' + c for c in clean]
                    if first.get(k) is not None and r.get(k) is not None and r[k] != first[k]})
    seen = st0_saw_close(window, first, closed_at)
    detail = {'window_samples': len(window), 'st0_ready': [r.get('ready_st0') for r in window][:20],
              'st0_epoch': [first.get('epoch_st0')] + [r.get('epoch_st0') for r in window][:20], 'other_epochs_moved': moved}
    if closed_at is None:
        return line(False, detail, inconclusive=True)
    return line(seen and not moved, detail, 'closed session not shown to be st0\'s')


# ------------------------------------------------------------------ gateway-session-timeout

class SessionTimeout(GatewayDrill):
    def run(self):
        f, s = self.f, self.s
        base = USER_BASE[self.name]
        users_a = list(range(base, base + s['GW_USERS'] // 2))
        users_b = list(range(base + 50, base + 50 + s['GW_USERS'] // 2))
        self.boot(users_a + users_b, s['GW_TAP_S'])
        rows_a = gateway_probe.story(s['TIMEOUT_REQUESTS'], users_a, f.m['seed'], UNIT, REST_PRICE, resend_every=0)
        rows_b = gateway_probe.story(s['TIMEOUT_REQUESTS'], users_b, f.m['seed'] + 1, UNIT, REST_PRICE, resend_every=0)
        load_a = self.start_load(rows_a, [self.gw('gw0')], 'load-a', s['TIMEOUT_RATE'])
        load_b = self.start_load(rows_b, [self.gw('gw1')], 'load-b', s['TIMEOUT_RATE'])
        self.sleep(s['TIMEOUT_FREEZE_AFTER_S'])
        before = self.sample()
        freeze = self.freeze_gw0()
        frozen_ns = time.time_ns()
        self.mark('frozen')
        samples = [before]
        while (time.time_ns() - frozen_ns) / 1e9 < s['TIMEOUT_FREEZE_S']:
            self.sleep(s['SAMPLE_S'])
            samples.append(self.sample())
        late = f.process_states('gw0')              # the end of the freeze: gw0 still stopped, the driver as it is now
        thaw = f.thaw_main('gw0')
        thawed_ns = time.time_ns()
        self.mark('thawed')
        branch = self.after_thaw()
        samples.append(self.sample())
        done_a = self.wait_done(load_a, s['GW_LOAD_BOUND_S'])
        done_b = self.wait_done(load_b, s['GW_LOAD_BOUND_S'])
        after = self.sample()
        attempts_a, attempts_b = _jsonl(load_a['attempts']), _jsonl(load_b['attempts'])
        lines = {}
        sessions = [r['gateway_sessions'] for r in samples[1:-1] if r['gateway_sessions'] is not None]
        dropped = before['gateway_sessions'] is not None and sessions and min(sessions) <= before['gateway_sessions'] - 1
        lines['frozen_session_closed'] = line(dropped, {'gateway_sessions_before': before['gateway_sessions'],
                                                        'while_frozen': sessions, 'bound_s': s['TIMEOUT_FREEZE_S']},
                                              'frozen session not closed within bound')
        d_res = (after['resumable_closed'] or 0) - (before['resumable_closed'] or 0)
        d_dis = (after['discard_closed'] or 0) - (before['discard_closed'] or 0)
        self.record['close_path'] = {'not_connected_path': d_dis > 0, 'discard_closes_delta': d_dis,
                                     'by_elimination': 'session timeout' if dropped and d_dis == 0 else None,
                                     'note': 'the core logs no session-close reason; the timeout path is named by elimination',
                                     'freeze': 'SIGSTOP of pid 1 (oe-gateway), SIGCONT at the thaw',
                                     'driver_mode': self.driver(), 'driver_while_frozen': [freeze.get('driver_state'),
                                                                                           late.get('driver')],
                                     'gw0_at_freeze_end': late.get('main'),
                                     'driver_after_thaw': thaw.get('driver_state'), 'gw0_branch': branch.get('branch'),
                                     'exit_code': branch.get('exit_code')}
        if self.driver() == 'external':
            # The slot's staged aeronmd is its own process: it must keep running while oe-gateway is stopped
            running = ('R', 'S', 'D')
            lines['driver_runs_while_frozen'] = line(freeze.get('driver_state') in running and late.get('driver') in running
                                                     and late.get('main') == 'T',
                                                     {'driver_state': [freeze.get('driver_state'), late.get('driver')],
                                                      'gateway_state': [freeze.get('main_state'), late.get('main')]},
                                                     'slot driver frozen with the gateway')
        lines['not_closed_at_ceiling'] = line(d_res == 0, {'resumable_closed_delta': d_res, 'discard_closes_delta': d_dis},
                                              'frozen session closed at the egress ceiling')
        commits = [r['commit'] for r in samples if r['commit'] is not None]
        lines['apply_not_paused'] = line(len(commits) >= 3 and commits[-1] > commits[0],
                                         {'samples': len(commits), 'flat_intervals': sum(1 for a, b in zip(commits, commits[1:]) if b <= a)},
                                         'core commit position stalled')
        window = [a for a in attempts_b if frozen_ns <= a['sent_ns'] <= thawed_ns]
        bad = [a for a in window if a['status'] == 0 or a['status'] >= 500]
        lines['gw1_answers_throughout'] = line(window and not bad, {'requests': len(window), 'errors': len(bad),
                                                                     'latency_ms': percentiles([(a['recv_ns'] - a['sent_ns']) / 1e6 for a in window])},
                                               'gw1 request unanswered while gw0 frozen', inconclusive=not window)
        lines['gw0_ready_after_thaw'] = line(branch.get('ready_s') is not None, branch, 'gw0 not ready after the thaw')
        # The requests gw0 held across the freeze (sent before the thaw, answered or cut after the freeze began): what gw0
        # answered them (2xx/4xx, 504, or nothing when it exited at the thaw), and how each key ended
        held = [a for a in attempts_a if a['sent_ns'] <= thawed_ns and a['recv_ns'] >= frozen_ns]
        answers = {}
        for a in held:
            code = (a.get('body') or {}).get('code') if isinstance(a.get('body'), dict) else None
            answers[f'{a["status"]} {code}'] = answers.get(f'{a["status"]} {code}', 0) + 1
        held_keys = {a['key'] for a in held}
        final = {}
        for a in attempts_a:
            if a['key'] in held_keys and gateway_probe.settled(a['status']):
                final.setdefault(a['key'], set()).add(gateway_probe.decision(a))
        split = [k for k, v in final.items() if len(v) > 1]
        self.record['held_by_gw0'] = {'requests': len(held), 'gw0_answers': answers, 'keys': len(held_keys),
                                      'keys_decided': len(final), 'branch': branch.get('branch')}
        lines['held_requests_decided_once'] = line(held and len(final) == len(held_keys) and not split,
                                                   self.record['held_by_gw0'], 'a held request decided twice or never',
                                                   inconclusive=not held)
        meaning, dump = f.core('order-dump', 'probe-admin', timeout=180)
        orders = (dump or {}).get('orders') or []
        result_a = gateway_probe.key_oracle(rows_a, attempts_a, orders, nothing_fills=True)
        result_b = gateway_probe.key_oracle(rows_b, attempts_b, orders, nothing_fills=True)
        failures = result_a['failures'] + result_b['failures']
        verdicts = {result_a['verdict'], result_b['verdict']}
        lines['one_decision_per_key'] = line(verdicts == {'PASS'}, {'gw0_keys': {k: result_a[k] for k in ('verdict', 'keys', 'answered', 'failures')},
                                                                    'gw1_keys': {k: result_b[k] for k in ('verdict', 'keys', 'answered', 'failures')}},
                                             failures[0] if failures else 'keys unanswered', inconclusive='INCONCLUSIVE' in verdicts and not failures)
        lines['load_finished'] = line(done_a and done_b, {'gw0_load': done_a, 'gw1_load': done_b}, 'load did not finish',
                                      inconclusive=not (done_a and done_b))
        requests = attempts_as_requests(attempts_a, rows_a) + attempts_as_requests(attempts_b, rows_b)
        money, order = self.money(creates_from(requests), [], core_drills.GATE_SEQUENCE)
        lines['money_exact'] = self.money_line(money, order)
        self.record['samples'] = samples
        (self.out / 'requests.json').write_text(json.dumps(requests) + '\n')
        return self.finish(lines)

    def freeze_gw0(self):
        """SIGSTOP oe-gateway in gw0 (pid 1 of its container): its keepalives stop; an embedded driver stops with it, a
        staged aeronmd (external) keeps running."""
        s = self.s
        return self.f.freeze_main('gw0', duration_s=s['TIMEOUT_FREEZE_S'], heal_bound_s=s['GW_READY_BOUND_S'] + 60)

    def after_thaw(self):
        """gw0 after the thaw: it exits 70 (its own liveness guards saw the freeze) and is restarted, or it stays up and
        reads ready again on a new session."""
        f, s = self.f, self.s
        cid = f.registry['containers']['gw0']
        start = self.clock()
        while self.clock() - start < s['GW_READY_BOUND_S']:
            state = f.inspect('container', cid)['State']
            if not state['Running']:
                code = state['ExitCode']
                f.record_fault({'kind': 'exit', 'target': 'gw0', 'exit_code': code})
                f.restart('gw0', ready_timeout=s['GW_READY_BOUND_S'])
                f.close_fault('gw0')
                return {'branch': 'exit and restart', 'exit_code': code, 'ready_s': round(self.clock() - start, 3)}
            if self.ready('gw0')[0] == 200:
                f.close_fault('gw0')
                return {'branch': 'reconnected', 'ready_s': round(self.clock() - start, 3)}
            self.sleep(0.5)
        return {'branch': None, 'ready_s': None}


# ------------------------------------------------------------------ fill-visibility-core

class FillVisibility(GatewayDrill):
    def run(self):
        f, s = self.f, self.s
        base = USER_BASE[self.name]
        makers = list(range(base, base + 2))
        takers = list(range(base + 10, base + 12))
        fuzzer = base + 30
        self.boot(makers + takers + [fuzzer], s['FILL_TAP_S'])
        layouts = [{'name': 'one gateway and stream', 'maker': makers[0], 'taker': takers[0], 'maker_gw': self.gw('gw0'),
                    'taker_gw': self.gw('gw0'), 'maker_st': self.st('st0'), 'taker_st': self.st('st0')},
                   {'name': 'across two of each', 'maker': makers[1], 'taker': takers[1], 'maker_gw': self.gw('gw0'),
                    'taker_gw': self.gw('gw1'), 'maker_st': self.st('st0'), 'taker_st': self.st('st1')}]
        muting = self.control == FILL_TEXT        # the stream-muted control; the asset-check control runs the fuzz
        plan = {'pairs': s['FILL_PAIRS'], 'layouts': layouts, 'market': 1, 'price': PAIR_PRICE, 'quantity': 10 * UNIT,
                'visible_bound_s': s['FILL_VISIBLE_BOUND_S'], 'booked_bound_s': s['FILL_VISIBLE_BOUND_S'],
                'poll_ms': s['FILL_POLL_MS'], 'stop_after_failures': 1 if muting else 0, 'signal_dir': '/data',
                'wait_go_s': 120}

        def mute(ready):
            # The control: both streams frozen once every client holds its snapshot (no frame leaves them), thawed after
            muted = []
            if muting:
                for slot in ('st0', 'st1'):
                    f.pause(slot, duration_s=600, heal_bound_s=120)
                    muted.append(slot)
            self.mark('pairs_started')
            return muted
        try:
            at_go, muted, result = self.probe_with_go('pairs', plan, 'pairs', ready_bound_s=4 * s['FILL_VISIBLE_BOUND_S'] + 60,
                                                      done_bound_s=s['FILL_PAIRS'] * (3 * s['FILL_VISIBLE_BOUND_S'] + 30) + 120,
                                                      between=mute)
        finally:
            for slot in ('st0', 'st1'):
                if f.inspect('container', f.registry['containers'][slot])['State'].get('Paused'):
                    self.thaw(slot)
        self.mark('pairs_done')
        self.record['muted'] = muted
        rows = result['pairs']
        accept = [(r['accepted_ns'] - r['sent_ns']) / 1e6 for r in rows if r.get('taker_order')]
        fill = [(r['fill_frame_ns'] - r['accepted_ns']) / 1e6 for r in rows if r.get('fill_frame_ns')]
        gone = [(r['orders_gone_ns'] - r['accepted_ns']) / 1e6 for r in rows if r.get('orders_gone_ns')]
        dist = {'n_pairs': len(rows), 'accept_ms': percentiles(accept), 'fill_frame_ms': percentiles(fill),
                'orders_gone_ms': percentiles(gone), 'by_layout': {}, 'order_polls': result.get('order_polls'),
                'order_poll_statuses': result.get('order_poll_statuses'), 'driver': self.driver(),
                'definition': {'accept': 'request sent to 201 received', 'fill_frame': "201 received to the taker's fill frame",
                               'orders_gone': '201 received to GET /orders no longer listing the order (polled from the 201 '
                                              'in its own thread every poll_ms; an identical read inside the gateway\'s '
                                              'GATEWAY_QUERY_MIN_INTERVAL_MS is answered from its read cache, so this '
                                              'instant includes that interval)'},
                'poll_ms': s['FILL_POLL_MS']}
        for lay in layouts:
            sub = [r for r in rows if r['layout'] == lay['name']]
            dist['by_layout'][lay['name']] = {
                'n': len(sub), 'accept_ms': percentiles([(r['accepted_ns'] - r['sent_ns']) / 1e6 for r in sub if r.get('taker_order')]),
                'fill_frame_ms': percentiles([(r['fill_frame_ns'] - r['accepted_ns']) / 1e6 for r in sub if r.get('fill_frame_ns')]),
                'orders_gone_ms': percentiles([(r['orders_gone_ns'] - r['accepted_ns']) / 1e6 for r in sub if r.get('orders_gone_ns')])}
        (self.out / 'fill-visibility.json').write_text(json.dumps(dist, indent=1) + '\n')
        (self.out / 'pairs.json').write_text(json.dumps(result) + '\n')
        self.record['distribution'] = dist
        self.record['streams_at_go'] = at_go.get('streams')
        lines = fill_lines(rows, s['FILL_PAIRS'], at_go.get('streams') or [], muting, s['FILL_VISIBLE_BOUND_S'])
        if muting:
            return self.finish(lines)
        # The fuzz runs before the money barrier: the orders it made (a shape-valid create the core accepts rests) and
        # every request the core decided are in the oracle's sample, so money is judged over everything the run did
        fuzz_lines, fuzz_log = self.fuzz(fuzzer, rows)
        decided = core_decided(fuzz_log)
        self.record['fuzz']['in_oracle'] = {'requests': len(decided), 'creates_acked': sum(
            1 for r in decided if r['method'] == 'POST' and 200 <= r['status'] < 300)}
        creates = creates_from(result['requests']) + creates_from(decided)
        money, order = self.money(creates, cancels_from(decided), core_drills.GATE_SEQUENCE)
        lines['money_exact'] = self.money_line(money, order)
        lines.update(fuzz_lines)
        return self.finish(lines)

    def thaw(self, slot):
        f, s = self.f, self.s
        f.unpause(slot)
        cid = f.registry['containers'][slot]
        start = self.clock()
        while self.clock() - start < s['GW_READY_BOUND_S']:
            if not f.inspect('container', cid)['State']['Running']:
                f.restart(slot, ready_timeout=s['GW_READY_BOUND_S'])
                break
            if self.ready(slot)[0] == 200:
                break
            self.sleep(0.5)
        f.close_fault(slot)

    def fuzz(self, user, pairs_rows):
        """Fuzzed REST inputs across the routes through gw1, before the money barrier: every one answered (never 0, 5xx or
        504), the leader's ingress decode counters unchanged, the nil UUID, an unknown field, a userId and an unknown
        assetId answered 400. Returns (lines, the request log)."""
        f, s = self.f, self.s
        _, before = self.leader_metrics()
        lane = (self.health('gw1') or {}).get('treasuryLane')
        live = next((r['maker_order'] for r in pairs_rows if r.get('maker_order')), '1')
        log = self.probe('fuzz', {'gw': self.gw('gw1'), 'user': user, 'seed': f.m['seed'] & 0xFFFFFFFF, 'count': s['FUZZ_CASES'],
                                  'user_order': live, 'request_bound_s': 30,
                                  'unknown_asset': f.GATEWAY_FUZZ_UNKNOWN_ASSET}, 'fuzz', timeout=900)
        self.sleep(2)
        _, after = self.leader_metrics()
        moved = {k: (after.get(k) or 0) - (before.get(k) or 0) for k in DECODE_COUNTERS}
        unanswered = [r for r in log if r['status'] == 0 or r['status'] >= 500]
        statuses = {}
        for r in log:
            statuses.setdefault(r['tag'], {}).setdefault(str(r['status']), 0)
            statuses[r['tag']][str(r['status'])] += 1
        shape = [r for r in log if r['tag'] in SHAPE_TAGS and r['status'] != 400]
        reached = [r for r in log if isinstance(r.get('reply'), dict) and r['reply'].get('reason')]
        unknown_asset = [r for r in log if r['tag'] == 'fuzz-unknown_asset']
        self.record['fuzz'] = {'cases': len(log), 'statuses': statuses, 'decode_counters_delta': moved,
                               'answered_by_the_core': len(reached),
                               'core_reasons': sorted({r['reply']['reason'] for r in reached}),
                               'leader_counters_present': all(k in after for k in DECODE_COUNTERS[:2]),
                               'gw1_treasury_lane': lane, 'unknown_asset': f.GATEWAY_FUZZ_UNKNOWN_ASSET,
                               'unknown_asset_answers': sorted({(r['status'], answer_code(r)) for r in unknown_asset}, key=str)}
        (self.out / 'fuzz.json').write_text(json.dumps(log) + '\n')
        # The unknown-asset case proves something only when the deposit route is live (the treasury lane on)
        lane_off = lane != 'on' or not unknown_asset
        return {'fuzz_no_decode_drop': line(not any(moved.values()) and not unanswered,
                                            {'decode_counters_delta': moved, 'unanswered': len(unanswered),
                                             'unanswered_tags': sorted({r['tag'] for r in unanswered}),
                                             'answered_by_the_core': len(reached), 'gw1_treasury_lane': lane,
                                             'unknown_asset_cases': len(unknown_asset)}, DECODE_TEXT,
                                            inconclusive='core_ingress_decode_rejects_total' not in after or not reached
                                            or lane_off),
                'fuzz_shape_refused': line(not shape, {'not_400': [(r['tag'], r['status']) for r in shape][:10]},
                                           'malformed request not refused 400')}, log

    def health(self, slot):
        port = self.f.m['ports']['gateway_admin' if slot.startswith('gw') else 'stream_admin']
        try:
            return json.loads(self.f.http(slot, port, '/health').get('body') or 'null')
        except ValueError:
            return None


# The fuzz tags the gateway must refuse 400 by itself: the nil UUID, an unknown field, a userId, an unknown assetId
SHAPE_TAGS = ('fuzz-nil_key', 'fuzz-unknown_field', 'fuzz-user_id', 'fuzz-unknown_asset')


def core_decided(log):
    """The fuzz requests the core decided or may have applied (the oracle's input): a 2xx, an answer that names a core
    reason, or no decisive answer (0, 5xx). A request the gateway refused by its own rules (400 VALIDATION, 401, 404
    FEATURE_DISABLED, 429) never left it: an order the core holds for one of them is caught by the oracle as an order no
    accepted request created."""
    out = []
    for r in log:
        reply = r.get('reply') if isinstance(r.get('reply'), dict) else {}
        if 200 <= r['status'] < 300 or reply.get('reason') or r['status'] == 0 or r['status'] >= 500:
            out.append(r)
    return out


FILL_TEXT = 'fill never visible'
NOT_LIVE_TEXT = 'stream not live before the pairs'


def fill_lines(rows, wanted, streams_at_go, control, bound_s):
    """The pair lines. A fill counts as never visible only when every stream client was connected and held its snapshot
    when the pairs began; otherwise the line fails with its own text, so a stream that was never reachable cannot pass
    as a muted one. A control stops at its first invisible fill, so its short run is not a refused pair."""
    invisible = [r['i'] for r in rows if r.get('failure') == FILL_TEXT]
    refused = [(r['i'], r.get('failure')) for r in rows if r.get('failure') not in (None, FILL_TEXT)]
    not_live = [s for s in streams_at_go if not (s.get('connects', 0) >= 1 and s.get('snapshots', 0) > 0)]
    short = len(rows) < wanted
    lines = {}
    lines['streams_live_before_pairs'] = line(streams_at_go and not not_live, {'streams': streams_at_go}, NOT_LIVE_TEXT,
                                              inconclusive=not streams_at_go)
    lines['pairs_complete'] = line(not refused and (not short or control),
                                   {'pairs': len(rows), 'wanted': wanted, 'refused': refused[:10],
                                    'stopped_at_first_invisible_fill': control and short},
                                   'pair not accepted' if refused else 'pairs cut short',
                                   inconclusive=not control and short and not refused)
    detail = {'invisible_pairs': invisible[:20], 'bound_s': bound_s, 'streams_not_live': not_live[:4]}
    if not_live or not streams_at_go:
        lines['fill_visible'] = line(False, detail, NOT_LIVE_TEXT)
    else:
        lines['fill_visible'] = line(rows and not invisible, detail, FILL_TEXT)
    accepted = [r for r in rows if r.get('taker_order')]
    gone = [r for r in accepted if r.get('orders_gone_ns')]
    lines['order_leaves_open_list'] = line(len(gone) == len(accepted), {'gone': len(gone), 'accepted': len(accepted)},
                                           'filled order still listed')
    return lines


# ------------------------------------------------------------------ tick-live-path

class TickLivePath(GatewayDrill):
    def run(self):
        f, s = self.f, self.s
        base = USER_BASE[self.name]
        maker, taker, trigger = base, base + 1, base + 2
        self.boot([maker, taker, trigger], s['TICK_TAP_S'])
        plan = {'gw': self.gw('gw0'), 'st': self.st('st0'), 'maker': maker, 'taker': taker, 'trigger': trigger, 'market': 1,
                # The MARKET BUY takes the whole 92 level, so the trigger's IOC at 94 trades at 94, through the stop at
                # 93.5; the stop's hold (stop x (1 + slippage) x qty) covers its fill at 94
                'empty_market': 2, 'asks': [[92 * FP, 10 * UNIT], [94 * FP, 1000 * UNIT], [95 * FP, 1000 * UNIT]],
                'market_qty': 10 * UNIT, 'stop_price': 93 * FP + FP // 2, 'stop_qty': 10 * UNIT, 'trigger_price': 94 * FP,
                'trigger_qty': 20 * UNIT, 'reference_bound_s': s['TICK_REFERENCE_BOUND_S'],
                'complete_bound_s': s['TICK_COMPLETE_BOUND_S'], 'phase': 'pass'}
        stopped = []
        if self.control:
            stopped = self.stop_forwarders()
        result = self.probe('tick', plan, 'tick-pass', timeout=s['TICK_REFERENCE_BOUND_S'] + 4 * s['TICK_COMPLETE_BOUND_S'] + 120)
        lines = {'market_order_completed': line(result['market'].get('completed'), {k: v for k, v in result['market'].items()
                                                                                  if k != 'statuses'}, 'market order not completed'),
                 'stop_order_completed': line(result['stop'].get('completed'), {k: result['stop'].get(k) for k in
                                                                               ('status', 'order', 'armed', 'completed')},
                                              'stop order not completed')}
        self.record['pass_leg'] = {k: v for k, v in result.items() if k != 'requests'}
        if not stopped:
            stopped = self.stop_forwarders()
        noref = self.probe('tick', dict(plan, phase='noref'), 'tick-noref', timeout=120)
        self.record['noref'] = {k: v for k, v in noref.items() if k != 'requests'}
        lines.update(noref_lines(noref, stopped, s['TICK_REQUEST_BOUND_S']))
        return self.finish(lines)

    def stop_forwarders(self):
        out = []
        for slot in ('fwd0', 'fwd1'):
            witness = self.f.stop(slot)
            out.append({'slot': slot, 'exit_code': witness.get('exit_code')})
        self.mark('forwarders_stopped')
        return out


def refused_noref(answer, bound_s):
    reason = (answer.get('reply') or {}).get('reason') if isinstance(answer.get('reply'), dict) else None
    took = (answer['recv_ns'] - answer['sent_ns']) / 1e9
    return answer['status'] == 422 and reason == 'NO_REFERENCE_PRICE' and took <= bound_s, \
        {'status': answer['status'], 'reason': reason, 'seconds': round(took, 3)}


def noref_lines(noref, stopped, bound_s):
    """With the forwarders stopped. A market no tick ever priced answers 422 NO_REFERENCE_PRICE inside the bound. A
    market that was priced keeps its last tick (the core holds no tick age), so its MARKET BUY is answered from that
    tick: the line asks only that it is answered inside the bound, never a hang, and records the answer as data."""
    traded_ok, traded = refused_noref(noref['traded_market'], bound_s)
    empty_ok, empty = refused_noref(noref['empty_market'], bound_s)
    traded['forwarders_stopped'] = stopped
    answered = traded['status'] == 422 or 200 <= traded['status'] < 300
    answered = answered and traded['seconds'] <= bound_s
    return {'no_reference_price': line(empty_ok, empty, 'no 422 NO_REFERENCE_PRICE on a market never priced'),
            'priced_market_answered': line(answered, dict(traded, refused=traded_ok),
                                           'MARKET order on a priced market unanswered with the forwarders stopped')}


DRILLS = {'gateway-kill-restart': KillRestart, 'stream-slow-consumer': SlowConsumer,
          'gateway-session-timeout': SessionTimeout, 'fill-visibility-core': FillVisibility, 'tick-live-path': TickLivePath}


def run(fixture, name, out_dir):
    drill = DRILLS[name](fixture, name, out_dir)
    result = drill.run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name} on the product gateway and stream binaries ({drill.driver()} driver)')
