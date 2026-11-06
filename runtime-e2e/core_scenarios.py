# SPDX-License-Identifier: Apache-2.0
"""Core-topology scenarios for fixture v2 (RC2 S14, harness H0).

``core-boot``  boot, empty genesis on the core, three authentication refusals and one authority refusal
               (the core moves ``assets_ingress_unauthorised_total``), slot states recorded.
``core-smoke`` H0 GREEN: funding while the gate is at GENESIS, gate OPEN, creates (one replayed) that
               reach DISPATCH_PENDING. With no forwarder the work must stay pending and the oracles
               must say INCONCLUSIVE, never PASS; a PASS would mean they accept unapplied commands.
``core-boots`` G15: N consecutive fresh boots (``ten_consecutive_boots`` when N = 10), flake rate kept.
"""
import json
from pathlib import Path
import subprocess
import sys
import time
import core_contracts

from contracts import FP, Inconclusive, Violation, fingerprint
import core_oracle
import journal_decode
import order_oracle
from oracle_model import BARRIER_COLLECTIONS

BUYER, SELLER = 72001, 72002
# The ME price band of BTC-USD is 0.01..100.00 (W0 answer 7), so the smoke prices inside it (S14's 100,000 predates the band).
PRICE, QTY = 50 * FP, FP // 100
SLIPPAGE_BPS = 500
# Genesis plan of core-smoke (contract 5.3): funded at genesis through the TOOL principal, no forwarder slot.
SMOKE_PLAN = {'users': [BUYER, SELLER], 'markets': [1],
              'funding': [{'user': BUYER, 'asset': 0, 'amount': 50_000 * FP}, {'user': SELLER, 'asset': 1, 'amount': FP}],
              'risk': {'slippage_bps': SLIPPAGE_BPS, 'collar_bps': 5000, 'per_sec': 200, 'max_open': 40}, 'tap_ms': 60_000}
# legacy_none is the H0 G2 RED witness (substituted, see README): a client presenting no credential, as
# every pre-RC1 client and today's v1 fixture does, is refused by the RC1 core.
AUTH_MODES = ['legacy_none', 'unknown_key', 'wrong_secret', 'class_mismatch']


def _ok(meaning, reply, what):
    if meaning != 'ANSWERED':
        raise Inconclusive(f'{what}: core probe {meaning}: {json.dumps(reply)}')
    return reply


def unauthorised_total(fixture):
    values = []
    for i in range(3):
        metrics = fixture.metrics(f'ae{i}', fixture.m['ports']['ae_metrics'])
        if 'assets_ingress_unauthorised_total' not in metrics:
            raise Inconclusive('AE does not export assets_ingress_unauthorised_total')
        values.append(int(metrics['assets_ingress_unauthorised_total']))
    return values


def money_dump(fixture):
    return _ok(*fixture.core('money-dump', 'probe-admin'), 'money-dump')


def order_dump(fixture):
    return _ok(*fixture.core('order-dump', 'probe-admin'), 'order-dump')['orders']


def verify_core_genesis(fixture):
    first, orders = money_dump(fixture), order_dump(fixture)
    time.sleep(.5)
    second = money_dump(fixture)
    if first != second:
        raise Inconclusive('changing core genesis')
    if second['balances'] or second['holds'] or second['lastAppliedTradeId'] != 0 or orders:
        raise Violation('core is not an empty financial and order genesis')
    if second['journalEnabled'] is not True:
        raise Violation('money journal not armed at genesis')
    return {'verified': True, 'balances': [], 'holds': [], 'live_orders': [], 'last_applied_trade_id': 0}


def me_refusal_control(fixture):
    """core-boot control (RC2 S15 5.3): an S6 ME refuses a session that presents no credential. Closes the
    ENFORCED_NOT_YET_EXERCISED placeholder; a not-enforced artifact is recorded as such, never as a pass."""
    if fixture.m['credentials']['me']['mode'] != 'enforced':
        return 'NOT_ENFORCED_BY_ARTIFACT: ME keys provisioned; refusal lands with RC2 S6'
    result = fixture.me_open_legs_unauthenticated()
    text = (result.stdout or '') + (result.stderr or '')
    if result.returncode == 0:
        raise Violation('ME session without a credential was not refused')
    if 'AuthenticationException' not in text:
        raise Inconclusive('ME connect without a credential failed, but not by an authentication refusal: ' + text[-200:])
    return {'result': 'REFUSED', 'error': 'AuthenticationException'}


def authentication_controls(fixture):
    """Refusals the core must make; each control is evidence only when the refusal is observed."""
    controls = {}
    for mode in AUTH_MODES:
        meaning, reply = fixture.core('unauth', 'probe-tool', mode=mode)
        if meaning != 'ANSWERED' or not reply or reply.get('refused') is not True:
            raise Violation(f'unauthenticated connect ({mode}) was not refused: {meaning} {json.dumps(reply)}')
        if not str(reply.get('error', '')).startswith('AuthenticationException'):
            raise Inconclusive(f'connect ({mode}) failed, but not by an authentication refusal: {reply.get("error")}')
        controls[mode] = 'REFUSED'
        if mode == 'legacy_none':
            controls['g2_legacy_witness'] = {
                'substitutes': 'H0 RED "a boot of a9a865d with today\'s fixture fails on authentication"',
                'client': 'CoreProbe with NullCredentialsSupplier (what the v1 fixture clients present)',
                'refusal': reply['error']}
    before = unauthorised_total(fixture)
    meaning, reply = fixture.core('deposit', 'probe-gateway', negative=1, user=BUYER, asset=0, amount=FP, rh=9, rl=1)
    if meaning != 'REFUSED':
        raise Violation(f'a GATEWAY session was allowed to deposit: {meaning} {json.dumps(reply)}')
    deadline = time.monotonic() + 10
    after = unauthorised_total(fixture)
    while not all(a > b for a, b in zip(after, before)) and time.monotonic() < deadline:
        time.sleep(.5); after = unauthorised_total(fixture)
    if not all(a > b for a, b in zip(after, before)):
        raise Violation(f'assets_ingress_unauthorised_total did not move on every member: {before} -> {after}')
    controls['authority'] = {'reply': reply['replies'][0], 'unauthorised_before': before, 'unauthorised_after': after}
    controls['me'] = me_refusal_control(fixture)
    return controls


def core_boot(fixture):
    started = fixture.registry['boot']
    genesis = verify_core_genesis(fixture)
    controls = authentication_controls(fixture)
    phases = started['phases']
    evidence = {'genesis': genesis, 'auth_controls': controls, 'slots': fixture.slots,
                'credentials': fixture.registry['credentials'],
                'boot_seconds': {'engines_ready': (phases['engines_ready_ns'] - started['started_ns']) / 1e9,
                                 'complete': (phases['complete_ns'] - started['started_ns']) / 1e9}}
    (fixture.root / 'core-boot.json').write_text(json.dumps(evidence, indent=2) + '\n')
    after = verify_core_genesis(fixture)   # the refused sessions left no trace in money or orders
    if after != genesis:
        raise Violation('a refused session changed the core genesis')
    return {'status': 'PASS', 'assertions': 5 + len(AUTH_MODES), 'processed': 1, 'skipped': 0, 'child_exit_codes': [0],
            'boot': evidence, 'scope': 'fixture v2 boot of the current core topology; not product acceptance'}


# ------------------------------------------------------------------ smoke


def _create(fixture, record, user, side, req, client):
    meaning, reply = fixture.core('create', 'probe-gateway', user=user, market=1, side=side, type='LIMIT', tif='GTC',
                                  price=PRICE, qty=QTY, budget=0, stop=0, delta=0, display=0, expires=0,
                                  rh=1, rl=req, ch=0, cl=client)
    row = {'request': [1, req], 'user': user, 'market': 1, 'side': side, 'type': 'LIMIT', 'tif': 'GTC', 'price': PRICE,
           'quantity': QTY, 'budget': 0, 'stop_price': 0, 'display_qty': 0}
    if meaning == 'UNKNOWN':
        row['reply'] = {'outcome': 'UNKNOWN'}
    else:
        r = reply['replies'][-1]
        row['reply'] = ({'outcome': 'ACK', 'order': r['order'], 'duplicate': r['duplicate'], 'hold_asset': r['hold_asset'],
                         'hold_amount': r['hold_amount'], 'status': r['status']} if r['t'] == 'OrderAck'
                        else {'outcome': 'REJECT', 'reason': r['reason']})
    record.append(row)
    return row


def _fund(fixture, record, kind, user, asset, amount, req, gate):
    meaning, reply = fixture.core(kind, 'probe-admin', user=user, asset=asset, amount=amount, rh=2, rl=req)
    outcome = {'ANSWERED': 'ACK', 'REFUSED': 'REJECT'}.get(meaning, 'UNKNOWN')
    record.append({'request': [2, req], 'kind': kind, 'user': user, 'asset': asset, 'amount': amount,
                   'outcome': outcome, 'gate': gate, 'reply': reply})


def read_tap(path):
    rows = {'dispatch': [], 'order_event': [], 'admission': [], 'order_fault': []}
    if path.exists():
        for line in path.read_text().splitlines():
            entry = json.loads(line)
            rows[entry['tap']].append(entry['row'])
    return rows


def money_journal(fixture):
    def rows(sql):
        return json.loads(fixture.psql('r01_money', "SELECT COALESCE(json_agg(t), '[]'::json) FROM (" + sql + ") t"))
    journal = []
    for row in rows('SELECT * FROM money_journal ORDER BY journal_seq'):
        kind = {2: 'deposit', 3: 'withdraw', 4: 'settle'}.get(row['movement_type'])
        if kind is None:
            raise Inconclusive('unmodelled money journal movement ' + str(row['movement_type']))
        entry = {'seq': row['journal_seq'], 'kind': kind}
        if kind == 'settle':
            entry.update(trade=row['trade_id'], buyer=row['buyer_user_id'], seller=row['seller_user_id'],
                         market=row['market_id'], price=row['price'], quantity=row['quantity'])
        else:
            entry.update(user=row['user_id'], asset=row['asset_id'], amount=row['amount'])
        journal.append(entry)
    legs = [{'seq': r['journal_seq'], 'user': r['user_id'], 'asset': r['asset_id'], 'role': r['asset_role'],
             'balance_after': r['balance_after']} for r in rows('SELECT * FROM money_journal_leg ORDER BY journal_seq, leg_no')]
    return journal, legs


def merge_member_lives(events, has_journal_seq):
    """One member's journal as one logical sequence. A member that was killed and restarted starts a NEW archive recording
    and re-journals the whole log it replays from journalSeq 1 (S15 W5 finding F-S15-31: me2 of lifecycle-faults held two
    recordings, 1..1233 then 1..1465, a second engine_config included). A journalSeq that appears in more than one
    recording must carry the same content in each (the journal is a function of the log), then it counts once; the same
    seq with different content is a divergence and stays a Violation. Without journalSeq (legacy profiles) nothing is merged."""
    plain = [{k: v for k, v in e.items() if k not in {'source', 'recording', 'position'}} for e in events]
    if not has_journal_seq or len({e.get('recording') for e in events}) <= 1:
        return plain
    # RC2 S16 5.4: keyed on (meEpoch, journalSeq), so two ME lives (a re-genesis restarts journalSeq at 1) never merge;
    # epochs keep the order of their first appearance
    order = {epoch: n for n, epoch in enumerate(dict.fromkeys(e.get('me_epoch') for e in plain))}
    by_seq = {}
    for e in plain:
        key = (order[e.get('me_epoch')], e['journal_seq'])
        seen = by_seq.setdefault(key, e)
        if seen != e:
            raise Violation(f'journalSeq {e["journal_seq"]} differs between two recordings of one ME member')
    return [by_seq[k] for k in sorted(by_seq)]


def me_journal(fixture):
    profile = journal_decode.load_profile(fixture.m['me_journal_profile'])
    decoded = {}
    for i in range(3):
        events = journal_decode.decode_dump(fixture.journal_dump(f'me{i}'), profile, require_end=True)
        decoded[f'me{i}'] = merge_member_lives(events, profile.has_journal_seq)
    if len({fingerprint(v) for v in decoded.values()}) != 1:
        raise Violation('ME members journaled different logical event sequences')
    return decoded['me0'], profile.has_journal_seq


# G6 export of the AE leader -> sample['counters'] (OM:37), so O11 is judged (OO:231-237)
COUNTER_METRICS = {'stale_outcomes': 'assets_order_stale_outcomes_total', 'redundant_outcomes': 'assets_order_redundant_outcomes_total',
                   'stale_terminals': 'assets_order_stale_terminals_total', 'conflicts': 'assets_order_conflicts_total',
                   'released_late': 'assets_released_late_total'}    # U1: RELEASED copies (L8 item 4, O11 W3)
SCRAPE_PREFIXES = {
    'ae': ('assets_cluster_role', 'assets_pending_commands', 'assets_order_', 'assets_release_confirm_stale_total', 'assets_market_',
           'assets_released_late_total', 'assets_me_release_early_total', 'assets_late_apply_on_dead_order_total',
           'assets_release_backlog', 'assets_me_ledger_size',                   # O-F4 (RUN:372-380)
           # RC2 S16 5.4: the capacity gate, the release path, the feed latch, the ticks
           'assets_release_', 'assets_me_capacity_', 'assets_feed_', 'assets_ticks_', 'assets_last_applied_trade_id'),
    'me': ('match_cluster_role', 'match_engine_next_journal_seq', 'match_durable_', 'match_command_ledger_size',
           'match_ingress_decode_rejects_total', 'match_ingress_unauthorized_total',    # O-F1 (RUN:331-338)
           'match_command_ledger_', 'match_release_', 'match_orders_submitted_total', 'match_trades_total'),   # S16 5.4
    'fwd': ('forwarder_resync_total', 'forwarder_session_reconnect_total', 'forwarder_session_new_leader_total',
            'forwarder_dispatch_seq', 'forwarder_ready', 'forwarder_tick_', 'forwarder_ticks_ready'),
    'bridge': ('bridge_ae_connected', 'bridge_ready', 'bridge_not_ready_bits', 'bridge_state', 'bridge_halted',
               'bridge_client_sessions_opened_total', 'bridge_halt_reason', 'bridge_core_halt_reason', 'bridge_skipped_total',
               'bridge_fences_total')}


def barrier_scrape(fixture, skip_me=False):
    """The contract 5.6 scrape set, per role. Names a role does not export are simply absent (the oracle reads
    sample.counters, this is evidence); a slot that is not STARTED is not scraped. ``skip_me``: RC2 S16 5.4, A04 life 1
    is judged on the ME frozen before the wipe, so the fresh ME is not read."""
    ports = fixture.m['ports']
    targets = [(f'{e}{i}', e, ports[e + '_metrics']) for e in (('ae',) if skip_me else ('ae', 'me')) for i in range(3)]
    for slot, state in (getattr(fixture, 'slots', None) or {}).items():
        if state.get('state') == 'STARTED':
            targets.append((slot, 'fwd' if slot.startswith('fwd') else 'bridge', ports['forwarder_http' if slot.startswith('fwd') else 'bridge_http']))
    scrape = {}
    for role, kind, port in targets:
        try:
            metrics = fixture.metrics(role, port)
        except Inconclusive as error:
            scrape[role] = {'unavailable': str(error)}
            continue
        scrape[role] = {k: v for k, v in metrics.items() if k.startswith(SCRAPE_PREFIXES[kind])}
    return scrape


def observe(fixture, frozen=None):
    """One barrier observation. ``frozen`` (RC2 S16 5.4, R6): A04 life 1's ME evidence read BEFORE the wipe
    ({me_journal, me_journal_seq, me_open_legs, scrape_me}); the fresh ME is then never queried."""
    money, orders = money_dump(fixture), order_dump(fixture)
    pending = _ok(*fixture.core('pending-dump', 'probe-forwarder'), 'pending-dump')
    if frozen is None:
        journal, has_seq = me_journal(fixture)
        legs = fixture.me_open_legs()
    else:
        journal, has_seq, legs = frozen['me_journal'], frozen['me_journal_seq'], frozen['me_open_legs']
    mj, mlegs = money_journal(fixture)
    gauges, leaders = {}, []
    for i in range(3):
        metrics = fixture.metrics(f'ae{i}', fixture.m['ports']['ae_metrics'])
        gauges[f'ae{i}'] = {k: int(metrics[k]) for k in ['assets_settle_faults_total', 'assets_settle_rejects_total']}
        if metrics.get('assets_cluster_role') == 2.0:
            leaders.append(metrics)
    if len(leaders) != 1:
        raise Inconclusive(f'no AE leader at the barrier: {len(leaders)} members report role 2')
    counters = {}
    for name, metric in COUNTER_METRICS.items():
        if metric not in leaders[0]:
            raise Inconclusive('AE leader does not export ' + metric)
        counters[name] = int(leaders[0][metric])
    core = {'balances': sorted(({'user': b['user'], 'asset': b['asset'], 'available': b['available'], 'locked': b['locked']}
                                for b in money['balances']), key=lambda b: (b['user'], b['asset'])),
            'holds': sorted(money['holds'], key=lambda h: h['order']),
            'live_orders': orders, 'last_applied_trade_id': money['lastAppliedTradeId'],
            'pending_dispatch': {'count': pending['count'], 'head': pending['head']}}
    # RC2 S16 3.3 / 5.4: the v7 FeedPositionReport fields money-dump exports since W2 (meEpoch, lastAppliedJournalSeq,
    # feedHalted, haltReason); absent on an older probe, then M10 keeps its old rule
    for name, key in (('bound_me_epoch', 'meEpoch'), ('feed_cursor', 'lastAppliedJournalSeq'), ('feed_halted', 'feedHalted'),
                      ('halt_reason', 'haltReason')):
        if key in money:
            core[name] = money[key]
    scrape = barrier_scrape(fixture, skip_me=frozen is not None)
    if frozen is not None:
        scrape.update(frozen.get('scrape_me') or {})
    return {'core': core, 'me_journal': journal, 'me_journal_seq': has_seq, 'me_open_legs': legs,
            'money_journal': mj, 'money_journal_legs': mlegs, 'gauges': gauges, 'pending': pending, 'counters': counters,
            'scrape': scrape}


def core_smoke(fixture):
    """The genesis (empty snapshot, tap, ME genesis, bridges, core genesis, risk, funding) ran in fixture.start(SMOKE_PLAN)."""
    genesis = fixture.registry['genesis_snapshot']
    tap_path = Path(fixture.registry['tap']['path'])
    tap_end_ns = fixture.registry['tap']['started_ns'] + fixture.registry['tap']['duration_ms'] * 1_000_000
    funding, creates = [dict(f) for f in fixture.registry['funding']], []
    _create(fixture, creates, SELLER, 'SELL', 1, 101)
    _create(fixture, creates, BUYER, 'BUY', 2, 102)
    _create(fixture, creates, BUYER, 'BUY', 2, 102)                                    # O1: replayed requestId
    remaining = (tap_end_ns - time.time_ns()) / 1e9 + 2
    if remaining > 0: time.sleep(remaining)
    tap = read_tap(tap_path)
    first = observe(fixture); time.sleep(1); second = observe(fixture)
    sample = {'version': 'core-sample-v2', 'markets': {'1': {'base': 1, 'quote': 0}},
              'risk': fixture.registry['risk'], 'genesis': genesis, 'counters': second['counters'],
              'funding': [{k: v for k, v in f.items() if k != 'reply'} for f in funding],
              'creates': creates, 'amends': [], 'cancels': [],
              'core_events': tap['order_event'], 'admission': tap['admission'], 'dispatch_tap': tap['dispatch'],
              **{k: second[k] for k in ['core', 'me_journal', 'me_journal_seq', 'me_open_legs', 'money_journal', 'money_journal_legs']},
              'faults': {'settle_fault': max(g['assets_settle_faults_total'] for g in second['gauges'].values()),
                         'settle_rejected': max(g['assets_settle_rejects_total'] for g in second['gauges'].values()),
                         'order_fault': len(tap['order_fault']),
                         'quarantined': sum(1 for e in tap['order_event'] if e['kind'] == 'QUARANTINED')},
              'declared': {'settle_fault': 0, 'settle_rejected': 0, 'order_fault': 0, 'quarantined': 0, 'halt': False,
                           'fault_open': False, 'forwarder_absent': all(fixture.slots[s]['state'] != 'STARTED' for s in ('fwd0', 'fwd1')),
                           'gate_sequence': [['SUSPENDED', 'GENESIS'], ['OPEN', 'ADMIN']],
                           'epochs': [int(fixture.genesis_id(), 16)]}}    # W0: the journal's meEpoch is the genesis id
    observations = []
    for obs in (first, second):
        view = dict(sample, **{k: obs[k] for k in ['core', 'me_journal', 'me_open_legs', 'money_journal', 'money_journal_legs']})
        observations.append({name + '_digest': fingerprint(view[name]) for name in BARRIER_COLLECTIONS})
    sample['barrier'] = {'input_closed': True, 'samples': observations}
    (fixture.root / 'core-sample.json').write_text(json.dumps(sample, indent=2) + '\n')
    money, orders = core_oracle.judge(sample), order_oracle.judge(sample)
    verdict = {'money': money, 'order': orders}
    (fixture.root / 'core-smoke.json').write_text(json.dumps(verdict, indent=2) + '\n')
    pending = [o['order'] for o in sample['core']['live_orders'] if o['status'] == 'PENDING_NEW']
    accepted = {c['reply'].get('order') for c in creates if c['reply'].get('outcome') == 'ACK'}
    if len(accepted) != 2 or set(pending) != accepted:
        raise Violation(f'expected both accepted creates DISPATCH_PENDING without a forwarder; pending {pending}, accepted {accepted}')
    replay = sorted({r['seq'] for r in second['pending']['entries']})
    if replay != sorted(r['seq'] for r in sample['dispatch_tap']) or second['pending']['count'] != len(replay):
        raise Violation(f'RequestPendingDispatch replay {replay} (count {second["pending"]["count"]}) != tapped dispatches')
    if not sample['dispatch_tap']:
        raise Inconclusive('the dispatch tap saw no MeDispatch; O3/O9/O10 have no independent witness')
    if not sample['declared']['forwarder_absent']:
        raise Inconclusive('core-smoke is defined for the topology without a forwarder')
    if money['status'] == 'FAIL' or orders['status'] == 'FAIL':
        return {'status': 'FAIL', 'error': 'oracle FAIL on the smoke stream', 'oracle': verdict, 'assertions': 1,
                'processed': len(creates), 'skipped': 0, 'child_exit_codes': [0]}
    if orders['status'] == 'PASS':
        raise Violation('order oracle PASSED unapplied commands with no forwarder')
    expected_open = {'O7', 'O10'}
    inconclusive = {k for k, v in orders['rules'].items() if v['status'] == 'INCONCLUSIVE'}
    if not expected_open <= inconclusive:
        raise Violation(f'pending work not reported INCONCLUSIVE by O7/O10: {inconclusive}')
    return {'status': 'PASS', 'assertions': 6, 'processed': len(creates) + len(funding), 'skipped': 0,
            'child_exit_codes': [0], 'oracle_status': {'money': money['status'], 'order': orders['status']},
            'order_inconclusive_rules': sorted(inconclusive), 'pending_orders': pending,
            'dispatches_tapped': len(sample['dispatch_tap']),
            'scope': 'H0 smoke: pending without a forwarder is INCONCLUSIVE by design; not product acceptance'}


# ------------------------------------------------------------------ G15 boot stability


def consecutive_boots(manifest, manifest_path, output, count):
    children, parent = [], Path(manifest_path).absolute().parent
    for index in range(count):
        # RC2 S17 (20.1 line 20): <kind>--<run_id>-boot-NN.json, the name the S16 kind rule accepts
        child_manifest, derived = core_contracts.child_manifest(manifest, parent, f'boot-{index:02d}')
        destination = output / f'boot-{index:02d}'
        started = time.monotonic()
        with (output / f'boot-{index:02d}.log').open('x') as log:
            process = subprocess.Popen([sys.executable, str(Path(__file__).with_name('runner.py')), '--manifest',
                                        str(child_manifest), '--scenario', 'core-boot', '--output', str(destination)],
                                       stdout=log, stderr=log)
            try:
                exit_code = process.wait(timeout=600)
            except subprocess.TimeoutExpired:
                process.terminate(); process.wait(timeout=90)
                raise Inconclusive(f'boot {index} exceeded its orchestration bound')
        result = json.loads((destination / 'result.json').read_text())
        children.append({'index': index, 'run_id': derived['run_id'], 'exit_code': exit_code, 'status': result['status'],
                         'error': result.get('error'), 'wall_seconds': round(time.monotonic() - started, 1),
                         'boot_seconds': (result.get('boot') or {}).get('boot_seconds'),
                         'teardown': result.get('teardown')})
        (output / 'children.json').write_text(json.dumps(children, indent=2) + '\n')
        if result.get('teardown') != 'COMPLETE_OWNED_RESOURCES_ONLY':
            raise Inconclusive(f'boot {index} teardown was not verified')
    passes = sum(c['status'] == 'PASS' for c in children)
    record = {'boots': count, 'passes': passes, 'flakes': count - passes, 'flake_rate': (count - passes) / count,
              'profile': {'timeouts': manifest['timeouts'], 'cpu_set_by_role': manifest['limits']['cpu_set_by_role'],
                          'cpu_quota_by_role': manifest['limits'].get('cpu_quota_by_role', {})}}
    name = 'ten_consecutive_boots' if count == 10 else f'{count}_consecutive_boots'
    (output / (name + '.json')).write_text(json.dumps({**record, 'children': children}, indent=2) + '\n')
    return {'status': 'PASS' if passes == count else 'FAIL', 'assertions': count, 'processed': count, 'skipped': 0,
            'child_exit_codes': [c['exit_code'] for c in children], name: record, 'children': children,
            'scope': 'G15 boot stability, functional fixture profile (R-T: no latency claim)'}
