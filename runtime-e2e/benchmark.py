# SPDX-License-Identifier: Apache-2.0
"""Single declared performance repeat, always backed by the exact financial oracle."""
import json
import time

from contracts import FP, Inconclusive, Violation
from fixture import JAVA
from faults import probe, counter
from metrics import evaluate, percentile
from observe import verify_genesis, stable_sample, sql_rows, collect
from scenarios import request, money, order_id
from resources import Resources


def benchmark(fixture, profile='normal', preflight=False):
    if profile not in {'normal', 'n_minus_one'}: raise Inconclusive('unknown workload profile')
    if not fixture.m.get('benchmark_helper'): raise Inconclusive('hash-pinned measurement helper is required')
    users = list(range(72000, 72100))
    initial = verify_genesis(fixture, users)
    funding = []
    for user in users:
        asset, amount = (1, 10 * FP) if user % 2 == 0 else (0, 1_000_000 * FP)
        response = request(fixture, 'POST', f'/api/v1/accounts/{user}/deposit',
                           {'assetId': asset, 'amount': money(amount)}, user)
        if response.get('success') is not True: raise Inconclusive('benchmark funding failed')
        funding.append({'kind': 'deposit', 'user': user, 'asset': asset, 'amount': amount})
    faults = []
    (fixture.root / 'benchmark-financial-inputs.json').write_text(json.dumps(
        {'initial_balances':initial,'funding':funding,'initial_snapshot_verified':True}, indent=2) + '\n')
    if profile == 'n_minus_one':
        for engine in ['me', 'ae']:
            before = {engine + str(i): probe(fixture, engine + str(i)) for i in range(3)}
            followers = [n for n, c in before.items() if counter(c, 201) == 0]
            if len(followers) != 2: raise Inconclusive('N-1 requires a known healthy quorum first')
            faults.append(fixture.kill(followers[-1]))
    budget = fixture.m['budgets']
    config = {'run_id': fixture.run_id, 'rate': 20 if preflight else budget[profile + '_offered_orders_per_s'],
              'warmup_seconds': 2 if preflight else budget['warmup_seconds'],
              'measurement_seconds': 5 if preflight else budget['measurement_seconds'], 'user_count': 100,
              'max_inflight':fixture.m['measurement_contract']['max_inflight'],
              'oms_url': f'http://{fixture.m["nodes"]["oms"]}:18080',
              'oms_jdbc': f'jdbc:postgresql://{fixture.gateway}:{fixture.pg_port}/r01_oms',
              'money_jdbc': f'jdbc:postgresql://{fixture.gateway}:{fixture.pg_port}/r01_money'}
    (fixture.root / 'benchmark-profile.json').write_text(json.dumps({'config':config, 'faults':faults,
        'preflight_only':preflight, 'scope':'single-host normal/N-1 steady load; no host-loss/failover-time claim'}, indent=2) + '\n')
    jvm = fixture.m.get('measurement_jvm')
    measurement_options = []
    if jvm is not None:
        if (jvm.get('collector') not in {'g1', 'generational-zgc'}
                or type(jvm.get('heap_mb')) is not int or not 512 <= jvm['heap_mb'] <= 1024):
            raise Inconclusive('measurement JVM must use a declared bounded heap and collector')
        measurement_options = [f'-Xms{jvm["heap_mb"]}m', f'-Xmx{jvm["heap_mb"]}m',
            '-Xlog:gc*,safepoint:file=/data/benchmark-gc.log:time,uptime,level,tags:filecount=3,filesize=8m']
        measurement_options += (['-XX:+UseZGC', '-XX:+ZGenerational']
                                if jvm['collector'] == 'generational-zgc' else ['-XX:+UseG1GC'])
    with Resources(fixture):
        child = fixture.execute('probe', JAVA + measurement_options + ['-cp', '/artifacts/oms.jar:/artifacts/benchmark-probe.jar',
                                'BenchmarkProbe'], input=json.dumps(config), timeout=240)
    summary = json.loads(child.stdout)
    (fixture.root / 'benchmark-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    events_path = fixture.root / 'state/probe/benchmark/events.jsonl'
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    accepted = []
    with (fixture.root / 'requests.jsonl').open('a') as requests:
        for event in events:
            if event['event'] != 'http': continue
            requests.write(json.dumps(event) + '\n')
            if event['response']['status'] in (200, 201):
                response = json.loads(event['response']['body'])
                if response.get('accepted') is True: accepted.append(order_id(response['omsOrderId']))
    # Wait for the accepted-order set to become stable in durable storage. The later full oracle
    # still checks every fill, journal record and held remainder; an incomplete trade cannot vanish.
    deadline = time.monotonic() + budget['backlog_drain_seconds']
    counts_before = None
    while time.monotonic() < deadline:
        rows = sql_rows(fixture, 'r01_oms', '''SELECT
            (SELECT count(*) FROM orders) AS orders,
            (SELECT count(*) FROM orders WHERE status IN ('PENDING_NEW','PENDING_TRIGGER')) AS pending,
            (SELECT count(DISTINCT trade_id) FROM executions) AS trades''')[0]
        if rows == counts_before and rows['orders'] >= len(accepted) and rows['pending'] == 0: break
        counts_before = rows; time.sleep(.5)
    else:
        # Retain actual financial and latency observations even when the gate fails. A timeout
        # must never discard the evidence or silently turn unfinished accepted work into zero work.
        partial = collect(fixture)
        (fixture.root / 'backlog-timeout-observation.json').write_text(json.dumps(partial, indent=2) + '\n')
        lag = [(e['started_ns'] - e['intended_ns']) / 1_000_000 for e in events if e['event'] == 'intent']
        notes = {'status':'FAIL', 'reason':'accepted-work backlog did not drain within declared budget',
                 'durable_counts_at_deadline':rows, 'accepted_count':len(accepted),
                 'generator_misses':summary['generator_misses'], 'generator_p99_lateness_ms_all_phases':percentile(lag,.99),
                 'money_oracle':'INCONCLUSIVE_PENDING_WORK_NO_STABLE_BARRIER'}
        try: notes['partial_quality'] = evaluate(events, partial['state'], budget, profile)
        except (Violation, Inconclusive) as error: notes['partial_quality_error'] = str(error)
        if summary['generator_misses'] or percentile(lag,.99) > budget['generator_p99_lateness_ms']:
            notes['status'] = 'INCONCLUSIVE'
        (fixture.root / 'quality-result.json').write_text(json.dumps(notes, indent=2) + '\n')
        if notes['status'] == 'FAIL': raise Violation(notes['reason'])
        raise Inconclusive('benchmark backlog and load-generator measurement bounds both failed')
    sample, exact = stable_sample(fixture, initial, funding, accepted, rows['trades'],
                                 timeout=budget['backlog_drain_seconds'])
    if preflight:
        required = {'intent','http','durable','settled','window'}
        if not required.issubset({e['event'] for e in events}) or summary['accepted'] != 140 or summary['durable_observed'] != 140:
            raise Inconclusive('measurement preflight did not observe every expected stage')
        return {'status':'PASS','assertions':6,'processed':exact['trades'],'skipped':0,'child_exit_codes':[0],
                'money':exact,'scope':'measurement instrumentation preflight only; quality budgets NOT_RUN'}
    decision = evaluate(events, sample, budget, profile)
    (fixture.root / 'quality-result.json').write_text(json.dumps(decision, indent=2) + '\n')
    return {'status':decision['status'],'assertions':9,'processed':exact['trades'],'skipped':0,
            'child_exit_codes':[0],'money':exact,'quality':decision,'faults':faults,
            'scope':'one retained performance repeat; aggregate/repeated acceptance remains separate'}
