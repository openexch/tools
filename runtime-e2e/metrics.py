# SPDX-License-Identifier: Apache-2.0
"""Quality decisions from retained open-loop intents and durable observations."""
import math
from collections import Counter, defaultdict

from contracts import Inconclusive, Violation


def percentile(values, fraction):
    if not values: raise Inconclusive('no latency samples')
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def evaluate(events, sample, budgets, profile):
    windows = [e for e in events if e['event'] == 'window']
    if len(windows) != 1: raise Inconclusive('missing/ambiguous measurement window')
    window = windows[0]
    start = window['start_ns'] + window['warmup_seconds'] * 1_000_000_000
    stop = start + window['measurement_seconds'] * 1_000_000_000
    intents = [e for e in events if e['event'] == 'intent']
    if len(intents) != window['total_scheduled'] or len({e['index'] for e in intents}) != len(intents):
        raise Inconclusive('generator did not account for every scheduled arrival')
    cohort = {e['index']: e for e in intents if start <= e['intended_ns'] < stop}
    if len(cohort) != window['rate'] * window['measurement_seconds']:
        raise Inconclusive('offered load does not match declared measurement window')
    latencies, lateness, measured_ids = [], [], set()
    commits_in_window = 0; committed = set()
    order_indices = {}
    for e in events:
        if e['event'] == 'http' and e['response']['status'] in (200, 201):
            import json
            reply = json.loads(e['response']['body'])
            if reply.get('accepted') is True:
                oid = int(reply['omsOrderId'])
                if oid in order_indices: raise Violation('duplicate accepted identity in measurement')
                order_indices[oid] = e['index']
        if e['event'] != 'durable' or e['index'] not in cohort: continue
        if e['status'] not in {'NEW', 'PARTIALLY_FILLED', 'FILLED'}: continue
        if order_indices.get(e['order_id']) != e['index']:
            raise Violation('durable latency does not belong to an accepted request identity')
        if e['index'] in committed: raise Violation('duplicate durable observation')
        committed.add(e['index']); measured_ids.add(e['order_id'])
        origin = cohort[e['index']]
        if e['intended_ns'] != origin['intended_ns'] or e['started_ns'] != origin['started_ns']:
            raise Violation('latency observation not bound to original request clock')
        delta = e['observed_ns'] - origin['intended_ns']
        if delta < 0: raise Inconclusive('invalid monotonic latency clock')
        latencies.append(delta / 1_000_000)
        commits_in_window += start <= e['observed_ns'] < stop
    for intent in cohort.values():
        delay = intent['started_ns'] - intent['intended_ns']
        if delay < 0: raise Inconclusive('generator dispatched before intended arrival')
        lateness.append(delay / 1_000_000)
    trades = defaultdict(set)
    for row in sample['executions']: trades[row['trade']].add(row['order'])
    settlements_in_window = 0; seen = set()
    for e in events:
        if e['event'] != 'settled': continue
        trade = e['trade_id']
        if trade in seen: raise Violation('duplicate durable journal observation')
        seen.add(trade)
        if trade not in trades or len(trades[trade]) != 2:
            raise Violation('settled counter has no exact two-leg execution evidence')
        if (start <= e['observed_ns'] < stop
                and all(order_indices.get(oid) in cohort for oid in trades[trade])):
            settlements_in_window += 1
    misses = sum(e['event'] == 'generator_overload' and e['index'] in cohort for e in events)
    seconds = window['measurement_seconds']
    result = {'profile': profile, 'offered': len(cohort), 'durable_completed': len(committed),
              'failed_or_uncompleted': len(cohort) - len(committed), 'generator_misses': misses,
              'latency_samples': len(latencies), 'success_ratio': len(committed) / len(cohort),
              'committed_orders_per_s': commits_in_window / seconds,
              'settled_trades_per_s': settlements_in_window / seconds,
              'generator_p99_lateness_ms': percentile(lateness, .99),
              'p99_ms': percentile(latencies, .99) if latencies else None,
              'p999_ms': percentile(latencies, .999) if latencies else None,
              'latency_boundary': 'intended arrival to first read of committed PostgreSQL order state; includes polling delay',
              'all_failures_counted_in_success_ratio': True}
    buckets = [.1, .2, .5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, float('inf')]
    histogram = Counter()
    for latency in latencies:
        edge = next(value for value in buckets if latency <= value)
        histogram['+Inf' if math.isinf(edge) else str(edge)] += 1
    result['histogram_upper_bound_ms'] = dict(histogram)
    inconclusive = []
    if misses: inconclusive.append('load generator exhausted its bounded in-flight capacity')
    if len(latencies) < budgets['minimum_latency_samples']: inconclusive.append('insufficient completed latency samples')
    if result['generator_p99_lateness_ms'] > budgets['generator_p99_lateness_ms']:
        inconclusive.append('load generator dispatch lag exceeds the declared measurement bound')
    prefix = 'normal' if profile == 'normal' else 'n_minus_one'
    violations = []
    for key, limit in [('p99_ms', budgets['p99_ms']), ('p999_ms', budgets['p999_ms'])]:
        if result[key] is not None and result[key] > limit: violations.append(key + ' above absolute budget')
    if result['committed_orders_per_s'] < budgets[prefix + '_committed_orders_per_s']:
        violations.append('committed goodput below absolute floor')
    if result['settled_trades_per_s'] < budgets[prefix + '_settled_tps']:
        violations.append('settled goodput below absolute floor')
    if result['success_ratio'] < budgets['steady_success_ratio']:
        violations.append('valid-work success ratio below absolute floor')
    result.update(status='INCONCLUSIVE' if inconclusive else 'FAIL' if violations else 'PASS',
                  measurement_issues=inconclusive, budget_violations=violations)
    return result
