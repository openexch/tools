# SPDX-License-Identifier: Apache-2.0
"""Fail-closed fixture and exact-money contracts for a synthetic runtime fixture.

This is a fixed-price LIMIT workload oracle. It makes no claim about amend,
iceberg or fees, and refuses an unproved or changing observation barrier.
"""
from collections import Counter, defaultdict
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re

FP = 100_000_000


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def integer(value):
    if type(value) is not int:
        raise Inconclusive('exact integer evidence required; no float/coercion')
    return value

class Inconclusive(ValueError):
    pass


class Violation(ValueError):
    pass


def check_result(result):
    if result.get('status') != 'PASS' or result.get('skipped') != 0:
        raise Inconclusive('non-PASS or skipped work')
    if integer(result.get('assertions')) <= 0 or integer(result.get('processed')) <= 0:
        raise Inconclusive('zero assertions or zero processed work')
    exits = result.get('child_exit_codes')
    if not isinstance(exits, list) or not exits:
        raise Inconclusive('missing child process evidence')
    if any(code != 0 for code in exits):
        raise Violation('child process failed')
    fault = result.get('fault')
    if fault and fault.get('kind') == 'kill':
        if fault.get('before_running') is not True or fault.get('after_running') is not False or fault.get('exit_observed') is not True:
            raise Inconclusive('kill did not demonstrably happen')


def validate_manifest(manifest, manifest_path):
    try:
        if manifest['schema_version'] != 1 or not re.fullmatch(r'r01-[0-9a-f]{12}', manifest['run_id']):
            raise Violation('unknown manifest or fixture identity')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', manifest['image']):
            raise Violation('runtime image must be immutable')
        path = Path(manifest_path).absolute()
        root = Path(manifest['state_root'])
        if root != path.parent / 'fixtures' / manifest['run_id'] or root.resolve() != root:
            raise Violation('state path escapes the manifest-owned fixture directory')
        if manifest['failure_domain'] != 'single_host_process_loss':
            raise Violation('single-host containers cannot prove host HA')
        net = ipaddress.ip_network(manifest['network']['subnet'])
        private = [ipaddress.ip_network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]
        if net.version != 4 or net.prefixlen != 24 or not any(net.subnet_of(n) for n in private) or manifest['network']['internal'] is not True:
            raise Violation('fixture needs its own internal RFC1918 /24 network')
        roles = {'me0','me1','me2','ae0','ae1','ae2','bridge','oms','market','projector','probe'}
        if set(manifest['nodes']) != roles or len(set(manifest['nodes'].values())) != len(roles):
            raise Violation('exactly three ME, three AE and the critical path are required')
        for value in manifest['nodes'].values():
            address = ipaddress.ip_address(value)
            if address not in net or address in {net.network_address, net.broadcast_address, net.network_address + 1}:
                raise Violation('endpoint is outside the fixture or collides with its gateway')
        for field in ['shm_mb', 'memory_mb', 'disk_min_free_mb']:
            if integer(manifest['limits'][field]) <= 0:
                raise Violation('resource limits must be positive and explicit')
        for field in ['p99_ms','p999_ms','normal_settled_tps','n_minus_one_settled_tps']:
            value = manifest['budgets'][field]
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise Violation('unknown/non-numeric quality budget')
        integer(manifest['seed'])
        for role in ['me','ae','bridge','oms','market','projector']:
            artifact = manifest['artifacts'][role]
            file = Path(artifact['path'])
            if not file.is_absolute() or file.is_symlink() or not file.is_file():
                raise Inconclusive('missing/untrusted artifact path: ' + role)
            if not re.fullmatch(r'[0-9a-f]{40}', artifact['source_sha']):
                raise Inconclusive('missing artifact source: ' + role)
            with file.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if digest != artifact['sha256']:
                raise Violation('artifact digest mismatch: ' + role)
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, (Violation, Inconclusive)):
            raise
        raise Inconclusive('incomplete manifest: ' + str(error)) from error


def reconcile(sample):
    required = ['initial_balances','funding','journal','journal_first_seq','markets',
                'accepted_order_ids','orders','executions','balances','holds','barrier']
    if any(field not in sample for field in required) or sample.get('initial_snapshot_verified') is not True:
        raise Inconclusive('genesis or required observation is missing')
    if not sample['accepted_order_ids'] or not sample['executions']:
        raise Inconclusive('no accepted and executed work')
    barrier = sample['barrier']
    snapshots = barrier.get('samples', [])
    if barrier.get('input_closed') is not True or barrier.get('pending_orders') != 0 or len(snapshots) != 2 or snapshots[0] != snapshots[1]:
        raise Inconclusive('no stable quiescence barrier')
    for collection in ['orders','executions','balances','holds']:
        if snapshots[1].get(collection + '_digest') != fingerprint(sample[collection]):
            raise Inconclusive('observation does not belong to the barrier: ' + collection)
    for field in ['ae_position','last_trade','journal_seq']:
        integer(snapshots[1].get(field))

    totals = defaultdict(int)
    initial_keys = set()
    for row in sample['initial_balances']:
        key = (integer(row['user']), integer(row['asset']))
        if key in initial_keys or integer(row['total']) < 0:
            raise Violation('invalid/duplicate genesis balance')
        initial_keys.add(key); totals[key] = row['total']
    if not initial_keys:
        raise Inconclusive('empty genesis')

    def funding_key(row):
        if row['kind'] not in {'deposit', 'withdraw'} or integer(row['amount']) <= 0:
            raise Violation('invalid external money movement')
        return row['kind'], integer(row['user']), integer(row['asset']), row['amount']

    expected_funding = Counter(funding_key(row) for row in sample['funding'])
    observed_funding = Counter()
    journal_trades = {}
    sequence = integer(sample['journal_first_seq'])
    for row in sample['journal']:
        if integer(row['seq']) != sequence:
            raise Violation('money journal gap, duplicate or out-of-order record')
        sequence += 1
        if row['kind'] in {'deposit','withdraw'}:
            observed_funding[funding_key(row)] += 1
        elif row['kind'] == 'settle':
            trade = integer(row['trade'])
            if trade in journal_trades:
                raise Violation('duplicate applied financial effect')
            journal_trades[trade] = row
        else:
            raise Inconclusive('unmodelled money journal movement')
    if observed_funding != expected_funding:
        raise Violation('lost/extra deposit or withdrawal')
    if snapshots[1]['journal_seq'] != sequence - 1:
        raise Inconclusive('projector has not reached the observed barrier')
    for row in sample['funding']:
        key = row['user'], row['asset']
        if key not in initial_keys:
            raise Inconclusive('funding target has no known initial balance')
        totals[key] += row['amount'] * (1 if row['kind'] == 'deposit' else -1)
    conservation = defaultdict(int)
    for (_, asset), amount in totals.items(): conservation[asset] += amount

    orders = {integer(row['id']): row for row in sample['orders']}
    accepted = [integer(value) for value in sample['accepted_order_ids']]
    if len(orders) != len(sample['orders']) or len(set(accepted)) != len(accepted) or set(accepted) != set(orders):
        raise Violation('accepted orders missing, duplicated or unexpected')
    fills = defaultdict(int)
    trade_rows = defaultdict(list)
    for execution in sample['executions']:
        oid = integer(execution['order'])
        if oid not in orders:
            raise Violation('execution without an accepted order')
        order = orders[oid]
        if any(execution[key] != order[key] for key in ['user','market','side']):
            raise Violation('execution identity mismatch')
        if integer(execution['quantity']) <= 0 or integer(execution['price']) <= 0:
            raise Violation('invalid execution amount')
        fills[oid] += execution['quantity']
        trade_rows[integer(execution['trade'])].append(execution)
    if set(journal_trades) != set(trade_rows):
        raise Violation('committed executions and applied settlements differ')
    for trade, pair in trade_rows.items():
        if len(pair) != 2 or {row['side'] for row in pair} != {'BUY','SELL'}:
            raise Violation('trade must have exactly one BUY and one SELL')
        buy = next(row for row in pair if row['side'] == 'BUY')
        sell = next(row for row in pair if row['side'] == 'SELL')
        if any(buy[key] != sell[key] for key in ['price','quantity','market']):
            raise Violation('trade legs disagree')
        journal = journal_trades[trade]
        expected = {'buyer': buy['user'], 'seller': sell['user'], 'price': buy['price'],
                    'quantity': buy['quantity'], 'market': buy['market']}
        if any(journal.get(key) != value for key, value in expected.items()):
            raise Violation('journal settlement differs from committed executions')
        market = sample['markets'].get(str(buy['market']))
        if market is None: raise Inconclusive('missing market/asset mapping')
        quote_amount = buy['price'] * buy['quantity'] // FP
        totals[(buy['user'], market['base'])] += buy['quantity']
        totals[(buy['user'], market['quote'])] -= quote_amount
        totals[(sell['user'], market['base'])] -= buy['quantity']
        totals[(sell['user'], market['quote'])] += quote_amount

    expected_holds = {}
    for oid, order in orders.items():
        filled = integer(order['filled']); quantity = integer(order['quantity'])
        if filled != fills[oid] or not 0 <= filled <= quantity:
            raise Violation('order fill sum mismatch')
        if order['status'] == 'FILLED' and filled != quantity:
            raise Violation('FILLED order is incomplete')
        if order['status'] not in {'NEW','PARTIALLY_FILLED','FILLED','CANCELLED','CANCELED','REJECTED','EXPIRED'}:
            raise Inconclusive('pending/unmodelled order state')
        if order['status'] in {'NEW','PARTIALLY_FILLED'}:
            if any(e['price'] != order['price'] for e in sample['executions'] if e['order'] == oid):
                raise Inconclusive('partial price improvement is outside this fixed-price workload')
            market = sample['markets'][str(order['market'])]
            if order['side'] == 'BUY': asset, amount = market['quote'], integer(order['price']) * (quantity - filled) // FP
            elif order['side'] == 'SELL': asset, amount = market['base'], quantity - filled
            else: raise Inconclusive('unknown order side')
            if amount > 0: expected_holds[oid] = (order['user'], asset, amount)
    actual_holds = {}
    for row in sample['holds']:
        oid = integer(row['order'])
        if oid in actual_holds: raise Violation('duplicate hold')
        actual_holds[oid] = (integer(row['user']), integer(row['asset']), integer(row['remaining']))
    if actual_holds != expected_holds:
        raise Violation('hold/open-order mismatch')
    locked = defaultdict(int)
    for user, asset, amount in expected_holds.values(): locked[(user, asset)] += amount
    actual = {}
    for row in sample['balances']:
        key = integer(row['user']), integer(row['asset'])
        if key in actual: raise Violation('duplicate balance')
        actual[key] = integer(row['available']), integer(row['locked'])
    observed_conservation = defaultdict(int)
    for key in set(totals) | set(actual):
        available, held = actual.get(key, (0, 0))
        if available < 0 or held < 0 or held != locked[key] or available + held != totals[key]:
            raise Violation('exact balance/non-negativity/hold invariant failed: ' + str(key))
        observed_conservation[key[1]] += available + held
    if observed_conservation != conservation:
        raise Violation('per-asset conservation failed')
    return {'orders': len(orders), 'trades': len(trade_rows),
            'funding_events': sum(expected_funding.values()), 'journal_rows': len(sample['journal'])}
