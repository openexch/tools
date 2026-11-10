# SPDX-License-Identifier: Apache-2.0
"""Order oracle v2 for the core topology (rules O1-O12).

Same sample and decision rule as ``core_oracle``. Witnesses: the core's own replies and OrderEvent
tap, an independent dispatch tap (TOOL session on CH_DISPATCH), the ME journal and the
ME's resting legs (OpenOrdersSnapshot 27).
"""
from collections import Counter, defaultdict

from contracts import Inconclusive, Violation, integer
from core_oracle import run_rules
from oracle_model import KIND_CODES, PENDING, RESULT_RELEASED, TERMINAL, attempt, request_key


def o1(m):
    """Over the 6.1-resolved request rows (Model.creates): an UNKNOWN resolved by its re-send is judged as that verdict;
    a run that ends with an unresolved UNKNOWN is INCONCLUSIVE, after every judgeable FAIL was looked for."""
    by_request = defaultdict(set)
    for create in m.creates:
        reply = create['reply']
        if reply.get('outcome') != 'ACK':
            continue
        key = request_key(create['request'])
        by_request[key].add(integer(reply['order']))
        if reply.get('duplicate') and m.create_by_request.get(key) != reply['order']:
            raise Violation(f'replayed request {key} acknowledged a different order')
    for key, orders in by_request.items():
        if len(orders) != 1:
            raise Violation(f'request {key} minted {len(orders)} orders {sorted(orders)}')
    owners = Counter(oid for key, oid in m.create_by_request.items())
    shared = [oid for oid, n in owners.items() if n > 1]
    if shared:
        raise Violation(f'order ids {shared} acknowledged for more than one requestId')
    first = {}
    for create in m.creates:
        if create['reply'].get('outcome') == 'ACK':
            key = request_key(create['request'])
            if key in first and not create['reply'].get('duplicate'):
                raise Violation(f'request {key} replayed but not acknowledged as duplicate')
            first.setdefault(key, create)
    known = set(m.orders)
    for row in m.tap.values():
        if row['order'] not in known:
            raise m.unaccounted(f'dispatch for order {row["order"]} that no accepted request created')
    for key in m.release_dispatches:   # a RELEASE_ID carries only the command id (order 0, user 0 on the wire)
        if key[0] not in known:
            raise m.unaccounted(f'RELEASE_ID for command {key} of an order no accepted request created')
    if m.unresolved:
        raise Inconclusive(f'unresolved gateway reply ({len(m.unresolved)})' if any('id' in r for r in m.unresolved)
                           else 'create outcome unknown')


def o2(m):
    for key, copies in m.outcome_copies.items():
        first = copies[0]
        for copy in copies[1:]:
            if copy['result'] == RESULT_RELEASED and first['result'] != RESULT_RELEASED:
                continue   # Model checked it is leg-less and follows a release of the order
            if (copy['applied_position'], copy['leg'], copy['result']) != (first['applied_position'], first['leg'], first['result']):
                raise Violation(f'command {key}: repeat outcome differs from the first '
                                f'(position {copy["applied_position"]} vs {first["applied_position"]})')
    legs = Counter(o['leg'] for o in m.first_outcome.values() if o['result'] == 0 and o['kind'] in (0, 2))
    doubled = [leg for leg, n in legs.items() if n > 1]
    if doubled:
        raise Violation(f'ME legs {doubled} created by more than one command')


def o3(m):
    m.require_tap_closed()   # A hole in the tap is INCONCLUSIVE, never "the core never dispatched"
    attempts = defaultdict(list)
    for key, row in m.tap.items():
        high, low = key
        kind = low & 3
        if high not in m.orders:
            raise m.unaccounted(f'command idHigh {high} is not a core order id')
        if kind not in (0, 1, 2) or KIND_CODES.get(row['kind']) != kind:
            raise Violation(f'command {key}: idLow kind {kind} does not match dispatch kind {row["kind"]}')
        attempts[high].append(low >> 2)
    triggered = {e['order'] for e in m.s['core_events'] if e['kind'] == 'TRIGGERED'}
    for oid, seen in attempts.items():
        # A stop order's accept consumes attempt 0 and its trigger mints the child CREATE as attempt 1
        # (OrderEngine.fire: attempt++), so the first dispatch of a triggered order is attempt 1 (dense from there)
        first = 1 if oid in triggered and min(seen) == 1 else 0
        if sorted(seen) != list(range(first, first + len(seen))):
            raise Violation(f'order {oid}: attempts {sorted(seen)} skip or reuse an attempt')
    for key in m.outcome_copies:
        if key not in m.tap:
            raise Violation(f'ME outcome for command {key} the core never dispatched')


def _legs(m):
    legs = defaultdict(set)
    for key, outcome in m.first_outcome.items():
        if outcome['result'] == 0 and outcome['kind'] in (0, 2):
            legs[key[0]].add(outcome['leg'])
    return legs


def o4(m):
    m.check_ownership()
    legs = _legs(m)
    for oid, trade_legs in m.trade_legs.items():
        orphan = trade_legs - legs.get(oid, set())
        if orphan:
            raise Violation(f'order {oid}: trades on legs {sorted(orphan)} absent from its leg history')
    resting = {}
    for row in m.s['me_open_legs']:
        if row['leg'] in resting:
            raise Violation(f'ME reports leg {row["leg"]} twice')
        resting[row['leg']] = row
    expected = {}
    for oid, row in m.live.items():
        if row['status'] in {'PENDING_TRIGGER', 'PENDING_NEW'}:
            continue
        if not row.get('me_order_id'):
            raise Violation(f'live order {oid} is {row["status"]} but has no ME leg')
        expected[row['me_order_id']] = oid
    if set(resting) != set(expected):
        raise Violation(f'ME resting legs != live core legs: ME only {sorted(set(resting) - set(expected))[:5]}, '
                        f'core only {sorted(set(expected) - set(resting))[:5]}')
    for leg, row in resting.items():
        if row['order'] != expected[leg]:
            raise Violation(f'ME leg {leg} belongs to order {row["order"]}, core says {expected[leg]}')


def o5(m):
    """A non-live order with no tapped terminal is ``tap_loss`` (INCONCLUSIVE on that id) when an order-event
    gap or a tap session window lies after its last tapped event; outside every window it stays a FAIL."""
    last_event = defaultdict(int)
    for event in m.s['core_events']:
        last_event[event['order']] = max(last_event[event['order']], integer(event['seq']))
    tap_loss = []
    terminal = defaultdict(list)
    for event in m.s['core_events']:
        if event['status'] in TERMINAL:
            terminal[event['order']].append(event)
    for oid, events in terminal.items():
        if len(events) > 1:
            raise Violation(f'order {oid}: {len(events)} terminal events')
        if oid in m.live:
            raise Violation(f'order {oid} is terminal in events but still live in the core')
    for oid in m.orders:
        if oid in m.live:
            continue
        if oid not in terminal:
            if m.in_event_window(last_event[oid]):
                tap_loss.append(oid)
                continue
            raise Violation(f'order {oid} left the live set without a terminal event')
        status = terminal[oid][0]['status']
        _, _, quantity = m.amend_chain(oid)
        if status == 'FILLED' and m.fills[oid] != quantity:
            raise Violation(f'order {oid}: FILLED but ME fills {m.fills[oid]} != quantity {quantity}')
        if status != 'FILLED' and m.fills[oid] == quantity and quantity:
            raise Violation(f'order {oid}: fully filled at the ME but terminal {status}')
        if status in {'CANCELLED', 'EXPIRED'}:
            evidence = any(t['order'] == oid and t['status'] in {'CANCELLED', 'EXPIRED'} for t in m.terminals) or any(
                key[0] == oid and o['kind'] == 1 and o['result'] == 0 for key, o in m.first_outcome.items())
            if not evidence and _legs(m).get(oid):
                raise Violation(f'order {oid}: {status} without an ME cancel outcome or terminal on its leg')
        if status == 'REJECTED':
            evidence = any(key[0] == oid and o['kind'] == 0 and o['result'] != 0 for key, o in m.first_outcome.items()) or any(
                t['order'] == oid and t['status'] == 'REJECTED' for t in m.terminals)
            if not evidence:
                raise Violation(f'order {oid}: REJECTED without an ME rejection')
    if tap_loss:
        raise Inconclusive(f'tap_loss: no terminal event tapped for orders {tap_loss[:5]} ({len(tap_loss)}) inside a tap window')


def o6(m):
    for oid, row in m.live.items():
        if row['filled'] != m.fills[oid]:
            raise Violation(f'order {oid}: core filled {row["filled"]} != ME trade sum {m.fills[oid]}')
        if row['remaining'] != row['quantity'] - row['filled']:
            raise Violation(f'order {oid}: remaining {row["remaining"]} != quantity - filled')
        if row['status'] == 'FILLED':
            raise Violation(f'order {oid}: FILLED but still live')
    for event in m.s['core_events']:
        if event['status'] == 'FILLED' and event['filled'] != m.fills[event['order']]:
            raise Violation(f'order {event["order"]}: FILLED event filled {event["filled"]} != ME sum {m.fills[event["order"]]}')


def o7(m):
    pending = [oid for oid, row in m.live.items() if row['status'] in PENDING]
    count = m.s['core']['pending_dispatch']['count']
    if pending or count:
        if m.declared.get('fault_open') or m.declared.get('forwarder_absent'):
            raise Inconclusive(f'{len(pending)} orders pending dispatch with a declared open fault or no forwarder')
        raise Violation(f'orders {pending[:5]} still DISPATCH_PENDING (pending count {count}) at the barrier')


def o8(m):
    for oid, create in m.orders.items():
        if create['type'] == 'ICEBERG':
            slices = sorted((r for r in m.tap.values() if r['order'] == oid and r['kind'] == 'CREATE'), key=attempt)
            total = sum(r['quantity'] for r in slices)
            if any(r['quantity'] > create['display_qty'] for r in slices):
                raise Violation(f'iceberg {oid}: a slice exceeds displayQty')
            live = m.live.get(oid)
            if live is None:
                status = next((e['status'] for e in m.s['core_events'] if e['order'] == oid and e['status'] in TERMINAL), None)
                if status == 'FILLED' and total != create['quantity']:
                    raise Violation(f'iceberg {oid}: slices sum {total} != quantity {create["quantity"]}')
                if total < m.fills[oid] or total > create['quantity']:
                    raise Violation(f'iceberg {oid}: slices sum {total} outside [filled, quantity]')
            else:
                hidden = integer(live.get('hidden_qty', 0))
                if total + hidden != create['quantity']:
                    raise Violation(f'iceberg {oid}: slices {total} + hidden {hidden} != quantity {create["quantity"]}')
            if m.fills[oid] < sum(r['quantity'] for r in slices[:-1]):
                raise Violation(f'iceberg {oid}: refilled before the previous slice filled')
        if create['type'] in {'STOP_LOSS', 'TRAILING_STOP'} and create['side'] == 'BUY':
            child = sorted((r for r in m.tap.values() if r['order'] == oid and r['kind'] == 'CREATE'), key=attempt)
            if child:
                trigger = [e for e in m.s['core_events'] if e['order'] == oid and e['kind'] == 'TRIGGERED']
                if len(trigger) != 1 or type(trigger[0].get('hold_remaining')) is not int:
                    raise Inconclusive(f'stop {oid}: no TRIGGERED event with hold_remaining witnesses the trigger')
                if child[0]['budget'] != trigger[0]['hold_remaining']:
                    raise Violation(f'stop {oid}: child budget {child[0]["budget"]} != parent hold remaining at trigger '
                                    f'{trigger[0]["hold_remaining"]}')


def in_ordering_exception(window, row, outcome):
    """An inversion inside the declared window (the ids the new ME term's first resync re-sent) is recorded,
    not judged: dispatchSeq <= until_seq and, when declared, first-applied at or after from_journal_seq."""
    if not window:
        return False
    if row['seq'] > integer(window['until_seq']):
        return False
    start = window.get('from_journal_seq')
    return start is None or (outcome.get('journal_seq') is not None and outcome['journal_seq'] >= start)


def o9(m):
    window = m.declared.get('ordering_exception')
    inside = 0
    previous = -1
    per_order = defaultdict(lambda: -1)
    for key, outcome in m.first_outcome.items():
        row = m.tap.get(key)
        if row is None or row.get('seq') is None:
            continue  # O3 reports a missing one; a backfilled row with an unknown seq has no order to judge
        if row['seq'] < previous:
            if not in_ordering_exception(window, row, outcome):
                raise Violation(f'command {key} first-applied after a later dispatchSeq ({row["seq"]} < {previous})')
            inside += 1
        previous = max(previous, row['seq'])
        attempt = key[1] >> 2
        if attempt < per_order[key[0]]:
            raise Violation(f'order {key[0]}: attempt {attempt} applied after attempt {per_order[key[0]]}')
        per_order[key[0]] = attempt
    if window:
        return {'status': 'PASS', 'o9_exception_inversions': inside, 'window': window}


def moot_command(m, key):
    """A CANCEL or AMEND the forwarders lost whose order the ME itself ended (a terminal in the journal). The core
    resolves such an order by the ME's trade or terminal (implicit ack) and clears the pending command, so the
    forwarders' resync has nothing left to re-send and the ME never sees it: nothing is owed. A CREATE is never moot (the
    ME cannot end an order it never created) and a live order's lost cancel or amend is still a FAIL (it stays pending)."""
    if key[1] & 3 not in (1, 2):
        return False
    return any(e['order'] == key[0] for e in m.terminals)


def o10(m):
    m.require_tap_closed()   # judged on the union of tapped and backfilled dispatches
    missing = [key for key in m.tap if key not in m.first_outcome and not moot_command(m, key)]
    if missing:
        if m.declared.get('fault_open') or m.declared.get('forwarder_absent'):
            raise Inconclusive(f'{len(missing)} dispatches not applied with a declared open fault or no forwarder')
        raise Violation(f'dispatched commands never applied at the ME: {missing[:5]}')
    # The excused moot commands are counted per run, so a drill that leans on the rule shows it
    return {'status': 'PASS', 'moot_excused': sum(1 for key in m.tap if key not in m.first_outcome)}


def preempted_outcomes(m):
    """First outcomes the core can no longer match to a pending command, because the ME's own records resolved the
    command first (implicit acks): a CREATE or AMEND outcome after a trade or terminal on its leg, a CANCEL outcome
    after the terminal of its leg. OrderEngine.outcomeV3 sends every such record to Table D (unmatchedV3)."""
    traded, ended, ended_orders, first, count = set(), set(), set(), set(), 0
    for event in m.journal:
        if event['type'] == 'trade':
            traded.update((event['taker_leg'], event['maker_leg']))
        elif event['type'] == 'terminal':
            ended.add(event['leg'])
            ended_orders.add(event['order'])
        elif event['type'] == 'outcome':
            key = (event['command_id_high'], event['command_id_low'])
            if key in first:
                continue
            first.add(key)
            if event['leg'] and (event['leg'] in ended or event['kind'] in (0, 2) and event['leg'] in traded):
                count += 1
            elif not event['leg'] and event['kind'] in (1, 2) and event['order'] in ended_orders:
                # A CANCEL or AMEND for an order the ME had already ended answers UNKNOWN_LEG with leg 0, so the
                # leg tests above cannot see it; the order id still names the ended order (counted by the core as stale)
                count += 1
    return count


def o11(m):
    """Every ME outcome record the core did not match to its pending command is counted once by Table D: stale (U3,
    U7), redundant (U2, U6) or released late (U1, a RELEASED copy). The unmatched records are the copies beyond the
    first plus the first outcomes the ME's own trade or terminal resolved first (an amendment: "stale + redundant ==
    duplicates" held only while no forwarder ran; the first forwarder run counted 15 preempted, 0 copies)."""
    quarantined = m.s['faults'].get('quarantined')
    if type(quarantined) is not int:
        raise Inconclusive('quarantine count missing')
    if quarantined != m.declared.get('quarantined', 0):
        raise Violation(f'quarantined {quarantined} != declared {m.declared.get("quarantined", 0)}')
    counters = m.s.get('counters')
    if not counters:
        raise Inconclusive('order-engine stale/redundant counters not exported')
    duplicates = sum(len(c) - 1 for c in m.outcome_copies.values())
    released = len(m.released_repeats)
    if 'released_late' not in counters and released:
        raise Inconclusive('RELEASED copies journaled but core_released_late_total not exported')
    preempted = preempted_outcomes(m)
    seen = counters['stale_outcomes'] + counters['redundant_outcomes'] + counters.get('released_late', 0)
    if seen != duplicates + preempted:
        raise Violation(f'stale + redundant + released late outcomes {seen} != duplicate ME outcome records {duplicates} '
                        f'+ outcomes the ME resolved first {preempted}')
    return {'status': 'PASS', 'duplicates': duplicates, 'preempted': preempted, 'released_late': released}


def o12(m):
    declared = m.declared.get('gate_sequence')
    if declared is None:
        raise Inconclusive('drill did not declare its gate sequence')
    observed = [[a['state'], a['reason']] for a in m.s['admission'] if a['market'] == 0]
    compact = [step for i, step in enumerate(observed) if i == 0 or step != observed[i - 1]]
    if compact != declared:
        raise Violation(f'gate transitions {compact} != declared {declared}')


RULES = [('O1', o1), ('O2', o2), ('O3', o3), ('O4', o4), ('O5', o5), ('O6', o6), ('O7', o7), ('O8', o8),
         ('O9', o9), ('O10', o10), ('O11', o11), ('O12', o12)]


def judge(sample):
    return run_rules(sample, RULES)
