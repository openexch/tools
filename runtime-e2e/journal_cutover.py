# SPDX-License-Identifier: Apache-2.0
"""R02 W6: OMS journal-consumer recovery and fill visibility latency.

The C++ projector is frozen so trades commit in the ME while the OMS cannot see them; the OMS is
then SIGKILLed, the projector commits those trades while the OMS is down, and the restarted OMS
must reach the exact money oracle from its own checkpoint. Latency is reported, never accepted:
no fill-notification budget has been declared.
"""
import json
import time

from contracts import FP, Inconclusive, Violation
from observe import stable_sample, verify_genesis
from scenarios import money, request

BUYER, SELLER = 71001, 71002
PRICE, QUANTITY = '100000.00000000', '0.01000000'

# Runs inside the probe container: one docker exec per batch, so timings exclude orchestration.
PROBE = r'''import json,sys,time,urllib.request,urllib.error
job=json.loads(sys.stdin.read())
def call(method,path,body,user):
    headers={"Content-Type":"application/json","Authorization":"Bearer dev:"+str(user)}
    data=json.dumps(body).encode() if body is not None else None
    started=time.monotonic_ns()
    try:
        r=urllib.request.urlopen(urllib.request.Request(job["base"]+path,data=data,headers=headers,method=method),timeout=5)
        response={"status":r.status,"body":r.read().decode()}
    except urllib.error.HTTPError as e: response={"status":e.code,"body":e.read().decode()}
    except Exception as e: response={"status":0,"error":str(e)}
    return {"method":method,"path":path,"request":body,"user":user,"response":response,
            "elapsed_ns":time.monotonic_ns()-started,"sent_ns":started}
def submit(client,user,side):
    return call("POST","/api/v1/orders",{"marketId":1,"side":side,"orderType":"LIMIT","price":job["price"],
                "quantity":job["quantity"],"clientOrderId":client},user)
def oid(record):
    reply=json.loads(record["response"].get("body") or "{}")
    return reply.get("omsOrderId") if record["response"]["status"] in (200,201) and reply.get("accepted") is True else None
records,pairs=[],[]
for pair in job["pairs"]:
    sell=submit(pair["sell"],job["seller"],"SELL"); records.append(sell)
    buy=submit(pair["buy"],job["buyer"],"BUY"); records.append(buy)
    entry={"sell":oid(sell),"buy":oid(buy),"buy_sent_ns":buy["sent_ns"],"buy_acked_ns":buy["sent_ns"]+buy["elapsed_ns"]}
    if job["poll"] and entry["sell"] and entry["buy"]:
        deadline=time.monotonic_ns()+job["poll_timeout_ns"]
        while time.monotonic_ns()<deadline:
            seen=call("GET","/api/v1/orders/"+str(entry["buy"]),None,job["buyer"])
            body=json.loads(seen["response"].get("body") or "{}")
            if body.get("status")=="FILLED":
                entry["buy_filled_seen_ns"]=seen["sent_ns"]+seen["elapsed_ns"]; break
            time.sleep(0.001)
    pairs.append(entry)
print(json.dumps({"records":records,"pairs":pairs}))
'''


def _probe(fixture, label, count, poll):
    job = {'base': f'http://{fixture.m["nodes"]["oms"]}:18080', 'price': PRICE, 'quantity': QUANTITY,
           'buyer': BUYER, 'seller': SELLER, 'poll': poll, 'poll_timeout_ns': 10_000_000_000,
           'pairs': [{'sell': f'{fixture.run_id}-{label}-{i}-s', 'buy': f'{fixture.run_id}-{label}-{i}-b'}
                     for i in range(count)]}
    out = fixture.execute('probe', ['python3', '-c', PROBE], input=json.dumps(job), timeout=30 + 11 * count)
    result = json.loads(out.stdout)
    with (fixture.root / 'requests.jsonl').open('a') as log:
        for record in result['records']:
            record = {k: v for k, v in record.items() if k != 'sent_ns'}
            if record['method'] == 'POST': log.write(json.dumps(record) + '\n')
    accepted = []
    for pair in result['pairs']:
        if not pair['sell'] or not pair['buy']:
            raise Violation(f'{label} order was not accepted with an exact identity')
        accepted += [int(pair['sell']), int(pair['buy'])]
    return result['pairs'], accepted


def _scalar(fixture, sql):
    value = fixture.psql('r01_oms', sql)
    if value in ('', None): raise Inconclusive('missing checkpoint row: ' + sql)
    return int(value)


def _percentiles(values):
    ordered = sorted(values)
    pick = lambda q: ordered[min(len(ordered) - 1, int(q * len(ordered)))]
    return {'count': len(ordered), 'p50_us': pick(.5) // 1000, 'p90_us': pick(.9) // 1000,
            'p99_us': pick(.99) // 1000, 'max_us': ordered[-1] // 1000}


def journal_oms_restart(fixture, latency_pairs=20, outage_pairs=6):
    if not fixture.m.get('journal_cutover'):
        raise Inconclusive('W6 requires the journal cutover topology')
    evidence = {'latency_pairs': latency_pairs, 'outage_pairs': outage_pairs}
    save = lambda: (fixture.root / 'journal-oms-restart.json').write_text(json.dumps(evidence, indent=2) + '\n')
    initial = verify_genesis(fixture, (BUYER, SELLER))
    funding = []
    for kind, user, asset, amount in [('deposit', BUYER, 0, 50_000 * FP), ('deposit', SELLER, 1, FP)]:
        reply = request(fixture, 'POST', f'/api/v1/accounts/{user}/{kind}', {'assetId': asset, 'amount': money(amount)}, user)
        if reply.get('success') is not True:
            raise Violation('funding was not acknowledged')
        funding.append({'kind': kind, 'user': user, 'asset': asset, 'amount': amount})

    # 1. Fill visibility: taker acknowledged -> OMS reports FILLED, journal path end to end.
    pairs, accepted = _probe(fixture, 'lat', latency_pairs, poll=True)
    seen = [p['buy_filled_seen_ns'] - p['buy_acked_ns'] for p in pairs if 'buy_filled_seen_ns' in p]
    if len(seen) != latency_pairs:
        raise Violation('a taker fill never became visible through the OMS within 10 s')
    evidence['fill_visibility'] = {**_percentiles(seen), 'measured': 'taker HTTP ack to first GET showing FILLED',
                                   'includes': 'projector commit, OMS 5 ms poll, 1 ms probe poll, HTTP',
                                   'budget': 'UNDECLARED', 'acceptance': 'NOT_EVALUATED'}
    save()

    # 2. Freeze the projector: trades commit in the ME and AE but never reach the OMS journal.
    xp = fixture.registry['containers']['xprojector']
    before = _scalar(fixture, 'SELECT last_trade_id FROM execution_projector_checkpoint')
    if before != latency_pairs: raise Inconclusive('projector did not commit the latency phase exactly')
    fixture.command(['docker', 'pause', xp]); evidence['projector_paused'] = True; save()
    try:
        _, outage = _probe(fixture, 'out', outage_pairs, poll=False)
        accepted += outage
        oms_seen = _scalar(fixture, 'SELECT last_trade_id FROM oms_journal_consumer_checkpoint')
        evidence['fault'] = fixture.kill('oms')
    finally:
        fixture.command(['docker', 'unpause', xp]); evidence['projector_unpaused'] = True; save()
    expected = latency_pairs + outage_pairs
    evidence['oms_last_trade_at_kill'] = oms_seen

    # 3. While the OMS is down, the projector must commit every outage trade.
    deadline = time.monotonic() + 30
    while _scalar(fixture, 'SELECT last_trade_id FROM execution_projector_checkpoint') < expected:
        if time.monotonic() > deadline: raise Violation('projector did not commit the outage trades')
        time.sleep(.2)
    still = _scalar(fixture, 'SELECT last_trade_id FROM oms_journal_consumer_checkpoint')
    evidence['committed_while_oms_down'] = expected - still
    if oms_seen != latency_pairs or still != latency_pairs:
        raise Inconclusive('OMS applied outage trades before the kill; recovery path not exercised')
    save()

    # 4. Restart the same OMS container and state; admission must wait for the consumer.
    restarted = time.monotonic_ns()
    fixture.command(['docker', 'start', fixture.registry['containers']['oms']])
    fixture.wait_http('oms', 18080, '/metrics', timeout=120,
                      predicate=lambda r: 'oms_admission_ready 1.0' in r['body'])
    evidence['restart_to_admission_ms'] = (time.monotonic_ns() - restarted) // 1_000_000

    (fixture.root / 'workload.json').write_text(json.dumps({'funding': funding, 'accepted': accepted,
        'pairs': expected, 'input_closed': True}, indent=2) + '\n')
    sample, counts = stable_sample(fixture, initial, funding, accepted, expected)

    # 5. Exactly-once: consumer at the projector, one resolved ME command per accepted order.
    after = _scalar(fixture, 'SELECT last_trade_id FROM oms_journal_consumer_checkpoint')
    commands = json.loads(fixture.psql('r01_oms', "SELECT json_build_object('total',count(*),"
        "'resolved',count(*) FILTER (WHERE state='RESOLVED'),'orders',count(DISTINCT oms_order_id)) FROM oms_me_commands"))
    evidence.update(oms_last_trade_after=after, me_commands=commands); save()
    if after != expected: raise Violation('OMS consumer checkpoint differs from the committed trade set')
    if commands != {'total': len(accepted), 'resolved': len(accepted), 'orders': len(accepted)}:
        raise Violation('ME commands are not exactly one resolved command per accepted order')
    return {'status': 'PASS', 'assertions': 7, 'processed': counts['trades'], 'skipped': 0,
            'child_exit_codes': [0], 'money': counts, 'fault': evidence['fault'],
            'committed_while_oms_down': evidence['committed_while_oms_down'],
            'fill_visibility': evidence['fill_visibility'],
            'restart_to_admission_ms': evidence['restart_to_admission_ms'],
            'failure_domain': fixture.m['failure_domain'],
            'scope': 'OMS SIGKILL with fills committed while down; latency reported, budget undeclared'}
