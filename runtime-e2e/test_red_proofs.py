# SPDX-License-Identifier: Apache-2.0
"""The red proofs at unit level: the PG-sourced order sample and its control lines, the source scan of the core oracle
path, the money twin's lines and the money oracle on a stale money history, the ownership verdict, the scenarios'
registration and refusals."""
import copy
import importlib.util
import os
from pathlib import Path
import re
import shutil
import tempfile
import tokenize
import unittest

from contracts import Inconclusive, Violation
import core_contracts
import core_oracle
import nightly
import oracle_samples
import order_oracle
import pg_control
import red_proofs
import refusals
import release_cut
import smoke_core
import table_owners

HERE = Path(__file__).parent

# ------------------------------------------------------------------ the source scan (row: no PG order relation on the oracle path)

# The modules on the core oracle path: the sample's builders (core_scenarios.observe, the drills' build_sample, the
# gateway drill's barrier), the ME journal decode, the model and both oracles, and the shared fingerprint
ORACLE_PATH = ('contracts.py', 'oracle_model.py', 'core_oracle.py', 'order_oracle.py', 'core_scenarios.py', 'core_drills.py',
               'gateway_scenarios.py', 'journal_decode.py')
ORDER_RELATIONS = ('oe_orders', 'oe_fills', 'oe_order_events', 'orders', 'executions', r'gateway_\w+_v1', r'md_\w+')
# A relation named after FROM, JOIN, INTO, UPDATE, TABLE or COPY, or inside to_regclass('...'), in a string literal
READ = re.compile(r'(?i)(?:\b(?:from|join|into|update|table|copy)\s+(?:only\s+)?|regclass\(\s*\'?)'
                  r'(?:\\?"?public\\?"?\.)?\\?"?(' + '|'.join(ORDER_RELATIONS) + r')\\?"?\b')
SCAN_TEXT = 'order relation read on the oracle path'


def scan(paths):
    """Every string literal of the modules that reads an order relation: ['<file>:<line>', ...]; and every import of the
    control module (pg_control) on the path, which would make the PG-sourced sample a product sample."""
    found = []
    for path in paths:
        with open(path, 'rb') as source:
            for token in tokenize.tokenize(source.readline):
                if token.type == tokenize.STRING or getattr(tokenize, 'FSTRING_MIDDLE', -1) == token.type:
                    if READ.search(token.string):
                        found.append(f'{Path(path).name}:{token.start[0]}')
                elif token.type == tokenize.NAME and token.string == 'pg_control':
                    found.append(f'{Path(path).name}:{token.start[0]}')
    return found


class SourceScanTest(unittest.TestCase):
    def test_no_order_relation_is_read_on_the_core_oracle_path(self):
        found = scan([HERE / name for name in ORACLE_PATH])
        self.assertEqual(found, [], SCAN_TEXT + ': ' + ', '.join(found))

    def test_control_a_planted_read_in_a_copied_module_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            copy_path = Path(d) / 'core_scenarios.py'
            shutil.copyfile(HERE / 'core_scenarios.py', copy_path)
            text = copy_path.read_text()
            planted = text + '\n\ndef planted(fixture):\n    return fixture.psql(\'r01_gateway\', \'SELECT order_id, status FROM oe_orders\')\n'
            copy_path.write_text(planted)
            line_no = planted.count('\n', 0, planted.index('SELECT order_id')) + 1
            found = scan([copy_path])
            self.assertEqual(found, [f'core_scenarios.py:{line_no}'])
            print(f'{SCAN_TEXT}: {found[0]}')

    def test_the_scan_reads_quoted_and_qualified_names_and_regclass(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'm.py'
            p.write_text('A = "SELECT * FROM public.\\"oe_fills\\""\nB = "select to_regclass(\'public.md_trades\')"\n'
                         'C = "JOIN gateway_order_history_v1 g"\nD = "live_orders"\nE = "the orders channel"\n'
                         'import pg_control\n')
            self.assertEqual(scan([p]), ['m.py:1', 'm.py:2', 'm.py:3', 'm.py:6'])


# ------------------------------------------------------------------ the PG-sourced order sample

def pg_rows(sample):
    """The order history projection as it would hold the sample's orders, exactly (every order its last status)."""
    events = sorted(sample['core_events'], key=lambda e: e['seq'])
    last = {}
    for e in events:
        last[e['order']] = e
    live = {r['order']: r for r in sample['core']['live_orders']}
    orders = []
    for create in sample['creates']:
        oid = create['reply'].get('order')
        if create['reply'].get('outcome') != 'ACK' or create['reply'].get('duplicate') or oid in {o['order_id'] for o in orders}:
            continue
        row = live.get(oid)
        status = row['status'] if row else last[oid]['status']
        quantity = row['quantity'] if row else create['quantity']
        filled = row['filled'] if row else last[oid]['filled']
        orders.append({'order_id': oid, 'user_id': create['user'], 'market_id': create['market'], 'status': status,
                       'side': create['side'], 'type': create['type'], 'time_in_force': create['tif'],
                       'price': (row or create)['price'] or None, 'stop_price': create['stop_price'] or None,
                       'quantity': quantity, 'filled_quantity': filled, 'remaining_quantity': quantity - filled,
                       'hold_asset_id': create['reply']['hold_asset'],
                       'hold_amount': row['hold_amount'] if row else create['reply']['hold_amount'],
                       'me_order_id': row['me_order_id'] if row else None})
    rows, filled = [], {}
    for e in events:
        delta = e['filled'] - filled.get(e['order'], 0)
        filled[e['order']] = e['filled']
        rows.append({'journal_seq': e['seq'], 'order_id': e['order'], 'event': e['kind'], 'status': e['status'],
                     'trade_id': 1 if e['kind'] == 'FILL' else 0, 'last_qty': delta if e['kind'] == 'FILL' else 0,
                     'hold_remaining': e.get('hold_remaining', 0), 'core_log_position': 0})
    return {'orders': orders, 'events': rows, 'fills': []}


class PgSampleTest(unittest.TestCase):
    def setUp(self):
        self.sample = oracle_samples.clean_sample()
        self.pg = pg_rows(self.sample)

    def test_field_map_reads_only_named_columns(self):
        self.assertEqual(set(pg_control.LIVE_MAP) & set(pg_control.LIVE_ABSENT), set())
        self.assertIn('filled_quantity', pg_control.ORDER_COLUMNS)
        self.assertIn('last_qty', pg_control.EVENT_COLUMNS)
        self.assertIn('FROM oe_orders', pg_control.read_sql())

    def test_pg_equal_to_the_core_passes_every_rule_that_reads_mapped_fields(self):
        variant = pg_control.pg_sample(self.sample, self.pg)
        self.assertEqual(variant['core']['live_orders'][0]['me_order_id'], 5004)
        verdict = order_oracle.judge(variant)
        statuses = {k: v['status'] for k, v in verdict['rules'].items()}
        # The clean sample's iceberg makes O8 read hidden_qty, which PG does not carry: INCONCLUSIVE with its name, never
        # a KeyError; every other rule PASSes on the PG copy of a projection that equals the core
        self.assertEqual({k for k, v in statuses.items() if v != 'PASS'}, {'O8'})
        self.assertIn('pg sample incomplete: hidden_qty', verdict['rules']['O8']['detail'])
        differs, _ = pg_control.divergence(self.sample, self.pg)
        self.assertFalse(differs)

    def test_a_lagging_projection_fails_on_o4_o5_o6(self):
        # The projection stopped before the last event: order 1001's FILL (seq 9) is missing and its row is still live
        pg = copy.deepcopy(self.pg)
        pg['events'] = [e for e in pg['events'] if e['journal_seq'] != 9]
        row = next(o for o in pg['orders'] if o['order_id'] == 1001)
        row.update(status='PARTIALLY_FILLED', filled_quantity=oracle_samples.Q, remaining_quantity=oracle_samples.Q,
                   me_order_id=5001)
        differs, detail = pg_control.divergence(self.sample, pg)
        self.assertTrue(differs)
        self.assertEqual(detail['event_seqs_missing_in_pg'], [9])
        verdict = order_oracle.judge(pg_control.pg_sample(self.sample, pg))
        failing = {k for k, v in verdict['rules'].items() if v['status'] == 'FAIL'}
        self.assertTrue(failing & {'O4', 'O5', 'O6'}, verdict['rules'])
        lines = pg_control.control_lines({'status': 'PASS'}, {'status': 'PASS'}, differs, detail, verdict)
        lines['pg_oracle_not_pass']['consequence_of'] = 'divergence'
        lines['pg_sample_complete'] = pg_control.line(True, {}, None)   # the iceberg's O8 (see above) is not this row
        status, _ = smoke_core.verdict(lines)
        self.assertEqual(status, 'PASS', lines)

    def test_control_the_pg_oracle_forced_to_pass(self):
        lines = pg_control.control_lines({'status': 'PASS'}, {'status': 'PASS'}, True, {}, {'status': 'PASS', 'rules': {}})
        status, _ = smoke_core.verdict(lines)
        self.assertEqual(status, 'FAIL')
        self.assertEqual(lines['pg_oracle_not_pass']['text'], pg_control.PASSED_TEXT)
        print(lines['pg_oracle_not_pass']['text'])

    def test_control_pg_equal_to_the_core_is_vacuous(self):
        lines = pg_control.control_lines({'status': 'PASS'}, {'status': 'PASS'}, False, {}, {'status': 'PASS', 'rules': {}})
        lines['pg_oracle_not_pass']['consequence_of'] = 'divergence'
        status, control = smoke_core.verdict(lines, ('pg-no-freeze', pg_control.VACUOUS_TEXT, True))
        self.assertEqual(status, 'INCONCLUSIVE')
        self.assertTrue(control['held'])

    def test_control_a_pg_row_without_a_mapped_field(self):
        pg = copy.deepcopy(self.pg)
        del pg['orders'][0]['remaining_quantity']
        pg['orders'][0]['status'] = 'NEW'
        with self.assertRaises(Inconclusive) as caught:
            pg_control.pg_sample(self.sample, pg)
        self.assertEqual(str(caught.exception), 'pg sample incomplete: remaining')
        print(caught.exception)
        row = pg_control.StrictRow(order=1)
        with self.assertRaisesRegex(Inconclusive, '^pg sample incomplete: budget$'):
            row.get('budget', 0)
        verdict = {'status': 'INCONCLUSIVE', 'rules': {'O8': {'status': 'INCONCLUSIVE',
                                                              'detail': 'Inconclusive: pg sample incomplete: hidden_qty'}}}
        lines = pg_control.control_lines({'status': 'PASS'}, {'status': 'PASS'}, True, {}, verdict)
        self.assertEqual(lines['pg_sample_complete']['text'], 'pg sample incomplete: hidden_qty')
        self.assertEqual(smoke_core.verdict(lines)[0], 'INCONCLUSIVE')

    def test_the_barrier_belongs_to_the_pg_read(self):
        variant = pg_control.pg_sample(self.sample, self.pg)
        self.assertEqual(variant['barrier']['samples'][0], variant['barrier']['samples'][1])
        self.assertNotEqual(variant['barrier']['samples'][1]['core_events_digest'],
                            self.sample['barrier']['samples'][1]['core_events_digest'])

    def test_read_pg_needs_two_equal_reads(self):
        reads = iter(['{"orders": [], "events": [], "fills": []}', '{"orders": [{"order_id": 1}], "events": [], "fills": []}',
                      '{"orders": [{"order_id": 1}], "events": [], "fills": []}'])
        got = pg_control.read_pg(lambda db, sql: next(reads), 'r01_gateway', sleep=lambda s: None)
        self.assertEqual(got['orders'], [{'order_id': 1}])
        clock = iter(range(0, 1000, 10))
        with self.assertRaisesRegex(Inconclusive, 'pg sample did not settle'):
            n = iter(range(10 ** 6))
            pg_control.read_pg(lambda db, sql: '{"orders": [%d], "events": [], "fills": []}' % next(n), 'r01_gateway',
                               clock=lambda: next(clock), sleep=lambda s: None, bound_s=30)

    def test_dropped_record_must_be_the_last_of_its_order(self):
        sample = {'core_events': [{'seq': 1, 'order': 7}, {'seq': 2, 'order': 7}, {'seq': 3, 'order': 8}]}
        self.assertTrue(red_proofs.dropped_line(sample, 2)['holds'])
        sample['core_events'].append({'seq': 4, 'order': 7})
        out = red_proofs.dropped_line(sample, 2)
        self.assertEqual((out['holds'], out['text'], out.get('inconclusive')),
                         (False, 'dropped record is not the last of its order', True))


# ------------------------------------------------------------------ the money twin

def log_row(kind, status, sent_ns):
    return {'path': f'/api/v2/balances/{kind}', 'status': status, 'sent_ns': sent_ns}


class MoneyTwinTest(unittest.TestCase):
    def test_the_money_oracle_does_not_pass_on_a_stale_money_history(self):
        sample = oracle_samples.clean_sample()
        self.assertEqual(core_oracle.judge(sample)['status'], 'PASS')

        def stale(s):
            # the money projector froze before the last movement (the withdrawal): the history lacks its record
            last = s['money_journal'][-1]['seq']
            s['money_journal'] = s['money_journal'][:-1]
            s['money_journal_legs'] = [leg for leg in s['money_journal_legs'] if leg['seq'] != last]
        verdict = core_oracle.judge(oracle_samples.variant(sample, stale))
        self.assertNotEqual(verdict['status'], 'PASS')
        self.assertEqual(verdict['rules']['M14']['status'], 'FAIL', verdict['rules'])
        lines = red_proofs.money_lines(verdict, {'status': 'PASS'})
        self.assertEqual(lines['money_oracle_names_staleness']['detail']['named'], ['M14'])

    def test_movement_after_the_freeze(self):
        sample = {'core': {'last_applied_trade_id': 9},
                  'me_journal': [{'type': 'trade', 'trade_id': t} for t in (6, 7, 8, 9)]}
        log = [log_row('deposit', 200, 5), log_row('deposit', 200, 20), log_row('withdraw', 200, 21)]
        out = red_proofs.movement_after_freeze(log, sample, 10, 7)
        self.assertTrue(out['holds'])
        self.assertEqual(out['detail']['trades_after'], [8, 9])
        none = red_proofs.movement_after_freeze(log[:1], {'core': {'last_applied_trade_id': 7}, 'me_journal': []}, 10, 7)
        self.assertEqual((none['holds'], none['text'], none.get('inconclusive')), (False, red_proofs.NO_MOVEMENT_TEXT, True))
        some = red_proofs.movement_after_freeze(log[:2], {'core': {'last_applied_trade_id': 7}, 'me_journal': []}, 10, 7)
        self.assertEqual(some['text'], 'money movement after the freeze incomplete: withdrawal')

    def test_history_behind_against_the_decided_records(self):
        sample = {'core': {'last_applied_trade_id': 2}, 'funding': [{'outcome': 'ACK'}] * 3 + [{'outcome': 'REJECT'}],
                  'me_journal': [{'type': 'trade', 'trade_id': 1}, {'type': 'trade', 'trade_id': 2}],
                  'money_journal': [{}] * 4}
        self.assertTrue(red_proofs.history_behind(sample)['holds'])
        sample['money_journal'] = [{}] * 5
        head = red_proofs.history_behind(sample)
        self.assertEqual((head['text'], head.get('inconclusive')), (red_proofs.MONEY_AT_HEAD_TEXT, True))

    def test_control_the_money_oracle_passing_fails_the_twin(self):
        lines = {'money_after_freeze': red_proofs.line(True, {}),
                 'money_history_behind': smoke_core.consequence(red_proofs.line(True, {}), 'money_after_freeze')}
        lines.update(red_proofs.money_lines({'status': 'PASS', 'rules': {}}, {'status': 'PASS'}))
        status, _ = smoke_core.verdict(lines)
        self.assertEqual(status, 'FAIL')
        self.assertEqual(lines['money_oracle_not_pass']['text'], red_proofs.MONEY_PASSED_TEXT)

    def test_vacuity_controls_hold_alone(self):
        # no movement after the freeze: the history line is not judged, only the vacuity text fails
        lines = {'money_after_freeze': red_proofs.line(False, {}, red_proofs.NO_MOVEMENT_TEXT, inconclusive=True),
                 'money_history_behind': smoke_core.consequence(red_proofs.line(False, {}, red_proofs.MONEY_AT_HEAD_TEXT,
                                                                                inconclusive=True), 'money_after_freeze')}
        lines.update(red_proofs.money_lines({'status': 'PASS', 'rules': {}}, {'status': 'PASS'}))
        status, control = smoke_core.verdict(lines, red_proofs.CONTROLS['money-creates-only'])
        self.assertEqual((status, control['held']), ('INCONCLUSIVE', True))


# ------------------------------------------------------------------ one writer per table

NODES = {'projector': '10.0.0.9', 'pj0': '10.0.0.20', 'pj1': '10.0.0.21', 'gw0': '10.0.0.30', 'md0': '10.0.0.40'}
ALL = ['DELETE', 'INSERT', 'REFERENCES', 'SELECT', 'TRIGGER', 'TRUNCATE', 'UPDATE']


def relation(name, kind, owner, effective, acl=()):
    return {'name': name, 'kind': kind, 'owner': owner, 'acl': list(acl), 'effective': effective}


def green_listing():
    """The listing the role plan gives (the shape of table_owners.take_listing)."""
    ret = core_contracts.RETENTION_ROLE
    dbs = {}
    for db, spec in core_contracts.TABLE_OWNERS.items():
        rels = []
        history = spec.get('retention_tables')
        for name, writer in spec['tables'].items():
            eff = {writer: list(ALL)}
            if spec['retention'] and (history is None or name in history):
                eff[ret] = ['TRUNCATE'] if db == 'r01_money' else ['DELETE', 'TRUNCATE']
            rels.append(relation(name, 'r', writer, eff))
        for name, writer in spec['views'].items():
            readers = spec['view_readers'][name]
            eff = {writer: list(ALL), **{r: ['SELECT'] for r in readers}}
            if 'oe_history_reader' in readers:
                eff['oe_gateway'] = ['SELECT']
            if spec['retention'] and history is None:
                eff[ret] = ['DELETE', 'TRUNCATE']
            rels.append(relation(name, 'v', writer, eff, [f'{writer}=arwdDxt/{writer}'] + [f'{r}=r/{writer}' for r in readers]))
        dbs[db] = {'relations': rels, 'default_acl': []}
    roles = [{'name': 'runtime_fixture', 'login': True, 'super': True}] + [
        {'name': r, 'login': True, 'super': False} for r in core_contracts.LOGIN_ROLES]
    sessions = [{'db': 'r01_money', 'user': 'core', 'addr': '10.0.0.9'},
                {'db': 'r01_gateway', 'user': 'oe_projector', 'addr': '10.0.0.20'},
                {'db': 'oe_marketdata', 'user': 'oe_marketdata_writer', 'addr': '10.0.0.40'},
                {'db': 'r01_money', 'user': 'runtime_fixture', 'addr': '10.0.0.1'}]
    return {'databases': dbs, 'roles': roles, 'sessions': sessions}


DECLARED = {'projector': ['core'], 'pj0': ['oe_projector'], 'pj1': ['oe_projector'], 'gw0': ['oe_gateway'],
            'md0': ['oe_marketdata_writer']}


def failing(lines):
    return sorted(v['text'] for v in lines.values() if not v['holds'])


def rel(listing, db, name):
    return next(r for r in listing['databases'][db]['relations'] if r['name'] == name)


class TableOwnersTest(unittest.TestCase):
    def test_the_role_plan_holds(self):
        lines, info = table_owners.judge(green_listing(), DECLARED, NODES)
        self.assertEqual(failing(lines), [])
        self.assertEqual(info['superusers'], ['runtime_fixture'])

    def test_view_readers_are_per_view(self):
        listing = green_listing()
        rels = {r['name']: r for r in listing['databases']['r01_money']['relations']}
        # the gateway's history reader on the money lookup view, and oe_money_reader on it, are both unnamed there
        for grantee in ('oe_history_reader', 'oe_money_reader'):
            view = dict(rels['money_journal_leg_asset'], acl=['core=arwdDxt/core', f'{grantee}=r/core'])
            planted = copy.deepcopy(listing)
            planted['databases']['r01_money']['relations'] = [view if r['name'] == view['name'] else r
                                                              for r in planted['databases']['r01_money']['relations']]
            lines, _ = table_owners.judge(planted, DECLARED, NODES)
            self.assertEqual(failing(lines), [f'view readable by an unnamed role: money_journal_leg_asset: {grantee}'])
        self.assertIn('oe_money_reader=r/core', rels['gateway_balance_movements_v1']['acl'])

    def test_the_retention_role_keeps_the_money_history_tables_only(self):
        listing = green_listing()
        for r in listing['databases']['r01_money']['relations']:
            if r['name'] == 'money_market_asset':
                r['effective']['history_retention'] = ['DELETE', 'TRUNCATE']
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['retention role has a grant outside its tables: money_market_asset'])

    def test_red_two_writer_kinds_on_the_superuser_login(self):
        # today's fixture: the money projector and oe-projector both log in as the initdb superuser
        declared = dict(DECLARED, projector=['runtime_fixture'], pj0=['runtime_fixture'], pj1=['runtime_fixture'])
        listing = green_listing()
        listing['sessions'] = [dict(s, user='runtime_fixture') if s['addr'] in ('10.0.0.9', '10.0.0.20') else s
                               for s in listing['sessions']]
        lines, _ = table_owners.judge(listing, declared, NODES)
        self.assertIn('login role shared by two process kinds: runtime_fixture', failing(lines))
        self.assertIn('process kind logs in as the bootstrap superuser: oe-projector', failing(lines))

    def test_control_gateway_insert_on_oe_orders(self):
        listing = green_listing()
        rel(listing, 'r01_gateway', 'oe_orders')['effective']['oe_gateway'] = ['INSERT']
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['second writer on oe_orders: oe_gateway'])
        self.assertEqual(smoke_core.verdict(lines, red_proofs.CONTROLS['owners-gateway-insert'])[0], 'PASS')

    def test_control_retention_insert(self):
        listing = green_listing()
        rel(listing, 'oe_marketdata', 'md_trades')['effective']['history_retention'] += ['INSERT']
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['retention role can insert: md_trades'])
        self.assertEqual(smoke_core.verdict(lines, red_proofs.CONTROLS['owners-retention-insert'])[0], 'PASS')

    def test_control_relation_created_before_the_default_privileges(self):
        listing = green_listing()
        for r in listing['databases']['r01_gateway']['relations']:
            r['effective'].pop('history_retention', None)
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), sorted('retention role has no grant: ' + t
                                                for t in core_contracts.TABLE_OWNERS['r01_gateway']['tables']))
        self.assertEqual(smoke_core.verdict(lines, red_proofs.CONTROLS['owners-late-default-privileges'])[0], 'PASS')

    def test_control_a_third_role_with_delete(self):
        listing = green_listing()
        rel(listing, 'r01_money', 'money_journal')['effective']['planted_cleaner'] = ['DELETE']
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['unnamed delete role on money_journal: planted_cleaner'])
        self.assertEqual(smoke_core.verdict(lines, red_proofs.CONTROLS['owners-third-delete-role'])[0], 'PASS')

    def test_the_money_history_gives_the_retention_role_truncate_alone(self):
        # the age delete is the schema's own function: DELETE or SELECT on the money history is a grant outside its tables
        for extra in ('DELETE', 'SELECT'):
            listing = green_listing()
            rel(listing, 'r01_money', 'money_journal')['effective']['history_retention'] = ['TRUNCATE', extra]
            self.assertEqual(failing(table_owners.judge(listing, DECLARED, NODES)[0]),
                             ['retention role has a grant outside its tables: money_journal'])
        listing = green_listing()
        rel(listing, 'r01_money', 'money_journal_leg')['effective'].pop('history_retention')
        self.assertEqual(failing(table_owners.judge(listing, DECLARED, NODES)[0]), ['retention role has no grant: money_journal_leg'])
        # the retention mark and totals: the projector's own, nothing for the retention role; absent on a cut whose
        # projector does not create them, which is not a missing relation
        listing = green_listing()
        rel(listing, 'r01_money', 'money_journal_pruned')['effective']['history_retention'] = ['TRUNCATE']
        self.assertEqual(failing(table_owners.judge(listing, DECLARED, NODES)[0]),
                         ['retention role has a grant outside its tables: money_journal_pruned'])
        listing = green_listing()
        listing['databases']['r01_money']['relations'] = [r for r in listing['databases']['r01_money']['relations']
                                                          if not r['name'].startswith('money_journal_pruned')]
        self.assertEqual(failing(table_owners.judge(listing, DECLARED, NODES)[0]), [])

    def test_views_are_judged_apart(self):
        listing = green_listing()
        view = rel(listing, 'r01_gateway', 'gateway_fills_v1')
        view['acl'].append('oe_stream=r/oe_projector')
        view['effective']['history_retention'] = ['DELETE', 'SELECT', 'TRUNCATE']
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['retention role has a grant outside its tables: gateway_fills_v1',
                                          'view readable by an unnamed role: gateway_fills_v1: oe_stream'])
        # a view without the retention role's DELETE is fine (at most DELETE and TRUNCATE); a table without it is not
        view['effective'].pop('history_retention'); view['acl'].pop()
        self.assertEqual(failing(table_owners.judge(listing, DECLARED, NODES)[0]), [])

    def test_no_retention_role_where_the_table_gives_it_none(self):
        listing = green_listing()
        rel(listing, 'r01_history_b', 'oe_orders')['effective']['history_retention'] = ['DELETE', 'TRUNCATE']
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['retention role has a grant outside its tables: oe_orders'])

    def test_unnamed_and_missing_relations_and_owner(self):
        listing = green_listing()
        listing['databases']['r01_money']['relations'].append(relation('scratch', 'r', 'core', {'core': ALL}))
        listing['databases']['oe_marketdata']['relations'] = [
            r for r in listing['databases']['oe_marketdata']['relations'] if r['name'] != 'md_state']
        rel(listing, 'r01_gateway', 'oe_fills')['owner'] = 'oe_gateway'
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['owner of oe_fills is oe_gateway, the table names oe_projector',
                                          'relation missing: oe_marketdata.md_state',
                                          'relation not in the ownership table: r01_money.scratch'])
        self.assertEqual(smoke_core.verdict(lines)[0], 'INCONCLUSIVE')

    def test_a_session_under_an_undeclared_role(self):
        listing = green_listing()
        listing['sessions'].append({'db': 'r01_gateway', 'user': 'oe_projector', 'addr': '10.0.0.30'})
        lines, _ = table_owners.judge(listing, DECLARED, NODES)
        self.assertEqual(failing(lines), ['login role shared by two process kinds: oe_projector',
                                          'undeclared login: oe-gateway as oe_projector'])

    def test_env_logins_read_user_names_only(self):
        env = {'PROJECTOR_POSTGRES_USER': 'core', 'PROJECTOR_POSTGRES_PASSWORD': 'secret',
               'GATEWAY_PG_URL': 'postgresql://oe_gateway@10.0.0.1:5432/r01_gateway', 'MD_PG_USER': 'oe_marketdata_writer',
               'MD_PG_PASSWORD_FILE': '/data/pg-password', 'HISTORY_PROJECTOR_PG_URL': 'postgresql://10.0.0.1/x'}
        self.assertEqual(table_owners.env_logins(env), {'core', 'oe_gateway', 'oe_marketdata_writer'})

    def test_the_fixture_plan_is_the_console_plan(self):
        # cloud-console services/historydb.go: one login role per process kind, the reader group, the retention role
        self.assertEqual(set(core_contracts.LOGIN_ROLES), {'core', 'oe_gateway', 'oe_stream', 'oe_projector',
                                                           'oe_marketdata_writer', 'history_retention'})
        self.assertNotIn(core_contracts.FIXTURE_SUPERUSER, core_contracts.LOGIN_ROLES)
        plan = core_contracts.DATABASE_ROLE_PLAN
        self.assertEqual(plan['r01_gateway']['writers'], ['oe_gateway', 'oe_projector'])
        self.assertEqual(plan['r01_money']['retention_select'], [])
        self.assertEqual(plan['r01_money']['retention_truncate_only'], ['money_journal', 'money_journal_leg'])
        self.assertFalse(plan['r01_history_b']['retention'])
        self.assertEqual(set(plan), set(core_contracts.TABLE_OWNERS))


# ------------------------------------------------------------------ registration and refusals

class RegistrationTest(unittest.TestCase):
    def test_the_scenarios_are_known_to_the_nightly(self):
        for name in red_proofs.SCENARIOS:
            self.assertTrue(nightly.scenario_known(name), name)

    def test_kinds(self):
        def manifest(kind):
            spec = core_contracts.GATEWAY_KINDS[kind]
            slots = dict(spec['slots'], **spec['projectors'], fwd0='ct_forwarder', fwd1='ct_forwarder')
            return {'manifest_kind': kind, 'slot_artifacts': slots}
        self.assertIsNone(red_proofs.check_scenario(manifest('cps'), 'core-table-owners', environ={}))
        self.assertIsNone(red_proofs.check_scenario(manifest('pj-nc-dropone-ext'), 'core-control-pgorders', environ={}))
        with self.assertRaisesRegex(Inconclusive, 'runs on cps, cps-ext; this manifest is pj-nc-dropone'):
            red_proofs.check_scenario(manifest('pj-nc-dropone'), 'core-control-stale-money-history', environ={})
        with self.assertRaisesRegex(Inconclusive, 'is a control of core-table-owners'):
            red_proofs.check_scenario(manifest('cps'), 'core-control-pgorders', environ={'RED_CONTROL': 'owners-gateway-insert'})
        self.assertEqual(red_proofs.check_scenario(manifest('cps'), 'core-control-pgorders', environ={'RED_CONTROL': 'pg-no-freeze'}),
                         ('pg-no-freeze', 'control vacuous: PG equals the core', True))



class RefusalRowTest(unittest.TestCase):
    """The second-writer row: the OMS cannot start next to a core; each refusal and its control (refusals.py)."""

    def test_a_cut_with_oms_app_is_refused(self):
        import test_release_cut as trc
        with tempfile.TemporaryDirectory() as d:
            w = trc.World(d)
            patch = trc.mock.patch.object(release_cut, 'git_blob', w.blob); patch.start(); self.addCleanup(patch.stop)
            p = w.put('old/oms-app.jar', b'oms-app'); w.pin(p, trc.TAG['core'], 'oms-app.jar')
            m = copy.deepcopy(w.m)
            m['artifacts']['oms-app'] = trc.World.entry(p, trc.TAG['core'], 'attested')

            def leg(rules):
                found = release_cut.check(m, rules=rules, old_pins=w.pins)
                named = [t for r, t in found.items if r == 'K5' and 'oms-app' in t]
                return None if named else refusals.CUT_TEXT
            self.assertIsNone(leg(release_cut.RULES))
            off = leg(tuple(r for r in release_cut.RULES if r != 'K5'))
            self.assertEqual(off, refusals.CUT_TEXT)
            print(off)

    def test_a_manifest_with_the_role_oms_is_refused(self):
        import test_core_fixture
        with tempfile.TemporaryDirectory() as d:
            m = test_core_fixture.manifest(d)
            m['nodes']['oms'] = '172.30.99.250'
            path = Path(d) / 'manifest.json'

            def leg(module):
                try:
                    module.validate_core_manifest(m, path, cpu_count=24)
                except Violation as error:
                    if 'legacy roles are absent from the core topology: oms' in str(error):
                        return None
                return refusals.ROLE_TEXT
            self.assertIsNone(leg(core_contracts))
            # the test copy: the same module with the legacy-role refusal switched off
            source = (HERE / 'core_contracts.py').read_text()
            anchor = '        legacy = LEGACY_ROLES & set(nodes)\n'
            self.assertEqual(source.count(anchor), 1)
            copy_path = Path(d) / 'core_contracts_off.py'
            copy_path.write_text(source.replace(anchor, '        legacy = set()\n'))
            spec = importlib.util.spec_from_file_location('core_contracts_off', copy_path)
            off_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(off_module)
            off = leg(off_module)
            self.assertEqual(off, refusals.ROLE_TEXT)
            print(off)

    @unittest.skipUnless(os.environ.get('CONSOLE_TREE'), 'CONSOLE_TREE (a cloud-console tree) not set: refusals 3 and 4 '
                                                         'run with python3 refusals.py --console <tree>')
    def test_the_console_refusals(self):
        rows = refusals.console_legs(os.environ['CONSOLE_TREE'])
        self.assertTrue(all(h for _, h, _ in rows), rows)
        self.assertEqual([t for _, _, t in rows if 'accepted' in t], [refusals.SETTING_TEXT, refusals.SERVICE_TEXT])

    def test_the_switch_off_patches_apply(self):
        with tempfile.TemporaryDirectory() as d:
            tree = Path(d)
            (tree / 'config').mkdir(); (tree / 'services').mkdir()
            (tree / 'config' / 'retired.go').write_text('var RetiredEnv = []RetiredSetting{\n'
                                                        '\t{"OMS_PROJECT_DIR", "", "the Java OMS"},\n\t{"SIM_BINARY", "", "x"},\n}\n')
            (tree / 'services' / 'catalog_test.go').write_text('func v1ProcessSet(external bool) map[string]bool {\n'
                                                              '\tset := map[string]bool{}\n\treturn set\n}\n\n'
                                                              '// processSetDiff names\n')
            refusals.switch_off_setting(tree); refusals.switch_off_service(tree)
            self.assertNotIn('OMS_PROJECT_DIR', (tree / 'config' / 'retired.go').read_text())
            self.assertIn('set["oms"] = true', (tree / 'services' / 'catalog_test.go').read_text())


if __name__ == '__main__':
    unittest.main()
