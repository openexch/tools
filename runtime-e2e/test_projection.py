# SPDX-License-Identifier: Apache-2.0
"""The projection slots, the stand-in, the dump tool, the replay-count probe and the projection drills' registry."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from contracts import Inconclusive, Violation
import core_contracts
from core_contracts import validate_core_manifest
from credentials import KeyRing
import projection_drills
import projection_dump
import projector_stub
import replay_count
from test_core_fixture import fixture_for, write
from test_gateway_fixture import gateway_manifest


def projection_manifest(directory, driver='external', mode='follow', slots=None):
    """A gateway manifest with the two projection roles and every projection artifact pinned."""
    m = gateway_manifest(directory, driver)
    for j, role in enumerate(sorted(core_contracts.PROJECTION_ROLES)):
        m['nodes'][role] = f'172.30.99.{44 + j}'
    m['ports'] = core_contracts.ports_of(m)
    libs = copy.deepcopy(m['artifacts']['forwarder']['libs']) if driver == 'external' else None
    stub = dict(write(directory, 'projector_stub.py', b'# stub'), target='projector_stub', driver='embedded', mode=mode)
    projector = dict(write(directory, 'oe-projector', b'elf-oe-projector'), target='oe-projector', driver=driver)
    if libs:
        projector['libs'] = libs
    m['artifacts'].update(projector_stub=stub, history_projector=projector, history_projector_nc=None)
    m['slot_artifacts'].update(slots or {'pj0': 'projector_stub', 'pj1': 'projector_stub'})
    return m


def projection_fixture(directory, driver='external', mode='follow'):
    f = fixture_for(projection_manifest(directory, driver, mode), directory)
    f.gateway_slots = f.projection_slots = True
    f.keys = KeyRing(gateway=True, projection=True)
    f.secret_values = f.keys.secrets()
    return f


class ProjectionContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name
        self.path = Path(self.dir) / 'manifest.json'
        self.m = projection_manifest(self.dir)

    def tearDown(self):
        self.temp.cleanup()

    def check(self, m):
        validate_core_manifest(m, self.path, cpu_count=24)

    def bad(self, edit, text):
        m = copy.deepcopy(self.m); edit(m)
        with self.assertRaises(Violation) as caught:
            self.check(m)
        self.assertIn(text, str(caught.exception))

    def test_a_projection_manifest_passes_in_both_driver_modes(self):
        self.check(self.m)
        self.check(projection_manifest(self.dir, 'embedded'))
        self.assertTrue(core_contracts.projection_manifest(self.m))
        self.assertEqual(core_contracts.roles_of(self.m),
                         core_contracts.ROLES | core_contracts.GATEWAY_ROLES | core_contracts.PROJECTION_ROLES)
        self.assertEqual(core_contracts.ports_of(self.m)['projector_admin'], 8095)

    def test_the_two_roles_are_declared_together_and_only_with_the_gateway_roles(self):
        self.bad(lambda m: m['nodes'].pop('pj1'), 'declared together')
        m = copy.deepcopy(self.m)
        for role in core_contracts.GATEWAY_ROLES:
            m['nodes'].pop(role)
        with self.assertRaisesRegex(Violation, 'need the gateway roles'):
            core_contracts.projection_manifest(m)

    def test_artifacts_are_declared_pinned_and_targeted(self):
        self.bad(lambda m: m['artifacts'].pop('history_projector'), 'declares every projection artifact')
        self.bad(lambda m: m['artifacts']['projector_stub'].__setitem__('target', 'oe-projector'), 'target must be projector_stub')
        self.bad(lambda m: m['artifacts']['projector_stub'].__setitem__('driver', 'external'), 'embedded driver')
        self.bad(lambda m: m['artifacts']['projector_stub'].__setitem__('mode', 'eager'), 'names its mode')
        self.bad(lambda m: m['artifacts']['history_projector'].__setitem__('mode', 'follow'), 'only the stand-in has a mode')
        self.bad(lambda m: m['artifacts']['history_projector'].pop('libs'), 'an external slot stages aeronmd')
        self.bad(lambda m: m['slot_artifacts'].__setitem__('pj0', 'gateway'), 'cannot run artifact')
        self.bad(lambda m: m['artifacts'].__setitem__('projector_stub', None), 'artifacts.projector_stub is null')
        self.bad(lambda m: m['ports'].pop('projector_admin'), 'port profile')

    def test_projection_kinds_are_gateway_and_cut_kinds_with_legal_slots(self):
        self.assertEqual(core_contracts.PROJECTION_KINDS - core_contracts.PROJECTOR_BINARY_KINDS,
                         {'pj-dry', 'pj-dry-ext', 'pj-dry-beatalways'})
        self.assertEqual(core_contracts.PROJECTOR_BINARY_KINDS,
                         {'pj', 'pj-ext', 'pj-nc-pinrecording', 'pj-nc-nostopreplay-ext', 'pj-nc-wallclock', 'pj-nc-dropone',
                          'pj-nc-beatalways', 'pj-nc-nostale'})
        for kind in core_contracts.PROJECTION_KINDS:
            spec = core_contracts.GATEWAY_KINDS[kind]
            self.assertIn(kind, core_contracts.CUT_KINDS)
            self.assertEqual(set(spec['projectors']), core_contracts.PROJECTION_ROLES)
            if kind in core_contracts.PROJECTOR_BINARY_KINDS:
                self.assertNotIn('stub_mode', spec)
                nc = 'history_projector_nc' in spec['projectors'].values()
                self.assertEqual(nc, spec.get('projector_define') in core_contracts.PROJECTION_NC_DEFINES)
            else:
                self.assertIn(spec['stub_mode'], core_contracts.STUB_MODES)
            self.assertEqual('-ext' in kind, spec['driver'] == 'external')
        self.assertEqual(core_contracts.GATEWAY_KINDS['pj-dry-beatalways']['projection_control'], 'history-freshness')
        # every control of the binary drills has its kind, and the compared projections run the control build
        controls = {k: v['projection_control'] for k, v in core_contracts.GATEWAY_KINDS.items()
                    if k in core_contracts.PROJECTOR_BINARY_KINDS and v.get('projection_control')}
        self.assertEqual(sorted(controls.values()), sorted(projection_drills.SCENARIOS * 2))
        for kind in ('pj-nc-wallclock', 'pj-nc-dropone', 'pj-nc-nostopreplay-ext'):
            self.assertEqual(set(core_contracts.GATEWAY_KINDS[kind]['projectors'].values()), {'history_projector_nc'})

    def test_a_control_build_names_its_one_define_of_its_kind(self):
        m = projection_manifest(self.dir, slots={'pj0': 'history_projector_nc', 'pj1': 'history_projector'})
        m['manifest_kind'] = 'pj-nc-pinrecording'
        nc = dict(m['artifacts']['history_projector'], defines=['PROJ_NC_PIN_RECORDING'])
        m['artifacts']['history_projector_nc'] = nc
        check = core_contracts.validate_projection_artifacts
        check(m)
        for defines, text in ((['PROJ_NC_DROP_ONE'], 'is the PROJ_NC_PIN_RECORDING build'),
                              (['PROJ_NC_WHATEVER'], 'one control define'), (None, 'one control define')):
            bad = copy.deepcopy(m); bad['artifacts']['history_projector_nc']['defines'] = defines
            with self.assertRaisesRegex(Violation, text):
                check(bad)
        bad = copy.deepcopy(m); bad['artifacts']['history_projector']['defines'] = ['PROJ_NC_DROP_ONE']
        with self.assertRaisesRegex(Violation, 'only a control build names defines'):
            check(bad)

    def test_projection_keys_only_for_a_projection_manifest(self):
        ring = KeyRing(gateway=True, projection=True)
        for slot, key_id in (('pj0', 57), ('pj1', 58)):
            self.assertEqual(ring.keys[(slot, 'ae')][:2], (key_id, 'GATEWAY'))
        self.assertNotIn(('pj0', 'ae'), KeyRing(gateway=True).keys)


class ProjectionFixtureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_stub_env_in_both_driver_modes_is_allowlisted_and_names_its_own_database_and_key(self):
        from core_contracts import assert_production_timeouts
        for driver in ('external', 'embedded'):
            f = projection_fixture(self.dir, driver)
            for slot, database in (('pj0', 'r01_gateway'), ('pj1', 'r01_history_b')):
                env = f.projection_slot_env(slot)
                assert_production_timeouts(env, f.allowed_env())
                self.assertTrue(env['STUB_PG_URL'].endswith('/' + database))
                self.assertEqual(env['CORE_AUTH_CREDENTIAL'], f.keys.credential(slot, 'ae'))
                self.assertEqual(env['STUB_ADMIN_BIND'], f.m['nodes'][slot] + ':8095')
                self.assertEqual(env['CORE_LOCAL_HOST'], f.m['nodes'][slot])
                self.assertEqual(env['STUB_MODE'], 'follow')
            f.projection_targets = {'pj1': 'r01_gateway'}
            self.assertTrue(f.projection_slot_env('pj1')['STUB_PG_URL'].endswith('/r01_gateway'))

    def test_the_binary_env_in_both_driver_modes_names_its_sources_database_key_file_and_journal(self):
        from core_contracts import assert_production_timeouts
        for driver in ('external', 'embedded'):
            with self.subTest(driver=driver):
                f = projection_fixture(self.dir, driver)
                f.m['slot_artifacts'].update(pj0='history_projector', pj1='history_projector')
                f.m['manifest_kind'] = 'pj' if driver == 'embedded' else 'pj-ext'
                self.assertTrue(f.projector_binary())
                env = f.projection_slot_env('pj0')
                assert_production_timeouts(env, f.allowed_env())
                self.assertFalse([k for k in env if core_contracts.TIMEOUT_WORDS.search(k)])
                self.assertEqual(env['HISTORY_PROJECTOR_DRIVER_MODE'], driver)
                self.assertEqual('AERON_DIR' in env, driver == 'external')
                self.assertEqual('HISTORY_PROJECTOR_DRIVER_DIR' in env, driver == 'embedded')
                self.assertTrue(env['HISTORY_PROJECTOR_PG_URL'].endswith('/r01_gateway'))
                self.assertEqual(env['HISTORY_PROJECTOR_CLUSTER_KEY_FILE'], '/data/cluster-key')
                self.assertEqual(env['HISTORY_PROJECTOR_JOURNAL_STREAM'], '4102')
                self.assertEqual(env['HISTORY_PROJECTOR_JOURNAL_ARCHIVES'].split(','),
                                 [f.archive_endpoint(f'ae{i}') for i in range(3)])
                self.assertEqual(len(env['HISTORY_PROJECTOR_JOURNAL_NODE_ENDPOINTS'].split(',')), 3)
                self.assertEqual(env['HISTORY_PROJECTOR_LOCAL_HOST'], f.m['nodes']['pj0'])
                f.projection_sources = {'pj1': ['ae2']}
                env1 = f.projection_slot_env('pj1')
                self.assertEqual(env1['HISTORY_PROJECTOR_JOURNAL_ARCHIVES'], f.archive_endpoint('ae2'))
                self.assertTrue(env1['HISTORY_PROJECTOR_PG_URL'].endswith('/r01_history_b'))
                f.projection_sources = {'pj1': ['ae2', 'ae2']}
                with self.assertRaisesRegex(Violation, 'distinct core members'):
                    f.projection_slot_env('pj1')
                command = ' '.join(f.projector_slot_command('pj0'))
                self.assertIn('exec /artifacts/history_projector/bin', command)
                self.assertEqual('aeronmd' in command, driver == 'external')
                # the gateways read history through the reader role, the members count the projector's replays
                self.assertIn(core_contracts.HISTORY_READER_LOGIN + '@', f.gateway_pg_url('gw0'))
                f.gateway_history_database = {'gw0': 'r01_history_b'}
                self.assertTrue(f.gateway_pg_url('gw0').endswith('/r01_history_b'))
                self.assertTrue(f.gateway_pg_url('gw1').endswith('/r01_gateway'))
                self.assertEqual(f.engine_env('ae', 0)['CORE_ARCHIVE_REPLAY_PROBE_STREAM'], '4302')
                self.assertNotIn('CORE_ARCHIVE_REPLAY_PROBE_STREAM', f.engine_env('me', 0))

    def test_the_binary_health_reads_into_the_drills_keys(self):
        body = {'version': 'dev', 'build': 'b' * 40, 'projector': {
            'role': 'writer', 'cursor': {'appliedSeq': 41, 'epoch': 7}, 'halt': {'reason': None, 'detail': None},
            'pg': {'lastError': ''},
            'follow': {'source': 1, 'endpoint': '172.30.99.15:19401', 'archiveId': 9, 'recordingId': 3, 'chainIndex': 1,
                       'phase': 'LIVE', 'headSeq': 44, 'beats': 5, 'lagEvents': 3, 'replaysOpen': 1,
                       'counts': {'switches': 2, 'behind': 1, 'stopRequestsAnswered': 0}}}}
        nodes = {'ae0': '172.30.99.13', 'ae1': '172.30.99.14', 'ae2': '172.30.99.15'}
        from core_fixture import projector_health_view
        v = projector_health_view(body, ['ae0', 'ae2'], nodes)
        self.assertEqual(v['source']['member'], 'ae2')
        self.assertEqual((v['role'], v['applied_seq'], v['head_seq'], v['source_switches'], v['beats'], v['halt']),
                         ('writer', 41, 44, 2, 5, None))
        self.assertEqual(v['recordings_walked']['recording_id'], 3)
        body['projector']['follow']['source'] = None
        self.assertEqual(projector_health_view(body, ['ae0', 'ae2'], nodes)['source']['member'], 'ae2')   # by endpoint
        self.assertIsNone(projector_health_view({}, ['ae0'], nodes)['role'])

    def test_readiness_is_health_and_projection_roles_are_fault_targets(self):
        f = projection_fixture(self.dir)
        self.assertEqual(f.ready_target('pj0'), (8095, '/health'))
        f.registry['containers']['pj0'] = 'c-pj0'
        self.assertEqual(f._fault_target('pj0'), 'c-pj0')
        import core_fixture
        self.assertEqual(core_fixture.role_kind('pj1'), 'projection')

    def test_only_a_second_database_is_recreated(self):
        f = projection_fixture(self.dir)
        with self.assertRaisesRegex(Violation, 'only a second projection database'):
            f.recreate_projection_database('r01_gateway')
        with self.assertRaisesRegex(Violation, 'unknown projection database'):
            f.projection_pg_url('r01_money')


class StubMappingTest(unittest.TestCase):
    EVENT = {'seq': 7, 'order': 41, 'kind': 'FILL', 'status': 'PARTIALLY_FILLED', 'reason': 'NONE', 'filled': 5, 'quantity': 9,
             'remaining': 4, 'trade': 3, 'leg': 0, 'hold_amount': 900, 'hold_remaining': 400, 'log_position': 1234,
             'user': 87001, 'market': 1, 'side': 'BUY', 'type': 'MARKET', 'tif': 'IOC', 'price': 77, 'stop_price': 0,
             'last_price': 90, 'last_qty': 5, 'hold_asset': 0, 'client_order_id_high': 0, 'client_order_id_low': 0,
             'created_ms': 10, 'updated_ms': 11, 'me_reason': 255}

    def test_read_contract_null_rules(self):
        cols = projector_stub.order_columns(self.EVENT)
        self.assertIsNone(cols['price'])          # MARKET has no price
        self.assertIsNone(cols['stop_price'])
        self.assertIsNone(cols['reason'])
        self.assertIsNone(cols['me_reason'])
        self.assertIsNone(cols['me_order_id'])
        self.assertIsNone(cols['client_order_id'])
        self.assertEqual(projector_stub.order_columns(dict(self.EVENT, type='LIMIT'))['price'], 77)
        self.assertEqual(projector_stub.client_order_id(0, 1), '00000000-0000-0000-0000-000000000001')

    def test_batch_is_dense_fenced_and_writes_a_fill_only_for_a_trade(self):
        events = [dict(self.EVENT, seq=8), dict(self.EVENT, seq=9, trade=0, last_qty=0, kind='FILL')]
        sql = projector_stub.batch_sql(events, 7, 'pj0-x', lambda e: 'TAKER')
        self.assertEqual(sum(1 for s in sql if s.startswith('INSERT INTO oe_fills')), 1)
        self.assertIn("WHERE writer_token = 'pj0-x' AND applied_seq = 7", sql[-1])
        self.assertIn('applied_seq = 9', sql[-1])
        with self.assertRaisesRegex(ValueError, 'not dense'):
            projector_stub.batch_sql([dict(self.EVENT, seq=9)], 7, 't', lambda e: 'NONE')

    def test_payload_is_canonical(self):
        a = projector_stub.payload(self.EVENT)
        b = projector_stub.payload(dict(reversed(list(self.EVENT.items()))))
        self.assertEqual(a, b)
        self.assertEqual(projector_stub.lit("o'k"), "'o''k'")
        self.assertEqual(projector_stub.lit(b'\x01'), "'\\x01'::bytea")

    def test_settings_are_positive_integers_with_defaults(self):
        self.assertEqual(projector_stub.settings({})['STUB_LEASE_MS'], 10000)
        self.assertEqual(projector_stub.settings({'STUB_POLL_MS': '250'})['STUB_POLL_MS'], 250)
        with self.assertRaises(SystemExit):
            projector_stub.settings({'STUB_POLL_MS': '0'})

    def test_the_url_is_explicit(self):
        pg = projector_stub.Pg('postgresql://runtime_fixture@172.30.99.1:55500/r01_gateway')
        self.assertEqual((pg.user, pg.host, pg.port, pg.database), ('runtime_fixture', '172.30.99.1', 55500, 'r01_gateway'))
        with self.assertRaises(SystemExit):
            projector_stub.Pg('postgresql://h/db')


class FakePg:
    """The stand-in's database as the sequence of answers its cycle reads."""

    def __init__(self, lease=True, applied=0, halt=None):
        self.lease, self.applied, self.halt, self.sent = lease, applied, halt, []
        self.sock = object()

    def query(self, sql):
        self.sent.append(sql)
        if sql.startswith('UPDATE oe_projection_state SET writer_token'):
            return [('UPDATE 1' if self.lease else 'UPDATE 0', [])]
        if sql.startswith('SELECT applied_seq'):
            return [('SELECT 1', [[str(self.applied), '0', self.halt]])]
        if sql.startswith('SELECT trade_id'):
            return [('SELECT 0', [])]
        if sql.startswith('BEGIN'):
            return [('BEGIN', [])] + [('INSERT 0 1', [])] * (sql.count(';') - 1) + [('UPDATE 1', [])]
        return [('UPDATE 1', [])]


class StubCycleTest(unittest.TestCase):
    ENV = {'STUB_ADMIN_BIND': '127.0.0.1:0', 'STUB_PG_URL': 'postgresql://u@h:1/d', 'STUB_INSTANCE': 'pj0',
           'STUB_CORE_PROBE': 'cp', 'STUB_MEMBER_METRICS': 'ae0@h:1', 'CORE_ADDRESSES': 'a', 'CORE_PORT_BASE': '1',
           'CLUSTER_PORT_STRIDE': '1', 'CORE_LOCAL_HOST': 'h', 'CORE_AUTH_CREDENTIAL': 'c'}

    def stub(self, reply, **pg):
        s = projector_stub.Stub(dict(self.ENV))
        s.pg = FakePg(**pg)
        s.leader = lambda: ('ae1', 'h:1')
        s.read = lambda applied: (s.clock(), reply)
        return s

    def event(self, seq, **kv):
        return dict(StubMappingTest.EVENT, seq=seq, kind='ACCEPTED', trade=0, last_qty=0, **kv)

    def test_a_standby_holds_no_session(self):
        s = self.stub(None, lease=False)
        s.read = lambda applied: self.fail('a standby read the core')
        s.cycle()
        self.assertEqual(s.health()['role'], 'standby')

    def test_beats_only_at_the_head(self):
        s = self.stub({'last_seq': 3, 'events': [self.event(1), self.event(2)], 'lost': []})
        s.cycle()
        self.assertEqual(s.health()['beats'], 0)
        self.assertEqual(s.health()['applied_seq'], 2)
        s = self.stub({'last_seq': 2, 'events': [self.event(1), self.event(2)], 'lost': []})
        s.cycle()
        self.assertEqual(s.health()['beats'], 1)

    def test_the_genesis_id_of_a_reply_is_recorded_when_present(self):
        s = self.stub({'last_seq': 2, 'events': [self.event(1), self.event(2)], 'lost': [], 'genesis_id': 4242424242424242})
        s.cycle()
        self.assertEqual(s.health()['genesis_id'], 4242424242424242)
        self.assertTrue(any('epoch = 4242424242424242' in q for q in s.pg.sent))
        s = self.stub({'last_seq': 2, 'events': [self.event(1), self.event(2)], 'lost': []})
        s.cycle()
        self.assertEqual(s.health()['genesis_id'], 0)
        self.assertTrue(any('epoch = 0' in q for q in s.pg.sent))
        s = self.stub({'last_seq': 2, 'events': [self.event(1), self.event(2)], 'lost': [], 'genesis_id': -9223372036854775808})
        s.cycle()
        self.assertEqual(s.health()['genesis_id'], 0)       # the SBE null value of a pre-v9 reply is not a genesis

    def test_no_answer_no_beat_and_an_overrun_parks(self):
        s = self.stub(None)
        s.cycle()
        self.assertEqual((s.health()['beats'], s.health()['probe_unanswered']), (0, 1))
        s = self.stub({'last_seq': 9, 'events': [self.event(5)], 'lost': [[1, 4]]})
        s.cycle()
        self.assertEqual(s.health()['halt']['reason'], 'GAP')
        self.assertFalse(any(q.startswith('BEGIN') for q in s.pg.sent))

    def test_a_lost_fence_rolls_back_and_becomes_a_standby(self):
        s = self.stub({'last_seq': 1, 'events': [self.event(1)], 'lost': []})
        s.pg.query_real = s.pg.query
        s.pg.query = lambda sql: ([('BEGIN', []), ('UPDATE 0', [])] if sql.startswith('BEGIN') else s.pg.query_real(sql))
        s.cycle()
        self.assertEqual((s.health()['role'], s.health()['fence_lost'], s.health()['beats']), ('standby', 1, 0))
        self.assertIn('ROLLBACK', s.pg.sent)

    def test_probe_time_is_counted_answered_or_not(self):
        s = projector_stub.Stub(dict(self.ENV))
        ticks = iter([10.0, 10.75, 20.0, 20.5])
        s.clock = lambda: next(ticks)
        answered = mock.Mock(returncode=0, stdout='{"last_seq": 0, "events": [], "lost": []}\n', stderr='')
        failed = mock.Mock(returncode=1, stdout='', stderr='no leader')
        with mock.patch.object(projector_stub.subprocess, 'run', side_effect=[answered, failed]):
            self.assertIsNotNone(s.read(0)[1])
            self.assertIsNone(s.read(0)[1])
        self.assertEqual(s.health()['probe_ms_total'], 1250)

    def test_the_leader_change_counts_a_switch(self):
        s = self.stub({'last_seq': 0, 'events': [], 'lost': []})
        s.cycle()
        s.leader = lambda: ('ae2', 'h:1')
        s.cycle()
        self.assertEqual((s.health()['source']['member'], s.health()['source_switches']), ('ae2', 1))


class PgWireTest(unittest.TestCase):
    def test_simple_query_rows_tags_and_errors(self):
        pg = projector_stub.Pg('postgresql://u@h:1/d')
        msgs = []

        def msg(kind, payload):
            msgs.append(kind + struct.pack('!i', len(payload) + 4) + payload)
        msg(b'T', b'\0\1')
        msg(b'D', struct.pack('!h', 2) + struct.pack('!i', 1) + b'7' + struct.pack('!i', -1))
        msg(b'C', b'SELECT 1\0')
        msg(b'Z', b'I')
        msg(b'E', b'SERROR\0C23505\0Mduplicate key\0\0')
        msg(b'Z', b'E')
        data = b''.join(msgs)

        class Sock:
            at = 0

            def sendall(self, b):
                pass

            def recv(self, n):
                out = data[Sock.at:Sock.at + n]
                Sock.at += len(out)
                return out
        pg.sock = Sock()
        self.assertEqual(pg.query('SELECT 1'), [('SELECT 1', [['7', None]])])
        with self.assertRaisesRegex(projector_stub.PgError, '23505: duplicate key'):
            pg.query('INSERT')


class DumpToolTest(unittest.TestCase):
    def test_fixed_columns_ordered_by_key_and_no_wall_clock(self):
        sql = projection_dump.copy_sql('oe_fills')
        self.assertTrue(sql.startswith('COPY (SELECT trade_id, order_id,'))
        self.assertTrue(sql.endswith('ORDER BY trade_id, order_id) TO STDOUT'))
        for columns, _ in projection_dump.SETS['all'].values():
            for clock in ('ingested_at', 'beat_at', 'lease_until', 'updated_at'):
                self.assertNotIn(clock, columns)

    def test_dump_hashes_each_table_and_reports_absent_tables(self):
        def run(sql):
            if sql.startswith('SELECT to_regclass'):
                return b'f\n' if 'oe_fills' in sql else b't\n'
            if sql.startswith('SELECT column_name'):
                return b''
            return b'1\tx\n2\ty\n'
        with tempfile.TemporaryDirectory() as d:
            out = projection_dump.dump(run, d, projection_dump.HISTORY_TABLES)
            self.assertEqual(out['oe_fills'], {'absent': True})
            self.assertEqual(out['oe_orders']['sha256'], hashlib.sha256(b'1\tx\n2\ty\n').hexdigest())
            self.assertEqual(out['oe_orders']['rows'], 2)
            sums = (Path(d) / 'SHA256SUMS').read_text()
            self.assertIn('oe_orders.copy', sums)
            self.assertNotIn('oe_fills', sums)

    def test_equal_names_every_differing_or_absent_table(self):
        a = {'t1': {'sha256': 'x'}, 't2': {'sha256': 'y'}, 't3': {'absent': True}}
        b = {'t1': {'sha256': 'x'}, 't2': {'sha256': 'z'}, 't3': {'absent': True}}
        self.assertEqual(projection_dump.equal(a, b), ['t2', 't3'])
        self.assertEqual(projection_dump.equal({'t1': {'sha256': 'x'}}, {'t1': {'sha256': 'x'}}), [])


def cnc_bytes(counters):
    """A synthetic cnc.dat: metadata at 128, zero-length driver buffers, ``counters`` as (type, key bytes, label, value)."""
    meta_len, values_len = 512 * len(counters), 128 * len(counters)
    data = bytearray(128 + meta_len + values_len)
    struct.pack_into('<6i', data, 0, 512, 0, 0, meta_len, values_len, 0)
    for i, (type_id, key, label, value) in enumerate(counters):
        at = 128 + i * 512
        struct.pack_into('<ii', data, at, 1, type_id)
        data[at + 16:at + 16 + len(key)] = key
        struct.pack_into('<i', data, at + 128, len(label))
        data[at + 132:at + 132 + len(label)] = label.encode()
        struct.pack_into('<q', data, 128 + meta_len + i * 128, value)
    return bytes(data)


def pub_key(registration, session, stream, channel):
    return struct.pack('<qiii', registration, session, stream, len(channel)) + channel.encode()


class ReplayCountTest(unittest.TestCase):
    def test_counts_network_publications_on_the_replay_streams(self):
        data = cnc_bytes([(2, pub_key(11, 5, 9161, 'aeron:udp?endpoint=10.0.0.9:20121'), 'snd-pos: 11 5 9161', 1),
                          (2, pub_key(12, 6, 102, 'aeron:udp?endpoint=10.0.0.4:20480'), 'snd-pos: 12 6 102', 2),
                          (1, pub_key(11, 5, 9161, 'aeron:udp'), 'pub-lmt: 11 5 9161', 3)])
        version, rows = replay_count.counters(data)
        self.assertEqual(version, 512)
        pubs = replay_count.publications(rows)
        self.assertEqual([(p['stream'], p['session'], p['registration']) for p in pubs], [(9161, 5, 11), (102, 6, 12)])
        self.assertEqual(pubs[0]['channel'], 'aeron:udp?endpoint=10.0.0.9:20121')

    def test_the_fixture_runs_the_probe_inside_the_member(self):
        f = projection_fixture(tempfile.mkdtemp())
        calls = []

        class R:
            returncode, stderr = 0, ''
            stdout = '{"replays": {"9161": 1}, "shm_bytes": 5}\n'
        f.execute = lambda name, argv, **kw: calls.append((name, argv, kw)) or R()
        self.assertEqual(f.replay_count('ae1', [9161])['replays'], {'9161': 1})
        self.assertEqual(calls[0][0], 'ae1')
        self.assertEqual(calls[0][1], ['python3', '-I', '-', '9161'])
        self.assertIn('def counters', calls[0][2]['input'])
        with self.assertRaises(Violation):
            f.replay_count('me0', [9161])


class DrillRegistryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    def test_three_ids_are_registered(self):
        self.assertEqual(set(projection_drills.SCENARIOS),
                         {'projector-me-restart-follow', 'projection-byte-equal-replay', 'history-freshness'})
        self.assertEqual(set(projection_drills.CONTROL_TEXT), set(projection_drills.SCENARIOS))

    def test_unimplemented_and_unknown_are_refused_before_any_container(self):
        m = projection_manifest(self.dir)
        self.assertEqual(projection_drills.check_scenario(m, 'history-freshness'), 'stub')
        with self.assertRaisesRegex(Inconclusive, 'unknown projection scenario'):
            projection_drills.check_scenario(m, 'history-whatever')
        binary = projection_manifest(self.dir, slots={'pj0': 'history_projector', 'pj1': 'history_projector'})
        mixed = projection_manifest(self.dir, slots={'pj0': 'history_projector', 'pj1': 'projector_stub'})
        for name in projection_drills.SCENARIOS:
            self.assertEqual(projection_drills.check_scenario(binary, name), 'binary')
            with self.assertRaisesRegex(Inconclusive, 'runs on the projector binary'):
                projection_drills.check_scenario(mixed, name)
        with self.assertRaisesRegex(Inconclusive, 'declares the projection roles'):
            projection_drills.check_scenario(gateway_manifest(self.dir), 'history-freshness')

    def test_a_control_kind_runs_only_its_drill(self):
        m = dict(projection_manifest(self.dir, mode='beat-always'), manifest_kind='pj-dry-beatalways')
        self.assertEqual(projection_drills.control_of(m, 'history-freshness'), 'stale history served as fresh')
        with self.assertRaisesRegex(Inconclusive, 'is the control of history-freshness'):
            projection_drills.check_scenario(m, 'projection-byte-equal-replay')

    def test_a_control_kind_of_the_binary_names_its_own_text(self):
        for kind, text in (('pj-nc-nostopreplay-ext', 'orphan replay remains on core member'),
                           ('pj-nc-pinrecording', 'projector did not follow the successor recording'),
                           ('pj-nc-dropone', 'journalSeq missing in projection'),
                           ('pj-nc-wallclock', 'projection dump differs'),
                           ('pj-nc-beatalways', 'stale history served as fresh'), ('pj-nc-nostale', 'stale label missing')):
            m = dict(projection_manifest(self.dir), manifest_kind=kind)
            scenario = core_contracts.GATEWAY_KINDS[kind]['projection_control']
            self.assertEqual(projection_drills.control_of(m, scenario), text)

    def test_runner_refuses_an_unrunnable_projection_plan_with_a_non_zero_exit(self):
        import subprocess
        import sys
        m = projection_manifest(self.dir, slots={'pj0': 'history_projector', 'pj1': 'projector_stub'})
        path = Path(self.dir) / 'fixtures'
        m['state_root'] = str(path / m['run_id'])
        manifest = Path(self.dir) / 'manifest.json'
        manifest.write_text(json.dumps(m))
        out = Path(self.dir) / 'out'
        runner = Path(projection_drills.__file__).with_name('runner.py')
        with mock.patch.dict('os.environ', {}):
            r = subprocess.run([sys.executable, str(runner), '--manifest', str(manifest), '--scenario', 'history-freshness',
                                '--output', str(out)], capture_output=True, text=True, timeout=120)
        self.assertNotEqual(r.returncode, 0)
        result = json.loads((out / 'result.json').read_text())
        self.assertEqual(result['status'], 'INCONCLUSIVE')
        self.assertFalse((path / m['run_id']).exists())


class DrillLogicTest(unittest.TestCase):
    def test_dry_verdict_judges_only_lines_that_do_not_await(self):
        line = projection_drills.line
        lines = {'a': line(True, {}), 'b': projection_drills.awaits(False, {}, 'stale label missing', 'gateway')}
        status, control, waiting = projection_drills.dry_verdict(lines, None)
        self.assertEqual((status, control), ('PASS', None))
        self.assertEqual(waiting['b']['text'], 'stale label missing')
        lines['c'] = line(False, {}, 'stale history served as fresh')
        self.assertEqual(projection_drills.dry_verdict(lines, None)[0], 'FAIL')
        self.assertEqual(projection_drills.dry_verdict(lines, 'stale history served as fresh')[0], 'PASS')
        self.assertEqual(projection_drills.dry_verdict({'a': line(True, {})}, 'stale history served as fresh')[0], 'FAIL')
        self.assertEqual(projection_drills.dry_verdict({'a': line(True, {}, inconclusive=True)}, None)[0], 'INCONCLUSIVE')

    def test_a_control_fails_on_any_other_failing_or_inconclusive_judged_line(self):
        line = projection_drills.line
        text = 'stale history served as fresh'
        only = {'a': line(True, {}), 'e': line(False, {}, text)}
        self.assertEqual(projection_drills.dry_verdict(only, text)[0], 'PASS')
        other = dict(only, f=line(False, {}, 'order entry failed while PostgreSQL was down'))
        status, record, _ = projection_drills.dry_verdict(other, text)
        self.assertEqual(status, 'FAIL')
        self.assertEqual(record['other_failed_lines'], ['f'])
        self.assertEqual(projection_drills.dry_verdict(dict(only, g=line(True, {}, inconclusive=True)), text)[0], 'FAIL')
        waiting = dict(only, w=projection_drills.awaits(False, {}, 'stale label missing', 'gateway'))
        self.assertEqual(projection_drills.dry_verdict(waiting, text)[0], 'PASS')

    def test_the_stale_bound_is_stale_plus_one_probe_plus_one_sample(self):
        p = projection_drills.settings({})
        self.assertEqual(projection_drills.stale_bound_s(p), (3000 + 1000 + 500) / 1000)
        self.assertEqual(projection_drills.stale_bound_s(dict(p, SAMPLE_MS=200, STEP_SETTLE_S=30)), 4.2)

    def test_the_fresh_age_is_judged_against_the_setting_only(self):
        p = projection_drills.settings({})
        self.assertTrue(projection_drills.fresh_ages_hold([622, 3000], p))
        self.assertFalse(projection_drills.fresh_ages_hold([622, 3001], p))
        self.assertFalse(projection_drills.fresh_ages_hold([None], p))

    def test_the_slow_member_needs_a_slowdown_witness_against_the_baseline(self):
        p = projection_drills.settings({})
        base = {'polls': 16, 'probe_ms': 16 * 900, 'unanswered': 0}
        same = projection_drills.slow_witness(base, {'polls': 15, 'probe_ms': 15 * 950, 'unanswered': 0}, p)
        self.assertFalse(same['slowed'])
        slower = projection_drills.slow_witness(base, {'polls': 8, 'probe_ms': 8 * 2000, 'unanswered': 0}, p)
        self.assertTrue(slower['slowed'])
        self.assertEqual(slower['probe_ms_mean'], [900, 2000])
        self.assertTrue(projection_drills.slow_witness(base, {'polls': 3, 'probe_ms': 2700, 'unanswered': 1}, p)['slowed'])
        self.assertIsNone(projection_drills.slow_witness({'polls': 0, 'probe_ms': 0, 'unanswered': 0},
                                                         {'polls': 3, 'probe_ms': 2700, 'unanswered': 0}, p)['slowed'])

    def test_crossing_story_alternates_sides_at_one_price_and_is_deterministic(self):
        rows = projection_drills.crossing_story(6, [1, 2], 7)
        self.assertEqual([r['body']['side'] for r in rows], ['BUY', 'SELL'] * 3)
        self.assertEqual({r['body']['price'] for r in rows}, {'90'})
        self.assertEqual(rows, projection_drills.crossing_story(6, [1, 2], 7))
        self.assertEqual(len({r['quantity'] for r in rows}), 6)

    def test_orders_and_fills_against_the_oracle(self):
        ev = [{'seq': 1, 'order': 5, 'kind': 'ACCEPTED', 'status': 'NEW', 'filled': 0, 'remaining': 2, 'hold_remaining': 9, 'trade': 0},
              {'seq': 2, 'order': 6, 'kind': 'ACCEPTED', 'status': 'NEW', 'filled': 0, 'remaining': 2, 'hold_remaining': 1, 'trade': 0},
              {'seq': 3, 'order': 6, 'kind': 'FILL', 'status': 'FILLED', 'filled': 2, 'remaining': 0, 'hold_remaining': 0, 'trade': 4},
              {'seq': 4, 'order': 5, 'kind': 'FILL', 'status': 'FILLED', 'filled': 2, 'remaining': 0, 'hold_remaining': 0, 'trade': 4}]
        rows = [{'order_id': 5, 'status': 'FILLED', 'filled_quantity': 2, 'remaining_quantity': 0, 'hold_remaining': 0},
                {'order_id': 6, 'status': 'FILLED', 'filled_quantity': 2, 'remaining_quantity': 0, 'hold_remaining': 0}]
        self.assertEqual(projection_drills.compare_orders(ev, rows)['differences'], 0)
        rows[0] = dict(rows[0], hold_remaining=3)
        self.assertEqual(projection_drills.compare_orders(ev, rows)['differences'], 1)
        fills = [{'trade_id': 4, 'order_id': 6, 'maker': False}, {'trade_id': 4, 'order_id': 5, 'maker': True}]
        trades = [{'trade_id': 4, 'taker_order': 6, 'maker_order': 5}]
        self.assertTrue(projection_drills.compare_fills(ev, fills, trades)['equal'])
        swapped = [dict(fills[0], maker=True), dict(fills[1], maker=False)]
        self.assertEqual(projection_drills.compare_fills(ev, swapped, trades)['maker_wrong'], [[4, 6], [4, 5]])
        self.assertFalse(projection_drills.compare_fills(ev, fills[:1], trades)['equal'])

    def test_density_against_the_head(self):
        self.assertTrue(projection_drills.density([1, 2, 3], 3)['dense'])
        d = projection_drills.density([1, 3], 3)
        self.assertFalse(d['dense'])
        self.assertEqual(d['missing'], [2])
        self.assertEqual(projection_drills.density([1, 2, 3, 4], 3)['above_head'], [4])

    def test_replay_baseline(self):
        back = projection_drills.baseline_back
        base = {'ae0': {'replays': {'9161': 1}, 'shm_bytes': 100}, 'ae1': {'replays': {'9161': 0}, 'shm_bytes': 100}}
        self.assertTrue(back(base, {'ae0': {'replays': {'9161': 1}}, 'ae1': {'replays': {'9161': 0}}})['back'])
        self.assertFalse(back(base, {'ae0': {'replays': {'9161': 2}}, 'ae1': {'replays': {}}})['back'])
        self.assertFalse(back(base, {'ae0': {'error': 'x'}, 'ae1': {'replays': {}}})['back'])
        # the money projector re-attached to another member: back; an orphan left on the old one: not back
        self.assertTrue(back(base, {'ae0': {'replays': {'9161': 0}}, 'ae1': {'replays': {'9161': 1}}})['back'])
        self.assertFalse(back(base, {'ae0': {'replays': {'9161': 1}}, 'ae1': {'replays': {'9161': 1}}})['count_back'])
        # the history replay stream follows the running slots' own /health: the writer's member may serve one
        h = str(projection_drills.HISTORY_PROJECTOR_REPLAY_STREAM)
        base = {m: {'replays': {'9161': 0, h: 1 if m == 'ae0' else 0}, 'shm_bytes': 100} for m in ('ae0', 'ae1', 'ae2')}
        moved = {m: {'replays': {'9161': 0, h: 1 if m == 'ae2' else 0}, 'shm_bytes': 100} for m in ('ae0', 'ae1', 'ae2')}
        self.assertTrue(back(base, moved, [('ae2', 1), ('ae1', 0)])['back'])
        out = back(base, moved, [('ae0', 1)])
        self.assertFalse(out['count_back'])
        self.assertEqual(out['over'], [{'member': 'ae2', 'stream': h, 'replays': 1, 'allowed': 0}])
        # /dev/shm: the members together against the baseline total plus the slack
        grown = {m: dict(v, shm_bytes=150) for m, v in moved.items()}
        self.assertTrue(back(base, grown, [('ae2', 1)], shm_slack=150)['shm_back'])
        self.assertFalse(back(base, grown, [('ae2', 1)], shm_slack=149)['shm_back'])
        self.assertTrue(back(base, grown, [('ae2', 1)])['shm_back'])
        # the readers from the slots' /health
        health = {'pj0': {'role': 'writer', 'source': {'member': 'ae1'}, 'replays_open': None},
                  'pj1': {'role': 'standby', 'source': {'member': 'ae2'}, 'replays_open': 0}, 'gw': {'error': 'down'}}
        self.assertEqual(projection_drills.replay_readers(health), [('ae1', 1), ('ae2', 0)])

    def test_the_successor_text_needs_a_new_recording_and_a_stuck_projection(self):
        verdict = projection_drills.successor_verdict
        ok = {'caught_up': {'caught_up': True}}
        new = {'member': 'ae1', 'before': [3], 'after': [3, 7]}
        same = {'member': 'ae2', 'before': [3], 'after': [3]}
        stuck = {'caught_up': {'caught_up': False, 'applied': 40}, 'applied_after_fault': 40}
        slow = {'caught_up': {'caught_up': False, 'applied': 55}, 'applied_after_fault': 40}
        self.assertIsNone(verdict({'b': dict(ok, recordings=new), 'c': ok})['text'])
        self.assertEqual(verdict({'b': dict(stuck, recordings=new)})['text'], projection_drills.CONTROL_TEXT['projector-me-restart-follow'])
        # a new recording at (b), stuck from (c) on
        self.assertEqual(verdict({'b': dict(ok, recordings=new), 'c': dict(stuck, recordings=same)})['stuck_step'], 'c')
        self.assertEqual(verdict({'b': dict(ok, recordings=new), 'c': dict(stuck, recordings=same)})['text'],
                         projection_drills.CONTROL_TEXT['projector-me-restart-follow'])
        # behind but still applying, or stuck with no new recording: the other text
        self.assertEqual(verdict({'b': dict(slow, recordings=new)})['text'], 'projection behind the core head')
        self.assertEqual(verdict({'b': ok, 'd': dict(stuck, recordings=same)})['text'], 'projection behind the core head')

    def test_no_exit_outside_the_drills_own_kills_and_stops(self):
        import types

        def run(faults, running=('pj0', 'pj1'), codes=None):
            states = {r: {'Running': r in running, 'ExitCode': (codes or {}).get(r, 0)} for r in ('pj0', 'pj1')}
            f = types.SimpleNamespace(registry={'faults': faults, 'containers': {r: r for r in states}},
                                      inspect=lambda kind, cid: {'State': states[cid]})
            return projection_drills.ProjectionDrill.exits_line(types.SimpleNamespace(f=f), ('pj0', 'pj1'))
        kill = [{'kind': 'kill', 'target': 'pj0'}, {'kind': 'restart', 'target': 'pj0', 'exit_code': 137}]
        self.assertTrue(run(kill)['holds'])
        # the standby exited 70 and is down at the end
        out = run(kill, running=('pj0',), codes={'pj1': 70})
        self.assertFalse(out['holds'])
        self.assertEqual(out['detail']['unexpected'], [{'target': 'pj1', 'exit_code': 70, 'running': False}])
        # a restart that found an exit the drill did not cause
        self.assertFalse(run([{'kind': 'restart', 'target': 'pj1', 'exit_code': 70}])['holds'])
        self.assertFalse(run([{'kind': 'kill', 'target': 'pj1'}, {'kind': 'restart', 'target': 'pj1', 'exit_code': 70}])['holds'])
        stop = [{'kind': 'stop', 'target': 'pj1', 'exit_code': 143}, {'kind': 'restart', 'target': 'pj1', 'exit_code': 143}]
        self.assertTrue(run(stop)['holds'])

    def test_history_reads_by_cause_group(self):
        metrics = ('# HELP gateway_history_reads_total x\n'
                   'gateway_history_reads_total{query="orders",result="unavailable",cause="no_heartbeat"} 4\n'
                   'gateway_history_reads_total{query="order",result="unavailable",cause="unreachable"} 2\n'
                   'gateway_history_reads_total{query="orders",result="unavailable",cause="timeout"} 1\n'
                   'gateway_history_reads_total{query="orders",result="ok",cause="none"} 9\n'
                   'gateway_history_reads_total{query="order",result="not_found",cause="none"} 1\n'
                   'gateway_history_reads_total{query="orders",result="busy",cause="expired"} 3\n')
        self.assertEqual(projection_drills.history_reads_by_group(metrics),
                         {'heartbeat': 4, 'pg': 3, 'ok': 9, 'not_found': 1, 'busy': 3})
        self.assertEqual(projection_drills.history_reads_by_group(''), {})

    def test_the_stale_label(self):
        self.assertIs(projection_drills.fresh_label({'stale': False, 'ageMs': 1}), False)
        self.assertIs(projection_drills.fresh_label({'stale': True}), True)
        self.assertEqual(projection_drills.fresh_label({'ageMs': 1}), 'missing')
        self.assertEqual(projection_drills.fresh_label(None), 'missing')

    def test_the_member_cut_and_the_slow_rule(self):
        m = projection_manifest(tempfile.mkdtemp())
        rules = projection_drills.isolation_arguments(m, 'ae1', 'add')
        self.assertEqual(len(rules), 4)
        self.assertIn(('ae1', ['-w', '2', '-A', 'INPUT', '-p', 'udp', '-s', m['nodes']['ae0'], '-j', 'DROP']), rules)
        self.assertIn(('ae2', ['-w', '2', '-A', 'INPUT', '-p', 'udp', '-s', m['nodes']['ae1'], '-j', 'DROP']), rules)
        # no OUTPUT drop: a dropped send fails with EPERM in the sender and the core fails fast on a run of them
        self.assertFalse([r for _, r in rules if 'OUTPUT' in r])
        self.assertEqual(projection_drills.isolation_arguments(m, 'ae1', 'delete')[0][1][2], '-D')
        with self.assertRaises(Violation):
            projection_drills.isolation_arguments(m, 'me1', 'add')
        slow = projection_drills.slow_arguments(m, 'ae1', 'pj0', 'add', 50)
        self.assertEqual(slow[-7:], ['statistic', '--mode', 'random', '--probability', '0.50', '-j', 'DROP'])
        self.assertIn(m['nodes']['ae1'], slow)
        self.assertEqual(slow[3:8], ['INPUT', '-p', 'udp', '-s', m['nodes']['ae1']])
        with self.assertRaises(Violation):
            projection_drills.slow_arguments(m, 'ae1', 'pj0', 'add', 100)
        listing = ('Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n'
                   ' pkts bytes target prot opt in out source destination\n'
                   f'   37  4200 DROP 17 -- * * {m["nodes"]["ae1"]} 0.0.0.0/0 statistic mode random probability 0.50000000000\n')
        self.assertEqual(projection_drills.dropped_packets(listing, m['nodes']['ae1']), 37)
        self.assertIsNone(projection_drills.dropped_packets('', m['nodes']['ae1']))
        # only the replay's own destination port on pj0 is slowed (its archive control session and the cluster
        # session are not touched: a slow source, never a silent one)
        keep = projection_drills.slow_rate_arguments(m, 'ae1', 'add', 100, 40123)
        self.assertEqual([r[3] for r in keep], ['INPUT', 'INPUT'])
        self.assertEqual(keep[0][4:10], ['-p', 'udp', '-s', m['nodes']['ae1'], '--dport', '40123'])
        self.assertEqual(keep[0][-9:], ['statistic', '--mode', 'nth', '--every', '100', '--packet', '0', '-j', 'ACCEPT'])
        self.assertEqual(keep[1][-2:], ['-j', 'DROP'])
        with self.assertRaises(Violation):
            projection_drills.slow_rate_arguments(m, 'ae1', 'add', 1, 40123)
        with self.assertRaises(Violation):
            projection_drills.slow_rate_arguments(m, 'ae1', 'add', 100, None)
        both = listing + f'   12  900 ACCEPT 17 -- * * {m["nodes"]["ae1"]} 0.0.0.0/0 statistic mode nth every 100\n'
        self.assertEqual(projection_drills.dropped_packets(both, m['nodes']['ae1']), 37)

    def test_settings_are_overridable_positive_integers(self):
        self.assertEqual(projection_drills.settings({})['HISTORY_PROJECTOR_ORPHAN_BOUND_MS'], 30000)
        self.assertEqual(projection_drills.settings({'FREEZE_S': '20'})['FREEZE_S'], 20)
        with self.assertRaises(Violation):
            projection_drills.settings({'FREEZE_S': '-1'})


class ReleaseCutProjectionTest(unittest.TestCase):
    def test_a_drifted_probe_is_waived_only_in_a_rig_with_a_named_drift_from_this_tree(self):
        import release_cut
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'CoreProbe.java'; src.write_bytes(b'probe source')
            jar = Path(d) / 'CoreProbe.jar'; jar.write_bytes(b'jar')
            entry = {'path': str(jar), 'sha256': hashlib.sha256(b'jar').hexdigest(), 'source_path': str(src),
                     'source_sha256': hashlib.sha256(b'probe source').hexdigest()}
            cut = {'harness': {'core_probe': {'sha256': 'other'}}}
            m = {'core_probe': entry, 'harness_drift': {'reason': 'dry run'}}
            self.assertIn('compiled from this harness tree', release_cut.drifted_probe(m, cut, 'rig', 'core_probe', src))
            self.assertIsNone(release_cut.drifted_probe(m, cut, 'product', 'core_probe', src))
            self.assertIsNone(release_cut.drifted_probe(dict(m, harness_drift=None), cut, 'rig', 'core_probe', src))
            self.assertIsNone(release_cut.drifted_probe(m, cut, 'rig', 'journal_probe', src))
            other = Path(d) / 'Other.java'; other.write_bytes(b'another source')
            self.assertIsNone(release_cut.drifted_probe(m, cut, 'rig', 'core_probe', other))


class BinaryDrillLogicTest(unittest.TestCase):
    def test_a_consequence_is_judged_only_when_its_line_holds(self):
        line = projection_drills.line
        follow = line(False, {}, 'projector did not follow the successor recording')
        oracle = projection_drills.consequence(line(False, {}, 'projected orders or fills differ from the oracle'),
                                               'follows_successor_recording')
        lines = {'follows_successor_recording': follow, 'projection_equals_oracle': oracle, 'other': line(True, {})}
        status, control, waiting = projection_drills.dry_verdict(lines, 'projector did not follow the successor recording')
        self.assertEqual((status, control['failed_lines'], control['other_failed_lines']),
                         ('PASS', ['follows_successor_recording'], []))
        self.assertEqual(waiting['projection_equals_oracle']['consequence_of'], 'follows_successor_recording')
        self.assertEqual(projection_drills.dry_verdict(lines, None)[0], 'FAIL')
        # once the line it depends on holds, the consequence is judged like any line
        lines['follows_successor_recording'] = line(True, {})
        status, control, _ = projection_drills.dry_verdict(lines, 'projector did not follow the successor recording')
        self.assertEqual((status, control['other_failed_lines']), ('FAIL', ['projection_equals_oracle']))

    def test_awaits_is_an_ordinary_line_on_the_binary(self):
        out = projection_drills.awaits(False, {}, 'stale label missing', 'gateway', judged=True)
        self.assertNotIn('awaits', out)
        self.assertEqual(out['text'], 'stale label missing')
        self.assertTrue(projection_drills.awaits(False, {}, 'x', 'gateway', judged=True, inconclusive=True)['inconclusive'])
        self.assertEqual(projection_drills.awaits(False, {}, 'x', 'why')['awaits'], 'why')

    def test_the_slow_witness_on_the_binary(self):
        witness = projection_drills.slow_witness_binary
        base = [{'phase': 'baseline', 'source': 'ae1', 'behind': 0, 'switches': 1, 'lag_events': 2}]
        same = [{'phase': 'slow', 'source': 'ae1', 'behind': 0, 'switches': 1, 'lag_events': 1}]
        self.assertFalse(witness(base + same, 'ae1')['slowed'])
        self.assertTrue(witness(base + [dict(same[0], behind=1)], 'ae1')['slowed'])
        # the switch (what (g) tests) is recorded, never the witness; one lag sample above the baseline is noise
        for slow in ({'switches': 2}, {'source': 'ae2'}, {'lag_events': 30}):
            out = witness(base + [dict(same[0], **slow)], 'ae1')
            self.assertFalse(out['slowed'], slow)
        self.assertTrue(witness(base + same + [dict(same[0], switches=2)], 'ae1')['switches_rose'])
        high = dict(same[0], lag_events=30)
        self.assertTrue(witness(base + [high, high], 'ae1')['slowed'])
        self.assertFalse(witness(base + [high, same[0], high], 'ae1')['slowed'])
        self.assertTrue(witness(base + [high, same[0], high], 'ae1', lag_samples=1)['slowed'])
        self.assertIsNone(witness(base, 'ae1')['slowed'])
        # leaving the slowed member is recorded, never the witness: a member made silent is left on its archive's
        # timeout, which is not a slow source
        left = dict(same[0], source='ae2')
        out = witness(base + [left], 'ae1', dropped=12)
        self.assertFalse(out['slowed'])
        self.assertTrue(out['left_while_dropping'])
        self.assertFalse(witness(base + [left], 'ae1', dropped=0)['left_while_dropping'])

    def test_the_dump_takes_a_column_beyond_its_list(self):
        listing = b'order_id\nprojected_at\nstatus\n'
        self.assertEqual(projection_dump.extra_columns(listing, 'oe_orders'), ['projected_at'])
        self.assertEqual(projection_dump.extra_columns(b'ingested_at\njournal_seq\n', 'money_journal'), [])
        self.assertIn('last_log_position, projected_at FROM oe_orders', projection_dump.copy_sql('oe_orders', extra=['projected_at']))
        with self.assertRaises(ValueError):
            projection_dump.extra_columns(b'x; DROP\n', 'oe_orders')

        def run(sql):
            if sql.startswith('SELECT to_regclass'):
                return b't\n'
            if sql.startswith('SELECT column_name'):
                return b'projected_at\n' if 'oe_orders' in sql else b''
            return (b'with\n' if 'projected_at' in sql else b'without\n')
        with tempfile.TemporaryDirectory() as d:
            out = projection_dump.dump(run, d, projection_dump.HISTORY_TABLES)
            self.assertEqual(out['oe_orders']['extra_columns'], ['projected_at'])
            self.assertEqual(out['oe_orders']['sha256'], hashlib.sha256(b'with\n').hexdigest())
            self.assertEqual(out['oe_orders']['sha256_fixed'], hashlib.sha256(b'without\n').hexdigest())
            self.assertNotIn('extra_columns', out['oe_fills'])
            self.assertNotIn('sha256_fixed', out['oe_fills'])
            # a dump without the column: different on the whole, equal on the fixed columns
            plain = {t: dict(r) for t, r in out.items()}
            plain['oe_orders'] = {'sha256': out['oe_orders']['sha256_fixed']}
            self.assertEqual(projection_dump.equal(out, plain), ['oe_orders'])
            self.assertEqual(projection_dump.equal(out, plain, fixed=True), [])


class ReleaseCutProjectorTest(unittest.TestCase):
    """rc2-cut/4: oe-projector is a product artifact; substrate.aeron_patches is required, re-hashed and the cluster-tools
    lock's set; a control build of oe-projector is the cut's gateway commit configured with its one define."""

    def setUp(self):
        import release_cut
        import test_release_cut
        self.rc = release_cut
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.w = test_release_cut.World(self.root / 'cut')
        patch = mock.patch.object(release_cut, 'git_blob', self.w.blob); patch.start(); self.addCleanup(patch.stop)

    def tearDown(self):
        self.temp.cleanup()

    def found(self, m):
        return self.rc.check_cut(m, old_pins=self.w.pins).items

    def test_the_cut_carries_oe_projector_and_its_aeron_patches(self):
        self.assertIn('oe-projector', self.w.m['artifacts'])
        self.assertEqual(self.rc.fixture_names()['history_projector'], 'oe-projector')
        self.assertEqual(self.found(self.w.m), [])

    def test_aeron_patches_missing_changed_or_not_the_locks_are_refused(self):
        m = copy.deepcopy(self.w.m); m['substrate'].pop('aeron_patches')
        self.assertIn('K9', {r for r, _ in self.found(m)})
        m = copy.deepcopy(self.w.m); Path(m['substrate']['aeron_patches'][0]['path']).write_bytes(b'edited')
        self.assertTrue(any(r == 'K1' and 'aeron_patches[0]' in t for r, t in self.found(m)), self.found(m))
        m = copy.deepcopy(self.w.m)
        self.w.ct_lock = json.dumps({'aeron_patches': [{'path': 'third_party/aeron-patches/0001-fix.patch',
                                                         'sha256': 'f' * 64}]}).encode()
        self.assertTrue(any(r == 'K4' and "not the cluster-tools lock's" in t for r, t in self.found(m)), self.found(m))
        self.w.ct_lock = None
        self.assertTrue(any(r == 'K4' and 'not readable' in t for r, t in self.found(m)))
        # an rc2-cut/3 cut stays valid without it
        old = __import__('test_release_cut').World(self.root / 'old', 'rc2-cut/3')
        self.assertNotIn('aeron_patches', old.m['substrate'])
        self.assertEqual(self.rc.check_cut(old.m, old_pins=old.pins).items, [])

    def nc(self, control='PROJ_NC_DROP_ONE', defines=('PROJ_NC_DROP_ONE',), body=None):
        build = self.root / ('pj-nc-' + control.lower()); (build / 'inst' / 'bin').mkdir(parents=True, exist_ok=True)
        (build / 'CMakeCache.txt').write_text(f'OE_PROJECTOR_CONTROL:STRING={control}\n')
        b = build / 'inst' / 'bin' / 'oe-projector'; b.write_bytes(body or b'nc ' + self.w.m['repos']['gateway'].encode())
        return {'path': str(b), 'sha256': hashlib.sha256(b.read_bytes()).hexdigest(), 'source_sha': self.w.m['repos']['gateway'],
                'defines': list(defines), 'target': 'oe-projector'}

    def fixture(self, cls, **extra):
        m = {'artifacts': extra, 'harness_commit': self.w.m['harness_commit'], 'harness_dirty': False}
        return self.rc.check_fixture(m, self.w.m, cls, old_pins=self.w.pins).items

    def test_a_projector_control_build_is_the_cuts_gateway_with_its_define(self):
        self.assertEqual(self.fixture('rig', history_projector_nc=self.nc()), [])
        self.assertIn(('K3', 'artifacts.history_projector_nc: a test-only build (history_projector_nc) in a product kind'),
                      self.fixture('product', history_projector_nc=self.nc()))
        items = self.fixture('rig', history_projector_nc=self.nc(control='PROJ_NC_BEAT_ALWAYS'))
        self.assertTrue(any(r == 'K4' and 'OE_PROJECTOR_CONTROL' in t for r, t in items), items)
        items = self.fixture('rig', history_projector_nc=self.nc(body=b'another gateway'))
        self.assertTrue(any(r == 'K4' and 'is not a build of the cut' in t for r, t in items), items)
        a = self.w.m['artifacts']['oe-projector']
        product = {'path': a['path'], 'sha256': a['sha256'], 'source_sha': a['source_sha']}
        self.assertEqual(self.fixture('product', history_projector=product), [])


if __name__ == '__main__':
    unittest.main()


class DrillRoundOneTest(unittest.TestCase):
    """The hung-writer orphan line, the orphan watch, the thaw branch of the freshness drill and the C start order."""

    def drill(self):
        d = mock.Mock()
        d.p = projection_drills.settings({})
        d.binary = True
        return d

    def hung(self, mode, present, gone_ms):
        return {'target': 'pj1', 'member': 'ae0', 'mode': mode, 'takeover_s': 10.5,
                'orphan': {'present_at_takeover': present, 'gone_after_takeover_ms': gone_ms}}

    def test_the_hung_writer_line_judges_only_an_orphan_served_at_the_takeover(self):
        judge = projection_drills.MeRestartFollow.hung_line
        d = self.drill()
        self.assertTrue(judge(d, self.hung('external', True, 400))['holds'])
        failed = judge(d, self.hung('external', True, None))
        self.assertEqual((failed['holds'], failed['text'], bool(failed.get('inconclusive'))),
                         (False, projection_drills.ORPHAN_TEXT, False))
        late = judge(d, self.hung('external', True, d.p['ORPHAN_STOP_BOUND_MS'] + 1))
        self.assertFalse(late['holds'])
        untested = judge(d, self.hung('external', False, None))
        self.assertTrue(untested['inconclusive'])
        embedded = judge(d, self.hung('embedded', False, None))
        self.assertTrue(embedded['holds'])
        self.assertFalse(embedded['detail']['exercised'])
        self.assertTrue(judge(d, {'skipped': 'no writer'})['inconclusive'])

    def test_the_orphan_watch_times_the_takeover_and_the_end_of_the_orphan(self):
        d = self.drill()
        clock = iter([1.0, 2.0, 3.0, 3.5, 4.0, 4.5, 5.0])
        d.clock = lambda: next(clock)
        d.sleep = lambda s: None
        served = iter([1, 1, 1, 0])
        d.f.replay_count = lambda m, s: {'replays': {str(projection_drills.HISTORY_PROJECTOR_REPLAY_STREAM): next(served)}}
        d.f.projection_health = lambda slot: {'role': 'writer', 'source': {'member': 'ae1'}, 'replays_open': 1}
        watch = projection_drills.OrphanWatch(d, 'ae0', 'pj0', 0.0)
        self.assertTrue(watch.sample('standby'))
        watch.after_takeover(2.0)
        out = watch.summary()
        self.assertTrue(out['present_at_takeover'])
        self.assertEqual(out['gone_after_takeover_ms'], 2500)
        self.assertEqual([s[2] for s in out['samples']], [1, 1, 1, 0])

    def test_an_orphan_gone_before_the_takeover_is_not_present(self):
        d = self.drill()
        clock = iter([1.0, 2.0, 3.0])
        d.clock = lambda: next(clock)
        served = iter([1, 0, 0])
        d.f.replay_count = lambda m, s: {'replays': {str(projection_drills.HISTORY_PROJECTOR_REPLAY_STREAM): next(served)}}
        d.f.projection_health = lambda slot: {'role': 'standby'}
        watch = projection_drills.OrphanWatch(d, 'ae0', 'pj0', 0.0)
        watch.sample(); watch.sample()
        # a sample without an orphan before the takeover is not its end (a moment of equality while the writer is
        # frozen); the first such sample from the takeover on is
        self.assertIsNone(watch.gone_s)
        watch.after_takeover(2.5)
        out = watch.summary()
        self.assertEqual((out['present_at_takeover'], out['gone_s'], out['gone_after_takeover_ms']), (False, 3.0, None))

    def thaw(self, running, code=70, tail=''):
        d = self.drill()
        clock = iter(x * 0.5 for x in range(100))
        d.clock = lambda: next(clock)
        d.sleep = lambda s: None
        d.f.registry = {'containers': {'pj0': 'c0'}}
        d.f.inspect = lambda kind, cid: {'State': {'Running': running, 'ExitCode': None if running else code}}
        d.f.command = lambda argv, check=False: mock.Mock(stdout=tail, stderr='')
        d.f.restart = mock.Mock(return_value={'started_at': 't'})
        return d, projection_drills.HistoryFreshness.thaw_branch(d, 0.0)

    def test_the_thaw_branch_restarts_only_an_exit_70_on_the_driver_rule(self):
        d, out = self.thaw(True)
        self.assertEqual(out, {'outcome': 'running'})
        d.f.restart.assert_not_called()
        line_70 = ('oe-projector exit 70: no conductor heartbeat for 13138 ms after a process pause of 13399 ms (this '
                   'process did not run: SIGSTOP, a VM or GC freeze), not a conductor or driver wedge; the driver timeout '
                   'is 10000 ms (F3b)\n')
        d, out = self.thaw(False, 70, line_70)
        self.assertEqual(out['outcome'], 'restarted')
        d.f.restart.assert_called_once()
        d, out = self.thaw(False, 70, 'oe-projector exit 70: duty watchdog: pj-duty did not run for 5000 ms\n')
        self.assertEqual(out['outcome'], 'exited')
        d.f.restart.assert_not_called()
        d, out = self.thaw(False, 1, line_70)
        self.assertEqual(out['outcome'], 'exited')
        # the Aeron client's own report of the same rule (its conductor did not run past the driver timeout) can come
        # first; it is the driver rule when the interval it names lies above the timeout it names
        client = 'FATAL aeron client error, exiting 70: service interval exceeded in ns: timeout=10000000000, interval=12103159791\n'
        d, out = self.thaw(False, 70, client)
        self.assertEqual(out['outcome'], 'restarted')
        d, out = self.thaw(False, 70, client.replace('interval=12103159791', 'interval=9103159791'))
        self.assertEqual(out['outcome'], 'exited')

    def test_the_freeze_outlasts_the_gateway_health_refresh(self):
        p = projection_drills.settings({})
        # gw0's /health turns stale after its stale threshold plus its history probe cadence (the drill's gateway
        # settings), and the freeze ends below the projector's driver bound so that the SIGCONT resume is exercised
        self.assertGreater(p['FREEZE_S'] * 1000, p['HISTORY_STALE_MS'] + p['HISTORY_GATEWAY_PROBE_MS'] + p['SAMPLE_MS'])
        self.assertLess(p['FREEZE_S'] * 1000, p['PROJECTOR_DRIVER_BOUND_MS'])
        self.assertGreater(p['FREEZE_LONG_S'] * 1000, p['PROJECTOR_DRIVER_BOUND_MS'])
        self.assertTrue(projection_drills.health_stale({'body': '{"history": {"stale": true}}'}))
        self.assertFalse(projection_drills.health_stale({'body': '{"history": {"stale": false}}'}))
        self.assertFalse(projection_drills.health_stale(None))


class VerifierFixesTest(unittest.TestCase):
    """(g) passes only on a BEHIND switch; the short freeze resumes and the long one exits only on the driver rule;
    the drill's driver liveness and gateway history settings go through the fixture's guard; one ready bound."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.dir = self.temp.name

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def samples(behind_at_switch):
        base = [{'phase': 'baseline', 't': 0.5, 'source': 'ae0', 'behind': 1, 'switches': 2, 'lag_events': 0, 'beat_at_us': 1}]
        slow = [{'phase': 'slow', 't': 5.0, 'source': 'ae0', 'behind': 1, 'switches': 2, 'lag_events': 90, 'beat_at_us': 1},
                {'phase': 'slow', 't': 10.0, 'source': 'ae2', 'behind': behind_at_switch, 'switches': 3, 'lag_events': 90,
                 'beat_at_us': 2}]
        after = [{'phase': 'after', 't': 1.0, 'source': 'ae2', 'behind': behind_at_switch, 'switches': 3, 'lag_events': 0,
                  'beat_at_us': 3}]
        return base + slow + after

    def test_the_switch_line_holds_only_on_a_behind_switch(self):
        verdict = projection_drills.g_switch_verdict
        out = verdict(self.samples(2), 'ae0', [])
        self.assertTrue(out['holds'], out)
        self.assertEqual(out['detail']['behind_at_switch'], True)
        gone = 'source 172.30.216.10:19301 left: ARCHIVE_GONE: (107) Transport endpoint is not connected'
        out = verdict(self.samples(1), 'ae0', [gone])
        self.assertFalse(out['holds'])
        self.assertTrue(out['inconclusive'])
        self.assertEqual(out['text'], 'switch was not BEHIND')
        self.assertEqual(out['detail']['left_reasons'], [gone])
        stuck = [dict(s, source='ae0') for s in self.samples(1)]
        out = verdict(stuck, 'ae0', [])
        self.assertEqual((out['holds'], bool(out.get('inconclusive')), out['text']),
                         (False, False, 'attached to a lagging source while another was current'))
        # a BEHIND switch with no beat after it fails on its own text
        quiet = [dict(s, beat_at_us=1) for s in self.samples(2)]
        out = verdict(quiet, 'ae0', [])
        self.assertEqual((out['holds'], out['text']), (False, 'attached to a lagging source while another was current'))

    def test_the_short_thaw_must_resume_and_the_long_one_may_exit_only_on_the_driver_rule(self):
        judge = projection_drills.thaw_line
        self.assertTrue(judge({'outcome': 'running'}, long=False)['holds'])
        short = judge({'outcome': 'restarted'}, long=False)
        self.assertEqual((short['holds'], short['text']), (False, 'projector exited on a thaw below its driver bound'))
        self.assertTrue(judge({'outcome': 'restarted'}, long=True)['holds'])
        self.assertTrue(judge({'outcome': 'running'}, long=True)['holds'])
        bad = judge({'outcome': 'exited'}, long=True)
        self.assertEqual((bad['holds'], bad['text']), (False, 'projector exited on the thaw for another reason'))

    def test_the_freshness_gateway_settings_reach_the_gateway_slots_through_the_guard(self):
        from core_contracts import assert_production_timeouts
        for driver in ('external', 'embedded'):
            with self.subTest(driver=driver):
                f = projection_fixture(self.dir, driver)
                p = projection_drills.settings({})
                f.gateway_env_overrides = projection_drills.freshness_gateway_settings(p)
                env = f.gateway_slot_env('gw0')
                assert_production_timeouts(env, f.allowed_env())
                self.assertEqual(env['GATEWAY_HISTORY_STALE_MS'], str(p['HISTORY_STALE_MS']))
                self.assertEqual(env['GATEWAY_HISTORY_PROBE_MS'], str(p['HISTORY_GATEWAY_PROBE_MS']))
                f.gateway_env_overrides = {'gw0': {'GATEWAY_HISTORY_MAX_AGE_MS': '9000'}}
                with self.assertRaisesRegex(Violation, 'GATEWAY_HISTORY_MAX_AGE_MS'):
                    f.gateway_slot_env('gw0')

    def test_the_projection_driver_liveness_is_an_exact_exempt_value(self):
        f = projection_fixture(self.dir, 'external')
        f.m['slot_artifacts'].update(pj0='history_projector', pj1='history_projector')
        p = projection_drills.settings({})
        f.projection_aeronmd_env = projection_drills.follow_driver_env(p)
        self.assertEqual(f.projection_aeronmd_env, core_contracts.PROJECTION_DRIVER_LIVENESS_EXEMPT)
        command = ' '.join(f.projector_slot_command('pj0'))
        self.assertIn('AERON_CLIENT_LIVENESS_TIMEOUT=60s', command)
        self.assertEqual(f.registry['projection_aeronmd_env']['pj0'], core_contracts.PROJECTION_DRIVER_LIVENESS_EXEMPT)
        f.projection_aeronmd_env = projection_drills.follow_driver_env(dict(p, PJ_DRIVER_CLIENT_LIVENESS_S=30))
        with self.assertRaisesRegex(Violation, 'timeout setting'):
            f.projector_slot_command('pj0')
        f.projection_aeronmd_env = {'AERON_DIR_DELETE_ON_START': '1', 'AERON_TERM_BUFFER_LENGTH': '65536'}
        with self.assertRaisesRegex(Violation, 'allowlist'):
            f.projector_slot_command('pj0')

    def test_restarts_wait_on_one_ready_bound_setting(self):
        import inspect
        self.assertEqual(projection_drills.settings({})['PROJECTOR_READY_BOUND_S'], 60)
        self.assertNotIn('ready_timeout=60', inspect.getsource(projection_drills))


class ReplayPortTest(unittest.TestCase):
    def test_the_bound_udp_ports_and_the_busiest_from_a_member(self):
        proc = ('  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n'
                '  12: 2C631EAC:500A 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1 2 0 0\n'
                '  13: 2C631EAC:9CBB 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1 2 0 0\n'
                '  14: 2C631EAC:A0F1 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 1 2 0 0\n')
        self.assertEqual(projection_drills.udp_ports(proc), [20490, 40123, 41201])
        listing = ('Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n'
                   ' pkts bytes target prot opt in out source destination\n'
                   '   31  4000 ACCEPT 17 -- * * 172.30.216.11 0.0.0.0/0 udp dpt:40123\n'
                   '    9   400 ACCEPT 17 -- * * 172.30.216.11 0.0.0.0/0 udp dpt:41201\n'
                   '   80  9000 ACCEPT 17 -- * * 172.30.216.12 0.0.0.0/0 udp dpt:41201\n')
        self.assertEqual(projection_drills.port_counts(listing, '172.30.216.11'), {40123: 31, 41201: 9})
        self.assertEqual(projection_drills.port_counts('', '172.30.216.11'), {})


class SlowMemberRunTest(unittest.TestCase):
    def test_the_binary_slow_step_finds_the_replay_port_and_slows_only_it(self):
        d = mock.Mock()
        d.p = projection_drills.settings({})
        d.binary = True
        t = iter(x * 0.5 for x in range(10000))
        d.clock = lambda: next(t)
        d.sleep = lambda s: None
        d.record = {}
        d.f.m = {'nodes': {'ae1': '172.30.216.11', 'pj0': '172.30.216.44'}}
        d.f.PROJECTOR_RESPONSE_PORT = 20490
        d.f.execute.return_value = mock.Mock(stdout='  sl local\n 1: 2C631EAC:500A 0\n 2: 2C631EAC:9CBB 0\n')
        calls = []

        def netfilter(target, argv):
            calls.append(argv)
            if '-L' in argv:
                return ('   44  4000 ACCEPT 17 -- * * 172.30.216.11 0.0.0.0/0 udp dpt:40123\n'
                        '    3  300 ACCEPT 17 -- * * 172.30.216.11 0.0.0.0/0 udp dpt:20490\n'
                        '   12  900 DROP 17 -- * * 172.30.216.11 0.0.0.0/0 udp dpt:40123\n')
            return ''
        d.f.netfilter = netfilter
        state = {'n': 0}

        def health(slot):
            state['n'] += 1
            n = state['n']
            return {'source': {'member': 'ae1' if n < 34 else 'ae2'}, 'behind': 2 if n > 32 else 1, 'source_switches': 2,
                    'lag_events': 50 if 22 < n < 34 else 0}
        d.f.projection_health = health
        d.beat_at_us = lambda: state['n']
        d.left_lines = lambda slot: []
        d.replay_port = lambda member: projection_drills.HistoryFreshness.replay_port(d, member)
        out = projection_drills.HistoryFreshness.slow_member_binary(d, 'ae1')
        self.assertTrue(out['g_slow_member_method']['holds'], out)
        self.assertTrue(out['g_switch_and_beats_resume']['holds'], out)
        slowed = [a for a in calls if '--dport' in a and 'statistic' in a]
        self.assertTrue(slowed and all(a[a.index('--dport') + 1] == '40123' for a in slowed))
        self.assertEqual(d.record['slow']['replay_port']['replay_port'], 40123)


class LeaderlessWindowTest(unittest.TestCase):
    def test_the_window_runs_from_the_leader_death_the_watcher_saw_before_it(self):
        self.assertAlmostEqual(projection_drills.finished_at_epoch('2026-11-19T01:39:13.337075792Z'),
                               1795052353.337075792, places=5)
        self.assertIsNone(projection_drills.finished_at_epoch('0001-01-01T00:00:00Z'))
        rows = [{'w': 100.0, 'leaders': [], 'answered': 5}, {'w': 100.5, 'leaders': [], 'answered': 6},
                {'w': 101.0, 'leaders': [], 'answered': 6}, {'w': 103.4, 'leaders': ['ae1'], 'answered': 6}]
        after, window = projection_drills.leaderless_rows(rows, 100.7)
        self.assertEqual([r['w'] for r in after], [101.0, 103.4])
        self.assertAlmostEqual(window, 2.7)
        # no new leader seen, or no death time: no window
        self.assertIsNone(projection_drills.leaderless_rows(rows[:3], 100.7)[1])
        self.assertIsNone(projection_drills.leaderless_rows(rows, None)[1])


class NightPlanProjectionTest(unittest.TestCase):
    def test_the_external_night_runs_the_three_drills_in_both_modes(self):
        import nightly
        plan = nightly.parse_plan(json.loads((Path(nightly.__file__).with_name('nightly-cut-external.json')).read_text()))
        entries = {(e['kind'], e['scenario']) for e in plan if e['scenario'] in projection_drills.SCENARIOS}
        self.assertEqual(entries, {(k, s) for k in ('pj', 'pj-ext') for s in projection_drills.SCENARIOS})
        self.assertEqual(len(plan), 32)
        embedded = nightly.parse_plan(json.loads((Path(nightly.__file__).with_name('nightly-cut-embedded.json')).read_text()))
        self.assertFalse([e for e in embedded if e['scenario'] in projection_drills.SCENARIOS])


