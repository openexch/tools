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
    m['artifacts'].update(projector_stub=stub, history_projector=projector)
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
        self.assertEqual(core_contracts.PROJECTION_KINDS, {'pj-dry', 'pj-dry-ext', 'pj-dry-beatalways'})
        for kind in core_contracts.PROJECTION_KINDS:
            spec = core_contracts.GATEWAY_KINDS[kind]
            self.assertIn(kind, core_contracts.CUT_KINDS)
            self.assertEqual(set(spec['projectors']), core_contracts.PROJECTION_ROLES)
            self.assertIn(spec['stub_mode'], core_contracts.STUB_MODES)
            self.assertEqual('-ext' in kind, spec['driver'] == 'external')
        self.assertEqual(core_contracts.GATEWAY_KINDS['pj-dry-beatalways']['projection_control'], 'history-freshness')

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

    def test_the_binary_slot_is_refused_until_the_harness_runs_it(self):
        f = projection_fixture(self.dir)
        f.m['slot_artifacts']['pj0'] = 'history_projector'
        with self.assertRaisesRegex(Inconclusive, 'not runnable by this harness yet'):
            f.projection_slot_env('pj0')

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
        for name in projection_drills.SCENARIOS:
            with self.assertRaisesRegex(Inconclusive, 'not implemented yet'):
                projection_drills.check_scenario(binary, name)
        with self.assertRaisesRegex(Inconclusive, 'declares the projection roles'):
            projection_drills.check_scenario(gateway_manifest(self.dir), 'history-freshness')

    def test_a_control_kind_runs_only_its_drill(self):
        m = dict(projection_manifest(self.dir, mode='beat-always'), manifest_kind='pj-dry-beatalways')
        self.assertEqual(projection_drills.control_of(m, 'history-freshness'), 'stale history served as fresh')
        with self.assertRaisesRegex(Inconclusive, 'is the control of history-freshness'):
            projection_drills.check_scenario(m, 'projection-byte-equal-replay')

    def test_runner_refuses_an_unimplemented_projection_scenario_with_a_non_zero_exit(self):
        import subprocess
        import sys
        m = projection_manifest(self.dir, slots={'pj0': 'history_projector', 'pj1': 'history_projector'})
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
        self.assertEqual(projection_drills.stale_bound_s(p), (5000 + 1000 + 500) / 1000)
        self.assertEqual(projection_drills.stale_bound_s(dict(p, SAMPLE_MS=200, STEP_SETTLE_S=30)), 6.2)

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
        base = {'ae0': {'replays': {'9161': 1}}, 'ae1': {'replays': {'9161': 0}}}
        self.assertTrue(projection_drills.baseline_back(base, {'ae0': {'replays': {'9161': 1}}, 'ae1': {'replays': {'9161': 0}}}))
        self.assertFalse(projection_drills.baseline_back(base, {'ae0': {'replays': {'9161': 2}}, 'ae1': {'replays': {}}}))
        self.assertFalse(projection_drills.baseline_back(base, {'ae0': {'error': 'x'}, 'ae1': {'replays': {}}}))

    def test_the_member_cut_and_the_slow_rule(self):
        m = projection_manifest(tempfile.mkdtemp())
        rules = projection_drills.isolation_arguments(m, 'ae1', 'add')
        self.assertEqual(len(rules), 4)
        self.assertIn(['-w', '2', '-A', 'INPUT', '-p', 'udp', '-s', m['nodes']['ae0'], '-j', 'DROP'], rules)
        self.assertIn(['-w', '2', '-A', 'OUTPUT', '-p', 'udp', '-d', m['nodes']['ae2'], '-j', 'DROP'], rules)
        self.assertEqual(projection_drills.isolation_arguments(m, 'ae1', 'delete')[0][2], '-D')
        with self.assertRaises(Violation):
            projection_drills.isolation_arguments(m, 'me1', 'add')
        slow = projection_drills.slow_arguments(m, 'ae1', 'pj0', 'add', 50)
        self.assertEqual(slow[-7:], ['statistic', '--mode', 'random', '--probability', '0.50', '-j', 'DROP'])
        self.assertIn(m['nodes']['pj0'], slow)
        with self.assertRaises(Violation):
            projection_drills.slow_arguments(m, 'ae1', 'pj0', 'add', 100)
        listing = ('Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n'
                   ' pkts bytes target prot opt in out source destination\n'
                   f'   37  4200 DROP 17 -- * * 0.0.0.0/0 {m["nodes"]["pj0"]} statistic mode random probability 0.50000000000\n')
        self.assertEqual(projection_drills.dropped_packets(listing, m['nodes']['pj0']), 37)
        self.assertIsNone(projection_drills.dropped_packets('', m['nodes']['pj0']))

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


if __name__ == '__main__':
    unittest.main()
