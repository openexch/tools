# SPDX-License-Identifier: Apache-2.0
"""JournalProbe decoding: pinned schema files, loud refusal of anything undeclared, schema 4 drop-in."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

import journal_decode
import sbe_layout

SCHEMAS = Path(__file__).parent / 'schemas'


def encode(schema, template, values):
    message = schema.messages[template]
    body = bytearray(message.block_length)
    for field in message.fields:
        value = values.get(field.name, 0)
        if field.kind == 'enum':
            value = next(code for code, name in field.values.items() if name == value) if isinstance(value, str) else value
        if field.kind == 'char':
            body[field.offset:field.offset + field.length] = value.encode().ljust(field.length, b'\0')
            continue
        struct.pack_into(schema.order + field.fmt, body, field.offset, value)
    return struct.pack(schema.order + 'HHHH', message.block_length, template, schema.schema_id, schema.version) + bytes(body)


def row(frame, position, recording=0, fragmented=False):
    return json.dumps({'kind': 'frame', 'source': 'me0', 'recording': recording, 'position': position,
                       'fragmented': fragmented, 'hex': frame.hex()})


SCHEMA4 = '''<?xml version="1.0" encoding="UTF-8"?>
<sbe:messageSchema xmlns:sbe="http://fixprotocol.io/2016/sbe" package="x" id="4" version="1" byteOrder="littleEndian">
  <types>
    <composite name="messageHeader"><type name="blockLength" primitiveType="uint16"/><type name="templateId" primitiveType="uint16"/>
      <type name="schemaId" primitiveType="uint16"/><type name="version" primitiveType="uint16"/></composite>
    <enum name="BooleanType" encodingType="uint8"><validValue name="FALSE">0</validValue><validValue name="TRUE">1</validValue></enum>
  </types>
  <sbe:message name="Trade" id="1">
    <field name="journalSeq" id="1" type="int64"/><field name="meEpoch" id="2" type="int64"/>
    <field name="tradeId" id="3" type="int64"/><field name="marketId" id="4" type="int32"/>
    <field name="takerOrderId" id="5" type="int64"/><field name="takerUserId" id="6" type="int64"/>
    <field name="makerOrderId" id="7" type="int64"/><field name="makerUserId" id="8" type="int64"/>
    <field name="price" id="9" type="int64"/><field name="quantity" id="10" type="int64"/>
    <field name="takerIsBuy" id="11" type="BooleanType"/><field name="takerOmsOrderId" id="12" type="int64"/>
    <field name="makerOmsOrderId" id="13" type="int64"/>
  </sbe:message>
</sbe:messageSchema>
'''


class JournalDecodeTest(unittest.TestCase):
    def setUp(self):
        self.profile = journal_decode.load_profile('me-journal-v1')
        self.journal = sbe_layout.load(SCHEMAS / 'settlement-journal-schema.xml')
        self.orders = sbe_layout.load(SCHEMAS / 'order-schema.xml')

    def test_block_lengths_match_the_generated_codecs(self):
        # match-common generated BLOCK_LENGTH: JournalTrade 93, JournalTerminal 45, JournalCommandOutcome 116.
        self.assertEqual(self.journal.messages[1].block_length, 93)
        self.assertEqual(self.journal.messages[2].block_length, 45)
        self.assertEqual(self.orders.messages[28].block_length, 116)

    def test_current_journal_round_trip(self):
        trade = encode(self.journal, 1, {'tradeId': 7, 'marketId': 1, 'takerOrderId': 5002, 'takerUserId': 71001,
                                         'makerOrderId': 5001, 'makerUserId': 71002, 'price': 10, 'quantity': 3,
                                         'takerIsBuy': 'TRUE', 'takerOmsOrderId': 1002, 'makerOmsOrderId': 1001})
        terminal = encode(self.journal, 2, {'orderId': 5002, 'userId': 71001, 'marketId': 1, 'status': 'FILLED', 'omsOrderId': 1002})
        outcome = encode(self.orders, 28, {'commandIdHigh': 1002, 'commandIdLow': 0, 'orderId': 5002, 'appliedPosition': 640,
                                           'result': 0, 'omsOrderId': 1002})
        events = journal_decode.decode_dump([row(outcome, 0), row(trade, 160), row(terminal, 288)], self.profile)
        self.assertEqual([e['type'] for e in events], ['outcome', 'trade', 'terminal'])
        self.assertEqual(events[1]['taker_is_buy'], True)
        self.assertEqual(events[1]['trade_id'], 7)
        self.assertEqual(events[2]['status'], 'FILLED')
        self.assertEqual((events[0]['command_id_high'], events[0]['leg'], events[0]['applied_position']), (1002, 5002, 640))
        self.assertIsNone(events[0]['journal_seq'])

    def test_unknown_template_stops_loudly(self):
        snapshot = encode(self.orders, 7, {})   # RequestOpenOrdersSnapshot is not a journal record
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'unknown journal record'):
            journal_decode.decode_dump([row(snapshot, 0)], self.profile)
        foreign = bytearray(encode(self.journal, 1, {})); foreign[4:6] = (9).to_bytes(2, 'little')
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'schema 9'):
            journal_decode.decode_dump([row(bytes(foreign), 0)], self.profile)

    def test_wrong_length_version_fragment_and_order_stop_loudly(self):
        trade = encode(self.journal, 1, {'takerIsBuy': 'FALSE'})
        for frame in [trade[:-1], trade + b'\0']:
            with self.assertRaises(journal_decode.JournalSchemaError):
                journal_decode.decode_dump([row(frame, 0)], self.profile)
        bumped = bytearray(trade); bumped[6:8] = (2).to_bytes(2, 'little')
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'version 2'):
            journal_decode.decode_dump([row(bytes(bumped), 0)], self.profile)
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'fragmented'):
            journal_decode.decode_dump([row(trade, 0, fragmented=True)], self.profile)
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'not increasing'):
            journal_decode.decode_dump([row(trade, 64), row(trade, 64)], self.profile)
        bad_status = encode(self.journal, 2, {'status': 2}); bad_status = bad_status[:8 + 28] + b'\x07' + bad_status[8 + 29:]
        with self.assertRaises(journal_decode.JournalSchemaError):
            journal_decode.decode_dump([row(bad_status, 0)], self.profile)

    def test_dump_completeness_marker(self):
        trade = encode(self.journal, 1, {'takerIsBuy': 'TRUE'})
        recording = json.dumps({'kind': 'recording', 'source': 'me0', 'recording': 0, 'start': 0, 'stop': 160, 'active': True})
        end = lambda n: json.dumps({'kind': 'end', 'source': 'me0', 'recordings': 1, 'frames': n})
        self.assertEqual(len(journal_decode.decode_dump([recording, row(trade, 0), end(1)], self.profile, require_end=True)), 1)
        for lines in [[recording, row(trade, 0)], [recording, row(trade, 0), end(2)], [end(0), row(trade, 0)]]:
            with self.assertRaises(journal_decode.JournalSchemaError):
                journal_decode.decode_dump(lines, self.profile, require_end=True)

    def test_pending_profile_refuses_to_load(self):
        with tempfile.TemporaryDirectory() as temp:
            spec = json.loads((SCHEMAS / 'journal-profiles.json').read_text())
            spec['profiles']['me-journal-4']['status'] = 'pending'
            spec['profiles']['me-journal-4']['schemas'][0]['sha256'] = None
            path = Path(temp) / 'profiles.json'; path.write_text(json.dumps(spec))
            with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'pending'):
                journal_decode.load_profile('me-journal-4', path)

    def _dropped(self, temp, xml, pin=True):
        directory = Path(temp)
        for name in ['settlement-journal-schema.xml', 'order-schema.xml']:
            shutil.copyfile(SCHEMAS / name, directory / name)
        (directory / 'me-journal-schema-4.xml').write_text(xml)
        spec = json.loads((SCHEMAS / 'journal-profiles.json').read_text())
        profile = spec['profiles']['me-journal-4']
        profile['status'] = 'active'
        profile['schemas'][0]['sha256'] = hashlib.sha256(xml.encode()).hexdigest() if pin else '0' * 64
        profile['records'] = profile['records'][:1]
        (directory / 'profiles.json').write_text(json.dumps(spec))
        return directory

    def test_schema4_drops_in_and_carries_journal_seq_and_epoch(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self._dropped(temp, SCHEMA4)
            profile = journal_decode.load_profile('me-journal-4', directory / 'profiles.json', directory)
            schema = sbe_layout.load(directory / 'me-journal-schema-4.xml')
            frame = encode(schema, 1, {'journalSeq': 1, 'meEpoch': 77, 'tradeId': 1, 'takerIsBuy': 'TRUE', 'price': 5, 'quantity': 2})
            event = journal_decode.decode_dump([row(frame, 0)], profile)[0]
            self.assertEqual((event['journal_seq'], event['me_epoch'], event['trade_id']), (1, 77, 1))

    def test_schema4_drop_in_with_changed_file_or_missing_field_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = self._dropped(temp, SCHEMA4, pin=False)
            with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'sha256'):
                journal_decode.load_profile('me-journal-4', directory / 'profiles.json', directory)
        with tempfile.TemporaryDirectory() as temp:
            directory = self._dropped(temp, SCHEMA4.replace('meEpoch', 'epochId'))
            with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'lacks mapped fields'):
                journal_decode.load_profile('me-journal-4', directory / 'profiles.json', directory)

    def test_group_bearing_template_is_not_a_journal_record(self):
        with self.assertRaises(sbe_layout.SchemaError):
            self.orders.decode(encode(self.orders, 27, {}) if not self.orders.messages[27].variable else
                               struct.pack('<HHHH', self.orders.messages[27].block_length, 27, 1, 11)
                               + bytes(self.orders.messages[27].block_length))


# ---------------------------------------------------------------- RC2 S15 W1, contract 5.4: profile 4 and group support

PINNED_SCHEMA4 = 'a7c58d87e4f1cfaa642014e4c92f46492c5fe20d36bd6b1d127dd7fa05a3541a'


def pack_fields(order, fields, values, size):
    body = bytearray(size)
    for field in fields:
        value = values.get(field.name, 0)
        if field.kind == 'enum' and isinstance(value, str):
            value = next(code for code, name in field.values.items() if name == value)
        struct.pack_into(order + field.fmt, body, field.offset, value)
    return bytes(body)


# The release entry layout, written out by hand from the XML comment (22 bytes), so the test does not
# take its group layout from the code under test.
ENTRY_FIELDS = [sbe_layout.Field('commandIdHigh', 0, 'prim', 8, 'q'), sbe_layout.Field('idLowFloor', 8, 'prim', 8, 'q'),
                sbe_layout.Field('scope', 16, 'enum', 1, 'B', values={0: 'UP_TO', 1: 'ORDER'}),
                sbe_layout.Field('result', 17, 'enum', 1, 'B', values={0: 'APPLIED', 1: 'NOOP', 2: 'LEG_LIVE'}),
                sbe_layout.Field('removed', 18, 'prim', 4, 'i')]
ENTRY_BLOCK = 22


def encode_release(schema, root, entries, declared_count=None, entry_block=None):
    message = schema.messages[4]
    frame = bytearray(struct.pack(schema.order + 'HHHH', message.block_length, 4, schema.schema_id, schema.version))
    frame += pack_fields(schema.order, message.fields, root, message.block_length)
    frame += struct.pack(schema.order + 'HH', ENTRY_BLOCK if entry_block is None else entry_block,
                         len(entries) if declared_count is None else declared_count)
    for entry in entries:
        frame += pack_fields(schema.order, ENTRY_FIELDS, entry, ENTRY_BLOCK)
    return bytes(frame)


class Profile4Test(unittest.TestCase):
    def setUp(self):
        self.profile = journal_decode.load_profile('me-journal-4')
        self.schema = sbe_layout.load(SCHEMAS / 'me-journal-schema-4.xml')

    def test_profile4_is_active_and_pinned_to_the_s1_file(self):
        self.assertEqual(hashlib.sha256((SCHEMAS / 'me-journal-schema-4.xml').read_bytes()).hexdigest(), PINNED_SCHEMA4)
        spec = json.loads((SCHEMAS / 'journal-profiles.json').read_text())['profiles']['me-journal-4']
        self.assertEqual((spec['status'], spec['schemas'][0]['sha256']), ('active', PINNED_SCHEMA4))
        self.assertEqual([self.schema.messages[t].block_length for t in (1, 2, 3, 4, 5)], [109, 62, 153, 44, 39])
        self.assertEqual((self.schema.messages[4].group.name, self.schema.messages[4].group.block_length), ('releases', 22))

    def test_profile4_decodes_a_release_with_two_entries(self):
        frame = encode_release(self.schema, {'journalSeq': 9, 'meEpoch': 3, 'egressSeq': 70, 'releaseSeq': 4, 'ledgerSize': 12,
                                              'ledgerCapacity': 100000, 'tombstoneRanges': 1},
                               [{'commandIdHigh': 1002, 'idLowFloor': 0, 'scope': 'ORDER', 'result': 'APPLIED', 'removed': 2},
                                {'commandIdHigh': 1003, 'idLowFloor': 7, 'scope': 'UP_TO', 'result': 'NOOP', 'removed': 0}])
        self.assertEqual(len(frame), 8 + 44 + 4 + 2 * 22)
        event = journal_decode.decode_dump([row(frame, 0)], self.profile)[0]
        self.assertEqual(event['type'], 'release')
        self.assertEqual((event['journal_seq'], event['me_epoch'], event['egress_seq'], event['release_seq'], event['ledger_size'],
                          event['ledger_capacity'], event['tombstone_ranges']), (9, 3, 70, 4, 12, 100000, 1))
        self.assertEqual(event['releases'], [
            {'commandIdHigh': 1002, 'idLowFloor': 0, 'scope': 'ORDER', 'result': 'APPLIED', 'removed': 2},
            {'commandIdHigh': 1003, 'idLowFloor': 7, 'scope': 'UP_TO', 'result': 'NOOP', 'removed': 0}])

    def test_empty_and_full_release_groups_decode(self):
        for count in (0, 48):
            frame = encode_release(self.schema, {'journalSeq': 1, 'meEpoch': 1}, [{'commandIdHigh': i} for i in range(count)])
            event = journal_decode.decode_dump([row(frame, 0)], self.profile)[0]
            self.assertEqual(len(event['releases']), count)
        self.assertEqual(len(frame), 1112)

    def test_group_overrun_is_refused(self):
        frame = encode_release(self.schema, {'journalSeq': 1, 'meEpoch': 1}, [{'commandIdHigh': 1}], declared_count=48)
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'template 4 group overruns the frame'):
            journal_decode.decode_dump([row(frame, 0)], self.profile)

    def test_group_trailing_bytes_and_wrong_entry_block_are_refused(self):
        frame = encode_release(self.schema, {'journalSeq': 1, 'meEpoch': 1}, [{'commandIdHigh': 1}])
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'template 4'):
            journal_decode.decode_dump([row(frame + b'\0', 0)], self.profile)
        wrong = encode_release(self.schema, {'journalSeq': 1, 'meEpoch': 1}, [{'commandIdHigh': 1}], entry_block=24)
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'template 4 group entry block 24'):
            journal_decode.decode_dump([row(wrong, 0)], self.profile)
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'template 4'):
            journal_decode.decode_dump([row(frame[:8 + 44 + 2], 0)], self.profile)   # cut inside the group header

    def test_nested_group_and_data_and_two_groups_are_still_refused(self):
        header = ('<?xml version="1.0"?><sbe:messageSchema xmlns:sbe="http://fixprotocol.io/2016/sbe" package="x" id="9" version="1" '
                  'byteOrder="littleEndian"><types><composite name="messageHeader"><type name="blockLength" primitiveType="uint16"/>'
                  '<type name="templateId" primitiveType="uint16"/><type name="schemaId" primitiveType="uint16"/>'
                  '<type name="version" primitiveType="uint16"/></composite><composite name="groupSizeEncoding">'
                  '<type name="blockLength" primitiveType="uint16"/><type name="numInGroup" primitiveType="uint16"/></composite>'
                  '</types><sbe:message name="M" id="1"><field name="a" id="1" type="int64"/>')
        cases = {
            'nested': '<group name="g" id="10" dimensionType="groupSizeEncoding"><field name="x" id="1" type="int64"/>'
                      '<group name="h" id="11" dimensionType="groupSizeEncoding"><field name="y" id="1" type="int64"/></group></group>',
            'two': '<group name="g" id="10" dimensionType="groupSizeEncoding"><field name="x" id="1" type="int64"/></group>'
                   '<group name="h" id="11" dimensionType="groupSizeEncoding"><field name="y" id="1" type="int64"/></group>',
            'data_in_group': '<group name="g" id="10" dimensionType="groupSizeEncoding"><field name="x" id="1" type="int64"/>'
                             '<data name="d" id="2" type="varDataEncoding"/></group>'}
        with tempfile.TemporaryDirectory() as temp:
            for name, body in cases.items():
                path = Path(temp) / (name + '.xml'); path.write_text(header + body + '</sbe:message></sbe:messageSchema>')
                schema = sbe_layout.load(path)
                frame = struct.pack('<HHHH', 8, 1, 9, 1) + bytes(8)
                with self.subTest(case=name), self.assertRaisesRegex(sbe_layout.SchemaError, 'carries a group/var-data part'):
                    schema.decode(frame)
            path = Path(temp) / 'data.xml'
            path.write_text(header + '<data name="d" id="2" type="varDataEncoding"/></sbe:message></sbe:messageSchema>')
            schema = sbe_layout.load(path)
            frame = struct.pack('<HHHH', 8, 1, 9, 1) + bytes(8)
            with self.assertRaisesRegex(sbe_layout.SchemaError, 'carries a group/var-data part'):
                schema.decode(frame)

    def test_every_record_decodes_with_require_end(self):
        trade = encode(self.schema, 1, {'journalSeq': 1, 'meEpoch': 2, 'tradeId': 7, 'takerIsBuy': 'TRUE', 'price': 5, 'quantity': 2})
        terminal = encode(self.schema, 2, {'journalSeq': 2, 'meEpoch': 2, 'orderId': 9, 'status': 'FILLED', 'rejectReason': 0})
        outcome = encode(self.schema, 3, {'journalSeq': 3, 'meEpoch': 2, 'commandIdHigh': 4, 'result': 0, 'ledgerSize': 3})
        release = encode_release(self.schema, {'journalSeq': 4, 'meEpoch': 2}, [{'commandIdHigh': 4, 'scope': 'ORDER'}])
        config = encode(self.schema, 5, {'journalSeq': 5, 'meEpoch': 2, 'egressSeq': 11, 'configVersion': 1, 'behaviorVersion': 2,
                                         'ledgerCapacity': 100000, 'maxWireVersion': 12, 'decision': 'FRESH'})
        recording = json.dumps({'kind': 'recording', 'source': 'me0', 'recording': 0, 'start': 0, 'stop': 1, 'active': True})
        end = json.dumps({'kind': 'end', 'source': 'me0', 'recordings': 1, 'frames': 5})
        lines = [recording] + [row(f, 64 * i) for i, f in enumerate([trade, terminal, outcome, release, config])] + [end]
        events = journal_decode.decode_dump(lines, self.profile, require_end=True)
        self.assertEqual([e['type'] for e in events], ['trade', 'terminal', 'outcome', 'release', 'engine_config'])
        self.assertEqual([e['journal_seq'] for e in events], [1, 2, 3, 4, 5])
        self.assertEqual({k: events[4][k] for k in ['egress_seq', 'config_version', 'behavior_version', 'ledger_capacity',
                                                      'max_wire_version', 'decision']},
                         {'egress_seq': 11, 'config_version': 1, 'behavior_version': 2, 'ledger_capacity': 100000,
                          'max_wire_version': 12, 'decision': 'FRESH'})


if __name__ == '__main__':
    unittest.main()
