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

    def test_pending_schema4_profile_refuses_to_load(self):
        with self.assertRaisesRegex(journal_decode.JournalSchemaError, 'pending'):
            journal_decode.load_profile('me-journal-4')

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


if __name__ == '__main__':
    unittest.main()
