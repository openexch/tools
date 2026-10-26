# SPDX-License-Identifier: Apache-2.0
"""Pluggable, fail-loud decoder for ME journal frames dumped by JournalProbe.

A profile (``schemas/journal-profiles.json``) names the pinned schema files and maps each
(schemaId, templateId) to a normalized oracle event. RC2 S1's schema 4 is a pending profile until
its XML is dropped in and pinned. Anything not declared, a changed schema file, a fragmented or
mis-sized frame, or a frame of a schema the profile does not carry stops decoding with
``JournalSchemaError``: the oracle never guesses a record.
"""
import hashlib
import json
from pathlib import Path

import sbe_layout

SCHEMA_DIR = Path(__file__).parent / 'schemas'
PROFILES = SCHEMA_DIR / 'journal-profiles.json'
TERMINAL_STATUS = {2: 'FILLED', 3: 'CANCELLED', 4: 'REJECTED', 5: 'EXPIRED'}


class JournalSchemaError(ValueError):
    pass


class Profile:
    def __init__(self, name, spec, schema_dir):
        self.name = name
        self.has_journal_seq = spec['has_journal_seq']
        self.schemas = {}
        for entry in spec['schemas']:
            path = schema_dir / entry['file']
            if entry['sha256'] is None or not path.is_file():
                raise JournalSchemaError(f'profile {name}: schema file {entry["file"]} is not dropped in and pinned')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != entry['sha256']:
                raise JournalSchemaError(f'profile {name}: {entry["file"]} sha256 {digest} != pinned {entry["sha256"]}')
            try:
                schema = sbe_layout.load(path)
            except sbe_layout.SchemaError as error:
                raise JournalSchemaError(f'profile {name}: {error}') from error
            if schema.schema_id in self.schemas:
                raise JournalSchemaError(f'profile {name}: two files declare schema {schema.schema_id}')
            self.schemas[schema.schema_id] = schema
        self.records = {}
        for record in spec['records']:
            key = (record['schema_id'], record['template_id'])
            schema = self.schemas.get(record['schema_id'])
            message = schema.messages.get(record['template_id']) if schema else None
            if message is None:
                raise JournalSchemaError(f'profile {name}: record {key} is not declared by its schema file')
            missing = [xml for xml in record['fields'].values() if xml not in message.field_names()]
            if missing:
                raise JournalSchemaError(f'profile {name}: template {key} lacks mapped fields {missing}')
            if self.has_journal_seq and not {'journal_seq', 'me_epoch'} <= set(record['fields']):
                raise JournalSchemaError(f'profile {name}: template {key} must map journal_seq and me_epoch')
            self.records[key] = record

    def decode(self, data):
        if len(data) < sbe_layout.HEADER_LENGTH:
            raise JournalSchemaError('journal frame shorter than an SBE header')
        schema_id = int.from_bytes(data[4:6], 'little')
        template_id = int.from_bytes(data[2:4], 'little')
        schema = self.schemas.get(schema_id)
        record = self.records.get((schema_id, template_id))
        if schema is None or record is None:
            raise JournalSchemaError(f'profile {self.name}: unknown journal record schema {schema_id} template {template_id}')
        try:
            _, values = schema.decode(data)
        except sbe_layout.SchemaError as error:
            raise JournalSchemaError(f'profile {self.name}: {error}') from error
        event = {'type': record['type']}
        for normalized, xml in record['fields'].items():
            event[normalized] = values[xml]
        if not self.has_journal_seq:
            event['journal_seq'] = None
            event['me_epoch'] = None
        if record['type'] == 'terminal' and isinstance(event['status'], int):
            if event['status'] not in TERMINAL_STATUS:
                raise JournalSchemaError(f'terminal status {event["status"]} is not a terminal')
            event['status'] = TERMINAL_STATUS[event['status']]
        if record['type'] == 'trade' and not isinstance(event['taker_is_buy'], bool):
            flag = event['taker_is_buy']
            event['taker_is_buy'] = {'TRUE': True, 'FALSE': False, 1: True, 0: False}[flag]
        return event


def profiles_spec(path=PROFILES):
    return json.loads(Path(path).read_text())['profiles']


def load_profile(name, path=PROFILES, schema_dir=SCHEMA_DIR):
    spec = profiles_spec(path).get(name)
    if spec is None:
        raise JournalSchemaError(f'unknown journal profile {name}')
    if spec['status'] != 'active':
        raise JournalSchemaError(f'journal profile {name} is {spec["status"]}: {spec["source"]}')
    return Profile(name, spec, Path(schema_dir))


def decode_dump(lines, profile, require_end=False):
    """JournalProbe JSONL -> normalized events in recording order, with recording provenance."""
    events, last, end = [], {}, None
    for raw in lines:
        if not raw.strip():
            continue
        row = json.loads(raw)
        if end is not None:
            raise JournalSchemaError('JournalProbe row after its end marker')
        if row.get('kind') == 'recording':
            continue
        if row.get('kind') == 'end':
            end = row
            continue
        if row.get('kind') != 'frame':
            raise JournalSchemaError('unexpected JournalProbe row: ' + raw[:120])
        if row.get('fragmented'):
            raise JournalSchemaError(f'fragmented journal frame at recording {row["recording"]} position {row["position"]}')
        recording, position = row['recording'], row['position']
        if position <= last.get(recording, -1):
            raise JournalSchemaError(f'journal positions not increasing on recording {recording}')
        last[recording] = position
        event = profile.decode(bytes.fromhex(row['hex']))
        event.update(source=row['source'], recording=recording, position=position)
        events.append(event)
    if require_end:
        if end is None:
            raise JournalSchemaError('JournalProbe dump has no end marker: the replay did not complete')
        if end['frames'] != len(events):
            raise JournalSchemaError(f'JournalProbe end marker counts {end["frames"]} frames, decoded {len(events)}')
    return events
