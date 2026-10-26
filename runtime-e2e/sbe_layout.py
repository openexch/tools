# SPDX-License-Identifier: Apache-2.0
"""Fixed-block SBE layouts read from the schema XML itself.

The ME journal decoder is driven by the pinned schema file, not by hand-copied offsets: when RC2 S1
freezes journal schema 4 its XML drops into ``schemas/`` and this module computes the layout. Only
what a journal record may contain is supported (primitives, fixed char arrays, enums, sets and
composites of those). A group or var-data field is refused loudly: a journal record is one
unfragmented fixed-length frame.
"""
import struct
import xml.etree.ElementTree as ET

PRIMITIVES = {'char': ('c', 1), 'int8': ('b', 1), 'uint8': ('B', 1), 'int16': ('h', 2), 'uint16': ('H', 2),
              'int32': ('i', 4), 'uint32': ('I', 4), 'int64': ('q', 8), 'uint64': ('Q', 8),
              'float': ('f', 4), 'double': ('d', 8)}
HEADER_LENGTH = 8


class SchemaError(ValueError):
    """The schema file or a frame does not fit the fixed-block journal contract."""


def _local(tag):
    return tag.rsplit('}', 1)[-1]


class Field:
    def __init__(self, name, offset, kind, size, fmt=None, length=1, values=None, since=0):
        self.name, self.offset, self.kind, self.size = name, offset, kind, size
        self.fmt, self.length, self.values, self.since = fmt, length, values, since

    def decode(self, data, base, order):
        if self.kind == 'char':
            raw = data[base + self.offset: base + self.offset + self.length]
            return raw.split(b'\0', 1)[0].decode('ascii')
        if self.kind == 'composite':
            return {f.name: f.decode(data, base + self.offset, order) for f in self.values}
        value = struct.unpack_from(order + self.fmt, data, base + self.offset)[0]
        if self.kind == 'enum':
            if value not in self.values:
                raise SchemaError(f'field {self.name}: value {value} outside the declared enum')
            return self.values[value]
        return value


class Message:
    def __init__(self, name, template_id, block_length, fields):
        self.name, self.template_id, self.block_length, self.fields = name, template_id, block_length, fields

    def field_names(self):
        return [f.name for f in self.fields]


class Schema:
    def __init__(self, schema_id, version, order, messages):
        self.schema_id, self.version, self.order, self.messages = schema_id, version, order, messages

    def decode(self, data, offset=0, length=None):
        """Decode one complete frame; the block length must equal the template's exactly."""
        length = len(data) - offset if length is None else length
        if length < HEADER_LENGTH:
            raise SchemaError('frame shorter than the SBE header')
        block, template, schema_id, version = struct.unpack_from(self.order + 'HHHH', data, offset)
        if schema_id != self.schema_id:
            raise SchemaError(f'frame schema {schema_id} decoded with schema {self.schema_id}')
        if version != self.version:
            raise SchemaError(f'schema {schema_id} version {version} is not the pinned version {self.version}')
        message = self.messages.get(template)
        if message is None:
            raise SchemaError(f'unknown template {template} in schema {schema_id} v{version}')
        if message.variable:
            raise SchemaError(f'template {template} carries a group/var-data part; not a fixed journal record')
        if block != message.block_length or length != HEADER_LENGTH + block:
            raise SchemaError(f'template {template} block {block}/frame {length} != declared {message.block_length}')
        body = offset + HEADER_LENGTH
        return message, {f.name: f.decode(data, body, self.order) for f in message.fields}


def _type_table(types):
    table = {}
    for node in types:
        kind = _local(node.tag)
        name = node.get('name')
        if kind == 'type':
            table[name] = ('type', node)
        elif kind in ('enum', 'set'):
            table[name] = (kind, node)
        elif kind == 'composite':
            table[name] = ('composite', node)
    return table


def _resolve(type_name, table, name, offset):
    if type_name in PRIMITIVES:
        fmt, size = PRIMITIVES[type_name]
        return Field(name, offset, 'prim', size, fmt)
    entry = table.get(type_name)
    if entry is None:
        raise SchemaError(f'field {name}: unknown type {type_name}')
    kind, node = entry
    if kind == 'type':
        primitive = node.get('primitiveType')
        length = int(node.get('length', '1'))
        if primitive == 'char' and length > 1:
            return Field(name, offset, 'char', length, length=length)
        if length != 1 or primitive not in PRIMITIVES:
            raise SchemaError(f'field {name}: unsupported array type {type_name}')
        fmt, size = PRIMITIVES[primitive]
        return Field(name, offset, 'prim', size, fmt)
    if kind == 'enum':
        fmt, size = PRIMITIVES[node.get('encodingType')]
        values = {int(v.text.strip()): v.get('name') for v in node if _local(v.tag) == 'validValue'}
        return Field(name, offset, 'enum', size, fmt, values=values)
    if kind == 'set':
        fmt, size = PRIMITIVES[node.get('encodingType')]
        return Field(name, offset, 'prim', size, fmt)
    parts, inner = [], 0
    for child in node:
        if _local(child.tag) != 'type':
            raise SchemaError(f'field {name}: nested composite member {child.get("name")} unsupported')
        part = _resolve(child.get('primitiveType'), table, child.get('name'), inner)
        parts.append(part); inner += part.size
    return Field(name, offset, 'composite', inner, values=parts)


def load(path):
    """Parse a schema XML into fixed-block layouts. Raises SchemaError on anything a journal cannot carry."""
    root = ET.parse(path).getroot()
    if _local(root.tag) != 'messageSchema':
        raise SchemaError(f'{path}: not an SBE messageSchema')
    order = '<' if root.get('byteOrder', 'littleEndian') == 'littleEndian' else '>'
    schema_id, version = int(root.get('id')), int(root.get('version', '0'))
    table = {}
    for types in root:
        if _local(types.tag) == 'types':
            table.update(_type_table(types))
    messages = {}
    for node in root:
        if _local(node.tag) != 'message':
            continue
        template = int(node.get('id'))
        fields, offset = [], 0
        has_variable = False
        for child in node:
            kind = _local(child.tag)
            if kind in ('group', 'data'):
                has_variable = True
                continue
            if kind != 'field':
                continue
            since = int(child.get('sinceVersion', '0'))
            if child.get('offset') is not None:
                offset = int(child.get('offset'))
            field = _resolve(child.get('type'), table, child.get('name'), offset)
            field.since = since
            fields.append(field); offset += field.size
        declared = node.get('blockLength')
        block = int(declared) if declared is not None else offset
        if template in messages:
            raise SchemaError(f'{path}: duplicate template id {template}')
        message = Message(node.get('name'), template, block, fields)
        message.variable = has_variable
        messages[template] = message
    return Schema(schema_id, version, order, messages)
