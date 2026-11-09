# SPDX-License-Identifier: Apache-2.0
"""Fixed-block SBE layouts read from the schema XML itself.

The ME journal decoder is driven by the pinned schema file, not by hand-copied offsets: when the ME journal
freezes journal schema 4 its XML drops into ``schemas/`` and this module computes the layout. Only
what a journal record may contain is supported (primitives, fixed char arrays, enums, sets and
composites of those). A group or var-data field is refused loudly: a journal record is one
unfragmented fixed-length frame.

One flat repeating group per message is supported, because the ME journal's
CommandRelease (template 4) carries the ``releases`` group. A group is the dimension header
(``groupSizeEncoding``: blockLength uint16 + numInGroup uint16) and ``numInGroup`` fixed entries of
``blockLength`` bytes; the total frame length must equal ``HEADER + block + 4 + n * entryBlock`` exactly.
A nested group, a second group, a ``<data>`` part or a group that carries ``<data>`` is still refused.
"""
import struct
import xml.etree.ElementTree as ET

PRIMITIVES = {'char': ('c', 1), 'int8': ('b', 1), 'uint8': ('B', 1), 'int16': ('h', 2), 'uint16': ('H', 2),
              'int32': ('i', 4), 'uint32': ('I', 4), 'int64': ('q', 8), 'uint64': ('Q', 8),
              'float': ('f', 4), 'double': ('d', 8)}
HEADER_LENGTH = 8
GROUP_HEADER_LENGTH = 4


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


class Group:
    """One flat repeating group: entry fields at offsets inside an entry of ``block_length`` bytes."""

    def __init__(self, name, block_length, fields):
        self.name, self.block_length, self.fields = name, block_length, fields

    def field_names(self):
        return [f.name for f in self.fields]


class Message:
    def __init__(self, name, template_id, block_length, fields, group=None):
        self.name, self.template_id, self.block_length, self.fields = name, template_id, block_length, fields
        self.group = group
        self.variable = False

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
        group = message.group
        if group is None:
            if block != message.block_length or length != HEADER_LENGTH + block:
                raise SchemaError(f'template {template} block {block}/frame {length} != declared {message.block_length}')
        elif block != message.block_length or length < HEADER_LENGTH + block + GROUP_HEADER_LENGTH:
            raise SchemaError(f'template {template} block {block}/frame {length} != declared {message.block_length} '
                              f'plus a {group.name} group header')
        body = offset + HEADER_LENGTH
        values = {f.name: f.decode(data, body, self.order) for f in message.fields}
        if group is not None:
            values[group.name] = self._group(data, body + block, offset + length, template, group)
        return message, values

    def _group(self, data, start, end, template, group):
        entry_block, count = struct.unpack_from(self.order + 'HH', data, start)
        if entry_block != group.block_length:
            raise SchemaError(f'template {template} group entry block {entry_block} != declared {group.block_length}')
        first = start + GROUP_HEADER_LENGTH
        if first + count * entry_block > end:
            raise SchemaError(f'template {template} group overruns the frame')
        if first + count * entry_block != end:
            raise SchemaError(f'template {template} frame carries {end - first - count * entry_block} bytes after its '
                              f'{count} {group.name} entries')
        return [{f.name: f.decode(data, first + i * entry_block, self.order) for f in group.fields} for i in range(count)]


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


def _group(node, table, path, template):
    """A flat repeating group, or None when it is not one (a nested group, var-data, another dimension header)."""
    dimension = table.get(node.get('dimensionType') or 'groupSizeEncoding')
    parts = [(c.get('name'), c.get('primitiveType')) for c in dimension[1]] if dimension and dimension[0] == 'composite' else None
    if parts != [('blockLength', 'uint16'), ('numInGroup', 'uint16')]:
        return None
    fields, offset = [], 0
    for child in node:
        kind = _local(child.tag)
        if kind in ('group', 'data'):
            return None
        if kind != 'field':
            continue
        if child.get('offset') is not None:
            offset = int(child.get('offset'))
        field = _resolve(child.get('type'), table, child.get('name'), offset)
        field.since = int(child.get('sinceVersion', '0'))
        fields.append(field); offset += field.size
    declared = node.get('blockLength')
    return Group(node.get('name'), int(declared) if declared is not None else offset, fields)


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
        group = None
        for child in node:
            kind = _local(child.tag)
            if kind == 'data':
                has_variable = True
                continue
            if kind == 'group':
                # Anything beyond one flat fixed group stays "variable": loaded, but refused at decode as today.
                flat = None if group is not None or has_variable else _group(child, table, path, template)
                if flat is None:
                    has_variable = True
                else:
                    group = flat
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
        message = Message(node.get('name'), template, block, fields, group)
        message.variable = has_variable
        messages[template] = message
    return Schema(schema_id, version, order, messages)
