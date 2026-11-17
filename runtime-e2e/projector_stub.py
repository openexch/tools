# SPDX-License-Identifier: Apache-2.0
"""Test-only stand-in for the history projector: the projection drills' dry run before the projector binary exists.

Never published and never a product. It runs in a projector slot (``pj0``, ``pj1``) and fills the projection's base
tables and the three read relations of the gateway's history read contract from the core's order-event ring, so a drill
(story sizes, kill windows, the oracle comparison against PostgreSQL, the dump and hash step, the ``sources.json``
writer, the freeze bound of the freshness drill) can be run end to end against it. Standard library only.

What it does, every ``STUB_POLL_MS``:

* lease: one conditional UPDATE of the state row takes or renews the writer lease (database clock); zero rows is a
  standby, which holds no session and writes nothing. Every batch is fenced by the same predicate in its own transaction.
* read: one ``CoreProbe order-events from=<applied_seq> fields=full`` JVM on the slot's own GATEWAY key (a fresh cluster
  session per poll; the reply's ``last_seq`` is the core's head at that instant, the head probe).
* apply: one transaction per page, records in sequence order: the event row (its canonical JSON as the payload), the
  order row from the record's full state (guarded by ``last_event_seq``), a fill row for a FILL with tradeId > 0, then the
  state row ``WHERE writer_token = <mine>``; zero rows rolls back and the copy becomes a standby. A record at or below the
  cursor is compared with the stored payload; a difference parks the stub (``PAYLOAD_CONFLICT``). A ring overrun parks
  it (``GAP``): the ring no longer holds the next record.
* beat: when the probe answered, its head is at or below ``applied_seq`` and nothing is parked, ``beat_at`` is set to
  the database clock minus the time since the probe was sent.

What it does not do (the projector's job, stated so nobody reads a stub result as one): no Archive replay, no chain
following, no source list (its only source is the cluster session; the "attached source" it reports is the core member
that was leader at its last poll, read from the members' own metrics endpoints), no genesis check (wire v8 carries no
genesis id on a reply, so ``epoch`` stays 0), no ME cause on a record. ``liquidity`` is taken from the apply order of a
trade's two FILL records (the first is the taker), which the projector must not do.

Settings (environment, positive integers, defaults in ``SETTINGS``): STUB_POLL_MS, STUB_PAGE_EVENTS, STUB_LEASE_MS,
STUB_LEASE_POLL_MS, STUB_PROBE_BOUND_MS. Required: STUB_ADMIN_BIND, STUB_PG_URL (postgresql://user@host:port/db),
STUB_INSTANCE, STUB_CORE_PROBE (class path), STUB_MEMBER_METRICS (``name@host:port`` list), CORE_ADDRESSES,
CORE_PORT_BASE, CLUSTER_PORT_STRIDE, CORE_LOCAL_HOST, CORE_AUTH_CREDENTIAL. STUB_MODE: ``follow`` (default) or
``beat-always`` (the control of the freshness drill: it beats whatever the head, so stale history reads fresh).
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import uuid

JAVA = ['java', '--add-opens', 'java.base/jdk.internal.misc=ALL-UNNAMED', '--add-opens', 'java.base/sun.nio.ch=ALL-UNNAMED',
        '--add-opens', 'java.base/java.nio=ALL-UNNAMED', '-Xms64m', '-Xmx256m', '-Duser.home=/tmp']
SETTINGS = {'STUB_POLL_MS': 500, 'STUB_PAGE_EVENTS': 4096, 'STUB_LEASE_MS': 10000, 'STUB_LEASE_POLL_MS': 1000,
            'STUB_PROBE_BOUND_MS': 30000}
MODES = ('follow', 'beat-always')
NULL_PRICE_TYPES = {'MARKET', 'STOP_LOSS', 'TRAILING_STOP'}
ME_REASON_NONE = 255

# The projection's schema as the stub writes it: the base tables of the projection and the read contract's three
# relations as views over them. Applied under a transaction-scoped advisory lock (two copies may boot at once).
SCHEMA = """
CREATE TABLE IF NOT EXISTS oe_projection_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), epoch BIGINT NOT NULL DEFAULT 0,
    applied_seq BIGINT NOT NULL DEFAULT 0, applied_log_position BIGINT NOT NULL DEFAULT 0,
    applied_order_id BIGINT NOT NULL DEFAULT 0, head_seq BIGINT, beat_at TIMESTAMPTZ, writer_token TEXT,
    lease_until TIMESTAMPTZ, halt_reason TEXT, halt_detail TEXT, updated_at TIMESTAMPTZ);
INSERT INTO oe_projection_state (singleton) VALUES (TRUE) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS oe_projection_source_memo (source TEXT PRIMARY KEY, archive_id BIGINT, recording_id BIGINT,
    end_position BIGINT, seq BIGINT);
CREATE TABLE IF NOT EXISTS oe_projection_replay (source TEXT NOT NULL, archive_id BIGINT, replay_session_id BIGINT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (source, replay_session_id));
CREATE TABLE IF NOT EXISTS oe_order_events (
    journal_seq BIGINT PRIMARY KEY CHECK (journal_seq > 0), order_id BIGINT NOT NULL, user_id BIGINT NOT NULL,
    event TEXT NOT NULL, status TEXT NOT NULL, core_log_position BIGINT NOT NULL, liquidity TEXT NOT NULL,
    me_epoch BIGINT NOT NULL, me_journal_seq BIGINT NOT NULL, me_log_position BIGINT NOT NULL,
    me_timestamp_ms BIGINT NOT NULL, trade_id BIGINT NOT NULL, last_price BIGINT NOT NULL, last_qty BIGINT NOT NULL,
    hold_remaining BIGINT NOT NULL, at_ms BIGINT NOT NULL, payload BYTEA NOT NULL);
CREATE TABLE IF NOT EXISTS oe_orders (
    order_id BIGINT PRIMARY KEY CHECK (order_id > 0), user_id BIGINT NOT NULL, client_order_id UUID,
    market_id INTEGER NOT NULL, side TEXT NOT NULL, type TEXT NOT NULL, time_in_force TEXT NOT NULL, price BIGINT,
    stop_price BIGINT, quantity BIGINT NOT NULL, filled_quantity BIGINT NOT NULL, remaining_quantity BIGINT NOT NULL,
    status TEXT NOT NULL, reason TEXT, me_reason SMALLINT, me_order_id BIGINT, hold_asset_id INTEGER NOT NULL,
    hold_amount BIGINT NOT NULL, hold_remaining BIGINT NOT NULL, created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL, last_event_seq BIGINT NOT NULL, last_log_position BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS oe_orders_user_key ON oe_orders (user_id, updated_at_ms DESC, order_id DESC);
CREATE INDEX IF NOT EXISTS oe_orders_user_market_key ON oe_orders (user_id, market_id, updated_at_ms DESC, order_id DESC);
CREATE INDEX IF NOT EXISTS oe_orders_user_status_key ON oe_orders (user_id, status, updated_at_ms DESC, order_id DESC);
CREATE TABLE IF NOT EXISTS oe_fills (
    trade_id BIGINT NOT NULL CHECK (trade_id > 0), order_id BIGINT NOT NULL REFERENCES oe_orders (order_id),
    user_id BIGINT NOT NULL, market_id INTEGER NOT NULL, side TEXT NOT NULL, price BIGINT NOT NULL,
    quantity BIGINT NOT NULL, maker BOOLEAN NOT NULL, executed_at_ms BIGINT NOT NULL,
    event_seq BIGINT NOT NULL REFERENCES oe_order_events (journal_seq), core_log_position BIGINT NOT NULL,
    me_epoch BIGINT NOT NULL, me_journal_seq BIGINT NOT NULL, me_log_position BIGINT NOT NULL,
    me_timestamp_ms BIGINT NOT NULL, PRIMARY KEY (trade_id, order_id));
CREATE INDEX IF NOT EXISTS oe_fills_user_key ON oe_fills (user_id, executed_at_ms DESC, trade_id DESC, order_id DESC);
CREATE INDEX IF NOT EXISTS oe_fills_user_market_key ON oe_fills (user_id, market_id, executed_at_ms DESC, trade_id DESC, order_id DESC);
CREATE INDEX IF NOT EXISTS oe_fills_user_order_key ON oe_fills (user_id, order_id, executed_at_ms DESC, trade_id DESC);
CREATE OR REPLACE VIEW gateway_order_history_v1 AS SELECT order_id, user_id, client_order_id, market_id, side, type,
    time_in_force, price, stop_price, quantity, filled_quantity, remaining_quantity, status, reason, me_reason, me_order_id,
    hold_asset_id, hold_amount, hold_remaining, created_at_ms, updated_at_ms FROM oe_orders;
CREATE OR REPLACE VIEW gateway_fills_v1 AS SELECT trade_id, order_id, user_id, market_id, side, price, quantity, maker,
    executed_at_ms FROM oe_fills;
CREATE OR REPLACE VIEW gateway_history_heartbeat_v1 AS SELECT singleton, beat_at, applied_order_id,
    applied_seq AS applied_event_seq, epoch FROM oe_projection_state WHERE beat_at IS NOT NULL;
"""
SCHEMA_LOCK = 4802201   # the advisory lock key of the stub's migration


def settings(environ=os.environ):
    out = {}
    for name, default in SETTINGS.items():
        value = environ.get(name)
        if value is None or value == '':
            out[name] = default
        elif not value.isdigit() or int(value) < 1:
            raise SystemExit(f'projector_stub: {name} must be a positive integer, got {value!r}')
        else:
            out[name] = int(value)
    return out


# ------------------------------------------------------------------ PostgreSQL: the simple-query protocol, trust auth

class PgError(Exception):
    pass


class Pg:
    """One connection, simple query protocol, text results. Enough for the stub: no parameters, no COPY."""

    def __init__(self, url, timeout_s=10):
        m = re.fullmatch(r'postgres(?:ql)?://([^@/:]+)@([^/:]+):(\d+)/([A-Za-z0-9_]+)', url or '')
        if not m:
            raise SystemExit('projector_stub: STUB_PG_URL is postgresql://user@host:port/database')
        self.user, self.host, self.port, self.database = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        self.timeout_s = timeout_s
        self.sock = None
        self.status = None

    def connect(self):
        self.close()
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
        params = b''.join(k.encode() + b'\0' + v.encode() + b'\0' for k, v in
                          (('user', self.user), ('database', self.database), ('application_name', 'projector_stub'))) + b'\0'
        body = struct.pack('!i', 196608) + params
        self.sock.sendall(struct.pack('!i', len(body) + 4) + body)
        while True:
            kind, payload = self._read()
            if kind == b'R' and struct.unpack('!i', payload[:4])[0] != 0:
                raise PgError('authentication other than trust is not supported by the stub')
            if kind == b'E':
                raise PgError(self._error(payload))
            if kind == b'Z':
                self.status = payload[:1]
                return

    def close(self):
        if self.sock is not None:
            try:
                self.sock.sendall(b'X' + struct.pack('!i', 4))
            except OSError:
                pass
            self.sock.close()
            self.sock = None

    def _exact(self, n):
        out = b''
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise PgError('connection closed by the server')
            out += chunk
        return out

    def _read(self):
        header = self._exact(5)
        return header[:1], self._exact(struct.unpack('!i', header[1:])[0] - 4)

    @staticmethod
    def _error(payload):
        fields = {}
        for part in payload.split(b'\0'):
            if part:
                fields[part[:1]] = part[1:].decode(errors='replace')
        return f'{fields.get(b"C", "?")}: {fields.get(b"M", "?")}'

    def query(self, sql):
        """Run ``sql`` (one or more statements). Returns [(command tag, rows)], rows as lists of text-or-None. An error
        raises PgError after the server's ReadyForQuery (the transaction status is then 'E' inside a BEGIN)."""
        data = sql.encode() + b'\0'
        self.sock.sendall(b'Q' + struct.pack('!i', len(data) + 4) + data)
        results, rows, error = [], [], None
        while True:
            kind, payload = self._read()
            if kind == b'D':
                n = struct.unpack('!h', payload[:2])[0]
                at, row = 2, []
                for _ in range(n):
                    size = struct.unpack('!i', payload[at:at + 4])[0]
                    at += 4
                    row.append(None if size < 0 else payload[at:at + size].decode())
                    at += max(size, 0)
                rows.append(row)
            elif kind == b'C':
                results.append((payload.rstrip(b'\0').decode(), rows))
                rows = []
            elif kind == b'E':
                error = self._error(payload)
            elif kind == b'Z':
                self.status = payload[:1]
                if error:
                    raise PgError(error)
                return results


def lit(value):
    """A SQL literal for the stub's values: None, int, bool, str (quoted), bytes (hex bytea)."""
    if value is None:
        return 'NULL'
    if isinstance(value, bool):
        return 'TRUE' if value else 'FALSE'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, bytes):
        return "'\\x" + value.hex() + "'::bytea"
    return "'" + str(value).replace("'", "''") + "'"


# ------------------------------------------------------------------ the mapping (record -> columns)

def payload(event):
    """The stand-in record bytes: the event's canonical JSON (sorted keys, no spaces)."""
    return json.dumps(event, sort_keys=True, separators=(',', ':')).encode()


def client_order_id(high, low):
    value = ((int(high) & (2 ** 64 - 1)) << 64) | (int(low) & (2 ** 64 - 1))
    return None if value == 0 else str(uuid.UUID(int=value))


def order_columns(e):
    """The read contract's 21 order columns from one full-state record (null rules of the read contract)."""
    return {'order_id': e['order'], 'user_id': e['user'],
            'client_order_id': client_order_id(e.get('client_order_id_high', 0), e.get('client_order_id_low', 0)),
            'market_id': e['market'], 'side': e['side'], 'type': e['type'], 'time_in_force': e['tif'],
            'price': None if e['type'] in NULL_PRICE_TYPES else e['price'],
            'stop_price': e['stop_price'] or None, 'quantity': e['quantity'], 'filled_quantity': e['filled'],
            'remaining_quantity': e['remaining'], 'status': e['status'],
            'reason': None if e['reason'] == 'NONE' else e['reason'],
            'me_reason': None if e['me_reason'] == ME_REASON_NONE else e['me_reason'],
            'me_order_id': e['leg'] or None, 'hold_asset_id': e['hold_asset'], 'hold_amount': e['hold_amount'],
            'hold_remaining': e['hold_remaining'], 'created_at_ms': e['created_ms'], 'updated_at_ms': e['updated_ms']}


def is_fill(e):
    return e['kind'] == 'FILL' and e['trade'] > 0 and e['last_qty'] > 0


def batch_sql(events, applied, token, liquidity_of):
    """The statements of one apply transaction (without BEGIN/COMMIT), in sequence order, ending with the fenced state
    update. ``liquidity_of(event)`` -> 'TAKER' | 'MAKER' | 'NONE'."""
    out = []
    last = applied
    top_order = 0
    for e in events:
        seq = e['seq']
        if seq != last + 1:
            raise ValueError(f'batch not dense: {seq} after {last}')
        liquidity = liquidity_of(e)
        out.append('INSERT INTO oe_order_events VALUES (' + ', '.join(lit(v) for v in (
            seq, e['order'], e['user'], e['kind'], e['status'], e['log_position'], liquidity, 0, 0, 0, 0, e['trade'],
            e['last_price'], e['last_qty'], e['hold_remaining'], e['updated_ms'], payload(e))) + ')')
        cols = order_columns(e)
        cols.update(last_event_seq=seq, last_log_position=e['log_position'])
        names = list(cols)
        out.append(f'INSERT INTO oe_orders ({", ".join(names)}) VALUES ({", ".join(lit(cols[n]) for n in names)}) '
                   f'ON CONFLICT (order_id) DO UPDATE SET '
                   + ', '.join(f'{n} = EXCLUDED.{n}' for n in names if n != 'order_id')
                   + f' WHERE oe_orders.last_event_seq < {seq}')
        if is_fill(e):
            out.append('INSERT INTO oe_fills VALUES (' + ', '.join(lit(v) for v in (
                e['trade'], e['order'], e['user'], e['market'], e['side'], e['last_price'], e['last_qty'],
                liquidity == 'MAKER', e['updated_ms'], seq, e['log_position'], 0, 0, 0, 0)) + ')')
        top_order = max(top_order, e['order'])
        last = seq
    log_position = events[-1]['log_position'] if events else 0
    out.append(f'UPDATE oe_projection_state SET applied_seq = {last}, applied_log_position = {log_position}, '
               f'applied_order_id = GREATEST(applied_order_id, {top_order}), updated_at = clock_timestamp(), '
               f'lease_until = clock_timestamp() + lease_interval() WHERE writer_token = {lit(token)} AND applied_seq = {applied}')
    return out


# ------------------------------------------------------------------ the stub

class Stub:
    clock = staticmethod(time.monotonic)
    sleep = staticmethod(time.sleep)

    def __init__(self, environ=os.environ):
        self.env = environ
        self.s = settings(environ)
        self.mode = environ.get('STUB_MODE') or 'follow'
        if self.mode not in MODES:
            raise SystemExit(f'projector_stub: STUB_MODE is one of {MODES}, got {self.mode!r}')
        for name in ('STUB_ADMIN_BIND', 'STUB_PG_URL', 'STUB_INSTANCE', 'STUB_CORE_PROBE', 'STUB_MEMBER_METRICS',
                     'CORE_ADDRESSES', 'CORE_PORT_BASE', 'CLUSTER_PORT_STRIDE', 'CORE_LOCAL_HOST', 'CORE_AUTH_CREDENTIAL'):
            if not environ.get(name):
                raise SystemExit(f'projector_stub: {name} is required')
        self.instance = environ['STUB_INSTANCE']
        self.token = f'{self.instance}-{uuid.uuid4().hex[:12]}'
        self.members = []
        for part in environ['STUB_MEMBER_METRICS'].split(','):
            name, _, endpoint = part.partition('@')
            self.members.append((name, endpoint))
        self.pg = Pg(environ['STUB_PG_URL'])
        self.lock = threading.Lock()
        self.h = {'instance': self.instance, 'mode': self.mode, 'settings': self.s, 'role': 'starting',
                  'applied_seq': None, 'head_seq': None, 'halt': None, 'source': None, 'source_switches': 0,
                  'polls': 0, 'probe_unanswered': 0, 'probe_ms_total': 0, 'batches': 0, 'events_applied': 0, 'skips': 0, 'beats': 0,
                  'pg_failures': 0, 'fence_lost': 0, 'last_probe_sent_ns': None, 'last_probe_answered_ns': None, 'last_beat_ns': None,
                  'started_ns': time.time_ns(), 'driver': 'embedded (CoreProbe, one JVM per poll)',
                  'recordings_walked': [], 'archive_id': None}

    def note(self, **kv):
        with self.lock:
            self.h.update(kv)

    def count(self, key, n=1):
        with self.lock:
            self.h[key] += n

    def health(self):
        with self.lock:
            return json.loads(json.dumps(self.h))

    # -------------------------------------------------------------- database

    def migrate(self):
        self.pg.query('BEGIN; SELECT pg_advisory_xact_lock(%d);' % SCHEMA_LOCK + SCHEMA
                      + 'CREATE OR REPLACE FUNCTION lease_interval() RETURNS interval LANGUAGE sql IMMUTABLE AS '
                      + f"$$ SELECT interval '{self.s['STUB_LEASE_MS']} milliseconds' $$; COMMIT;")

    def take_lease(self):
        """True when this copy holds the lease after one conditional UPDATE (its own expired or free lease)."""
        tag, _ = self.pg.query(
            f"UPDATE oe_projection_state SET writer_token = {lit(self.token)}, lease_until = clock_timestamp() + "
            f"lease_interval() WHERE writer_token = {lit(self.token)} OR lease_until IS NULL OR lease_until < clock_timestamp()")[0]
        return tag == 'UPDATE 1'

    def state(self):
        _, rows = self.pg.query('SELECT applied_seq, applied_order_id, halt_reason FROM oe_projection_state')[0]
        return int(rows[0][0]), int(rows[0][1]), rows[0][2]

    def halt(self, reason, detail):
        self.note(halt={'reason': reason, 'detail': detail})
        self.pg.query(f'UPDATE oe_projection_state SET halt_reason = {lit(reason)}, halt_detail = {lit(detail)}, '
                      f'updated_at = clock_timestamp() WHERE writer_token = {lit(self.token)}')

    # -------------------------------------------------------------- the core

    def leader(self):
        """The member whose own metrics say leader (role 2), or None. Read over the network, never a shared disk."""
        for name, endpoint in self.members:
            try:
                with urllib.request.urlopen(f'http://{endpoint}/metrics', timeout=2) as r:
                    text = r.read().decode(errors='replace')
            except OSError:
                continue
            if re.search(r'^core_cluster_role(\{[^}]*\})? 2(\.0)?$', text, re.M):
                return name, endpoint
        return None

    def read(self, applied):
        """One CoreProbe order-events JVM: (sent monotonic, reply or None)."""
        sent = self.clock()
        self.note(last_probe_sent_ns=time.time_ns())
        argv = JAVA + ['-cp', self.env['STUB_CORE_PROBE'], 'CoreProbe', 'order-events', f'from={applied}',
                       f'until={applied + self.s["STUB_PAGE_EVENTS"]}', f'max={self.s["STUB_PAGE_EVENTS"]}', 'fields=full']
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=self.s['STUB_PROBE_BOUND_MS'] / 1000)
        except subprocess.TimeoutExpired:
            r = None
        # the probe's own time (answered or not): the drill's slowdown witness is its mean per poll
        self.count('probe_ms_total', max(0, int(round((self.clock() - sent) * 1000))))
        if r is None:
            self.note(last_probe_error={'exit': None, 'detail': 'no answer within STUB_PROBE_BOUND_MS'})
            return sent, None
        lines = [l for l in r.stdout.splitlines() if l.startswith('{')]
        if r.returncode != 0 or not lines:
            self.note(last_probe_error={'exit': r.returncode, 'detail': (r.stderr or r.stdout or '')[-400:]})
            return sent, None
        return sent, json.loads(lines[-1])

    # -------------------------------------------------------------- one cycle

    def apply(self, events, applied):
        """Apply one dense page past ``applied``; True when committed under this copy's lease."""
        takers = {}

        def liquidity_of(e):
            if not is_fill(e):
                return 'NONE'
            first = takers.setdefault(e['trade'], e['order'])
            return 'TAKER' if first == e['order'] else 'MAKER'
        if events:
            _, rows = self.pg.query('SELECT trade_id, order_id FROM oe_order_events WHERE trade_id IN ('
                                    + ', '.join(str(t) for t in sorted({e['trade'] for e in events if is_fill(e)}) or [0])
                                    + ") AND event = 'FILL' ORDER BY journal_seq")[0]
            for trade, order in rows:
                takers.setdefault(int(trade), int(order))
        statements = batch_sql(events, applied, self.token, liquidity_of)
        results = self.pg.query('BEGIN; ' + '; '.join(statements))
        if results[-1][0] != 'UPDATE 1':
            self.pg.query('ROLLBACK')
            self.count('fence_lost')
            return False
        self.pg.query('COMMIT')
        return True

    def compare(self, events):
        """Records at or below the cursor: compared with the stored payload, byte for byte. Returns the conflict or None."""
        for e in events:
            _, rows = self.pg.query(f'SELECT encode(payload, \'hex\') FROM oe_order_events WHERE journal_seq = {e["seq"]}')[0]
            if rows and bytes.fromhex(rows[0][0]) != payload(e):
                return e['seq']
            self.count('skips')
        return None

    def beat(self, sent):
        elapsed_ms = max(0, int((self.clock() - sent) * 1000))
        self.pg.query(f"UPDATE oe_projection_state SET beat_at = clock_timestamp() - interval '{elapsed_ms} milliseconds' "
                      f'WHERE writer_token = {lit(self.token)}')
        self.count('beats')
        self.note(last_beat_ns=time.time_ns())

    def cycle(self):
        if not self.take_lease():
            self.note(role='standby')
            return self.s['STUB_LEASE_POLL_MS']
        self.note(role='writer')
        applied, _, halt = self.state()
        self.note(applied_seq=applied)
        source = self.leader()
        previous = self.health().get('source')
        if source and previous and previous.get('member') != source[0]:
            self.count('source_switches')
        if source:
            self.note(source={'member': source[0], 'metrics': source[1], 'kind': 'cluster-session-leader'})
        sent, reply = self.read(applied)
        self.count('polls')
        if reply is None:
            self.count('probe_unanswered')
            return self.s['STUB_POLL_MS']
        head = reply.get('last_seq')
        self.note(head_seq=head, last_probe_answered_ns=time.time_ns())
        self.pg.query(f'UPDATE oe_projection_state SET head_seq = {lit(head)} WHERE writer_token = {lit(self.token)}')
        if reply.get('lost'):
            self.halt('GAP', json.dumps(reply['lost']))
            return self.s['STUB_POLL_MS']
        events = sorted(reply.get('events') or [], key=lambda e: e['seq'])
        old = [e for e in events if e['seq'] <= applied]
        new = [e for e in events if e['seq'] > applied]
        conflict = self.compare(old)
        if conflict is not None:
            self.halt('PAYLOAD_CONFLICT', f'seq {conflict}')
            return self.s['STUB_POLL_MS']
        if new:
            if not self.apply(new, applied):
                self.note(role='standby')
                return self.s['STUB_LEASE_POLL_MS']
            self.count('batches')
            self.count('events_applied', len(new))
            applied = new[-1]['seq']
            self.note(applied_seq=applied)
        if halt is None and head is not None and applied >= head:
            self.beat(sent)
        return 0 if new and len(new) >= self.s['STUB_PAGE_EVENTS'] else self.s['STUB_POLL_MS']

    def beat_always(self):
        """The control mode: a beat every poll interval on its own connection, whatever the head, the session or the
        probe say (only a frozen process stops it)."""
        pg = Pg(self.env['STUB_PG_URL'])
        while True:
            try:
                if pg.sock is None:
                    pg.connect()
                tag, _ = pg.query(f'UPDATE oe_projection_state SET beat_at = clock_timestamp() '
                                  f'WHERE writer_token = {lit(self.token)}')[0]
                if tag == 'UPDATE 1':
                    self.count('beats')
                    self.note(last_beat_ns=time.time_ns())
            except (OSError, PgError):
                pg.close()
            self.sleep(self.s['STUB_POLL_MS'] / 1000)

    def run(self):
        if self.mode == 'beat-always':
            threading.Thread(target=self.beat_always, daemon=True).start()
        while True:
            try:
                if self.pg.sock is None:
                    self.pg.connect()
                    self.migrate()
                wait = self.cycle()
            except (OSError, PgError) as error:
                self.count('pg_failures')
                self.note(last_pg_error=str(error)[:300])
                self.pg.close()
                wait = self.s['STUB_POLL_MS']
            self.sleep(wait / 1000)


def serve(stub, bind):
    host, _, port = bind.rpartition(':')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            h = stub.health()
            fresh = h['last_probe_answered_ns'] is not None and time.time_ns() - h['last_probe_answered_ns'] < 5e9
            if self.path == '/health':
                self.answer(200, h)
            elif self.path == '/ready':
                ok = h['role'] == 'writer' and h['halt'] is None and fresh
                self.answer(200 if ok else 503, {'ready': ok, 'role': h['role'], 'halt': h['halt']})
            elif self.path == '/metrics':
                text = ''.join(f'projector_stub_{k} {v}\n' for k, v in h.items() if isinstance(v, int) and not isinstance(v, bool))
                self.answer(200, text)
            else:
                self.answer(404, {'error': 'not found'})

        def answer(self, status, body):
            data = (body if isinstance(body, str) else json.dumps(body)).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain' if isinstance(body, str) else 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    stub = Stub()
    serve(stub, os.environ['STUB_ADMIN_BIND'])
    print(json.dumps({'event': 'start', 'instance': stub.instance, 'mode': stub.mode, 'settings': stub.s}), flush=True)
    stub.run()


if __name__ == '__main__':
    sys.exit(main())
