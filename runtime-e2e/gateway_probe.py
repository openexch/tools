# SPDX-License-Identifier: Apache-2.0
"""The gateway probe: client load with Idempotency-Key, the order oracle per key, and a stream client that records frames.

It runs inside the probe container (``python3 -I``, standard library only) and reaches the gateways and streams over the
fixture network, never through a disk. Three parts:

* ``load``: N order requests across the drill's users, each with its own Idempotency-Key (a UUID) and its own quantity
  (``quantity_of``), so a live order names the key that made it. Every request is retried with the SAME key and body
  until it is answered (any status other than 0, 502, 503 and 504) or ``--retry-bound-s`` passes; attempts rotate over
  the targets. Every ``--resend-every``-th key is sent once more after its answer, to the other target: the stored
  decision must come back. One JSON line per attempt; the run ends on ``--stop-file`` or when every key is settled.
* ``key_oracle`` (host side): per key, every answer must name one decision and the core must hold at most one order of
  the key's (user, quantity); the control text of a second order is exactly ``second order for one Idempotency-Key``.
* ``stream``: a minimal RFC 6455 client (text frames, ping/pong, close) that authenticates with a first frame,
  subscribes and writes every frame it receives, with its receive time, to a JSON line file.

Sizes, rates and bounds are arguments with defaults, never limits.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import socket
import struct
import sys
import threading
import time
import uuid

FP = 10 ** 8
RETRY_STATUSES = {0, 502, 503, 504}          # 0 = no HTTP answer (refused, reset, timed out)
SECOND_ORDER = 'second order for one Idempotency-Key'
NOT_LIVE = 'answered order not live'


# ------------------------------------------------------------------ the story

def quantity_of(index, unit):
    """The quantity of request ``index``: unique per request, so (user, quantity) names its key."""
    return (index + 1) * unit


def story(requests, users, seed, unit, price, market=1, resend_every=4):
    """The request table: [{i, key, user, body, resend}]. Deterministic in ``seed``; keys are UUIDs."""
    rng = random.Random(seed)
    rows = []
    for i in range(requests):
        key = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        qty = quantity_of(i, unit)
        # No clientOrderId: the core refuses a second order of one user with the same clientOrderId
        # (DUPLICATE_CLIENT_ORDER_ID), which would hide a gateway that mints a fresh request id on a retry and make the
        # drill's control vacuous. The quantity names the key instead.
        body = {'marketId': str(market), 'side': 'BUY', 'type': 'LIMIT', 'timeInForce': 'GTC', 'price': money(price),
                'quantity': money(qty)}
        rows.append({'i': i, 'key': key, 'user': users[i % len(users)], 'quantity': qty, 'body': body,
                     'resend': resend_every > 0 and i % resend_every == resend_every - 1})
    return rows


def money(units):
    whole, frac = divmod(int(units), FP)
    return f'{whole}.{frac:08d}'.rstrip('0').rstrip('.') if frac else str(whole)


def post(target, path, headers, body, timeout_s):
    """One HTTP request; (status, json body or text, error). Status 0 when nothing came back."""
    return request('POST', target, path, headers, body, timeout_s)


def request(method, target, path, headers, body, timeout_s):
    """One HTTP request of any method (``body`` None sends none); (status, json body or text, error)."""
    host, _, port = target.rpartition(':')
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout_s)
    try:
        if body is None:
            conn.request(method, path, headers=dict(headers))
        else:
            data = body if isinstance(body, (bytes, str)) else json.dumps(body)
            conn.request(method, path, body=data, headers={**headers, 'Content-Type': 'application/json'})
        response = conn.getresponse()
        raw = response.read().decode(errors='replace')
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = raw
        return response.status, parsed, None
    except (OSError, http.client.HTTPException) as error:
        return 0, None, f'{type(error).__name__}: {error}'
    finally:
        conn.close()


def settled(status):
    return status not in RETRY_STATUSES


class Load:
    def __init__(self, rows, targets, api_keys, out, retry_bound_s=120, attempt_s=30, backoff_s=0.5, concurrency=4,
                 stop_file=None, sender=post, clock=time.monotonic, sleep=time.sleep, rate=0):
        self.rows, self.targets, self.keys = rows, targets, api_keys
        self.rate, self.next_slot = rate, None
        self.out, self.retry_bound_s, self.attempt_s, self.backoff_s = out, retry_bound_s, attempt_s, backoff_s
        self.concurrency, self.stop_file, self.sender, self.clock, self.sleep = concurrency, stop_file, sender, clock, sleep
        self.lock = threading.Lock()
        self.next = 0

    def record(self, row):
        with self.lock:
            with open(self.out, 'a') as f:
                f.write(json.dumps(row) + '\n')

    def stopped(self):
        return bool(self.stop_file) and os.path.exists(self.stop_file)

    def pace(self):
        """With a rate, one attempt per 1/rate seconds over all workers (a schedule, not a limit of the system)."""
        if not self.rate:
            return
        with self.lock:
            now = self.clock()
            slot = now if self.next_slot is None or self.next_slot < now else self.next_slot
            self.next_slot = slot + 1.0 / self.rate
        if slot > now:
            self.sleep(slot - now)

    def attempt(self, row, n, target, phase):
        self.pace()
        sent = time.time_ns()
        status, body, error = self.sender(target, '/api/v2/orders', {'X-API-Key': self.keys[str(row['user'])],
                                                                     'Idempotency-Key': row['key']}, row['body'], self.attempt_s)
        self.record({'i': row['i'], 'key': row['key'], 'user': row['user'], 'quantity': row['quantity'], 'attempt': n,
                     'phase': phase, 'target': target, 'status': status, 'body': body, 'error': error, 'sent_ns': sent,
                     'recv_ns': time.time_ns()})
        return status, body

    def one(self, row):
        """Send until answered (same key, same body), then the resend to the next target when the row asks for it."""
        deadline = self.clock() + self.retry_bound_s
        n, status = 0, 0
        while not self.stopped():
            target = self.targets[(row['i'] + n) % len(self.targets)]
            status, _ = self.attempt(row, n, target, 'send')
            n += 1
            if settled(status) or self.clock() >= deadline:
                break
            self.sleep(self.backoff_s)
        if settled(status) and row['resend'] and not self.stopped():
            self.attempt(row, n, self.targets[(row['i'] + n) % len(self.targets)], 'resend')

    def worker(self):
        while True:
            with self.lock:
                if self.next >= len(self.rows) or self.stopped():
                    return
                row = self.rows[self.next]
                self.next += 1
            self.one(row)

    def run(self):
        threads = [threading.Thread(target=self.worker, daemon=True) for _ in range(max(1, self.concurrency))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


# ------------------------------------------------------------------ the order oracle per key

def key_oracle(rows, attempts, live_orders, market=1, nothing_fills=False):
    """Judge the load. ``rows``: the story table; ``attempts``: the attempt lines; ``live_orders``: the core's open orders
    (CoreProbe order-dump rows). Returns {verdict, failures, keys, unanswered, ...}; ``failures`` holds one text per
    broken rule, the second-order text exactly ``SECOND_ORDER``. With ``nothing_fills`` (a story where no order can
    trade or be cancelled) a key answered with an order must also have that order live."""
    by_key = {r['key']: r for r in rows}
    answers = {}
    for a in attempts:
        if a['key'] in by_key and settled(a['status']):
            answers.setdefault(a['key'], []).append(a)
    users = {r['user'] for r in rows}
    owned = {}
    for o in live_orders:
        if o.get('user') in users and o.get('market') == market:
            owned.setdefault((o['user'], o['quantity']), []).append(o)
    failures, unanswered, second, split, missing, not_live = [], [], [], [], [], []
    for key, row in by_key.items():
        got = answers.get(key) or []
        if not got:
            unanswered.append(key)
        decisions = {decision(a) for a in got}
        if len(decisions) > 1:
            split.append(key)
        orders = owned.pop((row['user'], row['quantity']), [])
        if len(orders) > 1:
            second.append(key)
        ids = {d[1] for d in decisions if d[0] == 'order'}
        if ids and orders and not ids & {str(o['order']) for o in orders}:
            missing.append(key)
        if ids and not orders and nothing_fills:
            not_live.append(key)
    stray = sorted(o['order'] for orders in owned.values() for o in orders)
    if second:
        failures.append(SECOND_ORDER)
    if split:
        failures.append('a retried key answered two decisions')
    if missing:
        failures.append('answered order is not the live order of its key')
    if stray:
        failures.append('a live order no key made')
    if not_live:
        failures.append(NOT_LIVE)
    verdict = 'FAIL' if failures else 'INCONCLUSIVE' if unanswered else 'PASS'
    return {'verdict': verdict, 'failures': failures, 'keys': len(by_key), 'answered': len(by_key) - len(unanswered),
            'unanswered': unanswered[:20], 'unanswered_count': len(unanswered), 'second_order_keys': second[:20],
            'split_keys': split[:20], 'missing_keys': missing[:20], 'stray_orders': stray[:20], 'not_live_keys': not_live[:20],
            'resends': sum(1 for a in attempts if a.get('phase') == 'resend'),
            'retried_keys': len({a['key'] for a in attempts if a.get('attempt', 0) > 0 and a.get('phase') == 'send'})}


def decision(attempt):
    """What one answer decided: ('order', orderId) for a 2xx, else ('reject', status, code)."""
    body = attempt.get('body') if isinstance(attempt.get('body'), dict) else {}
    if 200 <= attempt['status'] < 300:
        return ('order', str(body.get('orderId')))
    return ('reject', attempt['status'], body.get('code'))


# ------------------------------------------------------------------ the stream client (RFC 6455)

def ws_frame(opcode, payload, mask=None):
    """One client frame: FIN set, masked (a client always masks)."""
    mask = mask if mask is not None else os.urandom(4)
    head = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([0x80 | n])
    elif n < 1 << 16:
        head += bytes([0x80 | 126]) + struct.pack('!H', n)
    else:
        head += bytes([0x80 | 127]) + struct.pack('!Q', n)
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def ws_parse(buffer):
    """(fin, opcode, payload, consumed) of the first complete server frame in ``buffer``, or None. A server frame is
    never masked; a masked one is refused."""
    if len(buffer) < 2:
        return None
    fin, opcode = buffer[0] & 0x80, buffer[0] & 0x0F
    if buffer[1] & 0x80:
        raise ValueError('a server frame is never masked')
    n, at = buffer[1] & 0x7F, 2
    if n == 126:
        if len(buffer) < 4:
            return None
        n, at = struct.unpack('!H', buffer[2:4])[0], 4
    elif n == 127:
        if len(buffer) < 10:
            return None
        n, at = struct.unpack('!Q', buffer[2:10])[0], 10
    if len(buffer) < at + n:
        return None
    return bool(fin), opcode, bytes(buffer[at:at + n]), at + n


def ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()


class WsClient:
    def __init__(self, host, port, path='/ws/v2', timeout_s=10, headers=None):
        self.sock = socket.create_connection((host, port), timeout=timeout_s)
        key = base64.b64encode(os.urandom(16)).decode()
        extra = ''.join(f'{k}: {v}\r\n' for k, v in (headers or {}).items())
        upgrade = (f'GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                   f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n')
        self.sock.sendall(upgrade.encode())
        head = b''
        while b'\r\n\r\n' not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError('closed during the upgrade')
            head += chunk
        head, _, self.buffer = head.partition(b'\r\n\r\n')
        lines = head.decode(errors='replace').split('\r\n')
        if ' 101 ' not in lines[0] + ' ':
            raise ConnectionError('upgrade refused: ' + lines[0])
        accept = next((l.split(':', 1)[1].strip() for l in lines[1:] if l.lower().startswith('sec-websocket-accept:')), None)
        if accept != ws_accept(key):
            raise ConnectionError('bad Sec-WebSocket-Accept')
        self.buffer = bytearray(self.buffer)
        self.fragments = []

    def send(self, obj):
        self.sock.sendall(ws_frame(0x1, json.dumps(obj).encode()))

    def recv(self):
        """The next text message (str), or ('close', code) on a close frame. Pings are answered."""
        while True:
            parsed = ws_parse(self.buffer)
            if parsed is None:
                chunk = self.sock.recv(65536)
                if not chunk:
                    return ('close', None)
                self.buffer += chunk
                continue
            fin, opcode, payload, used = parsed
            del self.buffer[:used]
            if opcode == 0x9:
                self.sock.sendall(ws_frame(0xA, payload))
                continue
            if opcode == 0x8:
                code = struct.unpack('!H', payload[:2])[0] if len(payload) >= 2 else None
                return ('close', code)
            if opcode in (0x1, 0x0):
                self.fragments.append(payload)
                if fin:
                    text, self.fragments = b''.join(self.fragments).decode(), []
                    return text


def stream(target, token, channels, out, stop_file=None, seconds=60):
    """Record every frame of one connection: auth first frame, subscribe, then until the stop file or ``seconds``."""
    host, _, port = target.rpartition(':')
    client = WsClient(host, int(port))
    client.sock.settimeout(1.0)
    client.send({'op': 'auth', 'token': token})
    client.send({'op': 'subscribe', 'channels': channels})
    deadline = time.monotonic() + seconds
    with open(out, 'a') as f:
        while time.monotonic() < deadline and not (stop_file and os.path.exists(stop_file)):
            try:
                frame = client.recv()
            except socket.timeout:
                continue
            row = {'recv_ns': time.time_ns()}
            if isinstance(frame, tuple):
                row['close'] = frame[1]
                f.write(json.dumps(row) + '\n')
                break
            try:
                row['frame'] = json.loads(frame)
            except ValueError:
                row['text'] = frame
            f.write(json.dumps(row) + '\n')
            f.flush()


# ------------------------------------------------------------------ the stream client's view of one user

TERMINAL = {'FILLED', 'CANCELLED', 'REJECTED', 'EXPIRED'}


class OrderView:
    """What a stream client knows of its user's open orders: a ``snapshot`` (orders channel) replaces the set, an
    ``order`` frame updates or removes one order (a terminal status removes it), a ``resync`` waits for the next
    snapshot. ``fill`` frames are kept with their receive time. Pure: frames in, state out."""

    def __init__(self):
        self.open, self.fills, self.statuses = {}, {}, {}
        self.snapshots, self.resyncs, self.frames, self.last_seq = 0, 0, 0, None
        self.awaiting_snapshot = True

    def apply(self, frame, recv_ns):
        self.frames += 1
        kind = frame.get('type')
        if isinstance(frame.get('eventSeq'), int):
            self.last_seq = frame['eventSeq']
        if kind == 'snapshot' and frame.get('channel') == 'orders':
            self.open = {str(o['orderId']): o.get('status') for o in frame.get('orders') or []}
            self.snapshots += 1
            self.awaiting_snapshot = False
            for o in frame.get('orders') or []:
                self.statuses.setdefault(str(o['orderId']), []).append([o.get('status'), recv_ns])
        elif kind == 'order':
            order = frame.get('order') or {}
            oid, status = str(order.get('orderId')), order.get('status')
            self.statuses.setdefault(oid, []).append([status, recv_ns])
            if not self.awaiting_snapshot:
                if status in TERMINAL:
                    self.open.pop(oid, None)
                else:
                    self.open[oid] = status
        elif kind == 'fill':
            fill = frame.get('fill') or {}
            self.fills.setdefault(str(fill.get('orderId')), []).append(recv_ns)
        elif kind == 'resync':
            self.resyncs += 1
            self.awaiting_snapshot = True

    def final(self):
        return {'open': sorted(self.open, key=int), 'snapshots': self.snapshots, 'resyncs': self.resyncs,
                'frames': self.frames, 'last_seq': self.last_seq, 'awaiting_snapshot': self.awaiting_snapshot}


class StreamConn(threading.Thread):
    """One user's connection to one stream, kept open (reconnected after a close) until ``stop()``. The credential goes
    in the upgrade's X-API-Key header, never in a URL."""

    def __init__(self, target, api_key, channels=('orders', 'fills'), log=None, reconnect_s=1.0):
        super().__init__(daemon=True)
        self.target, self.api_key, self.channels, self.log, self.reconnect_s = target, api_key, list(channels), log, reconnect_s
        self.view, self.cond, self.halt = OrderView(), threading.Condition(), threading.Event()
        self.closes, self.connects, self.errors = [], 0, []

    def stop(self):
        self.halt.set()

    def wait(self, predicate, timeout_s):
        """Wait until ``predicate(view)`` holds; True, or False at the bound."""
        deadline = time.monotonic() + timeout_s
        with self.cond:
            while not predicate(self.view):
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self.cond.wait(min(left, 0.2))
        return True

    def run(self):
        host, _, port = self.target.rpartition(':')
        while not self.halt.is_set():
            try:
                client = WsClient(host, int(port), headers={'X-API-Key': self.api_key})
                client.sock.settimeout(0.5)
                client.send({'op': 'subscribe', 'channels': self.channels})
                self.connects += 1
            except (OSError, ConnectionError) as error:
                self.errors.append([time.time_ns(), f'{type(error).__name__}: {error}'][:2])
                self.halt.wait(self.reconnect_s)
                continue
            while not self.halt.is_set():
                try:
                    frame = client.recv()
                except socket.timeout:
                    continue
                except (OSError, ValueError) as error:
                    frame = ('close', f'{type(error).__name__}')
                now = time.time_ns()
                if isinstance(frame, tuple):
                    self.closes.append([now, frame[1]])
                    with self.cond:
                        self.view.awaiting_snapshot = True
                        self.cond.notify_all()
                    break
                try:
                    parsed = json.loads(frame)
                except ValueError:
                    continue
                with self.cond:
                    self.view.apply(parsed, now)
                    self.cond.notify_all()
                if self.log is not None:
                    self.log.write(json.dumps({'recv_ns': now, 'frame': parsed}) + '\n')
            try:
                client.sock.close()
            except OSError:
                pass
            if not self.halt.is_set():
                self.halt.wait(self.reconnect_s)


def streams(conns, keys, out, stop_file, seconds):
    """Hold one StreamConn per {user, target} until the stop file (or ``seconds``); then write each one's final view."""
    running = []
    logs = Path(out).with_suffix('.frames')
    logs.mkdir(parents=True, exist_ok=True)
    for c in conns:
        log = open(logs / f'{c["user"]}-{c["target"].replace(":", "_")}.jsonl', 'a', buffering=1)
        conn = StreamConn(c['target'], keys[str(c['user'])], log=log)
        conn.start()
        running.append((c, conn, log))
    deadline = time.monotonic() + seconds
    progress, written = Path(str(out)[:-len('.json')] + '.progress.json' if str(out).endswith('.json') else str(out) + '.progress'), 0.0
    while time.monotonic() < deadline and not (stop_file and os.path.exists(stop_file)):
        time.sleep(0.2)
        if time.monotonic() - written >= 1.0:
            rows = []
            for c, conn, _ in running:
                with conn.cond:
                    rows.append(dict(c, **conn.view.final(), connects=conn.connects, closes=conn.closes[:20]))
            tmp = progress.with_name(progress.name + '.tmp')
            tmp.write_text(json.dumps(rows) + '\n')
            os.replace(tmp, progress)
            written = time.monotonic()
    result = []
    for c, conn, log in running:
        conn.stop()
    for c, conn, log in running:
        conn.join(5)
        log.close()
        with conn.cond:
            result.append(dict(c, **conn.view.final(), connects=conn.connects, closes=conn.closes[:20],
                               errors=conn.errors[:5]))
    Path(out).write_text(json.dumps(result) + '\n')


# ------------------------------------------------------------------ order requests on behalf of a user

def order_body(market, side, kind, tif, price=None, quantity=None, budget=None, stop_price=None):
    body = {'marketId': str(market), 'side': side, 'type': kind, 'timeInForce': tif, 'quantity': money(quantity)}
    if price is not None:
        body['price'] = money(price)
    if budget is not None:
        body['budget'] = money(budget)
    if stop_price is not None:
        body['stopPrice'] = money(stop_price)
    return body


class Client:
    """Requests of one run, each recorded (route, status, body, send and receive times) for the host's oracles."""

    def __init__(self, keys, timeout_s=30):
        self.keys, self.timeout_s, self.log, self.lock = keys, timeout_s, [], threading.Lock()
        self.send = request

    def call(self, method, target, path, user, body=None, key=None, tag=None):
        headers = {'X-API-Key': self.keys[str(user)]}
        if key is not None:
            headers['Idempotency-Key'] = key
        sent = time.time_ns()
        status, reply, error = self.send(method, target, path, headers, body, self.timeout_s)
        row = {'method': method, 'target': target, 'path': path, 'user': user, 'key': key, 'body': body, 'status': status,
               'reply': reply, 'error': error, 'sent_ns': sent, 'recv_ns': time.time_ns(), 'tag': tag}
        with self.lock:
            self.log.append(row)
        return row

    def create(self, target, user, body, key=None, tag=None):
        return self.call('POST', target, '/api/v2/orders', user, body, key or str(uuid.uuid4()), tag)

    def open_ids(self, target, user, market):
        row = self.call('GET', target, f'/api/v2/orders?marketId={market}', user, tag='open')
        if row['status'] != 200 or not isinstance(row['reply'], dict):
            return None
        return {str(o['orderId']) for o in row['reply'].get('orders') or []}


def order_id(row):
    return str(row['reply'].get('orderId')) if isinstance(row.get('reply'), dict) and 200 <= row['status'] < 300 else None


# ------------------------------------------------------------------ fill visibility (closed loop)

def handshake(signal_dir, name, info, wait_s, clock=time.monotonic, sleep=time.sleep):
    """Write ``<name>.ready`` (``info`` as JSON) into ``signal_dir`` and wait for ``<name>.go`` up to ``wait_s``: the host
    acts between the two (for example mutes a stream once every client holds its snapshot). True when go was seen."""
    signal = Path(signal_dir)
    tmp = signal / f'{name}.ready.tmp'
    tmp.write_text(json.dumps(info) + '\n')
    os.replace(tmp, signal / f'{name}.ready')
    deadline = clock() + wait_s
    while not (signal / f'{name}.go').exists():
        if clock() >= deadline:
            return False
        sleep(0.05)
    return True


class GonePoller(threading.Thread):
    """Polls ``fetch()`` (one GET /orders: its request row, ``reply`` the open ids or None) from the moment it starts
    until ``order`` is no longer listed or ``bound_s`` passes; ``gone_ns`` is the receive time of the first answer that
    no longer lists it. Started at the 201, so the instant does not wait on anything else."""

    def __init__(self, fetch, order, bound_s, poll_s, clock=time.monotonic, sleep=time.sleep):
        super().__init__(daemon=True)
        self.fetch, self.order, self.bound_s, self.poll_s, self.clock, self.sleep = fetch, order, bound_s, poll_s, clock, sleep
        self.gone_ns, self.polls = None, 0

    def run(self):
        deadline = self.clock() + self.bound_s
        while self.clock() < deadline:
            ids, recv_ns = self.fetch()
            self.polls += 1
            if ids is not None and self.order not in ids:
                self.gone_ns = recv_ns
                return
            self.sleep(self.poll_s)


def stream_states(conns):
    """Each stream client's connects and snapshots, as the host's check that every stream was live before the pairs."""
    out = []
    for (user, target), conn in conns.items():
        with conn.cond:
            out.append({'user': user, 'target': target, 'connects': conn.connects, 'snapshots': conn.view.snapshots})
    return out


def pairs(plan, keys, out):
    """``plan``: {pairs: n, layouts: [{maker, taker, maker_gw, taker_gw, maker_st, taker_st}], market, price, quantity,
    visible_bound_s, booked_bound_s, poll_ms, stop_after_failures, signal_dir, wait_go_s}. Every stream client first
    holds its snapshot; with ``signal_dir`` the probe then writes ``pairs.ready`` (each client's connects and snapshots)
    and waits for ``pairs.go``. Per pair, in a closed loop: the maker's SELL is sent and waited for as NEW on the maker's
    stream (booked by the ME); then the taker's crossing BUY: accept latency is the request sent to its 201; fill
    visibility is the 201 to the taker's ``fill`` frame on the taker's stream, and the 201 to ``GET /orders`` no longer
    listing the order (polled in its own thread from the 201). Every instant is recorded; no bound is a pass criterion."""
    client = Client(keys)
    conns = {}
    for lay in plan['layouts']:
        for user, st in ((lay['maker'], lay['maker_st']), (lay['taker'], lay['taker_st'])):
            if (user, st) not in conns:
                conns[(user, st)] = StreamConn(st, keys[str(user)])
                conns[(user, st)].start()
    for conn in conns.values():
        conn.wait(lambda v: v.snapshots > 0, plan['visible_bound_s'])
    at_go = stream_states(conns)
    go = handshake(plan['signal_dir'], 'pairs', {'streams': at_go}, plan.get('wait_go_s', 120)) if plan.get('signal_dir') else None
    rows, failures = [], 0
    for i in range(plan['pairs']):
        lay = plan['layouts'][i % len(plan['layouts'])]
        maker_view, taker_view = conns[(lay['maker'], lay['maker_st'])], conns[(lay['taker'], lay['taker_st'])]
        row = {'i': i, 'layout': lay['name'], 'maker': lay['maker'], 'taker': lay['taker']}
        m = client.create(lay['maker_gw'], lay['maker'], order_body(plan['market'], 'SELL', 'LIMIT', 'GTC', plan['price'],
                                                                     plan['quantity']), tag=f'maker-{i}')
        row['maker_status'], row['maker_order'] = m['status'], order_id(m)
        if row['maker_order'] is None:
            row['failure'] = 'maker not accepted'
        else:
            mid = row['maker_order']
            row['maker_booked'] = maker_view.wait(lambda v: any(s in ('NEW', 'PARTIALLY_FILLED') for s, _ in
                                                                    v.statuses.get(mid, [])), plan['booked_bound_s'])
            t = client.create(lay['taker_gw'], lay['taker'], order_body(plan['market'], 'BUY', 'LIMIT', 'GTC', plan['price'],
                                                                         plan['quantity']), tag=f'taker-{i}')
            row.update(taker_status=t['status'], taker_order=order_id(t), sent_ns=t['sent_ns'], accepted_ns=t['recv_ns'])
            tid = row['taker_order']
            if tid is None:
                row['failure'] = 'taker not accepted'
            else:
                def fetch(lay=lay):
                    r = client.call('GET', lay['taker_gw'], f'/api/v2/orders?marketId={plan["market"]}', lay['taker'], tag='open')
                    ok = r['status'] == 200 and isinstance(r['reply'], dict)
                    return ({str(o['orderId']) for o in r['reply'].get('orders') or []} if ok else None), r['recv_ns']
                poller = GonePoller(fetch, tid, plan['visible_bound_s'], plan['poll_ms'] / 1000)
                poller.start()
                seen = taker_view.wait(lambda v: tid in v.fills, plan['visible_bound_s'])
                with taker_view.cond:
                    row['fill_frame_ns'] = taker_view.view.fills[tid][0] if seen else None
                poller.join(plan['visible_bound_s'] + 30)
                row['orders_gone_ns'], row['order_polls'] = poller.gone_ns, poller.polls
                if not seen:
                    row['failure'] = 'fill never visible'
                    failures += 1
        rows.append(row)
        if plan.get('stop_after_failures') and failures >= plan['stop_after_failures']:
            break
    for conn in conns.values():
        conn.stop()
    Path(out).write_text(json.dumps({'pairs': rows, 'requests': [r for r in client.log if r['tag'] != 'open'],
                                     'order_polls': sum(1 for r in client.log if r['tag'] == 'open'),
                                     'order_poll_statuses': sorted({r['status'] for r in client.log if r['tag'] == 'open'}),
                                     'streams_at_go': at_go, 'go': go,
                                     'streams': [dict(user=u, target=s, **c.view.final(), connects=c.connects,
                                                      closes=c.closes[:10]) for (u, s), c in conns.items()]}) + '\n')


# ------------------------------------------------------------------ the tick live path

def tick(plan, keys, out):
    """``plan``: {gw, st, maker, taker, trigger, market, empty_market, asks: [[price, qty]], market_qty, stop_price,
    stop_qty, trigger_price, trigger_qty, reference_bound_s, complete_bound_s, signal_dir, phase}. Phase ``pass``: the
    maker's asks rest; a MARKET BUY with no budget is retried with a new key while the core answers NO_REFERENCE_PRICE
    (no tick yet), until 201 or the bound; it must end FILLED on the taker's stream. A STOP_LOSS BUY above the last
    trade arms, the trigger user's crossing BUY trades through its stop price, and the stop must end FILLED. Phase
    ``noref``: (forwarders stopped by the fixture) a MARKET BUY on a market no tick ever priced is answered 422
    NO_REFERENCE_PRICE inside the request bound; one on the traded market is recorded as data."""
    client = Client(keys)
    result = {'phase': plan['phase']}
    if plan['phase'] == 'noref':
        for name, market in (('empty_market', plan['empty_market']), ('traded_market', plan['market'])):
            row = client.create(plan['gw'], plan['taker'], order_body(market, 'BUY', 'MARKET', 'IOC', quantity=plan['market_qty']),
                                tag='noref-' + name)
            result[name] = {k: row[k] for k in ('status', 'reply', 'error', 'sent_ns', 'recv_ns')}
        result['requests'] = client.log
        Path(out).write_text(json.dumps(result) + '\n')
        return
    taker = StreamConn(plan['st'], keys[str(plan['taker'])])
    taker.start()
    taker.wait(lambda v: v.snapshots > 0, plan['complete_bound_s'])
    for price, qty in plan['asks']:
        client.create(plan['gw'], plan['maker'], order_body(plan['market'], 'SELL', 'LIMIT', 'GTC', price, qty), tag='ask')
    deadline, answer, tries = time.monotonic() + plan['reference_bound_s'], None, 0
    while time.monotonic() < deadline:
        tries += 1
        answer = client.create(plan['gw'], plan['taker'], order_body(plan['market'], 'BUY', 'MARKET', 'IOC',
                                                                     quantity=plan['market_qty']), tag='market')
        code = (answer['reply'] or {}).get('reason') if isinstance(answer['reply'], dict) else None
        if not (answer['status'] == 422 and code == 'NO_REFERENCE_PRICE'):
            break
        time.sleep(0.5)
    result['market'] = {'tries': tries, 'status': answer['status'] if answer else None,
                        'reply': answer['reply'] if answer else None, 'order': order_id(answer) if answer else None}
    mid = result['market']['order']
    result['market']['completed'] = bool(mid) and taker.wait(lambda v: any(s == 'FILLED' for s, _ in v.statuses.get(mid, [])),
                                                              plan['complete_bound_s'])
    with taker.cond:
        result['market']['statuses'] = taker.view.statuses.get(mid or '', [])
    stop = client.create(plan['gw'], plan['taker'], order_body(plan['market'], 'BUY', 'STOP_LOSS', 'GTC', quantity=plan['stop_qty'],
                                                               stop_price=plan['stop_price']), tag='stop')
    sid = order_id(stop)
    result['stop'] = {'status': stop['status'], 'reply': stop['reply'], 'order': sid}
    if sid:
        result['stop']['armed'] = taker.wait(lambda v: bool(v.statuses.get(sid)), plan['complete_bound_s'])
        trig = client.create(plan['gw'], plan['trigger'], order_body(plan['market'], 'BUY', 'LIMIT', 'IOC', plan['trigger_price'],
                                                                     plan['trigger_qty']), tag='trigger')
        result['trigger'] = {'status': trig['status'], 'reply': trig['reply']}
        result['stop']['completed'] = taker.wait(lambda v: any(s == 'FILLED' for s, _ in v.statuses.get(sid, [])),
                                                 plan['complete_bound_s'])
        with taker.cond:
            result['stop']['statuses'] = taker.view.statuses.get(sid, [])
    else:
        result['stop']['completed'] = False
    taker.stop()
    result['requests'] = client.log
    Path(out).write_text(json.dumps(result) + '\n')


# ------------------------------------------------------------------ resends under a closed gate, cancels, fuzz

def resend(rows, targets, keys, fresh, out):
    """Every row of ``rows`` (story rows already decided) sent once more to each target with its key and body; then
    ``fresh`` new keys (the gate witness: under a closed gate a new create is refused ADMISSION_CLOSED)."""
    client = Client(keys)
    for row in rows:
        for target in targets:
            client.create(target, row['user'], row['body'], row['key'], tag='stored')
    for n, row in enumerate(fresh):
        client.create(targets[n % len(targets)], row['user'], row['body'], row['key'], tag='fresh')
    Path(out).write_text(json.dumps(client.log) + '\n')


def settle(rows, targets, keys, out, bound_s=60, backoff_s=0.5, sender=None, clock=time.monotonic, sleep=time.sleep):
    """Every row ({key, user, body}) sent with its key and body, rotating over ``targets``, until it is answered (any
    status but 0, 502, 503, 504) or ``bound_s`` passes; each answer recorded with tag ``settle``. Used after a closed gate
    reopens, so a key the gate refused ends decided. ``out`` None returns the log without writing it."""
    client = Client(keys)
    if sender is not None:
        client.send = sender
    for row in rows:
        deadline, n = clock() + bound_s, 0
        while True:
            r = client.create(targets[n % len(targets)], row['user'], row['body'], row['key'], tag='settle')
            n += 1
            if settled(r['status']) or clock() >= deadline:
                break
            sleep(backoff_s)
    if out is not None:
        Path(out).write_text(json.dumps(client.log) + '\n')
    return client.log


def place(rows, target, keys, out):
    """Every row ({key, user, body, tag}) sent once to ``target``; each answer recorded."""
    client = Client(keys)
    for row in rows:
        client.create(target, row['user'], row['body'], row['key'], tag=row.get('tag', 'place'))
    Path(out).write_text(json.dumps(client.log) + '\n')


def cancels(plan, keys, out):
    """``plan``: {gw, users, market, rest_price, stop_price, quantity, per_user, signal_dir, window_s}. Rest orders and
    arm stops, write ``cancels.ready``; on ``cancels.go`` send an unkeyed DELETE for every one of them, spread over
    ``window_s`` (the fixture kills the core leader inside that window), then a keyed cancel of one more resting order
    twice (the replay must be PENDING_CANCEL) and a first-offer cancel of an unknown id (404)."""
    client = Client(keys)
    targets = []
    for user in plan['users']:
        for n in range(plan['per_user']):
            r = client.create(plan['gw'], user, order_body(plan['market'], 'BUY', 'LIMIT', 'GTC', plan['rest_price'],
                                                          plan['quantity']), tag='rest')
            if order_id(r):
                targets.append((user, order_id(r), 'resting'))
            s = client.create(plan['gw'], user, order_body(plan['market'], 'BUY', 'STOP_LOSS', 'GTC', quantity=plan['quantity'],
                                                          stop_price=plan['stop_price']), tag='stop')
            if order_id(s):
                targets.append((user, order_id(s), 'stop'))
    keyed = client.create(plan['gw'], plan['users'][0], order_body(plan['market'], 'BUY', 'LIMIT', 'GTC', plan['rest_price'],
                                                                  plan['quantity']), tag='rest')
    signal = Path(plan['signal_dir'])
    (signal / 'cancels.ready').write_text(json.dumps({'orders': len(targets)}))
    deadline = time.monotonic() + plan['wait_go_s']
    while not (signal / 'cancels.go').exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    gap = plan['window_s'] / max(1, len(targets))
    threads = []
    for user, oid, what in targets:
        t = threading.Thread(target=client.call, args=('DELETE', plan['gw'], f'/api/v2/orders/{oid}', user),
                             kwargs={'tag': 'cancel-' + what}, daemon=True)
        t.start()
        threads.append(t)
        time.sleep(gap)
    for t in threads:
        t.join(plan['request_bound_s'])
    if order_id(keyed):
        key = str(uuid.uuid4())
        for n in range(2):
            client.call('DELETE', plan['gw'], f'/api/v2/orders/{order_id(keyed)}', plan['users'][0], key=key, tag=f'keyed-{n}')
    client.call('DELETE', plan['gw'], '/api/v2/orders/' + str(plan['unknown_order']), plan['users'][0], tag='unknown')
    Path(out).write_text(json.dumps({'targets': targets, 'requests': client.log}) + '\n')


FUZZ_FIELDS = ['marketId', 'side', 'type', 'timeInForce', 'price', 'quantity', 'budget', 'stopPrice', 'clientOrderId']


def fuzz_cases(seed, count, user_order, unknown_asset=999):
    """Malformed REST inputs across the routes, deterministic in ``seed``: (method, path, body, key, kind). Every one must be
    answered (an HTTP status) and none may reach the core as a frame it drops. ``unknown_asset`` is an asset id the core's
    config does not list (a deposit of it is refused 400 by the gateway's asset check)."""
    rng = random.Random(seed)
    good = {'marketId': '1', 'side': 'BUY', 'type': 'LIMIT', 'timeInForce': 'GTC', 'price': '50', 'quantity': '0.001'}
    bad_values = [None, 1.5, -1, 'x', '', '1e3', '0.000000001', '99999999999999999999', [], {}, True, '\u0000', '-0', ' 1']
    cases = []
    for n in range(count):
        kind = rng.choice(['field', 'unknown_field', 'user_id', 'nil_key', 'bad_key', 'json', 'path', 'query', 'cancel',
                           'amend', 'deposit', 'unknown_asset', 'number_money', 'core'])
        key = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        body = dict(good)
        method, path = 'POST', '/api/v2/orders'
        if kind == 'field':
            body[rng.choice(FUZZ_FIELDS)] = rng.choice(bad_values)
        elif kind == 'unknown_field':
            body[rng.choice(['orderType', 'foo', 'userid', 'Price'])] = 'x'
        elif kind == 'user_id':
            body['userId'] = str(rng.randrange(1, 10**6))
        elif kind == 'nil_key':
            key = '00000000-0000-0000-0000-000000000000'
        elif kind == 'bad_key':
            key = rng.choice(['', 'x' * 65, 'with space', 'é'])
        elif kind == 'json':
            body = rng.choice(['{', '[]', 'null', '{"marketId":', '"x"', '1'])
        elif kind == 'number_money':
            body['price'] = 50
        elif kind == 'core':
            # Shape-valid, refused by the core's rules: these cross the wire, so the decode counters see them
            body.update(rng.choice([{'marketId': '99'}, {'quantity': '99999999'}, {'price': '50.00000003'},
                                    {'price': '0.00000001'}, {'marketId': '0'}]))
        elif kind == 'path':
            method, path, body = rng.choice(['GET', 'DELETE', 'PUT']), '/api/v2/orders/' + rng.choice(['0', '-1', 'x', '1e3',
                                                                                                        '99999999999999999999999']), None
        elif kind == 'query':
            method, path, body = 'GET', '/api/v2/orders?' + rng.choice(['marketId=x', 'userId=1', 'foo=1', 'marketId=-1',
                                                                         'marketId=1&marketId=2']), None
        elif kind == 'cancel':
            path, body = '/api/v2/orders/cancel', rng.choice([{'orderIds': ['x']}, {'orderIds': [1]}, {'all': 'yes'},
                                                               {'orderIds': [], 'all': True}, {'userId': '1', 'all': True}])
        elif kind == 'amend':
            method, path = 'PUT', '/api/v2/orders/' + str(user_order)
            body = rng.choice([{'price': 50}, {'quantity': 'x'}, {'price': '50', 'foo': 1}, {}, {'userId': '1'}])
        elif kind == 'deposit':
            path = '/api/v2/balances/deposit'
            body = rng.choice([{'assetId': '0', 'amount': 1}, {'assetId': 'x', 'amount': '1'}, {'assetId': '0', 'amount': '0'},
                               {'assetId': '0', 'amount': '1', 'userId': '1'}])
        elif kind == 'unknown_asset':
            path, body = '/api/v2/balances/deposit', {'assetId': str(unknown_asset), 'amount': '1'}
        cases.append({'n': n, 'kind': kind, 'method': method, 'path': path, 'body': body, 'key': key})
    return cases


def fuzz(plan, keys, out):
    """Send every fuzz case through ``plan['gw']`` as ``plan['user']``; record each answer."""
    client = Client(keys, timeout_s=plan['request_bound_s'])
    for case in fuzz_cases(plan['seed'], plan['count'], plan['user_order'], plan.get('unknown_asset', 999)):
        client.call(case['method'], plan['gw'], case['path'], plan['user'], case['body'], case['key'], tag='fuzz-' + case['kind'])
    Path(out).write_text(json.dumps(client.log) + '\n')


# ------------------------------------------------------------------ command line

def main(argv=None):
    parser = argparse.ArgumentParser(description='gateway probe')
    sub = parser.add_subparsers(dest='verb', required=True)
    p = sub.add_parser('load')
    p.add_argument('--targets', required=True, help='host:port,... of the gateways')
    p.add_argument('--keys', required=True, help='JSON {userId: apiKey}')
    p.add_argument('--story', required=True, help='JSON story table (story())')
    p.add_argument('--out', required=True)
    p.add_argument('--stop-file')
    p.add_argument('--done-file', required=True)
    p.add_argument('--concurrency', type=int, default=4)
    p.add_argument('--retry-bound-s', type=float, default=120)
    p.add_argument('--attempt-s', type=float, default=30)
    p.add_argument('--rate', type=float, default=0, help='attempts per second over all workers (0: unpaced)')
    s = sub.add_parser('stream')
    s.add_argument('--target', required=True); s.add_argument('--token-file', required=True)
    s.add_argument('--channels', default='orders,fills,balances'); s.add_argument('--out', required=True)
    s.add_argument('--stop-file'); s.add_argument('--seconds', type=float, default=60)
    for verb in ('pairs', 'tick', 'cancels', 'fuzz', 'resend', 'streams', 'settle', 'place'):
        v = sub.add_parser(verb)
        v.add_argument('--plan', required=True, help='JSON plan file')
        v.add_argument('--keys', required=True)
        v.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    if args.verb in ('pairs', 'tick', 'cancels', 'fuzz', 'resend', 'streams', 'settle', 'place'):
        plan = json.loads(Path(args.plan).read_text())
        keys = json.loads(Path(args.keys).read_text())
        if args.verb == 'settle':
            settle(plan['rows'], plan['targets'], keys, args.out, plan['bound_s'], plan.get('backoff_s', 0.5))
        elif args.verb == 'place':
            place(plan['rows'], plan['target'], keys, args.out)
        elif args.verb == 'resend':
            resend(plan['rows'], plan['targets'], keys, plan['fresh'], args.out)
        elif args.verb == 'streams':
            streams(plan['conns'], keys, args.out, plan['stop_file'], plan['seconds'])
        else:
            {'pairs': pairs, 'tick': tick, 'cancels': cancels, 'fuzz': fuzz}[args.verb](plan, keys, args.out)
        return 0
    if args.verb == 'load':
        keys = json.loads(Path(args.keys).read_text())
        rows = json.loads(Path(args.story).read_text())
        started = time.time_ns()
        Load(rows, args.targets.split(','), keys, args.out, retry_bound_s=args.retry_bound_s, attempt_s=args.attempt_s,
             concurrency=args.concurrency, stop_file=args.stop_file, rate=args.rate).run()
        Path(args.done_file).write_text(json.dumps({'started_ns': started, 'ended_ns': time.time_ns()}) + '\n')
        return 0
    stream(args.target, Path(args.token_file).read_text().strip(), args.channels.split(','), args.out, args.stop_file,
           args.seconds)
    return 0


if __name__ == '__main__':
    sys.exit(main())
