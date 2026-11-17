# SPDX-License-Identifier: Apache-2.0
"""Test-only HTTP shim over CoreProbe verbs: the gateway drills' dry run before oe-gateway runs in the fixture.

Never published and never a product: it exists so a gateway drill (client load with keys, the order oracle per key,
key provisioning, kill windows) can be run end to end against a stand-in. Each request runs one ``CoreProbe create``
JVM on the slot's own GATEWAY key; there is no session, no cache and no state, so a SIGKILL loses only the requests in
flight, as it does for the real gateway. Only what the drills use is served:

  POST /api/v2/orders   X-API-Key (users from SHIM_API_KEYS_FILE, ``key:userId``), Idempotency-Key required; body
                        {marketId, side, type, timeInForce, price, quantity, clientOrderId?}; ids and money are decimal strings.
                        201 {orderId, status, duplicate} on OrderAck, 422 {code} on OrderReject, 504 OUTCOME_UNKNOWN when
                        the probe had no answer. The request id is the key itself (a UUID) or the first 16 bytes of its
                        sha256, as oe-gateway derives it.
  GET /ready            200 once listening with its users loaded (no core round trip, see Shim.ready)
  GET /health, /metrics the shim's counters

SHIM_MODE=fresh-key is the control: every attempt gets a fresh random request id, so a retried request makes a second
order (what GW_NC_FRESH_KEY does to oe-gateway). Environment (all set by the fixture): SHIM_HTTP_BIND, SHIM_API_KEYS_FILE,
SHIM_MODE, SHIM_CORE_PROBE (the probe class path), CORE_ADDRESSES, CORE_PORT_BASE, CLUSTER_PORT_STRIDE, CORE_LOCAL_HOST,
CORE_AUTH_CREDENTIAL. Settings with defaults: SHIM_CONCURRENCY (2 probe JVMs at once), SHIM_PROBE_BOUND_MS (60000).
"""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid

FP = 10 ** 8
JAVA = ['java', '--add-opens', 'java.base/jdk.internal.misc=ALL-UNNAMED', '--add-opens', 'java.base/sun.nio.ch=ALL-UNNAMED',
        '--add-opens', 'java.base/java.nio=ALL-UNNAMED', '-Xms64m', '-Xmx256m', '-Duser.home=/tmp']
SIDES, TYPES, TIFS = {'BUY', 'SELL'}, {'LIMIT', 'MARKET'}, {'GTC', 'IOC', 'FOK'}
MONEY = re.compile(r'(0|[1-9][0-9]{0,11})(\.[0-9]{1,8})?')
KEY_CHARS = re.compile(r'[\x21-\x7e]{1,64}')
EXIT_MEANING = {0: 'ANSWERED', 3: 'UNKNOWN', 4: 'REFUSED'}


def setting(name, default):
    value = os.environ.get(name)
    if value is None or value == '':
        return default
    if not value.isdigit() or int(value) < 1:
        raise SystemExit(f'gateway_shim: {name} must be a positive integer, got {value!r}')
    return int(value)


def units(text):
    """A decimal money string as integer units at 10^8, or None."""
    if not isinstance(text, str) or not MONEY.fullmatch(text):
        return None
    whole, _, frac = text.partition('.')
    return int(whole) * FP + int((frac + '0' * 8)[:8])


def signed(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def request_id(key):
    """oe-gateway's derivation (Rest.cpp parseIdempotencyKey): a UUID is the id itself, any other key the first 16 bytes
    of its sha256. (high, low) as signed int64, or None for an invalid or nil key."""
    if not isinstance(key, str) or not KEY_CHARS.fullmatch(key):
        return None
    try:
        value = uuid.UUID(key).int if re.fullmatch(r'[0-9a-fA-F-]{36}', key) else None
    except ValueError:
        value = None
    if value is None:
        value = int.from_bytes(hashlib.sha256(key.encode()).digest()[:16], 'big')
    if value == 0:
        return None
    return signed(value >> 64), signed(value & ((1 << 64) - 1))


def client_order_id(text):
    if text is None:
        return 0, 0
    value = uuid.UUID(text).int
    if value == 0:
        raise ValueError('nil')
    return signed(value >> 64), signed(value & ((1 << 64) - 1))


def parse_order(body):
    """The CoreProbe create arguments of a REST order body, or (None, detail)."""
    try:
        data = json.loads(body or b'{}')
    except ValueError:
        return None, 'body is not JSON'
    if not isinstance(data, dict):
        return None, 'body is not an object'
    allowed = {'marketId', 'side', 'type', 'timeInForce', 'price', 'quantity', 'clientOrderId'}
    if set(data) - allowed:
        return None, 'unknown field ' + sorted(set(data) - allowed)[0]
    market, side, kind, tif = data.get('marketId'), data.get('side'), data.get('type'), data.get('timeInForce')
    price, qty = units(data.get('price')), units(data.get('quantity'))
    # Ids are decimal strings, as oe-gateway reads them (a JSON number is refused)
    market = int(market) if isinstance(market, str) and re.fullmatch(r'[1-9][0-9]{0,9}', market) else None
    if market is None or side not in SIDES or kind not in TYPES or tif not in TIFS or qty is None:
        return None, 'marketId, side, type, timeInForce and quantity are required'
    if kind == 'LIMIT' and price is None:
        return None, 'price is required with LIMIT'
    try:
        ch, cl = client_order_id(data.get('clientOrderId'))
    except ValueError:
        return None, 'clientOrderId must be a UUID other than the nil UUID'
    return {'market': market, 'side': side, 'type': kind, 'tif': tif, 'price': price or 0, 'qty': qty, 'budget': 0,
            'stop': 0, 'delta': 0, 'display': 0, 'expires': 0, 'ch': ch, 'cl': cl}, None


def load_users(path):
    users = {}
    with open(path) as fh:
        text = fh.read()
    for line in text.splitlines():
        if line.strip():
            key, _, user = line.rpartition(':')
            users[key] = int(user)
    return users


class Shim:
    def __init__(self, env=os.environ, runner=subprocess.run):
        self.env, self.runner = env, runner
        self.mode = env.get('SHIM_MODE', 'stored')
        if self.mode not in ('stored', 'fresh-key'):
            raise SystemExit('gateway_shim: SHIM_MODE must be stored or fresh-key')
        self.users = load_users(env['SHIM_API_KEYS_FILE'])
        self.slots = threading.BoundedSemaphore(setting('SHIM_CONCURRENCY', 2))
        self.bound_s = setting('SHIM_PROBE_BOUND_MS', 60000) / 1000
        self.lock = threading.Lock()
        self.counts = {}
        self.probe_s = [0.0, 0]
        self.inflight = 0

    def count(self, code):
        with self.lock:
            self.counts[code] = self.counts.get(code, 0) + 1

    def probe(self, verb, args):
        """One CoreProbe verb; (meaning, reply)."""
        argv = JAVA + ['-cp', self.env['SHIM_CORE_PROBE'], 'CoreProbe', verb] + [f'{k}={v}' for k, v in args.items()]
        env = {k: self.env[k] for k in ('CORE_ADDRESSES', 'CORE_PORT_BASE', 'CLUSTER_PORT_STRIDE', 'CORE_LOCAL_HOST',
                                        'CORE_AUTH_CREDENTIAL', 'PATH') if k in self.env}
        started = time.monotonic()
        with self.slots:
            with self.lock:
                self.inflight += 1
            try:
                r = self.runner(argv, capture_output=True, text=True, env=env, timeout=self.bound_s)
                code, out = r.returncode, r.stdout
                if code != 0:
                    tail = ' | '.join(((r.stdout or '') + (r.stderr or '')).strip().splitlines()[-3:])
                    sys.stderr.write(f'shim: CoreProbe {verb} exited {code}: {tail}\n')
            except subprocess.TimeoutExpired:
                code, out = 3, ''
            finally:
                with self.lock:
                    self.inflight -= 1
                    self.probe_s[0] += time.monotonic() - started
                    self.probe_s[1] += 1
        lines = [line for line in (out or '').splitlines() if line.startswith('{')]
        reply = json.loads(lines[-1]) if lines else None
        return EXIT_MEANING.get(code, 'CRASHED'), reply

    def ready(self):
        """Listening with its users loaded. No core round trip: CoreProbe's query verbs do not register a GATEWAY session
        first, so the core answers them UNREGISTERED_SESSION on the slot's key; a create registers, so the first order
        is the shim's first core round trip."""
        return bool(self.users)

    def create(self, user, key, body):
        order, detail = parse_order(body)
        if order is None:
            return 400, {'error': detail, 'code': 'VALIDATION'}
        rid = request_id(key)
        if rid is None:
            return 400, {'error': 'Idempotency-Key is invalid', 'code': 'VALIDATION'}
        if self.mode == 'fresh-key':
            rid = (signed(secrets.randbits(64)) or 1, signed(secrets.randbits(64)) or 1)
        meaning, reply = self.probe('create', dict(order, user=user, rh=rid[0], rl=rid[1]))
        rows = (reply or {}).get('replies') or []
        ack = next((r for r in rows if r.get('t') == 'OrderAck'), None)
        reject = next((r for r in rows if r.get('t') == 'OrderReject'), None)
        if ack is not None:
            return 201, {'orderId': str(ack['order']), 'status': ack['status'], 'duplicate': ack['duplicate']}
        if reject is not None:
            return 422, {'error': 'rejected', 'code': reject['reason'], 'keyFinal': True,
                         **({'orderId': str(reject['order'])} if reject.get('order') else {})}
        return 504, {'error': 'no answer from the core', 'code': 'OUTCOME_UNKNOWN', 'meaning': meaning}

    def metrics(self):
        with self.lock:
            lines = [f'shim_requests_total{{code="{c}"}} {n}' for c, n in sorted(self.counts.items())]
            lines += [f'shim_probe_seconds_sum {self.probe_s[0]:.3f}', f'shim_probe_seconds_count {self.probe_s[1]}',
                      f'shim_inflight {self.inflight}']
        return '\n'.join(lines) + '\n'


def handler(shim):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt, *args):
            sys.stderr.write('shim ' + (fmt % args) + '\n')

        def send(self, status, body, content='application/json'):
            data = (json.dumps(body) if content == 'application/json' else body).encode()
            self.send_response(status)
            self.send_header('Content-Type', content)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            shim.count(str(status))

        def do_GET(self):
            if self.path == '/ready':
                return self.send(200, {'ready': True}) if shim.ready() else self.send(503, {'failing': ['users_loaded']})
            if self.path == '/health':
                return self.send(200, {'mode': shim.mode, 'users': len(shim.users), 'inflight': shim.inflight})
            if self.path == '/metrics':
                return self.send(200, shim.metrics(), 'text/plain')
            return self.send(404, {'code': 'NOT_FOUND'})

        def do_POST(self):
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else b''
            if self.path != '/api/v2/orders':
                return self.send(404, {'code': 'NOT_FOUND'})
            user = shim.users.get(self.headers.get('X-API-Key') or '')
            if user is None:
                return self.send(401, {'code': 'UNAUTHENTICATED'})
            keys = self.headers.get_all('Idempotency-Key') or []
            if len(keys) != 1:
                return self.send(400, {'error': 'one Idempotency-Key is required', 'code': 'VALIDATION'})
            status, out = shim.create(user, keys[0], body)
            return self.send(status, out)
    return Handler


def main():
    shim = Shim()
    host, _, port = os.environ['SHIM_HTTP_BIND'].rpartition(':')
    server = ThreadingHTTPServer((host, int(port)), handler(shim))
    server.daemon_threads = True
    sys.stderr.write(f'gateway_shim: mode {shim.mode}, {len(shim.users)} users, listening on {host}:{port}\n')
    server.serve_forever()


if __name__ == '__main__':
    main()
