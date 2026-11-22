# SPDX-License-Identifier: Apache-2.0
"""The market-data drills of the core topology: faults of the public market-data service (oe-marketdata in md0) and of what
it reads, each judged against the ME journal, and each ending with the two-sample barrier, both core oracles PASS and
fills > 0 (a market-data fault must not change money or stop matching).

Six scenario ids, dispatched by runner.py on a critical-path kind (md0 on the cut's oe-marketdata) or on a market-data
drill kind (md0 on a test build of the cut's gateway commit, ``core_contracts.GATEWAY_KINDS`` ``marketdata_defines``):

* ``core-md-exactly-once`` (kinds cps-mdtc, cps-mdtc-ext: the commit-pause seam): the story trades; md0 is killed with
  SIGKILL inside a paused commit, after the batch went to a subscribed client and before its COMMIT, twice in one run, and
  started again. After the barrier ``md_trades`` equals the journal's trade set by trade id and ``md_candles`` equals a
  recomputation from it.
* ``core-md-failover``: the ME leader is killed twice while the story trades. md0's journal archives are ordered so that
  the first kill hits the member whose recording it follows. The book goes stale and heals after each change; the
  follower records a stall and fails over; a client connected through both kills sees no tradeId twice; the trade set
  stays exact. Heal times and the book against tape skew are recorded as data.
* ``core-md-history-loss``: the market history database refused and returned twice while the story trades: the book
  stays live and ``/ready/book`` ready, ``/ready`` fails on ``history_writable``, ``/api/candles`` answers 503
  HISTORY_UNAVAILABLE, the pending trades drain after each return (recoveries >= 2) and a connected client sees no
  tradeId twice. Then once more with md0 started while the database is down: a new subscriber gets the book and one
  ERROR HISTORY_UNAVAILABLE naming tape, candles and ticker, no handshake TICKERS and no empty series; when the database
  returns, a fresh initial state with TICKERS.
* ``core-md-epoch``: md0 started against a market history whose ``md_state.me_epoch`` names another genesis: the writer
  parks (EPOCH_MISMATCH, ``market history belongs to another genesis``), writes no row and sends no live trade, the book
  serves and ``/ready`` fails on ``no_halt``; then the reset (md0 stopped, the relations truncated) and a clean start.
* ``core-md-driverkill``: external kind: the staged aeronmd killed; md0 exits 70, is started again, and the book and
  trades recover. Embedded kind: the embedded driver shares md0's process, so unlinking its directory leaves the mappings
  live: md0 must keep serving (no exit past its driver timeout, ME session ready, commits at the tape's head).
* ``core-md-frozen``: md0 stopped with SIGSTOP, its ME session not closed by the client, for longer than the service's
  MD_EGRESS_STALE_MS, twice while the story trades: the forwarders' book frames and dispatches and the bridge's core
  cursor keep moving, the ME egress age the forwarders see stays under the drill bound; after SIGCONT the book heals.
  Whether and when the ME closed the frozen session, the ME's egress offer give-ups and its order latency are recorded.

Controls. A market-data drill kind's ``control_text`` (a test build with one rule off) names the text its drill's line
must fail with; the harness controls are the setting MD_CONTROL (CONTROLS: one fault step skipped or shortened). A
control run passes only when a judged line fails with exactly the control's text and no other judged line fails; an
INCONCLUSIVE control (the fault never happened) ends INCONCLUSIVE with its text. ``<id>`` in a text stands for the trade
id the line names; ``|`` separates the texts of one control.

Every size, bound and wait is a setting (SETTINGS, overridden by an environment variable of the same name), recorded.
"""
from collections import Counter
import json
import os
from pathlib import Path
import re
import time

from contracts import FP, Inconclusive, Violation
import core_contracts
import gateway_probe
from gateway_scenarios import line
import smoke_core
from smoke_core import (CriticalPathDrill, consequence, fills_line, judged, money_call, oracle_lines, order_call,
                        trades_of, MARKET, QUOTE_ASSET, BASE_ASSET, UNIT, LOW_BUY, PAIR_PRICE)
from gateway_shim import units

SCENARIOS = ('core-md-exactly-once', 'core-md-failover', 'core-md-history-loss', 'core-md-epoch', 'core-md-driverkill',
             'core-md-frozen')
SETTINGS = {
    # the story: crossing pairs per round on market 1 at MD_PRICES prices, and the rounds before, inside and after a fault
    'MD_PAIRS': 4, 'MD_PRICES': 2,
    # faults per run (the driver loss once, as its row asks; every other fault twice)
    'MD_CYCLES': 2, 'MD_DRIVER_CYCLES': 1,
    # core-md-exactly-once: the commit pause of the test build and the wait for a paused commit after a round
    'MD_COMMIT_PAUSE_MS': 4000, 'MD_PAUSE_WAIT_S': 30,
    # md0's readiness after a start, and the wait for md_trades to hold every journal trade after the barrier
    'MD_READY_BOUND_S': 90, 'MD_SETTLE_S': 60,
    # core-md-failover: the wait for a new ME leader and for the book to go stale and heal, and the least time between an
    # ME member's kill and its start (a start before its archive mark file times out is refused by the member)
    'MD_LEADER_BOUND_S': 60, 'MD_HEAL_BOUND_S': 60, 'MD_ME_RESTART_AFTER_S': 15,
    # core-md-history-loss: how long the market history stays down, and the drain after each return
    'MD_HISTORY_DOWN_S': 8, 'MD_DRAIN_BOUND_S': 60,
    # core-md-epoch: how long the parked writer is watched
    'MD_PARK_S': 8,
    # core-md-driverkill: the wait for the exit after the external driver's loss (the service's own driver timeout is its
    # default), and how long md0 is watched for an exit after its embedded driver's directory is unlinked (past that timeout)
    'MD_EXIT_BOUND_S': 60, 'MD_EMBEDDED_WATCH_S': 20,
    # core-md-frozen: the freeze, the service's MD_EGRESS_STALE_MS it must exceed (the service runs on its default), the
    # sample period while frozen and the bound on the forwarders' ME egress age (drill bounds, never limits of a binary)
    'MD_FREEZE_S': 20, 'MD_EGRESS_STALE_MS': 10000, 'MD_FREEZE_SAMPLE_MS': 1000, 'MD_EGRESS_AGE_BOUND_MS': 5000,
    'MD_POLL_MS': 500, 'MD_TAP_S': 3600,
}
# MD_CONTROL -> (scenario, the text its line fails with, whether the run then ends INCONCLUSIVE)
CONTROLS = {
    'never-killed': ('core-md-exactly-once', 'writer was never killed', True),
    'no-leader-change': ('core-md-failover', 'ME leader did not change', True),
    'never-down': ('core-md-history-loss', 'market history was never down', True),
    'driver-kept': ('core-md-driverkill', 'driver was never lost', True),
    'never-frozen': ('core-md-frozen', 'market service was never frozen', True),
    'short-freeze': ('core-md-frozen', 'freeze was shorter than the stale time', True),
}
CONTROL_SETTING = 'MD_CONTROL'
USER_BASE = {'core-md-exactly-once': 95001, 'core-md-failover': 95101, 'core-md-history-loss': 95201,
             'core-md-epoch': 95301, 'core-md-driverkill': 95401, 'core-md-frozen': 95501}
# The six candle intervals the service writes (gateway marketdata/Candles.h CANDLE_INTERVALS_S)
CANDLE_INTERVALS_S = (60, 300, 900, 3600, 14400, 86400)
PAUSED = re.compile(r'commit of journalSeq (\d+)\.\.(\d+) paused (\d+) ms before COMMIT')
EXIT_DRIVER = 70
BOOK_TYPES = ('BOOK_SNAPSHOT', 'BOOK_DELTA')
# The embedded leg of the driver loss: driver and client share one process, so unlinking the driver's directory leaves
# its mappings live and the process serving; only the external driver can be lost on its own
EMBEDDED_DRIVER_NOTE = 'embedded driver shares the process: exit 70 applies to the external driver'


def settings(environ=os.environ):
    out = {}
    for name, default in SETTINGS.items():
        value = environ.get(name)
        if value is None or value == '':
            out[name] = default
            continue
        if not value.isdigit() or int(value) < 1:
            raise Violation(f'{name} must be a positive integer, got {value!r}')
        out[name] = int(value)
    return out


def is_scenario(name):
    return name in SCENARIOS


def control_of(manifest, name, environ=os.environ):
    """(control name, text, inconclusive) of this run, or None: the kind's ``control_text`` (a test build, for the drill
    the kind names) or the MD_CONTROL setting (one of CONTROLS, for its own scenario only); both at once are refused."""
    spec = core_contracts.GATEWAY_KINDS.get(manifest.get('manifest_kind')) or {}
    setting = environ.get(CONTROL_SETTING) or None
    if spec.get('control_text') and spec.get('md_drill'):
        if setting:
            raise Inconclusive(f'{CONTROL_SETTING}={setting} on the control kind {manifest.get("manifest_kind")}: one control a run')
        return manifest.get('manifest_kind'), spec['control_text'], False
    if setting is None:
        return None
    if setting not in CONTROLS:
        raise Violation(f'{CONTROL_SETTING} is one of {", ".join(sorted(CONTROLS))}, got {setting!r}')
    scenario, text, inconclusive = CONTROLS[setting]
    if scenario != name:
        raise Inconclusive(f'{CONTROL_SETTING}={setting} is a control of {scenario}, not of {name}')
    return setting, text, inconclusive


def check_scenario(manifest, name, environ=os.environ):
    """Before any container starts: an unknown id is refused; the drills need a critical-path kind with md0 and both
    forwarders; a market-data drill kind runs only the drill it names, and core-md-exactly-once runs only on a kind whose
    md0 carries the commit-pause seam. Returns the run's control or None."""
    if not is_scenario(name):
        raise Inconclusive('unknown market-data scenario: ' + name)
    kind = manifest.get('manifest_kind')
    if kind not in core_contracts.MARKETDATA_KINDS or not core_contracts.marketdata_manifest(manifest):
        raise Inconclusive(f'{name} runs on a market-data kind ({", ".join(sorted(core_contracts.MARKETDATA_KINDS))}); '
                           f'this manifest is {kind}')
    spec = core_contracts.GATEWAY_KINDS[kind]
    slots = manifest.get('slot_artifacts') or {}
    if not slots.get('md0') or not (slots.get('fwd0') and slots.get('fwd1')):
        raise Inconclusive(f'{name} needs md0 and both forwarders; {kind} stages md0={slots.get("md0")}, '
                           f'fwd0={slots.get("fwd0")}, fwd1={slots.get("fwd1")}')
    if spec.get('md_drill') and spec['md_drill'] != name:
        raise Inconclusive(f'kind {kind} runs {spec["md_drill"]} only, not {name}')
    seam = 'MD_TC_COMMIT_PAUSE' in (spec.get('marketdata_defines') or [])
    if name == 'core-md-exactly-once' and not seam:
        raise Inconclusive(f'{name} kills the writer inside a paused commit: it runs on a kind whose md0 carries '
                           f'MD_TC_COMMIT_PAUSE (cps-mdtc, cps-mdtc-ext, cps-mdnc-split); this manifest is {kind}')
    if name == 'core-md-driverkill' and spec.get('driver') not in ('embedded', 'external'):
        raise Inconclusive(f'{name} needs a driver mode on {kind}')
    return control_of(manifest, name, environ)


def scenario(fixture, name, out_dir):
    """runner.py entry for the market-data scenario ids."""
    control = check_scenario(fixture.m, name)
    cls = {'core-md-exactly-once': ExactlyOnce, 'core-md-failover': Failover, 'core-md-history-loss': HistoryLoss,
           'core-md-epoch': Epoch, 'core-md-driverkill': DriverKill, 'core-md-frozen': Frozen}[name]
    result = cls(fixture, name, Path(out_dir) / 'drill', control).run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name} on {fixture.m.get("manifest_kind")} (engines {fixture.engine_driver()})')


# ------------------------------------------------------------------ the verdict (pure)

def text_matches(text, expected):
    """A line's text against a control's: ``expected`` may hold alternatives split by ``|``, and ``<id>`` stands for the
    decimal id the line names."""
    if not text:
        return False
    for option in expected.split('|'):
        pattern = '^' + re.escape(option).replace(re.escape('<id>'), r'\d+') + '$'
        if re.match(pattern, text):
            return True
    return False


def verdict(lines, control=None):
    """As smoke_core.verdict, with this module's text matcher."""
    j = judged(lines)
    failing = {k: v for k, v in j.items() if not v['holds']}
    if control is None:
        if any(v.get('inconclusive') for v in j.values()):
            return 'INCONCLUSIVE', None
        return ('PASS' if not failing else 'FAIL'), None
    name, text, inconclusive = control
    matched = sorted(k for k, v in failing.items() if text_matches(v.get('text'), text))
    others = {k: v.get('text') for k, v in failing.items() if k not in matched}
    held = bool(matched) and not others
    status = ('INCONCLUSIVE' if inconclusive else 'PASS') if held else 'FAIL'
    return status, {'name': name, 'expected_text': text, 'expected_inconclusive': inconclusive, 'held': held,
                    'failed_lines': matched, 'other_failures': others}


def count_line(count, never_text, once_text, inconclusive_when_none=True):
    """A fault that must happen twice: none is ``never_text`` (INCONCLUSIVE), one is ``once_text``."""
    detail = {'count': count}
    if count == 0:
        return line(False, detail, never_text, inconclusive=inconclusive_when_none)
    return line(count >= 2, detail, once_text)


# ------------------------------------------------------------------ the market history against the journal (pure)

def journal_trades(sample, market=MARKET):
    return {t['trade_id']: t for t in trades_of(sample) if t.get('market') == market}


def history_line(trades, rows):
    """``md_trades`` equals the ME journal's trade set by trade id, with equal price, quantity and taker side, each id once.
    Texts: ``missing trade <id>``, ``duplicate trade <id>`` (an id twice, or an id the journal does not hold), else
    ``market history differs from the journal: trade <id>``."""
    seen = Counter(r['trade_id'] for r in rows)
    have = {r['trade_id']: r for r in rows}
    missing = sorted(set(trades) - set(have))
    extra = sorted(set(have) - set(trades))
    twice = sorted(k for k, n in seen.items() if n > 1)
    wrong = []
    for tid, t in sorted(trades.items()):
        r = have.get(tid)
        if r is not None and (r['price'], r['quantity'], r['taker_is_buy']) != (t['price'], t['quantity'], t['taker_is_buy']):
            wrong.append(tid)
    detail = {'journal_trades': len(trades), 'rows': len(rows), 'missing': missing[:10], 'extra': extra[:10],
              'twice': twice[:10], 'differs': wrong[:10]}
    if missing:
        text = f'missing trade {missing[0]}'
    elif twice or extra:
        text = f'duplicate trade {(twice or extra)[0]}'
    elif wrong:
        text = f'market history differs from the journal: trade {wrong[0]}'
    else:
        text = None
    return line(text is None and bool(trades), detail, text, inconclusive=not trades)


def candles_of(rows):
    """The six intervals' candles of a trade set, in journal order: {(market, interval_s, bucket_start_ms): candle} with
    open, high, low, close, volume_base, volume_quote (price x quantity in full precision), trade_count, last_trade_id;
    the bucket of a trade is chosen from its journal timestamp."""
    out = {}
    for r in sorted(rows, key=lambda r: r['journal_seq']):
        for interval in CANDLE_INTERVALS_S:
            width = interval * 1000
            key = (r['market_id'], interval, (r['executed_at_ms'] // width) * width)
            c = out.get(key)
            if c is None:
                out[key] = {'open': r['price'], 'high': r['price'], 'low': r['price'], 'close': r['price'],
                            'volume_base': r['quantity'], 'volume_quote': r['price'] * r['quantity'], 'trade_count': 1,
                            'last_trade_id': r['trade_id']}
            else:
                c.update(high=max(c['high'], r['price']), low=min(c['low'], r['price']), close=r['price'],
                         volume_base=c['volume_base'] + r['quantity'],
                         volume_quote=c['volume_quote'] + r['price'] * r['quantity'], trade_count=c['trade_count'] + 1,
                         last_trade_id=r['trade_id'])
    return out


def candles_line(rows, stored):
    """``md_candles`` equals a recomputation from ``md_trades`` (``stored``: the relation's rows)."""
    want = candles_of(rows)
    have = {(c['market_id'], c['interval_s'], c['bucket_start_ms']): {k: int(c[k]) for k in
            ('open', 'high', 'low', 'close', 'volume_base', 'volume_quote', 'trade_count', 'last_trade_id')} for c in stored}
    differ = sorted(k for k in set(want) | set(have) if want.get(k) != have.get(k))
    detail = {'candles': len(want), 'stored': len(have),
              'differs': [{'key': list(k), 'stored': have.get(k), 'recomputed': want.get(k)} for k in differ[:5]]}
    return line(not differ and bool(want), detail, 'candles differ from the trade set', inconclusive=not want)


# ------------------------------------------------------------------ the public feed (pure)

def connections(frames):
    """The feed's rows split into connections (a ``connect`` row starts one): [[row, ...], ...]."""
    out = []
    for row in frames:
        if 'connect' in row or not out:
            out.append([])
        out[-1].append(row)
    return out


def tape_trades(rows):
    out = []
    for row in rows:
        frame = row.get('frame') or {}
        if frame.get('type') == 'TRADES_BATCH':
            for t in frame.get('trades') or []:
                out.append({'trade_id': int(t['tradeId']), 'journal_seq': t.get('journalSeq'), 'recv_ns': row.get('recv_ns')})
    return out


def twice_line(frames):
    """No connection of the feed saw one tradeId twice. Text ``trade <id> sent twice to one connection``."""
    twice = []
    for n, conn in enumerate(connections(frames)):
        seen = Counter(t['trade_id'] for t in tape_trades(conn))
        twice += [{'connection': n, 'trade': k, 'times': v} for k, v in sorted(seen.items()) if v > 1]
    trades = sum(len(tape_trades(c)) for c in connections(frames))
    detail = {'connections': len(connections(frames)), 'tape_trades': trades, 'twice': twice[:10]}
    return line(not twice and trades > 0, detail, f'trade {twice[0]["trade"]} sent twice to one connection' if twice
                else 'no trade on the public tape', inconclusive=not twice and trades == 0)


def book_heal(frames, after_ns, bound_ns=None):
    """After ``after_ns``: the first book snapshot marked stale and the first fresh snapshot after it (receive times), and
    whether a fresh book frame was served before any stale one (a book served across the change)."""
    stale_at = fresh_at = served_at = None
    for row in frames:
        t = row.get('recv_ns') or 0
        frame = row.get('frame') or {}
        if t < after_ns or frame.get('type') not in BOOK_TYPES or frame.get('marketId') != MARKET:
            continue
        if bound_ns is not None and t > bound_ns:
            break
        if stale_at is None:
            if frame['type'] == 'BOOK_SNAPSHOT' and frame.get('stale'):
                stale_at = t
            elif served_at is None:
                served_at = t
        elif frame['type'] == 'BOOK_SNAPSHOT' and not frame.get('stale'):
            fresh_at = t
            break
    return {'stale_at_ns': stale_at, 'fresh_at_ns': fresh_at, 'served_before_stale_ns': served_at,
            'heal_s': round((fresh_at - after_ns) / 1e9, 3) if fresh_at else None}


def heal_line(changes):
    """After each ME leader change the subscribed client got a stale book snapshot and then a fresh one."""
    bad = [c for c in changes if not (c['heal'].get('stale_at_ns') and c['heal'].get('fresh_at_ns'))]
    text = None
    if bad:
        across = [c for c in bad if not c['heal'].get('stale_at_ns') and c['heal'].get('served_before_stale_ns')]
        text = 'book served across an ME session change' if across else 'book did not go stale and heal after a leader change'
    return line(not bad and bool(changes), {'changes': [{k: c.get(k) for k in ('cycle', 'killed', 'heal')} for c in changes]},
                text, inconclusive=not changes)


def skew(frames, journal):
    """Data only: for each tape trade, its receive time minus the trade's journal timestamp (ms), as percentiles."""
    values = []
    for t in tape_trades(frames):
        j = journal.get(t['trade_id'])
        if j and t.get('recv_ns'):
            values.append(t['recv_ns'] / 1e6 - j['timestamp'])
    values.sort()
    pick = lambda q: round(values[min(len(values) - 1, int(q * len(values)))], 1) if values else None
    return {'n': len(values), 'p50_ms': pick(0.5), 'p99_ms': pick(0.99), 'max_ms': values[-1] if values else None}


def start_state_line(frames, started_ns):
    """The first subscriber of a service started while the market history was down: before the trade path started
    (``started_ns``) it got the confirmation, the book snapshot and one ERROR HISTORY_UNAVAILABLE naming tape, candles and
    ticker, and no TICKERS, TRADES_BATCH, CANDLE_HISTORY or TICKER_STATS; after it, a fresh initial state with TICKERS."""
    before = [(r.get('frame') or {}) for r in frames if (r.get('recv_ns') or 0) < (started_ns or 1 << 62) and r.get('frame')]
    after = [(r.get('frame') or {}) for r in frames if started_ns and (r.get('recv_ns') or 0) >= started_ns and r.get('frame')]
    kinds = [f.get('type') for f in before]
    errors = [f for f in before if f.get('type') == 'ERROR' and f.get('code') == 'HISTORY_UNAVAILABLE']
    series = [k for k in kinds if k in ('TRADES_BATCH', 'CANDLE_HISTORY', 'TICKER_STATS', 'TICKERS')]
    detail = {'before': Counter(kinds), 'errors': errors[:2], 'after': Counter(f.get('type') for f in after),
              'trade_path_started_ns': started_ns}
    if series:
        return line(False, detail, 'empty series sent without the history')
    ok = ('SUBSCRIPTION_CONFIRMED' in kinds and 'BOOK_SNAPSHOT' in kinds and len(errors) == 1
          and sorted(errors[0].get('parts') or []) == ['candles', 'tape', 'ticker'])
    if not ok:
        return line(False, detail, 'history unavailable was not reported at the start')
    fresh = any(f.get('type') == 'TICKERS' for f in after) and any(f.get('type') == 'BOOK_SNAPSHOT' for f in after)
    return line(fresh, detail, 'no fresh initial state when the trade path started', inconclusive=not started_ns)


# ------------------------------------------------------------------ the drills

def metric(values, name):
    """The sum of every series of ``name`` (any labels), or None when the service exports none."""
    found = [v for k, v in (values or {}).items() if k == name or k.startswith(name + '{')]
    return sum(found) if found else None


class MdDrill(CriticalPathDrill):
    """The critical-path drill base (REST client, probe, both oracles) plus md0's own reads, the public feeds and the end
    lines every market-data drill carries."""

    def __init__(self, fixture, name, out_dir, control):
        super().__init__(fixture, name, out_dir, control)
        self.md = settings()
        self.record.update(md_settings=self.md, md_kind_defines=self.spec.get('marketdata_defines'))
        self.feeds = []

    def users(self, n=2):
        base = USER_BASE[self.name]
        return list(range(base, base + n))

    # ---------------------------------------------------------------- boot

    def boot_md(self, archive_order=None, env=None):
        """The critical-path boot with md0 held back, then md0 started on the archive order and test settings the drill
        gives (recorded), the public feed subscribed, both users funded and a resting order on every expected market."""
        f = self.f
        a, b = self.users(2)
        f.marketdata_deferred = True
        self.boot_cps([a, b])
        f.marketdata_archive_order = archive_order(f) if callable(archive_order) else archive_order
        f.marketdata_env_overrides = env
        self.record['md0_start'] = {'archive_order': f.marketdata_archive_order, 'env': env}
        f.marketdata_deferred = False
        f.start_marketdata_slots()
        self.record['slots']['md0'] = f.slots.get('md0')
        self.start_feed('md-feed')
        self.fund(a, b)
        self.seed_books(a)
        return a, b

    def seed_books(self, user):
        """One resting BUY per expected market (a market the ME has no order for has no book snapshot, and book_fresh is
        judged on every expected market); the answers recorded."""
        calls = []
        for market in [int(m) for m in core_contracts.MARKETDATA_EXPECTED_MARKETS.split(',')]:
            calls.append({'user': user, 'method': 'POST', 'path': '/api/v2/orders', 'key': smoke_core.new_key(),
                          'tag': f'seed-{market}', 'retry': True,
                          'body': gateway_probe.order_body(market, 'BUY', 'LIMIT', 'GTC', LOW_BUY, 5 * UNIT)})
        rows = self.calls(calls)
        self.record['seeded_books'] = {r['tag']: r['status'] for r in rows}

    def story(self, a, b, tag, base_qty=3):
        return self.pairs(a, b, self.md['MD_PAIRS'], self.md['MD_PRICES'], tag=tag, base_qty=base_qty)

    # ---------------------------------------------------------------- md0 reads

    def admin(self, path):
        response = self.f.http('md0', self.f.m['ports']['md_admin'], path)
        try:
            body = json.loads(response.get('body') or 'null')
        except ValueError:
            body = response.get('body')
        return response.get('status'), body

    def health(self):
        return self.f.marketdata_health() or {}

    def trades_view(self):
        return (self.health().get('trades') or {})

    def md_metrics(self):
        try:
            return self.f.metrics('md0', self.f.m['ports']['md_admin'])
        except Inconclusive:
            return {}

    def running(self, slot='md0'):
        return self.f.inspect('container', self.f.registry['containers'][slot])['State']['Running']

    def md_log(self):
        cid = self.f.registry['containers']['md0']
        out = self.f.command(['docker', 'logs', cid], check=False)
        return (out.stdout or '') + (out.stderr or '')

    def md_rows_full(self):
        """md_trades with every column the lines read, in journal order; None while the relation does not exist."""
        db = core_contracts.MARKETDATA_DATABASE
        try:
            if self.f.psql(db, "SELECT to_regclass('public.md_trades') IS NOT NULL") != 't':
                return None
            return json.loads(self.f.psql(db, "SELECT COALESCE(json_agg(t ORDER BY t.journal_seq), '[]'::json) FROM "
                                              "(SELECT market_id, trade_id, price, quantity, taker_is_buy, executed_at_ms, "
                                              "journal_seq FROM md_trades) t") or '[]')
        except (Inconclusive, Violation, ValueError):
            return None

    def md_candles(self):
        db = core_contracts.MARKETDATA_DATABASE
        try:
            return json.loads(self.f.psql(db, "SELECT COALESCE(json_agg(c), '[]'::json) FROM (SELECT market_id, interval_s, "
                                              "bucket_start_ms, open, high, low, close, volume_base, volume_quote, "
                                              "trade_count, last_trade_id FROM md_candles) c") or '[]')
        except (Inconclusive, Violation, ValueError):
            return []

    def md_state(self):
        db = core_contracts.MARKETDATA_DATABASE
        try:
            rows = json.loads(self.f.psql(db, "SELECT COALESCE(json_agg(s), '[]'::json) FROM (SELECT me_epoch::text AS "
                                              "me_epoch, last_journal_seq, first_journal_seq FROM md_state) s") or '[]')
        except (Inconclusive, Violation, ValueError):
            return None
        return rows[0] if rows else None

    def wait_condition(self, name, bound_s):
        """Poll md0's /ready until the condition ``name`` is not among its failing ones; the wait in s, or None."""
        started = self.clock()
        while self.clock() - started < bound_s:
            status, body = self.admin('/ready')
            if isinstance(body, dict) and name not in (body.get('failing') or []) and status in (200, 503):
                return round(self.clock() - started, 3)
            self.sleep(self.md['MD_POLL_MS'] / 1000)
        return None

    def wait_ready(self, path='/ready/session', bound_s=None):
        """Poll md0's ``path`` until 200 or the bound; (answered 200, waited s, last body)."""
        started, body = self.clock(), None
        while True:
            status, body = self.admin(path)
            if status == 200:
                return True, round(self.clock() - started, 3), body
            if self.clock() - started >= (bound_s or self.md['MD_READY_BOUND_S']):
                return False, round(self.clock() - started, 3), body
            self.sleep(self.md['MD_POLL_MS'] / 1000)

    # ---------------------------------------------------------------- the public feeds

    def start_feed(self, name):
        plan = {'target': self.md_target(), 'market': MARKET, 'stop_file': f'/data/{name}.stop', 'seconds': self.md['MD_TAP_S']}
        (self.probe_dir / f'{name}-plan.json').write_text(json.dumps(plan))
        self.probe_bg(['python3', '-I', '/data/gateway_probe.py', 'mdfeed', '--plan', f'/data/{name}-plan.json', '--out',
                       f'/data/{name}.jsonl'], name)
        self.feeds.append(name)

    def feed(self, name='md-feed'):
        path = self.probe_dir / f'{name}.jsonl'
        rows = []
        for text in (path.read_text().splitlines() if path.exists() else []):
            try:
                rows.append(json.loads(text))
            except ValueError:
                continue
        return rows

    def stop_feeds(self):
        for name in self.feeds:
            (self.probe_dir / f'{name}.stop').write_text('stop\n')
        self.sleep(1.5)
        out = {}
        for name in self.feeds:
            out[name] = self.feed(name)
            (self.out / f'{name}.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in out[name]))
        return out

    # ---------------------------------------------------------------- the end of every drill

    def end_lines(self, a, b):
        """Input closed, the barrier and both core oracles, fills > 0; then md_trades against the journal (after waiting up
        to MD_SETTLE_S for it to hold every journal trade) and md_candles against a recomputation."""
        self.cancel_all([a, b])
        self.mark('input_closed')
        money, order, sample = self.oracle()
        lines = oracle_lines(money, order)
        lines['fills'] = fills_line(sample)
        trades = journal_trades(sample)
        rows, waited = self.wait_for(lambda: (lambda r: r if r is not None and set(trades) <= {x['trade_id'] for x in r}
                                              else None)(self.md_rows_full()), self.md['MD_SETTLE_S'])
        rows = rows if rows is not None else (self.md_rows_full() or [])
        self.record['md_settle_s'] = waited
        self.record['md_state'] = self.md_state()
        self.record['md_health_end'] = self.health()
        lines['market_history'] = history_line(trades, rows)
        lines['candles'] = consequence(candles_line(rows, self.md_candles()), 'market_history')
        return lines, sample, trades

    vacuous = None              # a control run whose rule was never exercised: INCONCLUSIVE with this text

    def finish(self, lines):
        status, control = verdict(lines, self.cps_control)
        if control and self.vacuous and not control['held']:
            status = 'INCONCLUSIVE'
            control['vacuous'] = self.vacuous
        result = {'status': status, 'lines': lines, 'record': self.record}
        if control:
            result['control'] = control
        failing = [v.get('text') or k for k, v in judged(lines).items() if not v['holds']]
        if status != 'PASS' or control:
            result['error'] = '; '.join(failing) if failing else None
        if control and control.get('vacuous'):
            result['error'] = control['vacuous']
        (self.out / 'drill.json').write_text(json.dumps(result, indent=1, default=str) + '\n')
        (self.out / 'requests.json').write_text(json.dumps(self.log, indent=1, default=str) + '\n')
        return result


class ExactlyOnce(MdDrill):
    """core-md-exactly-once: md0 killed inside a paused commit, after the batch was sent and before its COMMIT, twice."""

    def run(self):
        md = self.md
        # every commit of a process pauses before its COMMIT (none skipped): the window the kill lands in
        a, b = self.boot_md(env={'MDTC_COMMIT_PAUSE_MS': md['MD_COMMIT_PAUSE_MS'], 'MDTC_COMMIT_PAUSE_SKIP': 0})
        self.story(a, b, 'story-before')
        kills = []
        cycles = 0 if self.control_name == 'never-killed' else md['MD_CYCLES']
        for n in range(cycles):
            kills.append(self.kill_in_commit(a, b, n + 1))
        if self.control_name == 'never-killed':
            self.story(a, b, 'story-no-kill', base_qty=4)
        self.story(a, b, 'story-after', base_qty=5)
        self.record['kills'] = kills
        lines, sample, trades = self.end_lines(a, b)
        landed = [k for k in kills if k.get('killed')]
        lines['writer_killed'] = count_line(len(landed), 'writer was never killed', 'writer was killed once')
        inside = [k for k in landed if k.get('sent_before_kill')]
        lines['kill_between_send_and_commit'] = consequence(
            line(len(inside) == len(landed) and bool(landed), {'kills': [{x: k.get(x) for x in
                 ('cycle', 'paused_range', 'sent_before_kill', 'cursor_at_kill', 'restarted')} for k in landed]},
                 'a kill did not land between the send and the commit', inconclusive=len(inside) != len(landed)),
            'writer_killed')
        restarts = sum(1 for k in landed if k.get('restarted'))
        lines['md_restarts'] = consequence(line(restarts >= 2, {'restarts': restarts}, 'market writer restarted once'),
                                           'writer_killed')
        return self.finish(lines)

    def kill_in_commit(self, a, b, cycle):
        """A story round, then the next paused commit of md0: when its range holds a trade the subscribed client already
        received, SIGKILL md0 inside the pause; then start it again (same environment, so its commits pause again)."""
        md, f = self.md, self.f
        before = len(PAUSED.findall(self.md_log()))
        self.story(a, b, f'story-kill{cycle}', base_qty=3 + cycle)
        row = {'cycle': cycle, 'killed': False}
        started = self.clock()
        while self.clock() - started < md['MD_PAUSE_WAIT_S']:
            paused = PAUSED.findall(self.md_log())
            if len(paused) > before:
                lo, hi = int(paused[-1][0]), int(paused[-1][1])
                sent = [t for t in tape_trades(self.feed()) if t.get('journal_seq') is not None and lo <= t['journal_seq'] <= hi]
                if sent:
                    row['kill'] = f.kill('md0')
                    row.update(killed=True, paused_range=[lo, hi], sent_before_kill=[t['trade_id'] for t in sent][:10],
                               cursor_at_kill=(self.md_state() or {}).get('last_journal_seq'))
                    self.mark(f'kill{cycle}')
                    break
                before = len(paused)
            self.sleep(md['MD_POLL_MS'] / 1000)
        if row['killed']:
            restart = f.restart('md0', ready_timeout=md['MD_READY_BOUND_S'])
            row['restarted'] = bool(restart.get('ready'))
            row['restart'] = {k: restart.get(k) for k in ('started_at', 'exit_code', 'readiness')}
        else:
            row['why'] = f'no paused commit whose range the client had received within {md["MD_PAUSE_WAIT_S"]} s'
        return row


class Failover(MdDrill):
    """core-md-failover: the ME leader killed twice; the first kill hits the member md0's follower reads."""

    def run(self):
        md, f = self.md, self.f

        def leader_first(fixture):
            leader = fixture.leader('me')
            first = int(leader[2:]) if leader else 0
            return [first] + [i for i in range(3) if i != first]
        a, b = self.boot_md(archive_order=leader_first)
        self.story(a, b, 'story-before')
        reads_before = (self.trades_view().get('counts') or {}).get('reReads') or 0
        changes = []
        cycles = 0 if self.control_name == 'no-leader-change' else md['MD_CYCLES']
        for n in range(cycles):
            changes.append(self.kill_leader(a, b, n + 1))
        if self.control_name == 'no-leader-change':
            self.story(a, b, 'story-no-kill', base_qty=4)
        self.story(a, b, 'story-after', base_qty=6)
        self.sleep(2)
        frames = self.stop_feeds()['md-feed']
        for c in changes:
            c['heal'] = book_heal(frames, c['killed_ns'])
        self.record['changes'] = changes
        lines, sample, trades = self.end_lines(a, b)
        changed = [c for c in changes if c.get('new_leader') and c['new_leader'] != c['killed']]
        lines['leader_changed'] = count_line(len(changed), 'ME leader did not change', 'ME leader changed once')
        lines['book_heal'] = consequence(heal_line(changed), 'leader_changed')
        followed = [c for c in changed if c.get('followed_member_killed')]
        # the follower judged the stopped recording: a stall counted, journal_fresh false until the failover, the source
        # switched and journal_fresh true again
        stalled = [c for c in followed if c.get('stalls_delta', 0) > 0 and c.get('switched')
                   and c.get('journal_stale_seen_s') is not None and c.get('journal_fresh_again_s') is not None]
        lines['follower_failover'] = consequence(
            line(bool(followed) and len(stalled) == len(followed),
                 {'followed_kills': [{k: c.get(k) for k in ('cycle', 'killed', 'source_before', 'source_after', 'stalls_delta',
                                                           'switches_delta', 'journal_stale_seen_s', 'journal_fresh_again_s',
                                                           'stall_reasons')} for c in followed]},
                 'followed a stopped recording', inconclusive=not followed), 'leader_changed')
        lines['no_trade_twice'] = twice_line(frames)
        re_reads = ((self.trades_view().get('counts') or {}).get('reReads') or 0) - reads_before
        self.record['re_reads'] = re_reads
        if self.cps_control and 'NO_LIVE_EMIT' in ''.join(self.spec.get('marketdata_defines') or []) and not re_reads:
            # the live-emit rule only acts on a record read twice; with none, the control cannot show anything
            self.vacuous = 'control vacuous: no journal record was read twice'
        self.record['skew'] = skew(frames, trades)
        return self.finish(lines)

    def kill_leader(self, a, b, cycle):
        """Kill the ME leader under a story round: the new leader elected, the killed member started again and back; the
        follower's source, stall count and switches before and after, and whether journal_fresh returned."""
        md, f = self.md, self.f
        leader = f.leader('me')
        view = self.trades_view()
        order = f.marketdata_archive_order or [0, 1, 2]
        source = view.get('source')
        row = {'cycle': cycle, 'killed': leader, 'source_before': source,
               'followed_member_killed': leader is not None and source is not None and f'me{order[source]}' == leader,
               'stalls_before': metric(self.md_metrics(), 'md_source_stalls_total'),
               'switches_before': (view.get('counts') or {}).get('switches')}
        if leader is None:
            row['why'] = 'no ME leader'
            return row
        self.calls([order_call(b, 'SELL', PAIR_PRICE, 2 * UNIT, f'pre-kill{cycle}'),
                    order_call(a, 'BUY', PAIR_PRICE, 2 * UNIT, f'pre-kill{cycle}')])
        row['killed_ns'] = time.time_ns()
        row['kill'] = f.kill(leader)
        self.mark(f'kill{cycle}')
        # from the kill on: the new leader, and md0's /ready sampled for journal_fresh (false while the follower reads a
        # stopped recording, true again after the failover)
        started, new, seen_false, fresh_again = self.clock(), None, None, None
        while self.clock() - started < md['MD_LEADER_BOUND_S'] + md['MD_HEAL_BOUND_S']:
            if new is None:
                now = f.leader('me')
                if now and now != leader:
                    new, row['leader_wait_s'] = now, round(self.clock() - started, 3)
            status, body = self.admin('/ready')
            failing = body.get('failing') if isinstance(body, dict) else None
            if failing is not None:
                if 'journal_fresh' in failing and seen_false is None:
                    seen_false = round(self.clock() - started, 3)
                elif 'journal_fresh' not in failing and seen_false is not None and fresh_again is None:
                    fresh_again = round(self.clock() - started, 3)
            if new and (fresh_again is not None or (not row['followed_member_killed']
                                                     and self.clock() - started > md['MD_HISTORY_DOWN_S'])):
                break
            self.sleep(md['MD_POLL_MS'] / 1000)
        row.update(new_leader=new, journal_stale_seen_s=seen_false, journal_fresh_again_s=fresh_again)
        self.story(a, b, f'story-kill{cycle}', base_qty=3 + cycle)
        left = md['MD_ME_RESTART_AFTER_S'] - (time.time_ns() - row['killed_ns']) / 1e9
        if left > 0:
            self.sleep(left)
        restart = f.restart(leader, ready_timeout=md['MD_READY_BOUND_S'])
        row['restart'] = {k: restart.get(k) for k in ('started_at', 'exit_code')}
        view = self.trades_view()
        row.update(source_after=view.get('source'), stalls_after=metric(self.md_metrics(), 'md_source_stalls_total'),
                   switches_after=(view.get('counts') or {}).get('switches'))
        row['stalls_delta'] = (row['stalls_after'] or 0) - (row['stalls_before'] or 0)
        row['switches_delta'] = (row['switches_after'] or 0) - (row['switches_before'] or 0)
        row['switched'] = row['switches_delta'] > 0 or row['source_after'] != row['source_before']
        row['stall_reasons'] = {k: v for k, v in self.md_metrics().items() if k.startswith('md_source_stalls_total{') and v}
        return row


class HistoryLoss(MdDrill):
    """core-md-history-loss: the market history database down and back twice, then once more across an md0 start."""

    def run(self):
        md, f = self.md, self.f
        a, b = self.boot_md()
        self.story(a, b, 'story-before')
        outages = []
        cycles = 0 if self.control_name == 'never-down' else md['MD_CYCLES']
        recoveries_before = metric(self.md_metrics(), 'md_history_recoveries_total') or 0
        for n in range(cycles):
            outages.append(self.outage(a, b, n + 1))
        if self.control_name == 'never-down':
            self.story(a, b, 'story-no-outage', base_qty=4)
        recoveries = (metric(self.md_metrics(), 'md_history_recoveries_total') or 0) - recoveries_before
        start = self.down_at_start(a, b) if cycles else None
        self.story(a, b, 'story-after', base_qty=6)
        self.sleep(2)
        feeds = self.stop_feeds()
        self.record.update(outages=outages, recoveries=recoveries, down_at_start=start)
        lines, sample, trades = self.end_lines(a, b)
        lines['history_down'] = count_line(len(outages), 'market history was never down', 'market history loss ran once')
        o = outages
        lines['book_live_while_down'] = consequence(
            line(bool(o) and all(x['book_frames_delta'] > 0 and x['ready_book'] == 200 for x in o),
                 {'outages': [{k: x.get(k) for k in ('cycle', 'book_frames_delta', 'ready_book')} for x in o]},
                 'book stopped while the market history was down'), 'history_down')
        lines['ready_names_history'] = consequence(
            line(bool(o) and all(x['ready'] == 503 and 'history_writable' in (x['ready_failing'] or []) for x in o),
                 {'outages': [{k: x.get(k) for k in ('cycle', 'ready', 'ready_failing')} for x in o]},
                 'readiness did not name the market history'), 'history_down')
        lines['candles_503'] = consequence(
            line(bool(o) and all(x['candles'] == [503, 'HISTORY_UNAVAILABLE'] for x in o),
                 {'outages': [{k: x.get(k) for k in ('cycle', 'candles')} for x in o]},
                 'REST candles answered without the history'), 'history_down')
        lines['drained_after_return'] = consequence(
            line(bool(o) and all(x['drained'] for x in o) and recoveries >= 2,
                 {'recoveries': recoveries, 'drain_s': [x.get('drain_s') for x in o]},
                 'market history did not recover after its return'), 'history_down')
        lines['no_trade_twice'] = twice_line(feeds['md-feed'])
        if start is not None:
            lines['down_at_start'] = consequence(start_state_line(feeds.get('md-feed-start') or [], start.get('up_ns')),
                                                 'history_down')
        return self.finish(lines)

    def outage(self, a, b, cycle):
        md, f = self.md, self.f
        frames_before = metric(self.md_metrics(), 'md_book_frames_total') or 0
        row = {'cycle': cycle, 'down': f.marketdata_database_down(True)}
        self.mark(f'outage{cycle}_down')
        self.story(a, b, f'story-outage{cycle}', base_qty=3 + cycle)
        self.sleep(md['MD_HISTORY_DOWN_S'])
        row['ready_book'], _ = self.admin('/ready/book')
        row['ready'], body = self.admin('/ready')
        row['ready_failing'] = (body or {}).get('failing') if isinstance(body, dict) else None
        r = f.http('md0', f.m['ports']['md_public'], f'/api/candles?marketId={MARKET}&interval=1m&limit=10')
        try:
            code = (json.loads(r.get('body') or '{}') or {}).get('code')
        except ValueError:
            code = None
        row['candles'] = [r.get('status'), code]
        row['book_frames_delta'] = (metric(self.md_metrics(), 'md_book_frames_total') or 0) - frames_before
        row['up'] = f.marketdata_database_down(False)
        self.mark(f'outage{cycle}_up')
        drained, row['drain_s'] = self.wait_for(lambda: (lambda v: v.get('history', {}).get('writable')
                                                          and v.get('pending') == 0)(self.trades_view()), md['MD_DRAIN_BOUND_S'])
        row['drained'] = bool(drained)
        return row

    def down_at_start(self, a, b):
        """The database down, md0 stopped and started again, a new subscriber; trades while down; the database back, the
        moment the trade path started (health ``trades.started``) recorded for the subscriber's frames."""
        md, f = self.md, self.f
        row = {'down': f.marketdata_database_down(True)}
        row['stop'] = f.stop('md0')
        row['start'] = {k: v for k, v in f.restart('md0', ready_timeout=md['MD_READY_BOUND_S']).items()
                        if k in ('started_at', 'exit_code')}
        self.start_feed('md-feed-start')
        self.story(a, b, 'story-down-at-start', base_qty=5)
        self.sleep(md['MD_HISTORY_DOWN_S'])
        row['trades_started_while_down'] = self.trades_view().get('started')
        # the trade path cannot start before the database returns: the subscriber's frames are split at that moment
        row['up_ns'] = time.time_ns()
        row['up'] = f.marketdata_database_down(False)
        started, row['start_wait_s'] = self.wait_for(lambda: self.trades_view().get('started'), md['MD_DRAIN_BOUND_S'])
        row['trade_path_started'] = bool(started)
        if not started:
            row['up_ns'] = None
        self.sleep(2)
        return row


class Epoch(MdDrill):
    """core-md-epoch: md0 against the market history of another genesis, then the reset, then a clean start."""

    def run(self):
        md, f = self.md, self.f
        a, b = self.boot_md()
        self.story(a, b, 'story-before')
        self.wait_for(lambda: self.trades_view().get('pending') == 0, md['MD_SETTLE_S'])
        park = {'stop': f.stop('md0')}
        state = self.md_state() or {}
        planted = str(int(state.get('me_epoch') or 0) ^ 1)
        f.psql(core_contracts.MARKETDATA_DATABASE, f'UPDATE md_state SET me_epoch = {planted}')
        park['planted'] = {'before': state, 'me_epoch': planted}
        rows_before = len(self.md_rows_full() or [])
        f.restart('md0', ready_timeout=md['MD_READY_BOUND_S'])
        # the parked writer is the thing under test: md0 stays a declared target until the reset brings it back
        f.open_fault('md0', md['MD_PARK_S'] + md['MD_READY_BOUND_S'], reason='writer parked on another genesis')
        frames_before = metric(self.md_metrics(), 'md_book_frames_total') or 0
        self.story(a, b, 'story-parked', base_qty=4)
        self.sleep(md['MD_PARK_S'])
        running = self.running()
        view = self.trades_view() if running else {}
        park.update(running=running, exit=None if running else self.f.inspect('container', f.registry['containers']['md0'])['State']['ExitCode'],
                    halt=view.get('halt'), halt_detail=view.get('haltDetail'), live_emitted=view.get('liveEmitted'),
                    read_seq=view.get('readSeq'), rows_before=rows_before, rows_after=len(self.md_rows_full() or []),
                    state_after=self.md_state(), log_text='market history belongs to another genesis' in self.md_log())
        park['ready'], body = self.admin('/ready') if running else (None, None)
        park['ready_failing'] = body.get('failing') if isinstance(body, dict) else None
        park['ready_book'], _ = self.admin('/ready/book') if running else (None, None)
        park['book_frames_delta'] = ((metric(self.md_metrics(), 'md_book_frames_total') or 0) - frames_before) if running else 0
        self.mark('parked')
        # the reset: md0 stopped (pid gone), the relations truncated, md0 started on an empty history
        reset = {'stop': f.stop('md0') if running else {'already_exited': park['exit']}}
        f.psql(core_contracts.MARKETDATA_DATABASE, 'TRUNCATE md_trades, md_candles, md_state')
        f.restart('md0', ready_timeout=md['MD_READY_BOUND_S'])
        self.mark('reset')
        self.story(a, b, 'story-after-reset', base_qty=5)
        self.wait_for(lambda: self.trades_view().get('pending') == 0 and self.trades_view().get('started'), md['MD_SETTLE_S'])
        reset.update(view={k: self.trades_view().get(k) for k in ('halt', 'halts', 'partial', 'firstSeq', 'epoch')},
                     state=self.md_state())
        self.record.update(park=park, reset=reset)
        lines, sample, trades = self.end_lines(a, b)
        epoch = str((trades_of(sample) or [{}])[0].get('me_epoch'))
        took = (park['rows_after'] > park['rows_before'] or (park.get('live_emitted') or 0) > 0
                or (not running and park.get('exit') == 75))
        if took:
            parked = line(False, {k: park.get(k) for k in ('halt', 'rows_before', 'rows_after', 'live_emitted', 'exit')},
                          'trades of two genesis epochs in one history')
        else:
            parked = line(park.get('halt') == 'EPOCH_MISMATCH' and park.get('log_text'),
                          {k: park.get(k) for k in ('halt', 'halt_detail', 'log_text', 'rows_before', 'rows_after',
                                                    'live_emitted')}, 'writer did not park on another genesis')
        lines['parked'] = parked
        lines['book_serves_parked'] = consequence(line(park.get('ready_book') == 200 and park['book_frames_delta'] > 0,
                                                       {k: park.get(k) for k in ('ready_book', 'book_frames_delta')},
                                                       'book stopped while the writer was parked'), 'parked')
        lines['ready_names_halt'] = consequence(line(park.get('ready') == 503 and 'no_halt' in (park.get('ready_failing') or []),
                                                     {k: park.get(k) for k in ('ready', 'ready_failing')},
                                                     'readiness did not name the halt'), 'parked')
        state = reset.get('state') or {}
        lines['clean_after_reset'] = line(str(state.get('me_epoch')) == epoch and state.get('first_journal_seq') == 1
                                          and not (reset['view'].get('halts')) and reset['view'].get('partial') is False,
                                          {'state': state, 'journal_epoch': epoch, 'view': reset['view']},
                                          'the reset did not give a clean start')
        return self.finish(lines)


class DriverKill(MdDrill):
    """core-md-driverkill: the media driver lost under md0 (external: aeronmd killed; embedded: its directory removed)."""

    def run(self):
        md, f = self.md, self.f
        a, b = self.boot_md()
        self.story(a, b, 'story-before')
        losses = []
        cycles = 0 if self.control_name == 'driver-kept' else md['MD_DRIVER_CYCLES']
        for n in range(cycles):
            losses.append(self.lose_driver(a, b, n + 1))
        if self.control_name == 'driver-kept':
            self.story(a, b, 'story-no-loss', base_qty=4)
        self.story(a, b, 'story-after', base_qty=6)
        self.record['losses'] = losses
        lines, sample, trades = self.end_lines(a, b)
        lost = [x for x in losses if x.get('lost')]
        lines['driver_lost'] = line(bool(lost) and len(lost) == cycles, {'losses': len(lost), 'cycles': cycles},
                                    'driver was never lost', inconclusive=not lost)
        external = [x for x in lost if x['mode'] == 'external']
        embedded = [x for x in lost if x['mode'] != 'external']
        if external or not lost:
            lines['exit_70'] = consequence(line(bool(external) and all(x.get('exit_code') == EXIT_DRIVER for x in external),
                                                {'exits': [x.get('exit_code') for x in external],
                                                 'waits': [x.get('exit_wait_s') for x in external]},
                                                'market service did not exit 70 after the driver loss'), 'driver_lost')
            lines['recovered'] = consequence(line(bool(external) and all(x.get('recovered') for x in external),
                                                  {'losses': [{k: x.get(k) for k in ('cycle', 'ready_after', 'committed_after')}
                                                              for x in external]},
                                                  'market service did not recover after the driver loss'), 'exit_70')
        if embedded:
            # the embedded driver shares the process: unlinking its directory leaves the mappings live, so the service
            # must keep serving, with no exit, its ME session ready and its commits moving
            self.record['embedded_note'] = EMBEDDED_DRIVER_NOTE
            lines['serves_after_unlink'] = consequence(
                line(all(x.get('kept_serving') for x in embedded),
                     {'note': EMBEDDED_DRIVER_NOTE, 'losses': [{k: x.get(k) for k in ('cycle', 'watch_s', 'exit_code',
                                                                                     'still_running')} for x in embedded]},
                     'market service stopped serving after its embedded driver directory was unlinked'), 'driver_lost')
        return self.finish(lines)

    def lose_driver(self, a, b, cycle):
        md, f = self.md, self.f
        mode = (f.m['artifacts'][f.slot_artifact('md0')] or {}).get('driver')
        row = {'cycle': cycle, 'mode': mode}
        if mode == 'external':
            row['loss'] = f.exec_kill('md0', '/data/aeronmd.pid', heal_bound_s=md['MD_EXIT_BOUND_S'] + 60)
        else:
            directory = ((self.health().get('driver') or {}).get('dir'))
            if not directory or not directory.startswith('/dev/shm/'):
                row['why'] = f'no embedded driver directory under /dev/shm in /health: {directory!r}'
                return row
            f.open_fault('md0', 0, md['MD_EXIT_BOUND_S'] + 60, reason='embedded driver directory removed')
            out = f.execute('md0', ['rm', '-rf', directory], timeout=15, check=False)
            row['loss'] = f.record_fault({'kind': 'driver_dir_removed', 'target': 'md0', 'dir': directory,
                                          'exit_code': out.returncode})
        row['lost'] = True
        self.mark(f'driver_lost{cycle}')
        self.story(a, b, f'story-loss{cycle}', base_qty=3 + cycle)
        if mode != 'external':
            return self.watch_embedded(a, b, cycle, row)
        try:
            exited = f.wait_exit('md0', EXIT_DRIVER, md['MD_EXIT_BOUND_S'])
            row.update(exit_code=exited['exit_code'], exit_wait_s=exited['waited_s'])
        except Inconclusive as error:
            state = f.inspect('container', f.registry['containers']['md0'])['State']
            row.update(exit_code=None if state['Running'] else state['ExitCode'], exit_error=str(error))
            if state['Running']:
                f.close_fault('md0')
                return row
        restart = f.restart('md0', ready_timeout=md['MD_READY_BOUND_S'])
        row['restart'] = {k: restart.get(k) for k in ('started_at', 'exit_code', 'driver')}
        self.story(a, b, f'story-recovered{cycle}', base_qty=5)
        ready, _, _ = self.wait_ready('/ready/session')
        head = max((t['journal_seq'] for t in tape_trades(self.feed())), default=0)
        committed, _ = self.wait_for(lambda: (self.trades_view().get('committedSeq') or 0) >= head, md['MD_SETTLE_S'])
        row.update(ready_after=ready, committed_after=bool(committed), recovered=ready and bool(committed))
        return row


    def watch_embedded(self, a, b, cycle, row):
        """The embedded leg: for MD_EMBEDDED_WATCH_S (past the service's driver timeout) md0 must not exit; then a story
        round, and md0's ME session ready and its commits at the tape's head."""
        md, f = self.md, self.f
        started = self.clock()
        exited = None
        while self.clock() - started < md['MD_EMBEDDED_WATCH_S']:
            if not self.running():
                exited = f.inspect('container', f.registry['containers']['md0'])['State']['ExitCode']
                break
            self.sleep(md['MD_POLL_MS'] / 1000)
        row.update(watch_s=round(self.clock() - started, 3), exit_code=exited)
        if exited is not None:
            f.restart('md0', ready_timeout=md['MD_READY_BOUND_S'])
            row['kept_serving'] = False
            return row
        before = self.trades_view().get('committedSeq') or 0
        self.story(a, b, f'story-unlinked{cycle}', base_qty=5)
        ready, _, _ = self.wait_ready('/ready/session')
        head = max((t['journal_seq'] for t in tape_trades(self.feed())), default=0)
        committed, _ = self.wait_for(lambda: (self.trades_view().get('committedSeq') or 0) >= head, md['MD_SETTLE_S'])
        after = self.trades_view().get('committedSeq') or 0
        row['still_running'] = {'ready_session': ready, 'committed_before': before, 'committed_after': after,
                                'tape_head_seq': head, 'driver': self.health().get('driver')}
        row['kept_serving'] = bool(ready and committed and after > before and self.running())
        f.close_fault('md0')
        return row


class Frozen(MdDrill):
    """core-md-frozen: md0 frozen with SIGSTOP past its egress stale time, twice, while the story trades."""

    def run(self):
        md, f = self.md, self.f
        a, b = self.boot_md()
        self.story(a, b, 'story-before')
        freezes = []
        cycles = 0 if self.control_name == 'never-frozen' else md['MD_CYCLES']
        seconds = md['MD_FREEZE_S'] if self.control_name != 'short-freeze' else max(1, md['MD_EGRESS_STALE_MS'] // 2000)
        for n in range(cycles):
            freezes.append(self.freeze(a, b, n + 1, seconds))
        if self.control_name == 'never-frozen':
            self.story(a, b, 'story-no-freeze', base_qty=4)
        self.story(a, b, 'story-after', base_qty=6)
        self.sleep(2)
        frames = self.stop_feeds()['md-feed']
        for x in freezes:
            x['heal'] = book_heal(frames, x['thawed_ns'])
        self.record['freezes'] = freezes
        lines, sample, trades = self.end_lines(a, b)
        traded = {t.get('taker_order') for t in trades_of(sample)} | {t.get('maker_order') for t in trades_of(sample)}
        for x in freezes:
            x['round_filled'] = bool(x['round_orders']) and set(x['round_orders']) <= traded
        long_enough = [x for x in freezes if x['frozen_s'] * 1000 > md['MD_EGRESS_STALE_MS']]
        if freezes and not long_enough:
            lines['frozen'] = line(False, {'freezes': [x['frozen_s'] for x in freezes], 'stale_ms': md['MD_EGRESS_STALE_MS']},
                                   'freeze was shorter than the stale time', inconclusive=True)
        else:
            lines['frozen'] = count_line(len(long_enough), 'market service was never frozen', 'market service frozen once')
        lines['matching_continued'] = consequence(
            line(all(x['book_frames_delta'] > 0 and x['dispatch_delta'] > 0 and x['bridge_cursor_delta'] > 0
                     and x['round_filled'] for x in freezes) and bool(freezes),
                 {'freezes': [{k: x.get(k) for k in ('cycle', 'book_frames_delta', 'dispatch_delta', 'bridge_cursor_delta',
                                                     'round_filled')} for x in freezes]},
                 'matching or settlement stalled while the market service was frozen'), 'frozen')
        lines['egress_age'] = consequence(
            line(bool(freezes) and all((x['egress_age_max_ms'] or 0) < md['MD_EGRESS_AGE_BOUND_MS'] for x in freezes),
                 {'bound_ms': md['MD_EGRESS_AGE_BOUND_MS'], 'max_ms': [x['egress_age_max_ms'] for x in freezes]},
                 'ME egress age above the drill bound while the market service was frozen'), 'frozen')
        lines['book_healed'] = consequence(
            line(bool(freezes) and all(x.get('book_ready_after_thaw') for x in freezes),
                 {'freezes': [{k: x.get(k) for k in ('cycle', 'book_ready_before', 'book_ready_after_thaw', 'book_ready_s',
                                                     'branch', 'heal')} for x in freezes]},
                 'book did not heal after the freeze',
                 inconclusive=not all(x.get('book_ready_before') for x in freezes)), 'frozen')
        return self.finish(lines)

    def counters(self):
        f, ports = self.f, self.f.m['ports']
        out = {'book_frames': 0, 'dispatch': 0, 'egress_age_ms': 0}
        for slot in ('fwd0', 'fwd1'):
            try:
                m = f.metrics(slot, ports['forwarder_http'])
            except Inconclusive:
                continue
            out['book_frames'] += metric(m, 'forwarder_book_frames_total') or 0
            out['dispatch'] += metric(m, 'forwarder_dispatch_sent_total') or 0
            out['egress_age_ms'] = max(out['egress_age_ms'], metric(m, 'forwarder_me_egress_age_ms') or 0)
        try:
            out['bridge_cursor'] = metric(f.metrics('bridge0', ports['bridge_http']), 'bridge_core_cursor') or 0
        except Inconclusive:
            out['bridge_cursor'] = 0
        leader = f.leader('me')
        if leader:
            try:
                m = f.metrics(leader, ports['me_metrics'])
                out['me'] = {'leader': leader, 'egress_offer_giveups': metric(m, 'match_egress_offer_giveups_total'),
                             'order_latency_sum_s': metric(m, 'match_order_latency_seconds_sum'),
                             'order_latency_count': metric(m, 'match_order_latency_seconds_count')}
            except Inconclusive:
                pass
        return out

    def freeze(self, a, b, cycle, seconds):
        md, f = self.md, self.f
        # the precondition: the book is ready before the freeze, so a heal after it means something
        book_ready, _, _ = self.wait_ready('/ready/book', md['MD_HEAL_BOUND_S'])
        before = self.counters()
        session_ends = metric(self.md_metrics(), 'md_me_session_ends_total') or 0
        row = {'cycle': cycle, 'book_ready_before': book_ready, 'freeze': f.freeze_main('md0', duration_s=seconds)}
        frozen_at = self.clock()
        self.mark(f'freeze{cycle}')
        rows = self.story(a, b, f'story-frozen{cycle}', base_qty=3 + cycle)
        ages = []
        while self.clock() - frozen_at < seconds:
            ages.append(self.counters()['egress_age_ms'])
            self.sleep(md['MD_FREEZE_SAMPLE_MS'] / 1000)
        after = self.counters()
        row['thaw'] = f.thaw_main('md0')
        row['frozen_s'] = round(self.clock() - frozen_at, 3)
        row['thawed_ns'] = time.time_ns()
        self.mark(f'thaw{cycle}')
        orders = sorted({smoke_core.order_id_of(r) for r in rows} - {None})
        row.update(book_frames_delta=after['book_frames'] - before['book_frames'], dispatch_delta=after['dispatch'] - before['dispatch'],
                   bridge_cursor_delta=after['bridge_cursor'] - before['bridge_cursor'], egress_age_max_ms=max(ages or [0]),
                   me_before=before.get('me'), me_after=after.get('me'),
                   round_orders=orders if len(orders) == len(rows) else [])
        # a process frozen past its own bounds may exit when it runs again (the product's choice, recorded): restarted as
        # its supervisor would
        self.sleep(2)
        if not self.running():
            state = f.inspect('container', f.registry['containers']['md0'])['State']
            row['branch'] = {'exited': state['ExitCode']}
            f.restart('md0', ready_timeout=md['MD_READY_BOUND_S'])
        else:
            row['branch'] = {'running': True}
        row['session_ready'], row['session_ready_s'], _ = self.wait_ready('/ready/session')
        row['book_ready_after_thaw'], row['book_ready_s'], row['book_ready_body'] = self.wait_ready('/ready/book',
                                                                                                    md['MD_HEAL_BOUND_S'])
        row['me_session_ends_delta'] = (metric(self.md_metrics(), 'md_me_session_ends_total') or 0) - session_ends
        f.close_fault('md0')
        return row
