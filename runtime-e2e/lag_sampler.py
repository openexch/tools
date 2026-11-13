#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Replica lag sampler: ONE long-lived process that polls the leader's and the replica's ``/metrics`` at a fixed rate.

usage: lag_sampler.py --members URL,URL,URL --replica URL --out DIR [--hz 10] [--term-bytes N] [--duration-s S]
                      [--stop-file PATH] [--request-timeout-s 0.5]

One formula for every place the lag is sampled from gauges (the fixture's probe container, a rig):
    lag_bytes(t) = core_log_position(leader, t) - shadow_replica_applied_position(replica, t)
``core_log_position`` is the leader's applied position of the service, at most one duty cycle behind commit; the
replica's ``shadow_replica_internal_lag_bytes`` (recorded - applied) is recorded alongside, so the transport leg
(commit - recorded) is separable. Each tick reads the cached leader (``core_cluster_role`` 2) and the replica; when the
cached member is not the leader any more, the members are scanned again.

Writes ``DIR/lag.tsv`` (one row per tick, flushed) and, on the stop file or the duration, ``DIR/summary.json`` with the
achieved rate (the target rate is a setting; what was achieved is recorded, never assumed). Standard library only, so the
probe image's own python runs it with ``-I``.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

COLUMNS = ['t_ns', 'leader', 'leader_position', 'applied', 'recorded', 'internal_lag', 'time_lag_ms', 'lag_bytes']
POSITION_NOTE = 'leader core_log_position: the applied position of the service, at most one duty cycle behind commit'
LEADER_ROLE = 2.0
LINE = re.compile(r'([a-zA-Z_:][a-zA-Z0-9_:]*(?:\{[^}]*\})?)\s+(\S+)(?:\s+\d+)?')


def parse(text):
    """Prometheus text -> {name: value}; labelled names keep their label block. A malformed line is skipped here (the
    sampler records what it can read; the fixture's own parser is the strict one)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = LINE.fullmatch(line)
        if match:
            try:
                out[match.group(1)] = float(match.group(2))
            except ValueError:
                continue
    return out


def row(t_ns, leader_index, leader, replica):
    """One sample from a leader scrape and a replica scrape; None where a gauge is missing."""
    position, applied = leader.get('core_log_position'), replica.get('shadow_replica_applied_position')
    return {'t_ns': t_ns, 'leader': leader_index, 'leader_position': position, 'applied': applied,
            'recorded': replica.get('shadow_replica_recorded_position'),
            'internal_lag': replica.get('shadow_replica_internal_lag_bytes'),
            'time_lag_ms': replica.get('shadow_replica_time_lag_ms'),
            'lag_bytes': None if position is None or applied is None else position - applied}


def summarize(rows, started_ns, ended_ns, target_hz, term_bytes=None, errors=0):
    """The run's summary: max lag over the whole window, the achieved rate and the log growth (B/s)."""
    lags = [r['lag_bytes'] for r in rows if r['lag_bytes'] is not None]
    internal = [r['internal_lag'] for r in rows if r['internal_lag'] is not None]
    times = [r['time_lag_ms'] for r in rows if r['time_lag_ms'] is not None]
    positions = [(r['t_ns'], r['leader_position']) for r in rows if r['leader_position'] is not None]
    seconds = max((ended_ns - started_ns) / 1e9, 1e-9)
    growth = None
    if len(positions) >= 2 and positions[-1][0] > positions[0][0]:
        growth = (positions[-1][1] - positions[0][1]) / ((positions[-1][0] - positions[0][0]) / 1e9)
    out = {'samples': len(rows), 'samples_with_lag': len(lags), 'duration_s': round(seconds, 3), 'target_hz': target_hz,
           'achieved_hz': round(len(rows) / seconds, 3), 'max_lag_bytes': max(lags) if lags else None,
           'max_internal_lag_bytes': max(internal) if internal else None, 'max_time_lag_ms': max(times) if times else None,
           'log_bytes_per_s': None if growth is None else round(growth, 1), 'errors': errors, 'position': POSITION_NOTE,
           'formula': 'core_log_position(leader) - shadow_replica_applied_position(replica)'}
    if term_bytes is not None:
        out['term_bytes'] = term_bytes
        out['within_term'] = None if not lags else max(lags) <= term_bytes
    return out


def read_tsv(path):
    """The rows of a lag.tsv (numbers parsed, empty cells None): the drills read the file the sampler wrote."""
    rows = []
    lines = Path(path).read_text().splitlines() if Path(path).exists() else []
    for line in lines[1:]:
        cells = line.split('\t')
        if len(cells) != len(COLUMNS):
            continue
        rows.append({k: (None if v == '' else float(v) if k != 't_ns' else int(v)) for k, v in zip(COLUMNS, cells)})
    return rows


class Sampler:
    def __init__(self, members, replica, fetch, clock=time.time_ns):
        self.members, self.replica, self.fetch, self.clock = list(members), replica, fetch, clock
        self.leader = None
        self.errors = 0

    def _leader(self):
        if self.leader is not None:
            try:
                scrape = self.fetch(self.members[self.leader])
                if scrape.get('core_cluster_role') == LEADER_ROLE:
                    return self.leader, scrape
            except Exception:
                self.errors += 1
        for index, url in enumerate(self.members):
            try:
                scrape = self.fetch(url)
            except Exception:
                self.errors += 1
                continue
            if scrape.get('core_cluster_role') == LEADER_ROLE:
                self.leader = index
                return index, scrape
        self.leader = None
        return None, {}

    def tick(self):
        t = self.clock()
        index, leader = self._leader()
        try:
            replica = self.fetch(self.replica)
        except Exception:
            self.errors += 1
            replica = {}
        return row(t, index, leader, replica)


def fetcher(timeout_s):
    def fetch(url):
        with urllib.request.urlopen(url, timeout=timeout_s) as response:
            return parse(response.read().decode())
    return fetch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--members', required=True, help='comma list of the members\' /metrics URLs')
    parser.add_argument('--replica', required=True, help='the replica\'s /metrics URL')
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--hz', type=float, default=10.0)
    parser.add_argument('--term-bytes', type=int)
    parser.add_argument('--duration-s', type=float)
    parser.add_argument('--stop-file', type=Path)
    parser.add_argument('--request-timeout-s', type=float, default=0.5)
    args = parser.parse_args(argv)
    if not 1 <= args.hz <= 100:
        parser.error('--hz must be within 1..100')
    if args.duration_s is None and args.stop_file is None:
        parser.error('a sampler ends on --duration-s or --stop-file')
    args.out.mkdir(parents=True, exist_ok=True)
    sampler = Sampler(args.members.split(','), args.replica, fetcher(args.request_timeout_s))
    period_ns = int(1e9 / args.hz)
    started = time.time_ns()
    rows = []
    with (args.out / 'lag.tsv').open('w') as out:
        out.write('\t'.join(COLUMNS) + '\n'); out.flush()
        tick = 0
        while True:
            if args.stop_file is not None and args.stop_file.exists():
                break
            if args.duration_s is not None and time.time_ns() - started >= args.duration_s * 1e9:
                break
            r = sampler.tick()
            rows.append(r)
            out.write('\t'.join('' if r[c] is None else str(int(r[c]) if c != 't_ns' and float(r[c]).is_integer() else r[c])
                                for c in COLUMNS) + '\n')
            out.flush()
            tick += 1
            delay = started + tick * period_ns - time.time_ns()     # a fixed schedule: a slow tick is never hidden
            if delay > 0:
                time.sleep(delay / 1e9)
    summary = summarize(rows, started, time.time_ns(), args.hz, args.term_bytes, sampler.errors)
    tmp = args.out / '.summary.json'
    tmp.write_text(json.dumps(summary, indent=1) + '\n')
    os.replace(tmp, args.out / 'summary.json')
    return 0


if __name__ == '__main__':
    sys.exit(main())
