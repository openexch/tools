# SPDX-License-Identifier: Apache-2.0
"""RC2 S17 W3: cross-version (new side), activation and rollback scenarios (contract 5.2, 6, 8.2, 10; 20.1 lines 5-16, 21, 24-29).

Scenarios (runner.py dispatches every ``core-xver-*``, ``core-act-*`` and ``core-rollback-*`` name here):
  core-xver-me-new-on-old-{snaptail,snapquiet,log}   X-1a/b/c, RC2 ME jar on a v0.5.0-beta ME state   (s17-xver | s17-xver-ext)
  core-xver-ae-new-on-old-{snaptail,log}             X-3a/b,   RC2 core jar on a v0.5.0-beta AE state (s17-xver | s17-xver-ext)
  core-xver-bridge-on-old-archive                    X-7, the C++ bridge on a v0.5.0-beta ME journal archive (s17-xver[-ext])
  core-act-{leaderkill,toolkill,toolkill-2,nobridge,latemember,fwdfirst}   X-A1..X-A5 (toolkill = after CoreConfig 1,
                                                     toolkill-2 = after CoreConfig 1 and 2: the two runs of X-A2)     (s17-act)
  core-rollback-old-line                             X-R                                                              (s17-rollback)
  controls (8.2): core-xver-ctl-{me-same,me-old-same,ae-same,ae-old-same,x7-wiped}, core-rollback-ctl-omit-{journal,pgdump}

No scenario puts a tag jar under test (0.1): the tag jars run only to validate a seed (the old-same controls) and in X-R, through
the legacy tag profile (legacy_tag.py). Every verdict is judged on observed exits, /ready answers, the active probe's answers and
log lines (4), never on a timer expiring without an observation. Pass lines: 6.7 (X-7), 6.8 (X-A), 6.9 (X-R), 6.10 (X-1, X-3).
"""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time

from contracts import Inconclusive, Violation

B0 = Path('/home/emre/Apps/openexchange/.runtime-handoff/20260927-r00')
PREFIXES = ('core-xver-', 'core-act-', 'core-rollback-')
DEFAULTS = {'XVER_BOUND_S': 150, 'XVER_STAGGER_S': 5, 'XVER_TAIL_MIN': 8, 'ENGINE_QUORUM_WAIT_MS': 120000,
            'XVER_SAMPLE_S': 60, 'XVER_LATE_JOIN_S': 30, 'XVER_FWD_WAIT_S': 30, 'XVER_PROBE_INFLIGHT': 2,
            'XVER_PROBE_INTERVAL_S': 1,
            'XVER_FATAL_GRACE_S': 5, 'XVER_LEGACY_OCTET': 187}
SEEDS = Path(os.environ.get('XVER_SEEDS', str(B0 / 'local-runs/s17/seeds-w1')))
CUT = Path(os.environ.get('XVER_CUT', str(B0 / 'workspace/notebook/reports/runtime-handoff-execution/R10/rc2-cut-manifest.json')))
XVER_KINDS = ('s17-xver', 's17-xver-ext')
MODE = {'s17-xver': 'emb', 's17-xver-ext': 'ext'}


def settings(env=None):
    """The X settings (4, PO-14): every value a setting with its default; XVER_BOUND_S must hold the quorum wait plus the fatal
    grace plus the stagger, else a log-only case could never classify its late member."""
    env = os.environ if env is None else env
    out = {}
    for key, default in DEFAULTS.items():
        raw = env.get(key)
        if raw is None:
            out[key] = default
            continue
        try:
            value = float(raw)
        except ValueError:
            value = -1
        if value <= 0:
            raise Violation(f'{key} must be a positive number, got {raw!r}')
        out[key] = int(value) if value == int(value) else value
    need = out['ENGINE_QUORUM_WAIT_MS'] / 1000 + out['XVER_FATAL_GRACE_S'] + 2 * out['XVER_STAGGER_S']
    if out['XVER_BOUND_S'] < need:
        raise Violation(f'XVER_BOUND_S {out["XVER_BOUND_S"]} s cannot hold ENGINE_QUORUM_WAIT_MS + fatal grace + stagger ({need} s)')
    return out


def check_engine_env(env):
    """PO-14: the production quorum wait is used unchanged; the harness never shortens it."""
    if 'ENGINE_QUORUM_WAIT_MS' in env:
        raise Violation('the X runs use the engine default; the harness never sets ENGINE_QUORUM_WAIT_MS')


# ------------------------------------------------------------------ cases (6, 6.10: 17 cases, 51 runs)

def _state_case(row, engine, seed, variant, scenario, classes, sites):
    return {'row': row, 'engine': engine, 'seed': seed, 'variant': variant, 'scenario': scenario, 'classes': classes,
            'sites': set(sites), 'binary': 'rc2', 'kinds': XVER_KINDS}


SNAP3 = {'replay-halted': 3, 'quorum-exited': 0, 'other': 0}
LOG21 = {'replay-halted': 2, 'quorum-exited': 1, 'other': 0}
CASES = {}
for _mode in ('emb', 'ext'):
    CASES[f'X-1a-{_mode}'] = _state_case('01', 'me', 'A', 'snapshot-tail', 'core-xver-me-new-on-old-snaptail', SNAP3,
                                         ['me-r0-restored'])
    CASES[f'X-1b-{_mode}'] = _state_case('01', 'me', 'B', 'snapshot-quiet', 'core-xver-me-new-on-old-snapquiet', SNAP3,
                                         ['me-envelope'])
    CASES[f'X-1c-{_mode}'] = _state_case('01', 'me', 'C', 'log', 'core-xver-me-new-on-old-log', LOG21,
                                         ['me-r0-session-open', 'me-r0-ingress'])
    CASES[f'X-3a-{_mode}'] = _state_case('10', 'ae', 'A', 'snapshot-tail', 'core-xver-ae-new-on-old-snaptail', SNAP3,
                                         ['ae-envelope'])
    CASES[f'X-3b-{_mode}'] = _state_case('10', 'ae', 'C', 'log', 'core-xver-ae-new-on-old-log', LOG21,
                                         ['ae-r0-session-open', 'ae-r0-ingress'])
CASES['X-7'] = {'row': '20', 'scenario': 'core-xver-bridge-on-old-archive', 'seed': 'C', 'binary': 'rc2', 'kinds': XVER_KINDS}
for _case, _row, _names in (('X-A1', '33', ('core-act-leaderkill',)), ('X-A2', '34, 35', ('core-act-toolkill', 'core-act-toolkill-2')),
                            ('X-A3', '36', ('core-act-nobridge',)), ('X-A4', '37', ('core-act-latemember',)),
                            ('X-A5', '39', ('core-act-fwdfirst',))):
    CASES[_case] = {'row': _row, 'scenario': _names[0], 'scenarios': _names, 'binary': 'rc2', 'kinds': ('s17-act',)}
CASES['X-R'] = {'row': '49', 'scenario': 'core-rollback-old-line', 'seed': 'R', 'binary': 'rc2', 'kinds': ('s17-rollback',)}
CONTROLS = {
    'core-xver-ctl-me-same': {'engine': 'me', 'under_test': 'rc2', 'kinds': XVER_KINDS, 'of': 'X-1'},
    'core-xver-ctl-ae-same': {'engine': 'ae', 'under_test': 'rc2', 'kinds': XVER_KINDS, 'of': 'X-3'},
    'core-xver-ctl-me-old-same': {'engine': 'me', 'under_test': 'tag-seed-validity', 'kinds': XVER_KINDS, 'of': 'X-1', 'seed': 'A'},
    'core-xver-ctl-ae-old-same': {'engine': 'ae', 'under_test': 'tag-seed-validity', 'kinds': XVER_KINDS, 'of': 'X-3', 'seed': 'A'},
    'core-xver-ctl-x7-wiped': {'under_test': 'rc2', 'kinds': XVER_KINDS, 'of': 'X-7'},
    'core-rollback-ctl-omit-journal': {'under_test': 'rollback-restore', 'kinds': ('s17-rollback',), 'of': 'X-R',
                                       'omit': 'ae-money-journal'},
    'core-rollback-ctl-omit-pgdump': {'under_test': 'rollback-restore', 'kinds': ('s17-rollback',), 'of': 'X-R', 'omit': 'pg-dump'},
}
SCENARIO_NAMES = sorted({n for c in CASES.values() for n in c.get('scenarios', (c['scenario'],))} | set(CONTROLS))


def case_for(scenario, kind):
    """The case id of a scenario on a manifest kind (X-1/X-3 carry the driver mode of the kind)."""
    for case, spec in CASES.items():
        if scenario in spec.get('scenarios', (spec['scenario'],)):
            if kind not in spec['kinds']:
                raise Inconclusive(f'{scenario} runs on the {" or ".join(spec["kinds"])} kind{"s" if len(spec["kinds"]) > 1 else ""}'
                                   f', not {kind}')
            if case[-4:] in ('-emb', '-ext'):
                return case[:-3] + MODE[kind]
            return case
    if scenario in CONTROLS:
        if kind not in CONTROLS[scenario]['kinds']:
            raise Inconclusive(f'{scenario} runs on the {" or ".join(CONTROLS[scenario]["kinds"])} kinds, not {kind}')
        return 'control:' + scenario
    raise Inconclusive('unknown cross-version scenario: ' + scenario)


# ------------------------------------------------------------------ the refusal-site table (5.2, 6.10; W12 at the cut commits)

COMMITS = {'match': 'c35689577e8cd524d91692bce6d964c02b45daef', 'assets': 'eb559a7f9070296bae9c73a3087e49a01efb5852',
           'cluster-kit': '947fe50aa2161ae9f302a90c6e1a6bad7eb0eb32', 'cluster-tools': 'e56a4ce5b1118e9c57b975725be6c6010bfdb52d'}
_R0 = (r'CRITICAL: principal-less session in log: pre-S6 history, clean genesis required \(({}), clusterSessionId=(-?[0-9]+), '
       r'logPosition=(-?[0-9]+)\)')
ACS_ME = 'match-cluster/src/main/java/com/match/infrastructure/persistence/AppClusteredService.java'
ACS_AE = 'assets-cluster/src/main/java/com/openexchange/assets/infrastructure/persistence/AssetsClusteredService.java'
KIT_GATE = 'cluster-kit src/main/java/com/openexchange/cluster/auth/PrincipalGate.java:15,40-42'
SITES = {
    'me-r0-restored': {'engine': 'me', 're': _R0.format('restored session'), 'layer': 'application (kit PrincipalGate)',
                       'reads': f'match {ACS_ME}:1452 (the restored session principal, onStart)', 'prints': f'{ACS_ME}:231-237',
                       'rule': KIT_GATE, 'commit': COMMITS['match']},
    'me-r0-session-open': {'engine': 'me', 're': _R0.format('session open'), 'layer': 'application (kit PrincipalGate)',
                           'reads': f'match {ACS_ME}:1635 (onSessionOpen replayed from the log)', 'prints': f'{ACS_ME}:231-237',
                           'rule': KIT_GATE, 'commit': COMMITS['match']},
    'me-r0-ingress': {'engine': 'me', 're': _R0.format('ingress frame'), 'layer': 'application (kit PrincipalGate)',
                      'reads': f'match {ACS_ME}:1737 (an ingress frame of a principal-less session)', 'prints': f'{ACS_ME}:231-237',
                      'rule': KIT_GATE, 'commit': COMMITS['match']},
    'me-envelope': {'engine': 'me', 're': r'CRITICAL: snapshot refused: snapshot envelope magic missing \(length=-?[0-9]+\)',
                    'layer': 'application (R-ME-1)',
                    'reads': 'match match-cluster/src/main/java/com/match/infrastructure/persistence/SnapshotCodec.java:334-337',
                    'prints': f'{ACS_ME}:1510', 'commit': COMMITS['match']},
    'me-lossy-restore': {'engine': 'me', 're': r'order\(s\) dropped during restore', 'layer': 'application (R-ME-2)',
                         'reads': f'match {ACS_ME}:1598', 'prints': f'{ACS_ME}:1510', 'commit': COMMITS['match']},
    'ae-r0-restored': {'engine': 'ae', 're': _R0.format('restored session'), 'layer': 'application (kit PrincipalGate)',
                       'reads': f'assets {ACS_AE}:293 and SessionRegistry.java:158 (section-9 rows print logPosition -1)',
                       'prints': f'{ACS_AE}:280-285', 'rule': KIT_GATE, 'commit': COMMITS['assets']},
    'ae-r0-session-open': {'engine': 'ae', 're': _R0.format('session open'), 'layer': 'application (kit PrincipalGate)',
                           'reads': 'assets assets-cluster/src/main/java/com/openexchange/assets/infrastructure/persistence/'
                                    'AssetsLogApplier.java:170 (the applier, a replayed SessionOpen)',
                           'prints': f'{ACS_AE}:280-285', 'rule': KIT_GATE, 'commit': COMMITS['assets']},
    'ae-r0-ingress': {'engine': 'ae', 're': _R0.format('ingress frame'), 'layer': 'application (kit PrincipalGate)',
                      'reads': f'assets {ACS_AE}:722-729 (a container session with no registry row)',
                      'prints': f'{ACS_AE}:280-285', 'rule': KIT_GATE, 'commit': COMMITS['assets']},
    'ae-envelope': {'engine': 'ae', 're': r'FATAL snapshot refused: snapshot envelope magic missing \(length=-?[0-9]+\)',
                    'layer': 'application (kit SnapshotEnvelope)',
                    'reads': 'cluster-kit src/main/java/com/openexchange/cluster/SnapshotEnvelope.java:72-73',
                    'prints': f'{ACS_AE}:1102', 'commit': COMMITS['cluster-kit']},
    'quorum': {'engine': '*', 're': r'no cluster quorum observed within ([0-9]+) ms since the consensus module launched',
               'layer': 'kit QuorumWatchdog', 'reads': 'cluster-kit src/main/java/com/openexchange/cluster/QuorumWatchdog.java:174',
               'prints': 'cluster-kit EngineLifecycle.java:251-253', 'commit': COMMITS['cluster-kit']},
    'bridge-foreign-head': {'engine': 'bridge', 're': r'foreign journal at the chain head', 'layer': 'bridge B1',
                            'reads': 'cluster-tools domain/bridge/src/BridgeDomain.cpp:1484 (foreignHeadEverywhere)',
                            'prints': 'cluster-tools app/bridge/BridgeAgent.h:1403', 'commit': COMMITS['cluster-tools']},
    'admin-ack-40': {'engine': 'driver', 're': r'ADMIN OPEN GLOBAL never accepted: last reason 40 FEED_HALTED', 'code': 40,
                     'name': 'FEED_HALTED', 'layer': 'core admission',
                     'reads': 'assets assets-cluster/src/main/java/com/openexchange/assets/application/engine/AssetsEngine.java:1824',
                     'prints': 'cluster-tools app/forwarder/it/T1CoreDriver.java:248', 'commit': COMMITS['assets']},
    'admin-ack-41': {'engine': 'driver', 're': r'ADMIN OPEN GLOBAL never accepted: last reason 41 ME_LANE_INACTIVE', 'code': 41,
                     'name': 'ME_LANE_INACTIVE', 'layer': 'core admission',
                     'reads': 'assets assets-cluster/src/main/java/com/openexchange/assets/application/engine/AssetsEngine.java:1828',
                     'prints': 'cluster-tools app/forwarder/it/T1CoreDriver.java:248', 'commit': COMMITS['assets']},
    'admin-ack-45': {'engine': 'driver', 're': r'ADMIN OPEN GLOBAL never accepted: last reason 45 HALT_HOLDER_PENDING', 'code': 45,
                     'name': 'HALT_HOLDER_PENDING', 'layer': 'core admission (G1)',
                     'reads': 'assets assets-cluster/src/main/java/com/openexchange/assets/application/engine/AssetsEngine.java:1836, '
                              'CoreRejectReason.java:66', 'prints': 'cluster-tools app/forwarder/it/T1CoreDriver.java:248',
                     'commit': COMMITS['assets']},
}
SUBSTRATE = [r'(?i)active mark file', r'(?i)archive\.catalog|archive catalog', r'(?i)mark file', r'(?i)cnc\.dat|CnC file',
             r'(?i)recording\.log|RecordingLog', r'(?i)aeron.*version']


def match_site(text, engine):
    """The first refusal-site of ``engine`` (me | ae | bridge | driver) in ``text``, or None."""
    best = None
    for key, site in SITES.items():
        if site['engine'] not in (engine, '*') or (site['engine'] == '*' and engine not in ('me', 'ae')):
            continue
        hit = re.search(site['re'], text)
        if hit and (best is None or hit.start() < best[0]):
            best = (hit.start(), key, hit)
    if best is None:
        return None
    _, key, hit = best
    out = {'key': key, 'line': text[text.rfind('\n', 0, hit.start()) + 1: (text.find('\n', hit.end()) + 1 or len(text) + 1) - 1],
           **{k: v for k, v in SITES[key].items() if k != 're'}}
    if key.endswith(('-restored', '-session-open', '-ingress')):
        out['clusterSessionId'], out['logPosition'] = int(hit.group(2)), int(hit.group(3))
    if key == 'quorum':
        out['wait_ms'] = int(hit.group(1))
    return out


def classify_member(m, allowed):
    """6.10: replay-halted (exit 1, a refusal text that maps to a site of this case), quorum-exited (exit 1, the kit watchdog
    text) or other (with the reason and, for an Aeron-level refusal, the layer: never written down as an application text)."""
    out = {'role': m['role'], 'exit_code': m.get('exit_code')}
    if m.get('running'):
        return dict(out, **{'class': 'other', 'reason': 'still Running'})
    text = m.get('log') or ''
    engine = m['role'][:2]
    refusal = None
    for line in text.splitlines():
        site = match_site(line, engine)
        if site and site['key'] != 'quorum':
            refusal = site
            break
    quorum = None if refusal else match_site(text, engine)
    if m.get('exit_code') != 1:
        reason = f'exit {m.get("exit_code")}, not 1' + (' (78 is a configuration exit, never the refusing layer)'
                                                       if m.get('exit_code') == 78 else '')
        return dict(out, **{'class': 'other', 'reason': reason, 'site': refusal})
    if refusal:
        if refusal['key'] in allowed:
            return dict(out, **{'class': 'replay-halted', 'site': refusal})
        return dict(out, **{'class': 'other', 'reason': f'refusal at {refusal["key"]}, not a site of this case', 'site': refusal})
    if quorum:
        return dict(out, **{'class': 'quorum-exited', 'site': quorum})
    for pattern in SUBSTRATE:
        if re.search(pattern, text):
            return dict(out, **{'class': 'other', 'layer': 'aeron substrate',
                                'reason': 'an Aeron-level refusal (' + re.search(pattern, text).group(0) + ')'})
    return dict(out, **{'class': 'other', 'reason': 'exit 1 with no refusal text'})


def capture_witness(m):
    """X-3(b): the member's log from its start banner to its CRITICAL line in one file, and no INGRESS DROP (schema) between."""
    lines = (m.get('log') or '').splitlines()
    idx = next((i for i, l in enumerate(lines) if 'CRITICAL: principal-less session' in l), None)
    if idx is None:
        return {'role': m['role'], 'critical': None}
    return {'role': m['role'], 'banner': lines[0][:200] if lines else None, 'critical': lines[idx][:300], 'lines_between': idx,
            'ingress_drops': sum(1 for l in lines[:idx] if 'INGRESS DROP (schema)' in l)}


VERDICT_STATUS = {'REFUSED': 'PASS', 'GUARDED-silent': 'FAIL', 'FAIL': 'FAIL', 'INCONCLUSIVE': 'INCONCLUSIVE', 'PASS': 'PASS',
                  'OPENED': 'PASS', 'NOT-OPENED': 'INCONCLUSIVE'}


def verdict_status(verdict):
    return VERDICT_STATUS[verdict]


def judge_state(case, members, probes, bound_s, quorum_wait_ms):
    """The REFUSED (state kind) pass line of 6.10 for X-1 and X-3; GUARDED-silent when anything served."""
    spec = CASES[case]
    reasons = []
    last_start = max(m['started_ns'] for m in members)
    served = [m['role'] for m in members if m.get('ready_200')]
    answered = [p for p in probes if p.get('answered')]
    classes = [classify_member(m, spec['sites']) for m in members]
    counts = {c: sum(1 for x in classes if x['class'] == c) for c in ('replay-halted', 'quorum-exited', 'other')}
    out = {'case': case, 'classes': counts, 'members': classes}
    if served or answered:
        reasons.append(f'served on the foreign state: /ready 200 from {served}, {len(answered)} probe attempt(s) answered')
        return dict(out, verdict='GUARDED-silent', reasons=reasons)
    for c in classes:
        if c['class'] == 'other':
            reasons.append(f'{c["role"]} other: {c["reason"]}')
    if counts != spec['classes']:
        reasons.append(f'class counts {counts} != the stagger\'s prediction {spec["classes"]}')
    for m, c in zip(members, classes):
        if m.get('finished_ns') is not None:
            after = round((m['finished_ns'] - last_start) / 1e9, 1)
            if after > bound_s:
                reasons.append(f'{m["role"]} exited {after} s after the last member start, beyond XVER_BOUND_S {bound_s}')
        if c['class'] == 'quorum-exited' and c['site'].get('wait_ms') != quorum_wait_ms:
            reasons.append(f'{m["role"]} quorum wait {c["site"].get("wait_ms")} ms != ENGINE_QUORUM_WAIT_MS {quorum_wait_ms}')
    verdict = 'INCONCLUSIVE' if reasons else 'REFUSED'
    if spec['variant'] == 'log' and spec['engine'] == 'ae':
        halted = [m for m, c in zip(members, classes) if c['class'] == 'replay-halted']
        caps = [capture_witness(m) for m in halted]
        positions = sorted({c['site']['logPosition'] for c in classes if c['class'] == 'replay-halted'})
        out['capture'] = {'members': caps, 'logPositions': positions}
        for cap in caps:
            if cap['critical'] is None:
                reasons.append(f'{cap["role"]} log has no CRITICAL line from its start banner (capture witness)')
            elif cap['ingress_drops']:
                reasons.append(f'{cap["role"]} dropped {cap["ingress_drops"]} frame(s) (INGRESS DROP (schema)) before its '
                               'CRITICAL line')
                verdict = 'FAIL'
        if len(positions) > 1:
            reasons.append(f'the two replaying members name different logPositions {positions}')
        if reasons and verdict != 'FAIL':
            verdict = 'INCONCLUSIVE'
    return dict(out, verdict=verdict, reasons=reasons)


# ------------------------------------------------------------------ seeds (5.2 seed_state witnesses)

def seed_witness(shape, root, role, tail_min):
    """The non-vacuity witness of one seeded member: snapshot recordings measured from its recording.log, the tail counts and the
    recorded tree hash from the seed's witness.json (W1). A seed that contradicts its variant is refused."""
    import r10_cut
    root = Path(root)
    witness_path = root / 'witness.json'
    if not witness_path.is_file():
        raise Inconclusive(f'seed {shape}: no witness.json in {root}')
    w = json.loads(witness_path.read_text())
    tree = (w.get('trees') or {}).get(role)
    if not tree:
        raise Inconclusive(f'seed {shape} {role}: no recorded tree hash')
    log = root / role / 'state' / 'cluster' / 'recording.log'
    snaps = r10_cut.snapshot_count(log) if log.is_file() else 0
    tail, opens = int(w.get('tail_requests_after_snapshot') or 0), int(w.get('tail_session_opens') or 0)
    out = {'shape': shape, 'role': role, 'recorded_sha256': tree['sha256'], 'snapshot_recordings': snaps,
           'tail_requests_after_snapshot': tail, 'tail_session_opens': opens, 'witness_file': str(witness_path)}
    if shape in ('A', 'B') and snaps < 1:
        raise Inconclusive(f'seed {shape} {role}: a snapshot variant needs a snapshot recording (recording.log lists none)')
    if shape == 'A' and (tail < tail_min or opens < 1):
        raise Inconclusive(f'seed A {role}: a tail of {tail} request(s) and {opens} session open(s), the snapshot+tail variant '
                           f'needs >= {tail_min} + 1')
    if shape == 'B' and (tail or opens):
        raise Inconclusive(f'seed B {role}: the empty-tail variant has {tail} request(s) after the snapshot')
    if shape in ('C', 'R') and snaps:
        raise Inconclusive(f'seed {shape} {role}: a log-only variant forbids a snapshot ({snaps} in recording.log)')
    return out


# ------------------------------------------------------------------ the X-7 pass line (6.7, 20.1 line 28)

def _dedupe(rows):
    out = []
    for r in rows:
        if not out or out[-1] != list(r[:2]):
            out.append(list(r[:2]))
    return out


def judge_x7(obs):
    reasons, fail = [], False
    down = sorted({m for s in obs['samples'] for m, up in s['me_running'].items() if not up})
    if down:
        return {'verdict': 'INCONCLUSIVE', 'reasons': [f'an ME journal archive was unreachable during the sampling '
                                                       f'({", ".join(down)})']}
    for b in ('bridge0', 'bridge1'):
        details = {s['bridges'][b]['health'].get('haltDetail') for s in obs['samples']}
        warns = obs['bridge_logs'].get(b, '').count('foreign journal at the chain head')
        if details == {'NONE'} and not warns:
            return {'verdict': 'INCONCLUSIVE', 'reasons': [f'{b} haltDetail NONE and no WARN: a source was UNREACHABLE (C8)']}
    if obs.get('sample_s', 0) < 60:
        reasons.append(f'sampling {obs.get("sample_s")} s < 60 s')
    for b in ('bridge0', 'bridge1'):
        for s in obs['samples']:
            row = s['bridges'][b]
            h = row.get('health') or {}
            if row.get('status') != 503 or h.get('haltReason') != 'SOURCE_SCHEMA' or h.get('haltDetail') != 'FOREIGN_JOURNAL_HEAD' \
                    or h.get('halted') is not True:
                reasons.append(f'{b} not HALTED SOURCE_SCHEMA FOREIGN_JOURNAL_HEAD with /health 503 in a sample: '
                               f'{row.get("status")} {h.get("haltReason")} {h.get("haltDetail")}')
                break
        for s in obs['samples']:
            n = (s['bridges'][b].get('health') or {}).get('relistsSinceHalt')
            if n:
                reasons.append(f'{b} relistsSinceHalt {n} in a sample')
                break
        text = obs['bridge_logs'].get(b, '')
        if 'halt left' in text:
            reasons.append(f'{b} logged "halt left"')
            fail = True
        warns = text.count('foreign journal at the chain head')
        if warns != 1:
            reasons.append(f'{b} logged the foreign-head WARN {warns} time(s), want once')
    for money in obs['money']:
        if money.get('meEpoch') or money.get('lastAppliedJournalSeq'):
            reasons.append(f'the core bound: meEpoch {money.get("meEpoch")}, lastAppliedJournalSeq {money.get("lastAppliedJournalSeq")}')
            fail = True
            break
        if money.get('feedHalted') is not True or money.get('haltReason') != 'SOURCE_SCHEMA':
            reasons.append(f'core feedHalted {money.get("feedHalted")} haltReason {money.get("haltReason")}, want true SOURCE_SCHEMA')
            break
    gate = _dedupe(obs['gate_rows'])
    if gate != [['SUSPENDED', 'GENESIS'], ['SUSPENDED', 'BRIDGE_HALT']]:
        reasons.append(f'GLOBAL admission rows {gate}, want [SUSPENDED, GENESIS] then [SUSPENDED, BRIDGE_HALT]')
        if any(g[0] == 'OPEN' for g in gate):
            fail = True
    driver = obs['driver']
    if driver.get('exit') == 0 or 'GLOBAL OPEN' in driver.get('out', '').replace('never accepted', ''):
        reasons.append('an OPEN(GLOBAL, ADMIN) was ACCEPTED or DUPLICATE: the genesis driver opened the gate')
        fail = True
    elif match_site(driver.get('out', ''), 'driver', ) is None or match_site(driver['out'], 'driver')['key'] != 'admin-ack-40':
        reasons.append('the driver did not end with "ADMIN OPEN GLOBAL never accepted: last reason 40 FEED_HALTED"')
    order = obs['probe_order']
    last = ((order.get('reply') or {}).get('replies') or [{}])[-1]
    if order.get('meaning') != 'REFUSED' or last.get('reason') != 'GATE_CLOSED' or not order.get('after_bridge_halt'):
        reasons.append(f'the probe order was not refused GATE_CLOSED after the first BRIDGE_HALT row: {order.get("meaning")} '
                       f'{last}')
        if order.get('meaning') == 'ANSWERED':
            fail = True
    if obs['probe_deposit'].get('meaning') != 'ANSWERED':
        reasons.append(f'the probe deposit was not ACKed ({obs["probe_deposit"].get("meaning")})')
    return {'verdict': 'FAIL' if fail else ('INCONCLUSIVE' if reasons else 'REFUSED'), 'reasons': reasons, 'gate': gate}


def judge_x7_wiped(obs):
    """Control xver-x7-wiped (8.2): with the archives wiped the same run binds, OPEN(ADMIN) ACCEPTED, [OPEN, ADMIN]."""
    reasons = []
    gate = _dedupe(obs['gate_rows'])
    if ['OPEN', 'ADMIN'] not in gate:
        reasons.append(f'the gate never reached [OPEN, ADMIN]: {gate}')
    if obs['driver'].get('exit') != 0:
        reasons.append(f'the genesis driver exited {obs["driver"].get("exit")}')
    if not any(m.get('meEpoch') for m in obs['money']):
        reasons.append('the core never bound')
    return {'verdict': 'NOT-OPENED' if reasons else 'OPENED', 'reasons': reasons, 'gate': gate}


# ------------------------------------------------------------------ the X-A judges (6.8)

def _results(out):
    return {int(v): int(r) for v, r in re.findall(r'CoreConfig (\d) result (\d+)', out or '')}


def judge_a1(obs):
    reasons = []
    rec = obs['record']
    if rec.get('status') != 'OK':
        reasons.append(f'the activation record reads {rec.get("status")}, want OK: {rec.get("refusals")}')
    if (rec.get('members_up') or {}).get('me') != 2:
        reasons.append(f'members_up me {(rec.get("members_up") or {}).get("me")}, want 2/3 at the record time')
    if obs['killed'] not in [s['role'] for s in obs['audit'].get('stopped') or []]:
        reasons.append(f'the audit does not name the killed member {obs["killed"]}')
    if obs['rerun_core'].get('exit') == 0 or _results(obs['rerun_core'].get('out')).get(1) != 4:
        reasons.append('the core tool re-run was not refused STALE at CoreConfig 1')
    if obs['rerun_me'].get('exit') != 0 or f'EPOCH {obs["genesis_id"]}' not in obs['rerun_me'].get('out', ''):
        reasons.append('the ME FRESH re-run with the same id did not answer the bound epoch (DUPLICATE)')
    for m, n in sorted(obs['me_engine_configs_after_rerun'].items()):
        if n != 1:
            reasons.append(f'the ME FRESH re-run wrote a second engine_config record on {m}')
    if not obs.get('restart_ready'):
        reasons.append('the killed member did not come back ready')
    if obs.get('gate') != 'OPEN':
        reasons.append(f'the gate is {obs.get("gate")} after the genesis')
    return {'verdict': 'FAIL' if reasons else 'PASS', 'reasons': reasons}


def judge_a2(obs):
    reasons, out = [], {}
    if obs['before'].get('status') not in ('INCOMPLETE', 'ABORTED'):
        reasons.append(f'the record before the recovery reads {obs["before"].get("status")}, want INCOMPLETE or ABORTED')
    if obs['gate_after_partial'] != 'GENESIS':
        reasons.append(f'the gate after the partial genesis is {obs["gate_after_partial"]}, want [SUSPENDED, GENESIS]')
    if _results(obs['new_id_core'].get('out')).get(1) != 2 or obs['new_id_core'].get('exit') == 0:
        reasons.append('the new genesisId was not REJECTED at CoreConfig 1')
    if not obs.get('new_id_me_rejected'):
        reasons.append('the ME FRESH with a new genesisId was not REJECTED_GENESIS')
    same = obs['same_id']
    if obs['stop_after'] == 1:
        if same.get('exit') != 0 or obs.get('gate_final') != 'OPEN':
            reasons.append(f'after CoreConfig 1 the same-id re-run did not resume to [OPEN, ADMIN] (exit {same.get("exit")}, '
                           f'gate {obs.get("gate_final")})')
    else:
        if same.get('exit') == 0 or _results(same.get('out')).get(1) != 4:
            reasons.append('after CoreConfig 1 and 2 the same-id re-run was not refused STALE at CoreConfig 1')
        if obs.get('gate_final') != 'GENESIS' or obs.get('bound_after_same_id'):
            reasons.append(f'after the refused re-run the gate is {obs.get("gate_final")} and meEpoch '
                           f'{obs.get("bound_after_same_id")}, want GENESIS and 0')
        rec = obs.get('recovery') or {}
        out['recovery'] = ('finish opened: [OPEN, ADMIN]' if rec.get('opened') else
                           'finish did not open: a wipe of both clusters and a new genesisId')
    return dict(out, verdict='FAIL' if reasons else 'PASS', reasons=reasons)


def judge_a3(obs):
    reasons = []
    site = match_site(obs['driver'].get('out', ''), 'driver')
    if obs['driver'].get('exit') == 0 or not site or site['key'] != 'admin-ack-41':
        reasons.append('the no-bridge genesis driver did not fail on 41 ME_LANE_INACTIVE')
    if obs['gate_no_bridge'] != 'GENESIS':
        reasons.append(f'the gate is {obs["gate_no_bridge"]} with no bridge, want GENESIS')
    p = obs['probe_open_no_bridge']
    if p.get('meaning') != 'REFUSED' or p.get('reason') != 41:
        reasons.append(f'the explicit OPEN with no bridge was not REJECTED 41: {p}')
    if obs['before'].get('status') not in ('INCOMPLETE', 'ABORTED'):
        reasons.append(f'the record before the open reads {obs["before"].get("status")}, want INCOMPLETE')
    if obs.get('bound_after_s') is None:
        reasons.append('the epoch did not bind after the bridge started')
    if obs['gate_after_bind'] != 'GENESIS':
        reasons.append(f'the gate left GENESIS before the explicit open ({obs["gate_after_bind"]})')
    p = obs['probe_open_after_bind']
    if p.get('result') != 'ACCEPTED' or obs.get('gate_final') != 'OPEN':
        reasons.append(f'the explicit OPEN after the bind was not ACCEPTED to [OPEN, ADMIN]: {p} gate {obs.get("gate_final")}')
    return {'verdict': 'FAIL' if reasons else 'PASS', 'reasons': reasons}


LOCAL_FIELDS = {'source', 'recording'}


def judge_a4(obs):
    reasons = []
    r5 = obs['record5']
    if set(r5) != {'me0', 'me1', 'me2'}:
        reasons.append(f'record 5 not dumped on every member: {sorted(r5)}')
    else:
        ref = r5['me0']
        for m in ('me1', 'me2'):
            for k in sorted(set(ref) | set(r5[m])):
                if k not in LOCAL_FIELDS and ref.get(k) != r5[m].get(k):
                    reasons.append(f'{m} record 5 differs from me0 in {k}')
    pos = obs['ae_log_positions']
    if len(pos) != 3 or len(set(pos.values())) != 1:
        reasons.append(f'AE logPositions differ at quiescence: {pos}')
    for m, ready in sorted(obs['late_ready'].items()):
        if not ready:
            reasons.append(f'the late member {m} did not become ready')
    return {'verdict': 'FAIL' if reasons else 'PASS', 'reasons': reasons}


def judge_a5(obs):
    reasons = []
    for row in obs['wait_rows']:
        for fwd, (running, status) in sorted(row.items()):
            if not running:
                reasons.append(f'{fwd} exited before the genesis (wait row)')
            elif status == 200:
                reasons.append(f'{fwd} answered /ready 200 while the epoch was 0')
    reasons = sorted(set(reasons))
    for fwd in ('fwd0', 'fwd1'):
        if obs['epoch_waits'].get(fwd, 0) < 2:
            reasons.append(f'{fwd} logged {obs["epoch_waits"].get(fwd, 0)} epoch wait(s); a reconnect every about 5 s expected')
        if not obs['bound_lines'].get(fwd):
            reasons.append(f'{fwd} never logged "ME epoch bound"')
        if obs['restarts'].get(fwd):
            reasons.append(f'{fwd} restarted {obs["restarts"][fwd]} time(s)')
    if not obs.get('ready_after_genesis'):
        reasons.append('the forwarders did not become ready after the genesis')
    return {'verdict': 'FAIL' if reasons else 'PASS', 'reasons': reasons}


# ------------------------------------------------------------------ the X-R judge (6.9)

def judge_rollback(d0, d1, post, omitted=None, error=None):
    """Pass: D1 == D0 and the post-restore scenario passes. ``omitted`` (control xr-omit): the restore omitted one item and must
    FAIL the equality or the post-restore scenario (an error in the restore counts as that failure)."""
    reasons = []
    if error:
        reasons.append(f'the restore failed: {error}')
    if d1 is not None:
        for key in sorted(k for k in d0 if k != 'combined'):
            if (d1.get(key) or {}).get('sha256') != d0[key]['sha256']:
                reasons.append(f'D1 != D0 in {key}')
    elif not error:
        reasons.append('D1 was not taken')
    if post is not None:
        if not (all(post.get('deposits') or [False]) and all(post.get('orders') or [False]) and post.get('changed')):
            reasons.append(f'the post-restore scenario did not pass: {post}')
    elif not error:
        reasons.append('the post-restore scenario did not run')
    if omitted:
        return {'verdict': 'PASS' if reasons else 'FAIL', 'omitted': omitted,
                'reasons': reasons or [f'the restore without {omitted} still passed: the control did not bite']}
    return {'verdict': 'FAIL' if reasons else 'PASS', 'reasons': reasons}


# ------------------------------------------------------------------ the active probe (5.2)

def probe_answered(engine, code, stdout, meaning):
    """ME: JournalProbe open-legs (a session plus one request) answered; AE: a CoreProbe deposit answered (ACK or REJECT)."""
    if engine == 'me':
        return code == 0 and '"verb":"open-legs"' in (stdout or '')
    return meaning in ('ANSWERED', 'REFUSED')


def probe_cadence(rows, s):
    """The measured attempt rate (coordinator: ~0.3/s as measured on the cut, a recorded value, not a line)."""
    if len(rows) < 2:
        return {'attempts': len(rows), 'per_s': None, 'interval_s': s['XVER_PROBE_INTERVAL_S'], 'inflight': s['XVER_PROBE_INFLIGHT']}
    span = (max(r['started_ns'] for r in rows) - min(r['started_ns'] for r in rows)) / 1e9
    return {'attempts': len(rows), 'span_s': round(span, 1), 'per_s': round((len(rows) - 1) / span, 3) if span else None,
            'interval_s': s['XVER_PROBE_INTERVAL_S'], 'inflight': s['XVER_PROBE_INFLIGHT']}


class ActiveProbe(threading.Thread):
    """During every X run a client at the binary's own wire attempts a session plus one request: ME ``JournalProbe open-legs``
    (the T1MeDriver connect retries for 60 s, too slow for a 1 s cadence), AE ``CoreProbe deposit`` on the TOOL principal. One
    attempt starts every second while fewer than ``inflight`` are running; every attempt and answer is a row of ``out``."""

    def __init__(self, f, engine, out, inflight=2, interval=1.0):
        super().__init__(daemon=True)
        self.f, self.engine, self.out, self.inflight, self.interval = f, engine, Path(out), inflight, interval
        self.rows, self.lock, self.stop_event, self.running, self.seq = [], threading.Lock(), threading.Event(), 0, 0

    def attempt(self, n):
        from core_fixture import JAVA
        started = time.time_ns()
        try:
            if self.engine == 'me':
                f = self.f
                ingress = ','.join(f'{i}={f.m["nodes"][f"me{i}"]}:{f.m["ports"]["me_base"] + i * f.m["ports"]["stride"] + 2}'
                                   for i in range(3))
                argv = ['timeout', '-k', '5', '20'] + JAVA + ['-cp', '/artifacts/journal-probe.jar:/artifacts/me.jar',
                                                              'JournalProbe', 'open-legs', f'ingress={ingress}',
                                                              f'local={f.m["nodes"]["probe"]}']
                env = {'ME_AUTH_CREDENTIAL': f.keys.credential('probe-admin', 'me')}
                r = f.execute('probe', argv, environment=env, timeout=40, check=False, accepted=tuple(range(256)))
                row = {'code': r.returncode, 'out': (r.stdout or '')[-300:], 'meaning': None}
            else:
                meaning, reply = self.f.core('deposit', 'probe-tool', timeout=40, user=990001, asset=0, amount=1, rh=9, rl=n)
                row = {'code': None, 'meaning': meaning, 'out': json.dumps(reply)[-300:] if reply else ''}
        except Exception as error:                      # a refused attempt is evidence, never a crash of the run
            row = {'code': None, 'meaning': 'ERROR', 'out': str(error)[-300:]}
        row.update(n=n, started_ns=started, ended_ns=time.time_ns())
        row['answered'] = probe_answered(self.engine, row['code'], row['out'], row['meaning'])
        row['at_ns'] = row['ended_ns']
        with self.lock:
            self.rows.append(row)
            self.running -= 1
            with self.out.open('a') as stream:
                stream.write(json.dumps(row) + '\n')

    def run(self):
        while not self.stop_event.is_set():
            with self.lock:
                free = self.running < self.inflight
                if free:
                    self.running += 1
                    self.seq += 1
                    n = self.seq
            if free:
                threading.Thread(target=self.attempt, args=(n,), daemon=True).start()
            self.stop_event.wait(self.interval)

    def stop(self, drain_s=45):
        self.stop_event.set()
        deadline = time.time() + drain_s
        while time.time() < deadline:
            with self.lock:
                if self.running == 0:
                    break
            time.sleep(0.5)
        with self.lock:
            return list(self.rows)


# ------------------------------------------------------------------ scenario plumbing

def _iso_ns(text):
    from core_drills import _iso_ns as iso
    return iso(text)


def _note(out, **kw):
    kw['at_ns'] = time.time_ns()
    with (Path(out) / 'timeline.jsonl').open('a') as stream:
        stream.write(json.dumps(kw, default=str) + '\n')


def _docker_logs(f, role):
    from credentials import redact
    cid = f.registry['containers'][role]
    r = f.command(['docker', 'logs', '--timestamps', cid], check=False)
    return redact((r.stdout or '') + (r.stderr or ''), f.secret_values)


def _strip_stamps(text):
    return '\n'.join(l.split(' ', 1)[1] if re.match(r'\d{4}-\d\d-\d\dT', l) else l for l in text.splitlines())


def _cut_aeron():
    try:
        return json.loads(CUT.read_text())['substrate']['aeron']['host_aeronmd']
    except (OSError, ValueError, KeyError):
        return None


def _audit(f, out, name, started_only=False):
    import r10_cut
    try:
        return r10_cut.audit_fixture(f, Path(out) / name, aeron_version=_cut_aeron(), started_only=started_only)
    except Exception as error:
        report = {'status': 'ERROR', 'error': str(error)[:500], 'findings': [str(error)[:300]], 'stopped': [], 'members_up': {}}
        (Path(out) / name).write_text(json.dumps(report, indent=1) + '\n')
        return report


def _record(f, out, audit, name='rc2-activation-record.json'):
    import r10_cut
    record, _ = r10_cut.write_activation_record(out, Path(out) / name, state_root=f.root, audit=audit)
    return record


def _child_exits(fixtures):
    codes = []
    for f in fixtures:
        commands = Path(f.root) / 'commands.jsonl'
        if not commands.exists():
            continue
        for line in commands.read_text().splitlines():
            r = json.loads(line)
            if 'accepted_exit_codes' in r:          # CoreFixture rows; a legacy fixture's failing command raised already
                codes.append(0 if r['exit_code'] in r['accepted_exit_codes'] else r['exit_code'])
    return codes or [0]


def _boot_base(f):
    f.check_image(); f.stage_artifacts(); f.start_network()
    f.spawn('probe', f.probe_command())


def _spawn_engine(f, role):
    engine, i = role[:2], int(role[2:])
    env = f.engine_env(engine, i)
    check_engine_env(env)
    return f.spawn(role, f.engine_command(engine, i), env)


def _state(f, role):
    return f.inspect('container', f.registry['containers'][role])['State']


def _watch_members(f, roles, out, bound_s, last_start_ns, serve_hold_s=15):
    """Poll every second until every member exited, or every member served for ``serve_hold_s``, or the bound passed."""
    port = f.m['ports'][roles[0][:2] + '_metrics']
    ready, served_since = {r: False for r in roles}, None
    while time.time_ns() < last_start_ns + bound_s * 1_000_000_000:
        row = {}
        for r in roles:
            st = _state(f, r)
            code = None
            if st['Running']:
                code = f.http(r, port, '/ready').get('status')
                ready[r] = ready[r] or code == 200
            row[r] = [st['Running'], st['ExitCode'], code]
        _note(out, ev='members', state=row)
        if not any(v[0] for v in row.values()):
            break
        if all(v[2] == 200 for v in row.values()):
            served_since = served_since or time.time()
            if time.time() - served_since >= serve_hold_s:
                break
        time.sleep(1)
    return ready


def _members(f, roles, starts, ready):
    out = []
    for r in roles:
        st = _state(f, r)
        log = _docker_logs(f, r)
        (f.root / 'logs' / f'{r}.xver.log').write_text(log)
        out.append({'role': r, 'running': st['Running'], 'exit_code': None if st['Running'] else st['ExitCode'],
                    'started_ns': starts[r], 'finished_ns': None if st['Running'] else _iso_ns(st['FinishedAt']),
                    'log': _strip_stamps(log), 'ready_200': ready[r]})
    return out


def _recovery_line(f, engine, out):
    """C5: wipe the same containers and boot them clean on the run's intended jar: /ready 200 on every member."""
    roles = [f'{engine}{i}' for i in range(3)]
    for r in roles:
        if _state(f, r)['Running']:
            f.command(['docker', 'kill', '--signal=KILL', f.registry['containers'][r]])
        f.wipe_engine(r, projection_dump_required=False, reason='the X run seeded a foreign state; no money moved in this fixture')
    try:
        w = f.start_members(engine, ready_timeout=150)
        return {'ready': True, 'witness': w}
    except Inconclusive as error:
        return {'ready': False, 'error': str(error)}


def _seed_members(f, shape, roles, tail_min, parts=None):
    root = SEEDS / shape
    out = {}
    for r in roles:
        w = seed_witness(shape, root, r, tail_min)
        out[r] = f.seed_state(r, root / r, w['recorded_sha256'], witness=w, parts=parts)
    return out


def _result(verdict, extra, fixtures, assertions):
    status = verdict_status(verdict['verdict'])
    return dict(extra, status=status, xver_verdict=verdict['verdict'], verdict=verdict, assertions=assertions, processed=1,
                skipped=0, child_exit_codes=_child_exits(fixtures))


# ------------------------------------------------------------------ X-1, X-3 and the same-version controls

def run_state_case(manifest, case, out, s, seed_override=None, control=None):
    from core_fixture import CoreFixture
    spec = CASES.get(case) or {}
    engine = spec.get('engine') or CONTROLS[control]['engine']
    roles = [f'{engine}{i}' for i in range(3)]
    f = CoreFixture(manifest, drill=True)
    fixtures = [f]
    try:
        _boot_base(f)
        if seed_override is not None:
            hashes = _hashes(seed_override)
            seeds = {r: f.seed_state(r, seed_override / r, hashes[r], witness={'shape': 'RC2 state (control)'}) for r in roles}
        else:
            seeds = _seed_members(f, spec['seed'], roles, s['XVER_TAIL_MIN'])
        probe = ActiveProbe(f, engine, Path(out) / 'probe.jsonl', inflight=s['XVER_PROBE_INFLIGHT'],
                            interval=s['XVER_PROBE_INTERVAL_S'])
        starts = {}
        for i, r in enumerate(roles):
            _spawn_engine(f, r)
            starts[r] = _iso_ns(_state(f, r)['StartedAt'])
            _note(out, ev='started', role=r)
            if i == 0:
                probe.start()
            if i < 2:
                time.sleep(s['XVER_STAGGER_S'])
        ready = _watch_members(f, roles, out, s['XVER_BOUND_S'], max(starts.values()))
        probes = probe.stop()
        members = _members(f, roles, starts, ready)
        for m_ in members:              # the refusal under test: an exited member is an expected stop, named in the audit
            if not m_['running']:
                f.open_fault(m_['role'], 0, 600, reason=f'exited {m_["exit_code"]}: the X run under test')
        audit = _audit(f, out, 'audit-end.json', started_only=True)
        if control:
            served = all(m['ready_200'] for m in members) and any(p['answered'] for p in probes)
            verdict = {'verdict': 'PASS' if served else 'FAIL', 'reasons': [] if served else
                       [f'the same-version control did not serve: ready {ready}, {sum(p["answered"] for p in probes)} answered'],
                       'ready': ready}
            return _result(verdict, {'case': 'control:' + control, 'seeds': seeds, 'audit': audit['status']}, fixtures,
                           len(roles) + 1)
        verdict = judge_state(case, members, probes, s['XVER_BOUND_S'], s['ENGINE_QUORUM_WAIT_MS'])
        verdict['probe_attempts'] = len(probes)
        verdict['probe_cadence'] = probe_cadence(probes, s)
        verdict['probe_answered'] = sum(p['answered'] for p in probes)
        for m in verdict['members']:
            if m.get('site'):
                m['site'] = {k: v for k, v in m['site'].items()}
        extra = {'case': case, 'row': spec['row'], 'seeds': {r: {k: v for k, v in w.items() if k != 'listing_before'}
                                                             for r, w in seeds.items()},
                 'audit': audit['status'], 'driver_mode': f.engine_driver()}
        if verdict['verdict'] == 'REFUSED':
            rec = _recovery_line(f, engine, out)
            extra['recovery'] = rec
            if not rec['ready']:
                verdict = dict(verdict, verdict='INCONCLUSIVE', reasons=verdict['reasons'] + [
                    'the recovery line failed (C5): ' + rec.get('error', '')])
        (Path(out) / 'xver-verdict.json').write_text(json.dumps(verdict, indent=1, default=str) + '\n')
        return _result(verdict, extra, fixtures, len(members) + 2)
    finally:
        f.close()


def _hashes(root):
    import legacy_tag
    return {p.name: legacy_tag.tree_hash(p)['sha256'] for p in Path(root).iterdir() if p.is_dir()}


def run_same_control(manifest, control, out, s):
    """xver-me-same / xver-ae-same: the RC2 jar on an RC2 state seeded the same way must start and serve. The RC2 state comes
    from a first fixture (a child manifest): the members boot (the ME takes its behaviour-2 genesis), stop politely, and their
    state dirs are copied out."""
    import core_contracts
    from core_fixture import CoreFixture
    engine = CONTROLS[control]['engine']
    roles = [f'{engine}{i}' for i in range(3)]
    m = json.loads(Path(manifest).read_text())
    child, _ = core_contracts.child_manifest(m, Path(manifest).parent, 'mkstate')
    seed = Path(out) / 'seed-rc2'
    f0 = CoreFixture(child, drill=True)
    try:
        _boot_base(f0)
        for r in roles:
            _spawn_engine(f0, r)
        for r in roles:
            f0.wait_http(r, f0.m['ports'][engine + '_metrics'], '/ready', timeout=120)
        if engine == 'me':
            f0.registry['lives'] = {'1': {'me': {'genesis_id': f0.genesis_id(1)}}}
            f0.me_genesis({'ledger_capacity': 100_000})
        for r in roles:
            f0.stop(r)
        for r in roles:
            shutil.copytree(f0.root / 'state' / r, seed / r, symlinks=True)
    finally:
        f0.close()
    return run_state_case(manifest, None, out, s, seed_override=seed, control=control)


def run_old_same_control(manifest, control, out, s):
    """xver-me-old-same / xver-ae-old-same: the TAG jar on the v0.5.0-beta seed, seeded the same way, must start and serve (the
    seed-validity control of X-1 / X-3; the tag jar validates the seed, it is not under test)."""
    import legacy_tag
    spec = CONTROLS[control]
    engine, shape = spec['engine'], spec['seed']
    roles = [f'{engine}{i}' for i in range(3)]
    name = f'old-same-{engine}-{Path(out).name[-12:]}'.lower().replace('_', '-')[:40]
    path, _ = legacy_tag.legacy_manifest(re.sub(r'[^a-z0-9-]', '-', name), s['XVER_LEGACY_OCTET'], B0 / 'local-runs/s17/legacy-ctl')
    f = SeededLegacyFixture(path)
    try:
        f.stage_artifacts(); f.start_network()
        f.spawn('probe', ['sleep', 'infinity'])
        seeds = {}
        for i, r in enumerate(roles):
            w = seed_witness(shape, SEEDS / shape, r, s['XVER_TAIL_MIN'])
            seeds[r] = f.seed(r, SEEDS / shape / r, w['recorded_sha256'], w)
            f.spawn_engine(r)
            if i < 2:
                time.sleep(s['XVER_STAGGER_S'])
        ready = {}
        for r in roles:
            try:
                f.wait_http(r, 0, '/ready', timeout=s['XVER_BOUND_S'])
                ready[r] = True
            except Inconclusive as error:
                ready[r] = str(error)
        leader = None
        try:
            leader = f.leader(engine)
        except Inconclusive as error:
            leader = str(error)
        served = all(v is True for v in ready.values()) and isinstance(leader, int)
        verdict = {'verdict': 'PASS' if served else 'FAIL', 'ready': ready, 'leader': leader,
                   'reasons': [] if served else [f'the tag jar did not serve its own seed: {ready}, leader {leader}']}
        return {'status': verdict['verdict'], 'xver_verdict': verdict['verdict'], 'verdict': verdict, 'case': 'control:' + control,
                'seeds': seeds, 'legacy_manifest': str(path), 'assertions': 4, 'processed': 1, 'skipped': 0,
                'child_exit_codes': [0]}
    finally:
        f.close()


def _legacy_base():
    import legacy_tag
    return legacy_tag.LegacyTagFixture


class SeededLegacyFixture(_legacy_base()):
    """The legacy tag profile with seeded engine members (the old-same controls, X-R's restore)."""
    seeds = None

    def seed(self, role, src, recorded, witness=None):
        import legacy_tag
        tree = legacy_tag.tree_hash(src)
        if tree['sha256'] != recorded:
            raise Inconclusive(f'seed tree hash differs from the recorded one: {src}')
        dest = self.root / 'state' / role
        shutil.copytree(src, dest, symlinks=True)
        self.seeds = dict(self.seeds or {}, **{role: str(src)})
        return {'role': role, 'source': str(src), 'tree': tree, 'witness': witness}

    def spawn(self, name, command, environment=None):
        state = self.root / 'state' / name
        if name not in (self.seeds or {}):
            return super().spawn(name, command, environment)
        real = Path.mkdir                      # the frozen Fixture.spawn creates the dir; a seeded member's dir exists

        def mkdir(p, *a, **kw):
            return real(p, *a, **{**kw, 'exist_ok': True}) if p == state else real(p, *a, **kw)
        Path.mkdir = mkdir
        try:
            return super().spawn(name, command, environment)
        finally:
            Path.mkdir = real

    def spawn_engine(self, role):
        from fixture import JAVA
        engine, i = role[:2], int(role[2:])
        port = 9000 if engine == 'me' else 19300
        env = {'CLUSTER_PORT_STRIDE': '100', 'BASE_DIR': '/data/state', 'TRANSPORT_DRIVER_MODE': 'embedded',
               'TRANSPORT_IDLE_MODE': 'backoff', 'TRANSPORT_TERM_LENGTH': '1m', 'TRANSPORT_LOG_TERM_LENGTH': '1m',
               'TRANSPORT_SNAPSHOT_TERM_LENGTH': '1m', 'MATCH_ENGINE_BOOK_CAPACITY': '4096', 'SNAPSHOT_LOG_BYTES': '1073741824',
               'SNAPSHOT_INTERVAL_MINUTES': '5', 'CLUSTER_NODE': str(i),
               'CLUSTER_ADDRESSES': ','.join(self.m['nodes'][f'{engine}{k}'] for k in range(3)), 'CLUSTER_PORT_BASE': str(port)}
        if engine == 'me':
            env.update(METRICS_PORT='19500', SETTLEMENT_JOURNAL_ENABLED='true', SETTLEMENT_JOURNAL_DIR='/data/journal',
                       SETTLEMENT_JOURNAL_ARCHIVE_BIND='0.0.0.0')
        else:
            env['ASSETS_NODE_PORT'] = '19700'
        return self.spawn(role, JAVA + ['-jar', f'/artifacts/{engine}.jar'], env)


# ------------------------------------------------------------------ X-7 and the wiped control

X7_PLAN = {'users': [], 'markets': [1], 'funding': [], 'tap_ms': 420_000}


def _gate_rows(f):
    rows = []
    path = Path(f.registry['tap']['path'])
    for line in (path.read_text().splitlines() if path.exists() else []):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get('tap') == 'admission' and e['row'].get('market') == 0:
            rows.append([e['row']['state'], e['row']['reason'], e['row'].get('at_ms')])
    return rows


def _money(f):
    meaning, reply = f.core('money-dump', 'probe-admin', timeout=60)
    return reply or {'meaning': meaning}


def _boot_engines(f, stop_before=(), seed=None, s=None):
    """CoreFixture.start up to the engines' /ready (CF:672-690) with two seams: members ``seed`` gives a seeded part, members
    ``stop_before`` are stopped (registered fault targets) before the genesis (X-A4)."""
    from core_fixture import ENGINES, REGENESIS_HEAL_BOUND_S
    _boot_base(f); f.start_database()
    f.registry['boot'] = {'started_ns': time.time_ns(), 'phases': {}}
    for engine in ('ae', 'me'):
        for i in range(3):
            role = f'{engine}{i}'
            if seed and role in seed:
                seed[role] = f.seed_state(role, seed[role][0], seed[role][1], witness=seed[role][2], parts=('journal',))
            _spawn_engine(f, role)
    for role in stop_before:
        f.stop(role, heal_bound_s=REGENESIS_HEAL_BOUND_S)
    for engine in ('ae', 'me'):
        for i in range(3):
            if f'{engine}{i}' not in stop_before:
                f.wait_http(f'{engine}{i}', f.m['ports'][engine + '_metrics'], '/ready', timeout=120)
    if f.engine_driver() == 'external':
        for role in ENGINES:
            if role not in stop_before:
                f.registry.setdefault('driver_identity', {})[role] = f.driver_identity(role)
    f.registry['boot']['phases']['engines_ready_ns'] = time.time_ns()
    f.save()


def _steps(f, plan, steps):
    from core_fixture import GENESIS_ORDER
    phases = f.registry['boot']['phases']
    if 'lives' not in f.registry:
        gid = f.genesis_id(1)
        f.registry['lives'] = {'1': {'me': {'genesis_id': gid}, 'core': {'genesis_id': gid}}}
        f.registry['genesis'] = {'genesis_id': gid, 'ledger_capacity': plan.get('ledger_capacity', 100_000), 'life': 1,
                                 'derivation': f.genesis_derivation()}
    names = dict(GENESIS_ORDER)
    for step in steps:
        if step == 'fund':
            phases['first_deposit_ns'] = time.time_ns()
        getattr(f, step)(plan)
        phases[names[step]] = time.time_ns()
        f.save()


def _core_driver(f, genesis_id=None, timeout=150):
    from core_fixture import PROBE_AERON_DIR
    r = f._driver('t1_core_driver', 'T1CoreDriver', 'genesis', PROBE_AERON_DIR, f._ingress('ae'),
                  genesis_id or f.genesis_id(1), 100_000, 0, 'via-bridge', timeout=timeout, check=False, accepted=(0, 1))
    return {'exit': r.returncode, 'out': (r.stdout or '') + (r.stderr or '')}


def _me_driver(f, genesis_id, timeout=150):
    from core_fixture import PROBE_AERON_DIR
    r = f._driver('t1_me_driver', 'T1MeDriver', 'genesis', PROBE_AERON_DIR, f._ingress('me'), genesis_id, 100_000,
                  timeout=timeout, check=False, accepted=(0, 1, 78))
    return {'exit': r.returncode, 'out': (r.stdout or '') + (r.stderr or '')}


def run_x7(manifest, out, s, wiped=False):
    from core_fixture import CoreFixture
    f = CoreFixture(manifest, drill=True)
    fixtures = [f]
    try:
        seed = None
        if not wiped:
            seed = {}
            for r in ('me0', 'me1', 'me2'):
                w = seed_witness('C', SEEDS / 'C', r, s['XVER_TAIL_MIN'])
                seed[r] = (SEEDS / 'C' / r, w['recorded_sha256'], w)
        _boot_engines(f, seed=seed)
        plan = dict(X7_PLAN)
        _steps(f, plan, ['snapshot_genesis', 'start_tap_witness', 'me_genesis', 'arm_money_journal', 'start_projector'])
        if wiped:
            f.start_bridges(plan)
        else:
            for slot in ('bridge0', 'bridge1'):
                f.spawn(slot, f.slot_command(slot), f.slot_process_env(slot))
        _note(out, ev='bridges started')
        driver = _core_driver(f)
        _note(out, ev='driver', exit=driver['exit'], text=driver['out'][-600:])
        gate_rows = _gate_rows(f)
        halt_at = next((g[2] for g in gate_rows if g[1] == 'BRIDGE_HALT'), None)
        money = [_money(f)]
        order_meaning, order_reply = f.core('create', 'probe-gateway', user=990002, market=1, side='BUY', type='LIMIT', tif='GTC',
                                            price=100, qty=1, budget=0, stop=0, delta=0, display=0, expires=0, rh=1, rl=1, ch=0,
                                            cl=1)
        sent_ms = time.time_ns() // 1_000_000
        deposit_meaning, _ = f.core('deposit', 'probe-tool', user=990002, asset=0, amount=1, rh=2, rl=1)
        samples = []
        started = time.time()
        while time.time() - started < s['XVER_SAMPLE_S']:
            row = {'at_ns': time.time_ns(), 'me_running': {r: _state(f, r)['Running'] for r in ('me0', 'me1', 'me2')},
                   'bridges': {}}
            for b in ('bridge0', 'bridge1'):
                running = _state(f, b)['Running']
                h = f.http(b, f.m['ports']['bridge_http'], '/health') if running else {'status': None, 'body': ''}
                try:
                    body = json.loads(h.get('body') or '{}')
                except ValueError:
                    body = {}
                row['bridges'][b] = {'status': h.get('status'), 'health': body, 'running': running}
            samples.append(row)
            time.sleep(2)
        sample_s = round(time.time() - started, 1)
        money.append(_money(f))
        obs = {'samples': samples, 'sample_s': sample_s, 'money': money, 'gate_rows': [g[:2] for g in _gate_rows(f)],
               'bridge_logs': {b: _strip_stamps(_docker_logs(f, b)) for b in ('bridge0', 'bridge1')}, 'driver': driver,
               'probe_order': {'meaning': order_meaning, 'reply': order_reply,
                               'after_bridge_halt': halt_at is not None and sent_ms > halt_at},
               'probe_deposit': {'meaning': deposit_meaning}}
        (Path(out) / 'x7-observations.json').write_text(json.dumps(obs, indent=1, default=str) + '\n')
        verdict = judge_x7_wiped(obs) if wiped else judge_x7(obs)
        audit = _audit(f, out, 'audit-end.json', started_only=True)
        return _result(verdict, {'case': 'control:core-xver-ctl-x7-wiped' if wiped else 'X-7', 'row': '20',
                                 'seeds': seed and {k: {kk: vv for kk, vv in v.items() if kk != 'listing_before'}
                                                    for k, v in seed.items()},
                                 'audit': audit['status']}, fixtures, len(samples) + 6)
    finally:
        f.close()


# ------------------------------------------------------------------ X-A1..X-A5 (6.8)

ACT_PLAN = None


def _act_plan():
    import core_scenarios
    plan = copy.deepcopy(core_scenarios.SMOKE_PLAN)
    plan['tap_ms'] = 600_000
    return plan


def _gate_now(f):
    g = f.tap_gate(0)
    return g['state'] if g and g['state'] == 'OPEN' else (g['reason'] if g else None)


def _journal_records(f, members):
    import r10_cut
    import sbe_layout
    schema = sbe_layout.load(r10_cut.ME_JOURNAL_SCHEMA)
    out, counts = {}, {}
    for m in members:
        lines = f.journal_dump(m)
        r5 = r10_cut._decode_record5(lines, schema.messages[5], schema.order)
        if r5:
            r5['recording'] = next((json.loads(l).get('recording') for l in lines if '"kind":"frame"' in l), None)
            out[m] = r5
        counts[m] = sum(1 for l in lines if '"kind":"frame"' in l and l.count('"hex":"') and
                        bytes.fromhex(json.loads(l)['hex'])[2:4] == b'\x05\x00')
    return out, counts


def run_act(manifest, name, out, s):
    from core_fixture import CoreFixture, GENESIS_ORDER
    f = CoreFixture(manifest, drill=True)
    plan = _act_plan()
    order = [step for step, _ in GENESIS_ORDER]
    try:
        if name == 'core-act-leaderkill':
            _boot_engines(f)
            _steps(f, plan, order[:order.index('start_bridges')])
            lead = f.leader('me')
            if lead is None:
                raise Inconclusive('no ME leader after the ME FRESH')
            f.kill(lead)
            _note(out, ev='killed ME leader', role=lead)
            _steps(f, plan, order[order.index('start_bridges'):])
            audit = _audit(f, out, 'audit.json')
            record = _record(f, out, audit)
            gid = int(f.genesis_id(1), 16)
            rerun_core = _core_driver(f)
            rerun_me = _me_driver(f, f.genesis_id(1))
            up = [m for m in ('me0', 'me1', 'me2') if m != lead]
            _, counts = _journal_records(f, up)
            try:
                f.restart(lead, ready_timeout=120)
                restarted = True
            except Inconclusive as error:
                restarted = str(error)
            obs = {'record': record, 'killed': lead, 'audit': audit, 'rerun_core': rerun_core, 'rerun_me': rerun_me,
                   'me_engine_configs_after_rerun': counts, 'restart_ready': restarted is True, 'gate': _gate_now(f),
                   'genesis_id': gid}
            verdict = judge_a1(obs)
        elif name in ('core-act-toolkill', 'core-act-toolkill-2'):
            k = 2 if name.endswith('-2') else 1
            _boot_engines(f)
            _steps(f, plan, order[:order.index('core_genesis')])
            partial = f.core_genesis_partial(plan, k)
            time.sleep(3)
            gate_partial = _gate_now(f)
            audit = _audit(f, out, 'audit.json')
            before = _record(f, out, audit, 'rc2-activation-record.before-recovery.json')
            new_core = _core_driver(f, genesis_id=f.genesis_id(2))
            new_me = _me_driver(f, f.genesis_id(2), timeout=120)
            me_logs = ''.join(_docker_logs(f, m) for m in ('me0', 'me1', 'me2'))
            same = _core_driver(f)
            time.sleep(3)
            obs = {'stop_after': k, 'partial': partial, 'before': before, 'gate_after_partial': gate_partial,
                   'new_id_core': new_core, 'new_id_me': new_me, 'new_id_me_rejected': 'REJECTED_GENESIS' in me_logs,
                   'same_id': same, 'gate_final': _gate_now(f)}
            if k == 2:
                obs['bound_after_same_id'] = _money(f).get('meEpoch')
                finish = f.core_genesis_finish(plan)
                bound = None
                for _ in range(20):
                    bound = _money(f).get('meEpoch')
                    if bound:
                        break
                    time.sleep(3)
                meaning, reply = f.core('gate', 'probe-admin', market=0, state='OPEN', reason='ADMIN')
                time.sleep(3)
                obs['recovery'] = {'finish': finish['results'], 'bound': bound, 'open': {'meaning': meaning, 'reply': reply},
                                   'opened': _gate_now(f) == 'OPEN'}
            obs['record_after'] = _record(f, out, _audit(f, out, 'audit-end.json'))
            verdict = judge_a2(obs)
        elif name == 'core-act-nobridge':
            _boot_engines(f)
            _steps(f, plan, order[:order.index('start_bridges')])
            driver = _core_driver(f)
            gate0 = _gate_now(f)
            meaning, reply = f.core('gate', 'probe-admin', market=0, state='OPEN', reason='ADMIN')
            ack = next((r for r in (reply or {}).get('replies') or [] if r.get('t') == 'AdminAck'), {})
            before = _record(f, out, _audit(f, out, 'audit.json'), 'rc2-activation-record.before-recovery.json')
            t = time.time()
            f.start_bridges(plan)
            f.registry['boot']['phases']['bridges_ready_ns'] = time.time_ns()
            bound_after = None
            while time.time() - t < 60:
                if _money(f).get('meEpoch'):
                    bound_after = round(time.time() - t, 1)
                    f.registry['boot']['phases']['core_bound_ns'] = time.time_ns()
                    break
                time.sleep(2)
            gate1 = _gate_now(f)
            m2, r2 = f.core('gate', 'probe-admin', market=0, state='OPEN', reason='ADMIN')
            ack2 = next((r for r in (r2 or {}).get('replies') or [] if r.get('t') == 'AdminAck'), {})
            time.sleep(3)
            obs = {'driver': driver, 'gate_no_bridge': gate0, 'probe_open_no_bridge': {'meaning': meaning, 'reason': ack.get('reason')},
                   'before': before, 'bound_after_s': bound_after, 'gate_after_bind': gate1,
                   'probe_open_after_bind': {'meaning': m2, 'result': ack2.get('result')}, 'gate_final': _gate_now(f)}
            obs['record_after'] = _record(f, out, _audit(f, out, 'audit-end.json'))
            verdict = judge_a3(obs)
        elif name == 'core-act-latemember':
            late = ('me2', 'ae2')
            _boot_engines(f, stop_before=late)
            rest_ready = time.time()
            _steps(f, plan, order)
            audit = _audit(f, out, 'audit.json')
            record = _record(f, out, audit)
            wait = s['XVER_LATE_JOIN_S'] - (time.time() - rest_ready)
            if wait > 0:
                time.sleep(wait)
            ready = {}
            for m in late:
                try:
                    f.restart(m, ready_timeout=120)
                    ready[m] = True
                except Inconclusive as error:
                    ready[m] = False
                    _note(out, ev='late member not ready', role=m, error=str(error))
            time.sleep(5)
            r5, _ = _journal_records(f, ['me0', 'me1', 'me2'])
            positions = _ae_log_positions(f, out)
            obs = {'record5': r5, 'ae_log_positions': positions, 'late_ready': ready, 'record': record}
            verdict = judge_a4(obs)
        elif name == 'core-act-fwdfirst':
            _boot_engines(f)
            _steps(f, plan, order[:order.index('me_genesis')])
            started = {}
            for slot in ('fwd0', 'fwd1'):
                f.spawn(slot, f.slot_command(slot), f.slot_process_env(slot))
                started[slot] = _state(f, slot)['StartedAt']
            rows = []
            t = time.time()
            while time.time() - t < s['XVER_FWD_WAIT_S']:
                row = {}
                for slot in ('fwd0', 'fwd1'):
                    st = _state(f, slot)
                    row[slot] = [st['Running'], f.http(slot, f.m['ports']['forwarder_http'], '/ready').get('status')
                                 if st['Running'] else None]
                rows.append(row)
                time.sleep(1)
            _steps(f, plan, [s_ for s_ in order[order.index('me_genesis'):] if s_ != 'start_forwarders'])
            ready = True
            for slot in ('fwd0', 'fwd1'):
                try:
                    f.wait_http(slot, f.m['ports']['forwarder_http'], '/ready', timeout=90)
                    f.slots[slot] = f.slot_row(slot, f.slot_artifact(slot))
                except Inconclusive:
                    ready = False
            f.slots['shadow0'] = f.start_slot('shadow0')
            f.registry['boot']['phases']['forwarders_ready_ns'] = time.time_ns(); f.save()
            logs = {slot: _docker_logs(f, slot) for slot in ('fwd0', 'fwd1')}
            restarts = {slot: int(_state(f, slot)['StartedAt'] != started[slot]) for slot in ('fwd0', 'fwd1')}
            obs = {'wait_rows': rows, 'wait_s': s['XVER_FWD_WAIT_S'],
                   'epoch_waits': {k: v.count('waiting for the epoch') for k, v in logs.items()},
                   'bound_lines': {k: v.count('ME epoch bound') for k, v in logs.items()},
                   'resync': {k: v.count('RESYNC') for k, v in logs.items()}, 'restarts': restarts,
                   'ready_after_genesis': ready}
            obs['record'] = _record(f, out, _audit(f, out, 'audit.json'))
            verdict = judge_a5(obs)
        else:
            raise Inconclusive('unknown activation scenario: ' + name)
        (Path(out) / 'xact-observations.json').write_text(json.dumps(obs, indent=1, default=str) + '\n')
        return _result(verdict, {'case': case_for(name, 's17-act'), 'row': CASES[case_for(name, 's17-act')]['row']}, [f], 6)
    finally:
        f.close()


def _ae_log_positions(f, out, bound_s=30):
    """X-A4: ``ClusterTool list-members`` on each AE member until the members' logPositions are equal (quiescence) or the
    bound passes; the outputs are evidence."""
    from core_fixture import JAVA
    positions = {}
    t = time.time()
    while time.time() - t < bound_s:
        positions = {}
        for i in range(3):
            role = f'ae{i}'
            argv = JAVA + [f'-Daeron.dir=/dev/shm/aeron-{role}' if f.engine_driver() == 'external' else '-Daeron.dir=/dev/shm/aeron',
                           '-cp', '/artifacts/ae.jar', 'io.aeron.cluster.ClusterTool', '/data/state/cluster', 'list-members']
            r = f.execute(role, argv, timeout=60, check=False, accepted=tuple(range(256)))
            text = (r.stdout or '') + (r.stderr or '')
            _note(out, ev='list-members', role=role, out=text[-800:])
            own = re.search(r'memberId=(\d+)', text)
            members = dict(re.findall(r'ClusterMember\{id=(\d+).*?logPosition=(-?\d+)', text))
            if own and own.group(1) in members:
                positions[role] = int(members[own.group(1)])
        if len(positions) == 3 and len(set(positions.values())) == 1:
            break
        time.sleep(3)
    return positions


# ------------------------------------------------------------------ X-R (6.9)

def run_rollback(manifest, out, s, omit=None):
    import legacy_tag
    import r10_cut
    from core_fixture import CoreFixture
    import core_scenarios
    from scenarios import critical_path_smoke, request, money
    from contracts import FP
    out = Path(out)
    archive = out / 'archive'
    tag = re.sub(r'[^a-z0-9-]', '', out.name.lower())[-10:] or 'x'
    l1, _ = legacy_tag.legacy_manifest(f'xr-{tag}-l1', s['XVER_LEGACY_OCTET'], B0 / 'local-runs/s17/legacy-xr')
    l2_path = None
    result = {'case': 'control:' + (omit or '') if omit else 'X-R', 'row': '49', 'omit': omit}
    fixtures = []
    # 1, 2: the tag line, D0, the archive
    f1 = legacy_tag.LegacyTagFixture(l1)
    try:
        f1.start()
        smoke = critical_path_smoke(f1)
        (archive / 'db').mkdir(parents=True)
        d0 = legacy_tag.dump_d(f1, keep=archive / 'db')
        f1.stop_engines()
        for name in ('oms', 'market', 'bridge', 'projector'):
            f1.command(['docker', 'kill', f1.registry['containers'][name]], check=False)
        shutil.copytree(f1.root / 'state', archive / 'state', symlinks=True)
        inventory = {p.name: legacy_tag.tree_hash(p) for p in sorted((archive / 'state').iterdir())}
        (out / 'archive-inventory.json').write_text(json.dumps({'state_trees': inventory, 'D0': d0, 'smoke': smoke['status'],
                                                                'not_in_the_rig': ['host aeronmd dir and binary', 'unit files',
                                                                                   'cloud-console state']}, indent=1) + '\n')
    finally:
        f1.close()
    # 3: the forward order on wiped roots: precheck, cut genesis, traffic
    c = CoreFixture(manifest, drill=True)
    fixtures.append(c)
    try:
        pre = r10_cut.precheck([c.root], pg_rows={})
        (out / 'precheck.json').write_text(json.dumps(pre, indent=1) + '\n')
        if pre['status'] != 'CLEAN':
            raise Inconclusive(f'precheck refused the forward order: {pre["refusals"]}')
        c.start(core_scenarios.SMOKE_PLAN)
        result['forward'] = {'gate': c.tap_gate(0), 'funding': len(c.registry.get('funding') or [])}
        _record(c, out, _audit(c, out, 'audit-forward.json'), 'rc2-activation-record.forward.json')
    finally:
        c.close()
    # 4, 5: restore every archived item (or all but ``omit``) into a fresh legacy root on the same addresses; D1; new traffic
    l2_path, _ = legacy_tag.legacy_manifest(f'xr-{tag}-l2', s['XVER_LEGACY_OCTET'], B0 / 'local-runs/s17/legacy-xr')
    l2 = json.loads(l2_path.read_text())
    l1m = json.loads(Path(l1).read_text())
    l2['nodes'] = l1m['nodes']
    l2_path.write_text(json.dumps(l2, indent=1) + '\n')
    d1, post, error = None, None, None
    f2 = RestoredLegacyFixture(l2_path)
    f2.archive, f2.omit = archive, omit
    try:
        f2.start()
        f2.restore_market()
        d1 = legacy_tag.dump_d(f2)
        before = d1['combined']
        post = {'deposits': [], 'orders': []}
        for u in (72001, 72002):
            r = request(f2, 'POST', f'/api/v1/accounts/{u}/deposit', {'assetId': 0, 'amount': money(10000 * FP)}, u)
            post['deposits'].append(bool(r.get('success')))
        for k in range(3):
            r = request(f2, 'POST', '/api/v1/orders', {'marketId': 1, 'side': 'BUY', 'orderType': 'LIMIT',
                                                       'price': '1000.00000000', 'quantity': '0.01000000',
                                                       'clientOrderId': f'{f2.run_id}-post-{k}'}, 72001)
            post['orders'].append(bool(r.get('accepted')))
        post['changed'] = legacy_tag.dump_d(f2)['combined'] != before
    except Exception as e:
        error = f'{type(e).__name__}: {str(e)[:300]}'
    finally:
        try:
            f2.close()
        except Exception as e:
            error = error or f'teardown: {e}'
    verdict = judge_rollback(d0, d1, post, omitted=omit, error=error)
    (out / 'xr-dumps.json').write_text(json.dumps({'D0': d0, 'D1': d1, 'post': post, 'error': error}, indent=1) + '\n')
    result.update(legacy_manifests=[str(l1), str(l2_path)], D0=d0['combined'], D1=(d1 or {}).get('combined'))
    return _result(verdict, result, fixtures, 4)


class RestoredLegacyFixture(SeededLegacyFixture):
    """X-R step 4-5: every engine state tree and the OMS/money dumps restored (``omit``: ``ae-money-journal`` drops the AE
    archive recordings other than the cluster log; ``pg-dump`` drops the r01_money dump); r01_market rows are reloaded after
    the market gateway created its hypertable (20.1 line 21)."""
    archive, omit = None, None

    def spawn(self, name, command, environment=None):
        src = self.archive / 'state' / name
        if name[:2] in ('me', 'ae') and src.is_dir() and name not in (self.seeds or {}):
            import legacy_tag
            self.seed(name, src, legacy_tag.tree_hash(src)['sha256'])
            if self.omit == 'ae-money-journal' and name.startswith('ae'):
                import r10_cut
                log = self.root / 'state' / name / 'state' / 'cluster' / 'recording.log'
                keep = {e['recording_id'] for e in r10_cut.recording_log(log) if e['type'] == 'TERM'}
                for rec in (self.root / 'state' / name / 'state' / 'archive').glob('*.rec'):
                    if int(rec.name.split('-')[0]) not in keep:
                        rec.unlink()
        return super().spawn(name, command, environment)

    def start_database(self):
        super().start_database()
        for db in ('r01_oms', 'r01_money'):
            if self.omit == 'pg-dump' and db == 'r01_money':
                continue
            sql = (self.archive / 'db' / f'{db}.dump.sql').read_text()
            r = subprocess.run([str(self.pg / 'psql'), '-h', self.gateway, '-p', str(self.pg_port), '-U', 'runtime_fixture', '-d',
                                db, '-v', 'ON_ERROR_STOP=1', '-q'], input=sql, capture_output=True, text=True)
            if r.returncode:
                raise Inconclusive(f'restore of {db} failed: {r.stderr[:300]}')

    def restore_market(self):
        import legacy_tag
        by = {}
        for line in (self.archive / 'db' / 'r01_market.dump.sql').read_text().splitlines():
            if line.startswith('INSERT '):
                _, table, row = line.split(' ', 2)
                by.setdefault(table, []).append(row)
        for table, rows in by.items():
            if not re.fullmatch(r'[a-z_][a-z0-9_]*', table):
                raise Violation('unexpected market table ' + table)
            legacy_tag._psql_out(self, 'r01_market', f'COPY public.{table} FROM STDIN WITH (FORMAT csv)', inp='\n'.join(rows) + '\n')


# ------------------------------------------------------------------ entry

def scenario(manifest_path, name, out_dir):
    """runner.py entry for ``core-xver-*``, ``core-act-*`` and ``core-rollback-*``. Each scenario owns its fixtures and closes
    them; the result carries the case, the verdict and the child exit codes of every core fixture."""
    m = json.loads(Path(manifest_path).read_text())
    case = case_for(name, m.get('manifest_kind'))
    s = settings()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'settings.json').write_text(json.dumps({'settings': s, 'seeds': str(SEEDS), 'cut': str(CUT), 'case': case}, indent=1))
    if case.startswith('control:'):
        if name in ('core-xver-ctl-me-same', 'core-xver-ctl-ae-same'):
            return run_same_control(manifest_path, name, out, s)
        if name.endswith('-old-same'):
            return run_old_same_control(manifest_path, name, out, s)
        if name == 'core-xver-ctl-x7-wiped':
            return run_x7(manifest_path, out, s, wiped=True)
        return run_rollback(manifest_path, out, s, omit=CONTROLS[name]['omit'])
    if case.startswith(('X-1', 'X-3')):
        return run_state_case(manifest_path, case, out, s)
    if case == 'X-7':
        return run_x7(manifest_path, out, s)
    if case.startswith('X-A'):
        return run_act(manifest_path, name, out, s)
    return run_rollback(manifest_path, out, s)
