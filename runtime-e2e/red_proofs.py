# SPDX-License-Identifier: Apache-2.0
"""The red proofs of the core topology: oracles that read history cannot PASS, and one writer per table.

Three scenario ids, dispatched by runner.py on a manifest of a critical-path kind (``cps``, ``cps-ext``) or, for the
first, a projector drop-control kind (``pj-nc-dropone``, ``pj-nc-dropone-ext``):

* ``core-control-pgorders``: the order oracle fed from the order history projection on a projection that provably
  diverged from the core. Two forms, chosen by the kind: (a) on a drop-control kind every projector acknowledges one
  journal record (journalSeq 2, the build's default) and never writes it; the workload makes that record the last of its
  order (the first order rests and its acknowledgement is waited for before anything else is sent), so the final
  ``oe_orders`` row differs, not only the event dump; (b) on ``cps`` pj0 is frozen (SIGSTOP) before the last batch. After
  the barrier: the product oracles on the core sample, the divergence (the live rows and event sequences the PG-sourced
  oracle reads against the core's order dump and tap), the PG-sourced sample (pg_control: an explicit field map), and the
  order oracle on it. The control holds when the product oracles PASS, the divergence holds and the PG-sourced oracle
  does not PASS, failing on O4, O5 or O6. If it PASSes: ``oracle passed from PG orders``.
* ``core-control-stale-money-history``: the money twin. The money projector (``projector``) is frozen before the last
  batch, and the last batch lands a deposit, a withdrawal and a fill after the freeze (each recorded against the freeze
  time and the frozen history's head). The money oracle reads the money history from PostgreSQL; on the stale copy it
  must not PASS (M13, M14 or the barrier). If it PASSes: ``money oracle passed on a stale money history``.
* ``core-table-owners``: one writer role per relation in every fixture database (core_contracts.TABLE_OWNERS), at most
  the retention role beside it with DELETE and TRUNCATE, no process kind on the bootstrap superuser login, tables and
  views judged apart (table_owners). The listing is taken after every writer created its relations.

Controls: the setting ``RED_CONTROL`` (CONTROLS: one rule switched off or one input planted, recorded with the run). A
control run passes when a judged line fails with exactly the control's text and no other judged line fails (smoke_core
verdict); a vacuity control ends INCONCLUSIVE with its text. Sizes and bounds are settings (SETTINGS), recorded.
"""
import json
import os
from pathlib import Path
import time

from contracts import FP, Inconclusive, Violation
import core_contracts
import order_oracle
import pg_control
import table_owners
from gateway_scenarios import line
from smoke_core import (LOW_BUY, QUOTE_ASSET, REST_PRICE, UNIT, CriticalPathDrill, consequence, money_call, new_key,
                        order_call, order_id_of)

SCENARIOS = ('core-control-pgorders', 'core-control-stale-money-history', 'core-table-owners')
SETTINGS = {
    # crossing pairs before the freeze and in the last batch; how long the frozen state is held after the last batch
    'RED_PAIRS': 4, 'RED_LAST_PAIRS': 2, 'RED_SETTLE_S': 3,
    # polls of an order, of the money history and of the relations' existence (drill bounds, never limits of a binary)
    'RED_WAIT_S': 20, 'RED_CATCHUP_S': 60,
}
MONEY_PASSED_TEXT = 'money oracle passed on a stale money history'
MONEY_AT_HEAD_TEXT = 'control vacuous: money history at the head'
NO_MOVEMENT_TEXT = 'control vacuous: no money movement after the freeze'
CONTROLS = {
    'pg-no-freeze': ('core-control-pgorders', pg_control.VACUOUS_TEXT, True),
    'money-no-freeze': ('core-control-stale-money-history', MONEY_AT_HEAD_TEXT, True),
    'money-creates-only': ('core-control-stale-money-history', NO_MOVEMENT_TEXT, True),
    'owners-gateway-insert': ('core-table-owners', 'second writer on oe_orders: ' + core_contracts.GATEWAY_LOGIN, False),
    'owners-retention-insert': ('core-table-owners', 'retention role can insert: md_trades', False),
    'owners-late-default-privileges': ('core-table-owners', 'retention role has no grant:', False),
    'owners-third-delete-role': ('core-table-owners', 'unnamed delete role on money_journal: planted_cleaner', False),
}
CONTROL_SETTING = 'RED_CONTROL'
USER_BASE = {'core-control-pgorders': 94001, 'core-control-stale-money-history': 95001, 'core-table-owners': 96001}
PLANTED_DELETE_ROLE = 'planted_cleaner'
DROP_KINDS = {'pj-nc-dropone', 'pj-nc-dropone-ext'}
KINDS = {'core-control-pgorders': {'cps', 'cps-ext'} | DROP_KINDS,
         'core-control-stale-money-history': {'cps', 'cps-ext'}, 'core-table-owners': {'cps', 'cps-ext'}}


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


def control_of(name, environ=os.environ):
    setting = environ.get(CONTROL_SETTING) or None
    if setting is None:
        return None
    if setting not in CONTROLS:
        raise Violation(f'{CONTROL_SETTING} is one of {", ".join(sorted(CONTROLS))}, got {setting!r}')
    scenario, text, inconclusive = CONTROLS[setting]
    if scenario != name:
        raise Inconclusive(f'{CONTROL_SETTING}={setting} is a control of {scenario}, not of {name}')
    return setting, text, inconclusive


def check_scenario(manifest, name, environ=os.environ):
    """Before any container starts: the scenario's kinds only, the projector binary in pj0 and pj1, the product gateway
    and stream binaries, forwarders running. Returns the run's control or None."""
    if not is_scenario(name):
        raise Inconclusive('unknown red-proof scenario: ' + name)
    kind = manifest.get('manifest_kind')
    if kind not in KINDS[name]:
        raise Inconclusive(f'{name} runs on {", ".join(sorted(KINDS[name]))}; this manifest is {kind}')
    slots = manifest.get('slot_artifacts') or {}
    wanted = {'gw0': 'gateway', 'gw1': 'gateway', 'st0': 'stream', 'st1': 'stream'}
    wrong = {k: slots.get(k) for k, v in wanted.items() if slots.get(k) != v}
    if wrong or not {slots.get('pj0'), slots.get('pj1')} <= {'history_projector', 'history_projector_nc'}:
        raise Inconclusive(f'{name} runs on the product binaries in the user-facing slots; this kind stages '
                           + ', '.join(f'{k}={v}' for k, v in sorted(slots.items()) if k in wanted or k.startswith('pj')))
    if not any(slots.get(s) for s in ('fwd0', 'fwd1')):
        raise Inconclusive(f'{name} needs the forwarders; {kind} runs none')
    if kind in DROP_KINDS and (core_contracts.GATEWAY_KINDS[kind].get('projector_define') != 'PROJ_NC_DROP_ONE'):
        raise Inconclusive(f'{kind} is not the projector drop control')
    return control_of(name, environ)


def scenario(fixture, name, out_dir):
    """runner.py entry for the red-proof scenario ids."""
    control = check_scenario(fixture.m, name)
    cls = {'core-control-pgorders': PgOrdersDrill, 'core-control-stale-money-history': StaleMoneyDrill,
           'core-table-owners': TableOwnersDrill}[name]
    result = cls(fixture, name, Path(out_dir) / 'drill', control).run()
    return dict(result, assertions=len(result['lines']), processed=1, skipped=0, child_exit_codes=[0],
                scope=f'{name} on {fixture.m.get("manifest_kind")} (engines {fixture.engine_driver()})')


# ------------------------------------------------------------------ pure lines

def movement_after_freeze(log, sample, frozen_at_ns, frozen_trade):
    """The money movements the core decided after the freeze: an acknowledged deposit and withdrawal sent after it, and an
    ME trade above the frozen history's last settled trade (applied by the core). Holds when all three landed; none is
    the vacuity (INCONCLUSIVE); some is a FAIL naming the part missing."""
    def acked(kind):
        return [r for r in log if r['path'] == f'/api/v2/balances/{kind}' and 200 <= r['status'] < 300
                and r['sent_ns'] > frozen_at_ns]
    applied = (sample.get('core') or {}).get('last_applied_trade_id') or 0
    trades = sorted(t['trade_id'] for t in sample.get('me_journal') or [] if t.get('type') == 'trade'
                    and t['trade_id'] > frozen_trade and t['trade_id'] <= applied)
    parts = {'deposit': len(acked('deposit')), 'withdrawal': len(acked('withdraw')), 'fill': len(trades)}
    detail = dict(parts, frozen_at_ns=frozen_at_ns, frozen_history_last_trade=frozen_trade, trades_after=trades[:10],
                  core_last_applied_trade=applied)
    if not any(parts.values()):
        return line(False, detail, NO_MOVEMENT_TEXT, inconclusive=True)
    missing = [k for k, v in parts.items() if not v]
    return line(not missing, detail, 'money movement after the freeze incomplete: ' + (missing[0] if missing else ''))


def history_behind(sample):
    """The money history against what the core decided: one record per acknowledged funding row and per ME trade the
    core applied. Behind holds; equal is the vacuity (INCONCLUSIVE); ahead is a FAIL."""
    applied = (sample.get('core') or {}).get('last_applied_trade_id') or 0
    funding = sum(1 for r in sample.get('funding') or [] if r.get('outcome') == 'ACK')
    trades = sum(1 for t in sample.get('me_journal') or [] if t.get('type') == 'trade' and t['trade_id'] <= applied)
    have = len(sample.get('money_journal') or [])
    detail = {'decided_records': funding + trades, 'funding_acked': funding, 'trades_applied': trades,
              'money_history_records': have}
    if have == funding + trades:
        return line(False, detail, MONEY_AT_HEAD_TEXT, inconclusive=True)
    return line(have < funding + trades, detail, 'money history ahead of the core')


def money_lines(money, order):
    failing = sorted(k for k, v in (money.get('rules') or {}).items() if v.get('status') == 'FAIL')
    unsure = sorted(k for k, v in (money.get('rules') or {}).items() if v.get('status') == 'INCONCLUSIVE')
    barrier = 'barrier' in str(money.get('error') or '')
    named = sorted((set(failing) | set(unsure)) & {'M13', 'M14'}) + (['barrier'] if barrier else [])
    return {
        'product_order_oracle': line(order['status'] == 'PASS', {'status': order['status']}, 'order oracle not PASS',
                                     inconclusive=order['status'] == 'INCONCLUSIVE'),
        'money_oracle_not_pass': consequence(line(money['status'] != 'PASS',
                                                  {'status': money['status'], 'failing': failing, 'inconclusive': unsure,
                                                   'error': money.get('error'),
                                                   'details': {k: v.get('detail') for k, v in (money.get('rules') or {}).items()
                                                               if v.get('status') != 'PASS'}},
                                                  MONEY_PASSED_TEXT), 'money_history_behind'),
        'money_oracle_names_staleness': consequence(line(bool(named), {'named': named},
                                                         'money oracle failed outside M13, M14 and the barrier'),
                                                    'money_oracle_not_pass'),
    }


# ------------------------------------------------------------------ the drills

class RedDrill(CriticalPathDrill):
    def __init__(self, fixture, name, out_dir, control):
        super().__init__(fixture, name, out_dir, control)
        self.r = settings()
        self.record['red_settings'] = self.r

    def users(self, n=2):
        base = USER_BASE[self.name]
        return list(range(base, base + n))

    def wait_status(self, user, order, statuses, bound_s=None):
        state, waited = self.wait_for(lambda: (lambda s: s if s.get('status') in statuses else None)(self.order_state(user, order)),
                                      bound_s or self.r['RED_WAIT_S'])
        return {'order': order, 'state': (state or {}).get('status'), 'waited_s': waited}

    def finish_lines(self, lines, extra_files=None):
        for name, value in (extra_files or {}).items():
            (self.out / name).write_text(json.dumps(value, indent=1, default=str) + '\n')
        return self.finish(lines)


class PgOrdersDrill(RedDrill):
    """Row: an oracle that reads PG orders cannot PASS (see the module text)."""

    def pg_progress(self):
        """(orders, FILLED orders) in pj0's oe_orders, (0, 0) while unreadable."""
        try:
            # no failing child command while the projector has not created its schema yet
            if self.f.psql('r01_gateway', "SELECT to_regclass('public.oe_orders') IS NOT NULL") != 't':
                return 0, 0
            text = self.f.psql('r01_gateway', "SELECT count(*) || ' ' || count(*) FILTER (WHERE status = 'FILLED') "
                                              'FROM oe_orders')
            orders, filled = (int(x) for x in text.split())
            return orders, filled
        except (Inconclusive, Violation, ValueError):
            return 0, 0

    def run(self):
        f, r = self.f, self.r
        form = 'a' if f.m.get('manifest_kind') in DROP_KINDS else 'b'
        self.record['form'] = form
        a, b = self.users()
        self.boot_cps([a, b])
        work = {'fund': self.fund(a, b)}
        # the first order rests; its acknowledgement (the record after its acceptance, journalSeq 2) is waited for before
        # anything else is sent, so in form (a) the dropped record is the last of its order
        first = self.one(order_call(a, 'BUY', LOW_BUY, 5 * UNIT, 'rest-first'))
        first_id = order_id_of(first)
        work['first'] = self.wait_status(a, first_id, {'NEW'}) if first_id else None
        work['pairs'] = [x['status'] for x in self.pairs(a, b, r['RED_PAIRS'], 2)]
        frozen = None
        if form == 'b':
            # the projection holds everything before the last batch (the orders created so far, the pairs filled), so
            # what the freeze leaves out is the last batch only
            created = len(self.orders_by_user().get(a, set()) | self.orders_by_user().get(b, set()))
            filled = 2 * r['RED_PAIRS']
            caught, waited = self.wait_for(lambda: self.pg_progress()[0] >= created and self.pg_progress()[1] >= filled,
                                           r['RED_CATCHUP_S'])
            self.record['before_freeze'] = {'caught_up': bool(caught), 'orders_created': created, 'filled_wanted': filled,
                                            'pg': self.pg_progress(), 'waited_s': waited}
            if self.control_name != 'pg-no-freeze':
                frozen = f.freeze_main('pj0', duration_s=r['RED_CATCHUP_S'] * 4)
                self.record['pg_at_freeze'] = self.pg_progress()
        self.record['freeze'] = frozen
        self.mark('last_batch')
        # the last batch: a resting order partly filled by a smaller taker, and more crossing pairs
        rest = self.one(order_call(b, 'SELL', REST_PRICE, 50 * UNIT, 'rest-last'))
        rest_id = order_id_of(rest)
        work['rest'] = self.wait_status(b, rest_id, {'NEW'}) if rest_id else None
        work['taker'] = self.one(order_call(a, 'BUY', REST_PRICE, 20 * UNIT, 'partial-taker'))['status']
        work['partial'] = self.wait_status(b, rest_id, {'PARTIALLY_FILLED'}) if rest_id else None
        work['last_pairs'] = [x['status'] for x in self.pairs(a, b, r['RED_LAST_PAIRS'], 1, tag='last-pair')]
        self.record['work'] = work
        self.mark('input_closed')
        self.sleep(r['RED_SETTLE_S'])
        money, order, sample = self.oracle()
        head = max((e['seq'] for e in sample.get('core_events') or []), default=0)
        if self.control_name == 'pg-no-freeze':
            # the vacuity control: the projection caught up before PG is read
            self.record['history_catchup'] = self.wait_history(head, r['RED_CATCHUP_S'])
        pg = pg_control.read_pg(f.psql, 'r01_gateway')
        self.record['pg_applied_seq'] = self.history_head()
        differs, detail = pg_control.divergence(sample, pg)
        detail['core_event_head'] = head
        try:
            variant = pg_control.pg_sample(sample, pg)
            pg_verdict = order_oracle.judge(variant)
        except Inconclusive as error:
            variant, pg_verdict = None, {'status': 'INCONCLUSIVE', 'rules': {}, 'error': str(error)}
        lines = pg_control.control_lines(money, order, differs, detail, pg_verdict)
        lines['pg_oracle_not_pass']['consequence_of'] = 'divergence'
        if form == 'a':
            lines['dropped_record_last_of_its_order'] = dropped_line(sample, 2)
        else:
            lines['frozen_before_last_batch'] = line(frozen is not None or self.control_name == 'pg-no-freeze',
                                                     {'freeze': frozen}, 'pj0 was never frozen')
        if frozen is not None:
            thaw = f.thaw_main('pj0')
            self.record['thaw'] = thaw
            self.record['after_thaw'] = self.wait_history(head, r['RED_CATCHUP_S'])
            if self.record['after_thaw']['caught_up']:
                f.close_fault('pj0')
        return self.finish_lines(lines, {'pg-read.json': pg, 'pg-oracle.json': pg_verdict,
                                         'pg-sample.json': variant if variant is not None else {}})


def dropped_line(sample, seq):
    """Form (a)'s precondition: the core's record journalSeq ``seq`` is the last record of its order, so the projection
    that never writes it keeps a final row that differs from the core."""
    events = sorted(sample.get('core_events') or [], key=lambda e: e['seq'])
    hit = next((e for e in events if e['seq'] == seq), None)
    later = [e['seq'] for e in events if hit and e['order'] == hit['order'] and e['seq'] > seq]
    return line(hit is not None and not later, {'record': hit, 'later_records_of_its_order': later},
                'dropped record is not the last of its order', inconclusive=hit is None or bool(later))


class StaleMoneyDrill(RedDrill):
    """Row: the money twin (see the module text)."""

    def money_history_head(self):
        """(records, last settled trade) of the money history as PostgreSQL holds it now."""
        text = self.f.psql('r01_money', "SELECT count(*) || ' ' || COALESCE(max(trade_id), 0) FROM money_journal")
        count, trade = (int(x) for x in text.split())
        return count, trade

    def run(self):
        f, r = self.f, self.r
        a, b = self.users()
        self.boot_cps([a, b])
        work = {'fund': [x['status'] for x in self.fund(a, b)], 'pairs': [x['status'] for x in self.pairs(a, b, r['RED_PAIRS'], 2)]}
        # the money history reaches the decided records before the freeze, so what the freeze leaves out is the last batch
        decided = 2 + r['RED_PAIRS']
        _, waited = self.wait_for(lambda: self.money_history_head()[0] >= decided, r['RED_CATCHUP_S'])
        frozen = None
        if self.control_name != 'money-no-freeze':
            frozen = f.freeze_main('projector', duration_s=r['RED_CATCHUP_S'] * 4)
        frozen_at_ns = time.time_ns()
        records, frozen_trade = self.money_history_head()
        self.record['freeze'] = {'fault': frozen, 'at_ns': frozen_at_ns, 'history_records': records,
                                 'history_last_trade': frozen_trade, 'waited_s': waited}
        self.mark('last_batch')
        if self.control_name == 'money-creates-only':
            placed = self.one(order_call(a, 'BUY', LOW_BUY, 3 * UNIT, 'create-after-freeze'))
            oid = order_id_of(placed)
            work['last'] = [placed['status']]
            if oid:
                work['last'].append(self.one({'user': a, 'method': 'DELETE', 'path': f'/api/v2/orders/{oid}',
                                              'key': new_key(), 'tag': 'cancel-after-freeze'})['status'])
        else:
            work['last'] = [x['status'] for x in self.calls([
                money_call(a, 'deposit', QUOTE_ASSET, 10 * FP, 'deposit-after-freeze'),
                money_call(a, 'withdraw', QUOTE_ASSET, 5 * FP, 'withdraw-after-freeze')])]
            work['last_pairs'] = [x['status'] for x in self.pairs(a, b, r['RED_LAST_PAIRS'], 1, tag='pair-after-freeze')]
        self.record['work'] = work
        self.mark('input_closed')
        self.sleep(r['RED_SETTLE_S'])
        money, order, sample = self.oracle()
        lines = {'money_after_freeze': movement_after_freeze(self.log, sample, frozen_at_ns, frozen_trade),
                 'money_history_behind': consequence(history_behind(sample), 'money_after_freeze')}
        lines.update(money_lines(money, order))
        if self.control_name != 'money-no-freeze':
            lines['frozen_before_last_batch'] = line(frozen is not None, {'freeze': frozen}, 'money projector was never frozen')
        if frozen is not None:
            self.record['thaw'] = f.thaw_main('projector')
            target = history_behind(sample)['detail']['decided_records']
            caught, waited = self.wait_for(lambda: self.money_history_head()[0] >= target, r['RED_CATCHUP_S'])
            self.record['after_thaw'] = {'caught_up': bool(caught), 'target_records': target,
                                         'records': self.money_history_head()[0], 'waited_s': waited}
            if caught:
                f.close_fault('projector')
        return self.finish_lines(lines)


class TableOwnersDrill(RedDrill):
    """Row: one writer per table (see the module text and table_owners)."""

    def relations_exist(self):
        checks = {'r01_money': 'money_journal', 'r01_gateway': 'oe_orders', 'r01_history_b': 'oe_orders',
                  core_contracts.MARKETDATA_DATABASE: 'md_trades'}
        try:
            return all(self.f.psql(db, f"SELECT to_regclass('public.{rel}') IS NOT NULL") == 't' for db, rel in checks.items())
        except (Inconclusive, Violation):
            return False

    def run(self):
        f, r = self.f, self.r
        if self.control_name == 'owners-late-default-privileges':
            f.deferred_default_privileges = frozenset({'r01_gateway'})
        a, b = self.users()
        self.boot_cps([a, b])
        work = {'fund': [x['status'] for x in self.fund(a, b)], 'pairs': [x['status'] for x in self.pairs(a, b, r['RED_PAIRS'], 2)]}
        exists, waited = self.wait_for(self.relations_exist, r['RED_CATCHUP_S'])
        work['relations_exist'] = {'all': bool(exists), 'waited_s': waited}
        planted = None
        if self.control_name == 'owners-late-default-privileges':
            f.set_default_privileges('r01_gateway')
            planted = 'default privileges of r01_gateway set after its writers created their relations'
        elif self.control_name == 'owners-gateway-insert':
            f.psql('r01_gateway', f'GRANT INSERT ON oe_orders TO {core_contracts.GATEWAY_LOGIN}')
            planted = f'GRANT INSERT ON oe_orders TO {core_contracts.GATEWAY_LOGIN}'
        elif self.control_name == 'owners-retention-insert':
            f.psql(core_contracts.MARKETDATA_DATABASE, f'GRANT INSERT ON md_trades TO {core_contracts.RETENTION_ROLE}')
            planted = f'GRANT INSERT ON md_trades TO {core_contracts.RETENTION_ROLE}'
        elif self.control_name == 'owners-third-delete-role':
            f.psql('postgres', f'CREATE ROLE {PLANTED_DELETE_ROLE} NOLOGIN')
            f.psql('r01_money', f'GRANT DELETE ON money_journal TO {PLANTED_DELETE_ROLE}')
            planted = f'GRANT DELETE ON money_journal TO {PLANTED_DELETE_ROLE}'
        self.record['planted'] = planted
        self.record['work'] = work
        listing = table_owners.take_listing(f)
        declared = table_owners.declared_logins(f)
        lines, info = table_owners.judge(listing, declared, f.m['nodes'])
        self.record['logins'] = info
        lines['relations_created'] = line(bool(exists), work['relations_exist'], 'a writer never created its relations',
                                          inconclusive=not exists)
        return self.finish_lines(lines, {'grants-listing.json': listing, 'declared-logins.json': declared})
