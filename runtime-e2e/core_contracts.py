# SPDX-License-Identifier: Apache-2.0
"""Manifest schema v2: the core topology.

The legacy schema v1 (OMS order entry, PostgreSQL order truth) stays in contracts.py for the frozen
v0.5 scenarios. v2 is the OMS + ledger core: ME x3, AE x3, two forwarder slots, two bridge slots, the
money projector, the shadow replica slot and the probe. A slot a manifest leaves empty declares ``null`` and is skipped,
never faked; the replica slot runs the core jar as ``CORE_ROLE=replica`` on the replica kinds (``REPLICA_KINDS``).
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

from contracts import Inconclusive, Violation, integer
import journal_decode

ENGINES = [e + str(i) for e in ('me', 'ae') for i in range(3)]
SLOTS = {'fwd0': 'forwarder', 'fwd1': 'forwarder', 'bridge0': 'bridge', 'bridge1': 'bridge', 'shadow0': 'shadow'}
ROLES = set(ENGINES) | set(SLOTS) | {'projector', 'probe'}
LEGACY_ROLES = {'oms', 'market', 'bridge', 'xprojector'}
REQUIRED_JARS = ['ae', 'me', 'projector']
OPTIONAL_BINARIES = ['forwarder', 'forwarder_b', 'bridge', 'bridge_b', 'shadow']
SLOT_ARTIFACTS = {'fwd0': {'forwarder', 'forwarder_b'}, 'fwd1': {'forwarder', 'forwarder_b'},
                  'bridge0': {'bridge', 'bridge_b'}, 'bridge1': {'bridge', 'bridge_b'}, 'shadow0': {'shadow'}}
PORT_PROFILE = {'me_base': 9000, 'ae_base': 19300, 'stride': 100, 'me_metrics': 19500, 'ae_metrics': 19700,
                'bridge_http': 9600, 'projector_http': 9601, 'forwarder_http': 9700, 'journal_replay': 19820,
                'shadow_metrics': 19703}
# The user-facing slots: two order gateways (oe-gateway) and two user streams (oe-stream), each in its own 1-CPU container
# and its own cluster session. A manifest declares all four roles or none (older manifests have none); a declared slot
# may be null (skipped, never faked). Each slot may run the product binary or, in a rig kind, a test-only alternative:
#   gateway_nc    oe-gateway of the cut's gateway commit built with one control define (the kind's ``nc_define``)
#   gateway_stub  the test-only HTTP shim over CoreProbe verbs (gateway_shim.py, never published): gateway dry runs
#   session_stub  ct_session_stub of the cut's cluster-tools commit (never published): stream dry runs
GATEWAY_SLOTS = {'gw0': 'gateway', 'gw1': 'gateway', 'st0': 'stream', 'st1': 'stream'}
GATEWAY_ROLES = set(GATEWAY_SLOTS)
GATEWAY_BINARIES = ['gateway', 'gateway_nc', 'stream', 'gateway_stub', 'session_stub']
GATEWAY_SLOT_ARTIFACTS = {'gw0': {'gateway', 'gateway_nc', 'gateway_stub'}, 'gw1': {'gateway', 'gateway_nc', 'gateway_stub'},
                          'st0': {'stream', 'session_stub'}, 'st1': {'stream', 'session_stub'}}
# The test-only alternatives: refused in a product kind (release_cut K3), each checked against the cut it claims
GATEWAY_TEST_ARTIFACTS = {'gateway_nc', 'gateway_stub', 'session_stub'}
# The control defines a gateway_nc build may carry (the gateway's own control names, CoreSession.h and GatewayRoutes.cpp)
GATEWAY_NC_DEFINES = {'GW_NC_FRESH_KEY', 'GW_NC_NO_CANCEL_REOFFER_RULE', 'GW_NC_NO_ASSET_CHECK', 'GW_NC_NO_STALE_LABEL'}
# Ports of the gateway roles (every role has its own address, so gw0 and gw1 share the numbers)
GATEWAY_PORTS = {'gateway_http': 8080, 'gateway_admin': 8081, 'stream_ws': 8090, 'stream_admin': 8091, 'shim_http': 8085}
# The history projection's slots: two projector copies, each in its own container, each on its own GATEWAY key (the head
# probe's session class). A manifest declares both or neither, and only on a gateway manifest (pj0 writes the database the
# gateways read history from). A declared slot may be null. A slot runs the projector binary (history_projector,
# oe-projector of the cut's gateway commit) or, in a rig kind, a test-only alternative:
#   history_projector_nc  oe-projector of the cut's gateway commit built with one control define
#                         (-DOE_PROJECTOR_CONTROL=<PROJ_NC_...>, an install tree holding oe-projector alone; never
#                         published). The drop control also reads PROJ_NC_DROP_SEQ from its environment (default 2: the
#                         journalSeq it acknowledges and never writes); the fixture leaves it at that default.
#   projector_stub        projector_stub.py (never published): the projection drills' dry runs before the binary existed
PROJECTION_SLOTS = {'pj0': 'history_projector', 'pj1': 'history_projector'}
PROJECTION_ROLES = set(PROJECTION_SLOTS)
PROJECTION_BINARIES = ['history_projector', 'history_projector_nc', 'projector_stub']
PROJECTION_SLOT_ARTIFACTS = {s: {'history_projector', 'history_projector_nc', 'projector_stub'} for s in ('pj0', 'pj1')}
PROJECTION_TEST_ARTIFACTS = {'history_projector_nc', 'projector_stub'}
PROJECTION_TARGETS = {'history_projector': 'oe-projector', 'history_projector_nc': 'oe-projector',
                      'projector_stub': 'projector_stub'}
# The control defines a history_projector_nc build may carry (the gateway's own names, projector/*.h)
PROJECTION_NC_DEFINES = {'PROJ_NC_PIN_RECORDING', 'PROJ_NC_NO_STOP_REPLAY', 'PROJ_NC_WALLCLOCK_COLUMN', 'PROJ_NC_DROP_ONE',
                         'PROJ_NC_BEAT_ALWAYS'}
PROJECTION_PORTS = {'projector_admin': 8095}
# The projector binary's journal and session settings on the fixture (gateway README "History projector"): the core's
# order journal (stream 4102 on the archive's control stream 10, recorded over IPC at the members' IPC MTU), the replay
# stream the members' replay gauge counts (CORE_ARCHIVE_REPLAY_PROBE_STREAM on the core members). Settings with
# defaults: leases, probes, back-offs and timeouts are never set, the binary runs on its own defaults.
HISTORY_PROJECTOR_JOURNAL = {'HISTORY_PROJECTOR_JOURNAL_CONTROL_STREAM': '10', 'HISTORY_PROJECTOR_JOURNAL_STREAM': '4102',
                             'HISTORY_PROJECTOR_JOURNAL_CHANNEL': 'aeron:ipc', 'HISTORY_PROJECTOR_JOURNAL_MTU': '1408',
                             'HISTORY_PROJECTOR_REPLAY_STREAM': '4302'}
# The fixture's PostgreSQL roles: the console's role plan (cloud-console services/historydb.go) on the fixture's database
# names. One login role per process kind, none of them the bootstrap superuser (initdb's, which only the harness itself
# uses: its reads, its drills' faults and the database steps below). A retention role that may only delete (DELETE and
# TRUNCATE through each writer's default privileges, set before that writer first starts, and SELECT on the two money
# tables its age delete reads) and that no process logs in as here. oe-stream logs in nowhere on the fixture (api-key
# auth only); its role is made as the console makes it.
FIXTURE_SUPERUSER = 'runtime_fixture'
MONEY_PROJECTOR_LOGIN = 'core'
GATEWAY_LOGIN = 'oe_gateway'
STREAM_LOGIN = 'oe_stream'
HISTORY_PROJECTOR_LOGIN = 'oe_projector'
RETENTION_ROLE = 'history_retention'
# The login role the gateways read a projection database through on a kind that runs the projector binary: the gateway's
# own login, a member of the schema's reader group role (sql/history_projection_v1.sql), SELECT on the four read relations
HISTORY_READER_GROUP = 'oe_history_reader'
# The money database's read group of the balance movements view (core-projector V002 grants SELECT on the view to it and
# creates it only when the migrating role may create roles; like the console, the fixture creates it first, NOLOGIN)
MONEY_READER_GROUP = 'oe_money_reader'
HISTORY_READER_LOGIN = GATEWAY_LOGIN
# The stand-in's modes: ``follow`` beats only at the core's head; ``beat-always`` beats whatever the head (the freshness
# drill's control: stale history then reads fresh)
STUB_MODES = {'follow', 'beat-always'}
# The projection databases (the fixture's PostgreSQL): pj0 writes the gateways' database, pj1 a second one
PROJECTION_DATABASES = {'pj0': 'r01_gateway', 'pj1': 'r01_history_b'}
# The public market-data slot: oe-marketdata of the cut's gateway commit in md0, its own container and address, one
# GATEWAY-class session on the ME and the ME journal's archives as its trade path, writing the market history database
# under its own login role. A manifest declares md0 or not, and only next to the gateway roles. A declared slot may be
# null (not started). A cut of layout rc2-cut/5 lists oe-marketdata and the slot stages it; on an older cut the slot
# stages the product build of the cut's gateway commit that MK_MARKETDATA names (release_cut checks its stamp against the
# cut's gateway sha). ``marketdata_nc`` is a test build of the same commit (rig kinds only): oe-marketdata compiled with
# the test defines its ``defines`` list (a test seam such as the commit pause, or one rule switched off), and nothing else.
MARKETDATA_SLOTS = {'md0': 'marketdata'}
MARKETDATA_ROLES = set(MARKETDATA_SLOTS)
MARKETDATA_BINARIES = ['marketdata', 'marketdata_nc']
MARKETDATA_SLOT_ARTIFACTS = {'md0': {'marketdata', 'marketdata_nc'}}
MARKETDATA_TARGETS = {'marketdata': 'oe-marketdata', 'marketdata_nc': 'oe-marketdata'}
MARKETDATA_TEST_ARTIFACTS = {'marketdata_nc'}
# The test defines a marketdata_nc build may carry (gateway marketdata/*.cpp; never in a published binary):
#   MD_TC_COMMIT_PAUSE          each commit waits MDTC_COMMIT_PAUSE_MS before its COMMIT (the seam the writer is killed in)
#   MD_NC_COMMIT_SPLIT          with the pause: the cursor commits in a transaction of its own, before the rows
#   MD_NC_NO_EPOCH_CHECK        a record of another genesis taken like any other
#   MD_NC_EMPTY_SERIES          empty tape and candle series sent while the market history was down at the start
#   MD_NC_REST_FROM_MEMORY      GET /api/candles answers a failed history read with 200 and the candles in hand
#   MD_NC_NO_LIVE_EMIT_CURSOR   a trade read again is handed to the live path again
#   MD_NC_NO_STALL_CHECK        the journal follower never judges its source stalled (it never fails over)
MARKETDATA_NC_DEFINES = {'MD_TC_COMMIT_PAUSE', 'MD_NC_COMMIT_SPLIT', 'MD_NC_NO_EPOCH_CHECK', 'MD_NC_EMPTY_SERIES',
                         'MD_NC_REST_FROM_MEMORY', 'MD_NC_NO_LIVE_EMIT_CURSOR', 'MD_NC_NO_STALL_CHECK'}
# The commit-pause test build's two settings (read only by a build with MD_TC_COMMIT_PAUSE): the pause and the commits of
# the process that go through before the first pause
MARKETDATA_TEST_ENV = {'MDTC_COMMIT_PAUSE_MS', 'MDTC_COMMIT_PAUSE_SKIP'}
MARKETDATA_PORTS = {'md_public': 8110, 'md_admin': 8111}
# The market history database and its writer role (fixed names that cannot meet a legacy one); the service applies its
# own schema (sql/market_history_v1.sql) and owns every relation
MARKETDATA_DATABASE = 'oe_marketdata'
MARKETDATA_WRITER = 'oe_marketdata_writer'
# The login roles and the process kind of each (the retention role is the console's, never a fixture process)
LOGIN_ROLES = {MONEY_PROJECTOR_LOGIN: 'money projector', GATEWAY_LOGIN: 'oe-gateway', STREAM_LOGIN: 'oe-stream',
               HISTORY_PROJECTOR_LOGIN: 'oe-projector', MARKETDATA_WRITER: 'oe-marketdata', RETENTION_ROLE: 'console retention'}
# The database step of each fixture database (the console's historyDatabases on the fixture's names): its owner at
# creation, the roles granted CONNECT, the writers (USAGE and CREATE on schema public, and the retention role's default
# privileges when ``retention``), the readers (USAGE), each writer's default SELECT grantees, and the relations the
# retention role reads. CREATE on schema public is revoked from PUBLIC. r01_history_b (a second projection, drills only)
# has no retention role.
DATABASE_ROLE_PLAN = {
    'r01_money': {'owner': MONEY_PROJECTOR_LOGIN, 'connect': [MONEY_PROJECTOR_LOGIN, RETENTION_ROLE],
                  'writers': [MONEY_PROJECTOR_LOGIN], 'readers': [], 'default_select': {}, 'retention': True,
                  'retention_select': ['money_journal', 'money_journal_leg']},
    'r01_gateway': {'owner': GATEWAY_LOGIN, 'connect': [GATEWAY_LOGIN, STREAM_LOGIN, HISTORY_PROJECTOR_LOGIN, RETENTION_ROLE],
                    'writers': [GATEWAY_LOGIN, HISTORY_PROJECTOR_LOGIN], 'readers': [STREAM_LOGIN, HISTORY_READER_GROUP],
                    'default_select': {GATEWAY_LOGIN: [STREAM_LOGIN]}, 'retention': True, 'retention_select': []},
    'r01_history_b': {'owner': HISTORY_PROJECTOR_LOGIN, 'connect': [GATEWAY_LOGIN, HISTORY_PROJECTOR_LOGIN],
                      'writers': [HISTORY_PROJECTOR_LOGIN], 'readers': [HISTORY_READER_GROUP], 'default_select': {},
                      'retention': False, 'retention_select': []},
    MARKETDATA_DATABASE: {'owner': MARKETDATA_WRITER, 'connect': [MARKETDATA_WRITER, RETENTION_ROLE],
                          'writers': [MARKETDATA_WRITER], 'readers': [], 'default_select': {}, 'retention': True,
                          'retention_select': []},
}
# The ownership table (one writer per relation): per database, each table and view with the role that writes it, the
# readers of each view (``view_readers``: view -> roles), whether the retention role belongs there and, when only some of
# its tables are history (``retention_tables``), which: every other relation of that database gives the retention role
# nothing. Gateway's users store is not on the fixture (api-key auth). The money database carries the core projector's
# V002 too: the market asset lookup table and two views, the balance movements view readable by oe_money_reader only.
_PROJECTION_TABLES = ('oe_orders', 'oe_fills', 'oe_order_events', 'oe_projection_state', 'oe_projection_source_memo',
                      'oe_projection_replay', 'oe_projection_schema')
_PROJECTION_VIEWS = ('gateway_order_history_v1', 'gateway_fills_v1', 'gateway_order_trail_v1', 'gateway_history_heartbeat_v1')
TABLE_OWNERS = {
    'r01_money': {'tables': {t: MONEY_PROJECTOR_LOGIN for t in ('money_journal', 'money_journal_leg', 'money_market_asset')},
                  'views': {v: MONEY_PROJECTOR_LOGIN for v in ('money_journal_leg_asset', 'gateway_balance_movements_v1')},
                  'view_readers': {'money_journal_leg_asset': [], 'gateway_balance_movements_v1': [MONEY_READER_GROUP]},
                  'retention': True, 'retention_tables': ['money_journal', 'money_journal_leg']},
    'r01_gateway': {'tables': {t: HISTORY_PROJECTOR_LOGIN for t in _PROJECTION_TABLES},
                    'views': {v: HISTORY_PROJECTOR_LOGIN for v in _PROJECTION_VIEWS},
                    'view_readers': {v: [HISTORY_READER_GROUP] for v in _PROJECTION_VIEWS}, 'retention': True},
    'r01_history_b': {'tables': {t: HISTORY_PROJECTOR_LOGIN for t in _PROJECTION_TABLES},
                      'views': {v: HISTORY_PROJECTOR_LOGIN for v in _PROJECTION_VIEWS},
                      'view_readers': {v: [HISTORY_READER_GROUP] for v in _PROJECTION_VIEWS}, 'retention': False},
    MARKETDATA_DATABASE: {'tables': {t: MARKETDATA_WRITER for t in ('md_trades', 'md_candles', 'md_state')}, 'views': {},
                          'view_readers': {}, 'retention': True},
}
# The ME journal as the bridge reads it (stream, control stream, the archive's MTU), on the service's own replay stream;
# the markets the fixture's genesis creates. Settings of the fixture, not limits of the binary.
MARKETDATA_JOURNAL = {'MD_JOURNAL_CONTROL_STREAM': '4010', 'MD_JOURNAL_STREAM': '4001', 'MD_JOURNAL_CHANNEL': 'aeron:ipc',
                      'MD_REPLAY_STREAM': '4014', 'MD_JOURNAL_MTU': '1408'}
MARKETDATA_EXPECTED_MARKETS = '1,2,3,4,5'
# JVM system properties a manifest may set on the core members (core_jvm_properties): the per-session egress ceiling of
# the slow-consumer drill. A setting of the core (SessionEgressQueue), never a timeout.
CORE_JVM_PROPERTIES = {'core.egress.max.capacity.bytes'}


def gateway_manifest(manifest):
    """True when ``manifest`` declares the gateway roles (all four), False when it declares none of them."""
    present = GATEWAY_ROLES & set((manifest or {}).get('nodes') or {})
    if present and present != GATEWAY_ROLES:
        raise Violation('the gateway roles are declared together: ' + ', '.join(sorted(GATEWAY_ROLES)) + '; got '
                        + ', '.join(sorted(present)))
    return bool(present)


def projection_manifest(manifest):
    """True when ``manifest`` declares the projection roles (both), False when it declares neither. They need the gateway
    roles: pj0 writes the database the gateways read history from."""
    present = PROJECTION_ROLES & set((manifest or {}).get('nodes') or {})
    if present and present != PROJECTION_ROLES:
        raise Violation('the projection roles are declared together: ' + ', '.join(sorted(PROJECTION_ROLES)) + '; got '
                        + ', '.join(sorted(present)))
    if present and not gateway_manifest(manifest):
        raise Violation('the projection roles need the gateway roles (pj0 writes the gateways\' history database)')
    return bool(present)


def marketdata_manifest(manifest):
    """True when ``manifest`` declares the market-data role md0, False when not. It needs the gateway roles."""
    present = MARKETDATA_ROLES & set((manifest or {}).get('nodes') or {})
    if present and not gateway_manifest(manifest):
        raise Violation('the market-data role needs the gateway roles')
    return bool(present)


def roles_of(manifest):
    """The roles a manifest must declare: ROLES, plus the gateway roles on a gateway manifest, the projection roles on
    a projection manifest and md0 on a market-data manifest."""
    return (ROLES | (GATEWAY_ROLES if gateway_manifest(manifest) else set())
            | (PROJECTION_ROLES if projection_manifest(manifest) else set())
            | (MARKETDATA_ROLES if marketdata_manifest(manifest) else set()))


def slots_of(manifest):
    return {**SLOTS, **(GATEWAY_SLOTS if gateway_manifest(manifest) else {}),
            **(PROJECTION_SLOTS if projection_manifest(manifest) else {}),
            **(MARKETDATA_SLOTS if marketdata_manifest(manifest) else {})}


def ports_of(manifest):
    """The port profile a manifest must carry."""
    return {**PORT_PROFILE, **(GATEWAY_PORTS if gateway_manifest(manifest) else {}),
            **(PROJECTION_PORTS if projection_manifest(manifest) else {}),
            **(MARKETDATA_PORTS if marketdata_manifest(manifest) else {})}


# The replica's port slot (CLUSTER_REPLICA_SLOT): its ports are ae_base + slot x stride + offset, like a member's
REPLICA_SLOT = 3
# A replica restarted right after a kill or an exit meets its own archive's mark file, as an AE member does (the same
# measured 12.5 s, AE_RESTART_MIN_AFTER_KILL_S in core_fixture); a setting, recorded as waited_after_kill_s
SHADOW_RESTART_MIN_AFTER_KILL_S = 12.5
AE_CREDENTIAL_ENV = {'keys_env': 'CORE_AUTH_KEYS', 'credential_env': 'CORE_AUTH_CREDENTIAL'}
# The environment names retired by the rename of the engine to core, old to new (the core's RetiredSettings table for the
# names this harness sets, plus the probe's own). A fixture that still sets one was written for the old names: it is
# refused naming the new one, never passed on and never translated.
RETIRED_ENV = {'ASSETS_NODE_PORT': 'CORE_NODE_PORT', 'ASSETS_AUTH_KEYS': 'CORE_AUTH_KEYS',
               'AE_AUTH_CREDENTIAL': 'CORE_AUTH_CREDENTIAL', 'BRIDGE_AE_CLUSTER_ADDRESSES': 'BRIDGE_CORE_CLUSTER_ADDRESSES',
               'BRIDGE_AE_PORT_BASE': 'BRIDGE_CORE_PORT_BASE', 'BRIDGE_AE_EGRESS_ENDPOINT': 'BRIDGE_CORE_EGRESS_ENDPOINT',
               'PROJECTOR_AE_JOURNAL_ARCHIVES': 'PROJECTOR_CORE_JOURNAL_ARCHIVES', 'CORE_AE_ADDRESSES': 'CORE_ADDRESSES',
               'CORE_AE_PORT_BASE': 'CORE_PORT_BASE'}


def retired_env_refusal(name):
    """The refusal line for a retired environment name, or None when the name is not retired."""
    if name not in RETIRED_ENV:
        return None
    return (f'the environment variable {name} is retired; it is now {RETIRED_ENV[name]} '
            '(rename the setting; the old name is never read)')

ME_AUTH_MODES = {'enforced', 'not_enforced_by_artifact'}
# The drills are about elections, so the fixture keeps every production timeout. Everything is an
# allowlist: the manifest's top-level keys, the environment names a fixture process may receive, and
# the environment the pinned image itself carries. Anything else is refused, never filtered.
MANIFEST_KEYS = {'schema_version', 'topology', 'run_id', 'timeouts', 'image', 'state_root', 'failure_domain',
                 'network', 'nodes', 'ports', 'seed', 'cpu_set', 'limits', 'artifacts', 'slot_artifacts', 'core_probe',
                 'journal_probe', 'credentials', 'me_journal_profile', 'postgres_bin', 'postgres_port'}
OPTIONAL_MANIFEST_KEYS = {'netfilter_helper', 'host_loss_acceptance', 'profile_note', 'measurement_purpose',
                          'harness_commit', 'harness_dirty',
                          # The probe's own aeronmd and the two T1 drivers, hash-pinned
                          'probe_libs', 't1_me_driver', 't1_core_driver',
                          # The engines' driver profile and its staged driver; the builder's kind
                          'engine_driver', 'engine_libs', 'manifest_kind',
                          # The money projector's driver profile and its staged driver
                          'projector_driver', 'projector_libs', 'node_layout',
                          # A rig manifest's named waiver of the harness pin (smokes before a cut regeneration)
                          'harness_drift',
                          # The core members' JVM properties (CORE_JVM_PROPERTIES), the slow-consumer kinds' egress ceiling
                          'core_jvm_properties'}
DRIVER_MODES = {'embedded', 'external'}
LIB_KEYS = {'path', 'sha256', 'exec'}
# Pinned single-file helper programs, checked like core_probe / journal_probe (path + source_path hashes).
PINNED_PROGRAMS = ['core_probe', 'journal_probe']
OPTIONAL_PROGRAMS = ['t1_me_driver', 't1_core_driver']
# Names the fixture itself sets (core_fixture: ENGINE_COMMON, engine_env, projector, slot_env, probe_env).
PROCESS_ENV = {
    'CLUSTER_PORT_STRIDE', 'BASE_DIR', 'TRANSPORT_DRIVER_MODE', 'TRANSPORT_IDLE_MODE', 'TRANSPORT_TERM_LENGTH',
    'TRANSPORT_LOG_TERM_LENGTH', 'TRANSPORT_SNAPSHOT_TERM_LENGTH', 'MATCH_ENGINE_BOOK_CAPACITY', 'SNAPSHOT_LOG_BYTES',
    'SNAPSHOT_INTERVAL_MINUTES', 'CLUSTER_NODE', 'CLUSTER_ADDRESSES', 'CLUSTER_PORT_BASE', 'METRICS_PORT',
    'SETTLEMENT_JOURNAL_ENABLED', 'SETTLEMENT_JOURNAL_DIR', 'SETTLEMENT_JOURNAL_ARCHIVE_BIND', 'CORE_NODE_PORT',
    'CORE_AUTH_KEYS', 'CORE_AUTH_CREDENTIAL',
    # The ME builds its engine config from the replicated EngineConfig record, not from env knobs (RUN:158)
    'MATCH_ENGINE_FROM_CONFIG',
    'PROJECTOR_POSTGRES_URL', 'PROJECTOR_POSTGRES_USER', 'PROJECTOR_POSTGRES_PASSWORD', 'PROJECTOR_CORE_JOURNAL_ARCHIVES',
    'PROJECTOR_LOCAL_HOST', 'PROJECTOR_METRICS_PORT',
    # Assets c68d163 ProjectorDriver (PROJECTOR_DRIVER_MODE embedded|external, strict; external reads AERON_DIR)
    'PROJECTOR_DRIVER_MODE',
    # ct-forwarder strict env (FC:156-265). ME_AUTH_CREDENTIAL is NOT here: a manifest's credentials.me names reach
    # processes through allowed_env() (validate_core_manifest refuses a credentials.me name that is in this set).
    'FWD_CORE_INGRESS', 'FWD_CORE_RESPONSE_CHANNEL', 'FWD_ME_INGRESS', 'FWD_ME_RESPONSE_CHANNEL', 'FWD_INGRESS_CHANNEL',
    'FWD_DRIVER_MODE', 'FWD_DRIVER_DIR', 'FWD_DRIVER_TIMEOUT_MS', 'FWD_INSTANCE_ID', 'FWD_HTTP_BIND', 'AERON_DIR',
    # ct-bridge strict env (BC:42-55, 235-327)
    'BRIDGE_ME_JOURNAL_ARCHIVES', 'BRIDGE_JOURNAL_CONTROL_STREAM', 'BRIDGE_JOURNAL_STREAM', 'BRIDGE_JOURNAL_CHANNEL',
    'BRIDGE_REPLAY_STREAM', 'BRIDGE_JOURNAL_MTU', 'BRIDGE_LOCAL_HOST', 'BRIDGE_DRIVER_MODE', 'BRIDGE_DRIVER_DIR',
    'BRIDGE_DRIVER_TIMEOUT_MS', 'BRIDGE_CORE_CLUSTER_ADDRESSES', 'BRIDGE_CORE_PORT_BASE', 'BRIDGE_CORE_EGRESS_ENDPOINT',
    'BRIDGE_INSTANCE_ID', 'BRIDGE_HTTP_BIND',
    # the staged aeronmd: deleted on start and shutdown so a restart never attaches to a dead driver
    'AERON_DIR_DELETE_ON_START', 'AERON_DIR_DELETE_ON_SHUTDOWN', 'LD_LIBRARY_PATH',
    'CORE_ADDRESSES', 'CORE_PORT_BASE', 'CORE_LOCAL_HOST',
    # The members' shadow block (engine_env, REPLICA_KINDS) and the replica (replica_env); the core README names each
    'SNAPSHOT_MODE', 'SHADOW_PULL_SOURCES', 'SHADOW_PRODUCER_BUFFER_MB', 'SHADOW_WITNESS_ALARM_MS', 'SHADOW_ANCHOR_RULE',
    'CORE_ROLE', 'CLUSTER_REPLICA_SLOT', 'CLUSTER_REPLICA_ADDRESS', 'REPLICA_BACKUP_SOURCE', 'REPLICA_SHADOW_BUFFER_MB',
    'REPLICA_CATCHUP_RCV_WND', 'SHADOW_RETAIN_N', 'REPLICA_BACKUP_COOLDOWN_MS', 'SHADOW_REBOOTSTRAP_REPLAY_FAILURES',
    'REPLICA_BACKUP_QUERY_INTERVAL_MS',
    # the core's archive segment length (members and replica of the replica and full drill kinds; core README)
    'ARCHIVE_SEGMENT_LENGTH',
    # the AE members' rejoin watchdog wait, on the peer-loss drills only (member_rejoin_wait_ms; a timeout name:
    # it passes the guard only at the exact value the drill recorded)
    'ENGINE_REJOIN_WAIT_MS'} | {
    # oe-gateway and oe-stream (gateway README "Run"; strict: every problem in one pass, exit 78). Timeouts, stale bounds and
    # cadences are never set: the binaries run on their defaults, as the engines run on production timeouts. The one
    # exception is the history stale bound and its /health probe cadence, which the history-freshness drill sets on
    # the gateway slots (recorded with the run) so that a freeze below the projector's driver bound reads stale.
    'GATEWAY_DRIVER_MODE', 'GATEWAY_DRIVER_DIR', 'GATEWAY_CORE_INGRESS', 'GATEWAY_CORE_INGRESS_CHANNEL',
    'GATEWAY_CORE_RESPONSE_CHANNEL', 'GATEWAY_INSTANCE_ID', 'GATEWAY_HTTP_BIND', 'GATEWAY_ADMIN_BIND', 'GATEWAY_AUTH_MODES',
    'GATEWAY_API_KEYS_FILE', 'GATEWAY_PG_URL', 'GATEWAY_ALLOW_TREASURY_LANE', 'GATEWAY_TREASURY_CREDENTIAL',
    'GATEWAY_FAUCET_MAX_AMOUNT', 'GATEWAY_HISTORY_STALE_MS', 'GATEWAY_HISTORY_PROBE_MS', 'STREAM_DRIVER_MODE', 'STREAM_DRIVER_DIR', 'STREAM_CORE_INGRESS',
    'STREAM_CORE_INGRESS_CHANNEL', 'STREAM_CORE_RESPONSE_CHANNEL', 'STREAM_INSTANCE_ID', 'STREAM_WS_BIND',
    'STREAM_ADMIN_BIND', 'STREAM_AUTH_MODES', 'STREAM_CORE_NODE_ENDPOINTS', 'STREAM_ME_NODE_ENDPOINTS',
    # the test-only HTTP shim (gateway_shim.py): its listener and its users file
    'SHIM_HTTP_BIND', 'SHIM_API_KEYS_FILE', 'SHIM_MODE', 'SHIM_CORE_PROBE',
    # the test-only projection stand-in (projector_stub.py): its listener, database, mode, member endpoints and settings
    'STUB_ADMIN_BIND', 'STUB_PG_URL', 'STUB_INSTANCE', 'STUB_CORE_PROBE', 'STUB_MEMBER_METRICS', 'STUB_MODE',
    'STUB_POLL_MS', 'STUB_PAGE_EVENTS', 'STUB_LEASE_MS', 'STUB_LEASE_POLL_MS', 'STUB_PROBE_BOUND_MS',
    # oe-projector (gateway README "History projector"; strict, exit 78): only the required settings, the rest on defaults
    'HISTORY_PROJECTOR_DRIVER_MODE', 'HISTORY_PROJECTOR_DRIVER_DIR', 'HISTORY_PROJECTOR_INSTANCE_ID',
    'HISTORY_PROJECTOR_ADMIN_BIND', 'HISTORY_PROJECTOR_JOURNAL_ARCHIVES', 'HISTORY_PROJECTOR_JOURNAL_CONTROL_STREAM',
    'HISTORY_PROJECTOR_JOURNAL_STREAM', 'HISTORY_PROJECTOR_JOURNAL_CHANNEL', 'HISTORY_PROJECTOR_REPLAY_STREAM',
    'HISTORY_PROJECTOR_JOURNAL_MTU', 'HISTORY_PROJECTOR_LOCAL_HOST', 'HISTORY_PROJECTOR_JOURNAL_NODE_ENDPOINTS',
    'HISTORY_PROJECTOR_CLUSTER_MEMBERS', 'HISTORY_PROJECTOR_CLUSTER_KEY_FILE', 'HISTORY_PROJECTOR_CORE_INGRESS_CHANNEL',
    'HISTORY_PROJECTOR_CORE_RESPONSE_CHANNEL', 'HISTORY_PROJECTOR_PG_URL',
    # one setting a drill may set (projection-byte-equal-replay C: the rebuild's batch size, recorded with the run)
    'HISTORY_PROJECTOR_BATCH_EVENTS',
    # the core members' replay gauge (core README): the replay stream core_archive_replays_active counts
    'CORE_ARCHIVE_REPLAY_PROBE_STREAM',
    # oe-marketdata (gateway marketdata/MarketDataSettings.h; strict, exit 78): only the required settings, the rest on
    # its defaults (stale bounds, timeouts and sizes are never set)
    'MD_DRIVER_MODE', 'MD_DRIVER_DIR', 'MD_INSTANCE_ID', 'MD_ME_CLUSTER_ADDRESSES', 'MD_ME_PORT_BASE',
    'MD_ME_EGRESS_ENDPOINT', 'MD_ME_JOURNAL_ARCHIVES', 'MD_JOURNAL_CONTROL_STREAM', 'MD_JOURNAL_STREAM',
    'MD_JOURNAL_CHANNEL', 'MD_REPLAY_STREAM', 'MD_JOURNAL_MTU', 'MD_LOCAL_HOST', 'MD_PUBLIC_BIND', 'MD_ADMIN_BIND',
    'MD_PG_URL', 'MD_PG_USER', 'MD_PG_PASSWORD_FILE', 'MD_CORS_ORIGINS', 'MD_EXPECTED_MARKETS',
    # the commit-pause test build of oe-marketdata (marketdata_nc with MD_TC_COMMIT_PAUSE; a drill sets them, recorded)
    'MDTC_COMMIT_PAUSE_MS', 'MDTC_COMMIT_PAUSE_SKIP'}
# Only `execute` on the probe container may carry these (the pinned T1 drivers). The values are
# session secrets except T1_ME_MARKETS and T1_LOCAL_HOST. T1_BRIDGE_KEY, T1_TAP_KEY and T1_ME_FORWARDER_KEY are
# never set: the via-bridge genesis needs no bridge key and the capture/resend verbs are not run from the probe.
PROBE_ENV = {'T1_ADMIN_KEY', 'T1_TOOL_KEY', 'T1_GATEWAY_KEY', 'T1_ME_ADMIN_KEY', 'T1_ME_MARKETS', 'T1_LOCAL_HOST'}
# The two names the C++ binaries require (no default, DT:28-35) and the one value the fixture
# passes. It is the client's liveness bound on its own media driver, not an election, heartbeat or session timeout.
DRIVER_TIMEOUT_EXEMPT = {'FWD_DRIVER_TIMEOUT_MS': '5000', 'BRIDGE_DRIVER_TIMEOUT_MS': '5000'}
# The one driver setting pair a drill gives a projection slot's staged aeronmd (projector-me-restart-follow, the hung
# writer): an external driver keeps a stopped client this long, so the replay the hung copy recorded stays served and
# the standby's stop-on-takeover rule is what ends it. The unblock timeout must lie above the client liveness (the
# driver refuses otherwise). Exact values only; the drill records them and judges the stop rule under them.
PROJECTION_DRIVER_LIVENESS_EXEMPT = {'AERON_CLIENT_LIVENESS_TIMEOUT': '60s', 'AERON_PUBLICATION_UNBLOCK_TIMEOUT': '75s'}
IMAGE_ENV = {'PATH', 'JAVA_HOME', 'JAVA_VERSION', 'LANG', 'LANGUAGE', 'LC_ALL', 'HOME', 'TZ'}
# REJOIN_WAIT: the members' rejoin watchdog wait is an election bound too; it passes only at the exact value a peer
# loss drill recorded (CoreFixture.member_rejoin_wait_env, timeout_exempt)
TIMEOUT_WORDS = re.compile(r'TIMEOUT|HEARTBEAT|ELECTION|LIVENESS|REJOIN_WAIT', re.IGNORECASE)
JVM_TIMEOUT = re.compile(r'-D\S*(timeout|heartbeat|election|liveness)', re.IGNORECASE)

# The engine container's staged driver. driver.properties is a byte copy of me/deploy/media-driver/driver.properties
# (c53dd20) and driver-dev.properties the overlay the launch-driver.sh dev profile applies (LD:19-20, SHARED threading and
# backoff idles: the engine member has one CPU). Nothing else, nothing missing.
ENGINE_LIBS = {'aeronmd', 'libaeron_driver.so', 'libaeron.so', 'driver.properties', 'driver-dev.properties'}
# The embedded driver overrides the external driver must equal (MEC:221-236, ME AeronCluster.launchWithEmbeddedDriver; the AE
# context AEC:205-214 sets the same values except the two untethered timeouts, which only the ME codes). driverTimeoutMs(500)
# is a client setting and has no driver counterpart. sparse.file=false is DP's own pin.
ENGINE_DRIVER_PROPERTIES = {
    'aeron.mtu.length': '8192', 'aeron.term.buffer.length': '16m', 'aeron.ipc.term.buffer.length': '16m',
    'aeron.term.buffer.sparse.file': 'false', 'aeron.socket.so_sndbuf': '4m', 'aeron.socket.so_rcvbuf': '4m',
    'aeron.rcv.initial.window.length': '4m', 'aeron.timer.interval': '500us', 'aeron.client.liveness.timeout': '5s',
    'aeron.publication.unblock.timeout': '10s', 'aeron.untethered.window.limit.timeout': '100ms',
    'aeron.untethered.resting.timeout': '100ms'}
DEV_OVERLAY_KEYS = {'aeron.threading.mode', 'aeron.conductor.idle.strategy', 'aeron.sender.idle.strategy',
                    'aeron.receiver.idle.strategy', 'aeron.shared.idle.strategy', 'aeron.sharednetwork.idle.strategy'}
# The eleven base manifests (mk_manifests.py). The kind is pinned in the manifest and is the file name's prefix
# ("<kind>--<tag>.json"), so a guard keyed on it cannot be satisfied by renaming a file.
BASE_KINDS = {'s16', 's16-ext', 's16-embedded', 's16-n1', 's16-a03', 's16-a03-embedded', 's16-a05', 's16-a05-embedded',
             's16-red-a03', 's16-red-a04', 's16-ctl-edk-cnctimeout'}
# The s17 kinds, derived from the cut manifest by ``mk_manifests.py --cut``. The RED and A03 kinds
# stage negative targets of a test-config build of the cut's cluster-tools commit.
CUT_KINDS = {'s17', 's17-ext', 's17-embedded', 's17-n1', 's17-xver', 's17-xver-ext', 's17-act', 's17-rollback', 's17-a05',
             's17-a05-embedded', 's17-a05-keep', 's17-a05-reverse', 's17-ctl-edk-cnctimeout',
             's17-a03', 's17-a03-embedded', 's17-red-a03', 's17-red-a04', 's17-red1', 's17-red2'}
# The replica kinds, named by content and derived from the cut like the s17 kinds. Each runs the core jar as the shadow
# replica in shadow0 and its AE members in SNAPSHOT_MODE=shadow; the env each adds to the common shadow block
# (core_fixture.engine_env / replica_env) is the kind's, because env lives in manifests (one kind per control setting).
#   shadow               slots external, engines and replica embedded
#   shadow-ext           engines and replica on the staged aeronmd
#   shadow-anyverified   members purge behind one producer's ALIGNED (the re-bootstrap drill: the replica is down)
#   shadow-cooldown30    the supplier-loss control: the replica's backup cool-down 30 s
#   shadow-detectoronly  the re-bootstrap control: the detector counts and never acts (members as shadow-anyverified,
#                        else nothing is purged below the stopped replica and the detector has nothing to count)
#   shadow-query         the leader-loss and catalog rows: a 13 s backup query interval (10 s sits below window + 1000,
#                        a CRITICAL line)
#   shadow-query-ext     shadow-query with the engines and the replica on the staged aeronmd
#   shadow-anyverified-ext  shadow-anyverified with the engines and the replica on the staged aeronmd
REPLICA_KINDS = {
    'shadow': {'members': {}, 'replica': {}},
    'shadow-ext': {'members': {}, 'replica': {}},
    'shadow-anyverified': {'members': {'SHADOW_ANCHOR_RULE': 'any-verified'}, 'replica': {}},
    'shadow-cooldown30': {'members': {}, 'replica': {'REPLICA_BACKUP_COOLDOWN_MS': '30000'}},
    'shadow-detectoronly': {'members': {'SHADOW_ANCHOR_RULE': 'any-verified'},
                            'replica': {'SHADOW_REBOOTSTRAP_REPLAY_FAILURES': '0'}},
    'shadow-query': {'members': {}, 'replica': {'REPLICA_BACKUP_QUERY_INTERVAL_MS': '13000'}},
    'shadow-query-ext': {'members': {}, 'replica': {'REPLICA_BACKUP_QUERY_INTERVAL_MS': '13000'}},
    'shadow-anyverified-ext': {'members': {'SHADOW_ANCHOR_RULE': 'any-verified'}, 'replica': {}},
}
# The full-mode control kind: no replica, SNAPSHOT_MODE unset (full snapshots), the same snapshot cadence
FULL_KINDS = {'full'}
# The members' shadow block of every replica kind and the cadence every replica and full kind runs (settings)
MEMBER_SHADOW_ENV = {'SNAPSHOT_MODE': 'shadow', 'SHADOW_PRODUCER_BUFFER_MB': '64', 'SHADOW_WITNESS_ALARM_MS': '120000'}
DRILL_CADENCE_ENV = {'SNAPSHOT_INTERVAL_MINUTES': '1'}
# The rejoin watchdog (cluster-kit RejoinWatchdog, ENGINE_REJOIN_WAIT_MS): a member that has known a leader and then
# stays in one leaderless election for the wait exits 1 for a supervised restart. The kit default is 60 s. The peer
# loss drills (REJOIN_WAIT_DRILLS) hold a deliberate quorum loss with one member alone for longer than that (110 to
# 152 s measured), and the fixture restarts nobody, so on the default the lone survivor exits in the middle of the
# drill and the drill loses the member it observes. Those two drills alone run the AE members on a wait above their
# longest quorum-loss bound (replica_drills.quorum_loss_bound_s) and refuse to start when their own settings would
# reach it; every other drill and kind keeps the kit default. The value passes the fixture's timeout guard only as the
# exact value the drill recorded, and reaches the witness. REPLICA_MEMBER_REJOIN_WAIT_MS overrides the default. The
# kit-default behaviour under the same quorum loss is pinned by the control peerloss-loud-unblocked-kitwait.
KIT_REJOIN_WAIT_DEFAULT_MS = 60000
REJOIN_WAIT_SETTING = 'REPLICA_MEMBER_REJOIN_WAIT_MS'
REJOIN_WAIT_DEFAULT_MS = 330000
REJOIN_WAIT_RANGE_MS = (61000, 3600000)
REJOIN_WAIT_DRILLS = ('peerloss', 'peerloss_loud')          # replica_drills steps whose quorum loss outlasts 60 s


def member_rejoin_wait_ms(env=None):
    """The replica kinds' ENGINE_REJOIN_WAIT_MS: REPLICA_MEMBER_REJOIN_WAIT_MS when set (range-checked), else the default."""
    env = os.environ if env is None else env
    raw = env.get(REJOIN_WAIT_SETTING)
    if raw is None or raw == '':
        return REJOIN_WAIT_DEFAULT_MS
    if not re.fullmatch(r'[0-9]+', raw):
        raise Violation(f'{REJOIN_WAIT_SETTING} must be a whole number of milliseconds, got {raw!r}')
    value = int(raw)
    low, high = REJOIN_WAIT_RANGE_MS
    if not low <= value <= high:
        raise Violation(f'{REJOIN_WAIT_SETTING} {value} is outside {low}..{high}')
    return value


# The kit after the rejoin kit gates its watchdog during a genuine quorum loss (the watchdog no longer trips while a
# majority of the members is unreachable). The cut's kit is the pin its core jar carries (release_cut.kit_pin_of). On a
# kit newer than this pin, the peer-loss drills need no rejoin-wait override and the kit-default control expects the
# survivor to outlast the quorum loss; on this pin (or an older kit) both keep the watchdog behaviour. Pins are ordered
# by X.Y.Z, then, on one X.Y.Z, by the runtime build date of the qualifier (X.Y.Z-runtime.YYYYMMDD...): the repo has
# shipped two builds of one X.Y.Z before. Two builds of one X.Y.Z that the date cannot order are INCONCLUSIVE.
KIT_WATCHDOG_UNGATED_PIN = '0.1.23-runtime.20261118.rejoin.g8a6fb55'
KIT_PIN_RE = re.compile(r'(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?')
KIT_BUILD_DATE_RE = re.compile(r'runtime\.(\d{8})(?:\.|$)')


def kit_version(pin):
    """(X, Y, Z) of a cluster-kit pin such as 0.1.23-runtime.20261118.rejoin.g8a6fb55; Inconclusive when unreadable."""
    found = KIT_PIN_RE.fullmatch(pin) if isinstance(pin, str) else None
    if not found:
        raise Inconclusive(f'cluster-kit pin {pin!r} is not X.Y.Z[-qualifier]: the drill cannot tell which kit it runs')
    return tuple(int(found.group(i)) for i in (1, 2, 3))


def kit_build_date(pin):
    """The runtime build date (YYYYMMDD) of a pin's qualifier, or None."""
    found = KIT_PIN_RE.fullmatch(pin) if isinstance(pin, str) else None
    date = KIT_BUILD_DATE_RE.match(found.group(4) or '') if found else None
    return date.group(1) if date else None


def kit_newer(pin, than):
    """True when ``pin`` is a newer kit than ``than``: a higher X.Y.Z, or on one X.Y.Z a later runtime build date.
    Inconclusive when the two are different builds of one X.Y.Z the date cannot order."""
    mine, theirs = kit_version(pin), kit_version(than)
    if mine != theirs:
        return mine > theirs
    if pin == than:
        return False
    a, b = kit_build_date(pin), kit_build_date(than)
    if a is None or b is None or a == b:
        raise Inconclusive(f'cluster-kit pin {pin!r} and {than!r} are two builds of {".".join(map(str, mine))}: the '
                           f'drill cannot order them (no distinct runtime build date)')
    return a > b


def kit_watchdog_gated(pin):
    """True when the kit ``pin`` gates its rejoin watchdog during a genuine quorum loss (newer than the rejoin kit)."""
    return kit_newer(pin, KIT_WATCHDOG_UNGATED_PIN)


# A member stranded below the leader's log start. A kit that holds its retention floor for a down member lets it catch
# up. The leader writes a member off when it held the floor past the bound (RETENTION_MEMBER_WAIT_MS since the member
# last moved, or RETENTION_MEMBER_WAIT_BYTES behind the newest snapshot): one CRITICAL "member <id> STRANDED" line, and
# the purge proceeds. With RETENTION_FLOOR=report the floor is only logged, never applied. A member that then returns
# below the leader's log start is exited by its catch-up watchdog (after ENGINE_CATCHUP_REFUSALS failed catch-ups or
# ENGINE_CATCHUP_REFUSAL_WAIT_MS of them) with a CRITICAL line and a FATAL reason, both naming its log position, the
# leader's log start and the leader's member id. Names, texts, defaults and ranges are the kit's
# (SnapshotLogPruner, CatchupWatchdog).
LOUD_STRAND_RES = (
    re.compile(r"CRITICAL catch-up watchdog: .*?this member's log position (\d+) is below the log start position (\d+) "
               r"of the leader \(member (\d+)\)"),
    re.compile(r"member cannot catch up: its log position (\d+) is below the leader's log start position (\d+) "
               r"\(leader member (\d+)\)"))
WRITTEN_OFF_RE = re.compile(r'\bmember (\d+) STRANDED: it has held the retention floor past the bound')
FLOOR_GIVEN_UP_TEXT = 'the retention floor has been unknown for'
RETENTION_FLOOR_SETTING = 'RETENTION_FLOOR'
RETENTION_FLOOR_MODES = ('apply', 'report')
RETENTION_FLOOR_DEFAULT = 'apply'
RETENTION_MEMBER_WAIT_BYTES_SETTING = 'RETENTION_MEMBER_WAIT_BYTES'
RETENTION_MEMBER_WAIT_BYTES_DEFAULT = 2 << 30           # SnapshotLogPruner.DEFAULT_MEMBER_WAIT_BYTES
RETENTION_MEMBER_WAIT_BYTES_RANGE = (1 << 20, 1 << 40)
RETENTION_MEMBER_WAIT_MS_SETTING = 'RETENTION_MEMBER_WAIT_MS'
RETENTION_MEMBER_WAIT_MS_DEFAULT = 30 * 60 * 1000       # SnapshotLogPruner.DEFAULT_MEMBER_WAIT_MS
RETENTION_MEMBER_WAIT_MS_RANGE = (1000, 7 * 24 * 3600 * 1000)


def loud_strand_of(line):
    """{position, log_start, leader_member} of the kit's catch-up watchdog CRITICAL line or FATAL reason, else None."""
    for pattern in LOUD_STRAND_RES:
        found = pattern.search(line or '')
        if found:
            return {'position': int(found.group(1)), 'log_start': int(found.group(2)),
                    'leader_member': int(found.group(3))}
    return None


def written_off(line, member_id):
    """True when ``line`` is the leader's CRITICAL STRANDED line for cluster member ``member_id``."""
    found = WRITTEN_OFF_RE.search(line or '')
    return bool(found) and int(found.group(1)) == member_id


# The replica's settings on the fixture (core README "Replica"): FOLLOWER keeps replay off the leader; the catch-up window
# is the replica's own (it never reads TRANSPORT_LOG_RCV_WINDOW); the term is the members' (the lag default reads it)
REPLICA_ENV = {'CORE_ROLE': 'replica', 'CLUSTER_REPLICA_SLOT': str(REPLICA_SLOT), 'REPLICA_BACKUP_SOURCE': 'FOLLOWER',
               'REPLICA_SHADOW_BUFFER_MB': '64', 'REPLICA_CATCHUP_RCV_WND': '512k', 'SHADOW_RETAIN_N': '3'}
# The gateway kinds, derived from the cut like the s17 kinds; each declares the four gateway roles. ``driver`` is the
# gateway and stream slots' driver mode and the engines' (one mode per kind, so every drill runs as an embedded and an
# external entry); ``slots`` the artifact of each gateway slot (None: the slot is declared and empty); ``core_jvm``
# the core members' JVM properties (CORE_JVM_PROPERTIES); ``shim_mode`` the HTTP shim's mode (gateway dry runs).
#   gw, gw-ext                  the product binaries in all four slots
#   gw-slow, gw-slow-ext        the slow-consumer drill: the core's egress ceiling lowered so the story reaches it
#   gw-freshkey(-ext)           the kill-restart control: gw0 runs oe-gateway built with GW_NC_FRESH_KEY
#   gw-noreoffer                the kill-restart control of the cancel re-offer rule: gw1 (the cancel phase's gateway)
#                               runs oe-gateway built with GW_NC_NO_CANCEL_REOFFER_RULE
#   gw-noassetcheck             the fill-visibility control of the asset check: gw1 (the fuzz's gateway) runs oe-gateway
#                               built with GW_NC_NO_ASSET_CHECK
# ``nc_define`` names the control define of the kind's gateway_nc build (default GW_NC_FRESH_KEY).
#   gw-dry-stream(-ext)         stream dry run: st0 = ct_session_stub, the ceiling lowered, no gateway binary
#   gw-dry-stream-ceiling16m    its control: the ceiling left at the core's 16 MiB default
#   gw-dry-gateway(-ext)        gateway dry run: gw0 and gw1 = the HTTP shim over CoreProbe verbs
#   gw-dry-gateway-freshkey     its control: the shim mints a fresh request id on every attempt
DRILL_EGRESS_CEILING_BYTES = 262144        # a setting of the slow-consumer kinds (256 KiB), never a limit
_LOWERED = {'core.egress.max.capacity.bytes': str(DRILL_EGRESS_CEILING_BYTES)}
_ALL = {'gw0': 'gateway', 'gw1': 'gateway', 'st0': 'stream', 'st1': 'stream'}
GATEWAY_KINDS = {
    'gw': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}},
    'gw-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': {}},
    'gw-slow': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': dict(_LOWERED)},
    'gw-slow-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': dict(_LOWERED)},
    'gw-freshkey': {'driver': 'embedded', 'slots': dict(_ALL, gw0='gateway_nc'), 'core_jvm': {}},
    'gw-freshkey-ext': {'driver': 'external', 'slots': dict(_ALL, gw0='gateway_nc'), 'core_jvm': {}},
    'gw-dry-stream': {'driver': 'embedded', 'slots': {'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None},
                      'core_jvm': dict(_LOWERED)},
    'gw-dry-stream-ext': {'driver': 'external', 'slots': {'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None},
                          'core_jvm': dict(_LOWERED)},
    'gw-dry-stream-ceiling16m': {'driver': 'embedded', 'slots': {'gw0': None, 'gw1': None, 'st0': 'session_stub', 'st1': None},
                                 'core_jvm': {}},
    'gw-dry-gateway': {'driver': 'embedded', 'slots': {'gw0': 'gateway_stub', 'gw1': 'gateway_stub', 'st0': None, 'st1': None},
                       'core_jvm': {}, 'shim_mode': 'stored'},
    'gw-dry-gateway-ext': {'driver': 'external', 'core_jvm': {}, 'shim_mode': 'stored',
                           'slots': {'gw0': 'gateway_stub', 'gw1': 'gateway_stub', 'st0': None, 'st1': None}},
    'gw-dry-gateway-freshkey': {'driver': 'embedded', 'core_jvm': {}, 'shim_mode': 'fresh-key',
                                'slots': {'gw0': 'gateway_stub', 'gw1': 'gateway_stub', 'st0': None, 'st1': None}},
}
# The control kinds of the five drills: ``control`` names the scenario whose line must fail, ``control_text`` overrides
# the scenario's text (gateway_drills.CONTROL_TEXT), ``drill`` sets drill sizes (gateway_drills.SETTINGS names) and
# ``behavior`` the core behaviour version (default GATEWAY_CORE_BEHAVIOR).
#   gw-freshkey(-ext)          gateway-kill-restart: gw0 mints a fresh request id per attempt (GW_NC_FRESH_KEY)
#   gw-b3                      gateway-kill-restart: the core left at behaviour 3, where the gate is checked before the
#                              requestId lookup, so a stored acceptance sent again under a closed gate is refused
#   gw-slow-ceiling16m         stream-slow-consumer: the egress ceiling left at the core's 16 MiB
#   gw-timeout-shortfreeze     gateway-session-timeout: gw0 frozen for less than the core's session timeout, so its
#                              keepalives resume before the core closes the session
#   gw-fill-muted              fill-visibility-core: both streams frozen while the pairs run
#   gw-tick-nofwd              tick-live-path: the forwarders stopped before the pass leg
#   gw-noreoffer               gateway-kill-restart: a re-offered unkeyed cancel answered by its reject
#   gw-noassetcheck            fill-visibility-core: a deposit of an unknown assetId sent to the core, which drops it
GATEWAY_CORE_BEHAVIOR = 4
GATEWAY_KINDS.update({
    'gw-freshkey': dict(GATEWAY_KINDS['gw-freshkey'], control='gateway-kill-restart'),
    'gw-freshkey-ext': dict(GATEWAY_KINDS['gw-freshkey-ext'], control='gateway-kill-restart'),
    'gw-b3': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'behavior': 3, 'control': 'gateway-kill-restart',
              'control_text': 'stored acceptance answered ADMISSION_CLOSED'},
    'gw-slow-ceiling16m': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'control': 'stream-slow-consumer'},
    'gw-timeout-shortfreeze': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'control': 'gateway-session-timeout',
                               'drill': {'TIMEOUT_FREEZE_S': 4}},
    'gw-fill-muted': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'control': 'fill-visibility-core',
                      'drill': {'FILL_PAIRS': 2}},
    'gw-tick-nofwd': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'control': 'tick-live-path',
                      'drill': {'TICK_REFERENCE_BOUND_S': 20, 'TICK_COMPLETE_BOUND_S': 10}},
    'gw-noreoffer': {'driver': 'embedded', 'slots': dict(_ALL, gw1='gateway_nc'), 'core_jvm': {},
                     'nc_define': 'GW_NC_NO_CANCEL_REOFFER_RULE', 'control': 'gateway-kill-restart',
                     'control_text': 'successful cancel answered NOT_FOUND'},
    'gw-noassetcheck': {'driver': 'embedded', 'slots': dict(_ALL, gw1='gateway_nc'), 'core_jvm': {},
                        'nc_define': 'GW_NC_NO_ASSET_CHECK', 'control': 'fill-visibility-core',
                        'control_text': 'request unanswered: decode drop', 'drill': {'FILL_PAIRS': 20}},
})
GATEWAY_NC_DEFAULT_DEFINE = 'GW_NC_FRESH_KEY'
# The projection kinds: gateway kinds with the projection slots. ``projectors`` names the artifact of pj0 and pj1 and
# ``stub_mode`` the stand-in's mode. The product gateway and stream binaries of the cut run in the gateway slots.
#   pj-dry, pj-dry-ext          the projection drills' dry runs: pj0 and pj1 = projector_stub (follow)
#   pj-dry-beatalways           the freshness drill's dry-run control: pj0 beats whatever the head
_PJ_STUB = {'pj0': 'projector_stub', 'pj1': 'projector_stub'}
GATEWAY_KINDS.update({
    'pj-dry': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_STUB), 'stub_mode': 'follow'},
    'pj-dry-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_STUB),
                   'stub_mode': 'follow'},
    'pj-dry-beatalways': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_STUB),
                          'stub_mode': 'beat-always', 'projection_control': 'history-freshness'},
})
# The kinds of the projector binary (the drills on oe-projector of the cut): pj0 and pj1 = history_projector.
#   pj, pj-ext                  the three drills, embedded and external (engines, slots and projectors in that mode)
# Their controls (one mode each, as the other drills' controls; ``projection_control`` names the drill whose line must
# fail and ``control_text`` its text; ``projector_define`` the control define of the kind's history_projector_nc build,
# which runs in every slot that drill compares or follows):
#   pj-nc-pinrecording          projector-me-restart-follow: pj0 reads only the first recording it read (the successor
#                               after the attached member's restart is never followed); pj1 is the product standby
#   pj-nc-nostopreplay-ext      projector-me-restart-follow: neither copy stops a recorded replay of an earlier writer
#                               (external: only a live driver keeps a hung copy's replay served past the takeover)
#   pj-nc-wallclock             projection-byte-equal-replay: every compared projection carries a wall-clock column
#   pj-nc-dropone               projection-byte-equal-replay: every compared projection acknowledges journalSeq
#                               PROJ_NC_DROP_SEQ (default 2) and never writes it
#   pj-nc-beatalways            history-freshness: pj0 beats at every fence whatever the head
#   pj-nc-nostale               history-freshness: gw0 runs oe-gateway built with GW_NC_NO_STALE_LABEL
#   <control>-ext               the same control on the external driver, for each control above but the no-stop one
_PJ_BIN = {'pj0': 'history_projector', 'pj1': 'history_projector'}
_PJ_NC = {'pj0': 'history_projector_nc', 'pj1': 'history_projector_nc'}
GATEWAY_KINDS.update({
    'pj': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN)},
    'pj-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN)},
    'pj-nc-pinrecording': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {},
                           'projectors': {'pj0': 'history_projector_nc', 'pj1': 'history_projector'},
                           'projector_define': 'PROJ_NC_PIN_RECORDING', 'projection_control': 'projector-me-restart-follow'},
    'pj-nc-nostopreplay-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_NC),
                           'projector_define': 'PROJ_NC_NO_STOP_REPLAY', 'projection_control': 'projector-me-restart-follow',
                           'control_text': 'orphan replay remains on core member'},
    'pj-nc-wallclock': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_NC),
                        'projector_define': 'PROJ_NC_WALLCLOCK_COLUMN', 'projection_control': 'projection-byte-equal-replay'},
    'pj-nc-dropone': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_NC),
                      'projector_define': 'PROJ_NC_DROP_ONE', 'projection_control': 'projection-byte-equal-replay',
                      'control_text': 'journalSeq missing in projection'},
    'pj-nc-beatalways': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {},
                         'projectors': {'pj0': 'history_projector_nc', 'pj1': 'history_projector'},
                         'projector_define': 'PROJ_NC_BEAT_ALWAYS', 'projection_control': 'history-freshness'},
    'pj-nc-nostale': {'driver': 'embedded', 'slots': dict(_ALL, gw0='gateway_nc'), 'core_jvm': {},
                      'nc_define': 'GW_NC_NO_STALE_LABEL', 'projectors': dict(_PJ_BIN),
                      'projection_control': 'history-freshness', 'control_text': 'stale label missing'},
})
# The external legs of the embedded controls: the same control on the external driver (engines, slots and projectors);
# the no-stop control has no embedded leg (a stopped copy keeps no subscription on the embedded driver)
PROJECTION_CONTROL_EXT_TWINS = {k + '-ext': k for k in ('pj-nc-pinrecording', 'pj-nc-wallclock', 'pj-nc-dropone',
                                                       'pj-nc-beatalways', 'pj-nc-nostale')}
GATEWAY_KINDS.update({twin: dict(GATEWAY_KINDS[base], driver='external')
                      for twin, base in PROJECTION_CONTROL_EXT_TWINS.items()})
# The critical-path kinds: the projector binary kind plus the market-data slot md0 (oe-marketdata of the cut's gateway
# commit on the kind's driver mode). ``slot_plan`` names the forwarder and bridge plan (default A: the cut's builds).
#   cps, cps-ext                the critical-path smoke, the gate brake and the history loss, both engine driver modes
#   cps-nofwd, cps-nofwd-ext    both forwarder slots empty: nothing reaches the ME (the smoke's non-vacuity control)
#   cps-nc-dropone              the smoke on oe-projector built with PROJ_NC_DROP_ONE in pj0 and pj1 (the history line's
#                               control, ``smoke_control`` names the scenario and ``control_text`` its text; one mode,
#                               as the other drills' controls)
_MD = {'md0': 'marketdata'}
GATEWAY_KINDS.update({
    'cps': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN), 'marketdata': dict(_MD)},
    'cps-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                'marketdata': dict(_MD)},
    'cps-nofwd': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                  'marketdata': dict(_MD), 'slot_plan': 'NOFWD'},
    'cps-nofwd-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                      'marketdata': dict(_MD), 'slot_plan': 'NOFWD'},
    'cps-nc-dropone': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_NC),
                       'projector_define': 'PROJ_NC_DROP_ONE', 'marketdata': dict(_MD),
                       'smoke_control': 'critical-path-smoke-core', 'control_text': 'history differs from the core: missing event'},
})
# The market-data drill kinds (md_drills): the critical-path kind with md0 on a marketdata_nc build of the cut's gateway
# commit, ``marketdata_defines`` its test defines and ``md_drill`` the one drill the kind runs; a control kind also names
# ``control_text``, the text the drill's line must fail with.
#   cps-mdtc, cps-mdtc-ext      core-md-exactly-once: the commit-pause seam (the writer is killed inside a commit)
#   cps-mdnc-split              core-md-exactly-once: the seam plus the cursor committed apart from the rows
#   cps-mdnc-epoch              core-md-epoch: the epoch check off
#   cps-mdnc-emptyseries        core-md-history-loss: empty series sent while the history was down at the start
#   cps-mdnc-restmemory         core-md-history-loss: /api/candles answered from memory during the outage
#   cps-mdnc-liveemit           core-md-failover: the live-emit cursor off
#   cps-mdnc-nostall            core-md-failover: stall detection off
# Each control runs in one mode, as the other drills' controls.
_MDNC = {'md0': 'marketdata_nc'}
GATEWAY_KINDS.update({
    'cps-mdtc': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                 'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_TC_COMMIT_PAUSE'], 'md_drill': 'core-md-exactly-once'},
    'cps-mdtc-ext': {'driver': 'external', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                     'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_TC_COMMIT_PAUSE'],
                     'md_drill': 'core-md-exactly-once'},
    'cps-mdnc-split': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                       'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_TC_COMMIT_PAUSE', 'MD_NC_COMMIT_SPLIT'],
                       'md_drill': 'core-md-exactly-once', 'control_text': 'missing trade <id>|duplicate trade <id>'},
    'cps-mdnc-epoch': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                       'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_NC_NO_EPOCH_CHECK'], 'md_drill': 'core-md-epoch',
                       'control_text': 'trades of two genesis epochs in one history'},
    'cps-mdnc-emptyseries': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                             'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_NC_EMPTY_SERIES'],
                             'md_drill': 'core-md-history-loss', 'control_text': 'empty series sent without the history'},
    'cps-mdnc-restmemory': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                            'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_NC_REST_FROM_MEMORY'],
                            'md_drill': 'core-md-history-loss', 'control_text': 'REST candles answered without the history'},
    'cps-mdnc-liveemit': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                          'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_NC_NO_LIVE_EMIT_CURSOR'],
                          'md_drill': 'core-md-failover', 'control_text': 'trade <id> sent twice to one connection'},
    'cps-mdnc-nostall': {'driver': 'embedded', 'slots': dict(_ALL), 'core_jvm': {}, 'projectors': dict(_PJ_BIN),
                         'marketdata': dict(_MDNC), 'marketdata_defines': ['MD_NC_NO_STALL_CHECK'],
                         'md_drill': 'core-md-failover', 'control_text': 'followed a stopped recording'},
})
MARKETDATA_KINDS = {k for k, v in GATEWAY_KINDS.items() if v.get('marketdata')}
# The kinds whose md0 runs the product oe-marketdata (the smoke, the gate brake, the history loss and the product legs of
# the market-data drills)
MARKETDATA_PRODUCT_KINDS = {k for k in MARKETDATA_KINDS if set(GATEWAY_KINDS[k]['marketdata'].values()) <= {'marketdata'}}
PROJECTION_KINDS = {k for k, v in GATEWAY_KINDS.items() if v.get('projectors')}
# The kinds whose projection slots run the projector binary (product or control build), not the stand-in
PROJECTOR_BINARY_KINDS = {k for k in PROJECTION_KINDS
                          if set(GATEWAY_KINDS[k]['projectors'].values()) & {'history_projector', 'history_projector_nc'}}


def nc_define(kind):
    """The control define of a gateway kind's gateway_nc build."""
    return (GATEWAY_KINDS.get(kind) or {}).get('nc_define', GATEWAY_NC_DEFAULT_DEFINE)
SHIM_MODES = {'stored', 'fresh-key'}
CUT_KINDS = CUT_KINDS | set(REPLICA_KINDS) | FULL_KINDS | set(GATEWAY_KINDS)
KINDS = BASE_KINDS | CUT_KINDS


def cut_derived(kind):
    """True for a kind ``mk_manifests.build_from_cut`` derives (the s17 kinds and the replica and full kinds)."""
    return kind in CUT_KINDS
EDK_CNCTIMEOUT_KIND = 's16-ctl-edk-cnctimeout'
EDK_CNCTIMEOUT_KINDS = {EDK_CNCTIMEOUT_KIND, 's17-ctl-edk-cnctimeout'}
ENGINE_DRIVER_SKIP_MEMBERS = ('ae0', 'me0')          # cnc_timeout_loud: one AE member and one ME member
NC_TARGET = re.compile(r'ct_(forwarder|bridge)_nc_[a-z0-9_]+')
CMAKE_TARGET = re.compile(r'[A-Za-z0-9_.-]{1,64}')
A03_NC_TARGET = 'ct_forwarder_nc_norelease'           # A03 phase 1 only
# Build A (ct 2be3a19, pinned in the old-artifact pins) predates the
# /health "build" field: its /health format strings have no "build" key (the cut's ct-forwarder/ct-bridge end in
# ``"build":"%s"``). Its identity is its pinned sha256 alone. Keyed by those exact bytes, so no other binary may omit the field.
HEALTH_BUILD_ABSENT = {
    '75baf2994c0b898fc4fadd6cbe889b3cc189acc3ed9d0be9b0d03fa15ff513c4': 'ct-2be3a19/ct-forwarder',
    'c6e68edc2d7bc0cde3b95c449e476cf945e1869b2a6dd85392d951fcd6eca88a': 'ct-2be3a19/ct-bridge',
}


def health_build_expected(entry):
    """What ``/health.build`` of a slot binary answers: None for a pinned build without the field (HEALTH_BUILD_ABSENT, by
    sha256), else the artifact's ``source_sha`` (absent: None, which then never equals a reported build)."""
    entry = entry or {}
    if entry.get('sha256') in HEALTH_BUILD_ABSENT:
        return None
    return entry.get('source_sha')


# A dated exception to "negative builds never share a manifest with build B": the A03 kinds of the base set and
# of the cut (mk_manifests KINDS / CUT_KINDS, slot plan A03). The runner keyed it on 's16-a03'.
A03_KINDS = {'s16-a03', 's16-a03-embedded', 's17-a03', 's17-a03-embedded'}


def a03_phase1_declared(manifest):
    """True when ``manifest`` declares the A03 phase-1 swap and nothing more: an A03 kind, both forwarder
    slots on ``forwarder_b`` = ``ct_forwarder_nc_norelease``, build A (a real build) staged as ``forwarder`` for the
    ``replace_slot`` swap, both bridges on ``bridge`` and no ``bridge_b``."""
    if manifest.get('manifest_kind') not in A03_KINDS:
        return False
    art, slots = manifest.get('artifacts') or {}, manifest.get('slot_artifacts') or {}
    swap_to = art.get('forwarder') or {}
    return (slots.get('fwd0') == 'forwarder_b' and slots.get('fwd1') == 'forwarder_b'
            and (art.get('forwarder_b') or {}).get('target') == A03_NC_TARGET
            and bool(swap_to) and not NC_TARGET.fullmatch(str(swap_to.get('target') or ''))
            and art.get('bridge_b') is None and slots.get('bridge0') == 'bridge' and slots.get('bridge1') == 'bridge')


def _file(entry, what, keys=('path', 'sha256')):
    file = Path(entry['path'])
    if not file.is_absolute() or file.is_symlink() or not file.is_file():
        raise Inconclusive('missing/untrusted artifact path: ' + what)
    with file.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != entry[keys[1]]:
        raise Violation('artifact digest mismatch: ' + what)


def _lib(entry, what, changed=None):
    """A staged library: path + sha256, optional boolean exec flag, nothing else."""
    if not isinstance(entry, dict) or set(entry) - LIB_KEYS or not {'path', 'sha256'} <= set(entry):
        raise Violation(what + ': library key set is path, sha256, exec; got ' + str(sorted(entry) if isinstance(entry, dict) else entry))
    if 'exec' in entry and type(entry['exec']) is not bool:
        raise Violation(what + ': library exec must be a boolean')
    try:
        _file(entry, what)
    except Violation:
        if changed:
            raise Violation(changed) from None
        raise


def _source(entry, what):
    if not re.fullmatch(r'[0-9a-f]{40}', entry.get('source_sha') or ''):
        raise Inconclusive('missing artifact source commit: ' + what)



_UNITS = {'k': 1024, 'm': 1024 ** 2, 'g': 1024 ** 3}
_TIME = {'ns': 1, 'us': 1000, 'ms': 1000 ** 2, 's': 1000 ** 3}


def aeron_value(text):
    """A property value as the Aeron drivers read it: sizes k/m/g (binary), durations ns/us/ms/s (to ns), else the text."""
    value = text.strip().lower()
    match = re.fullmatch(r'(\d+)(ns|us|ms|s)', value)
    if match:
        return ('ns', int(match.group(1)) * _TIME[match.group(2)])
    match = re.fullmatch(r'(\d+)([kmg]?)', value)
    if match:
        return ('n', int(match.group(1)) * _UNITS.get(match.group(2), 1))
    return ('text', value)


def parse_properties(text, what):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' not in line:
            raise Violation(f'{what}: not a key=value line: {line[:80]}')
        key, value = (part.strip() for part in line.split('=', 1))
        if key in values:
            raise Violation(f'{what}: {key} is set twice')
        values[key] = value
    return values


def check_driver_properties(properties_text, overlay_text):
    """The pinned external driver properties equal the embedded overrides (a drift is a Violation), and the dev
    overlay sets only threading and idle keys, SHARED threading, never a pinned value."""
    props = parse_properties(properties_text, 'driver.properties')
    drift = sorted(k for k, v in ENGINE_DRIVER_PROPERTIES.items() if k not in props or aeron_value(props[k]) != aeron_value(v))
    if drift:
        raise Violation('driver.properties drifts from the embedded overrides: ' + ', '.join(
            f'{k} {props.get(k, "<missing>")} != {ENGINE_DRIVER_PROPERTIES[k]}' for k in drift))
    overlay = parse_properties(overlay_text, 'driver-dev.properties')
    extra = sorted(set(overlay) - DEV_OVERLAY_KEYS)
    if extra:
        raise Violation('driver-dev.properties may set only threading and idle keys; refused ' + ', '.join(extra))
    if overlay.get('aeron.threading.mode') != 'SHARED':
        raise Violation('driver-dev.properties must set aeron.threading.mode=SHARED (the member has one CPU)')
    return props, overlay


def _validate_driver_block(manifest, mode_key, libs_key, who):
    mode = manifest.get(mode_key, 'embedded')
    if mode not in DRIVER_MODES:
        raise Violation(f'{mode_key} must be embedded or external, got ' + str(mode))
    libs = manifest.get(libs_key)
    if mode == 'embedded':
        if libs is not None:
            raise Violation(f'{libs_key} without {mode_key} external: {who} stage no driver')
        return
    if not libs:
        raise Violation(f'{mode_key} external needs {libs_key} (aeronmd, its two .so, driver.properties, the dev overlay)')
    if set(libs) != ENGINE_LIBS:
        raise Violation(f'{libs_key} must be exactly ' + ', '.join(sorted(ENGINE_LIBS)) + '; got ' + ', '.join(sorted(libs)))
    for name, lib in libs.items():
        _lib(lib, f'{libs_key} ' + name, changed=f'{libs_key} changed: ' + name)
        if (name == 'aeronmd') != (lib.get('exec') is True):
            raise Violation(f'{libs_key} aeronmd must be exec and nothing else may be: ' + name)
    check_driver_properties(Path(libs['driver.properties']['path']).read_text(),
                            Path(libs['driver-dev.properties']['path']).read_text())


def validate_engine_driver(manifest):
    _validate_driver_block(manifest, 'engine_driver', 'engine_libs', 'the embedded engines')


def validate_projector_driver(manifest):
    """The money projector's driver mode, the same rules as the engines' (an external projector
    stages the pinned aeronmd set and attaches to it at AERON_DIR; an embedded one stages nothing and never sets AERON_DIR)."""
    _validate_driver_block(manifest, 'projector_driver', 'projector_libs', 'an embedded projector')


def _target(manifest, name):
    entry = manifest['artifacts'].get(name)
    return None if entry is None else entry.get('target')


def validate_build_b(manifest, path):
    """Build B rules by manifest kind (kinded manifests carry ``manifest_kind``; older manifests have none and keep the old rules)."""
    for name in OPTIONAL_BINARIES:
        entry = manifest['artifacts'].get(name)
        if entry is not None and 'target' in entry and not CMAKE_TARGET.fullmatch(str(entry['target'])):
            raise Violation(f'{name}: target must be a CMake target name')
    kind = manifest.get('manifest_kind')
    if kind is None:
        return
    if kind not in KINDS:
        raise Violation('unknown manifest kind ' + str(kind))
    if Path(path).name.split('--')[0].removesuffix('.json') != kind:
        raise Violation(f'manifest kind {kind} does not match the file name {Path(path).name}')
    staged = [n for n in ('forwarder_b', 'bridge_b') if manifest['artifacts'].get(n) is not None]
    for name in staged + [n for n in ('forwarder', 'bridge') if manifest['artifacts'].get(n) is not None]:
        if _target(manifest, name) is None:
            raise Violation(f'{name} needs a pinned CMake target (artifacts.{name}.target, set by mk_manifests.py)')
    for name in ('forwarder', 'bridge'):
        if manifest['artifacts'].get(name) is not None and NC_TARGET.fullmatch(_target(manifest, name)):
            raise Violation(f'build A {name} must be a real build, got {_target(manifest, name)}')
    rest = kind.split('-', 1)[1] if '-' in kind else ''
    if rest.startswith('a05'):
        for name in staged:
            if NC_TARGET.fullmatch(_target(manifest, name)):
                raise Violation(f'an A05 manifest stages the negative build {_target(manifest, name)} as {name}: build B is a '
                                'real ct build')
    elif rest.startswith('red'):         # red-a03/red-a04, red1/red2
        for name in staged:
            if not NC_TARGET.fullmatch(_target(manifest, name)):
                raise Violation(f'a RED manifest stages the real build {_target(manifest, name)} as {name}')
    elif rest.startswith('a03'):
        if staged != ['forwarder_b'] or _target(manifest, 'forwarder_b') != A03_NC_TARGET or manifest['artifacts'].get('forwarder') is None:
            raise Violation(f'an A03 manifest stages {A03_NC_TARGET} as forwarder_b and build A as forwarder, nothing else '
                            '(the A03 drain is the forwarder swap)')
    elif staged:
        raise Violation(f'manifest kind {kind} stages no build B: ' + ', '.join(staged))


def check_build_b(manifest, scenario_name):
    """5.2 at the scenario: core-drill-a05-* refuses an nc_ target as build B, core-red-* refuses a real build as ``*_b``."""
    for name in ('forwarder_b', 'bridge_b'):
        entry = manifest['artifacts'].get(name)
        if entry is None:
            continue
        target = entry.get('target')
        if scenario_name.startswith('core-drill-a05-'):
            if target is None:
                raise Violation(f'{name} needs a pinned CMake target for an A05 drill')
            if NC_TARGET.fullmatch(target):
                raise Violation(f'an A05 drill refuses the negative build {target} as {name}')
        elif scenario_name.startswith('core-red-') and target is not None and not NC_TARGET.fullmatch(target):
            raise Violation(f'a RED runs a negative build; refused the real build {target} as {name}')


def check_engine_driver_skip(manifest, path, value):
    """ENGINE_DRIVER_SKIP=1 (the harness environment; the wrapper of the two members then starts no aeronmd) only on the
    edk-cnctimeout control manifest. Returns the members whose driver is skipped (empty when unset)."""
    if value is None or value == '':
        return ()
    kind = manifest.get('manifest_kind')
    if kind not in EDK_CNCTIMEOUT_KINDS or Path(path).name.split('--')[0].removesuffix('.json') != kind:
        raise Violation(f'ENGINE_DRIVER_SKIP is refused outside {EDK_CNCTIMEOUT_KIND}.json; manifest {Path(path).name}')
    if manifest.get('engine_driver') != 'external':
        raise Violation('ENGINE_DRIVER_SKIP needs engine_driver external')
    if value != '1':
        raise Violation('ENGINE_DRIVER_SKIP=1 only (it skips ' + ' and '.join(ENGINE_DRIVER_SKIP_MEMBERS) + ')')
    return ENGINE_DRIVER_SKIP_MEMBERS


def validate_cpus(manifest, cpu_count):
    limits = manifest['limits']
    cpu_set = manifest['cpu_set']
    if not isinstance(cpu_set, list) or not cpu_set or len(set(cpu_set)) != len(cpu_set):
        raise Violation('cpu_set must be an explicit list of distinct CPUs')
    by_role = limits.get('cpu_set_by_role', {})
    roles = roles_of(manifest)
    for role, cpus in by_role.items():
        if role not in roles:
            raise Violation('cpu set for an unknown role: ' + role)
        if (not isinstance(cpus, list) or not cpus or len(set(cpus)) != len(cpus)
                or any(type(c) is not int or c < 0 or c >= cpu_count for c in cpus)):
            raise Violation('invalid cpu set for ' + role)
    missing = [r for r in ENGINES if r not in by_role]
    if missing:
        raise Violation('every engine member must be pinned to its own cpuset: ' + ', '.join(missing))
    used = set()
    for role in ENGINES:
        cpus = set(by_role[role])
        if cpus & used:
            raise Violation('engine cpusets must be pairwise disjoint: ' + role)
        if not cpus <= set(cpu_set):
            raise Violation('engine cpuset outside the fixture cpu_set: ' + role)
        used |= cpus
    probe = set(by_role.get('probe', []))
    if not probe or probe & set(cpu_set):
        raise Violation('probe CPUs must be explicit and separate from service CPUs')
    for role, quota in limits.get('cpu_quota_by_role', {}).items():
        cpus = by_role.get(role, cpu_set)
        if role not in roles or type(quota) not in (int, float) or not 0 < quota <= len(cpus):
            raise Violation('invalid bounded CPU quota for ' + str(role))


def validate_replica_slot(manifest):
    """shadow0 runs the core jar as the replica (one artifact) through the engines' wrapper (their driver mode), on the
    replica kinds and nowhere else among the kinded manifests."""
    kind = manifest.get('manifest_kind')
    slot = manifest['slot_artifacts'].get('shadow0')
    entry = manifest['artifacts'].get('shadow')
    if kind in REPLICA_KINDS and slot != 'shadow':
        raise Violation(f'manifest kind {kind} runs the replica: slot_artifacts.shadow0 must be shadow, got {slot}')
    if kind is not None and kind not in REPLICA_KINDS and slot is not None:
        raise Violation(f'manifest kind {kind} runs no replica: slot_artifacts.shadow0 must be null, got {slot}')
    if slot != 'shadow':
        return
    if entry is None:
        raise Violation('shadow0 runs the shadow artifact, but artifacts.shadow is null')
    if entry.get('sha256') != (manifest['artifacts'].get('ae') or {}).get('sha256'):
        raise Violation('artifacts.shadow must be the core jar (artifacts.ae): the replica is CORE_ROLE=replica of that jar')
    if entry.get('driver') != manifest.get('engine_driver', 'embedded'):
        raise Violation(f'artifacts.shadow driver {entry.get("driver")} must equal engine_driver '
                        f'{manifest.get("engine_driver", "embedded")}: the replica runs through the engines\' wrapper')
    if entry.get('libs'):
        raise Violation('artifacts.shadow stages no libs: an external replica runs on engine_libs')


GATEWAY_ARTIFACT_KEYS = {'path', 'sha256', 'source_sha', 'driver', 'target', 'libs', 'defines', 'mode'}
GATEWAY_TARGETS = {'gateway': 'oe-gateway', 'gateway_nc': 'oe-gateway', 'stream': 'oe-stream', 'gateway_stub': 'gateway_shim',
                   'session_stub': 'ct_session_stub'}


PROJECTION_ARTIFACT_KEYS = {'path', 'sha256', 'source_sha', 'driver', 'target', 'libs', 'mode', 'defines'}


def validate_projection_artifacts(manifest):
    """The projection binaries of a projection manifest: each declared (null when absent), pinned like a slot binary,
    its target fixed by its key. The stand-in runs CoreProbe JVMs (each on its own embedded driver), so it is embedded
    and names its mode; the projector binary names its driver mode and stages the external driver's libraries."""
    artifacts = manifest['artifacts']
    for name in PROJECTION_BINARIES:
        if name not in artifacts:
            raise Violation('a projection manifest declares every projection artifact explicitly (null when absent): ' + name)
        entry = artifacts[name]
        if entry is None:
            continue
        if not isinstance(entry, dict) or set(entry) - PROJECTION_ARTIFACT_KEYS:
            raise Violation(f'{name}: artifact keys are ' + ', '.join(sorted(PROJECTION_ARTIFACT_KEYS)))
        _source(entry, name); _file(entry, name)
        if entry.get('target') != PROJECTION_TARGETS[name]:
            raise Violation(f'{name}: target must be {PROJECTION_TARGETS[name]}, got {entry.get("target")!r}')
        if entry.get('driver') not in DRIVER_MODES:
            raise Violation(name + ': driver must be embedded or external')
        if name == 'projector_stub' and (entry['driver'] != 'embedded' or entry.get('mode') not in STUB_MODES):
            raise Violation('projector_stub: the stand-in runs CoreProbe on its embedded driver (driver embedded) and names '
                            'its mode: ' + ', '.join(sorted(STUB_MODES)))
        if name != 'projector_stub' and 'mode' in entry:
            raise Violation(name + ': only the stand-in has a mode')
        defines = entry.get('defines')
        if name == 'history_projector_nc':
            if not isinstance(defines, list) or len(defines) != 1 or not set(defines) <= PROJECTION_NC_DEFINES:
                raise Violation('history_projector_nc names its one control define, one of '
                                + ', '.join(sorted(PROJECTION_NC_DEFINES)))
            kind = manifest.get('manifest_kind')
            want = (GATEWAY_KINDS.get(kind) or {}).get('projector_define')
            if kind in GATEWAY_KINDS and defines != [want]:
                raise Violation(f'history_projector_nc of kind {kind} is the {want} build, got defines {defines}')
        elif defines is not None:
            raise Violation(name + ': only a control build names defines')
        libs = entry.get('libs') or {}
        if entry['driver'] == 'external' and name != 'projector_stub' and set(libs) != {'aeronmd', 'libaeron_driver.so', 'libaeron.so'}:
            raise Violation(f'{name}: an external slot stages aeronmd, libaeron_driver.so and libaeron.so')
        for lib_name, lib in libs.items():
            if '/' in lib_name:
                raise Violation(name + ': library names are flat file names')
            _lib(lib, name + ' library ' + lib_name)


MARKETDATA_ARTIFACT_KEYS = {'path', 'sha256', 'source_sha', 'driver', 'target', 'libs', 'defines'}


def validate_marketdata_artifacts(manifest):
    """The market-data binary of a market-data manifest: declared (null when absent), pinned like a slot binary, its
    target oe-marketdata; an external one stages the driver files."""
    artifacts = manifest['artifacts']
    for name in MARKETDATA_BINARIES:
        if name not in artifacts:
            raise Violation('a market-data manifest declares its artifact explicitly (null when absent): ' + name)
        entry = artifacts[name]
        if entry is None:
            continue
        if not isinstance(entry, dict) or set(entry) - MARKETDATA_ARTIFACT_KEYS:
            raise Violation(f'{name}: artifact keys are ' + ', '.join(sorted(MARKETDATA_ARTIFACT_KEYS)))
        _source(entry, name); _file(entry, name)
        if entry.get('target') != MARKETDATA_TARGETS[name]:
            raise Violation(f'{name}: target must be {MARKETDATA_TARGETS[name]}, got {entry.get("target")!r}')
        if entry.get('driver') not in DRIVER_MODES:
            raise Violation(name + ': driver must be embedded or external')
        defines = entry.get('defines')
        if name in MARKETDATA_TEST_ARTIFACTS:
            if not isinstance(defines, list) or not defines or not set(defines) <= MARKETDATA_NC_DEFINES:
                raise Violation(f'{name}: defines is a non-empty list of ' + ', '.join(sorted(MARKETDATA_NC_DEFINES)))
        elif defines is not None:
            raise Violation(f'{name}: the product build carries no defines')
        libs = entry.get('libs') or {}
        if entry['driver'] == 'external' and set(libs) != {'aeronmd', 'libaeron_driver.so', 'libaeron.so'}:
            raise Violation(f'{name}: an external slot stages aeronmd, libaeron_driver.so and libaeron.so')
        for lib_name, lib in libs.items():
            if '/' in lib_name:
                raise Violation(name + ': library names are flat file names')
            _lib(lib, name + ' library ' + lib_name)


def validate_gateway_artifacts(manifest):
    """The gateway binaries of a gateway manifest: each declared (null when absent), pinned like a slot binary (path,
    sha256, 40-hex source commit, driver mode, the libraries an external one stages), its target fixed by its key. A
    gateway_nc names its control defines; the HTTP shim runs CoreProbe JVMs (each on its own embedded driver), so it is
    embedded and names its mode."""
    artifacts = manifest['artifacts']
    for name in GATEWAY_BINARIES:
        if name not in artifacts:
            raise Violation('a gateway manifest declares every gateway artifact explicitly (null when absent): ' + name)
        entry = artifacts[name]
        if entry is None:
            continue
        if not isinstance(entry, dict) or set(entry) - GATEWAY_ARTIFACT_KEYS:
            raise Violation(f'{name}: artifact keys are ' + ', '.join(sorted(GATEWAY_ARTIFACT_KEYS)))
        _source(entry, name); _file(entry, name)
        if entry.get('target') != GATEWAY_TARGETS[name]:
            raise Violation(f'{name}: target must be {GATEWAY_TARGETS[name]}, got {entry.get("target")!r}')
        if entry.get('driver') not in DRIVER_MODES:
            raise Violation(name + ': driver must be embedded or external')
        if name == 'gateway_stub' and (entry['driver'] != 'embedded' or entry.get('mode') not in SHIM_MODES):
            raise Violation('gateway_stub: the shim runs CoreProbe on its embedded driver (driver embedded) and names its '
                            'mode: ' + ', '.join(sorted(SHIM_MODES)))
        if name != 'gateway_stub' and 'mode' in entry:
            raise Violation(name + ': only the shim has a mode')
        defines = entry.get('defines')
        if name == 'gateway_nc':
            if not isinstance(defines, list) or not defines or not set(defines) <= GATEWAY_NC_DEFINES:
                raise Violation('gateway_nc names its control defines, a non-empty subset of ' + ', '.join(sorted(GATEWAY_NC_DEFINES)))
            kind = manifest.get('manifest_kind')
            if kind in GATEWAY_KINDS and defines != [nc_define(kind)]:
                raise Violation(f'gateway_nc of kind {kind} is the {nc_define(kind)} build, got defines {defines}')
        elif defines is not None:
            raise Violation(name + ': only gateway_nc carries control defines')
        libs = entry.get('libs') or {}
        if entry['driver'] == 'external' and name != 'gateway_stub' and set(libs) != {'aeronmd', 'libaeron_driver.so', 'libaeron.so'}:
            raise Violation(f'{name}: an external slot stages aeronmd, libaeron_driver.so and libaeron.so')
        for lib_name, lib in libs.items():
            if '/' in lib_name:
                raise Violation(name + ': library names are flat file names')
            _lib(lib, name + ' library ' + lib_name)


def validate_core_jvm_properties(manifest):
    """``core_jvm_properties``: {name: positive integer string} over CORE_JVM_PROPERTIES; never a timeout."""
    props = manifest.get('core_jvm_properties')
    if props is None:
        return
    if not isinstance(props, dict):
        raise Violation('core_jvm_properties must be an object')
    for key, value in props.items():
        if key not in CORE_JVM_PROPERTIES:
            raise Violation('core_jvm_properties is an allowlist; refused ' + str(key))
        if not (isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,11}', value)):
            raise Violation(f'core_jvm_properties.{key} must be a positive integer string, got {value!r}')


def validate_role_limits(limits, roles=ROLES):
    """Optional per-role overrides of shm_mb / memory_mb (an ME member needs 1.5 GiB of tmpfs)."""
    for key in ('shm_mb_by_role', 'memory_mb_by_role'):
        for role, value in (limits.get(key) or {}).items():
            if role not in roles:
                raise Violation(key + ' names an unknown role: ' + str(role))
            if integer(value) <= 0:
                raise Violation(key + ' must be positive and explicit: ' + role)


def validate_core_manifest(manifest, manifest_path, cpu_count=None, profiles=journal_decode.PROFILES,
                           require_me_enforced=False):
    cpu_count = os.cpu_count() if cpu_count is None else cpu_count
    try:
        if manifest['schema_version'] != 2 or manifest.get('topology') != 'core':
            raise Violation('core manifest must be schema_version 2, topology core')
        if not re.fullmatch(r'rc2-[0-9a-f]{12}', manifest['run_id']):
            raise Violation('unknown core fixture identity')
        missing = MANIFEST_KEYS - set(manifest)
        if missing:
            raise Inconclusive('incomplete core manifest: ' + ', '.join(sorted(missing)))
        unknown = set(manifest) - MANIFEST_KEYS - OPTIONAL_MANIFEST_KEYS
        if unknown:
            raise Violation('manifest keys are an allowlist; refused ' + ', '.join(sorted(unknown)))
        if manifest['timeouts'] != 'production':
            raise Violation('the core fixture runs production election/heartbeat/session timeouts only')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', manifest['image']):
            raise Violation('runtime image must be immutable')
        path = Path(manifest_path).absolute()
        root = Path(manifest['state_root'])
        if root != path.parent / 'fixtures' / manifest['run_id'] or root.resolve() != root:
            raise Violation('state path escapes the manifest-owned fixture directory')
        if manifest['failure_domain'] != 'single_host_process_loss':
            raise Violation('single-host containers cannot prove host HA')
        net = ipaddress.ip_network(manifest['network']['subnet'])
        private = [ipaddress.ip_network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]
        # Archive control ports (AE and ME journal) are reachable only inside this internal network.
        if (net.version != 4 or net.prefixlen != 24 or not any(net.subnet_of(n) for n in private)
                or manifest['network']['internal'] is not True):
            raise Violation('fixture needs its own internal RFC1918 /24 network: no archive port leaves it')
        nodes = manifest['nodes']
        legacy = LEGACY_ROLES & set(nodes)
        if legacy:
            raise Violation('legacy roles are absent from the core topology: ' + ', '.join(sorted(legacy)))
        gateway = gateway_manifest(manifest)
        roles = roles_of(manifest)
        if set(nodes) != roles:
            raise Violation('core topology roles are exactly ' + ', '.join(sorted(roles)) + '; got '
                            + ', '.join(sorted(set(nodes) ^ roles)))
        if len(set(nodes.values())) != len(nodes):
            raise Violation('two roles share an address')
        for value in nodes.values():
            address = ipaddress.ip_address(value)
            if address not in net or address in {net.network_address, net.broadcast_address, net.network_address + 1}:
                raise Violation('endpoint is outside the fixture or collides with its gateway')
        projection = projection_manifest(manifest)
        if manifest['ports'] != ports_of(manifest):
            raise Violation('core port profile differs from the fixture contract')
        for field in ['shm_mb', 'memory_mb', 'disk_min_free_mb']:
            if integer(manifest['limits'][field]) <= 0:
                raise Violation('resource limits must be positive and explicit')
        validate_role_limits(manifest['limits'], roles)
        validate_cpus(manifest, cpu_count)
        integer(manifest['seed'])
        artifacts = manifest['artifacts']
        marketdata = marketdata_manifest(manifest)
        unknown = (set(artifacts) - set(REQUIRED_JARS) - set(OPTIONAL_BINARIES) - (set(GATEWAY_BINARIES) if gateway else set())
                   - (set(PROJECTION_BINARIES) if projection else set()) - (set(MARKETDATA_BINARIES) if marketdata else set()))
        if unknown:
            raise Violation('unknown artifacts: ' + ', '.join(sorted(unknown)))
        for role in REQUIRED_JARS:
            if artifacts.get(role) is None:
                raise Inconclusive('missing required artifact: ' + role)
            _source(artifacts[role], role); _file(artifacts[role], role)
        for role in OPTIONAL_BINARIES:
            if role not in artifacts:
                raise Violation('optional slot artifact must be declared explicitly (null when absent): ' + role)
            entry = artifacts[role]
            if entry is None:
                continue
            _source(entry, role); _file(entry, role)
            if entry.get('driver') == 'java_media_driver':
                raise Violation('driver java_media_driver is retired: external means the staged aeronmd')
            if entry.get('driver') not in DRIVER_MODES:
                raise Violation(role + ': driver must be embedded or external')
            for name, lib in (entry.get('libs') or {}).items():
                if '/' in name:
                    raise Violation(role + ': library names are flat file names')
                _lib(lib, role + ' library ' + name)
        if gateway:
            validate_gateway_artifacts(manifest)
        if projection:
            validate_projection_artifacts(manifest)
        if marketdata:
            validate_marketdata_artifacts(manifest)
        slots = manifest['slot_artifacts']
        if set(slots) != set(slots_of(manifest)):
            raise Violation('slot_artifacts must name every slot role: ' + ', '.join(sorted(slots_of(manifest))))
        for slot, name in slots.items():
            if name is not None and name not in {**SLOT_ARTIFACTS, **GATEWAY_SLOT_ARTIFACTS, **PROJECTION_SLOT_ARTIFACTS,
                                                 **MARKETDATA_SLOT_ARTIFACTS}[slot]:
                raise Violation(f'slot {slot} cannot run artifact {name}')
            if name is not None and (slot in GATEWAY_SLOTS or slot in PROJECTION_SLOTS or slot in MARKETDATA_SLOTS) \
                    and artifacts.get(name) is None:
                raise Violation(f'slot {slot} runs {name}, but artifacts.{name} is null')
        validate_core_jvm_properties(manifest)
        validate_replica_slot(manifest)
        for key in PINNED_PROGRAMS + [k for k in OPTIONAL_PROGRAMS if k in manifest]:
            helper = manifest[key]
            for path_key, digest_key in [('path', 'sha256'), ('source_path', 'source_sha256')]:
                file = Path(helper[path_key])
                if not file.is_absolute() or file.is_symlink() or not file.is_file():
                    raise Inconclusive('missing probe input: ' + key + ' ' + path_key)
                if hashlib.sha256(file.read_bytes()).hexdigest() != helper[digest_key]:
                    raise Violation('probe input changed: ' + key + ' ' + path_key)
        for name, lib in (manifest.get('probe_libs') or {}).items():
            if '/' in name:
                raise Violation('probe_libs: library names are flat file names')
            _lib(lib, 'probe_libs ' + name, changed='probe input changed: probe_libs ' + name)
        drivers = [k for k in ('t1_me_driver', 't1_core_driver') if k in manifest]
        if drivers and not (manifest.get('probe_libs') or {}).get('aeronmd'):
            # The T1 drivers attach to the probe's own aeronmd; without it the probe would idle and the
            # drivers fail at me_genesis with an opaque Aeron error, after every container started
            raise Violation(f'{" and ".join(drivers)} pinned without probe_libs.aeronmd: the T1 drivers need the probe\'s '
                            'staged media driver')
        credentials = manifest['credentials']
        if credentials.get('ae') != AE_CREDENTIAL_ENV:
            retired = [retired_env_refusal(v) for v in (credentials.get('ae') or {}).values() if v in RETIRED_ENV]
            raise Violation('core credentials must use CORE_AUTH_KEYS / CORE_AUTH_CREDENTIAL'
                            + (': ' + '; '.join(retired) if retired else ''))
        me = credentials.get('me') or {}
        if me.get('mode') not in ME_AUTH_MODES:
            raise Violation('ME credential mode must be declared: enforced | not_enforced_by_artifact')
        if require_me_enforced and me['mode'] != 'enforced':
            raise Violation('ME credential mode must be enforced for drills: an authenticating ME refuses a credential-less session')
        for key in ['keys_env', 'credential_env']:
            if not re.fullmatch(r'[A-Z][A-Z0-9_]{2,63}', me.get(key) or ''):
                raise Violation('ME credential environment names must be explicit')
            if me[key] in PROCESS_ENV or me[key] in IMAGE_ENV or me[key] in RETIRED_ENV or TIMEOUT_WORDS.search(me[key]):
                raise Violation('ME credential environment name collides with a fixture variable: ' + me[key])
        if me['keys_env'] == me['credential_env']:
            raise Violation('ME key table and credential need distinct environment names')
        validate_engine_driver(manifest)
        validate_projector_driver(manifest)
        validate_build_b(manifest, path)
        profile = manifest['me_journal_profile']
        if profile not in journal_decode.profiles_spec(profiles):
            raise Violation('unknown ME journal profile ' + str(profile))
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, (Violation, Inconclusive)):
            raise
        raise Inconclusive('incomplete core manifest: ' + str(error)) from error


def assert_production_timeouts(environment, allowed=PROCESS_ENV, exempt_values=None):
    """Fixture-side guard: a process receives only allowlisted names, and no value carries a timeout. A timeout name
    passes only at its exact exempt value (DRIVER_TIMEOUT_EXEMPT, or the map a caller names)."""
    exempt_values = DRIVER_TIMEOUT_EXEMPT if exempt_values is None else exempt_values
    for key, value in environment.items():
        if key in RETIRED_ENV:
            raise Violation('refusing a retired environment name: ' + retired_env_refusal(key))
        if key not in allowed:
            raise Violation('environment names are an allowlist; refusing ' + key)
        exempt = key in exempt_values and type(value) is str and value == exempt_values[key]
        if (TIMEOUT_WORDS.search(key) and not exempt) or JVM_TIMEOUT.search(str(value)):
            raise Violation('refusing to pass a timeout setting to a fixture process: ' + key)



def check_image_config(config):
    """The same allowlist for the pinned image itself: its Env names are allowlisted and nothing in Env, Entrypoint or
    Cmd carries a JVM timeout override. Returns the env NAMES for the ownership record."""
    env = dict(entry.split('=', 1) for entry in config.get('Env') or [])
    unknown = set(env) - IMAGE_ENV
    if unknown:
        raise Violation('pinned image carries non-allowlisted environment ' + ', '.join(sorted(unknown)))
    for text in list(env.values()) + list(config.get('Entrypoint') or []) + list(config.get('Cmd') or []):
        if JVM_TIMEOUT.search(text):
            raise Violation('pinned image carries a timeout override: ' + text)
    return sorted(env)


GENESIS_DERIVATION = 'per-run: odd(sha256(run_id) mod 2^61 + life - 1), in [1, 2^62)'


def derive_genesis_id(run_id, life=1):
    """The ME/core genesisId of one run, derived from its run_id at run time (deterministic, odd,
    in [1, 2^62), distinct per life), so two runs of one kind (siblings that differ only in run_id) never repeat an id."""
    import hashlib
    if type(life) is not int or life < 1:
        raise Violation('a genesis life is a positive integer: ' + repr(life))
    base = int.from_bytes(hashlib.sha256(str(run_id).encode()).digest(), 'big') % (1 << 61)
    return hex(((base + life - 1) % (1 << 61)) * 2 + 1)


def child_manifest(manifest, parent, tag):
    """A child of ``manifest`` with a fresh run identity, written under ``parent`` as
    ``<kind>--<run_id>-<tag>.json`` when the manifest carries a kind (the name ``validate_build_b`` checks against
    ``manifest_kind``, as mk_manifests.py writes them), else ``<run_id>-<tag>-manifest.json`` as before. Returns (path, child)."""
    import uuid
    child = json.loads(json.dumps(manifest))
    child['run_id'] = 'rc2-' + uuid.uuid4().hex[:12]
    parent = Path(parent)
    child['state_root'] = str(parent / 'fixtures' / child['run_id'])
    if '--' in tag or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', tag):
        raise Violation('a child manifest tag is a short name without "--": ' + tag)
    kind = child.get('manifest_kind')
    path = parent / (f'{kind}--{child["run_id"]}-{tag}.json' if kind else f'{child["run_id"]}-{tag}-manifest.json')
    with path.open('x') as stream:
        json.dump(child, stream, indent=1); stream.write('\n')
    return path, child


def load(path):
    return json.loads(Path(path).read_text())
