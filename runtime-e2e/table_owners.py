# SPDX-License-Identifier: Apache-2.0
"""One writer per table: the grants and login-role listing of every fixture database, and its verdict (pure).

The listing (``listing_sql`` per database, ``roles_sql`` and ``sessions_sql`` once) is taken by the bootstrap superuser
after every writer created its relations. For each relation of schema public (tables and views; indexes and sequences are
not relations of the ownership table) it records the owner, the ACL as granted and, per role that is neither a superuser
nor a predefined ``pg_*`` role, the privileges the role holds in effect (``has_table_privilege``: through ownership, a
grant to the role or to a group it belongs to). The logins come from two sources: what each process was told
(``declared_logins``, the user names of its PostgreSQL settings) and the sessions the server holds at the listing
(``pg_stat_activity``, the client address mapped to its slot).

``judge`` returns one line per finding source (the shape of smoke_core's lines), so a control can name exactly one:

* ``login:<role>``             a login role used by more than one process kind -> ``login role shared by two process
                               kinds: <role>``
* ``superuser:<kind>``         a process kind logs in as a superuser -> ``process kind logs in as the bootstrap superuser:
                               <kind>``
* ``session:<slot>``           a session from a slot's address under another role than the slot declares ->
                               ``undeclared login: <kind> as <role>``
* ``relation:<db>.<rel>``      a relation the ownership table does not name -> ``relation not in the ownership table:
                               <db>.<rel>``; a named one missing -> ``relation missing: <db>.<rel>`` (INCONCLUSIVE: its
                               writer has not created it)
* ``owner:<db>.<rel>``         ``owner of <rel> is <role>, the table names <writer>``
* ``writer:<db>.<rel>``        the roles with INSERT or UPDATE (the retention role judged apart): more than the named
                               writer -> ``second writer on <rel>: <role>``; none -> ``no writer on <rel>``
* ``delete:<db>.<rel>``        DELETE or TRUNCATE held by a role that is neither the writer nor, where the table names it,
                               the retention role -> ``unnamed delete role on <rel>: <role>``
* ``retention:<db>.<rel>``     on a table the retention role belongs to: INSERT or UPDATE -> ``retention role can insert:
                               <rel>``; DELETE or TRUNCATE missing -> ``retention role has no grant: <rel>``; anything else
                               (SELECT outside the relations its age delete reads, REFERENCES, TRIGGER) or any grant where
                               the table gives it no place -> ``retention role has a grant outside its tables: <rel>``. On a
                               view it may hold at most DELETE and TRUNCATE.
* ``readers:<db>.<view>``      SELECT granted on a view to a role other than its owner and the named reader group ->
                               ``view readable by an unnamed role: <view>: <role>``

The bootstrap superuser and every other superuser are listed apart (``superusers``) and never judged as writers; no
process kind may log in as one.
"""
import json
from urllib.parse import urlparse

import core_contracts

PRIVILEGES = ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER')
RELATION_KINDS = {'r': 'table', 'p': 'table', 'v': 'view', 'm': 'view', 'f': 'table'}

# The process kind of each fixture slot that may log in to PostgreSQL (the money projector is the ``projector`` node)
SLOT_KINDS = {'projector': 'money projector', 'pj0': 'oe-projector', 'pj1': 'oe-projector', 'gw0': 'oe-gateway',
              'gw1': 'oe-gateway', 'st0': 'oe-stream', 'st1': 'oe-stream', 'md0': 'oe-marketdata'}


def listing_sql():
    """One database's relations of schema public, as one JSON value."""
    privileges = ', '.join(f"'{p}'" for p in PRIVILEGES)
    return ("SELECT COALESCE(json_agg(json_build_object('name', c.relname, 'kind', c.relkind, "
            "'owner', pg_get_userbyid(c.relowner), 'acl', COALESCE(c.relacl::text[], ARRAY[]::text[]), "
            "'effective', (SELECT COALESCE(json_object_agg(r.rolname, (SELECT COALESCE(json_agg(p ORDER BY p), '[]'::json) "
            f"FROM unnest(ARRAY[{privileges}]) p WHERE has_table_privilege(r.oid, c.oid, p))), '{{}}'::json) "
            "FROM pg_roles r WHERE NOT r.rolsuper AND r.rolname !~ '^pg_')) ORDER BY c.relname), '[]'::json) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')")


def default_acl_sql():
    return ("SELECT COALESCE(json_agg(json_build_object('role', pg_get_userbyid(d.defaclrole), 'type', d.defaclobjtype, "
            "'acl', d.defaclacl::text[]) ORDER BY 1), '[]'::json) FROM pg_default_acl d")


def roles_sql():
    return ("SELECT COALESCE(json_agg(json_build_object('name', r.rolname, 'login', r.rolcanlogin, 'super', r.rolsuper, "
            "'member_of', ARRAY(SELECT b.rolname FROM pg_auth_members m JOIN pg_roles b ON b.oid = m.roleid "
            "WHERE m.member = r.oid ORDER BY 1)) ORDER BY r.rolname), '[]'::json) FROM pg_roles r WHERE r.rolname !~ '^pg_'")


def sessions_sql():
    return ("SELECT COALESCE(json_agg(json_build_object('db', datname, 'user', usename, 'addr', host(client_addr)) "
            "ORDER BY datname, usename), '[]'::json) FROM pg_stat_activity "
            "WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()")


def take_listing(fixture):
    """Every fixture database's relations and default privileges, the roles and the sessions (as the superuser)."""
    databases = json.loads(fixture.psql('postgres', "SELECT COALESCE(json_agg(datname ORDER BY datname), '[]'::json) "
                                                    "FROM pg_database WHERE NOT datistemplate AND datname <> 'postgres'"))
    out = {'databases': {}, 'roles': json.loads(fixture.psql('postgres', roles_sql())),
           'sessions': json.loads(fixture.psql('postgres', sessions_sql()))}
    for database in databases:
        out['databases'][database] = {'relations': json.loads(fixture.psql(database, listing_sql())),
                                      'default_acl': json.loads(fixture.psql(database, default_acl_sql()))}
    return out


def url_user(value):
    """The user name of a libpq URL (``postgresql://user@host:port/db``), None without one."""
    try:
        return urlparse(value).username
    except ValueError:
        return None


def env_logins(env):
    """The PostgreSQL user names a process's environment declares: ``*_PG_USER``, ``*_POSTGRES_USER`` and the user of a
    ``*_PG_URL``. Values only of those names are read (never a password)."""
    out = set()
    for key, value in env.items():
        if key.endswith(('_PG_USER', '_POSTGRES_USER')) and value:
            out.add(value)
        elif key.endswith('_PG_URL') and value:
            user = url_user(value)
            if user:
                out.add(user)
    return out


def declared_logins(fixture):
    """{slot: [user, ...]} from each running fixture container's environment (docker inspect), for the slots of
    SLOT_KINDS: what each process was told to log in as, read from the container, not from the harness's own code."""
    out = {}
    for slot, cid in sorted((fixture.registry.get('containers') or {}).items()):
        if slot not in SLOT_KINDS:
            continue
        config = fixture.inspect('container', cid).get('Config') or {}
        env = dict(entry.split('=', 1) for entry in config.get('Env') or [] if '=' in entry)
        users = sorted(env_logins(env))
        if users:
            out[slot] = users
    return out


def slot_of_address(nodes, address):
    for slot, ip in (nodes or {}).items():
        if ip == address:
            return slot
    return None


def _line(holds, detail, text, inconclusive=False):
    return {'holds': bool(holds), 'detail': detail, 'text': None if holds else text, 'inconclusive': bool(inconclusive)}


def judge(listing, declared, nodes, plan=None, retention=None, reader_group=None):
    """The lines of the ownership row over one listing (see the module text). ``declared``: {slot: [user]}; ``nodes``:
    the manifest's {slot: address}; ``plan``: core_contracts.TABLE_OWNERS by default."""
    plan = core_contracts.TABLE_OWNERS if plan is None else plan
    retention = retention or core_contracts.RETENTION_ROLE
    retention_select = {db: set(p.get('retention_select') or []) for db, p in core_contracts.DATABASE_ROLE_PLAN.items()}
    supers = sorted(r['name'] for r in listing['roles'] if r.get('super'))
    lines = {}

    # Logins: one process kind per login role, none of them a superuser
    kinds_by_role = {}
    for slot, users in sorted(declared.items()):
        for user in users:
            kinds_by_role.setdefault(user, set()).add(SLOT_KINDS.get(slot, slot))
    sessions = []
    for s in listing.get('sessions') or []:
        slot = slot_of_address(nodes, s.get('addr'))
        sessions.append(dict(s, slot=slot))
        if slot in SLOT_KINDS:
            kinds_by_role.setdefault(s['user'], set()).add(SLOT_KINDS[slot])
            if s['user'] not in (declared.get(slot) or []):
                lines['session:' + slot] = _line(False, {'session': s}, f'undeclared login: {SLOT_KINDS[slot]} as {s["user"]}')
    for role, kinds in sorted(kinds_by_role.items()):
        lines['login:' + role] = _line(len(kinds) == 1, {'kinds': sorted(kinds)},
                                       f'login role shared by two process kinds: {role}')
    by_kind = {}
    for role, kinds in kinds_by_role.items():
        for kind in kinds:
            by_kind.setdefault(kind, set()).add(role)
    for kind, roles in sorted(by_kind.items()):
        lines['superuser:' + kind] = _line(not (roles & set(supers)), {'roles': sorted(roles)},
                                           f'process kind logs in as the bootstrap superuser: {kind}')

    # Relations: every relation named, every named one present, one writer, deletes only by the named roles
    for db, spec in sorted(plan.items()):
        got = (listing['databases'].get(db) or {}).get('relations')
        if got is None:
            lines['database:' + db] = _line(False, {'database': db}, f'database missing: {db}', inconclusive=True)
            continue
        named = dict(spec['tables'], **spec['views'])
        present = {r['name']: r for r in got}
        for name in sorted(set(named) - set(present)):
            lines[f'relation:{db}.{name}'] = _line(False, {}, f'relation missing: {db}.{name}', inconclusive=True)
        for name, rel in sorted(present.items()):
            key = f'{db}.{name}'
            if name not in named:
                lines['relation:' + key] = _line(False, {'owner': rel['owner'], 'kind': rel['kind']},
                                                 f'relation not in the ownership table: {key}')
                continue
            writer, view = named[name], RELATION_KINDS.get(rel['kind']) == 'view'
            effective = {role: set(p) for role, p in (rel.get('effective') or {}).items()}
            lines['owner:' + key] = _line(rel['owner'] == writer, {'owner': rel['owner'], 'writer': writer},
                                          f'owner of {name} is {rel["owner"]}, the table names {writer}')
            writers = sorted(r for r, p in effective.items() if p & {'INSERT', 'UPDATE'} and r != retention)
            others = [r for r in writers if r != writer]
            lines['writer:' + key] = _line(writers == [writer], {'writers': writers, 'named': writer},
                                           f'second writer on {name}: {others[0]}' if others else f'no writer on {name}')
            allowed_delete = {writer, retention}       # the retention role is judged by its own line
            deleters = sorted(r for r, p in effective.items() if p & {'DELETE', 'TRUNCATE'} and r not in allowed_delete)
            lines['delete:' + key] = _line(not deleters, {'roles': deleters},
                                           f'unnamed delete role on {name}: {deleters[0]}' if deleters else None)
            held = effective.get(retention, set())
            history = spec.get('retention_tables')
            if not spec['retention'] or (history is not None and name not in history):
                ok, text = not held, f'retention role has a grant outside its tables: {name}'
            elif held & {'INSERT', 'UPDATE'}:
                ok, text = False, f'retention role can insert: {name}'
            elif view:
                ok, text = held <= {'DELETE', 'TRUNCATE'}, f'retention role has a grant outside its tables: {name}'
            elif not {'DELETE', 'TRUNCATE'} <= held:
                ok, text = False, f'retention role has no grant: {name}'
            else:
                extra = held - {'DELETE', 'TRUNCATE'} - ({'SELECT'} if name in retention_select.get(db, set()) else set())
                ok, text = not extra, f'retention role has a grant outside its tables: {name}'
            lines['retention:' + key] = _line(ok, {'held': sorted(held), 'table_names_it': spec['retention']}, text)
            if view:
                readers = sorted(g for g in acl_grantees(rel.get('acl'), 'r') if g not in {rel['owner']}
                                 | set((spec.get('view_readers') or {}).get(name) or []))
                lines['readers:' + key] = _line(not readers, {'readers': readers},
                                                f'view readable by an unnamed role: {name}: {readers[0]}' if readers else None)
    for db in sorted(set(listing['databases']) - set(plan)):
        rels = listing['databases'][db].get('relations') or []
        for rel in rels:
            lines[f'relation:{db}.{rel["name"]}'] = _line(False, {'owner': rel['owner']},
                                                          f'relation not in the ownership table: {db}.{rel["name"]}')
    return lines, {'superusers': supers, 'sessions': sessions, 'logins': {r: sorted(k) for r, k in kinds_by_role.items()}}


def acl_grantees(acl, letter):
    """The grantees of an ACL (``grantee=privs/grantor`` items) whose privileges carry ``letter`` (r = SELECT)."""
    out = []
    for item in acl or []:
        grantee, _, rest = item.partition('=')
        privs = rest.split('/', 1)[0]
        if letter in privs:
            out.append(grantee or 'PUBLIC')
    return out
