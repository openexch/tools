# SPDX-License-Identifier: Apache-2.0
"""Per-run session keys for the core topology.

Every run mints fresh 32-byte secrets. Both tables use the v1 key spec of the cluster-kit
authenticator: ``keyId:CLASS:secretHex::users=*`` entries joined by ``;``. The users
field is mandatory and ``users=*`` is the only any-user form (a key with no users field fails the load);
every fixture principal is any-user. Clients receive one ``keyId:CLASS:secretHex`` credential (unchanged).
The ME table holds classes FORWARDER and ADMIN, and GATEWAY for the market-data slot. The replica's REPLICA key (SessionClass.REPLICA, 7 since money-schema
v7) is minted only for a manifest that runs the replica, so a table never names a class an older core cannot load. Evidence carries key ids and classes
only; ``secrets()`` is what the fixture redacts from every retained log.
"""
import secrets

AE_CLASSES = {'GATEWAY', 'FORWARDER', 'BRIDGE', 'ADMIN', 'TOOL', 'TREASURY', 'REPLICA'}
ME_CLASSES = {'FORWARDER', 'ADMIN', 'GATEWAY'}

# (principal, cluster, class, keyId). keyIds are fixed per principal so evidence is comparable across
# runs; only the secrets change. shadow0 (the replica) gets its key only when the manifest runs it (REPLICA_PRINCIPAL).
PRINCIPALS = [
    ('probe-gateway', 'ae', 'GATEWAY', 11), ('probe-admin', 'ae', 'ADMIN', 12), ('probe-tool', 'ae', 'TOOL', 13),
    ('probe-forwarder', 'ae', 'FORWARDER', 14),
    ('fwd0', 'ae', 'FORWARDER', 21), ('fwd1', 'ae', 'FORWARDER', 22),
    ('bridge0', 'ae', 'BRIDGE', 31), ('bridge1', 'ae', 'BRIDGE', 32),
    ('fwd0', 'me', 'FORWARDER', 121), ('fwd1', 'me', 'FORWARDER', 122), ('probe-admin', 'me', 'ADMIN', 112),
]
REPLICA_PRINCIPAL = ('shadow0', 'ae', 'REPLICA', 41)
RESERVED = {'shadow0': 'this manifest runs no replica (slot_artifacts.shadow0 null): no REPLICA key is minted'}
# The gateway and stream slots (minted only for a manifest that runs them): one GATEWAY key each. A stream serves
# exchange-wide order events (the replay query needs an any-user principal), so its key is a GATEWAY key with users=*, as
# every fixture key is. The gateway_stub (the test-only HTTP shim) runs in gw0/gw1 on the slot's own key.
# Each gateway also holds a TREASURY key (the gateway's treasury lane: deposit and withdraw on their own TREASURY
# session); like every key of the table it sits in CORE_AUTH_KEYS on all three members.
GATEWAY_PRINCIPALS = [('gw0', 'ae', 'GATEWAY', 51), ('gw1', 'ae', 'GATEWAY', 52), ('st0', 'ae', 'GATEWAY', 53),
                      ('st1', 'ae', 'GATEWAY', 54), ('gw0-treasury', 'ae', 'TREASURY', 55),
                      ('gw1-treasury', 'ae', 'TREASURY', 56)]
# The projection slots (minted only for a manifest that runs them): one GATEWAY key each, the class of the projector's
# head probe (an any-user order-event query), as a stream's key is
PROJECTION_PRINCIPALS = [('pj0', 'ae', 'GATEWAY', 57), ('pj1', 'ae', 'GATEWAY', 58)]
# The market-data slot (minted only for a manifest that runs it): one GATEWAY key on the ME, the class the ME admits for
# market data (egress only, no ingress but the keepalive)
MARKETDATA_PRINCIPALS = [('md0', 'me', 'GATEWAY', 131)]
# A user API key of the gateway's api-key auth mode (GATEWAY_API_KEYS_FILE, one ``key:userId`` per line): 32 random
# bytes as 64 hex characters (the gateway's floor is 16 characters)
API_KEY_BYTES = 32


class KeyRing:
    def __init__(self, secret_source=None, replica=False, gateway=False, projection=False, marketdata=False):
        source = secret_source or (lambda: secrets.token_bytes(32))
        self.source = source
        self.keys = {}
        self.user_keys = {}
        self.gateway = gateway
        self.reserved = {} if replica else dict(RESERVED)
        for principal, cluster, cls, key_id in (PRINCIPALS + ([REPLICA_PRINCIPAL] if replica else [])
                                                + (GATEWAY_PRINCIPALS if gateway else [])
                                                + (PROJECTION_PRINCIPALS if projection else [])
                                                + (MARKETDATA_PRINCIPALS if marketdata else [])):
            if cls not in (AE_CLASSES if cluster == 'ae' else ME_CLASSES):
                raise ValueError(f'{principal}: class {cls} not valid on {cluster}')
            secret = source()
            if len(secret) != 32:
                raise ValueError('a session secret must be 32 bytes')
            self.keys[(principal, cluster)] = (key_id, cls, secret.hex())
        ids = [(c, k) for (_, c), (k, _, _) in self.keys.items()]
        if len(set(ids)) != len(ids):
            raise ValueError('duplicate key id within one cluster')

    def table(self, cluster):
        return ';'.join(f'{k}:{c}:{s}::users=*' for (_, cl), (k, c, s) in sorted(self.keys.items(), key=lambda i: i[1][0])
                        if cl == cluster)

    def credential(self, principal, cluster):
        key_id, cls, secret = self.keys[(principal, cluster)]
        return f'{key_id}:{cls}:{secret}'

    def secrets(self):
        return {secret for _, _, secret in self.keys.values()} | set(getattr(self, 'user_keys', {}).values())

    def api_keys(self, users):
        """The gateway API key of each user (minted on first use, then fixed for the run): {user: key}. Only a keyring
        of a manifest that runs the gateway slots mints them."""
        if not self.gateway:
            raise ValueError('this manifest runs no gateway slot: no user API key is minted')
        out = {}
        for user in users:
            if type(user) is not int or user < 1:
                raise ValueError('a user id is a positive integer: ' + repr(user))
            if user not in self.user_keys:
                secret = self.source()
                if len(secret) != API_KEY_BYTES:
                    raise ValueError('an API key is 32 random bytes')
                self.user_keys[user] = secret.hex()
            out[user] = self.user_keys[user]
        return out

    def api_keys_file(self, users):
        """The text of GATEWAY_API_KEYS_FILE for ``users``: one ``key:userId`` per line, sorted by user."""
        keys = self.api_keys(users)
        return ''.join(f'{keys[u]}:{u}\n' for u in sorted(keys))

    def evidence(self):
        """Key ids and classes only; never a secret."""
        rows = [{'principal': p, 'cluster': c, 'key_id': k, 'class': cls}
                for (p, c), (k, cls, _) in sorted(self.keys.items())]
        out = {'keys': rows, 'reserved': dict(getattr(self, 'reserved', RESERVED))}
        if getattr(self, 'gateway', False):
            out['api_key_users'] = sorted(self.user_keys)
        return out


def redact(text, values):
    for value in values:
        text = text.replace(value, '<redacted>')
    return text
