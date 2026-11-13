# SPDX-License-Identifier: Apache-2.0
"""Per-run session keys for the core topology.

Every run mints fresh 32-byte secrets. Both tables use the v1 key spec of the cluster-kit
authenticator: ``keyId:CLASS:secretHex::users=*`` entries joined by ``;``. The users
field is mandatory and ``users=*`` is the only any-user form (a key with no users field fails the load);
every fixture principal is any-user. Clients receive one ``keyId:CLASS:secretHex`` credential (unchanged).
The ME table holds classes FORWARDER and ADMIN. The replica's REPLICA key (SessionClass.REPLICA, 7 since money-schema
v7) is minted only for a manifest that runs the replica, so a table never names a class an older core cannot load. Evidence carries key ids and classes
only; ``secrets()`` is what the fixture redacts from every retained log.
"""
import secrets

AE_CLASSES = {'GATEWAY', 'FORWARDER', 'BRIDGE', 'ADMIN', 'TOOL', 'TREASURY', 'REPLICA'}
ME_CLASSES = {'FORWARDER', 'ADMIN'}

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


class KeyRing:
    def __init__(self, secret_source=None, replica=False):
        source = secret_source or (lambda: secrets.token_bytes(32))
        self.keys = {}
        self.reserved = {} if replica else dict(RESERVED)
        for principal, cluster, cls, key_id in PRINCIPALS + ([REPLICA_PRINCIPAL] if replica else []):
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
        return {secret for _, _, secret in self.keys.values()}

    def evidence(self):
        """Key ids and classes only; never a secret."""
        rows = [{'principal': p, 'cluster': c, 'key_id': k, 'class': cls}
                for (p, c), (k, cls, _) in sorted(self.keys.items())]
        return {'keys': rows, 'reserved': dict(getattr(self, 'reserved', RESERVED))}


def redact(text, values):
    for value in values:
        text = text.replace(value, '<redacted>')
    return text
