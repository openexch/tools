# SPDX-License-Identifier: Apache-2.0
"""Per-run session keys for the core topology (harness 2.7 item 2, critic G2/G31).

Every run mints fresh 32-byte secrets. The AE table uses the RC1 K6 v1 spec
(``keyId:CLASS:secretHex``, entries joined by ``;``, AuthKeyTable.fromSpec); clients receive one
``keyId:CLASS:secretHex`` credential. The ME table (classes FORWARDER and ADMIN, RC2 L5) uses the same
format, since S6 ports the same authenticator into cluster-kit. Evidence carries key ids and classes
only; ``secrets()`` is what the fixture redacts from every retained log.
"""
import secrets

AE_CLASSES = {'GATEWAY', 'FORWARDER', 'BRIDGE', 'ADMIN', 'TOOL', 'TREASURY'}
ME_CLASSES = {'FORWARDER', 'ADMIN'}

# (principal, cluster, class, keyId). keyIds are fixed per principal so evidence is comparable across
# runs; only the secrets change. shadow0 is a reserved slot: SessionClass.REPLICA (7) arrives with the
# RC2 S1 wire freeze, and an AE table naming an unknown class refuses to load, so no key is minted.
PRINCIPALS = [
    ('probe-gateway', 'ae', 'GATEWAY', 11), ('probe-admin', 'ae', 'ADMIN', 12), ('probe-tool', 'ae', 'TOOL', 13),
    ('probe-forwarder', 'ae', 'FORWARDER', 14),
    ('fwd0', 'ae', 'FORWARDER', 21), ('fwd1', 'ae', 'FORWARDER', 22),
    ('bridge0', 'ae', 'BRIDGE', 31), ('bridge1', 'ae', 'BRIDGE', 32),
    ('fwd0', 'me', 'FORWARDER', 121), ('fwd1', 'me', 'FORWARDER', 122), ('probe-admin', 'me', 'ADMIN', 112),
]
RESERVED = {'shadow0': 'REPLICA class (7) does not exist before money-schema v7 (RC2 S1); RCS S9 provisions it'}


class KeyRing:
    def __init__(self, secret_source=None):
        source = secret_source or (lambda: secrets.token_bytes(32))
        self.keys = {}
        for principal, cluster, cls, key_id in PRINCIPALS:
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
        return ';'.join(f'{k}:{c}:{s}' for (_, cl), (k, c, s) in sorted(self.keys.items(), key=lambda i: i[1][0])
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
        return {'keys': rows, 'reserved': RESERVED}


def redact(text, values):
    for value in values:
        text = text.replace(value, '<redacted>')
    return text
