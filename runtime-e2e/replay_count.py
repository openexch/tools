# SPDX-License-Identifier: Apache-2.0
"""The replay-count probe of one core member, run INSIDE that member's container (``docker exec -i <member> python3 -I -``
with this file on stdin), as an operator would: it reads the member's own media driver counters from its ``cnc.dat`` and
the bytes of the driver directory under /dev/shm. It never talks to a projector. Standard library only.

A replay publication is counted as a sender-position counter (type 2, ``snd-pos``: one per network publication of the
member's driver) whose stream id is one of the replay streams named on the command line: the Archive sends a replay as
an exclusive network publication on the replay channel and stream its client asked for, so a projector's open replays
are the member's network publications on that projector's replay stream. Every network publication is listed with its
stream id, so a run shows what else the driver holds.

Usage: replay_count.py <replay stream id>[,<id>...]  -> one JSON line:
  {"drivers": [{"dir", "cnc_version", "publications": [{"stream", "session", "registration", "channel"}],
                "replays": {stream: n}}], "replays": {stream: n}, "shm_bytes": n, "shm_dirs": {dir: bytes}}

CnC layout (Aeron CncFileDescriptor, version 0.2.x): five int32 buffer lengths at 4..20 (to-driver, to-clients, counter
metadata, counter values, error log), client liveness int64 at 24, start timestamp at 32, pid at 40, file page size at 48;
the buffers start at 128 in that order. A counter metadata record is 512 bytes (state int32 at 0, type id at 4, key at
16, label length at 128, label at 132); the value record is 128 bytes (value int64 at 0). The key of a publication
counter is registrationId int64, sessionId int32, streamId int32, channel length int32 and the channel.
"""
import json
import os
import struct
import sys

META_END = 128
METADATA_RECORD = 512
VALUE_RECORD = 128
RECORD_ALLOCATED = 1
SENDER_POSITION = 2


def counters(data):
    """[(id, type, key bytes, label, value)] of the allocated counters of one cnc.dat."""
    version, to_driver, to_clients, meta_len, values_len, errors = struct.unpack_from('<6i', data, 0)
    meta = META_END + to_driver + to_clients
    values = meta + meta_len
    out = []
    for i in range(meta_len // METADATA_RECORD):
        at = meta + i * METADATA_RECORD
        state, type_id = struct.unpack_from('<ii', data, at)
        if state != RECORD_ALLOCATED:
            continue
        label_len = struct.unpack_from('<i', data, at + 128)[0]
        label = data[at + 132:at + 132 + max(0, min(label_len, 380))].decode(errors='replace')
        value = struct.unpack_from('<q', data, values + i * VALUE_RECORD)[0] if values + (i + 1) * VALUE_RECORD <= len(data) else None
        out.append((i, type_id, data[at + 16:at + 128], label, value))
    return version, out


def publications(rows):
    out = []
    for _, type_id, key, label, _ in rows:
        if type_id != SENDER_POSITION:
            continue
        registration, session, stream, channel_len = struct.unpack_from('<qiii', key, 0)
        channel = key[20:20 + max(0, min(channel_len, len(key) - 20))].decode(errors='replace')
        out.append({'stream': stream, 'session': session, 'registration': registration, 'channel': channel, 'label': label})
    return out


def du(path):
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_blocks * 512
            except OSError:
                pass
    return total


def main(argv):
    streams = sorted({int(s) for s in argv[1].split(',') if s}) if len(argv) > 1 else []
    drivers, total = [], {str(s): 0 for s in streams}
    shm = '/dev/shm'
    dirs = {}
    for root, _, files in os.walk(shm):
        if 'cnc.dat' in files:
            dirs[root] = None
    for d in sorted(dirs):
        try:
            with open(os.path.join(d, 'cnc.dat'), 'rb') as f:
                data = f.read()
            version, rows = counters(data)
        except (OSError, struct.error) as error:
            drivers.append({'dir': d, 'error': str(error)})
            continue
        pubs = publications(rows)
        replays = {str(s): sum(1 for p in pubs if p['stream'] == s) for s in streams}
        for s, n in replays.items():
            total[s] += n
        drivers.append({'dir': d, 'cnc_version': version, 'publications': pubs, 'replays': replays})
    top = {}
    try:
        for name in os.listdir(shm):
            top[name] = du(os.path.join(shm, name))
    except OSError:
        pass
    print(json.dumps({'drivers': drivers, 'replays': total, 'shm_bytes': du(shm), 'shm_dirs': top}, sort_keys=True))


if __name__ == '__main__':
    main(sys.argv)
