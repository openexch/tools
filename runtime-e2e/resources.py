# SPDX-License-Identifier: Apache-2.0
"""Read-only, bounded resource sampler for already-owned fixture containers."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time

from contracts import Inconclusive, Violation
from fixture import LABEL


class Resources:
    def __init__(self, fixture):
        self.fixture = fixture
        self.ids = dict(fixture.registry['containers'])
        self.stop_event = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.run, name='fixture-resource-sampler', daemon=True)

    def snapshot(self):
        result = subprocess.run(['docker', 'container', 'inspect', *self.ids.values()],
                                capture_output=True, text=True, timeout=10)
        if result.returncode: raise Inconclusive('resource sampler could not inspect owned containers')
        by_id = {row['Id']:row for row in json.loads(result.stdout)}
        sample = {'monotonic_ns':time.monotonic_ns(), 'wall_ns':time.time_ns(), 'containers':{},
                  'loadavg':Path('/proc/loadavg').read_text().strip(),
                  'host_cpu':Path('/proc/stat').read_text().splitlines()[0],
                  'disk_free_bytes':shutil.disk_usage(self.fixture.root).free}
        for name, cid in self.ids.items():
            row = by_id[cid]; labels = row['Config']['Labels']
            if labels.get(LABEL) != self.fixture.run_id or labels.get(LABEL + '.token') != self.fixture.token:
                raise Violation('resource sampler ownership mismatch')
            process = row['State']; limits = row['HostConfig']
            data = {'running':process['Running'], 'oom_killed':process['OOMKilled'],
                    'memory_limit':limits['Memory'], 'nano_cpus':limits['NanoCpus'],
                    'cpu_set':limits['CpusetCpus']}
            if process['Running']:
                pid = process['Pid']; proc = Path('/proc') / str(pid)
                lines = (proc / 'cgroup').read_text().splitlines()
                paths = [line.split(':',2)[2] for line in lines if line.startswith('0::')]
                if len(paths) != 1: raise Inconclusive('cgroup v2 metrics unavailable')
                group = Path('/sys/fs/cgroup') / paths[0].lstrip('/')
                if not group.resolve().is_relative_to('/sys/fs/cgroup'):
                    raise Violation('cgroup path escaped metrics filesystem')
                for field in ['cpu.stat','memory.current','memory.peak','memory.events','io.stat']:
                    path = group / field
                    data[field] = path.read_text().strip() if path.exists() else None
            sample['containers'][name] = data
        return sample

    def run(self):
        try:
            with (self.fixture.root / 'resources.jsonl').open('x') as out:
                while True:
                    out.write(json.dumps(self.snapshot()) + '\n'); out.flush()
                    if self.stop_event.wait(5):
                        out.write(json.dumps(self.snapshot()) + '\n'); break
        except Exception as error:
            self.error = error

    def __enter__(self):
        self.thread.start(); return self

    def __exit__(self, kind, value, traceback):
        self.stop_event.set(); self.thread.join(timeout=15)
        if self.thread.is_alive(): raise Inconclusive('resource sampler did not stop')
        if self.error and kind is None: raise Inconclusive('resource sampling failed: ' + str(self.error))
