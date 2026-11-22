# SPDX-License-Identifier: Apache-2.0
"""The second-writer row on the core topology: the OMS cannot start next to a core, so its four refusals are one row.

On the core topology the OMS is never a second writer because nothing can start it:

1. a cut that names ``oms-app`` is refused (release_cut rule K5);
2. a v2 manifest with the legacy role ``oms`` is refused (core_contracts.validate_core_manifest);
3. the console refuses to boot with the retired setting ``OMS_PROJECT_DIR`` (cloud-console config/retired.go, called at
   boot by main.go);
4. a planted ``oms`` service in the console catalog is flagged by the console's process-set check.

Each refusal has a control: the same check with that one refusal switched off in a test copy must accept, and the row
then prints ``retired artifact accepted: oms-app``, ``legacy role accepted: oms``, ``retired setting accepted:
OMS_PROJECT_DIR`` or ``retired service accepted: oms``. Legs 1 and 2 run in this repository's unit suite
(test_red_proofs.RefusalRowTest). Legs 3 and 4 need a cloud-console tree (private repository) and a Go toolchain with the
console's modules in the local module cache; this module runs them on a copy of the tree:

    python3 refusals.py --console <cloud-console tree>

It prints one line per leg and per control and exits 0 only when every refusal holds and every control prints its text.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SETTING_TEXT = 'retired setting accepted: OMS_PROJECT_DIR'
SERVICE_TEXT = 'retired service accepted: oms'
CUT_TEXT = 'retired artifact accepted: oms-app'
ROLE_TEXT = 'legacy role accepted: oms'

GO_CONFIG_TEST = '''// SPDX-License-Identifier: Apache-2.0
package config

import "testing"

// The refusal row: the console refuses to boot with the retired OMS setting.
func TestRefusalRowRetiredSetting(t *testing.T) {
	err := RefuseRetiredEnv(func(k string) (string, bool) {
		if k == "OMS_PROJECT_DIR" {
			return "/srv/oms", true
		}
		return "", false
	})
	if err == nil {
		t.Fatal("''' + SETTING_TEXT + '''")
	}
	t.Log("refused: " + err.Error())
}
'''
GO_SERVICES_TEST = '''// SPDX-License-Identifier: Apache-2.0
package services

import (
	"strings"
	"testing"
)

// The refusal row: a planted oms service in the catalog is flagged by the process-set check.
func TestRefusalRowRetiredService(t *testing.T) {
	_, demo := v1Catalog("demo")
	planted := append(append([]ServiceDef{}, demo...), ServiceDef{Name: "oms"})
	d := processSetDiff(planted, v1ProcessSet(true))
	if strings.Join(d, ",") != "unexpected oms" {
		t.Fatalf("''' + SERVICE_TEXT + ''' (%v)", d)
	}
	t.Log("refused: " + strings.Join(d, ","))
}
'''


def console_copy(tree, dest):
    """A copy of the console tree without its git directory, with the row's two Go tests added."""
    shutil.copytree(tree, dest, ignore=shutil.ignore_patterns('.git'))
    (Path(dest) / 'config' / 'zz_refusal_row_test.go').write_text(GO_CONFIG_TEST)
    (Path(dest) / 'services' / 'zz_refusal_row_test.go').write_text(GO_SERVICES_TEST)
    return Path(dest)


def switch_off_setting(tree):
    """The test copy without the OMS_PROJECT_DIR refusal (its line removed from the retired list)."""
    path = Path(tree) / 'config' / 'retired.go'
    lines = path.read_text().splitlines(keepends=True)
    kept = [x for x in lines if '{"OMS_PROJECT_DIR",' not in x]
    if len(kept) != len(lines) - 1:
        raise SystemExit('the retired list does not name OMS_PROJECT_DIR once')
    path.write_text(''.join(kept))


def switch_off_service(tree):
    """The test copy whose process set takes an ``oms`` service as expected (the flag switched off)."""
    path = Path(tree) / 'services' / 'catalog_test.go'
    text = path.read_text()
    anchor = 'func v1ProcessSet(external bool) map[string]bool {\n'
    if text.count(anchor) != 1:
        raise SystemExit('v1ProcessSet not found once in services/catalog_test.go')
    path.write_text(text.replace('\treturn set\n}\n\n// processSetDiff', '\tset["oms"] = true\n\treturn set\n}\n\n// processSetDiff', 1))
    if 'set["oms"] = true' not in path.read_text():
        raise SystemExit('could not switch the process-set flag off')


def go_test(tree, package, test):
    """(passed, output) of one Go test of the copy, offline (the local module cache only)."""
    env = dict(os.environ, GOFLAGS='-mod=mod', GOPROXY='off', GOTOOLCHAIN='local')
    r = subprocess.run(['go', 'test', '-count=1', '-v', '-run', '^' + test + '$', './' + package], cwd=tree, env=env,
                       capture_output=True, text=True, timeout=900)
    return r.returncode == 0, r.stdout + r.stderr


def boot_calls_the_refusal(tree):
    """main.go refuses retired settings at boot (the check the Go test calls is the one the console runs)."""
    return 'RefuseRetiredEnv(os.LookupEnv)' in (Path(tree) / 'main.go').read_text()


def console_legs(tree):
    """[(leg, holds, text printed)] for legs 3 and 4 and their controls, on copies of ``tree``."""
    out = []
    with tempfile.TemporaryDirectory() as d:
        product = console_copy(tree, Path(d) / 'product')
        out.append(('boot calls RefuseRetiredEnv', boot_calls_the_refusal(product), 'main.go:RefuseRetiredEnv(os.LookupEnv)'))
        for package, test, text, switch in (('config', 'TestRefusalRowRetiredSetting', SETTING_TEXT, switch_off_setting),
                                            ('services', 'TestRefusalRowRetiredService', SERVICE_TEXT, switch_off_service)):
            passed, output = go_test(product, package, test)
            refused = [x.strip() for x in output.splitlines() if 'refused: ' in x]
            out.append((f'{package}: {test}', passed, refused[0] if refused else output.strip()[-400:]))
            off = console_copy(tree, Path(d) / ('off-' + package))
            switch(off)
            passed_off, output_off = go_test(off, package, test)
            printed = text if text in output_off else output_off.strip()[-400:]
            out.append((f'control {package}: refusal switched off', not passed_off and text in output_off, printed))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--console', required=True, type=Path, help='a cloud-console tree (read only; a copy is tested)')
    args = parser.parse_args(argv)
    rows = console_legs(args.console)
    for leg, holds, text in rows:
        print(f'{"OK  " if holds else "FAIL"} {leg}: {text}')
    return 0 if all(h for _, h, _ in rows) else 1


if __name__ == '__main__':
    sys.exit(main())
