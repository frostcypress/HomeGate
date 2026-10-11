#!/usr/bin/env python3
"""Execute the nine retained browser test bodies, without shell/platform skips."""
import json
import os
from pathlib import Path
import re
import shutil
import sys
from playwright.sync_api import sync_playwright
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / 'build/browser-regressions'
OUT.mkdir(parents=True, exist_ok=True)
with sync_playwright() as playwright:
    executable = os.environ.get('HOMEGATE_BROWSER', playwright.chromium.executable_path)
assert Path(executable).is_file(), 'Install Chromium: python3 -m playwright install chromium'
original_which = shutil.which
shutil.which = lambda name, *a, **kw: executable if name in (
    'chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable') else original_which(name, *a, **kw)
passed = []
for script in sorted((ROOT / 'scripts').glob('*.sh')):
    text = script.read_text(encoding='utf-8')
    if 'from playwright.sync_api import sync_playwright' not in text:
        continue
    match = re.search(r"python3[^\n]*<<'PY'\n(.*?)\nPY", text, re.S)
    assert match, script
    arguments = re.findall(r'"\$(\w+)([^"]*)"', text[match.start():].splitlines()[0])
    app = ROOT / 'project/luci/lua/luasrc/view/homegate'
    paths = {'ROOT': ROOT, 'APP': app, 'OUT': OUT / script.stem,
             **{key: app / name for key, name in [('COMMON', 'common.htm'),
                 ('PUBLIC', 'public.htm'), ('BASIC', 'basic.htm'), ('WOL', 'wol.htm'),
                 ('MAINT', 'maintenance.htm')]}}
    paths['OUT'].mkdir(exist_ok=True)
    sys.argv = [script.name] + [str(paths[var]) + suffix for var, suffix in arguments]
    try:
        exec(compile(match[1], str(script), 'exec'), {})
    except SystemExit as error:
        if error.code not in (None, 0):
            raise
    passed.append(script.name)
assert len(passed) == 9, passed
(OUT / 'browser-tests.json').write_text(json.dumps(passed, indent=2), encoding='utf-8')
print('Existing browser regressions: PASS (9)')
