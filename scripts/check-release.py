#!/usr/bin/env python3
"""Check generated release structure, source parity and shell syntax (Linux CI)."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('release', ROOT / 'scripts/build-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
packages = list((ROOT / 'dist').glob('*.ipk'))
assert len(packages) == 3
for file in packages:
    control, data = release.verify(file, release.version()[1])
    with tempfile.TemporaryDirectory() as temp:
        for name, (blob, _) in {**control, **data}.items():
            if blob.startswith(b'#!/bin/sh'):
                check = Path(temp) / 'script.sh'
                check.write_bytes(blob)
                subprocess.run(['sh', '-n', str(check)], check=True)
print('Three package structures, lifecycle and shell syntax: PASS')
