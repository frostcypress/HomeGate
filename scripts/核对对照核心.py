#!/usr/bin/env python3
"""Prove the migration reference still contains every original Go source byte."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile
from project import ROOT

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--baseline-source-zip', type=Path, required=True)
parser.add_argument('--report', type=Path, default=ROOT / 'docs/核心对照校验.json')
args = parser.parse_args()
changed, missing, names = [], [], []
with zipfile.ZipFile(args.baseline_source_zip) as archive:
    for name in archive.namelist():
        if not name.startswith('core/') or not name.endswith('.go'):
            continue
        relative = PurePosixPath(name).relative_to('core')
        if '..' in relative.parts:
            raise ValueError('Unsafe baseline path')
        names.append(name)
        current = ROOT / 'project/core/src' / relative.as_posix()
        if not current.is_file():
            missing.append(name)
        elif current.read_bytes() != archive.read(name):
            changed.append(name)
report = {'baseline_sha256': hashlib.sha256(args.baseline_source_zip.read_bytes()).hexdigest(),
          'go_files': len(names), 'changed_go_files': changed, 'missing_go_files': missing,
          'scope': 'Go source byte comparison only; generated Lua/rules and UI changes are separate'}
args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, ensure_ascii=False))
if not names or changed or missing:
    raise SystemExit(2)
