#!/usr/bin/env python3
"""Fail closed until a target and compliant core have been verified."""
import argparse
import json
from pathlib import Path
import re
import sys
from project import ROOT, identity, verify_generated, selected_sdk_series


def validate(target, frontend, fmt, release=False, root=ROOT):
    verify_generated(root)
    project = json.loads((root / 'project.json').read_text(encoding='utf-8'))
    errors = []
    if target.get('schema') != 1 or target.get('verified') is not True:
        errors.append('目标设备尚未核实')
    for key in ('distribution', 'version', 'device', 'target', 'subtarget', 'architecture', 'abi', 'evidence'):
        if not isinstance(target.get(key), str) or not target[key].strip():
            errors.append(f'缺少目标信息：{key}')
    actual = target.get('package_format')
    if actual not in ('ipk', 'apk') or (fmt != 'auto' and fmt != actual):
        errors.append('包格式与已核实目标不匹配')
    if target.get('luci', {}).get(frontend) is not True or target.get('luci', {}).get('bootstrap') is not True:
        errors.append('所选 LuCI 实现或 Bootstrap 基准尚未核实')
    sdk = target.get('sdk', {})
    if actual in ('ipk','apk'):
        series=selected_sdk_series(actual,root)
        if not isinstance(sdk.get('version'),str) or not re.fullmatch(re.escape(series)+r'(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?',sdk['version']):
            errors.append(f'包格式 {actual} 必须使用用户选定的 SDK {series} 系列')
    if not isinstance(sdk.get('url'), str) or not sdk['url'].startswith('https://'):
        errors.append('缺少可信 HTTPS SDK URL')
    if not re.fullmatch(r'[a-f0-9]{64}', str(sdk.get('sha256', ''))):
        errors.append('缺少 SDK SHA-256')
    for key in ('ram_kib', 'overlay_available_kib'):
        value = target.get('resources', {}).get(key)
        if type(value) is not int or value <= 0:
            errors.append(f'资源预算尚未核实：{key}')
    core = project.get('core', {})
    if core.get('implementation') not in ('shell', 'c') or core.get('migration_complete') is not True:
        errors.append('核心仍为 Go 对照实现，Shell/C 完整迁移尚未完成')
    if core.get('package') != identity(root)['slug'] + '-core':
        errors.append('Core 包名迁移及旧包升级方案尚未完成')
    if release and project.get('release_ready') is not True:
        errors.append('实机验收和正式发布证据尚未完成')
    if errors:
        raise ValueError('\n'.join(errors))
    return actual


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--luci', choices=('lua', 'js'), required=True)
    parser.add_argument('--format', choices=('auto', 'ipk', 'apk'), default='auto')
    parser.add_argument('--release', action='store_true')
    args = parser.parse_args()
    try:
        target = json.loads(args.target.read_text(encoding='utf-8'))
        print(validate(target, args.luci, args.format, args.release))
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print(f'不允许构建/发布：\n{exc}', file=sys.stderr)
        sys.exit(2)
