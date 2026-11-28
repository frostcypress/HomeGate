#!/usr/bin/env python3
"""Verify that LuCI retains the complete installed release and reset uses it."""
from pathlib import Path
import re
from lupa.lua51 import LuaRuntime
ROOT = Path(__file__).resolve().parent.parent
controller = (ROOT / 'project/luci/lua/luasrc/controller/homegate.lua').read_text(encoding='utf-8')
function = controller[controller.index('local function package_info()'):controller.index('local function find_account_by_identity')]
lua = LuaRuntime(unpack_returned_tuples=True)
for installed in ('1.2.3-2', '1.2.3-17', '1.3.0-1', '1.3.0-3', '-'):
    lua.globals().installed = installed
    lua.execute('function package_field(pkg, field) return installed end')
    result = lua.execute(function + '\nreturn package_info()')
    assert result['product'] == installed, (installed, result['product'])
    assert result['core'] == installed
version = (ROOT / 'homegate-version.mk').read_text(encoding='utf-8')
expected = re.search(r'^HOMEGATE_VERSION:=(.+)$',version,re.M)[1] + '-' + re.search(r'^HOMEGATE_RELEASE:=(.+)$',version,re.M)[1]
packages = list((ROOT / 'dist').glob('*_' + expected + '_*.ipk'))
assert len(packages) == 3, 'Build the three current release packages first'
for package in packages:
    if package.name.startswith('homegate_'):
        import io, tarfile
        with tarfile.open(package) as outer:
            payload = outer.extractfile(next(m for m in outer if m.name.endswith('data.tar.gz'))).read()
        with tarfile.open(fileobj=io.BytesIO(payload)) as data:
            config = data.extractfile(next(m for m in data if m.name.endswith('etc/config/homegate'))).read()
        assert ("option version '" + expected + "'").encode() in config
assert 'local v = package_info().product' in controller
print('Complete release display and reset regression: PASS (5 version cases)')
