#!/usr/bin/env python3
"""Execute real Lua navigation/export handlers in a mocked read-only UCI host."""
import json
from pathlib import Path
import re
import shlex
from lupa.lua51 import LuaRuntime
from project import ROOT

controller = ROOT / 'project/luci/lua/luasrc/controller/homegate.lua'
lua = LuaRuntime(unpack_returned_tuples=True)
lua.execute('''
captured = {}
routes = {}
cursor = {foreach=function(self, package, kind, callback)
    assert(package == 'homegate')
    for _, section in ipairs(sections or {}) do
        if section['.type'] == kind then callback(section) end
    end
end}
package.preload['luci.model.uci'] = function() return {cursor=function() return cursor end} end
package.preload['luci.http'] = function() return {
    header=function(...) end, prepare_content=function(...) end,
    write=function(value) captured[#captured+1]=value end,
    formvalue=function() return nil end
} end
function entry(path, action, title, order)
    routes[table.concat(path, '/')] = {title=title, order=order}
    return {}
end
function alias(...) return {} end
function call(...) return {} end
function post(...) return {} end
function firstchild(...) return {} end
function _(text) return text end
''')
codec = ROOT / 'project/luci/lua/luasrc/model/homegate/backup.lua'
lua.execute('package.preload["luci.model.homegate.backup"]=function()\n' + codec.read_text(encoding='utf-8') + '\nend')
lua.execute(controller.read_text(encoding='utf-8'))
module = lua.globals().luci.controller.homegate
module.index()
visible = {}
for key, value in lua.globals().routes.items():
    if value['title'] and key.count('/') == 3:
        visible[key.rsplit('/', 1)[1]] = value['title']
assert visible == {'overview': 'Overview', 'settings': 'Settings', 'maintenance': 'Maintenance'}, visible
menu = json.loads((ROOT / 'project/luci/js/root/usr/share/luci/menu.d/luci-app-homegate.json').read_text(encoding='utf-8'))
modern = {key.rsplit('/', 1)[1]: value['title'] for key, value in menu.items()
          if key.count('/') == 3 and value.get('title')}
assert modern == visible
sections = [
    {'.name': 'main', '.type': 'homegate', 'enabled': '1', 'log_level': 'info', 'secret': 'MAIN_SECRET'},
    {'.name': 'dns_a', '.type': 'dns_account', 'name': "Alice's DNS", 'provider': 'cloudflare',
     'id': 'KEY_ID_SECRET', 'secret': 'TOKEN_SECRET', 'account_id': 'ACCOUNT_SECRET', 'future_token': 'FUTURE_SECRET'},
    {'.name': 'ddns_a', '.type': 'ddns_rule', 'zone': 'example.test', 'account': 'dns_a', 'url': 'https://USER:PASS@example.test/'},
    {'.name': 'web_a', '.type': 'web_rule', 'domain': 'host.example.test', 'target': 'http://USER:PASS@192.0.2.1/'},
    {'.name': 'cert_a', '.type': 'certificate', 'source': 'local', 'domains': ['a.example.test', 'b.example.test'], 'private_key': 'PRIVATE_KEY_SECRET'},
    {'.name': 'alien', '.type': 'other_plugin', 'name': 'UNRELATED_CONFIG'}
]
lua.globals().sections = lua.table_from(sections, recursive=True)
module.action_config_export()
body = ''.join(value for _, value in lua.globals().captured.items())
assert '# homegate-backup-format: 2' in body and '# secrets: omitted' in body
for secret in ('MAIN_SECRET', 'KEY_ID_SECRET', 'TOKEN_SECRET', 'ACCOUNT_SECRET', 'FUTURE_SECRET',
               'USER:PASS', 'PRIVATE_KEY_SECRET', 'INJECTION', 'UNRELATED_CONFIG'):
    assert secret not in body, secret
assert "option enabled '0'" in body
assert "list domains 'a.example.test'" in body
assert "list domains 'b.example.test'" in body
line = next(line for line in body.splitlines() if 'option name' in line)
assert shlex.split(line) == ['option', 'name', "Alice's DNS"], line
for page in ('overview', 'maintenance'):
    template = (ROOT / 'project/luci/lua/luasrc/view/homegate' / (page + '.htm')).read_text(encoding='utf-8')
    chunks = ['local out={}; local function write(value) out[#out+1]=tostring(value or "") end']
    for part in re.split(r'(<%.*?%>)', template, flags=re.S):
        if not part.startswith('<%'):
            chunks.append('write(' + json.dumps(part, ensure_ascii=False) + ')')
            continue
        tag = part[2:-2]
        if tag.startswith('='):
            chunks.append('write(' + tag[1:] + ')')
        elif tag.startswith(':'):
            chunks.append('write(' + json.dumps(tag[1:]) + ')')
        elif not tag.startswith('+'):
            chunks.append(tag)
    lua.execute('assert(loadstring(...))', '\n'.join(chunks))
po = (ROOT / 'project/luci/common/po/zh_Hans/homegate.po').read_text(encoding='utf-8')
for title in ('Overview', 'Settings', 'Maintenance', 'Version Management', 'Runtime Logs', 'Plugin Operations'):
    assert 'msgid ' + json.dumps(title) in po, title
print('PASS Lua/JS navigation, real Lua safe export, quoting, list preservation, unknown-secret exclusion, template syntax')
