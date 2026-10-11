#!/usr/bin/env python3
"""Execute the shared Lua 5.1 public UCI codec and real read-only handlers."""
import copy
import json
from pathlib import Path
import unittest
from lupa.lua51 import LuaRuntime
from project import ROOT

CODEC = ROOT / 'project/luci/lua/luasrc/model/homegate/backup.lua'
CONTROLLER = ROOT / 'project/luci/lua/luasrc/controller/homegate.lua'
HEADER = '# homegate-backup-format: 2\n# plugin: homegate\n# schema: public-uci-v1\n# secrets: omitted\n'
BUSINESS = '''
config homegate 'main'
 option enabled '1'
 option access_enabled '1'
 option access_allow '192.0.2.1,2001:db8::/32'
 option last_wol_host 'host_a'
config dns_account 'dns_a'
 option name 'DNS 账户'
 option provider 'cloudflare'
config ddns_rule 'ddns_a'
 option enabled '1'
 option account 'dns_a'
 option zone 'example.test'
 option host 'www.example.test'
config certificate 'cert_a'
 option enabled '1'
 option source 'acme'
 option account 'dns_a'
 option zone 'example.test'
 list domains 'example.test'
 list domains '*.example.test'
config web_rule 'web_a'
 option enabled '1'
 option domain 'www.example.test'
 option certificate 'cert_a'
config wol_host 'host_a'
 option name '电脑'
 option mac 'AA-BB-CC-DD-EE-FF'
'''
BODY = HEADER + BUSINESS


class Preview(unittest.TestCase):
    def setUp(self):
        self.lua = LuaRuntime(unpack_returned_tuples=True)
        self.codec = self.lua.execute(CODEC.read_text(encoding='utf-8'))

    def parsed(self, body=BODY):
        result = self.codec.parse(body)
        if isinstance(result, tuple):
            self.fail(result[1])
        return result

    def rejected(self, body, message=None):
        result = self.codec.parse(body)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[0])
        if message:
            self.assertIn(message, result[1])
        self.assertNotIn('SECRET_SENTINEL', result[1])

    def cursor(self, sections):
        self.lua.globals().sections = self.lua.table_from(sections, recursive=True)
        return self.lua.execute('''return {foreach=function(self, pkg, kind, cb)
          assert(pkg=='homegate'); for _,s in ipairs(sections) do if s['.type']==kind then cb(s) end end
        end, set=function() error('UCI write prohibited') end,
        commit=function() error('UCI commit prohibited') end}''')

    def sections(self):
        out = []
        for _, section in self.parsed().items():
            raw = dict(section['values'].items())
            if not isinstance(raw.get('domains'), (str, type(None))):
                raw['domains'] = [v for _, v in raw['domains'].items()]
            raw.update({'.name': section['name'], '.type': section['kind']})
            if 'enabled' in raw:
                raw['enabled'] = '1'
            out.append(raw)
        out[0]['access_enabled'] = '1'
        return out

    def test_six_business_types_defaults_and_disabled_candidate(self):
        doc = self.parsed()
        self.assertEqual(len(doc), 6)
        for _, section in doc.items():
            if section['values']['enabled'] is not None:
                self.assertEqual(section['values']['enabled'], '0')
        self.assertEqual(doc[1]['values']['access_enabled'], '0')
        self.assertEqual(doc[6]['values']['mac'], 'AA:BB:CC:DD:EE:FF')

    def test_export_import_roundtrip_and_private_omission(self):
        sections = self.sections()
        for s in sections:
            s.update(secret='SECRET_SENTINEL', future_token='SECRET_SENTINEL')
            if s['.type'] == 'dns_account':
                s.update(id='SECRET_SENTINEL', account_id='SECRET_SENTINEL', endpoint='SECRET_SENTINEL')
            if s['.type'] in ('ddns_rule', 'web_rule'):
                s.update(url='https://SECRET_SENTINEL@example.test/', target='http://SECRET_SENTINEL@192.0.2.1/')
        cursor = self.cursor(sections)
        backup = self.codec.export(cursor)
        self.assertIsInstance(backup, str)
        self.assertNotIn('SECRET_SENTINEL', backup)
        self.assertIn("list domains '*.example.test'", backup)
        self.parsed(backup)
        self.assertEqual(backup, self.codec.export(cursor))

    def test_old_public_v1_format_supported_but_unversioned_denied(self):
        self.parsed('# homegate-backup-format: 1\n# secrets: omitted\n' + BUSINESS)
        self.rejected(BUSINESS, 'format')
        self.rejected(HEADER.replace('homegate\n', 'other-plugin\n') + BUSINESS, 'plugin')
        self.rejected(HEADER.replace('public-uci-v1', 'public-uci-v99') + BUSINESS, 'schema')

    def test_duplicate_or_misplaced_metadata(self):
        self.rejected(HEADER + '# plugin: homegate\n' + BUSINESS, 'metadata')
        self.rejected(BODY + '# schema: public-uci-v1\n', 'metadata')

    def test_private_unknown_fields_and_types(self):
        for field in ('id', 'secret', 'account_id', 'endpoint', 'target', 'url', 'private_key', 'future_token'):
            self.rejected(HEADER + "config homegate 'main'\n option " + field + " 'SECRET_SENTINEL'\n", 'private')
        self.rejected(BODY + "config network 'wan'\n", 'section')
        self.rejected(BODY + "include '/etc/passwd'\n", 'directives')

    def test_duplicates_anonymous_sections_and_wrong_main(self):
        self.rejected(BODY + "config dns_account 'dns_a'\n", 'duplicate')
        self.rejected(BODY.replace("option enabled '1'", "option enabled '1'\n option enabled '0'", 1), 'Duplicate')
        self.rejected(BODY.replace("config dns_account 'dns_a'", 'config dns_account'), 'Named')
        self.rejected(BODY.replace("homegate 'main'", "homegate 'main_other'"), 'section')

    def test_uci_quotes_and_inert_shell_like_data(self):
        sections = self.sections()
        sections[1]['name'] = "Alice's $(touch nope); `cmd` <img onerror=1> \\\""
        backup = self.codec.export(self.cursor(sections))
        self.assertIsInstance(backup, str)
        doc = self.parsed(backup)
        self.assertEqual(doc[2]['values']['name'], sections[1]['name'])
        self.parsed(BODY.replace("'DNS 账户'", '"DNS account"'))
        self.rejected(BODY.replace("'DNS 账户'", "'unclosed"), 'syntax')

    def test_scalar_validation_and_decimal_normalization(self):
        doc = self.parsed(BODY.replace("option enabled '1'", "option enabled '1'\n option https_port '00443'", 1))
        self.assertEqual(doc[1]['values']['https_port'], '443')
        for key, value in [('https_port','65536'), ('ddns_interval','59'), ('renew_days','0'), ('log_level','verbose'), ('access_enabled','yes'), ('acme_directory','https://SECRET_SENTINEL@example.test/')]:
            self.rejected(HEADER + "config homegate 'main'\n option " + key + " '" + value + "'\n", 'field')
        for provider in ('aliyun','cloudflare','dnspod','huaweicloud'):
            self.parsed(BODY.replace("'cloudflare'", "'"+provider+"'"))

    def test_ipv4_ipv6_and_prefix_validation(self):
        for v in ('', '0.0.0.0/0', '::/0', '::1', '2001:db8::1/128', '::ffff:192.0.2.1', '192.0.2.0/24; 2001:db8:0:1:2:3:4:5/64'):
            self.parsed(BODY.replace('192.0.2.1,2001:db8::/32', v))
        for v in ('256.1.1.1','01.2.3.4','192.0.2.1/33','::/129','1::2::3','1:2:3',':::','SECRET_SENTINEL'):
            self.rejected(BODY.replace('192.0.2.1,2001:db8::/32', v), 'field')

    def test_reference_types_zones_certificate_coverage_and_mac(self):
        for a,b in [("account 'dns_a'", "account 'absent'"), ("account 'dns_a'", "account 'cert_a'"), ("last_wol_host 'host_a'", "last_wol_host 'dns_a'"), ("certificate 'cert_a'", "certificate 'dns_a'"), ("host 'www.example.test'", "host 'www.other.test'"), ("domains '*.example.test'", "domains '*.other.test'"), ("domain 'www.example.test'", "domain 'www.other.test'"), ("mac 'AA-BB-CC-DD-EE-FF'", "mac 'FF:FF:FF:FF:FF:FF'")]:
            with self.subTest(field=a, value=b):
                self.rejected(BODY.replace(' option '+a, ' option '+b).replace(' list '+a, ' list '+b))

    def test_duplicate_domains_and_services(self):
        self.rejected(BODY.replace("list domains '*.example.test'", "list domains 'example.test'"))
        self.rejected(BODY + "config web_rule 'web_b'\n option domain 'www.example.test'\n", 'Duplicate')

    def test_framing_utf8_and_resource_limits(self):
        self.parsed(BODY.replace('\n','\r\n'))
        for bad in ('\x00','\x01','\x1b','\x7f','\r'):
            self.rejected(BODY + bad)
        self.rejected(BODY + 'x' * 262144, 'large')
        self.rejected(BODY + '\n' * 8192, 'line')
        self.rejected(BODY + '#' + 'x' * 4096, 'line')
        self.rejected(BODY.replace('DNS 账户', 'X'*256), 'field')
        self.rejected(BODY.encode().replace('DNS 账户'.encode(), b'\xc0\xaf'), 'field')
        self.rejected(BODY + ''.join("config dns_account 'extra_%d'\n option provider 'aliyun'\n" % i for i in range(32)), 'many')

    def test_preview_precise_diff_no_mutation_and_no_secret_echo(self):
        sections = self.sections()
        sections[1]['secret'] = 'SECRET_SENTINEL'
        sections[0]['acme_directory'] = 'https://SECRET_SENTINEL@example.test/'
        before = copy.deepcopy(sections)
        report = self.codec.preview(self.cursor(sections), BODY)
        text = self.codec.json(report)
        data = json.loads(text)
        self.assertTrue(data['ok'])
        self.assertFalse(data['can_commit'])
        self.assertEqual(data['section_count'], 6)
        self.assertNotIn('SECRET_SENTINEL', text)
        self.assertIn({'section':'main','kind':'homegate','field':'enabled','before':'1','after':'0'}, data['changes'])
        self.assertEqual(sections, before)

    def test_existing_oversized_config_cannot_silently_export_partial_backup(self):
        sections=self.sections()+[{'.name':'old_%d'%i,'.type':'wol_host','mac':'AA:00:00:00:00:02'} for i in range(128)]
        result=self.codec.export(self.cursor(sections))
        self.assertIsNone(result[0])
        result=self.codec.preview(self.cursor(sections), BODY)
        self.assertIsNone(result[0])
        self.assertIn('limit', result[1])
        result=self.codec.export(self.cursor(self.sections()+[{'.name':'invalid\nSECRET_SENTINEL','.type':'dns_account'}]))
        self.assertIsNone(result[0])
        self.assertNotIn('SECRET_SENTINEL',result[1])

    def test_create_remove_type_changes_and_no_change_case(self):
        sections = self.sections()
        sections.append({'.name':'removed_host','.type':'wol_host','name':'old','mac':'AA:00:00:00:00:02'})
        data = json.loads(self.codec.json(self.codec.preview(self.cursor(sections), BODY)))
        self.assertIn({'section':'removed_host','kind':'wol_host','field':'.section','before':'Present','after':'Absent'},data['changes'])
        backup = self.codec.export(self.cursor(self.sections()))
        current = []
        for _, s in self.parsed(backup).items():
            values = dict(s['values'].items())
            if s['kind'] == 'certificate':
                values['domains'] = list(values['domains'].values())
            values.update({'.name':s['name'],'.type':s['kind']})
            current.append(values)
        report = json.loads(self.codec.json(self.codec.preview(self.cursor(current), backup)))
        self.assertEqual(report['changes'], [])

    def test_real_import_handler_never_executes_or_writes_even_crafted_mode(self):
        cursor = self.cursor(self.sections())
        self.lua.globals().cursor = cursor
        self.lua.globals().payload = BODY
        self.lua.execute('''captured={}; mode='apply'
          package.preload['luci.model.uci']=function() return {cursor=function() return cursor end} end
          package.preload['luci.http']=function() return {
            formvalue=function(k) if k=='config_payload' then return payload else return mode end end,
            prepare_content=function(v) assert(v=='application/json') end,
            write=function(v) captured[#captured+1]=v end} end
          package.preload['luci.sys']=function() error('Shell access prohibited') end
          io.open=function() error('File access prohibited') end
        ''')
        self.lua.execute('package.preload["luci.model.homegate.backup"]=function()\n'+CODEC.read_text(encoding='utf-8')+'\nend')
        self.lua.execute(CONTROLLER.read_text(encoding='utf-8'))
        self.lua.globals().luci.controller.homegate.action_config_import()
        report = json.loads(''.join(self.lua.globals().captured.values()))
        self.assertTrue(report['ok'])
        self.assertFalse(report['can_commit'])
        self.lua.globals().captured = self.lua.table()
        self.lua.globals().payload = BODY + "option secret 'SECRET_SENTINEL'\n"
        self.lua.globals().luci.controller.homegate.action_config_import()
        raw = ''.join(self.lua.globals().captured.values())
        self.assertFalse(json.loads(raw)['ok'])
        self.assertNotIn('SECRET_SENTINEL', raw)

    def test_embedded_reference_uses_byte_identical_codec_and_post_route(self):
        bundle=(ROOT/'project/core/src/internal/frontend/controller.lua').read_text(encoding='utf-8')
        expected='package.preload["luci.model.homegate.backup"] = function()\n'+CODEC.read_text(encoding='utf-8')+'\nend\n'+CONTROLLER.read_text(encoding='utf-8')
        self.assertEqual(bundle, expected)
        routes=json.loads((ROOT/'project/core/src/internal/frontend/routes.json').read_text(encoding='utf-8'))
        self.assertEqual(routes['config_import'], {'handler':'action_config_import','write':True})
        recipe=(ROOT/'project/luci/Makefile').read_text(encoding='utf-8')
        self.assertIn('$(INSTALL_DATA) ./lua/luasrc/model/homegate/backup.lua $(1)/usr/lib/lua/luci/model/homegate/backup.lua',recipe)
        self.assertNotIn('cp ', CONTROLLER.read_text(encoding='utf-8').split('function action_config_import()')[1].split('local function reset_homegate_config')[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
