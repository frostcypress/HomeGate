import json,re,subprocess,unittest
from project import ROOT
from engineering_runtime import GATES,SCOPE,payload,web_payload

class Deployment(unittest.TestCase):
    def test_profiles_are_explicit_and_production_sources_stay_closed(self):
        for name,gates in GATES.items():
            raw=(ROOT/'project/core/prototype'/name).read_text()
            for gate in gates:self.assertEqual(len(re.findall('^'+gate+'=false$',raw,re.M)),1,(name,gate))
        generated=payload(ROOT)
        for name in ['homegate-config-prototype.sh','homegate-service-observer-watchdog.sh']:
            self.assertIn(b'service_actions_enabled=false',generated['project/core/prototype/'+name])
        self.assertIn(b'ddns_schedule_enabled=true',generated['project/core/prototype/homegate-ddns-schedule.sh'])
        self.assertIn(b'ddns_schedule_continuous_enabled=true',generated['project/core/prototype/homegate-ddns-schedule.sh'])
        self.assertIn(b'ddns_schedule_continuous_enabled=false',(ROOT/'project/core/prototype/homegate-ddns-schedule.sh').read_bytes())
        self.assertNotIn(b'sha256sum -c',generated['project/core/prototype/homegate-ddns-schedule.sh'])
        self.assertIn(b'[ "$public_binding" = "$public_actual" ]',generated['project/core/prototype/homegate-ddns-schedule.sh'])
        self.assertIn(b'ddns_schedule_events_enabled=false',(ROOT/'project/core/prototype/homegate-ddns-schedule.sh').read_bytes())
        self.assertIn(b'lifecycle_intent_record_enabled=true',generated['project/core/prototype/homegate-lifecycle-prepare.sh'])
    def test_deployed_shell_lua_grammar_and_fixed_namespace(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime()
        for name,raw in payload(ROOT).items():
            self.assertNotIn(b'\r',raw,name)
            if name.endswith('.sh'):
                proc=subprocess.run(['busybox','ash','-n'],input=raw,capture_output=True)
                self.assertEqual(proc.returncode,0,(name,proc.stderr))
            elif name.endswith('.lua'):lua.compile(raw)
            if name.startswith('project/core/prototype/'):
                if name.endswith('/homegate-config-prototype.sh'):
                    self.assertIn(b'production_copy_source=/etc/config/homegate\n',raw)
                    self.assertIn(b'production_copy_runtime=/var/run/homegate\n',raw)
                    raw=raw.replace(b'production_copy_source=/etc/config/homegate\n',b'').replace(b'production_copy_runtime=/var/run/homegate\n',b'')
                self.assertNotRegex(raw,rb'/etc/(?:config/homegate|homegate)(?:[\s/\'";]|$)',name)
                self.assertNotRegex(raw,rb'/var/run/homegate(?:[\s/\'";]|$)',name)
    def test_target_and_dependencies_match_manual_business_scope(self):
        target=json.loads((ROOT/'targets/engineering-24.10.6-ipq807x.json').read_text())
        self.assertEqual(target['scope'],SCOPE);self.assertFalse(target['production_replacement'])
        self.assertFalse(target['native_target_code']);self.assertEqual(target['package_architecture'],'all')
        recipe=(ROOT/'packaging/engineering/Makefile').read_text()
        for dep in ['coreutils-stat','luci-lib-jsonc','curl','ca-bundle','openssl-util','flock','ip-full','ubus']:
            self.assertIn('+'+dep,recipe)
        self.assertIn('/etc/config/homegate_engineering',recipe)
        for hook in ['postinst','postrm']:self.assertNotIn('/'+hook,recipe)
        prerm=recipe.split('define Package/homegate-engineering-core/prerm\n',1)[1].split('\nendef',1)[0]
        self.assertIn('schedule-quiescent',prerm);self.assertNotRegex(prerm,r'(?m)^\s*(?:rm|rmdir|unlink)\b')
        init=(ROOT/'packaging/engineering/files/homegate-engineering.init').read_text()
        self.assertIn('[ "$#" -eq 2 ] && [ "$2" = --confirm ] || exit 0',init)
    def test_public_wrapper_rejects_paths_and_never_implicitly_grants(self):
        for name in ['homegate-engineering','ddns-control.sh','service-disabled','config-web.sh','schedule-control.sh','homegate-engineering.init','95-homegate-engineering']:
            raw=(ROOT/'packaging/engineering/files'/name).read_bytes()
            p=subprocess.run(['busybox','ash','-n'],input=raw,capture_output=True)
            self.assertEqual(p.returncode,0,(name,p.stderr))
        raw=(ROOT/'packaging/engineering/files/ddns-control.sh').read_text()
        self.assertIn('exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-',raw)
        self.assertNotIn('eval ',raw);self.assertNotIn('rm -r',raw)
        self.assertIn('grant-commit) exec ash',raw)
    def test_installed_web_namespace_and_code(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime()
        generated=web_payload(ROOT)
        for name,raw in generated.items():
            if name.endswith('.lua'):lua.compile(raw)
            self.assertNotIn(b'luci.model.homegate.',raw,name)
            self.assertNotIn(b'admin/services/homegate/',raw,name)
        for name in ['config-web.lua','config-model.lua']:lua.compile((ROOT/'packaging/engineering/files'/name).read_bytes())
        view=generated['usr/lib/lua/luci/view/homegate_engineering/ddns.htm']
        self.assertIn(b'/homegate-engineering/ddns-ui.js',view)
        controller=(ROOT/'packaging/engineering/files/controller.lua').read_text()
        self.assertIn("post('config_'..action)",controller)
        self.assertIn("action=='cert_import' and 262144 or 32768",controller)

if __name__=='__main__':unittest.main(verbosity=2)
