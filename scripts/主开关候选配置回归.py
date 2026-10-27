#!/usr/bin/env python3
"""Private switch overlays preserve the bound generation and all other choices."""
import argparse
import json
import os
import unittest
from project import ROOT
from 核心配置校验回归 import models,RAW
from 启动配置接合回归 import Published as PublishedBase
from 启用意图应用核对回归 import Request as ApplicationRequest

PROTO=ROOT/'project/core/prototype'
PRIVATE_RAW=RAW.replace("config dns_account 'dns_a'","config dns_account 'dns_a'\n option secret 'PRIVATE_SENTINEL'")

def fixture(raw=PRIVATE_RAW,projected=False):
    lua,codec,validator,ip=models()
    model=lua.execute((PROTO/'startup-candidate.lua').read_text())
    intent=lua.execute((PROTO/'startup-intent.lua').read_text())
    public,slots=codec.migration(raw)
    source=codec.private_configuration(public if projected else raw)
    snapshot=lua.table_from(dict(revision=7,configuration=codec.parse(public),credentials=slots))
    return lua,codec,validator,ip,model,intent,source,snapshot

class Static(unittest.TestCase):
    def test_ordinary_source_changes_only_main_and_preserves_all_private_values(self):
        for observed in ['0','1']:
            for desired in ['enabled','disabled']:
                lua,codec,validator,ip,model,intent,source,snapshot=fixture(PRIVATE_RAW.replace("option enabled '1'","option enabled '"+observed+"'",1))
                before=codec.json(source);baseline=codec.json(snapshot)
                result=model.build(snapshot,source,desired,codec,validator,ip,intent)
                self.assertIsNotNone(result);self.assertEqual(result['base_revision'],7)
                self.assertEqual(codec.json(result['configuration']),codec.json(snapshot['configuration']))
                self.assertEqual(codec.json(result['credentials']),codec.json(snapshot['credentials']))
                expected=json.loads(codec.json(source['configuration']))
                flags=json.loads(codec.json(source['switches']))
                flags['main']['enabled']='1' if desired=='enabled' else '0'
                for section in expected:
                    for key,value in flags[section['name']].items():
                        if key!='kind':section['values'][key]=value
                self.assertEqual(json.loads(codec.json(result['active_configuration'])),expected)
                self.assertEqual(codec.json(result['switches']),codec.json(lua.table_from(flags,recursive=True)))
                self.assertEqual(codec.json(source),before);self.assertEqual(codec.json(snapshot),baseline)
    def test_projection_uses_current_generation_slots_without_restoring_lost_switches(self):
        lua,codec,validator,ip,model,intent,source,snapshot=fixture(projected=True)
        result=model.build(snapshot,source,'enabled',codec,validator,ip,intent)
        self.assertFalse(result['source_intent']['known']);self.assertEqual(result['source_intent']['desired_state'],'unconfirmed')
        self.assertEqual(result['credentials']['cloudflare.dns_a.secret'],'PRIVATE_SENTINEL')
        self.assertEqual(result['switches']['main']['enabled'],'1')
        self.assertEqual(result['switches']['main']['access_enabled'],'0')
        for name in ['ddns_a','cert_a','web_a']:self.assertEqual(result['switches'][name]['enabled'],'0')
        self.assertEqual(source['switches']['main']['enabled'],'0')
    def test_bad_revision_request_source_binding_web_target_and_switches_refuse(self):
        lua,codec,validator,ip,model,intent,source,snapshot=fixture()
        for desired in [None,'','1','SECRET_SENTINEL']:
            self.assertIsNone(model.build(snapshot,source,desired,codec,validator,ip,intent))
        for revision in [0,33,1.5,'7']:
            snapshot['revision']=revision;self.assertIsNone(model.build(snapshot,source,'enabled',codec,validator,ip,intent))
        snapshot['revision']=7;snapshot['configuration'][1]['values']['ddns_interval']='600'
        self.assertIsNone(model.build(snapshot,source,'enabled',codec,validator,ip,intent))
        lua,codec,validator,ip,model,intent,source,snapshot=fixture(PRIVATE_RAW.replace('https://127.0.0.1:8443/a?q=1','ftp://PRIVATE_SENTINEL'))
        self.assertIsNone(model.build(snapshot,source,'enabled',codec,validator,ip,intent))
        lua,codec,validator,ip,model,intent,source,snapshot=fixture()
        source['switches']['ddns_a']['enabled']='2'
        self.assertIsNone(model.build(snapshot,source,'enabled',codec,validator,ip,intent))
    def test_candidate_copies_nested_domains_credentials_and_switches(self):
        lua,codec,validator,ip,model,intent,source,snapshot=fixture()
        before=codec.json(source);baseline=codec.json(snapshot)
        result=model.build(snapshot,source,'disabled',codec,validator,ip,intent)
        result['credentials']['cloudflare.dns_a.secret']='changed'
        result['switches']['web_a']['enabled']='0'
        for section in result['active_configuration'].values():
            if section['kind']=='certificate':section['values']['domains'][1]='changed.test'
        self.assertEqual(codec.json(source),before);self.assertEqual(codec.json(snapshot),baseline)
        again=model.build(snapshot,source,'enabled',codec,validator,ip,intent)
        self.assertEqual(again['credentials']['cloudflare.dns_a.secret'],'PRIVATE_SENTINEL')
    def test_pure_model_summary_grammar_and_disabled_public_codec_remain(self):
        import tree_sitter,tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        self.assertFalse(parser.parse((PROTO/'homegate-lifecycle-prepare.sh').read_bytes()).root_node.has_error)
        LuaRuntime().compile((PROTO/'homegate-startup.lua').read_bytes())
        body=(PROTO/'startup-candidate.lua').read_text()
        for forbidden in ['io.','os.','loadfile','require(']:self.assertNotIn(forbidden,body)
        lua,codec,validator,ip,model,intent,source,snapshot=fixture()
        result=model.build(snapshot,source,'enabled',codec,validator,ip,intent)
        summary=codec.json(model.summary(result))
        for secret in ['PRIVATE_SENTINEL','example.test','127.0.0.1','dns_a']:self.assertNotIn(secret,summary)
        self.assertFalse(model.summary(result)['ordinary_publication_supported'])
        self.assertEqual(snapshot['configuration'][1]['values']['enabled'],'0')
        self.assertIn('lifecycle_intent_check_enabled=false',(PROTO/'homegate-lifecycle-prepare.sh').read_text())

class Published(ApplicationRequest,PublishedBase):
    def alter_snapshot(self,expression):
        tool=self.bin/'lua';target=tool.resolve();tool.unlink();self.lua_restore=(tool,target)
        body='#!'+os.sys.executable+'\nimport os,sys,subprocess\n'
        body+='if len(sys.argv)>2 and sys.argv[1].endswith("/homegate-startup.lua") and sys.argv[2]=="request-report":\n'
        body+=' raw=sys.stdin.buffer.read()\n raw='+expression+'\n sys.exit(subprocess.run(['+repr(str(target))+',*sys.argv[1:]],input=raw).returncode)\n'
        body+='os.execv('+repr(str(target))+',['+repr(str(target))+',*sys.argv[1:]])\n'
        tool.write_text(body);tool.chmod(0o700)
    def test_integrated_candidate_is_private_unpublished_and_main_only(self):
        before=self.contents();source=self.source.read_bytes()
        for desired in ['enabled','disabled']:
            report=self.request('lifecycle-intent-check',desired,'--confirm');c=report['candidate']
            self.assertEqual(c['format'],'private-switch-overlay-v1');self.assertEqual(c['base_revision'],self.revision)
            self.assertEqual(c['main_enabled'],desired=='enabled')
            for flag in ['checked','only_main_switch_requested','other_switches_preserved_as_observed','credentials_preserved','public_configuration_unchanged']:self.assertTrue(c[flag])
            for flag in ['persisted','ordinary_publication_supported','original_projection_intents_restored']:self.assertFalse(c[flag])
            self.assertFalse(report['request']['source_intent']['known'])
        self.assertEqual(self.contents(),before);self.assertEqual(self.source.read_bytes(),source)
    def test_incomplete_private_snapshot_cannot_be_a_candidate(self):
        self.alter_snapshot("raw[:-4]");before=self.contents();self.request(expected=7);self.assertEqual(self.contents(),before)
    def test_different_valid_revision_cannot_be_a_candidate(self):
        prefix=b'HGPRIVATE1\n'+str(self.revision).encode()+b'\n'
        replacement=b'HGPRIVATE1\n'+(b'1' if self.revision!=1 else b'2')+b'\n'
        self.alter_snapshot('raw.replace('+repr(prefix)+','+repr(replacement)+',1)')
        before=self.contents();self.request(expected=7);self.assertEqual(self.contents(),before)
    def test_different_public_configuration_cannot_share_the_source(self):
        self.alter_snapshot('raw.replace(b"ddns_interval \'300\'",b"ddns_interval \'600\'",1)')
        before=self.contents();self.request(expected=7);self.assertEqual(self.contents(),before)
    def test_source_provenance_must_match_the_bound_preflight(self):
        self.inject_report(" sys.argv[4]='ordinary-enabled'")
        before=self.contents();self.request(expected=7);self.assertEqual(self.contents(),before)
    def test_missing_candidate_model_cannot_return_partial_success(self):
        (self.engine.parent/'startup-candidate.lua').unlink()
        before=self.contents();self.request(expected=7);self.assertEqual(self.contents(),before)
    def test_source_change_after_real_candidate_generation_discards_success(self):
        tool=self.bin/'lua';target=tool.resolve();tool.unlink();self.lua_restore=(tool,target)
        marker=self.base/'candidate-built'
        body='#!'+os.sys.executable+'\nimport os,sys,subprocess\nfrom pathlib import Path\n'
        body+='if len(sys.argv)>2 and sys.argv[1].endswith("/homegate-startup.lua") and sys.argv[2]=="request-report":\n'
        body+=' p=subprocess.run(['+repr(str(target))+',*sys.argv[1:]],input=sys.stdin.buffer.read(),capture_output=True)\n'
        body+=' assert p.returncode==0\n Path('+repr(str(marker))+').write_text("generated")\n'
        body+=' source=Path('+repr(str(self.source))+');source.write_bytes(source.read_bytes()+b"\\n")\n sys.stdout.buffer.write(p.stdout);sys.exit(p.returncode)\n'
        body+='os.execv('+repr(str(target))+',['+repr(str(target))+',*sys.argv[1:]])\n'
        tool.write_text(body);tool.chmod(0o700)
        before=self.contents();self.request(expected=7);self.assertEqual(marker.read_text(),'generated');self.assertEqual(self.contents(),before)

def suite(runtime):
    cls=Published if runtime else Static
    return unittest.TestSuite(cls(n) for n,v in cls.__dict__.items() if n.startswith('test_') and callable(v))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true');a=p.parse_args()
    result=unittest.TextTestRunner(verbosity=2,failfast=True).run(suite(a.runtime));raise SystemExit(not result.wasSuccessful())
