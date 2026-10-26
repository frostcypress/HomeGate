#!/usr/bin/env python3
"""Finite foreground admissions and cooperative lifecycle against real TLS fixtures."""
import argparse,copy,hashlib,json,os,re,signal,subprocess,threading,time,unittest
from pathlib import Path
from project import ROOT
from DDNS全批协调回归 import CF as CFBase,Ali as AliBase,DNP as DNPBase,HW as HWBase,Static as BaseStatic
from DDNS全批协调回归 import MixedCF as MixedCFBase,MixedAli as MixedAliBase,MixedDNP as MixedDNPBase,MixedHW as MixedHWBase
from DDNS计划回归 import fixture_uid
PROTO=ROOT/'project/core/prototype'

class Static(BaseStatic):
    def setUp(self):super().setUp();self.policy=self.lua.execute((PROTO/'ddns-schedule.lua').read_bytes())
    def test_due_member_minimum_wait_and_global_refusal(self):
        decide=lambda rows:self.policy.decision(self.table(rows))
        self.assertEqual(decide([{'rule':'a','status':'waiting','retry_in':300},{'rule':'b','status':'retry_wait','retry_in':60}]),(b'wait',60))
        self.assertEqual(decide([{'rule':'a','status':'ready','retry_in':0},{'rule':'b','status':'paused','retry_in':0}]),(b'ready',0))
        self.assertEqual(decide([{'rule':'a','status':'paused','retry_in':0}]),(b'idle',0))
        for status in ['blocked','reconciliation_required','unauthorized','clock_invalid']:
            self.assertEqual(decide([{'rule':'a','status':'ready','retry_in':0},{'rule':'b','status':status,'retry_in':0}]),(b'blocked',0))
        for rows in [[],[{'rule':'a','status':'waiting','retry_in':0}],[{'rule':'a','status':'ready','retry_in':0}]*2]:self.assertIsNone(decide(rows))
    def specimen(self):return {'schema':'HGDDNSSCHEDULE1','identity':'a'*64,'generation':'b'*64,'grant':'c'*64,'revision':3,'boot':'11111111-1111-1111-1111-111111111111','pid':'123','birth':'456','token':'d'*32,'started':1000,'deadline':1900}
    def test_immutable_lease_has_fixed_admission_budget_and_bounded_identity(self):
        d=self.specimen();self.assertTrue(self.policy.lease(self.table(d)));self.assertEqual((self.policy.budget,self.policy.limit),(900,8))
        for k,v in [('deadline',1901),('pid','1'),('birth','0'),('token','bad'),('generation','-'),('revision',33),('extra','PRIVATE_SENTINEL')]:
            bad={**d,k:v};self.assertFalse(self.policy.lease(self.table(bad)))
    def test_batch_receipt_requires_exact_prefix_framing_and_conservative_effect(self):
        row={'rule':'ddns_a','provider':'cloudflare','status':'unchanged','effect':'none','error_kind':'','retryable':False,'retry_in':0}
        d={'api_version':1,'prototype':True,'ok':True,'phase':'ddns-batch','configuration_revision':3,'effect':'none','sampled':True,'write_ready':False,'rules':[row]};raw=json.dumps(d,separators=(',',':')).encode()+b'\n'
        check=lambda r,o:self.policy.batch(r,self.table(o),b'3',b'0',self.table(['ddns_a']),self.codec.json)
        self.assertEqual(check(raw,d),b'none');self.assertIsNone(check(raw+b' ',d))
        for key,value in [('rule','other'),('effect','unknown'),('status','created'),('extra','SECRET_SENTINEL')]:
            bad=copy.deepcopy(d);bad['rules'][0][key]=value;self.assertIsNone(check(json.dumps(bad,separators=(',',':')).encode()+b'\n',bad))
    def test_interface_retry_wait_and_recovery_preserve_independent_state(self):
        state=self.lua.execute((PROTO/'ddns-state.lua').read_bytes())
        context={'rule':'ddns_b','provider':'cloudflare','revision':3,'identity':'a'*64,'generation':'b'*64,'boot':'11111111-1111-1111-1111-111111111111','interval':300}
        failed=state.finish(state.begin(self.table(context),None,1000),1000,b'failed',b'network_unavailable',b'none',True)
        self.assertTrue(state.valid(failed));self.assertEqual((failed[b'failures'],failed[b'delay']),(1,300))
        self.assertEqual(state.decision(failed,self.table(context),1299,False,True,False),(b'retry_wait',1))
        self.assertEqual(state.decision(failed,self.table(context),1300,False,True,False),(b'ready',0))
        restored=state.finish(state.begin(self.table(context),failed,1300),1300,b'unchanged',b'',b'none',False)
        self.assertEqual((restored[b'failures'],restored[b'delay'],restored[b'outcome']),(0,300,b'unchanged'))
        self.assertEqual(state.decision(restored,self.table(context),1599,False,True,False),(b'waiting',1))
    def test_repeated_interface_network_failure_has_bounded_backoff(self):
        state=self.lua.execute((PROTO/'ddns-state.lua').read_bytes())
        context=self.table({'rule':'ddns_b','provider':'cloudflare','revision':3,'identity':'a'*64,'generation':'b'*64,'boot':'11111111-1111-1111-1111-111111111111','interval':300})
        old=None;now=1000
        for attempt in range(1,11):
            old=state.finish(state.begin(context,old,now),now,b'failed',b'network_unavailable',b'none',True)
            failures=min(attempt,8);delay=max(300,min(3600,60*2**(failures-1)))
            self.assertEqual((old[b'failures'],old[b'delay']),(failures,delay));self.assertTrue(state.valid(old))
            self.assertEqual(state.decision(old,context,now+delay-1,False,True,False),(b'retry_wait',1));now+=delay
    def test_mixed_batch_network_error_and_unknown_receipts_keep_distinct_effects(self):
        def row(rule,status='unchanged',effect='none',kind='',retry=False):return {'rule':rule,'provider':'cloudflare','status':status,'effect':effect,'error_kind':kind,'retryable':retry,'retry_in':0}
        rows=[row('ddns_a'),row('ddns_b','network_unavailable',kind='network_unavailable',retry=True),row('ddns_c')]
        doc={'api_version':1,'prototype':True,'ok':False,'phase':'ddns-batch','configuration_revision':3,'effect':'none','sampled':True,'write_ready':False,'rules':rows}
        check=lambda:self.policy.batch(json.dumps(doc,separators=(',',':')).encode()+b'\n',self.table(doc),b'3',b'1',self.table(['ddns_a','ddns_b','ddns_c']),self.codec.json)
        self.assertEqual(check(),b'none')
        rows[1]=row('ddns_b','failed','unknown','temporary');rows[2]=row('ddns_c','blocked');doc['effect']='unknown';self.assertEqual(check(),b'unknown')
        rows[1]['retryable']=True;self.assertIsNone(check())

    def test_gate_grammar_fixed_paths_and_no_signal_or_closeout(self):
        import tree_sitter,tree_sitter_bash
        parser=tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()));body=(PROTO/'homegate-ddns-schedule.sh').read_bytes();self.assertFalse(parser.parse(body).root_node.has_error);self.assertNotIn(b'\r',body);self.assertEqual(body.count(b'ddns_schedule_enabled=false'),1)
        for forbidden in [b'kill ',b'killpg',b'--confirm-closeouts',b'collect-receipt',b'retire-archive',b'rm -r',b'eval ',b'curl']:self.assertNotIn(forbidden,body)
        self.assertIn(b'[ "$owner" = 0 ]',body)
        for name in ['ddns-schedule.lua','homegate-ddns-schedule.lua']:self.lua.compile((PROTO/name).read_bytes())
        self.assertNotIn('prototype/',(PROTO.parent/'Makefile').read_text())

class ScheduleMixin:
    def setUp(self):
        super().setUp();self.schedule=self.engine.parent/'homegate-ddns-schedule.sh';self.schedule_dir=self.native.lockdir/'ddns-schedule';self.releases=[];self.jobs=[]
        mapping={'/var/run/homegate':str(self.native.lockdir),'/etc/homegate/transactions':str(self.store),'/proc/sys/kernel/random/boot_id':str(self.boot_id)}
        body=self.schedule.read_text().replace('ddns_schedule_enabled=false','ddns_schedule_enabled=true');body=re.sub('|'.join(re.escape(k) for k in sorted(mapping,key=len,reverse=True)),lambda m:mapping[m[0]],body).replace('moment=$(lua "$dir/worker-process.lua" now 2>/dev/null)','moment=$(cat '+str(self.clock)+')')
        self.schedule.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(self.bin))))
    def tearDown(self):
        for event in self.releases:event.set()
        for job in self.jobs:
            if job.poll() is None:
                job.terminate()
                try:job.communicate(timeout=40)
                except subprocess.TimeoutExpired:job.kill();job.communicate(timeout=5)
        super().tearDown()
    def public(self,raw):
        out=json.loads(raw);self.assertFalse(out['write_ready']);self.assertEqual(out['effect'],'none')
        for marker in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL',b'example.test',b'2001:db8',b'pppoe-wan',b'identity',b'generation',b'grant',b'token',b'pid',b'birth']:self.assertNotIn(marker,raw)
        return out
    def start(self):
        p=subprocess.Popen([self.busybox,'ash',str(self.schedule),'run','--confirm'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.jobs.append(p);return p
    def finish(self,p,expected=0,timeout=100):
        out,err=p.communicate(timeout=timeout);self.assertEqual((p.returncode,err),(expected,b''),(out,err));self.assertEqual(self.config_bytes(),self.baseline_config);return self.public(out)
    def control_call(self,action,expected=0,args=None,env=None):
        n=len(self.calls);p=subprocess.run([self.busybox,'ash',str(self.schedule),*(args if args is not None else [action]+([] if action=='status' else ['--confirm']))],env=env or self.env,capture_output=True,timeout=12);self.assertEqual((p.returncode,p.stderr),(expected,b''),(p.stdout,p.stderr));self.assertEqual(len(self.calls),n);return self.public(p.stdout)
    def wait_for(self,p,status='waiting',timeout=45):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if p.poll() is not None:self.fail(self.finish(p,p.returncode))
            f=self.schedule_dir/'report'
            if f.exists():
                try:
                    d=json.loads(f.read_bytes().splitlines()[0])
                    if d['status']==status:return d
                except (ValueError,IndexError):pass
            time.sleep(.05)
        self.fail('bounded fixture did not reach '+status)
    def record(self,name='lease'):
        raw=(self.schedule_dir/name).read_bytes();body,digest=raw.splitlines();self.assertEqual(hashlib.sha256(body+b'\n').hexdigest().encode(),digest);return json.loads(body)
    def rewrite_lease(self,mutate):
        d=self.record();mutate(d);body=json.dumps(d,sort_keys=True,separators=(',',':')).encode()+b'\n';(self.schedule_dir/'lease').write_bytes(body+hashlib.sha256(body).hexdigest().encode()+b'\n')
    def accelerate(self,step=300):
        self.fault('sleep','from pathlib import Path\np=Path('+repr(str(self.clock))+')\nif sys.argv[1:]==["1"]: p.write_text(str(int(p.read_text())+'+str(step)+')+"\\n");sys.exit(0)')
    def gated_http(self):
        entered=threading.Event();release=threading.Event();self.releases.append(release)
        def hook(*args):
            if not entered.is_set():entered.set();release.wait(20)
        self.hook=hook;return entered,release
    def test_confirmed_mutation_stops_before_next_rule_without_closeout(self):
        p=self.start();out=self.finish(p,4);self.assertEqual((out['ticks'],out['reason'],out['last_effect']),(1,'blocked','confirmed'));self.assertEqual(len(self.mutations()),1);self.assertTrue(self.journal.exists());self.assertFalse(self.archive.exists());self.assertFalse((self.store/'dns-batch-results').exists());before=self.files(self.journal)
        self.control_call('reap',4);self.control_call('run',4);self.assertEqual(before,self.files(self.journal));self.maintenance('collect-receipt');self.maintenance('retire-archive');self.control_call('reap');self.assertFalse(self.schedule_dir.exists())
    def test_noop_wait_stop_is_cooperative_and_gate_independent(self):
        self.assertEqual(self.control_call('status')['status'],'idle');self.assertFalse(self.schedule_dir.exists());self.seed();p=self.start();self.wait_for(p);n=len(self.calls);self.assertTrue(self.control_call('status')['running'])
        self.schedule.write_text(self.schedule.read_text().replace('ddns_schedule_enabled=true','ddns_schedule_enabled=false'));self.control_call('stop');out=self.finish(p);self.assertEqual((out['ticks'],out['reason']),(1,'stopped'));self.assertEqual(len(self.calls),n);self.assertEqual(self.mutations(),[]);self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes']);self.control_call('reap')
    def test_unknown_mutation_preserves_original_fences_and_never_restarts(self):
        def hook(*args):
            action=args[0];mutation=action!='GET' if self.provider in ['cloudflare','huaweicloud'] else action==('AddDomainRecord' if self.provider=='aliyun' else 'CreateRecord')
            if mutation:self.seed();return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy','Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
        self.hook=hook;p=self.start();out=self.finish(p,4);self.hook=None;self.assertEqual(out['reason'],'reconciliation_required');self.assertEqual(out['last_effect'],'unknown');before=self.files(self.journal);self.assertTrue(list(self.native.lockdir.glob('.ddns-plan-*')));self.control_call('reap',4);self.control_call('run',4);self.assertEqual(before,self.files(self.journal));self.assertEqual(len(self.mutations()),1)

class CF(ScheduleMixin,CFBase):pass
class Ali(ScheduleMixin,AliBase):pass
class DNP(ScheduleMixin,DNPBase):pass
class HW(ScheduleMixin,HWBase):pass

class Boundaries(CF):
    def test_budget_stops_after_three_due_rounds_without_polling_http(self):
        self.seed();self.accelerate();out=self.finish(self.start());self.assertEqual((out['reason'],out['ticks']),('budget',3));self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes']*3);self.assertEqual(self.mutations(),[]);self.control_call('reap')
    def test_tick_limit_stops_even_inside_remaining_budget(self):
        # One explicitly authorized member is sufficient to exercise all eight
        # real admissions. Two-member pacing remains covered by the budget test
        # and provider cases; repeating it here exhausted the 200s wall budget.
        current=self.cli('status')['revision'];body=(self.store/f'gen-{current}/public.conf').read_bytes().replace(b"option ddns_interval '300'",b"option ddns_interval '60'");p=self.cli('preview',payload=body);tx=self.cli('commit-apply-projection',p['confirmation']);self.cli('projection-publish',tx['apply_handle'],'apply');self.cli('apply-finish-projection',tx['apply_handle']);p=self.auth('preview','ddns_a');self.auth('commit',p['confirmation']);self.baseline_config=self.config_bytes()
        self.seed();self.accelerate(60);out=self.finish(self.start(),timeout=200);self.assertEqual((out['reason'],out['ticks']),('ticks',8));self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes']*8);self.assertEqual(self.mutations(),[])
        self.assertEqual(len(self.calls),16);self.assertTrue((self.state_dir/'ddns_a').is_file());self.assertFalse((self.state_dir/'ddns_b').exists())
    def test_cli_gate_concurrent_run_and_shared_locks_refuse(self):
        import fcntl
        for args in [[],['run'],['run','--confirm-closeouts'],['stop'],['reap','bad']]:self.control_call('run',2,args=args)
        text=self.schedule.read_text();self.schedule.write_text(text.replace('ddns_schedule_enabled=true','ddns_schedule_enabled=false'));self.control_call('run',2,env={**self.env,'ddns_schedule_enabled':'true'});self.schedule.write_text(text)
        for path in [self.native.lock,self.store/'.supervisor.lock']:
            with path.open('rb') as f:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);self.control_call('run',4)
        self.assertFalse(self.schedule_dir.exists());self.assertEqual(self.calls,[]);self.seed();p=self.start();self.wait_for(p);self.control_call('run',4);self.control_call('reap',4);self.control_call('stop');self.finish(p)
    def test_source_change_while_waiting_refuses_next_dispatch(self):
        self.seed();p=self.start();self.wait_for(p);n=len(self.calls);self.source.write_bytes(self.source.read_bytes()+b'\n');self.baseline_config=self.config_bytes();self.clock.write_text('1300\n');out=self.finish(p,4);self.assertEqual(out['reason'],'changed');self.assertEqual(len(self.calls),n)
    def test_revoked_grant_refuses_next_dispatch_without_erasing_state(self):
        self.seed();p=self.start();self.wait_for(p);before=self.files(self.state_dir);n=len(self.calls);self.revoke_fixture();self.clock.write_text('1300\n');out=self.finish(p,4);self.assertEqual(out['reason'],'changed');self.assertEqual(self.files(self.state_dir),before);self.assertEqual(len(self.calls),n);self.control_call('reap')
    def test_stop_during_provider_read_waits_for_admitted_batch(self):
        self.seed();entered,release=self.gated_http();p=self.start();self.assertTrue(entered.wait(30));self.assertEqual(self.control_call('stop')['status'],'stopping');self.control_call('reap',4);self.assertIsNone(p.poll());release.set();out=self.finish(p);self.assertEqual((out['reason'],out['ticks']),('stopped',1));self.assertEqual(self.mutations(),[]);self.assertFalse(self.journal.exists());self.control_call('reap')
    def test_term_during_provider_read_does_not_abandon_batch(self):
        self.seed();entered,release=self.gated_http();p=self.start();self.assertTrue(entered.wait(30));p.send_signal(signal.SIGTERM);time.sleep(.1);self.assertIsNone(p.poll());release.set();out=self.finish(p);self.assertEqual((out['reason'],out['ticks']),('stopped',1));self.assertEqual(self.mutations(),[]);self.control_call('reap')
    def test_owner_death_preserves_control_and_reap_waits_for_shared_locks(self):
        self.seed();entered,release=self.gated_http();p=self.start();self.assertTrue(entered.wait(30));p.kill();p.communicate(timeout=5);out=self.control_call('status');self.assertEqual((out['status'],out['last_effect']),('interrupted','unknown'));self.control_call('reap',4);self.control_call('run',4);release.set()
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            proc=subprocess.run([self.busybox,'ash',str(self.schedule),'reap','--confirm'],env=self.env,capture_output=True,timeout=12)
            if proc.returncode==0:self.public(proc.stdout);break
            self.assertEqual(proc.returncode,4,(proc.stdout,proc.stderr));time.sleep(.2)
        else:self.fail('original bounded batch did not release its common locks')
        self.assertEqual(self.mutations(),[]);self.assertFalse(self.schedule_dir.exists())
    def test_unknown_control_member_and_link_are_preserved(self):
        self.seed();p=self.start();self.wait_for(p);extra=self.schedule_dir/'unknown';extra.write_bytes(b'KEEP');extra.chmod(0o600);out=self.finish(p,7);self.assertEqual(out['reason'],'failed');self.control_call('reap',7);self.assertEqual(extra.read_bytes(),b'KEEP');extra.unlink()
        outside=self.base/'outside-control';outside.write_bytes(b'KEEP');outside.chmod(0o600);(self.schedule_dir/'stop').symlink_to(outside);self.control_call('stop',7);self.control_call('reap',7);self.assertEqual(outside.read_bytes(),b'KEEP')
    def test_interrupted_lease_and_report_publications_need_explicit_reap(self):
        for suffix in ['/lease.next','/report.next']:
            self.fault('mv','sys.exit(1) if any(a.endswith('+repr(suffix)+') for a in sys.argv[1:]) else None');self.finish(self.start(),7);self.restore_tool('mv');self.assertTrue((self.schedule_dir/suffix[1:]).exists());self.control_call('run',4);self.assertEqual(self.calls,[]);self.control_call('reap');self.assertFalse(self.schedule_dir.exists())
    def test_foreign_live_pid_and_cold_boot_never_receive_signals(self):
        self.seed();p=self.start();self.wait_for(p);self.control_call('stop');self.finish(p);old=self.record();foreign=subprocess.Popen([self.busybox,'sleep','20']);self.jobs.append(foreign)
        try:
            birth=Path('/proc/'+str(foreign.pid)+'/stat').read_text().split(') ')[1].split()[19];self.rewrite_lease(lambda d:d.update(pid=str(foreign.pid),birth=birth));self.control_call('reap',7);self.assertIsNone(foreign.poll())
            self.boot_id.write_text('22222222-2222-2222-2222-222222222222\n');self.control_call('reap');self.assertIsNone(foreign.poll())
        finally:foreign.terminate();foreign.communicate(timeout=5)

class MixedScheduleMixin(ScheduleMixin):
    def track_wait_boundary(self):
        # A waiting report is published before wake is calculated. Only the
        # scheduler-owned real sleep proves the wake deadline used this clock.
        self.waiting_probe=self.base/'schedule-wait-boundary'
        self.fault('sleep',"from pathlib import Path\nimport json\n"
            "if sys.argv[1:]==['1']:\n"
            " lease=json.loads(Path("+repr(str(self.schedule_dir/'lease'))+").read_bytes().splitlines()[0])\n"
            " if lease['pid']==str(os.getppid()):\n"
            "  report=json.loads(Path("+repr(str(self.schedule_dir/'report'))+").read_bytes().splitlines()[0])\n"
            "  if report['status']=='waiting':\n"
            "   target=Path("+repr(str(self.waiting_probe))+");pending=target.with_suffix('.next')\n"
            "   pending.write_text(json.dumps({'ticks':report['ticks'],'moment':Path("+repr(str(self.clock))+").read_text().strip()}))\n"
            "   pending.chmod(0o600);os.replace(pending,target)\n")
    def wait_boundary_reached(self,ticks):
        probe=getattr(self,'waiting_probe',None)
        if probe is None:return True
        if not probe.exists():return False
        doc=json.loads(probe.read_bytes())
        return doc=={'ticks':ticks,'moment':self.clock.read_text().strip()}
    def seed_all_mixed(self):
        for name,value in [('ddns_a','2001:db8::2'),('ddns_b','2001:db8:2::9'),('ddns_c','2001:db8:3::8')]:self.seed_mixed(name,value)
    def wait_tick(self,process,ticks,timeout=90):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if process.poll() is not None:self.fail(self.finish(process,process.returncode))
            report=self.schedule_dir/'report'
            if report.exists():
                doc=json.loads(report.read_bytes().splitlines()[0])
                if doc['status']=='waiting' and doc['ticks']==ticks and self.wait_boundary_reached(ticks):return doc
            time.sleep(.05)
        self.fail('Mixed schedule did not finish bounded tick '+str(ticks))
    def stop_waiting(self,process):
        # Nonblocking control-lock contention is exit 4, not durable corruption.
        # Retry only this explicit stop intent, with a fixed local deadline.
        end=time.monotonic()+5;calls=len(self.calls)
        while time.monotonic()<end:
            request=subprocess.run([self.busybox,'ash',str(self.schedule),'stop','--confirm'],env=self.env,capture_output=True,timeout=12)
            self.assertEqual(request.stderr,b'');self.assertEqual(len(self.calls),calls)
            if request.returncode==0:return self.public(request.stdout)
            self.assertEqual(request.returncode,4,(request.stdout,request.stderr));self.public(request.stdout)
            self.assertIsNone(process.poll(),'Schedule ended before explicit stop could be accepted');time.sleep(.02)
        self.fail('Schedule control lock stayed busy beyond bounded stop deadline')
    def test_interface_withdrawal_wait_and_recovery_use_fresh_independent_samples(self):
        self.track_wait_boundary();self.seed_all_mixed();original=self.settings['addresses'];process=self.start();self.wait_tick(process,1)
        self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes'])
        self.settings['addresses']=''.join(line+'\n' for line in original.splitlines() if 'odd-uplink' not in line);self.control.write_text(json.dumps(self.settings));self.clock.write_text('1300\n');self.wait_tick(process,2)
        failed=json.loads((self.state_dir/'ddns_b').read_bytes());self.assertEqual((failed['outcome'],failed['error_kind'],failed['failures']),('retry_wait','network_unavailable',1))
        for name in ['ddns_a','ddns_c']:
            good=json.loads((self.state_dir/name).read_bytes());self.assertEqual((good['outcome'],good['failures']),('unchanged',0))
        sample=self.netlog.read_bytes();self.settings['addresses']=original;self.control.write_text(json.dumps(self.settings));self.clock.write_text('1599\n')
        self.assertEqual(self.control_call('status')['ticks'],2);self.assertEqual(self.netlog.read_bytes(),sample)
        self.clock.write_text('1600\n');self.wait_tick(process,3);restored=json.loads((self.state_dir/'ddns_b').read_bytes());self.assertEqual((restored['outcome'],restored['failures']),('unchanged',0))
        self.stop_waiting(process);out=self.finish(process);self.assertEqual((out['ticks'],out['reason'],out['last_effect']),(3,'stopped','none'))
        self.assertEqual(self.netlog.read_text().splitlines(),['addresses','routes']*3);self.assertEqual(self.mutations(),[]);self.assertFalse(self.journal.exists());self.control_call('reap')
    def test_changed_interface_address_stops_with_original_confirmed_receipt(self):
        self.seed_all_mixed();self.settings['addresses']=self.settings['addresses'].replace('2001:db8:2::9','2001:db8:2::7');self.control.write_text(json.dumps(self.settings))
        out=self.finish(self.start(),4);self.assertEqual((out['ticks'],out['reason'],out['last_effect']),(1,'blocked','confirmed'))
        batch=json.loads((self.schedule_dir/'batch').read_bytes());self.assertEqual([row['status'] for row in batch['rules']],['unchanged','updated','blocked'])
        slot=self.journal/('slot-'+(self.journal/'current').read_text().strip());self.assertEqual(json.loads((slot/'context').read_bytes())['request'],{'operation':'upsert','kind':'ddns','resource':'ddns_b','value':'2001:db8:2::7'})
        before=self.files(self.journal);calls=len(self.calls);self.control_call('reap',4);self.control_call('run',4)
        self.assertEqual(self.files(self.journal),before);self.assertEqual(len(self.calls),calls);self.assertEqual(len(self.mutations()),1);self.assertFalse(self.archive.exists());self.assertFalse((self.store/'dns-batch-results').exists())

class MixedCF(MixedScheduleMixin,MixedCFBase):pass
class MixedAli(MixedScheduleMixin,MixedAliBase):pass
class MixedDNP(MixedScheduleMixin,MixedDNPBase):pass
class MixedHW(MixedScheduleMixin,MixedHWBase):pass
class MixedBoundaries(MixedCF):
    def test_mixed_interface_configuration_change_stops_next_admission(self):
        self.seed_all_mixed();process=self.start();self.wait_tick(process,1);sample=self.netlog.read_bytes();calls=len(self.calls)
        self.source.write_bytes(self.source.read_bytes().replace(b'odd-uplink',b'another-uplink'));self.baseline_config=self.config_bytes();self.clock.write_text('1300\n')
        out=self.finish(process,4);self.assertEqual((out['reason'],out['ticks']),('changed',1));self.assertEqual(self.netlog.read_bytes(),sample);self.assertEqual(len(self.calls),calls);self.assertEqual(self.mutations(),[])
    def test_unknown_middle_interface_result_stops_without_retry_or_closeout(self):
        self.seed_mixed('ddns_a','2001:db8::2');self.seed_mixed('ddns_c','2001:db8:3::8')
        def hook(*args):
            if args[0]!='GET':self.seed_mixed('ddns_b','2001:db8:2::9');return 500,{'success':False,'errors':[]}
        self.hook=hook;out=self.finish(self.start(),4);self.hook=None;self.assertEqual((out['ticks'],out['reason'],out['last_effect']),(1,'reconciliation_required','unknown'))
        before=self.files(self.journal);calls=len(self.calls);sample=self.netlog.read_bytes();self.control_call('reap',4);self.control_call('run',4)
        self.assertEqual(self.files(self.journal),before);self.assertEqual(len(self.calls),calls);self.assertEqual(self.netlog.read_bytes(),sample);self.assertEqual(len(self.mutations()),1);self.assertFalse(self.archive.exists())

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--runtime',action='store_true')
    mode=p.add_mutually_exclusive_group();mode.add_argument('--mixed-only',action='store_true');mode.add_argument('--auto-only',action='store_true')
    p.add_argument('--list-tests',action='store_true');p.add_argument('--case');a=p.parse_args();suite=unittest.TestSuite()
    if (a.mixed_only or a.auto_only) and not a.runtime:p.error('Source selection requires --runtime')
    mixed=[MixedCF,MixedAli,MixedDNP,MixedHW,MixedBoundaries]
    for cls in ((mixed if a.mixed_only else [CF,Ali,DNP,HW,Boundaries] if a.auto_only else [CF,Ali,DNP,HW,Boundaries]+mixed) if a.runtime else [Static]):
        methods=MixedBoundaries.__dict__ if cls is MixedBoundaries else MixedScheduleMixin.__dict__ if cls in mixed else Boundaries.__dict__ if cls is Boundaries else ScheduleMixin.__dict__ if a.runtime else Static.__dict__
        suite.addTests(cls(n) for n,v in methods.items() if n.startswith('test_') and callable(v) and (not a.case or a.case==n))
    if not suite.countTestCases():p.error('No cases')
    if a.list_tests:
        print(json.dumps([test.id() for test in suite]));raise SystemExit(0)
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
