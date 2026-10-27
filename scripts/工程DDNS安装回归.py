#!/usr/bin/env python3
"""Run installed engineering bytes in disposable chroots with loopback TLS DNS.

Only external tools/network endpoints are fixtures. The deployed business files
are neither patched nor granted access to the production /etc namespace.
"""
import argparse,hashlib,json,os,re,shutil,stat,subprocess,sys,time
from pathlib import Path
from project import ROOT,identity
from engineering_runtime import stage,SCOPE
from DDNS执行回归 import CF,Ali,DNP,HW,rec,ali_record,dnp_record,hw_record
from DDNS计划回归 import ADDR,ROUTE

def digest(file):return hashlib.sha256(file.read_bytes()).hexdigest()

def copy_runtime(root,binary,destination=None):
    dest=root/(destination or str(binary).lstrip('/'));dest.parent.mkdir(parents=True,exist_ok=True)
    if dest.is_symlink():dest.unlink()
    shutil.copyfile(binary,dest);dest.chmod(0o755)
    p=subprocess.run(['ldd',str(binary)],capture_output=True,text=True)
    if p.returncode and 'not a dynamic executable' not in p.stderr+p.stdout:raise RuntimeError(p.stderr+p.stdout)
    for name in re.findall(r'(?:=>\s+)?(/[^\s()]+)',p.stdout):
        dep=Path(name);target=root/str(dep).lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
        if not target.exists():shutil.copyfile(dep,target);target.chmod(0o755)

def script(root,name,body):
    file=root/name;file.parent.mkdir(parents=True,exist_ok=True)
    if file.is_symlink():file.unlink()
    file.write_text('#!/bin/sh\n'+body+'\n');file.chmod(0o755)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work-dir',type=Path,required=True)
    p.add_argument('--installed-root',type=Path)
    p.add_argument('--report',type=Path,required=True)
    p.add_argument('--provider',choices=['cloudflare','aliyun','dnspod','huaweicloud'])
    mode=p.add_mutually_exclusive_group()
    mode.add_argument('--contracts',action='store_true',help='Verify account/zone reads and exact-host delete through installed bytes')
    mode.add_argument('--schedule',action='store_true',help='Verify finite scheduled TLS no-op and unknown barriers instead of the manual sequence')
    args=p.parse_args();assert os.getuid()==0 and not args.work_dir.exists()
    args.work_dir.mkdir(mode=0o700,parents=True)
    rows=[]
    busybox=ROOT/'build/busybox-runtime/busybox-1.33.2/busybox'
    os.environ['PATH']=str(busybox.parent)+':'+os.environ['PATH']
    for cls,provider in [(CF,'cloudflare'),(Ali,'aliyun'),(DNP,'dnspod'),(HW,'huaweicloud')]:
        if args.provider and args.provider!=provider:continue
        cls.setUpClass();fixture=cls();ready=False;mounted=False
        root=args.work_dir/provider
        try:
            fixture.setUp();ready=True
            if args.installed_root:
                shutil.copytree(args.installed_root,root,symlinks=True,
                    ignore=lambda directory,names:['dev','proc'] if Path(directory)==args.installed_root else [])
            else:
                root.mkdir(mode=0o700)
                base=root/'usr/libexec/homegate-engineering';stage(ROOT,base)
                for name in ['engineering.lua','ddns-control.sh','apply-handle.lua','service-disabled','config-web.sh','config-web.lua','schedule-control.sh']:
                    dest=base/name;shutil.copyfile(ROOT/'packaging/engineering/files'/name,dest);dest.chmod(0o755)
                script(root,'usr/bin/homegate-engineering',(ROOT/'packaging/engineering/files/homegate-engineering').read_text().removeprefix('#!/bin/sh\n'))
            base=root/'usr/libexec/homegate-engineering'
            business={str(f.relative_to(root)):digest(f) for f in base.rglob('*') if f.is_file()}
            business['usr/bin/homegate-engineering']=digest(root/'usr/bin/homegate-engineering')
            copy_runtime(root,busybox,'bin/busybox')
            for name in subprocess.check_output([str(busybox),'--list'],text=True).splitlines():
                dest=root/'bin'/name
                if not dest.exists():dest.symlink_to('busybox')
            copy_runtime(root,Path('/usr/bin/lua5.1'),'usr/bin/lua')
            copy_runtime(root,Path('/usr/bin/stat'))
            copy_runtime(root,Path('/usr/bin/sed'))
            copy_runtime(root,Path('/usr/bin/openssl'))
            copy_runtime(root,fixture.real_curl,'usr/libexec/fixture-curl')
            copy_runtime(root,ROOT/'build/service-observer/luci/jsonc.so','usr/lib/lua/5.1/luci/jsonc.so')
            # Preserve strict TLS. Only the configured URL's host/port changes
            # at this external curl fixture; CA verification remains enabled.
            origin='https://127.0.0.1:'+str(fixture.server.server_port)
            expressions="'s#https://[^/\"]*#"+origin+"#g'"
            script(root,'usr/bin/curl','[ "$1" = --disable ] && [ "$2" = --config ] || exit 99\nrequest=$3;shift 3\ncount=$#\nwhile [ "$count" -gt 0 ];do argument=$1;shift;case "$argument" in https://api.cloudflare.com/*) argument="'+origin+'${argument#https://api.cloudflare.com}";; esac;set -- "$@" "$argument";count=$((count-1));done\nsed '+expressions+' "$request" | /usr/libexec/fixture-curl --disable --config - "$@" --show-error 2>/tmp/fixture-curl-error\nrc=$?;printf "%s\\n" "$rc" >/tmp/fixture-curl-exit;exit "$rc"')
            ca=root/'etc/ssl/certs/ca-certificates.crt';ca.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(fixture.ca_dir/'ca.pem',ca)
            script(root,'sbin/ip',"case \"$*\" in *addr*) cat <<'ADDR'\n"+ADDR+"ADDR\n;; *) cat <<'ROUTE'\n"+ROUTE+'ROUTE\n;; esac')
            script(root,'sbin/ubus','case "$*" in *service*) printf \'{}\\n\';; *) printf \'{"up":true,"l3_device":"eth4"}\\n\';; esac')
            script(root,'etc/rc.common','exit 99')
            for name in ['etc/config','var/run','tmp','proc','dev']:(root/name).mkdir(parents=True,exist_ok=True)
            (root/'tmp').chmod(0o1777)
            null=root/'dev/null'
            if not null.exists():os.mknod(null,stat.S_IFCHR|0o666,os.makedev(1,3))
            random=root/'dev/urandom'
            if not random.exists():os.mknod(random,stat.S_IFCHR|0o444,os.makedev(1,9))
            source=root/'etc/config/homegate_engineering';source.write_bytes(fixture.source.read_bytes());source.chmod(0o600)
            sentinels={'etc/config/homegate':b'PRODUCTION_CONFIG_KEEP','etc/homegate/keep':b'PRODUCTION_VAULT_KEEP',
                       'usr/bin/homegate':b'PRODUCTION_BINARY_KEEP','etc/init.d/homegate':b'PRODUCTION_SERVICE_KEEP'}
            for name,raw in sentinels.items():
                dest=root/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw);dest.chmod(0o600)
            subprocess.run(['mount','--bind','/proc',str(root/'proc')],check=True);mounted=True
            results=[];readonly_probe_refusals=0
            def call(label,*argv,expected=0,data=b'',record=True,transient_observation=False):
                nonlocal readonly_probe_refusals
                proc=subprocess.run(['chroot',str(root),'/usr/bin/homegate-engineering',*argv],input=data,
                    capture_output=True,timeout=50,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                if transient_observation and argv==('schedule-status',) and proc.returncode==7:
                    # A read can straddle owner exit. Never retry a business
                    # operation, and never accept a durable unreadable state:
                    # only the fixed conservative status refusal is eligible,
                    # under wait_schedule's unchanged local deadline.
                    refused=json.loads(proc.stdout)
                    assert proc.stderr==b'' and refused=={'api_version':1,'prototype':True,'ok':False,'phase':'ddns-schedule','effect':'none','write_ready':False,'error':'DDNS schedule is unavailable'}
                    readonly_probe_refusals+=1;return None
                assert (proc.returncode,proc.stderr)==(expected,b''),(provider,label,proc.returncode,proc.stdout,proc.stderr)
                assert len(proc.stdout)<=16384,(label,'unbounded output')
                for secret in [b'SECRET_SENTINEL',b'PRIVATE_SENTINEL']:
                    assert secret not in proc.stdout,(label,'sensitive response')
                doc=json.loads(proc.stdout)
                if not (argv[0]=='schedule-status' and expected==0 and doc.get('phase')=='ddns-schedule' and 'status' in doc):
                    assert doc['ok']==(expected==0 or (expected==4 and doc.get('phase')=='ddns-state' and 'status' in doc)),(label,doc)
                if record:results.append(label);print(provider,label,flush=True)
                return doc
            call('prepare','prepare')
            before_calls=len(fixture.calls)
            call('ungranted-sync-refused','ddns-sync','ddns_a',expected=7)
            assert len(fixture.calls)==before_calls
            token=call('private-import-preview','import-preview')['confirmation']
            call('private-import-commit','import-commit',token)
            token=call('ordinary-activation-preview','activate-preview')['confirmation']
            call('ordinary-activation-commit','config-commit',token)
            public=source.read_bytes();assert b'SECRET_SENTINEL' not in public and b"option enabled '1'" not in public
            store=root/'etc/homegate-engineering/transactions'
            assert any(b'SECRET_SENTINEL' in f.read_bytes() for f in store.glob('gen-*/credentials/*'))
            call('ordinary-source-still-ungranted','ddns-sync','ddns_a',expected=4)
            if args.contracts:
                # The record fixtures' default domain-list responses are empty
                # for Ali/DNSPod. Supply one known signed zone at this external
                # API boundary; authentication/signature checks run before hook.
                def zone_read_hook(*argv):
                    if provider=='aliyun' and argv[0]=='DescribeDomains':
                        q=argv[1];return 200,{'RequestId':'fixture','TotalCount':1,'PageNumber':int(q['PageNumber'][0]),'PageSize':int(q['PageSize'][0]),'Domains':{'Domain':[{'DomainName':'example.test'}]}}
                    if provider=='dnspod' and argv[0]=='DescribeDomainList':
                        return 200,{'Response':{'RequestId':'fixture','DomainCountInfo':{'DomainTotal':1},'DomainList':[{'Name':'example.test'}]}}
                fixture.hook=zone_read_hook
                status=call('credentials-without-DDNS-write-grant','dns-provider-status','dns_a');assert status['credentials_valid']
                zones=call('all-zones-without-DDNS-write-grant','dns-zones','dns_a');assert zones['zones']==['example.test']
                fixture.hook=None
                calls=len(fixture.calls)
                call('delete-requires-explicit-confirmation','ddns-delete','ddns_a',expected=2)
                call('delete-requires-current-rule-grant','ddns-delete','ddns_a','--confirm',expected=4)
                assert len(fixture.calls)==calls and not fixture.mutations()
            token=call('grant-preview-only','grant-preview','ddns_a')['confirmation']
            call('preview-alone-cannot-sync','ddns-sync','ddns_a',expected=4)
            call('grant-commit','grant-commit',token)
            if args.contracts:
                script(root,'sbin/ip','printf used >/tmp/ip-used\nexit 99')
                def record(n,typ='AAAA',host='www',value='2001:db8::1'):
                    return {'cloudflare':lambda:rec(n,typ=typ,name=host+'.example.test',value=value),
                            'aliyun':lambda:ali_record(n,typ=typ,rr=host,value=value),
                            'dnspod':lambda:dnp_record(n,typ=typ,rr=host,value=value),
                            'huaweicloud':lambda:hw_record(n,typ=typ,name=host+'.example.test.',values=[value])}[provider]()
                fixture.add(record(10,typ='TXT',value='TXT_KEEP'));fixture.add(record(11,host='other'))
                unrelated={k:json.loads(json.dumps(v)) for k,v in fixture.db.items()}
                fixture.add(record(1))
                if provider!='huaweicloud':fixture.add(record(2,value='2001:db8::9'))
                deleted=call('delete-all-exact-host-AAAA-without-WAN','ddns-delete','ddns_a','--confirm')
                assert deleted['phase']=='ddns-delete' and deleted['effect']=='confirmed' and deleted['result']=='deleted'
                assert deleted['affected']==(1 if provider=='huaweicloud' else 2)
                assert fixture.db==unrelated and not (root/'tmp/ip-used').exists()
                journal=store/'dns-operation';saved={str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()}
                count=len(fixture.calls)
                call('confirmed-delete-blocks-repeat','ddns-delete','ddns_a','--confirm',expected=4)
                assert count==len(fixture.calls)
                slot=journal/('slot-'+(journal/'current').read_text().strip());job=(slot/'manifest').read_text().splitlines()[6]
                context=json.loads((slot/'context').read_bytes());assert context['request']=={'operation':'delete','kind':'ddns','resource':'ddns_a','value':'','all':True}
                call('delete-read-only-reconciliation','ddns-reconcile',provider,'dns_a',job,'--confirm')
                assert saved=={str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()}
                call('archive-confirmed-delete','ddns-collect-receipt',provider,'dns_a',job,'--confirm')
                assert not journal.exists()
                empty=call('absent-AAAA-delete-is-noop','ddns-delete','ddns_a','--confirm')
                assert empty['result']=='unchanged' and empty['effect']=='none' and not journal.exists() and fixture.db==unrelated
                call('revoke-before-delete','grant-revoke','--confirm')
                count=len(fixture.calls);call('revoked-delete-refused','ddns-delete','ddns_a','--confirm',expected=4);assert count==len(fixture.calls)
                token=call('regrant-delete-preview','grant-preview','ddns_a')['confirmation'];call('regrant-delete-commit','grant-commit',token)
                fixture.add(record(1))
                def unknown_delete_hook(*argv):
                    method=argv[0];is_delete=method=='DELETE' if provider in ['cloudflare','huaweicloud'] else method==('DeleteRecord' if provider=='dnspod' else 'DeleteDomainRecord')
                    if is_delete:
                        fixture.db.clear();fixture.db.update(unrelated)
                        return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy','Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
                fixture.hook=unknown_delete_hook
                unknown=call('unknown-delete-keeps-original-barrier','ddns-delete','ddns_a','--confirm',expected=1);fixture.hook=None
                assert unknown['effect']=='unknown' and not unknown['retryable']
                saved={str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()};count=len(fixture.calls)
                call('unknown-delete-never-retries','ddns-delete','ddns_a','--confirm',expected=4)
                call('unknown-delete-blocks-sync','ddns-sync','ddns_a',expected=4)
                assert count==len(fixture.calls) and saved=={str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()}
                assert fixture.db==unrelated and not (root/'tmp/ip-used').exists()
                for name,raw in sentinels.items():assert (root/name).read_bytes()==raw
                for name,sha in business.items():assert digest(root/name)==sha
                rows.append({'provider':provider,'checks':results,'checks_count':len(results),'installed_business_bytes_unchanged':True,'production_sentinels_unchanged':True,'TLS_verified':True,'other_host_and_TXT_preserved':True,'WAN_not_sampled':True})
                checkpoint={'version':identity()['normalized'],'scope':SCOPE,'business_subscope':'account-zone-delete','providers':rows,'actual_IPK_payload':bool(args.installed_root),'real_DNS_used':False,'router_installed':False,'tests':sum(r['checks_count'] for r in rows),'complete':len(rows)==(1 if args.provider else 4)}
                args.report.write_text(json.dumps(checkpoint,ensure_ascii=False,indent=2)+'\n');continue
            if args.schedule:
                def wait_schedule(predicate):
                    deadline=time.monotonic()+35;last=None
                    while time.monotonic()<deadline:
                        last=call('schedule-observation','schedule-status',record=False,transient_observation=True)
                        if last is not None and predicate(last):return last
                        time.sleep(.1)
                    raise AssertionError((provider,'schedule observation timeout',last))
                fixture.seed()
                call('start-explicit-finite-session','schedule-start','--confirm')
                wait_schedule(lambda d:d['status']=='waiting' and d['ticks']==1)
                assert json.loads((root/'var/run/homegate-engineering/ddns-state/ddns_a').read_bytes())['outcome']=='unchanged'
                results.append('real-TLS-scheduled-noop')
                assert fixture.calls and not fixture.mutations()
                work=root/'var/run/homegate-engineering/ddns-schedule';lease=(work/'lease').read_bytes();count=len(fixture.calls)
                event=call('network-wake-current-lease','schedule-event','ifupdate','wan6','pppoe-wan');assert event['matched']
                time.sleep(1.1);assert (work/'lease').read_bytes()==lease and len(fixture.calls)==count
                call('cooperative-session-stop','schedule-stop','--confirm')
                wait_schedule(lambda d:d['status']=='finished' and d['reason']=='stopped')
                call('explicit-quiescent-reap','schedule-reap','--confirm');assert not work.exists()
                call('reset-known-noop-history','ddns-reset','ddns_a','--confirm')
                fixture.db.clear()
                def unknown_schedule_hook(*argv):
                    method=argv[0]
                    mutating=(method!='GET') if provider in ['cloudflare','huaweicloud'] else method==('CreateRecord' if provider=='dnspod' else 'AddDomainRecord')
                    if mutating:
                        fixture.seed()
                        return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy','Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
                fixture.hook=unknown_schedule_hook
                call('start-new-explicit-session','schedule-start','--confirm')
                unknown=wait_schedule(lambda d:d['status']=='finished' and d['last_effect']=='unknown')
                fixture.hook=None;assert unknown['reason']=='reconciliation_required';results.append('real-TLS-unknown-stops-admission')
                journal=store/'dns-operation';original={str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()};assert original
                count=len(fixture.calls)
                call('unknown-refuses-reap','schedule-reap','--confirm',expected=4)
                call('unknown-refuses-restart','schedule-start','--confirm',expected=4)
                prerm=root/'usr/lib/opkg/info/homegate-engineering-core.prerm'
                if prerm.exists():
                    refused=subprocess.run(['chroot',str(root),'/bin/sh','/usr/lib/opkg/info/homegate-engineering-core.prerm'],capture_output=True,timeout=15)
                    assert (refused.returncode,refused.stdout,refused.stderr)==(4,b'',b''),(provider,'package removal must retain unknown evidence',refused.returncode)
                    results.append('actual-package-prerm-refuses-unknown-removal')
                event=call('network-cannot-restart-unknown-session','schedule-event','ifup','wan6','pppoe-wan');assert not event['active']
                assert count==len(fixture.calls) and original=={str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()}
                for name,raw in sentinels.items():assert (root/name).read_bytes()==raw
                for name,sha in business.items():assert digest(root/name)==sha
                rows.append({'provider':provider,'checks':results,'checks_count':len(results),'mutations':len(fixture.mutations()),'readonly_probe_refusals':readonly_probe_refusals,'installed_business_bytes_unchanged':True,'production_sentinels_unchanged':True,'TLS_verified':True})
                checkpoint={'version':identity()['normalized'],'scope':SCOPE,'business_subscope':'finite-scheduled-ddns','providers':rows,'actual_IPK_payload':bool(args.installed_root),'real_DNS_used':False,'router_installed':False,'external_tools_are_disposable_fixtures':True,'tests':sum(r['checks_count'] for r in rows),'complete':len(rows)==(1 if args.provider else 4)}
                args.report.write_text(json.dumps(checkpoint,ensure_ascii=False,indent=2)+'\n')
                continue
            result=call('AAAA-create','ddns-sync','ddns_a')
            assert result['effect']=='confirmed',result
            assert len(fixture.mutations())==1
            journal=store/'dns-operation';original={str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()}
            call('completed-operation-blocks-repeat','ddns-sync','ddns_a',expected=4)
            assert len(fixture.mutations())==1
            slot=journal/('slot-'+(journal/'current').read_text().strip())
            job=(slot/'manifest').read_text().splitlines()[6]
            call('read-only-reconciliation','ddns-reconcile',provider,'dns_a',job,'--confirm')
            assert {str(f.relative_to(journal)):digest(f) for f in journal.rglob('*') if f.is_file()}==original
            call('confirmed-receipt-archive','ddns-collect-receipt',provider,'dns_a',job,'--confirm')
            assert not journal.exists() and (store/'dns-settled').exists()
            # Pacing is an actual runtime guard. A subsequent status can be
            # waiting, rather than pretending a second cloud update occurred.
            call('installed-status','ddns-status','ddns_a')
            call('explicit-cache-reset','ddns-reset','ddns_a','--confirm')
            unchanged=call('same-AAAA-noop','ddns-sync','ddns_a')
            assert unchanged['effect']=='none' and unchanged['result']=='unchanged'
            assert len(fixture.mutations())==1 and not journal.exists()
            call('cache-reset-before-update','ddns-reset','ddns_a','--confirm')
            fixture.db.clear();fixture.seed('2001:db8::1')
            updated=call('AAAA-update','ddns-sync','ddns_a')
            assert updated['effect']=='confirmed' and updated['result']=='updated'
            assert len(fixture.mutations())==2
            call('retire-previous-bound-archive','ddns-retire-archive',provider,'dns_a',job,'--confirm')
            slot=journal/('slot-'+(journal/'current').read_text().strip())
            job=(slot/'manifest').read_text().splitlines()[6]
            call('archive-updated-receipt','ddns-collect-receipt',provider,'dns_a',job,'--confirm')
            call('explicit-revocation','grant-revoke','--confirm')
            call('revoked-sync-refused','ddns-sync','ddns_a',expected=4)
            assert len(fixture.mutations())==2
            token=call('regrant-preview','grant-preview','ddns_a')['confirmation']
            call('regrant-commit','grant-commit',token)
            call('cache-reset-before-unknown','ddns-reset','ddns_a','--confirm')
            fixture.db.clear()
            def unknown_hook(*argv):
                method=argv[0]
                mutating=(method!='GET') if provider in ['cloudflare','huaweicloud'] else method==('CreateRecord' if provider=='dnspod' else 'AddDomainRecord')
                if mutating:
                    fixture.seed()
                    return 500,{'success':False,'errors':[],'Code':'InternalError','code':'busy',
                                'Response':{'Error':{'Code':'InternalError','Message':'SECRET_SENTINEL'}}}
            fixture.hook=unknown_hook
            unknown=call('unknown-write-keeps-durable-fence','ddns-sync','ddns_a',expected=1)
            fixture.hook=None
            assert unknown['effect']=='unknown' and not unknown['retryable'] and unknown['reconciliation_required']
            count=len(fixture.calls);mutation_count=len(fixture.mutations())
            call('unknown-write-never-auto-retries','ddns-sync','ddns_a',expected=4)
            call('cache-reset-cannot-clear-durable-fence','ddns-reset','ddns_a','--confirm',expected=4)
            slot=journal/('slot-'+(journal/'current').read_text().strip())
            job=(slot/'manifest').read_text().splitlines()[6]
            call('unknown-cannot-be-archived-as-success','ddns-collect-receipt',provider,'dns_a',job,'--confirm',expected=4)
            assert len(fixture.calls)==count and len(fixture.mutations())==mutation_count
            observation=call('unknown-read-only-reconciliation','ddns-reconcile',provider,'dns_a',job,'--confirm')
            assert observation['effect']=='unknown' and journal.exists()
            count=len(fixture.calls)
            call('observed-record-does-not-clear-unknown','ddns-sync','ddns_a',expected=4)
            assert len(fixture.calls)==count and len(fixture.mutations())==mutation_count
            for name,raw in sentinels.items():assert (root/name).read_bytes()==raw,name
            for name,sha in business.items():assert digest(root/name)==sha,name
            assert source.stat().st_mode&0o777==0o600
            rows.append({'provider':provider,'checks':results,'checks_count':len(results),'mutations':len(fixture.mutations()),
                         'installed_business_bytes_unchanged':True,'production_sentinels_unchanged':True,'TLS_verified':True})
        finally:
            if mounted:subprocess.run(['umount',str(root/'proc')],check=True)
            if ready:fixture.tearDown()
    report={'version':identity()['normalized'],'scope':SCOPE,'business_subscope':'account-zone-delete' if args.contracts else 'finite-scheduled-ddns' if args.schedule else 'manual-ddns','providers':rows,
            'actual_IPK_payload':bool(args.installed_root),'real_DNS_used':False,'router_installed':False,
            'external_tools_are_disposable_fixtures':True,'tests':sum(r['checks_count'] for r in rows),'complete':len(rows)==(1 if args.provider else 4)}
    args.report.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report,ensure_ascii=False),flush=True)

if __name__=='__main__':main()
