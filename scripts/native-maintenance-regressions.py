#!/usr/bin/env python3
"""Exercise real Web owner/session/locks against private host paths, no router."""
import argparse,fcntl,json,os,subprocess,tempfile,time
from pathlib import Path
from production_runtime import payload
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--nixio-dir',type=Path,required=True);p.add_argument('--jsonc-dir',type=Path,required=True);p.add_argument('--busybox',type=Path,required=True)
a=p.parse_args();uid=os.getuid();assert uid!=0
files=payload(ROOT);results=[]
with tempfile.TemporaryDirectory(prefix='homegate-maintenance-') as td:
 root=Path(td);core=root/'core';tools=root/'tools';tools.mkdir();core.mkdir();jobs=root/'jobs';run=root/'run';marker=root/'executed';barrier=root/'package-state'
 cp=str(a.nixio_dir/'?.so')+';'+str(a.jsonc_dir/'?.so')+';;';lp=str(a.nixio_dir/'?.lua')+';;'
 env={**os.environ,'LUA_CPATH':cp,'LUA_PATH':lp,'LD_LIBRARY_PATH':str(a.nixio_dir.parent)+':'+os.environ.get('LD_LIBRARY_PATH','')}
 def tool(name,body,python=False):
  dest=tools/name;dest.write_text(('#!/usr/bin/python3\n' if python else '#!/bin/sh\n')+body+'\n');dest.chmod(0o755)
 for name in ['ash','sleep','kill']:tool(name,'exec '+str(a.busybox)+' '+name+' "$@"')
 tool('lua','exec env LUA_CPATH='+repr(cp)+' LUA_PATH='+repr(lp)+' /usr/bin/lua5.1 "$@"')
 tool('fsync','import os,sys\nfor p in sys.argv[1:]:\n f=os.open(p,os.O_RDONLY);os.fsync(f);os.close(f)',True)
 names=['native-web.sh','native-web-session.lua','native-web-store.lua','strict-web-json.lua','legacy-routes.json','project/luci/lua/luasrc/model/homegate/backup.lua','project/core/prototype/worker-process.lua']
 for name in names:
  raw=files['usr/libexec/homegate/'+name].decode()
  for src,dest in [('/usr/libexec/homegate',str(core)),('/tmp/homegate-frontend-jobs',str(jobs)),('/var/run/homegate',str(run)),('/etc/homegate/package-state',str(barrier)),('/etc/.homegate-transition/hold',str(root/'hold'))]:raw=raw.replace(src,dest)
  raw=raw.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin','PATH='+str(tools)+':/usr/bin:/bin').replace('"$(id -u)" = 0','"$(id -u)" = '+str(uid)).replace('0:700',str(uid)+':700').replace('0:600:1',str(uid)+':600:1').replace('uid==0','uid=='+str(uid)).replace('uid~=0','uid~='+str(uid)).replace('nx.getuid()~=0','nx.getuid()~='+str(uid)).replace("'/bin/ash'",repr(str(tools/'ash')))
  dest=core/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(raw)
 # Only the operation body is a fixture; admission, session, process identity,
 # owner deadline, runtime directory, FD locks and result publication are real.
 (core/'native-web.lua').write_text('local f=assert(io.open('+json.dumps(str(marker))+',"a"));f:write("executed\\n");f:close();io.write(\'{"api_version":1,"ok":true,"body":"download fixture"}\\n\')\n')
 request=root/'request';request.write_text('{"route":"config_export","write":true,"form":{}}\n');request.chmod(0o600)
 def command(action,value):
  return subprocess.run([str(a.busybox),'ash',str(core/'native-web.sh'),action,str(value)],env=env,capture_output=True,text=True,timeout=8)
 def submit():
  r=command('submit',request);assert r.returncode==0,(r.stdout,r.stderr);return json.loads(r.stdout)['job']
 def finish(token):
  end=time.monotonic()+7
  while time.monotonic()<end:
   r=command('status',token);assert r.returncode==0,r.stdout;d=json.loads(r.stdout)
   if not d['pending']:
    result=d['result'];ack=command('ack',token);assert ack.returncode==0;return result
   time.sleep(.03)
  raise AssertionError('owner did not return')
 def check(name,value):assert value,name;results.append(name);print('PASS',name,flush=True)
 # Prove the old code's missing-directory condition under the same real owner.
 script=core/'native-web.sh';fixed=script.read_text();old=fixed.replace('  if [ ! -e "$run" ] && [ ! -L "$run" ];then mkdir "$run" || dir "$run" || fail;fi\n','');assert old!=fixed
 script.write_text(old);r=finish(submit());check('old owner reproduces no runtime directory refusal',not r['ok'] and r['started'] is False and not marker.exists());script.write_text(fixed)
 r=finish(submit());check('inactive fresh runtime succeeds without service initialization',r['ok'] and run.is_dir() and (run.stat().st_mode&0o777)==0o700 and marker.read_text().count('executed')==1)
 r=finish(submit());check('existing safe runtime reuses lock and executes once',r['ok'] and marker.read_text().count('executed')==2)
 run.chmod(0o755);r=finish(submit());check('unsafe runtime refuses without chmod or operation',not r['ok'] and r['error_code']=='runtime-directory' and (run.stat().st_mode&0o777)==0o755 and marker.read_text().count('executed')==2);run.chmod(0o700)
 moved=root/'preserved-run';run.rename(moved);run.symlink_to(moved,target_is_directory=True);r=finish(submit());check('runtime symlink refuses without following it',not r['ok'] and r['error_code']=='runtime-directory' and marker.read_text().count('executed')==2);run.unlink();moved.rename(run)
 lock=run/'frontend-web.lock';fd=lock.open('a');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);token=submit();time.sleep(.2);r=json.loads(command('status',token).stdout);check('busy lock never runs concurrently',r['pending'] and marker.read_text().count('executed')==2);fd.close();r=finish(token);check('waiting owner executes once after lock release',r['ok'] and marker.read_text().count('executed')==3)
 check('terminal acknowledgement leaves no jobs',not any(p.is_dir() for p in jobs.iterdir()))
print(json.dumps({'passed':len(results),'cases':results,'scope':'Unprivileged real nixio/fs/setsid, BusyBox ash and flock; UID/fixed paths and operation body are fixtures. No target acceptance.'},indent=2))
