#!/usr/bin/env python3
"""Real nixio session/exec and bounded Web transport; private temporary paths only."""
import argparse,json,os,signal,subprocess,tempfile,time
from pathlib import Path
from production_runtime import payload
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--nixio-dir',type=Path,required=True)
p.add_argument('--jsonc-dir',type=Path,required=True)
p.add_argument('--busybox',type=Path,required=True)
args=p.parse_args();files=payload(ROOT);results=[]
assert os.name=='posix' and os.getuid()!=0,'Use an unprivileged Linux test UID'
def check(name,condition):
 assert condition,name
 results.append(name);print('PASS',name,flush=True)
with tempfile.TemporaryDirectory(prefix='homegate-web-session-') as td:
 root=Path(td);core=root/'core';core.mkdir();tools=root/'tools';tools.mkdir()
 launcher=core/'native-web-session.lua'
 original=files['usr/libexec/homegate/native-web-session.lua'].decode()
 # Host-only UID/path substitutions; setsid, exec and process identities are real.
 raw=original.replace('nx.getuid()~=0','nx.getuid()~='+str(os.getuid()))
 probe=root/'probe.sh';probe.write_text('#!/bin/sh\nprintf "%s:%s:%s:%s:%s\\n" "$$" "$(ps -o pgid= -p $$ | tr -d \' \')" "$(ps -o sid= -p $$ | tr -d \' \')" "$1" "$2"\nexit 23\n')
 launcher.write_text(raw.replace("'/bin/ash'","'/bin/sh'").replace('/usr/libexec/homegate/native-web.sh',str(probe)))
 env={**os.environ,'LUA_CPATH':str(args.nixio_dir/'?.so')+';;'}
 def launch(argv,session=False,path=launcher):
  return subprocess.run(['lua5.1',str(path),*argv],env=env,start_new_session=session,capture_output=True,text=True,timeout=5)
 for action,value in [('read-owner',str(root/'request')),('owner','a'*32)]:
  r=launch([action,value]);v=r.stdout.strip().split(':',4)
  check(action+' keeps PID=PGID=SID and exit status',r.returncode==23 and len(v)==5 and v[0]==v[1]==v[2] and v[3:]==[action,value])
 for name,argv,session in [('group leader refuses',['owner','a'*32],True),('unknown action',['execute','a'*32],False),('invalid token',['owner','../unsafe'],False),('relative path',['read-owner','relative'],False),('control in path',['read-owner','/tmp/a\nb'],False),('extra argument',['owner','a'*32,'x'],False)]:
  r=launch(argv,session);check(name,r.returncode==126 and json.loads(r.stdout)['ok'] is False)
 missing=root/'missing.lua';missing.write_text("package.preload.nixio=function()return {}end\n"+raw)
 r=launch(['owner','a'*32],path=missing);check('missing capability refuses',r.returncode==126 and json.loads(r.stdout)['ok'] is False)
 broken=root/'broken.lua';broken.write_text(raw.replace('/bin/ash','/nonexistent/homegate-ash'))
 r=launch(['owner','a'*32],path=broken);check('exec failure refuses',r.returncode==126 and json.loads(r.stdout)['ok'] is False)
 for name in ['native-cli-core.sh','native-web.sh','native-public.lua','VERSION','RELEASE','project/core/prototype/worker-process.lua','project/luci/lua/luasrc/model/homegate/backup.lua']:
  dest=core/name;dest.parent.mkdir(parents=True,exist_ok=True)
  data=files['usr/libexec/homegate/'+name]
  if name.endswith('.sh'):data=data.replace(b'PATH=/usr/sbin:/usr/bin:/sbin:/bin',('PATH='+str(tools)).encode()).replace(b'/usr/libexec/homegate',str(core).encode())
  dest.write_bytes(data)
 launcher.write_text(raw.replace("'/bin/ash'",json.dumps(str(tools/'ash'))).replace('/usr/libexec/homegate/native-web.sh',str(core/'native-web.sh')))
 def tool(name,body):
  path=tools/name;path.write_text('#!/bin/sh\n'+body+'\n');path.chmod(0o755)
 for name in ['ash','sleep','kill']:tool(name,'exec '+str(args.busybox)+' '+name+' "$@"')
 tool('id','printf "0\\n"')
 preload=root/'preload.lua'
 preload.write_text('package.cpath='+json.dumps(str(args.nixio_dir/'?.so')+';'+str(args.jsonc_dir/'?.so')+';')+'..package.cpath\n'+"package.preload['nixio.fs']=function()return {lstat=function(p)local f=io.open(p,'rb');if not f then return nil end;local n=f:seek('end');f:close();return {type='reg',uid=0,nlink=1,size=n,modedec=644,dev=1,ino=1}end}end\n")
 tool('lua',"exec /usr/bin/lua5.1 -e 'dofile(\""+str(preload)+"\")' \"$@\"")
 public=root/'homegate';public.write_bytes(files['usr/bin/homegate'].replace(b'PATH=/usr/sbin:/usr/bin:/sbin:/bin',('PATH='+str(tools)).encode()).replace(b'/usr/libexec/homegate',str(core).encode()))
 request=root/'request';request.write_text('{"route":"overview","write":false,"form":{}}\n')
 def transport(body):
  (core/'native-web.lua').write_text(body)
  return subprocess.run([str(args.busybox),'ash',str(public),'web-read',str(request)],capture_output=True,text=True,timeout=25)
 r=transport("io.write('{\"api_version\":1,\"ok\":true,\"template\":\"homegate/overview\",\"data\":{}}\\n')")
 check('public read succeeds with no setsid executable',r.returncode==0 and json.loads(r.stdout)['ok'] is True and not (tools/'setsid').exists())
 r=transport("io.write('{\"api_version\":1,\"ok\":false,\"error\":\"controlled-refusal\"}\\n')")
 check('structured inner rejection survives framing',json.loads(r.stdout)['error']=='controlled-refusal')
 marker=root/'pids';body="local nx=require'nixio';local f=assert(io.open("+json.dumps(str(marker))+",'w'));f:write(nx.getpid());f:close();nx.nanosleep(30)"
 started=time.monotonic();r=transport(body);elapsed=time.monotonic()-started
 check('read deadline returns bounded failure',17<=elapsed<23 and r.returncode!=0 and json.loads(r.stdout)['ok'] is False)
 pid=int(marker.read_text());stat=Path('/proc')/str(pid)/'stat'
 check('deadline terminates the read process',not stat.exists() or stat.read_text().rsplit(')',1)[1].split()[0]=='Z')
print(json.dumps({'passed':len(results),'cases':results,'scope':'real host nixio process APIs; private paths/host UID and controlled page/fs metadata; no router acceptance'},indent=2))
