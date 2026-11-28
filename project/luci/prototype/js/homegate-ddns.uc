'use strict';
import { mkdir, open, unlink, rmdir, popen } from 'fs';
// Candidate only. HTTP transport must enforce rpcd session ACL before dispatch; local ubus does not. Not installed.
const native_ddns_rpc_enabled = false;
function denied(action) { return {api_version:1,prototype:true,ok:false,phase:'ddns-ui',effect:action=='submit'?'unknown':'none',write_ready:false,error:'DDNS UI request refused'}; }
function execute(action,args) {
 if (!native_ddns_rpc_enabled) return denied(action);
 let body;
 if (action == 'maintain_preview' && type(args.job)=='string' && match(args.job,/^[0-9a-f]{32}$/)) body=sprintf('{"action":"maintain_preview","job":%J}\n',args.job);
 else if (action == 'maintain_commit' && type(args.job)=='string' && match(args.job,/^[0-9a-f]{32}$/) && type(args.confirmation)=='string' && match(args.confirmation,/^[0-9a-f]{32}$/) && type(args.consent)=='string' && args.consent=='1') body=sprintf('{"action":"maintain_commit","job":%J,"confirmation":%J,"consent":"1"}\n',args.job,args.confirmation);
 else if (action == 'jobs') body='{"action":"jobs"}\n';
 else if (action == 'submit' && type(args.job)=='string' && match(args.job,/^[0-9a-f]{32}$/) && type(args.rule)=='string' && length(args.rule)<=64 && match(args.rule,/^[a-zA-Z0-9_\-]+$/) && type(args.consent)=='string' && args.consent=='1') body=sprintf('{"action":"submit","job":%J,"rule":%J,"consent":"1"}\n',args.job,args.rule);
 else if (action == 'status') body='{"action":"status"}\n';
 else if (action == 'preview' && type(args.selection)=='string' && length(args.selection)<=2079 && match(args.selection,/^[a-zA-Z0-9_,\-]+$/)) body=sprintf('{"action":"preview","selection":%J}\n',args.selection);
 else if (action == 'commit' && type(args.confirmation)=='string' && match(args.confirmation,/^[0-9a-f]{32}$/) && type(args.consent)=='string' && args.consent=='1') body=sprintf('{"action":"commit","confirmation":%J,"consent":"1"}\n',args.confirmation);
 else if (action == 'revoke' && type(args.consent)=='string' && args.consent=='1') body='{"action":"revoke","consent":"1"}\n';
 else return denied(action);
 const uuid=open('/proc/sys/kernel/random/uuid','r');if(!uuid)return denied(action);
 const value=uuid.read(38);uuid.close();
 const m=match(value || '',/^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\n$/);if(!m)return denied(action);
 const dir='/tmp/homegate-ddns-ui-'+m[1]+m[2]+m[3]+m[4]+m[5],path=dir+'/request';
 if(!mkdir(dir,0700))return denied(action);
 let fd,result;
 try {
  fd=open(path,'wx',0600);if(!fd)die('request');
  const n=fd.write(body),closed=fd.close();fd=null;if(n!=length(body)||!closed)die('request');
  fd=popen("/usr/libexec/homegate/ddns-ui '"+path+"' 2>/dev/null");if(!fd)die('response');
  const out=fd.read(65537);fd.close();fd=null;if(type(out)!='string'||length(out)>65536)die('response');
  result=json(out);
  const allowed={api_version:true,prototype:true,ok:true,phase:true,operation:true,effect:true,write_ready:true,report:true};
  if(type(result)!='object'||length(keys(result))!=8)die('response');
  for(let k in result)if(!allowed[k])die('response');
  if(result.api_version!=1||result.prototype!=true||result.ok!=true||result.phase!='ddns-ui'||result.operation!=action||result.effect!=(action=='submit'?'unknown':'none')||result.write_ready!=false||type(result.report)!='object')die('response');
 }
 catch(e){result=denied(action);}
 if(fd)fd.close();unlink(path);rmdir(dir);return result;
}
return {homegate_ddns:{
 maintain_preview:{args:{job:''},call:request=>execute('maintain_preview',request.args)},
 maintain_commit:{args:{job:'',confirmation:'',consent:''},call:request=>execute('maintain_commit',request.args)},
 jobs:{args:{},call:request=>execute('jobs',request.args)},
 submit:{args:{job:'',rule:'',consent:''},call:request=>execute('submit',request.args)},
 status:{args:{},call:request=>execute('status',request.args)},
 preview:{args:{selection:''},call:request=>execute('preview',request.args)},
 commit:{args:{confirmation:'',consent:''},call:request=>execute('commit',request.args)},
 revoke:{args:{consent:''},call:request=>execute('revoke',request.args)}
}};
