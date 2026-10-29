(function(){
'use strict';
var root=document.getElementById('homegate-engineering-config');if(!root)return;
var pending='',pendingAction='apply',finish='',busy=false;
function el(id){return document.getElementById(id);}
function show(value){el('hg-config-result').textContent=JSON.stringify(value,null,2);}
function buttons(){el('hg-config-apply').textContent=pendingAction==='production_copy_commit'?'确认复制生产配置':'确认应用配置';el('hg-config-apply').disabled=busy||!pending;el('hg-config-finish').disabled=busy||!finish;}
function request(action,form,done){
 if(busy)return;busy=true;buttons();
 var xhr=new XMLHttpRequest(),write=action!=='read'&&action!=='schedule_status'&&action!=='lifecycle_status'&&action!=='cert_status'&&action!=='acme_status'&&action!=='acme_schedule_status'&&action!=='proxy_status'&&action!=='access_status'&&action!=='access_recent',body=[],fields=form||{};
 var url=root.getAttribute('data-endpoint')+'/'+action;if(!write){var query=[];Object.keys(fields).forEach(function(k){query.push(encodeURIComponent(k)+'='+encodeURIComponent(fields[k]));});if(query.length)url+='?'+query.join('&');}
 xhr.open(write?'POST':'GET',url,true);xhr.timeout=30000;
 if(write){body.push('token='+encodeURIComponent(root.getAttribute('data-token')));Object.keys(fields).forEach(function(k){body.push(encodeURIComponent(k)+'='+encodeURIComponent(fields[k]));});xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');}
 function end(){busy=false;buttons();}
 xhr.onload=function(){end();try{
  if(xhr.responseText.length>524288)throw new Error();var d=JSON.parse(xhr.responseText);show(d);
  if(d.report&&d.report.confirmation&&d.ok){pending=d.report.confirmation;pendingAction=d.report.operation==='production-copy'?'production_copy_commit':'apply';}
  if(d.report&&d.report.application_pending&&d.report.apply_handle)finish=d.report.apply_handle;
  if(d.ok&&(action==='apply'||action==='production_copy_commit')){pending='';finish='';}
  if(d.ok&&action==='finish')finish='';
  if(d.ok&&action==='cancel')pending='';
  buttons();if(d.ok&&done)done(d);
 }catch(e){show({ok:false,error:'响应不可用，请刷新状态；不要重复提交写入任务。'});}};
 xhr.onerror=xhr.ontimeout=function(){end();show({ok:false,error:'请求未完成，请刷新检查已保留状态。'});};
 xhr.send(write?body.join('&'):null);
}
function table(target,rows,form,columns){
 var mount=el(target);while(mount.firstChild)mount.removeChild(mount.firstChild);
 var t=document.createElement('table');t.className='table';
 rows.forEach(function(row){var tr=document.createElement('tr');columns.forEach(function(k){var td=document.createElement('td');td.textContent=row[k]||'';tr.appendChild(td);});
  var td=document.createElement('td'),b=document.createElement('button');b.type='button';b.className='cbi-button';b.textContent='编辑';b.onclick=function(){columns.forEach(function(k){if(form.elements[k])form.elements[k].value=row[k]||'';});};td.appendChild(b);if(target==='hg-config-accounts'){
   [['provider_status','校验凭据'],['zones','发现区域']].forEach(function(op){var c=document.createElement('button');c.type='button';c.className='cbi-button';c.textContent=op[1];c.onclick=function(){request(op[0],{id:row.id});};td.appendChild(c);});
  }tr.appendChild(td);t.appendChild(tr);
 });mount.appendChild(t);
}
function refresh(){request('read',{},function(d){table('hg-config-accounts',d.accounts||[],el('hg-config-account'),['id','name','provider']);table('hg-config-rules',d.rules||[],el('hg-config-rule'),['id','account','zone','host','source','interface']);if(d.access){['allow','deny','region'].forEach(function(k){el('hg-access-policy').elements[k].value=d.access[k]||'';});}});}
function bind(formId,action,names){var form=el(formId);form.onsubmit=function(e){e.preventDefault();var fields={};names.forEach(function(k){fields[k]=form.elements[k].value;});
 if((action==='secret_put'||action==='web_target_put')){fields.consent='1';form.elements.value.value='';}
 request(action,fields);
};}
bind('hg-access-policy','preview_access',['allow','deny','region']);
['update','refresh','status','recent','clear','clear_denied','stop','reap'].forEach(function(op){el('hg-access-'+op).onclick=function(){var fields={};if(['status','recent'].indexOf(op)<0){if(!window.confirm(op==='clear'||op==='clear_denied'?'清理本插件最近访问观察？这不会改变访问规则。':op==='stop'?'停止本次地址库下载？保留原有效库。':'执行本次 CN 地址库操作？已有代理继续使用其启动时快照。'))return;fields.consent='1';}request('access_'+op,fields,function(d){if(op==='recent'){var mount=el('hg-access-recent');while(mount.firstChild)mount.removeChild(mount.firstChild);var t=document.createElement('table');t.className='table';(d.report.entries||[]).forEach(function(row){var tr=document.createElement('tr');[row.ip,row.host,row.allowed?'允许':'拒绝',row.reason,row.count,row.time].forEach(function(v){var td=document.createElement('td');td.textContent=String(v);tr.appendChild(td);});t.appendChild(tr);});mount.appendChild(t);}});};});
bind('hg-web-rule','preview_web_rule',['id','domain','https','certificate']);
bind('hg-web-target','web_target_put',['id','value']);
['start','status','stop','reap'].forEach(function(op){el('hg-proxy-'+op).onclick=function(){var fields={};if(op==='start'){fields.selection=el('hg-proxy-run').elements.selection.value;fields.policy=el('hg-proxy-run').elements.policy.value;}if(op!=='status'){if(!window.confirm(op==='start'?'启动所选规则的工程代理？这会监听工程端口；当前不自动配置防火墙。':op==='stop'?'停止工程代理？现有连接将断开。':'收起已停止代理会话？'))return;fields.consent='1';}request('proxy_'+op,fields);};});
bind('hg-acme-certificate','preview_acme_certificate',['id','name','account','zone','domains','email','environment']);
bind('hg-local-certificate','preview_local_certificate',['id','name','domains']);
bind('hg-config-account','preview_account',['id','name','provider']);bind('hg-config-rule','preview_rule',['id','account','zone','host','source','interface']);bind('hg-config-secret','secret_put',['id','provider','slot','value']);
['start','status','stop','reap'].forEach(function(op){el('hg-acme-schedule-'+op).onclick=function(){var fields={};if(op==='start')fields.id=el('hg-acme-task').elements.id.value;if(op!=='status'){if(!window.confirm(op==='start'?'启动此证书的定时续签会话？每小时检查；退出页面后继续，重启后需重新明确启动。':op==='stop'?'停止定时续签及本会话已接纳的任务？':'收起已结束会话？未决挑战仍须先明确处理。'))return;fields.consent='1';}request('acme_schedule_'+op,fields);};});
['issue','renew','status','stop','cleanup'].forEach(function(op){el('hg-acme-'+op).onclick=function(){var form=el('hg-acme-task'),fields={};
 if(op==='issue'||op==='renew'){
  if(!window.crypto||!window.crypto.getRandomValues){show({ok:false,error:'浏览器缺少安全任务标识支持。'});return;}
  var bytes=new Uint8Array(16);window.crypto.getRandomValues(bytes);var job='';for(var i=0;i<bytes.length;i++)job+=('0'+bytes[i].toString(16)).slice(-2);
  form.elements.job.value=job;fields.id=form.elements.id.value;
 }
 fields.job=form.elements.job.value;if(op!=='status')fields.consent='1';
 if((op==='stop'||op==='cleanup')&&!window.confirm(op==='stop'?'停止本次签发？未决 TXT 会保留供明确核对。':'仅清理本任务已确认拥有的挑战 TXT？未知写入将拒绝清理。'))return;
 request('acme_'+op,fields);
};});
el('hg-certificate-import').onsubmit=function(e){e.preventDefault();var form=e.target;
 var fields={id:form.elements.id.value,certificate_pem:form.elements.certificate_pem.value,private_key_pem:form.elements.private_key_pem.value,consent:'1'};
 form.elements.private_key_pem.value='';request('cert_import',fields);
};
['status','resume','cancel'].forEach(function(op){el('hg-certificate-'+op).onclick=function(){var fields={id:el('hg-certificate-import').elements.id.value};if(op!=='status')fields.consent='1';request('cert_'+op,fields);};});
el('hg-delete-rule').onsubmit=function(e){e.preventDefault();var form=e.target;
 if(!form.elements.confirm_all.checked||!window.confirm('删除该规则受管主机的全部 AAAA 记录？其他主机和 TXT 不受影响。'))return;
 request('delete_rule',{id:form.elements.id.value,consent:'1'});
};
el('hg-config-refresh').onclick=refresh;el('hg-config-prepare').onclick=function(){request('prepare',{},refresh);};
el('hg-config-recover').onclick=function(){if(window.confirm('恢复上一次未完成应用之前的工程配置？已保留的 DNS 恢复记录不会被清除。'))request('recover',{consent:'1'},refresh);};
el('hg-production-copy-preview').onclick=function(){request('production_copy_preview');};
el('hg-config-activate').onclick=function(){request('activate_preview');};
el('hg-config-apply').onclick=function(){request(pendingAction,{confirmation:pending,consent:'1'},refresh);};
el('hg-config-finish').onclick=function(){request('finish',{confirmation:finish,consent:'1'},refresh);};
el('hg-config-cancel').onclick=function(){request('cancel');};refresh();
['enable','disable','status'].forEach(function(op){el('hg-lifecycle-'+op).onclick=function(){request('lifecycle_'+op,op==='status'?{}:{consent:'1'});};});
['serve','start','status','stop','reap'].forEach(function(op){el('hg-schedule-'+op).onclick=function(){request('schedule_'+op,op==='status'?{}:{consent:'1'});};});
}());
