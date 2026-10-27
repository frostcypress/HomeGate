(function(){
'use strict';
var root=document.getElementById('homegate-engineering-config');if(!root)return;
var pending='',finish='',busy=false;
function el(id){return document.getElementById(id);}
function show(value){el('hg-config-result').textContent=JSON.stringify(value,null,2);}
function buttons(){el('hg-config-apply').disabled=busy||!pending;el('hg-config-finish').disabled=busy||!finish;}
function request(action,form,done){
 if(busy)return;busy=true;buttons();
 var xhr=new XMLHttpRequest(),write=action!=='read'&&action!=='schedule_status',body=[],fields=form||{};
 xhr.open(write?'POST':'GET',root.getAttribute('data-endpoint')+'/'+action,true);xhr.timeout=30000;
 if(write){body.push('token='+encodeURIComponent(root.getAttribute('data-token')));Object.keys(fields).forEach(function(k){body.push(encodeURIComponent(k)+'='+encodeURIComponent(fields[k]));});xhr.setRequestHeader('Content-Type','application/x-www-form-urlencoded');}
 function end(){busy=false;buttons();}
 xhr.onload=function(){end();try{
  if(xhr.responseText.length>524288)throw new Error();var d=JSON.parse(xhr.responseText);show(d);
  if(d.report&&d.report.confirmation&&d.ok)pending=d.report.confirmation;
  if(d.report&&d.report.application_pending&&d.report.apply_handle)finish=d.report.apply_handle;
  if(d.ok&&action==='apply'){pending='';finish='';}
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
function refresh(){request('read',{},function(d){table('hg-config-accounts',d.accounts||[],el('hg-config-account'),['id','name','provider']);table('hg-config-rules',d.rules||[],el('hg-config-rule'),['id','account','zone','host','source','interface']);});}
function bind(formId,action,names){var form=el(formId);form.onsubmit=function(e){e.preventDefault();var fields={};names.forEach(function(k){fields[k]=form.elements[k].value;});
 if(action==='secret_put'){fields.consent='1';form.elements.value.value='';}
 request(action,fields);
};}
bind('hg-config-account','preview_account',['id','name','provider']);bind('hg-config-rule','preview_rule',['id','account','zone','host','source','interface']);bind('hg-config-secret','secret_put',['id','provider','slot','value']);
el('hg-delete-rule').onsubmit=function(e){e.preventDefault();var form=e.target;
 if(!form.elements.confirm_all.checked||!window.confirm('删除该规则受管主机的全部 AAAA 记录？其他主机和 TXT 不受影响。'))return;
 request('delete_rule',{id:form.elements.id.value,consent:'1'});
};
el('hg-config-refresh').onclick=refresh;el('hg-config-prepare').onclick=function(){request('prepare',{},refresh);};
el('hg-config-activate').onclick=function(){request('activate_preview');};
el('hg-config-apply').onclick=function(){request('apply',{confirmation:pending,consent:'1'},refresh);};
el('hg-config-finish').onclick=function(){request('finish',{confirmation:finish,consent:'1'},refresh);};
el('hg-config-cancel').onclick=function(){request('cancel');};refresh();
['start','status','stop','reap'].forEach(function(op){el('hg-schedule-'+op).onclick=function(){request('schedule_'+op,op==='status'?{}:{consent:'1'});};});
}());
