/* Shared native DOM for both LuCI candidates. No inline server values or HTML. */
(function(global){
'use strict';
var statuses={ready:'可运行',stale:'状态已过期',waiting:'等待间隔',retry_wait:'退避等待',paused:'已暂停',blocked:'恢复屏障阻止',reconciliation_required:'需要核实',unauthorized:'未获授权',clock_invalid:'时钟异常'};
function id(v){return typeof v==='string'&&/^[a-zA-Z0-9_-]{1,64}$/.test(v);}
function names(r){return r.rules||(r.rule?[r.rule]:[]);}
function mount(root,request){
 var busy=false,epoch=0,staged=null,chosen={},rows=[],jobBusy=false,jobsKnown=false,jobs=[],ticket=null,uncertain=false,polls=0,timer=null,mstaged=null,maintenanceButtons=[];
 function node(tag,text,cls){var e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e;}
 function button(text,fn){var e=node('button',text,'cbi-button');e.type='button';e.onclick=fn;return e;}
 root.replaceChildren();root.className='cbi-section';
 root.appendChild(node('h3','DDNS 运行授权'));
 root.appendChild(node('p','选择已保存的规则，先预览，再明确确认授权。授权不会立即更新 DNS 或启动服务。'));
 var notice=node('p','正在读取状态…');notice.setAttribute('role','status');root.appendChild(notice);
 var table=node('table',undefined,'table cbi-section-table'),head=node('thead'),title=node('tr',undefined,'tr cbi-section-table-titles');
 ['选择','规则','供应商','状态','等待秒数'].forEach(function(t){title.appendChild(node('th',t,'th'));});head.appendChild(title);table.appendChild(head);
 var body=node('tbody');table.appendChild(body);var wrap=node('div');wrap.style.overflowX='auto';wrap.appendChild(table);root.appendChild(wrap);
 var actions=node('div',undefined,'cbi-page-actions');root.appendChild(actions);
 var refresh=button('刷新状态',function(){read();}),preview=button('预览授权',function(){prepare();}),revoke=button('撤销当前授权',function(){
  if(busy||!global.confirm('撤销当前全部 DDNS 规则授权？已开始的操作仍需等待结束。'))return;
  invalidate();perform('revoke',{consent:'1'},function(d){if(d.report.authorized!==false||d.report.revoked!==true)throw new Error();notice.textContent='已撤销授权，请刷新状态。';});
 });actions.appendChild(refresh);actions.appendChild(preview);actions.appendChild(revoke);
 var run=button('同步所选规则一次',submit);actions.appendChild(run);
 var jobNotice=node('p','正在读取保留任务…');jobNotice.setAttribute('role','status');root.appendChild(jobNotice);
 var jobList=node('ul');jobList.setAttribute('aria-label','保留的 DDNS 任务');root.appendChild(jobList);
 root.appendChild(node('p','每次仅同步一条规则，最多保留 8 份内存任务。不会自动重发、清理或收尾；重启后任务摘要丢失，原持久回执仍需明确处理。'));
 var pane=node('div');pane.hidden=true;pane.setAttribute('aria-live','polite');root.appendChild(pane);
 var scope=node('p'),consent=node('input');consent.type='checkbox';consent.id='hg-ddns-consent';
 var label=node('label','我确认允许这些规则执行 DDNS');label.htmlFor=consent.id;
 var commit=button('确认授权',function(){
  if(busy||!staged||!consent.checked)return;
  var nonce=staged.confirmation,expected=names(staged);invalidate();perform('commit',{confirmation:nonce,consent:'1'},function(d){if(d.report.authorized!==true||d.report.service_started!==false||JSON.stringify(names(d.report))!==JSON.stringify(expected))throw new Error();notice.textContent='授权已保存，未启动服务。请刷新状态。';});
 }),close=button('关闭预览',function(){invalidate();});
 pane.appendChild(scope);pane.appendChild(consent);pane.appendChild(label);pane.appendChild(commit);pane.appendChild(close);
 var mpane=node('div');mpane.hidden=true;mpane.setAttribute('aria-live','polite');root.appendChild(mpane);
 var mscope=node('p'),mconsent=node('input');mconsent.type='checkbox';mconsent.id='hg-ddns-maintain-consent';
 var mlabel=node('label','我确认只维护本次预览的任务');mlabel.htmlFor=mconsent.id;
 var mcommit=button('确认此次维护',function(){
  if(busy||!mstaged||!mconsent.checked)return;var intent=mstaged;invalidate();perform('maintain_commit',{job:intent.job,confirmation:intent.confirmation,consent:'1'},function(d){
   var r=d.report;if(!exact(r,['api_version','prototype','ok','phase','job','rule','operation','completed','effect','write_ready'])||r.phase!=='ddns-maintenance'||r.job!==intent.job||r.rule!==intent.rule||r.operation!==intent.operation||r.completed!==true||r.effect!=='none'||r.write_ready!==false)throw new Error();
   notice.textContent='此次维护已完成；未提交新的 DNS 操作。请刷新规则状态。';loadJobs();
  });
 });mpane.appendChild(mscope);mpane.appendChild(mconsent);mpane.appendChild(mlabel);mpane.appendChild(mcommit);mpane.appendChild(button('关闭维护预览',invalidate));mconsent.onchange=controls;
 function selected(){return Object.keys(chosen).filter(function(k){return chosen[k];}).sort();}
 function controls(){refresh.disabled=busy;preview.disabled=busy||selected().length===0;revoke.disabled=busy;commit.disabled=busy||!staged||!consent.checked;mcommit.disabled=busy||!mstaged||!mconsent.checked;maintenanceButtons.forEach(function(b){b.disabled=busy||jobBusy||uncertain;});run.disabled=busy||jobBusy||!jobsKnown||uncertain||selected().length!==1||jobs.length>=8||jobs.some(function(j){return j.pending||j.state==='interrupted'||j.last_effect==='unknown';});}
 function invalidate(){epoch++;staged=null;consent.checked=false;pane.hidden=true;mstaged=null;mconsent.checked=false;mpane.hidden=true;controls();}
 consent.onchange=controls;
 function valid(d,action){return d&&d.api_version===1&&d.prototype===true&&d.ok===true&&d.phase==='ddns-ui'&&d.operation===action&&d.effect===(action==='submit'?'unknown':'none')&&d.write_ready===false&&d.report&&d.report.ok===true;}
 function exact(d,fields){return d&&typeof d==='object'&&Object.keys(d).length===fields.length&&fields.every(function(k){return Object.prototype.hasOwnProperty.call(d,k);});}
 function jobValid(j){
  if(!exact(j,['api_version','prototype','ok','phase','job','rule','configuration_revision','pending','state','result','last_effect','reason','effect','write_ready'])||j.api_version!==1||j.prototype!==true||j.ok!==true||j.phase!=='ddns-job'||!/^[0-9a-f]{32}$/.test(j.job)||!id(j.rule)||!Number.isInteger(j.configuration_revision)||j.configuration_revision<1||j.configuration_revision>32||j.effect!=='none'||j.write_ready!==false)return false;
  if(j.state==='pending'||j.state==='interrupted')return j.pending===(j.state==='pending')&&j.result===false&&j.last_effect==='unknown'&&j.reason===(j.pending?'accepted':'interrupted');
  var r=j.result;if(j.state!=='finished'||j.pending!==false||!exact(r,['rule','provider','status','effect','error_kind','retryable','retry_in'])||r.rule!==j.rule||!['cloudflare','aliyun','dnspod','huaweicloud'].includes(r.provider)||!['none','confirmed','unknown'].includes(r.effect)||r.effect!==j.last_effect||!Number.isInteger(r.retry_in)||r.retry_in<0||r.retry_in>999999999||typeof r.retryable!=='boolean'||!['','authentication','not_found','unsupported','invalid_request','invalid_zone','temporary','network_unavailable','timeout','rate_limit','invalid_configuration'].includes(r.error_kind))return false;
  if(!Object.prototype.hasOwnProperty.call(statuses,r.status)&&!['created','updated','unchanged','failed'].includes(r.status))return false;
  if(['created','updated'].includes(r.status)&&(r.effect!=='confirmed'||r.error_kind!==''||r.retryable))return false;
  if(r.status==='unchanged'&&(r.effect!=='none'||r.error_kind!==''||r.retryable))return false;
  if(r.status==='failed'&&!['none','unknown'].includes(r.effect))return false;
  if(!['created','updated','unchanged','failed'].includes(r.status)&&r.effect!=='none')return false;
  return (j.reason==='archived'&&r.effect==='confirmed')||(j.reason==='compacted'&&r.effect==='none')||j.reason==='completed'||(j.reason==='changed'&&r.effect==='none')||(j.reason==='unavailable'&&r.effect==='unknown');
 }
 function drawJobs(){
  jobList.replaceChildren();maintenanceButtons=[];jobs.forEach(function(j){var text=j.pending?'等待或执行中':j.state==='interrupted'?'任务中断，结果未知':j.last_effect==='unknown'?'结果未知，保留证据，请核实':j.reason==='archived'?'回执已归档，保留原摘要':j.reason==='compacted'?'明细已释放，保留任务标识':({created:'已创建；需明确收尾',updated:'已更新；需明确收尾',unchanged:'记录未变',failed:'执行失败'}[j.result.status]||statuses[j.result.status]);var item=node('li',j.rule+' · '+text+' · '+j.job);jobList.appendChild(item);
   if(j.state==='finished'&&j.last_effect!=='unknown'&&!['archived','compacted'].includes(j.reason)){var b=button('预览维护 '+j.rule,function(){maintain(j);});maintenanceButtons.push(b);item.appendChild(b);}
  });
  jobNotice.textContent=uncertain?'提交结果未确认，只读取保留任务；请勿重发。':jobs.length>=8?'已保留 8 份任务；需要后续明确维护。':jobs.some(function(j){return j.pending;})?'任务尚未完成，正在读取结果。':jobs.length?'保留任务已读取；未知或中断结果需要核实。':'当前没有保留任务。';
 }
 function maintain(job){
  if(busy||jobBusy||uncertain)return;invalidate();perform('maintain_preview',{job:job.job},function(d){
   var r=d.report,operation=job.last_effect==='confirmed'?'archive':'compact';
   if(!exact(r,['api_version','prototype','ok','phase','job','rule','operation','confirmation','expires_in','effect','write_ready'])||r.phase!=='ddns-maintenance'||r.job!==job.job||r.rule!==job.rule||r.operation!==operation||!/^[0-9a-f]{32}$/.test(r.confirmation)||r.expires_in!==300||r.effect!=='none'||r.write_ready!==false)throw new Error();
   mstaged=r;mscope.textContent=(operation==='archive'?'仅归档此任务的已确认原回执，不删除归档。':'仅释放此任务的已知未写入原始明细。')+'任务标识保留用于防重放，占用本次启动的 8 个标识预算；预览有效 300 秒。';mpane.hidden=false;notice.textContent='维护预览尚未执行，请核对后勾选确认。';
  });
 }
 function loadJobs(){
  if(jobBusy)return;if(timer){global.clearTimeout(timer);timer=null;}jobBusy=true;controls();
  Promise.resolve().then(function(){return request('jobs',{});}).then(function(d){
   var r=d&&d.report;if(!valid(d,'jobs')||!exact(r,['api_version','prototype','ok','phase','jobs','effect','write_ready'])||r.api_version!==1||r.prototype!==true||r.ok!==true||r.phase!=='ddns-jobs'||r.effect!=='none'||r.write_ready!==false||!Array.isArray(r.jobs)||r.jobs.length>8)throw new Error();
   var previous='';r.jobs.forEach(function(j){if(!jobValid(j)||previous>=j.job)throw new Error();previous=j.job;});jobs=r.jobs;jobsKnown=true;
   if(ticket&&jobs.some(function(j){return j.job===ticket;})){uncertain=false;ticket=null;}drawJobs();
   if(jobs.some(function(j){return j.pending;})){if(polls<180){polls++;timer=global.setTimeout(loadJobs,1000);}else jobNotice.textContent='轮询已暂停；任务未被重发，请手动刷新读取。';}
  }).catch(function(){jobsKnown=false;jobNotice.textContent='任务读取未确认，请刷新读取；不要重复提交。';}).finally(function(){jobBusy=false;controls();});
 }
 function submit(){
  if(run.disabled||!global.confirm('现在仅同步所选的一条 DDNS 规则？这可能修改 DNS，成功回执仍需另行明确收尾。'))return;
  var list=selected(),bytes=new Uint8Array(16);if(!global.crypto||!global.crypto.getRandomValues){jobNotice.textContent='安全任务标识不可用，未提交。';return;}global.crypto.getRandomValues(bytes);ticket=Array.from(bytes,function(v){return v.toString(16).padStart(2,'0');}).join('');
  var sent=ticket;uncertain=true;jobBusy=true;invalidate();controls();
  Promise.resolve().then(function(){return request('submit',{job:sent,rule:list[0],consent:'1'});}).then(function(d){if(!valid(d,'submit')||!jobValid(d.report)||d.report.job!==sent||d.report.rule!==list[0])throw new Error();}).catch(function(){jobNotice.textContent='提交结果未确认，只读取保留任务；请勿重发。';}).finally(function(){jobBusy=false;polls=0;loadJobs();});
 }
 function perform(action,form,accept){
  if(busy)return;busy=true;controls();var sequence=epoch;
  Promise.resolve().then(function(){return request(action,form);}).then(function(d){
   if(sequence!==epoch)return;if(!valid(d,action))throw new Error();accept(d);
  }).catch(function(){if(sequence===epoch){invalidate();notice.textContent='请求未确认，请先刷新状态。请勿自动重复提交。';}}).finally(function(){busy=false;controls();});
 }
 function read(){
  if(busy)return;polls=0;loadJobs();invalidate();perform('status',{},function(d){
   var r=d.report,seen={};if(r.phase!=='ddns-status'||!Array.isArray(r.rules)||r.rules.length>32)throw new Error();
   r.rules.forEach(function(row){if(!row||!id(row.rule)||seen[row.rule]||!Object.prototype.hasOwnProperty.call(statuses,row.status)||!['cloudflare','aliyun','dnspod','huaweicloud'].includes(row.provider)||row.effect!=='none'||!Number.isInteger(row.retry_in)||row.retry_in<0||row.retry_in>999999999)throw new Error();seen[row.rule]=true;});
   rows=r.rules;body.replaceChildren();var next={};
   rows.forEach(function(row){var tr=node('tr',undefined,'tr cbi-section-table-row'),cell=node('td',undefined,'td'),input=node('input');input.type='checkbox';input.setAttribute('aria-label','选择 '+row.rule);input.checked=!!chosen[row.rule];next[row.rule]=input.checked;
    input.onchange=function(){chosen[row.rule]=input.checked;invalidate();};cell.appendChild(input);tr.appendChild(cell);
    [row.rule,row.provider,statuses[row.status],String(row.retry_in)].forEach(function(v){tr.appendChild(node('td',v,'td'));});body.appendChild(tr);});
   chosen=next;notice.textContent=rows.length?'状态已读取。等待、暂停或恢复屏障不代表允许立即执行。':'当前没有 DDNS 规则。';
  });
 }
 function prepare(){
  if(busy)return;var list=selected();if(!list.length||list.length>32)return;invalidate();perform('preview',{selection:list.join(',')},function(d){
   var r=d.report,actual=names(r);if(r.phase!=='ddns-authority'||r.authorized!==false||r.service_started!==false||r.expires_in!==300||!/^[0-9a-f]{32}$/.test(r.confirmation)||!Number.isInteger(r.configuration_revision)||r.configuration_revision<1||r.configuration_revision>32||JSON.stringify(actual)!==JSON.stringify(list))throw new Error();
   staged=r;scope.textContent='将授权：'+actual.join('、')+'；配置版本 '+r.configuration_revision+'。预览有效期 300 秒，配置变化后需重新预览。';pane.hidden=false;notice.textContent='预览尚未授权。请核对规则后确认。';
  });
 }
 controls();read();return {refresh:read};
}
global.HomeGateDDNS={mount:mount};
}(window));
