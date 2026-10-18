'use strict';
'require view';
'require rpc';
var read=rpc.declare({object:'homegate_ddns',method:'status',params:[]});
var maintainPreview=rpc.declare({object:'homegate_ddns',method:'maintain_preview',params:['job']});
var maintainCommit=rpc.declare({object:'homegate_ddns',method:'maintain_commit',params:['job','confirmation','consent']});
var jobs=rpc.declare({object:'homegate_ddns',method:'jobs',params:[]});
var submit=rpc.declare({object:'homegate_ddns',method:'submit',params:['job','rule','consent']});
var preview=rpc.declare({object:'homegate_ddns',method:'preview',params:['selection']});
var commit=rpc.declare({object:'homegate_ddns',method:'commit',params:['confirmation','consent']});
var revoke=rpc.declare({object:'homegate_ddns',method:'revoke',params:['consent']});
return view.extend({
 load:function(){return new Promise(function(resolve,reject){
  if(window.HomeGateDDNS){resolve();return;}
  var script=document.createElement('script');script.src=L.resource('homegate/ddns-ui.js');script.onload=resolve;script.onerror=reject;document.head.appendChild(script);
 });},
 render:function(){var root=E('div',{'class':'cbi-section'});window.HomeGateDDNS.mount(root,function(action,form){
  if(action==='status')return read();if(action==='jobs')return jobs();if(action==='maintain_preview')return maintainPreview(form.job);if(action==='maintain_commit')return maintainCommit(form.job,form.confirmation,form.consent);if(action==='submit')return submit(form.job,form.rule,form.consent);if(action==='preview')return preview(form.selection);if(action==='commit')return commit(form.confirmation,form.consent);if(action==='revoke')return revoke(form.consent);return Promise.reject(new Error('Invalid action'));
 });return root;},handleSave:null,handleSaveApply:null,handleReset:null
});
