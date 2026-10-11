'use strict';
'require baseclass';
'require rpc';
'require ui';

const read = rpc.declare({object:'homegate',method:'read',params:['route','form']});
const write = rpc.declare({object:'homegate',method:'write',params:['route','form']});
const poll = rpc.declare({object:'homegate',method:'poll',params:['job']});
const ack = rpc.declare({object:'homegate',method:'ack',params:['job']});
const prefix = '/admin/services/homegate/';
const submissions = new WeakMap();
function submitPage(root,page,mode) {
 if (!['basic','public','wol','maintenance'].includes(page) || !['save','apply'].includes(mode)) throw new Error(_('Invalid HomeGate action'));
 const form=root.querySelector('#homegate-'+page+'-form');
 if (!form) throw new Error(_('Invalid HomeGate action'));
 const submitter=document.createElement('button');
 submitter.type='submit';submitter.name='mode';submitter.value=mode;submitter.hidden=true;
 form.appendChild(submitter);submissions.delete(form);
 try {
  // requestSubmit preserves browser validation and canonical onsubmit staging.
  form.requestSubmit(submitter);
  return submissions.get(form) || Promise.resolve(false);
 } finally {submitter.remove();}
}
function routeURL(value) {
 const parsed = new URL(value,location.href);
 const index = parsed.pathname.indexOf(prefix);
 if (parsed.origin !== location.origin || index < 0) throw new Error(_('Invalid HomeGate action'));
 const route = parsed.pathname.slice(index + prefix.length).replace(/\/$/,'');
 if (!/^[a-z_]+(?:\/[a-z_]+)?$/.test(route)) throw new Error(_('Invalid HomeGate action'));
 return {route,form:Object.fromEntries(parsed.searchParams.entries()),parsed};
}
async function action(route,form) {
 const submitted = await write(route,form);
 if (!submitted.ok || !submitted.job) throw new Error(submitted.error || _('Unable to queue action'));
 const deadline = Date.now() + 260000;
 while (Date.now() < deadline) {
  await new Promise(resolve=>setTimeout(resolve,500));
  const state = await poll(submitted.job);
  if (!state.ok) throw new Error(state.error || _('Unable to read action result'));
  if (state.pending) continue;
  if (!state.result) throw new Error(_('Invalid HomeGate bridge response'));
  // Acknowledge only after obtaining the complete result. Files contain secrets
  // for authorized exports and must disappear without waiting for TTL cleanup.
  await ack(submitted.job).catch(()=>{});
  return state.result;
 }
 throw new Error(_('Action timed out; inspect status before retrying'));
}
function finish(result) {
 if (result.redirect) {
  const destination = routeURL(result.redirect);
  if (!['basic','public','wol','maintenance'].includes(destination.route)) throw new Error(_('Invalid HomeGate action'));
  location.href = result.redirect;
  return;
 }
 if (!result.ok) throw new Error(result.error || _('Action failed'));
 const disposition = (result.headers || {})['Content-Disposition'] || '';
 if (disposition) {
  const match = /filename="?([^";]+)"?/.exec(disposition);
  const name = match && /^[\w.-]+$/.test(match[1]) ? match[1] : 'homegate-export.txt';
  const blob = new Blob([result.body || ''],{type:(result.headers || {})['Content-Type'] || 'text/plain'});
  const href = URL.createObjectURL(blob), link = document.createElement('a');
  link.href = href; link.download = name; link.click();
  setTimeout(()=>URL.revokeObjectURL(href),1000);
 }
}
function install(root) {
 window.homegateXHR = {get:function(value,extra,callback) {
  let destination;
  try {destination=routeURL(value);} catch(e) {callback({status:400,responseText:''},null);return;}
  const form = Object.assign({},destination.form,extra || {});
  const abort = {aborted:false,abort:function(){this.aborted=true;}};
  read(destination.route,form).then(result=>{
   if(abort.aborted)return;
   let parsed=null;
   try {parsed=JSON.parse(result.body || '');} catch(e) {}
   callback({status:result.ok?200:500,responseText:result.body || ''},parsed);
  },()=>{if(!abort.aborted)callback({status:503,responseText:''},null);});
  return abort;
 }};
 const pending = new WeakSet();
 async function submit(form,submitter) {
  if (pending.has(form)) return;
  pending.add(form);
  const originallyDisabled = submitter && submitter.disabled;
  try {
   // Build values before disabling the successful submit control.
   const values = {};
   new FormData(form).forEach((value,key)=>{if(typeof value !== 'string')throw new Error(_('Unsupported file upload'));values[key]=value;});
   if(submitter && submitter.name)values[submitter.name]=submitter.value;
   const destination=routeURL(form.action);
   if(submitter)submitter.disabled=true;
   finish(await action(destination.route,Object.assign({},destination.form,values)));
  } catch(e) {ui.addNotification(null,E('p',{},e.message),'error');}
  finally {pending.delete(form);if(submitter)submitter.disabled=originallyDisabled;}
 }
 // Modal portals and hgSubmitPost append forms directly to document.body.
 // Intercept only validated HomeGate actions; other LuCI forms keep their API.
 window.homegateNativeSubmit=submit;
 if (!window.homegateNativeHooked) {
  window.homegateNativeHooked=true;
  document.addEventListener('submit',event=>{
   if(event.defaultPrevented)return;
   try {routeURL(event.target.action);} catch(e) {return;}
   event.preventDefault();submissions.set(event.target,window.homegateNativeSubmit(event.target,event.submitter));
  });
  const original=HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit=function(){
   try {routeURL(this.action);} catch(e) {return original.call(this);}
   window.homegateNativeSubmit(this,null);
  };
 }
 return root;
}
return baseclass.extend({load:function(page){const form=Object.fromEntries(new URL(location.href).searchParams.entries());return read(page,form).then(result=>{if(!result.ok)throw new Error(result.error || _('Unable to load HomeGate'));return result.data;});},install,submitPage});
