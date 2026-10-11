'use strict';
'require view';
'require homegate.transport as transport';
'require homegate.basic as template';
return view.extend({
 load: function() {return transport.load('basic');},
 render: function(data) {
  const root = E('div',{'class':'homegate-native'});
  root.innerHTML = template.render(data);
  root.querySelector('.cbi-page-actions').remove();
  this.root = root;
  transport.install(root);
  // LuCI mounts the returned tree before the next animation frame. Recreate
  // trusted, build-time script elements to execute the unchanged UI helpers.
  requestAnimationFrame(function(){root.querySelectorAll('script').forEach(function(old){const next=document.createElement('script');next.textContent=old.textContent;old.replaceWith(next);});});
  return root;
 },
 handleSave: function() {return transport.submitPage(this.root,'basic','save');},
 handleSaveApply: function(ev,mode) {
  if (String(mode)!=='0' && String(mode)!=='1') throw new Error(_('Invalid HomeGate action'));
  // Service-specific apply: both official menu choices apply HomeGate only.
  // Never apply unrelated LuCI UCI changes or promise network rollback here.
  return transport.submitPage(this.root,'basic','apply');
 },
 handleReset: function() {location.href=L.url('admin','services','homegate','basic');}
});
