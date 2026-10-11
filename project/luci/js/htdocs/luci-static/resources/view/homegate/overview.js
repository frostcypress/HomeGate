'use strict';
'require view';
'require homegate.transport as transport';
'require homegate.overview as template';
return view.extend({
 load: function() { return transport.load('overview'); },
 render: function(data) { const root=E('div'); root.innerHTML=template.render(data); return root; },
 handleSave: null,
 handleSaveApply: null,
 handleReset: null
});
