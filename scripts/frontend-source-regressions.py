#!/usr/bin/env python3
"""Current static UI contracts; runtime/theme tests are separate browser suites."""
from pathlib import Path
import re,subprocess,sys
ROOT=Path(__file__).resolve().parents[1];app=ROOT/'project/luci'
views=app/'lua/luasrc/view/homegate';modules=app/'js/htdocs/luci-static/resources'
po=(app/'common/po/zh_Hans/homegate.po').read_text(encoding='utf-8')
ids=set(re.findall(r'^msgid "(.*)"$',po,re.M))
for name in ('basic','public','wol','maintenance'):
 text=(views/(name+'.htm')).read_text(encoding='utf-8')
 assert 'id="homegate-'+name+'-form"' in text
 footer=re.search(r'<div class="cbi-page-actions">(.*?)</div>',text,re.S);assert footer,name
 buttons=re.findall(r'<input\b([^\n]*)',footer[1]);assert len(buttons)==3
 assert text.count('name="mode" value="apply"')==1
 for mode,attrs in zip(('apply','save'),buttons):
  assert 'type="submit"' in attrs and "this.form.elements['mode'].value='"+mode+"'" in attrs
  assert attrs.count(' value=')==1 and 'name="mode"' not in attrs
  assert 'form="homegate-'+name+'-form"' in attrs
 assert 'type="button"' in buttons[2] and 'cbi-button-reset' in buttons[2]
 assert all('hg-page-' not in attrs for attrs in buttons)
 missing=set(re.findall(r'<%:([^%]+)%>',text))-ids;assert not missing,(name,missing)
 wrapper=(modules/'view/homegate'/(name+'.js')).read_text(encoding='utf-8')
 assert "'require view';" in wrapper and 'return view.extend({' in wrapper
 assert 'handleSave: null' not in wrapper and 'transport.submitPage' in wrapper
 assert 'addFooter:' not in wrapper and "root.querySelector('.cbi-page-actions').remove()" in wrapper
common=(views/'common.htm').read_text(encoding='utf-8')
assert not re.search(r'\.hg-page-(actions|btn-[46])',common)
public=(views/'public.htm').read_text(encoding='utf-8')
assert '<%:Certificate Scope%>' not in public and '<%:Access Time%>' in public
assert 'class="cbi-input-checkbox" type="checkbox" id="hg-public-https"' in public
subprocess.run([sys.executable,str(ROOT/'scripts/build-js-views.py')],check=True)
for name in ('common','transport','basic','public','wol','maintenance'):
 source=(modules/'homegate'/(name+'.js')).read_text(encoding='utf-8')
 assert "'require baseclass';" in source and 'return baseclass.extend({' in source,name
print('PASS current frontend sources: forms, native footer, translations, module exports')
