#!/usr/bin/env python3
"""Compile the frozen HTML templates to native JavaScript (no browser Lua VM).

Only the template language used by HomeGate is accepted. Unknown constructs fail
the build, avoiding silent drift between the legacy and modern frontends.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VIEWS = ROOT / 'project/luci/lua/luasrc/view/homegate'
OUT = ROOT / 'project/luci/js/htdocs/luci-static/resources/homegate'

class Expression:
    pattern = re.compile(r"\s*(?:('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")|(\d+)|(\w+)|(~=|==|\.\.|[().,#{}\[\]+-]))")
    precedence = {'or': 1, 'and': 2, '==': 3, '~=': 3, '..': 4, '+': 5, '-': 5}
    def __init__(self, source):
        self.tokens = []
        pos = 0
        while pos < len(source.strip()):
            m = self.pattern.match(source.strip(), pos)
            if not m:
                raise ValueError('Unsupported expression: ' + source)
            self.tokens.append(next(x for x in m.groups() if x is not None)); pos = m.end()
        self.i = 0
    def take(self):
        token = self.tokens[self.i]; self.i += 1; return token
    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None
    def expect(self, token):
        assert self.take() == token
    def parse(self, level=0):
        token = self.take()
        if token == '(':
            left = self.parse(); self.expect(')')
        elif token == '{':
            self.expect('}'); left = '[]'
        elif token in ('not', '#'):
            value = self.parse(6)
            left = '!truth(' + value + ')' if token == 'not' else 'items(' + value + ').length'
        elif token.startswith(('"', "'")):
            # Template strings contain no Lua-only escapes; JSON preserves them.
            import ast
            left = json.dumps(ast.literal_eval(token), ensure_ascii=False)
        elif token.isdigit(): left = token
        elif token in ('nil', 'true', 'false'): left = {'nil': 'null', 'true': 'true', 'false': 'false'}[token]
        else: left = token
        while self.peek() in ('.', '[', '('):
            op = self.take()
            if op == '.': left = 'get(' + left + ',' + json.dumps(self.take()) + ')'
            elif op == '[':
                key = self.parse(); self.expect(']'); left = 'get(' + left + ',' + key + ')'
            else:
                args = []
                if self.peek() != ')':
                    args.append(self.parse())
                    while self.peek() == ',': self.take(); args.append(self.parse())
                self.expect(')'); left += '(' + ','.join(args) + ')'
        while self.peek() in self.precedence and self.precedence[self.peek()] >= level:
            op = self.take(); right = self.parse(self.precedence[op] + (0 if op == '..' else 1))
            if op in ('and', 'or'): left = op + 'Value(' + left + ',()=>(' + right + '))'
            elif op == '..': left = '(String(' + left + ')+String(' + right + '))'
            else: left = '(' + left + {'==': '===', '~=': '!==', '+': '+', '-': '-'}[op] + right + ')'
        return left

def expression(source):
    parser = Expression(source); result = parser.parse()
    if parser.peek() is not None: raise ValueError('Unused tokens: ' + source)
    return result

PRELUDE = r'''
const string = {format:(pattern,days)=>String(pattern).replace('%d',String(days))};
const truth = v => v !== null && v !== undefined && v !== false;
const andValue = (a,b) => truth(a) ? b() : a;
const orValue = (a,b) => truth(a) ? a : b();
const get = (v,k) => v == null ? null : (v[k] === undefined ? null : v[k]);
const items = v => Array.isArray(v) ? v : [];
const pcdata = v => String(v == null ? '' : v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const translate = v => _(String(v == null ? '' : v));
const url = p => L.url.apply(L, p.split('/'));
const tonumber = v => v == null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v);
const b = v => ['1','true','yes','on'].includes(v);
const credential = (p,name) => items(get(p,'credentials')).find(f=>f.name === name) || null;
const ca_directory = (c,env) => orValue(get(get(c,'directories'),env),()=>(''));
const {main={},packages={},status={},services=[],hosts=[],dns_accounts=[],certificates=[],dns_provider_catalog=[],acme_ca_catalog=[],access_regions=[],retired_access_region=false,wol_interfaces=[],wol_clients=[],wol_selected_interface=null,public_count=0,wol_count=0,notice='',error_message='',token='',default_renew_days=null,acme_directory=null,resume_public=null,resume_account=null} = data;
let access_scope = get(main,'access_enabled') === '1' ? (get(main,'access_region') || '__manual__') : '';
let html = '';
'''

def compile_view(path):
    text = path.read_text(encoding='utf-8')
    # Shared CSS/helpers are generated once, not duplicated into every page.
    text = re.sub(r'<%\+(header|footer)%>', '', text)
    code = ["'use strict';", "'require baseclass';", *([] if path.stem == 'common' else ["'require homegate.common as shared';"]), '// Generated by scripts/build-js-views.py; edit the canonical HTM files.', 'return baseclass.extend({render: function(data) {', PRELUDE]
    for part in re.split(r'(<%.*?%>)', text, flags=re.S):
        if not part: continue
        if not part.startswith('<%'):
            part = part.replace('XHR.', 'HGXHR.')
            # XHR remains local to HomeGate; never replace LuCI's global transport.
            part = part.replace('<script type="text/javascript">', '<script type="text/javascript">\nvar HGXHR = window.homegateXHR;')
            code.append('html += ' + json.dumps(part, ensure_ascii=False) + ';'); continue
        tag = part[2:-2].strip()
        if tag.startswith('='): code.append('html += String(' + expression(tag[1:]) + ');')
        elif tag == '+homegate/common': code.append('html += shared.render(data);')
        elif tag.startswith(':'): code.append('html += pcdata(_(' + json.dumps(tag[1:]) + '));')
        elif tag.startswith('local function') or tag.startswith('local access_scope'): continue
        elif tag.startswith('if '): code.append('if (truth(' + expression(tag[3:-5].strip()) + ')) {')
        elif tag.startswith('elseif '): code.append('} else if (truth(' + expression(tag[7:-5].strip()) + ')) {')
        elif tag == 'else': code.append('} else {')
        elif tag == 'end': code.append('}')
        elif tag.startswith('for '):
            m = re.fullmatch(r'for (\w+), (\w+) in ipairs\((.*?)\) do(?:\s+(.*))?', tag, re.S)
            if not m: raise ValueError('Unsupported loop: ' + tag)
            index, name, values, locals_ = m.groups()
            code.append('for (const [' + index + '_zero,' + name + '] of items(' + expression(values) + ').entries()) {')
            if index != '_': code.append('const ' + index + ' = ' + index + '_zero + 1;')
            if locals_:
                for local in locals_.split(';'):
                    lm = re.fullmatch(r'local (\w+)\s*=\s*(.*)', local.strip())
                    if not lm: raise ValueError('Unsupported local: ' + local)
                    code.append('const ' + lm[1] + ' = ' + expression(lm[2]) + ';')
        else: raise ValueError('Unsupported template tag: ' + tag)
    code.append('return html; }});')
    return '\n'.join(code)

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name in ('common', 'overview', 'basic', 'public', 'wol', 'maintenance'):
        OUT.joinpath(name + '.js').write_text(compile_view(VIEWS / (name + '.htm')), encoding='utf-8', newline='\n')
    print('Generated shared module + 5 native JavaScript views from canonical templates')

if __name__ == '__main__': main()
