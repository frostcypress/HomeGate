#!/usr/bin/env python3
"""Generate Core's embedded rules and route allowlist from the legacy authority."""
import json, re
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
source=ROOT/'project/luci/lua/luasrc/controller/homegate.lua'
target=ROOT/'project/core/src/internal/frontend'
target.mkdir(parents=True,exist_ok=True)
(target/'controller.lua').write_bytes(source.read_bytes())
routes={}
for path,kind,handler in re.findall(r'entry\(\{([^}]+)\},\s*(call|post)\("([^"]+)"\)',source.read_text(encoding='utf-8')):
    fields=re.findall(r'"([^"]+)"',path)
    if fields[:3]==['admin','services','homegate']:
        routes['/'.join(fields[3:])]={'handler':handler,'write':kind=='post'}
(target/'routes.json').write_text(json.dumps(routes,sort_keys=True,indent=2)+'\n',newline='\n')
print('Shared rules and explicit route allowlist generated:',len(routes))
