#!/usr/bin/python3
"""External command-boundary model only; never real kernel/target evidence."""
import json,subprocess,sys,time
from pathlib import Path
p=Path('/teststate');path=p/'fw-kernel.json';fault=p/'fw-fault'
d=json.loads(path.read_text());args=sys.argv[1:]
assert args[:2]==['-w','1'] and args[2]=='-t';tab=args[3];a=args[4:];assert tab in ('nat','filter')
mode=fault.read_text() if fault.exists() else ''
with (p/'fw-calls').open('a') as f:f.write(json.dumps([tab,*a])+'\n')
def fail(text,code=1):sys.stderr.write(text+'\n');sys.exit(code)
if mode=='permission':fail('Permission denied; cannot inspect rules',4)
if mode=='hold':
 child=subprocess.Popen(['/usr/sbin/busybox','sleep','45']);(p/'fw-held-pid').write_text(str(child.pid));(p/'fw-entered').touch();time.sleep(45);sys.exit(4)
if mode=='fail-once' and a[:2]==['-A','HG_ENG_NAT']:fault.unlink();fail('Injected REDIRECT failure',3)
if mode=='cleanup-fail' and a[0] in ('-D','-F','-X'):fail('Injected cleanup failure',4)
chains=d[tab];op=a[0];name=a[1] if len(a)>1 else None
if op=='-S':
 if name is not None and name not in chains:fail('No chain/target/match by that name.')
 for current in [name] if name is not None else chains:
  print(('-P '+current+' ACCEPT') if current in ('INPUT','PREROUTING') else '-N '+current)
  for rule in chains[current]:print(' '.join(['-A',current,*rule]))
 sys.exit(0)
assert name in ('HG_ENG_NAT','HG_ENG_INPUT','INPUT','PREROUTING')
if op=='-N':
 assert name.startswith('HG_ENG_')
 if name in chains:fail('Chain already exists',1)
 chains[name]=[]
elif op=='-I':
 assert name in ('INPUT','PREROUTING') and a[2]=='1' and a[3:]==['-j','HG_ENG_NAT' if tab=='nat' else 'HG_ENG_INPUT'];chains[name].insert(0,a[3:])
elif op=='-A':
 assert name.startswith('HG_ENG_') and a[2]=='-i' and a[4:7]==['-p','tcp','--dport']
 if name not in chains:fail('No chain/target/match by that name.')
 chains[name].append(a[2:])
elif op=='-D':
 assert name in ('INPUT','PREROUTING') and a[2:]==['-j','HG_ENG_NAT' if tab=='nat' else 'HG_ENG_INPUT']
 if a[2:] not in chains[name]:fail('Bad rule (does a matching rule exist in that chain?).')
 chains[name].remove(a[2:])
elif op=='-F':
 assert name.startswith('HG_ENG_')
 if name not in chains:fail('No chain/target/match by that name.')
 chains[name]=[]
elif op=='-X':
 assert name.startswith('HG_ENG_')
 if name not in chains:fail('No chain/target/match by that name.')
 if any(name in rule for rules in chains.values() for rule in rules):fail('Chain is referenced',4)
 del chains[name]
else:raise AssertionError(a)
tmp=p/'fw-kernel.next';tmp.write_text(json.dumps(d));tmp.replace(path)
