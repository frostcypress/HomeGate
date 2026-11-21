#!/usr/bin/python3
"""External command-boundary model only; never real kernel/target evidence."""
import ipaddress,json,subprocess,sys,time
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
if mode=='slow-apply' and a[0] in ('-N','-A','-I'):time.sleep(1.2)
if mode=='no-tcp-reset' and a[0]=='-A' and a[-4:]==['-j','REJECT','--reject-with','tcp-reset']:
 fail('No chain/target/match by that name.')
chains=d[tab];op=a[0];name=a[1] if len(a)>1 else None
if op=='-S':
 if name is not None and name not in chains:fail('No chain/target/match by that name.')
 for current in [name] if name is not None else chains:
  print(('-P '+current+' ACCEPT') if current in ('INPUT','PREROUTING') else '-N '+current)
  for rule in chains[current]:
   displayed=rule
   if rule[0]=='-d':
    destination=ipaddress.IPv6Network(rule[1])
    assert destination.prefixlen==128
    displayed=['-d',str(destination.network_address),*rule[2:6],'-m','tcp',*rule[6:]]
   print(' '.join(['-A',current,*displayed]))
 sys.exit(0)
assert name in ('HG_ENG_NAT','HG_ENG_INPUT','INPUT','PREROUTING')
if op=='-N':
 assert name.startswith('HG_ENG_')
 if name in chains:fail('Chain already exists',1)
 chains[name]=[]
elif op=='-I':
 assert name in ('INPUT','PREROUTING') and a[2]=='1' and a[3:]==['-j','HG_ENG_NAT' if tab=='nat' else 'HG_ENG_INPUT'];chains[name].insert(0,a[3:])
elif op=='-A':
 assert name.startswith('HG_ENG_')
 match=a[2:]
 if match[0]=='-d':
  assert ipaddress.IPv6Network(match[1]).prefixlen==128
  if tab=='filter':
   assert match[7] in ('80','443')
   assert match[8:] in (['-j','DROP'],['-j','REJECT','--reject-with','tcp-reset'])
  match=match[2:]
 if match[0]=='!':
  assert tab=='filter' and match[1:3]==['-i','lo'] and match[-2:]==['-j','DROP']
  match=match[1:]
 assert match[0]=='-i' and match[2:5]==['-p','tcp','--dport']
 if '-m' in match:
  assert tab=='filter' and match[6:11]==['-m','conntrack','--ctstate','DNAT','--ctorigdstport']
  assert match[11] in ('80','443') and match[12:]==['-j','ACCEPT']
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
