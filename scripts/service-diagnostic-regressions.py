#!/usr/bin/env python3
"""No-network router/client diagnostics: family failures, HTTP denial, secret isolation."""
from pathlib import Path
import os,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='hg-service-diag-') as temp:
 root=Path(temp);tools=root/'bin';tools.mkdir();out=root/'report';out.mkdir()
 commands={
 'uci':'''case "$*" in
 "-q show homegate") printf "homegate.web1=web_rule\\nhomegate.disabled=web_rule\\nhomegate.bad=web_rule\\nhomegate.account=dns_account\\nhomegate.account.secret='MUST_NOT_LEAK'\\n";;
 "-q get homegate.disabled.enabled") echo 0;;
 "-q get homegate.web1.enabled"|"-q get homegate.bad.enabled") echo 1;;
 "-q get homegate.web1.domain") echo service.example;;
 "-q get homegate.bad.domain") echo 'https://user:password@example/' ;;
 "-q get homegate.web1.https") echo 1;;
 "-q get homegate.main.https_port") echo 443;;
 *) echo 'UNAUTHORIZED_UCI_COMMAND' >>"$TEST_TRACE";exit 1;;esac''',
 'curl':'''printf '%s\\n' "$*" >>"$TEST_TRACE"
 case "$1" in -4) echo 'Could not resolve host';exit 6;;-6) echo 'http_code=403';echo 'remote_ip=2001:db8::1';exit 0;;*) exit 1;;esac''',
 'homegate':'printf "%s\\n" "$*" >>"$TEST_TRACE"; echo \'{"ok":true,"entries":[]}\'',
 'nslookup':'echo "Name: service.example";echo "Address: 2001:db8::1"',
 'ss':'echo "LISTEN 0 128 [::]:443"', 'ip6tables-save':'echo fixture-ipv6', 'iptables-save':'echo fixture-ipv4'}
 for name,body in commands.items():
  f=tools/name;f.write_text('#!/bin/sh\n'+body+'\n');f.chmod(0o755)
 trace=root/'trace';env=dict(os.environ,PATH=str(tools)+':'+os.environ['PATH'],TEST_TRACE=str(trace))
 runner=root/'run.sh';runner.write_text('''#!/bin/sh
set -u
OUT="$1"
record(){ printf '%s\\n' "$*" >>"$OUT/events.log"; }
snapshot(){ name=$1;shift;"$@" >"$OUT/$name.log" 2>&1; }
. "$2"
''')
 result=subprocess.run(['sh',str(runner),str(out),str(ROOT/'scripts/service-network-diagnostic.sh')],env=env,capture_output=True,text=True)
 assert result.returncode==0,(result.stdout,result.stderr)
 assert (out/'service-targets.txt').read_text(encoding='utf-8')=='https://service.example:443/\n'
 assert 'curl_exit=6' in (out/'service-1-ipv4.log').read_text(encoding='utf-8')
 assert 'http_code=403' in (out/'service-1-ipv6.log').read_text(encoding='utf-8')
 assert 'curl_exit=0' in (out/'service-1-ipv6.log').read_text(encoding='utf-8')
 text=''.join(f.read_text(encoding='utf-8') for f in out.rglob('*') if f.is_file())
 assert 'MUST_NOT_LEAK' not in text and 'password' not in text
 assert 'UNAUTHORIZED_UCI_COMMAND' not in trace.read_text(encoding='utf-8')
 assert 'access-recent' in trace.read_text(encoding='utf-8') and '--head' in trace.read_text(encoding='utf-8')
 print('PASS router diagnostic: IPv4 DNS failure / IPv6 HTTP 403 / disabled & invalid targets / secret isolation')
 # Client test only invokes the mock curl; archive contains no host changes.
 targets=root/'targets.txt';targets.write_text('https://service.example:443/\n')
 result=subprocess.run(['sh',str(ROOT/'scripts/client-service-check.sh'),str(targets)],env=dict(env,TMPDIR=str(root)),capture_output=True,text=True)
 assert result.returncode==0,(result.stdout,result.stderr)
 import tarfile
 archive=Path(result.stdout.strip().split('REPORT ',1)[1]);assert archive.is_file()
 with tarfile.open(archive) as t:
  log=t.extractfile(next(f for f in t if f.name.endswith('/client.log'))).read().decode()
 assert 'curl_exit=6' in log and 'http_code=403' in log and 'environment-proxy' in log and 'role=client' in log
 print('PASS client diagnostic: separate route/family probes and automatic archive')
