#!/usr/bin/env python3
"""Source-bound network CLI, real shell/sysfs fixture and retained watchdog."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unittest
from project import ROOT, identity
from DDNS计划回归 import fixture_uid
from 核心账户CLI回归 import CF as AccountFixture

PROTO = ROOT / 'project/core/prototype'
ADDR = '12: pppoe-wan inet6 2001:0DB8:0000:0:0:0:0:2/64 scope global dynamic\n13: br-lan inet6 2001:db8:1::1/64 scope global\n'
ROUTE = 'default via fe80::1 dev pppoe-wan metric 512\n'


class Static(unittest.TestCase):
    def test_changed_grammar_closed_gates_and_fixed_execution(self):
        import tree_sitter, tree_sitter_bash
        from lupa.lua51 import LuaRuntime
        parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))
        for name in ['homegate-cli.sh', 'homegate-network-read.sh', 'homegate-network-worker.sh',
                     'homegate-service-observer-watchdog.sh']:
            body = (PROTO / name).read_bytes()
            self.assertNotIn(b'\r', body)
            self.assertFalse(parser.parse(body).root_node.has_error, name)
        for name in ['homegate-network.lua', 'network-report.lua']:
            LuaRuntime().compile((PROTO / name).read_bytes())
        for name in ['homegate-network-read.sh', 'homegate-network-worker.sh', 'homegate-service-observer-watchdog.sh']:
            self.assertEqual((PROTO / name).read_text().count('network_resolve_enabled=false'), 1)
        worker = (PROTO / 'homegate-network-worker.sh').read_text()
        self.assertIn('sys_root=/sys/class/net', worker)
        self.assertIn('"$count" -le 1024', worker)
        self.assertNotIn('eval ', worker)
        self.assertNotIn('prototype/', (PROTO.parent / 'Makefile').read_text())

    def test_pure_ipv6_compression_and_lan_frame_against_independent_ipaddress(self):
        from lupa.lua51 import LuaRuntime
        lua = LuaRuntime(unpack_returned_tuples=True)
        model = lua.execute((PROTO / 'network-report.lua').read_text())
        plan = lua.execute((PROTO / 'cloudflare-record-plan.lua').read_text())
        wan = lua.execute((PROTO / 'wan6-plan.lua').read_text())
        for value in ['::', '::1', '2001:0DB8:0:0:0:0:0:2', '2001:0:0:1:0:0:1:1',
                      '2001:db8:0:1:2:3:4:0', '2001:db8::192.0.2.1', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']:
            self.assertEqual(model.ipv6(value, plan), ipaddress.IPv6Address(value).compressed)
        data, ok = model.lan('HGLAN1\nok\neth3\n.vlan0\neth1\nEND\n', 'br-lan', wan)
        self.assertTrue(ok)
        self.assertEqual(list(data['members'].values()), ['.vlan0', 'eth1', 'eth3'])
        for invalid in ['HGLAN1\nok\neth1\neth1\nEND\n', 'HGLAN1\nok\n../bad\nEND\n',
                        'HGLAN1\nok\neth1END\n', 'HGLAN1\nunavailable\neth1\nEND\n']:
            self.assertIsNone(model.lan(invalid, 'br-lan', wan))

    def test_reference_report_and_legacy_diagnostic_exit_semantics(self):
        report = (ROOT / 'project/core/src/internal/network/report.go').read_text()
        self.assertEqual(set(re.findall(r'json:"([^",]+)', report)),
                         {'api_version', 'ok', 'version', 'phase', 'network', 'error'})
        main = (ROOT / 'project/core/src/cmd/homegate/main.go').read_text()
        branch = main.split('case "network-resolve":', 1)[1].split('\n\tcase ', 1)[0]
        self.assertIn('api.WriteJSON(os.Stdout, a.NetworkStatus(ctx))', branch)
        self.assertNotIn('if !report.OK', branch)
        from DDNS生命周期CLI回归 import build_suite
        self.assertEqual([test.id() for test in build_suite(False) if isinstance(test, Static)],
                         [test.id() for test in suite(False)])


class Runtime(AccountFixture):
    def setUp(self):
        super().setUp()
        self.network_entry = self.engine.parent / 'homegate-network-read.sh'
        self.network_worker = self.engine.parent / 'homegate-network-worker.sh'
        self.network_adapter = self.engine.parent / 'homegate-network.lua'
        self.sysnet = self.base / 'sys-net'
        self.brif = self.sysnet / 'br-lan/brif'
        self.brif.mkdir(parents=True)
        for member in ['eth3', 'eth1', '.vlan0']:
            (self.brif / member).touch()
        self.net_control = self.base / 'network-settings'
        self.net_log = self.base / 'network-calls'
        self.settings = {'addresses': ADDR, 'routes': ROUTE, 'wan6': {'up': True, 'l3_device': 'eth4'},
                         'delay': 0, 'address_rc': 0, 'route_rc': 0, 'wan6_rc': 0, 'change_source': False}
        self.save_settings()
        command = ('#!' + sys.executable + '\nimport json,os,sys,time\nfrom pathlib import Path\n'
                   'data=json.loads(Path(' + repr(str(self.net_control)) + ').read_text())\n'
                   'kind="wan6" if "ubus" in sys.argv[0] else "addresses" if "addr" in sys.argv else "routes"\n'
                   'fds=[fd for fd in range(3,10) if Path("/proc/self/fd/"+str(fd)).exists()]\n'
                   'with open(' + repr(str(self.net_log)) + ',"a") as f:f.write(json.dumps({"kind":kind,"args":sys.argv[1:],"fds":fds})+"\\n")\n'
                   'if kind=="addresses":\n time.sleep(data["delay"])\n'
                   'if data["change_source"]:\n Path(' + repr(str(self.source)) + ').write_bytes(' + repr(self.source_before + b'\n') + ')\n'
                   'print(json.dumps(data[kind]) if kind=="wan6" else data[kind],end="")\n'
                   'sys.exit(data[{"addresses":"address_rc","routes":"route_rc","wan6":"wan6_rc"}[kind]])\n')
        self.net_ip = self.base / 'network-ip-fixture'
        self.net_ubus = self.base / 'network-ubus-fixture'
        for file in [self.net_ip, self.net_ubus]:
            file.write_text(command)
            file.chmod(0o700)
        paths = {'/var/run/homegate': str(self.native.lockdir), '/etc/homegate/transactions': str(self.store)}
        for file in [self.network_entry, self.network_worker, self.engine.parent / 'homegate-service-observer-watchdog.sh']:
            body = file.read_text().replace('network_resolve_enabled=false', 'network_resolve_enabled=true')
            if file != self.engine.parent / 'homegate-service-observer-watchdog.sh':
                body = re.sub('|'.join(re.escape(k) for k in paths), lambda m: paths[m[0]], body)
            body = body.replace('sys_root=/sys/class/net', 'sys_root=' + str(self.sysnet))
            file.write_text(fixture_uid(body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'PATH=' + str(self.bin))))
        body = self.network_adapter.read_text().replace("dir..'/../../../'..name", json.dumps(str(ROOT)) + "..'/'..name")
        body = body.replace('/sbin/ip', str(self.net_ip)).replace('/bin/ubus', str(self.net_ubus))
        self.network_adapter.write_text('package.cpath=' + json.dumps(str(ROOT / 'build/service-observer/?.so') + ';;') + '\n' + body)

    def save_settings(self):
        self.net_control.write_text(json.dumps(self.settings))

    def net_calls(self):
        return [json.loads(row) for row in self.net_log.read_text().splitlines()] if self.net_log.exists() else []

    def network(self, expected=0, ok=None, args=None, env=None):
        result = subprocess.run([self.busybox, 'ash', str(self.candidate), *(args or ['network-resolve'])],
                                env=env or self.env, capture_output=True, timeout=12)
        self.assertEqual((result.returncode, result.stderr), (expected, b''), result.stdout)
        self.assertLess(len(result.stdout), 65536)
        for marker in [b'SECRET_SENTINEL', b'PRIVATE_SENTINEL', b'OLD_ID', b'example.test', os.fsencode(self.store)]:
            self.assertNotIn(marker, result.stdout)
        report = json.loads(result.stdout)
        if ok is not None:
            self.assertEqual(report['ok'], ok)
        self.assertFalse(report['write_ready'])
        self.assertEqual(report['effect'], 'none')
        self.assertEqual(self.calls, [], 'Network diagnostic called a DNS provider')
        return report

    def unchanged_network(self):
        self.unchanged_status()
        self.assertFalse(list(self.native.lockdir.glob('.network-read-*')))
        self.assertEqual(self.calls, [])

    def publish_bridge(self, bridge):
        current = self.cli('status')['revision']
        body = (self.store / f'gen-{current}/public.conf').read_bytes()
        self.assertIn(b"option wol_interface 'br-lan'", body)
        body = body.replace(b"option wol_interface 'br-lan'", ("option wol_interface '" + bridge + "'").encode())
        preview = self.cli('preview', payload=body)
        tx = self.cli('commit-apply-projection', preview['confirmation'])
        self.cli('projection-publish', tx['apply_handle'], 'apply')
        self.cli('apply-finish-projection', tx['apply_handle'])
        self.revision = self.cli('status')['revision']
        self.before = self.contents()
        self.source_before = self.source.read_bytes()

    def test_route_owner_skips_ubus_and_returns_canonical_wan_and_sorted_lan(self):
        report = self.network(ok=True)
        self.assertEqual(report['version'], identity()['normalized'])
        self.assertEqual(report['phase'], 'network-resolver')
        self.assertEqual(report['configuration_revision'], self.revision)
        self.assertEqual(report['network'], {'wan': {'public_ipv6': '2001:db8::2', 'device': 'pppoe-wan', 'source': 'public-ip'},
                                            'lan': {'bridge': 'br-lan', 'members': ['.vlan0', 'eth1', 'eth3']}})
        self.assertEqual([c['kind'] for c in self.net_calls()], ['addresses', 'routes'])
        self.assertTrue(all(c['fds'] == [] for c in self.net_calls()))
        self.assertEqual(self.net_calls()[0]['args'], ['-6', '-o', 'addr', 'show', 'scope', 'global'])
        self.assertEqual(self.net_calls()[1]['args'], ['-6', 'route', 'show', 'default'])
        self.unchanged_network()

    def test_ubus_fallback_uses_actual_public_address_owner(self):
        self.settings.update(addresses='8: odd-uplink inet6 2001:db8:2::9/64 scope global\n', routes='',
                             wan6={'up': True, 'l3_device': 'odd-uplink', 'ignored': 'PRIVATE_SENTINEL'})
        self.save_settings()
        report = self.network(ok=True)
        self.assertEqual(report['network']['wan']['device'], 'odd-uplink')
        self.assertEqual([c['kind'] for c in self.net_calls()], ['addresses', 'routes', 'wan6'])
        self.assertEqual(self.net_calls()[-1]['args'], ['call', 'network.interface.wan6', 'status'])
        self.unchanged_network()

    def test_unavailable_wan_is_a_zero_exit_diagnostic_with_independent_lan(self):
        self.settings['addresses'] = '13: br-lan inet6 2001:db8:1::1/64 scope global\n'
        self.save_settings()
        report = self.network(ok=False)
        self.assertEqual(report['network']['wan'], {'device': 'pppoe-wan', 'source': 'default-route'})
        self.assertEqual(report['network']['lan']['members'], ['.vlan0', 'eth1', 'eth3'])
        self.settings.update(routes='', wan6={'up': False})
        self.save_settings()
        self.assertEqual(self.network(ok=False)['network']['wan'], {})
        self.unchanged_network()

    def test_down_or_unusable_wan_does_not_publish_a_stale_public_address(self):
        self.settings.update(routes='', wan6={'up': False, 'l3_device': 'eth4'})
        self.save_settings()
        self.assertNotIn('public_ipv6', self.network(ok=False)['network']['wan'])
        self.settings.update(addresses=ADDR.replace('scope global dynamic', 'scope global deprecated'), routes=ROUTE)
        self.save_settings()
        self.assertNotIn('public_ipv6', self.network(ok=False)['network']['wan'])
        self.unchanged_network()

    def test_missing_lan_keeps_a_valid_wan_and_an_empty_members_array(self):
        self.publish_bridge('missing-lan')
        report = self.network(ok=False)
        self.assertEqual(report['network']['wan']['public_ipv6'], '2001:db8::2')
        self.assertEqual(report['network']['lan'], {'bridge': 'missing-lan', 'members': []})
        directory = self.sysnet / 'missing-lan'
        directory.mkdir(mode=0o000)
        try:
            self.assertEqual(self.network(ok=False)['network']['lan']['members'], [])
        finally:
            directory.chmod(0o700)
        self.unchanged_network()

    def test_configured_physical_lan_and_empty_bridge_default(self):
        self.publish_bridge('lan0')
        (self.sysnet / 'lan0').mkdir()
        self.assertEqual(self.network(ok=True)['network']['lan'], {'bridge': 'lan0', 'members': []})
        self.unchanged_network()

    def test_empty_configured_bridge_defaults_to_br_lan(self):
        self.publish_bridge('')
        self.assertEqual(self.network(ok=True)['network']['lan']['bridge'], 'br-lan')
        self.unchanged_network()

    def test_arguments_environment_gates_and_traversal_are_refused_before_sampling(self):
        for extra in ['br-lan', '/sys', '--confirm', '$(id)']:
            self.network(2, args=['network-resolve', extra])
        self.network_entry.write_text(self.network_entry.read_text().replace('network_resolve_enabled=true', 'network_resolve_enabled=false'))
        self.network(2, env={**self.env, 'network_resolve_enabled': 'true', 'HOMEGATE_SYS_CLASS_NET': str(self.sysnet)})
        self.network_entry.write_text(self.network_entry.read_text().replace('network_resolve_enabled=false', 'network_resolve_enabled=true'))
        self.publish_bridge('..')
        self.network(7)
        self.assertEqual(self.net_calls(), [])

    def test_locks_and_changed_source_refuse_and_do_not_reuse_orphan_results(self):
        import fcntl
        for file in [self.native.lock, self.store / '.supervisor.lock']:
            with file.open('rb') as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.network(4)
        self.source.write_bytes(self.source_before + b'\n')
        self.network(7)
        self.assertEqual(self.net_calls(), [])
        self.source.write_bytes(self.source_before)
        self.settings['change_source'] = True
        self.save_settings()
        report = self.network(7)
        self.assertNotIn('network', report)
        self.assertTrue(list(self.native.lockdir.glob('.network-read-*')))
        self.source.write_bytes(self.source_before)
        count = len(self.net_calls())
        self.network(4)
        self.assertEqual(len(self.net_calls()), count)

    def test_replaced_lock_inode_is_not_accepted(self):
        self.fault('flock', "if sys.argv[1:]==['-n','6']:\n from pathlib import Path\n p=Path(" +
                   repr(str(self.native.lock)) + ");p.unlink();p.touch(mode=0o600)")
        self.network(4)
        self.assertEqual(self.net_calls(), [])

    def test_tampered_worker_effect_never_enters_the_public_report(self):
        self.network_adapter.write_text(self.network_adapter.read_text().replace('if #output>65536 then',
                                        "output=output:gsub('none','confirmed')\nif #output>65536 then"))
        self.network(7)
        self.assertTrue(list(self.native.lockdir.glob('.network-read-*')))

    def test_lan_member_limit_is_reported_unavailable_without_a_partial_list(self):
        for n in range(1025):
            (self.brif / ('p' + str(n))).touch()
        report = self.network(ok=False)
        self.assertEqual(report['network']['lan']['members'], [])
        self.assertIn('public_ipv6', report['network']['wan'])
        self.unchanged_network()

    def test_stalled_network_command_has_existing_independent_deadline(self):
        self.settings['delay'] = 30
        self.save_settings()
        start = time.monotonic()
        self.network(7)
        self.assertLess(time.monotonic() - start, 10)
        self.assertTrue(list(self.native.lockdir.glob('.network-read-*')))
        self.network(4)

    def test_caller_loss_keeps_locks_until_watchdog_stops_its_own_family(self):
        import fcntl
        self.settings['delay'] = 30
        self.save_settings()
        process = subprocess.Popen([self.busybox, 'ash', str(self.candidate), 'network-resolve'], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        deadline = time.monotonic() + 5
        while not self.net_calls() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(self.net_calls())
        self.group()
        process.kill()
        with self.native.lock.open('rb') as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            deadline = time.monotonic() + 9
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.05)
        process.communicate(timeout=2)
        self.assertTrue(list(self.native.lockdir.glob('.network-read-*')))
        self.network(4)


def suite(runtime):
    return unittest.defaultTestLoader.loadTestsFromTestCase(Runtime if runtime else Static) if not runtime else \
        unittest.TestSuite(Runtime(name) for name, value in Runtime.__dict__.items() if name.startswith('test_') and callable(value))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', action='store_true')
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite(args.runtime))
    raise SystemExit(not result.wasSuccessful())
