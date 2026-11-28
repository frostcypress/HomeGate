#!/usr/bin/env python3
"""DDNS WAN recovery and retry protections for all supported providers."""
import unittest

from project import ROOT


class WANRecovery(unittest.TestCase):
    def test_ddns_wan_event_policy(self):
        from lupa.lua51 import LuaRuntime
        lua=LuaRuntime(unpack_returned_tuples=True)
        policy=lua.execute((ROOT/'project/core/prototype/ddns-state.lua').read_bytes())
        for provider in ('aliyun','cloudflare','dnspod'):
            context=lua.table_from(dict(rule='ddns_a',provider=provider,revision=1,identity='a'*64,
                generation='b'*64,boot='11111111-1111-1111-1111-111111111111',interval=300,wan_sample='c'*64))
            start=policy.begin(context,None,1000)
            last=policy.finish(start,1001,'updated','','confirmed',False)
            self.assertEqual(policy.decision(last,context,1010,False,True,False,True),('waiting',291))
            context['wan_sample']='d'*64
            self.assertEqual(policy.decision(last,context,1010,False,True,False,False),('waiting',291))
            self.assertEqual(policy.decision(last,context,1010,False,True,False,True),('ready',0))
            self.assertEqual(policy.decision(last,context,1010,True,True,False,True),('blocked',0))
            self.assertEqual(policy.decision(last,context,1010,False,False,False,True),('unauthorized',0))
            for error,effect,retryable,expected in (
                ('rate_limit','none',True,('retry_wait',291)),
                ('authentication','none',False,('paused',0)),
                ('timeout','unknown',False,('reconciliation_required',0)),
            ):
                failed=policy.finish(start,1001,'failed',error,effect,retryable)
                self.assertEqual(policy.decision(failed,context,1010,False,True,False,True),expected)
            self.assertNotIn('wan_sample',policy.report(last,context,1010,False,True,False))
            context['wan_sample']=None
            self.assertEqual(policy.decision(last,context,1010,False,True,False,True),('waiting',291))
            last['wan_sample']=None
            context['wan_sample']='d'*64
            self.assertTrue(policy.valid(last))
            self.assertEqual(policy.decision(last,context,1010,False,True,False,True),('ready',0))

            old_address_failure=policy.finish(start,1001,'failed','network_unavailable','none',True)
            self.assertEqual(policy.decision(old_address_failure,context,1010,False,True,False,True),('ready',0))
            context['wan_sample']='c'*64
            self.assertEqual(policy.decision(old_address_failure,context,1010,False,True,False,True),('retry_wait',291))
            context['wan_sample']=None
            no_address=policy.begin(context,None,1000)
            outage=policy.finish(no_address,1001,'failed','network_unavailable','none',True,True)
            self.assertTrue(outage['wan_unavailable'])
            self.assertEqual(policy.decision(outage,context,1010,False,True,False,True),('retry_wait',291))
            context['wan_sample']='d'*64
            self.assertEqual(policy.decision(outage,context,1010,False,True,False,False),('retry_wait',291))
            self.assertEqual(policy.decision(outage,context,1010,False,True,False,True),('ready',0))
            self.assertEqual(policy.decision(outage,context,1010,False,False,False,True),('unauthorized',0))
            self.assertEqual(policy.decision(outage,context,1010,True,True,False,True),('blocked',0))
            outage['wan_unavailable']=None
            self.assertTrue(policy.valid(outage))
            self.assertEqual(policy.decision(outage,context,1010,False,True,False,True),('retry_wait',291))


if __name__ == '__main__':
    unittest.main(verbosity=2)
