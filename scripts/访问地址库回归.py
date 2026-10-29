#!/usr/bin/env python3
"""Pure APNIC counts, range boundaries and bounded dual-stack cache contracts."""
import io,unittest
from pathlib import Path
from lupa.lua51 import LuaRuntime
from project import ROOT
BASE=ROOT/'project/core/prototype'
VALID='2|apnic|20261028|4|19830613|20261028|+1000\napnic|*|ipv4|*|2|summary\napnic|*|ipv6|*|1|summary\napnic|*|asn|*|1|summary\napnic|CN|ipv4|198.51.100.0|6|20261028|allocated\napnic|CN|ipv6|2001:db8:abcd::|48|20261028|assigned\napnic|US|ipv4|203.0.113.0|256|20261028|allocated\napnic|CN|asn|64496|1|20261028|allocated\n'
class Region(unittest.TestCase):
 def setUp(self):
  self.lua=LuaRuntime(unpack_returned_tuples=True);self.lua.execute('arg={[0]=...}',str(BASE/'access-region.lua'))
  self.model=self.lua.execute('return assert(loadfile(...))()',str(BASE/'access-region.lua'))
  self.invoke=self.lua.eval('function(model,body,cache,now) local pos=1;local input={read=function(self,n)if pos>#body then return nil end;local v=body:sub(pos,pos+n-1);pos=pos+#v;return v end};local parts={};local out={write=function(self,v)parts[#parts+1]=v;return true end};local ok,result=pcall(cache and model.cache or model.parse,input,out,now or 1793190000);return ok,table.concat(parts),result end')
 def parse(self,body=VALID):return self.invoke(self.model,body,False,None)
 def test_exact_non_power_of_two_v4_and_native_v6(self):
  ok,body,d=self.parse();self.assertTrue(ok,d);self.assertIn('198.51.100.0/30\n198.51.100.4/31\n',body);self.assertIn('2001:0db8:abcd:0000:0000:0000:0000:0000/48',body);self.assertNotIn('203.0.113.',body);self.assertEqual(d['ipv4'],2);self.assertEqual(d['ipv6'],1)
 def test_truncated_and_bad_counts_never_form_cache(self):
  for body in [VALID.rsplit('apnic|CN|asn',1)[0],VALID.replace('|4|19830613','|5|19830613'),VALID.replace('|ipv4|*|2|summary','|ipv4|*|3|summary'),VALID.replace('apnic|*|asn|*|1|summary\n','')]:self.assertFalse(self.parse(body)[0])
 def test_country_status_and_dual_stack_constraints(self):
  for body in [VALID.replace('|CN|ipv6|','|US|ipv6|'),VALID.replace('|CN|ipv4|','|US|ipv4|'),VALID.replace('|assigned','|reserved')]:self.assertFalse(self.parse(body)[0])
 def test_bad_networks_and_overflow_rejected(self):
  for old,new in [('198.51.100.0|6','255.255.255.254|6'),('198.51.100.0|6','198.051.100.0|6'),('2001:db8:abcd::|48','2001:db8:abcd::1|48'),('2001:db8:abcd::|48','::ffff:192.0.2.0|120'),('198.51.100.0|6','198.51.100.0|4294967296')]:self.assertFalse(self.parse(VALID.replace(old,new))[0],new)
 def test_invalid_header_summary_duplicates_and_empty(self):
  for body in ['',VALID.replace('2|apnic','2|other',1),VALID.replace('apnic|*|ipv4|*|2|summary\n','apnic|*|ipv4|*|2|summary\napnic|*|ipv4|*|2|summary\n'),VALID.replace('|allocated','|reserved').replace('|assigned','|reserved')]:self.assertFalse(self.parse(body)[0])
 def test_cache_fresh_stale_and_exact_geo_output(self):
  ok,body,_=self.parse();self.assertTrue(ok)
  ok,geo,d=self.invoke(self.model,body,True,1793190000);self.assertTrue(ok,d);self.assertFalse(d['stale']);self.assertIn('198.51.100.4/31 1;',geo)
  self.assertTrue(self.invoke(self.model,body,True,1793190000+604801)[2]['stale'])
 def test_cache_corruption_and_future_clock_refused(self):
  _,body,_=self.parse()
  for b in [body[:-5],body.replace('|2|1','|3|1'),body+'; return 200;\n',body+'198.51.100.0/30\n']:self.assertFalse(self.invoke(self.model,b,True,1793190000)[0])
  self.assertFalse(self.invoke(self.model,body,True,1793180000)[0])
 def test_line_and_total_bytes_are_bounded(self):
  self.assertFalse(self.parse('#'+'x'*1048577+'\n'+VALID)[0])
  f=self.lua.eval('function(model) local n=0;local stream={read=function(self,size)n=n+size;if n>model.limit+8192 then error("unbounded")end;return string.rep("#",size-1).."\\n"end};return pcall(model.parse,stream,{write=function()end},1793190000)end')
  self.assertFalse(f(self.model)[0])
if __name__=='__main__':unittest.main(verbosity=2)
