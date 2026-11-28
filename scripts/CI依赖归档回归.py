#!/usr/bin/env python3
"""Pinned download failover, publication and actual recipe refusal contracts."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch
from project import ROOT

spec=importlib.util.spec_from_file_location('busybox_archive',ROOT/'scripts/准备BusyBox归档.py')
archive=importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)

class Archive(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='homegate pinned archive ')
        self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)
        self.output=self.base/'build/busybox-runtime/busybox-1.33.2.tar.bz2'
        self.payload=b'fixture verified archive\x00\n';self.calls=[]
        self.original_sha=archive.SHA
        self.a=patch.object(archive,'ARCHIVE',self.output);self.a.start();self.addCleanup(self.a.stop)
        self.b=patch.object(archive,'SHA',hashlib.sha256(self.payload).hexdigest());self.b.start();self.addCleanup(self.b.stop)
    def invoke(self,effects):
        def run(command,**kwargs):
            self.calls.append((command,kwargs));pending=Path(command[command.index('--output')+1])
            effect=effects[len(self.calls)-1]
            if isinstance(effect,Exception):raise effect
            code,data=effect;pending.write_bytes(data)
            return subprocess.CompletedProcess(command,code)
        with patch.object(archive.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            result=archive.prepare()
        if self.output.parent.exists():self.assertEqual(list(self.output.parent.glob('.busybox-download-*')),[])
        return result
    def seed(self,data):
        self.output.parent.mkdir(parents=True);self.output.write_bytes(data)
    def test_pinned_sources_limits_TLS_and_no_version_or_hash_change(self):
        self.assertEqual(self.original_sha,'6843ba7977081e735fa0fdb05893e3c002c8c5ad7c9c80da206e603cc0ac47e7')
        self.assertEqual(archive.URLS,('https://sources.openwrt.org/busybox-1.33.2.tar.bz2','https://busybox.net/downloads/busybox-1.33.2.tar.bz2'))
        self.assertEqual(self.invoke([(0,self.payload)]),0)
        command,kwargs=self.calls[0]
        for flag in ('--fail','--location','--proto','--proto-redir','--max-filesize'):self.assertIn(flag,command)
        self.assertEqual(command[command.index('--max-time')+1],'45');self.assertEqual(kwargs,dict(timeout=50,check=False))
        self.assertNotIn('--insecure',command);self.assertNotIn('-k',command)
    def test_valid_cache_is_verified_without_download_or_inode_replacement(self):
        self.seed(self.payload);inode=self.output.stat().st_ino
        self.assertEqual(self.invoke([]),0);self.assertEqual(self.calls,[]);self.assertEqual(self.output.stat().st_ino,inode)
    def test_corrupt_cache_is_replaced_only_by_verified_download(self):
        self.seed(b'old invalid cache')
        self.assertEqual(self.invoke([(0,self.payload)]),0);self.assertEqual(self.output.read_bytes(),self.payload)
    def test_TLS_transport_failure_tries_other_fixed_source(self):
        self.assertEqual(self.invoke([(28,b'partial TLS response'),(0,self.payload)]),0)
        self.assertEqual([c[-1] for c,k in self.calls],list(archive.URLS));self.assertEqual(self.output.read_bytes(),self.payload)
    def test_wrong_hash_or_oversize_is_never_published(self):
        self.assertEqual(self.invoke([(0,b'wrong archive'),(0,b'x'*(archive.LIMIT+1))]),1)
        self.assertFalse(self.output.exists());self.assertEqual(len(self.calls),2)
    def test_outer_timeout_is_bounded_and_failover_cleans_partial(self):
        error=subprocess.TimeoutExpired('curl',50)
        self.assertEqual(self.invoke([error,(0,self.payload)]),0);self.assertEqual(len(self.calls),2)
    def test_all_sources_fail_preserves_old_cache_and_does_not_retry_forever(self):
        self.seed(b'KEEP OLD CACHE')
        self.assertEqual(self.invoke([(28,b'partial'),(22,b'error')]),1)
        self.assertEqual(self.output.read_bytes(),b'KEEP OLD CACHE');self.assertEqual(len(self.calls),2)
    def test_symlink_cache_is_refused_and_arguments_do_not_enable_alternate_paths(self):
        outside=self.base/'outside';outside.write_bytes(b'KEEP');self.output.parent.mkdir(parents=True);self.output.symlink_to(outside)
        self.assertEqual(self.invoke([]),1);self.assertEqual(self.calls,[]);self.assertEqual(outside.read_bytes(),b'KEEP')
        p=subprocess.run([sys.executable,str(ROOT/'scripts/准备BusyBox归档.py'),'--output','outside'],capture_output=True,timeout=5)
        self.assertEqual(p.returncode,2)
    def test_both_actual_recipes_stop_before_extraction_on_archive_failure(self):
        extended=(ROOT/'scripts/准备扩展CI环境.sh').read_text()
        workflow=(ROOT/'.github/workflows/编译发布.yml').read_text()
        begin=workflow.index('          mkdir -p build/busybox-runtime\n')
        block=workflow[begin:workflow.index('          tar -xjf ',begin)]
        recipes=[extended[extended.index('mkdir -p build/busybox-runtime\n'):extended.index('tar -xjf ')],textwrap.dedent(block)]
        bindir=self.base/'bin';bindir.mkdir();stub=bindir/'python3';stub.write_text('#!/bin/sh\nexit 19\n');stub.chmod(0o755)
        for body in recipes:
            self.assertIn('python3 scripts/准备BusyBox归档.py',body)
            self.assertIn(self.original_sha,body)
            self.assertNotIn('busybox.net',body)
            marker=self.base/'MUST-NOT-EXTRACT'
            p=subprocess.run(['sh','-eu','-c',body+'\nprintf bad > "'+str(marker)+'"'],cwd=self.base,
                env={**os.environ,'PATH':str(bindir)+':'+os.environ['PATH']},capture_output=True,timeout=5)
            self.assertEqual(p.returncode,19,p.stderr);self.assertFalse(marker.exists())

if __name__=='__main__':unittest.main(verbosity=2)
