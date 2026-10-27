"""Fixed image reader tests; actual filesystem measurement needs nonroot POSIX."""
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT/'fox', ROOT/'converter'):
    if str(folder) not in sys.path:
        sys.path.insert(0,str(folder))
from qa.operator import fresh_image as image

POSIX = os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()>0


def filesystem_snapshot(root):
    result={}
    for path in (root,*sorted(root.rglob('*'))):
        info=path.lstat()
        result[str(path)]=(info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,
                          info.st_mtime_ns,info.st_ctime_ns,
                          hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else None)
    return result


class PureImageTests(unittest.TestCase):
    def test_import_is_inert(self):
        code="""import importlib,pathlib,socket,sqlite3,subprocess,sys\nfrom unittest.mock import patch\nr=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(r))\ndef no(*a,**k):raise AssertionError('IMPORT_EFFECT')\nwith patch.object(pathlib.Path,'mkdir',side_effect=no),patch.object(sqlite3,'connect',side_effect=no),patch.object(subprocess,'run',side_effect=no),patch.object(socket.socket,'connect',side_effect=no):\n importlib.import_module('qa.operator.fresh_image')\nassert 'fox.app' not in sys.modules\nprint('INERT')\n"""
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(ROOT)],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'INERT')

    def test_wrong_provider_is_rejected_before_property_or_process(self):
        touched=[]
        class CallerObject:
            @property
            def configuration(self):
                touched.append(True);raise AssertionError('CALLBACK_BEFORE_AUTHORITY')
        with patch.object(subprocess,'run',side_effect=AssertionError('NO_PROCESS')):
            for value in (None,{},CallerObject()):
                with self.subTest(value=type(value).__name__),self.assertRaises(image.ImagePayloadError):
                    image.measure_runtime_payload(value,{})
        self.assertEqual(touched,[])

    def test_generated_reader_uses_exact_reviewed_core(self):
        program=image.reader_program()
        nodes={node.name:node for node in ast.parse(program).body if isinstance(node,ast.FunctionDef)}
        expected=ast.parse(inspect.getsource(image.measure_files)).body[0]
        self.assertEqual(ast.dump(nodes['measure_files'],include_attributes=False),ast.dump(expected,include_attributes=False))
        self.assertNotIn('subprocess',program)
        compile(program,'<reviewed-image-reader>','exec')
        self.assertEqual(set(image.ROOTS),{'fox','converter'})
        self.assertTrue(all(PurePosixPath(path).is_absolute() for path in image.PYTHON.values()))

    def test_packet_duplicate_nonfinite_and_oversize_reject(self):
        for raw in (b'{"role":"fox","role":"converter"}',b'{"x":NaN}',b' '*1_000_001):
            with self.subTest(length=len(raw)),self.assertRaises(image.ImagePayloadError):
                image.parse(raw)


@unittest.skipUnless(POSIX,'Actual O_NOFOLLOW filesystem checks require nonroot POSIX')
class FileMeasurementTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='fip-');self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.code,self.ui=self.root/'code',self.root/'ui'
        self.code.mkdir();(self.ui/'assets').mkdir(parents=True)
        files={self.code/'__init__.py':b'',self.code/'app.py':b'REVIEWED PYTHON SOURCE\n',
               self.ui/'index.html':b'<!-- synthetic reader fixture, not a product -->',
               self.ui/'assets/unit.js':b'/* reviewed synthetic asset */'}
        for path,raw in files.items():path.write_bytes(raw)
        self.expected={str(path):hashlib.sha256(raw).hexdigest() for path,raw in files.items()}

    def measure(self):
        return image.measure_files((str(self.code),str(self.ui)),self.expected)

    def test_real_tree_hash_matches_without_any_change(self):
        before=filesystem_snapshot(self.root)
        with patch.object(subprocess,'run',side_effect=AssertionError('NO_PROCESS')), \
             patch.object(socket.socket,'connect',side_effect=AssertionError('NO_NETWORK')):
            result=self.measure()
        self.assertEqual(result['file_count'],len(self.expected))
        self.assertEqual(result['measured_sha256'],hashlib.sha256(image.canonical(self.expected)).hexdigest())
        self.assertEqual(filesystem_snapshot(self.root),before)

    def test_changed_missing_extra_file_and_extra_directory_reject(self):
        for variant in ('changed','missing','extra','directory'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory(prefix='fip-copy-') as directory:
                destination=Path(directory)/'copy';shutil.copytree(self.root,destination)
                expected={str(destination/Path(name).relative_to(self.root)):sha for name,sha in self.expected.items()}
                path=destination/'code/app.py'
                if variant=='changed':path.write_bytes(b'UNREVIEWED SOURCE')
                elif variant=='missing':path.unlink()
                elif variant=='extra':(destination/'code/unknown.py').write_bytes(b'extra')
                else:(destination/'code/unknown').mkdir()
                before=filesystem_snapshot(destination)
                with self.assertRaises(image.ImagePayloadError):
                    image.measure_files((str(destination/'code'),str(destination/'ui')),expected)
                self.assertEqual(filesystem_snapshot(destination),before)

    def test_symlink_and_hardlink_are_not_followed(self):
        original=self.code/'app.py'
        retained=self.root/'retained.py';original.rename(retained)
        original.symlink_to(retained)
        with self.assertRaises(image.ImagePayloadError):self.measure()
        original.unlink();os.link(retained,original)
        with self.assertRaises(image.ImagePayloadError):self.measure()

    def test_cache_and_traversal_cannot_be_declared_as_reviewed(self):
        for name in (str(self.code/'__pycache__/app.pyc'),str(self.code/'../ui/index.html')):
            with self.subTest(name=name),self.assertRaises(image.ImagePayloadError):
                image.measure_files((str(self.code),str(self.ui)),{name:'a'*64})
        (self.code/'__pycache__').mkdir()
        with self.assertRaises(image.ImagePayloadError):self.measure()

    def test_reader_enforces_file_and_total_byte_limits(self):
        with patch.object(image,'MAX_FILE',1),self.assertRaises(image.ImagePayloadError):self.measure()
        with patch.object(image,'MAX_TOTAL',1),self.assertRaises(image.ImagePayloadError):self.measure()

    def test_file_changed_later_in_scan_cannot_use_earlier_hash(self):
        real_scandir=os.scandir
        def altered_scandir(path):
            # Code root is visited after UI (LIFO); mutate an already sampled
            # UI file without changing its directory entry or file length.
            if Path(path)==self.code:
                file=self.ui/'index.html';raw=file.read_bytes();file.write_bytes(b'X'+raw[1:])
            return real_scandir(path)
        with patch.object(os,'scandir',side_effect=altered_scandir),self.assertRaises(image.ImagePayloadError):
            self.measure()


if __name__=='__main__':unittest.main()
