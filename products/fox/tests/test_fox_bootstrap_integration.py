"""Opt-in real pinned setup runtime; no Oracle, app import or cloud calls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import urllib.request

import pytest

ROOT=Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('checkpoint',['absent','artifacts_downloaded','complete_tree_without_receipt'])
def test_real_os_python_bootstrap_cold_warm_and_tamper(tmp_path,checkpoint):
    if os.name!='posix' or os.geteuid()==0:pytest.skip('actual nonroot Linux required')
    archive=os.environ.get('FOX_BOOTSTRAP_PYTHON_ARCHIVE');wheel=os.environ.get('FOX_BOOTSTRAP_XML_WHEEL')
    if not archive or not wheel:pytest.skip('explicit pinned upstream test artifacts required')
    tmp_path.chmod(0o700);seed=tmp_path/'seed';seed.mkdir(mode=0o700)
    for source,name in ((archive,'python.tgz'),(wheel,'xml.whl')):
        shutil.copyfile(source,seed/name);(seed/name).chmod(0o600)
    runtime=tmp_path/'managed'
    retained=None
    if checkpoint=='artifacts_downloaded':
        spec=importlib.util.spec_from_file_location('bootstrap_resume_test',ROOT/'deployment/bootstrap_runtime.py')
        b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
        runtime.mkdir(mode=0o700);b.new(runtime/'intent.json',b.canonical(b.manifest()))
        for source,component in ((seed/'python.tgz',b.PYTHON),(seed/'xml.whl',b.XML)):
            raw=source.read_bytes();assert b.sha(raw)==component['sha256']
            b.new(runtime/component['name'],raw)
        retained=(runtime/'python.tar.gz').stat()
    args=['/bin/bash',str(ROOT/'scripts/install-fox.sh'),'--runtime-root',str(runtime),
          '--python-archive',str(seed/'python.tgz'),'--xml-wheel',str(seed/'xml.whl'),'--prepare-only']
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}
    def run():return subprocess.run(args,env=env,cwd=str(ROOT),capture_output=True,text=True,timeout=180,umask=0o077)
    if checkpoint=='complete_tree_without_receipt':
        initial=run();assert initial.returncode==0,initial.stdout+initial.stderr
        retained=(runtime/'python/bin/python3.12').stat()
        (runtime/'complete.json').rename(tmp_path/'retained-complete.json')
    cold=run();assert cold.returncode==0,cold.stdout+cold.stderr
    first=json.loads(cold.stdout);assert not first['conversion_ready']
    if checkpoint=='complete_tree_without_receipt':
        assert first['continued']=='COMPLETE_TREE_RECONCILED' and first['reused']
        after=(runtime/'python/bin/python3.12').stat()
        assert (after.st_ino,after.st_mtime_ns)==(retained.st_ino,retained.st_mtime_ns)
        retained=None
    else:assert first['reused'] is False
    if retained:
        after=(runtime/'python.tar.gz').stat()
        assert (after.st_ino,after.st_mtime_ns)==(retained.st_ino,retained.st_mtime_ns)
    before=(runtime/'complete.json').read_bytes()
    warm=run();assert warm.returncode==0,warm.stdout+warm.stderr
    second=json.loads(warm.stdout);assert second['reused'] is True
    assert (runtime/'complete.json').read_bytes()==before
    forged=json.loads(before);forged['ready']=True
    (tmp_path/'forged-complete.json').write_text(json.dumps(forged))
    (runtime/'complete.json').write_bytes((tmp_path/'forged-complete.json').read_bytes())
    rejected=run();assert rejected.returncode==2
    assert json.loads(rejected.stdout)['code']=='RUNTIME_COMPLETION_CHANGED'
    (runtime/'complete.json').write_bytes(before)  # restore this owned fixture only
    probe=subprocess.run([first['python'],'-I','-B','-c',
        "import sys,defusedxml,json;print(json.dumps([sys.version.split()[0],defusedxml.__version__]))"],
        env=env,capture_output=True,text=True,timeout=20)
    assert json.loads(probe.stdout)==['3.12.16','0.7.1']
    # Exercise the actual launcher through exec into the real wizard, then
    # close only this owned process. The private code never enters assertions.
    child=subprocess.Popen(args[:-1],env=env,cwd=str(ROOT),stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        readable,_,_=select.select([child.stdout],[],[],30)
        assert readable,'launcher did not report setup'
        startup=json.loads(child.stdout.readline())
        assert startup['setup_url'].startswith('http://127.0.0.1:')
        assert not startup['conversion_ready']
        with urllib.request.urlopen(startup['setup_url'],timeout=10) as response:
            assert response.status==200 and b'Administrator setup' in response.read()
    finally:
        if child.poll() is None:child.send_signal(signal.SIGINT)
        child.communicate(timeout=10)
    assert child.returncode==0
    # Retain a deliberately altered private test cache; no altered code may run.
    marker=tmp_path/'must-not-run'
    source=runtime/'python/lib/python3.12/site-packages/defusedxml/__init__.py'
    source.write_text("from pathlib import Path\nPath({!r}).write_text('unsafe')\n".format(str(marker)))
    failed=run();assert failed.returncode==2
    assert json.loads(failed.stdout)['code'] in ('RUNTIME_TREE_FILE_CHANGED','RUNTIME_TREE_CONTENT_CHANGED')
    assert not marker.exists() and (runtime/'complete.json').read_bytes()==before
