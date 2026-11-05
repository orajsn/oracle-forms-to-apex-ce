"""Local-only saved-output UI fixture, with real package/status/API readers.

Oracle/OPAF transports are authored test doubles in the existing package
fixture. This cannot establish a live import, runtime proof or human acceptance.
"""
import argparse
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import socket
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);args=parser.parse_args()
    folder=Path(args.root).resolve(strict=True)
    if (ROOT.parent/'work').resolve() not in folder.parents:raise ValueError('Test artifacts must stay in product work.')
    # Oracle package fixture paths are deep; use a short, new local scratch
    # root on Windows rather than change system long-path settings.
    base=Path(tempfile.mkdtemp(prefix='foxh-')).resolve()
    for key in tuple(os.environ):
        if key.startswith(('FOX_','F2A_')):os.environ.pop(key)
    sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(128)
    origin='http://127.0.0.1:'+str(sock.getsockname()[1])
    os.environ.update(FOX_DATA_DIR=str(base/'data'),FOX_ADMIN_USERNAME='synthetic-owner',
        FOX_PUBLIC_ORIGIN=origin,FOX_CONVERSION_PROFILE='native-project-v1',FOX_VERIFICATION_ENABLED='0')
    for path in (ROOT,ROOT/'tests',ROOT.parent/'converter',ROOT.parent/'converter/tests',ROOT.parent):
        sys.path.insert(0,str(path))
    import pytest
    from test_project_verification_runtime import actual_release,case,row
    factory=SimpleNamespace(mktemp=lambda name:Path(tempfile.mkdtemp(prefix=name,dir=base)))
    with pytest.MonkeyPatch.context() as patch:
        with redirect_stdout(io.StringIO()):
            built=actual_release.__wrapped__(factory,SimpleNamespace(param=1))
            saved=case.__wrapped__(built,base,patch)
        from test_source_history_api import no_external_actions
        # Uvicorn asks platform.system() during startup. On Windows its first
        # stdlib lookup may spawn `ver`; cache this read-only OS probe before
        # the fixture forbids all subsequent external actions, without an allowlist.
        platform.system()
        no_external_actions.__wrapped__(patch)
        from fox.app import create_app,password_hash
        import uvicorn
        os.environ['FOX_PASSWORD_HASH']=password_hash('synthetic-history-only')
        app=create_app(saved.root,enable_worker=False)
        original=row(saved)
        def jobs():return {str(p.relative_to(saved.job)):hashlib.sha256(p.read_bytes()).hexdigest() for p in saved.job.rglob('*') if p.is_file()}
        original_files=jobs()
        source=next(f for f in saved.snapshot['files'] if f['name'].endswith('.xml'))
        old_name=next(f['form_name'] for f in built.project['forms'] if f['source_name']==source['name'])
        renamed=source['text'].replace('Name="'+old_name+'"','Name="RENAMED_AFTER_RUN"',1)
        if renamed==source['text']:raise ValueError('Fixture form name was not replaced')
        server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',log_level='warning'))
        def stop():
            if sys.stdin.readline().strip()=='STOP':server.should_exit=True
        threading.Thread(target=stop,daemon=True).start()
        print(json.dumps({'origin':origin,'project_id':saved.snapshot['project_id'],
            'project_name':saved.snapshot['project_name'],'run_id':saved.run_id,
            'form_names':[f['form_name'] for f in built.project['forms']],
            'replacement':{'name':source['name'],'text':renamed},
            'synthetic_source':True,'oracle_executed':False,'model_executed':False}),flush=True)
        server.run(sockets=[sock])
        with sqlite3.connect(saved.root/'fox.sqlite3') as db:
            runs=db.execute('SELECT count(*) FROM runs').fetchone()[0]
            accepted=db.execute('SELECT count(*) FROM acceptances').fetchone()[0]
        preserved=original==row(saved) and original_files==jobs() and runs==1 and accepted==0
        (folder/'server-result.json').write_text(json.dumps({'retained_run_preserved':preserved,
            'runs':runs,'acceptances':accepted,'oracle_executed':False,'model_executed':False}),encoding='utf-8')
        if not preserved:raise AssertionError('Saved run changed during read-only history checks')
