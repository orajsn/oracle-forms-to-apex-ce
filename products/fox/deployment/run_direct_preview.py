#!/usr/bin/env python3
"""Run isolated loopback FOX services using explicit protected configuration.

Requires installed dependencies, Forms/Java, SQLcl and a separately configured
runtime verifier. No public listener, database replay or dependency installation.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


def run(config_path):
    if os.name != 'posix':
        raise ValueError('This preview launcher requires Linux.')
    import fcntl
    config_path=Path(config_path).absolute()
    if config_path.is_symlink() or stat.S_IMODE(config_path.stat().st_mode) != 0o600:
        raise ValueError('Configuration must be a private regular file (0600).')
    cfg=json.loads(config_path.read_text())
    root=Path(cfg['instance_root']); product=Path(cfg['product_root'])
    if not root.is_absolute() or root.resolve()!=root or not root.is_dir():
        raise ValueError('Instance root must be an existing unlinked absolute directory.')
    temporary=root/'tmp'
    if temporary.is_symlink():raise ValueError('Preview scratch directory must not be linked.')
    temporary.mkdir(mode=0o700,exist_ok=True)
    if not temporary.is_dir() or stat.S_IMODE(temporary.stat().st_mode)!=0o700:
        raise ValueError('Preview scratch directory must be private (0700).')
    api_port, converter_port=cfg['api_port'],cfg['converter_port']
    if any(type(p) is not int or not 1024<=p<=65535 for p in (api_port,converter_port)) or api_port==converter_port:
        raise ValueError('Choose distinct unprivileged loopback ports.')
    with (root/'preview.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        env=dict(os.environ)
        env.update({str(k):str(v) for k,v in cfg['environment'].items()})
        env.update(PYTHONPATH=os.pathsep.join(str(product/p) for p in ('fox','converter','.')),
                   PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(temporary),FOX_RUN_ADAPTER='oci-genai',
                   FOX_DATA_DIR=str(root/'data'),FOX_HOSTED_FORMS_QUEUE=str(root/'forms-queue'),
                   FOX_PUBLIC_ORIGIN=f'http://127.0.0.1:{api_port}',
                   F2A_MCP_HOST='127.0.0.1',F2A_MCP_PORT=str(converter_port),
                   F2A_JOBS_ROOT=str(root/'jobs'))
        credentials=json.loads(Path(cfg['credentials_file']).read_text())
        env['FOX_ADMIN_USERNAME']=credentials['username']
        env['FOX_PASSWORD_HASH']=credentials['password_hash']
        env['F2A_MCP_BEARER_TOKEN']=credentials['converter_token']
        commands=[('api',[sys.executable,'-m','uvicorn','fox.app:app','--host','127.0.0.1','--port',str(api_port)]),
                  ('converter',[sys.executable,'-m','forms2apex.server']),
                  ('forms',[sys.executable,'-m','fox.hosted_forms_worker','--queue-root',str(root/'forms-queue'),
                    '--oracle-home',cfg['oracle_home'],'--java-home',cfg['java_home'],'--temp-root',str(root/'forms-tmp'),'--poll-seconds','2']),
                  ('runtime',[sys.executable,str(product/'deployment/poll_direct_runtime.py')])]
        children=[]; logs=[]; stopping=False
        def stop(*args):
            nonlocal stopping
            stopping=True
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        try:
            for name,command in commands:
                log=(root/'logs'/f'{name}-{time.time_ns()}.log').open('xb');logs.append(log)
                child=subprocess.Popen(command,cwd=product,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT)
                children.append(child)
            print(json.dumps({'status':'STARTED','pids':[p.pid for p in children],'origin':env['FOX_PUBLIC_ORIGIN']}),flush=True)
            while not stopping:
                failed=[p.returncode for p in children if p.poll() is not None]
                if failed:
                    raise RuntimeError('Preview service exited; inspect its log before restarting.')
                time.sleep(1)
        finally:
            for child in children:
                if child.poll() is None:child.terminate()
            for child in children:
                try:child.wait(timeout=20)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            for log in logs:log.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True)
    run(parser.parse_args().config)
