#!/usr/bin/env python3
"""Run a direct-OCI format-only preview: API and optional native extraction.

No converter/runtime worker, target database credentials, dependency installation,
public listener or automatic retry. Oracle tooling remains an explicit prerequisite.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

FIELDS={'schema_version','instance_root','product_root','api_port',
        'ui_credentials_file','design_profile_file','sqlcl_path','forms'}


def absolute(value):
    path=Path(value)
    if not path.is_absolute() or '..' in path.parts or path.resolve()!=path:
        raise ValueError('Use absolute, unlinked configured paths.')
    return path


def private_json(value):
    path=absolute(value)
    if not path.is_file() or path.stat().st_size>65536:
        raise ValueError('A bounded private configuration file is required.')
    info=path.stat()
    if os.name=='posix' and (info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600):
        raise ValueError('Configuration files must belong to the operator and have mode0600.')
    def unique(pairs):
        result={}
        for key,item in pairs:
            if key in result:raise ValueError('Duplicate configuration property.')
            result[key]=item
        return result
    try:return json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=unique)
    except (UnicodeError,ValueError):raise ValueError('Private configuration is not valid JSON.') from None


def configuration(path):
    value=private_json(path)
    if type(value) is not dict or set(value)!=FIELDS or type(value['schema_version']) is not int or value['schema_version']!=1:
        raise ValueError('Unsupported export-preview configuration.')
    for key in ('instance_root','product_root','ui_credentials_file','design_profile_file','sqlcl_path'):
        value[key]=absolute(value[key])
    root,product=value['instance_root'],value['product_root']
    if not root.is_dir() or not product.is_dir():raise ValueError('Existing instance and packaged product directories are required.')
    if os.name=='posix' and (root.stat().st_uid!=os.getuid() or stat.S_IMODE(root.stat().st_mode)!=0o700):
        raise ValueError('The instance directory must be operator-owned mode0700.')
    for path in (product/'fox/fox/app.py',product/'fox/dist/index.html',value['design_profile_file'],value['sqlcl_path']):
        if path.is_symlink() or not path.is_file():raise ValueError('Packaged API/UI, provider profile and SQLcl must be present.')
    if type(value['api_port']) is not int or not 1024<=value['api_port']<=65535:
        raise ValueError('Use an unprivileged loopback port.')
    credentials=private_json(value['ui_credentials_file'])
    if (type(credentials) is not dict or set(credentials)!={'username','password_hash'}
            or type(credentials['username']) is not str or not 1<=len(credentials['username'])<=180
            or any(ord(c)<32 for c in credentials['username'])
            or type(credentials['password_hash']) is not str
            or not re.fullmatch('[a-f0-9]{32}:[a-f0-9]{128}',credentials['password_hash'])):
        raise ValueError('Provide only the UI username and supported password hash, without database credentials.')
    forms=value['forms']
    if forms is not None:
        if type(forms) is not dict or set(forms)!={'oracle_home','java_home'}:raise ValueError('Invalid Forms tool configuration.')
        value['forms']={key:absolute(item) for key,item in forms.items()}
        if not all(path.is_dir() for path in value['forms'].values()):raise ValueError('Existing Oracle Forms and Java directories are required.')
    return value,credentials


def launch_plan(value,credentials,*,environ=None,python=None):
    root,product=value['instance_root'],value['product_root']
    env={key:item for key,item in (os.environ if environ is None else environ).items()
         if not key.startswith(('FOX_','F2A_')) and key!='PYTHONHOME'}
    env.update(PYTHONPATH=os.pathsep.join(str(product/p) for p in ('fox','converter')),
        PYTHONDONTWRITEBYTECODE='1',TMPDIR=str(root/'tmp'),
        FOX_DATA_DIR=str(root/'data'),FOX_PUBLIC_ORIGIN=f"http://127.0.0.1:{value['api_port']}",
        FOX_RUN_ADAPTER='oci-genai',FOX_CONVERSION_PROFILE='native-project-v1',
        FOX_DEFAULT_DELIVERY_MODE='apexlang_package',
        FOX_PROTOTYPE_PROFILE_FILE=str(value['design_profile_file']),
        FOX_EXPORT_SQLCL_PATH=str(value['sqlcl_path']),FOX_PROTOTYPE_AUTHORITY_ENABLED='0',
        FOX_ADMIN_USERNAME=credentials['username'],FOX_PASSWORD_HASH=credentials['password_hash'])
    python=python or sys.executable
    commands=[('api',[python,'-m','uvicorn','fox.app:app','--host','127.0.0.1','--port',str(value['api_port'])])]
    if value['forms'] is not None:
        env['FOX_HOSTED_FORMS_QUEUE']=str(root/'forms-queue')
        commands.append(('forms',[python,'-m','fox.hosted_forms_worker','--queue-root',str(root/'forms-queue'),
            '--oracle-home',str(value['forms']['oracle_home']),'--java-home',str(value['forms']['java_home']),
            '--temp-root',str(root/'forms-tmp'),'--poll-seconds','2']))
    return env,commands


def run(path):
    if os.name!='posix' or os.geteuid()==0:raise ValueError('Run this preview as a nonroot Linux operator.')
    import fcntl
    value,credentials=configuration(path);root=value['instance_root']
    env,commands=launch_plan(value,credentials)
    os.umask(0o077)
    # Same lock as the existing lab launcher: never run two owners for one store.
    descriptor=os.open(str(root/'preview.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Another preview supervisor owns this instance; no services started.') from None
        folders=['data','tmp','logs']+(['forms-queue','forms-tmp'] if value['forms'] else [])
        for name in folders:
            folder=root/name
            if folder.is_symlink():raise ValueError('Instance storage must not be linked.')
            folder.mkdir(mode=0o700,exist_ok=True)
            if not folder.is_dir() or stat.S_IMODE(folder.stat().st_mode)!=0o700:raise ValueError('Instance storage must be private directories.')
        children=[];logs=[];stopping=False
        def stop(*_):
            nonlocal stopping
            stopping=True
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        try:
            for name,command in commands:
                log=(root/'logs'/f'export-{name}-{time.time_ns()}.log').open('xb');logs.append(log)
                children.append(subprocess.Popen(command,cwd=value['product_root'],env=env,
                    stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT))
            print(json.dumps({'status':'STARTED','delivery_mode':'apexlang_package',
                'services':[name for name,_ in commands],'pids':[p.pid for p in children],
                'origin':env['FOX_PUBLIC_ORIGIN'],'database_runtime_services_started':False}),flush=True)
            while not stopping:
                if any(child.poll() is not None for child in children):
                    raise RuntimeError('An export-preview service exited. Inspect its private log before restarting.')
                time.sleep(1)
        finally:
            for child in children:
                if child.poll() is None:child.terminate()
            for child in children:
                try:child.wait(timeout=15)
                except subprocess.TimeoutExpired:child.kill();child.wait()
            for log in logs:log.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        value,credentials=configuration(args.config);env,commands=launch_plan(value,credentials)
        print(json.dumps({'status':'CONFIGURATION_PRESENT','delivery_mode':'apexlang_package',
            'services':[name for name,_ in commands],'origin':env['FOX_PUBLIC_ORIGIN'],
            'database_runtime_services_started':False,'services_started':False}))
    else:run(args.config)
