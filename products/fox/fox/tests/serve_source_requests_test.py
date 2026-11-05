"""Explicit local-only UI test server: synthetic data, disabled conversion worker."""
import argparse
import json
import os
from pathlib import Path
import socket
import sys
import threading

ROOT=Path(__file__).resolve().parents[1]


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);args=parser.parse_args()
    folder=Path(args.root).resolve(strict=True)
    assert (ROOT.parent/'work').resolve() in folder.parents
    data=folder/'data';assert not data.exists()
    for key in tuple(os.environ):
        if key.startswith(('FOX_','F2A_')):os.environ.pop(key)
    sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(128)
    origin='http://127.0.0.1:'+str(sock.getsockname()[1])
    os.environ.update(FOX_DATA_DIR=str(data),FOX_ADMIN_USERNAME='source-flow-test',
        FOX_PUBLIC_ORIGIN=origin,FOX_CONVERSION_PROFILE='native-project-v1',FOX_VERIFICATION_ENABLED='0')
    sys.path.insert(0,str(ROOT))
    from fox.app import create_app,password_hash
    import uvicorn
    os.environ['FOX_PASSWORD_HASH']=password_hash('synthetic-source-flow-only')
    app=create_app(data,enable_worker=False)
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',log_level='warning'))
    def stop():
        if sys.stdin.readline().strip()=='STOP':server.should_exit=True
    threading.Thread(target=stop,daemon=True).start()
    print(json.dumps({'origin':origin,'synthetic':True,'conversion_worker_enabled':False}),flush=True)
    server.run(sockets=[sock])
