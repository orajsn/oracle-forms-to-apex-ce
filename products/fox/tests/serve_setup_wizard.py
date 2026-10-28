"""Owned local browser-test server, with explicit stdin shutdown; no Oracle."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

def main():
    root=Path(__file__).resolve().parents[1]
    sys.path[:0]=[str(root),str(root/'fox'),str(root/'converter')]
    from qa.operator.setup_wizard import Controller,create_server
    controller=Controller();server,token=create_server(controller=controller)
    directory=tempfile.mkdtemp(prefix='fox-setup-browser-')
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
    thread.start()
    print(json.dumps({'url':'http://127.0.0.1:'+str(server.server_port),
        'token':token,'installation_root':directory+'/instance','pid':os.getpid()}),flush=True)
    try:sys.stdin.readline()
    finally:
        server.shutdown();server.server_close();thread.join(10)
        print(json.dumps({'closed':not thread.is_alive(),'state':controller.recheck(),
                         'synthetic_test_state_retained':True}),flush=True)

if __name__=='__main__':main()
