"""Isolated real FOX HTTP server; synthetic native XML only, no Oracle proof.

The queue, redaction, receipts, source history, SQLite and HTTP routes are real.
Only Oracle's native exporter is replaced by the existing paired XML fixture.
"""
import argparse
import json
import os
from pathlib import Path
import threading

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--port', type=int, required=True)
args = parser.parse_args()
root = args.root.resolve()
root.mkdir(parents=True, exist_ok=False)
os.environ.update(FOX_DATA_DIR=str(root / 'data'),
                  FOX_HOSTED_FORMS_QUEUE=str(root / 'queue'),
                  FOX_PUBLIC_ORIGIN=f'http://127.0.0.1:{args.port}',
                  FOX_ADMIN_USERNAME='synthetic-hosted-qa',
                  FOX_CONVERSION_PROFILE='native-project-v1')

from fox.app import create_app, password_hash
from fox.hosted_forms_jobs import HostedFormsJobs
from fox.native_preparation import prepare_native_source
from test_native_preparation import factory
import uvicorn

os.environ['FOX_PASSWORD_HASH'] = password_hash('synthetic-local-test-only')
app = create_app(root / 'data', enable_worker=False)
queue = HostedFormsJobs(root / 'queue')
stop = threading.Event()


def process():
    while not stop.wait(0.1):
        for jid in queue.list_pending():
            result = queue.process(jid, prepare=lambda source, output, **kw:
                                   prepare_native_source(source, output,
                                                         backend_factory=factory(), **kw))
            print(json.dumps({'synthetic_native_only': True, 'job_id': jid,
                              'status': result['status']}), flush=True)


thread = threading.Thread(target=process, daemon=True)
thread.start()
try:
    uvicorn.run(app, host='127.0.0.1', port=args.port, log_level='info')
finally:
    stop.set()
    thread.join(timeout=5)
