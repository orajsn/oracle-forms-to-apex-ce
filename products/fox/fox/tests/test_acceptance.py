import hashlib
import sqlite3
import time
import json
from types import SimpleNamespace

from test_fox import client, signed_in, project
from fox.worker import process_one


def test_arbitrary_unclassified_package_cannot_be_accepted(client):
    c,root=signed_in(client); pid=project(c)
    c.post(f'/api/projects/{pid}/sources',files={'files':('sample.xml',b'<FormModule Name="SYNTHETIC"/>')})
    source_hash=c.get(f'/api/projects/{pid}').json()['inventory']['source_hash']
    artifact=root/'jobs'/'fixture'/'apex-package.zip'
    artifact.parent.mkdir(parents=True);artifact.write_bytes(b'synthetic package fixture')
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',('fixture',pid,source_hash,'REVIEW_REQUIRED','Tests passed',time.time(),time.time(),str(artifact.relative_to(root))))
    url=f'/api/projects/{pid}/runs/fixture'
    body=dict(source_hash=source_hash,business_flow_tested=True,remediation_reviewed=True,notes='Synthetic test: search, detail and missing desktop integration reviewed.')
    assert c.get(url+'/download').status_code==409
    assert c.post(url+'/accept',json={**body,'business_flow_tested':False}).status_code==422
    assert c.post(url+'/accept',json={**body,'source_hash':'0'*64}).status_code==409
    assert c.post(url+'/accept',json={**body,'notes':'   '}).status_code==422
    result=c.post(url+'/accept',json=body)
    # A DB state and arbitrary bytes are not technical release evidence.
    # Positive project/native download coverage uses real package validators
    # and retained proof, not this earlier permissive prototype fixture.
    assert result.status_code==409
    assert c.get(url+'/download').status_code==409
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0]==0
    artifact.write_bytes(b'changed')
    assert c.get(url+'/download').status_code==409


def test_acceptance_cannot_promote_failed_run(client):
    c,root=signed_in(client); pid=project(c)
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',('failed',pid,'0'*64,'ATTENTION','Invalid',time.time(),time.time(),None))
    assert c.post(f'/api/projects/{pid}/runs/failed/accept',json=dict(source_hash='0'*64,business_flow_tested=True,remediation_reviewed=True,notes='Cannot bypass checks')).status_code==409


def test_successful_worker_requires_human_review(client,monkeypatch):
    c,root=signed_in(client);pid=project(c)
    job=root/'jobs'/'fixture';job.mkdir(parents=True)
    (job/'source-snapshot.json').write_text(json.dumps({'conversion_profile': 'legacy-html-prototype-v1'}))
    (job/'release-evidence.json').write_text(json.dumps(dict.fromkeys(['reviewer_approved','sqlcl_valid','import_passed','runtime_smoke_passed','package_reimport_passed'],True)))
    (job/'apex-package.zip').write_bytes(b'synthetic package')
    def db():
        conn=sqlite3.connect(root/'fox.sqlite3');conn.row_factory=sqlite3.Row;return conn
    with db() as conn:
        conn.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',('fixture',pid,'0'*64,'QUEUED','Queued',time.time(),time.time(),None))
    monkeypatch.setenv('FOX_RUN_ADAPTER','synthetic-test-adapter')
    monkeypatch.setattr('fox.worker.subprocess.run',lambda *a,**kw:SimpleNamespace(returncode=0))
    process_one(db,root)
    with db() as conn: assert conn.execute('SELECT state FROM runs').fetchone()[0]=='REVIEW_REQUIRED'
    assert c.get(f'/api/projects/{pid}/runs/fixture/download').status_code==409
