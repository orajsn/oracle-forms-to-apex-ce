import hashlib
import json
from pathlib import Path

import pytest

from fox.intake import checked_source, inventory
from fox.opaf import OpafClient, OpafError, stage_job, WORKFLOW_ID, ConverterClient


def fixture(tmp_path):
    job=tmp_path/('fox-'+'a'*20);job.mkdir()
    shared=tmp_path/'shared';shared.mkdir()
    source=checked_source('synthetic.xml',b'<FormModule Name="SYNTHETIC"><Block Name="ORDERS"/></FormModule>')
    snapshot={'files':[source],'source_hash':inventory([source])['source_hash']}
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    return job,shared,snapshot


def test_stages_only_readable_source_and_refuses_replay(tmp_path):
    job,shared,snapshot=fixture(tmp_path)
    target=stage_job(job,shared)
    assert not (target/'source-snapshot.json').exists()
    manifest=json.loads((target/'intake/manifest.json').read_text())
    raw=(target/'intake/synthetic.xml').read_bytes()
    assert manifest['files'][0]['sha256']==hashlib.sha256(raw).hexdigest()
    assert manifest['source_manifest_sha256']==snapshot['source_hash']
    with pytest.raises(OpafError,match='already handed off'): stage_job(job,shared)


def test_changed_source_and_oversize_fail_before_staging(tmp_path):
    job,shared,snapshot=fixture(tmp_path)
    snapshot['files'][0]['text']='<FormModule Name="CHANGED"/>'
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    with pytest.raises(ValueError,match='changed'):stage_job(job,shared)
    assert list(shared.iterdir())==[]
    snapshot['files'][0]['text']='x'*300001
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    with pytest.raises(ValueError,match='300 KB'):stage_job(job,shared)


def test_pinned_tls_blocks_credentials_before_request(monkeypatch):
    class Connection:
        sock=None
        def __init__(self,*a,**k):self.sock=self
        def connect(self):pass
        def getpeercert(self,**k):return b'wrong certificate'
        def request(self,*a,**k):pytest.fail('Credentials must not be sent before pin check')
        def close(self):pass
    monkeypatch.setattr('fox.opaf.http.client.HTTPSConnection',Connection)
    with pytest.raises(OpafError,match='TLS identity'):
        OpafClient('https://localhost:8080/agentFactory','test','test').run('fox-'+'a'*20)


def test_documented_protocol_no_retry_and_exact_workflow(monkeypatch):
    calls=[]
    def request(self,method,path,payload=None,login=False):
        calls.append((method,path,payload,login)); return {'ok':True}
    monkeypatch.setattr(OpafClient,'_request',request)
    client=OpafClient('https://localhost:8080/agentFactory','test','test')
    assert client.run('fox-'+'a'*20)=={'ok':True}
    assert calls[0][0:2]==('GET','/v1/loginValidation')
    assert calls[1][0:2]==('POST','/v1/agentBuilder/run/'+WORKFLOW_ID)
    assert json.loads(calls[1][2]['message'])=={'job_id':'fox-'+'a'*20}
    assert len(calls)==2


@pytest.mark.parametrize('url',['http://localhost/agentFactory','https://u:p@localhost/agentFactory','https://localhost/other'])
def test_bad_base_url_rejected(url):
    with pytest.raises(ValueError):OpafClient(url,'u','p')

@pytest.mark.parametrize('url',['http://example.com:8091','https://127.0.0.1:8091','http://127.0.0.1:8092','http://u:p@127.0.0.1:8091'])
def test_gateway_cannot_send_token_off_vm(url):
    with pytest.raises(OpafError):ConverterClient(url,'x'*48)
