import hashlib
from types import SimpleNamespace
import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient
from forms2apex.fox_gateway import attach_routes, stage_snapshot

def snapshot(text='<FormModule Name="SYNTHETIC"/>'):
    digest=hashlib.sha256(text.encode()).hexdigest()
    return {'source_hash':hashlib.sha256(('synthetic.xml:'+digest).encode()).hexdigest(),'files':[{'name':'synthetic.xml','text':text,'sha256':digest}]}

def test_stage_immutable_and_hashed(tmp_path):
    jid='fox-'+'a'*20
    assert stage_snapshot(tmp_path,jid,snapshot())['state']=='INTAKE_READY'
    with pytest.raises(FileExistsError):stage_snapshot(tmp_path,jid,snapshot())

@pytest.mark.parametrize('text',['<!DOCTYPE x [<!ENTITY x "bad">]><x>&x;</x>','<broken>','<x>password=notasecret</x>','INSERT INTO table1 VALUES (1);'])
def test_unsafe_sources_never_stage(tmp_path,text):
    with pytest.raises(Exception):stage_snapshot(tmp_path,'fox-'+'a'*20,snapshot(text))
    assert not list(tmp_path.iterdir())

def test_custom_routes_require_auth(tmp_path):
    routes=[]
    class MCP:
        def custom_route(self,path,methods,**kwargs):
            def decorator(func):routes.append(Route(path,func,methods=methods));return func
            return decorator
    settings=SimpleNamespace(jobs_root=tmp_path,bearer_token='x'*48)
    attach_routes(MCP(),None,settings)
    client=TestClient(Starlette(routes=routes))
    path='/fox/jobs/fox-'+'a'*20
    for method,url in [('POST',path),('GET',path),('GET','/fox/target-profile'),('POST',path+'/release'),('GET',path+'/package'),('POST',path+'/review'),('POST',path+'/actions/import')]:
        assert client.request(method,url).status_code==401
    result=client.post(path,headers={'Authorization':'Bearer '+'x'*48},json=snapshot())
    assert result.status_code==201
    assert client.post(path,headers={'Authorization':'Bearer '+'x'*48},json=snapshot()).status_code==409


def test_unbound_package_download_is_blocked(tmp_path):
    routes=[]
    class MCP:
        def custom_route(self,path,methods,**kwargs):
            def decorator(func):routes.append(Route(path,func,methods=methods));return func
            return decorator
    job_id='fox-'+'b'*20;root=tmp_path/job_id;root.mkdir()
    (root/'release-evidence.json').write_text('{}')
    (root/'apex-package.zip').write_bytes(b'old unbound artifact')
    def blocked(job_id):raise RuntimeError('Unbound')
    workflow=SimpleNamespace(store=SimpleNamespace(require=lambda jid:root),status=lambda jid:{'state':'IMPORTED'},assert_artifact_binding=blocked)
    attach_routes(MCP(),workflow,SimpleNamespace(jobs_root=tmp_path,bearer_token='x'*48))
    with TestClient(Starlette(routes=routes)) as client:
        result=client.get('/fox/jobs/'+job_id+'/package',headers={'Authorization':'Bearer '+'x'*48})
    assert result.status_code==409 and 'old unbound' not in result.text

def test_incorrect_combined_manifest_hash_cannot_stage(tmp_path):
    value=snapshot();value['source_hash']='a'*64
    with pytest.raises(ValueError,match='manifest hash'):stage_snapshot(tmp_path,'fox-'+'c'*20,value)
    assert not list(tmp_path.iterdir())

def test_bom_readable_source_keeps_original_hash(tmp_path):
    value=snapshot();raw=b'\xef\xbb\xbf'+value['files'][0]['text'].encode()
    value['files'][0]['sha256']=hashlib.sha256(raw).hexdigest()
    value['source_hash']=hashlib.sha256(('synthetic.xml:'+value['files'][0]['sha256']).encode()).hexdigest()
    jid='fox-'+'d'*20
    stage_snapshot(tmp_path,jid,value)
    assert (tmp_path/jid/'intake/synthetic.xml').read_bytes()==raw
