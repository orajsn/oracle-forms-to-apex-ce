"""Real local HTTP routing with fake external stages; no Oracle/provider calls."""
from types import SimpleNamespace
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient
from forms2apex.prototype_routes import attach_prototype_routes

JOB='fox-'+'a'*20
TOKEN='synthetic-route-test-only'

class MCP:
    def __init__(self):self.routes=[]
    def custom_route(self,path,methods,include_in_schema=False):
        def register(fn):
            self.routes.append(Route(path,fn,methods=methods));return fn
        return register

class Gateway:
    def __init__(self):self.calls=[];self.saved=None;self.failure=False
    def supports(self,stage):return stage in ('validate','prepare_schema','import')
    def stage_source_authority(self,job,value):
        self.calls.append(('stage',job,value));return {'staged':True}
    def recover_source_authority(self,job):
        self.calls.append(('authority_read',job));return self.saved
    def run_stage(self,stage,value):
        self.calls.append(('run',stage,value))
        if self.failure:raise RuntimeError('private source details must not be exposed')
        return {'stage':stage}
    def recover_stage_for_job(self,job,stage):
        self.calls.append(('read',job,stage));return self.saved

def setup():
    mcp=MCP();gateway=Gateway()
    attach_prototype_routes(mcp,gateway,SimpleNamespace(bearer_token=TOKEN))
    return TestClient(Starlette(routes=mcp.routes)),gateway

def test_auth_rejects_before_body_or_gateway():
    client,gateway=setup()
    assert client.post(f'/fox/prototype/jobs/{JOB}/authority',content=b'not-json').status_code==401
    assert client.get(f'/fox/prototype/jobs/{JOB}/stages/import').status_code==401
    assert gateway.calls==[]

def test_authority_post_and_read_are_distinct():
    client,gateway=setup();headers={'Authorization':'Bearer '+TOKEN}
    assert client.post(f'/fox/prototype/jobs/{JOB}/authority',json={'bundle':'synthetic'},headers=headers).status_code==201
    assert client.get(f'/fox/prototype/jobs/{JOB}/authority',headers=headers).status_code==404
    assert [row[0] for row in gateway.calls]==['stage','authority_read']

def test_get_missing_stage_never_replays():
    client,gateway=setup();headers={'Authorization':'Bearer '+TOKEN}
    for _ in range(2):assert client.get(f'/fox/prototype/jobs/{JOB}/stages/import',headers=headers).status_code==404
    assert [row[0] for row in gateway.calls]==['read','read']

def test_stage_requires_exact_job_and_known_stage():
    client,gateway=setup();headers={'Authorization':'Bearer '+TOKEN}
    assert client.post(f'/fox/prototype/jobs/{JOB}/stages/validate',json={'job_id':'fox-'+'b'*20},headers=headers).status_code==409
    assert client.get(f'/fox/prototype/jobs/{JOB}/stages/delete',headers=headers).status_code==409
    assert gateway.calls==[]
    assert client.post(f'/fox/prototype/jobs/{JOB}/stages/validate',json={'job_id':JOB},headers=headers).json()=={'stage':'validate'}

def test_duplicate_and_nonfinite_json_rejected():
    client,gateway=setup();headers={'Authorization':'Bearer '+TOKEN}
    for raw in ('{"x":1,"x":2}','{"x":NaN}'):
        assert client.post(f'/fox/prototype/jobs/{JOB}/authority',content=raw,headers=headers).status_code==409
    assert gateway.calls==[]

def test_private_errors_are_not_reflected():
    client,gateway=setup();gateway.failure=True
    result=client.post(f'/fox/prototype/jobs/{JOB}/stages/import',json={'job_id':JOB},headers={'Authorization':'Bearer '+TOKEN})
    assert result.status_code==409 and 'private source details' not in result.text

def test_capabilities_require_auth_and_do_not_execute():
    client,gateway=setup()
    assert client.get('/fox/prototype/capabilities').status_code==401
    result=client.get('/fox/prototype/capabilities',headers={'Authorization':'Bearer '+TOKEN})
    assert result.json()=={'schema_version':1,'scope':'fox-prototype-capabilities-v1',
                           'stages':['validate','prepare_schema','import']}
    assert gateway.calls==[]
