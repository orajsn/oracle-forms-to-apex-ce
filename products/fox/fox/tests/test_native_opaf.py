import hashlib,json
import pytest
from fox.opaf import OpafClient,OpafError,canonical_hash,load_native_profile

ROLE={'workflow_id':'A'*32,'model':'xai.grok-4.3','graph_sha256':canonical_hash({'nodes':[]})}

def test_invocation_records_actual_distinct_response_and_hashes(monkeypatch):
    calls=[];reply={'roomId':'ABC123','message':{'verdict':'approve'}}
    def request(self,method,path,payload=None,login=False):
        calls.append((method,path,payload,login))
        if path.endswith('loginValidation'):return {}
        if method=='GET':return {'data':{'published':1,'data':{'nodes':[]}}}
        return reply
    monkeypatch.setattr(OpafClient,'_request',request)
    payload={'job_id':'synthetic'}
    value,receipt=OpafClient('https://localhost:8080/agentFactory','u','p').invoke(ROLE,payload)
    assert value==reply['message'] and receipt['room_id']=='ABC123'
    assert receipt['request_sha256']==canonical_hash(payload)
    assert receipt['response_sha256']==canonical_hash(reply)
    assert receipt['completed_at_utc']>=receipt['started_at_utc']
    assert len(calls)==3 and json.loads(calls[-1][2]['message'])==payload

def test_changed_workflow_blocks_model_call(monkeypatch):
    calls=[]
    def request(self,method,path,payload=None,login=False):
        calls.append(method)
        return {} if login else {'data':{'published':1,'data':{'nodes':['changed']}}}
    monkeypatch.setattr(OpafClient,'_request',request)
    with pytest.raises(OpafError,match='changed'):
        OpafClient('https://localhost:8080/agentFactory','u','p').invoke(ROLE,{})
    assert calls==['GET','GET']

@pytest.mark.parametrize('reply',[{}, {'roomId':'id','message':'not JSON'},{'message':{}},{'roomId':'id','message':[]}])
def test_malformed_role_output_never_becomes_evidence(monkeypatch,reply):
    def request(self,method,path,payload=None,login=False):
        if login:return {}
        if method=='GET':return {'data':{'published':1,'data':{'nodes':[]}}}
        return reply
    monkeypatch.setattr(OpafClient,'_request',request)
    with pytest.raises(OpafError):OpafClient('https://localhost:8080/agentFactory','u','p').invoke(ROLE,{})

def test_profile_requires_two_distinct_roles(tmp_path):
    p=tmp_path/'profile.json'
    p.write_text(json.dumps({'schema_version':1,'profile_id':'native-table-form-v1','opaf_base_url':'https://localhost:8080/agentFactory',
                           'certificate_sha256':'a'*64,'mapper':ROLE,'reviewer':ROLE}))
    with pytest.raises(OpafError,match='separate'):load_native_profile(p)
