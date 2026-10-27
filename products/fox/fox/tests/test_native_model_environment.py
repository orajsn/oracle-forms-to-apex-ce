"""Synthetic model-environment contracts; no service/model/database calls."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from fox import opaf
from fox import native_pipeline as pipeline
from fox.opaf import OpafClient, OpafError, canonical_hash, validate_model_environment
from test_native_pipeline import NativeHarness, read_json, write_json, package_bytes

ROOT = Path(__file__).resolve().parents[2]
SECRET = 'SYNTHETIC-CONFIG-SECRET-MUST-NOT-ESCAPE'


@pytest.fixture
def environment_case(monkeypatch):
    target = json.loads((ROOT / 'deployment/target-profile.jsn.json').read_text())
    graph = json.loads((ROOT / 'deployment/native-opaf-mapper.json').read_text())['data']
    target['opaf']['roles']['mapper']['graph_sha256'] = canonical_hash(graph)
    role = target['opaf']['roles']['mapper']
    selected = next(n['data']['template']['llmToUse']['value'] for n in graph['nodes'] if n['data']['type']=='llmStep')
    case = {'target':target, 'role':role, 'graph':graph, 'published':1, 'calls':[],
        'version':{'VERSION_STRING':'26.4.0.0.0','VERSION_NUMBER':264000,'BUILD_ID':1780444486153,
                   'HOSTNAME':SECRET},
        'rows':[{'name':selected,'provider':'oci','isActive':'Y','createdBy':SECRET,
                 'connectionDetails':{'model_id':role['model'],'credentials_type':'INSTANCE_PRINCIPAL',
                    'compartment_id':target['oci']['compartment_id'],
                    'service_endpoint':'https://inference.generativeai.us-ashburn-1.oci.oraclecloud.com',
                    'api_key':SECRET}}],
        'request':{'job_id':'fox-'+'a'*20,'source_hash':'b'*64,'inventory':{},'native_form':{}},
        'output':{'roomId':'synthetic-mapper-room','message':{'synthetic':True}}}
    def request(self,method,path,payload=None,login=False):
        case['calls'].append((method,path))
        if path=='/v1/loginValidation':return {}
        if path=='/v1/version':return deepcopy(case['version'])
        if path=='/v1/getSavedLLMConfigurations':return {'data':{'savedConfiguration':deepcopy(case['rows'])}}
        if path.startswith('/v1/agents/'):
            return {'data':{'published':case['published'],'data':deepcopy(case['graph'])}}
        if path.startswith('/v1/agentBuilder/run/'):
            assert method=='POST'
            return deepcopy(case['output'])
        pytest.fail('Unexpected API path')
    monkeypatch.setattr(OpafClient,'_request',request)
    case['client']=OpafClient(target['opaf']['base_url'],'synthetic',SECRET,target['opaf']['certificate_sha256'])
    return case


def invoke(case):
    return case['client'].invoke_with_environment(case['role'],case['request'],
        role_name='mapper',target_profile=case['target'])


def observe(case):
    return case['client'].observe_environment(case['role'],case['request'],
        role_name='mapper',target_profile=case['target'])


def test_health_observation_uses_only_get_and_contains_no_execution_or_secret_claim(environment_case):
    case=environment_case
    case['request']['inventory']={'source':SECRET}
    observed=observe(case)
    assert len(case['calls'])==4 and all(method=='GET' for method,_ in case['calls'])
    assert [path for _,path in case['calls']]==['/v1/loginValidation','/v1/version',
        '/v1/agents/'+case['role']['workflow_id'],'/v1/getSavedLLMConfigurations']
    assert observed['workflow']['model']=='xai.grok-4.3'
    assert observed['opaf_version']=='26.4.0.0.0'
    assert SECRET not in json.dumps(observed)
    assert not {'invocation','room_id','verdict','approved','started_at_utc','completed_at_utc','request_sha256','response_sha256'} & set(observed)


@pytest.mark.parametrize('change',[
    lambda c:c['version'].update(VERSION_NUMBER=264001),
    lambda c:c['version'].update(BUILD_ID='1780444486153'),
    lambda c:c['version'].update(VERSION_STRING='other'),
    lambda c:c['rows'][0]['connectionDetails'].update(model_id='other'),
    lambda c:c['rows'][0]['connectionDetails'].update(credentials_type='API_KEY'),
    lambda c:c['rows'][0]['connectionDetails'].update(service_endpoint='https://other.invalid'),
    lambda c:c['rows'][0]['connectionDetails'].update(compartment_id='other'),
    lambda c:c.update(published=0),
    lambda c:c['graph']['nodes'].append({'data':{'type':'mcpServerToolRunner'}}),
    lambda c:c['rows'].append(deepcopy(c['rows'][0])),
])
def test_get_only_observation_retains_all_drift_checks(environment_case,change):
    case=environment_case;change(case)
    with pytest.raises(OpafError) as err:observe(case)
    assert SECRET not in str(err.value)
    assert all(method=='GET' for method,_ in case['calls'])


def test_invoke_reuses_read_only_observer_without_duplicate_environment_requests(environment_case,monkeypatch):
    case=environment_case
    observed=observe(case)
    case['calls'].clear()
    visits=[]
    def same_observer(role,request,*,role_name,target_profile):
        visits.append(role_name)
        assert role==case['role'] and request==case['request'] and target_profile==case['target']
        return observed
    monkeypatch.setattr(case['client'],'observe_environment',same_observer)
    _,_,actual=invoke(case)
    assert visits==['mapper'] and actual==observed
    assert case['calls']==[('POST','/v1/agentBuilder/run/'+case['role']['workflow_id'])]


def test_actual_version_graph_and_selected_model_bound_without_secret_output(environment_case,monkeypatch):
    case=environment_case
    output,receipt,observed=invoke(case)
    assert output==case['output']['message']
    assert observed['workflow']['model']==case['rows'][0]['connectionDetails']['model_id']
    assert observed['opaf']['version_number']==264000
    assert observed['opaf']['build_id']==1780444486153
    assert observed['opaf']['model_authentication']=='oci_instance_principal'
    assert SECRET not in json.dumps((output,receipt,observed))
    assert [p for m,p in case['calls']]==['/v1/loginValidation','/v1/version',
        '/v1/agents/'+case['role']['workflow_id'],'/v1/getSavedLLMConfigurations',
        '/v1/agentBuilder/run/'+case['role']['workflow_id']]
    # Cross-check the converter's independent final observation contract.
    monkeypatch.syspath_prepend(str(ROOT/'converter'))
    from forms2apex.runtime_preflight import validate_model_environment_observation
    assert validate_model_environment_observation(case['target'],observed,
        job_id=case['request']['job_id'],source_manifest_sha256=case['request']['source_hash'],
        role='mapper',invocation=receipt)==observed


@pytest.mark.parametrize('field,value',[
    ('model_id','other-model'),('credentials_type','API_KEY'),('compartment_id','wrong-compartment'),
    ('service_endpoint','https://wrong.example.invalid'),])
def test_actual_connection_drift_blocks_inference(environment_case,field,value):
    case=environment_case;case['rows'][0]['connectionDetails'][field]=value
    with pytest.raises(OpafError) as err:invoke(case)
    assert SECRET not in str(err.value)
    assert not any(method=='POST' for method,_ in case['calls'])


@pytest.mark.parametrize('change',[
    lambda c:c['rows'][0].update(provider='other'),
    lambda c:c['rows'][0].update(isActive='N'),
    lambda c:c['rows'].append(deepcopy(c['rows'][0])),
    lambda c:c['rows'].clear(),
    lambda c:c.update(rows={}),
    lambda c:c['rows'][0].update(connectionDetails=SECRET),
    lambda c:c.update(published=1.0),
    lambda c:c.update(published=0),
    lambda c:c['graph']['nodes'].append({'data':{'type':'mcpServerToolRunner'}}),
])
def test_invalid_saved_selection_or_graph_never_runs(environment_case,change):
    case=environment_case;change(case)
    with pytest.raises(OpafError) as err:invoke(case)
    assert SECRET not in str(err.value)
    assert not any(method=='POST' for method,_ in case['calls'])


@pytest.mark.parametrize('field,value',[
    ('VERSION_STRING','26.5.0.0.0'),('VERSION_NUMBER',264001),('BUILD_ID',0),
    ('VERSION_NUMBER',True),('BUILD_ID','1780444486153'),])
def test_actual_version_tuple_must_match_before_inference(environment_case,field,value):
    case=environment_case;case['version'][field]=value
    with pytest.raises(OpafError):invoke(case)
    assert not any(method=='POST' for method,_ in case['calls'])


def test_observation_time_covers_all_environment_reads(environment_case,monkeypatch):
    begin=datetime(2026,10,17,tzinfo=timezone.utc)
    clocks=iter((begin,begin+timedelta(seconds=121)))
    monkeypatch.setattr(opaf,'_utc_now',lambda:next(clocks))
    with pytest.raises(OpafError,match='historical'):invoke(environment_case)
    assert not any(method=='POST' for method,_ in environment_case['calls'])


def test_historical_environment_does_not_expire_against_today(environment_case,monkeypatch):
    old=datetime(2000,1,1,tzinfo=timezone.utc)
    clocks=iter((old,old+timedelta(seconds=5),old+timedelta(seconds=50)))
    monkeypatch.setattr(opaf,'_utc_now',lambda:next(clocks))
    _,receipt,observed=invoke(environment_case)
    monkeypatch.setattr(opaf,'_utc_now',lambda:pytest.fail('Historical check must not use current clock'))
    assert validate_model_environment(observed,environment_case['target'],'mapper',environment_case['request'],receipt)==observed


def test_environment_job_source_and_role_binding_reject_tamper(environment_case):
    _,receipt,observed=invoke(environment_case)
    for field,value in [('job_id','fox-'+'c'*20),('source_manifest_sha256','d'*64),
                        ('role','reviewer'),('target_profile_sha256','e'*64),('extra',True)]:
        changed={**observed,field:value}
        with pytest.raises(OpafError):validate_model_environment(changed,environment_case['target'],
            'mapper',environment_case['request'],receipt)


def test_pipeline_observations_are_checkpointed_and_resume_needs_no_opaf_or_profile(tmp_path,monkeypatch):
    harness=NativeHarness(tmp_path,monkeypatch)
    harness.run()
    assert harness.target_profile_requests==2
    assert set(harness.review_payload['model_environment'])=={'mapper','reviewer'}
    for name in ('mapper','reviewer'):
        saved=read_json(harness.checkpoints/(name+'.json'))
        assert saved['model_environment_sha256']==canonical_hash(saved['model_environment'])
        assert saved['model_environment']==harness.review_payload['model_environment'][name]
    before={p.name:p.read_bytes() for p in harness.checkpoints.glob('*.json')}
    # Host/model offline and profile endpoint unavailable after review sealing.
    harness.model_failures={'mapper':AssertionError('Do not call mapper'),'reviewer':AssertionError('Do not call reviewer')}
    harness.responses['target-profile']={}
    harness.run()
    assert harness.target_profile_requests==2
    assert len(harness.model_calls)==2 and harness.counts('import')==1
    assert {p.name:p.read_bytes() for p in harness.checkpoints.glob('*.json')}==before


def test_checkpoint_observation_change_blocks_without_model_replay(tmp_path,monkeypatch):
    harness=NativeHarness(tmp_path,monkeypatch);harness.run()
    saved=read_json(harness.checkpoints/'mapper.json')
    saved['model_environment']['opaf']['build_id']=0
    write_json(harness.checkpoints/'mapper.json',saved)
    with pytest.raises(OpafError,match='environment'):harness.run()
    assert len(harness.model_calls)==2 and harness.target_profile_requests==2


@pytest.mark.parametrize('change',[
    lambda value:value.update(target_profile_sha256='0'*64),
    lambda value:value['target_profile']['opaf']['roles']['mapper'].update(model='other'),
    lambda value:value['target_profile'].update(active=False),
    lambda value:value.update(extra=True),
])
def test_invalid_target_handshake_blocks_new_model(tmp_path,monkeypatch,change):
    harness=NativeHarness(tmp_path,monkeypatch)
    envelope={'target_profile':deepcopy(harness.target_profile),'target_profile_sha256':canonical_hash(harness.target_profile)}
    change(envelope);harness.responses['target-profile']=envelope
    with pytest.raises(OpafError,match='target profile'):harness.run()
    assert not harness.model_calls


def test_retained_legacy_checkpoint_is_not_upgraded_or_replayed(tmp_path,monkeypatch):
    harness=NativeHarness(tmp_path,monkeypatch)
    harness.checkpoints.mkdir()
    inspection={'job_id':harness.job.name,'modules':[{'file':'native-beta.xml'}],'remediation_items':[]}
    write_json(harness.checkpoints/'inspection.json',inspection)
    request={'job_id':harness.job.name,'source_hash':harness.snapshot['source_hash'],
             'inventory':inspection,'native_form':harness.snapshot['native_form']}
    candidate,mapper=harness.invoke(harness.profile['mapper'],request)
    review_request={**request,'candidate':candidate,'candidate_sha256':canonical_hash(candidate)}
    review,reviewer=harness.invoke(harness.profile['reviewer'],review_request)
    for name,submitted,output,invocation in [('mapper',request,candidate,mapper),('reviewer',review_request,review,reviewer)]:
        write_json(harness.checkpoints/(name+'.json'),{'request_sha256':canonical_hash(submitted),
            'role':harness.profile[name],'output':output,'output_sha256':canonical_hash(output),'invocation':invocation})
    sealed=harness.request('POST',harness.path+'/review',{'job_id':harness.job.name,
        'source_hash':harness.snapshot['source_hash'],'candidate':candidate,'mapper_invocation':mapper,
        'reviewer_invocation':reviewer,'review':review})
    write_json(harness.checkpoints/'review-receipt.json',sealed)
    harness.state={**harness.remote('IMPORTED'),'validation':{'passed':True},'import':harness.import_identity()}
    before={name:(harness.checkpoints/(name+'.json')).read_bytes() for name in ('mapper','reviewer')}
    harness.model_calls.clear();harness.responses['target-profile']={}
    harness.run()
    assert not harness.model_calls and harness.target_profile_requests==0
    assert 'model_environment' not in harness.review_payload
    assert harness.receipt['schema_version']==1
    assert before=={name:(harness.checkpoints/(name+'.json')).read_bytes() for name in ('mapper','reviewer')}


def test_unsealed_legacy_checkpoint_blocks_without_observation_fabrication(tmp_path,monkeypatch):
    harness=NativeHarness(tmp_path,monkeypatch);harness.run()
    (harness.checkpoints/'review-receipt.json').unlink()
    for name in ('mapper','reviewer'):
        path=harness.checkpoints/(name+'.json');saved=read_json(path)
        saved.pop('model_environment');saved.pop('model_environment_sha256');write_json(path,saved)
    with pytest.raises(OpafError,match='Unsealed legacy'):harness.run()
    assert len(harness.model_calls)==2 and harness.target_profile_requests==2


@pytest.fixture
def historical_package(tmp_path,monkeypatch):
    harness=NativeHarness(tmp_path,monkeypatch)
    target=json.loads((ROOT/'deployment/target-profile.jsn.json').read_text())
    assert canonical_hash(target)=='7c7b73d43febc9befb1d43e47449a02cc7894b879dd4bc32904cec538e5f95e6'
    harness.target_profile=target
    harness.profile={'schema_version':1,'profile_id':pipeline.PROFILE_ID,
        'opaf_base_url':target['opaf']['base_url'],'certificate_sha256':target['opaf']['certificate_sha256'],
        **deepcopy(target['opaf']['roles'])}
    write_json(harness.profile_path,harness.profile)
    harness.run()
    return harness.members(),harness.evidence(),harness.snapshot['native_form'],target


def reseal_review(members,evidence,change):
    members=deepcopy(members);evidence=deepcopy(evidence)
    review=json.loads(members['evidence/native-review.json'])
    change(review)
    review['receipt_sha256']=canonical_hash({k:v for k,v in review.items() if k!='receipt_sha256'})
    evidence['review_receipt_sha256']=review['receipt_sha256']
    members['evidence/native-review.json']=json.dumps(review).encode()
    members['evidence/release-evidence.json']=json.dumps(evidence).encode()
    return members,evidence


def test_v2_package_has_self_contained_registered_historical_profile_without_active_calls(historical_package,monkeypatch):
    members,evidence,native,target=historical_package
    raw=package_bytes(members)
    monkeypatch.setattr(pipeline,'ConverterClient',lambda *a,**k:pytest.fail('Offline package must not fetch active profile'))
    monkeypatch.setattr(pipeline,'OpafClient',lambda *a,**k:pytest.fail('Offline package must not contact OPAF'))
    assert pipeline.verify_package(raw,evidence,native)==hashlib.sha256(raw).hexdigest()
    assert pipeline.verify_package(raw,evidence,native,deepcopy(target))==hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize('change',[
    lambda b:b+b'\n',
    lambda b:json.dumps(json.loads(b),indent=2).encode(),
    lambda b:b'\xef\xbb\xbf'+b,
    lambda b:b.replace(b'"schema_version":1',b'"schema_version":1,"schema_version":1'),
    lambda b:b.replace(b'"build_id":1780444486153',b'"build_id":1780444486154'),
])
def test_v2_profile_member_requires_exact_sealed_canonical_bytes(historical_package,change):
    members,evidence,native,target=historical_package
    members['evidence/target-profile.json']=change(members['evidence/target-profile.json'])
    with pytest.raises(OpafError,match='canonical snapshot'):
        pipeline.verify_package(package_bytes(members),evidence,native,target)


@pytest.mark.parametrize('missing',['member','sealed'])
def test_v2_profile_is_required_in_receipt_and_package(historical_package,missing):
    members,evidence,native,target=historical_package
    if missing=='member':members.pop('evidence/target-profile.json')
    else:members,evidence=reseal_review(members,evidence,lambda review:review.pop('historical_target_profile'))
    with pytest.raises(OpafError,match='sealed historical'):
        pipeline.verify_package(package_bytes(members),evidence,native,target)


def test_changed_active_profile_cannot_replace_cached_historical_data(historical_package):
    members,evidence,native,target=historical_package
    changed=deepcopy(target);changed['tested_versions']['apex']='26.2.0'
    with pytest.raises(OpafError,match='Cached historical'):
        pipeline.verify_package(package_bytes(members),evidence,native,changed)
    # Without a supplied active profile, the registered historical package still verifies.
    assert pipeline.verify_package(package_bytes(members),evidence,native)


@pytest.mark.parametrize('field,value',[
    ('target_profile_sha256','0'*64),('source_manifest_sha256','0'*64),
    ('job_id','fox-'+'f'*20),('role','mapper'),('observed_at_utc','1990-01-01T00:00:00Z'),
])
def test_resealed_environment_cannot_escape_deep_historical_binding(historical_package,field,value):
    members,evidence,native,target=historical_package
    members,evidence=reseal_review(members,evidence,
        lambda review:review['model_environment']['reviewer'].update({field:value}))
    with pytest.raises(OpafError,match='historical invocation'):
        pipeline.verify_package(package_bytes(members),evidence,native,target)


def test_unregistered_package_profile_needs_trusted_job_cache(tmp_path,monkeypatch):
    harness=NativeHarness(tmp_path,monkeypatch);harness.run()
    raw=package_bytes(harness.members())
    assert pipeline.verify_package(raw,harness.evidence(),harness.snapshot['native_form'],harness.target_profile)
    with pytest.raises(OpafError,match='Unregistered historical'):
        pipeline.verify_package(raw,harness.evidence(),harness.snapshot['native_form'])


@pytest.mark.parametrize('added',['member','profile','environment'])
def test_v1_package_rejects_invented_profile_or_environment(historical_package,added):
    members,evidence,native,target=historical_package
    def make_v1(review):
        review['schema_version']=1
        review.pop('model_environment');review.pop('historical_target_profile')
        if added=='profile':review['historical_target_profile']=target
        if added=='environment':review['model_environment']={}
    members,evidence=reseal_review(members,evidence,make_v1)
    if added!='member':members.pop('evidence/target-profile.json')
    with pytest.raises(OpafError,match='Legacy review'):
        pipeline.verify_package(package_bytes(members),evidence,native)
