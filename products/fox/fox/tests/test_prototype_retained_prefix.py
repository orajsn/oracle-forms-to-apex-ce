"""Bounded prefix contracts; unit seams are authored, not live-flow evidence."""
from copy import deepcopy
from pathlib import Path

import pytest

from fox import prototype_candidate_continuation as cf, prototype_mapping_epochs as epochs
from fox import prototype_pipeline as pipeline
from fox.opaf import OpafError, canonical_hash
from fox.prototype_read_scope import current_read_root
from test_prototype_pipeline import documents, PROFILE, TARGET


@pytest.fixture
def prefix(tmp_path,monkeypatch):
    root=tmp_path/'prototype-pipeline'
    (root/'epochs/epoch-000004').mkdir(parents=True)
    plan={'requests':[{'focus_id':'first'},{'focus_id':'second'},{'focus_id':'frontier'}]}
    views=[{'candidate':{'focus':row['focus_id']},'checked':{'approved_structured_design':True},
        'proof':{'focus_id':row['focus_id'],'sealed':'authored-unit-only'}} for row in plan['requests'][:2]]
    record={'plan':{'completed_focus_count':2,'focus_id':'frontier',
        'prior_proofs_sha256':canonical_hash([row['proof'] for row in views])}}
    calls=[]
    def validate(*args):
        assert current_read_root()==root.absolute()
        calls.append('validated-record');return deepcopy(record)
    def active(_root,_packet,_plan,request,_target,previous,*,runtime=None):
        assert runtime is None and current_read_root()==root.absolute()
        assert len(previous)==len([x for x in calls if isinstance(x,tuple)])
        calls.append(('read',request['focus_id']))
        return deepcopy(views[len(previous)])
    monkeypatch.setattr(cf,'validate_technical_record',validate)
    monkeypatch.setattr(epochs,'active_focus',active)
    return root,plan,views,record,calls


def test_prefix_is_approved_proof_bound_pure_and_scope_closes(prefix,monkeypatch):
    root,plan,expected,record,calls=prefix
    before={p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}
    def forbidden(*a,**kw):pytest.fail('Pure prefix attempted a write or provider operation.')
    with monkeypatch.context() as pure:
        for name in ('mkdir','write_bytes','write_text','unlink','rename'):
            pure.setattr(Path,name,forbidden)
        result=pipeline._retained_candidate_prefix(root,{},plan,{})
    assert result==expected and current_read_root() is None
    assert calls==['validated-record',('read','first'),('read','second')]
    assert {p.relative_to(root):p.read_bytes() for p in root.rglob('*') if p.is_file()}==before


@pytest.mark.parametrize('change',['count-type','count-overrun','count-zero','focus','proof','negative','unsealed'])
def test_unauthorized_or_changed_prefix_never_becomes_execution_fallback(prefix,monkeypatch,change):
    root,plan,views,record,calls=prefix
    if change=='count-type':record['plan']['completed_focus_count']=True
    elif change=='count-overrun':record['plan']['completed_focus_count']=3
    elif change=='count-zero':record['plan']['completed_focus_count']=0
    elif change=='focus':record['plan']['focus_id']='wrong'
    elif change=='proof':views[0]['proof']['sealed']='changed'
    elif change=='negative':views[0]['checked']['approved_structured_design']=False
    else:
        def unsealed(*a,**kw):raise OpafError('Authored unsealed role envelope.')
        monkeypatch.setattr(epochs,'active_focus',unsealed)
    with pytest.raises(OpafError):pipeline._retained_candidate_prefix(root,{},plan,{})
    assert current_read_root() is None


def test_pipeline_uses_runtime_only_after_exact_validated_prefix_and_exit(tmp_path,monkeypatch):
    from fox.forms_focus import build_focus_plan
    from fox.forms_understanding_packet import local_packet
    docs=documents();packet=local_packet(docs)
    plan=build_focus_plan(docs,expected_source_binding=packet['source_binding'],approved_chunk_hashes={})
    assert len(plan['requests'])>=2
    job=tmp_path/('fox-'+'a'*20);root=job/'prototype-pipeline'
    (root/'epochs/epoch-000004').mkdir(parents=True)
    view={'candidate':{'unit':'authored-readonly-prefix'},'checked':{'approved_structured_design':True},
        'proof':{'focus_id':plan['requests'][0]['focus_id'],'sealed':'authored-unit-only'}}
    record={'plan':{'completed_focus_count':1,'focus_id':plan['requests'][1]['focus_id'],
        'prior_proofs_sha256':canonical_hash([view['proof']])}}
    monkeypatch.setattr(cf,'present',lambda _:True)
    monkeypatch.setattr(cf,'validate_technical_record',lambda *a:deepcopy(record))
    monkeypatch.setattr(epochs,'technical_record',lambda _:None)
    # The pipeline reads the immutable record digest for its existing result
    # label, but the count selector still comes from the validator above.
    (root/cf.RECORD).write_text('{}')
    from fox import prototype_dsc_identity_repair as dsc
    monkeypatch.setattr(dsc,'present',lambda _:False)
    calls=[]
    class FrontierReached(Exception):pass
    def active(_root,_packet,_plan,request,_target,previous,*,runtime=None):
        if request['focus_id']==plan['requests'][0]['focus_id']:
            assert runtime is None and current_read_root()==root.absolute() and previous==[]
            calls.append('retained');return deepcopy(view)
        assert current_read_root() is None and runtime is not None and previous==[view]
        calls.append('frontier-runtime');raise FrontierReached()
    monkeypatch.setattr(epochs,'active_focus',active)
    with pytest.raises(FrontierReached):
        pipeline.run_prototype_pipeline(job,docs,project_id='unit-project',project_name='Unit project',
            expected_source_binding=packet['source_binding'],approved_chunk_hashes={},
            approved_policy_id=pipeline.POLICY_ID,opaf_client=None,profile=deepcopy(PROFILE),
            target_profile_loader=lambda:deepcopy(TARGET),processing_approval_check=lambda _:True)
    assert calls==['retained','frontier-runtime']


@pytest.mark.parametrize('drift',['owner','consent','source','target'])
def test_existing_fresh_operation_gate_remains_outside_read_scope(prefix,tmp_path,drift):
    root,plan,_,_,_=prefix
    pipeline._retained_candidate_prefix(root,{},plan,{})
    assert current_read_root() is None
    directory=tmp_path/'frontier';directory.mkdir()
    checks=[]
    def approve(context):
        assert current_read_root() is None;checks.append('fresh-owner-consent')
        return drift=='target'
    changed=deepcopy(TARGET);changed['opaf']['roles']['reviewer']['workflow_id']='C'*32
    with pytest.raises(OpafError):
        pipeline._role(directory,'reviewer',None,PROFILE['reviewer'],{},
            {'job_id':'fox-'+'b'*20,'source_hash':'b'*64},lambda:changed,approve,{})
    assert checks==['fresh-owner-consent'] and list(directory.iterdir())==[]
