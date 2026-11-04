"""Synthetic failure captures; no live authority, closure or QA execution."""
import base64
from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/'fox'),str(ROOT/'converter')]
from qa.operator import contracts as c, project_contracts as pc, product_verifier as v
from qa.operator import qa_stage_reconciliation as r, project_qa_contracts as preparation
from qa.operator.tests.test_project_qa_dispatch import qa_case, case, project_job
from fox import verification_queue as q

INSTALLATION='8'*64
CONVERTER='9'*64
TOKEN='0123456789abcdef'*2
encode=lambda raw:base64.b64encode(raw).decode()
raw=lambda value:c.canonical_bytes(value)


@pytest.fixture
def capture(qa_case):
    packet,inputs,_=qa_case
    manifest=v.build_manifest({'schema_version':2,'scope':'fox-product-verifier-operator-config-v2',
        'enabled':True,'images':{'fox':v.clean.FOX_IMAGE,'converter':v.clean.IMAGE}})
    release=c.digest(raw(manifest));plan_raw=base64.b64decode(packet['plan_b64']);plan=c.load_json(plan_raw)
    binding=q.VerificationBinding(*(plan['binding'][k] for k in
        ('job_id','source_manifest_sha256','package_sha256')),release)
    row={**binding.payload(),'binding_sha256':q._digest(binding.payload()),
        'state':'attention','claim_token':TOKEN,'proof_sha256':None,
        'attention_code':'BACKEND_OUTCOME_UNCONFIRMED','created_at_utc':'2026-10-25T01:00:00Z',
        'updated_at_utc':'2026-10-25T01:01:00Z'}
    row['record_sha256']=q._digest(row)
    files={name:inputs[name] for name in preparation.EVIDENCE};files['plan.json']=plan_raw
    journal={'session.json':{'scope':'fox-product-verifier-session-v1','release_sha256':release,
        'started_at_utc':'2026-10-25T01:00:00Z','startup_authorized':True,
        'bounds':{'max_jobs':1,'max_polls':120,'max_seconds':7200,'poll_seconds':5}},
        'attention.json':{'status':'ATTENTION','release_sha256':release,'known_claim':True,
            'code':'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE','automatic_replay_permitted':False}}
    results={'claim':{'status':'CLAIMED','claim':{'binding':binding.payload(),'attempt_token':TOKEN}},
        'prepare':{'conversion_profile':'native-project-v1',**{k:val for k,val in binding.payload().items()
            if k!='verifier_release_sha256'},'operator_code_sha256':plan['operator_code_sha256'],
            'plan_sha256':packet['plan_sha256']},'clean_check':{'state':'PREPARED','plan_sha256':packet['plan_sha256']}}
    for phase in r.PHASES:
        if phase+'.evidence.json' not in files:
            files[phase+'.evidence.json']=raw({'scope':'synthetic-'+phase+'-evidence'})
        digest=c.digest(files[phase+'.evidence.json'])
        intent={'schema_version':1,'scope':pc.PHASE_SCOPE,'plan_sha256':packet['plan_sha256'],
            'phase':phase,'state':'intent','started_at_utc':'2026-10-25T01:00:00Z',
            'finished_at_utc':None,'evidence_sha256':None}
        files[phase+'.intent.json']=raw(intent)
        files[phase+'.complete.json']=raw({**intent,'state':'complete',
            'finished_at_utc':'2026-10-25T01:01:00Z','evidence_sha256':digest})
        results[phase]={'state':'QA_READY' if phase=='verify' else 'PHASE_COMPLETE',
            'action':'COMPLETED_ONCE','plan_sha256':packet['plan_sha256'],'evidence_sha256':digest}
    for step in ('claim',*r.STEPS,'qa_stage'):
        label='p0001-'+step.replace('_','-')
        intent={'scope':'fox-product-verifier-step-v1','release_sha256':release,'step':label,
            'binding_sha256':None if step=='claim' else c.digest(raw(binding.payload()))}
        journal[label+'.intent.json']=intent
        if step!='qa_stage':journal[label+'.complete.json']={'scope':'fox-product-verifier-step-result-v1',
            'release_sha256':release,'intent_sha256':c.digest(raw(intent)),'result':results[step]}
    return {'scope':r.CAPTURE_SCOPE,'writes_requested':False,'installation_sha256':INSTALLATION,
        'release':manifest,'session':'session-'+'a'*24,'journal':{k:encode(raw(val)) for k,val in journal.items()},
        'product':{'queue':row,'run':{'id':binding.job_id,'source_hash':binding.source_manifest_sha256,
            'state':'QA_REQUIRED','artifact':f'jobs/{binding.job_id}/apex-package.zip'},
            'technical_proof_count':0,'human_acceptance_count':0},
        'clean':{name:encode(data) for name,data in files.items()},
        'observation':{'service':{'LoadState':'loaded','ActiveState':'failed','SubState':'failed','MainPID':'0'},
            'active_sqlcl_pids':[],'active_browser_pids':[],'stage_exists':False,
            'stage_path':'/home/opc/.config/fox-qa/project-v1-stages/'+packet['plan_sha256']+'/'+packet['source_sha256'],
            'stage_image_tags_present':[],'launch_intent_exists':False,'dispatch_receipt_exists':False},
        'dependency_probe':{'module':'fox.native_verification','exit_code':1,'error_kind':'ModuleNotFoundError',
            'source_sha256':packet['source_sha256'],'container_id':CONVERTER,'converter_image':manifest['images']['converter']}}


def assess(value,**overrides):
    return r.assess_capture(value,**{'expected_release_sha256':c.digest(raw(value['release'])),
        'expected_installation_sha256':INSTALLATION,'expected_converter_id':CONVERTER,
        'expected_converter_image':value['release']['images']['converter'],**overrides})


def test_classification_preserves_existing_app_without_success_retry_or_closure(capture):
    original=deepcopy(capture);result=assess(capture)
    assert capture==original
    assert result['failed_phase']=='qa_stage'
    assert result['completed_steps']==list(r.STEPS)
    assert result['expected_versions']['apex'] in ('26.1.5','26.1.6')
    assert all(result[k] is False for k in ('closure_performed','technical_success',
        'human_acceptance_recorded','automatic_replay_permitted','recovery_authorized'))
    assert result['current_admission_blocks'] is True
    assert TOKEN not in json.dumps(result)
    assert 'runtime-credentials.json' not in result['clean_sha256']


def test_missing_changed_or_later_phase_evidence_never_grants_disposition(capture):
    mutations=[
        lambda x:x.update(writes_requested=True),
        lambda x:x['product'].update(technical_proof_count=1),
        lambda x:x['product'].update(human_acceptance_count=False),
        lambda x:x['product']['run'].update(state='VERIFIED'),
        lambda x:x['product']['run'].update(unexpected='not an approved capture field'),
        lambda x:x['journal'].update({'session.json':encode(b'{"scope":1,"scope":2}')}),
        lambda x:x['journal'].update({'attention.json':'not base64'}),
        lambda x:x['release'].update(enabled=False),
        lambda x:x['journal'].pop('p0001-verify.complete.json'),
        lambda x:x['journal'].update({'p0001-qa-run.intent.json':encode(b'{}')}),
        lambda x:x['journal'].update({'p0001-qa-stage.complete.json':encode(b'{}')}),
        lambda x:x['clean'].update({'runtime-credentials.json':encode(b'{}')}),
        lambda x:x['clean'].update({'verify.evidence.json':encode(b'{}')}),
        lambda x:x['clean'].update({'schema.evidence.json':encode(b'{}')}),
        lambda x:x['observation']['service'].update(MainPID='123'),
        lambda x:x['observation'].update(active_sqlcl_pids=[1]),
        lambda x:x['observation'].update(active_browser_pids=[1]),
        lambda x:x['observation'].update(stage_exists=True),
        lambda x:x['observation'].update(stage_exists=0),
        lambda x:x['observation'].update(stage_path='/elsewhere'),
        lambda x:x['observation'].update(stage_image_tags_present=['retained-image']),
        lambda x:x['observation'].update(launch_intent_exists=True),
        lambda x:x['observation'].update(dispatch_receipt_exists=True),
        lambda x:x['dependency_probe'].update(exit_code=0),
        lambda x:x['dependency_probe'].update(exit_code=True),
        lambda x:x['dependency_probe'].update(module='other.module'),
        lambda x:x['dependency_probe'].update(container_id='0'*64),
    ]
    for mutation in mutations:
        value=deepcopy(capture);mutation(value)
        with pytest.raises(r.QaStageEvidenceError):assess(value)


def test_captured_values_cannot_replace_independently_reviewed_identity(capture):
    for field,value in (('expected_release_sha256','0'*64),('expected_installation_sha256','0'*64),
            ('expected_converter_id','0'*64),('expected_converter_image','sha256:'+'0'*64)):
        with pytest.raises(r.QaStageEvidenceError):assess(capture,**{field:value})


def test_credential_free_evidence_does_not_weaken_normal_runner_accounts(qa_case):
    packet,inputs,_=qa_case
    plan=base64.b64decode(packet['plan_b64']);code=packet['descriptor']['clean_operator_code_sha256']
    evidence={name:inputs[name] for name in preparation.EVIDENCE}
    prepared=preparation.prepare_evidence(plan,evidence,operator_code_sha256=code)
    assert set(prepared)=={'profile.json','target.json'}
    with pytest.raises((ValueError,RuntimeError)):
        preparation.prepare_inputs(plan,evidence,operator_code_sha256=code)
    with pytest.raises((ValueError,RuntimeError)):
        preparation.prepare_evidence(plan,{**evidence,'runtime-credentials.json':b'{}'},operator_code_sha256=code)


def test_large_capture_digest_has_separate_bound_and_canonical_identity():
    import hashlib
    value={'encoded_package':'x'*300000,'nested':{'b':2,'a':1}}
    expected=(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
    assert r._capture_digest(value)==hashlib.sha256(expected).hexdigest()
    with pytest.raises(r.QaStageEvidenceError,match='CAPTURE_BOUND'):
        r._capture_digest({'encoded_package':'x'*64000001})


def test_module_import_does_not_offer_a_recovery_writer():
    assert not any(hasattr(r,name) for name in ('close_failure','retry','stage','run','promote','execute'))
