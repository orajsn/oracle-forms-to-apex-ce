"""Real project package and SQLite gates; authored stopped observer, no live authority."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import sqlite3

import pytest

from fox import verification_recovery as r, verification_runtime as runtime
from test_qa_stage_recovery import stage_case as original_stage_case, actual_release, case, no_external_actions, original_rows


@pytest.fixture
def prewrite_case(original_stage_case):
    case,database,binding,claim,store,old=original_stage_case
    value=deepcopy(old)
    for name in ('completed_steps','missing_dependency'):value.pop(name)
    value.update(scope='fox-project-prewrite-qa-assessment-v1',status='CLASSIFIED_PROJECT_PREWRITE_QA_NOT_CLOSED',
        retained_steps=list(r.PHASES),failed_phase='qa_run',dispatch_state='PREFLIGHT_BLOCKED',
        qa_image='8'*64,qa_run_id='FPQ-20261025T010130-1234abcd',qa_report_sha256='9'*64)
    value['retained_sha256']={name:'d'*64 for name in ('session.json','attention.json',
        *('p0001-'+step.replace('_','-')+suffix for step in ('claim',*r.PHASES) for suffix in ('.intent.json','.complete.json')))}
    collection={name:'e'*64 for name in ('package.zip','native-project-spec.json','source-to-apex.json',
        'allocation-receipt.json','verification-profile.json','clean-import-receipt.json','qa-profile.json','target-receipt.json',
        'qa-result.json','stage-receipt.json','launch-intent.json','launch-receipt.json','collection-manifest.json')}
    for target,source in {'package.zip':'package.zip','native-project-spec.json':'native-project-spec.json','source-to-apex.json':'source-to-apex.json',
        'allocation-receipt.json':'allocate.evidence.json','verification-profile.json':'verification-profile.json','clean-import-receipt.json':'verify.evidence.json'}.items():
        collection[target]=value['clean_sha256'][source]
    collection['qa-result.json']=value['qa_report_sha256'];value['collection_sha256']=collection
    return case,database,binding,claim,store,value,old


def close(item,value=None,observer=None):
    case,_,_,_,store,saved,_=item;value=value or saved;raw=r.canonical_bytes(value)
    return store.close_project_prewrite_failure(raw,expected_sha256=r.digest(raw),
        observer=observer or (lambda *a:deepcopy(value)),apply=True,now=case.now)


def test_exact_append_retains_rows_files_failed_state_and_never_grants_retry(prewrite_case):
    case,database,binding,claim,store,value,_=prewrite_case
    before=original_rows(database);files={p:r.digest(p.read_bytes()) for p in case.job.rglob('*') if p.is_file()}
    assert store.eligibility(binding.job_id)['blocks_admission'] is True
    assert store.initialize_project_prewrite_ledger(apply=True)['created'] is True
    assert store.initialize_project_prewrite_ledger(apply=True)['created'] is False
    result=close(prewrite_case)
    assert result['status']=='FAILED_PROJECT_PREWRITE_QA_CLOSED' and result['action']=='RECORDED_ONCE'
    assert all(result[k] is False for k in ('technical_success','human_acceptance_recorded','automatic_retry_permitted'))
    assert original_rows(database)==before and all(r.digest(p.read_bytes())==sha for p,sha in files.items())
    assert claim.attempt_token not in json.dumps(result)
    assert store.eligibility(binding.job_id)=={'blocks_admission':False,'recovery_state':'project_prewrite_failed_closed','retry_eligible':False}
    with store._db() as db:
        db.execute('BEGIN');assert store.normal_claim_allowed(db,binding) is False
    assert close(prewrite_case,observer=lambda *a:pytest.fail('No duplicate observation/append'))['action']=='ALREADY_RECORDED_NO_REPLAY'


def test_explicit_initialization_and_fresh_in_transaction_observation_required(prewrite_case):
    *_,store,value,old=prewrite_case
    with pytest.raises(r.RecoveryError,match='EXPLICIT_INITIALIZATION'):store.initialize_project_prewrite_ledger()
    with pytest.raises(r.RecoveryError,match='EXPLICIT_LEDGER'):close(prewrite_case)
    store.initialize_project_prewrite_ledger(apply=True);before=original_rows(store.database)
    def changed(*a):return {**value,'capture_sha256':'0'*64}
    def failed(*a):raise RuntimeError('PRIVATE_SENTINEL')
    for observer in (changed,failed,lambda *a:None):
        with pytest.raises(r.RecoveryError) as error:close(prewrite_case,observer=observer)
        assert 'PRIVATE_SENTINEL' not in str(error.value)
    assert original_rows(store.database)==before and store.eligibility(value['binding']['job_id'])['blocks_admission'] is True


@pytest.mark.parametrize('fault',['success','retry','human','17-files','dispatch-file','wrong-package','wrong-policy','wrong-claim','wrong-family'])
def test_wrong_or_success_shaped_assessments_do_not_close(prewrite_case,fault):
    *_,store,saved,old=prewrite_case;store.initialize_project_prewrite_ledger(apply=True);value=deepcopy(saved)
    if fault=='success':value['technical_success']=True
    elif fault=='retry':value['recovery_authorized']=True
    elif fault=='human':value['human_acceptance_recorded']=True
    elif fault=='17-files':value['retained_sha256']=old['retained_sha256']
    elif fault=='dispatch-file':value['collection_sha256']['dispatch-receipt.json']='e'*64
    elif fault=='wrong-package':value['collection_sha256']['package.zip']='e'*64
    elif fault=='wrong-policy':value['target']['compartment_id']='another-compartment'
    elif fault=='wrong-claim':value['claim_sha256']='0'*64
    else:value['scope']='fox-project-qa-stage-failure-assessment-v1'
    with pytest.raises((r.RecoveryError,ValueError)):close(prewrite_case,value)
    with sqlite3.connect(store.database) as db:assert db.execute('SELECT count(*) FROM verification_project_prewrite_failures').fetchone()[0]==0


def test_actual_sqlite_competing_append_is_once_only(prewrite_case):
    *_,store,_,_=prewrite_case;store.initialize_project_prewrite_ledger(apply=True)
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:close(prewrite_case),range(2)))
    assert sorted(v['action'] for v in results)==['ALREADY_RECORDED_NO_REPLAY','RECORDED_ONCE']


def test_append_fences_are_enforced_and_never_silently_repaired(prewrite_case):
    *_,store,_,_=prewrite_case;store.initialize_project_prewrite_ledger(apply=True);close(prewrite_case)
    with sqlite3.connect(store.database) as db:
        for statement in ('DELETE FROM verification_project_prewrite_failures',"UPDATE verification_project_prewrite_failures SET closed_at_utc='changed'"):
            with pytest.raises(sqlite3.IntegrityError):db.execute(statement)
        db.execute('DROP TRIGGER verification_project_prewrite_failures_no_update')
    with pytest.raises(r.RecoveryError,match='SCHEMA_OR_FENCES'):store.initialize_project_prewrite_ledger(apply=True)
    assert store.rollout_readiness()['ready'] is False


def test_public_status_is_failure_not_pass_or_retry_and_rechecks_retained_package(prewrite_case):
    case,database,binding,claim,store,_,_=prewrite_case
    store.initialize_project_prewrite_ledger(apply=True);close(prewrite_case)
    with sqlite3.connect(database) as db:
        runtime.initialize_contact_schema(db);db.row_factory=sqlite3.Row;run=dict(db.execute('SELECT * FROM runs WHERE id=?',(binding.job_id,)).fetchone())
    result=runtime.public_status(case.root,run,runtime.VerificationConfig(True,'9'*64))
    assert result['state']=='project_prewrite_failed_closed' and 'before test-data writes' in result['message']
    assert 'No successful verification or automatic retry' in result['message'] and claim.attempt_token not in json.dumps(result)
    (case.job/'apex-package.zip').write_bytes(b'changed synthetic fixture')
    assert store.eligibility(binding.job_id)['blocks_admission'] is True


@pytest.mark.parametrize('first',['stage','prewrite'])
def test_failure_families_cannot_relabel_each_other(prewrite_case,first):
    case,_,_,_,store,new,old=prewrite_case
    store.initialize_project_prewrite_ledger(apply=True);store.initialize_qa_stage_failure_ledger(apply=True)
    def old_close():
        raw=r.canonical_bytes(old);return store.close_qa_stage_failure(raw,expected_sha256=r.digest(raw),observer=lambda *a:deepcopy(old),apply=True,now=case.now)
    if first=='stage':
        old_close()
        with pytest.raises(r.RecoveryError,match='CONFLICTING'):close(prewrite_case)
    else:
        close(prewrite_case)
        with pytest.raises(r.RecoveryError,match='CONFLICTING'):old_close()
