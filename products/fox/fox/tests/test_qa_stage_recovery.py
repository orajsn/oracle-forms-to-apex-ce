"""Real project package/store gates; synthetic stopped observer, no live writes.

These tests exercise the append-only backend, not host exclusion or live
classification authority. The separate raw-capture tests cover that classifier.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import socket
import sqlite3
import subprocess

import pytest

from fox import verification_recovery as r, verification_runtime as runtime
from fox.verification_queue import VerificationBinding,VerificationQueue
from test_project_verification_runtime import actual_release,case


@pytest.fixture(autouse=True)
def no_external_actions(monkeypatch):
    def denied(*args,**kwargs):pytest.fail('No external action is allowed in ledger tests')
    monkeypatch.setattr(socket,'create_connection',denied)
    monkeypatch.setattr(socket.socket,'connect',denied)
    monkeypatch.setattr(subprocess,'run',denied)
    monkeypatch.setattr(subprocess,'Popen',denied)


def original_rows(database):
    with sqlite3.connect(database) as db:
        return r.VerificationRecovery._precheck_original_rows(db)


@pytest.fixture
def stage_case(case):
    database=case.root/'fox.sqlite3'
    # This low-level release fixture predates normal UI intake approvals.
    # Explicitly authorize its synthetic processing, never business acceptance.
    case.snapshot['approvals']={'redacted_source':True,'external_ai':True,'synthetic_prototype':True}
    (case.job/'source-snapshot.json').write_bytes(r.canonical_bytes(case.snapshot))
    binding=VerificationBinding(case.run_id,case.snapshot['source_hash'],r.digest(case.built.package),'a'*64)
    queue=VerificationQueue(database,enabled=True,verifier_release_sha256=binding.verifier_release_sha256)
    queue.initialize();queue.enqueue(binding);claim=queue.claim_next();queue.attention(claim)
    with sqlite3.connect(database) as db:
        db.row_factory=sqlite3.Row
        row=dict(db.execute('SELECT * FROM verification_queue WHERE job_id=?',(case.run_id,)).fetchone())
    retained={name:'d'*64 for name in ('session.json','attention.json','p0001-qa-stage.intent.json',
        *('p0001-'+step+suffix for step in ('claim','prepare','clean-check','allocate','schema','import','verify')
          for suffix in ('.intent.json','.complete.json')))}
    clean={name:'e'*64 for name in ('package.zip','native-project-spec.json','source-to-apex.json',
        'allocate.evidence.json','verification-profile.json','verify.evidence.json','plan.json',
        'schema.evidence.json','import.evidence.json',
        *(phase+suffix for phase in ('allocate','schema','import','verify')
          for suffix in ('.intent.json','.complete.json')))}
    clean['package.zip']=binding.package_sha256
    policy={'schema_version':1,'scope':'fox-native-verification-profile-v2','policy_id':r.POLICY_ID,
        'binding':{k:v for k,v in binding.payload().items() if k!='verifier_release_sha256'}
            | {'allocation_receipt_sha256':clean['allocate.evidence.json']},
        'target':case.policy.target,'expected_versions':case.policy.versions,'max_evidence_age_seconds':86400}
    clean['verification-profile.json']=r.digest(r.canonical_bytes(policy))
    assessment={'schema_version':1,'scope':'fox-project-qa-stage-failure-assessment-v1',
        'status':'CLASSIFIED_QA_STAGE_FAILURE_NOT_CLOSED','binding':binding.payload(),
        'session':'session-'+'b'*24,'installation_sha256':'c'*64,'legacy_record_sha256':row['record_sha256'],
        'claim_sha256':r.claim_sha256(claim),'retained_sha256':retained,'clean_sha256':clean,
        'capture_sha256':'f'*64,'plan_sha256':clean['plan.json'],'qa_source_sha256':'7'*64,
        'completed_steps':['prepare','clean_check','allocate','schema','import','verify'],
        'failed_phase':'qa_stage','missing_dependency':'fox.native_verification',
        'target':case.policy.target,'expected_versions':case.policy.versions,
        'current_admission_blocks':True,'closure_performed':False,'technical_success':False,
        'human_acceptance_recorded':False,'automatic_replay_permitted':False,'recovery_authorized':False}
    return case,database,binding,claim,r.VerificationRecovery(database,enabled=True),assessment


def close(value,assessment=None,observer=None):
    case,_,_,_,store,saved=value;assessment=assessment or saved;raw=r.canonical_bytes(assessment)
    return store.close_qa_stage_failure(raw,expected_sha256=r.digest(raw),
        observer=observer or (lambda *args:deepcopy(assessment)),apply=True,now=case.now)


def test_closure_preserves_project_queue_claim_artifacts_and_no_pass_or_retry(stage_case):
    case,database,binding,claim,store,value=stage_case
    original=original_rows(database);files={p:r.digest(p.read_bytes()) for p in case.job.rglob('*') if p.is_file()}
    assert store.eligibility(binding.job_id)['blocks_admission'] is True
    assert store.initialize_qa_stage_failure_ledger(apply=True)['created'] is True
    assert store.initialize_qa_stage_failure_ledger(apply=True)['created'] is False
    result=close(stage_case)
    assert result['status']=='FAILED_QA_STAGE_CLOSED' and result['action']=='RECORDED_ONCE'
    assert all(result[k] is False for k in ('technical_success','human_acceptance_recorded','automatic_retry_permitted'))
    assert original_rows(database)==original and all(r.digest(p.read_bytes())==sha for p,sha in files.items())
    assert claim.attempt_token not in json.dumps(result)
    assert store.eligibility(binding.job_id)=={'blocks_admission':False,'recovery_state':'qa_stage_failed_closed','retry_eligible':False}
    with store._db() as db:
        db.execute('BEGIN')
        assert store.normal_claim_allowed(db,binding) is False
    again=close(stage_case,observer=lambda *args:pytest.fail('Do not re-observe an identical recorded append'))
    assert again['action']=='ALREADY_RECORDED_NO_REPLAY' and original_rows(database)==original


def test_explicit_initialization_hash_and_protected_observer_are_required(stage_case):
    *_,store,value=stage_case;raw=r.canonical_bytes(value)
    with pytest.raises(r.RecoveryError,match='EXPLICIT_INITIALIZATION'):store.initialize_qa_stage_failure_ledger()
    with pytest.raises(r.RecoveryError,match='PROTECTED_OBSERVER'):
        store.close_qa_stage_failure(raw,expected_sha256=r.digest(raw),apply=True)
    with pytest.raises(r.RecoveryError,match='EXPLICIT_LEDGER'):close(stage_case)
    store.initialize_qa_stage_failure_ledger(apply=True)
    with pytest.raises(r.RecoveryError,match='EXACT_REVIEWED'):
        store.close_qa_stage_failure(raw,expected_sha256='0'*64,observer=lambda *a:value,apply=True)


def test_changed_or_successful_summary_is_never_closed(stage_case):
    _,database,_,_,store,original=stage_case;store.initialize_qa_stage_failure_ledger(apply=True)
    before=original_rows(database)
    mutations=[lambda d:d.update(technical_success=True),lambda d:d.update(closure_performed=True),
        lambda d:d.update(recovery_authorized=True),lambda d:d.update(automatic_replay_permitted=True),
        lambda d:d.update(human_acceptance_recorded=True),lambda d:d.update(failed_phase='clean_check'),
        lambda d:d.update(legacy_record_sha256='9'*64),lambda d:d.update(claim_sha256='9'*64),
        lambda d:d['retained_sha256'].pop('p0001-verify.complete.json'),
        lambda d:d['retained_sha256'].update({'p0001-qa-run.intent.json':'9'*64}),
        lambda d:d['clean_sha256'].update({'runtime-credentials.json':'9'*64}),
        lambda d:d['clean_sha256'].update({'package.zip':'9'*64}),
        lambda d:d['target'].update(compartment_id='not-jsn'),lambda d:d['expected_versions'].update(apex='26.1.999')]
    for mutation in mutations:
        value=deepcopy(original);mutation(value)
        with pytest.raises((r.RecoveryError,ValueError)):close(stage_case,value)
    assert original_rows(database)==before
    with sqlite3.connect(database) as db:assert db.execute('SELECT count(*) FROM verification_qa_stage_failures').fetchone()[0]==0


def test_failed_or_changed_fresh_observer_rolls_back(stage_case):
    _,database,binding,_,store,value=stage_case;store.initialize_qa_stage_failure_ledger(apply=True)
    original=original_rows(database)
    def raises(*a):raise RuntimeError('PRIVATE_DIAGNOSTIC_SENTINEL')
    for observer in (raises,lambda *a:None,lambda *a:{**value,'capture_sha256':'0'*64}):
        with pytest.raises(r.RecoveryError) as error:close(stage_case,observer=observer)
        assert 'PRIVATE_DIAGNOSTIC_SENTINEL' not in str(error.value)
    assert original_rows(database)==original and store.eligibility(binding.job_id)['blocks_admission'] is True


def test_fences_and_retained_source_are_rechecked_not_repaired(stage_case):
    _,database,binding,_,store,_=stage_case;store.initialize_qa_stage_failure_ledger(apply=True);close(stage_case)
    with sqlite3.connect(database) as db:
        for statement in ('DELETE FROM verification_qa_stage_failures',"UPDATE verification_qa_stage_failures SET closed_at_utc='changed'"):
            with pytest.raises(sqlite3.IntegrityError):db.execute(statement)
        db.execute('DROP TRIGGER verification_qa_stage_failures_no_update')
    with pytest.raises(r.RecoveryError,match='SCHEMA_OR_FENCES'):store.initialize_qa_stage_failure_ledger(apply=True)
    assert store.eligibility(binding.job_id)['blocks_admission'] is True


def test_changed_retained_package_blocks_admission_after_closure(stage_case):
    case,_,binding,_,store,_=stage_case;store.initialize_qa_stage_failure_ledger(apply=True);close(stage_case)
    (case.job/'apex-package.zip').write_bytes(b'changed synthetic bytes')
    assert store.eligibility(binding.job_id)['blocks_admission'] is True


def test_competing_append_is_once_only_under_actual_sqlite_transactions(stage_case):
    *_,store,_=stage_case;store.initialize_qa_stage_failure_ledger(apply=True)
    with ThreadPoolExecutor(max_workers=2) as executor:results=list(executor.map(lambda _:close(stage_case),range(2)))
    assert sorted(item['action'] for item in results)==['ALREADY_RECORDED_NO_REPLAY','RECORDED_ONCE']


def test_public_status_explains_generated_app_and_environment_repair_without_secret(stage_case):
    case,database,binding,claim,store,_=stage_case
    store.initialize_qa_stage_failure_ledger(apply=True);close(stage_case)
    with sqlite3.connect(database) as db:
        runtime.initialize_contact_schema(db);db.row_factory=sqlite3.Row
        run=dict(db.execute('SELECT * FROM runs WHERE id=?',(binding.job_id,)).fetchone())
    status=runtime.public_status(case.root,run,runtime.VerificationConfig(True,'9'*64))
    assert status['state']=='qa_stage_failed_closed'
    assert 'APEX was generated and clean-imported' in status['message']
    assert 'No technical success or automatic retry' in status['message']
    assert claim.attempt_token not in json.dumps(status)
    assert set(status)=={'configured','state','operator_contact','operator_last_seen_at_utc','queue_updated_at_utc','message'}


def test_orphaned_failure_history_cannot_disappear_from_global_admission(stage_case):
    _,database,_,_,store,_=stage_case;store.initialize_qa_stage_failure_ledger(apply=True);close(stage_case)
    # Deliberate corruption of disposable fixture data, not a supported action.
    with sqlite3.connect(database) as db:
        db.execute('PRAGMA foreign_keys=OFF');db.execute('DELETE FROM verification_queue');db.execute('DELETE FROM runs')
    assert store.rollout_readiness()['ready'] is False


@pytest.mark.parametrize('first',['stage','precheck'])
def test_failure_families_cannot_relabel_each_other(stage_case,first):
    case,database,binding,claim,store,stage=stage_case
    store.initialize_precheck_ledger(apply=True);store.initialize_qa_stage_failure_ledger(apply=True)
    legacy={'schema_version':1,'scope':'fox-read-only-precheck-assessment-v1',
        'status':'CLASSIFIED_PRECHECK_FAILURE_REQUIRES_PROTECTED_RECOVERY','binding':binding.payload(),
        'session':stage['session'],'legacy_record_sha256':stage['legacy_record_sha256'],
        'claim_sha256':r.claim_sha256(claim),'retained_sha256':{name:'d'*64 for name in
            ('session.json','attention.json','p0001-claim.intent.json','p0001-claim.complete.json',
             'p0001-prepare.intent.json','p0001-prepare.complete.json','p0001-clean-check.intent.json')},
        'package_sha256':binding.package_sha256,'source_snapshot_sha256':r.digest((case.job/'source-snapshot.json').read_bytes()),
        'release_evidence_sha256':r.digest((case.job/'release-evidence.json').read_bytes()),
        'plan_sha256':'e'*64,'operator_code_sha256':'f'*64,'failed_phase':'clean_check',
        'missing_dependency':'fox.project_qa_plan','current_admission_blocks':True,'closure_performed':False,
        'technical_success':False,'human_acceptance_recorded':False,'automatic_replay_permitted':False,
        'scope_note':'Retained evidence classification only. No host authority, closure, import, retry or readiness is granted.'}
    def close_legacy():
        raw=r.canonical_bytes(legacy)
        return store.close_precheck_failure(raw,expected_sha256=r.digest(raw),observer=lambda *a:deepcopy(legacy),apply=True,now=case.now)
    if first=='stage':
        close(stage_case)
        with pytest.raises(r.RecoveryError,match='CONFLICTING'):close_legacy()
    else:
        close_legacy()
        with pytest.raises(r.RecoveryError,match='CONFLICTING'):close(stage_case)
