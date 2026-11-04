"""Real retained-package gates, synthetic SQLite and injected stopped observer.

No live job/capture is used and no Oracle/network/subprocess action is allowed.
"""
from copy import deepcopy
import json
import sqlite3

import pytest

from fox import verification_recovery as r
from test_native_pipeline import harness,valid_package
from test_native_verification import proof_case
from test_native_verification_policy import v2_case
from test_verification_recovery import example,no_external_actions,preserved,record,NOW


def assessment(example):
    bundle,database,queue,claim,store,_=example
    binding=claim.binding
    with sqlite3.connect(database) as db:
        db.row_factory=sqlite3.Row
        row=dict(db.execute('SELECT * FROM verification_queue WHERE job_id=?',(binding.job_id,)).fetchone())
    job=database.parent/'jobs'/binding.job_id
    return {'schema_version':1,'scope':'fox-read-only-precheck-assessment-v1',
        'status':'CLASSIFIED_PRECHECK_FAILURE_REQUIRES_PROTECTED_RECOVERY',
        'binding':binding.payload(),'session':'session-'+'e'*24,
        'legacy_record_sha256':row['record_sha256'],'claim_sha256':r.claim_sha256(claim),
        'retained_sha256':{name:'d'*64 for name in ('session.json','attention.json',
            'p0001-claim.intent.json','p0001-claim.complete.json','p0001-prepare.intent.json',
            'p0001-prepare.complete.json','p0001-clean-check.intent.json')},
        'package_sha256':binding.package_sha256,
        'source_snapshot_sha256':r.digest((job/'source-snapshot.json').read_bytes()),
        'release_evidence_sha256':r.digest((job/'release-evidence.json').read_bytes()),
        'plan_sha256':'b'*64,'operator_code_sha256':'f'*64,'failed_phase':'clean_check',
        'missing_dependency':'fox.project_qa_plan','current_admission_blocks':True,
        'closure_performed':False,'technical_success':False,'human_acceptance_recorded':False,
        'automatic_replay_permitted':False,
        'scope_note':'Retained evidence classification only. No host authority, closure, import, retry or readiness is granted.'}


def close(example,value=None,observer=None):
    value=value or assessment(example);raw=r.canonical_bytes(value)
    return example[4].close_precheck_failure(raw,expected_sha256=r.digest(raw),
        observer=observer or (lambda binding,session:deepcopy(value)),apply=True,now=NOW)


def test_close_is_append_only_and_never_promotes_accepts_or_retries(example):
    _,database,_,claim,store,_=example
    original=preserved(database)
    assert store.eligibility(claim.binding.job_id)['blocks_admission'] is True
    assert store.initialize_precheck_ledger(apply=True)['created'] is True
    assert store.initialize_precheck_ledger(apply=True)['created'] is False
    calls=[];value=assessment(example)
    first=close(example,value,lambda *args:(calls.append(args) or deepcopy(value)))
    assert first['status']=='FAILED_PRECHECK_CLOSED' and first['action']=='RECORDED_ONCE'
    assert all(first[key] is False for key in ('technical_success','human_acceptance_recorded','automatic_retry_permitted'))
    assert claim.attempt_token not in json.dumps(first)
    assert preserved(database)==original and len(calls)==1
    assert store.eligibility(claim.binding.job_id)=={'blocks_admission':False,
        'recovery_state':'precheck_failed_closed','retry_eligible':False}
    second=close(example,value,lambda *args:pytest.fail('A lost reply must not re-observe or repeat closure.'))
    assert second['action']=='ALREADY_RECORDED_NO_REPLAY' and preserved(database)==original


def test_explicit_initialization_and_actual_observer_are_required(example):
    store=example[4];value=assessment(example);raw=r.canonical_bytes(value)
    with pytest.raises(r.RecoveryError,match='EXPLICIT_INITIALIZATION'):
        store.initialize_precheck_ledger()
    with pytest.raises(r.RecoveryError,match='PROTECTED_OBSERVER'):
        store.close_precheck_failure(raw,expected_sha256=r.digest(raw),apply=True)
    with pytest.raises(r.RecoveryError,match='EXPLICIT_LEDGER'):
        close(example,value)


@pytest.mark.parametrize('mutate',[
    lambda d:d.update(technical_success=True),lambda d:d.update(closure_performed=True),
    lambda d:d.update(automatic_replay_permitted=True),lambda d:d.update(human_acceptance_recorded=True),
    lambda d:d.update(failed_phase='import'),lambda d:d.update(legacy_record_sha256='9'*64),
    lambda d:d.update(claim_sha256='9'*64),lambda d:d.update(source_snapshot_sha256='9'*64),
    lambda d:d['retained_sha256'].update({'p0001-import.intent.json':'9'*64}),
])
def test_changed_or_successful_evidence_cannot_be_closed(example,mutate):
    store=example[4];store.initialize_precheck_ledger(apply=True)
    original=preserved(example[1]);value=assessment(example);mutate(value)
    with pytest.raises(r.RecoveryError):close(example,value)
    assert preserved(example[1])==original
    with sqlite3.connect(example[1]) as db:
        assert db.execute('SELECT COUNT(*) FROM verification_precheck_failures').fetchone()[0]==0


@pytest.mark.parametrize('mode',['changed','unavailable','raises'])
def test_observer_failure_rolls_back_without_a_closure(example,mode):
    store=example[4];store.initialize_precheck_ledger(apply=True)
    value=assessment(example);original=preserved(example[1])
    def observer(*args):
        if mode=='raises':raise RuntimeError('PRIVATE_PROVIDER_SENTINEL')
        if mode=='unavailable':return None
        return {**value,'plan_sha256':'9'*64}
    with pytest.raises(r.RecoveryError) as error:close(example,value,observer)
    assert 'PRIVATE_PROVIDER_SENTINEL' not in str(error.value)
    assert preserved(example[1])==original
    assert store.eligibility(example[3].binding.job_id)['blocks_admission'] is True


def test_completed_qa_disposition_cannot_be_relabelled_as_a_precheck(example):
    record(example)
    example[4].initialize_precheck_ledger(apply=True)
    with pytest.raises(r.RecoveryError,match='CONFLICTING_RECOVERY_HISTORY'):close(example)


def test_fences_prevent_edit_delete_and_silent_repair(example):
    store=example[4];store.initialize_precheck_ledger(apply=True);close(example)
    with sqlite3.connect(example[1]) as db:
        with pytest.raises(sqlite3.IntegrityError):db.execute('DELETE FROM verification_precheck_failures')
        with pytest.raises(sqlite3.IntegrityError):db.execute("UPDATE verification_precheck_failures SET closed_at_utc='changed'")
        db.execute('DROP TRIGGER verification_precheck_failures_no_update')
    with pytest.raises(r.RecoveryError,match='SCHEMA_OR_FENCES'):store.initialize_precheck_ledger(apply=True)
    assert store.eligibility(example[3].binding.job_id)['blocks_admission'] is True


def test_changed_retained_bytes_make_closed_history_non_admissible(example):
    store=example[4];store.initialize_precheck_ledger(apply=True);close(example)
    job=example[1].parent/'jobs'/example[3].binding.job_id
    (job/'source-snapshot.json').write_bytes(b'{"changed":true}')
    assert store.eligibility(example[3].binding.job_id)['blocks_admission'] is True


def test_public_status_explains_old_precheck_under_a_new_release_without_private_data(example):
    from fox import verification_runtime as runtime
    store=example[4];store.initialize_precheck_ledger(apply=True);close(example)
    with sqlite3.connect(example[1]) as db:
        runtime.initialize_contact_schema(db)
        db.row_factory=sqlite3.Row
        run=dict(db.execute('SELECT * FROM runs WHERE id=?',(example[3].binding.job_id,)).fetchone())
    status=runtime.public_status(example[1].parent,run,runtime.VerificationConfig(True,'b'*64))
    assert status['state']=='precheck_failed_closed'
    assert 'stopped before QA' in status['message'] and 'original output is preserved' in status['message']
    assert 'No technical success or automatic retry' in status['message']
    assert example[3].attempt_token not in json.dumps(status)
    assert set(status)=={'configured','state','operator_contact','operator_last_seen_at_utc','queue_updated_at_utc','message'}
