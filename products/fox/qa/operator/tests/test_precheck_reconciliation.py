"""Synthetic raw-journal classification only; no host/closure/Oracle authority."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/'fox')]
from fox import verification_queue as q
from qa.operator import contracts as C
from qa.operator.precheck_reconciliation import assess_capture,PrecheckEvidenceError

RELEASE='d'*64
OPERATOR='f'*64
TOKEN='0123456789abcdef'*2


def synthetic_capture():
    package=b'Clearly synthetic retained bytes; not an APEX validation fixture.'
    binding=q.VerificationBinding('fox-'+'1'*20,'a'*64,hashlib.sha256(package).hexdigest(),RELEASE)
    row={**binding.payload(),'binding_sha256':q._digest(binding.payload()),'state':'attention',
        'claim_token':TOKEN,'proof_sha256':None,'attention_code':'BACKEND_OUTCOME_UNCONFIRMED',
        'created_at_utc':'2026-11-04T00:00:00Z','updated_at_utc':'2026-11-04T00:01:00Z'}
    row['record_sha256']=q._digest(row)
    bsha=C.digest(C.canonical_bytes(binding.payload()))
    journal={'session.json':{'scope':'fox-product-verifier-session-v1','release_sha256':RELEASE,
        'started_at_utc':'2026-11-04T00:00:00Z','startup_authorized':True,
        'bounds':{'max_jobs':1,'max_polls':120,'max_seconds':7200,'poll_seconds':5}},
        'attention.json':{'status':'ATTENTION','release_sha256':RELEASE,'known_claim':True,
            'code':'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE','automatic_replay_permitted':False}}
    for phase in ('claim','prepare','clean-check'):
        label='p0001-'+phase
        journal[label+'.intent.json']={'scope':'fox-product-verifier-step-v1','release_sha256':RELEASE,
            'step':label,'binding_sha256':None if phase=='claim' else bsha}
    for phase,result in (
        ('claim',{'status':'CLAIMED','claim':{'binding':binding.payload(),'attempt_token':TOKEN}}),
        ('prepare',{'conversion_profile':'native-project-v1',**{k:v for k,v in binding.payload().items()
            if k!='verifier_release_sha256'},'plan_sha256':'b'*64,'operator_code_sha256':OPERATOR})):
        journal['p0001-'+phase+'.complete.json']={'scope':'fox-product-verifier-step-result-v1',
            'release_sha256':RELEASE,'intent_sha256':C.digest(C.canonical_bytes(journal['p0001-'+phase+'.intent.json'])),
            'result':result}
    encode=lambda value:base64.b64encode(C.canonical_bytes(value)).decode()
    return {'scope':'fox-precheck-read-only-capture-v1','writes_requested':False,
        'service':{'ActiveState':'failed','SubState':'failed','MainPID':'0','LoadState':'loaded'},
        'session':'session-'+'e'*24,'journal':{k:encode(v) for k,v in journal.items()},
        'converter':{'qa_files':{name:False for name in ('__init__.py','intake.py','native_source.py',
            'project_conversion.py','native_qa_plan.py','project_qa_plan.py')},'active_sqlcl_pids':[]},
        'fox':{'queue':row,'run':{'id':binding.job_id,'state':'QA_REQUIRED',
            'source_hash':binding.source_manifest_sha256,'artifact':'jobs/'+binding.job_id+'/apex-package.zip'},
            'profile':'native-project-v1','acceptance_count':0,'verification_tables':[],
            'job_files':{'apex-package.zip':base64.b64encode(package).decode(),
                'source-snapshot.json':encode({'source_hash':binding.source_manifest_sha256,
                    'approvals':{'redacted_source':True,'external_ai':True,'synthetic_prototype':True}}),
                'release-evidence.json':encode({'job_id':binding.job_id,'source_manifest_sha256':binding.source_manifest_sha256}),
                'native-project/download.json':encode({'source_hash':binding.source_manifest_sha256,
                    'package_sha256':binding.package_sha256})}}}


def assess(value):
    return assess_capture(value,expected_release_sha256=RELEASE,expected_operator_code_sha256=OPERATOR)


def change_journal(value,name,change):
    document=json.loads(base64.b64decode(value['journal'][name]));change(document)
    value['journal'][name]=base64.b64encode(C.canonical_bytes(document)).decode()


def test_known_precheck_is_classified_without_claiming_success_or_closure():
    value=synthetic_capture();original=deepcopy(value)
    result=assess(value)
    assert result['failed_phase']=='clean_check' and result['missing_dependency']=='fox.project_qa_plan'
    assert result['current_admission_blocks'] is True
    assert all(result[key] is False for key in ('closure_performed','technical_success',
        'human_acceptance_recorded','automatic_replay_permitted'))
    assert value==original and TOKEN not in json.dumps(result)


@pytest.mark.parametrize('mutate',[
    lambda x:x['service'].update(MainPID='123'),
    lambda x:x['service'].update(ActiveState='active'),
    lambda x:x['converter'].update(active_sqlcl_pids=[42]),
    lambda x:x['converter']['qa_files'].update({'project_qa_plan.py':True}),
    lambda x:x['converter']['qa_files'].update({'project_qa_plan.py':0}),
    lambda x:x['fox'].update(acceptance_count=1),
    lambda x:x['fox'].update(acceptance_count=False),
    lambda x:x['fox']['run'].update(state='VERIFIED'),
    lambda x:x['fox']['run'].update(source_hash='b'*64),
    lambda x:x['fox']['queue'].update(claim_token='9'*32),
    lambda x:x['fox']['job_files'].update({'apex-package.zip':base64.b64encode(b'changed').decode()}),
    lambda x:x['journal'].update({'p0001-import.intent.json':base64.b64encode(b'{}').decode()}),
    lambda x:x['journal'].update({'p0001-clean-check.complete.json':base64.b64encode(b'{}').decode()}),
    lambda x:x['journal'].pop('p0001-prepare.complete.json'),
    lambda x:change_journal(x,'session.json',lambda d:d['bounds'].update(max_jobs=2)),
    lambda x:change_journal(x,'attention.json',lambda d:d.update(known_claim=False)),
    lambda x:change_journal(x,'p0001-claim.complete.json',lambda d:d['result']['claim'].update(attempt_token='9'*32)),
    lambda x:change_journal(x,'p0001-prepare.complete.json',lambda d:d['result'].update(operator_code_sha256='9'*64)),
    lambda x:change_journal(x,'p0001-clean-check.intent.json',lambda d:d.update(binding_sha256='9'*64)),
])
def test_live_changed_uncertain_or_mixed_evidence_is_not_classified(mutate):
    value=synthetic_capture();mutate(value)
    with pytest.raises(PrecheckEvidenceError):assess(value)


def test_independent_release_pin_cannot_be_taken_from_the_capture():
    with pytest.raises(PrecheckEvidenceError,match='RELEASE_CHANGED'):
        assess_capture(synthetic_capture(),expected_release_sha256='9'*64,expected_operator_code_sha256=OPERATOR)


def test_duplicate_json_keys_do_not_get_last_value_selection():
    value=synthetic_capture()
    value['journal']['attention.json']=base64.b64encode(b'{"known_claim":false,"known_claim":true}').decode()
    with pytest.raises(PrecheckEvidenceError,match='DUPLICATE_JSON_KEY'):assess(value)
