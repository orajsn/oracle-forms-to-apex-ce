"""Modeled Oracle transports; real immutable retry/isolation readers, no live proof."""
from copy import deepcopy
import hashlib

import pytest

from forms2apex import blueprint_profiles
from forms2apex.project_reviews import canonical,digest,read_object
from forms2apex.security import alias_for_job
from forms2apex.target_profile import select_target_profile
from forms2apex.prototype_validation_retry import PREFIX
from test_prototype_gateway import case,advance,authority_bundle
from test_prototype_isolation import seal_import


@pytest.fixture
def retried_stopped(case):
    bundle=authority_bundle(case)  # Existing structural-only transport fixture.
    case.request['source_authority']=bundle['source_authority']
    case.adapter.stage_source_authority(case.request['job_id'],bundle)
    profile=select_target_profile('jsn-native-beta-v1')
    case.adapter.target_profile_loader=lambda settings:profile
    class AuthoredOwner:
        def __call__(self,request): return deepcopy(request)
        def authorize_validation_retry(self,request,key): return deepcopy(request)
    case.adapter.authorize=AuthoredOwner()  # Owner HTTP/SQLite is covered separately.
    original_validator=case.adapter.validator
    def failed(sql,app,log):
        log.write_text('authored initial wrapper failure')
        return {'passed':False,'return_code':126,'log':str(log)}
    case.adapter.validator=failed
    original=case.adapter.run_stage('validate',case.request)
    assert original['status']=='FAILED'
    root=case.settings.jobs_root/case.request['job_id']/'prototype-converter'
    before={p.name:p.read_bytes() for p in root.iterdir() if p.is_file()}
    case.adapter.validator=original_validator
    witness=case.adapter.validation_retry_witness(case.request['job_id'])
    receipt=case.adapter.retry_validation(case.request,witness,'a'*64)
    case.request['prior_receipts']['validate']=receipt
    files=case.renderer.render_native_blueprint(case.request['rendering_spec'])
    compiled=digest({n:hashlib.sha256(v.encode()).hexdigest() for n,v in files.items()})
    original_import=case.adapter.importer
    def imported(*args,**kwargs):
        return {**original_import(*args,**kwargs),'application_alias':alias_for_job(case.request['job_id']),
            'workspace':'FORMS2APEX_POC','compiled_metadata_sha256':compiled}
    case.adapter.importer=imported
    advance(case,'prepare_schema');advance(case,'import')
    case.root=root
    seal_import(case)  # Existing explicitly authored durable import fixture.
    (root/'verify_runtime-request.json').write_bytes(canonical(case.request))
    (root/'verify_runtime-intent.json').write_bytes(canonical({'request_sha256':digest(case.request)}))
    for name,raw in before.items(): assert (root/name).read_bytes()==raw
    return case


def test_completed_retry_has_exact_readonly_terminal_isolation(retried_stopped):
    case=retried_stopped
    before={p.relative_to(case.root):p.read_bytes() for p in case.root.rglob('*') if p.is_file()}
    result=case.adapter.isolation_witness(case.request['job_id'],'a'*64)
    assert result['boundary']=='runtime_not_dispatched'
    assert result['execution_authorized'] is result['retry_authorized'] is False
    assert before=={p.relative_to(case.root):p.read_bytes() for p in case.root.rglob('*') if p.is_file()}
    assert read_object(case.root/'validate.json')['status']=='FAILED'


def test_retry_isolation_rejects_unknown_nested_file(retried_stopped):
    case=retried_stopped
    (case.root/PREFIX/'unknown.json').write_text('{}')
    with pytest.raises(RuntimeError): case.adapter.isolation_witness(case.request['job_id'],'a'*64)


def test_schema3_omission_assessment_stage_and_recovery_remain_supported(case):
    """Exact historical transport grammar, structural fixture only."""
    import base64
    import json
    from test_prototype_gateway import rebind_bundle
    from forms2apex.prototype_gateway import _AUTHORITY_ROOT_FILES
    bundle=authority_bundle(case)
    members={row['path']:base64.b64decode(row['content_base64']) for row in bundle['files']}
    binding=json.loads(members['binding.json'])
    binding['candidate_format_policy']='exact-source-envelope-and-item-fact-aliases-v1'
    members['binding.json']=canonical(binding)
    members['assessment.json']=canonical({'structural_fixture':True})
    members['redacted-query-omission.json']=canonical({'structural_fixture':'historical-query-omission'})
    index=json.loads(members['review-index.json'])
    index.update(schema_version=3,candidate_format_policy=binding['candidate_format_policy'])
    index['provenance_files']=[{'path':name,'sha256':hashlib.sha256(raw).hexdigest()}
        for name,raw in sorted(members.items()) if name not in _AUTHORITY_ROOT_FILES and not name.startswith('sources/')]
    members['review-index.json']=canonical(index)
    bundle['source_authority']['binding_sha256']=digest(binding)
    bundle['source_authority']['review_index_sha256']=digest(index)
    bundle['files']=[{'path':name,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),
        'content_base64':base64.b64encode(raw).decode()} for name,raw in sorted(members.items())]
    rebind_bundle(bundle)
    receipt=case.adapter.stage_source_authority(case.request['job_id'],bundle)
    assert receipt['source_review_authorized'] is False
    assert case.adapter.recover_source_authority(case.request['job_id'])==receipt
