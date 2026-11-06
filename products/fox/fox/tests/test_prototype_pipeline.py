"""Synthetic adapter orchestration tests, NOT model/Oracle/browser live proof."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

from fox.forms_native_plan import POLICY_ID
from fox.forms_understanding_packet import local_packet
from fox.opaf import OpafError, canonical_hash
from fox.prototype_pipeline import (CONVERTER_STAGES, authorize_prototype_request,
                                    run_prototype_pipeline)


def documents():
    return [(name + '.xml', (
        f'<FormModule Name="{name}"><Block Name="MAIN" DatabaseBlock="true">'
        '<Item Name="VALUE" ItemType="Text Item" DataType="Char" '
        'MaximumLength="80" DatabaseItem="true" Prompt="Value"/>'
        '<Trigger Name="SAVE" TriggerText="BEGIN BUSINESS_API.SAVE; END;"/>'
        '</Block></FormModule>').encode()) for name in ('FIRST', 'SECOND')]


PROFILE = {
    'mapper': {'workflow_id': 'A' * 32, 'model': 'synthetic-mapper', 'graph_sha256': 'a' * 64},
    'reviewer': {'workflow_id': 'B' * 32, 'model': 'synthetic-reviewer', 'graph_sha256': 'b' * 64}}
TARGET = {'opaf': {'base_url': 'https://localhost:8080/agentFactory',
                  'certificate_sha256': 'c' * 64, 'model_authentication': 'oci_instance_principal',
                  'version_number': '26.4', 'build_id': 'synthetic', 'roles': PROFILE},
          'tested_versions': {'opaf': 'synthetic-26.4'}}


class SyntheticOpaf:
    """Authored replies with synthetic provenance; never an actual invocation."""

    def __init__(self):
        self.calls, self.observations = [], []
        self.fail_role = self.changes_role = self.invalid_candidate = None

    def observe_environment(self, role, identity, *, role_name, target_profile):
        self.observations.append((role_name, deepcopy(identity)))
        return {'schema_version': 1, 'scope': 'opaf-model-environment-v1',
                'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
                'job_id': identity['job_id'], 'role': role_name,
                'source_manifest_sha256': identity['source_hash'],
                'target_profile_sha256': canonical_hash(target_profile),
                'observed_at_utc': '2026-11-06T00:00:00+00:00',
                'opaf': {key: target_profile['opaf'][key] for key in
                         ('base_url', 'certificate_sha256', 'model_authentication', 'version_number', 'build_id')},
                'workflow': {**role, 'published': True}, 'opaf_version': 'synthetic-26.4'}

    def invoke(self, role, request):
        name = 'mapper' if role == PROFILE['mapper'] else 'reviewer'
        self.calls.append((name, deepcopy(request)))
        if self.fail_role == name:
            raise OSError('SENSITIVE_PROVIDER_ERROR_MUST_NOT_ESCAPE')
        if name == 'mapper':
            assert 'job_id' not in request and 'focus_request' not in request
            rows, screens = [], []
            screen_id = 'screen-' + request['focus_id']
            for obj in request['owned_objects']:
                row = {'source_object_id': obj['id'], 'disposition': 'unresolved',
                       'reason': 'Synthetic structural mapping; no translated business behavior.'}
                if obj['kind'] in ('Block', 'Item'):
                    row.update(disposition='proposed', screen_id=screen_id)
                    if obj['kind'] == 'Block':
                        row['native_component'] = 'form'
                    if not screens:
                        screens.append({'id': screen_id, 'title': 'Synthetic native screen'})
                rows.append(row)
            output = {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
                      'blueprint': {'schema_version': 1, 'scope': 'fox-forms-blueprint-v1',
                          'source_binding': request['source_binding'], 'objects': rows, 'screens': screens,
                          **{key: [] for key in ('claims', 'relationships', 'actions', 'questions', 'assumptions')}}}
            if self.invalid_candidate:
                output['blueprint']['objects'][0]['source_object_id'] = 'invented-owner'
        else:
            assert set(request) == {'request', 'candidate', 'candidate_sha256'}
            focus = request['request']
            output = {'source_binding': focus['source_binding'], 'focus_binding': focus['focus_binding'],
                      'candidate_sha256': request['candidate_sha256'], 'verdict': 'APPROVED', 'findings': []}
            if self.changes_role:
                output.update(verdict='CHANGES_REQUIRED', findings=[{
                    'source_object_id': None, 'code': 'REVIEW_MAPPING', 'detail': 'Synthetic authored rejection.'}])
        return output, {**role, 'room_id': 'synthetic-room-' + str(len(self.calls)),
                        'request_sha256': canonical_hash(request), 'response_sha256': canonical_hash(output),
                        'started_at_utc': '2026-11-06T00:00:01+00:00',
                        'completed_at_utc': '2026-11-06T00:00:02+00:00'}


class SyntheticConverter:
    """Authored stage receipts, not SQLcl/Oracle/authenticated browser proof."""

    def __init__(self, supported=CONVERTER_STAGES):
        self.supported, self.calls, self.recoveries = supported, [], []
        self.requests = []
        self.retained, self.fail_stage, self.bad_stage = {}, None, None

    def supports(self, stage):
        return stage in self.supported

    def recover_stage(self, stage, request):
        self.recoveries.append(stage)
        return self.retained.get(canonical_hash(request))

    def run_stage(self, stage, request):
        self.calls.append(stage)
        self.requests.append(deepcopy(request))
        receipt = {'stage': stage, 'request_sha256': canonical_hash(request),
                   'source_binding': request['source_binding'], 'plan_sha256': request['plan_sha256'],
                   'evidence_scope': 'AUTHORED_SYNTHETIC_ADAPTER_TEST_ONLY'}
        receipt.update({'validate': {'passed': True},
                        'prepare_schema': {'ready_for_import': True},
                        'import': {'imported': True, 'application_id': 123},
                        'verify_runtime': {'passed': True, 'authenticated': True, 'business_pages_tested': True},
                        'export': {'exported': True, 'package_sha256': 'e' * 64}}[stage])
        if self.bad_stage == stage:
            receipt['source_binding'] = '0' * 64
        self.retained[canonical_hash(request)] = receipt
        if self.fail_stage == stage:
            raise OSError('SENSITIVE_CONVERTER_ERROR_MUST_NOT_ESCAPE')
        return receipt


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    docs, client, approvals = documents(), SyntheticOpaf(), []
    kwargs = {'project_id': 'synthetic-project', 'project_name': 'Synthetic prototype',
              'expected_source_binding': local_packet(docs)['source_binding'],
              'approved_chunk_hashes': {}, 'approved_policy_id': POLICY_ID,
              'opaf_client': client, 'profile': deepcopy(PROFILE),
              'target_profile_loader': lambda: deepcopy(TARGET),
              'processing_approval_check': lambda context: approvals.append(context) or True}
    job = tmp_path / ('fox-' + '1' * 20)
    return job, docs, client, approvals, kwargs


def test_connected_two_form_design_and_real_renderer_candidate_without_fake_export(setup):
    job, docs, client, approvals, kwargs = setup
    originals = deepcopy(docs)
    result = run_prototype_pipeline(job, docs, **kwargs)
    assert docs == originals
    assert result['status'] == 'BLOCKED_ADAPTER' and result['stage'] == 'validate'
    assert result['assessment']['source_count'] == 2
    assert len(client.calls) == len(approvals) == result['assessment']['focus_count'] * 2
    assert all(set(identity) == {'job_id', 'source_hash'} for _, identity in client.observations)
    assert all(context['source_binding'] == kwargs['expected_source_binding'] for context in approvals)
    assert result['facts']['native_source_rendered'] is True
    assert all(result['facts'][key] is False for key in result['facts'] if key != 'native_source_rendered')
    raw = Path(result['artifacts']['candidate_apexlang']).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == result['artifacts']['candidate_apexlang_sha256']
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.namelist().count('application.apx') == 1
        assert len([name for name in archive.namelist() if name.startswith('pages/')]) >= 4
        assert all('BUSINESS_API.SAVE' not in archive.read(name).decode() for name in archive.namelist())
    plan = json.loads(Path(result['artifacts']['native_plan']).read_text())
    assert len(plan['rendering_spec']['blocks']) == 2
    assert any(row['code'] == 'code_unit_not_translated' for row in plan['remediation'])
    assert result['coverage']['accounted_objects'] == result['coverage']['source_objects']


def test_completed_model_results_resume_without_live_observation_or_post(setup):
    job, docs, client, approvals, kwargs = setup
    first = run_prototype_pipeline(job, docs, **kwargs)
    before = deepcopy((client.calls, client.observations, approvals))
    kwargs.update(opaf_client=None, target_profile_loader=None, processing_approval_check=None)
    assert run_prototype_pipeline(job, docs, **kwargs) == first
    assert (client.calls, client.observations, approvals) == before


@pytest.mark.parametrize('role', ['mapper', 'reviewer'])
def test_uncertain_model_never_replays_or_leaks_provider_error(setup, role):
    job, docs, client, _, kwargs = setup
    client.fail_role = role
    with pytest.raises(OpafError, match='reconcile without replay') as error:
        run_prototype_pipeline(job, docs, **kwargs)
    assert 'SENSITIVE' not in str(error.value)
    calls = deepcopy(client.calls)
    client.fail_role = None
    with pytest.raises(OpafError, match='uncertain'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert client.calls == calls


def test_fresh_processing_approval_is_checked_before_each_new_role(setup):
    job, docs, client, _, kwargs = setup
    checks = []
    kwargs['processing_approval_check'] = lambda context: checks.append(context) or context['role'] == 'mapper'
    with pytest.raises(OpafError, match='approval'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert [role for role, _ in client.calls] == ['mapper']
    assert [context['role'] for context in checks] == ['mapper', 'reviewer']
    assert not list(job.rglob('reviewer-intent.json'))


def test_reviewer_changes_block_whole_project_before_merge_or_render(setup):
    job, docs, client, _, kwargs = setup
    client.changes_role = True
    result = run_prototype_pipeline(job, docs, **kwargs)
    assert result['status'] == 'CHANGES_REQUIRED'
    assert not list(job.rglob('native-plan.json'))
    assert not list(job.rglob('candidate-apexlang.zip'))
    assert not any(result['facts'].values())


def test_malformed_mapper_never_reaches_reviewer(setup):
    job, docs, client, _, kwargs = setup
    client.invalid_candidate = True
    with pytest.raises(ValueError, match='Invalid source-bound'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert [role for role, _ in client.calls] == ['mapper']


@pytest.mark.parametrize('change', ['source', 'policy', 'profile', 'selection'])
def test_changed_binding_cannot_reuse_or_replay_old_results(setup, change):
    job, docs, client, _, kwargs = setup
    run_prototype_pipeline(job, docs, **kwargs)
    calls = deepcopy(client.calls)
    if change == 'source':
        docs[0] = docs[0][0], docs[0][1].replace(b'FIRST', b'CHANGED')
        kwargs['expected_source_binding'] = local_packet(docs)['source_binding']
    elif change == 'policy':
        kwargs['approved_policy_id'] = 'not-approved'
    elif change == 'profile':
        kwargs['profile']['mapper']['graph_sha256'] = 'd' * 64
    else:
        kwargs['approved_chunk_hashes'] = {'not-a-real-chunk': 'a' * 64}
    with pytest.raises((OpafError, ValueError)):
        run_prototype_pipeline(job, docs, **kwargs)
    assert client.calls == calls


def test_tampered_retained_model_output_is_not_accepted_or_replayed(setup):
    job, docs, client, _, kwargs = setup
    run_prototype_pipeline(job, docs, **kwargs)
    checkpoint = next(job.rglob('mapper.json'))
    saved = json.loads(checkpoint.read_text())
    saved['output_sha256'] = '0' * 64
    checkpoint.write_text(json.dumps(saved))
    calls = deepcopy(client.calls)
    with pytest.raises(OpafError, match='checkpoint changed'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert client.calls == calls


def test_authored_converter_receipts_exercise_stage_order_not_live_proof(setup):
    job, docs, _, _, kwargs = setup
    adapter = SyntheticConverter()
    result = run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert adapter.calls == list(CONVERTER_STAGES)
    assert result['status'] == 'APEX_GENERATED'
    assert result['facts']['native_apex_generated'] and result['facts']['runtime_verified']
    assert result['facts']['package_reimport_passed'] is False
    assert result['facts']['clean_schema_install_passed'] is False
    assert result['facts']['technically_verified'] is False
    assert result['facts']['download_ready'] is False
    assert result['facts']['business_behavior_accepted'] is False
    assert all(row['evidence_scope'] == 'AUTHORED_SYNTHETIC_ADAPTER_TEST_ONLY'
               for row in result['converter_receipts'].values())
    # Checkpoints alone permit offline restoration, not a fresh remote POST.
    assert run_prototype_pipeline(job, docs, **kwargs) == result


def test_missing_browser_stage_stops_before_final_export_or_download(setup):
    job, docs, _, _, kwargs = setup
    adapter = SyntheticConverter(supported=('validate', 'prepare_schema', 'import', 'export'))
    result = run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert result['status'] == 'BLOCKED_ADAPTER' and result['stage'] == 'verify_runtime'
    assert result['facts']['import_verified'] is True
    assert result['facts']['download_ready'] is False
    assert adapter.calls == ['validate', 'prepare_schema', 'import']


def test_lost_import_response_recovers_read_only_without_repeating_write(setup):
    job, docs, _, _, kwargs = setup
    adapter = SyntheticConverter()
    adapter.fail_stage = 'import'
    with pytest.raises(OpafError, match='reconcile without replay'):
        run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    adapter.fail_stage = None
    result = run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert result['status'] == 'APEX_GENERATED'
    assert result['facts']['technically_verified'] is False
    assert adapter.calls.count('import') == 1
    assert adapter.recoveries.count('import') == 2


def test_export_booleans_do_not_forge_missing_complete_package_gates(setup):
    job, docs, _, _, kwargs = setup

    class OverclaimingExport(SyntheticConverter):
        def run_stage(self, stage, request):
            receipt = super().run_stage(stage, request)
            if stage == 'export':
                receipt.update(package_reimport_passed=True, clean_schema_install_passed=True,
                               technically_verified=True, download_ready=True)
            return receipt

    result = run_prototype_pipeline(job, docs, converter_adapter=OverclaimingExport(), **kwargs)
    assert result['status'] == 'APEX_GENERATED'
    assert result['facts']['native_apex_generated'] is True
    assert result['facts']['runtime_verified'] is True
    assert all(result['facts'][field] is False for field in (
        'package_reimport_passed', 'clean_schema_install_passed', 'technically_verified', 'download_ready'))


def test_unknown_import_without_retained_result_never_replays(setup):
    job, docs, _, _, kwargs = setup
    adapter = SyntheticConverter()
    adapter.fail_stage = 'import'
    with pytest.raises(OpafError):
        run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    adapter.retained.clear()
    adapter.fail_stage = None
    result = run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert result['status'] == 'RECONCILIATION_REQUIRED' and result['stage'] == 'import'
    assert adapter.calls.count('import') == 1
    assert result['facts']['import_verified'] is False
    assert result['facts']['download_ready'] is False


def test_stale_converter_receipt_never_passes_gate(setup):
    job, docs, _, _, kwargs = setup
    adapter = SyntheticConverter()
    adapter.bad_stage = 'validate'
    with pytest.raises(OpafError, match='stale or unbound'):
        run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert adapter.calls == ['validate']


def test_private_authority_rebuilds_actual_artifacts_without_model_or_file_writes(setup):
    job, docs, client, _, kwargs = setup
    adapter = SyntheticConverter(supported=('validate',))
    run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    request = adapter.requests[0]
    calls = deepcopy((client.calls, client.observations))
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    assert authorize_prototype_request(job, request) is request
    after = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    assert before == after
    assert (client.calls, client.observations) == calls


@pytest.mark.parametrize('artifact', ['source', 'packet', 'review', 'invocation', 'target', 'merge', 'plan', 'zip', 'authority'])
def test_private_authority_rejects_changed_source_review_or_output(setup, artifact):
    job, docs, _, _, kwargs = setup
    adapter = SyntheticConverter(supported=('validate',))
    run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    request = adapter.requests[0]
    root = job / 'prototype-pipeline'
    if artifact == 'source':
        path = root / 'sources' / 'source-000.xml'
        path.write_bytes(path.read_bytes().replace(b'FIRST', b'OTHER'))
    elif artifact == 'zip':
        (root / 'candidate-apexlang.zip').write_bytes(b'not-the-retained-zip')
    elif artifact == 'authority':
        request['source_authority']['review_index_sha256'] = '0' * 64
    else:
        path = {'packet': root / 'packet.json', 'review': next(root.rglob('reviewer.json')),
                'invocation': next(root.rglob('mapper.json')), 'target': next(root.rglob('mapper-target.json')),
                'merge': root / 'merged-blueprint.json', 'plan': root / 'native-plan.json'}[artifact]
        value = json.loads(path.read_text())
        if artifact == 'review':
            value['output']['verdict'] = 'CHANGES_REQUIRED'
            value['output_sha256'] = canonical_hash(value['output'])
        elif artifact == 'invocation':
            value['invocation']['request_sha256'] = '0' * 64
        elif artifact == 'target':
            value['opaf']['roles']['mapper']['model'] = 'invented-model'
        else:
            value['source_binding'] = '0' * 64
        path.write_text(json.dumps(value))
    with pytest.raises((OpafError, ValueError)):
        authorize_prototype_request(job, request)


def test_changed_pending_converter_intent_blocks_even_if_remote_has_result(setup):
    job, docs, _, _, kwargs = setup
    adapter = SyntheticConverter()
    adapter.fail_stage = 'import'
    with pytest.raises(OpafError):
        run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    path = job / 'prototype-pipeline' / 'import-intent.json'
    path.write_text(json.dumps({'request_sha256': '0' * 64}))
    before = list(adapter.recoveries)
    with pytest.raises(OpafError, match='intent changed'):
        run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert adapter.recoveries == before


@pytest.mark.parametrize('field,value', [('project_name', 'x' * 81), ('project_id', '../unsafe'),
                                        ('project_name', '&APP_USER.')])
def test_invalid_native_identity_fails_before_any_model_call(setup, field, value):
    job, docs, client, _, kwargs = setup
    kwargs[field] = value
    with pytest.raises(OpafError, match='identity and name'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert not client.calls and not client.observations
    assert not job.exists()
