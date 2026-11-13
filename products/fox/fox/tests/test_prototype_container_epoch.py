"""Actual local API/worker/receiver; all provider/stage records are authored.

No OPAF, SQLcl, Oracle, hosted browser or business acceptance is claimed.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fox import prototype_container_epoch as container, prototype_mapping_epochs as epochs
from fox import prototype_clause_epoch as clause, prototype_job, prototype_authority, worker
from fox import prototype_design_context_v1 as context, prototype_container_proof as proof
from fox.forms_design_review import validate_design_review
from fox.opaf import canonical_hash, OpafError
from fox.prototype_transport import build_authority_bundle
from fox.prototype_pipeline import authorize_prototype_request
from test_prototype_clause_epoch import clause_case, next_body as clause_body
from test_prototype_mapping_epochs import epochs_case, EpochModel, tmp_path, api, submission, PROFILE
from test_source_history_api import client, settings, no_external_actions
from test_prototype_clause_proof import write, sealed_role


@pytest.fixture(autouse=True)
def container_source_model(monkeypatch):
    original = EpochModel.invoke
    def invoke(self, role, payload):
        output, invocation = original(self, role, payload)
        if role == PROFILE['mapper']:
            request = payload
            objects = {row['id']: row for row in request['owned_objects'] + request['context_objects']}
            screen_map = {}
            for row in output['blueprint']['objects']:
                source = objects[row['source_object_id']]
                if source['kind'] == 'FormModule':
                    row.update(disposition='omitted', reason='ordinary legacy visual container; web-recomposition')
                if row.get('screen_id') and source['kind'] == 'Block':
                    screen_map[row['screen_id']] = 'screen-' + source['id']
            for row in output['blueprint']['objects']:
                source = objects[row['source_object_id']]
                if row.get('screen_id'):
                    row['screen_id'] = 'screen-' + (source['id'] if source['kind'] == 'Block' else source['block_id'])
            for row in output['blueprint']['screens']:
                row['id'] = screen_map[row['id']]
            if self.special is not None and any(unit['source_attribute'] == 'WhereClause' for unit in request['code_units']):
                self.special = deepcopy(output)
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(EpochModel, 'invoke', invoke)


def stage_container(case):
    job, snapshot, target = case[4], case[5], case[10]['target_profile']
    raw = (job / 'source-snapshot.json').read_bytes()
    packet, plan = epochs.reconstruct(job, snapshot, raw, target)
    predecessor = epochs.read(job / clause.RECORD)
    views, rejected, old_review = container._historical(job / 'prototype-pipeline', packet, plan, target, predecessor)
    request = plan['requests'][0]
    module_id = next(row['id'] for row in request['owned_objects'] if row['kind'] == 'FormModule')
    original = views[0]['candidate']
    proposed, proposal = context.propose_container_retention(packet, request, original, module_id, canonical_hash(original))
    refs = container._refs(plan, views, target)
    del refs[request['focus_id']]
    prefix = context.validate_prefix_context(packet, plan,
        [proposed, *[row['candidate'] for row in views[1:]], rejected['candidate']], refs,
        expected_target_sha256=canonical_hash(target), container_proposals={request['focus_id']: proposal},
        unreviewed_focus_id=plan['requests'][7]['focus_id'])
    payload = proof.review_envelope(request, original, views[0]['proof'], proposed, proposal, prefix)
    original_files = {path.relative_to(job).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in job.rglob('*') if path.is_file()}
    base = container._stage(job)
    for directory in (base.parent, base, base / 'json', base / 'json/review'):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    directory = base / 'json'
    review = {'source_binding': request['source_binding'], 'focus_binding': request['focus_binding'],
        'candidate_sha256': canonical_hash(proposed), 'verdict': 'APPROVED', 'findings': []}
    invocation = sealed_role(directory, 'review', 'reviewer', target, payload, review,
        {'job_id': job.name, 'source_hash': packet['source_binding']})
    intent = {'schema_version': 1, 'scope': 'one-unadopted-root-proposal-review', 'job_id': job.name,
        'source_binding': packet['source_binding'], 'target_profile_sha256': canonical_hash(target),
        'module_sha256': proof.CONTEXT_MODULE_SHA256, 'original_candidate_sha256': canonical_hash(original),
        'candidate_sha256': canonical_hash(proposed), 'proposal_sha256': canonical_hash(proposal),
        'review_request_sha256': canonical_hash(payload), 'original_files_sha256': canonical_hash(original_files),
        'maximum_new_model_calls': 1, 'generation_calls': 0, 'focus8_calls': 0, 'automatic_retry': False,
        'production_run_resumed': False, 'proposal_adopted': False}
    for name, value in {'container-proposal.json': proposal, 'derived-root-candidate.json': proposed,
        'prefix-check.json': prefix, 'original-files.json': original_files, 'review-request.json': payload,
        'review-receipt.json': validate_design_review(request, proposed, review), 'diagnostic-intent.json': intent,
        'result.json': {**intent, 'status': 'ROOT_PROPOSAL_REVIEW_COMPLETED_UNADOPTED', 'review_verdict': 'APPROVED',
            'approved_structured_design': True, 'review_room_id': invocation['room_id'],
            'review_output_sha256': canonical_hash(review), 'finding_codes': [],
            'original_job_files_unchanged': len(original_files), 'apex_imported': False,
            'business_behavior_accepted': False}}.items():
        write(directory, name, value)
    manifest = {name: {'sha256': hashlib.sha256((directory / name).read_bytes()).hexdigest(),
        'bytes': (directory / name).stat().st_size} for name in proof.JSON_FILES}
    manifest['prototype_design_context.py'] = {'sha256': proof.CONTEXT_MODULE_SHA256,
        'bytes': len(Path(context.__file__).read_bytes())}
    descriptor = {'schema_version': 1, 'scope': container.STAGING_SCOPE, 'job_id': job.name,
        'project_id': snapshot['project_id'], 'owner': snapshot['approvals']['owner'],
        'snapshot_sha256': hashlib.sha256(raw).hexdigest(), 'source_hash': snapshot['source_hash'],
        'source_binding': packet['source_binding'], 'original_target_sha256': canonical_hash(target),
        'predecessor_sha256': canonical_hash(predecessor), 'module_id': module_id,
        'context_module_sha256': proof.CONTEXT_MODULE_SHA256, 'original_manifest': manifest,
        'original_manifest_sha256': canonical_hash(manifest), 'original_files': original_files,
        'original_files_sha256': canonical_hash(original_files), 'original_candidate_sha256': canonical_hash(original),
        'candidate_sha256': canonical_hash(proposed)}
    write(base, 'descriptor.json', descriptor)
    return descriptor


@pytest.fixture
def container_case(clause_case, monkeypatch):
    case = clause_case
    _, body = clause_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    case[7].changes_role = True
    worker.process_one(case[9], case[1])
    case[7].changes_role = None
    result = epochs.read(case[4] / 'prototype-result.json')
    assert result['status'] == 'CHANGES_REQUIRED'
    stage_container(case)
    return case


def next_body(case):
    response = case[0].get(api(case))
    assert response.status_code == 200, response.text
    plan = response.json()
    return plan, {**case[6], 'checkpoint_sha256': plan['checkpoint_sha256'],
        'expected_epoch_number': plan['epoch_number'], 'expected_predecessor_sha256': plan['predecessor_sha256'],
        'expected_container_proof_sha256': plan['expected_container_proof_sha256']}


def process(case, monkeypatch=None):
    errors = []
    if monkeypatch is not None:
        actual = prototype_job.run_prototype_job
        def traced(*args, **kwargs):
            try:
                return actual(*args, **kwargs)
            except Exception:
                import traceback
                errors.append(traceback.format_exc())
                raise
        monkeypatch.setattr(prototype_job, 'run_prototype_job', traced)
    worker.process_one(case[9], case[1])
    with case[9]() as db:
        row = db.execute('SELECT state,message FROM runs WHERE id=?', (case[3],)).fetchone()
    return row, errors


def test_connected_four_reuses_calls_publishes_one_result_and_authority_download_roundtrip(container_case, monkeypatch):
    from fox.prototype_download import retained_export_request
    from fox.prototype_result_publication import validate_publication
    from forms2apex.prototype_gateway import PrototypeGateway
    case = container_case
    c, root, _, rid, job, snapshot, _, model, converter, db, envelope = case
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    count = len(model.calls)
    plan, body = next_body(case)
    assert plan['strategy'] == container.STRATEGY and plan['epoch_number'] == 4
    assert plan['planned_corrective_operations'] == ['projection_review']
    assert [plan[key] for key in ('container_corrections', 'new_container_review_calls',
        'repeated_root_mapper_calls', 'repeated_projection_mapper_calls', 'corrective_projection_review_calls')] == [1, 0, 0, 0, 1]
    assert c.post(api(case, 'mapping-epochs'), json=body).status_code == 202
    assert c.post(api(case, 'mapping-epochs'), json=body).status_code == 200
    profile = root / 'public-profile.json'; profile.write_text(json.dumps(envelope)); profile.chmod(0o600)
    old_stage = converter.run_stage
    callbacks = []
    def checked(stage, request):
        prototype_authority.authorize_current(root, db, profile, request)
        callbacks.append(stage)
        return old_stage(stage, request)
    converter.run_stage = checked
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
    assert callbacks == ['validate', 'prepare_schema', 'import', 'verify_runtime', 'export']
    newer = model.calls[count:]
    assert newer[0][0] == 'reviewer' and newer[0][1]['request']['focus_id'] == plan['projection_focus_id']
    assert newer[0][1]['retained_rejection']['review']['verdict'] == 'CHANGES_REQUIRED'
    assert 'design_context' in newer[0][1]
    assert len([role for role, _ in newer if role == 'mapper']) == plan['remaining_focus_count']
    assert all((job / name).read_bytes() == raw for name, raw in before.items() if name.as_posix() != 'prototype-result.json')
    assert (job / container.RESULT_BASE / 'previous-result.json').read_bytes() == before[Path('prototype-result.json')]
    record = epochs.read(job / container.RECORD)
    assert validate_publication(job, record)['status'] == 'APEX_GENERATED'
    with db() as connection:
        epochs.validate_epoch_chain(job, snapshot, (job / 'source-snapshot.json').read_bytes(), connection)
        assert connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM events WHERE action=?', (epochs.EVENT,)).fetchone()[0] == 3
    request, _ = retained_export_request(job, snapshot, envelope)
    prototype_authority.authorize_current(root, db, profile, request)
    bundle = build_authority_bundle(job, request)
    paths = {row['path'] for row in bundle['files']}
    assert {container.PREFIX + '/container-proof/' + name for name in proof.JSON_FILES} <= paths
    assert not any(name.endswith('.py') for name in paths)
    index = epochs.read(job / 'prototype-pipeline/review-index.json')
    assert index['focuses'][0]['kind'] == 'DERIVED_APPROVED_CONTAINER_PROPOSAL'
    assert 'mapper_invocation' not in index['focuses'][0]
    assert index['focuses'][6]['kind'] == 'DERIVED_CLAUSE_DIAGNOSTIC'
    receiver = root / 'receiver'; receiver.mkdir()
    remote = receiver / rid
    gateway = PrototypeGateway(SimpleNamespace(jobs_root=receiver), authorize=lambda value: authorize_prototype_request(remote, value))
    staged = gateway.stage_source_authority(rid, bundle)
    gateway._authorize(request)
    assert gateway.recover_source_authority(rid) == staged


@pytest.mark.parametrize('mutation', ['proof', 'consent', 'predecessor', 'checkpoint', 'source', 'target', 'snapshot', 'owner', 'module', 'member', 'original-files'])
def test_stale_scope_proof_or_consent_never_queues(container_case, mutation):
    case = container_case
    _, body = next_body(case)
    calls = deepcopy((case[7].calls, case[8].calls))
    keys = {'proof': 'expected_container_proof_sha256', 'consent': 'approved_external_ai',
            'predecessor': 'expected_predecessor_sha256', 'checkpoint': 'checkpoint_sha256'}
    if mutation in keys:
        body[keys[mutation]] = False if mutation == 'consent' else '0' * 64
    elif mutation == 'member':
        with (container._stage(case[4]) / 'json/derived-root-candidate.json').open('ab') as stream:
            stream.write(b' ')
    else:
        value = epochs.read(container._stage(case[4]) / 'descriptor.json')
        key = {'source': 'source_binding', 'target': 'original_target_sha256', 'snapshot': 'snapshot_sha256',
               'owner': 'owner', 'module': 'context_module_sha256', 'original-files': 'original_files_sha256'}[mutation]
        value[key] = '0' * 64
        write(container._stage(case[4]), 'descriptor.json', value)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert not (case[4] / container.RECORD).exists()
    assert (case[7].calls, case[8].calls) == calls


@pytest.mark.parametrize('mutation', ['event', 'future', 'pending', 'fake-root', 'unknown-head', 'context', 'history', 'source'])
def test_postqueue_corruption_blocks_before_provider_configuration(container_case, monkeypatch, mutation):
    case = container_case
    plan, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    root = case[4] / 'prototype-pipeline'
    if mutation == 'event':
        with case[9]() as db:
            db.execute('DELETE FROM events WHERE object_id LIKE ?', (case[3] + ':epoch:000004:%',))
    elif mutation == 'unknown-head': write(case[4], 'mapping-epochs/epoch-000005.json', {})
    elif mutation == 'fake-root':
        _, full = epochs.reconstruct(case[4], case[5], (case[4] / 'source-snapshot.json').read_bytes(), case[10]['target_profile'])
        write(root, container.PREFIX + '/' + full['requests'][0]['focus_id'] + '/mapper.json', {})
    elif mutation == 'pending': write(root, container.PREFIX + '/' + plan['projection_focus_id'] + '/reviewer-intent.json', {})
    elif mutation == 'context': write(root, container.PREFIX + '/' + plan['projection_focus_id'] + '/reviewer-request.json', {})
    elif mutation == 'history':
        record = epochs.read(case[4] / container.RECORD)
        (case[4] / record['plan']['previous_result']['history_path']).unlink()
    elif mutation == 'source':
        with (root / 'sources/source-000.xml').open('ab') as stream: stream.write(b' ')
    else:
        _, full = epochs.reconstruct(case[4], case[5], (case[4] / 'source-snapshot.json').read_bytes(), case[10]['target_profile'])
        write(root, container.PREFIX + '/' + full['requests'][-1]['focus_id'] + '/mapper.json', {})
    calls, configured = deepcopy((case[7].calls, case[8].calls)), []
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: configured.append(True))
    process(case)
    assert configured == [] and (case[7].calls, case[8].calls) == calls


def test_concurrent_matching_posts_queue_exactly_one_same_run(container_case):
    from concurrent.futures import ThreadPoolExecutor
    case = container_case
    _, body = next_body(case)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: case[0].post(api(case, 'mapping-epochs'), json=body), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 202]
    with case[9]() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM events WHERE object_id LIKE ?', (case[3] + ':epoch:000004:%',)).fetchone()[0] == 1


def test_transaction_orphan_is_preserved_and_blocks_all_resubmission(container_case):
    case = container_case
    _, body = next_body(case)
    with case[9]() as db:
        db.execute("CREATE TRIGGER container_abort BEFORE INSERT ON events WHEN NEW.object_id LIKE '%:epoch:000004:%' BEGIN SELECT RAISE(ABORT,'Synthetic orphan'); END")
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert (case[4] / container.RECORD).exists()
    assert case[0].get(api(case)).status_code == 409
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409


@pytest.mark.parametrize('path,allowed', [
    ('epochs/epoch-000004/container-proof/review/reviewer.json', True),
    ('epochs/epoch-000004/container-proof/derived-root-candidate.json', True),
    ('epochs/epoch-000004/container-proof-descriptor.json', True),
    ('epochs/epoch-000004/epoch-record.json', True),
    ('epochs/epoch-000004/container-proof/prototype_design_context.py', False),
    ('epochs/epoch-000004/container-proof/extra.json', False),
    ('epochs/epoch-000004/container-proof/review/../reviewer.json', False),
    ('epochs/epoch-000005/epoch-record.json', False),
    ('epochs/epoch-000004/container-proof/review/reviewer.json/more', False)])
def test_sender_receiver_exact_four_head_json_whitelist(path, allowed):
    from fox.prototype_transport import _epoch_authority_member
    from forms2apex.prototype_gateway import _CONTAINER_FIXED_PATHS, _CONTAINER_FOCUS_PATH
    assert _epoch_authority_member(path, clause_epoch=True, container_epoch=True) is allowed
    assert bool(path in _CONTAINER_FIXED_PATHS or _CONTAINER_FOCUS_PATH.fullmatch(path)) is allowed
    assert not _epoch_authority_member(path, clause_epoch=True)
