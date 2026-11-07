"""Actual local API/worker/gateway; every source/model/stage reply is authored.

These tests prove local plumbing only, never OPAF/Oracle/runtime acceptance.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fox import prototype_clause_epoch as clause, prototype_mapping_epochs as epochs
from fox import prototype_job, prototype_authority, worker
from fox.opaf import canonical_hash, OpafError
from fox.prototype_clause_analysis import build_request, assemble_candidate, SCOPE
from fox.prototype_clause_proof import JSON_FILES, ASSEMBLER_SHA256
from fox.forms_design_review import validate_design_review
from fox.prototype_pipeline import authorize_prototype_request
from fox.prototype_transport import build_authority_bundle
from test_prototype_mapping_epochs import epochs_case, tmp_path, api, submission, PROFILE
from test_source_history_api import client, settings, no_external_actions
from test_prototype_clause_proof import write, sealed_role, independent_review_envelope


def stage(case):
    _, root, _, rid, job, snapshot, _, _, _, db, envelope = case
    target = envelope['target_profile']
    original = (job / 'source-snapshot.json').read_bytes()
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    predecessor = epochs.read(job / epochs.RECORD)
    focus = next(row for row in plan['requests'] if row['focus_id'] == predecessor['plan']['repair_focus_id'])
    historical = epochs.read(job / 'prototype-pipeline' / focus['focus_id'] / 'mapper.json')['output']
    historical, _ = epochs.resolved_mapper(job / 'prototype-pipeline' / focus['focus_id'], focus, historical)
    analysis_role = {'workflow_id': 'C' * 32, 'model': target['opaf']['roles']['mapper']['model'], 'graph_sha256': 'c' * 64}
    analysis = {'schema_version': 1, 'scope': SCOPE, 'analyses': [
        {'source_attribute': 'WhereClause', 'intent': 'Select rows whose flag equals seventeen.',
         'status': 'proposal', 'limitations': ['Authored synthetic data only; business behavior is not accepted.']},
        {'source_attribute': 'OrderByClause', 'intent': 'Sort returned names in descending order.',
         'status': 'proposal', 'limitations': []}]}
    base = clause._stage(job)
    for directory in (base.parent, base, base / 'json', base / 'json/analysis', base / 'json/review'):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    directory = base / 'json'
    stage_target = deepcopy(target)
    stage_target['opaf']['roles']['mapper'] = analysis_role
    identity = {'job_id': rid, 'source_hash': packet['source_binding']}
    compact = build_request(packet, focus, historical)
    invocation = sealed_role(directory, 'analysis', 'mapper', stage_target, compact, analysis, identity)
    candidate, assembly = assemble_candidate(packet, focus, historical, analysis)
    binding = {'schema_version': 1, 'scope': 'fox-clause-diagnostic-invocation-assembly-v1',
        'analysis_checkpoint_sha256': hashlib.sha256((directory / 'analysis/mapper.json').read_bytes()).hexdigest(),
        'analysis_invocation_sha256': canonical_hash(invocation), 'assembly_sha256': canonical_hash(assembly),
        'candidate_sha256': canonical_hash(candidate), 'analysis_request_sha256': canonical_hash(compact),
        'source_binding': identity['source_hash'], 'raw_model_output': False}
    payload = independent_review_envelope(focus, historical, compact, analysis, candidate, assembly, binding)
    review = {'source_binding': focus['source_binding'], 'focus_binding': focus['focus_binding'],
             'candidate_sha256': canonical_hash(candidate), 'verdict': 'APPROVED', 'findings': []}
    review_invocation = sealed_role(directory, 'review', 'reviewer', target, payload, review, identity)
    from fox import prototype_clause_analysis
    module = Path(prototype_clause_analysis.__file__).read_bytes()
    summary = {'scope': 'one-source-bound-clause-analysis-diagnostic-not-conversion', 'job_id': rid,
        'maximum_analysis_calls': 1, 'maximum_review_calls': 1, 'automatic_retry': False,
        'source_binding': focus['source_binding'], 'focus_request_sha256': canonical_hash(focus),
        'original_candidate_sha256': canonical_hash(historical), 'analysis_request_sha256': canonical_hash(compact),
        'module_sha256': ASSEMBLER_SHA256, 'original_target_sha256': canonical_hash(target),
        'analysis_target_sha256': canonical_hash(stage_target), 'clause_count': 2,
        'whole_clause_bytes': [row['unit']['bytes'] for row in compact['clauses']],
        'production_profile_activated': False, 'production_run_resumed': False, 'apex_imported': False,
        'approval_basis': 'Authored synthetic retained diagnostic; not an authority grant.'}
    for name, value in {'clause-request.json': compact, 'derived-candidate.json': candidate,
        'derived-assembly.json': assembly, 'assembly-binding.json': binding, 'diagnostic-intent.json': summary,
        'review-receipt.json': validate_design_review(focus, candidate, review), 'result.json': {
            **summary, 'status': 'CLAUSE_DIAGNOSTIC_COMPLETED', 'analysis_room_id': invocation['room_id'],
            'analysis_output_sha256': canonical_hash(analysis), 'derived_candidate_sha256': canonical_hash(candidate),
            'analysis_statuses': {row['source_attribute']: row['status'] for row in analysis['analyses']},
            'review_room_id': review_invocation['room_id'], 'review_verdict': 'APPROVED',
            'approved_structured_design': True, 'finding_count': 0, 'finding_codes': [],
            'original_job_files_unchanged': 1, 'business_behavior_accepted': False,
            'diagnostic_not_production_continuation': True}}.items():
        write(directory, name, value)
    manifest = {name: {'sha256': hashlib.sha256((directory / name).read_bytes()).hexdigest(),
                       'bytes': (directory / name).stat().st_size} for name in JSON_FILES}
    manifest['prototype_clause_analysis.py'] = {'sha256': ASSEMBLER_SHA256, 'bytes': len(module)}
    descriptor = {'schema_version': 1, 'scope': clause.STAGING_SCOPE, 'job_id': rid,
        'project_id': snapshot['project_id'], 'owner': snapshot['approvals']['owner'],
        'snapshot_sha256': hashlib.sha256(original).hexdigest(), 'source_hash': snapshot['source_hash'],
        'source_binding': focus['source_binding'], 'original_target_sha256': canonical_hash(target),
        'analysis_role': analysis_role, 'assembler_sha256': ASSEMBLER_SHA256,
        'original_manifest': manifest, 'original_manifest_sha256': canonical_hash(manifest),
        'candidate_sha256': canonical_hash(candidate)}
    write(base, 'descriptor.json', descriptor)
    return descriptor


@pytest.fixture
def clause_case(epochs_case, monkeypatch):
    case = epochs_case
    _, body = submission(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    model = case[7]
    invoke = model.invoke

    def deletion_only(role, request):
        output, invocation = invoke(role, request)
        if 'repair_context' in request:
            output = deepcopy(request['repair_context']['raw_candidate'])
            removed = {row['defective_claim_id'] for row in request['repair_context']['requirements']['required_behavior_units']}
            output['blueprint']['claims'] = [row for row in output['blueprint']['claims'] if row['id'] not in removed]
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation

    monkeypatch.setattr(model, 'invoke', deletion_only)
    worker.process_one(case[9], case[1])
    monkeypatch.setattr(model, 'invoke', invoke)
    with case[9]() as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (case[3],)).fetchone()[0] == 'ATTENTION'
    stage(case)
    return case


def next_body(case):
    response = case[0].get(api(case))
    assert response.status_code == 200, response.text
    plan = response.json()
    return plan, {**case[6], 'checkpoint_sha256': plan['checkpoint_sha256'],
        'expected_epoch_number': plan['epoch_number'], 'expected_predecessor_sha256': plan['predecessor_sha256'],
        'expected_clause_proof_sha256': plan['expected_clause_proof_sha256']}


def test_explicit_three_same_row_reuses_saved_calls_then_projects(clause_case, monkeypatch):
    case = clause_case
    c, root, _, rid, job, snapshot, _, model, converter, db, _ = case
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    with db() as connection:
        events = [tuple(row) for row in connection.execute('SELECT * FROM events ORDER BY rowid')]
    calls = deepcopy(model.calls)
    plan, body = next_body(case)
    assert plan['epoch_number'] == 3 and plan['strategy'] == clause.STRATEGY
    assert (plan['new_clause_analysis_calls'], plan['repeated_clause_review_calls'],
            plan['corrective_projection_review_calls']) == (0, 0, 1)
    assert plan['planned_corrective_operations'] == ['projection_review']
    assert c.post(api(case, 'mapping-epochs'), json=body).status_code == 202
    with db() as connection:
        epochs.validate_epoch_chain(job, snapshot, (job / 'source-snapshot.json').read_bytes(), connection)
    assert c.post(api(case, 'mapping-epochs'), json=body).status_code == 200
    errors = []
    actual = prototype_job.run_prototype_job

    def traced(*args, **kwargs):
        try:
            return actual(*args, **kwargs)
        except Exception:
            import traceback
            errors.append(traceback.format_exc())
            raise

    monkeypatch.setattr(prototype_job, 'run_prototype_job', traced)
    worker.process_one(db, root)
    with db() as connection:
        row = connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone()
        assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
        assert connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert [tuple(row) for row in connection.execute('SELECT * FROM events ORDER BY rowid LIMIT ?', (len(events),))] == events
    newer = model.calls[len(calls):]
    assert newer[0][0] == 'reviewer' and newer[0][1]['request']['focus_id'] == plan['projection_focus_id']
    assert newer[0][1]['review_context']['operation'] == 'projection_review'
    assert all(payload.get('review_context', {}).get('operation') != 'repair_review' and 'repair_context' not in payload for _, payload in newer)
    assert len([name for name, _ in newer if name == 'mapper']) == plan['remaining_focus_count']
    assert all((job / name).read_bytes() == raw for name, raw in before.items())
    assert not (job / 'prototype-pipeline' / clause.PREFIX / plan['repair_focus_id']).exists()
    assert converter.calls


def test_actual_local_authority_transport_and_gateway_json_only_roundtrip(clause_case):
    from fox.prototype_download import retained_export_request
    from forms2apex.prototype_gateway import PrototypeGateway
    case = clause_case
    c, root, _, rid, job, snapshot, _, _, converter, db, envelope = case
    _, body = next_body(case)
    assert c.post(api(case, 'mapping-epochs'), json=body).status_code == 202
    profile = root / 'public-profile.json'
    profile.write_text(json.dumps(envelope))
    profile.chmod(0o600)
    original = converter.run_stage
    callbacks = []

    def checked(stage_name, request):
        value = prototype_authority.authorize_current(root, db, profile, request)
        assert value['request_sha256'] == canonical_hash(request)
        callbacks.append(stage_name)
        return original(stage_name, request)

    converter.run_stage = checked
    worker.process_one(db, root)
    with db() as connection:
        row = connection.execute('SELECT state,message FROM runs WHERE id=?', (rid,)).fetchone()
        assert row['state'] == 'GENERATED', row['message']
    assert callbacks == ['validate', 'prepare_schema', 'import', 'verify_runtime', 'export']
    request, _ = retained_export_request(job, snapshot, envelope)
    bundle = build_authority_bundle(job, request)
    paths = {row['path'] for row in bundle['files']}
    assert {clause.PREFIX + '/clause-proof/' + name for name in JSON_FILES} <= paths
    assert not any(path.endswith('.py') for path in paths)
    index = epochs.read(job / 'prototype-pipeline/review-index.json')
    repair = next(row for row in index['focuses'] if row.get('kind') == 'DERIVED_CLAUSE_DIAGNOSTIC')
    assert 'mapper_invocation' not in repair and 'analysis_invocation' in repair
    remote_jobs = root / 'receiver'
    remote_jobs.mkdir()
    remote = remote_jobs / rid
    gateway = PrototypeGateway(SimpleNamespace(jobs_root=remote_jobs), authorize=lambda value: authorize_prototype_request(remote, value))
    staged = gateway.stage_source_authority(rid, bundle)
    gateway._authorize(request)
    assert gateway.recover_source_authority(rid) == staged
    with db() as connection:
        connection.execute('DELETE FROM events WHERE action=? AND object_id LIKE ?', (epochs.EVENT, rid + ':epoch:000003:%'))
    with pytest.raises(OpafError):
        prototype_authority.authorize_current(root, db, profile, request)


@pytest.mark.parametrize('mutation', ['proof-digest', 'consent', 'checkpoint', 'predecessor', 'role', 'source', 'target', 'snapshot', 'module', 'proof-byte'])
def test_stale_proof_or_fresh_consent_blocks_before_calls(clause_case, mutation):
    case = clause_case
    plan, body = next_body(case)
    before = deepcopy((case[7].calls, case[8].calls))
    if mutation in ('proof-digest', 'consent', 'checkpoint', 'predecessor'):
        key = {'proof-digest': 'expected_clause_proof_sha256', 'consent': 'approved_external_ai',
               'checkpoint': 'checkpoint_sha256', 'predecessor': 'expected_predecessor_sha256'}[mutation]
        body[key] = False if mutation == 'consent' else '0' * 64
    else:
        base = clause._stage(case[4])
        if mutation == 'proof-byte':
            with (base / 'json/derived-candidate.json').open('ab') as handle:
                handle.write(b' ')
        else:
            path = base / 'descriptor.json'
            value = epochs.read(path)
            if mutation == 'role': value['analysis_role']['graph_sha256'] = '0' * 64
            elif mutation == 'source': value['source_binding'] = '0' * 64
            elif mutation == 'target': value['original_target_sha256'] = '0' * 64
            elif mutation == 'snapshot': value['snapshot_sha256'] = '0' * 64
            else: value['assembler_sha256'] = '0' * 64
            write(base, 'descriptor.json', value)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert not (case[4] / clause.RECORD).exists()
    assert (case[7].calls, case[8].calls) == before


@pytest.mark.parametrize('mutation', ['event', 'future', 'pending', 'fake-repair', 'unknown-head', 'next-metadata'])
def test_postqueue_tampering_blocks_before_configuration(clause_case, monkeypatch, mutation):
    case = clause_case
    plan, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    root = case[4] / 'prototype-pipeline'
    if mutation == 'event':
        with case[9]() as db:
            db.execute('DELETE FROM events WHERE object_id LIKE ?', (case[3] + ':epoch:000003:%',))
    elif mutation == 'unknown-head': write(case[4], 'mapping-epochs/epoch-000004.json', {})
    elif mutation == 'fake-repair': write(root, clause.PREFIX + '/' + plan['repair_focus_id'] + '/mapper.json', {})
    elif mutation == 'pending': write(root, clause.PREFIX + '/' + plan['projection_focus_id'] + '/reviewer-intent.json', {})
    elif mutation == 'next-metadata': write(root, clause.PREFIX + '/' + plan['projection_focus_id'] + '/reviewer-request.json', {})
    else:
        record = epochs.read(case[4] / clause.RECORD)
        _, full = epochs.reconstruct(case[4], case[5], (case[4] / 'source-snapshot.json').read_bytes(), case[10]['target_profile'])
        write(root, clause.PREFIX + '/' + full['requests'][-1]['focus_id'] + '/mapper.json', {})
    calls, configured = deepcopy((case[7].calls, case[8].calls)), []
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: configured.append(True))
    worker.process_one(case[9], case[1])
    assert configured == [] and (case[7].calls, case[8].calls) == calls


def test_transaction_orphan_is_preserved_and_never_requeued(clause_case):
    case = clause_case
    _, body = next_body(case)
    with case[9]() as db:
        db.execute("CREATE TRIGGER clause_abort BEFORE INSERT ON events WHEN NEW.object_id LIKE '%:epoch:000003:%' BEGIN SELECT RAISE(ABORT,'Synthetic orphan'); END")
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert (case[4] / clause.RECORD).exists()
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert case[0].get(api(case)).status_code == 409


def test_concurrent_matching_posts_queue_once(clause_case):
    from concurrent.futures import ThreadPoolExecutor
    case = clause_case
    _, body = next_body(case)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: case[0].post(api(case, 'mapping-epochs'), json=body), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 202]
    with case[9]() as db:
        assert db.execute('SELECT COUNT(*) FROM events WHERE object_id LIKE ?',
                          (case[3] + ':epoch:000003:%',)).fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1


def test_stage_change_between_inspection_and_adoption_cannot_queue(clause_case, monkeypatch):
    case = clause_case
    _, body = next_body(case)
    original = clause.adopt

    def changed(job, snapshot, raw, record):
        with (clause._stage(job) / 'json/derived-candidate.json').open('ab') as handle:
            handle.write(b' ')
        return original(job, snapshot, raw, record)

    monkeypatch.setattr(clause, 'adopt', changed)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert not (case[4] / clause.RECORD).exists()


@pytest.mark.parametrize('path,allowed', [
    ('epochs/epoch-000003/clause-proof/analysis/mapper.json', True),
    ('epochs/epoch-000003/clause-proof/review/reviewer-target.json', True),
    ('epochs/epoch-000003/clause-proof-descriptor.json', True),
    ('epochs/epoch-000003/clause-proof/prototype_clause_analysis.py', False),
    ('epochs/epoch-000003/clause-proof/extra.json', False),
    ('epochs/epoch-000003/clause-proof/analysis/../mapper.json', False),
    ('epochs/epoch-000003/clause-proof/analysis/mapper.json/extra', False),
    ('epochs/epoch-000004/epoch-record.json', False),
    ('epochs/epoch-000002/clause-proof/analysis/mapper.json', False),
    ('/epochs/epoch-000003/epoch-record.json', False),
    ('epochs\\epoch-000003\\epoch-record.json', False)])
def test_sender_and_receiver_have_exact_json_only_three_path_parity(path, allowed):
    from fox.prototype_transport import _epoch_authority_member
    from forms2apex.prototype_gateway import _AUTHORITY_PATH, _CLAUSE_FIXED_PATHS, _CLAUSE_FOCUS_PATH
    assert _epoch_authority_member(path, clause_epoch=True) is allowed
    assert bool(_AUTHORITY_PATH.fullmatch(path) or path in _CLAUSE_FIXED_PATHS or _CLAUSE_FOCUS_PATH.fullmatch(path)) is allowed
    assert not _epoch_authority_member(path, clause_epoch=False)
