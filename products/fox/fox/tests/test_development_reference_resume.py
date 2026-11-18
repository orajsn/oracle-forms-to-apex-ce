"""Small synthetic retained-first-mapper and SQLite proofs; no live operations."""
import hashlib
import json
import os
import sqlite3

import pytest

from fox import prototype_development_reference_resume as resume
from fox.development_processing import prepare_development_processing
from fox.design_provider import roles
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.oci_genai import OciGenAiClient
from fox.opaf import OpafError, canonical_hash
from fox.prototype_admission import prepare_prototype_admission
from fox.prototype_job import validate_prototype_snapshot
from fox.prototype_pipeline import run_prototype_pipeline
from test_development_processing import context, source_hash
from test_oci_genai import InjectedService, fake_sdk, target

ERRORS = (OpafError, ValueError, KeyError, TypeError, OSError)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')


def read(path):
    return json.loads(path.read_bytes())


def hashes(job):
    return {p.relative_to(job).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in job.rglob('*') if p.is_file()}


@pytest.fixture
def retained(tmp_path, request):
    docs = [('example.xml', b'<FormModule Name="SYNTHETIC">'
        b'<Trigger Name="START" TriggerText="BEGIN APP.START(123); END;"/>'
        b'<Block Name="MAIN">'
        b'<Item Name="FIELD_A" ItemType="Text Item"/>'
        b'<Trigger Name="SAVE" TriggerText="BEGIN APP.SAVE(123); END;"/>'
        b'</Block><Block Name="OTHER"><Trigger Name="OTHER_SAVE" '
        b'TriggerText="BEGIN APP.OTHER_SAVE(456); END;"/></Block></FormModule>')]
    destination = target()
    base = context(docs)
    base['target_profile_sha256'] = canonical_hash(destination)
    packet = local_packet(docs)
    chunks = {row['id']: row['sha256'] for row in packet['chunks']}
    development = prepare_development_processing(docs, context=base, approved_chunk_hashes=chunks)
    from fox.prototype_dsc_identity_repair import TASK_POLICY
    metadata_policy = TASK_POLICY if getattr(request, 'param', None) == 'metadata' else None
    selected = prepare_prototype_admission(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes=chunks, target_profile_sha256=canonical_hash(destination),
        approved_redacted_source=False, approved_unredacted_development_source=True,
        approved_external_ai=True, approved_prototype_scope=True,
        processing_mode='development', development_processing=development, metadata_task_policy=metadata_policy,
        delivery_mode='apexlang_package')['prototype']
    snapshot = {'project': 'synthetic-project', 'project_id': 'synthetic-project',
        'project_name': 'Synthetic prototype', 'selected_source_set_id': 'ss-' + '1' * 32,
        'source_hash': source_hash(docs), 'conversion_profile': 'native-blueprint-prototype-v1',
        'files': [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
                   'text': raw.decode()} for name, raw in docs], 'prototype': selected,
        'approvals': {'owner': 'synthetic-owner', 'approved_at': 3.0, 'redacted_source': False,
            'external_ai': True, 'synthetic_prototype': True, 'unredacted_development_source': True}}
    assert validate_prototype_snapshot(snapshot) == docs
    job = tmp_path / ('fox-' + '1' * 20)
    job.mkdir()
    write(job / 'source-snapshot.json', snapshot)
    original = (job / 'source-snapshot.json').read_bytes()
    service = InjectedService()
    def chunk_claim(body):
        part = body['chat_response']['choices'][0]['message']['content'][0]
        output = json.loads(part['text'])
        if 'blueprint' not in output:
            pytest.fail('The uncorrected first mapper must stop before a reviewer.')
        request = json.loads(service.calls[-1][0]['chat_request']['messages'][1]['content'][0]['text'])
        assert request['chunks']
        chunk = request['chunks'][0]
        unit = next(row for row in request['code_units'] if row['id'] == chunk['code_unit_id'])
        output['blueprint']['claims'] = [{'id': 'save-intent', 'source_object_id': unit['owner_id'],
            'kind': 'behavior.intent', 'status': 'proposal', 'value': 'Retain source save intent 123.',
            'reason': 'Independent business review remains necessary.',
            'evidence_refs': [unit['owner_id'], chunk['id']]}]
        part['text'] = json.dumps(output)
    service.alter = chunk_claim
    client = OciGenAiClient(destination, client=service, sdk=fake_sdk())
    with pytest.raises(ValueError):
        run_prototype_pipeline(job, docs, project_id=snapshot['project_id'],
            project_name=snapshot['project_name'], expected_source_binding=selected['source_binding'],
            approved_chunk_hashes=chunks, approved_policy_id=selected['approved_policy_id'],
            opaf_client=client, profile=roles(destination), target_profile_loader=lambda: destination,
            processing_approval_check=lambda *_: True, delivery_mode='apexlang_package',
            focus_schema_version=selected['schema_version'],
            metadata_task_policy=selected.get('metadata_task_policy'),
            development_processing_sha256=selected['development_processing_sha256'])
    assert len(service.calls) == 1
    connection = sqlite3.connect(':memory:')
    connection.execute('CREATE TABLE events(owner TEXT,action TEXT,object_id TEXT,created REAL)')
    connection.execute('CREATE TABLE projects(id TEXT,owner TEXT)')
    connection.execute('INSERT INTO projects VALUES(?,?)', (snapshot['project_id'], snapshot['approvals']['owner']))
    yield job, snapshot, original, destination, connection, service
    connection.close()


def install(value):
    job, snapshot, original, destination, connection, _ = value
    plan = resume.inspect(job, snapshot, original, destination)
    technical, owner = resume.records(plan, snapshot['approvals']['owner'], 10.0)
    write(job / 'prototype-pipeline' / resume.TECHNICAL, technical)
    write(job / resume.OWNER_RECORD, owner)
    connection.execute('INSERT INTO events VALUES(?,?,?,?)',
        (owner['owner'], resume.EVENT, job.name + ':' + canonical_hash(owner), owner['approved_at']))
    return plan, technical, owner


def test_inspection_is_body_free_deterministic_and_does_not_replay(retained):
    job, snapshot, original, destination, _, service = retained
    before = hashes(job)
    plan = resume.inspect(job, snapshot, original, destination)
    assert resume.inspect(job, snapshot, original, destination) == plan
    assert hashes(job) == before and len(service.calls) == 1
    assert plan['before_files'] == before
    assert plan['snapshot_sha256'] == hashlib.sha256(original).hexdigest()
    assert plan['projection_claim_count'] == 1
    assert plan['first_mapper_invocation_sha256']
    assert plan['remaining_operations'][0] == {'focus_id': plan['first_focus_id'], 'role': 'reviewer'}
    assert {'focus_id': plan['first_focus_id'], 'role': 'mapper'} not in plan['remaining_operations']
    assert plan['remaining_operations'][-3:] == [{'stage': stage} for stage in ('render', 'offline_validate', 'package')]
    serialized = json.dumps(plan)
    for private in ('APP.SAVE', 'TriggerText', 'evidence_refs', 'Retain source save', 'blueprint'):
        assert private not in serialized
    assert 'chunk_evidence_policy' not in snapshot['prototype']


def test_records_bind_exact_original_consent_and_owner_without_legacy_approval(retained):
    job, snapshot, original, _, connection, _ = retained
    plan, technical, owner = install(retained)
    assert resume.technical(job / 'prototype-pipeline') == technical
    assert resume.validate_technical(job / 'prototype-pipeline', technical) == technical
    assert resume.validate_owner(job, snapshot, original, connection) == owner
    assert owner['technical_sha256'] == canonical_hash(technical)
    assert owner['original_consent_sha256'] == canonical_hash(snapshot['approvals'])
    assert owner['development_processing_sha256'] == snapshot['prototype']['development_processing_sha256']
    assert 'approvals' not in owner and 'redacted_source' not in owner
    assert resume.records(plan, owner['owner'], owner['approved_at']) == (technical, owner)
    technical['plan']['before_files'].clear()
    assert plan['before_files']


@pytest.mark.parametrize('approved_at', [True, False, 0, -1, float('nan'), float('inf'), '10'])
def test_record_time_is_strict(retained, approved_at):
    job, snapshot, original, destination, *_ = retained
    plan = resume.inspect(job, snapshot, original, destination)
    with pytest.raises(ERRORS): resume.records(plan, plan['owner'], approved_at)


def test_absent_records_and_events_are_legacy_none(retained):
    job, snapshot, original, _, connection, _ = retained
    assert resume.technical(job / 'prototype-pipeline') is None
    assert resume.validate_owner(job, snapshot, original, connection) is None


@pytest.mark.parametrize('retained', ['metadata'], indirect=True)
def test_declared_metadata_task_is_proven_and_preserved(retained):
    job, snapshot, original, destination, connection, service = retained
    plan, technical, owner = install(retained)
    task = 'prototype-pipeline/' + plan['first_focus_id'] + '/mapper-metadata-task.json'
    assert task in plan['before_files']
    assert resume.validate_owner(job, snapshot, original, connection) == owner
    assert resume.technical(job / 'prototype-pipeline') == technical
    assert len(service.calls) == 1
    altered = read(job / task)
    altered['metadata_guidance'] += ' Changed'
    write(job / task, altered)
    with pytest.raises(ERRORS): resume.technical(job / 'prototype-pipeline')


@pytest.mark.parametrize('change', ['already-valid', 'wrong-owner', 'invented-ref', 'nonmechanical-claim'])
def test_only_exact_chunk_reference_defect_is_eligible(retained, change):
    job, snapshot, original, destination, *_ = retained
    first = next((job / 'prototype-pipeline').glob('focus-*'))
    request, mapper = read(first / 'request.json'), read(first / 'mapper.json')
    claim = mapper['output']['blueprint']['claims'][0]
    if change == 'already-valid': claim['evidence_refs'][1] = request['chunks'][0]['code_unit_id']
    elif change == 'wrong-owner': claim['source_object_id'] = 'invented-owner'
    elif change == 'invented-ref': claim['evidence_refs'][1] = 'invented-ref'
    else:
        claim['status'] = 'source_fact'
        claim['kind'] = 'object.name'
    mapper['output_sha256'] = canonical_hash(mapper['output'])
    write(first / 'mapper.json', mapper)
    with pytest.raises(ERRORS): resume.inspect(job, snapshot, original, destination)


@pytest.mark.parametrize('change', ['legacy', 'new-policy', 'delivery-mode', 'selection', 'target', 'raw-snapshot'])
def test_snapshot_mode_selection_and_destination_cannot_change(retained, change):
    job, snapshot, original, destination, *_ = retained
    if change == 'legacy': snapshot['prototype'].pop('processing_mode')
    elif change == 'new-policy': snapshot['prototype']['chunk_evidence_policy'] = resume.POLICY
    elif change == 'delivery-mode': snapshot['prototype']['delivery_mode'] = 'other-mode'
    elif change == 'selection': snapshot['prototype']['approved_chunk_hashes'] = {}
    elif change == 'target': destination['design_provider']['roles']['mapper']['model'] = 'different-model'
    else: original += b' '
    with pytest.raises(ERRORS): resume.inspect(job, snapshot, original, destination)


@pytest.mark.parametrize('change', ['reviewer-intent', 'reviewer-result', 'other-focus',
    'other-result', 'recovery', 'unknown', 'unknown-empty-dir', 'unsealed-mapper',
    'changed-intent', 'changed-target', 'changed-binding', 'source', 'request'])
def test_inspection_rejects_competing_unsealed_unknown_and_changed_baseline(retained, change):
    job, snapshot, original, destination, *_ = retained
    root = job / 'prototype-pipeline'
    first = next(root.glob('focus-*'))
    if change == 'reviewer-intent': write(first / 'reviewer-intent.json', {})
    elif change == 'reviewer-result': write(first / 'reviewer.json', {})
    elif change == 'other-focus':
        focus = build_focus_plan(validate_prototype_snapshot(snapshot),
            expected_source_binding=snapshot['prototype']['source_binding'],
            approved_chunk_hashes=snapshot['prototype']['approved_chunk_hashes'], max_owned_objects=32)
        other = focus['requests'][1]
        write(root / other['focus_id'] / 'request.json', other)
    elif change == 'other-result': write(job / 'prototype-result.json', {})
    elif change == 'recovery': write(job / 'mapping-continuation.json', {})
    elif change == 'unknown': write(first / 'unrecognized.json', {})
    elif change == 'unknown-empty-dir': (root / 'unknown').mkdir()
    elif change == 'unsealed-mapper': (first / 'mapper.json').unlink()
    elif change == 'changed-intent': write(first / 'mapper-intent.json', {})
    elif change == 'changed-target': write(first / 'mapper-target.json', {})
    elif change == 'changed-binding': write(root / 'binding.json', {})
    elif change == 'source': (root / 'sources' / 'source-000.xml').write_bytes(b'<FormModule Name="OTHER"/>')
    else: write(first / 'request.json', {})
    with pytest.raises(ERRORS): resume.inspect(job, snapshot, original, destination)


@pytest.mark.parametrize('change', ['missing-owner', 'missing-technical', 'missing-event', 'orphan-event',
    'extra-event', 'wrong-event-object', 'wrong-event-owner', 'wrong-event-time', 'current-owner',
    'snapshot', 'technical', 'authorization'])
def test_owner_validator_rejects_missing_orphan_changed_records_and_events(retained, change):
    job, snapshot, original, _, connection, _ = retained
    _, technical, owner = install(retained)
    if change == 'missing-owner': (job / resume.OWNER_RECORD).unlink()
    elif change == 'missing-technical': (job / 'prototype-pipeline' / resume.TECHNICAL).unlink()
    elif change == 'missing-event': connection.execute('DELETE FROM events')
    elif change == 'orphan-event':
        (job / resume.OWNER_RECORD).unlink()
        (job / 'prototype-pipeline' / resume.TECHNICAL).unlink()
    elif change == 'extra-event':
        connection.execute('INSERT INTO events SELECT * FROM events')
    elif change.startswith('wrong-event'):
        field, value = {'wrong-event-object': ('object_id', job.name + ':wrong'),
            'wrong-event-owner': ('owner', 'other-owner'), 'wrong-event-time': ('created', 11.0)}[change]
        connection.execute('UPDATE events SET ' + field + '=?', (value,))
    elif change == 'current-owner': connection.execute('UPDATE projects SET owner=?', ('other-owner',))
    elif change == 'snapshot': snapshot['project_name'] = 'Changed snapshot'
    elif change == 'technical':
        technical['plan']['projected_candidate_sha256'] = 'f' * 64
        write(job / 'prototype-pipeline' / resume.TECHNICAL, technical)
    else:
        owner['original_consent_sha256'] = 'f' * 64
        write(job / resume.OWNER_RECORD, owner)
    with pytest.raises(ERRORS): resume.validate_owner(job, snapshot, original, connection)


def test_original_pins_stay_immutable_after_continuation(retained):
    job, snapshot, original, _, connection, _ = retained
    install(retained)
    first = next((job / 'prototype-pipeline').glob('focus-*'))
    mapper = read(first / 'mapper.json')
    mapper['output']['blueprint']['claims'][0]['value'] = 'Changed business value'
    mapper['output_sha256'] = canonical_hash(mapper['output'])
    write(first / 'mapper.json', mapper)
    with pytest.raises(ERRORS): resume.technical(job / 'prototype-pipeline')
    with pytest.raises(ERRORS): resume.validate_owner(job, snapshot, original, connection)


def test_normal_future_artifacts_are_allowed_without_weakening_first_projection(retained):
    job, snapshot, original, destination, connection, service = retained
    plan, technical, owner = install(retained)
    root = job / 'prototype-pipeline'
    first = root / plan['first_focus_id']
    from fox.prototype_development_reference_view import project
    docs = validate_prototype_snapshot(snapshot)
    candidate, evidence = project(docs, local_packet(docs), read(first / 'request.json'),
        read(first / 'mapper.json')['output'], destination)
    write(first / 'projection-candidate.json', candidate)
    write(first / 'projection-receipt.json', evidence)
    write(first / 'reviewer-request.json', {'synthetic': 'future file shape is checked by normal reviewer gate'})
    # Mere allowed-file presence never claims that the pipeline has succeeded.
    for name in resume._FUTURE_ROOT:
        write(root / name, {})
    log = b'Authored offline fixture log, not an actual SQLcl result.'
    (root / ('offline-' + hashlib.sha256(log).hexdigest() + '.log')).write_bytes(log)
    result = {'synthetic': True, 'business_behavior_accepted': False}
    write(job / 'prototype-result.json', result)
    write(job / 'prototype-results' / (canonical_hash(result) + '.json'), result)
    assert resume.technical(root) == technical
    assert resume.validate_owner(job, snapshot, original, connection) == owner
    assert len(service.calls) == 1
    candidate['blueprint']['claims'][0]['value'] = 'Unauthorized change'
    write(first / 'projection-candidate.json', candidate)
    with pytest.raises(ERRORS): resume.technical(root)


@pytest.mark.parametrize('name', ['epochs', 'unknown.json', 'prepare_schema.json',
    'import-intent.json', 'verify_runtime.json', 'offline-' + 'f' * 64 + '.log'])
def test_read_proof_rejects_unknown_conflicting_or_database_files(retained, name):
    job, *_ = retained
    install(retained)
    write(job / 'prototype-pipeline' / name, {})
    with pytest.raises(ERRORS): resume.technical(job / 'prototype-pipeline')


def test_hardlinked_original_is_rejected(retained, tmp_path):
    job, snapshot, original, destination, *_ = retained
    source = job / 'source-snapshot.json'
    os.link(source, tmp_path / 'snapshot-hardlink')
    with pytest.raises(ERRORS): resume.inspect(job, snapshot, original, destination)


def test_symlinked_directory_is_rejected(retained, tmp_path):
    job, snapshot, original, destination, *_ = retained
    try:
        (job / 'linked').symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip('Windows symlink privilege unavailable; hardlink checks ran separately.')
    with pytest.raises(ERRORS): resume.inspect(job, snapshot, original, destination)
