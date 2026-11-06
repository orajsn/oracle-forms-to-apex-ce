"""Queued prototype tests with real source bindings and synthetic transports."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from fox import prototype_job, source_history, worker
from fox.forms_understanding_packet import local_packet
from fox.intake import checked_source
from fox.opaf import OpafError, canonical_hash
from fox.prototype_admission import prepare_prototype_admission
from fox.storage import initialize_schema
from test_prototype_pipeline import PROFILE, TARGET, SyntheticConverter, SyntheticOpaf, documents


@pytest.fixture
def queued(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.delenv('FOX_INSTALLATION_MODE', raising=False)
    root = tmp_path / 'data'
    job = root / 'jobs' / ('fox-' + '3' * 20)
    job.mkdir(parents=True)
    docs = documents()
    files = [checked_source(name, raw) for name, raw in docs]
    database = root / 'fox.sqlite3'
    @contextmanager
    def db():
        connection = sqlite3.connect(database)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    with db() as connection:
        initialize_schema(connection)
        connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                           ('synthetic-project', 'synthetic-owner', 'Synthetic', 'Synthetic prototype', '', 1.0))
        source_history.create_project_selection(connection, 'synthetic-project', 1.0)
        source_history.publish_upload(connection, 'synthetic-project', files, 2.0, 'synthetic-owner')
        selected_id = source_history.selected_source_set_id(connection, 'synthetic-project')
        files = source_history.selected_sources(connection, 'synthetic-project')
    packet = local_packet(docs)
    selected = prepare_prototype_admission(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={}, target_profile_sha256=canonical_hash(TARGET),
        approved_redacted_source=True, approved_external_ai=True, approved_prototype_scope=True)['prototype']
    snapshot = {'project': 'synthetic-project', 'project_id': 'synthetic-project', 'project_name': 'Synthetic prototype',
                'source_hash': source_history._hash(files), 'conversion_profile': prototype_job.PROFILE_ID,
                'selected_source_set_id': selected_id, 'files': files, 'prototype': selected,
                'approvals': {'owner': 'synthetic-owner', 'approved_at': 3.0,
                              'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True}}
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    with db() as connection:
        connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
            (job.name, 'synthetic-project', snapshot['source_hash'], 'QUEUED', 'Synthetic queued', 3.0, 3.0, None))
    client, converter = SyntheticOpaf(), SyntheticConverter()
    configurations = []
    def configuration(approved_sha, *, installation_projection=None):
        configurations.append((approved_sha, installation_projection))
        assert approved_sha == canonical_hash(TARGET)
        return {'profile': deepcopy(PROFILE), 'opaf_client': client,
                'target_profile_loader': lambda: deepcopy(TARGET), 'converter_adapter': converter}
    monkeypatch.setattr(prototype_job, '_configuration', configuration)
    def forbidden(*args, **kwargs):
        pytest.fail('Prototype must not invoke legacy adapters, old verifier, or external process')
    from fox import native_project_pipeline, opaf, verification_runtime
    monkeypatch.setattr(native_project_pipeline, 'run_native_project_job', forbidden)
    monkeypatch.setattr(opaf, 'run_job', forbidden)
    monkeypatch.setattr(verification_runtime, 'enqueue_native', forbidden)
    monkeypatch.setattr(worker.subprocess, 'run', forbidden)
    return root, job, db, snapshot, client, converter, configurations


def saved_row(db, job):
    with db() as connection:
        return dict(connection.execute('SELECT * FROM runs WHERE id=?', (job.name,)).fetchone())


def test_worker_connects_explicit_queue_to_actual_pipeline_without_old_verifier(queued):
    root, job, db, _, client, converter, configurations = queued
    worker.process_one(db, root)
    row = saved_row(db, job)
    assert row['state'] == 'GENERATED' and row['artifact'] is None
    assert configurations and client.calls and converter.calls
    result = json.loads((job / 'prototype-result.json').read_text())
    assert result['status'] == 'APEX_GENERATED'
    assert result['facts']['native_apex_generated'] is True
    assert result['facts']['runtime_verified'] is True
    assert result['facts']['technically_verified'] is False
    assert result['facts']['clean_schema_install_passed'] is False
    assert result['facts']['package_reimport_passed'] is False
    assert result['facts']['download_ready'] is False
    assert not (job / 'release-evidence.json').exists()


@pytest.mark.parametrize('change', ['approval', 'owner', 'source', 'policy', 'chunk', 'target', 'source-set'])
def test_invalid_persisted_scope_stops_before_configuration_or_model(queued, change):
    root, job, db, snapshot, client, _, configurations = queued
    if change == 'approval':
        snapshot['approvals']['external_ai'] = False
    elif change == 'owner':
        snapshot['approvals']['owner'] = 'other-owner'
    elif change == 'source':
        snapshot['files'][0]['text'] += ' '
    elif change == 'policy':
        snapshot['prototype']['approved_policy_id'] = 'not-authorized'
    elif change == 'chunk':
        snapshot['prototype']['approved_chunk_hashes'] = {'invented': 'a' * 64}
    elif change == 'target':
        snapshot['prototype']['target_profile_sha256'] = 'not-a-sha'
    else:
        snapshot['selected_source_set_id'] = 'ss-' + 'f' * 32
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'ATTENTION'
    assert configurations == [] and client.calls == []


def test_source_selection_change_during_first_call_stops_following_reviewer(queued):
    root, job, db, _, client, _, _ = queued
    invoke = client.invoke
    def change_selection(role, request):
        result = invoke(role, request)
        with db() as connection:
            connection.execute("UPDATE projects SET owner='new-owner' WHERE id='synthetic-project'")
        return result
    client.invoke = change_selection
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'ATTENTION'
    assert [name for name, _ in client.calls] == ['mapper']


def test_uncertain_model_is_retained_without_replay_when_job_is_rechecked(queued):
    root, job, db, _, client, _, _ = queued
    client.fail_role = 'mapper'
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'ATTENTION'
    calls = deepcopy(client.calls)
    client.fail_role = None
    # Explicit test-only requeue models a permitted status check; the actual
    # pipeline must still reject the uncertain role instead of replaying it.
    with db() as connection:
        connection.execute("UPDATE runs SET state='QUEUED' WHERE id=?", (job.name,))
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'ATTENTION'
    assert client.calls == calls


def test_missing_runtime_adapter_retains_truthful_status_without_generation(queued):
    root, job, db, _, _, converter, _ = queued
    converter.supported = ('validate', 'prepare_schema', 'import')
    worker.process_one(db, root)
    result = json.loads((job / 'prototype-result.json').read_text())
    assert result['status'] == 'BLOCKED_ADAPTER' and result['stage'] == 'verify_runtime'
    assert result['facts']['import_verified'] is True
    assert saved_row(db, job)['state'] == 'ATTENTION'


def test_unknown_profile_with_prototype_marker_has_no_legacy_fallback(queued):
    root, job, db, snapshot, client, _, configurations = queued
    snapshot['conversion_profile'] = 'unknown'
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'ATTENTION'
    assert not configurations and not client.calls


def test_missing_explicit_adapter_has_no_fallback(queued, monkeypatch):
    root, job, db, _, client, _, configurations = queued
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'not-embedded')
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'ATTENTION'
    assert not configurations and not client.calls


def test_prototype_snapshot_above_old_two_mb_limit_is_processed_with_new_explicit_bound(queued):
    root, job, db, snapshot, _, _, _ = queued
    docs = documents()
    name, raw = docs[0]
    docs[0] = name, raw.replace(b'</FormModule>', b' ' * 2_010_000 + b'</FormModule>')
    with db() as connection:
        connection.execute('BEGIN IMMEDIATE')
        source_history.publish_upload(connection, 'synthetic-project',
            [checked_source(name, raw) for name, raw in docs], 4.0, 'synthetic-owner')
        files = source_history.selected_sources(connection, 'synthetic-project')
        snapshot['selected_source_set_id'] = source_history.selected_source_set_id(connection, 'synthetic-project')
        snapshot['files'] = files
        snapshot['source_hash'] = source_history._hash(files)
        connection.execute('UPDATE runs SET source_hash=? WHERE id=?', (snapshot['source_hash'], job.name))
    snapshot['prototype'] = prepare_prototype_admission(docs,
        expected_source_binding=local_packet(docs)['source_binding'], approved_chunk_hashes={},
        target_profile_sha256=canonical_hash(TARGET), approved_redacted_source=True,
        approved_external_ai=True, approved_prototype_scope=True)['prototype']
    path = job / 'source-snapshot.json'
    path.write_text(json.dumps(snapshot))
    assert 2_000_000 < path.stat().st_size < prototype_job.MAX_SNAPSHOT_BYTES
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'GENERATED'


def test_snapshot_over_explicit_size_bound_stops_before_configuration(queued, monkeypatch):
    root, job, db, _, client, _, configurations = queued
    monkeypatch.setattr(prototype_job, 'MAX_SNAPSHOT_BYTES', 1)
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'ATTENTION'
    assert not configurations and not client.calls


def test_blocked_result_resume_preserves_prior_result_without_replaying_models(queued):
    _, job, _, _, client, converter, _ = queued
    converter.supported = ('validate', 'prepare_schema', 'import')
    first = prototype_job.run_prototype_job(job, approval_check=lambda _: True)
    assert first['status'] == 'BLOCKED_ADAPTER'
    calls = deepcopy(client.calls)
    converter.supported = ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
    second = prototype_job.run_prototype_job(job, approval_check=lambda _: True)
    assert second['status'] == 'APEX_GENERATED'
    assert client.calls == calls
    history = [json.loads(path.read_text()) for path in (job / 'prototype-results').glob('*.json')]
    assert {value['status'] for value in history} == {'BLOCKED_ADAPTER', 'APEX_GENERATED'}
    assert json.loads((job / 'prototype-result.json').read_text()) == second


def test_profile_loader_is_read_only_and_does_not_pin_old_mapper_model(tmp_path):
    target = deepcopy(TARGET)
    target.update(active=True, scope={'data_mode': 'synthetic_test_only', 'existing_resources_only': True,
                                     'customer_deployment_authorized': False})
    target['opaf']['roles']['mapper']['model'] = 'xai.grok-4.7'
    envelope = {'target_profile': target, 'target_profile_sha256': canonical_hash(target)}
    path = tmp_path / 'prototype-profile.json'
    path.write_text(json.dumps(envelope))
    before = path.read_bytes()
    assert prototype_job.load_prototype_profile(path) == envelope
    assert path.read_bytes() == before


@pytest.mark.parametrize('change', ['hash', 'active', 'scope', 'roles', 'origin', 'certificate'])
def test_invalid_protected_profile_fails_before_any_client_connection(tmp_path, change):
    target = deepcopy(TARGET)
    target.update(active=True, scope={'data_mode': 'synthetic_test_only', 'existing_resources_only': True,
                                     'customer_deployment_authorized': False})
    if change == 'active':
        target['active'] = False
    elif change == 'scope':
        target['scope']['customer_deployment_authorized'] = True
    elif change == 'roles':
        target['opaf']['roles']['reviewer'] = deepcopy(target['opaf']['roles']['mapper'])
    elif change == 'origin':
        target['opaf']['base_url'] = 'http://not-approved/agentFactory'
    elif change == 'certificate':
        target['opaf']['certificate_sha256'] = 'invalid'
    envelope = {'target_profile': target, 'target_profile_sha256': canonical_hash(target)}
    if change == 'hash':
        envelope['target_profile_sha256'] = '0' * 64
    path = tmp_path / 'prototype-profile.json'
    path.write_text(json.dumps(envelope))
    with pytest.raises(OpafError, match='unavailable or invalid'):
        prototype_job.load_prototype_profile(path)
