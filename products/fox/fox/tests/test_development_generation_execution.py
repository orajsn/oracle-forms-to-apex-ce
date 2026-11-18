"""Synthetic provider execution with actual local worker/API/SQLite boundaries."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from fox import prototype_job, prototype_export_only as package, worker
from fox.opaf import canonical_hash, OpafError
from fox.prototype_pipeline import _role
from fox.forms_understanding_packet import approved_packet
from test_development_generation_routes import queued_case
from test_development_intake_routes import settings
from test_source_history_api import client, no_external_actions, settings as base_settings
from test_prototype_export_only import configured, MetadataModel, authored_validator, tree_bytes
from test_prototype_pipeline import TARGET, PROFILE


class DevelopmentModel(MetadataModel):
    """Authored structural proposal for the preparation fixture's control Block."""
    def invoke(self, role, request):
        output, invocation = super().invoke(role, request)
        if role == PROFILE['mapper']:
            objects = {row['id']: row for row in request['owned_objects']}
            for row in output['blueprint']['objects']:
                source = objects[row['source_object_id']]
                if source['kind'] == 'Block' and source['classification'] == 'control':
                    row['native_component'] = 'page-items'
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp('d')


@pytest.mark.parametrize('mutation', ['permission', 'target'])
def test_immediate_preinvoke_change_blocks_provider(tmp_path, mutation):
    directory = tmp_path / 'role'
    directory.mkdir()
    allowed, target, calls = [True], deepcopy(TARGET), []
    class Prepared:
        def invoke_prepared(self, role, request, identity, *, role_name, target_profile, before_invoke):
            if mutation == 'permission': allowed[0] = False
            else: target['opaf']['build_id'] = 'changed-after-preparation'
            before_invoke({})
            calls.append('forbidden-provider-submit')
            pytest.fail('Changed permission/target reached provider submission')
    with pytest.raises(OpafError, match='reconcile without replay'):
        _role(directory, 'mapper', Prepared(), PROFILE['mapper'], {'synthetic': True},
            {'job_id': 'fox-' + '1' * 20, 'source_hash': 'a' * 64},
            lambda: deepcopy(target), lambda context: allowed[0], {})
    assert calls == []
    assert not (directory / 'mapper-intent.json').exists()
    assert not (directory / 'mapper.json').exists()


def test_unknown_provider_outcome_retains_intent_without_automatic_replay(tmp_path):
    directory = tmp_path / 'role'
    directory.mkdir()
    calls = []
    class UnknownProvider:
        def invoke_prepared(self, role, request, identity, *, role_name, target_profile, before_invoke):
            before_invoke({})
            calls.append('synthetic-submission')
            raise TimeoutError('Synthetic unknown outcome, never retry automatically')
    args = (directory, 'mapper', UnknownProvider(), PROFILE['mapper'], {'synthetic': True},
        {'job_id': 'fox-' + '1' * 20, 'source_hash': 'a' * 64},
        lambda: deepcopy(TARGET), lambda context: True, {})
    with pytest.raises(OpafError, match='reconcile without replay'):
        _role(*args)
    assert (directory / 'mapper-intent.json').is_file()
    before = tree_bytes(directory)
    with pytest.raises(OpafError, match='uncertain'):
        _role(*args)
    assert calls == ['synthetic-submission'] and tree_bytes(directory) == before


@pytest.fixture
def executed(client, configured, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    c, root, pid, rid, snapshot = queued_case(client)
    model = DevelopmentModel()
    monkeypatch.setattr(package, 'package_configuration', lambda *args, **kwargs: {
        'profile': deepcopy(PROFILE), 'opaf_client': model,
        'target_profile_loader': lambda: deepcopy(TARGET), 'offline_validator': authored_validator})
    def forbidden(*args, **kwargs):
        pytest.fail('Development package must never construct the Oracle/converter gateway')
    monkeypatch.setattr(prototype_job, 'PrototypeHttpConverterAdapter', forbidden)
    monkeypatch.setattr(prototype_job, 'ConverterClient', forbidden)
    failures = []
    original_run = prototype_job.run_prototype_job
    def observed_run(*args, **kwargs):
        try:
            return original_run(*args, **kwargs)
        except Exception as error:
            failures.append(repr(error))
            raise
    monkeypatch.setattr(prototype_job, 'run_prototype_job', observed_run)
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3')
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    worker.process_one(db, root)
    with db() as connection:
        row = dict(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
    assert row['state'] == 'GENERATED', (row, failures)
    assert model.calls
    return c, root, pid, rid, snapshot, model


def test_development_worker_package_download_and_separate_acceptance(executed):
    c, root, pid, rid, snapshot, model = executed
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/output')
    assert response.status_code == 200, response.text
    output = response.json()
    assert output['format_validated'] is True
    assert output['runtime_verified'] is False and output['technically_verified'] is False
    assert output['business_behavior_accepted'] is False
    documents = prototype_job.validate_prototype_snapshot(snapshot)
    approved = snapshot['prototype']['approved_chunk_hashes']
    packet = approved_packet(documents,
        expected_source_binding=snapshot['prototype']['source_binding'], approved_chunk_hashes=approved)
    expected = {row['id']: row for row in packet['chunks']}
    assert approved
    for role in ('mapper', 'reviewer'):
        chunks = [chunk for name, request in model.calls if name == role
            for chunk in (request if role == 'mapper' else request['request'])['chunks']]
        assert {chunk['id']: chunk['sha256'] for chunk in chunks} == approved
        for chunk in chunks:
            assert chunk['text'] == expected[chunk['id']]['text']
        assert any("'APPROVED', 123.45" in chunk['text'] for chunk in chunks)
    raw = c.get(output['download_path'])
    assert raw.status_code == 200
    assert hashlib.sha256(raw.content).hexdigest() == output['package_sha256']
    job = root / 'jobs' / rid
    assert raw.content == (job / 'prototype-pipeline/apexlang-package.zip').read_bytes()
    binding = json.loads((job / 'prototype-pipeline/binding.json').read_bytes())
    assert binding['development_processing_sha256'] == snapshot['prototype']['development_processing_sha256']
    before, calls = tree_bytes(job), deepcopy(model.calls)
    assert c.get(output['download_path']).content == raw.content
    assert tree_bytes(job) == before and model.calls == calls
    assert not any((job / 'prototype-pipeline' / (stage + '.json')).exists()
        for stage in ('prepare_schema', 'import', 'verify_runtime', 'export'))


@pytest.mark.parametrize('mutation', ['event', 'mode', 'provenance'])
def test_retained_package_rechecks_development_approval_without_model_replay(executed, mutation):
    c, root, pid, rid, snapshot, model = executed
    calls = deepcopy(model.calls)
    if mutation == 'event':
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('DELETE FROM events WHERE object_id=?', (rid,))
    else:
        if mutation == 'mode':
            for key in ('processing_mode', 'development_processing', 'development_processing_sha256'):
                snapshot['prototype'].pop(key)
            snapshot['approvals'].pop('unredacted_development_source')
            snapshot['approvals']['redacted_source'] = True
        else:
            snapshot['prototype']['development_processing']['source_provenance'][0]['receipt_sha256'] = 'f' * 64
        (root / 'jobs' / rid / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    for route in ('output', 'download'):
        response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/{route}')
        assert response.status_code == 409, response.text
    assert model.calls == calls


@pytest.mark.parametrize('mutation', ['event', 'source-selection'])
def test_worker_rechecks_current_approval_before_synthetic_submission(client, configured, monkeypatch, mutation):
    c, root, pid, rid, snapshot = queued_case(client)
    model = DevelopmentModel()
    monkeypatch.setattr(package, 'package_configuration', lambda *args, **kwargs: {
        'profile': deepcopy(PROFILE), 'opaf_client': model,
        'target_profile_loader': lambda: deepcopy(TARGET), 'offline_validator': authored_validator})
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        if mutation == 'event': db.execute('DELETE FROM events WHERE object_id=?', (rid,))
        else: db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3')
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    worker.process_one(db, root)
    with db() as connection:
        assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    assert model.calls == []
    assert not list((root / 'jobs' / rid).rglob('*-intent.json'))
