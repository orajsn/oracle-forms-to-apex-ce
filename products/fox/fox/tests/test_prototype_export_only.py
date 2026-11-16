"""Synthetic provider/validator fixtures; no Oracle import or live-model claim."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import zipfile

import pytest

from fox import prototype_export_only as package, prototype_job, worker
from fox.opaf import OpafError, canonical_hash
from fox.prototype_pipeline import run_prototype_pipeline
from test_prototype_pipeline import setup, PROFILE, TARGET, SyntheticOpaf, SyntheticConverter
from test_prototype_project_routes import prepare
from test_source_history_api import client, settings, no_external_actions, upload, login, new_project, ORIGIN


@pytest.fixture
def tmp_path(tmp_path_factory):
    # Hash-named compiler evidence and nested APEX projects need a short Windows root.
    return tmp_path_factory.mktemp('x')


def authored_validator(raw, directory):
    assert zipfile.is_zipfile(io.BytesIO(raw))
    from fox.prototype_pipeline import _save_bytes_once
    log = b'AUTHORED SYNTHETIC VALIDATOR TEST LOG; not actual SQLcl execution.\n'
    digest = hashlib.sha256(log).hexdigest()
    _save_bytes_once(Path(directory) / ('offline-' + digest + '.log'), log)
    return {'passed': True, 'return_code': 0, 'connection_mode': '/nolog',
            'sqlcl_version': 'synthetic-test', 'validation_log_sha256': digest}


def run_package(setup, **extra):
    job, docs, model, approvals, kwargs = setup
    return run_prototype_pipeline(job, docs, **{**kwargs, 'delivery_mode': package.DELIVERY_MODE,
        'offline_validator': authored_validator, **extra})


def test_rendered_package(setup):
    result = run_package(setup)
    job, _, _, _, _ = setup
    root = job / 'prototype-pipeline'
    assert result['status'] == 'APEX_GENERATED' and result['format_validated'] is True
    assert result['facts']['sqlcl_validated'] and result['facts']['download_ready']
    assert all(result['facts'][key] is False for key in package.NOT_RUN)
    assert not any((root / (stage + '.json')).exists() for stage in
        ('prepare_schema', 'import', 'verify_runtime', 'export'))
    with zipfile.ZipFile(root / 'candidate-apexlang.zip') as candidate, zipfile.ZipFile(root / 'apexlang-package.zip') as delivered:
        assert all(candidate.read(name) == delivered.read(name) for name in candidate.namelist())
        metadata = json.loads(delivered.read('fox-package/metadata.json'))
        config = json.loads(candidate.read('.apex/apexlang.json'))
        assert metadata['compatibility']['mmd_version'] == config['mmdVersion']
        assert metadata['omissions'] and metadata['format_validated'] is True
        assert b'CREATE TABLE' in delivered.read('fox-package/supporting-schema.sql')
        assert b'not customer-schema facts' in delivered.read('fox-package/README.md')
        assert 'application.apx' in delivered.namelist()


def test_resume_without_calls(setup):
    first = run_package(setup)
    model = setup[2]
    before = deepcopy(model.calls)
    def forbidden(*args, **kwargs):
        pytest.fail('Retained validation/models must not replay.')
    assert run_package(setup, offline_validator=forbidden) == first
    assert model.calls == before


@pytest.mark.parametrize('kind', ['invalid', 'missing'])
def test_validator_blocks(setup, kind):
    def invalid(raw, directory):
        if kind == 'missing':
            raise OpafError('SQLcl/Java missing')
        return {**authored_validator(raw, directory), 'passed': False}
    with pytest.raises(OpafError):
        run_package(setup, offline_validator=invalid)
    assert not (setup[0] / 'prototype-pipeline/package-publication.json').exists()
    assert not (setup[0] / 'prototype-pipeline/apexlang-package.zip').exists()


def test_review_blocks(setup):
    setup[2].changes_role = True
    assert run_package(setup)['status'] == 'CHANGES_REQUIRED'
    assert not (setup[0] / 'prototype-pipeline/offline-validation.json').exists()


def test_prepared_callback_and_metrics(setup, monkeypatch):
    model, order = setup[2], []
    def prepared(role, request, identity, *, role_name, target_profile, before_invoke):
        environment = model.observe_environment(role, identity, role_name=role_name, target_profile=target_profile)
        before_invoke(environment)
        assert list(setup[0].rglob(role_name + '-intent.json'))
        order.append(role_name)
        output, invocation = model.invoke(role, request)
        return output, invocation, environment, {'provider': 'opaf', 'total_seconds': .25,
            'request_seconds': .2, 'source': 'MUST-NOT-BE-STORED', 'headers': {'secret': 'x'}}
    monkeypatch.setattr(model, 'invoke_prepared', prepared, raising=False)
    run_package(setup)
    assert order
    files = list(package._telemetry_directory(setup[0]).glob('*.json'))
    assert len(files) == len(order)
    assert not list((setup[0] / 'prototype-pipeline').rglob('*timing*'))
    assert all('MUST-NOT' not in path.read_text() and 'headers' not in path.read_text() for path in files)
    summary = package._timing_summary(setup[0], {'source_binding': setup[4]['expected_source_binding']})
    assert summary['provider_calls'] == len(order) and summary['available'] is True


def test_metrics_failure_safe(setup, monkeypatch):
    model = setup[2]
    def prepared(role, request, identity, *, role_name, target_profile, before_invoke):
        environment = model.observe_environment(role, identity, role_name=role_name, target_profile=target_profile)
        before_invoke(environment)
        output, invocation = model.invoke(role, request)
        return output, invocation, environment, {'total_seconds': .1}
    monkeypatch.setattr(model, 'invoke_prepared', prepared, raising=False)
    def failed(*args):
        raise OSError('advisory disk write failed')
    monkeypatch.setattr(package, 'save_provider_timing', failed)
    result = run_package(setup)
    calls = deepcopy(model.calls)
    assert result['format_validated']
    assert run_package(setup) == result and model.calls == calls


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', 'synthetic-not-opened')
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.setattr(prototype_job, 'load_prototype_profile', lambda path: {
        'target_profile_sha256': canonical_hash(TARGET), 'target_profile': deepcopy(TARGET)})


class MetadataModel(SyntheticOpaf):
    def invoke(self, role, request):
        task = request if role == PROFILE['mapper'] else {
            key: request[key] for key in ('request', 'candidate', 'candidate_sha256')}
        output, invocation = super().invoke(role, task)
        invocation['request_sha256'] = canonical_hash(request)
        return output, invocation


@pytest.fixture
def connected(client, configured, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    c, root, pid, _, body = prepare(client)
    body['delivery_mode'] = package.DELIVERY_MODE
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    rid = response.json()['id']
    model = MetadataModel()
    monkeypatch.setattr(package, 'package_configuration', lambda *args, **kwargs: {
        'profile': deepcopy(PROFILE), 'opaf_client': model,
        'target_profile_loader': lambda: deepcopy(TARGET), 'offline_validator': authored_validator})
    def forbidden(*args, **kwargs):
        pytest.fail('Package mode must not construct or call the DB/converter gateway.')
    monkeypatch.setattr(prototype_job, 'PrototypeHttpConverterAdapter', forbidden)
    monkeypatch.setattr(prototype_job, 'ConverterClient', forbidden)
    from contextlib import contextmanager
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
        row = connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone()
        assert row['state'] == 'GENERATED', dict(row)
        assert 'format validated' in row['message']
    return c, root, pid, rid, model


def test_connected_download(connected):
    c, root, pid, rid, model = connected
    job = root / 'jobs' / rid
    before = deepcopy(model.calls)
    result = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/output')
    assert result.status_code == 200, result.text
    output = result.json()
    assert output['scope'] == 'fox-apexlang-package-output-v1'
    assert output['format_validated'] and output['package_format'] == 'apexlang_zip'
    assert output['runtime_verified'] is False and output['technically_verified'] is False
    assert output['business_behavior_accepted'] is False
    raw = c.get(output['download_path'])
    assert raw.status_code == 200, raw.text
    assert raw.content == (job / 'prototype-pipeline/apexlang-package.zip').read_bytes()
    assert hashlib.sha256(raw.content).hexdigest() == output['package_sha256']
    assert c.get(output['download_path']).content == raw.content
    assert model.calls == before
    progress = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/progress').json()
    assert progress['delivery_mode'] == 'apexlang_package'
    assert [row['id'] for row in progress['stages']] == list(package.STAGES)
    assert all(row['status'] == 'recorded' for row in progress['stages'])
    assert progress['technically_verified'] is False


@pytest.mark.parametrize('change', ['zip', 'candidate', 'review', 'receipt', 'owner', 'source', 'mode', 'profile'])
def test_download_guards(connected, monkeypatch, change):
    c, root, pid, rid, _ = connected
    job = root / 'jobs' / rid
    if change in ('zip', 'candidate'):
        path = job / 'prototype-pipeline' / ('apexlang-package.zip' if change == 'zip' else 'candidate-apexlang.zip')
        path.write_bytes(path.read_bytes() + b'TAMPER')
    elif change == 'review':
        next((job / 'prototype-pipeline').rglob('reviewer.json')).unlink()
    elif change == 'receipt':
        (job / 'prototype-pipeline/offline-validation.json').write_text('{}')
    elif change == 'owner':
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('UPDATE projects SET owner=? WHERE id=?', ('other-owner', pid))
    elif change == 'source':
        upload(c, pid, [('new.xml', b'<FormModule Name="NEW"/>')])
    elif change == 'mode':
        path = job / 'source-snapshot.json'
        snapshot = json.loads(path.read_bytes())
        del snapshot['prototype']['delivery_mode']
        path.write_text(json.dumps(snapshot))
    else:
        monkeypatch.setattr(prototype_job, 'load_prototype_profile', lambda _: {'target_profile_sha256': 'f' * 64})
    for route in ('output', 'download'):
        response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/{route}')
        assert response.status_code in (404, 409), response.text


def test_download_auth(connected):
    c, _, pid, rid, _ = connected
    c.cookies.clear()
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/download').status_code == 401


def test_broken_telemetry_optional(connected):
    c, root, pid, rid, _ = connected
    path = package._telemetry_directory(root / 'jobs' / rid, create=True)
    (path / 'bad.json').write_text('[]')
    progress = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/progress')
    assert progress.status_code == 200
    assert progress.json()['timing']['available'] is False
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/download').status_code == 200


def test_broken_progress(connected):
    c, root, pid, rid, _ = connected
    path = root / 'jobs' / rid / 'prototype-pipeline/offline-validation.json'
    value = json.loads(path.read_bytes())
    value['validation']['passed'] = False
    path.write_text(json.dumps(value))
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/progress')
    assert response.status_code == 200
    assert response.json()['progress_available'] is False
    assert [row['id'] for row in response.json()['stages']] == list(package.STAGES)


@pytest.mark.parametrize('change', ['deleted', 'modified', 'oversized', 'directory', 'hardlink'])
def test_validation_log_required(connected, change):
    c, root, pid, rid, _ = connected
    job = root / 'jobs' / rid
    receipt = json.loads((job / 'prototype-pipeline/offline-validation.json').read_bytes())
    path = job / 'prototype-pipeline' / ('offline-' + receipt['validation']['validation_log_sha256'] + '.log')
    if change == 'deleted':
        path.unlink()
    elif change == 'modified':
        path.write_bytes(b'Not the actual retained validation output.')
    elif change == 'oversized':
        path.write_bytes(b'x' * (package.MAX_VALIDATION_LOG + 1))
    elif change == 'directory':
        path.unlink()
        path.mkdir()
    else:
        os.link(path, path.parent / 'duplicate-log-link')
    for route in ('output', 'download'):
        assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/{route}').status_code == 409


def test_resume_requires_log(setup):
    run_package(setup)
    path = next((setup[0] / 'prototype-pipeline').glob('offline-*.log'))
    path.unlink()
    before = deepcopy(setup[2].calls)
    with pytest.raises(OpafError, match='log is missing'):
        run_package(setup)
    assert setup[2].calls == before


def test_publication_requires_log(setup):
    def missing_log(raw, directory):
        return {'passed': True, 'return_code': 0, 'connection_mode': '/nolog',
            'sqlcl_version': 'synthetic-test', 'validation_log_sha256': hashlib.sha256(b'Absent log').hexdigest()}
    with pytest.raises(OpafError, match='log is missing'):
        run_package(setup, offline_validator=missing_log)
    assert not (setup[0] / 'prototype-pipeline/package-publication.json').exists()


def tree_bytes(job):
    return {p.relative_to(job).as_posix(): p.read_bytes() for p in job.rglob('*') if p.is_file()}


@pytest.fixture
def legacy(client, configured, monkeypatch):
    from contextlib import contextmanager
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    c, root, pid, _, body = prepare(client)
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202
    rid = response.json()['id']
    model, converter = MetadataModel(), SyntheticConverter()
    converter.fail_stage = 'verify_runtime'
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: {
        'profile': deepcopy(PROFILE), 'opaf_client': model,
        'target_profile_loader': lambda: deepcopy(TARGET), 'converter_adapter': converter})
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
        original_row = dict(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
    assert original_row['state'] == 'ATTENTION'
    job = root / 'jobs' / rid
    assert (job / 'prototype-pipeline/verify_runtime-intent.json').is_file()
    original_tree, model_calls, converter_calls = tree_bytes(job), deepcopy(model.calls), deepcopy(converter.calls)
    validations = []
    def validator(raw, directory):
        validations.append(hashlib.sha256(raw).hexdigest())
        return authored_validator(raw, directory)
    monkeypatch.setattr(package, 'validate_offline', validator)
    def forbidden(*args, **kwargs):
        pytest.fail('Saved delivery must not invoke models, gateway/configuration, Oracle or browser stages.')
    monkeypatch.setattr(prototype_job, '_configuration', forbidden)
    monkeypatch.setattr(prototype_job, 'ConverterClient', forbidden)
    monkeypatch.setattr(prototype_job, 'PrototypeHttpConverterAdapter', forbidden)
    yield c, root, pid, rid, job, validations, original_tree, original_row
    assert tree_bytes(job) == original_tree
    assert model.calls == model_calls and converter.calls == converter_calls
    with db() as connection:
        assert dict(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone()) == original_row


def readiness(legacy):
    c, _, pid, rid, *_ = legacy
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/saved-package/readiness')
    assert response.status_code == 200, response.text
    return response.json()


def saved_prepare(legacy, projection=None):
    c, _, pid, rid, *_ = legacy
    projection = projection or readiness(legacy)
    return c.post(f'/api/projects/{pid}/prototype-runs/{rid}/saved-package', json={
        'preparation_binding_sha256': projection['preparation_binding_sha256'],
        'approved_format_only_delivery': True})


def test_saved_connected(legacy):
    c, _, pid, rid, job, validations, *_ = legacy
    projection = readiness(legacy)
    assert projection['eligible'] and not projection['prepared'] and validations == []
    response = saved_prepare(legacy, projection)
    assert response.status_code == 200, response.text
    output = response.json()
    assert output['scope'] == 'fox-saved-apexlang-package-output-v1'
    assert output['status'] == 'PACKAGE_PREPARED' and output['legacy_run_state'] == 'ATTENTION'
    assert output['format_validated'] and output['runtime_verified'] is False
    assert output['selected_code_scope']['approved_chunk_hashes']
    raw = c.get(output['download_path'])
    assert raw.status_code == 200
    assert hashlib.sha256(raw.content).hexdigest() == output['package_sha256']
    with zipfile.ZipFile(io.BytesIO(raw.content)) as delivered, zipfile.ZipFile(job / 'prototype-pipeline/candidate-apexlang.zip') as candidate:
        assert all(delivered.read(name) == candidate.read(name) for name in candidate.namelist())
    assert saved_prepare(legacy, projection).json() == output and len(validations) == 1
    assert readiness(legacy)['prepared'] is True
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/saved-package/output').json() == output
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/download').status_code == 409
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/output').status_code == 409


@pytest.mark.parametrize('change', ['owner', 'source', 'profile', 'active', 'candidate', 'review', 'binding', 'consent'])
def test_saved_preparation_refused(client, configured, monkeypatch, tmp_path, change):
    # Separate fixture context keeps intentional adversarial changes out of preservation assertion.
    from contextlib import contextmanager
    generator = legacy.__wrapped__(client, configured, monkeypatch)
    case = next(generator)
    c, root, pid, rid, job, validations, original_tree, original_row = case
    projection = readiness(case)
    saved_snapshot = None
    changed_path = None
    if change == 'owner':
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('UPDATE projects SET owner=? WHERE id=?', ('other-owner', pid))
    elif change == 'source':
        upload(c, pid, [('new.xml', b'<FormModule Name="NEW"/>')])
    elif change == 'profile':
        monkeypatch.setattr(prototype_job, 'load_prototype_profile', lambda _: {'target_profile_sha256': 'f' * 64})
    elif change == 'active':
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (rid,))
    elif change in ('candidate', 'review'):
        changed_path = job / 'prototype-pipeline/candidate-apexlang.zip' if change == 'candidate' else next((job / 'prototype-pipeline').rglob('reviewer.json'))
        saved_snapshot = changed_path.read_bytes()
        changed_path.write_bytes(b'TAMPERED')
    else:
        body = {'preparation_binding_sha256': 'f' * 64 if change == 'binding' else projection['preparation_binding_sha256'],
                'approved_format_only_delivery': change != 'consent'}
        response = c.post(f'/api/projects/{pid}/prototype-runs/{rid}/saved-package', json=body)
        assert response.status_code == 409 and validations == []
        with pytest.raises(StopIteration):
            next(generator)
        return
    response = saved_prepare(case, projection)
    assert response.status_code in (404, 409) and validations == []
    # Restore only the intentional test corruption, not any product edit.
    if changed_path:
        changed_path.write_bytes(saved_snapshot)
    if change == 'active':
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('UPDATE runs SET state=? WHERE id=?', (original_row['state'], rid))
    with pytest.raises(StopIteration):
        next(generator)


@pytest.mark.parametrize('change', ['deleted-log', 'modified-log', 'zip'])
def test_saved_download_integrity(legacy, change):
    c, _, pid, rid, job, validations, *_ = legacy
    response = saved_prepare(legacy)
    assert response.status_code == 200
    directory = package._saved_directory(job)
    if change == 'deleted-log':
        next(directory.glob('offline-*.log')).unlink()
    elif change == 'modified-log':
        next(directory.glob('offline-*.log')).write_bytes(b'TAMPERED')
    else:
        (directory / 'apexlang-package.zip').write_bytes(b'TAMPERED')
    assert c.get(response.json()['download_path']).status_code == 409
    assert saved_prepare(legacy, {'preparation_binding_sha256': response.json()['preparation_binding_sha256']}).status_code == 409
    assert len(validations) == 1


@pytest.mark.parametrize('failure', ['compiler-missing', 'compiler-unavailable', 'validation-failed'])
def test_saved_validator_failure(legacy, monkeypatch, failure):
    def failed(raw, directory):
        if failure == 'compiler-missing':
            raise OpafError('No offline compiler')
        if failure == 'compiler-unavailable':
            raise package.OfflineCompilerUnavailable('Offline validation requires SQLcl and compatible Java.')
        return {**authored_validator(raw, directory), 'passed': False}
    monkeypatch.setattr(package, 'validate_offline', failed)
    response = saved_prepare(legacy)
    assert response.status_code == (503 if failure == 'compiler-unavailable' else 409)
    if failure == 'compiler-unavailable':
        assert 'requires SQLcl' in response.json()['detail']
    assert not (package._saved_directory(legacy[4]) / 'publication.json').exists()


def test_saved_requires_auth(legacy):
    c, _, pid, rid, *_ = legacy
    c.cookies.clear()
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/saved-package/readiness').status_code == 401
    assert c.post(f'/api/projects/{pid}/prototype-runs/{rid}/saved-package', json={
        'preparation_binding_sha256': 'a' * 64, 'approved_format_only_delivery': True}).status_code == 401


def test_real_prepared_provider_tree_clean(tmp_path, monkeypatch):
    from test_oci_genai import target, fake_sdk, InjectedService, documents
    from fox.oci_genai import OciGenAiClient
    from fox.design_provider import roles
    from fox.forms_understanding_packet import local_packet
    from fox.forms_native_plan import POLICY_ID
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    current, service = target(), InjectedService()
    client = OciGenAiClient(current, client=service, sdk=fake_sdk())
    docs = documents()
    job = tmp_path / 'data' / 'jobs' / ('fox-' + '8' * 20)
    job.parent.mkdir(parents=True)
    original_save = package.save_provider_timing
    checked_writes = []
    def checked_save(*args):
        before = tree_bytes(job)
        original_save(*args)
        assert tree_bytes(job) == before
        checked_writes.append(True)
    monkeypatch.setattr(package, 'save_provider_timing', checked_save)
    result = run_prototype_pipeline(job, docs, project_id='offline-project', project_name='Offline',
        expected_source_binding=local_packet(docs)['source_binding'], approved_chunk_hashes={},
        approved_policy_id=POLICY_ID, opaf_client=client, profile=roles(current),
        target_profile_loader=lambda: deepcopy(current), processing_approval_check=lambda _: True)
    assert result['status'] == 'BLOCKED_ADAPTER'
    original = tree_bytes(job)
    assert package._telemetry_directory(job).parent.parent == tmp_path / 'data'
    assert list(package._telemetry_directory(job).glob('*.json'))
    assert not (job / 'telemetry').exists()
    assert not (job.parent / 'telemetry').exists()
    summary = package._timing_summary(job, {'source_binding': local_packet(docs)['source_binding']})
    assert summary['available'] and summary['provider_calls'] == len(service.calls)
    assert len(checked_writes) == len(service.calls)
    assert tree_bytes(job) == original


def test_no_default_fake_pass(tmp_path, monkeypatch):
    monkeypatch.setenv('FOX_EXPORT_SQLCL_PATH', str(tmp_path / 'absent-sqlcl'))
    with pytest.raises(OpafError, match='requires SQLcl'):
        package.package_configuration('a' * 64)


def test_configuration_no_gateway(monkeypatch):
    from test_oci_genai import target
    target_profile = target()
    digest = canonical_hash(target_profile)
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', 'synthetic-not-opened')
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'oci-genai')
    monkeypatch.delenv('FOX_CONVERTER_URL', raising=False)
    monkeypatch.delenv('FOX_CONVERTER_CREDENTIAL_FILE', raising=False)
    monkeypatch.delenv('FOX_OPAF_CREDENTIAL_FILE', raising=False)
    monkeypatch.setattr(package, '_sqlcl_path', lambda: Path('synthetic-sqlcl'))
    monkeypatch.setattr(prototype_job, 'load_prototype_profile', lambda _: {
        'target_profile': target_profile, 'target_profile_sha256': digest})
    instance = object()
    monkeypatch.setattr('fox.oci_genai.OciGenAiClient', lambda target: instance)
    runtime = package.package_configuration(digest)
    assert runtime['opaf_client'] is instance
    assert 'gateway' not in runtime and 'converter_adapter' not in runtime


def test_resume_bad_validation(setup):
    run_package(setup)
    path = setup[0] / 'prototype-pipeline/offline-validation.json'
    receipt = json.loads(path.read_bytes())
    receipt['validation']['passed'] = False
    path.write_text(json.dumps(receipt))
    before = deepcopy(setup[2].calls)
    with pytest.raises(OpafError, match='validation did not pass'):
        run_package(setup)
    assert setup[2].calls == before


def test_creation_only_mode():
    from fox.prototype_project_routes import PrototypeContinuationInput
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match='creation-only'):
        PrototypeContinuationInput.model_validate({'delivery_mode': package.DELIVERY_MODE})


@pytest.fixture
def verifier_api(tmp_path, settings, configured, monkeypatch):
    from fastapi.testclient import TestClient
    from fox.app import create_app
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'a' * 64)
    calls = []
    def forbidden(*args, **kwargs):
        calls.append('fresh-runtime')
        raise AssertionError('Legacy runtime isolation callback reached')
    monkeypatch.setattr('fox.prototype_fresh_admission.prepare_fresh_admission', forbidden)
    monkeypatch.setattr(prototype_job, '_configuration', forbidden)
    root = tmp_path / 'v'
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        login(c)
        yield c, root, calls


def test_verifier_enabled_package(verifier_api, monkeypatch):
    c, root, calls = verifier_api
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    # Retain an unrelated unresolved legacy run exactly; no witness or replay.
    old = new_project(c)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
            ('fox-' + 'e' * 20, old, 'e' * 64, 'ATTENTION', 'Retained unknown outcome', 1., 1., None))
    pid = new_project(c)
    _, _, _, _, body = prepare((c, root, pid))
    body['delivery_mode'] = package.DELIVERY_MODE
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    rid = response.json()['id']
    monkeypatch.setattr(package, 'package_configuration', lambda *args, **kwargs: {
        'profile': deepcopy(PROFILE), 'opaf_client': MetadataModel(),
        'target_profile_loader': lambda: deepcopy(TARGET), 'offline_validator': authored_validator})
    from contextlib import contextmanager
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
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/download')
    assert response.status_code == 200, response.text
    assert calls == []
    with db() as connection:
        row = connection.execute('SELECT * FROM runs WHERE project=?', (old,)).fetchone()
        assert row['state'] == 'ATTENTION' and row['message'] == 'Retained unknown outcome'


def test_verifier_legacy_gate(verifier_api):
    c, root, calls = verifier_api
    pid = new_project(c)
    _, _, _, _, body = prepare((c, root, pid))
    with pytest.raises(AssertionError, match='Legacy runtime isolation'):
        c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert calls == ['fresh-runtime']
    body['delivery_mode'] = 'invalid-bypass'
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 422
    assert calls == ['fresh-runtime']


def test_package_active_conflict(client, configured):
    c, root, pid, _, body = prepare(client)
    body['delivery_mode'] = package.DELIVERY_MODE
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 202
    other = new_project(c)
    _, _, _, _, second = prepare((c, root, other))
    second['delivery_mode'] = package.DELIVERY_MODE
    assert c.post(f'/api/projects/{other}/prototype-runs', json=second).status_code == 429
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 409


def test_default_nolog(setup, monkeypatch, tmp_path):
    run_package(setup)
    raw = (setup[0] / 'prototype-pipeline/candidate-apexlang.zip').read_bytes()
    calls = []
    private_tmp = tmp_path / 'private-tmp'
    private_tmp.mkdir()
    monkeypatch.setattr(package.tempfile, 'tempdir', str(private_tmp))
    sqlcl = tmp_path / 'synthetic-sqlcl'
    sqlcl.write_bytes(b'Not an executable; subprocess calls are intercepted below.')
    monkeypatch.setattr(package, '_sqlcl_path', lambda: sqlcl)
    def run(args, **kwargs):
        calls.append(args)
        cwd = Path(kwargs['cwd'])
        assert cwd.parent == private_tmp and cwd.name.startswith('fox-apx-')
        if args == [str(sqlcl), '-version']:
            return SimpleNamespace(returncode=0, stdout='SQLcl: Release 26.1.2.0', stderr='')
        assert args[:4] == [str(sqlcl), '-nohistory', '-S', '/nolog']
        script = Path(args[4][1:])
        assert script.parent == cwd and script.is_file()
        text = script.read_text()
        assert 'apex validate -input "' + (cwd / 'project').as_posix() + '"' in text
        assert (cwd / 'project/application.apx').is_file()
        assert (cwd / 'project/.apex/apexlang.json').is_file()
        assert 'connect ' not in text.lower() and '-name' not in args
        return SimpleNamespace(returncode=0, stdout='Validation successful', stderr='')
    monkeypatch.setattr(package.subprocess, 'run', run)
    evidence = tmp_path / 'evidence'
    validated = package.validate_offline(raw, evidence)
    assert validated['passed'] and validated['connection_mode'] == '/nolog'
    assert validated['sqlcl_version'] == '26.1.2.0'
    assert len(calls) == 2
    package._validated_log(evidence, validated)
    assert list(private_tmp.iterdir()) == []
    assert [p.name for p in evidence.iterdir()] == ['offline-' + validated['validation_log_sha256'] + '.log']
