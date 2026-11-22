"""Restarted local API reads retain sealed bytes across engine drift.

Real isolated SQLite/API/worker; installed compiler fixture is synthetic only.
No live provider, SQLcl process, Oracle import or business acceptance is asserted.
"""
import hashlib
import shutil
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from fox import forms_facts, xml_mapping_job as jobs
from fox.app import create_app
from fox.opaf import OpafError
from fox.prototype_export_only import _compiler_evidence_dir, _members, _validated_log
from fox.prototype_pipeline import _save_bytes_once
from fox.worker import process_one
from test_xml_mapping import source
from test_xml_mapping_web import (
    ORIGIN, connection, installed_compiler, login, new_project,
    no_external_actions, settings, upload,
)


def test_deep_project_retains_and_rechecks_compiler_log(tmp_path):
    raw = b'Validation successful.\n'
    digest = hashlib.sha256(raw).hexdigest()
    proof = dict(passed=True, return_code=0, connection_mode='/nolog',
                 sqlcl_version='26.1', validation_log_sha256=digest)
    filename = 'offline-' + digest + '.log'
    directory = tmp_path
    while len(str(directory / filename)) < 275:
        directory /= 'another-project-level'
    storage = _compiler_evidence_dir(directory)
    storage.mkdir(parents=True, exist_ok=True)
    path = storage / filename
    try:
        assert _save_bytes_once(path, raw) == digest
        assert _validated_log(directory, proof) == proof
        path.write_bytes(b'Changed compiler log.\n')
        with pytest.raises(OpafError):
            _validated_log(directory, proof)
    finally:
        path.unlink(missing_ok=True)


def _files(directory):
    return {str(p.relative_to(directory)): p.read_bytes()
            for p in directory.rglob('*') if p.is_file()}


def _rows(root):
    with connection(root)() as db:
        return {table: [tuple(row) for row in db.execute(f'SELECT * FROM {table} ORDER BY rowid')]
                for table in ('runs', 'events', 'acceptances')}


def _complete(root, documents):
    # Exit the original app lifespan before constructing the restarted API.
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        login(c)
        pid = new_project(c)
        other_pid = new_project(c)
        upload(c, pid, documents)
        scope = c.get(f'/api/projects/{pid}/xml-mapping').json()
        assert scope['available'] is True, scope
        body = {key: scope[key] for key in (
            'source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')}
        body.update(request_id=str(uuid.uuid4()), approved_synthetic_scope=True,
                    approved_local_source_processing=True)
        queued = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
        assert queued.status_code == 202, queued.text
        process_one(connection(root), root)
        run = c.get(f"/api/projects/{pid}/xml-mapping/runs/{queued.json()['id']}").json()
        assert run['state'] == 'GENERATED', run
        response = c.get(run['download_url'])
        assert response.status_code == 200, response.text
        return pid, other_pid, scope, run, response.content


def _forbid_replay(monkeypatch):
    calls = []
    def forbid(name):
        def fail(*args, **kwargs):
            calls.append(name)
            raise AssertionError('Saved reads must not invoke ' + name)
        return fail
    for name in ('generate_xml_package', 'validate_xml_package', 'validate_offline'):
        monkeypatch.setattr(jobs.xml_mapping, name, forbid(name))
    return calls


@pytest.mark.parametrize('drift', ['renderer', 'parser'])
@pytest.mark.parametrize('empty_code', [False, True], ids=['two-modules', 'zero-code-units'])
@pytest.mark.parametrize('restore', [False, True], ids=['restart', 'sqlite-backup-restore'])
def test_restart_saved_output_survives_same_catalog_engine_drift(
        tmp_path_factory, settings, monkeypatch, drift, empty_code, restore):
    root = tmp_path_factory.mktemp('d') / 'r'
    # Deliberately not alphabetic: retained source identity must preserve the
    # generator's canonical ordering, not assume upload or snapshot row order.
    documents = ([('zero.xml', source(formula=None))] if empty_code else [
        ('z-last.xml', source(module='LAST', block='LAST_LINES')),
        ('a-first.xml', source(module='FIRST', block='FIRST_LINES',
                              extra='<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="COMMIT;"/>'))])
    pid, other_pid, scope, run, package = _complete(root, documents)
    assert run['total_units'] == (0 if empty_code else 3)
    assert run['unsupported_units'] == (0 if empty_code else 1)
    members = _members(package)
    for name, raw in documents:
        assert members['fox-package/sources/' + name] == raw
    before_files = _files(root / 'jobs')
    before_rows = _rows(root)
    if restore:
        restored = root.parent / 'restored'
        restored.mkdir()
        # SQLite's backup API, not a potentially inconsistent database-file
        # copy. Only this test's synthetic DB and job evidence are transferred.
        with connection(root)() as original, sqlite3.connect(restored / 'fox.sqlite3') as copied:
            original.backup(copied)
        shutil.copytree(root / 'jobs', restored / 'jobs')
        root = restored
    calls = _forbid_replay(monkeypatch)
    parser_calls = []
    if drift == 'parser':
        def reject_old_xml(*args, **kwargs):
            parser_calls.append(True)
            raise ValueError('Synthetic new parser rejects this historical XML')
        # Real common parser entry point, not an implementation-specific alias
        # in the retained reader. Fresh assessment may legitimately reject it.
        monkeypatch.setattr(forms_facts, 'assess_forms_xml', reject_old_xml)
    assert jobs.xml_mapping.mapping_catalog()['catalog_sha256'] == scope['catalog_sha256']
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as restarted:
        login(restarted)
        overview = restarted.get(f'/api/projects/{pid}/xml-mapping')
        assert overview.status_code == 200, overview.text
        assert overview.json()['runs'] == [run]
        assert overview.json()['available'] is (drift != 'parser')
        parser_calls.clear()  # Fresh assessment above is allowed to parse.
        status = restarted.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}")
        assert status.status_code == 200 and status.json() == run
        response = restarted.get(run['download_url'])
        assert response.status_code == 200 and response.content == package
        assert parser_calls == []
        assert response.headers['X-FOX-Runtime-Verified'] == 'false'
        assert response.headers['X-FOX-Business-Acceptance'] == 'not-asserted'
        for suffix in ('', '/download'):
            assert restarted.get(
                f"/api/projects/{other_pid}/xml-mapping/runs/{run['id']}{suffix}").status_code == 404
        restarted.cookies.clear()
        assert restarted.get(run['download_url']).status_code == 401
    assert calls == []
    assert _files(root / 'jobs') == before_files
    assert _rows(root) == before_rows
    assert len(before_rows['runs']) == 1 and before_rows['acceptances'] == []


@pytest.mark.parametrize('target', ['candidate', 'package', 'log', 'snapshot', 'result'])
def test_restart_tamper_stays_blocked_without_replay(
        tmp_path_factory, settings, monkeypatch, target):
    root = tmp_path_factory.mktemp('t') / 'r'
    pid, _, _, run, _ = _complete(root, [('order.xml', source())])
    directory = root / 'jobs' / run['id'] / 'xml-mapping'
    paths = {'candidate': directory / 'candidate.zip', 'package': directory / 'apexlang.zip',
             'log': next((directory / 'validation').glob('offline-*.log')),
             'snapshot': directory.parent / 'source-snapshot.json', 'result': directory / 'result.json'}
    path = paths[target]
    path.write_bytes(path.read_bytes() + b' TAMPER')
    before_files, before_rows = _files(root / 'jobs'), _rows(root)
    calls = _forbid_replay(monkeypatch)
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as restarted:
        login(restarted)
        assert restarted.get(run['download_url']).status_code == 409
        status = restarted.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
        assert status['state'] == 'ATTENTION' and status['format_validated'] is False
        overview = restarted.get(f'/api/projects/{pid}/xml-mapping').json()
        assert overview['available'] is False and overview['runs'][0]['state'] == 'ATTENTION'
    assert calls == []
    assert _files(root / 'jobs') == before_files
    assert _rows(root) == before_rows
