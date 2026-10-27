"""Synthetic admission fixtures prove app wiring only, never live authority."""
from copy import deepcopy
from contextlib import closing
import importlib
import sqlite3
import threading

from fastapi.testclient import TestClient
import pytest

from test_fresh_startup import ORIGIN, publish_test_a, synthetic


def test_session_and_project_configuration_receive_actual_validated_projection(synthetic, monkeypatch):
    app_module = importlib.import_module('fox.app')
    observed = []

    def configuration(*, installation_projection):
        observed.append(deepcopy(installation_projection))
        return {'conversion_profile': 'native-project-v1', 'conversion_configured': False,
                'configured_project_schema_versions': [1, 2], 'configuration_checks': [],
                'configuration_scope': 'Synthetic wiring test only; no connectivity check.'}

    monkeypatch.setattr(app_module, 'conversion_configuration', configuration)
    publish_test_a(synthetic)
    with TestClient(app_module.create_app(synthetic.root, enable_worker=False)) as client:
        assert client.post('/api/login', json={'username': 'synthetic-user', 'password': 'synthetic-password'},
                           headers={'origin': ORIGIN}).status_code == 200
        assert client.get('/api/session').status_code == 200
        response = client.post('/api/projects', json={'customer': 'Synthetic only', 'name': 'Projection test'},
                               headers={'origin': ORIGIN})
        assert response.status_code == 201
        assert client.get('/api/projects/' + response.json()['id']).status_code == 200
    assert observed == [synthetic.projection, synthetic.projection]


def test_admitted_worker_poll_receives_projection_not_legacy_default(synthetic, monkeypatch):
    app_module = importlib.import_module('fox.app')
    worker = importlib.import_module('fox.worker')
    observed, threads = [], []
    called = threading.Event()

    def process_one(connection, root, *, installation_projection):
        assert root == synthetic.root
        observed.append(deepcopy(installation_projection))
        threads.append(threading.current_thread())
        with connection() as db:
            db.execute("UPDATE runs SET state='ATTENTION',message='Synthetic wiring check only' WHERE state='QUEUED'")
        called.set()

    monkeypatch.setattr(worker, 'process_one', process_one)
    app = app_module.create_app(synthetic.root, enable_worker=True)
    with TestClient(app) as client:
        assert client.get('/api/health').json()['status'] == 'fenced'
        assert observed == []
        publish_test_a(synthetic)
        assert client.get('/api/installation').json()['state'] == 'NORMAL'
        # The real observer intentionally does not invoke a worker for an
        # empty queue. Add only a synthetic local row after admission opens.
        with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db, db:
            db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                       ('p', 'synthetic-user', 'Synthetic only', 'Wiring test', '', 1.0))
            db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                       ('fox-' + 'a' * 20, 'p', 'b' * 64, 'QUEUED', 'Synthetic only', 1.0, 1.0, None))
        assert called.wait(3), 'The admitted synthetic worker never polled.'
        assert observed and all(value == synthetic.projection for value in observed)
    for thread in set(threads):
        thread.join(timeout=3)
        assert not thread.is_alive(), 'Owned synthetic worker did not stop.'


@pytest.mark.parametrize('mismatch', [None, 'endpoint', 'missing_projection', 'null_projection', 'legacy_profile'])
def test_configuration_uses_fresh_endpoint_without_any_network(synthetic, monkeypatch, tmp_path, mismatch):
    app_module = importlib.import_module('fox.app')
    pipeline = importlib.import_module('fox.native_project_pipeline')
    import http.client

    def no_network(*args, **kwargs):
        raise AssertionError('Configuration must never check connectivity or send credentials.')

    monkeypatch.setattr(http.client.HTTPConnection, 'connect', no_network)
    monkeypatch.setattr(http.client.HTTPSConnection, 'connect', no_network)
    profile = tmp_path / 'synthetic-profile.json'; profile.write_text('{}')
    credentials = tmp_path / 'synthetic-credential-reference.json'; credentials.write_text('{}')
    monkeypatch.setattr(pipeline, 'load_project_profile', lambda _: {'schema_version': 2})
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.setenv('FOX_NATIVE_PROFILE_FILE', str(profile))
    monkeypatch.setenv('FOX_OPAF_CREDENTIAL_FILE', str(credentials))
    monkeypatch.setenv('FOX_CONVERTER_URL', synthetic.projection['converter_endpoint'])
    if mismatch == 'endpoint':
        monkeypatch.setenv('FOX_CONVERTER_URL', 'http://127.0.0.1:8091')
    if mismatch == 'legacy_profile':
        monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'legacy-html-prototype-v1')
    if mismatch == 'missing_projection':
        result = app_module.conversion_configuration()
    else:
        result = app_module.conversion_configuration(
            installation_projection=None if mismatch == 'null_projection' else synthetic.projection)
    assert result['conversion_configured'] is (mismatch is None)
    assert 'Configuration only' in result['configuration_scope']
