"""Synthetic API admission against canonical recovery/history modules."""
import json
from pathlib import Path
import sqlite3

from fastapi.testclient import TestClient
import pytest

from fox.app import create_app
from fox import source_history
from fox.verification_recovery import VerificationRecovery
from test_source_history_api import (settings, no_external_actions, login, new_project,
    sources, upload, selected, select, approvals, ORIGIN)


@pytest.fixture
def managed_client(tmp_path, settings, monkeypatch):
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'a' * 64)
    root = tmp_path / 'managed'
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as client:
        login(client)
        yield client, root, new_project(client)


def test_selected_old_complete_set_queues_under_real_recovery_gate_and_write_lock(managed_client, monkeypatch):
    client, root, pid = managed_client
    upload(client, pid, sources('A')); first = selected(client, pid)
    upload(client, pid, sources('B')); second = selected(client, pid)
    assert select(client, pid, first['id'], second['id']).status_code == 200
    observed = []
    original = VerificationRecovery.admission_allowed
    def admission(self, db):
        assert db.in_transaction
        assert source_history.selected_source_set_id(db, pid) == first['id']
        other = sqlite3.connect(root / 'fox.sqlite3', timeout=0)
        try:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                other.execute('BEGIN IMMEDIATE')
        finally:
            other.close()
        answer = original(self, db); observed.append(answer); return answer
    monkeypatch.setattr(VerificationRecovery, 'admission_allowed', admission)
    response = client.post(f'/api/projects/{pid}/runs', json=approvals(first['source_hash']))
    assert response.status_code == 202, response.text
    assert observed == [True]
    snapshot = json.loads((root / 'jobs' / response.json()['id'] / 'source-snapshot.json').read_bytes())
    assert snapshot['source_hash'] == first['source_hash']
    assert snapshot['inventory']['selected_source_set_id'] == first['id']
    assert {item['name']: item['text'] for item in snapshot['files']} == {name: raw.decode() for name, raw in sources('A')}
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


def test_unresolved_qa_row_blocks_new_selected_source_without_creating_job(managed_client):
    client, root, pid = managed_client
    first = upload(client, pid, sources('A'))
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', ('fox-' + '1' * 20, pid,
            first['source_hash'], 'QA_REQUIRED', 'Synthetic unresolved verification only.', 1, 1, None))
    second = upload(client, pid, sources('B'))
    response = client.post(f'/api/projects/{pid}/runs', json=approvals(second['source_hash']))
    assert response.status_code == 429
    assert not (root / 'jobs').exists()
    assert selected(client, pid)['source_hash'] == second['source_hash']


def test_changed_or_missing_recovery_schema_fails_closed_without_erasing_selected_history(managed_client):
    client, root, pid = managed_client
    uploaded = upload(client, pid, sources('A'))
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('DROP TABLE verification_queue')
    response = client.post(f'/api/projects/{pid}/runs', json=approvals(uploaded['source_hash']))
    assert response.status_code == 429
    assert selected(client, pid)['source_hash'] == uploaded['source_hash']
    assert not (root / 'jobs').exists()
