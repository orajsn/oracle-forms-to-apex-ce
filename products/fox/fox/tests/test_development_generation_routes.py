"""Actual isolated HTTP/SQLite development consent; no external executor."""
from copy import deepcopy
import json
import sqlite3

import pytest

from fox import source_history
from fox.prototype_job import validate_prototype_snapshot
from fox.source_processing_policy import DEVELOPMENT_EVENT, current_processing_approval
from test_development_intake_routes import prepare, settings
from test_source_history_api import (client, no_external_actions, settings as base_settings,
    new_project, upload, job_files, database_rows)
from test_prototype_project_routes import configured


def development_case(client):
    c, root, pid = client
    _, _, url = prepare(c, root, pid)
    assert c.post(url + '/adopt').status_code == 200
    response = c.get(f'/api/projects/{pid}/prototype-assessment')
    assert response.status_code == 200, response.text
    assessment = response.json()
    assert assessment['processing_mode'] == 'development'
    assert assessment['source_processing_allowed'] is True
    body = {key: assessment[key] for key in ('source_hash', 'source_binding',
        'target_profile_sha256', 'processing_mode', 'development_processing_context_sha256')}
    body.update(expected_current_source_set_id=assessment['selected_source_set_id'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in assessment['chunks']},
        approved_redacted_source=False, approved_unredacted_development_source=True,
        approved_external_ai=True, approved_prototype_scope=True, delivery_mode='apexlang_package')
    assert body['approved_chunk_hashes'], 'Exercise exact executable code, not metadata only.'
    return c, root, pid, assessment, body


def queued_case(client):
    c, root, pid, assessment, body = development_case(client)
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    rid = response.json()['id']
    project = c.get(f'/api/projects/{pid}')
    assert project.status_code == 200, project.text
    assert next(run for run in project.json()['runs'] if run['id'] == rid)['processing_mode'] == 'development'
    snapshot = json.loads((root / 'jobs' / rid / 'source-snapshot.json').read_bytes())
    return c, root, pid, rid, snapshot


def test_exact_development_source_queue_event_and_no_replay(client, configured):
    c, root, pid, rid, snapshot = queued_case(client)
    docs = validate_prototype_snapshot(snapshot)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        sources = source_history.selected_sources(db, pid)
        assert docs == [(row['name'], source_history.readable_source_bytes(row)) for row in sources]
        assert current_processing_approval(db, snapshot, rid, sources) is True
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
        event = db.execute('SELECT * FROM events WHERE action=?', (DEVELOPMENT_EVENT,)).fetchone()
        assert event['object_id'] == rid and event['created'] == snapshot['approvals']['approved_at']
    assert b'123.45' in docs[0][1] and b'APPROVED' in docs[0][1]
    assert snapshot['approvals']['redacted_source'] is False
    assert snapshot['approvals']['unredacted_development_source'] is True
    before = job_files(root)
    # Reconstruct the exact consent from immutable snapshot, never retry the provider.
    _, _, _, assessment, body = development_case_existing(c, root, pid)
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 409
    assert job_files(root) == before


def development_case_existing(c, root, pid):
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment').json()
    body = {key: assessment[key] for key in ('source_hash', 'source_binding',
        'target_profile_sha256', 'processing_mode', 'development_processing_context_sha256')}
    body.update(expected_current_source_set_id=assessment['selected_source_set_id'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in assessment['chunks']},
        approved_redacted_source=False, approved_unredacted_development_source=True,
        approved_external_ai=True, approved_prototype_scope=True, delivery_mode='apexlang_package')
    return c, root, pid, assessment, body


@pytest.mark.parametrize('mutation', ['legacy', 'digest', 'source-version', 'source-hash',
    'destination', 'mode', 'chunks', 'missing-consent', 'external', 'scope', 'delivery'])
def test_changed_or_missing_consent_never_queues(client, configured, mutation):
    c, root, pid, _, body = development_case(client)
    if mutation == 'legacy':
        for key in ('processing_mode', 'development_processing_context_sha256', 'approved_unredacted_development_source'):
            body.pop(key)
        body['approved_redacted_source'] = True
    elif mutation == 'digest': body['development_processing_context_sha256'] = 'f' * 64
    elif mutation == 'source-version': body['expected_current_source_set_id'] = 'ss-' + 'f' * 32
    elif mutation == 'source-hash': body['source_hash'] = 'f' * 64
    elif mutation == 'destination': body['target_profile_sha256'] = 'f' * 64
    elif mutation == 'mode': body['processing_mode'] = 'unknown'
    elif mutation == 'chunks': body['approved_chunk_hashes'][next(iter(body['approved_chunk_hashes']))] = 'f' * 64
    elif mutation == 'missing-consent': body.pop('approved_unredacted_development_source')
    elif mutation == 'external': body['approved_external_ai'] = False
    elif mutation == 'scope': body['approved_prototype_scope'] = False
    else: body.pop('delivery_mode')
    before = database_rows(root, 'events')
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code in (409, 422), response.text
    assert database_rows(root, 'runs') == [] and job_files(root) == {}
    assert database_rows(root, 'events') == before


@pytest.mark.parametrize('mutation', ['event-delete', 'event-owner', 'event-time', 'event-action',
    'provenance', 'strip-markers'])
def test_current_processing_approval_rejects_retained_mutations(client, configured, mutation):
    _, root, pid, rid, snapshot = queued_case(client)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        sources = source_history.selected_sources(db, pid)
        assert current_processing_approval(db, snapshot, rid, sources)
        if mutation == 'event-delete': db.execute('DELETE FROM events WHERE object_id=?', (rid,))
        elif mutation.startswith('event-'):
            column, value = {'event-owner': ('owner', 'other'), 'event-time': ('created', 0),
                'event-action': ('action', 'approved_prototype_conversion')}[mutation]
            db.execute(f'UPDATE events SET {column}=? WHERE object_id=?', (value, rid))
        elif mutation == 'provenance':
            snapshot['prototype']['development_processing']['source_provenance'][0]['receipt_sha256'] = 'f' * 64
        else:
            for key in ('processing_mode', 'development_processing', 'development_processing_sha256'):
                snapshot['prototype'].pop(key)
            snapshot['approvals'].pop('unredacted_development_source')
            snapshot['approvals']['redacted_source'] = True
        assert current_processing_approval(db, snapshot, rid, sources) is False


def test_legacy_recovery_and_cross_project_reads_reject_before_writes(client, configured):
    c, root, pid, rid, _ = queued_case(client)
    before, events, runs = job_files(root), database_rows(root, 'events'), database_rows(root, 'runs')
    for route in ('mapping-recovery', 'mapping-continuation', 'mapping-epochs/next',
        'validate-preclaim-continuation', 'redacted-query-omission', 'candidate-format-continuation',
        'dsc-identity-repair', 'review-correction', 'saved-package/readiness', 'saved-package/output', 'saved-package/download'):
        response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/{route}')
        assert response.status_code == 409, (route, response.text)
    for route in ('retry-mapping', 'continue-mapping', 'mapping-epochs', 'saved-package'):
        response = c.post(f'/api/projects/{pid}/prototype-runs/{rid}/{route}', json={
            'approved_redacted_source': True, 'approved_external_ai': True, 'approved_prototype_scope': True,
            'preparation_binding_sha256': 'a' * 64, 'approved_format_only_delivery': True})
        assert response.status_code in (409, 422), (route, response.text)
    other = new_project(c)
    for route in ('progress', 'output', 'download'):
        assert c.get(f'/api/projects/{other}/prototype-runs/{rid}/{route}').status_code == 404
    assert job_files(root) == before and database_rows(root, 'runs') == runs
    assert [row for row in database_rows(root, 'events') if row[3] != other] == events


def test_retained_development_progress_does_not_reconstruct_current_sources(client, configured, monkeypatch):
    c, root, pid, rid, _ = queued_case(client)
    def forbidden(*args, **kwargs):
        pytest.fail('Progress must not reconstruct current source provenance')
    monkeypatch.setattr(source_history, 'development_source_present', forbidden)
    monkeypatch.setattr(source_history, 'selected_sources', forbidden)
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/progress')
    assert response.status_code == 200, response.text
