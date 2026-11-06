"""Authenticated local HTTP checks; synthetic native output, no Oracle/AI calls."""
import json
import sqlite3

import pytest

from fox.hosted_forms_jobs import HostedFormsJobs
from fox.native_preparation import prepare_native_source
from test_native_preparation import factory
from test_source_history_api import (client, no_external_actions, settings as base_settings,
                                    upload, sources, new_project, selected, select)


@pytest.fixture
def settings(base_settings, monkeypatch, tmp_path):
    monkeypatch.setenv('FOX_HOSTED_FORMS_QUEUE', str(tmp_path / 'native-queue'))
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')


def submit(c, pid, *, jid='native-test-1', selected='null', name='synthetic.fmb', raw=b'SYNTHETIC_NOT_REAL_FMB'):
    return c.post(f'/api/projects/{pid}/native-preparations',
                  data={'request_id': jid, 'expected_current_source_set_id': selected},
                  files={'file': (name, raw)})


def process(root, jid='native-test-1'):
    q = HostedFormsJobs(root.parent / 'native-queue')
    return q.process(jid, prepare=lambda source, output, **kw:
                     prepare_native_source(source, output, backend_factory=factory(), **kw))


def test_raw_preparation_is_separate_then_adopts_once(client):
    c, root, pid = client
    listing = c.get(f'/api/projects/{pid}/native-preparations').json()
    assert listing['enabled'] and listing['jobs'] == []
    first = submit(c, pid)
    assert first.status_code == 202, first.text
    assert submit(c, pid).json() == first.json()
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
    path = f'/api/projects/{pid}/native-preparations/native-test-1'
    assert c.post(path + '/adopt').status_code == 409
    assert process(root)['status'] == 'PREPARED_REDACTED_REVIEW_REQUIRED'
    result = c.post(path + '/adopt')
    assert result.status_code == 200, result.text
    assert result.json()['adopted'] and not result.json()['processing_approved']
    assert c.post(path + '/adopt').json()['already_adopted'] is True
    assert c.get(f'/api/projects/{pid}/prototype-assessment').status_code == 200
    detail = c.get(f'/api/projects/{pid}')
    assert detail.status_code == 200, detail.text
    assert detail.json()['inventory']['project_assessment']['source_checks_passed'] is False
    assert detail.json()['project_capabilities']['process']['enabled'] is False
    assert c.get(f'/api/projects/{pid}/source-sets').status_code == 200
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM source_redaction_receipts').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='native_preparation_adopted'").fetchone()[0] == 1
    text = c.get(path).text
    assert 'SYNTHETIC_NOT_REAL_FMB' not in text and 'INSERT INTO' not in text
    assert str(root) not in text


def test_other_project_cannot_read_or_adopt_job(client):
    c, root, pid = client
    assert submit(c, pid).status_code == 202
    process(root)
    other = new_project(c)
    path = f'/api/projects/{other}/native-preparations/native-test-1'
    assert c.get(path).status_code == 404
    assert c.post(path + '/adopt').status_code == 404
    assert c.get(f'/api/projects/{other}/native-preparations').json()['jobs'] == []


def test_changed_project_sources_block_adoption_without_overwrite(client):
    c, root, pid = client
    assert submit(c, pid).status_code == 202
    process(root)
    upload(c, pid, sources())
    assert c.post(f'/api/projects/{pid}/native-preparations/native-test-1/adopt').status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM source_redaction_receipts').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 2


def test_unknown_processing_not_replayed(client):
    c, root, pid = client
    assert submit(c, pid).status_code == 202
    q = HostedFormsJobs(root.parent / 'native-queue')
    calls = []
    def fail(*args, **kwargs):
        calls.append(1)
        raise RuntimeError('PRIVATE_NATIVE_DIAGNOSTIC')
    first = q.process('native-test-1', prepare=fail)
    try:
        q.process('native-test-1', prepare=fail)
    except ValueError:
        pass
    assert calls == [1]
    response = c.get(f'/api/projects/{pid}/native-preparations/native-test-1')
    assert response.status_code == 200
    assert 'PRIVATE_NATIVE_DIAGNOSTIC' not in response.text
    assert c.post(f'/api/projects/{pid}/native-preparations/native-test-1/adopt').status_code == 409


@pytest.mark.parametrize('name', ['../bad.fmb', 'other.pll', 'source.xml', 'archive.zip'])
def test_initial_single_fmb_scope_is_explicit(client, name):
    c, root, pid = client
    assert submit(c, pid, name=name).status_code == 422
    assert c.get(f'/api/projects/{pid}/native-preparations').json()['jobs'] == []


def test_request_id_conflict_and_stale_selection(client):
    c, root, pid = client
    assert submit(c, pid).status_code == 202
    assert submit(c, pid, raw=b'DIFFERENT_SYNTHETIC').status_code == 503
    assert submit(c, pid, jid='second', selected='ss-' + 'a' * 32).status_code == 409


def test_requires_session(client):
    c, root, pid = client
    c.cookies.clear()
    assert c.get(f'/api/projects/{pid}/native-preparations').status_code == 401
    assert submit(c, pid).status_code == 401


def test_ambiguous_postwrite_submission_does_not_claim_rejection(client, monkeypatch):
    c, root, pid = client
    original = HostedFormsJobs.submit
    def accepted_then_error(self, **kwargs):
        original(self, **kwargs)
        raise OSError('Simulated lost response after ready marker.')
    monkeypatch.setattr(HostedFormsJobs, 'submit', accepted_then_error)
    assert submit(c, pid).status_code == 503
    result = c.get(f'/api/projects/{pid}/native-preparations/native-test-1')
    assert result.status_code == 200 and result.json()['status'] == 'QUEUED'


def test_adopted_job_does_not_falsely_add_to_reselected_old_version(client):
    c, root, pid = client
    upload(c, pid, sources())
    before = selected(c, pid)['id']
    assert submit(c, pid, selected=before).status_code == 202
    process(root)
    path = f'/api/projects/{pid}/native-preparations/native-test-1/adopt'
    adopted = c.post(path)
    assert adopted.status_code == 200
    after = adopted.json()['selected_source_set_id']
    assert select(c, pid, before, after).status_code == 200
    historical = c.post(path)
    assert historical.status_code == 409
    assert 'different saved source version' in historical.json()['detail']
    assert selected(c, pid)['id'] == before
