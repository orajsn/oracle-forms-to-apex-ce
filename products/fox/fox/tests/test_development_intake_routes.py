"""Actual local HTTP/SQLite acceptance with synthetic native bytes only."""
import hashlib
import json
import sqlite3

import pytest

from fox import development_source as dev, source_history
from fox.hosted_forms_jobs import HostedFormsJobs
from fox.native_preparation import prepare_native_source
from fox.forms_effective_view import derive_effective_view
from test_native_preparation import factory, pair
from test_source_history_api import client, no_external_actions, settings as base_settings, new_project, upload


@pytest.fixture
def settings(base_settings, monkeypatch, tmp_path):
    monkeypatch.setenv('FOX_HOSTED_FORMS_QUEUE', str(tmp_path / 'native-queue'))
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')


def prepare(c, root, pid, *, code="BEGIN INSERT INTO AUDIT_LOG VALUES ('APPROVED', 123.45); END;", jid='dev-http'):
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        selected = source_history.selected_source_set_id(db, pid)
    response = c.post(f'/api/projects/{pid}/native-preparations',
                      data={'request_id': jid, 'expected_current_source_set_id': selected or 'null', 'preparation_mode': dev.MODE},
                      files={'file': ('synthetic.fmb', b'SYNTHETIC_NOT_REAL_FMB')})
    assert response.status_code == 202, response.text
    queue = HostedFormsJobs(root.parent / 'native-queue')
    state = queue.process(jid, prepare=lambda source, output, **kw:
                          prepare_native_source(source, output, backend_factory=factory(pair(code)), **kw))
    return queue, state, f'/api/projects/{pid}/native-preparations/{jid}'


def test_clean_preservation_http_adoption_history_and_no_processing(client):
    c, root, pid = client
    assert dev.MODE in c.get(f'/api/projects/{pid}/native-preparations').json()['preparation_modes']
    queue, state, url = prepare(c, root, pid)
    assert state['status'] == dev.PREPARED
    for variant in ('overridden', 'all', 'effective'):
        response = c.get(url + '/source/' + variant)
        assert response.status_code == 200, response.text
        assert response.headers['cache-control'] == 'no-store'
        assert response.headers['x-content-type-options'] == 'nosniff'
        assert response.headers['content-disposition'].startswith('attachment;')
        if variant != 'effective':
            assert response.content == pair("BEGIN INSERT INTO AUDIT_LOG VALUES ('APPROVED', 123.45); END;")[variant.upper()]
    adopted = c.post(url + '/adopt')
    assert adopted.status_code == 200, adopted.text
    assert adopted.json()['adopted'] and adopted.json()['processing_approved'] is False
    assert c.post(url + '/adopt').json()['already_adopted']
    history = c.get(f'/api/projects/{pid}/source-sets')
    assert history.status_code == 200, history.text
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        selected = source_history.selected_sources(db, pid)
        assert source_history.development_source_present(db, pid, selected)
        assert len(selected) == 1 and '123.45' in selected[0]['text'] and 'APPROVED' in selected[0]['text']
        receipt = json.loads(db.execute('SELECT receipt_json FROM source_redaction_receipts WHERE project=?', (pid,)).fetchone()[0])
        assert receipt['policy_id'] == dev.POLICY_ID
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


def test_possible_credential_metadata_safe_adoption_blocked_download_owner_only(client):
    c, root, pid = client
    code = "BEGIN password := 'SYNTHETIC_CREDENTIAL'; END;"
    queue, state, url = prepare(c, root, pid, code=code)
    assert state['status'] == dev.CREDENTIAL_REVIEW
    assert c.post(url + '/adopt').status_code == 409
    status = c.get(url)
    assert status.status_code == 200
    assert 'SYNTHETIC_CREDENTIAL' not in status.text and str(root) not in status.text
    assert c.get(url + '/source/overridden').content == pair(code)['OVERRIDDEN']
    assert c.get(url + '/source/effective').status_code == 404
    other = new_project(c)
    assert c.get(f'/api/projects/{other}/native-preparations/dev-http/source/overridden').status_code == 404
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0


def test_unknown_mode_rejected_before_queue_write(client):
    c, root, pid = client
    response = c.post(f'/api/projects/{pid}/native-preparations',
                      data={'request_id': 'bad-mode', 'expected_current_source_set_id': 'null', 'preparation_mode': 'unknown'},
                      files={'file': ('synthetic.fmb', b'SYNTHETIC_NOT_REAL_FMB')})
    assert response.status_code == 422
    assert not (root.parent / 'native-queue/bad-mode').exists()


@pytest.mark.parametrize('tamper', ['policy', 'owner', 'bytes'])
def test_history_revalidates_retained_policy_even_for_ordinary_safe_xml(client, tamper):
    c, root, pid = client
    queue, state, url = prepare(c, root, pid, code='BEGIN NULL; END;')
    assert c.post(url + '/adopt').status_code == 200
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        source = source_history.selected_sources(db, pid)[0]
        if tamper == 'bytes':
            source['text'] += ' '
        else:
            # Explicit synthetic corruption: immutable triggers protect ordinary
            # writes. Recompute hash so this tests policy, not only receipt SHA.
            db.execute('DROP TRIGGER source_redaction_receipts_no_update')
            row = db.execute('SELECT receipt_json FROM source_redaction_receipts WHERE project=?', (pid,)).fetchone()
            receipt = json.loads(row[0])
            if tamper == 'policy':
                receipt['policy_id'] = 'forged'
            canonical = json.dumps(receipt, sort_keys=True, separators=(',', ':'))
            owner = db.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()[0]
            db.execute('UPDATE source_redaction_receipts SET receipt_json=?,receipt_sha256=?,owner=? WHERE project=?',
                       (canonical, hashlib.sha256(canonical.encode()).hexdigest(), 'other' if tamper == 'owner' else owner, pid))
        with pytest.raises(ValueError):
            source_history._checked(source, db, pid)


def test_existing_ordinary_same_bytes_cannot_be_retagged_by_adoption(client):
    c, root, pid = client
    code = 'BEGIN NULL; END;'
    outputs = pair(code)
    derived = derive_effective_view('synthetic_fmb.xml', outputs['OVERRIDDEN'], outputs['ALL'],
                                    binary_sha256=hashlib.sha256(b'SYNTHETIC_NOT_REAL_FMB').hexdigest())['derived_xml']
    upload(c, pid, [('synthetic_fmb.xml', derived)])
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        selected_before = source_history.selected_source_set_id(db, pid)
        assert not source_history.development_source_present(db, pid, source_history.selected_sources(db, pid))
    queue, state, url = prepare(c, root, pid, code=code)
    assert state['status'] == dev.PREPARED
    conflict = c.post(url + '/adopt')
    assert conflict.status_code == 409 and 'compatible preservation provenance' in conflict.text
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        assert source_history.selected_source_set_id(db, pid) == selected_before
        assert db.execute('SELECT COUNT(*) FROM source_redaction_receipts').fetchone()[0] == 0
        assert not source_history.development_source_present(db, pid, source_history.selected_sources(db, pid))
