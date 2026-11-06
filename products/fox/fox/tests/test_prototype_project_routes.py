"""Real isolated authenticated API/storage tests; no provider or Oracle calls."""
import json
import sqlite3

import pytest

from test_source_history_api import client, settings, no_external_actions, upload
from test_prototype_admission import documents


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', 'synthetic-profile-not-opened')
    monkeypatch.setattr('fox.prototype_job.load_prototype_profile',
                        lambda path: {'target_profile_sha256': 'a' * 64})


def prepare(client):
    c, root, pid = client
    upload(c, pid, documents())
    response = c.get(f'/api/projects/{pid}/prototype-assessment')
    assert response.status_code == 200, response.text
    assessment = response.json()
    body = {key: assessment[key] for key in ('source_hash', 'source_binding', 'target_profile_sha256')}
    body.update(expected_current_source_set_id=assessment['selected_source_set_id'],
                approved_chunk_hashes={row['id']: row['sha256'] for row in assessment['chunks']},
                approved_redacted_source=True, approved_external_ai=True, approved_prototype_scope=True)
    return c, root, pid, assessment, body


def test_authenticated_sources_queue_exact_prototype(client, configured):
    c, root, pid, assessment, body = prepare(client)
    assert assessment['conversion_configured'] is True
    assert assessment['processing_approved'] is False
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    snapshot = json.loads((root/'jobs'/response.json()['id']/'source-snapshot.json').read_bytes())
    assert snapshot['conversion_profile'] == 'native-blueprint-prototype-v1'
    assert snapshot['files'][0]['text'].encode() == documents()[0][1]
    assert snapshot['prototype']['source_binding'] == assessment['source_binding']
    assert snapshot['approvals']['synthetic_prototype'] is True
    from fox.prototype_job import validate_prototype_snapshot
    assert validate_prototype_snapshot(snapshot) == documents()
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs').fetchone()[0] == 'QUEUED'
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


@pytest.mark.parametrize('key,value', [('source_binding','b'*64), ('source_hash','b'*64),
    ('expected_current_source_set_id','ss-'+'b'*32), ('target_profile_sha256','b'*64),
    ('approved_external_ai',False), ('approved_redacted_source',False), ('approved_prototype_scope',False)])
def test_stale_or_unapproved_never_queues(client, configured, key, value):
    c, root, pid, _, body = prepare(client)
    body[key] = value
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 409
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0


def test_repeat_submission_never_replays(client, configured):
    c, root, pid, _, body = prepare(client)
    first = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert first.status_code == 202
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 409
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1


def test_unconfigured_keeps_assessment_and_blocks_queue(client, monkeypatch):
    monkeypatch.delenv('FOX_PROTOTYPE_PROFILE_FILE', raising=False)
    c, root, pid, assessment, body = prepare(client)
    assert assessment['conversion_configured'] is False
    body['target_profile_sha256'] = 'a'*64
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 503


def test_owner_boundary(client, configured):
    c, root, pid, _, body = prepare(client)
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('other', 'other-owner', 'Test','Private','',1))
    assert c.get('/api/projects/other/prototype-assessment').status_code == 404
    assert c.post('/api/projects/other/prototype-runs', json=body).status_code == 404


def test_no_consent_coercion(client, configured):
    c, _, pid, _, body = prepare(client)
    body['approved_external_ai'] = 1
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 422


def redacted_upload():
    from fox.forms_redaction import redact_forms_xml
    original = b'<FormModule Name="DEMO"><Block Name="MAIN" DatabaseBlock="true"><Trigger Name="SAVE" TriggerText="BEGIN INSERT INTO EXAMPLE (VALUE) VALUES (123456); END;"/></Block></FormModule>'
    return redact_forms_xml('demo.xml', original)


def post_redacted(c, pid, value, selected='null'):
    return c.post(f'/api/projects/{pid}/prototype-sources',
                  data={'expected_current_source_set_id': selected}, files=[
                      ('files', ('demo.xml', value['redacted_xml'])),
                      ('receipts', ('demo.xml.redaction.json', json.dumps(value['receipt']).encode()))])


def test_redacted_business_dml_has_explicit_intake_and_retained_history(client, configured):
    from fox import source_history
    c, root, pid = client
    value = redacted_upload()
    # Ordinary upload policy is unchanged, even for analysis-only DML.
    assert c.post(f'/api/projects/{pid}/sources', files=[('files',('demo.xml',value['redacted_xml']))]).status_code == 422
    response = post_redacted(c, pid, value)
    assert response.status_code == 200, response.text
    assert response.json()['processing_approved'] is False
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment')
    assert assessment.status_code == 200, assessment.text
    assert assessment.json()['code_unit_count'] == 1
    assert c.get(f'/api/projects/{pid}').status_code == 200
    with sqlite3.connect(root/'fox.sqlite3') as db:
        files = source_history.selected_sources(db, pid)
        assert source_history.readable_source_bytes(files[0]) == value['redacted_xml']
        assert db.execute('SELECT COUNT(*) FROM source_redaction_receipts').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        with pytest.raises(sqlite3.IntegrityError):
            db.execute('UPDATE source_redaction_receipts SET receipt_sha256=?', ('b'*64,))


def test_redacted_receipt_mismatch_rolls_back_source_and_provenance(client):
    c, root, pid = client
    value = redacted_upload()
    value['receipt']['redacted_sha256'] = 'b'*64
    assert post_redacted(c, pid, value).status_code == 422
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM source_redaction_receipts').fetchone()[0] == 0


def test_redacted_upload_requires_current_selection(client):
    c, root, pid = client
    value = redacted_upload()
    first = post_redacted(c, pid, value)
    assert first.status_code == 200
    assert post_redacted(c, pid, value).status_code == 409
    repeat = post_redacted(c, pid, value, first.json()['selected_source_set_id'])
    assert repeat.status_code == 200
    assert repeat.json()['changed'] is False
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 1


def test_redacted_source_history_revalidates_on_restart(client):
    from fox.app import create_app
    c, root, pid = client
    assert post_redacted(c, pid, redacted_upload()).status_code == 200
    # Real initialization rereads retained source history and provenance.
    restarted = create_app(root, enable_worker=False)
    assert restarted is not None
