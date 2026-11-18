"""Six-focus retained prose continuation: local API/SQLite/worker, fake SDK only."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

from fox import prototype_provider_reexecution as repeat
from fox.oci_genai import OciGenAiClient
from fox.opaf import canonical_hash
from fox.prototype_chunk_evidence import POLICY as V1
from fox.prototype_reference_echo import POLICY as V2
from fox.prototype_prose_segments import POLICY as V3
from test_development_reference_flow import (
    configured, runtime as reference_runtime, tmp_path, process, requests,
    assert_download, tree_bytes, queued_case)
from test_development_followup_flow import runtime as followup_runtime, endpoint, unchanged
from test_provider_reexecution_flow import (
    runtime as reexecution_runtime, unknown as original_unknown, attempt_url, attempt_body)
from test_development_intake_routes import settings
from test_source_history_api import (
    client, no_external_actions, settings as base_settings, login, ORIGIN, new_project)

LONG_PROPOSAL = ('Proposal text retained exactly for independent business review. ' * 12)[:604]
assert len(LONG_PROPOSAL) == 604


@pytest.fixture
def runtime(reexecution_runtime, monkeypatch):
    import test_development_intake_routes as intake
    original_pair = intake.pair
    extra = (b'<Block Name="SIXTH" DatabaseBlock="false"><Item Name="SIXTH_VALUE" ItemType="Text Item"/>'
             b'<Trigger Name="SIXTH_SAVE" TriggerText="BEGIN APP.SIXTH_SAVE(6); END;"/></Block>')
    monkeypatch.setattr(intake, 'pair', lambda code: {
        k: v.replace(b'</FormModule>', extra + b'</FormModule>') for k, v in original_pair(code).items()})
    service = reexecution_runtime
    original_alter = service.alter
    def long_fifth(body):
        original_alter(body)
        request = requests(service)[-1]
        if 'candidate' in request:
            return
        mapper_ids = list(dict.fromkeys(r['focus_id'] for r in requests(service) if 'candidate' not in r))
        if len(mapper_ids) >= 5 and request['focus_id'] == mapper_ids[4]:
            part = body['chat_response']['choices'][0]['message']['content'][0]
            output = json.loads(part['text'])
            assert len(output['blueprint']['claims']) == 1
            output['blueprint']['claims'][0]['value'] = LONG_PROPOSAL
            output['source_binding'] = request['source_binding']
            part['text'] = json.dumps(output)
    service.alter = long_fifth
    return service


def prose_url(case):
    return endpoint(case[2], case[3], 'development-prose-continuation')


def prose_body(case):
    response = case[0].get(prose_url(case))
    assert response.status_code == 200, response.text
    value = response.json()
    assert value['eligible'] and value['represented_claims'] == 1
    assert value['repeated_mapper_calls'] == 0 and value['business_behavior_accepted'] is False
    assert LONG_PROPOSAL not in response.text
    return {'plan_sha256': value['plan_sha256'], 'approved_lossless_prose_representation': True}


@pytest.fixture
def stopped(original_unknown, runtime):
    c, root, pid, rid, snapshot = original_unknown
    response = c.post(attempt_url(original_unknown), json=attempt_body(original_unknown))
    assert response.status_code == 202, response.text
    assert len(runtime.calls) == 8
    assert process(root)['state'] == 'ATTENTION', runtime.failures
    assert len(runtime.calls) == 10
    job = root / 'jobs' / rid
    assert len(list(job.rglob('reviewer.json'))) == 4
    mapper_ids = list(dict.fromkeys(r['focus_id'] for r in requests(runtime) if 'candidate' not in r))
    assert len(mapper_ids) == 5
    pivot = job / 'prototype-pipeline' / mapper_ids[4]
    raw = json.loads((pivot / 'mapper.json').read_bytes())['output']
    assert raw['source_binding'] == snapshot['prototype']['source_binding']
    assert raw['blueprint']['claims'][0]['value'] == LONG_PROPOSAL
    assert not (pivot / 'reviewer-intent.json').exists()
    assert len(list(repeat.paths(job)['receipts'].glob('*.response.json'))) == 3
    print('G5 retained fifth mapper: 10 attempts, 4 approved prefix reviews, 3 captured replies')
    return c, root, pid, rid, snapshot


def assert_represented(review_request):
    value = review_request['candidate']['blueprint']['claims'][0]['value']
    assert type(value) is list and 2 <= len(value) <= 4
    assert all(type(part) is str and 0 < len(part) <= 512 for part in value)
    assert ''.join(value) == LONG_PROPOSAL
    assert hashlib.sha256(''.join(value).encode()).hexdigest() == hashlib.sha256(LONG_PROPOSAL.encode()).hexdigest()
    assert review_request['review_context']['raw_candidate']['blueprint']['claims'][0]['value'] == LONG_PROPOSAL
    assert 'source_binding' not in review_request['candidate']


def test_same_run_lossless_prose_review_and_last_pair_preserve_all_prior_evidence(stopped, runtime, monkeypatch):
    from fox import prototype_prose_continuation as prose
    c, root, pid, rid, snapshot = stopped
    job = root / 'jobs' / rid
    before = tree_bytes(job)
    paths = repeat.paths(job)
    ledger_before, receipts_before = tree_bytes(paths['ledger']), tree_bytes(paths['receipts'])
    pivot = requests(runtime)[-1]['focus_id']
    def forbidden(*args, **kwargs):
        pytest.fail('Read-only continuation/output must not authenticate, create or sync.')
    with monkeypatch.context() as read_patch:
        read_patch.setattr(Path, 'mkdir', forbidden)
        read_patch.setattr(os, 'fsync', forbidden)
        read_patch.setattr(OciGenAiClient, '_client', forbidden)
        body = prose_body(stopped)
    assert tree_bytes(job) == before and len(runtime.calls) == 10
    assert not prose.path(job).exists()
    response = c.post(prose_url(stopped), json=body)
    assert response.status_code == 202, response.text
    assert response.json()['state'] == 'QUEUED'
    assert len(runtime.calls) == 10 and not prose.path(job).is_relative_to(job)
    authority_raw = prose.path(job).read_bytes()
    assert LONG_PROPOSAL not in authority_raw.decode()
    print('G5 explicit prose continuation admitted without provider call')
    assert process(root)['state'] == 'GENERATED', runtime.failures
    print('G5 worker GENERATED after 13 attempts')
    calls = requests(runtime)
    assert len(calls) == 13
    assert calls[10]['request']['focus_id'] == pivot and 'candidate' in calls[10]
    assert_represented(calls[10])
    mapper_ids = [r['focus_id'] for r in calls if 'candidate' not in r]
    assert len(mapper_ids) == 7 and len(set(mapper_ids)) == 6
    assert mapper_ids.count(runtime.pivot) == 2
    assert all(mapper_ids.count(fid) == 1 for fid in set(mapper_ids) - {runtime.pivot})
    assert len([r for r in calls if 'candidate' in r]) == 6
    unchanged(job, before)
    unchanged(paths['receipts'], receipts_before)
    assert tree_bytes(paths['ledger']) == ledger_before
    assert prose.path(job).read_bytes() == authority_raw
    index = json.loads((job / 'prototype-pipeline/review-index.json').read_bytes())
    assert index['schema_version'] == 8
    assert index['reference_policy_chain'] == [
        {'start_index': 0, 'policy': V1}, {'start_index': 2, 'policy': V2}, {'start_index': 4, 'policy': V3}]
    assert index['provider_attempt_lineage']['historical_outcome'] == 'unknown'
    assert index['provider_attempt_lineage']['new_attempt_adopted'] is True
    assert index['prose_representation_lineage']
    assert len(list(paths['receipts'].glob('*.response.json'))) == 6
    output = assert_download(c, root, pid, rid)
    print('G5 package output and download validated')
    sealed = tree_bytes(job)
    duplicate = c.post(prose_url(stopped), json=body)
    assert duplicate.status_code == 202, duplicate.text
    assert duplicate.json()['already_recorded'] and duplicate.json()['state'] == 'GENERATED'
    assert len(runtime.calls) == 13 and tree_bytes(job) == sealed
    # Construct another application against the retained DB/files (worker disabled).
    from fox.app import create_app
    with monkeypatch.context() as read_patch:
        read_patch.setattr(OciGenAiClient, '_client', forbidden)
        with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as restarted:
            login(restarted)
            assert_download(restarted, root, pid, rid)
            assert restarted.get(output['download_path']).status_code == 200
    assert tree_bytes(job) == sealed and len(runtime.calls) == 13
    return_value = c.get(prose_url(stopped))
    assert return_value.status_code == 200 and return_value.json()['continuation_recorded']
    print('G5 duplicate and restart reconstruction validated')
    for path in (prose.path(job), job / 'prototype-pipeline' / pivot / 'mapper.json',
                 next(paths['receipts'].glob('*.response.json'))):
        original = path.read_bytes()
        path.write_text('{}')
        assert c.get(endpoint(pid, rid, 'output')).status_code == 409, path
        assert c.get(endpoint(pid, rid, 'download')).status_code == 409, path
        path.write_bytes(original)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        event = db.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (prose.EVENT,)).fetchone()
        db.execute('DELETE FROM events WHERE action=?', (prose.EVENT,))
    assert c.get(endpoint(pid, rid, 'output')).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    assert_download(c, root, pid, rid)
    assert len(runtime.calls) == 13 and tree_bytes(job) == sealed
    print('G5 tamper/event rejection and exact restoration validated')


def test_exact_prose_admission_rejects_stale_missing_or_changed_authority(stopped, configured, runtime):
    from fox import prototype_prose_continuation as prose
    c, root, pid, rid, snapshot = stopped
    job = root / 'jobs' / rid
    body = prose_body(stopped)
    before = tree_bytes(job)
    for invalid in ({'plan_sha256': body['plan_sha256']},
                    {**body, 'approved_lossless_prose_representation': False},
                    {**body, 'approved_lossless_prose_representation': 1},
                    {**body, 'plan_sha256': 'f' * 64}):
        assert c.post(prose_url(stopped), json=invalid).status_code in (409, 422)
    original_target = configured['profile_id']
    configured['profile_id'] += '-changed'
    assert c.post(prose_url(stopped), json=body).status_code == 409
    configured['profile_id'] = original_target
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        owner = db.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()[0]
        db.execute('UPDATE projects SET owner=? WHERE id=?', ('synthetic-other', pid))
    assert c.post(prose_url(stopped), json=body).status_code == 404
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE projects SET owner=? WHERE id=?', (owner, pid))
        db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
    assert c.post(prose_url(stopped), json=body).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE project_source_selection SET current_source_set_id=? WHERE project=?',
                   (snapshot['selected_source_set_id'], pid))
        event = db.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (repeat.ADOPTION_EVENT,)).fetchone()
        db.execute('DELETE FROM events WHERE action=?', (repeat.ADOPTION_EVENT,))
    assert c.get(prose_url(stopped)).status_code == 409
    assert c.post(prose_url(stopped), json=body).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
    receipt = next(repeat.paths(job)['receipts'].glob('*.response.json'))
    original = receipt.read_bytes()
    receipt.write_text('{}')
    assert c.post(prose_url(stopped), json=body).status_code == 409
    receipt.write_bytes(original)
    other = new_project(c)
    assert c.post(endpoint(other, rid, 'development-prose-continuation'), json=body).status_code == 404
    assert not prose.path(job).exists()
    unchanged(job, before)
    assert len(runtime.calls) == 10
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'


def test_explicit_fresh_v3_uses_lossless_prose_without_old_recovery(client, configured, runtime, monkeypatch):
    from fox import prototype_project_routes as routes
    # Explicit synthetic V3 admission; this does not change the product default.
    monkeypatch.setattr(routes, 'CHUNK_EVIDENCE_POLICY', V3)
    runtime.pivot = 'fresh-has-no-prior-unknown'
    c, root, pid, rid, snapshot = queued_case(client)
    assert snapshot['prototype']['chunk_evidence_policy'] == V3
    assert process(root)['state'] == 'GENERATED', runtime.failures
    assert len(runtime.calls) == 12
    calls = requests(runtime)
    reviewers = [r for r in calls if 'candidate' in r]
    assert len(reviewers) == 6
    assert_represented(reviewers[4])
    index = json.loads((root / 'jobs' / rid / 'prototype-pipeline/review-index.json').read_bytes())
    assert index['schema_version'] == 8
    assert index['reference_policy_chain'] == [{'start_index': 0, 'policy': V3}]
    assert 'provider_attempt_lineage' not in index
    assert_download(c, root, pid, rid)
    assert not repeat.paths(root / 'jobs' / rid)['authority'].exists()
