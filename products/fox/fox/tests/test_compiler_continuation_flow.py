"""One actual local API/worker compile-only flow; retained fake-SDK history."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from fox import prototype_compiler_continuation as compiler
from fox import prototype_provider_reexecution as provider
from fox import prototype_prose_continuation as prose
from fox.oci_genai import OciGenAiClient
from fox.opaf import canonical_hash
from fox.prototype_job import validate_prototype_snapshot
from fox.prototype_admission import bound_focus_limit
from fox.forms_focus import build_focus_plan
from fox.forms_focus_merge import merge_focus_blueprints
from fox.prototype_item_screen_inheritance import project
from test_prototype_compiler_continuation import (
    reviewed, runtime, stopped, unknown, provider_runtime, followup_runtime,
    reference_runtime, prose_runtime, configured, client, no_external_actions,
    settings, base_settings, tmp_path, publish_session_seed)
from test_development_reference_flow import process, tree_bytes, assert_download
from test_development_followup_flow import endpoint, unchanged
from test_source_history_api import login, ORIGIN, new_project

@pytest.fixture
def seed(reviewed, pytestconfig, tmp_path_factory):
    metadata = publish_session_seed(reviewed, pytestconfig, tmp_path_factory)
    assert metadata['runtime_calls'] == len(reviewed[7].calls) == 13
    return reviewed


def compiler_url(pid, rid):
    return endpoint(pid, rid, 'development-compiler-continuation')


def test_compile_only_api_package_restart_and_rejections_preserve_all_reviews(seed, monkeypatch):
    c, root, pid, rid, snapshot, original, target, service = seed
    job, pipeline = root / 'jobs' / rid, root / 'jobs' / rid / 'prototype-pipeline'
    before = tree_bytes(job)
    assert len(before) == 82
    receipt_before = tree_bytes(provider.paths(job)['receipts'])
    assert len(receipt_before) == 12
    external = {kind: provider.paths(job)[kind].read_bytes() for kind in ('authority', 'consumed', 'adoption')}
    prose_before = prose.path(job).read_bytes()
    docs = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    focus = build_focus_plan(docs, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    originals, reviews = [], []
    for request in focus['requests']:
        directory = pipeline / request['focus_id']
        projection = directory / 'projection-candidate.json'
        candidate = json.loads(projection.read_bytes()) if projection.exists() else json.loads((directory / 'mapper.json').read_bytes())['output']
        review = json.loads((directory / 'reviewer.json').read_bytes())['output']
        assert review['candidate_sha256'] == canonical_hash(candidate)
        assert review['verdict'] == 'APPROVED'
        originals.append(candidate)
        reviews.append(review)
    expected, proof = project(docs, focus, originals)
    assert len(proof['changes']) == 2
    assert {row['focus_id'] for row in proof['changes']} == {focus['requests'][-1]['focus_id']}
    assert len({row['source_block_id'] for row in proof['changes']}) == 1
    for change in proof['changes']:
        assert 'screen_id' not in change['before']
        assert change['after'] == {**change['before'], 'screen_id': change['block_mapping']['screen_id']}
    expected_merge = merge_focus_blueprints(docs, focus, expected)
    assert [row['blueprint']['claims'] for row in originals] == [row['blueprint']['claims'] for row in expected]
    original_hashes = [canonical_hash(row) for row in originals]
    def no_provider(*args, **kwargs):
        pytest.fail('Compiler continuation must perform zero model/auth/runtime-focus operations.')
    for name in ('_client', 'invoke', 'invoke_prepared'):
        monkeypatch.setattr(OciGenAiClient, name, no_provider)
    monkeypatch.setattr(service, 'chat', no_provider)
    from fox import prototype_mapping_epochs as epochs
    original_focus = epochs.active_focus
    def read_only_focus(*args, **kwargs):
        if kwargs.get('runtime') is not None:
            no_provider()
        return original_focus(*args, **kwargs)
    monkeypatch.setattr(epochs, 'active_focus', read_only_focus)
    url = compiler_url(pid, rid)
    response = c.get(url)
    assert response.status_code == 200, response.text
    value = response.json()
    assert value['eligible'] and value['completed_item_links'] == 2 and value['new_model_calls'] == 0
    body = {'plan_sha256': value['plan_sha256'], 'approved_compiler_completion': True}
    assert not compiler.path(job).exists() and len(service.calls) == 13
    print('G6 read-only compiler plan has exactly two inherited links', flush=True)
    # Stale and missing authority rejects before creating any compiler record.
    for invalid in ({'plan_sha256': body['plan_sha256']},
                    {**body, 'approved_compiler_completion': False},
                    {**body, 'approved_compiler_completion': 1},
                    {**body, 'plan_sha256': 'f' * 64}):
        assert c.post(url, json=invalid).status_code in (409, 422)
    profile_id = target['profile_id']
    target['profile_id'] += '-changed'
    assert c.post(url, json=body).status_code == 409
    target['profile_id'] = profile_id
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        owner = db.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()[0]
        db.execute('UPDATE projects SET owner=? WHERE id=?', ('synthetic-other', pid))
    assert c.post(url, json=body).status_code == 404
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE projects SET owner=? WHERE id=?', (owner, pid))
        db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
    assert c.post(url, json=body).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE project_source_selection SET current_source_set_id=? WHERE project=?',
                   (snapshot['selected_source_set_id'], pid))
    for action in (prose.EVENT, provider.ADOPTION_EVENT):
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            event = db.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (action,)).fetchone()
            db.execute('DELETE FROM events WHERE action=?', (action,))
        assert c.get(url).status_code == 409
        assert c.post(url, json=body).status_code == 409
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
    saved = prose.path(job).read_bytes()
    prose.path(job).write_text('{}')
    assert c.post(url, json=body).status_code == 409
    prose.path(job).write_bytes(saved)
    store = provider.paths(job)['receipts']
    retained_store = store.with_name(store.name + '-retained')
    assert retained_store.is_relative_to(root) and not retained_store.exists()
    store.rename(retained_store)
    assert c.post(url, json=body).status_code == 409
    retained_store.rename(store)
    other = new_project(c)
    assert c.post(compiler_url(other, rid), json=body).status_code == 404
    assert not compiler.path(job).exists()
    assert len(service.calls) == 13
    unchanged(job, before)
    assert tree_bytes(store) == receipt_before
    print('G6 stale/missing owner-source-target-parent-event-record-store guards passed', flush=True)
    response = c.post(url, json=body)
    assert response.status_code == 202, response.text
    assert response.json()['state'] == 'QUEUED' and response.json()['new_model_calls'] == 0
    assert not compiler.path(job).is_relative_to(job)
    record_raw = compiler.path(job).read_bytes()
    record = json.loads(record_raw)
    assert record['plan_sha256'] == body['plan_sha256']
    assert record['plan']['original_candidate_sha256'] == original_hashes
    assert record['plan']['new_model_operations'] == 0
    assert record['plan']['remaining_operations'] == [{'stage': name} for name in ('render', 'offline_validate', 'package')]
    assert len(record['plan']['before_files']) == 82 and len(record['plan']['before_receipt_files']) == 12
    assert record['plan']['completion_count'] == 2
    print('G6 compiler continuation queued with provider/auth/runtime-focus traps active', flush=True)
    row = process(root)
    assert row['state'] == 'GENERATED', (row, service.failures)
    assert len(service.calls) == 13
    print('G6 compile-only worker GENERATED, provider calls remain 13', flush=True)
    unchanged(job, before)
    assert tree_bytes(store) == receipt_before
    assert all(provider.paths(job)[key].read_bytes() == value for key, value in external.items())
    assert prose.path(job).read_bytes() == prose_before
    assert compiler.path(job).read_bytes() == record_raw
    merged = json.loads((pipeline / 'merged-blueprint.json').read_bytes())
    assert canonical_hash(merged) == canonical_hash(expected_merge)
    index = json.loads((pipeline / 'review-index.json').read_bytes())
    assert index['schema_version'] == 9
    assert index['provider_attempt_lineage']['historical_outcome'] == 'unknown'
    assert index['prose_representation_lineage']
    lineage = index['compiler_derivation_lineage']
    assert lineage['completion_count'] == 2 and lineage['new_model_operations'] == 0
    assert lineage['original_candidate_sha256'] == original_hashes
    assert lineage['historical_reviews_relabelled'] is False
    assert lineage['review_authority_granted'] is False
    assert lineage['business_behavior_accepted'] is False
    assert lineage['compiler_receipt_sha256'] == canonical_hash(proof)
    assert [view['candidate_sha256'] for view in index['focuses']] == original_hashes
    assert [view['review_sha256'] for view in index['focuses']] == [canonical_hash(review) for review in reviews]
    assert len(index['reference_policy_chain']) == 3
    assert index['reference_policy_chain'][2]['start_index'] == 4
    sealed = tree_bytes(job)
    # New app against retained DB/files proves read reconstruction after restart.
    from fox.app import create_app
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as restarted:
        login(restarted)
        assert_download(restarted, root, pid, rid)
        duplicate = restarted.post(url, json=body)
        assert duplicate.status_code == 202, duplicate.text
        assert duplicate.json()['already_recorded'] and duplicate.json()['state'] == 'GENERATED'
    assert len(service.calls) == 13 and tree_bytes(job) == sealed
    print('G6 package/output/download and restart/duplicate passed with zero new calls', flush=True)
    original_record = compiler.path(job).read_bytes()
    compiler.path(job).write_text('{}')
    assert c.get(endpoint(pid, rid, 'output')).status_code == 409
    assert c.get(endpoint(pid, rid, 'download')).status_code == 409
    compiler.path(job).write_bytes(original_record)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        event = db.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (compiler.EVENT,)).fetchone()
        db.execute('DELETE FROM events WHERE action=?', (compiler.EVENT,))
    assert c.get(endpoint(pid, rid, 'output')).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'GENERATED'
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    assert len(service.calls) == 13
    unchanged(job, before)
    assert tree_bytes(store) == receipt_before
    print('G6 final compiler record/event tamper rejection passed', flush=True)
