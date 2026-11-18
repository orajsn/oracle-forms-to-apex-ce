"""Four-focus local API/SQLite/worker continuation; synthetic direct/compiler only."""
from copy import deepcopy
import json
import sqlite3

import pytest

from fox.prototype_chunk_evidence import POLICY as V1
from fox.prototype_reference_echo import POLICY as V2
from test_development_reference_flow import (
    configured, runtime as reference_runtime, tmp_path, seed_old, process, requests,
    assert_download, tree_bytes, queued_case)
from test_development_intake_routes import settings
from test_source_history_api import client, no_external_actions, settings as base_settings


@pytest.fixture
def runtime(reference_runtime, monkeypatch):
    from fox import prototype_job
    original_run = prototype_job.run_prototype_job
    reference_runtime.failures = []
    def observed(*args, **kwargs):
        try:
            return original_run(*args, **kwargs)
        except Exception as error:
            import traceback
            reference_runtime.failures.append(traceback.format_exc())
            raise
    monkeypatch.setattr(prototype_job, 'run_prototype_job', observed)
    import test_development_intake_routes as intake
    original_pair = intake.pair
    def four_focus_pair(code):
        extra = b''.join((f'<Block Name="EXTRA_{i}" DatabaseBlock="false"><Item Name="VALUE_{i}" ItemType="Text Item"/>'
            f'<Trigger Name="SAVE_{i}" TriggerText="BEGIN APP.SAVE({i}); END;"/></Block>').encode()
            for i in (2, 3))
        return {key: raw.replace(b'</FormModule>', extra + b'</FormModule>')
                for key, raw in original_pair(code).items()}
    monkeypatch.setattr(intake, 'pair', four_focus_pair)
    original_alter = reference_runtime.alter
    def echo_later(body):
        original_alter(body)
        request = requests(reference_runtime)[-1]
        if 'candidate' in request:
            return
        mapper_count = sum('candidate' not in r for r in requests(reference_runtime))
        if mapper_count >= 3 or getattr(reference_runtime, 'echo_all', False):
            part = body['chat_response']['choices'][0]['message']['content'][0]
            value = json.loads(part['text'])
            value['source_binding'] = request['source_binding']
            part['text'] = json.dumps(value)
    reference_runtime.alter = echo_later
    return reference_runtime


def endpoint(pid, rid, operation='development-reference-followup'):
    return f'/api/projects/{pid}/prototype-runs/{rid}/{operation}'


def approve(c, url):
    response = c.get(url)
    assert response.status_code == 200, response.text
    body = {'plan_sha256': response.json()['plan_sha256'], 'approved_source_reference_correction': True}
    response = c.post(url, json=body)
    assert response.status_code == 202, response.text
    return body


def unchanged(job, before):
    assert all((job / name).read_bytes() == raw for name, raw in before.items())


@pytest.fixture
def stopped(client, configured, runtime):
    c, root, pid, rid, snapshot = seed_old(client, configured)
    assert 'chunk_evidence_policy' not in snapshot['prototype']
    assert process(root)['state'] == 'ATTENTION'
    assert len(runtime.calls) == 1
    job = root / 'jobs' / rid
    original = tree_bytes(job)
    approve(c, endpoint(pid, rid, 'development-reference-resume'))
    assert process(root)['state'] == 'ATTENTION'
    assert len(runtime.calls) == 5
    assert len(list(job.rglob('reviewer.json'))) == 2
    unchanged(job, original)
    return c, root, pid, rid, snapshot


def test_same_run_followup_preserves_v1_prefix_and_only_starts_remaining_roles(stopped, configured, runtime):
    c, root, pid, rid, _ = stopped
    job = root / 'jobs' / rid
    before = tree_bytes(job)
    before_calls = deepcopy(runtime.calls)
    pivot = requests(runtime)[-1]['focus_id']
    body = approve(c, endpoint(pid, rid))
    assert runtime.calls == before_calls
    assert process(root)['state'] == 'GENERATED', runtime.failures
    unchanged(job, before)
    calls = requests(runtime)
    assert len(calls) == 8
    assert calls[5]['request']['focus_id'] == pivot and 'candidate' in calls[5]
    mappers = [r['focus_id'] for r in calls if 'candidate' not in r]
    reviewers = [r['request']['focus_id'] for r in calls if 'candidate' in r]
    assert len(mappers) == len(set(mappers)) == 4
    assert mappers == reviewers
    pipeline = job / 'prototype-pipeline'
    index = json.loads((pipeline / 'review-index.json').read_bytes())
    assert index['schema_version'] == 6
    assert index['reference_policy_chain'] == [
        {'start_index': 0, 'policy': V1}, {'start_index': 2, 'policy': V2}]
    assert index['reference_continuation_sha256'] and index['reference_followup_sha256']
    for position, fid in enumerate(mappers):
        receipt = json.loads((pipeline / fid / 'projection-receipt.json').read_bytes())
        assert receipt['policy'] == (V1 if position < 2 else V2)
    assert_download(c, root, pid, rid)
    sealed = tree_bytes(job)
    response = c.post(endpoint(pid, rid), json=body)
    assert response.status_code == 202 and response.json()['already_recorded']
    assert response.json()['state'] == 'GENERATED'
    assert tree_bytes(job) == sealed and len(runtime.calls) == 8
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'GENERATED'
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    # Reconstruct retained output against each original proof, never cached flags.
    for path in (job / 'development-reference-resume.json',
                 pipeline / 'development-reference-resume.json',
                 pipeline / mappers[0] / 'reviewer.json', pipeline / pivot / 'mapper.json',
                 job / 'source-snapshot.json'):
        original = path.read_bytes()
        path.write_text('{}')
        assert c.get(endpoint(pid, rid, 'output')).status_code == 409, path
        assert c.post(endpoint(pid, rid), json=body).status_code == 409, path
        path.write_bytes(original)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        event = db.execute("SELECT owner,action,object_id,created FROM events WHERE action='approved_prototype_development_reference_resume'").fetchone()
        db.execute('DELETE FROM events WHERE object_id=?', (event[2],))
    assert c.get(endpoint(pid, rid, 'output')).status_code == 409
    assert c.post(endpoint(pid, rid), json=body).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
    original_target = configured['profile_id']
    configured['profile_id'] += '-changed'
    assert c.get(endpoint(pid, rid, 'output')).status_code == 409
    assert c.post(endpoint(pid, rid), json=body).status_code == 409
    configured['profile_id'] = original_target
    assert_download(c, root, pid, rid)
    assert tree_bytes(job) == sealed and len(runtime.calls) == 8


def test_fresh_v2_combined_echo_chunk_runs_all_four_focuses(client, configured, runtime):
    runtime.echo_all = True
    c, root, pid, rid, snapshot = queued_case(client)
    assert snapshot['prototype']['chunk_evidence_policy'] == V2
    assert process(root)['state'] == 'GENERATED'
    assert len(runtime.calls) == 8
    index = json.loads((root / 'jobs' / rid / 'prototype-pipeline/review-index.json').read_bytes())
    assert index['schema_version'] == 6
    assert index['reference_policy_chain'] == [{'start_index': 0, 'policy': V2}]
    for reviewer in [r for r in requests(runtime) if 'candidate' in r]:
        assert 'source_binding' not in reviewer['candidate']
        for claim in reviewer['candidate']['blueprint']['claims']:
            units = {u['id']: u for u in reviewer['request']['code_units']}
            assert units[claim['evidence_refs'][1]]['owner_id'] == claim['source_object_id']
    assert_download(c, root, pid, rid)


@pytest.mark.parametrize('mutation', ['parent-owner', 'parent-technical', 'parent-event',
    'pivot', 'prefix', 'source', 'target', 'owner', 'plan', 'missing-consent',
    'child-owner', 'child-technical', 'child-event'])
def test_followup_admission_and_retained_output_fail_closed(stopped, configured, runtime, mutation):
    c, root, pid, rid, _ = stopped
    job = root / 'jobs' / rid
    url = endpoint(pid, rid)
    response = c.get(url)
    assert response.status_code == 200, response.text
    body = {'plan_sha256': response.json()['plan_sha256'], 'approved_source_reference_correction': True}
    generated = mutation.startswith('child-')
    if generated:
        assert c.post(url, json=body).status_code == 202
        assert process(root)['state'] == 'GENERATED'
        assert_download(c, root, pid, rid)
    if mutation == 'plan': body['plan_sha256'] = 'f' * 64
    elif mutation == 'missing-consent': body.pop('approved_source_reference_correction')
    elif mutation == 'target': configured['profile_id'] += '-changed'
    elif mutation in ('parent-owner', 'parent-technical', 'child-owner', 'child-technical'):
        record = 'development-reference-' + ('followup' if generated else 'resume') + '.json'
        path = job / record if mutation.endswith('owner') else job / 'prototype-pipeline' / record
        path.write_text('{}')
    elif mutation in ('pivot', 'prefix'):
        calls = requests(runtime)
        fid = calls[4]['focus_id'] if mutation == 'pivot' else calls[0]['focus_id']
        name = 'mapper.json' if mutation == 'pivot' else 'reviewer.json'
        (job / 'prototype-pipeline' / fid / name).write_text('{}')
    else:
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            if mutation.endswith('event'):
                action = 'approved_prototype_development_reference_' + ('followup' if generated else 'resume')
                db.execute('DELETE FROM events WHERE action=?', (action,))
            elif mutation == 'owner':
                db.execute('UPDATE projects SET owner=? WHERE id=?', ('synthetic-other', pid))
            else:
                db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
    before, call_count = tree_bytes(job), len(runtime.calls)
    response = c.post(url, json=body)
    assert response.status_code in (404, 409, 422), response.text
    if generated:
        for suffix in ('output', 'download'):
            assert c.get(endpoint(pid, rid, suffix)).status_code == 409
    assert tree_bytes(job) == before and len(runtime.calls) == call_count
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == (
            'GENERATED' if generated else 'ATTENTION')
