"""Local synthetic six-focus captured continuation; no real provider/SQLcl."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import time

import pytest

from fox import prototype_prose_continuation as prose
from fox import prototype_provider_reexecution as provider
from fox.oci_genai import OciGenAiClient
from fox.opaf import OpafError, canonical_hash
from fox.provider_receipts import LocalProviderReceiptStore
from fox.provider_reexecution_routes import _create, _private
from fox.prototype_job import read_prototype_snapshot
from test_provider_reexecution_flow import (runtime as provider_runtime, unknown,
    attempt_url, attempt_body, configured, client, no_external_actions, settings,
    base_settings, tmp_path, followup_runtime, reference_runtime)
from test_development_reference_flow import process, requests, tree_bytes, assert_download

ERRORS = (OpafError, ValueError, KeyError, TypeError, OSError)


@pytest.fixture
def runtime(provider_runtime, monkeypatch):
    import test_development_intake_routes as intake
    original_pair = intake.pair
    extra = (b'<Block Name="FINAL" DatabaseBlock="false"><Item Name="FINAL_VALUE" ItemType="Text Item"/>'
             b'<Trigger Name="FINAL_SAVE" TriggerText="BEGIN APP.FINAL_SAVE(6); END;"/></Block>')
    monkeypatch.setattr(intake, 'pair', lambda code: {
        key: raw.replace(b'</FormModule>', extra + b'</FormModule>') for key, raw in original_pair(code).items()})
    original_alter = provider_runtime.alter
    def long_fifth(body):
        original_alter(body)
        request = requests(provider_runtime)[-1]
        if 'candidate' in request: return
        ids = list(dict.fromkeys(row['focus_id'] for row in requests(provider_runtime) if 'candidate' not in row))
        index = ids.index(request['focus_id'])
        part = body['chat_response']['choices'][0]['message']['content'][0]
        value = json.loads(part['text'])
        if index == 1:
            value['blueprint']['claims'] = []
        if index == 4:
            value['blueprint']['claims'][0]['value'] = 'A' * 604
        part['text'] = json.dumps(value)
    provider_runtime.alter = long_fifth
    return provider_runtime


@pytest.fixture
def stopped(unknown, configured, runtime):
    c, root, pid, rid, _ = unknown
    response = c.post(attempt_url(unknown), json=attempt_body(unknown))
    assert response.status_code == 202, response.text
    row = process(root)
    assert row['state'] == 'ATTENTION', runtime.failures
    job = root / 'jobs' / rid
    snapshot, original = read_prototype_snapshot(job)
    assert len(runtime.calls) == 10
    assert len(list(job.rglob('reviewer.json'))) == 4
    assert len(tree_bytes(job)) == 64
    assert len(list(provider.paths(job)['receipts'].glob('*.json'))) == 6
    return c, root, pid, rid, snapshot, original, configured, runtime


def install(case):
    _, root, _, rid, snapshot, original, target, _ = case
    job = root / 'jobs' / rid
    plan = prose.inspect(job, snapshot, original, target)
    value = prose.records(plan, snapshot['approvals']['owner'], time.time())
    _private(prose.path(job).parent.parent)
    _private(prose.path(job).parent)
    _create(prose.path(job), value)
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (value['owner'], prose.EVENT, rid + ':' + canonical_hash(value), value['approved_at']))
    return job, plan, value


def test_exact_64_file_plan_is_body_free_and_reconstructed_without_calls_or_writes(stopped, monkeypatch):
    _, root, _, rid, snapshot, original, target, service = stopped
    job = root / 'jobs' / rid
    before, store = tree_bytes(job), tree_bytes(provider.paths(job)['receipts'])
    def forbidden(*a, **k): pytest.fail('Read proof must not create, flush, authenticate or invoke.')
    with monkeypatch.context() as guard:
        guard.setattr(Path, 'mkdir', forbidden)
        guard.setattr(os, 'fsync', forbidden)
        guard.setattr(OciGenAiClient, '_client', forbidden)
        plan = prose.inspect(job, snapshot, original, target)
        assert prose.inspect(job, snapshot, original, target) == plan
    assert len(plan['before_files']) == 64
    assert len(plan['before_receipt_files']) == 6
    assert len(plan['before_external_files']) == 3
    assert len(plan['prefix_proofs_sha256']) == 4 and plan['pivot_index'] == 4
    assert plan['projection_claim_count'] == 1 and plan['additional_mapper_replays'] == 0
    assert len([row for row in plan['remaining_operations'] if 'role' in row]) == 3
    assert before == tree_bytes(job) and store == tree_bytes(provider.paths(job)['receipts'])
    assert len(service.calls) == 10
    for text in ('A' * 30, 'TriggerText', 'evidence_refs', 'chat_response'):
        assert text not in json.dumps(plan)


def test_record_and_owner_event_are_exact_and_index_has_no_private_paths(stopped):
    _, root, _, rid, snapshot, original, _, service = stopped
    job, plan, value = install(stopped)
    assert prose.technical(job / 'prototype-pipeline') == value
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        assert prose.validate_owner(job, snapshot, original, connection) == value
    evidence = prose.index_evidence(job / 'prototype-pipeline')
    assert evidence['continuation_sha256'] == canonical_hash(value)
    assert evidence['additional_mapper_replays'] == 0 and evidence['business_behavior_accepted'] is False
    assert evidence['original_prose_bytes_preserved'] is True
    assert str(root) not in json.dumps(evidence) and 'chat_response' not in json.dumps(evidence)
    assert len(service.calls) == 10
    with pytest.raises(FileExistsError): _create(prose.path(job), value)
    for invalid in (True, 0, float('nan')):
        with pytest.raises(ERRORS): prose.records(plan, plan['owner'], invalid)


def test_only_three_remaining_roles_and_in_progress_receipts_pass_normal_worker(stopped, monkeypatch):
    c, root, pid, rid, _, _, _, service = stopped
    job, plan, _ = install(stopped)
    before = tree_bytes(job)
    old_store = tree_bytes(provider.paths(job)['receipts'])
    old_external = {key: provider.paths(job)[key].read_bytes() for key in ('authority', 'consumed', 'adoption')}
    checks = []
    original_begin = LocalProviderReceiptStore.begin
    def begin(store, binding, **kwargs):
        key = original_begin(store, binding, **kwargs)
        assert prose.technical(job / 'prototype-pipeline')
        checks.append(('intent', key))
        return key
    monkeypatch.setattr(LocalProviderReceiptStore, 'begin', begin)
    original_parse = OciGenAiClient._parse_response
    checking = False
    allowed = {(row['focus_id'], row['role']) for row in plan['remaining_operations'] if 'role' in row}
    def parsed(role, request, **kwargs):
        nonlocal checking
        focus = request.get('request', request)['focus_id']
        current = job / 'prototype-pipeline' / focus / (kwargs['name'] + '.json')
        if not checking and (focus, kwargs['name']) in allowed and not current.exists():
            checking = True
            try:
                assert prose.technical(job / 'prototype-pipeline')
                checks.append(('response', kwargs['client_request_id']))
            finally:
                checking = False
        return original_parse(role, request, **kwargs)
    monkeypatch.setattr(OciGenAiClient, '_parse_response', staticmethod(parsed))
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        connection.execute("UPDATE runs SET state='QUEUED' WHERE id=? AND state='ATTENTION' AND artifact IS NULL", (rid,))
    row = process(root)
    assert row['state'] == 'GENERATED', service.failures
    assert len(service.calls) == 13
    assert len([item for item in checks if item[0] == 'intent']) == 3
    # Each response is parsed on receipt and again for checkpoint binding;
    # this is local validation of the same captured call, not another POST.
    assert len({item[1] for item in checks if item[0] == 'response'}) == 3
    assert all((job / name).read_bytes() == raw for name, raw in before.items())
    assert all((provider.paths(job)['receipts'] / name).read_bytes() == raw for name, raw in old_store.items())
    assert all(provider.paths(job)[key].read_bytes() == raw for key, raw in old_external.items())
    assert_download(c, root, pid, rid)


def test_record_event_parent_and_current_owner_loss_are_rejected(stopped):
    _, root, pid, rid, snapshot, original, _, _ = stopped
    job, _, record = install(stopped)
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        event = connection.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (prose.EVENT,)).fetchone()
        connection.execute('DELETE FROM events WHERE action=?', (prose.EVENT,))
        with pytest.raises(ERRORS): prose.validate_owner(job, snapshot, original, connection)
        connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
        connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
        with pytest.raises(ERRORS): prose.validate_owner(job, snapshot, original, connection)
        connection.execute('DELETE FROM events WHERE action=?', (prose.EVENT,))
        connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
        original_record = prose.path(job).read_bytes()
        prose.path(job).unlink()
        with pytest.raises(ERRORS): prose.validate_owner(job, snapshot, original, connection)
        prose.path(job).write_bytes(original_record)
        os.chmod(prose.path(job), 0o600)
        connection.execute('UPDATE projects SET owner=? WHERE id=?', ('changed-owner', pid))
        with pytest.raises(ERRORS): prose.validate_owner(job, snapshot, original, connection)
        connection.execute('UPDATE projects SET owner=? WHERE id=?', (record['owner'], pid))
        connection.execute('DELETE FROM events WHERE action=?', (provider.ADOPTION_EVENT,))
        with pytest.raises(ERRORS): prose.validate_owner(job, snapshot, original, connection)


def test_old_job_external_and_receipt_bytes_cannot_change(stopped):
    _, root, _, rid, _, _, _, _ = stopped
    job, plan, _ = install(stopped)
    paths = [job / next(name for name in plan['before_files'] if name.endswith('/reviewer.json')),
        job / 'source-snapshot.json', provider.paths(job)['authority'],
        provider.paths(job)['consumed'], provider.paths(job)['adoption'],
        provider.paths(job)['receipts'] / next(iter(plan['before_receipt_files']))]
    for location in paths:
        original = location.read_bytes()
        try:
            location.write_bytes(original + b' ')
            with pytest.raises(ERRORS): prose.technical(job / 'prototype-pipeline')
        finally:
            location.write_bytes(original)
    assert prose.technical(job / 'prototype-pipeline')


def test_initial_inspection_rejects_fifth_review_sixth_work_and_result(stopped):
    _, root, _, rid, snapshot, original, target, _ = stopped
    job = root / 'jobs' / rid
    plan = prose.inspect(job, snapshot, original, target)
    for location in (job / 'prototype-pipeline' / plan['pivot_focus_id'] / 'reviewer-intent.json',
                     job / 'prototype-result.json'):
        location.write_text('{}')
        try:
            with pytest.raises(ERRORS): prose.inspect(job, snapshot, original, target)
        finally:
            location.unlink()
    unknown = job / 'prototype-pipeline' / ('focus-' + 'f' * 24)
    unknown.mkdir()
    try:
        with pytest.raises(ERRORS): prose.inspect(job, snapshot, original, target)
    finally:
        unknown.rmdir()


def test_unknown_or_orphan_receipts_cannot_expand_the_store(stopped):
    _, root, _, rid, _, _, _, _ = stopped
    job, _, _ = install(stopped)
    store = provider.paths(job)['receipts']
    for name in ('unknown.json', 'f' * 64 + '.response.json', 'f' * 64 + '.intent.json'):
        location = store / name
        location.write_text('{}')
        os.chmod(location, 0o600)
        try:
            with pytest.raises(ERRORS): prose.technical(job / 'prototype-pipeline')
        finally:
            location.unlink()


def test_absent_record_is_legacy_safe_even_for_fresh_v3_and_nonstandard_jobs(tmp_path):
    job = tmp_path / 'legacy-job'
    assert prose.technical(job / 'prototype-pipeline') is None
    assert prose.index_evidence(job / 'prototype-pipeline') is None
    with sqlite3.connect(':memory:') as connection:
        connection.execute('CREATE TABLE events(owner TEXT,action TEXT,object_id TEXT,created REAL)')
        assert prose.validate_owner(job, {'prototype': {'chunk_evidence_policy': prose.POLICY}}, b'', connection) is None
