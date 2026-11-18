"""Local API/SQLite/worker, fake direct SDK; one acknowledged new attempt only."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
from threading import Event
from types import SimpleNamespace

import pytest

from fox import prototype_provider_reexecution as repeat
from fox.oci_genai import OciGenAiClient
from fox.opaf import OpafError, canonical_hash
from fox.prototype_pipeline import _role
from fox.design_provider import roles
from fox.provider_receipts import LocalProviderReceiptStore
from test_development_reference_flow import (
    configured, runtime as reference_runtime, tmp_path, seed_old, process, requests,
    assert_download, tree_bytes)
from test_development_followup_flow import runtime as followup_runtime, approve, endpoint, unchanged
from test_development_intake_routes import settings
from test_source_history_api import client, no_external_actions, settings as base_settings
from test_oci_genai import fake_sdk


class SyntheticServiceError(Exception):
    status = 429
    code = 'TooManyRequests'
    headers = {'opc-request-id': 'synthetic-service-error'}


@pytest.fixture
def runtime(followup_runtime, monkeypatch):
    import test_development_intake_routes as intake
    original_pair = intake.pair
    extra = (b'<Block Name="LAST" DatabaseBlock="false"><Item Name="LAST_VALUE" ItemType="Text Item"/>'
             b'<Trigger Name="LAST_SAVE" TriggerText="BEGIN APP.LAST_SAVE(5); END;"/></Block>')
    monkeypatch.setattr(intake, 'pair', lambda code: {
        k: v.replace(b'</FormModule>', extra + b'</FormModule>') for k, v in original_pair(code).items()})
    service = followup_runtime
    original_chat = service.chat
    service.pivot = None
    service.new_outcome = 'valid'
    service.entered, service.release = Event(), Event()
    service.block_new = False
    service.durable_checks = 0
    def chat(details, **kwargs):
        request = json.loads(details['chat_request']['messages'][1]['content'][0]['text'])
        is_mapper = 'candidate' not in request
        previous = [r for r in requests(service) if 'candidate' not in r]
        if is_mapper and service.pivot is None and len(previous) == 3:
            service.pivot = request['focus_id']
            service.calls.append((deepcopy(details), kwargs))
            raise TimeoutError('Synthetic original unknown outcome; never a real operation.')
        if is_mapper and request['focus_id'] == service.pivot:
            paths = repeat.paths(service.job)
            authority = json.loads(paths['authority'].read_bytes())
            consumed = json.loads(paths['consumed'].read_bytes())
            # Separate connection proves transaction commit before SDK POST.
            with sqlite3.connect(service.root / 'fox.sqlite3') as connection:
                assert connection.execute('SELECT state FROM runs WHERE id=?', (service.job.name,)).fetchone()[0] == 'PROCESSING'
                for action, record, timestamp in ((repeat.EVENT, authority, 'approved_at'),
                                                  (repeat.CONSUMED_EVENT, consumed, 'consumed_at')):
                    rows = connection.execute('SELECT owner,object_id,created FROM events WHERE action=?', (action,)).fetchall()
                    assert rows == [(record['owner'], service.job.name + ':' + canonical_hash(record), record[timestamp])]
            assert len(list(paths['receipts'].glob('*.intent.json'))) == 1
            assert not list(paths['receipts'].glob('*.response.json'))
            service.durable_checks += 1
            service.entered.set()
            if service.block_new:
                assert service.release.wait(10), 'Concurrent synthetic request did not release provider.'
            if service.new_outcome in ('unknown', 'service-error'):
                service.calls.append((deepcopy(details), kwargs))
                if service.new_outcome == 'unknown':
                    raise TimeoutError('Synthetic new transport outcome also unknown.')
                raise SyntheticServiceError('Synthetic private error text must not leak.')
            if service.new_outcome == 'malformed':
                response = original_chat(details, **kwargs)
                response.data['chat_response']['choices'][0]['message']['content'][0]['text'] = 'invalid synthetic JSON'
                return response
            if service.new_outcome == 'wrong-echo':
                response = original_chat(details, **kwargs)
                part = response.data['chat_response']['choices'][0]['message']['content'][0]
                value = json.loads(part['text'])
                value['source_binding'] = 'f' * 64
                part['text'] = json.dumps(value)
                return response
        return original_chat(details, **kwargs)
    service.chat = chat
    import fox.provider_reexecution_routes as routes
    def direct(destination):
        sdk = fake_sdk()
        sdk.exceptions = SimpleNamespace(ServiceError=SyntheticServiceError)
        return OciGenAiClient(destination, client=service, sdk=sdk)
    monkeypatch.setattr(routes, 'OciGenAiClient', direct)
    original_parse = OciGenAiClient._parse_response
    service.capture_checks = 0
    def parsed(*args, **kwargs):
        if hasattr(service, 'job') and repeat.paths(service.job)['consumed'].exists():
            responses = list(repeat.paths(service.job)['receipts'].glob('*.response.json'))
            assert any(canonical_hash(json.loads(p.read_bytes())['payload']['body']) == canonical_hash(kwargs['body'])
                       for p in responses), 'SDK response must be durably captured before parsing.'
            service.capture_checks += 1
        return original_parse(*args, **kwargs)
    monkeypatch.setattr(OciGenAiClient, '_parse_response', staticmethod(parsed))
    return service


@pytest.fixture
def unknown(client, configured, runtime):
    c, root, pid, rid, snapshot = seed_old(client, configured)
    runtime.root, runtime.job = root, root / 'jobs' / rid
    assert process(root)['state'] == 'ATTENTION'
    assert len(runtime.calls) == 1
    approve(c, endpoint(pid, rid, 'development-reference-resume'))
    assert process(root)['state'] == 'ATTENTION'
    assert len(runtime.calls) == 5
    approve(c, endpoint(pid, rid))
    assert process(root)['state'] == 'ATTENTION', runtime.failures
    assert len(runtime.calls) == 7
    assert len(list(runtime.job.rglob('reviewer.json'))) == 3
    pivot = runtime.job / 'prototype-pipeline' / runtime.pivot
    assert (pivot / 'mapper-intent.json').is_file() and not (pivot / 'mapper.json').exists()
    assert not repeat.paths(runtime.job)['receipts'].exists()
    return c, root, pid, rid, snapshot


def attempt_url(case):
    _, _, pid, rid, _ = case
    return endpoint(pid, rid, 'provider-reexecution')


def attempt_body(case):
    response = case[0].get(attempt_url(case))
    assert response.status_code == 200, response.text
    assert response.json()['eligible']
    assert response.json()['historical_outcome'] == 'unknown'
    assert response.json()['approved_prefix_focuses'] == 3
    return {'plan_sha256': response.json()['plan_sha256'], 'acknowledged_unknown_outcome': True,
            'acknowledged_possible_extra_charge': True}


def test_exact_acknowledged_attempt_concurrent_duplicate_and_captured_remaining_flow(unknown, configured, runtime, monkeypatch):
    c, root, pid, rid, snapshot = unknown
    job = runtime.job
    before = tree_bytes(job)
    def forbidden(*args, **kwargs):
        pytest.fail('Read-only plan must not authenticate, create, sync or invoke.')
    with monkeypatch.context() as read_patch:
        import os
        read_patch.setattr(Path, 'mkdir', forbidden)
        read_patch.setattr(os, 'fsync', forbidden)
        read_patch.setattr(OciGenAiClient, '_client', forbidden)
        body = attempt_body(unknown)
    assert tree_bytes(job) == before and len(runtime.calls) == 7
    assert not repeat.paths(job)['ledger'].exists()
    # Generic pending-intent rejection is still authoritative outside operator path.
    directory = job / 'prototype-pipeline' / runtime.pivot
    request = json.loads((directory / 'request.json').read_bytes())
    with pytest.raises(OpafError, match='uncertain'):
        _role(directory, 'mapper', object(), roles(configured)['mapper'], request,
            {'job_id': rid, 'source_hash': snapshot['prototype']['source_binding']},
            lambda: configured, lambda context: True, {})
    for missing in ('acknowledged_unknown_outcome', 'acknowledged_possible_extra_charge'):
        for value in (None, False, 1):
            invalid = deepcopy(body)
            if value is None: invalid.pop(missing)
            else: invalid[missing] = value
            assert c.post(attempt_url(unknown), json=invalid).status_code == 422
    invalid = {**body, 'plan_sha256': 'f' * 64}
    assert c.post(attempt_url(unknown), json=invalid).status_code == 409
    original_target = configured['profile_id']
    configured['profile_id'] += '-changed'
    assert c.post(attempt_url(unknown), json=body).status_code == 409
    configured['profile_id'] = original_target
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        owner = db.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()[0]
        db.execute('UPDATE projects SET owner=? WHERE id=?', ('synthetic-other', pid))
    assert c.post(attempt_url(unknown), json=body).status_code == 404
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE projects SET owner=? WHERE id=?', (owner, pid))
        db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
    assert c.post(attempt_url(unknown), json=body).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE project_source_selection SET current_source_set_id=? WHERE project=?',
                   (snapshot['selected_source_set_id'], pid))
    unchanged(job, before)
    assert len(runtime.calls) == 7 and not repeat.paths(job)['ledger'].exists()
    runtime.block_new = True
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(c.post, attempt_url(unknown), json=body)
        try:
            assert runtime.entered.wait(15)
            duplicate = pool.submit(c.post, attempt_url(unknown), json=body).result(timeout=15)
            assert duplicate.status_code == 200, duplicate.text
            assert duplicate.json()['inference_repeated_by_this_request'] is False
        finally:
            runtime.release.set()
        response = first.result(timeout=30)
    assert response.status_code == 202, response.text
    assert response.json()['new_attempt_adopted']
    assert len(runtime.calls) == 8 and runtime.durable_checks == 1
    paths = repeat.paths(job)
    assert paths['consumed'].is_file() and paths['adoption'].is_file()
    from fox.provider_reexecution_routes import _create
    with pytest.raises(FileExistsError):
        _create(paths['consumed'], json.loads(paths['consumed'].read_bytes()))
    checkpoint = json.loads((directory / 'mapper.json').read_bytes())
    assert checkpoint['provider_reexecution']['new_attempt'] is True
    assert checkpoint['provider_reexecution']['attempt_number'] == 1
    assert 'provider_response_receipt' not in checkpoint
    unchanged(job, before)
    assert process(root)['state'] == 'GENERATED', runtime.failures
    assert len(runtime.calls) == 11
    assert requests(runtime)[8]['request']['focus_id'] == runtime.pivot
    assert len({r['focus_id'] for r in requests(runtime) if 'candidate' not in r}) == 5
    # Three remaining roles each carry generic receipts; historical prefix never does.
    remaining = [json.loads(p.read_bytes()) for p in job.rglob('*.json')
                 if p.name in ('mapper.json', 'reviewer.json') and 'provider_response_receipt' in json.loads(p.read_bytes())]
    assert len(remaining) == 3
    assert len(list(paths['receipts'].glob('*.intent.json'))) == 4
    assert len(list(paths['receipts'].glob('*.response.json'))) == 4
    assert runtime.capture_checks >= 4
    unchanged(job, before)
    index = json.loads((job / 'prototype-pipeline/review-index.json').read_bytes())
    assert index['schema_version'] == 7
    lineage = index['provider_attempt_lineage']
    assert lineage['historical_outcome'] == 'unknown' and lineage['new_attempt_adopted'] is True
    assert lineage['additional_attempt_limit'] == 1
    assert index['reference_policy_chain'][1]['start_index'] == 2
    assert_download(c, root, pid, rid)
    sealed = tree_bytes(job)
    # Read/download reconstruct without auth, filesystem creation or sync.
    with monkeypatch.context() as read_patch:
        import os
        read_patch.setattr(Path, 'mkdir', forbidden)
        read_patch.setattr(os, 'fsync', forbidden)
        read_patch.setattr(OciGenAiClient, '_client', forbidden)
        assert_download(c, root, pid, rid)
    assert tree_bytes(job) == sealed and len(runtime.calls) == 11
    # Completed duplicate may reject its artifact, but can never submit or requeue.
    duplicate = c.post(attempt_url(unknown), json=body)
    assert duplicate.status_code in (200, 409), duplicate.text
    assert len(runtime.calls) == 11
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'GENERATED'
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    # Every external proof is required for completed output; restore exact bytes.
    generic_response = paths['receipts'] / (remaining[0]['provider_response_receipt']['receipt_binding_sha256'] + '.response.json')
    for path in (paths['authority'], paths['adoption'], paths['consumed'],
                 next(paths['receipts'].glob('*.response.json')), generic_response):
        original = path.read_bytes()
        path.write_text('{}')
        assert c.get(endpoint(pid, rid, 'output')).status_code == 409, path
        assert c.get(endpoint(pid, rid, 'download')).status_code == 409, path
        path.write_bytes(original)
    for action in (repeat.EVENT, repeat.CONSUMED_EVENT, repeat.ADOPTION_EVENT):
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            event = db.execute('SELECT owner,action,object_id,created FROM events WHERE action=?', (action,)).fetchone()
            db.execute('DELETE FROM events WHERE action=?', (action,))
        assert c.get(endpoint(pid, rid, 'output')).status_code == 409
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
    assert_download(c, root, pid, rid)
    assert len(runtime.calls) == 11


@pytest.mark.parametrize('outcome', ['malformed', 'service-error', 'unknown', 'capture-failure', 'wrong-echo'])
def test_new_failed_or_unknown_outcome_consumes_budget_without_automatic_retry(unknown, configured, runtime, monkeypatch, outcome):
    c, root, pid, rid, snapshot = unknown
    job = runtime.job
    before = tree_bytes(job)
    body = attempt_body(unknown)
    runtime.new_outcome = outcome
    if outcome == 'capture-failure':
        def cannot_capture(*args, **kwargs):
            raise OSError('Synthetic receipt persistence interruption after SDK response.')
        monkeypatch.setattr(LocalProviderReceiptStore, 'capture', cannot_capture)
    response = c.post(attempt_url(unknown), json=body)
    assert response.status_code == 409, response.text
    assert len(runtime.calls) == 8 and runtime.durable_checks == 1
    paths = repeat.paths(job)
    consumed = paths['consumed'].read_bytes()
    assert not paths['adoption'].exists()
    assert not (job / 'prototype-pipeline' / runtime.pivot / 'mapper.json').exists()
    captured = list(paths['receipts'].glob('*.response.json'))
    assert bool(captured) == (outcome in ('malformed', 'service-error', 'wrong-echo'))
    if outcome == 'malformed':
        assert 'invalid synthetic JSON' in captured[0].read_text()
    if outcome == 'service-error':
        payload = json.loads(captured[0].read_bytes())['payload']
        assert payload['status'] == 429
        assert payload['body'] == {'scope': 'fox-oci-service-error-v1', 'code': 'TooManyRequests'}
        assert 'private error text' not in captured[0].read_text()
    unchanged(job, before)
    duplicate = c.post(attempt_url(unknown), json=body)
    assert duplicate.status_code in (200, 409), duplicate.text
    assert len(runtime.calls) == 8
    # Preserve, rather than erase, receipt evidence while simulating store loss.
    archived = paths['receipts'].with_name(paths['receipts'].name + '-retained')
    assert paths['receipts'].is_relative_to(root) and archived.is_relative_to(root)
    paths['receipts'].rename(archived)
    assert paths['consumed'].read_bytes() == consumed
    response = c.post(attempt_url(unknown), json=body)
    assert response.status_code in (200, 409), response.text
    assert len(runtime.calls) == 8 and paths['consumed'].read_bytes() == consumed
    assert process(root)['state'] == 'ATTENTION'
    assert len(runtime.calls) == 8
    unchanged(job, before)


def test_interruption_after_exclusive_latch_before_consumed_event_never_calls_sdk(unknown, runtime, monkeypatch):
    from fox import provider_reexecution_routes as routes
    c, root, pid, rid, _ = unknown
    body = attempt_body(unknown)
    original_event = routes._event
    def interrupted(c, action, run_id, record, timestamp):
        if action == repeat.CONSUMED_EVENT:
            raise OSError('Synthetic interruption after O_EXCL latch, before DB event commit.')
        return original_event(c, action, run_id, record, timestamp)
    monkeypatch.setattr(routes, '_event', interrupted)
    before = tree_bytes(runtime.job)
    assert c.post(attempt_url(unknown), json=body).status_code == 409
    paths = repeat.paths(runtime.job)
    assert paths['authority'].is_file() and paths['consumed'].is_file()
    assert not paths['adoption'].exists()
    assert not list(paths['receipts'].glob('*.intent.json'))
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM events WHERE action=?', (repeat.CONSUMED_EVENT,)).fetchone()[0] == 0
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    assert c.post(attempt_url(unknown), json=body).status_code == 409
    assert len(runtime.calls) == 7
    unchanged(runtime.job, before)


def test_changed_actual_sdk_wire_after_plan_consumes_but_never_submits(unknown, runtime, monkeypatch):
    c, root, pid, rid, _ = unknown
    body = attempt_body(unknown)
    before = tree_bytes(runtime.job)
    original_prepare = OciGenAiClient._prepare_request
    def changed_wire(self, role, request):
        name, details, digest = original_prepare(self, role, request)
        self._qa_prepare_count = getattr(self, '_qa_prepare_count', 0) + 1
        if self._qa_prepare_count > 1:
            details = deepcopy(details)
            details['chat_request']['temperature'] = 0.25
            digest = canonical_hash(self.sdk.util.to_dict(details))
        return name, details, digest
    monkeypatch.setattr(OciGenAiClient, '_prepare_request', changed_wire)
    response = c.post(attempt_url(unknown), json=body)
    assert response.status_code == 409, response.text
    paths = repeat.paths(runtime.job)
    assert paths['authority'].exists() and paths['consumed'].exists()
    assert not paths['adoption'].exists()
    assert not list(paths['receipts'].glob('*.intent.json'))
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM events WHERE action=?', (repeat.CONSUMED_EVENT,)).fetchone()[0] == 1
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    assert len(runtime.calls) == 7
    duplicate = c.post(attempt_url(unknown), json=body)
    assert duplicate.status_code in (200, 409), duplicate.text
    assert len(runtime.calls) == 7
    unchanged(runtime.job, before)
