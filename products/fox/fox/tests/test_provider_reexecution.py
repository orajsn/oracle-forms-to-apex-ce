"""Synthetic four-focus unknown outcome and one explicit new captured attempt."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

import pytest

from fox import prototype_provider_reexecution as retry
from fox import prototype_development_reference_resume as parent
from fox import prototype_development_reference_followup as followup
from fox.development_processing import prepare_development_processing
from fox.design_provider import roles
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.native_pipeline import _save_once
from fox.oci_genai import OciGenAiClient
from fox.opaf import OpafError, canonical_hash
from fox.provider_receipts import LocalProviderReceiptStore
from fox.prototype_admission import prepare_prototype_admission
from fox.prototype_dsc_identity_repair import TASK_POLICY, model_task
from fox.prototype_pipeline import run_prototype_pipeline
from test_development_processing import context, source_hash
from test_development_reference_resume import hashes, read, write
from test_oci_genai import InjectedService, fake_sdk, target

ERRORS = (OpafError, ValueError, KeyError, TypeError, OSError)


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp('r')


def private_write(path, value):
    path.parent.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path.parent.parent, 0o700)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def event(connection, action, job, value, timestamp):
    connection.execute('INSERT INTO events VALUES(?,?,?,?)',
        (value['owner'], action, job.name + ':' + canonical_hash(value), value[timestamp]))
    connection.commit()


@pytest.fixture
def unknown(tmp_path, request):
    block_count = 4 if getattr(request, 'param', None) == 'later-focus' else 3
    raw = ('<FormModule Name="SYNTHETIC"><Trigger Name="START" '
        'TriggerText="BEGIN APP.START(123); END;"/>' + ''.join(
        f'<Block Name="B{i}"><Item Name="FIELD" ItemType="Text Item"/>'
        f'<Trigger Name="SAVE" TriggerText="BEGIN APP.SAVE({i}); END;"/></Block>'
        for i in range(block_count)) + '</FormModule>').encode()
    docs, destination = [('example.xml', raw)], target()
    packet = local_packet(docs)
    chunks = {row['id']: row['sha256'] for row in packet['chunks']}
    base = context(docs)
    base['target_profile_sha256'] = canonical_hash(destination)
    development = prepare_development_processing(docs, context=base, approved_chunk_hashes=chunks)
    selected = prepare_prototype_admission(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes=chunks, target_profile_sha256=canonical_hash(destination),
        approved_redacted_source=False, approved_unredacted_development_source=True,
        approved_external_ai=True, approved_prototype_scope=True, metadata_task_policy=TASK_POLICY,
        processing_mode='development', development_processing=development, delivery_mode='apexlang_package')['prototype']
    snapshot = {'project': 'synthetic-project', 'project_id': 'synthetic-project',
        'project_name': 'Synthetic prototype', 'selected_source_set_id': 'ss-' + '1' * 32,
        'source_hash': source_hash(docs), 'conversion_profile': 'native-blueprint-prototype-v1',
        'files': [{'name': n, 'sha256': hashlib.sha256(b).hexdigest(), 'bytes': len(b), 'text': b.decode()} for n, b in docs],
        'prototype': selected, 'approvals': {'owner': 'synthetic-owner', 'approved_at': 3.0,
            'redacted_source': False, 'external_ai': True, 'synthetic_prototype': True,
            'unredacted_development_source': True}}
    job = tmp_path / 'jobs' / ('fox-' + 'a' * 20)
    job.mkdir(parents=True)
    write(job / 'source-snapshot.json', snapshot)
    original = (job / 'source-snapshot.json').read_bytes()
    focus = build_focus_plan(docs, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=chunks, max_owned_objects=32)
    assert len(focus['requests']) == block_count + 1
    ids = [row['focus_id'] for row in focus['requests']]
    service = InjectedService()
    def alter(body):
        request = json.loads(service.calls[-1][0]['chat_request']['messages'][1]['content'][0]['text'])
        if 'candidate' in request: return
        part = body['chat_response']['choices'][0]['message']['content'][0]
        output = json.loads(part['text'])
        chunk = request['chunks'][0]
        unit = next(row for row in request['code_units'] if row['id'] == chunk['code_unit_id'])
        output['blueprint']['claims'] = [{'id': 'intent-' + request['focus_id'],
            'source_object_id': unit['owner_id'], 'kind': 'behavior.intent', 'status': 'proposal',
            'value': 'Source proposal 123.', 'reason': 'Independent review required.',
            'evidence_refs': [unit['owner_id'], chunk['id']]}]
        if request['focus_id'] in ids[2:]: output['source_binding'] = request['source_binding']
        part['text'] = json.dumps(output)
    service.alter = alter
    direct = OciGenAiClient(destination, client=service, sdk=fake_sdk())
    options = dict(project_id=snapshot['project_id'], project_name=snapshot['project_name'],
        expected_source_binding=selected['source_binding'], approved_chunk_hashes=chunks,
        approved_policy_id=selected['approved_policy_id'], opaf_client=direct, profile=roles(destination),
        target_profile_loader=lambda: destination, processing_approval_check=lambda *_: True,
        delivery_mode='apexlang_package', focus_schema_version=selected['schema_version'],
        metadata_task_policy=TASK_POLICY, development_processing_sha256=selected['development_processing_sha256'])
    connection = sqlite3.connect(':memory:')
    connection.execute('CREATE TABLE events(owner TEXT,action TEXT,object_id TEXT,created REAL)')
    connection.execute('CREATE TABLE projects(id TEXT,owner TEXT)')
    connection.execute('INSERT INTO projects VALUES(?,?)', (snapshot['project_id'], snapshot['approvals']['owner']))
    with pytest.raises(ValueError): run_prototype_pipeline(job, docs, **options)
    for protocol, approved_at in ((parent, 10.0), (followup, 20.0)):
        plan = protocol.inspect(job, snapshot, original, destination)
        technical, owner = protocol.records(plan, snapshot['approvals']['owner'], approved_at)
        _save_once(job / 'prototype-pipeline' / protocol.TECHNICAL, technical)
        _save_once(job / protocol.OWNER_RECORD, owner)
        event(connection, protocol.EVENT, job, owner, 'approved_at')
        if protocol is parent:
            with pytest.raises(ValueError): run_prototype_pipeline(job, docs, **options)
    original_chat = service.chat
    def uncertain(details, **kwargs):
        request = json.loads(details['chat_request']['messages'][1]['content'][0]['text'])
        if request.get('focus_id') == ids[3]:
            service.calls.append((deepcopy(details), kwargs))
            raise TimeoutError('Authored UNKNOWN transport outcome; no real operation occurred.')
        return original_chat(details, **kwargs)
    service.chat = uncertain
    with pytest.raises(OpafError): run_prototype_pipeline(job, docs, **options)
    assert len(service.calls) == 7
    child = job / 'prototype-pipeline' / ids[3]
    effective = model_task(child, 'mapper', focus['requests'][3], write=False)
    wire = direct._prepare_request(roles(destination)['mapper'], effective)[2]
    yield job, snapshot, original, destination, connection, service, direct, effective, wire, options, original_chat
    connection.close()


def approve(case):
    job, snapshot, original, destination, connection, _, _, _, wire, *_ = case
    plan = retry.inspect(job, snapshot, original, destination, wire)
    value = retry.records(plan, snapshot['approvals']['owner'], time.time() - 3,
        acknowledged_unknown_outcome=True, acknowledged_possible_extra_charge=True)
    private_write(retry.paths(job)['authority'], value)
    event(connection, retry.EVENT, job, value, 'approved_at')
    return value


def consume(case, authority):
    job, _, _, _, connection, *_ = case
    assert retry.require_unconsumed(job, authority, connection)
    value = retry.consumption_record(authority, time.time() - 1)
    private_write(retry.paths(job)['consumed'], value)
    event(connection, retry.CONSUMED_EVENT, job, value, 'consumed_at')
    return value


def capture(case, authority, *, malformed=False):
    job, _, _, destination, connection, service, direct, effective, _, _, original_chat = case
    consumed = consume(case, authority)
    receipt_path = retry.paths(job)['receipts']
    receipt_path.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(receipt_path.parent, 0o700)
    store = LocalProviderReceiptStore(receipt_path, sealed_job_root=job)
    def chat(*args, **kwargs):
        assert retry.validate_consumed(job, authority, connection) == consumed
        return original_chat(*args, **kwargs)
    service.chat = chat
    if malformed:
        service.alter = lambda body: body['chat_response']['choices'][0]['message']['content'][0].update(text='invalid authored JSON')
    invoke = lambda: direct.invoke_prepared(roles(destination)['mapper'], effective,
        {'job_id': job.name, 'source_hash': authority['plan']['source_binding']}, role_name='mapper',
        target_profile=destination, before_invoke=lambda env: retry.validate_consumed(job, authority, connection),
        receipt_store=store)
    if malformed:
        with pytest.raises(OpafError): invoke()
    else: invoke()
    return consumed, store


def adopt(case, authority):
    job, _, _, _, connection, *_ = case
    consumed, store = capture(case, authority)
    saved, evidence = retry.captured_checkpoint(job, authority)
    marker = retry.adoption_record(authority, consumed, saved, evidence, time.time())
    child = job / 'prototype-pipeline' / authority['plan']['pivot_focus_id']
    _save_once(child / 'mapper.json', saved)
    private_write(retry.paths(job)['adoption'], marker)
    event(connection, retry.ADOPTION_EVENT, job, marker, 'adopted_at')
    return child, saved, marker, store


def test_body_free_exact_unknown_plan_and_all_ledgers_are_outside_sealed_job(unknown):
    job, snapshot, original, destination, connection, service, _, _, wire, *_ = unknown
    before = hashes(job)
    plan = retry.inspect(job, snapshot, original, destination, wire)
    assert plan['before_files'] == before and hashes(job) == before
    assert plan['pivot_index'] == 3 and len(plan['prefix_proofs_sha256']) == 3
    assert plan['historical_outcome'] == 'unknown' and plan['historical_wire_sha256'] is None
    assert plan['expected_new_wire_sha256'] == wire and plan['additional_attempt_limit'] == 1
    assert retry.validate_owner(job, snapshot, original, connection) is None
    assert len(service.calls) == 7
    for path in retry.paths(job).values(): assert not path.is_relative_to(job)
    assert not retry.paths(job)['receipts'].is_relative_to(retry.paths(job)['ledger'])
    for text in ('TriggerText', 'APP.START', 'evidence_refs', 'Source proposal'):
        assert text not in json.dumps(plan)


@pytest.mark.parametrize('unknown_ack,cost_ack', [(False, True), (True, False), (1, True), (True, 1), (None, True)])
def test_both_unknown_outcome_and_possible_extra_charge_acknowledgements_are_explicit(unknown, unknown_ack, cost_ack):
    job, snapshot, original, destination, _, _, _, _, wire, *_ = unknown
    plan = retry.inspect(job, snapshot, original, destination, wire)
    with pytest.raises(ERRORS): retry.records(plan, plan['owner'], time.time(),
        acknowledged_unknown_outcome=unknown_ack, acknowledged_possible_extra_charge=cost_ack)


def test_one_new_captured_attempt_is_labelled_and_timestamps_are_captured_not_invented(unknown, monkeypatch):
    job, snapshot, original, _, connection, service, *_ = unknown
    authority = approve(unknown)
    before = hashes(job)
    child, saved, marker, store = adopt(unknown, authority)
    assert saved['provider_reexecution']['new_attempt'] is True
    assert saved['provider_reexecution']['attempt_number'] == 1
    assert retry.validate_checkpoint(child, 'mapper', saved, connection=connection) == marker
    assert retry.validate_owner(job, snapshot, original, connection) == authority
    assert all(hashes(job)[name] == digest for name, digest in before.items())
    monkeypatch.setattr(OciGenAiClient, '_client', lambda *a: pytest.fail('Read proof must not initialize provider auth'))
    monkeypatch.setattr('fox.oci_genai._now', lambda: pytest.fail('Read proof must use captured timestamps'))
    assert retry.validate_checkpoint(child, 'mapper', saved) == marker
    intent = read(next(store.root.glob('*.intent.json')))['payload']
    response = read(next(store.root.glob('*.response.json')))['payload']
    assert saved['invocation']['started_at_utc'] == intent['started_at_utc']
    assert saved['invocation']['completed_at_utc'] == response['completed_at_utc']
    assert len(service.calls) == 8


def test_receipt_store_loss_does_not_reset_independent_consumption_budget(unknown):
    job, _, _, _, connection, *_ = unknown
    authority = approve(unknown)
    consume(unknown, authority)
    assert not retry.paths(job)['receipts'].exists()
    with pytest.raises(ERRORS): retry.require_unconsumed(job, authority, connection)
    retry.paths(job)['consumed'].unlink()
    with pytest.raises(ERRORS): retry.require_unconsumed(job, authority, connection)


@pytest.mark.parametrize('change', ['approval-event', 'parent-event', 'followup-event', 'owner', 'source', 'unknown-intent', 'target'])
def test_current_owner_parent_chains_and_before_files_are_required(unknown, change):
    job, snapshot, original, _, connection, *_ = unknown
    authority = approve(unknown)
    if change.endswith('event'):
        action = {'approval-event': retry.EVENT, 'parent-event': parent.EVENT, 'followup-event': followup.EVENT}[change]
        connection.execute('DELETE FROM events WHERE action=?', (action,))
    elif change == 'owner': connection.execute('UPDATE projects SET owner=?', ('other-owner',))
    elif change == 'source': (job / 'prototype-pipeline/sources/source-000.xml').write_bytes(b'changed')
    elif change == 'unknown-intent': write(job / 'prototype-pipeline' / authority['plan']['pivot_focus_id'] / 'mapper-intent.json', {})
    else: write(job / 'prototype-pipeline' / authority['plan']['pivot_focus_id'] / 'mapper-target.json', {})
    with pytest.raises(ERRORS): retry.validate_owner(job, snapshot, original, connection)
    with pytest.raises(ERRORS): retry.require_unconsumed(job, authority, connection)


@pytest.mark.parametrize('change', ['consumed-file', 'consumed-event', 'consumed-duplicate', 'adoption-file',
    'adoption-event', 'mapper-label', 'mapper-output', 'invocation', 'environment', 'raw-response'])
def test_exact_checkpoint_marker_receipt_and_independent_latch_are_required(unknown, change):
    job, snapshot, original, _, connection, *_ = unknown
    authority = approve(unknown)
    child, saved, _, store = adopt(unknown, authority)
    if change == 'consumed-file': retry.paths(job)['consumed'].unlink()
    elif change == 'consumed-event': connection.execute('DELETE FROM events WHERE action=?', (retry.CONSUMED_EVENT,))
    elif change == 'consumed-duplicate': connection.execute('INSERT INTO events SELECT * FROM events WHERE action=?', (retry.CONSUMED_EVENT,))
    elif change == 'adoption-file': retry.paths(job)['adoption'].unlink()
    elif change == 'adoption-event': connection.execute('DELETE FROM events WHERE action=?', (retry.ADOPTION_EVENT,))
    elif change == 'raw-response':
        path = next(store.root.glob('*.response.json'))
        value = read(path)
        value['payload']['status'] = 503
        write(path, value)
    else:
        if change == 'mapper-label': saved.pop('provider_reexecution')
        elif change == 'mapper-output': saved['output']['blueprint']['claims'][0]['value'] = 'Changed'
        elif change == 'invocation': saved['invocation']['started_at_utc'] = '2026-01-01T00:00:00+00:00'
        else: saved['model_environment']['sdk_version'] = 'changed'
        write(child / 'mapper.json', saved)
    with pytest.raises(ERRORS): retry.validate_owner(job, snapshot, original, connection)


def test_invalid_captured_json_stays_invalid_and_does_not_authorize_another_attempt(unknown):
    job, _, _, _, connection, service, *_ = unknown
    authority = approve(unknown)
    capture(unknown, authority, malformed=True)
    with pytest.raises(ERRORS): retry.captured_checkpoint(job, authority)
    with pytest.raises(ERRORS): retry.require_unconsumed(job, authority, connection)
    assert not (job / 'prototype-pipeline' / authority['plan']['pivot_focus_id'] / 'mapper.json').exists()
    assert len(service.calls) == 8


def test_generic_pending_gate_still_stops_without_an_approved_new_result(unknown):
    job, _, _, _, _, service, _, _, _, options, _ = unknown
    before, calls = hashes(job), len(service.calls)
    with pytest.raises(OpafError): run_prototype_pipeline(job, [('example.xml', (job / 'prototype-pipeline/sources/source-000.xml').read_bytes())], **options)
    assert hashes(job) == before and len(service.calls) == calls


def test_legacy_non_job_role_is_unchanged_and_unbound_marker_is_rejected(tmp_path):
    directory = tmp_path / 'legacy-role'
    assert retry.validate_checkpoint(directory, 'mapper', {}) is None
    with pytest.raises(ERRORS): retry.validate_checkpoint(directory, 'mapper', {'provider_reexecution': {}})


def test_additional_attempt_limit_cannot_use_a_boolean_alias():
    plan = {'scope': retry.SCOPE, 'owner': 'owner', 'pivot_index': 3, 'additional_attempt_limit': True}
    with pytest.raises(ERRORS): retry.records(plan, 'owner', 1.0,
        acknowledged_unknown_outcome=True, acknowledged_possible_extra_charge=True)


@pytest.mark.parametrize('unknown', ['later-focus'], indirect=True)
def test_remaining_operations_include_only_unstarted_later_focus_roles(unknown):
    job, snapshot, original, destination, _, _, _, _, wire, *_ = unknown
    plan = retry.inspect(job, snapshot, original, destination, wire)
    focus = build_focus_plan([('example.xml', (job / 'prototype-pipeline/sources/source-000.xml').read_bytes())],
        expected_source_binding=plan['source_binding'], approved_chunk_hashes=plan['approved_chunk_hashes'], max_owned_objects=32)
    assert plan['remaining_operations'][:3] == [
        {'focus_id': focus['requests'][3]['focus_id'], 'role': 'reviewer'},
        {'focus_id': focus['requests'][4]['focus_id'], 'role': 'mapper'},
        {'focus_id': focus['requests'][4]['focus_id'], 'role': 'reviewer'}]


@pytest.mark.parametrize('name', ['reviewer-intent.json', 'reviewer.json'])
def test_initial_inspection_rejects_any_fourth_review_work(unknown, name):
    job, snapshot, original, destination, _, _, _, _, wire, *_ = unknown
    child = next(path.parent for path in (job / 'prototype-pipeline').glob('focus-*/mapper-intent.json')
                 if not (path.parent / 'mapper.json').exists())
    write(child / name, {})
    with pytest.raises(ERRORS): retry.inspect(job, snapshot, original, destination, wire)
