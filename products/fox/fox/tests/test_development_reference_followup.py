"""Synthetic third-focus continuation proofs; no live model, cloud or Oracle."""
import json
import os

import pytest

from fox import prototype_development_reference_followup as followup
from fox import prototype_development_reference_resume as parent
from fox.design_provider import roles
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.oci_genai import OciGenAiClient
from fox.opaf import canonical_hash
from fox.prototype_job import validate_prototype_snapshot
from fox.prototype_pipeline import run_prototype_pipeline
from test_development_reference_resume import (ERRORS, hashes, install as install_parent,
                                               read, retained, write)
from test_oci_genai import fake_sdk


@pytest.fixture
def stopped(retained, request):
    job, snapshot, original, destination, connection, service = retained
    parent_plan, parent_technical, parent_owner = install_parent(retained)
    docs = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    focus = build_focus_plan(docs, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=32)
    assert len(focus['requests']) >= 3
    pivot_id = focus['requests'][2]['focus_id']
    unprojected_second = getattr(request, 'param', None) == 'unprojected-second'
    def combined_third(body):
        request = json.loads(service.calls[-1][0]['chat_request']['messages'][1]['content'][0]['text'])
        if 'candidate' in request:
            return
        if unprojected_second and request['focus_id'] == focus['requests'][1]['focus_id']:
            return
        part = body['chat_response']['choices'][0]['message']['content'][0]
        output = json.loads(part['text'])
        chunk = request['chunks'][0]
        unit = next(row for row in request['code_units'] if row['id'] == chunk['code_unit_id'])
        output['blueprint']['claims'] = [{'id': 'intent-' + request['focus_id'],
            'source_object_id': unit['owner_id'], 'kind': 'behavior.intent', 'status': 'proposal',
            'value': 'Keep exact source behavior proposal 123.', 'reason': 'Independent review required.',
            'evidence_refs': [unit['owner_id'], chunk['id']]}]
        if request['focus_id'] == pivot_id:
            output['source_binding'] = request['source_binding']
            if unprojected_second:
                claim = output['blueprint']['claims'][0]
                output['blueprint']['claims'] = [{**claim, 'id': claim['id'] + '-' + str(i)} for i in range(8)]
        part['text'] = json.dumps(output)
    service.alter = combined_third
    client = OciGenAiClient(destination, client=service, sdk=fake_sdk())
    with pytest.raises(ValueError):
        run_prototype_pipeline(job, docs, project_id=snapshot['project_id'],
            project_name=snapshot['project_name'], expected_source_binding=selected['source_binding'],
            approved_chunk_hashes=selected['approved_chunk_hashes'], approved_policy_id=selected['approved_policy_id'],
            opaf_client=client, profile=roles(destination), target_profile_loader=lambda: destination,
            processing_approval_check=lambda *_: True, delivery_mode='apexlang_package',
            focus_schema_version=selected['schema_version'], metadata_task_policy=selected.get('metadata_task_policy'),
            development_processing_sha256=selected['development_processing_sha256'])
    assert len(service.calls) == 5
    assert parent.validate_owner(job, snapshot, original, connection) == parent_owner
    assert read(job / 'prototype-pipeline' / parent.TECHNICAL) == parent_technical
    yield job, snapshot, original, destination, connection, service, focus


def install(value):
    job, snapshot, original, destination, connection, *_ = value
    plan = followup.inspect(job, snapshot, original, destination)
    technical, owner = followup.records(plan, snapshot['approvals']['owner'], 20.0)
    write(job / 'prototype-pipeline' / followup.TECHNICAL, technical)
    write(job / followup.OWNER_RECORD, owner)
    connection.execute('INSERT INTO events VALUES(?,?,?,?)',
        (owner['owner'], followup.EVENT, job.name + ':' + canonical_hash(owner), owner['approved_at']))
    return plan, technical, owner


def test_exact_two_focus_prefix_and_third_mapper_are_pinned_without_replay(stopped):
    job, snapshot, original, destination, connection, service, focus = stopped
    before = hashes(job)
    assert followup.validate_owner(job, snapshot, original, connection) is None
    plan = followup.inspect(job, snapshot, original, destination)
    assert followup.inspect(job, snapshot, original, destination) == plan
    assert plan['before_files'] == before and hashes(job) == before
    assert len(service.calls) == 5
    assert plan['pivot_index'] == 2 and plan['pivot_focus_id'] == focus['requests'][2]['focus_id']
    assert len(plan['prefix_proofs_sha256']) == 2
    assert plan['projection_claim_count'] == 1
    assert plan['remaining_operations'] == [
        {'focus_id': plan['pivot_focus_id'], 'role': 'reviewer'},
        {'stage': 'render'}, {'stage': 'offline_validate'}, {'stage': 'package'}]
    assert plan['parent_technical_sha256'] == canonical_hash(read(job / 'prototype-pipeline' / parent.TECHNICAL))
    assert plan['parent_owner_sha256'] == canonical_hash(read(job / parent.OWNER_RECORD))
    assert plan['parent_event_id'] == job.name + ':' + plan['parent_owner_sha256']
    for original_body in ('APP.START', 'TriggerText', 'evidence_refs', 'Keep exact source', 'blueprint'):
        assert original_body not in json.dumps(plan)


def test_child_and_parent_exact_records_validate_without_recursive_dispatch(stopped):
    job, snapshot, original, _, connection, service, _ = stopped
    plan, technical, owner = install(stopped)
    assert parent.validate_owner(job, snapshot, original, connection)
    assert parent.technical(job / 'prototype-pipeline')
    assert followup.technical(job / 'prototype-pipeline') == technical
    assert followup.validate_owner(job, snapshot, original, connection) == owner
    assert len(service.calls) == 5
    assert followup.records(plan, owner['owner'], owner['approved_at']) == (technical, owner)
    assert 'approvals' not in owner and 'redacted_source' not in owner
    assert owner['parent_event_id'] == plan['parent_event_id']


@pytest.mark.parametrize('retained', ['metadata'], indirect=True)
@pytest.mark.parametrize('stopped', ['unprojected-second'], indirect=True)
def test_actual_shape_seals_all_36_files_with_metadata_and_unprojected_second_focus(stopped):
    job, snapshot, original, _, connection, service, focus = stopped
    plan, technical, owner = install(stopped)
    assert len(plan['before_files']) == 36
    assert plan['projection_claim_count'] == 8
    assert len(service.calls) == 5
    assert followup.validate_owner(job, snapshot, original, connection) == owner
    assert followup.technical(job / 'prototype-pipeline') == technical
    assert not (job / 'prototype-pipeline' / focus['requests'][1]['focus_id'] / 'projection-receipt.json').exists()


@pytest.mark.parametrize('part', ['parent-owner', 'parent-technical', 'parent-event', 'parent-event-duplicate'])
def test_parent_record_or_event_loss_prevents_new_admission(stopped, part):
    job, snapshot, original, destination, connection, *_ = stopped
    if part == 'parent-owner': (job / parent.OWNER_RECORD).unlink()
    elif part == 'parent-technical': (job / 'prototype-pipeline' / parent.TECHNICAL).unlink()
    elif part == 'parent-event': connection.execute('DELETE FROM events WHERE action=?', (parent.EVENT,))
    else: connection.execute('INSERT INTO events SELECT * FROM events WHERE action=?', (parent.EVENT,))
    with pytest.raises(ERRORS): followup.validate_owner(job, snapshot, original, connection)
    if 'event' not in part:
        with pytest.raises(ERRORS): followup.inspect(job, snapshot, original, destination)


@pytest.mark.parametrize('change', ['pivot-reviewer-intent', 'pivot-reviewer-result', 'later-focus-dir',
    'result', 'package', 'unknown', 'prefix-unknown', 'parent-tamper', 'prefix-reviewer-missing',
    'prefix-unapproved', 'pivot-result-missing', 'pivot-intent', 'pivot-request'])
def test_initial_plan_rejects_incomplete_competing_or_unapproved_work(stopped, change):
    job, snapshot, original, destination, _, _, focus = stopped
    root = job / 'prototype-pipeline'
    pivot = root / focus['requests'][2]['focus_id']
    first = root / focus['requests'][0]['focus_id']
    if change == 'pivot-reviewer-intent': write(pivot / 'reviewer-intent.json', {})
    elif change == 'pivot-reviewer-result': write(pivot / 'reviewer.json', {})
    elif change == 'later-focus-dir': (root / ('focus-' + 'f' * 24)).mkdir()
    elif change == 'result': write(job / 'prototype-result.json', {})
    elif change == 'package': write(root / 'package-request.json', {})
    elif change == 'unknown': write(job / 'unknown.json', {})
    elif change == 'prefix-unknown': write(first / 'mapper-resolved.json', {})
    elif change == 'parent-tamper':
        owner = read(job / parent.OWNER_RECORD)
        owner['approved_at'] = 11.0
        write(job / parent.OWNER_RECORD, owner)
        # The pure plan can bind this valid parent shape, but its exact event
        # validation must still reject the changed parent at admission.
        with pytest.raises(ERRORS): followup.validate_owner(job, snapshot, original, stopped[4])
        return
    elif change == 'prefix-reviewer-missing': (first / 'reviewer.json').unlink()
    elif change == 'prefix-unapproved':
        reviewer = read(first / 'reviewer.json')
        reviewer['output']['verdict'] = 'CHANGES_REQUIRED'
        reviewer['output_sha256'] = canonical_hash(reviewer['output'])
        write(first / 'reviewer.json', reviewer)
    elif change == 'pivot-result-missing': (pivot / 'mapper.json').unlink()
    elif change == 'pivot-intent': write(pivot / 'mapper-intent.json', {})
    else: write(pivot / 'request.json', {})
    with pytest.raises(ERRORS): followup.inspect(job, snapshot, original, destination)


@pytest.mark.parametrize('change', ['missing-echo', 'wrong-echo', 'missing-chunk', 'unknown-ref', 'extra-key'])
def test_pivot_requires_both_exact_echo_and_inner_chunk_changes(stopped, change):
    job, snapshot, original, destination, _, _, focus = stopped
    child = job / 'prototype-pipeline' / focus['requests'][2]['focus_id']
    mapper = read(child / 'mapper.json')
    raw = mapper['output']
    if change == 'missing-echo': raw.pop('source_binding')
    elif change == 'wrong-echo': raw['source_binding'] = 'f' * 64
    elif change == 'missing-chunk':
        raw['blueprint']['claims'][0]['evidence_refs'][1] = focus['requests'][2]['chunks'][0]['code_unit_id']
    elif change == 'unknown-ref': raw['blueprint']['claims'][0]['evidence_refs'][1] = 'invented-ref'
    else: raw['unexpected'] = True
    mapper['output_sha256'] = canonical_hash(raw)
    write(child / 'mapper.json', mapper)
    with pytest.raises(ERRORS): followup.inspect(job, snapshot, original, destination)


@pytest.mark.parametrize('change', ['owner-missing', 'technical-missing', 'event-missing', 'event-orphan',
    'event-duplicate', 'event-owner', 'event-time', 'event-hash', 'parent-event-missing',
    'parent-owner-tamper', 'current-owner', 'snapshot', 'prefix-proof', 'pivot-mapper', 'before-files'])
def test_durable_validation_rejects_lost_or_changed_child_parent_and_originals(stopped, change):
    job, snapshot, original, _, connection, _, focus = stopped
    _, technical, owner = install(stopped)
    if change == 'owner-missing': (job / followup.OWNER_RECORD).unlink()
    elif change == 'technical-missing': (job / 'prototype-pipeline' / followup.TECHNICAL).unlink()
    elif change == 'event-missing': connection.execute('DELETE FROM events WHERE action=?', (followup.EVENT,))
    elif change == 'event-orphan':
        (job / followup.OWNER_RECORD).unlink()
        (job / 'prototype-pipeline' / followup.TECHNICAL).unlink()
    elif change == 'event-duplicate':
        connection.execute('INSERT INTO events SELECT * FROM events WHERE action=?', (followup.EVENT,))
    elif change in ('event-owner', 'event-time', 'event-hash'):
        column, value = {'event-owner': ('owner', 'other-owner'), 'event-time': ('created', 21.0),
                         'event-hash': ('object_id', job.name + ':wrong')}[change]
        connection.execute('UPDATE events SET ' + column + '=? WHERE action=?', (value, followup.EVENT))
    elif change == 'parent-event-missing': connection.execute('DELETE FROM events WHERE action=?', (parent.EVENT,))
    elif change == 'parent-owner-tamper':
        value = read(job / parent.OWNER_RECORD)
        value['approved_at'] = 11.0
        write(job / parent.OWNER_RECORD, value)
    elif change == 'current-owner': connection.execute('UPDATE projects SET owner=?', ('other-owner',))
    elif change == 'snapshot': snapshot['project_name'] = 'Changed'
    elif change == 'prefix-proof':
        value = read(job / 'prototype-pipeline' / focus['requests'][1]['focus_id'] / 'projection-receipt.json')
        value['independent_review_required'] = False
        write(job / 'prototype-pipeline' / focus['requests'][1]['focus_id'] / 'projection-receipt.json', value)
    elif change == 'pivot-mapper':
        value = read(job / 'prototype-pipeline' / focus['requests'][2]['focus_id'] / 'mapper.json')
        value['output']['blueprint']['claims'][0]['value'] = 'Changed business value'
        value['output_sha256'] = canonical_hash(value['output'])
        write(job / 'prototype-pipeline' / focus['requests'][2]['focus_id'] / 'mapper.json', value)
    else:
        technical['plan']['before_files'].clear()
        write(job / 'prototype-pipeline' / followup.TECHNICAL, technical)
    with pytest.raises(ERRORS): followup.validate_owner(job, snapshot, original, connection)


def test_fixed_pivot_survives_normal_future_files_without_changing_prefix(stopped):
    job, snapshot, original, destination, connection, service, focus = stopped
    plan, technical, owner = install(stopped)
    root = job / 'prototype-pipeline'
    child = root / plan['pivot_focus_id']
    from fox.prototype_reference_echo import project
    docs = validate_prototype_snapshot(snapshot)
    candidate, receipt = project(docs, local_packet(docs), focus['requests'][2],
        read(child / 'mapper.json')['output'], destination)
    write(child / 'projection-candidate.json', candidate)
    write(child / 'projection-receipt.json', receipt)
    write(child / 'reviewer-intent.json', {'synthetic': 'only file closure, not review acceptance'})
    for name in parent._FUTURE_ROOT:
        write(root / name, {})
    result = {'synthetic': True, 'business_behavior_accepted': False}
    write(job / 'prototype-result.json', result)
    write(job / 'prototype-results' / (canonical_hash(result) + '.json'), result)
    assert followup.technical(root) == technical
    assert followup.validate_owner(job, snapshot, original, connection) == owner
    assert len(service.calls) == 5
    assert all(hashes(job)[name] == digest for name, digest in plan['before_files'].items())
    receipt['independent_review_required'] = False
    write(child / 'projection-receipt.json', receipt)
    with pytest.raises(ERRORS): followup.technical(root)


@pytest.mark.parametrize('name', ['epochs', 'unknown.json', 'prepare_schema.json', 'import-intent.json'])
def test_new_unknown_or_database_files_are_rejected(stopped, name):
    job, *_ = stopped
    install(stopped)
    write(job / 'prototype-pipeline' / name, {})
    with pytest.raises(ERRORS): followup.technical(job / 'prototype-pipeline')


def test_approved_prefix_cannot_gain_extra_derived_files(stopped):
    job, _, _, _, _, _, focus = stopped
    install(stopped)
    write(job / 'prototype-pipeline' / focus['requests'][1]['focus_id'] / 'mapper-resolution.json', {})
    with pytest.raises(ERRORS): followup.technical(job / 'prototype-pipeline')


def test_hardlinked_pivot_is_rejected(stopped, tmp_path):
    job, snapshot, original, destination, _, _, focus = stopped
    path = job / 'prototype-pipeline' / focus['requests'][2]['focus_id'] / 'mapper.json'
    os.link(path, tmp_path / 'pivot-hardlink')
    with pytest.raises(ERRORS): followup.inspect(job, snapshot, original, destination)


@pytest.mark.parametrize('approved_at', [True, 0, -1, float('nan'), float('inf')])
def test_approval_time_is_strict(stopped, approved_at):
    job, snapshot, original, destination, *_ = stopped
    plan = followup.inspect(job, snapshot, original, destination)
    with pytest.raises(ERRORS): followup.records(plan, plan['owner'], approved_at)
