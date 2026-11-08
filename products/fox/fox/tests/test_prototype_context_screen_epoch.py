"""Local API/worker screen-only recovery; all provider/stage replies authored.

No actual OPAF/Oracle/production adoption or business acceptance is claimed.
"""
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from fox import prototype_context_screen_epoch as screen, prototype_mapping_epochs as epochs
from fox import prototype_partition_review_epoch as partition, prototype_container_epoch as container
from fox import prototype_job, prototype_result_publication as publication
from fox.opaf import OpafError, canonical_hash
from test_prototype_partition_review_epoch import (partition_case, next_body as partition_body, process,
    container_case, container_source_model, clause_case, epochs_case, tmp_path, client, settings,
    no_external_actions, api)
from test_prototype_pipeline import PROFILE


def files(job):
    return {p.relative_to(job).as_posix(): p.read_bytes() for p in job.rglob('*') if p.is_file()}


@pytest.fixture
def screen_case(partition_case, monkeypatch):
    case = partition_case
    _, old_body = partition_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=old_body).status_code == 202
    job, snapshot, target = case[4], case[5], case[10]['target_profile']
    packet, plan = epochs.reconstruct(job, snapshot, (job / 'source-snapshot.json').read_bytes(), target)
    request = plan['requests'][8]
    original = case[7].invoke
    def context_screen_only(role, payload):
        output, invocation = original(role, payload)
        if role == PROFILE['mapper'] and payload.get('focus_id') == request['focus_id']:
            owned = {row['id'] for row in request['owned_objects']}
            output['blueprint']['objects'] = [row for row in output['blueprint']['objects'] if row['source_object_id'] in owned]
            output['blueprint']['claims'] = [row for row in output['blueprint']['claims'] if row['source_object_id'] in owned]
            # Authored saved9 must reproduce the ACTUAL source-fact-clean stop,
            # not the older fixture's unrelated metadata-alias repair path.
            for claim in output['blueprint']['claims']:
                if claim['kind'] == 'object.item_type': claim['kind'] = 'item.item_type'
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(case[7], 'invoke', context_screen_only)
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'ATTENTION', errors
    assert not (job / partition.RESULT_BASE / 'publication.json').exists()
    directory = job / 'prototype-pipeline' / partition.PREFIX / request['focus_id']
    assert {p.name for p in directory.iterdir()} == {'mapper' + s for s in ('-request.json', '-target.json', '-intent.json', '.json')}
    assert len(epochs.read(directory / 'mapper.json')['output']['blueprint']['screens']) == 1
    return case, old_body


def next_body(item):
    case = item[0] if isinstance(item[0], tuple) else item
    response = case[0].get(api(case))
    assert response.status_code == 200, response.text
    plan = response.json()
    return plan, {**case[6], 'checkpoint_sha256': plan['checkpoint_sha256'],
        'expected_epoch_number': plan['epoch_number'], 'expected_predecessor_sha256': plan['predecessor_sha256'],
        'expected_screen_projection_sha256': plan['expected_screen_projection_sha256']}


def test_six_reuses_raw_mapper9_reviews_first_and_preserves_absent_fifth_publication(screen_case, monkeypatch):
    from fox.prototype_download import retained_export_request
    case, old_body = screen_case
    c, _, _, rid, job, snapshot, _, model, _, db, envelope = case
    before, calls = files(job), deepcopy(model.calls)
    old_four = epochs.read(job / container.RECORD)
    old_four_binding = publication._validate_historical_four_publication(job, old_four)
    old = epochs.read(job / partition.RECORD)
    request = epochs.reconstruct(job, snapshot, (job / 'source-snapshot.json').read_bytes(), envelope['target_profile'])[1]['requests'][8]
    raw_path = job / 'prototype-pipeline' / partition.PREFIX / request['focus_id'] / 'mapper.json'
    # Existing5 duplicate is a true no-op, never a row reset/requeue.
    duplicate = c.post(api(case, 'mapping-epochs'), json=old_body)
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()['state'] == 'ATTENTION' and files(job) == before and model.calls == calls
    # The normal full5 chain still rejects its compact duplicate: no global bypass.
    with db() as connection:
        with pytest.raises((OpafError, ValueError)):
            epochs.validate_epoch_chain(job, snapshot, (job / 'source-snapshot.json').read_bytes(), connection)
    plan, body = next_body(screen_case)
    assert plan['epoch_number'] == 6 and plan['strategy'] == screen.STRATEGY
    assert [plan[k] for k in ('ai_approved_focuses', 'source_checked_focuses', 'saved_mapping_focuses',
        'saved_mapping_source_checked', 'projected_context_screens', 'new_corrective_model_calls',
        'repeated_mapper_calls', 'repeated_reviewer_calls')] == [8, 8, 1, True, 1, 1, 0, 0]
    assert plan['remaining_focus_count'] == plan['unstarted_focus_count'] + 1
    assert plan['planned_corrective_operations'] == ['review_saved_projection']
    assert not set(plan) & {'expected_partition_proof_sha256', 'expected_container_proof_sha256', 'expected_clause_proof_sha256', 'reused_review_focuses'}
    assert files(job) == before
    queued = c.post(api(case, 'mapping-epochs'), json=body)
    assert queued.status_code == 202, queued.text
    assert c.post(api(case, 'mapping-epochs'), json=body).status_code == 200
    assert c.post(api(case, 'mapping-epochs'), json=old_body).status_code == 409
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
    new = model.calls[len(calls):]
    assert new[0][0] == 'reviewer' and new[0][1]['request']['focus_id'] == request['focus_id']
    assert new[0][1]['candidate']['blueprint']['screens'] == []
    assert new[1][0] == 'mapper' and new[1][1]['focus_id'] != request['focus_id']
    assert len([role for role, _ in new if role == 'mapper']) == plan['unstarted_focus_count']
    assert raw_path.read_bytes() == before[raw_path.relative_to(job).as_posix()]
    assert all((job / name).read_bytes() == raw for name, raw in before.items() if name != 'prototype-result.json')
    assert (job / screen.RESULT_BASE / 'previous-result.json').read_bytes() == before['prototype-result.json']
    assert not (job / partition.RESULT_BASE / 'publication.json').exists()
    assert publication._validate_historical_four_publication(job, old_four) == old_four_binding
    result = epochs.read(job / 'prototype-result.json')
    record = epochs.read(job / screen.RECORD)
    assert result['mapping_epoch_sha256'] == canonical_hash(record)
    assert publication.validate_publication(job, record)['status'] == 'APEX_GENERATED'
    index = epochs.read(job / 'prototype-pipeline/review-index.json')
    assert index['focuses'][8]['kind'] == 'REVIEWED_CONTEXT_SCREEN_PROJECTION'
    assert index['focuses'][8]['retained_mapper_directory'].startswith(partition.PREFIX)
    with db() as connection:
        assert connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM events WHERE action=?', (epochs.EVENT,)).fetchone()[0] == 5
        epochs.validate_epoch_chain(job, snapshot, (job / 'source-snapshot.json').read_bytes(), connection)
    retained_export_request(job, snapshot, envelope)
