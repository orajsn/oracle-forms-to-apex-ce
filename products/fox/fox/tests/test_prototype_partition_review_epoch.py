"""Actual local same-run API/worker; all provider/Oracle responses authored.

No production adoption, inference, Oracle write or business acceptance claim.
"""
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from fox import prototype_partition_review_epoch as partition, prototype_mapping_epochs as epochs
from fox import prototype_container_epoch as container, prototype_job, worker
from fox import prototype_result_publication as publication
from fox.opaf import OpafError, canonical_hash
from fox.prototype_partition_review import build_partition_review_task, TASK_SCOPE
from fox.prototype_partition_review_proof import FILES, FORMATTER_SHA256
from fox.forms_design_review import validate_design_review
from test_prototype_container_epoch import (container_case, container_source_model, next_body as container_body, process,
    clause_case, epochs_case, tmp_path, client, settings, no_external_actions, api)
from test_prototype_clause_proof import write
from test_prototype_partition_review_proof import checkpoint, review


def stage(case):
    job, snapshot, target = case[4], case[5], case[10]['target_profile']
    raw = (job / 'source-snapshot.json').read_bytes()
    packet, plan = epochs.reconstruct(job, snapshot, raw, target)
    predecessor = epochs.read(job / container.RECORD)
    views, rejected, request, receipt = partition._historical(job / 'prototype-pipeline', packet, plan, target, predecessor)
    pins = {'request_sha256': canonical_hash(request), 'receipt_sha256': canonical_hash(receipt),
            'output_sha256': canonical_hash(receipt['output'])}
    task, audit = build_partition_review_task(packet, plan, [view['candidate'] for view in views] + [rejected['candidate']],
        container._refs(plan, views, target), expected_target_sha256=canonical_hash(target),
        expected_candidate_sha256=canonical_hash(rejected['candidate']),
        historical_review={'request': request, 'receipt': receipt, 'target_profile': target},
        expected_history_pins=pins, review_context=request['review_context'])
    original_files = {path.relative_to(job).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in job.rglob('*') if path.is_file()}
    base = partition._stage(job)
    for directory in (base.parent, base, base / 'json', base / 'json/review'):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
    candidate = rejected['candidate']
    output = review(plan['requests'][7], candidate, True)
    saved = checkpoint(target, task, output, {'job_id': job.name, 'source_hash': packet['source_binding']},
        'authored-distinct-retained-compact-review', 6)
    checked = validate_design_review(plan['requests'][7], candidate, output)
    intent = {'schema_version': 1, 'scope': 'one-unadopted-compact-partition-review', 'job_id': job.name,
        'source_binding': packet['source_binding'], 'target_profile_sha256': canonical_hash(target),
        'module_sha256': FORMATTER_SHA256, 'candidate_sha256': canonical_hash(candidate),
        'original_request_sha256': canonical_hash(request), 'new_request_sha256': canonical_hash(task),
        'prior_review_receipt_sha256': canonical_hash(receipt), 'original_files_sha256': canonical_hash(original_files),
        'maximum_new_model_calls': 1, 'generation_calls': 0, 'automatic_retry': False,
        'production_run_resumed': False, 'proposal_adopted': False}
    values = {'diagnostic-intent.json': intent, 'original-files.json': original_files, 'review-request.json': task,
        'full-audit-context.json': audit, 'review-receipt.json': checked, 'review/reviewer-target.json': target,
        'review/reviewer-intent.json': saved['binding'], 'review/reviewer.json': saved, 'result.json': {**intent,
            'status': 'COMPACT_PARTITION_REVIEW_COMPLETED_UNADOPTED', 'structured_review_valid': True,
            'review_verdict': 'APPROVED', 'review_approved': True, 'review_room_id': saved['invocation']['room_id'],
            'review_output_sha256': canonical_hash(output), 'finding_codes': [],
            'original_job_files_unchanged': len(original_files), 'apex_imported': False, 'business_behavior_accepted': False}}
    for name, value in values.items(): write(base / 'json', name, value)
    manifest = {name: {'sha256': hashlib.sha256((base / 'json' / name).read_bytes()).hexdigest(),
        'bytes': (base / 'json' / name).stat().st_size} for name in FILES}
    descriptor = {'schema_version': 1, 'scope': partition.STAGING_SCOPE, 'job_id': job.name,
        'project_id': snapshot['project_id'], 'owner': snapshot['approvals']['owner'],
        'snapshot_sha256': hashlib.sha256(raw).hexdigest(), 'source_hash': snapshot['source_hash'],
        'source_binding': packet['source_binding'], 'original_target_sha256': canonical_hash(target),
        'predecessor_sha256': canonical_hash(predecessor), 'formatter_sha256': FORMATTER_SHA256,
        'original_manifest': manifest, 'original_manifest_sha256': canonical_hash(manifest),
        'original_files': original_files, 'original_files_sha256': canonical_hash(original_files),
        'candidate_sha256': canonical_hash(candidate), 'review_task_sha256': canonical_hash(task),
        'expected_history_pins': pins}
    write(base, 'descriptor.json', descriptor)
    return descriptor


@pytest.fixture
def partition_case(container_case, monkeypatch):
    case = container_case
    _, body = container_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    case[7].changes_role = True
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'ATTENTION', errors
    case[7].changes_role = None
    assert epochs.read(case[4] / 'prototype-result.json')['status'] == 'CHANGES_REQUIRED'
    stage(case)
    return case


def next_body(case):
    response = case[0].get(api(case))
    assert response.status_code == 200, response.text
    plan = response.json()
    return plan, {**case[6], 'checkpoint_sha256': plan['checkpoint_sha256'],
        'expected_epoch_number': plan['epoch_number'], 'expected_predecessor_sha256': plan['predecessor_sha256'],
        'expected_partition_proof_sha256': plan['expected_partition_proof_sha256']}


def test_explicit_five_reuses_eight_reviews_then_first_new_mapper_and_preserves_old_four_history(partition_case, monkeypatch):
    from fox.prototype_download import retained_export_request
    case = partition_case
    job = case[4]
    before = {path.relative_to(job).as_posix(): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    old_four = epochs.read(job / container.RECORD)
    old_publication = publication.validate_publication(job, old_four)
    old_views = []
    packet, plan_all = epochs.reconstruct(job, case[5], (job / 'source-snapshot.json').read_bytes(), case[10]['target_profile'])
    for request in plan_all['requests'][:7]:
        old_views.append(container.active_focus(job / 'prototype-pipeline', packet, plan_all, request,
            case[10]['target_profile'], old_views, old_four))
    calls = deepcopy(case[7].calls)
    plan, body = next_body(case)
    assert plan['epoch_number'] == 5 and plan['strategy'] == partition.STRATEGY
    assert (plan['ai_approved_focuses'], plan['source_checked_focuses'], plan['source_fact_violations']) == (8, 8, 0)
    assert plan['planned_corrective_operations'] == []
    assert [plan[key] for key in ('reused_review_focuses', 'new_corrective_model_calls', 'repeated_mapper_calls', 'repeated_reviewer_calls')] == [1, 0, 0, 0]
    assert not set(plan) & {'expected_clause_proof_sha256', 'expected_container_proof_sha256', 'analysis_role', 'corrective_projection_review_calls'}
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 200
    row, errors = process(case, monkeypatch)
    assert row['state'] == 'GENERATED', '\n'.join(errors) or row['message']
    new = case[7].calls[len(calls):]
    assert new[0][0] == 'mapper' and new[0][1]['focus_id'] == plan_all['requests'][8]['focus_id']
    assert len([role for role, _ in new if role == 'mapper']) == plan['remaining_focus_count']
    assert all(payload['scope'] == TASK_SCOPE and payload['historical_allegations'] is None
        and len(__import__('json').dumps(payload, ensure_ascii=False).encode()) <= 500_000
        for role, payload in new if role == 'reviewer')
    index = epochs.read(job / 'prototype-pipeline/review-index.json')
    assert index['focuses'][:7] == [view['proof'] for view in old_views]
    assert index['focuses'][7]['kind'] == 'RETAINED_COMPACT_PARTITION_REVIEW'
    assert 'mapper_invocation' not in index['focuses'][7]
    assert all((job / name).read_bytes() == raw for name, raw in before.items() if name != 'prototype-result.json')
    assert (job / partition.RESULT_BASE / 'previous-result.json').read_bytes() == before['prototype-result.json']
    assert publication._validate_historical_four_publication(job, old_four) == old_publication
    assert (job / old_publication['history_path']).read_bytes() == before[old_publication['history_path']]
    record = epochs.read(job / partition.RECORD)
    assert publication.validate_publication(job, record)['status'] == 'APEX_GENERATED'
    with case[9]() as db:
        epochs.validate_epoch_chain(job, case[5], (job / 'source-snapshot.json').read_bytes(), db)
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM events WHERE action=?', (epochs.EVENT,)).fetchone()[0] == 4
    retained_export_request(job, case[5], case[10])


@pytest.mark.parametrize('mutation', ['proof', 'source', 'consent', 'predecessor', 'checkpoint', 'formatter', 'candidate', 'task', 'member', 'old-history'])
def test_bad_proof_or_scope_fails_before_configuration(partition_case, mutation):
    case = partition_case
    _, body = next_body(case)
    calls = deepcopy(case[7].calls)
    keys = {'proof': 'expected_partition_proof_sha256', 'source': 'source_hash', 'consent': 'approved_external_ai',
        'predecessor': 'expected_predecessor_sha256', 'checkpoint': 'checkpoint_sha256'}
    if mutation in keys: body[keys[mutation]] = False if mutation == 'consent' else '0' * 64
    elif mutation == 'member':
        with (partition._stage(case[4]) / 'json/review-request.json').open('ab') as stream: stream.write(b' ')
    elif mutation == 'old-history':
        old = epochs.read(case[4] / container.RESULT_BASE / 'publication.json')
        (case[4] / old['history_path']).unlink()
    else:
        value = epochs.read(partition._stage(case[4]) / 'descriptor.json')
        value[{'formatter': 'formatter_sha256', 'candidate': 'candidate_sha256', 'task': 'review_task_sha256'}[mutation]] = '0' * 64
        write(partition._stage(case[4]), 'descriptor.json', value)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409
    assert not (case[4] / partition.RECORD).exists() and case[7].calls == calls


def test_matching_concurrent_posts_queue_once_and_orphan_blocks(partition_case):
    from concurrent.futures import ThreadPoolExecutor
    case = partition_case
    _, body = next_body(case)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: case[0].post(api(case, 'mapping-epochs'), json=body), range(2)))
    assert sorted(row.status_code for row in results) == [200, 202]
    with case[9]() as db:
        assert db.execute('SELECT COUNT(*) FROM events WHERE object_id LIKE ?', (case[3] + ':epoch:000005:%',)).fetchone()[0] == 1
        db.execute('DELETE FROM events WHERE object_id LIKE ?', (case[3] + ':epoch:000005:%',))
    assert case[0].get(api(case)).status_code == 409
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 409


@pytest.mark.parametrize('mutation', ['archive4', 'publication4', 'history4', 'unknown-history', 'future-call', 'repeated-eight', 'unknown-head', 'context'])
def test_postqueue_history_context_or_orphan_work_blocks_before_configuration(partition_case, monkeypatch, mutation):
    case = partition_case
    _, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    job = case[4]
    if mutation in ('archive4', 'publication4'):
        (job / container.RESULT_BASE / ('previous-result.json' if mutation == 'archive4' else 'publication.json')).unlink()
    elif mutation == 'history4':
        old = epochs.read(job / container.RESULT_BASE / 'publication.json'); (job / old['history_path']).unlink()
    elif mutation == 'unknown-history': write(job, 'prototype-results/' + '0' * 64 + '.json', {})
    elif mutation == 'unknown-head': write(job, 'mapping-epochs/epoch-000006.json', {})
    elif mutation == 'context': write(job, 'prototype-pipeline/' + partition.PREFIX + '/partition-proof/full-audit-context.json', {})
    else:
        _, plan = epochs.reconstruct(job, case[5], (job / 'source-snapshot.json').read_bytes(), case[10]['target_profile'])
        request = plan['requests'][7 if mutation == 'repeated-eight' else -1]
        write(job, 'prototype-pipeline/' + partition.PREFIX + '/' + request['focus_id'] + '/mapper-intent.json', {})
    configured, calls = [], deepcopy(case[7].calls)
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: configured.append(True))
    with pytest.raises((OpafError, ValueError, OSError, KeyError)):
        prototype_job.run_prototype_job(job, approval_check=lambda _: True)
    assert configured == [] and case[7].calls == calls


@pytest.mark.parametrize('crash', ['history', 'binding'])
def test_interrupted_five_publication_never_replays(partition_case, monkeypatch, crash):
    case = partition_case
    _, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    before = (case[4] / 'prototype-result.json').read_bytes()
    with monkeypatch.context() as failure:
        if crash == 'history':
            original = epochs.save
            def save(path, *args, **kwargs):
                if Path(path).name == 'publication.json': raise OSError('Authored interrupted binding')
                return original(path, *args, **kwargs)
            failure.setattr(epochs, 'save', save)
        else:
            failure.setattr(publication.os, 'replace', lambda *args: (_ for _ in ()).throw(OSError('Authored interrupted pointer')))
        row, _ = process(case)
    assert row['state'] == 'ATTENTION'
    assert (case[4] / 'prototype-result.json').read_bytes() == before
    calls, configured = deepcopy(case[7].calls), []
    monkeypatch.setattr(prototype_job, '_configuration', lambda *args, **kwargs: configured.append(True))
    with pytest.raises((OpafError, ValueError)):
        prototype_job.run_prototype_job(case[4], approval_check=lambda _: True)
    assert configured == [] and case[7].calls == calls
