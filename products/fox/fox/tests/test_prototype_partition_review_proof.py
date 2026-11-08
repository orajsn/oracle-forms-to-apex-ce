"""Authored synthetic retained-review bytes, not real provider/Oracle proof."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from fox import prototype_partition_review as formatter
from fox import prototype_partition_review_proof as proof
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.forms_design_review import validate_design_review
from fox.opaf import canonical_hash
from fox.prototype_design_context import build_review_context, REFERENCE_SCOPE
from fox.prototype_focus_projection import source_fact_gate
from test_prototype_design_context import mapping_candidate


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False).encode()


def manifest(members):
    return {name: {'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
            for name, body in members.items()}


def checkpoint(target, request, output, identity, room, second):
    role = target['opaf']['roles']['reviewer']
    binding = {'role': role, 'request_sha256': canonical_hash(request), **identity}
    invocation = {**role, 'room_id': room, 'request_sha256': canonical_hash(request),
        'response_sha256': 'd' * 64, 'started_at_utc': f'2026-11-08T00:00:{second:02d}Z',
        'completed_at_utc': f'2026-11-08T00:00:{second + 1:02d}Z'}
    environment = {'schema_version': 1, 'scope': 'opaf-model-environment-v1',
        'trust_boundary': 'authenticated_fox_executor_not_vendor_attestation',
        'job_id': identity['job_id'], 'role': 'reviewer', 'source_manifest_sha256': identity['source_hash'],
        'target_profile_sha256': canonical_hash(target), 'observed_at_utc': f'2026-11-08T00:00:{second - 1:02d}Z',
        'opaf': {key: target['opaf'][key] for key in ('base_url', 'certificate_sha256',
            'model_authentication', 'version_number', 'build_id')},
        'workflow': {**role, 'published': True}, 'opaf_version': target['tested_versions']['opaf']}
    return {'binding': binding, 'output': output, 'output_sha256': canonical_hash(output),
        'invocation': invocation, 'model_environment': environment,
        'model_environment_sha256': canonical_hash(environment)}


def review(request, candidate, approved):
    return {'source_binding': request['source_binding'], 'focus_binding': request['focus_binding'],
        'candidate_sha256': canonical_hash(candidate), 'verdict': 'APPROVED' if approved else 'CHANGES_REQUIRED',
        'findings': [] if approved else [{'source_object_id': None, 'code': 'SYNTHETIC_REJECTION',
            'detail': 'Authored past allegation, not a real review.'}]}


@pytest.fixture
def case(tmp_path):
    globals_ = ''.join(f'<VisualAttribute Name="V{i}"/>' for i in range(160))
    items = ''.join(f'<Item Name="I{i}" ItemType="Text Item" DatabaseItem="true"/>' for i in range(60))
    triggers = ''.join(f'<Trigger Name="T{i}" TriggerText="BEGIN NULL; END;"/>' for i in range(3))
    docs = [('authored.xml', ('<FormModule Name="AUTHORED_ONLY">' + globals_ +
        '<Block Name="MAIN" DatabaseBlock="true">' + items + triggers + '</Block></FormModule>').encode())]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=32)
    assert len(plan['requests']) == 8
    block = next(r for entry in packet['sources'] for r in entry['facts']['objects'] if r['kind'] == 'Block')
    candidates = [mapping_candidate(request, 'screen-' + block['id']) for request in plan['requests']]
    target = {'opaf': {'base_url': 'https://localhost:8080/agentFactory', 'certificate_sha256': 'c' * 64,
        'model_authentication': 'oci_instance_principal', 'version_number': 'authored', 'build_id': 'authored',
        'roles': {'mapper': {'workflow_id': 'A' * 32, 'model': 'authored-mapper', 'graph_sha256': 'a' * 64},
                  'reviewer': {'workflow_id': 'B' * 32, 'model': 'authored-reviewer', 'graph_sha256': 'b' * 64}}},
        'tested_versions': {'opaf': 'authored'}}
    identity = {'job_id': 'fox-' + '1' * 20, 'source_hash': packet['source_binding']}
    views = []
    for request, candidate in zip(plan['requests'][:7], candidates[:7], strict=True):
        payload = {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
        output = review(request, candidate, True)
        saved = checkpoint(target, payload, output, identity, 'authored-prior-' + str(len(views)), 1)
        checked = validate_design_review(request, candidate, output)
        views.append({'candidate': candidate, 'checked': checked, 'proof': {
            'focus_id': request['focus_id'], 'candidate_sha256': canonical_hash(candidate),
            'source_fact_check': source_fact_gate(packet, request, candidate),
            'review_request_sha256': canonical_hash(payload), 'review_receipt_sha256': canonical_hash(checked),
            'reviewer_invocation': saved['invocation']}})
    refs = {request['focus_id']: {'scope': REFERENCE_SCOPE, 'focus_id': request['focus_id'],
        'source_binding': packet['source_binding'], 'focus_request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(view['candidate']), 'target_profile_sha256': canonical_hash(target),
        'proof_sha256': canonical_hash(view['proof'])}
        for request, view in zip(plan['requests'][:7], views, strict=True)}
    request, candidate = plan['requests'][7], candidates[7]
    audit = build_review_context(packet, plan, candidates, refs,
        expected_target_sha256=canonical_hash(target), focus_id=request['focus_id'])
    output = review(request, candidate, False)
    ancient_payload = {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
    ancient = checkpoint(target, ancient_payload, output, identity, 'authored-older-rejection', 2)
    rejected_request = {**ancient_payload, 'design_context': audit,
        'review_context': {'scope': 'authored-projection-context', 'raw_candidate': deepcopy(candidate)},
        'retained_rejection': {'review': output, 'invocation': ancient['invocation'],
            'checkpoint_sha256': canonical_hash(ancient), 'candidate_unchanged': True}}
    rejected_receipt = checkpoint(target, rejected_request, output, identity, 'authored-epoch-four-rejection', 4)
    history_pins = {'request_sha256': canonical_hash(rejected_request),
        'receipt_sha256': canonical_hash(rejected_receipt), 'output_sha256': canonical_hash(output)}
    task, audit = formatter.build_partition_review_task(packet, plan, candidates, refs,
        expected_target_sha256=canonical_hash(target), expected_candidate_sha256=canonical_hash(candidate),
        historical_review={'request': rejected_request, 'receipt': rejected_receipt, 'target_profile': target},
        expected_history_pins=history_pins, review_context=rejected_request['review_context'])
    new_output = review(request, candidate, True)
    saved = checkpoint(target, task, new_output, identity, 'authored-new-compact-review', 6)
    checked = validate_design_review(request, candidate, new_output)
    original_files = {'source-snapshot.json': 'e' * 64, 'prototype-pipeline/authored-original.json': 'f' * 64}
    intent = {'schema_version': 1, 'scope': 'one-unadopted-compact-partition-review',
        'job_id': identity['job_id'], 'source_binding': packet['source_binding'],
        'target_profile_sha256': canonical_hash(target), 'module_sha256': proof.FORMATTER_SHA256,
        'candidate_sha256': canonical_hash(candidate), 'original_request_sha256': canonical_hash(rejected_request),
        'new_request_sha256': canonical_hash(task), 'prior_review_receipt_sha256': canonical_hash(rejected_receipt),
        'original_files_sha256': canonical_hash(original_files), 'maximum_new_model_calls': 1,
        'generation_calls': 0, 'automatic_retry': False, 'production_run_resumed': False, 'proposal_adopted': False}
    values = {'diagnostic-intent.json': intent, 'original-files.json': original_files,
        'review-request.json': task, 'full-audit-context.json': audit, 'review-receipt.json': checked,
        'review/reviewer-target.json': target, 'review/reviewer-intent.json': saved['binding'],
        'review/reviewer.json': saved, 'result.json': {**intent,
            'status': 'COMPACT_PARTITION_REVIEW_COMPLETED_UNADOPTED', 'structured_review_valid': True,
            'review_verdict': 'APPROVED', 'review_approved': True, 'review_room_id': saved['invocation']['room_id'],
            'review_output_sha256': canonical_hash(new_output), 'finding_codes': [],
            'original_job_files_unchanged': len(original_files), 'apex_imported': False,
            'business_behavior_accepted': False}}
    members = {name: encode(value) for name, value in values.items()}
    root = tmp_path / 'proof'
    for name, body in members.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    pins = manifest(members)
    bindings = {'approved_manifest': pins, 'expected_manifest_sha256': canonical_hash(pins),
        'formatter_sha256': proof.FORMATTER_SHA256, 'packet': packet, 'full_plan': plan,
        'historical_views': views, 'rejected_request': rejected_request, 'rejected_receipt': rejected_receipt,
        'original_target': target, 'identity': identity, 'original_files': original_files,
        'expected_history_pins': history_pins}
    return root, members, bindings


def update_member(case, name, mutate):
    root, members, bindings = case
    value = json.loads(members[name])
    mutate(value)
    members[name] = encode(value)
    (root / name).write_bytes(members[name])
    bindings['approved_manifest'] = manifest(members)
    bindings['expected_manifest_sha256'] = canonical_hash(bindings['approved_manifest'])


def reject(case):
    root, members, bindings = case
    for operation in (lambda: proof.read_partition_review_proof(root, **bindings),
                      lambda: proof.validate_partition_review_members(members, **bindings)):
        with pytest.raises(ValueError, match='^Invalid retained compact partition review proof[.]$'):
            operation()


def test_archive_receiver_exact_parity_immutable_and_no_external_actions(case, monkeypatch):
    root, members, bindings = case
    before = deepcopy((members, bindings))
    opened = Path.open
    def readonly(path, mode='r', *args, **kwargs):
        assert mode in ('r', 'rb') and path.is_relative_to(root)
        return opened(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', readonly)
    full = proof.read_partition_review_proof(root, **bindings)
    def forbidden(*args, **kwargs): raise AssertionError('Receiver must perform no filesystem/provider I/O.')
    monkeypatch.setattr(Path, 'open', forbidden)
    monkeypatch.setattr(Path, 'read_bytes', forbidden)
    import fox.prototype_pipeline
    monkeypatch.setattr(fox.prototype_pipeline, '_role', forbidden)
    received = proof.validate_partition_review_members(members, **bindings)
    assert full == received
    candidate, checked, provenance = received
    assert candidate == bindings['rejected_request']['candidate'] and checked['verdict'] == 'APPROVED'
    assert provenance['kind'] == 'RETAINED_COMPACT_PARTITION_REVIEW'
    assert provenance['formatter_identity_mode'] == 'EXPLICIT_TRUSTED_VERSION_PIN'
    assert provenance['formatter_module_bytes_read'] is False
    assert provenance['file_manifest_sha256'] == bindings['expected_manifest_sha256']
    for key in ('proposal_adopted', 'adoption_authorized', 'generation_ready', 'native_apex_generated',
        'technically_verified', 'import_verified', 'business_behavior_accepted', 'processing_consent_verified',
        'current_state_or_owner_consent_verified', 'old_review_provenance_independently_verified',
        'source_authenticity_independently_verified', 'original_job_files_independently_verified',
        'raw_full_blueprint_model_output'):
        assert provenance[key] is False
    assert (members, bindings) == before
    candidate['blueprint']['objects'].clear()
    provenance['original_file_descriptors'].clear()
    assert (members, bindings) == before


@pytest.mark.parametrize('name', sorted(proof.FILES))
def test_every_raw_member_hash_is_pinned(case, name):
    root, members, _ = case
    members[name] += b' '
    (root / name).write_bytes(members[name])
    reject(case)


@pytest.mark.parametrize('name', sorted(proof.FILES))
def test_every_missing_member_blocks_and_never_replays(case, name):
    root, members, _ = case
    del members[name]
    (root / name).unlink()
    reject(case)


@pytest.mark.parametrize('mutation', ['extra', 'path', 'empty', 'bytes-bool', 'oversized',
    'total-budget', 'manifest-pin', 'bad-sha', 'extra-pin', 'formatter', 'member-not-bytes'])
def test_manifest_names_pins_and_budgets_are_strict(case, mutation):
    _, members, bindings = case
    pins = bindings['approved_manifest']
    if mutation == 'extra': members['extra.json'] = b'{}'; pins['extra.json'] = {'sha256': 'b' * 64, 'bytes': 2}
    elif mutation == 'path': pins['../escape.json'] = pins.pop('result.json')
    elif mutation == 'empty': bindings['approved_manifest'] = {}
    elif mutation == 'bytes-bool': pins['result.json']['bytes'] = True
    elif mutation == 'oversized': pins['result.json']['bytes'] = proof.MAX_FILE_BYTES + 1
    elif mutation == 'total-budget':
        for pin in pins.values(): pin['bytes'] = proof.MAX_FILE_BYTES
    elif mutation == 'manifest-pin': bindings['expected_manifest_sha256'] = 'b' * 64
    elif mutation == 'bad-sha': pins['result.json']['sha256'] = 'not-a-sha'
    elif mutation == 'extra-pin': pins['result.json']['extra'] = True
    elif mutation == 'formatter': bindings['formatter_sha256'] = 'b' * 64
    else: members['result.json'] = bytearray(members['result.json'])
    if mutation == 'member-not-bytes':
        # Disk remains unchanged and valid; only the received representation is unsafe.
        proof.read_partition_review_proof(case[0], **bindings)
        with pytest.raises(ValueError): proof.validate_partition_review_members(members, **bindings)
    else:
        reject(case)


@pytest.mark.parametrize('name,path,value', [
    ('diagnostic-intent.json', ['maximum_new_model_calls'], 2),
    ('diagnostic-intent.json', ['generation_calls'], 1),
    ('diagnostic-intent.json', ['proposal_adopted'], True),
    ('diagnostic-intent.json', ['module_sha256'], 'b' * 64),
    ('result.json', ['production_run_resumed'], True),
    ('result.json', ['original_job_files_unchanged'], 135),
    ('result.json', ['review_output_sha256'], 'b' * 64),
    ('review-receipt.json', ['candidate_sha256'], 'b' * 64),
    ('review/reviewer-intent.json', ['job_id'], 'fox-' + '2' * 20),
    ('review/reviewer-target.json', ['opaf', 'roles', 'reviewer', 'model'], 'foreign'),
    ('review/reviewer.json', ['binding', 'source_hash'], 'b' * 64),
    ('review/reviewer.json', ['invocation', 'workflow_id'], 'C' * 32),
    ('review/reviewer.json', ['invocation', 'response_sha256'], 'bad'),
    ('review/reviewer.json', ['invocation', 'request_sha256'], 'b' * 64),
    ('review/reviewer.json', ['invocation', 'room_id'], 'authored-epoch-four-rejection'),
    ('review/reviewer.json', ['invocation', 'started_at_utc'], '2026-11-08T00:00:08Z'),
    ('review/reviewer.json', ['invocation', 'completed_at_utc'], 'not-a-time'),
    ('review/reviewer.json', ['model_environment', 'workflow', 'published'], False),
    ('review/reviewer.json', ['model_environment', 'role'], 'mapper'),
    ('review/reviewer.json', ['model_environment', 'observed_at_utc'], '2026-11-07T00:00:00Z'),
    ('review/reviewer.json', ['model_environment', 'target_profile_sha256'], 'b' * 64),
    ('review-request.json', ['target_profile_sha256'], 'b' * 64),
    ('review-request.json', ['task_binding'], 'b' * 64),
    ('full-audit-context.json', ['prefix_check', 'source_objects_checked'], 999),
])
def test_rehashed_member_still_requires_exact_task_role_and_result_chain(case, name, path, value):
    def mutate(data):
        for key in path[:-1]: data = data[key]
        data[path[-1]] = value
    update_member(case, name, mutate)
    reject(case)


@pytest.mark.parametrize('mutation', ['candidate', 'source', 'identity', 'target', 'prior-count',
    'prior-candidate', 'prior-approval', 'history-pin', 'old-receipt', 'old-environment',
    'old-time', 'old-retained-review', 'old-retained-candidate-flag', 'old-request-context',
    'unsafe-descriptor', 'descriptor-hash'])
def test_independently_supplied_source_history_and_original_pins_remain_binding(case, mutation):
    _, _, b = case
    if mutation == 'candidate': b['rejected_request']['candidate']['blueprint']['objects'][0]['reason'] = 'changed'
    elif mutation == 'source': b['packet']['source_binding'] = 'b' * 64
    elif mutation == 'identity': b['identity']['job_id'] = 'fox-' + '2' * 20
    elif mutation == 'target': b['original_target']['opaf']['roles']['reviewer']['model'] = 'foreign'
    elif mutation == 'prior-count': b['historical_views'].pop()
    elif mutation == 'prior-candidate': b['historical_views'][0]['candidate']['blueprint']['objects'][0]['reason'] = 'changed'
    elif mutation == 'prior-approval': b['historical_views'][0]['checked']['verdict'] = 'CHANGES_REQUIRED'
    elif mutation == 'history-pin': b['expected_history_pins']['receipt_sha256'] = 'b' * 64
    elif mutation == 'old-receipt': b['rejected_receipt']['output']['candidate_sha256'] = 'b' * 64
    elif mutation == 'old-environment': b['rejected_receipt']['model_environment']['workflow']['published'] = False
    elif mutation == 'old-time': b['rejected_receipt']['invocation']['started_at_utc'] = '2026-11-08T00:00:50Z'
    elif mutation == 'old-retained-review': b['rejected_request']['retained_rejection']['review']['candidate_sha256'] = 'b' * 64
    elif mutation == 'old-retained-candidate-flag': b['rejected_request']['retained_rejection']['candidate_unchanged'] = False
    elif mutation == 'old-request-context': b['rejected_request']['design_context']['owned_rows'].reverse()
    elif mutation == 'unsafe-descriptor': b['original_files']['../escape'] = 'b' * 64
    else: b['original_files']['source-snapshot.json'] = 'b' * 64
    reject(case)


def test_new_nonapproval_is_not_accepted_even_when_all_local_hashes_are_resealed(case):
    def mutate(saved):
        saved['output']['verdict'] = 'CHANGES_REQUIRED'
        saved['output']['findings'] = [{'source_object_id': None, 'code': 'AUTHORED', 'detail': 'Not approved.'}]
        saved['output_sha256'] = canonical_hash(saved['output'])
    update_member(case, 'review/reviewer.json', mutate)
    reject(case)


@pytest.mark.parametrize('mutation', ['old-now-approved', 'environment-resealed', 'timestamp-resealed',
    'new-before-old', 'extra-invocation-key', 'extra-checkpoint-key'])
def test_semantic_receipt_environment_and_timestamp_checks_not_just_cached_hashes(case, mutation):
    if mutation == 'old-now-approved':
        b = case[2]
        saved = b['rejected_receipt']
        saved['output'].update(verdict='APPROVED', findings=[])
        saved['output_sha256'] = canonical_hash(saved['output'])
        b['expected_history_pins']['receipt_sha256'] = canonical_hash(saved)
        b['expected_history_pins']['output_sha256'] = canonical_hash(saved['output'])
    else:
        def mutate(saved):
            if mutation == 'environment-resealed':
                saved['model_environment']['workflow']['published'] = False
                saved['model_environment_sha256'] = canonical_hash(saved['model_environment'])
            elif mutation == 'timestamp-resealed': saved['invocation']['completed_at_utc'] = '2026-11-08T00:00:01Z'
            elif mutation == 'new-before-old':
                saved['model_environment']['observed_at_utc'] = '2026-11-08T00:00:00Z'
                saved['model_environment_sha256'] = canonical_hash(saved['model_environment'])
                saved['invocation'].update(started_at_utc='2026-11-08T00:00:01Z', completed_at_utc='2026-11-08T00:00:02Z')
            elif mutation == 'extra-invocation-key': saved['invocation']['extra'] = True
            else: saved['extra'] = True
        update_member(case, 'review/reviewer.json', mutate)
    reject(case)


@pytest.mark.parametrize('raw', [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}',
    b'[]', b'{"x":' + b'[' * 30 + b'0' + b']' * 30 + b'}', b'\xff', b'{} {}'])
def test_malformed_duplicate_nonfinite_deep_or_invalid_json_rejected(case, raw):
    root, members, b = case
    members['result.json'] = raw
    (root / 'result.json').write_bytes(raw)
    b['approved_manifest'] = manifest(members)
    b['expected_manifest_sha256'] = canonical_hash(b['approved_manifest'])
    reject(case)


@pytest.mark.parametrize('extra', ['extra.json', 'prototype_partition_review.py', 'review/extra.json'])
def test_reader_rejects_any_extra_file_including_python(case, extra):
    root, _, bindings = case
    (root / extra).write_bytes(b'{}')
    with pytest.raises(ValueError): proof.read_partition_review_proof(root, **bindings)


def test_reader_rejects_hardlinked_member(case):
    root, _, bindings = case
    path = root / 'result.json'
    backup = root.parent / 'linked-copy.json'
    path.rename(backup)
    os.link(backup, path)
    with pytest.raises(ValueError): proof.read_partition_review_proof(root, **bindings)


def test_reader_rejects_relative_or_parent_traversal_root(case):
    root, _, bindings = case
    for unsafe in (Path('relative-proof'), root / '..' / root.name):
        with pytest.raises(ValueError): proof.read_partition_review_proof(unsafe, **bindings)


def test_reader_rejects_symlink_or_reparse_ancestors_without_following(case, monkeypatch):
    root, _, bindings = case
    original = proof._safe_stat
    def linked(path, *, directory):
        if path == root / 'review': raise ValueError('Synthetic linked directory; no traversal.')
        return original(path, directory=directory)
    monkeypatch.setattr(proof, '_safe_stat', linked)
    with pytest.raises(ValueError): proof.read_partition_review_proof(root, **bindings)


@pytest.mark.parametrize('kind', ['file-symlink', 'directory-symlink', 'reparse'])
def test_native_stat_boundary_rejects_link_metadata_before_member_reads(case, monkeypatch, kind):
    root, _, bindings = case
    original = Path.lstat
    target = root / ('result.json' if kind != 'directory-symlink' else 'review')
    def linked(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path != target: return value
        return SimpleNamespace(st_mode=stat.S_IFLNK if kind != 'reparse' else value.st_mode,
            st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT if kind == 'reparse' else 0,
            st_nlink=value.st_nlink)
    monkeypatch.setattr(Path, 'lstat', linked)
    with pytest.raises(ValueError): proof.read_partition_review_proof(root, **bindings)


def test_reader_rechecks_retained_bytes_after_validation(case, monkeypatch):
    root, _, bindings = case
    original = proof.validate_partition_review_members
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        with (root / 'result.json').open('ab') as stream: stream.write(b' ')
        return result
    monkeypatch.setattr(proof, 'validate_partition_review_members', changed)
    with pytest.raises(ValueError): proof.read_partition_review_proof(root, **bindings)
