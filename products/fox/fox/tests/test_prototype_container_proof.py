"""Synthetic retained-review bytes only; never actual model/Oracle acceptance."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from fox import prototype_design_context_v1 as context, prototype_container_proof as proof
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.forms_design_review import validate_design_review
from fox.prototype_focus_projection import source_fact_gate
from fox.opaf import canonical_hash
from test_prototype_design_context import mapping_candidate
from test_prototype_clause_proof import write, load, sealed_role


def manifest(root):
    return {name: {'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest(),
                   'bytes': (root / name).stat().st_size} for name in sorted(proof.FILES)}


def invocation(role, request, room):
    return {**role, 'room_id': room, 'request_sha256': canonical_hash(request), 'response_sha256': 'd' * 64,
            'started_at_utc': '2026-11-08T00:00:01Z', 'completed_at_utc': '2026-11-08T00:00:02Z'}


@pytest.fixture
def case(tmp_path):
    globals_ = ''.join(f'<VisualAttribute Name="V{i}"/>' for i in range(160))
    items = ''.join(f'<Item Name="I{i}" ItemType="Text Item" DatabaseItem="true"/>' for i in range(60))
    triggers = ''.join(f'<Trigger Name="T{i}" TriggerText="BEGIN NULL; END;"/>' for i in range(3))
    docs = [('synthetic.xml', ('<FormModule Name="SYNTHETIC_NO_CUSTOMER">' + globals_
        + '<Block Name="MAIN" DatabaseBlock="true">' + items + triggers + '</Block></FormModule>').encode())]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=32)
    assert len(plan['requests']) == 8
    block = next(row for entry in packet['sources'] for row in entry['facts']['objects'] if row['kind'] == 'Block')
    candidates = [mapping_candidate(request, 'screen-' + block['id'], omit_module=True) for request in plan['requests']]
    target = {'opaf': {'base_url': 'https://localhost:8080/agentFactory', 'certificate_sha256': 'c' * 64,
        'model_authentication': 'oci_instance_principal', 'version_number': 'synthetic', 'build_id': 'synthetic',
        'roles': {'mapper': {'workflow_id': 'A' * 32, 'model': 'synthetic-mapper', 'graph_sha256': 'a' * 64},
                  'reviewer': {'workflow_id': 'B' * 32, 'model': 'synthetic-reviewer', 'graph_sha256': 'b' * 64}}},
        'tested_versions': {'opaf': 'synthetic'}}
    views = []
    for index, (request, candidate) in enumerate(zip(plan['requests'][:7], candidates[:7], strict=True)):
        payload = {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
        old_review = {'source_binding': request['source_binding'], 'focus_binding': request['focus_binding'],
                      'candidate_sha256': canonical_hash(candidate), 'verdict': 'APPROVED', 'findings': []}
        checked = validate_design_review(request, candidate, old_review)
        old_proof = {'focus_id': request['focus_id'], 'candidate_sha256': canonical_hash(candidate),
            'source_fact_check': source_fact_gate(packet, request, candidate),
            'review_request_sha256': canonical_hash(payload), 'review_sha256': canonical_hash(old_review),
            'review_receipt_sha256': canonical_hash(checked),
            'reviewer_invocation': invocation(target['opaf']['roles']['reviewer'], payload, 'synthetic-old-root-' + str(index))}
        if index == 6:
            old_proof['kind'] = 'DERIVED_CLAUSE_DIAGNOSTIC'  # Authored typed provenance, not a fake mapper.
        views.append({'candidate': candidate, 'checked': checked, 'proof': old_proof})
    request8, candidate8 = plan['requests'][7], candidates[7]
    rejected = {'source_binding': packet['source_binding'], 'focus_binding': request8['focus_binding'],
        'candidate_sha256': canonical_hash(candidate8), 'verdict': 'CHANGES_REQUIRED',
        'findings': [{'source_object_id': None, 'code': 'SYNTHETIC_REJECTION', 'detail': 'Authored retained rejection, not live proof.'}]}
    old_invocation = invocation(target['opaf']['roles']['reviewer'], {'synthetic_rejected_request': True}, 'synthetic-rejected-eight')
    root = tmp_path / 'retained'; root.mkdir()
    (root / 'prototype_design_context.py').write_bytes(Path(context.__file__).read_bytes())
    request, original = plan['requests'][0], candidates[0]
    module_id = next(row['id'] for row in request['owned_objects'] if row['kind'] == 'FormModule')
    proposed, proposal = context.propose_container_retention(packet, request, original, module_id, canonical_hash(original))
    refs = {req['focus_id']: {'scope': context.REFERENCE_SCOPE, 'focus_id': req['focus_id'],
        'source_binding': packet['source_binding'], 'focus_request_sha256': canonical_hash(req),
        'candidate_sha256': canonical_hash(view['candidate']), 'target_profile_sha256': canonical_hash(target),
        'proof_sha256': canonical_hash(view['proof'])} for req, view in zip(plan['requests'][1:7], views[1:], strict=True)}
    prefix = context.validate_prefix_context(packet, plan, [proposed, *candidates[1:]], refs,
        expected_target_sha256=canonical_hash(target), container_proposals={request['focus_id']: proposal},
        unreviewed_focus_id=request8['focus_id'])
    # Independent exact wording copied from the one-shot contract, not reader helper.
    payload = {'request': request, 'candidate': proposed, 'candidate_sha256': canonical_hash(proposed),
        'review_context': {'schema_version': 1, 'scope': 'fox-unadopted-container-retention-review-v1',
            'proposal': proposal, 'original_candidate': original, 'original_active_proof': views[0]['proof'],
            'proposed_prefix_structural_check': prefix, 'root_owned_code_units': [],
            'production_active_root_remains_original': True, 'proposal_adopted': False,
            'scope_notice': 'This is a derived technical proposal for nonvisual FormModule metadata, not a mapper response or a change to business behavior. All other rows, code, claims and ordering are unchanged. The proposed prefix is not adopted and is not full-application validation.'}}
    identity = {'job_id': 'fox-' + '1' * 20, 'source_hash': packet['source_binding']}
    new_review = {'source_binding': packet['source_binding'], 'focus_binding': request['focus_binding'],
        'candidate_sha256': canonical_hash(proposed), 'verdict': 'APPROVED', 'findings': []}
    new_invocation = sealed_role(root, 'review', 'reviewer', target, payload, new_review, identity)
    checked = validate_design_review(request, proposed, new_review)
    original_files = {'source-snapshot.json': 'e' * 64, 'prototype-pipeline/source-unchanged.json': 'f' * 64}
    intent = {'schema_version': 1, 'scope': 'one-unadopted-root-proposal-review', 'job_id': identity['job_id'],
        'source_binding': packet['source_binding'], 'target_profile_sha256': canonical_hash(target),
        'module_sha256': proof.CONTEXT_MODULE_SHA256, 'original_candidate_sha256': canonical_hash(original),
        'candidate_sha256': canonical_hash(proposed), 'proposal_sha256': canonical_hash(proposal),
        'review_request_sha256': canonical_hash(payload), 'original_files_sha256': canonical_hash(original_files),
        'maximum_new_model_calls': 1, 'generation_calls': 0, 'focus8_calls': 0, 'automatic_retry': False,
        'production_run_resumed': False, 'proposal_adopted': False}
    values = {'diagnostic-intent.json': intent, 'original-files.json': original_files,
        'derived-root-candidate.json': proposed, 'container-proposal.json': proposal, 'prefix-check.json': prefix,
        'review-request.json': payload, 'review-receipt.json': checked, 'result.json': {
            **intent, 'status': 'ROOT_PROPOSAL_REVIEW_COMPLETED_UNADOPTED', 'review_verdict': 'APPROVED',
            'approved_structured_design': True, 'review_room_id': new_invocation['room_id'],
            'review_output_sha256': canonical_hash(new_review), 'finding_codes': [],
            'original_job_files_unchanged': len(original_files), 'apex_imported': False,
            'business_behavior_accepted': False}}
    for name, value in values.items():
        write(root, name, value)
    bindings = {'approved_manifest': manifest(root), 'packet': packet, 'full_plan': plan,
        'historical_views': views, 'rejected_candidate': candidate8, 'rejected_review': rejected,
        'rejected_invocation': old_invocation, 'original_target': target, 'identity': identity,
        'module_id': module_id, 'original_files': original_files}
    return root, bindings


def reject(root, bindings):
    with pytest.raises(ValueError, match='Invalid retained unadopted container-review proof'):
        proof.read_container_proof(root, **bindings)


def test_positive_full_chain_is_derived_unadopted_readonly_and_does_not_dereference_original_paths(case, monkeypatch):
    root, bindings = case
    before = deepcopy(bindings)
    files_before = manifest(root)
    path_open = Path.open
    allowed_module = Path(context.__file__)

    def readonly(path, mode='r', *args, **kwargs):
        assert mode in ('r', 'rb')
        assert path == allowed_module or path.is_relative_to(root), 'Original-file descriptors must never be read.'
        return path_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', readonly)
    candidate, checked, provenance = proof.read_container_proof(root, **bindings)
    assert candidate == load(root, 'derived-root-candidate.json')
    assert checked == load(root, 'review-receipt.json') and checked['verdict'] == 'APPROVED'
    assert provenance['kind'] == 'DERIVED_CONTAINER_RETENTION_REVIEW'
    assert provenance['archived_module_bytes_checked'] is True
    assert provenance['file_manifest'] == files_before and provenance['file_manifest_sha256'] == canonical_hash(files_before)
    for key in ('proposal_adopted', 'adoption_authorized', 'generation_ready', 'native_apex_generated',
        'import_verified', 'business_behavior_accepted', 'old_review_provenance_independently_verified',
        'original_job_files_independently_verified', 'current_state_or_owner_consent_verified', 'raw_full_blueprint_model_output'):
        assert provenance[key] is False
    assert bindings == before and manifest(root) == files_before
    candidate['blueprint']['objects'].clear(); provenance['original_file_descriptors'].clear()
    assert bindings == before and manifest(root) == files_before


def test_12_archive_and_11_json_receiver_parity(case):
    root, bindings = case
    full = proof.read_container_proof(root, **bindings)
    members = {name: (root / name).read_bytes() for name in proof.JSON_FILES}
    received = proof.validate_container_proof_members(members, context_module_sha256=proof.CONTEXT_MODULE_SHA256, **bindings)
    assert full[:2] == received[:2]
    assert received[2]['archived_module_bytes_checked'] is False
    full[2]['archived_module_bytes_checked'] = False
    assert full == received


@pytest.mark.parametrize('name', sorted(proof.FILES))
def test_manifest_rejects_every_changed_file(case, name):
    root, bindings = case
    with (root / name).open('ab') as stream: stream.write(b' ')
    reject(root, bindings)


@pytest.mark.parametrize('name', sorted(proof.FILES))
def test_missing_files_or_pending_only_review_never_replayed(case, name):
    root, bindings = case
    (root / name).unlink()
    reject(root, bindings)


@pytest.mark.parametrize('mutation', ['empty', 'missing', 'extra', 'path', 'bool-bytes', 'oversized', 'sha', 'extra-pin'])
def test_manifest_is_mandatory_exact_and_bounded(case, mutation):
    root, bindings = case
    pins = bindings['approved_manifest']
    if mutation == 'empty': bindings['approved_manifest'] = {}
    elif mutation == 'missing': pins.pop('result.json')
    elif mutation in ('extra', 'path'): pins['../outside.json' if mutation == 'path' else 'extra.json'] = deepcopy(pins['result.json'])
    elif mutation == 'bool-bytes': pins['result.json']['bytes'] = True
    elif mutation == 'oversized': pins['result.json']['bytes'] = proof.MAX_FILE_BYTES + 1
    elif mutation == 'sha': pins['result.json']['sha256'] = 'bad'
    else: pins['result.json']['approved'] = True
    reject(root, bindings)


@pytest.mark.parametrize('mutation', ['packet', 'plan', 'original', 'historical-proof', 'historical-approval-bool',
    'rejected-candidate', 'rejected-review', 'rejected-invocation', 'target', 'identity', 'module', 'original-files'])
def test_caller_original_source_role_target_and_job_bindings_are_mandatory(case, mutation):
    root, bindings = case
    if mutation == 'packet': bindings['packet']['source_binding'] = '0' * 64
    elif mutation == 'plan': bindings['full_plan']['plan_binding'] = '0' * 64
    elif mutation == 'original': bindings['historical_views'][0]['candidate']['blueprint']['objects'][1]['reason'] = 'Altered unrelated mapping.'
    elif mutation == 'historical-proof': bindings['historical_views'][1]['proof']['candidate_sha256'] = '0' * 64
    elif mutation == 'historical-approval-bool': bindings['historical_views'][0]['checked'] = {'approved_structured_design': True}
    elif mutation == 'rejected-candidate': bindings['rejected_candidate']['blueprint']['objects'][0]['screen_id'] = 'screen-foreign'
    elif mutation == 'rejected-review': bindings['rejected_review'].update(verdict='APPROVED', findings=[])
    elif mutation == 'rejected-invocation': bindings['rejected_invocation']['graph_sha256'] = '0' * 64
    elif mutation == 'target': bindings['original_target']['opaf']['roles']['reviewer']['model'] = 'different-model'
    elif mutation == 'identity': bindings['identity']['job_id'] = 'fox-' + '2' * 20
    elif mutation == 'module': bindings['module_id'] = 'unavailable-module'
    else: bindings['original_files']['source-snapshot.json'] = '0' * 64
    reject(root, bindings)


@pytest.mark.parametrize('name,mutation', [('derived-root-candidate.json', 'multirow'),
    ('container-proposal.json', 'proposal'), ('prefix-check.json', 'context'), ('review-request.json', 'wording'),
    ('review-request.json', 'prefix'), ('review-receipt.json', 'receipt'), ('diagnostic-intent.json', 'intent'),
    ('result.json', 'boolean'), ('review/reviewer-target.json', 'target'), ('review/reviewer-intent.json', 'request')])
def test_resealed_artifacts_still_must_reconstruct_exactly(case, name, mutation):
    root, bindings = case
    value = load(root, name)
    if mutation == 'multirow': value['blueprint']['objects'][1]['disposition'] = 'omitted'
    elif mutation == 'proposal': value['after']['reason'] = 'Different retention rationale.'
    elif mutation == 'context': value['source_objects_checked'] += 1
    elif mutation == 'wording': value['review_context']['scope_notice'] += ' Extra authority.'
    elif mutation == 'prefix': value['review_context']['proposed_prefix_structural_check']['authority_granted'] = True
    elif mutation == 'receipt': value['candidate_sha256'] = '0' * 64
    elif mutation == 'intent': value['maximum_new_model_calls'] = True
    elif mutation == 'boolean': value['proposal_adopted'] = True
    elif mutation == 'target': value['opaf']['roles']['reviewer']['graph_sha256'] = '0' * 64
    else: value['request_sha256'] = '0' * 64
    write(root, name, value); bindings['approved_manifest'] = manifest(root)
    reject(root, bindings)


@pytest.mark.parametrize('mutation', ['output-hash', 'environment-hash', 'environment', 'request-hash',
    'graph', 'role', 'response', 'time', 'wrong-candidate', 'rejected', 'old-root-room', 'old-eight-room'])
def test_new_reviewer_checkpoint_chain_not_result_status_is_checked(case, mutation):
    root, bindings = case
    value = load(root, 'review/reviewer.json')
    if mutation == 'output-hash': value['output_sha256'] = '0' * 64
    elif mutation == 'environment-hash': value['model_environment_sha256'] = '0' * 64
    elif mutation == 'environment':
        value['model_environment']['source_manifest_sha256'] = '0' * 64
        value['model_environment_sha256'] = canonical_hash(value['model_environment'])
    elif mutation == 'request-hash': value['invocation']['request_sha256'] = '0' * 64
    elif mutation == 'graph': value['invocation']['graph_sha256'] = '0' * 64
    elif mutation == 'role': value['invocation']['workflow_id'] = 'C' * 32
    elif mutation == 'response': value['invocation']['response_sha256'] = 'bad'
    elif mutation == 'time': value['invocation']['completed_at_utc'] = '2026-11-07T00:00:00Z'
    elif mutation == 'wrong-candidate':
        value['output']['candidate_sha256'] = '0' * 64; value['output_sha256'] = canonical_hash(value['output'])
    elif mutation == 'rejected':
        value['output'].update(verdict='CHANGES_REQUIRED', findings=[{'source_object_id': None, 'code': 'SYNTHETIC_REJECT', 'detail': 'Authored rejection.'}])
        value['output_sha256'] = canonical_hash(value['output'])
    elif mutation == 'old-root-room': value['invocation']['room_id'] = bindings['historical_views'][0]['proof']['reviewer_invocation']['room_id']
    else: value['invocation']['room_id'] = bindings['rejected_invocation']['room_id']
    write(root, 'review/reviewer.json', value); bindings['approved_manifest'] = manifest(root)
    reject(root, bindings)


@pytest.mark.parametrize('path', ['../outside.json', '/outside.json', 'C:/outside.json', 'folder\\outside.json',
                                'folder//outside.json', './outside.json'])
def test_original_file_descriptors_are_safe_even_if_caller_and_archive_match(case, path):
    root, bindings = case
    pins = {path: 'a' * 64}
    bindings['original_files'] = pins
    write(root, 'original-files.json', pins); bindings['approved_manifest'] = manifest(root)
    reject(root, bindings)


@pytest.mark.parametrize('mutation', ['python-member', 'missing-json', 'nonbytes', 'wrong-module', 'module-pin', 'extra-path'])
def test_json_receiver_accepts_only11_exact_members_and_installed_frozen_module(case, mutation):
    root, bindings = case
    members = {name: (root / name).read_bytes() for name in proof.JSON_FILES}
    module_sha = proof.CONTEXT_MODULE_SHA256
    if mutation == 'python-member': members['prototype_design_context.py'] = (root / 'prototype_design_context.py').read_bytes()
    elif mutation == 'missing-json': members.pop('result.json')
    elif mutation == 'nonbytes': members['result.json'] = bytearray(members['result.json'])
    elif mutation == 'wrong-module': module_sha = '0' * 64
    elif mutation == 'module-pin': bindings['approved_manifest']['prototype_design_context.py']['sha256'] = '0' * 64
    else: members['../result.json'] = members['result.json']
    with pytest.raises(ValueError):
        proof.validate_container_proof_members(members, context_module_sha256=module_sha, **bindings)


@pytest.mark.parametrize('mutation', ['extra-file', 'traversal-root', 'relative-root', 'duplicate-json', 'nonfinite', 'python-code'])
def test_unsafe_layout_json_or_archived_code_identity_rejected(case, mutation):
    root, bindings = case
    if mutation == 'extra-file': write(root, 'authority.json', {'approved': True})
    elif mutation == 'traversal-root': root = root / 'review' / '..'
    elif mutation == 'relative-root': root = Path('relative/retained')
    elif mutation == 'python-code':
        (root / 'prototype_design_context.py').write_bytes(b'raise RuntimeError("must never execute")')
        bindings['approved_manifest'] = manifest(root)
    else:
        (root / 'result.json').write_bytes(b'{"status":1,"status":1}' if mutation == 'duplicate-json' else b'{"status":NaN}')
        bindings['approved_manifest'] = manifest(root)
    reject(root, bindings)


def test_hardlink_rejected(case):
    root, bindings = case
    os.link(root / 'result.json', root.parent / 'outside-result.json')
    reject(root, bindings)


def test_reparse_ancestor_rejected(case, monkeypatch):
    root, bindings = case
    original = Path.lstat

    def linked(path):
        value = original(path)
        return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT) if path == root.parent else value

    monkeypatch.setattr(Path, 'lstat', linked)
    reject(root, bindings)


def test_changed_during_validation_rejected(case, monkeypatch):
    root, bindings = case
    original = proof._checked_role

    def changed(*args):
        result = original(*args)
        with (root / 'result.json').open('ab') as stream: stream.write(b' ')
        return result

    monkeypatch.setattr(proof, '_checked_role', changed)
    reject(root, bindings)
