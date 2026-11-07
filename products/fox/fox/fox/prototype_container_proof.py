"""Read-only, caller-pinned proof of one UNADOPTED container-retention review.

Original source authenticity, old review/environment provenance, owner consent
and current state remain caller duties. Only the new retained review chain is
rechecked here. No approval boolean or opaque hash grants adoption/execution.
Archived source is checked, NEVER executed or transferred to the JSON receiver.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import re

from . import prototype_design_context as context
from .forms_design_review import _canonical, validate_design_review
from .opaf import OpafError, canonical_hash
from .prototype_clause_proof import (_safe_stat, _check_names, _json, _same,
                                     _checked_role, MAX_FILE_BYTES, MAX_TOTAL_BYTES)
from .prototype_focus_projection import source_fact_gate
from .prototype_mapping_epochs import _descriptors

CONTEXT_MODULE_SHA256 = 'b48195fc859f52a7786e999350af3c7ec96c737d516caef906ea093347d2498c'
FILES = frozenset({'container-proposal.json', 'derived-root-candidate.json',
    'diagnostic-intent.json', 'original-files.json', 'prefix-check.json',
    'prototype_design_context.py', 'result.json', 'review-receipt.json', 'review-request.json',
    'review/reviewer-intent.json', 'review/reviewer-target.json', 'review/reviewer.json'})
JSON_FILES = FILES - {'prototype_design_context.py'}
SCOPE_NOTICE = ('This is a derived technical proposal for nonvisual FormModule metadata, not a mapper response '
    'or a change to business behavior. All other rows, code, claims and ordering are unchanged. '
    'The proposed prefix is not adopted and is not full-application validation.')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_ROOM = re.compile(r'[A-Za-z0-9_.:-]{1,128}\Z')


def _fail():
    raise ValueError('Invalid retained unadopted container-review proof.') from None


def _manifest(manifest):
    if type(manifest) is not dict or len(manifest) != len(FILES) or set(manifest) != FILES:
        _fail()
    for pin in manifest.values():
        if (type(pin) is not dict or set(pin) != {'sha256', 'bytes'}
                or type(pin['sha256']) is not str or not _SHA.fullmatch(pin['sha256'])
                or type(pin['bytes']) is not int or not 0 < pin['bytes'] <= MAX_FILE_BYTES):
            _fail()
    if sum(pin['bytes'] for pin in manifest.values()) > MAX_TOTAL_BYTES:
        _fail()


def _bundle(root, manifest):
    _manifest(manifest)
    if not root.is_absolute() or '..' in root.parts:
        _fail()
    for parent in (*reversed(root.parents), root):
        _safe_stat(parent, directory=True)
    _check_names(root, {name for name in FILES if '/' not in name} | {'review'})
    _safe_stat(root / 'review', directory=True)
    _check_names(root / 'review', {'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json'})
    raw = {}
    for name in sorted(FILES):  # Fixed known paths only, never manifest-selected paths.
        path = root / name
        before = _safe_stat(path, directory=False)
        if before.st_size != manifest[name]['bytes']:
            _fail()
        with path.open('rb') as stream:
            body = stream.read(MAX_FILE_BYTES + 1)
        after = _safe_stat(path, directory=False)
        if (len(body) != manifest[name]['bytes'] or hashlib.sha256(body).hexdigest() != manifest[name]['sha256']
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            _fail()
        raw[name] = body
    return raw


def review_envelope(request, original, original_proof, proposed, proposal, prefix):
    """Exact review-container-root-once contract, not a new invocation."""
    return {'request': request, 'candidate': proposed, 'candidate_sha256': canonical_hash(proposed),
        'review_context': {'schema_version': 1, 'scope': 'fox-unadopted-container-retention-review-v1',
            'proposal': proposal, 'original_candidate': original, 'original_active_proof': original_proof,
            'proposed_prefix_structural_check': prefix, 'root_owned_code_units': [],
            'production_active_root_remains_original': True, 'proposal_adopted': False,
            'scope_notice': SCOPE_NOTICE}}


def read_container_proof(root, **bindings):
    """Strict12-file reader -> (proposal candidate, checked APPROVED receipt, provenance).

    Required bindings are the same as validate_container_proof_members except its
    explicit context_module_sha256 argument. approved_manifest is a separately
    trusted exact original12-file {name:{sha256,bytes}} map, never bundle-issued.
    No original-files.json descriptor is ever dereferenced.
    """
    try:
        root = Path(root)
        raw = _bundle(root, bindings['approved_manifest'])
        if hashlib.sha256(raw['prototype_design_context.py']).hexdigest() != CONTEXT_MODULE_SHA256:
            _fail()
        result = _validate({name: raw[name] for name in JSON_FILES}, CONTEXT_MODULE_SHA256, **bindings)
        if _bundle(root, bindings['approved_manifest']) != raw:
            _fail()
        result[2]['archived_module_bytes_checked'] = True
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError, OpafError):
        _fail()


def validate_container_proof_members(members, *, context_module_sha256, **bindings):
    """Exact11 JSON name->bytes receiver; no Python source or extraction paths.

    Recomputes using installed frozen context module. Caller supplies the same
    trusted12-file archive manifest and original-file map. Old review/environment
    provenance is NOT attested by these bindings or by an approved boolean.
    """
    try:
        return _validate(members, context_module_sha256, **bindings)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError, OpafError):
        _fail()


def _historical_views(packet, plan, views, target):
    if type(views) is not list or len(views) != 7 or len(plan['requests']) < 8:
        _fail()
    for request, view in zip(plan['requests'][:7], views, strict=True):
        if type(view) is not dict or set(view) != {'candidate', 'checked', 'proof'}:
            _fail()
        candidate, checked, proof = view['candidate'], view['checked'], view['proof']
        _canonical(checked, MAX_FILE_BYTES)
        _canonical(proof, MAX_FILE_BYTES)
        if proof['focus_id'] != request['focus_id'] or proof['candidate_sha256'] != canonical_hash(candidate):
            _fail()
        _same(proof['source_fact_check'], source_fact_gate(packet, request, candidate))
        expected = {'verdict': 'APPROVED', 'candidate_sha256': canonical_hash(candidate),
            'source_binding': request['source_binding'], 'focus_binding': request['focus_binding'],
            'approved_structured_design': True, 'generation_ready': False, 'native_apex_generated': False,
            'native_apex_validity_verified': False, 'import_verified': False, 'business_behavior_accepted': False}
        _same(checked, expected)
        if 'review_receipt_sha256' in proof and proof['review_receipt_sha256'] != canonical_hash(checked):
            _fail()
        invocation = proof['reviewer_invocation']
        _old_invocation(invocation, target['opaf']['roles']['reviewer'])
        if invocation['request_sha256'] != proof['review_request_sha256']:
            _fail()
    # These are structural/canonical bindings only. Actual old review/environment
    # chain and active selection MUST already have been verified by the caller.


def _old_invocation(invocation, role):
    _canonical(invocation, 10_000)
    if (type(invocation) is not dict or set(invocation) != {'workflow_id', 'model', 'graph_sha256',
            'room_id', 'request_sha256', 'response_sha256', 'started_at_utc', 'completed_at_utc'}
            or type(invocation['room_id']) is not str or not _ROOM.fullmatch(invocation['room_id'])):
        _fail()
    for key in ('request_sha256', 'response_sha256'):
        if type(invocation[key]) is not str or not _SHA.fullmatch(invocation[key]):
            _fail()
    for key, value in role.items():
        if invocation.get(key) != value:
            _fail()
    # Timestamp/environment truth is deliberately left to the caller's old-role
    # validator; these metadata fields are not a new execution attestation.


def _validate(members, module_sha, *, approved_manifest, packet, full_plan, historical_views,
              rejected_candidate, rejected_review, rejected_invocation, original_target,
              identity, module_id, original_files):
    _manifest(approved_manifest)
    if (type(members) is not dict or len(members) != len(JSON_FILES) or set(members) != JSON_FILES
            or type(module_sha) is not str or module_sha != CONTEXT_MODULE_SHA256):
        _fail()
    members = dict(members)  # Immutable bytes snapshot, not a caller-mutated view.
    approved_manifest = deepcopy(approved_manifest)
    for name, body in members.items():
        if (type(body) is not bytes or len(body) != approved_manifest[name]['bytes']
                or hashlib.sha256(body).hexdigest() != approved_manifest[name]['sha256']):
            _fail()
    installed = Path(context.__file__).read_bytes()
    if (hashlib.sha256(installed).hexdigest() != CONTEXT_MODULE_SHA256
            or approved_manifest['prototype_design_context.py'] != {'sha256': CONTEXT_MODULE_SHA256, 'bytes': len(installed)}):
        _fail()
    values = {name: _json(body) for name, body in members.items()}
    _canonical(identity, 1000)
    _canonical(original_target, MAX_FILE_BYTES)
    if (type(identity) is not dict or set(identity) != {'job_id', 'source_hash'}
            or type(identity['job_id']) is not str or not re.fullmatch(r'fox-[a-f0-9]{20}', identity['job_id'])
            or identity['source_hash'] != packet['source_binding'] or identity['source_hash'] != full_plan['source_binding']):
        _fail()
    # Pure descriptor checks, deliberately NO filesystem lookup of these names.
    _descriptors(original_files)
    _same(values['original-files.json'], original_files)
    target_sha = canonical_hash(original_target)
    _historical_views(packet, full_plan, historical_views, original_target)
    rejected_request = full_plan['requests'][7]
    old_checked = validate_design_review(rejected_request, rejected_candidate, rejected_review)
    if old_checked['verdict'] != 'CHANGES_REQUIRED':
        _fail()
    _old_invocation(rejected_invocation, original_target['opaf']['roles']['reviewer'])
    request = full_plan['requests'][0]
    original = historical_views[0]['candidate']
    proposed, proposal = context.propose_container_retention(packet, request, original, module_id, canonical_hash(original))
    candidates = [proposed] + [deepcopy(view['candidate']) for view in historical_views[1:]] + [deepcopy(rejected_candidate)]
    refs = {req['focus_id']: {'scope': context.REFERENCE_SCOPE, 'focus_id': req['focus_id'],
            'source_binding': full_plan['source_binding'], 'focus_request_sha256': canonical_hash(req),
            'candidate_sha256': canonical_hash(view['candidate']), 'target_profile_sha256': target_sha,
            'proof_sha256': canonical_hash(view['proof'])}
            for req, view in zip(full_plan['requests'][1:7], historical_views[1:], strict=True)}
    prefix = context.validate_prefix_context(packet, full_plan, candidates, refs, expected_target_sha256=target_sha,
        container_proposals={request['focus_id']: proposal}, unreviewed_focus_id=rejected_request['focus_id'])
    payload = review_envelope(request, original, historical_views[0]['proof'], proposed, proposal, prefix)
    for name, expected in {'container-proposal.json': proposal, 'derived-root-candidate.json': proposed,
                           'prefix-check.json': prefix, 'review-request.json': payload}.items():
        _same(values[name], expected)
    review, invocation = _checked_role(members, values, 'review', 'reviewer', original_target, payload, identity)
    if invocation['room_id'] in {historical_views[0]['proof']['reviewer_invocation']['room_id'], rejected_invocation['room_id']}:
        _fail()
    checked = validate_design_review(request, proposed, review)
    if checked['verdict'] != 'APPROVED':
        _fail()
    _same(values['review-receipt.json'], checked)
    intent = {'schema_version': 1, 'scope': 'one-unadopted-root-proposal-review', 'job_id': identity['job_id'],
        'source_binding': identity['source_hash'], 'target_profile_sha256': target_sha,
        'module_sha256': CONTEXT_MODULE_SHA256, 'original_candidate_sha256': canonical_hash(original),
        'candidate_sha256': canonical_hash(proposed), 'proposal_sha256': canonical_hash(proposal),
        'review_request_sha256': canonical_hash(payload), 'original_files_sha256': canonical_hash(original_files),
        'maximum_new_model_calls': 1, 'generation_calls': 0, 'focus8_calls': 0, 'automatic_retry': False,
        'production_run_resumed': False, 'proposal_adopted': False}
    _same(values['diagnostic-intent.json'], intent)
    _same(values['result.json'], {**intent, 'status': 'ROOT_PROPOSAL_REVIEW_COMPLETED_UNADOPTED',
        'review_verdict': checked['verdict'], 'approved_structured_design': checked['approved_structured_design'],
        'review_room_id': invocation['room_id'], 'review_output_sha256': canonical_hash(review),
        'finding_codes': [row['code'] for row in review['findings']], 'original_job_files_unchanged': len(original_files),
        'apex_imported': False, 'business_behavior_accepted': False})
    provenance = {'schema_version': 1, 'scope': 'fox-unadopted-container-review-proof-v1', **identity,
        'kind': 'DERIVED_CONTAINER_RETENTION_REVIEW', 'focus_id': request['focus_id'], 'module_id': module_id,
        'focus_plan_sha256': canonical_hash(full_plan), 'target_profile_sha256': target_sha,
        'original_candidate_sha256': canonical_hash(original), 'candidate_sha256': canonical_hash(proposed),
        'proposal_sha256': canonical_hash(proposal), 'prefix_check_sha256': canonical_hash(prefix),
        'review_request_sha256': canonical_hash(payload), 'review_invocation': deepcopy(invocation),
        'review_output_sha256': canonical_hash(review), 'review_receipt_sha256': canonical_hash(checked),
        'rejected_candidate_sha256': canonical_hash(rejected_candidate), 'rejected_review_sha256': canonical_hash(rejected_review),
        'original_files_sha256': canonical_hash(original_files), 'original_file_descriptors': deepcopy(original_files),
        'file_manifest': deepcopy(approved_manifest), 'file_manifest_sha256': canonical_hash(approved_manifest),
        'checked_json_file_names': sorted(JSON_FILES), 'context_module_sha256': CONTEXT_MODULE_SHA256,
        'archived_module_bytes_checked': False, 'raw_full_blueprint_model_output': False,
        'old_review_provenance_independently_verified': False, 'original_job_files_independently_verified': False,
        'current_state_or_owner_consent_verified': False, 'proposal_adopted': False, 'adoption_authorized': False,
        'source_authenticity_independently_verified': False, 'processing_consent_verified': False,
        'generation_ready': False, 'native_apex_generated': False, 'native_apex_validity_verified': False,
        'technically_verified': False, 'import_verified': False,
        'business_behavior_accepted': False}
    return deepcopy(proposed), deepcopy(checked), provenance
