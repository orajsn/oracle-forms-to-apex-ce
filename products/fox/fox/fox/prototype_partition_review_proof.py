"""Strict retained compact-review proof, never adoption or processing authority.

Both APIs return (unchanged candidate, checked APPROVED receipt, provenance).
Inputs are independently pinned by the caller: nine-member raw-byte manifest,
its canonical hash, frozen formatter version, fresh packet/plan, seven already
verified historical views, original rejected reviewer request/checkpoint/target,
their canonical history pins, job identity and original-file descriptor map.
The receiver performs no filesystem/network I/O. formatter_sha256 is an EXPLICIT
trusted code-version pin, not a claim that archived/installed bytes were read;
callers must select trusted installed code at this version. No archived Python
is accepted, imported or executed. Source authenticity, actual prior provenance,
current owner/consent and downstream technical gates remain caller obligations.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
from pathlib import Path
import re

from . import prototype_partition_review as formatter
from .forms_design_review import _canonical, validate_design_review
from .opaf import OpafError, canonical_hash, validate_model_environment
from .prototype_clause_proof import _safe_stat, _check_names, _json, MAX_FILE_BYTES, MAX_TOTAL_BYTES
from .prototype_container_proof import _historical_views, _old_invocation
from .prototype_design_context import REFERENCE_SCOPE
from .prototype_mapping_epochs import _descriptors

FORMATTER_SHA256 = 'b81ec2cdd463c2db5b35d3fa1846f779d5191d079e07b1da94e89ae087785f57'
FILES = frozenset({'diagnostic-intent.json', 'original-files.json', 'review-request.json',
    'full-audit-context.json', 'review-receipt.json', 'result.json',
    'review/reviewer-target.json', 'review/reviewer-intent.json', 'review/reviewer.json'})
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_UTC = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z')
_ERRORS = (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, IndexError, StopIteration, OpafError)


def _fail():
    raise ValueError('Invalid retained compact partition review proof.') from None


def _same(left, right):
    if _canonical(left, MAX_FILE_BYTES) != _canonical(right, MAX_FILE_BYTES):
        _fail()


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        _fail()


def _manifest(manifest, expected_sha):
    _sha(expected_sha)
    if type(manifest) is not dict or set(manifest) != FILES:
        _fail()
    for pin in manifest.values():
        if (type(pin) is not dict or set(pin) != {'sha256', 'bytes'}
                or type(pin['bytes']) is not int or not 0 < pin['bytes'] <= MAX_FILE_BYTES):
            _fail()
        _sha(pin['sha256'])
    if sum(pin['bytes'] for pin in manifest.values()) > MAX_TOTAL_BYTES:
        _fail()
    _same(canonical_hash(manifest), expected_sha)


def _bundle(root, manifest, manifest_sha):
    _manifest(manifest, manifest_sha)
    if not root.is_absolute() or '..' in root.parts:
        _fail()
    for parent in (*reversed(root.parents), root):
        _safe_stat(parent, directory=True)
    _check_names(root, {name for name in FILES if '/' not in name} | {'review'})
    _safe_stat(root / 'review', directory=True)
    _check_names(root / 'review', {'reviewer-target.json', 'reviewer-intent.json', 'reviewer.json'})
    raw = {}
    for name in sorted(FILES):
        path, pin = root / name, manifest[name]
        before = _safe_stat(path, directory=False)
        if before.st_size != pin['bytes']:
            _fail()
        with path.open('rb') as stream:
            body = stream.read(MAX_FILE_BYTES + 1)
        after = _safe_stat(path, directory=False)
        if (len(body) != pin['bytes'] or hashlib.sha256(body).hexdigest() != pin['sha256']
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            _fail()
        raw[name] = body
    return raw


def _utc(value):
    if type(value) is not str or not _UTC.fullmatch(value):
        _fail()
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def _invocation(value, role):
    _old_invocation(value, role)
    if _utc(value['completed_at_utc']) < _utc(value['started_at_utc']):
        _fail()


def _role(checkpoint, intent, target, request, identity):
    """Validate retained complete data directly: no client or replay branch."""
    _canonical(checkpoint, MAX_FILE_BYTES)
    if type(checkpoint) is not dict or set(checkpoint) != {
            'binding', 'output', 'output_sha256', 'invocation',
            'model_environment', 'model_environment_sha256'}:
        _fail()
    role = target['opaf']['roles']['reviewer']
    binding = {'role': role, 'request_sha256': canonical_hash(request), **identity}
    _same(checkpoint['binding'], binding)
    if intent is not None:
        _same(intent, binding)
    _same(checkpoint['output_sha256'], canonical_hash(checkpoint['output']))
    _same(checkpoint['model_environment_sha256'], canonical_hash(checkpoint['model_environment']))
    invocation = checkpoint['invocation']
    _invocation(invocation, role)
    _same(invocation['request_sha256'], binding['request_sha256'])
    validate_model_environment(checkpoint['model_environment'], target, 'reviewer', identity, invocation)
    return checkpoint['output'], invocation


def read_partition_review_proof(root, **bindings):
    """Read exact regular-file layout twice; never open original descriptor paths.

    Required bindings are exactly those of validate_partition_review_members.
    Both APIs use the explicit trusted formatter version pin; neither claims to
    inspect archived Python, grant epoch reuse, verify consent or create a call.
    """
    try:
        root = Path(root)
        raw = _bundle(root, bindings['approved_manifest'], bindings['expected_manifest_sha256'])
        result = validate_partition_review_members(raw, **bindings)
        if _bundle(root, bindings['approved_manifest'], bindings['expected_manifest_sha256']) != raw:
            _fail()
        return result
    except _ERRORS:
        _fail()


def validate_partition_review_members(members, *, approved_manifest, expected_manifest_sha256,
        formatter_sha256, packet, full_plan, historical_views, rejected_request,
        rejected_receipt, original_target, identity, original_files, expected_history_pins):
    """Pure exact nine-name->bytes receiver, with no filesystem/provider access.

    Historical review request is the original epoch-four payload, not a fresh
    fabricated template. Its receipt/target and all seven prior active views
    must already have caller-verified authenticity and active-selection history.
    expected_history_pins are {request_sha256, receipt_sha256, output_sha256}.
    All hashes/flags here are structural bindings, not vendor or owner authority.
    """
    try:
        return _validate(members, approved_manifest, expected_manifest_sha256, formatter_sha256,
            packet, full_plan, historical_views, rejected_request, rejected_receipt,
            original_target, identity, original_files, expected_history_pins)
    except _ERRORS:
        _fail()


def _validate(members, manifest, manifest_sha, module_sha, packet, plan, views,
              rejected_request, rejected_receipt, target, identity, original_files, history_pins):
    _manifest(manifest, manifest_sha)
    if (type(members) is not dict or set(members) != FILES
            or type(module_sha) is not str or module_sha != FORMATTER_SHA256):
        _fail()
    raw, manifest = dict(members), deepcopy(manifest)
    for name, body in raw.items():
        if (type(body) is not bytes or len(body) != manifest[name]['bytes']
                or hashlib.sha256(body).hexdigest() != manifest[name]['sha256']):
            _fail()
    values = {name: _json(body) for name, body in raw.items()}
    _canonical(identity, 1000)
    _canonical(target, MAX_FILE_BYTES)
    if (type(identity) is not dict or set(identity) != {'job_id', 'source_hash'}
            or type(identity['job_id']) is not str or not re.fullmatch(r'fox-[a-f0-9]{20}', identity['job_id'])
            or identity['source_hash'] != packet['source_binding'] or identity['source_hash'] != plan['source_binding']):
        _fail()
    roles = target['opaf']['roles']
    for name in ('mapper', 'reviewer'):
        role = roles[name]
        if (type(role) is not dict or set(role) != {'workflow_id', 'model', 'graph_sha256'}
                or type(role['workflow_id']) is not str or not re.fullmatch(r'[A-Fa-f0-9]{16,64}', role['workflow_id'])
                or type(role['model']) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', role['model'])):
            _fail()
        _sha(role['graph_sha256'])
    if roles['mapper']['workflow_id'].upper() == roles['reviewer']['workflow_id'].upper():
        _fail()
    _descriptors(original_files)  # Validate names only; NEVER dereference them.
    _same(values['original-files.json'], original_files)
    _historical_views(packet, plan, views, target)
    for view in views:
        _invocation(view['proof']['reviewer_invocation'], roles['reviewer'])
    focus = plan['requests'][7]
    if type(rejected_request) is not dict or set(rejected_request) != {
            'request', 'candidate', 'candidate_sha256', 'design_context', 'review_context', 'retained_rejection'}:
        _fail()
    _same(rejected_request['request'], focus)
    candidate = rejected_request['candidate']
    rejected, prior_invocation = _role(rejected_receipt, None, target, rejected_request, identity)
    if validate_design_review(focus, candidate, rejected)['verdict'] != 'CHANGES_REQUIRED':
        _fail()
    retained = rejected_request['retained_rejection']
    if type(retained) is not dict or set(retained) != {'review', 'invocation', 'checkpoint_sha256', 'candidate_unchanged'}:
        _fail()
    if retained['candidate_unchanged'] is not True:
        _fail()
    _sha(retained['checkpoint_sha256'])
    _invocation(retained['invocation'], roles['reviewer'])
    if validate_design_review(focus, candidate, retained['review'])['verdict'] != 'CHANGES_REQUIRED':
        _fail()
    target_sha = canonical_hash(target)
    candidates = [view['candidate'] for view in views] + [candidate]
    refs = {request['focus_id']: {'scope': REFERENCE_SCOPE, 'focus_id': request['focus_id'],
        'source_binding': plan['source_binding'], 'focus_request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(view['candidate']), 'target_profile_sha256': target_sha,
        'proof_sha256': canonical_hash(view['proof'])}
        for request, view in zip(plan['requests'][:7], views, strict=True)}
    task, audit = formatter.build_partition_review_task(packet, plan, candidates, refs,
        expected_target_sha256=target_sha, expected_candidate_sha256=canonical_hash(candidate),
        historical_review={'request': rejected_request, 'receipt': rejected_receipt, 'target_profile': target},
        expected_history_pins=history_pins, review_context=rejected_request['review_context'])
    _same(values['review-request.json'], task)
    _same(values['full-audit-context.json'], audit)
    _same(rejected_request['design_context'], audit)
    _same(values['review/reviewer-target.json'], target)
    output, invocation = _role(values['review/reviewer.json'], values['review/reviewer-intent.json'],
                               target, task, identity)
    old_rooms = {prior_invocation['room_id'], retained['invocation']['room_id'],
                 *(view['proof']['reviewer_invocation']['room_id'] for view in views)}
    if (invocation['room_id'] in old_rooms
            or _utc(invocation['started_at_utc']) < _utc(prior_invocation['completed_at_utc'])):
        _fail()
    checked = validate_design_review(focus, candidate, output)
    if checked['verdict'] != 'APPROVED':
        _fail()
    _same(values['review-receipt.json'], checked)
    intent = {'schema_version': 1, 'scope': 'one-unadopted-compact-partition-review',
        'job_id': identity['job_id'], 'source_binding': plan['source_binding'],
        'target_profile_sha256': target_sha, 'module_sha256': FORMATTER_SHA256,
        'candidate_sha256': canonical_hash(candidate), 'original_request_sha256': canonical_hash(rejected_request),
        'new_request_sha256': canonical_hash(task), 'prior_review_receipt_sha256': canonical_hash(rejected_receipt),
        'original_files_sha256': canonical_hash(original_files), 'maximum_new_model_calls': 1,
        'generation_calls': 0, 'automatic_retry': False, 'production_run_resumed': False, 'proposal_adopted': False}
    _same(values['diagnostic-intent.json'], intent)
    _same(values['result.json'], {**intent, 'status': 'COMPACT_PARTITION_REVIEW_COMPLETED_UNADOPTED',
        'structured_review_valid': True, 'review_verdict': 'APPROVED', 'review_approved': True,
        'review_room_id': invocation['room_id'], 'review_output_sha256': canonical_hash(output),
        'finding_codes': [], 'original_job_files_unchanged': len(original_files),
        'apex_imported': False, 'business_behavior_accepted': False})
    provenance = {'schema_version': 1, 'scope': 'fox-retained-compact-partition-review-proof-v1',
        'kind': 'RETAINED_COMPACT_PARTITION_REVIEW', **deepcopy(identity), 'focus_id': focus['focus_id'],
        'focus_plan_sha256': canonical_hash(plan), 'focus_request_sha256': canonical_hash(focus),
        'candidate_sha256': canonical_hash(candidate), 'target_profile_sha256': target_sha,
        'formatter_sha256': FORMATTER_SHA256, 'formatter_identity_mode': 'EXPLICIT_TRUSTED_VERSION_PIN',
        'formatter_module_bytes_read': False, 'full_audit_context_sha256': canonical_hash(audit),
        'review_request_sha256': canonical_hash(task), 'review_invocation': deepcopy(invocation),
        'review_output_sha256': canonical_hash(output), 'review_receipt_sha256': canonical_hash(checked),
        'prior_review_request_sha256': canonical_hash(rejected_request),
        'prior_review_checkpoint_sha256': canonical_hash(rejected_receipt),
        'prior_review_output_sha256': canonical_hash(rejected), 'prior_review_invocation': deepcopy(prior_invocation),
        'original_files_sha256': canonical_hash(original_files), 'original_file_descriptors': deepcopy(original_files),
        'file_manifest': manifest, 'file_manifest_sha256': manifest_sha, 'checked_json_file_names': sorted(FILES),
        'raw_full_blueprint_model_output': False, 'source_authenticity_independently_verified': False,
        'old_review_provenance_independently_verified': False, 'original_job_files_independently_verified': False,
        'current_state_or_owner_consent_verified': False, 'processing_consent_verified': False,
        'proposal_adopted': False, 'adoption_authorized': False, 'generation_ready': False,
        'native_apex_generated': False, 'technically_verified': False, 'import_verified': False,
        'business_behavior_accepted': False}
    return deepcopy(candidate), deepcopy(checked), provenance
