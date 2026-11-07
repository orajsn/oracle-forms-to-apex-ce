"""Read-only, caller-pinned proof of a retained two-clause diagnostic.

This is NOT an epoch selector, processing grant, raw blueprint response, native
generation gate or business acceptance. Callers supply freshly reconstructed
source/focus/original and the independently trusted original target, analysis
role, job identity and exact file manifest. A manifest found inside the bundle
cannot grant itself trust. No retained Python is executed and no files are
written. Environment evidence is executor-observed, not vendor attestation.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import stat
from types import SimpleNamespace

from . import prototype_clause_analysis as assembler
from .forms_design_review import _canonical, validate_design_review
from .opaf import OpafError, canonical_hash
from .prototype_pipeline import _role

ASSEMBLER_SHA256 = 'b722fb5c851ca79da314d6a0412e06fe8190b09670e63b524fdb1c0c5780715a'
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 8_000_000
FILES = frozenset({
    'prototype_clause_analysis.py', 'diagnostic-intent.json', 'clause-request.json',
    'derived-candidate.json', 'derived-assembly.json', 'assembly-binding.json',
    'review-receipt.json', 'result.json',
    'analysis/mapper-intent.json', 'analysis/mapper-target.json', 'analysis/mapper.json',
    'review/reviewer-intent.json', 'review/reviewer-target.json', 'review/reviewer.json',
})
JSON_FILES = FILES - {'prototype_clause_analysis.py'}
_SHA = re.compile(r'[0-9a-f]{64}\Z')


def _fail():
    raise ValueError('Invalid retained source-bound clause diagnostic proof.') from None


def _same(left, right):
    # Canonical bytes distinguish bool/int and reject non-plain/unbounded JSON.
    if _canonical(left, MAX_FILE_BYTES) != _canonical(right, MAX_FILE_BYTES):
        _fail()


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            _fail()
        result[key] = value
    return result


def _json(raw):
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
    _canonical(value, MAX_FILE_BYTES)
    if type(value) is not dict:
        _fail()
    return value


def _safe_stat(path, *, directory):
    value = path.lstat()
    if (stat.S_ISLNK(value.st_mode)
            or getattr(value, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
            or not directory and value.st_nlink != 1):
        _fail()
    return value


def _manifest(approved_manifest):
    if (type(approved_manifest) is not dict or len(approved_manifest) != len(FILES)
            or set(approved_manifest) != FILES):
        _fail()
    for item in approved_manifest.values():
        if (type(item) is not dict or set(item) != {'sha256', 'bytes'}
                or type(item['sha256']) is not str or not _SHA.fullmatch(item['sha256'])
                or type(item['bytes']) is not int or not 0 < item['bytes'] <= MAX_FILE_BYTES):
            _fail()
    if sum(item['bytes'] for item in approved_manifest.values()) > MAX_TOTAL_BYTES:
        _fail()


def _check_names(directory, expected):
    names = set()
    for index, path in enumerate(directory.iterdir()):
        if index >= len(expected):
            _fail()
        names.add(path.name)
    if names != expected:
        _fail()


def _read_bundle(root, approved_manifest):
    _manifest(approved_manifest)
    if not root.is_absolute() or '..' in root.parts:
        _fail()
    for parent in (*reversed(root.parents), root):
        _safe_stat(parent, directory=True)
    # Enumerate only the fixed probe layout: no arbitrary manifest path joins.
    expected = {name for name in FILES if '/' not in name} | {'analysis', 'review'}
    _check_names(root, expected)
    for folder, role in (('analysis', 'mapper'), ('review', 'reviewer')):
        _safe_stat(root / folder, directory=True)
        _check_names(root / folder, {
            role + suffix for suffix in ('.json', '-intent.json', '-target.json')})
    raw = {}
    for name in sorted(FILES):
        path, pin = root / name, approved_manifest[name]
        before = _safe_stat(path, directory=False)
        if before.st_size != pin['bytes']:
            _fail()
        with path.open('rb') as handle:
            # Bound reads even when the file changes after the size check.
            body = handle.read(MAX_FILE_BYTES + 1)
        after = _safe_stat(path, directory=False)
        if (len(body) != pin['bytes'] or hashlib.sha256(body).hexdigest() != pin['sha256']
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            _fail()
        raw[name] = body
    return raw


class _SealedPath:
    """Minimal immutable byte view for the existing _role complete-only reader.

    _role never sees a mutable filesystem or a missing completion. The view has
    no write API; even its missing-result branch is denied fresh approval.
    """
    def __init__(self, files, name=''):
        self.files, self.name = files, name

    def __truediv__(self, name):
        return _SealedPath(self.files, self.name + '/' + name if self.name else name)

    def exists(self):
        return self.name in self.files

    def is_symlink(self):
        return False

    def is_file(self):
        return self.exists()

    def stat(self):
        return SimpleNamespace(st_size=len(self.files[self.name]))

    def read_text(self, encoding):
        return self.files[self.name].decode(encoding)


def _checked_role(raw, values, folder, name, target, request, identity):
    role = target['opaf']['roles'][name]
    binding = {'role': role, 'request_sha256': canonical_hash(request), **identity}
    _same(values[folder + '/' + name + '-intent.json'], binding)
    _same(values[folder + '/' + name + '-target.json'], target)
    saved = values[folder + '/' + name + '.json']
    if set(saved) != {'binding', 'output', 'output_sha256', 'invocation',
                      'model_environment', 'model_environment_sha256'}:
        _fail()
    invocation = saved['invocation']
    if (set(invocation) != {'workflow_id', 'model', 'graph_sha256', 'room_id',
                            'request_sha256', 'response_sha256', 'started_at_utc', 'completed_at_utc'}
            or type(invocation['room_id']) is not str
            or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', invocation['room_id'])
            or type(invocation['response_sha256']) is not str
            or not _SHA.fullmatch(invocation['response_sha256'])):
        _fail()
    # No client, filesystem loader or processing grant exists on this path.
    return _role(_SealedPath(raw, folder), name, None, role, request, identity,
                 None, lambda _: False, {'diagnostic_only': True})


def review_envelope(focus_request, original_candidate, compact, analysis, candidate, assembly, binding):
    """Exact diagnostic probe review request; reconstruction, not a new call."""
    return {'request': focus_request, 'candidate': candidate,
            'candidate_sha256': canonical_hash(candidate), 'review_context': {
                'schema_version': 1, 'scope': 'fox-dedicated-clause-derived-review-v1',
                'trusted_requirements': {
                    'compare_each_literal_clause_with_its_intent_and_limitations': True,
                    'reject_missing_conditions_ordering_or_invented_external_meaning': True,
                    'original_false_facts_are_historical_not_authority': True,
                    'require_both_clauses_and_action_references': True,
                    'assembly_is_derived_not_a_raw_blueprint_model_response': True,
                    'do_not_execute_or_accept_business_behavior': True},
                'original_candidate': original_candidate, 'clause_request': compact,
                'raw_clause_analyses': analysis, 'assembly': assembly, 'assembly_binding': binding}}


def read_clause_proof(root, *, approved_manifest, packet, focus_request,
                      original_candidate, original_target, analysis_role, identity):
    """Return (derived candidate, checked APPROVED receipt, provenance).

    approved_manifest is an independently approved exact {relative_name:
    {'sha256': raw-byte SHA256, 'bytes': positive int}} mapping. It is mandatory,
    not discovered or minted here. identity is exactly {job_id, source_hash};
    source_hash is the freshly reconstructed packet's source_binding. The caller
    remains responsible for source authenticity, original checkpoint provenance,
    approval/epoch adoption and normal downstream technical gates.
    """
    try:
        root = Path(root)
        raw = _read_bundle(root, approved_manifest)
        if hashlib.sha256(raw['prototype_clause_analysis.py']).hexdigest() != ASSEMBLER_SHA256:
            _fail()
        result = _validate_members({name: raw[name] for name in JSON_FILES}, approved_manifest,
                                   ASSEMBLER_SHA256, packet, focus_request, original_candidate,
                                   original_target, analysis_role, identity)
        # Detect retained-file changes during validation; preserve the original pin.
        if _read_bundle(root, approved_manifest) != raw:
            _fail()
        result[2]['retained_module_bytes_checked'] = True
        return result
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError, OpafError):
        _fail()


def validate_clause_proof_members(members, *, approved_manifest, assembler_sha256,
                                  packet, focus_request, original_candidate,
                                  original_target, analysis_role, identity):
    """Check exactly 13 named JSON byte members using the installed assembler.

    This explicit receiver boundary accepts no Python source or archive/path
    extraction instructions. approved_manifest still pins the original 14-file
    diagnostic, including its archived assembler identity; assembler_sha256 must
    be the separately trusted frozen identity, not a bundle-issued grant. JSON
    bytes are rehashed/reconstructed exactly as in read_clause_proof. This does
    not attest that the archived .py source was transferred or read here.
    """
    try:
        return _validate_members(members, approved_manifest, assembler_sha256, packet,
                                 focus_request, original_candidate, original_target, analysis_role, identity)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError, OpafError):
        _fail()


def _validate_members(raw, manifest, assembler_sha256, packet, focus, original,
                      original_target, analysis_role, identity):
    _manifest(manifest)
    if (type(raw) is not dict or len(raw) != len(JSON_FILES) or set(raw) != JSON_FILES
            or type(assembler_sha256) is not str or assembler_sha256 != ASSEMBLER_SHA256):
        _fail()
    for name, body in raw.items():
        if (type(body) is not bytes or len(body) != manifest[name]['bytes']
                or hashlib.sha256(body).hexdigest() != manifest[name]['sha256']):
            _fail()
    installed = Path(assembler.__file__).read_bytes()
    if (hashlib.sha256(installed).hexdigest() != ASSEMBLER_SHA256
            or manifest['prototype_clause_analysis.py'] != {
                'sha256': ASSEMBLER_SHA256, 'bytes': len(installed)}):
        _fail()
    for value in (manifest, packet, focus, original, original_target, analysis_role, identity):
        _canonical(value, MAX_FILE_BYTES)
    if (type(identity) is not dict or set(identity) != {'job_id', 'source_hash'}
            or type(identity['job_id']) is not str
            or not re.fullmatch(r'fox-[a-f0-9]{20}', identity['job_id'])
            or identity['source_hash'] != packet['source_binding']
            or identity['source_hash'] != focus['source_binding']):
        _fail()
    roles = original_target['opaf']['roles']
    for role in (analysis_role, roles['mapper'], roles['reviewer']):
        if (type(role) is not dict or set(role) != {'workflow_id', 'model', 'graph_sha256'}
                or type(role['workflow_id']) is not str
                or not re.fullmatch(r'[A-Fa-f0-9]{16,64}', role['workflow_id'])
                or type(role['model']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', role['model'])
                or type(role['graph_sha256']) is not str or not _SHA.fullmatch(role['graph_sha256'])):
            _fail()
    if (analysis_role['model'] != roles['mapper']['model']
            or len({role['workflow_id'].upper() for role in
                    (analysis_role, roles['mapper'], roles['reviewer'])}) != 3):
        _fail()
    stage_target = deepcopy(original_target)
    stage_target['opaf']['roles']['mapper'] = deepcopy(analysis_role)
    values = {name: _json(body) for name, body in raw.items()}
    compact = assembler.build_request(packet, focus, original)
    _same(values['clause-request.json'], compact)
    analysis, invocation = _checked_role(raw, values, 'analysis', 'mapper', stage_target, compact, identity)
    response = assembler.validate_response(analysis)
    candidate, assembly = assembler.assemble_candidate(packet, focus, original, response)
    _same(values['derived-candidate.json'], candidate)
    _same(values['derived-assembly.json'], assembly)
    binding = {'schema_version': 1, 'scope': 'fox-clause-diagnostic-invocation-assembly-v1',
               'analysis_checkpoint_sha256': hashlib.sha256(raw['analysis/mapper.json']).hexdigest(),
               'analysis_invocation_sha256': canonical_hash(invocation),
               'assembly_sha256': canonical_hash(assembly), 'candidate_sha256': canonical_hash(candidate),
               'analysis_request_sha256': canonical_hash(compact),
               'source_binding': identity['source_hash'], 'raw_model_output': False}
    _same(values['assembly-binding.json'], binding)
    payload = review_envelope(focus, original, compact, analysis, candidate, assembly, binding)
    review, review_invocation = _checked_role(raw, values, 'review', 'reviewer', original_target, payload, identity)
    if invocation['room_id'] == review_invocation['room_id']:
        _fail()
    checked = validate_design_review(focus, candidate, review)
    if checked['verdict'] != 'APPROVED':
        _fail()
    _same(values['review-receipt.json'], checked)
    intent = values['diagnostic-intent.json']
    basis = intent['approval_basis']
    if type(basis) is not str or not basis.strip() or len(basis) > 2000:
        _fail()
    summary = {'scope': 'one-source-bound-clause-analysis-diagnostic-not-conversion',
               'job_id': identity['job_id'], 'maximum_analysis_calls': 1, 'maximum_review_calls': 1,
               'automatic_retry': False, 'source_binding': identity['source_hash'],
               'focus_request_sha256': canonical_hash(focus), 'original_candidate_sha256': canonical_hash(original),
               'analysis_request_sha256': canonical_hash(compact), 'module_sha256': ASSEMBLER_SHA256,
               'original_target_sha256': canonical_hash(original_target),
               'analysis_target_sha256': canonical_hash(stage_target), 'clause_count': 2,
               'whole_clause_bytes': [clause['unit']['bytes'] for clause in compact['clauses']],
               'production_profile_activated': False, 'production_run_resumed': False, 'apex_imported': False,
               'approval_basis': basis}
    _same(intent, summary)
    result = values['result.json']
    reported_count = result['original_job_files_unchanged']
    if type(reported_count) is not int or not 0 < reported_count <= 100_000:
        _fail()
    _same(result, {**summary, 'status': 'CLAUSE_DIAGNOSTIC_COMPLETED',
                  'analysis_room_id': invocation['room_id'], 'analysis_output_sha256': canonical_hash(analysis),
                  'derived_candidate_sha256': canonical_hash(candidate),
                  'analysis_statuses': {row['source_attribute']: row['status'] for row in response['analyses']},
                  'review_room_id': review_invocation['room_id'], 'review_verdict': checked['verdict'],
                  'approved_structured_design': True, 'finding_count': len(review['findings']),
                  'finding_codes': [row['code'] for row in review['findings']],
                  'original_job_files_unchanged': reported_count, 'business_behavior_accepted': False,
                  'diagnostic_not_production_continuation': True})
    provenance = {'schema_version': 1, 'scope': 'fox-retained-clause-diagnostic-proof-v1',
                  **identity, 'focus_id': focus['focus_id'], 'focus_request_sha256': canonical_hash(focus),
                  'original_candidate_sha256': canonical_hash(original),
                  'original_target_sha256': canonical_hash(original_target),
                  'analysis_target_sha256': canonical_hash(stage_target),
                  'analysis_role': deepcopy(analysis_role),
                  'reviewer_role': deepcopy(roles['reviewer']),
                  'analysis_invocation': deepcopy(invocation), 'review_invocation': deepcopy(review_invocation),
                  'review_request_sha256': canonical_hash(payload), 'assembly_binding': deepcopy(binding),
                  'candidate_sha256': canonical_hash(candidate), 'file_manifest': deepcopy(manifest),
                  'file_manifest_sha256': canonical_hash(manifest),
                  'checked_json_file_names': sorted(JSON_FILES), 'installed_assembler_sha256': ASSEMBLER_SHA256,
                  'retained_module_bytes_checked': False,
                  'clause_analyses': deepcopy(response['analyses']),
                  'raw_full_blueprint_model_output': False, 'derived_diagnostic': True,
                  'approval_basis_is_authority': False, 'epoch_adoption_authorized': False,
                  'original_job_unchanged_independently_verified': False,
                  'generation_ready': False, 'native_apex_generated': False,
                  'native_apex_validity_verified': False, 'import_verified': False,
                  'business_behavior_accepted': False}
    return deepcopy(candidate), deepcopy(checked), provenance
