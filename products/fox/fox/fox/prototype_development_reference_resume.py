"""Exact stopped-first-mapper continuation proof; no writes or execution.

The old development snapshot and all original evidence remain immutable. Only
selected chunk references may project to their exact owned source code units.
These records authorize no provider operation without the normal current-owner,
source-history, destination and durable admission checks owned by the caller.
"""
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re
import stat

from .opaf import OpafError, canonical_hash
from .prototype_chunk_evidence import POLICY, project_chunk_evidence

SCOPE = 'fox-prototype-development-reference-resume-v1'
OWNER_RECORD = 'development-reference-resume.json'
TECHNICAL = 'development-reference-resume.json'
EVENT = 'approved_prototype_development_reference_resume'
_BASE = {'binding.json', 'sources-manifest.json', 'packet.json', 'assessment.json'}
_FIRST = {'request.json', 'mapper.json', 'mapper-intent.json', 'mapper-target.json'}
_FUTURE_FOCUS = _FIRST | {'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json',
    'reviewer-request.json', 'review-receipt.json', 'mapper-resolved.json',
    'mapper-resolution.json', 'projection-candidate.json', 'projection-receipt.json'}
_FUTURE_ROOT = {'merged-blueprint.json', 'native-plan.json', 'review-index.json',
    'rendered.json', 'candidate-apexlang.zip', 'package-request.json',
    'offline-validation.json', 'apexlang-package.zip', 'package-publication.json'}
_PLAN_KEYS = {'schema_version', 'scope', 'policy', 'job_id', 'project_id', 'owner',
    'snapshot_sha256', 'development_processing_sha256', 'original_consent_sha256',
    'source_hash', 'source_binding', 'selected_source_set_id', 'target_profile_sha256',
    'focus_plan_sha256', 'approved_chunk_hashes', 'first_focus_id',
    'first_request_sha256', 'first_mapper_sha256', 'first_mapper_invocation_sha256',
    'raw_candidate_sha256', 'projected_candidate_sha256', 'projection_receipt_sha256',
    'projection_claim_count', 'before_files', 'remaining_operations'}


def _fail():
    raise OpafError('Development reference continuation is changed, uncertain or outside its exact scope.') from None


def _same(left, right):
    if canonical_hash(left) != canonical_hash(right):
        _fail()


def _safe(path, *, directory=False):
    info = path.lstat()
    if (path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400
            or (not stat.S_ISDIR(info.st_mode) if directory else
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 20_000_000)):
        _fail()


def _read(path):
    _safe(path)
    return json.loads(path.read_bytes())


def _tree(job):
    """Enumerate ordinary files/dirs without following links or junctions."""
    _safe(job, directory=True)
    files, directories, pending = {}, set(), [job]
    while pending:
        for path in pending.pop().iterdir():
            name = path.relative_to(job).as_posix()
            if len(files) + len(directories) >= 4096:
                _fail()
            if path.is_dir():
                _safe(path, directory=True)
                directories.add(name)
                pending.append(path)
            else:
                _safe(path)
                files[name] = path
    return files, directories


def _hash(path):
    _safe(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reconstruct(job, snapshot, original, target):
    from .prototype_job import validate_prototype_snapshot
    from .forms_understanding_packet import local_packet
    from .forms_focus import build_focus_plan
    from .prototype_admission import bound_focus_limit
    from .design_provider import is_direct, roles, validate_roles
    if not re.fullmatch(r'fox-[a-f0-9]{20}', job.name):
        _fail()
    _safe(job, directory=True)
    _safe(job / 'prototype-pipeline', directory=True)
    _safe(job / 'source-snapshot.json')
    if (type(original) is not bytes or (job / 'source-snapshot.json').read_bytes() != original
            or json.loads(original) != snapshot):
        _fail()
    documents = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    if (selected.get('processing_mode') != 'development'
            or selected.get('delivery_mode') != 'apexlang_package'
            or 'chunk_evidence_policy' in selected
            or 'chunk_evidence_policy' in selected['development_processing']
            or 'retry_of' in snapshot or not is_direct(target)
            or canonical_hash(target) != selected['target_profile_sha256']):
        _fail()
    validate_roles(roles(target))
    packet = local_packet(documents)
    # This deliberately bounded path preserves the full original code selection.
    _same(selected['approved_chunk_hashes'], {row['id']: row['sha256'] for row in packet['chunks']})
    focus = build_focus_plan(documents, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    if not focus['requests'] or canonical_hash(focus) != selected['focus_plan_sha256']:
        _fail()
    binding = {'schema_version': selected['schema_version'], 'job_id': job.name,
        'project_id': snapshot['project_id'], 'project_name': snapshot['project_name'],
        'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256'],
        'profile_sha256': canonical_hash(roles(target)), 'approved_policy_id': selected['approved_policy_id'],
        'development_processing_sha256': selected['development_processing_sha256'],
        'delivery_mode': selected['delivery_mode']}
    if selected['schema_version'] == 2:
        binding['max_owned_objects'] = bound_focus_limit(selected)
    for key in ('metadata_task_policy', 'candidate_format_policy', 'native_input_policy', 'count_guard'):
        if key in selected:
            binding[key] = selected[key]
    root = job / 'prototype-pipeline'
    _same(_read(root / 'binding.json'), binding)
    _same(_read(root / 'packet.json'), packet)
    _same(_read(root / 'sources-manifest.json'), {'source_binding': selected['source_binding'],
        'selected_chunk_hashes': selected['approved_chunk_hashes'], 'files': [
            {'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
            for name, raw in documents]})
    _same(_read(root / 'assessment.json'), {'source_binding': selected['source_binding'],
        'source_count': len(documents), 'source_objects': focus['total_source_objects'],
        'focus_count': len(focus['requests'])})
    for index, (_, raw) in enumerate(documents):
        path = root / 'sources' / f'source-{index:03}.xml'
        _safe(path.parent, directory=True)
        _safe(path)
        if path.read_bytes() != raw:
            _fail()
    return documents, packet, focus


def _baseline_names(documents, focus, selected):
    first = focus['requests'][0]['focus_id']
    names = {'source-snapshot.json', *{'prototype-pipeline/' + name for name in _BASE},
        *{f'prototype-pipeline/sources/source-{i:03}.xml' for i in range(len(documents))},
        *{f'prototype-pipeline/{first}/{name}' for name in _FIRST}}
    if 'metadata_task_policy' in selected:
        names.add(f'prototype-pipeline/{first}/mapper-metadata-task.json')
    return names


def _closure(job, files, directories, documents, focus, selected, *, continued):
    baseline = _baseline_names(documents, focus, selected)
    allowed = set(baseline)
    allowed_dirs = {'prototype-pipeline', 'prototype-pipeline/sources',
                    'prototype-pipeline/' + focus['requests'][0]['focus_id']}
    if continued:
        allowed.update({OWNER_RECORD, 'prototype-pipeline/' + TECHNICAL, 'prototype-result.json'})
        allowed.update('prototype-pipeline/' + name for name in _FUTURE_ROOT)
        allowed_dirs.add('prototype-results')
        for name in files:
            if re.fullmatch(r'prototype-results/[a-f0-9]{64}\.json', name):
                if name.rsplit('/', 1)[-1][:-5] != canonical_hash(_read(files[name])):
                    _fail()
                allowed.add(name)
            if re.fullmatch(r'prototype-pipeline/offline-[a-f0-9]{64}\.log', name):
                if name.rsplit('-', 1)[-1][:-4] != _hash(files[name]):
                    _fail()
                allowed.add(name)
        for request in focus['requests']:
            child = 'prototype-pipeline/' + request['focus_id']
            allowed_dirs.add(child)
            allowed.update(child + '/' + name for name in _FUTURE_FOCUS)
            if 'metadata_task_policy' in selected:
                allowed.update(child + '/' + role + '-metadata-task.json' for role in ('mapper', 'reviewer'))
    if not baseline <= files.keys() or not files.keys() <= allowed or not directories <= allowed_dirs:
        _fail()


def _derive(job, snapshot, original, target, *, before_files=None):
    documents, packet, focus = _reconstruct(job, snapshot, original, target)
    selected = snapshot['prototype']
    files, directories = _tree(job)
    _closure(job, files, directories, documents, focus, selected, continued=before_files is not None)
    baseline = {name: _hash(files[name]) for name in sorted(_baseline_names(documents, focus, selected))}
    if before_files is not None:
        _same(baseline, before_files)
    first = focus['requests'][0]
    child = job / 'prototype-pipeline' / first['focus_id']
    _same(_read(child / 'request.json'), first)
    # Existing historical role verification validates the actual metadata task,
    # complete result, intent, target, invocation and executor environment.
    from .prototype_mapping_epochs import _role as existing_role
    raw, invocation = existing_role(child, 'mapper', first, target,
        {'job_id': job.name, 'source_hash': selected['source_binding']})
    from .prototype_focus_projection import source_fact_gate
    try:
        source_fact_gate(packet, first, raw)
    except ValueError:
        pass
    else:
        _fail()
    _, chunk_receipt = project_chunk_evidence(documents, first, raw)
    if chunk_receipt is None or not chunk_receipt['changes']:
        _fail()
    from .prototype_development_reference_view import project
    candidate, receipt = project(documents, packet, first, raw, target)
    if receipt is None:
        _fail()
    _same(receipt['chunk_evidence'], chunk_receipt)
    source_fact_gate(packet, first, candidate)
    remaining = [{'focus_id': first['focus_id'], 'role': 'reviewer'}]
    for request in focus['requests'][1:]:
        remaining.extend({'focus_id': request['focus_id'], 'role': role} for role in ('mapper', 'reviewer'))
    remaining.extend({'stage': stage} for stage in ('render', 'offline_validate', 'package'))
    plan = {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY,
        'job_id': job.name, 'project_id': snapshot['project_id'], 'owner': snapshot['approvals']['owner'],
        'snapshot_sha256': hashlib.sha256(original).hexdigest(),
        'development_processing_sha256': selected['development_processing_sha256'],
        'original_consent_sha256': canonical_hash(snapshot['approvals']),
        'source_hash': snapshot['source_hash'], 'source_binding': selected['source_binding'],
        'selected_source_set_id': snapshot['selected_source_set_id'],
        'target_profile_sha256': selected['target_profile_sha256'],
        'focus_plan_sha256': selected['focus_plan_sha256'],
        'approved_chunk_hashes': deepcopy(selected['approved_chunk_hashes']),
        'first_focus_id': first['focus_id'], 'first_request_sha256': canonical_hash(first),
        'first_mapper_sha256': canonical_hash(_read(child / 'mapper.json')),
        'first_mapper_invocation_sha256': canonical_hash(invocation),
        'raw_candidate_sha256': canonical_hash(raw), 'projected_candidate_sha256': canonical_hash(candidate),
        'projection_receipt_sha256': canonical_hash(receipt),
        'projection_claim_count': len(chunk_receipt['changes']),
        'before_files': baseline, 'remaining_operations': remaining}
    return plan, candidate, receipt


def inspect(job, snapshot, original, target):
    """Return one deterministic body-free plan; initial tree must be closed."""
    return _derive(Path(job), snapshot, original, target)[0]


def records(plan, owner, approved_at):
    """Pure durable record construction; callers still authenticate/admit."""
    if (type(plan) is not dict or set(plan) != _PLAN_KEYS
            or type(plan.get('schema_version')) is not int or plan['schema_version'] != 1
            or plan['scope'] != SCOPE or plan['policy'] != POLICY
            or type(owner) is not str or not owner or plan['owner'] != owner
            or type(approved_at) not in (int, float) or not math.isfinite(approved_at) or approved_at <= 0):
        _fail()
    technical_record = {'schema_version': 1, 'scope': SCOPE, 'plan': deepcopy(plan),
                        'plan_sha256': canonical_hash(plan)}
    owner_record = {'schema_version': 1, 'scope': SCOPE, 'job_id': plan['job_id'],
        'project_id': plan['project_id'], 'owner': owner, 'approved_at': approved_at,
        'snapshot_sha256': plan['snapshot_sha256'],
        'development_processing_sha256': plan['development_processing_sha256'],
        'original_consent_sha256': plan['original_consent_sha256'],
        'plan_sha256': canonical_hash(plan), 'technical_sha256': canonical_hash(technical_record)}
    return technical_record, owner_record


def technical(root):
    """Pure retained proof; deliberately does not consult any owner database."""
    root = Path(root)
    _safe(root.parent, directory=True)
    _safe(root, directory=True)
    path = root / TECHNICAL
    if not (path.exists() or path.is_symlink()):
        if (root.parent / OWNER_RECORD).exists() or (root.parent / OWNER_RECORD).is_symlink():
            _fail()
        return None
    return validate_technical(root)


def validate_technical(root, record=None):
    root = Path(root)
    _safe(root.parent, directory=True)
    _safe(root, directory=True)
    saved = _read(root / TECHNICAL)
    if record is not None:
        _same(record, saved)
    plan = saved['plan']
    snapshot_path = root.parent / 'source-snapshot.json'
    _safe(snapshot_path)
    original = snapshot_path.read_bytes()
    snapshot = json.loads(original)
    if (not re.fullmatch(r'focus-[a-f0-9]{24}', plan['first_focus_id'])
            or root.name != 'prototype-pipeline'):
        _fail()
    target = _read(root / plan['first_focus_id'] / 'mapper-target.json')
    expected, candidate, receipt = _derive(root.parent, snapshot, original, target,
                                           before_files=plan['before_files'])
    _same(plan, expected)
    _same(saved, records(expected, expected['owner'], 1.0)[0])
    # First-focus derived bytes can appear only as this exact projection.
    child = root / plan['first_focus_id']
    for name, value in (('projection-candidate.json', candidate), ('projection-receipt.json', receipt)):
        path = child / name
        if path.exists() or path.is_symlink():
            _same(_read(path), value)
    return saved


def validate_owner(job, snapshot, original, connection):
    """Require both immutable records plus one exact current-owner DB event."""
    job = Path(job)
    rows = connection.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
        '(object_id=? OR substr(object_id,1,?)=?)',
        (EVENT, job.name, len(job.name) + 1, job.name + ':')).fetchall()
    owner_path = job / OWNER_RECORD
    technical_path = job / 'prototype-pipeline' / TECHNICAL
    has_owner = owner_path.exists() or owner_path.is_symlink()
    has_technical = technical_path.exists() or technical_path.is_symlink()
    if not has_owner and not has_technical and not rows:
        return None
    if not has_owner or not has_technical:
        _fail()
    saved = validate_technical(job / 'prototype-pipeline')
    authorization = _read(owner_path)
    plan = saved['plan']
    expected = records(plan, snapshot['approvals']['owner'], authorization['approved_at'])[1]
    _same(authorization, expected)
    if ((job / 'source-snapshot.json').read_bytes() != original or json.loads(original) != snapshot
            or hashlib.sha256(original).hexdigest() != plan['snapshot_sha256']
            or snapshot['project_id'] != plan['project_id']):
        _fail()
    owners = connection.execute('SELECT owner FROM projects WHERE id=?', (snapshot['project_id'],)).fetchall()
    if ([tuple(row) for row in owners] != [(authorization['owner'],)]
            or [tuple(row) for row in rows] != [(authorization['owner'],
                job.name + ':' + canonical_hash(authorization), authorization['approved_at'])]):
        _fail()
    return authorization
