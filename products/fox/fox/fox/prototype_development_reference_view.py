"""Versioned initial development view with exact reference compatibility.

Original mapper responses remain immutable. Derived candidates always pass the
standard gates and receive a new independent review before native generation.
"""
from pathlib import Path

from .opaf import OpafError, canonical_hash
from .prototype_chunk_evidence import POLICY, project_chunk_evidence
from .prototype_focus_projection import source_fact_gate

SCOPE = 'fox-development-reference-view-v1'


def enabled(root):
    from .prototype_mapping_epochs import read
    from .prototype_job import read_prototype_snapshot
    root = Path(root)
    binding = read(root / 'binding.json')
    resume = root / 'development-reference-resume.json'
    if 'chunk_evidence_policy' in binding:
        snapshot, _ = read_prototype_snapshot(root.parent)
        selected = snapshot.get('prototype', {})
        if (binding['chunk_evidence_policy'] != POLICY
                or selected.get('chunk_evidence_policy') != POLICY
                or selected.get('processing_mode') != 'development'
                or selected.get('delivery_mode') != 'apexlang_package'
                or selected.get('development_processing_sha256') != binding.get('development_processing_sha256')
                or resume.exists() or resume.is_symlink()):
            raise OpafError('Development reference policy differs from its immutable admission.')
        return True
    if resume.exists() or resume.is_symlink():
        from .prototype_development_reference_resume import technical
        if technical(root) is None:
            raise OpafError('Development reference continuation is unavailable.')
        return True
    return False


def assert_initial_only(root):
    from . import prototype_preclaim_continuation as preclaim
    from . import prototype_query_omission_continuation as omission
    from . import prototype_candidate_continuation as candidate_format
    from . import prototype_direct_container as container
    from . import prototype_validation_retry as validation_retry
    from . import prototype_dsc_identity_repair as dsc
    root = Path(root)
    if (preclaim.present(root) or omission.present(root) or candidate_format.present(root)
            or container.present(root) or validation_retry.present(root.parent) or dsc.present(root)
            or any((root / name).exists() or (root / name).is_symlink() for name in ('epochs',))
            or any((root.parent / name).exists() or (root.parent / name).is_symlink()
                   for name in ('mapping-epochs', 'mapping-continuation.json', container.OWNER_RECORD))):
        raise OpafError('Development reference compatibility cannot reinterpret a legacy continuation.')


def project(documents, packet, request, raw, target):
    """Pure composition shared by execution, continuation plan and reconstruction."""
    from .forms_understanding_packet import local_packet
    from .prototype_claim_resolution import resolve_claim_owners
    from .prototype_candidate_format import normalize_candidate
    from .prototype_direct_container import project as container_project
    from .design_provider import is_direct
    if canonical_hash(packet) != canonical_hash(local_packet(documents)):
        raise ValueError('Reference projection requires the original complete source packet.')
    owner_receipt = format_receipt = chunk_receipt = container_receipt = None
    try:
        candidate, owner_receipt = resolve_claim_owners(request, raw)
    except ValueError:
        candidate, format_receipt = normalize_candidate(documents, request, raw)
    try:
        candidate, chunk_receipt = project_chunk_evidence(documents, request, candidate)
    except ValueError:
        if format_receipt is not None:
            raise
        candidate, format_receipt = normalize_candidate(documents, request, candidate)
        candidate, chunk_receipt = project_chunk_evidence(documents, request, candidate)
    if is_direct(target):
        candidate, container_receipt = container_project(packet, request, candidate)
    source_fact_gate(packet, request, candidate)
    if all(value is None for value in (owner_receipt, format_receipt, chunk_receipt, container_receipt)):
        return raw, None
    return candidate, {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY,
        'source_binding': request['source_binding'], 'focus_id': request['focus_id'],
        'request_sha256': canonical_hash(request), 'raw_candidate_sha256': canonical_hash(raw),
        'candidate_sha256': canonical_hash(candidate), 'owner_resolution': owner_receipt,
        'candidate_format': format_receipt, 'chunk_evidence': chunk_receipt,
        'container_retention': container_receipt, 'independent_review_required': True,
        'business_behavior_accepted': False}


def active_focus(root, packet, plan, request, target, previous, *, runtime=None):
    from . import prototype_mapping_epochs as epochs
    from .prototype_dsc_identity_repair import documents
    from .design_provider import invocation_id
    root = Path(root)
    if not enabled(root):
        raise OpafError('No exact development reference policy is enabled.')
    assert_initial_only(root)
    if epochs.technical_record(root) is not None:
        raise OpafError('Development reference policy cannot reinterpret a legacy epoch.')
    directory = root / request['focus_id']
    write = runtime is not None
    if write:
        directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink():
        raise OpafError('Unsafe development reference focus directory.')
    epochs.save(directory / 'request.json', request, write)
    identity = {'job_id': root.parent.name, 'source_hash': plan['source_binding']}
    raw, mapper = epochs._role(directory, 'mapper', request, target, identity, runtime)
    candidate, evidence = project(documents(root), packet, request, raw, target)
    gate = source_fact_gate(packet, request, candidate)
    derived = ('projection-candidate.json', 'projection-receipt.json', 'reviewer-request.json')
    if evidence is not None:
        payload = epochs.extended_review(request, candidate, raw, 'development_source_reference_projection', evidence)
        for name, value in zip(derived, (candidate, evidence, payload)):
            epochs.save(directory / name, value, write)
    else:
        if any((directory / name).exists() or (directory / name).is_symlink() for name in derived):
            raise OpafError('Unexpected development reference projection evidence.')
        payload = {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
    review, reviewer = epochs._role(directory, 'reviewer', payload, target, identity, runtime)
    used = {invocation_id(mapper)}
    for view in previous:
        for role in ('mapper_invocation', 'reviewer_invocation'):
            used.add(invocation_id(view['proof'][role]))
    if invocation_id(reviewer) in used:
        raise OpafError('Development projection requires a new independent reviewer invocation.')
    checked = epochs._review(request, candidate, review, directory)
    epochs.save(directory / 'review-receipt.json', checked, write)
    proof = {'focus_id': request['focus_id'], 'candidate_sha256': canonical_hash(candidate),
        'source_fact_check': gate, 'review_request_sha256': canonical_hash(payload),
        'review_sha256': canonical_hash(review), 'review_receipt_sha256': canonical_hash(checked),
        'active_directory': directory.relative_to(root).as_posix(),
        'mapper_invocation': mapper, 'reviewer_invocation': reviewer,
        'technical_evidence_sha256': canonical_hash(evidence) if evidence else None}
    return {'candidate': candidate, 'checked': checked, 'proof': proof}
