"""Deterministic claim reference resolution; never changes a model response."""
from copy import deepcopy

from . import forms_design_review
from .native_pipeline import _json, _save_once
from .opaf import OpafError, canonical_hash

STRATEGY = 'resolve-code-unit-owners-v1'
ARTIFACTS = ('mapper-resolved.json', 'mapper-resolution.json')


def resolve_claim_owners(request, raw):
    """Resolve only evidenced code-unit IDs to their exact owned object IDs.

    Return an unchanged valid legacy candidate without creating a new contract.
    Everything except the erroneous source_object_id fields remains identical.
    """
    owned = {row['id'] for row in request['owned_objects']}
    forms_design_review._canonical(raw, forms_design_review.MAX_CANDIDATE_BYTES)
    try:
        forms_design_review._candidate_shape(raw, request, owned)
        return raw, None
    except ValueError as error:
        original_error = error
    objects = request['owned_objects'] + request['context_objects']
    object_ids = [row['id'] for row in objects]
    units = request['code_units']
    unit_ids = [row['id'] for row in units]
    if (len(set(object_ids)) != len(object_ids) or len(set(unit_ids)) != len(unit_ids)
            or set(object_ids) & set(unit_ids)):
        raise ValueError('Ambiguous source-object/code-unit identity.')
    unit_map = {row['id']: row for row in units}
    result, changes = deepcopy(raw), []
    for index, claim in enumerate(result['blueprint']['claims']):
        ref = claim['source_object_id']
        if ref in owned:
            continue
        unit = unit_map.get(ref)
        refs = claim['evidence_refs']
        if (unit is None or unit['owner_id'] not in owned or type(refs) is not list
                or ref not in refs or len(set(refs)) != len(refs)
                or any(value != unit['owner_id'] and
                       (value not in unit_map or unit_map[value]['owner_id'] != unit['owner_id']) for value in refs)):
            raise ValueError('Claim code-unit owner is unknown, contextual or inconsistently evidenced.')
        claim['source_object_id'] = unit['owner_id']
        changes.append({'claim_index': index, 'claim_id': claim['id'],
                        'code_unit_id': ref, 'source_object_id': unit['owner_id']})
    if not changes:
        raise original_error
    forms_design_review._canonical(result, forms_design_review.MAX_CANDIDATE_BYTES)
    forms_design_review._candidate_shape(result, request, owned)
    receipt = {'schema_version': 1, 'scope': 'fox-prototype-claim-owner-resolution-v1',
        'strategy': STRATEGY, 'source_binding': request['source_binding'], 'focus_id': request['focus_id'],
        'request_sha256': canonical_hash(request), 'raw_candidate_sha256': canonical_hash(raw),
        'candidate_sha256': canonical_hash(result), 'resolutions': changes}
    return result, receipt


def resolved_mapper(directory, request, raw, *, write=False):
    """Create/check separate immutable evidence; original mapper.json is read-only."""
    candidate, receipt = resolve_claim_owners(request, raw)
    paths = [directory / name for name in ARTIFACTS]
    if receipt is None:
        if any(path.exists() or path.is_symlink() for path in paths):
            raise OpafError('Unexpected mapper resolution evidence for an unchanged candidate.')
        return candidate, None
    if write:
        _save_once(paths[0], candidate)
        _save_once(paths[1], receipt)
    if (canonical_hash(_json(paths[0])) != canonical_hash(candidate)
            or canonical_hash(_json(paths[1])) != canonical_hash(receipt)):
        raise OpafError('Mapper resolution differs from its original request and response.')
    return candidate, receipt
