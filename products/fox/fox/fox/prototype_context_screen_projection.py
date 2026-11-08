"""Pure, source-bound removal of exact prior context screen declarations.

No pipeline integration, I/O, model calls or approval. Callers reconstruct the
packet/plan and prior reviewed views from preserved originals and independently
verify their provenance, target and consent. Well-formed reference hashes are
technical bindings only, not evidence of permission or actual review.
"""
from copy import deepcopy

from . import forms_design_review as review
from . import prototype_design_context as context
from .forms_blueprint import _bounded_json
from .opaf import canonical_hash
from .prototype_focus_projection import source_fact_gate

PROJECTION_SCOPE = 'fox-context-screen-projection-v1'
MAX_RECEIPT_BYTES = 500_000
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, StopIteration, IndexError)


def _fail():
    raise ValueError('Invalid source-bound context screen projection.') from None


def _same(left, right):
    if canonical_hash(left) != canonical_hash(right):
        _fail()


def project_context_screens(packet, full_plan, candidates, proof_refs, *,
                            expected_source_binding, expected_plan_sha256,
                            expected_focus_id, expected_request_sha256,
                            expected_raw_candidate_sha256, expected_target_sha256):
    """Return (candidate, evidence receipt), with ONLY a possible screens delta.

    candidates is a nonempty contiguous plan prefix ending with the raw current
    candidate. proof_refs binds EVERY prior candidate (no future/current refs),
    using context.REFERENCE_SCOPE. All expected pins are independent caller
    inputs, not self-attestations. A no-duplicate candidate returns an explicit
    NO_CHANGE receipt. Both outcomes still require independent semantic review.
    Originals and retained prior reviews must be preserved, never overwritten.
    """
    try:
        return _project(packet, full_plan, candidates, proof_refs,
                        expected_source_binding, expected_plan_sha256,
                        expected_focus_id, expected_request_sha256,
                        expected_raw_candidate_sha256, expected_target_sha256)
    except _ERRORS:
        _fail()


def _project(packet, plan, candidates, refs, source_pin, plan_pin, focus_pin,
             request_pin, raw_pin, target):
    for pin in (source_pin, plan_pin, request_pin, raw_pin, target):
        context._sha(pin)
    _same(packet['source_binding'], source_pin)
    objects, _, requests, ownership = context._plan(packet, plan)
    _same(canonical_hash(plan), plan_pin)
    _bounded_json(candidates)
    if (type(candidates) is not list or not 1 <= len(candidates) <= len(requests)
            or type(refs) is not dict or type(focus_pin) is not str):
        _fail()
    ids = [c['focus_id'] for c in candidates]
    if ids != list(requests)[:len(ids)] or ids[-1] != focus_pin or set(refs) != set(ids[:-1]):
        _fail()
    request, raw = requests[focus_pin], candidates[-1]
    _same(canonical_hash(request), request_pin)
    source_fact_gate(packet, request, raw)
    _same(canonical_hash(raw), raw_pin)
    # Validate prior bindings and full source/ancestor/behavior context before
    # considering any deletion. This cannot authenticate historical provenance.
    prior_summary = None
    if candidates[:-1]:
        prior_summary = context.validate_prefix_context(packet, plan, candidates[:-1], refs,
            expected_target_sha256=target)
    prior_screens, prior_mappings = {}, {}
    for prior in candidates[:-1]:
        for mapping in prior['blueprint']['objects']:
            prior_mappings[mapping['source_object_id']] = mapping
        for screen in prior['blueprint']['screens']:
            if screen['id'] in prior_screens:
                _fail()
            prior_screens[screen['id']] = (screen, prior['focus_id'])
    owned = {row['id']: row for row in request['owned_objects']}
    contextual = {row['id']: row for row in request['context_objects']}
    removed, kept, seen = [], [], set()
    for index, screen in enumerate(raw['blueprint']['screens']):
        screen_id = screen['id']
        if screen_id in seen:
            _fail()
        seen.add(screen_id)
        if screen_id not in prior_screens:
            kept.append(deepcopy(screen))
            continue
        previous, prior_focus = prior_screens[screen_id]
        _same(screen, previous)  # Full declaration, not just ID or title.
        owners = [ref for ref, row in prior_mappings.items()
                  if objects[ref]['kind'] == 'Block' and row['disposition'] == 'proposed'
                  and row.get('screen_id') == screen_id]
        if len(owners) != 1:
            _fail()
        owner_id = owners[0]
        if (owner_id in owned or owner_id not in contextual or ownership[owner_id] != prior_focus
                or screen_id != 'screen-' + owner_id):
            _fail()
        references = []
        for mapping in raw['blueprint']['objects']:
            if mapping.get('screen_id') != screen_id:
                continue
            source = owned[mapping['source_object_id']]
            if (source['kind'] not in ('Item', 'Trigger') or source['block_id'] != owner_id
                    or mapping['disposition'] != 'proposed' or 'native_component' in mapping):
                _fail()
            ancestors, parent = set(), source['parent_id']
            while parent is not None:
                if parent in ancestors or parent not in objects:
                    _fail()
                ancestors.add(parent)
                parent = objects[parent]['parent_id']
            if owner_id not in ancestors:
                _fail()
            references.append(source['id'])
        # An unused duplicate is ambiguous rather than an inferred association.
        if not references:
            _fail()
        removed.append({'screen_index': index, 'declaration': deepcopy(screen),
            'source_block': deepcopy(objects[owner_id]),
            'owner_mapping': deepcopy(prior_mappings[owner_id]),
            'prior_focus_id': prior_focus, 'prior_reference': deepcopy(refs[prior_focus]),
            'current_reference_source_ids': references})
    candidate = deepcopy(raw)
    candidate['blueprint']['screens'] = kept
    source_fact_gate(packet, request, candidate)
    audit = context.build_review_context(packet, plan, [*candidates[:-1], candidate], refs,
        expected_target_sha256=target, focus_id=focus_pin)
    # Frozen context checks Items; also require subordinate Triggers to borrow
    # only their own source Block, including the NO_CHANGE path.
    for row in audit['owned_rows']:
        screen = row['screen_context']
        if screen is not None and row['source']['kind'] in ('Item', 'Trigger'):
            if (row['source']['block_id'] != screen['source_block']['id']
                    or screen['source_block']['id'] not in {a['source']['id'] for a in row['ancestors']}):
                _fail()
    receipt = {'schema_version': 1, 'scope': PROJECTION_SCOPE,
        'source_binding': source_pin, 'focus_plan_sha256': plan_pin,
        'focus_id': focus_pin, 'focus_request_sha256': request_pin,
        'target_profile_sha256': target, 'raw_candidate_sha256': raw_pin,
        'candidate_sha256': canonical_hash(candidate),
        'status': 'PROJECTED_UNREVIEWED' if removed else 'NO_CHANGE',
        'removed_screens': removed,
        'prior_prefix_sha256': canonical_hash(candidates[:-1]),
        'prior_references_sha256': canonical_hash(refs),
        'prior_prefix_check_sha256': canonical_hash(prior_summary),
        'derived_review_context_sha256': canonical_hash(audit),
        'only_screen_declarations_changed': True, 'raw_model_output': False,
        'independent_review_required': True, 'semantic_equivalence_asserted': False,
        'caller_must_reconstruct_prior_reviewed_views': True,
        'caller_must_preserve_originals': True, 'ai_approval_granted': False,
        **deepcopy(context._FALSE)}
    review._canonical(receipt, MAX_RECEIPT_BYTES)
    return candidate, receipt


def validate_context_screen_projection(candidate, receipt, packet, full_plan,
                                       candidates, proof_refs, **bindings):
    """Rebuild against fresh inputs/pins; reject receipt or behavior tampering.

    Returns a detached receipt, not approval, adoption or provenance evidence.
    """
    try:
        review._canonical(candidate, review.MAX_CANDIDATE_BYTES)
        review._canonical(receipt, MAX_RECEIPT_BYTES)
        expected, evidence = project_context_screens(packet, full_plan, candidates, proof_refs, **bindings)
        _same(candidate, expected)
        _same(receipt, evidence)
        return deepcopy(evidence)
    except _ERRORS:
        _fail()
