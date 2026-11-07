"""Exact source-fact checks and reversible technical focus projections.

No source facts are silently discarded to pass a gate. Excluded context metadata
and rationale remain verbatim in a receipt and require a new independent review.
"""
from copy import deepcopy

from .forms_blueprint import source_fact_index, validate_claim_evidence
from .forms_design_review import _candidate_shape, _canonical, MAX_CANDIDATE_BYTES
from .opaf import canonical_hash

STRATEGY = 'repair-source-facts-and-project-context-v1'


def fact_diagnostics(packet, request, candidate):
    objects, evidence, allowed = source_fact_index(packet)
    if candidate['blueprint']['source_binding'] != request['source_binding'] or packet['source_binding'] != request['source_binding']:
        raise ValueError('Source-fact check has a stale source binding.')
    owned = {row['id'] for row in request['owned_objects']}
    diagnostics = []
    for index, claim in enumerate(candidate['blueprint']['claims']):
        if claim['source_object_id'] not in owned:
            raise ValueError('Source-fact claims must retain focus ownership.')
        try:
            validate_claim_evidence(claim, objects, evidence, allowed)
        except ValueError:
            if claim.get('status') != 'source_fact':
                raise
            diagnostics.append({'claim_index': index, 'claim_id': claim['id'],
                'claim_sha256': canonical_hash(claim), 'kind': claim['kind'],
                'code': 'SOURCE_FACT_NOT_EXACT_WHITELISTED_EVIDENCE'})
    return diagnostics


def source_fact_gate(packet, request, candidate):
    _canonical(candidate, MAX_CANDIDATE_BYTES)
    _candidate_shape(candidate, request, {row['id'] for row in request['owned_objects']})
    if fact_diagnostics(packet, request, candidate):
        raise ValueError('Focus contains unsupported source-fact claims; AI approval is not source validation.')
    return {'schema_version': 1, 'scope': 'fox-focus-source-fact-check-v1',
        'source_binding': request['source_binding'], 'request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(candidate), 'source_facts_checked': True,
        'source_fact_claims': sum(row['status'] == 'source_fact' for row in candidate['blueprint']['claims']),
        'business_behavior_accepted': False}


def repair_requirements(packet, request, raw):
    """Recognize ONLY the bounded two unsupported clause claims, not any error."""
    _candidate_shape(raw, request, {row['id'] for row in request['owned_objects']})
    diagnostics = fact_diagnostics(packet, request, raw)
    if len(diagnostics) != 2 or {row['kind'] for row in diagnostics} != {'block.where', 'block.order'}:
        raise ValueError('Repair requires exactly the two source-fact clause defects.')
    attributes = {'block.where': 'WhereClause', 'block.order': 'OrderByClause'}
    required = []
    selected = {chunk['code_unit_id']: chunk for chunk in request['chunks']}
    for diagnostic in diagnostics:
        claim = raw['blueprint']['claims'][diagnostic['claim_index']]
        matches = [unit for unit in request['code_units'] if unit['owner_id'] == claim['source_object_id']
                   and unit['source_attribute'] == attributes[claim['kind']] and unit['id'] in selected]
        if len(matches) != 1 or 'FOX_REDACTED_' in selected[matches[0]['id']]['text']:
            raise ValueError('Exact complete unredacted clause evidence is required for this repair.')
        unit = matches[0]
        # Do not accept other claims/actions as missing behavior coverage. The
        # bounded repair exists because these exact units have no other design.
        if any(unit['id'] in row['evidence_refs'] and row['id'] != claim['id']
               and row['kind'] == 'behavior.intent' for row in raw['blueprint']['claims']):
            raise ValueError('Unexpected existing clause interpretation requires a separate review.')
        required.append({'unit_id': unit['id'], 'owner_id': unit['owner_id'], 'source_attribute': unit['source_attribute'],
                         'unit_sha256': unit['sha256'], 'defective_claim_id': claim['id']})
    return {'schema_version': 1, 'scope': 'fox-focus-clause-repair-requirements-v1',
        'diagnostics': diagnostics, 'required_behavior_units': required,
        'preserve_objects_screens_and_unrelated_design': True,
        'exact_source_fact_whitelist_required': True, 'simple_status_relabeling_forbidden': True,
        'each_required_unit_needs_behavior_intent_and_action': True,
        'external_semantics_must_remain_uncertain': True, 'automatic_repair_loop_permitted': False}


def validate_repair(packet, request, raw, candidate, requirements):
    if canonical_hash(requirements) != canonical_hash(repair_requirements(packet, request, raw)):
        raise ValueError('Repair requirements differ from fresh source diagnostics.')
    source_fact_gate(packet, request, candidate)
    before, after = raw['blueprint'], candidate['blueprint']
    for category in ('objects', 'screens', 'relationships', 'assumptions'):
        if canonical_hash(before[category]) != canonical_hash(after[category]):
            raise ValueError('Repair changed unrelated rendering or design choices.')
    bad = {row['defective_claim_id'] for row in requirements['required_behavior_units']}
    old_claims = {row['id']: row for row in before['claims']}
    new_claims = {row['id']: row for row in after['claims']}
    if len(old_claims) != len(before['claims']) or len(new_claims) != len(after['claims']):
        raise ValueError('Repair has duplicate claim identifiers.')
    for ref, row in old_claims.items():
        if ref not in bad and (ref not in new_claims or canonical_hash(row) != canonical_hash(new_claims[ref])):
            raise ValueError('Repair changed an unrelated original claim.')
    behavior_ids = set()
    for unit in requirements['required_behavior_units']:
        matches = [row for row in after['claims'] if row['source_object_id'] == unit['owner_id']
            and row['kind'] == 'behavior.intent' and row['status'] in ('proposal', 'unresolved')
            and type(row['value']) is str and row['value'].strip()
            and unit['unit_id'] in row['evidence_refs']]
        if not matches or not any(any(row['id'] in action['claim_ids'] for action in after['actions']) for row in matches):
            raise ValueError('Repaired clause needs evidenced behavior.intent and an action reference.')
        for row in matches:
            unsupported = old_claims[unit['defective_claim_id']]['value']
            if (row['value'] == unsupported or type(unsupported) is str and
                    ' '.join(row['value'].split()).casefold() == ' '.join(unsupported.split()).casefold()):
                raise ValueError('Relabeling an unsupported fact is not clause analysis.')
            behavior_ids.add(row['id'])
    changed = [row for row in after['claims'] if row['id'] not in old_claims or row['id'] in bad]
    if any(row['id'] not in behavior_ids for row in changed):
        raise ValueError('Repair added claims outside the exact affected clause coverage.')
    for category in ('actions', 'questions'):
        originals = {row['id']: row for row in before[category]}
        actual = {row['id']: row for row in after[category]}
        if any(ref not in actual or canonical_hash(row) != canonical_hash(actual[ref]) for ref, row in originals.items()):
            raise ValueError('Repair modified unrelated actions or questions.')
        for ref, row in actual.items():
            if ref in originals:
                continue
            if category == 'actions' and (not row['claim_ids'] or not set(row['claim_ids']) <= behavior_ids):
                raise ValueError('Repair action is outside affected behavior claims.')
            if category == 'questions' and row['source_object_id'] not in {unit['owner_id'] for unit in requirements['required_behavior_units']}:
                raise ValueError('Repair question is outside affected source ownership.')
    return source_fact_gate(packet, request, candidate)


def project_context(packet, request, raw, prior, prior_proof_sha256, prefix_candidates, *, strict_known_case=True):
    """Project exact duplicate context metadata, retaining raw rationale evidence."""
    owned = {row['id'] for row in request['owned_objects']}
    context = {row['id']: row for row in request['context_objects']}
    candidate = deepcopy(raw)
    blueprint, previous = candidate['blueprint'], prior['blueprint'] if prior is not None else {'objects': [], 'screens': []}
    extras = [row for row in blueprint['objects'] if row['source_object_id'] not in owned]
    if ((len(extras) != 1 if strict_known_case else len(extras) not in (0, 1))
            or extras and context.get(extras[0]['source_object_id'], {}).get('kind') != 'Block'):
        raise ValueError('Projection requires one exact context Block duplicate.')
    matches, duplicate_screens, screen_id = [], [], None
    if extras:
        excluded = extras[0]
        matches = [row for row in previous['objects'] if row['source_object_id'] == excluded['source_object_id']]
        if len(matches) != 1 or canonical_hash({k: v for k, v in matches[0].items() if k != 'reason'}) != canonical_hash({k: v for k, v in excluded.items() if k != 'reason'}):
            raise ValueError('Context Block mapping does not match fresh active prior proof.')
        screen_id = excluded.get('screen_id')
        duplicate_screens = [row for row in blueprint['screens'] if row['id'] == screen_id]
        prior_screens = [row for row in previous['screens'] if row['id'] == screen_id]
        if (len(prior_screens) != 1 or len(duplicate_screens) > 1
                or strict_known_case and len(duplicate_screens) != 1
                or duplicate_screens and canonical_hash(duplicate_screens) != canonical_hash(prior_screens)):
            raise ValueError('Context screen identity/title does not exactly match active prior proof.')
    removed_claims = [row for row in blueprint['claims'] if row['source_object_id'] not in owned]
    referenced = {ref for value in [raw, *prefix_candidates] for category in ('actions', 'relationships')
                  for row in value['blueprint'][category] for ref in row['claim_ids']}
    objects, evidence, allowed = source_fact_index(packet)
    if len(removed_claims) != 1 if strict_known_case else len(removed_claims) not in (0, 1):
        raise ValueError('Only one unreferenced context metadata fact may be projected.')
    for row in removed_claims:
        if (not extras or row['source_object_id'] != extras[0]['source_object_id'] or row['kind'] != 'object.kind'
                or row['status'] != 'source_fact' or row['value'] != 'Block' or row['id'] in referenced):
            raise ValueError('Context metadata is behavioral, referenced or not the exact permitted fact.')
        validate_claim_evidence(row, objects, evidence, allowed)
    blueprint['objects'] = [row for row in blueprint['objects'] if row['source_object_id'] in owned]
    excluded_screen_ids = {row['id'] for row in duplicate_screens}
    blueprint['screens'] = [row for row in blueprint['screens'] if row['id'] not in excluded_screen_ids]
    blueprint['claims'] = [row for row in blueprint['claims'] if row['source_object_id'] in owned]
    aliases = []
    for row in blueprint['claims']:
        if row['kind'] == 'object.item_type' and row['status'] == 'source_fact':
            if objects[row['source_object_id']]['kind'] != 'Item':
                raise ValueError('Item alias requires an owned Item.')
            old = deepcopy(row); row['kind'] = 'item.item_type'
            validate_claim_evidence(row, objects, evidence, allowed)
            aliases.append({'before': old, 'after': deepcopy(row)})
    if strict_known_case and len(aliases) != 2:
        raise ValueError('This bounded projection requires exactly two proven Item aliases.')
    from .prototype_claim_resolution import resolve_claim_owners
    candidate, owner_resolution = resolve_claim_owners(request, candidate)
    if not extras and not aliases and owner_resolution is None:
        raise ValueError('There is no exact technical projection to apply.')
    gate = source_fact_gate(packet, request, candidate)
    receipt = {'schema_version': 1, 'scope': 'fox-focus-context-projection-v1', 'strategy': STRATEGY,
        'source_binding': request['source_binding'], 'request_sha256': canonical_hash(request),
        'raw_candidate_sha256': canonical_hash(raw), 'candidate_sha256': canonical_hash(candidate),
        'prior_active_proof_sha256': prior_proof_sha256, 'excluded_objects': deepcopy(extras),
        'prior_objects': deepcopy(matches), 'excluded_screens': deepcopy(duplicate_screens),
        'excluded_claims': deepcopy(removed_claims), 'aliases': aliases,
        'rationale_semantic_equivalence_asserted': False, 'source_fact_check': gate}
    if owner_resolution is not None:
        receipt['owner_resolution_v1'] = owner_resolution
    return candidate, receipt
