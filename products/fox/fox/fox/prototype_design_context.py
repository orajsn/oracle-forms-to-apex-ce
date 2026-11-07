"""Pure proposals and partial-prefix design/reference checks, never authority.

Callers reconstruct packet/plan from preserved originals and independently check
source/whole-form consent, target pins and actual retained review/invocation
chains. Proof references below are caller-pinned bindings, NOT attestations. A
supplied approval boolean is not accepted. No review is approved, permission
inferred, model invoked, original changed, file written or application generated.
"""
from copy import deepcopy
import hashlib
import re

from . import forms_design_review as review
from .forms_blueprint import _bounded_json, source_fact_index
from .forms_focus import MAX_PLAN_BYTES, MAX_REQUESTS, PLAN_SCOPE
from .forms_understanding_packet import _canonical as packet_bytes
from .opaf import canonical_hash
from .prototype_focus_projection import source_fact_gate

PROPOSAL_SCOPE = 'fox-form-container-retention-proposal-v1'
REFERENCE_SCOPE = 'fox-active-design-proof-reference-v1'
PREFIX_SCOPE = 'fox-design-prefix-context-v1'
REVIEW_SCOPE = 'fox-design-review-context-v1'
MAX_CONTEXT_BYTES = 500_000
RETENTION_REASON = ('Retain the source FormModule as nonvisual container metadata; descendant mappings '
                    'require separate context validation and independent review. No executable behavior '
                    'or whole-form omission is asserted.')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_FALSE = {'authority_granted': False, 'processing_consent_verified': False,
          'historical_review_provenance_verified': False, 'full_application_validated': False,
          'generation_ready': False, 'native_apex_generated': False, 'import_verified': False,
          'business_behavior_accepted': False}


def _fail():
    raise ValueError('Invalid source-bound design context.') from None


def _same(left, right):
    if canonical_hash(left) != canonical_hash(right):
        _fail()


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        _fail()


def _packet(packet):
    objects, _, _ = source_fact_index(packet)
    units = {row['id']: row for entry in packet['sources'] for row in entry['facts']['code_units']}
    chunks = {row['code_unit_id']: row for row in packet['chunks']}
    if len(chunks) != len(packet['chunks']) or set(chunks) != set(units):
        _fail()
    return objects, units, chunks


def _focus(packet, objects, units, chunks, request, selected=None):
    """Rebuild one request from fresh metadata and hash-checked whole text."""
    review._canonical(request, review.MAX_REQUEST_BYTES)
    review._keys(request, review._REQUEST_KEYS)
    if (type(request['schema_version']) is not int or request['schema_version'] != 1
            or request['scope'] != review.REQUEST_SCOPE or request['source_binding'] != packet['source_binding']):
        _fail()
    _same(request['safety'], review._SAFETY)
    owned = request['owned_objects']
    if type(owned) is not list or not owned:
        _fail()
    ids = [row['id'] for row in owned]
    if len(set(ids)) != len(ids) or any(ref not in objects for ref in ids):
        _fail()
    order = {ref: index for index, ref in enumerate(objects)}
    if ids != sorted(ids, key=order.__getitem__):
        _fail()
    for row in owned:
        _same(row, objects[row['id']])
    entries = [entry for entry in packet['sources'] if set(ids) <= {row['id'] for row in entry['facts']['objects']}]
    if len(entries) != 1:
        _fail()
    facts = entries[0]['facts']
    expected_units = [unit for ref in ids for unit in facts['code_units'] if unit['owner_id'] == ref]
    _same(request['code_units'], expected_units)
    associated = set(ids) | {unit['id'] for unit in expected_units}
    links = [row for row in facts['links'] if row['source_id'] in associated]
    dependencies = [row for row in facts['dependencies'] if row['source_id'] in associated]
    findings = [row for row in facts['findings'] if not row['object_ids'] or associated.intersection(row['object_ids'])]
    context = set()

    def ancestry(ref):
        visited = set()
        while ref is not None:
            if ref not in objects or ref in visited:
                _fail()
            visited.add(ref)
            context.add(ref)
            ref = objects[ref]['parent_id']

    for row in owned:
        ancestry(row['parent_id'])
    for row in links:
        if row['status'] == 'resolved':
            ancestry(row['target_id'])
    for row in findings:
        for ref in row['object_ids']:
            ancestry(ref)
    expected_chunks = []
    supplied = request['chunks']
    if type(supplied) is not list:
        _fail()
    by_unit = {row['code_unit_id']: row for row in supplied}
    if len(by_unit) != len(supplied):
        _fail()
    if selected is None:
        selected = {row['id']: row['sha256'] for row in supplied}
    for unit in expected_units:
        descriptor = chunks[unit['id']]
        if descriptor['id'] not in selected:
            continue
        if selected[descriptor['id']] != descriptor['sha256'] or unit['id'] not in by_unit:
            _fail()
        row = by_unit[unit['id']]
        if type(row.get('text')) is not str:
            _fail()
        body = row['text'].encode('utf-8')
        if len(body) != unit['bytes'] or hashlib.sha256(body).hexdigest() != unit['sha256']:
            _fail()
        expected_chunks.append({**descriptor, 'text': row['text']})
    expected = {'schema_version': 1, 'scope': review.REQUEST_SCOPE, 'source_binding': packet['source_binding'],
                'focus_id': 'focus-' + canonical_hash([packet['source_binding'], ids])[:24],
                'source_index': [entry['source'] for entry in packet['sources']], 'owned_objects': owned,
                'context_objects': [objects[ref] for ref in sorted(context - set(ids), key=order.__getitem__)],
                'code_units': expected_units, 'links': links, 'dependencies': dependencies, 'findings': findings,
                'chunks': expected_chunks, 'unselected_code_unit_ids': [unit['id'] for unit in expected_units
                    if chunks[unit['id']]['id'] not in selected], 'safety': review._SAFETY}
    expected['focus_binding'] = canonical_hash(expected)
    _same(request, expected)


def propose_container_retention(packet, focus_request, original_candidate, module_id, expected_original_sha):
    """Explicitly SELECTED unreviewed technical proposal, never an automatic fix.

    Caller checks the actual original-candidate pin and whole-source/scope consent.
    Only one owned root FormModule disposition/reason changes. No rationale regex,
    source-fact equivalence, approval, business-scope choice or execution grant.
    """
    try:
        return _propose(packet, focus_request, original_candidate, module_id, expected_original_sha)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError):
        _fail()


def _propose(packet, request, original, module_id, expected_sha):
    objects, units, chunks = _packet(packet)
    _focus(packet, objects, units, chunks, request)
    _sha(expected_sha)
    review._canonical(original, review.MAX_CANDIDATE_BYTES)
    if canonical_hash(original) != expected_sha or type(module_id) is not str or module_id not in objects:
        _fail()
    source_fact_gate(packet, request, original)
    source = objects[module_id]
    if (source['kind'] != 'FormModule' or source['parent_id'] is not None or source['module_id'] != module_id
            or module_id not in {row['id'] for row in request['owned_objects']}
            or any(unit['owner_id'] == module_id for unit in units.values())):
        _fail()
    index = next(i for i, row in enumerate(original['blueprint']['objects']) if row['source_object_id'] == module_id)
    before = original['blueprint']['objects'][index]
    if set(before) != {'source_object_id', 'disposition', 'reason'} or before['disposition'] != 'omitted':
        _fail()
    candidate = deepcopy(original)
    after = {**before, 'disposition': 'unresolved', 'reason': RETENTION_REASON}
    candidate['blueprint']['objects'][index] = after
    receipt = {'schema_version': 1, 'scope': PROPOSAL_SCOPE, 'source_binding': packet['source_binding'],
               'focus_id': request['focus_id'], 'focus_request_sha256': canonical_hash(request),
               'module_id': module_id, 'object_index': index, 'source_object': deepcopy(source),
               'original_candidate_sha256': expected_sha, 'candidate_sha256': canonical_hash(candidate),
               'before': deepcopy(before), 'after': deepcopy(after), 'raw_model_output': False,
               'proposal_status': 'UNREVIEWED', 'independent_review_required': True,
               'semantic_equivalence_asserted': False, **_FALSE}
    return candidate, receipt


def _plan(packet, plan):
    objects, units, chunks = _packet(packet)
    _bounded_json(plan)
    if len(packet_bytes(plan)) > MAX_PLAN_BYTES:
        _fail()
    review._keys(plan, {'schema_version', 'scope', 'source_binding', 'selected_chunk_hashes',
                       'max_owned_objects', 'requests', 'total_source_objects', 'plan_binding'})
    if (type(plan['schema_version']) is not int or plan['schema_version'] != 1 or plan['scope'] != PLAN_SCOPE
            or plan['source_binding'] != packet['source_binding']
            or type(plan['max_owned_objects']) is not int or not 1 <= plan['max_owned_objects'] <= 10_000
            or type(plan['total_source_objects']) is not int or plan['total_source_objects'] != len(objects)
            or type(plan['requests']) is not list or not 1 <= len(plan['requests']) <= MAX_REQUESTS
            or type(plan['selected_chunk_hashes']) is not dict):
        _fail()
    _same(plan['plan_binding'], canonical_hash({key: value for key, value in plan.items() if key != 'plan_binding'}))
    available = {row['id']: row['sha256'] for row in chunks.values()}
    if any(ref not in available or available[ref] != value for ref, value in plan['selected_chunk_hashes'].items()):
        _fail()
    owned, requests = {}, {}
    for request in plan['requests']:
        _focus(packet, objects, units, chunks, request, plan['selected_chunk_hashes'])
        ref = request['focus_id']
        if ref in requests or len(request['owned_objects']) > plan['max_owned_objects']:
            _fail()
        requests[ref] = request
        for row in request['owned_objects']:
            if row['id'] in owned:
                _fail()
            owned[row['id']] = ref
    if owned.keys() != objects.keys():
        _fail()
    return objects, units, requests, owned


def _reference(request, candidate, ref, target):
    review._canonical(ref, 10_000)
    review._keys(ref, {'scope', 'focus_id', 'source_binding', 'focus_request_sha256',
                      'candidate_sha256', 'target_profile_sha256', 'proof_sha256'})
    _sha(ref['proof_sha256'])
    expected = {'scope': REFERENCE_SCOPE, 'focus_id': request['focus_id'], 'source_binding': request['source_binding'],
                'focus_request_sha256': canonical_hash(request), 'candidate_sha256': canonical_hash(candidate),
                'target_profile_sha256': target, 'proof_sha256': ref['proof_sha256']}
    _same(ref, expected)
    return {'kind': 'CALLER_PINNED_RETAINED_REFERENCE', **deepcopy(ref)}


def _proposal_reference(packet, request, candidate, receipt):
    review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
    original = deepcopy(candidate)
    index = receipt['object_index']
    if type(index) is not int or not 0 <= index < len(original['blueprint']['objects']):
        _fail()
    original['blueprint']['objects'][index] = deepcopy(receipt['before'])
    rebuilt, expected = _propose(packet, request, original, receipt['module_id'], receipt['original_candidate_sha256'])
    _same(candidate, rebuilt)
    _same(receipt, expected)
    return {'kind': 'UNREVIEWED_CONTAINER_RETENTION_PROPOSAL', 'focus_id': request['focus_id'],
            'candidate_sha256': canonical_hash(candidate), 'proposal_receipt_sha256': canonical_hash(receipt)}


def validate_prefix_context(packet, full_plan, candidates, proof_refs, *, expected_target_sha256,
                            container_proposals=None, unreviewed_focus_id=None):
    """Check STRUCTURAL prefix/reference coherence; no review/permission claim.

    candidates is a nonempty contiguous prefix in full_plan order. proof_refs maps
    retained focus IDs to exact REFERENCE_SCOPE bindings; caller verifies actual
    review/environment provenance separately. container_proposals explicitly maps
    unreviewed container amendments to their reconstructed receipts. Optionally
    the LAST candidate can be unreviewed_focus_id (e.g. a retained rejection).
    These explicit structural inputs never become approved owner references.
    """
    try:
        return _prefix(packet, full_plan, candidates, proof_refs, expected_target_sha256,
                       container_proposals, unreviewed_focus_id)[0]
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError, StopIteration):
        _fail()


def _prefix(packet, plan, candidates, refs, target, proposals, unreviewed):
    objects, units, requests, ownership = _plan(packet, plan)
    _sha(target)
    _bounded_json(candidates)
    if (type(candidates) is not list or not 1 <= len(candidates) <= len(requests)
            or type(refs) is not dict or len(refs) > MAX_REQUESTS
            or proposals is not None and (type(proposals) is not dict or len(proposals) > 4)):
        _fail()
    proposals = {} if proposals is None else proposals
    ids = [row['focus_id'] for row in candidates]
    if ids != list(requests)[:len(ids)] or len(proposals) > 4 or not set(proposals) <= set(ids):
        _fail()
    if unreviewed is not None and (type(unreviewed) is not str or unreviewed != ids[-1] or unreviewed in proposals):
        _fail()
    expected_refs = set(ids) - set(proposals) - ({unreviewed} if unreviewed else set())
    if set(refs) != expected_refs:
        _fail()
    bindings, mappings, screens, screen_owners = {}, {}, {}, {}
    used = set(objects) | set(units)
    request_order = {ref: index for index, ref in enumerate(requests)}
    for candidate in candidates:
        ref = candidate['focus_id']
        request = requests[ref]
        source_fact_gate(packet, request, candidate)
        if ref in proposals:
            bindings[ref] = _proposal_reference(packet, request, candidate, proposals[ref])
        elif ref == unreviewed:
            bindings[ref] = {'kind': 'CURRENT_UNREVIEWED_CANDIDATE', 'focus_id': ref,
                             'candidate_sha256': canonical_hash(candidate)}
        else:
            bindings[ref] = _reference(request, candidate, refs[ref], target)
        bp = candidate['blueprint']
        claims = {row['id']: row for row in bp['claims']}
        for category in ('screens', 'claims', 'relationships', 'actions', 'questions', 'assumptions'):
            for row in bp[category]:
                if row['id'] in used:
                    _fail()
                used.add(row['id'])
        for category in ('actions', 'relationships'):
            for row in bp[category]:
                if not row['claim_ids'] or len(set(row['claim_ids'])) != len(row['claim_ids']) or not set(row['claim_ids']) <= claims.keys():
                    _fail()
        for row in bp['objects']:
            mappings[row['source_object_id']] = row
            source = objects[row['source_object_id']]
            if row['disposition'] != 'proposed':
                if 'screen_id' in row or 'native_component' in row:
                    _fail()
                continue
            if 'screen_id' not in row:
                _fail()
            if source['kind'] == 'Block':
                components = {'database': {'form', 'interactive-grid', 'report'}, 'control': {'page-items'}}
                if row.get('native_component') not in components.get(source['classification'], set()):
                    _fail()
                screen_owners.setdefault(row['screen_id'], []).append(row['source_object_id'])
            elif 'native_component' in row:
                _fail()
        for screen in bp['screens']:
            owners = [row for row in bp['objects'] if objects[row['source_object_id']]['kind'] == 'Block'
                      and row['disposition'] == 'proposed' and row['screen_id'] == screen['id']]
            if len(owners) != 1 or screen['id'] != 'screen-' + owners[0]['source_object_id']:
                _fail()
            screens[screen['id']] = (screen, ref)
    for screen_id, owners in screen_owners.items():
        if len(owners) != 1 or screen_id not in screens or ownership[owners[0]] != screens[screen_id][1]:
            _fail()
    rows = []
    for candidate in candidates:
        ref = candidate['focus_id']
        request = requests[ref]
        supplied = {row['code_unit_id']: row for row in request['chunks']}
        bp = candidate['blueprint']
        for mapping in bp['objects']:
            source = objects[mapping['source_object_id']]
            ancestors, seen, parent = [], set(), source['parent_id']
            while parent is not None:
                if parent in seen or parent not in objects:
                    _fail()
                seen.add(parent)
                if parent not in mappings or request_order[ownership[parent]] > request_order[ref]:
                    _fail()
                ancestor = objects[parent]
                parent_mapping = mappings[parent]
                if (mapping['disposition'] == 'proposed' and ancestor['kind'] in ('Block', 'FormModule')
                        and parent_mapping['disposition'] == 'omitted'):
                    _fail()
                ancestors.append({'source': deepcopy(ancestor), 'mapping': deepcopy(parent_mapping),
                                  'owner_binding': deepcopy(bindings[ownership[parent]])})
                parent = ancestor['parent_id']
            screen_context = None
            unit_coverage = []
            if mapping['disposition'] == 'proposed':
                screen_id = mapping['screen_id']
                if screen_id not in screens:
                    _fail()
                screen, screen_focus = screens[screen_id]
                if request_order[screen_focus] > request_order[ref]:
                    _fail()
                owner_id = screen_owners[screen_id][0]
                owner = objects[owner_id]
                if source['kind'] == 'Item':
                    if source['block_id'] != owner_id or mappings[owner_id]['disposition'] != 'proposed':
                        _fail()
                screen_context = {'declaration': deepcopy(screen), 'source_block': deepcopy(owner),
                                  'owner_mapping': deepcopy(mappings[owner_id]),
                                  'owner_binding': deepcopy(bindings[screen_focus]),
                                  'borrowed_from_prior_focus': screen_focus != ref}
                if source['kind'] in ('Trigger', 'ProgramUnit'):
                    required = [unit for unit in units.values() if unit['owner_id'] == source['id']]
                    if not required:
                        _fail()
                    for unit in required:
                        if unit['id'] not in supplied:
                            _fail()
                        claims = [row for row in bp['claims'] if row['source_object_id'] == source['id']
                                  and row['kind'] == 'behavior.intent' and row['status'] in ('proposal', 'unresolved')
                                  and type(row['value']) is str and row['value'].strip() and unit['id'] in row['evidence_refs']]
                        actions = [row for row in bp['actions'] if any(claim['id'] in row['claim_ids'] for claim in claims)]
                        if not claims or not actions:
                            _fail()
                        unit_coverage.append({'unit': deepcopy(unit), 'selected_chunk_sha256': supplied[unit['id']]['sha256'],
                                              'claim_ids': [row['id'] for row in claims], 'action_ids': [row['id'] for row in actions]})
            rows.append({'focus_id': ref, 'source': deepcopy(source), 'mapping': deepcopy(mapping),
                         'owner_binding': deepcopy(bindings[ref]), 'ancestors': ancestors,
                         'screen_context': screen_context, 'unit_coverage': unit_coverage})
    summary = {'schema_version': 1, 'scope': PREFIX_SCOPE, 'source_binding': packet['source_binding'],
               'focus_plan_sha256': canonical_hash(plan), 'target_profile_sha256': target,
               'focus_ids': ids, 'candidate_sha256': [canonical_hash(row) for row in candidates],
               'reference_bindings': deepcopy(bindings), 'structural_prefix_valid': True,
               'unreviewed_container_proposal_focus_ids': [ref for ref in ids if ref in proposals],
               'current_unreviewed_focus_id': unreviewed, 'source_objects_checked': len(mappings),
               'caller_must_verify_source_authenticity_and_review_provenance': True, **_FALSE}
    review._canonical(summary, MAX_CONTEXT_BYTES)
    return summary, rows


def build_review_context(packet, full_plan, candidates, proof_refs, *, expected_target_sha256, focus_id):
    """Context DATA for the last unreviewed candidate, not a reviewer decision.

    All PRIOR references must already have had their actual historical review/
    invocation provenance independently verified by the caller. No unreviewed
    container-proposal substitution is accepted here. This pure check validates
    bindings only and cannot detect a fabricated but well-formed proof hash; its
    output explicitly grants no approval, consent, execution or adoption authority.
    """
    try:
        if type(focus_id) is not str or not focus_id:
            _fail()
        summary, rows = _prefix(packet, full_plan, candidates, proof_refs, expected_target_sha256, None, focus_id)
        result = {'schema_version': 1, 'scope': REVIEW_SCOPE, 'focus_id': focus_id,
                  'source_binding': packet['source_binding'], 'target_profile_sha256': expected_target_sha256,
                  'focus_request_sha256': canonical_hash(full_plan['requests'][len(candidates) - 1]),
                  'candidate_sha256': canonical_hash(candidates[-1]), 'prefix_check': summary,
                  'owned_rows': [row for row in rows if row['focus_id'] == focus_id],
                  'review_required': True, **_FALSE}
        review._canonical(result, MAX_CONTEXT_BYTES)
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError, StopIteration):
        _fail()
