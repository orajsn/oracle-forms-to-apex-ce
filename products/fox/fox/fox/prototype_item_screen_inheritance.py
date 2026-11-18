"""Pure exact missing Item-screen completion against preserved Forms sources.

Only a schema-mandated redundant link to an already explicit same-focus Block
screen may be added. Original candidates/reviews remain unchanged. This module
does not decide whether post-review compilation completion is authorized.
"""
from copy import deepcopy
import hashlib

from . import forms_design_review as review
from .forms_blueprint import _bounded_json
from .forms_focus import build_focus_plan
from .forms_focus_merge import merge_focus_blueprints
from .forms_understanding_packet import local_packet
from .opaf import canonical_hash
from .prototype_focus_projection import source_fact_gate

POLICY = 'exact-owned-source-block-item-screen-inheritance-v1'
SCOPE = 'fox-item-screen-inheritance-v1'
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, IndexError)


def _fail():
    raise ValueError('Design is outside exact absent Item-screen inheritance.') from None


def project(documents, plan, responses):
    """Return (completed responses, proof), granting no review authority."""
    try:
        return _project(documents, plan, responses)
    except _ERRORS:
        _fail()


def _project(documents, plan, responses):
    _bounded_json(plan)
    _bounded_json(responses)
    if type(plan) is not dict or type(responses) is not list:
        _fail()
    packet = local_packet(documents)
    rebuilt = build_focus_plan(documents, expected_source_binding=plan['source_binding'],
        approved_chunk_hashes=plan['selected_chunk_hashes'], max_owned_objects=plan['max_owned_objects'])
    if canonical_hash(rebuilt) != canonical_hash(plan):
        _fail()
    requests = {row['focus_id']: row for row in rebuilt['requests']}
    indexed = {}
    for response in responses:
        if (type(response) is not dict or type(response.get('focus_id')) is not str
                or response['focus_id'] not in requests or response['focus_id'] in indexed):
            _fail()
        source_fact_gate(packet, requests[response['focus_id']], response)
        indexed[response['focus_id']] = response
    if indexed.keys() != requests.keys():
        _fail()
    try:
        merge_focus_blueprints(documents, rebuilt, responses)
    except ValueError:
        # Only the exact absent-key edit below is permitted. The unchanged final
        # full merge must pass, so unrelated latent defects cannot be hidden.
        pass
    else:
        return responses, None
    sources = {row['id']: row for entry in packet['sources'] for row in entry['facts']['objects']}
    completed, changes = deepcopy(responses), []
    for response_index, response in enumerate(completed):
        request = requests[response['focus_id']]
        owned = {row['id'] for row in request['owned_objects']}
        mappings = {row['source_object_id']: row for row in response['blueprint']['objects']}
        for object_index, row in enumerate(response['blueprint']['objects']):
            source = sources[row['source_object_id']]
            if source['kind'] != 'Item' or row['disposition'] != 'proposed' or 'screen_id' in row:
                continue
            block_id = source['block_id']
            if (block_id not in owned or source['parent_id'] != block_id
                    or block_id not in mappings):
                _fail()
            block_source, block = sources[block_id], mappings[block_id]
            if (block_source['kind'] != 'Block' or block_source['module_id'] != source['module_id']
                    or block['disposition'] != 'proposed' or type(block.get('screen_id')) is not str
                    or type(block.get('native_component')) is not str):
                _fail()
            screen_id = block['screen_id']
            screens = [screen for screen in response['blueprint']['screens'] if screen['id'] == screen_id]
            if len(screens) != 1:
                _fail()
            before = deepcopy(row)
            row['screen_id'] = screen_id
            changes.append({'focus_id': response['focus_id'],
                'path': [response_index, 'blueprint', 'objects', object_index, 'screen_id'],
                'source_object_id': source['id'], 'source_block_id': block_id,
                'source_item': deepcopy(source), 'source_block': deepcopy(block_source),
                'block_mapping': deepcopy(block), 'local_screen': deepcopy(screens[0]),
                'before': before, 'after': deepcopy(row),
                'before_row_sha256': canonical_hash(before), 'after_row_sha256': canonical_hash(row)})
    if not changes:
        _fail()
    for response in completed:
        source_fact_gate(packet, requests[response['focus_id']], response)
    merged = merge_focus_blueprints(documents, rebuilt, completed)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY,
        'completion_kind': 'deterministic_compiler_constraint_completion',
        'source_binding': packet['source_binding'],
        'source_documents': [{'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                             for name, body in documents],
        'packet_sha256': canonical_hash(packet), 'plan_sha256': canonical_hash(rebuilt),
        'original_responses_sha256': canonical_hash(responses), 'completed_responses_sha256': canonical_hash(completed),
        'focus_bindings': [{'focus_id': before['focus_id'],
            'original_candidate_sha256': canonical_hash(before), 'completed_candidate_sha256': canonical_hash(after)}
            for before, after in zip(responses, completed, strict=True)],
        'changes': changes, 'merged_result_sha256': canonical_hash(merged),
        'merged_blueprint_sha256': canonical_hash(merged['blueprint']), 'merge_validation': merged['validation'],
        'review_authority_granted': False, 'historical_reviews_relabelled': False,
        'review_requirement_decided': False, 'semantic_equivalence_attested': False,
        'processing_consent_verified': False, 'execution_authorized': False,
        'business_behavior_accepted': False}
    review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
    return completed, receipt


def validate(documents, plan, responses, completed_responses, receipt):
    """Reconstruct full source proof, every completion and unchanged full merge."""
    expected, proof = project(documents, plan, responses)
    try:
        _bounded_json(completed_responses)
        if receipt is not None:
            review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
        if (canonical_hash(expected) != canonical_hash(completed_responses)
                or canonical_hash(proof) != canonical_hash(receipt)):
            _fail()
    except _ERRORS:
        _fail()
    return True
