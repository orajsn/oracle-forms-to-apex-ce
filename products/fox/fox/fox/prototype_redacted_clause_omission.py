"""Pure, explicit omission proposal for two source-bound masked query clauses.

This is not the unredacted clause-analysis/repair policy. No masked meaning is
reconstructed and no source-fact whitelist is changed. Caller duties include
source/redaction provenance, explicit synthetic-prototype omission consent,
retained-run reconciliation and a fresh independent review before continuation.
The stage string is a misuse guard, not proof of those duties or authority.
"""
from copy import deepcopy
import hashlib
import re

from . import forms_design_review as review
from . import prototype_design_context as context
from .forms_blueprint import source_fact_index
from .forms_redaction import _tokens
from .forms_understanding_packet import local_packet
from .opaf import canonical_hash
from .prototype_focus_projection import fact_diagnostics, source_fact_gate

SCOPE = 'fox-prototype-redacted-clause-omission-v1'
POLICY = 'explicit-masked-block-query-omission-v1'
STAGE = 'pre_review_mapping'
_ATTRIBUTES = {'block.where': 'WhereClause', 'block.order': 'OrderByClause'}
_LITERAL = re.compile(r'FOX_REDACTED_LITERAL_[1-9][0-9]*\Z')
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, IndexError, StopIteration)
_TEXT = {
    'WhereClause': (
        'NOT IMPLEMENTED: the source row-filter condition is explicitly omitted from this synthetic prototype. '
        'Masked literals and runtime-global meaning remain unresolved.',
        ('What business condition should the row filter enforce? Ask the application owner for an approved '
         'non-sensitive specification; do not restore masked values.',
         'Which runtime globals, if any, does this row filter require? Ask the application owner what defines, '
         'initializes and resets them, and what should happen when a global is unset.')),
    'OrderByClause': (
        'NOT IMPLEMENTED: the source result ordering is explicitly omitted from this synthetic prototype. '
        'No equivalent result order is asserted.',
        ('Is the original result ordering required for the prototype? Ask the business owner to confirm the '
         'ordering fields, directions and tie handling, or explicitly accept its omission.',)),
}


def _fail():
    raise ValueError('Invalid source-bound redacted clause omission proposal.') from None


def _identifiers(blueprint, evidence):
    """Do not repair existing collisions or dangling design references."""
    used, claims = set(evidence), set()
    for category in ('screens', 'claims', 'relationships', 'actions', 'questions', 'assumptions'):
        for row in blueprint[category]:
            ref = row['id']
            if ref in used:
                _fail()
            used.add(ref)
            if category == 'claims':
                claims.add(ref)
    for category in ('relationships', 'actions'):
        for row in blueprint[category]:
            refs = row['claim_ids']
            if not refs or len(set(refs)) != len(refs) or not set(refs) <= claims:
                _fail()
    return used


def _new_id(stem, used):
    ref, suffix = stem, 1
    while ref in used:
        ref = stem + '-' + str(suffix)
        suffix += 1
    used.add(ref)
    return ref


def omit_redacted_clauses(documents, request, raw, *, expected_original_sha256, stage):
    """Return a NEW (candidate, evidence receipt), both unreviewed, without I/O.

    Documents are preserved XML (name, bytes) tuples, never caller-authored fact
    dictionaries. Exactly the two unsupported claims on one owned Block may
    change. Their asserted values are NOT interpreted or proven; exact originals
    remain in the receipt. Only a matching optional envelope echo is removed.
    """
    try:
        return _omit(documents, request, raw, expected_original_sha256, stage)
    except _ERRORS:
        _fail()


def _omit(documents, request, raw, expected_original_sha256, stage):
    review._canonical(raw, review.MAX_CANDIDATE_BYTES)
    review._canonical(request, review.MAX_REQUEST_BYTES)
    review._sha(expected_original_sha256)
    if type(stage) is not str or stage != STAGE or canonical_hash(raw) != expected_original_sha256:
        _fail()
    if (type(documents) is not list or not documents
            or any(type(row) is not tuple or len(row) != 2
                   or type(row[0]) is not str or type(row[1]) is not bytes for row in documents)):
        _fail()
    packet = local_packet(documents)
    objects, units, chunks = context._packet(packet)
    context._focus(packet, objects, units, chunks, request)
    _, evidence, _ = source_fact_index(packet)
    candidate = deepcopy(raw)
    echo = None
    if type(candidate) is not dict:
        _fail()
    if 'source_binding' in candidate:
        echo = candidate.pop('source_binding')
        if type(echo) is not str or echo != packet['source_binding']:
            _fail()
    review._candidate_shape(candidate, request, {row['id'] for row in request['owned_objects']})
    blueprint = candidate['blueprint']
    used = _identifiers(blueprint, evidence)
    diagnostics = fact_diagnostics(packet, request, candidate)
    if len(diagnostics) != 2 or {row['kind'] for row in diagnostics} != set(_ATTRIBUTES):
        _fail()
    selected = {row['code_unit_id']: row for row in request['chunks']}
    owner = None
    changes = []
    for kind, attribute in _ATTRIBUTES.items():
        diagnostic = next(row for row in diagnostics if row['kind'] == kind)
        index = diagnostic['claim_index']
        before = deepcopy(blueprint['claims'][index])
        ref = before['source_object_id']
        if (objects[ref]['kind'] != 'Block' or owner is not None and ref != owner
                or type(before['value']) is not str or not before['value'].strip()):
            _fail()
        owner = ref
        matches = [unit for unit in request['code_units']
                   if unit['owner_id'] == owner and unit['source_attribute'] == attribute]
        if len(matches) != 1:
            _fail()
        unit = matches[0]
        if before['evidence_refs'] != [unit['id']] or unit['id'] not in selected:
            _fail()
        chunk = selected[unit['id']]
        # _focus reconstructed descriptors, body hashes, owner metadata and the
        # whole request from the fresh original bytes. Keep the exact unit and
        # source descriptors below; never normalize or execute the clause text.
        if attribute == 'WhereClause':
            tokens = _tokens(chunk['text'])
            if not any(token_kind == 'word' and _LITERAL.fullmatch(token)
                       for token_kind, token in tokens):
                _fail()
        if any(row['id'] != before['id'] and unit['id'] in row['evidence_refs']
               and row['kind'].startswith('behavior.') for row in blueprint['claims']):
            _fail()
        if any(before['id'] in row['claim_ids'] for category in ('actions', 'relationships')
               for row in blueprint[category]):
            _fail()
        value, questions = _TEXT[attribute]
        after = {**deepcopy(before), 'kind': 'behavior.intent', 'status': 'unresolved', 'value': value,
                 'reason': 'Explicit source-linked query-clause omission, not a translation or source fact. '
                           'Excluded from implemented behavior; manual remediation is non-executable. '
                           'Fresh independent review and explicit scope consent are required.'}
        blueprint['claims'][index] = after
        stem = 'masked-clause-' + canonical_hash([packet['source_binding'], unit['id'], unit['sha256']])[:24]
        action = {'id': _new_id(stem + '-manual-remediation', used), 'claim_ids': [after['id']]}
        blueprint['actions'].append(action)
        added_questions = []
        for text in questions:
            question = {'id': _new_id(stem + '-question', used), 'source_object_id': owner,
                        'text': attribute + ' [' + unit['id'] + ']: ' + text}
            blueprint['questions'].append(question)
            added_questions.append(deepcopy(question))
        source = next(entry['source'] for entry in packet['sources']
                      if any(row['id'] == unit['id'] for row in entry['facts']['code_units']))
        changes.append({'source_attribute': attribute, 'source': deepcopy(source),
                        'source_object': deepcopy(objects[owner]), 'source_unit': deepcopy(unit),
                        'source_chunk': deepcopy(chunks[unit['id']]),
                        'claim_index': index, 'before': before, 'after': deepcopy(after),
                        'before_claim_sha256': canonical_hash(before),
                        'after_claim_sha256': canonical_hash(after),
                        'added_action': deepcopy(action), 'added_questions': added_questions,
                        'execution_status': 'not_executed', 'included_in_implemented_behavior': False,
                        'original_claim_value_proven': False})
    gate = source_fact_gate(packet, request, candidate)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY, 'stage': stage,
               'focus_id': request['focus_id'], 'source_binding': packet['source_binding'],
               'source_documents': [{'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                                    for name, body in documents],
               'packet_sha256': canonical_hash(packet), 'request_sha256': canonical_hash(request),
               'original_candidate_sha256': expected_original_sha256,
               'candidate_sha256': canonical_hash(candidate),
               'removed_matching_source_binding_echo': echo, 'diagnostics': diagnostics, 'changes': changes,
               'source_fact_check': gate, 'proposal_status': 'UNREVIEWED',
               'independent_review_required': True, 'fresh_independent_review_required': True,
               'processing_consent_verified': False, 'omission_consent_verified': False,
               'semantic_equivalence_asserted': False, 'masked_values_reconstructed': False,
               'execution_authorized': False, 'code_executed': False, 'generation_ready': False,
               'native_apex_generated': False, 'import_verified': False,
               'business_behavior_accepted': False}
    review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
    return candidate, receipt


def validate_omission(documents, request, raw, candidate, receipt, *, expected_original_sha256, stage):
    """Rebuild exact transformation; caller-edited candidates/receipts fail closed."""
    expected, proof = omit_redacted_clauses(documents, request, raw,
                                          expected_original_sha256=expected_original_sha256, stage=stage)
    try:
        review._canonical(candidate, review.MAX_CANDIDATE_BYTES)
        review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
        if canonical_hash(candidate) != canonical_hash(expected) or canonical_hash(receipt) != canonical_hash(proof):
            _fail()
    except _ERRORS:
        _fail()
    return True
