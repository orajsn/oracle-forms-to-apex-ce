"""Pure exact-source candidate format compatibility; never semantic approval.

Original model output is untouched. Only a matching envelope echo and two
machine-proven Item fact kind aliases may change. No value/status/ref is repaired.
Callers still require the normal context, independent review and execution gates.
"""
from copy import deepcopy
import hashlib

from . import forms_design_review as review
from .forms_blueprint import source_fact_index, validate_claim_evidence
from .forms_understanding_packet import local_packet
from .opaf import canonical_hash
from .prototype_focus_projection import source_fact_gate
from . import prototype_design_context as context

SCOPE = 'fox-prototype-candidate-format-v1'
POLICY = 'exact-source-envelope-and-item-fact-aliases-v1'
ALIASES = {'object.item_type': 'item.item_type',
           'object.database_item': 'item.database_item'}
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, IndexError)


def _fail():
    raise ValueError('Candidate format is outside exact source-bound normalization.') from None


def normalize_candidate(documents, request, raw):
    """Return (candidate, receipt); canonical legacy output has no new receipt.

    documents are original (name, bytes) pairs, not caller-supplied facts. The
    full fresh packet and exact focus request are reconstructed before alias
    evidence is considered. No processing consent or source authenticity is
    attested: those remain fresh caller responsibilities.
    """
    try:
        return _normalize(documents, request, raw)
    except _ERRORS:
        _fail()


def _normalize(documents, request, raw):
    # Bound plain JSON before any copying or user-controlled equality hooks.
    review._canonical(raw, review.MAX_CANDIDATE_BYTES)
    review._canonical(request, review.MAX_REQUEST_BYTES)
    if type(documents) is not list or not documents:
        _fail()
    for row in documents:
        if type(row) not in (tuple, list) or len(row) != 2 or type(row[0]) is not str or type(row[1]) is not bytes:
            _fail()
    packet = local_packet(documents)
    objects, units, chunks = context._packet(packet)
    context._focus(packet, objects, units, chunks, request)
    objects, evidence, allowed = source_fact_index(packet)
    candidate, changes = deepcopy(raw), []
    if type(candidate) is not dict or set(candidate) - {'focus_id', 'focus_binding', 'blueprint', 'source_binding'}:
        _fail()
    if 'source_binding' in candidate:
        echo = candidate['source_binding']
        if (type(echo) is not str or echo != request['source_binding']
                or echo != candidate['blueprint']['source_binding'] or echo != packet['source_binding']):
            _fail()
        del candidate['source_binding']
        changes.append({'operation': 'remove_matching_echo', 'path': ['source_binding'], 'before': echo})
    owned = {row['id'] for row in request['owned_objects']}
    # Shape validation permits arbitrary claim kind text, but cannot relax
    # ownership, required fields, candidate/focus bindings or unknown extras.
    review._candidate_shape(candidate, request, owned)
    for index, claim in enumerate(candidate['blueprint']['claims']):
        if claim['kind'] not in ALIASES:
            continue
        owner = claim['source_object_id']
        if owner not in owned or objects[owner]['kind'] != 'Item' or claim['status'] != 'source_fact':
            _fail()
        before = deepcopy(claim)
        claim['kind'] = ALIASES[before['kind']]
        # Exact original value, JSON type and every evidence ref must already
        # match the canonical machine-extracted fact. Never guess/coerce them.
        validate_claim_evidence(claim, objects, evidence, allowed)
        changes.append({'operation': 'canonicalize_item_fact_kind',
            'path': ['blueprint', 'claims', index, 'kind'], 'claim_id': claim['id'],
            'source_object_id': owner, 'before': before['kind'], 'after': claim['kind'],
            'before_claim_sha256': canonical_hash(before), 'after_claim_sha256': canonical_hash(claim)})
    source_fact_gate(packet, request, candidate)
    if not changes:
        return raw, None
    receipt = {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY,
        'focus_id': request['focus_id'], 'source_binding': packet['source_binding'],
        'source_documents': [{'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                             for name, body in documents],
        'packet_sha256': canonical_hash(packet), 'request_sha256': canonical_hash(request),
        'raw_candidate_sha256': canonical_hash(raw), 'candidate_sha256': canonical_hash(candidate),
        'changes': changes, 'independent_review_required': True,
        'semantic_equivalence_attested': False, 'execution_authorized': False,
        'business_behavior_accepted': False}
    review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
    return candidate, receipt


def validate_normalization(documents, request, raw, candidate, receipt):
    """Reconstruct rather than trusting caller hashes, edits or ready flags."""
    expected, proof = normalize_candidate(documents, request, raw)
    try:
        review._canonical(candidate, review.MAX_CANDIDATE_BYTES)
        if receipt is not None:
            review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
        if canonical_hash(expected) != canonical_hash(candidate) or canonical_hash(proof) != canonical_hash(receipt):
            _fail()
    except _ERRORS:
        _fail()
    return True
