"""Pure, opt-in selected-chunk evidence projection; never semantic approval.

Only exact selected chunk IDs on uncertain behavior claims become their original
code-unit IDs. Sources, original responses and every other candidate field stay
unchanged. This policy never extends the existing candidate-format policy.
"""
from copy import deepcopy
import hashlib

from . import forms_design_review as review
from . import prototype_design_context as context
from .forms_blueprint import source_fact_index
from .forms_understanding_packet import local_packet
from .opaf import canonical_hash
from .prototype_focus_projection import source_fact_gate

SCOPE = 'fox-prototype-chunk-evidence-projection-v1'
POLICY = 'exact-selected-chunk-to-owned-code-unit-v1'
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, IndexError)


def _fail():
    raise ValueError('Candidate evidence is outside exact selected-chunk projection.') from None


def project_chunk_evidence(documents, request, raw):
    """Return (candidate, receipt) after proving source/selection/owner equality.

    The caller retains the original response and separately verifies current
    source, processing approval, target and independent review provenance.
    Canonical valid input is an identity operation with no projection receipt.
    """
    try:
        return _project(documents, request, raw)
    except _ERRORS:
        _fail()


def _project(documents, request, raw):
    review._canonical(raw, review.MAX_CANDIDATE_BYTES)
    review._canonical(request, review.MAX_REQUEST_BYTES)
    if (type(documents) is not list or not documents or any(
            type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
            or type(row[1]) is not bytes for row in documents)):
        _fail()
    packet = local_packet(documents)
    objects, units, descriptors = context._packet(packet)
    context._focus(packet, objects, units, descriptors, request)
    owned = {row['id'] for row in request['owned_objects']}
    review._candidate_shape(raw, request, owned)
    # The focus shape gate intentionally leaves final merged-ID checks to its
    # later validator. Projection must never hide duplicate claim identities.
    _, evidence, _ = source_fact_index(packet)
    seen = set(objects) | set(evidence) | {row['id'] for row in packet['chunks']}
    for category in ('screens', 'claims', 'actions', 'relationships', 'questions', 'assumptions'):
        for row in raw['blueprint'][category]:
            if row['id'] in seen:
                _fail()
            seen.add(row['id'])
    selected = {row['id']: row for row in request['chunks']}
    selected_units = {row['code_unit_id'] for row in request['chunks']}
    all_chunks = {row['id']: row for row in packet['chunks']}
    candidate, changes = deepcopy(raw), []
    for index, claim in enumerate(candidate['blueprint']['claims']):
        refs = claim['evidence_refs']
        if len(set(refs)) != len(refs):
            _fail()
        chunk_refs = [ref for ref in refs if ref in all_chunks]
        if not chunk_refs:
            continue
        owner = claim['source_object_id']
        if (claim['kind'] != 'behavior.intent' or claim['status'] not in ('proposal', 'unresolved')
                or owner not in owned or owner not in refs):
            _fail()
        before = deepcopy(claim)
        mappings = []
        for ref_index, ref in enumerate(refs):
            if ref in all_chunks:
                if ref not in selected:
                    _fail()
                chunk = selected[ref]
                unit = units[chunk['code_unit_id']]
                if unit['owner_id'] != owner:
                    _fail()
                refs[ref_index] = unit['id']
                mappings.append({'ref_index': ref_index, 'before': ref, 'after': unit['id'],
                    'code_unit_sha256': unit['sha256'], 'code_unit_bytes': unit['bytes'],
                    'source_sha256': chunk['source_sha256']})
            elif ref != owner and (ref not in selected_units or units[ref]['owner_id'] != owner):
                _fail()
        if len(set(refs)) != len(refs):
            _fail()
        changes.append({'path': ['blueprint', 'claims', index, 'evidence_refs'],
            'claim_id': claim['id'], 'source_object_id': owner,
            'before': before['evidence_refs'], 'after': deepcopy(refs), 'mappings': mappings,
            'before_claim_sha256': canonical_hash(before), 'after_claim_sha256': canonical_hash(claim)})
    gate = source_fact_gate(packet, request, candidate)
    if not changes:
        return raw, None
    receipt = {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY,
        'focus_id': request['focus_id'], 'source_binding': packet['source_binding'],
        'source_documents': [{'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                             for name, body in documents],
        'packet_sha256': canonical_hash(packet), 'request_sha256': canonical_hash(request),
        'raw_candidate_sha256': canonical_hash(raw), 'candidate_sha256': canonical_hash(candidate),
        'changes': changes, 'source_fact_check': gate, 'independent_review_required': True,
        'processing_consent_verified': False, 'semantic_equivalence_attested': False,
        'execution_authorized': False, 'business_behavior_accepted': False}
    review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
    return candidate, receipt


def validate_chunk_evidence(documents, request, raw, candidate, receipt):
    """Rederive the entire projection and receipt; never trust supplied hashes."""
    expected, proof = project_chunk_evidence(documents, request, raw)
    try:
        review._canonical(candidate, review.MAX_CANDIDATE_BYTES)
        if receipt is not None:
            review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
        if canonical_hash(expected) != canonical_hash(candidate) or canonical_hash(proof) != canonical_hash(receipt):
            _fail()
    except _ERRORS:
        _fail()
    return True
