"""V2 exact source-echo removal composed with unchanged V1 reference proof.

Original sources, mapper output and prior review evidence remain immutable.
This pure projection requires fresh independent review and grants no authority.
"""
from copy import deepcopy
import hashlib

from . import forms_design_review as review
from .opaf import canonical_hash
from .prototype_focus_projection import source_fact_gate

POLICY = 'exact-source-echo-and-selected-chunk-references-v2'
SCOPE = 'fox-development-reference-echo-v2'
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, IndexError)


def _fail():
    raise ValueError('Candidate is outside exact source-echo reference projection.') from None


def project(documents, packet, request, raw, target):
    """Remove only an exact redundant source echo, then apply the V1 view.

    Consent, current owner/source/target and historical invocation provenance
    remain caller responsibilities. No provider, file or database is accessed.
    """
    try:
        return _project(documents, packet, request, raw, target)
    except _ERRORS:
        _fail()


def _project(documents, packet, request, raw, target):
    review._canonical(raw, review.MAX_CANDIDATE_BYTES)
    review._canonical(request, review.MAX_REQUEST_BYTES)
    if type(raw) is not dict or type(packet) is not dict:
        _fail()
    prepared = deepcopy(raw)
    echo_removal = None
    if 'source_binding' in prepared:
        echo = prepared['source_binding']
        if (type(echo) is not str or echo != request['source_binding']
                or echo != packet['source_binding'] or echo != prepared['blueprint']['source_binding']):
            _fail()
        del prepared['source_binding']
        echo_removal = {'operation': 'remove_matching_source_binding_echo',
                        'path': ['source_binding'], 'before': echo}
    # Lazy import is deliberate: V1 dispatch can select this wrapper while
    # this wrapper composes V1's unchanged pure reference/container operations.
    from .prototype_development_reference_view import project as project_v1
    candidate, inner = project_v1(documents, packet, request, prepared, target)
    gate = source_fact_gate(packet, request, candidate)
    if echo_removal is None and inner is None:
        return raw, None
    receipt = {'schema_version': 2, 'scope': SCOPE, 'policy': POLICY,
        'source_binding': request['source_binding'], 'focus_id': request['focus_id'],
        'source_documents': [{'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                             for name, body in documents],
        'packet_sha256': canonical_hash(packet), 'request_sha256': canonical_hash(request),
        'target_profile_sha256': canonical_hash(target), 'raw_candidate_sha256': canonical_hash(raw),
        'prepared_candidate_sha256': canonical_hash(prepared), 'candidate_sha256': canonical_hash(candidate),
        'echo_removal': echo_removal, 'v1_projection': inner, 'source_fact_check': gate,
        'independent_review_required': True, 'processing_consent_verified': False,
        'semantic_equivalence_attested': False, 'execution_authorized': False,
        'business_behavior_accepted': False}
    review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
    return candidate, receipt


def validate(documents, packet, request, raw, target, candidate, receipt):
    """Rebuild both projections and compare complete canonical values."""
    expected, proof = project(documents, packet, request, raw, target)
    try:
        review._canonical(candidate, review.MAX_CANDIDATE_BYTES)
        if receipt is not None:
            review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
        if canonical_hash(expected) != canonical_hash(candidate) or canonical_hash(proof) != canonical_hash(receipt):
            _fail()
    except _ERRORS:
        _fail()
    return True
