"""Lossless, bounded behavior prose representation composed with V2 proof.

Original source, response, characters and whitespace stay unchanged. Array
representation is unreviewed until a fresh independent review; no semantic or
business-equivalence claim follows from exact byte recomposition.
"""
from copy import deepcopy
import hashlib

from . import forms_design_review as review
from .opaf import canonical_hash
from .prototype_focus_projection import source_fact_gate

POLICY = 'lossless-bounded-behavior-prose-segments-v3'
SCOPE = 'fox-development-prose-segments-v3'
MAX_SEGMENT = 512
MAX_SEGMENTS = 4
MAX_TEXT = MAX_SEGMENT * MAX_SEGMENTS
_ERRORS = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
           OverflowError, UnicodeError, IndexError)


def _fail():
    raise ValueError('Candidate is outside lossless bounded behavior-prose representation.') from None


def _text_descriptor(text):
    raw = text.encode('utf-8')
    return {'characters': len(text), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _segments(text):
    review._text(text, MAX_TEXT)
    segments, cursor = [], 0
    while len(text) - cursor > MAX_SEGMENT:
        slots = MAX_SEGMENTS - len(segments)
        if slots <= 1:
            _fail()
        minimum = max(cursor + 1, len(text) - MAX_SEGMENT * (slots - 1))
        maximum = cursor + MAX_SEGMENT
        # Preserve whitespace on the preceding segment. A cut must leave both
        # sides nonblank: the existing scalar validator still checks each part.
        possible = [end for end in range(maximum, minimum - 1, -1)
                    if text[cursor:end].strip() and text[end:].strip()]
        whitespace = [end for end in possible if text[end - 1].isspace()]
        if not possible:
            _fail()
        end = (whitespace or possible)[0]
        segments.append(text[cursor:end])
        cursor = end
    segments.append(text[cursor:])
    if not 2 <= len(segments) <= MAX_SEGMENTS:
        _fail()
    for segment in segments:
        review._text(segment, MAX_SEGMENT)
    if ''.join(segments).encode('utf-8') != text.encode('utf-8'):
        _fail()
    return segments


def project(documents, packet, request, raw, target):
    """Return the exact bounded representation plus separately bound proof.

    Only uncertain behavior-intent scalar strings in the 513..2048 character
    window may become up to four ordinary schema-valid string array elements.
    """
    try:
        return _project(documents, packet, request, raw, target)
    except _ERRORS:
        _fail()


def _project(documents, packet, request, raw, target):
    review._canonical(raw, review.MAX_CANDIDATE_BYTES)
    review._canonical(request, review.MAX_REQUEST_BYTES)
    if type(raw) is not dict:
        _fail()
    prepared, changes = deepcopy(raw), []
    for index, claim in enumerate(review._rows(prepared['blueprint']['claims'])):
        if type(claim) is not dict:
            _fail()
        value = claim.get('value')
        if (claim.get('kind') != 'behavior.intent' or claim.get('status') not in ('proposal', 'unresolved')
                or type(value) is not str or not MAX_SEGMENT < len(value) <= MAX_TEXT):
            continue
        before_hash = canonical_hash(claim)
        segments = _segments(value)
        claim['value'] = segments
        changes.append({'path': ['blueprint', 'claims', index, 'value'],
            'claim_id': claim['id'], 'source_object_id': claim['source_object_id'], 'before': value,
            'before_text': _text_descriptor(value),
            'segments': [_text_descriptor(segment) for segment in segments],
            'recomposed_text': _text_descriptor(''.join(segments)),
            'before_claim_sha256': before_hash, 'prepared_claim_sha256': canonical_hash(claim)})
    # Keep the V2 echo/reference/container composition unchanged and lazy.
    from .prototype_reference_echo import project as project_v2
    candidate, inner = project_v2(documents, packet, request, prepared, target)
    gate = source_fact_gate(packet, request, candidate)
    if not changes and inner is None:
        return raw, None
    receipt = {'schema_version': 3, 'scope': SCOPE, 'policy': POLICY,
        'source_binding': request['source_binding'], 'focus_id': request['focus_id'],
        'source_documents': [{'name': name, 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                             for name, body in documents],
        'packet_sha256': canonical_hash(packet), 'request_sha256': canonical_hash(request),
        'target_profile_sha256': canonical_hash(target), 'raw_candidate_sha256': canonical_hash(raw),
        'prepared_candidate_sha256': canonical_hash(prepared), 'candidate_sha256': canonical_hash(candidate),
        'changes': changes, 'v2_projection': inner, 'source_fact_check': gate,
        'independent_review_required': True, 'processing_consent_verified': False,
        'semantic_equivalence_attested': False, 'execution_authorized': False,
        'business_behavior_accepted': False}
    review._canonical(receipt, review.MAX_CANDIDATE_BYTES)
    return candidate, receipt


def validate(documents, packet, request, raw, target, candidate, receipt):
    """Rederive every character, segment and nested receipt from original input."""
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
