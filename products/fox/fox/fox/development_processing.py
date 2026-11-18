"""Exact preserved-source consent bindings; no I/O, rewriting or execution.

Receipt descriptors must come from transaction-current, validated source history.
These hashes bind the owner's explicit approval; they never grant it themselves.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import re

from .development_source import POLICY_ID as DEVELOPMENT_SOURCE_POLICY
from .forms_redaction import POLICY_ID as REDACTED_SOURCE_POLICY
from .forms_understanding_packet import local_packet
from .opaf import canonical_hash

PROCESSING_MODE = 'development'
POLICY_ID = 'unredacted-development-processing-v1'
_DELIVERY_MODE = 'apexlang_package'
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_PROJECT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z')
_SOURCE_SET = re.compile(r'ss-[a-f0-9]{32}\Z')
_CONTEXT_KEYS = {'schema_version', 'policy_id', 'processing_mode', 'project_id',
                 'selected_source_set_id', 'source_hash', 'source_binding',
                 'source_provenance', 'target_profile_sha256', 'delivery_mode'}


def _fail():
    raise ValueError('Development processing consent is invalid, stale or mismatched.')


def _sha(value):
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def describe_development_processing(documents, *, project_id, selected_source_set_id,
                                    source_hash, source_provenance,
                                    target_profile_sha256, delivery_mode, chunk_evidence_policy=None):
    """Bind the exact project/version/receipt/destination shown before approval.

    Selection is added at the explicit POST, so a client can echo this context's
    digest without implementing canonical hashing when choosing code units.
    """
    if (not isinstance(project_id, str) or not _PROJECT.fullmatch(project_id)
            or not isinstance(selected_source_set_id, str) or not _SOURCE_SET.fullmatch(selected_source_set_id)
            or not _sha(source_hash) or not _sha(target_profile_sha256)
            or delivery_mode != _DELIVERY_MODE):
        _fail()
    packet = local_packet(documents)
    original = sorted((name, hashlib.sha256(raw).hexdigest()) for name, raw in documents)
    manifest = '\n'.join(name + ':' + digest for name, digest in original)
    if hashlib.sha256(manifest.encode('utf-8')).hexdigest() != source_hash:
        _fail()
    if type(source_provenance) is not list or len(source_provenance) != len(original):
        _fail()
    found_development = False
    for descriptor, (name, digest) in zip(source_provenance, original):
        if (type(descriptor) is not dict
                or set(descriptor) != {'name', 'sha256', 'policy_id', 'receipt_sha256'}
                or descriptor['name'] != name or descriptor['sha256'] != digest):
            _fail()
        policy, receipt = descriptor['policy_id'], descriptor['receipt_sha256']
        if policy == 'ordinary-intake':
            if receipt is not None:
                _fail()
        elif policy in (DEVELOPMENT_SOURCE_POLICY, REDACTED_SOURCE_POLICY):
            if not _sha(receipt):
                _fail()
            found_development |= policy == DEVELOPMENT_SOURCE_POLICY
        else:
            _fail()
    if not found_development:
        _fail()
    optional = {}
    if chunk_evidence_policy is not None:
        from .prototype_chunk_evidence import POLICY
        from .prototype_reference_echo import POLICY as ECHO_POLICY
        if chunk_evidence_policy not in (POLICY, ECHO_POLICY):
            _fail()
        optional['chunk_evidence_policy'] = chunk_evidence_policy
    return {'schema_version': 1, 'policy_id': POLICY_ID, 'processing_mode': PROCESSING_MODE,
            'project_id': project_id, 'selected_source_set_id': selected_source_set_id,
            'source_hash': source_hash, 'source_binding': packet['source_binding'],
            'source_provenance': deepcopy(source_provenance),
            'target_profile_sha256': target_profile_sha256, 'delivery_mode': delivery_mode, **optional}


def prepare_development_processing(documents, *, context, approved_chunk_hashes):
    """Rebuild the review context and bind the exact submitted code selection."""
    optional = {'chunk_evidence_policy'} if type(context) is dict and 'chunk_evidence_policy' in context else set()
    if (type(context) is not dict or set(context) != _CONTEXT_KEYS | optional
            or type(context.get('schema_version')) is not int or context['schema_version'] != 1
            or context.get('policy_id') != POLICY_ID or context.get('processing_mode') != PROCESSING_MODE):
        _fail()
    expected = describe_development_processing(documents,
        **{key: context[key] for key in ('project_id', 'selected_source_set_id', 'source_hash',
            'source_provenance', 'target_profile_sha256', 'delivery_mode')},
        **({'chunk_evidence_policy': context['chunk_evidence_policy']} if optional else {}))
    if expected != context or type(approved_chunk_hashes) is not dict:
        _fail()
    available = {row['id']: row['sha256'] for row in local_packet(documents)['chunks']}
    if any(type(key) is not str or not _sha(digest) or available.get(key) != digest
           for key, digest in approved_chunk_hashes.items()):
        _fail()
    return {**expected, 'approved_chunk_hashes': deepcopy(approved_chunk_hashes)}


def validate_development_processing(binding, *, documents, approved_chunk_hashes,
                                    target_profile_sha256, delivery_mode, project_id=None,
                                    selected_source_set_id=None, source_hash=None, chunk_evidence_policy=None):
    """Check a full immutable binding against fresh derivation and job identity."""
    optional = {'chunk_evidence_policy'} if type(binding) is dict and 'chunk_evidence_policy' in binding else set()
    if (type(binding) is not dict or set(binding) != _CONTEXT_KEYS | {'approved_chunk_hashes'} | optional
            or binding.get('chunk_evidence_policy') != chunk_evidence_policy):
        _fail()
    for key, expected in (('project_id', project_id), ('selected_source_set_id', selected_source_set_id),
                          ('source_hash', source_hash), ('target_profile_sha256', target_profile_sha256),
                          ('delivery_mode', delivery_mode), ('approved_chunk_hashes', approved_chunk_hashes)):
        if (key in ('project_id', 'selected_source_set_id', 'source_hash') and expected is None):
            continue
        if binding[key] != expected:
            _fail()
    context = {key: binding[key] for key in _CONTEXT_KEYS | optional}
    expected = prepare_development_processing(documents, context=context,
                                               approved_chunk_hashes=approved_chunk_hashes)
    if expected != binding:
        _fail()
    return expected


def bound_development_processing(selected, approvals):
    """Dispatch consent mode without reinterpreting legacy redacted approval.

    Full original-byte validation follows in the caller. A stripped development
    mode cannot pass as legacy while either new approval/binding marker remains.
    Current source-history provenance is separately checked by the worker.
    """
    fields = {'processing_mode', 'development_processing', 'development_processing_sha256'}
    present = fields.intersection(selected)
    if not present:
        if ('unredacted_development_source' in approvals
                or approvals.get('redacted_source') is not True):
            _fail()
        return None
    if (present != fields or selected.get('processing_mode') != PROCESSING_MODE
            or approvals.get('redacted_source') is not False
            or approvals.get('unredacted_development_source') is not True
            or not _sha(selected.get('development_processing_sha256'))
            or canonical_hash(selected['development_processing']) != selected['development_processing_sha256']):
        _fail()
    return selected['development_processing']
