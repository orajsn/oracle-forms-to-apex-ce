"""Derive prototype consent bindings without invoking AI or changing sources.

This is an alternate assessment path, not a relaxation of existing native-project
eligibility. Its caller owns authenticated project/source-version selection and
must persist that identity and the approvals with the immutable job snapshot.
"""
from __future__ import annotations

import re

from .forms_focus import build_focus_plan
from .forms_native_plan import POLICY_ID
from .forms_understanding_packet import local_packet
from .opaf import canonical_hash

PROFILE_ID = 'native-blueprint-prototype-v1'


def describe_prototype_sources(documents):
    """Return exact reviewable unit hashes, never source code or transfer consent."""
    packet = local_packet(documents)
    labels = {}
    for source in packet['sources']:
        objects = {row['id']: row for row in source['facts']['objects']}
        for unit in source['facts']['code_units']:
            owner = objects[unit['owner_id']]
            labels[unit['id']] = (owner['kind'] + ': ' + (owner.get('name') or 'Unnamed'))[:200]
    return {
        'conversion_profile': PROFILE_ID,
        'source_binding': packet['source_binding'],
        'source_count': len(packet['sources']),
        'code_unit_count': len(packet['chunks']),
        'chunks': [{**{key: chunk[key] for key in ('id', 'sha256', 'bytes')},
                    'label': labels[chunk['code_unit_id']]}
                   for chunk in packet['chunks']],
        'approved_policy_id': POLICY_ID,
        'processing_approved': False,
        'business_behavior_accepted': False,
        'scope_notice': ('Generate a native APEX prototype using synthetic storage. '
                         'Missing dependencies and unsupported behavior remain remediation; '
                         'generation does not mean business behavior is accepted.'),
    }


def prepare_prototype_admission(documents, *, expected_source_binding,
                                approved_chunk_hashes, target_profile_sha256,
                                approved_redacted_source, approved_external_ai,
                                approved_prototype_scope):
    """Recheck exact source, selected whole units and destination before queueing.

    A hash is a binding, not authorization. These booleans must come from the
    authenticated owner's explicit submission, not defaults or model output.
    Empty selection is permitted only as a clearly labelled metadata-only run.
    """
    if not all(value is True for value in (
            approved_redacted_source, approved_external_ai, approved_prototype_scope)):
        raise ValueError('Confirm redacted source, external AI processing and synthetic prototype scope.')
    if not isinstance(target_profile_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', target_profile_sha256):
        raise ValueError('The configured prototype destination must be checked before conversion.')
    description = describe_prototype_sources(documents)
    plan = build_focus_plan(documents, expected_source_binding=expected_source_binding,
                            approved_chunk_hashes=approved_chunk_hashes)
    return {
        'prototype': {
            'schema_version': 1,
            'source_binding': description['source_binding'],
            'focus_plan_sha256': canonical_hash(plan),
            'approved_chunk_hashes': dict(approved_chunk_hashes),
            'approved_policy_id': POLICY_ID,
            'target_profile_sha256': target_profile_sha256,
        },
        'summary': {
            'source_count': description['source_count'],
            'code_unit_count': description['code_unit_count'],
            'selected_code_unit_count': len(approved_chunk_hashes),
            'focus_count': len(plan['requests']),
            'source_object_count': plan['total_source_objects'],
            'metadata_only': not bool(approved_chunk_hashes),
            'business_behavior_accepted': False,
        },
    }
