"""Same-byte DSCName evidence supplement and unreviewed reason-only projection.

Legacy facts, packet bindings, XML and model requests are never changed. This
version recognizes only direct unqualified DSCName on a Forms DataSourceColumn.
An identity is source metadata, not a SQL identifier, implemented behavior,
review approval, model-transfer consent or execution authority.
"""
from copy import deepcopy
import re

from . import forms_facts as facts
from . import forms_understanding_packet as packets
from .forms_design_review import _canonical, _candidate_shape, MAX_CANDIDATE_BYTES
from .opaf import canonical_hash

SCOPE = 'fox-forms-dsc-identity-supplement-v1'
POLICY = 'direct-dscname-same-bytes-v1'
PROJECTION_SCOPE = 'fox-dsc-unresolved-reason-projection-v1'
MAX_SUPPLEMENT_BYTES = 2_000_000
OLD_REASONS = frozenset({
    'OBJECT_NAME_UNAVAILABLE',
    'OBJECT_NAME_UNAVAILABLE finding; column name missing',
    'Object name is missing or outside the bounded identifier format.',
    'Object name unavailable per OBJECT_NAME_UNAVAILABLE finding',
})
SAFETY = {'local_only': True, 'source_content_is_untrusted': True,
          'code_executed': False, 'transfer_authorized': False,
          'model_submission_allowed': False, 'native_generation_allowed': False,
          'review_approved': False, 'business_behavior_accepted': False}
_MISSING = re.compile(r'\b(?:missing|unavailable|unknown|unidentified|unnamed|absent)\b', re.I)
_IDENTITY = re.compile(r'\b(?:names?|identit(?:y|ies)|columns?|datasourcecolumns?|dscname)\b', re.I)
_DSC = re.compile(r'\b(?:datasourcecolumns?|dscname|data\s+source\s+columns?)\b', re.I)


def _fail():
    raise ValueError('DSC identity evidence or reason-only projection is outside the exact supported scope.') from None


def _same(left, right, maximum=MAX_SUPPLEMENT_BYTES):
    if _canonical(left, maximum) != _canonical(right, maximum):
        _fail()


def build_identity_supplement(documents):
    """Reconstruct metadata from original bytes, without altering legacy facts."""
    try:
        return _build(documents)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError):
        _fail()


def _build(documents):
    # This enforces existing file/count/total budgets, safe XML and secrets policy.
    packet = packets.local_packet(documents)
    sources = {entry['source']['name']: entry for entry in packet['sources']}
    identities = []
    for name, raw in sorted(documents, key=lambda row: row[0]):
        root, locations = facts._safe_input(name, raw)
        nodes = list(root.iter())
        if len(nodes) != len(locations):
            _fail()
        parents = {child: parent for parent in nodes for child in parent}
        node_locations = dict(zip(nodes, locations, strict=True))
        entry = sources[name]
        by_path = {row['location']['path']: row for row in entry['facts']['objects']}
        seen = set()
        for node, location in zip(nodes, locations, strict=True):
            kind = facts._local(node.tag)
            identity_keys = {key for key in node.attrib if facts._local(key) in {'Name', 'DSCName'}}
            if kind != 'DataSourceColumn':
                if any(facts._local(key) == 'DSCName' for key in identity_keys):
                    _fail()
                continue
            # ElementTree expands qualified attributes to {URI}local. Exact key
            # equality proves this one direct, unqualified identity without
            # interpreting any namespace prefix/inherited/default provenance.
            # Do not revalidate unrelated typed properties via effective-view:
            # their existing native gates retain ownership of those decisions.
            if not facts._supported(node.tag) or identity_keys != {'DSCName'}:
                _fail()
            row = by_path.get(location['path'])
            value = node.get('DSCName')
            parent = parents.get(node)
            parent_row = by_path.get(node_locations[parent]['path']) if parent is not None else None
            if (row is None or row['kind'] != 'DataSourceColumn' or row['name'] is not None
                    or facts._identifier(value) is None or parent is None
                    or not facts._supported(parent.tag) or facts._local(parent.tag) != 'Block'
                    or parent_row is None or parent_row['kind'] != 'Block'
                    or row['block_id'] != parent_row['id'] or row['parent_id'] != parent_row['id']
                    or row['module_id'] != parent_row['module_id']):
                _fail()
            key = row['parent_id'], value.casefold()
            if key in seen:
                _fail()
            seen.add(key)
            identities.append({'source_sha256': entry['source']['sha256'],
                'source_object_id': row['id'], 'kind': 'DataSourceColumn',
                'legacy_name': None, 'name': value, 'identity_attribute': 'DSCName',
                'provenance': 'direct_unqualified', 'location': deepcopy(row['location']),
                'module_id': row['module_id'], 'parent_id': row['parent_id'], 'block_id': row['block_id']})
    result = {'schema_version': 1, 'scope': SCOPE, 'policy_id': POLICY,
        'legacy_source_binding': packet['source_binding'],
        'sources': [deepcopy(entry['source']) for entry in packet['sources']],
        'identities': identities, 'identity_count': len(identities), 'safety': deepcopy(SAFETY)}
    _canonical(result, MAX_SUPPLEMENT_BYTES)
    return result


def validate_identity_supplement(documents, supplement):
    """A caller-supplied ready/safety flag is never evidence: rebuild everything."""
    expected = build_identity_supplement(documents)
    _same(supplement, expected)
    return deepcopy(expected)


def _strings(value):
    if type(value) is str:
        yield value
    elif type(value) is dict:
        for key, child in value.items():
            yield key
            yield from _strings(child)
    elif type(value) is list:
        for child in value:
            yield from _strings(child)


def _dependent(value, identities):
    """Conservative references/prose fence; never infer business equivalence."""
    ids = {row['source_object_id'] for row in identities}
    for text in _strings(value):
        if any(ref in text for ref in ids):
            _fail()
        if (_DSC.search(text) or 'OBJECT_NAME_UNAVAILABLE' in text.upper()
                or _MISSING.search(text) and _IDENTITY.search(text)):
            _fail()


def projected_reason(name):
    """Plain metadata wording only; no disposition/behavior claim is upgraded."""
    if type(name) is not str or facts._identifier(name) is None:
        _fail()
    return (f"Source DataSourceColumn identity '{name}' is supplied by DSCName. "
            'Retained as unresolved metadata; this profile does not implement or render its business behavior.')


def project_candidate_reasons(documents, request, candidate, supplement):
    """Return a new unreviewed candidate; change only exact owned DSC reasons."""
    try:
        return _project(documents, request, candidate, supplement)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError):
        _fail()


def _project(documents, request, candidate, supplement):
    evidence = validate_identity_supplement(documents, supplement)
    packet = packets.local_packet(documents)
    # Existing pure validator rederives all owned/context metadata, findings,
    # selected whole chunks and focus hashes, rather than trusting request flags.
    from .prototype_design_context import _packet, _focus
    objects, units, chunks = _packet(packet)
    _focus(packet, objects, units, chunks, request)
    _canonical(candidate, MAX_CANDIDATE_BYTES)
    owned = {row['id']: row for row in request['owned_objects']}
    _candidate_shape(candidate, request, set(owned))
    from .prototype_focus_projection import source_fact_gate
    source_fact_gate(packet, request, candidate)
    identities = {row['source_object_id']: row for row in evidence['identities']}
    changed = {ref for ref, row in owned.items() if row['kind'] == 'DataSourceColumn'}
    if not changed or not changed <= identities.keys():
        _fail()
    projected = deepcopy(candidate)
    ids = []
    for old, new in zip(candidate['blueprint']['objects'], projected['blueprint']['objects'], strict=True):
        ref = old['source_object_id']
        if ref not in changed:
            _dependent(old, evidence['identities'])
            continue
        if (set(old) != {'source_object_id', 'disposition', 'reason'}
                or old['disposition'] != 'unresolved' or old['reason'] not in OLD_REASONS
                or owned[ref]['name'] is not None):
            _fail()
        new['reason'] = projected_reason(identities[ref]['name'])
        ids.append(ref)
    for category in ('screens', 'claims', 'relationships', 'actions', 'questions', 'assumptions'):
        _dependent(candidate['blueprint'][category], evidence['identities'])
    if set(ids) != changed:
        _fail()
    _canonical(projected, MAX_CANDIDATE_BYTES)
    receipt = {'schema_version': 1, 'scope': PROJECTION_SCOPE, 'policy_id': POLICY,
        'legacy_source_binding': packet['source_binding'], 'focus_id': request['focus_id'],
        'focus_request_sha256': canonical_hash(request), 'supplement_sha256': canonical_hash(evidence),
        'old_candidate_sha256': canonical_hash(candidate), 'new_candidate_sha256': canonical_hash(projected),
        'changed_object_ids': ids, 'changed_object_count': len(ids),
        'only_object_reasons_changed': True, 'unresolved_dispositions_preserved': True,
        'new_independent_review_required': True, 'safety': deepcopy(SAFETY)}
    return projected, receipt


def validate_candidate_projection(documents, request, candidate, supplement, projected, receipt):
    """Reconstruct outputs; receipts/flags cannot waive independent review."""
    expected, proof = project_candidate_reasons(documents, request, candidate, supplement)
    _same(projected, expected, MAX_CANDIDATE_BYTES)
    _same(receipt, proof)
    return deepcopy(proof)
