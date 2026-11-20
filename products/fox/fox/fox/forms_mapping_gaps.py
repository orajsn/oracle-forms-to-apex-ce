"""Actionable source-linked gaps; engine limitations are not missing customer files.

Lexical dependency candidates alone never prove an absent routine/schema body.
Generation status remains authoritative; this module only explains unfinished units.
"""
from collections import Counter
import re

from .forms_behavior_plan import decode_control_entities, UnsupportedBehavior
from .forms_facts import _mask_code

CATEGORIES = ('engine_mapping', 'engine_context', 'missing_source', 'review_required')
_OWNERS = {'engine_mapping': 'FOX_ENGINE', 'engine_context': 'FOX_ENGINE',
           'missing_source': 'SOURCE_OWNER', 'review_required': 'REVIEWER'}
# Only recognizer-established missing definitions belong here, never a generic
# parser rejection or a lexical database/routine candidate.
_MISSING = {'local_function_definition_missing', 'comparison_function_definition_missing',
            'local_comparison_function_missing'}
_CONTEXT = {'cross_block_reference', 'source_item_has_no_parent_report_column',
            'input_computation_or_summary_not_implemented',
            'supported_local_function_has_no_supported_caller',
            'control_binding_missing', 'control_session_binding_missing'}
_BIND = re.compile(r':([A-Za-z][A-Za-z0-9_$#]*)(?:\.([A-Za-z][A-Za-z0-9_$#]*))?')


def _cross_block(code, owner, objects):
    block_id, module = owner.get('block_id'), owner.get('module_id')
    if block_id is None:
        return False
    blocks = {obj['id']: obj for obj in objects.values() if obj['kind'] == 'Block' and obj['module_id'] == module}
    for match in _BIND.finditer(code):
        first, second = match.groups()
        if second:
            found = [b for b in blocks.values() if (b['name'] or '').upper() == first.upper()]
            if len(found) == 1 and found[0]['id'] != block_id:
                return True
        else:
            local = [o for o in objects.values() if o['kind'] == 'Item' and o.get('block_id') == block_id and (o['name'] or '').upper() == first.upper()]
            candidates = [o for o in objects.values() if o['kind'] == 'Item' and o.get('module_id') == module and (o['name'] or '').upper() == first.upper()]
            if not local and len(candidates) == 1 and candidates[0].get('block_id') != block_id:
                return True
    return False


def classify_gaps(packet, chunks, coverage):
    """Return one primary explanation per unconverted unit, preserving exact IDs."""
    objects = {o['id']: o for entry in packet['sources'] for o in entry['facts']['objects']}
    units = {u['id']: (u, entry['source']) for entry in packet['sources'] for u in entry['facts']['code_units']}
    texts = {c['code_unit_id']: c for c in chunks}
    if len(coverage) != len(units) or len({r['source_unit_id'] for r in coverage}) != len(units):
        raise ValueError('Gap coverage must account for every exact source unit once.')
    gaps = []
    for row in coverage:
        unit, source = units[row['source_unit_id']]
        chunk = texts[unit['id']]
        if row['source_unit_sha256'] != unit['sha256'] or chunk['sha256'] != unit['sha256']:
            raise ValueError('Gap evidence does not match original source.')
        if row['status'] == 'generated_wired_adapted':
            continue
        owner = objects[unit['owner_id']]
        reason = row.get('reason', 'mapping_not_implemented')
        category = 'engine_mapping'
        message = 'The source is present, but FOX has not implemented this complete behavior pattern.'
        action = 'Extend the reusable mapping and verify its source semantics and target wiring.'
        try:
            semantic, _ = decode_control_entities(chunk['text'])
            code = _mask_code(semantic)
        except UnsupportedBehavior:
            code = ''
        if reason == 'parent_value_copy_encoded_write_lifecycle_unimplemented':
            category = 'engine_context'
            message = 'The parent-value copy procedure is generated, but its insert/update event is not wired.'
            action = 'Wire the original write event and required validation/permission guards before activating the generated review code.'
        elif reason == 'draft_policy_context_unresolved':
            category = 'engine_context'
            message = 'FOX could not establish edit permissions for this draft. The generated screen is read-only.'
            action = 'Resolve the source record-entry policy and its field bindings before enabling draft edits and validation.'
        elif reason == 'policy_rule_partial_draft_guard':
            category = 'engine_context'
            message = "The draft editor checks the selected parent's edit permissions before changing draft records."
            action = 'Connect the remaining field and block permissions to their target actions and verify the original record-entry timing.'
        elif reason == 'policy_rule_encoded_event_context_unimplemented':
            category = 'engine_context'
            message = 'The complete rule is encoded as review PL/SQL, but its Forms event and required state providers are not wired.'
            action = 'Wire the original event, scalar context and ordered effects; enforce permissions on the server before activating writes.'
        elif reason in _MISSING:
            category = 'missing_source'
            message = 'The called routine definition was not found in the supplied source set.'
            action = 'Supply the routine source or identify its authoritative database/library implementation.'
        elif any(part in reason for part in ('ambiguous', 'not_unique', 'entity_inside_literal', 'conflict')):
            category = 'review_required'
            message = 'The source reference or encoding is ambiguous; FOX cannot select a meaning reliably.'
            action = 'Confirm the authoritative source/reference or encoding before adding the mapping.'
        elif 'capacity' in reason:
            message = 'The rule is recognized, but this package exceeds the current renderer capacity.'
            action = 'Extend the renderer capacity or select a smaller explicit conversion scope.'
        elif reason in _CONTEXT or reason.endswith('_context_required') or _cross_block(code, owner, objects):
            category = 'engine_context'
            message = 'The source needs record, control-state or caller context that FOX has not wired yet.'
            action = 'Implement the exact parent-child/session/caller binding; keep any additional mapping gaps explicit.'
        elif owner['kind'] == 'RecordGroup' or unit['source_attribute'] in {'OrderByClause', 'WhereClause'}:
            message = 'The SQL source is present; its query, filter, ordering or lookup behavior is not yet mapped.'
            action = 'Implement the reusable query/LOV mapping and verify its database and parameter bindings.'
        elif owner['kind'] == 'ProgramUnit':
            message = 'The routine body is present; its statements or executable call sites are not yet mapped.'
            action = 'Translate the complete routine and bind its supported callers without changing side effects.'
        elif re.search(r'\b(?:INSERT|UPDATE|DELETE|COMMIT|ROLLBACK)\b', code, re.I):
            message = 'The source contains database or transaction operations that FOX has not translated.'
            action = 'Implement the original operation order, transaction boundaries and required database interfaces.'
        elif re.search(r'\bSET_(?:BLOCK|ITEM)_PROPERTY\b', code, re.I):
            message = 'The source changes UI or edit permissions that FOX has not mapped.'
            action = 'Map the exact flags and their event timing, including any required server-side enforcement.'
        elif reason == 'not_selected':
            message = 'This source unit was outside the selected conversion scope.'
            action = 'Select the complete unit in a new explicitly scoped run when its mapping is available.'
        gaps.append({'source_unit_id': unit['id'], 'source_name': owner['name'] or owner['kind'],
            'source_file': source['name'], 'source_line': unit['location']['line'],
            'category': category, 'reason': reason, 'message': message,
            'next_action': action, 'owner': _OWNERS[category]})
    counts = Counter(row['category'] for row in gaps)
    return {'schema_version': 1, 'scope': 'fox-source-mapping-gaps-v1',
            'source_binding': packet['source_binding'], 'not_yet_converted': len(gaps),
            'summary': {key: counts[key] for key in CATEGORIES}, 'gaps': gaps,
            'dependency_candidates_are_confirmed_missing_inputs': False}
