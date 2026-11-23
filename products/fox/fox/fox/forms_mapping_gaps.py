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
        if reason == 'saved_display_partly_connected':
            category = 'engine_context'
            message = 'The report calculates ' + row['display_target'] + ' from the saved row using the source expression.'
            action = 'Verify the original event timing and the effect of edits before saving. Source database and commit routines keep their own status.'
        elif reason == 'module_navigation_partly_connected':
            category = 'engine_context'
            message = 'A button opens the generated pages for ' + row['module_target'] + '.'
            action = 'Verify startup, return navigation, shared values and transaction behavior for the original call.'
        elif reason == 'module_navigation_pending':
            target = row.get('module_target') or 'the target form'
            cause = row.get('module_gap')
            if cause == 'MODULE_NAV_TARGET_SOURCE_ABSENT':
                category = 'missing_source'
                message = 'The button names form ' + target + ', which is absent from this project.'
                action = 'Add the named Forms module to the project and generate a package for the new source selection.'
            elif cause == 'MODULE_NAV_TARGET_SOURCE_AMBIGUOUS':
                category = 'review_required'
                message = 'More than one supplied module is named ' + target + '.'
                action = 'Select the intended source version for that module and generate again.'
            elif cause in {'MODULE_NAV_TARGET_HAS_NO_RENDERED_BLOCKS', 'MODULE_NAV_CALLER_BLOCK_NOT_RENDERED'}:
                category = 'engine_context'
                message = 'The form action requires a generated page for both its caller and its destination.'
                action = 'Check block coverage for the calling form and ' + target + '.'
            elif cause == 'MODULE_NAV_OPERATION_CAPACITY':
                message = 'This package reached the limit for generated module buttons.'
                action = 'Review the module-navigation receipt for the affected controls.'
            else:
                message = 'This event contains a form call that FOX could not bind to a single push-button destination.'
                action = 'Review the source event, its arguments and the module-navigation receipt.'
        elif reason == 'scalar_event_host_pending':
            category = 'engine_context'
            message = 'The complete trigger body is available as a typed PL/SQL procedure in scalar-events.sql.'
            action = 'Use its source-linked parameter list in the mapping ledger to bind the event host, current row and trusted Forms context.'
        elif reason == 'parent_value_copy_encoded_write_lifecycle_unimplemented':
            category = 'engine_context'
            message = 'The parent-value copy procedure is generated, but its insert/update event is not wired.'
            action = 'Wire the original write event and required validation/permission guards before activating the generated review code.'
        elif reason == 'item_lookup_partly_connected':
            category = 'engine_context'
            message = 'The draft applies the source field effects it can bind and stops when the required lookup is unavailable.'
            action = 'Verify the lookup table, return field and current-record inputs identified in the item-validation receipt.'
        elif reason == 'item_lookup_validation_binding_pending':
            category = 'engine_context'
            message = 'The item rule is encoded with its single-row lookup and ordered field assignments. Its required native bindings remain incomplete.'
            action = 'Inspect the item-validation receipt for the unresolved field, source table or draft binding.'
        elif reason in ('item_entry_partly_connected','item_entry_provider_pending',
                        'item_entry_draft_connected','item_entry_draft_callable'):
            category = 'engine_context'
            bounds = row.get('item_entry_boundaries', ())
            wiring = row.get('item_entry_draft_wiring')
            if wiring == 'bag':
                message = 'Enter current bag runs the XML rule on the selected draft. The reset clears the bag code, focuses the header destination and clears the navigation marker after focus succeeds.'
                action = 'Use the bag draft entry action. A branch requiring the original whole-form commit needs verified form status, validation and posting across changed blocks.'
            elif wiring == 'note':
                message = 'Enter selected consignment runs the XML rule on the selected saved record. On the assignment branch it rounds each saved consignment weight up and adds the results to calculate the current bag draft cost weight.'
                action = 'Review the draft and its related details. Original transient lookups, unposted detail changes and a required whole-form commit need their respective providers.'
            elif wiring == 'routine':
                message = 'The local routine is callable with the current saved selection and bag draft. It focuses the source field before applying the detail total to that draft.'
                action = ('No active invocation was identified in the supplied module. Bind a verified caller if this routine is needed.'
                          if row.get('item_entry_caller_absent') else 'Connect the identified caller to the bound current record and verify its runtime behavior.')
            elif row.get('item_entry_caller_absent') or 'original_caller_absent_from_supplied_source' in bounds:
                message = ('The routine has a callable target on the saved-record screen.'
                           if row.get('item_entry_native_callable') else 'The local routine is encoded in source order.')
                message += ' No active caller was identified in the supplied module.'
                action = 'Identify a real invocation and supply its current record, field navigation and effective detail-buffer total.'
            else:
                message = 'The XML defines the ordered field-entry branches. The live form status and effective record buffer determine which branch runs.'
                action = 'Bind the current item and record, and verify validation, posting and commit of all changed blocks when the dirty-form branch runs.'
            if not wiring and reason == 'item_entry_partly_connected':
                message += ' The saved-record screen can evaluate the snapshot branch, show the detail total and focus the bound field.'
            elif row.get('item_entry_binding_gap'):
                message += ' ' + row['item_entry_binding_gap']
        elif reason == 'delete_check_partly_connected':
            category = 'engine_context'
            if row['delete_event'] == 'ON-CHECK-DELETE-MASTER':
                message = 'The selected master can be checked for matching detail rows using its source relation. Delete permission is checked separately.'
                action = 'Inspect the selected record and its linked details. Verify the original delete event and transaction before enabling removal.'
            else:
                message = 'The selected record has a delete check. Its source permission, posting actions and transaction still need verified providers.'
                requirements = row['delete_requirements']
                routines = requirements['interfaces'] + requirements['posting_interfaces']
                action = 'Verify ' + ', '.join(routines) + ' and the form-wide commit before enabling deletion.'
        elif reason == 'delete_posting_binding_pending':
            category = 'engine_context'
            message = 'The source delete workflow is encoded in execution order. Its event still needs verified runtime bindings.'
            requirements = row['delete_requirements']
            action = ('Verify the source interface ' + ', '.join(requirements['interfaces']) + ' before enabling this action.'
                      if requirements['interfaces'] else 'Verify the source record, detail relation and delete event binding.')
            if requirements['delete_tables']:
                action += ' Verify the scoped deletes on ' + ' and '.join(requirements['delete_tables']) + '.'
            if requirements['requests_database_commit']:
                message += ' The trigger requests a database commit before it deletes matching child rows.'
        elif reason == 'staged_query_partly_connected':
            category = 'engine_context'
            message = 'Execute query can refresh staged rows for the entered key in the APEX session. Other database callers may depend on the original staging table and transaction.'
            action = 'Verify the source read interface, staging-table visibility and transaction ownership before enabling the workflow against original data.'
        elif reason == 'staged_query_binding_pending':
            category = 'engine_context'
            message = 'The staging statements and block query are encoded in source order. The generated screen still needs a verified query binding.'
            action = 'Review the staged-query receipt for the unresolved source columns, filter or target page.'
        elif reason == 'approval_readiness_partly_connected':
            category = 'engine_context'
            message = 'The approval button can check the selected saved manifest and its related rows. The source workflow has additional commit stages before the external calls.'
            action = 'Review the results on the readiness page, then bind whole-form state, each commit and both external routine interfaces before enabling business approval.'
            if row.get('saved_weight_correction') == 'connected':
                action = 'Use Correct saved bag weight to resolve a weight blocker and recheck this manifest. Whole-form state, commits and both external routines still need verified bindings.'
            elif row.get('saved_weight_correction') == 'unavailable':
                reason = row.get('saved_weight_correction_reason', '')
                detail = {
                    'NUMERIC_CORRECTION_EXPLICIT_DECIMAL_PICTURE_REQUIRED': 'The source has no supported number format for editing the weight.',
                    'NUMERIC_CORRECTION_NUMERIC_SOURCE_GUARD_REQUIRED': 'The source weight field has no uniquely bound numeric validation trigger.',
                    'NUMERIC_CORRECTION_FIELD_UPDATE_POLICY_DENIED': 'The source edit policy does not allow this field correction.',
                    'NUMERIC_CORRECTION_EDITABLE_STORED_NUMERIC_FIELD_REQUIRED': 'The weight field could not be verified as an editable stored number.',
                }.get(reason, 'A saved-weight correction is unavailable for this form.')
                message += ' ' + detail
                action += ' See the field and permission checks in the numeric correction receipt.'
        elif reason == 'approval_source_binding_pending':
            category = 'engine_context'
            message = 'The approval workflow is encoded in source order. Its selected-row inputs or button permission still need a native binding.'
            action = 'Inspect the approval plan and action receipt for the exact missing fields, relation or permission.'
        elif reason == 'draft_policy_context_unresolved':
            category = 'engine_context'
            message = 'FOX could not establish edit permissions for this draft. The generated screen is read-only.'
            action = 'Resolve the source record-entry policy and its field bindings before enabling draft edits and validation.'
        elif reason == 'policy_rule_partial_draft_guard':
            category = 'engine_context'
            message = "The draft editor checks the selected parent's edit permissions before changing draft records."
            action = 'Connect the remaining field and block permissions to their target actions and verify the original record-entry timing.'
        elif reason == 'master_population_partly_connected':
            category = 'engine_context'
            message = 'The selected master now controls its related rows using the source relation and key guard.'
            action = 'Verify the remaining record states, clear behavior and cursor restoration against the original form.'
        elif reason == 'master_query_helper_partly_connected':
            category = 'engine_context'
            message = 'The selected-master flow uses this helper at its recorded call sites.'
            action = 'Connect the remaining callers and verify how failures, cursor movement and Forms message levels are handled.'
        elif reason == 'master_clear_partly_connected':
            category = 'engine_context'
            message = 'Changing the selected master checks its connected child session drafts and offers a way to keep or discard their changes.'
            action = 'Connect the other descendant buffers and complete the form-wide commit and clear lifecycle.'
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
