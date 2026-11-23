"""Explicit, source-proved parent copies into a new synthetic rate draft.

This recipe grants no implicit Forms event, source-query or posting authority.
Fresh compilation is the source authority; retained hashes detect drift, not a
signature or permission to trust an arbitrary external recipe.
"""
from __future__ import annotations

from copy import deepcopy
import re

from forms2apex import native_record_groups as groups, native_relations as native
from .forms_rate_numbers import _events
from .forms_relation_plan import parse_join_condition, relation_attribute_sha256
from .forms_route_lookup_plan import _flag, _normal_receipts, _policy, compile_row_lookups
from .forms_understanding_packet import generation_sources

SCOPE = 'fox-source-rate-parent-v1'
_ID = re.compile(r'ff1-[a-f0-9]{24}')
_SHA = re.compile(r'[a-f0-9]{64}')
_FALSE = ('original_interface_enabled', 'customer_table_writes', 'source_query_executed',
          'implicit_event_context', 'runtime_verified', 'business_accepted')


def _need(value, reason):
    if not value:
        raise ValueError('RATE_PARENT_' + reason)


def _digest(receipt):
    return 'rate-parent-' + groups._sha(groups._json({k: v for k, v in receipt.items() if k != 'contract_id'}))[:24]


def _hash(value):
    return groups._sha(groups._json(value))


def _one(values, reason):
    _need(len(values) == 1, reason)
    return values[0]


def _char_rules(p, *, child=False):
    _need(p.get('DatabaseItem', '').lower() == 'true' and
          p.get('DataType', '').upper() in ('CHAR', 'VARCHAR2') and
          p.get('ItemType', '').upper() == 'TEXT ITEM', 'EXPLICIT_STORED_CHARACTER_REQUIRED')
    maximum = p.get('MaximumLength', '')
    _need(type(maximum) is str and re.fullmatch(r'[1-9][0-9]{0,3}', maximum) and int(maximum) <= 4000,
          'EXPLICIT_CHARACTER_LENGTH_REQUIRED')
    semantics = p.get('DataLengthSemantics', '').strip().upper()
    _need(semantics in ('', 'BYTE', 'CHAR'), 'LENGTH_SEMANTICS_UNRESOLVED')
    required = p.get('Required', '').strip().lower()
    _need(required in ('', 'true', 'false'), 'NULL_RULE_UNRESOLVED')
    _need(not any(p.get(k, '').strip() for k in ('Formula', 'InitialValue', 'SynchronizeWithItem',
                                               'LowestAllowedValue', 'HighestAllowedValue', 'FormatMask',
                                               'LovName', 'ImplementationClass', 'PropertyClass',
                                               'SubclassModule', 'SubclassObjectName')) and
          all(p.get(k, '').strip().upper() in ('', 'NONE') for k in
              ('CalculateMode', 'CalculationMode', 'SummaryFunction')) and
          p.get('ValidateFromList', '').lower() in ('', 'false'), 'OVERRIDE_OR_DERIVED_KEY_UNPROVEN')
    if not child:
        _need(not p.get('CopyValueFromItem', '').strip(), 'PARENT_INITIALIZER_UNPROVEN')
    return {'max_length': int(maximum), 'length_semantics': semantics or 'BYTE',
            'source_length_semantics': semantics or None, 'required': required == 'true'}


def _target(block, files):
    _need(block.get('classification') == 'database' and block.get('native_component', 'report') == 'report' and
          block.get('synthetic_key', {}).get('column') == 'FOX_ROW_ID' and
          block['synthetic_key'].get('source_derived') is False and
          block['synthetic_key'].get('source_item_id') is None,
          'NATIVE_REPORT_REQUIRED')
    groups._identifier(block['table_name'])
    _need(re.fullmatch(r'FOX_NATIVE_[A-F0-9]{19}', block['table_name']), 'PERMITTED_NATIVE_TABLE_REQUIRED')
    # Earlier deterministic mappers may already have added native buttons or
    # LOV/navigation controls. Fresh trace + exact supporting DDL (checked by
    # _normal_receipts) prove the local storage; final UI text is no authority
    # for this read, and must not be mistaken for a pristine pre-relation page.
    text = files.get(block['report_file'], b'').decode('utf-8')
    _need(text.startswith(f"page {block['report_page_id']} (\n") and
          '        authentication: required\n' in text and
          '        pageAccessProtection: argumentsMustHaveChecksum\n' in text,
          'NATIVE_REPORT_IDENTITY_REQUIRED')
    return {'table': block['table_name'], 'report_file': block['report_file'],
            'report_page_id': block['report_page_id'], 'row_id_column': 'FOX_ROW_ID'}


def _block_policy(p, *, child):
    _need(p.get('DatabaseBlock', '').lower() in ('', 'true') and
          p.get('QueryDataSourceType', 'TABLE').upper() == 'TABLE' and
          not any(p.get(k, '').strip() for k in ('ImplementationClass', 'PropertyClass',
                                                'SubclassModule', 'SubclassObjectName')),
          'BLOCK_POLICY_UNPROVEN')
    if child:
        _need(all(_flag(p, k) for k in ('InsertAllowed', 'UpdateAllowed', 'Enabled')), 'EDIT_DISABLED')


def _component(parent, child, pitem, citem, props, blocks, slot):
    pp, cp = props[pitem['id']], props[citem['id']]
    pr, cr = _char_rules(pp), _char_rules(cp, child=True)
    copy = cp.get('CopyValueFromItem', '').strip()
    _need(re.fullmatch(r'[A-Za-z][A-Za-z0-9_$#]*\.[A-Za-z][A-Za-z0-9_$#]*', copy) and
          copy.upper() == parent['name'].upper() + '.' + pitem['name'].upper(), 'EXPLICIT_COMPONENT_COPY_REQUIRED')
    _need(all(_flag(cp, k) for k in ('InsertAllowed', 'UpdateAllowed', 'Enabled')), 'EDIT_DISABLED')
    result = {'slot': slot, 'column': f'K{slot:03d}', 'data_type': 'VARCHAR2', 'copy_from': copy,
              'parent_item_id': pitem['id'], 'parent_name': pitem['name'],
              'child_item_id': citem['id'], 'child_name': citem['name'], **cr,
              'parent_max_length': pr['max_length'], 'parent_length_semantics': pr['length_semantics'],
              'parent_source_length_semantics': pr['source_length_semantics'], 'parent_required': pr['required'],
              'null_policy': 'reject_any_null_join_component',
              'length_policy': 'check_characters_and_database_bytes_without_truncation',
              'direct_edit_allowed': False, 'programmatic_return_allowed': False,
              'source_properties': deepcopy(cp), 'source_properties_sha256': _hash(cp),
              'parent_properties': deepcopy(pp), 'parent_properties_sha256': _hash(pp),
              'parent_source_object': deepcopy(pitem), 'child_source_object': deepcopy(citem)}
    for role, item, owner in (('parent', pitem, parent), ('child', citem, child)):
        field = _one([f for f in blocks[owner['id']]['items'] if f['source_item_id'] == item['id']],
                     'UNIQUE_NATIVE_FIELD_REQUIRED')
        _need(field['data_type'] == 'VARCHAR2' and field['source_name'] == item['name'], 'NATIVE_FIELD_TYPE')
        groups._identifier(field['column'])
        _need(re.fullmatch(r'F_[A-F0-9]{24}', field['column']), 'NATIVE_FIELD_COLUMN')
        result[role + '_column'] = field['column']
        result[role + '_native_field'] = deepcopy(field)
    return result


def _binding(relation, parent, child, objects, props, trace, files, units, texts, route):
    attrs = props[relation['id']]
    _need(relation['parent_id'] == parent['id'] and relation['block_id'] == parent['id'] and
          attrs.get('RelationType', '').upper() == 'JOIN', 'EXPLICIT_PARENT_JOIN_REQUIRED')
    pairs = parse_join_condition(attrs.get('JoinCondition'), parent['name'], child['name'],
        child_item_names=[o['name'] for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == child['id']])
    _need(1 <= len(pairs) <= 4, 'JOIN_COMPONENT_COUNT')
    blocks = {b['source_block_id']: b for b in trace['blocks']}
    _need(parent['id'] in blocks and child['id'] in blocks, 'BOTH_NATIVE_REPORTS_REQUIRED')
    _block_policy(props[parent['id']], child=False)
    _block_policy(props[child['id']], child=True)
    parent_target, child_target = _target(blocks[parent['id']], files), _target(blocks[child['id']], files)
    occupied = {f['source_item_id'] for f in route['fields']}
    components = []
    for slot, (pn, cn) in enumerate(pairs, 1):
        found = []
        for block, name in ((parent, pn), (child, cn)):
            found.append(_one([o for o in objects.values() if o['kind'] == 'Item' and
                              o['block_id'] == block['id'] and (o['name'] or '').upper() == name],
                             'SOURCE_ITEM_NOT_UNIQUE'))
        pi, ci = found
        _need(ci['id'] not in occupied, 'OVERLAPPING_ROUTE_FIELD')
        f = _component(parent, child, pi, ci, props, blocks, slot)
        # Check every stored column identity, not only the chosen first key.
        for item in found:
            source_column = props[item['id']].get('ColumnName', item['name']).upper()
            _need(sum(props[o['id']].get('ColumnName', o['name']).upper() == source_column
                      for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == item['block_id'] and
                      o.get('database_item') is True) == 1, 'SOURCE_COLUMN_NOT_UNIQUE')
        _policy(child, ci, [{'source_item_id': ci['id']}], objects, props, units, texts)
        scans, omissions, mentions = _events(ci, child, objects, props, units, texts)
        f.update(source_event_scan=scans, omitted_legacy_date_callbacks=omissions,
                 omitted_source_identifier_references=mentions)
        components.append(f)
    _need(len({f['parent_item_id'] for f in components}) == len(components) and
          len({f['child_item_id'] for f in components}) == len(components), 'DISTINCT_COMPONENTS_REQUIRED')
    return {'relation_id': relation['id'], 'relation_name': relation['name'],
            'source_attribute_sha256': relation_attribute_sha256(attrs), 'source_attributes': deepcopy(attrs),
            'relation_source_object': deepcopy(relation),
            'parent_block_id': parent['id'], 'parent_name': parent['name'],
            'child_block_id': child['id'], 'child_name': child['name'],
            'parent_source_object': deepcopy(parent), 'child_source_object': deepcopy(child),
            'parent_properties': deepcopy(props[parent['id']]), 'child_properties': deepcopy(props[child['id']]),
            'parent': parent_target, 'child': child_target, 'join_pairs': components,
            'parent_native_block': deepcopy(blocks[parent['id']]),
            'parent_snapshot_columns': [{'column': f['parent_column'], 'data_type': f['data_type']}
                                        for f in components],
            'selection_policy': 'explicit_row_id_and_current_copied_key_fingerprint',
            'copy_policy': 'atomic_create_only_immutable_parent_snapshot',
            'legacy_copy_timing_verified': False, 'implicit_event_context': False}


def _entry_operation(binding, plan, receipt, source_binding):
    _need(type(plan) is dict and plan.get('scope') == native.SCOPE and
          plan.get('source_binding') == source_binding and
          all(plan.get(k) is False for k in ('native_generated', 'runtime_verified', 'business_accepted')) and
          plan.get('plan_sha256') == native._sha(native._json({k: v for k, v in plan.items() if k != 'plan_sha256'})),
          'NATIVE_RELATION_PLAN_REQUIRED')
    _need(type(receipt) is dict and receipt.get('scope') == native.RENDERER and
          receipt.get('source_binding') == source_binding and receipt.get('native_generated') is True and
          all(receipt.get(k) is False for k in ('runtime_verified', 'business_accepted')) and
          receipt.get('write_lifecycle') is False and receipt.get('plan_sha256') == plan['plan_sha256'] and
          receipt.get('plan_artifact_sha256') == native._sha(native._json(plan)), 'NATIVE_RELATION_RECEIPT_REQUIRED')
    op = _one([o for o in plan.get('operations', []) if o['relation_id'] == binding['relation_id']],
              'MATCHING_NATIVE_RELATION_REQUIRED')
    _need(all(op.get(k) == binding.get(k) for k in ('relation_id', 'parent_block_id', 'child_block_id',
                                                  'source_attribute_sha256', 'parent', 'child')) and
          op.get('source_module_id') == binding['relation_source_object']['module_id'] and
          op.get('join_pairs') == [{k: f[k] for k in ('parent_item_id', 'parent_column', 'child_item_id',
                                                    'child_column', 'data_type')} for f in binding['join_pairs']],
          'NATIVE_RELATION_COMPONENT_MISMATCH')
    action = _one([o for o in receipt.get('generated_operations', []) if o['relation_id'] == binding['relation_id']],
                  'MATCHING_NATIVE_ACTION_REQUIRED')
    _need(action.get('generation_status') == 'read_navigation_generated' and
          action.get('write_lifecycle') is False and
          action.get('parent_block_id') == binding['parent_block_id'] and
          action.get('child_block_id') == binding['child_block_id'] and
          action.get('source_module_id') == op.get('source_module_id') and
          type(action.get('page_id')) is int and 1 <= action['page_id'] <= 8999 and
          action.get('page_file') == f"pages/p{action['page_id']:05d}-fox_relation_{action['page_id']}.apx" and
          action.get('parent_item') == f"P{action['page_id']}_PARENT_ID", 'NATIVE_ACTION_BINDING')
    return action


def _native_entry(binding, files, trace, source_binding):
    try:
        plan = native._read_json(files['fox-package/relation-plan.json'])
        receipt = native._read_json(files['fox-package/relation-receipt.json'])
    except (KeyError, TypeError, ValueError):
        raise ValueError('RATE_PARENT_GENERATED_NATIVE_RELATION_REQUIRED') from None
    action = _entry_operation(binding, plan, receipt, source_binding)
    _need(plan.get('parent_trace_canonical_sha256') == native._sha(native._json(trace)), 'NATIVE_RELATION_TRACE_MISMATCH')
    text = files.get(action['page_file'], b'').decode('utf-8')
    _need(text.startswith(f"page {action['page_id']} (\n") and
          '        authentication: required\n' in text and
          '        pageAccessProtection: argumentsMustHaveChecksum\n' in text and
          f"pageItem {action['parent_item']} (" in text and
          'sessionStateProtection: checksumRequiredSessionLevel' in text,
          'NATIVE_RELATION_PAGE_REQUIRED')
    for pair in binding['join_pairs']:
        _need(f"fox_parent.{pair['parent_column']} = fox_child.{pair['child_column']}" in text,
              'NATIVE_RELATION_PAGE_COMPONENT_MISMATCH')
    return {'plan': deepcopy(plan), 'receipt': deepcopy(receipt), 'action': deepcopy(action),
            'page_sha256': groups._sha(files[action['page_file']])}


def compile_rate_parent(documents, packet, chunks, trace, files, group_receipt, lov_receipt, route_contract):
    """Fresh proof of ALL copies on exactly one incoming parent relation."""
    with generation_sources(documents):
        objects, props = _normal_receipts(documents, packet, chunks, trace, files, group_receipt, lov_receipt)
        _need(route_contract in compile_row_lookups(documents, packet, chunks, trace, files, group_receipt, lov_receipt),
              'FRESH_ROUTE_REQUIRED')
        child = objects[route_contract['source_block_id']]
        units = [u for s in packet['sources'] for u in s['facts']['code_units']]
        texts = {c['code_unit_id']: c for c in chunks}
        requested = any(props[o['id']].get('CopyValueFromItem', '').strip() for o in objects.values()
                        if o['kind'] == 'Item' and o['block_id'] == child['id'])
        relations = [o for o in objects.values() if o['kind'] == 'Relation' and
                     o['module_id'] == child['module_id'] and
                     props[o['id']].get('DetailBlock', '').upper() == child['name'].upper()]
        candidates, gaps = [], []
        for relation in relations if requested else []:
            try:
                _need(len(relations) == 1, 'INCOMING_PARENT_RELATION_NOT_UNIQUE')
                parent = objects.get(relation['block_id'])
                _need(parent and parent['kind'] == 'Block' and parent['id'] != child['id'] and
                      parent['module_id'] == child['module_id'], 'PARENT_BLOCK_REQUIRED')
                for block in (parent, child):
                    _need(sum(o['kind'] == 'Block' and o['module_id'] == block['module_id'] and
                              (o['name'] or '').upper() == block['name'].upper() for o in objects.values()) == 1,
                          'BLOCK_NOT_UNIQUE')
                binding = _binding(relation, parent, child, objects, props, trace, files, units, texts, route_contract)
                binding['native_entry'] = _native_entry(binding, files, trace, route_contract['source_binding'])
                candidates.append(binding)
            except ValueError as exc:
                gaps.append({'relation_id': relation['id'], 'source_block_id': child['id'],
                             'reason': str(exc) if str(exc).startswith('RATE_PARENT_') else 'RATE_PARENT_' + str(exc),
                             'native_event_wired': False})
        if requested and not relations:
            gaps.append({'relation_id': None, 'source_block_id': child['id'],
                         'reason': 'RATE_PARENT_EXPLICIT_PARENT_RELATION_REQUIRED', 'native_event_wired': False})
        r = {'schema_version': 1, 'scope': SCOPE, **{k: route_contract[k] for k in
             ('source_binding', 'project_id', 'source_module_id', 'source_block_id')},
             'route_contract_id': route_contract['contract_id'], 'binding': candidates[0] if len(candidates) == 1 else None,
             'gaps': gaps, 'partial_scope_required': True, **{k: False for k in _FALSE},
             'source_manifest': [deepcopy(s['source']) for s in packet['sources']],
             'trace_sha256': _hash(trace), 'schema_sha256': groups._sha(files['fox-package/supporting-schema.sql']),
             'scope_note': 'Explicit creation of a synthetic rate only. All join components copy together and remain immutable on Keep/Save/Reopen. Missing length semantics use conservative character AND database-byte limits. Source timing, original queries, authorization, posting and reassignment remain unimplemented.'}
        if r['binding']:
            for f in r['binding']['join_pairs']:
                if f['source_length_semantics'] is None or f['parent_source_length_semantics'] is None:
                    r['gaps'].append({'relation_id': r['binding']['relation_id'], 'source_block_id': child['id'],
                                     'source_item_id': f['child_item_id'], 'native_event_wired': False,
                                     'reason': 'RATE_PARENT_SOURCE_LENGTH_SEMANTICS_ABSENT_CONSERVATIVE_BYTE_AND_CHAR_LIMIT'})
        r['contract_id'] = _digest(r)
        return validate_rate_parent(r, route_contract)


def validate_rate_parent(receipt, route_contract):
    """Reject malformed retained recipes with a bounded diagnostic."""
    try:
        return _validate_rate_parent(receipt, route_contract)
    except (KeyError, TypeError, AttributeError, UnicodeError, IndexError):
        raise ValueError('RATE_PARENT_MALFORMED_RECEIPT') from None


def _validate_rate_parent(receipt, route_contract):
    """Validate a retained compiler recipe; never substitute it for fresh proof."""
    if receipt is None:
        return None
    r = deepcopy(receipt)
    _need(type(route_contract) is dict and route_contract.get('contract_id') == 'row-lookup-' +
          _hash({k: v for k, v in route_contract.items() if k != 'contract_id'})[:24], 'ROUTE_HASH')
    _need(type(r) is dict and r.get('scope') == SCOPE and type(r.get('schema_version')) is int and
          r['schema_version'] == 1 and r.get('contract_id') == _digest(r), 'RECEIPT_HASH')
    _need(all(r.get(k) == route_contract.get(k) for k in
              ('source_binding', 'project_id', 'source_module_id', 'source_block_id')) and
          r.get('route_contract_id') == route_contract['contract_id'], 'ROUTE_BINDING')
    _need(r.get('partial_scope_required') is True and all(r.get(k) is False for k in _FALSE), 'SOURCE_GATES')
    _need(type(r.get('gaps')) is list and all(type(g) is dict and g.get('native_event_wired') is False and
          g.get('source_block_id') == r['source_block_id'] and type(g.get('reason')) is str and
          g['reason'].startswith('RATE_PARENT_') for g in r['gaps']), 'GAPS')
    for k in ('trace_sha256', 'schema_sha256'):
        _need(type(r.get(k)) is str and _SHA.fullmatch(r[k]), 'RETAINED_HASH')
    b = r.get('binding')
    if b is None:
        return r
    _need(type(b) is dict and b.get('child_block_id') == r['source_block_id'] and
          b.get('parent_block_id') != b.get('child_block_id') and
          b.get('source_attribute_sha256') == relation_attribute_sha256(b['source_attributes']) and
          b.get('implicit_event_context') is False and b.get('legacy_copy_timing_verified') is False and
          b.get('copy_policy') == 'atomic_create_only_immutable_parent_snapshot' and
          b.get('selection_policy') == 'explicit_row_id_and_current_copied_key_fingerprint', 'BINDING')
    sources = r.get('source_manifest')
    _need(type(sources) is list and 1 <= len(sources) <= 4, 'SOURCE_MANIFEST')
    def identity(obj, kind, oid):
        _need(type(obj) is dict and obj.get('id') == oid and obj.get('kind') == kind and
              type(oid) is str and _ID.fullmatch(oid) and obj.get('module_id') == r['source_module_id'], 'SOURCE_IDENTITY')
        _need(any(oid == 'ff1-' + groups._sha((s['sha256'] + '\n' + obj['location']['path'] + '\n').encode())[:24]
                  for s in sources), 'SOURCE_LOCATION_HASH')
    identity(b['relation_source_object'], 'Relation', b['relation_id'])
    _need(b['relation_source_object']['parent_id'] == b['parent_block_id'] and
          b['relation_source_object']['block_id'] == b['parent_block_id'] and
          b['source_attributes'].get('DetailBlock', '').upper() == b['child_name'].upper() and
          b['source_attributes'].get('RelationType', '').upper() == 'JOIN', 'RELATION_OWNER')
    for role in ('parent', 'child'):
        identity(b[role + '_source_object'], 'Block', b[role + '_block_id'])
        _need(b[role + '_source_object']['name'] == b[role + '_name'] and
              b[role + '_properties'].get('Name') == b[role + '_name'], 'BLOCK_NAME')
        _block_policy(b[role + '_properties'], child=role == 'child')
        t = b[role]
        from forms2apex import native_blueprint
        _need(t['table'] == native_blueprint._table(r['project_id'], r['source_binding'], b[role + '_block_id']) and
              t['row_id_column'] == 'FOX_ROW_ID' and
              type(t['report_page_id']) is int and 1 <= t['report_page_id'] < 9000 and
              re.fullmatch(r'pages/p[0-9]{5}-[A-Za-z0-9_-]+\.apx', t['report_file']), 'TARGET')
    _need(b['parent']['table'] != b['child']['table'], 'TARGET_COLLISION')
    entry = b.get('native_entry')
    _need(type(entry) is dict and entry.get('action') ==
          _entry_operation(b, entry['plan'], entry['receipt'], r['source_binding']) and
          type(entry.get('page_sha256')) is str and _SHA.fullmatch(entry['page_sha256']) and
          entry['plan'].get('parent_trace_canonical_sha256') == r['trace_sha256'], 'NATIVE_ENTRY_PROOF')
    nb = b['parent_native_block']
    _need(nb['source_block_id'] == b['parent_block_id'] and nb['table_name'] == b['parent']['table'] and
          nb['report_page_id'] == b['parent']['report_page_id'] and nb['report_file'] == b['parent']['report_file'] and
          b['parent_snapshot_columns'] == [{'column': f['parent_column'], 'data_type': f['data_type']}
                                           for f in b['join_pairs']] and
          all(any(nf['column'] == f['column'] and nf['data_type'] == f['data_type'] for nf in nb['items'])
              for f in b['parent_snapshot_columns']),
          'PARENT_SNAPSHOT')
    _need(len({f['column'] for f in b['parent_snapshot_columns']}) == len(b['parent_snapshot_columns']) and
          all(re.fullmatch(r'F_[A-F0-9]{24}', f['column']) and f['data_type'] in ('VARCHAR2', 'NUMBER', 'DATE')
              for f in b['parent_snapshot_columns']), 'PARENT_SNAPSHOT_COLUMNS')
    pairs = b.get('join_pairs')
    _need(type(pairs) is list and 1 <= len(pairs) <= 4, 'COMPONENTS')
    parsed = parse_join_condition(b['source_attributes']['JoinCondition'], b['parent_name'], b['child_name'],
                                  child_item_names=[f['child_name'] for f in pairs])
    _need(parsed == [(f['parent_name'].upper(), f['child_name'].upper()) for f in pairs], 'COMPLETE_JOIN_REQUIRED')
    for role in ('parent', 'child'):
        _need(len({f[role + '_item_id'] for f in pairs}) == len(pairs) and
              len({f[role + '_column'] for f in pairs}) == len(pairs), 'DISTINCT_COMPONENTS_REQUIRED')
    occupied = {f['source_item_id'] for f in route_contract['fields']}
    for slot, f in enumerate(pairs, 1):
        _need(f['slot'] == slot and f['column'] == f'K{slot:03d}' and f['data_type'] == 'VARCHAR2' and
              f['child_item_id'] not in occupied and f['direct_edit_allowed'] is False and
              f['programmatic_return_allowed'] is False, 'COMPONENT_STORAGE')
        for role, prop_key in (('parent', 'parent_properties'), ('child', 'source_properties')):
            obj, p = f[role + '_source_object'], f[prop_key]
            identity(obj, 'Item', f[role + '_item_id'])
            _need(obj['block_id'] == b[role + '_block_id'] and obj['name'] == f[role + '_name'] and
                  p.get('Name') == obj['name'] and f[prop_key + '_sha256'] == _hash(p), 'COMPONENT_PROOF')
            rules = _char_rules(p, child=role == 'child')
            prefix = '' if role == 'child' else 'parent_'
            _need(all(f[prefix + k] == v for k, v in rules.items()), 'COMPONENT_RULES')
            nf = f[role + '_native_field']
            _need(nf['source_item_id'] == obj['id'] and nf['source_name'] == obj['name'] and
                  nf['column'] == f[role + '_column'] and nf['data_type'] == 'VARCHAR2' and
                  nf['column'] == native_blueprint._field_name(obj['id']) and
                  nf['report_page_id'] == b[role]['report_page_id'], 'NATIVE_FIELD_PROOF')
        _need(f['copy_from'] == f['source_properties'].get('CopyValueFromItem', '').strip() and
              f['copy_from'].upper() == b['parent_name'].upper() + '.' + f['parent_name'].upper() and
              all(_flag(f['source_properties'], k) for k in ('InsertAllowed', 'UpdateAllowed', 'Enabled')) and
              f['null_policy'] == 'reject_any_null_join_component' and
              f['length_policy'] == 'check_characters_and_database_bytes_without_truncation', 'COPY_PROOF')
        _need(type(f.get('source_event_scan')) is list and all(e.get('native_event_wired') is False and
              _ID.fullmatch(e['source_unit_id']) and _ID.fullmatch(e['source_owner_id']) and
              _SHA.fullmatch(e['source_unit_sha256']) and re.fullmatch(r'fup1-[a-f0-9]{64}', e['source_chunk_id'])
              for e in f['source_event_scan']), 'EVENT_PROOF')
    return r


def validate_parent_values(values, receipt, route_contract, *, encoding='utf-8'):
    """Reference only: runtime must additionally use Oracle LENGTHB, never guess NLS."""
    checked = validate_rate_parent(receipt, route_contract)
    _need(checked and checked['binding'] and type(values) in (list, tuple) and
          len(values) == len(checked['binding']['join_pairs']), 'VALUES')
    result = []
    for value, field in zip(values, checked['binding']['join_pairs'], strict=True):
        _need(type(value) is str and value != '', 'NULL_PARENT_COMPONENT')
        try:
            size = len(value.encode(encoding))
        except (UnicodeError, LookupError):
            raise ValueError('RATE_PARENT_VALUE_ENCODING') from None
        _need(len(value) <= field['max_length'] and
              (field['length_semantics'] == 'CHAR' or size <= field['max_length']) and
              len(value) <= field['parent_max_length'] and
              (field['parent_length_semantics'] == 'CHAR' or size <= field['parent_max_length']), 'VALUE_LENGTH')
        result.append(value)
    return tuple(result)
