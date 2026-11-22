"""Prove companion LOVs sharing an existing source-linked row draft.

Normal reference-query and LOV receipts remain the coverage authorities. Only
explicit return mappings become row fields; other projections stay catalog-only.
This module never executes source queries, lifecycle events or business writes.
"""
from __future__ import annotations

from copy import deepcopy
import re

from forms2apex import native_record_groups as groups
from .forms_behavior_plan import decode_control_entities
from .forms_interface_inventory import _lex
from .forms_route_lookup_plan import _flag, _normal_receipts, _one, _policy, compile_row_lookups
from .forms_understanding_packet import generation_sources

SCOPE = 'fox-source-rate-companion-choices-v1'


def _need(value, reason):
    if not value:
        raise ValueError('RATE_CHOICES_' + reason)


def _digest(value, key, prefix):
    body = deepcopy(value)
    body.pop(key, None)
    return prefix + groups._sha(groups._json(body))[:24]


def _query(query):
    _need(set(query) in ({'tables', 'projections', 'predicates', 'order'},
                        {'tables', 'projections', 'predicates', 'order', 'select_all'}), 'CLOSED_QUERY_REQUIRED')
    _need('select_all' not in query or query['select_all'] is True, 'SELECT_ALL_FLAG')
    raw = groups.render_query(query, {})
    parsed, bindings, _ = groups.parse_record_group_query(raw)
    _need(parsed == query and not bindings and len(query['tables']) == 1 and
          len(query['tables'][0]) == 1, 'UNBOUND_SINGLE_TABLE_REQUIRED')
    table = groups._identifier(query['tables'][0][0])
    def column(parts):
        _need(len(parts) == 1 or (len(parts) == 2 and parts[0] == table), 'FOREIGN_COLUMN')
        return groups._identifier(parts[-1])
    names = [column(p) for p in query['projections']]
    _need(1 <= len(names) <= 18 and len(names) == len(set(names)) and
          not set(names) & {'FOX_CHOICE', 'FOX_ROW_UUID'}, 'DISTINCT_PROJECTIONS_REQUIRED')
    _need(len(query['predicates']) <= 1, 'STATUS_FILTER_ONLY')
    for predicate in query['predicates']:
        _need(set(predicate) == {'left', 'op', 'right'} and predicate['op'] == '=' and
              predicate['left']['kind'] == 'column' and predicate['right']['kind'] == 'string' and
              predicate['right']['value'] in ('1', 'Y'), 'STATUS_FILTER_ONLY')
        column(predicate['left']['parts'])
    for term in query['order']:
        _need(set(term) == {'parts', 'direction'} and term['direction'] in (None, 'ASC', 'DESC') and
              column(term['parts']) in names, 'SOURCE_ORDER_REQUIRED')
    return table, names


def _dynamic_choice_policy(caller, objects, units, texts):
    # Even an indirectly invoked local routine can replace a LOV/group query.
    # Unknown group/LOV mutations are conservatively unresolved for this module.
    mutators = {'SET_LOV_PROPERTY', 'SET_LOV_COLUMN_PROPERTY', 'SET_GROUP_CHAR_CELL',
                'SET_GROUP_NUMBER_CELL', 'SET_GROUP_DATE_CELL', 'ADD_GROUP_COLUMN',
                'ADD_GROUP_ROW', 'DELETE_GROUP', 'DELETE_GROUP_ROW', 'POPULATE_GROUP',
                'POPULATE_GROUP_WITH_QUERY', 'CREATE_GROUP', 'CREATE_GROUP_FROM_QUERY'}
    for unit in units:
        if objects[unit['owner_id']]['module_id'] != caller['module_id']:
            continue
        semantic, _ = decode_control_entities(texts[unit['id']]['text'])
        tokens, errors = _lex(semantic)
        _need(not errors, 'DYNAMIC_SCAN_INCOMPLETE')
        _need(not any(t[0] == 'word' and t[1].upper() in mutators for t in tokens),
              'DYNAMIC_CHOICE_OVERRIDE_UNPROVEN')


def _contract(group, lov, caller, route, objects, props, units, texts, slot, mappings):
    block = objects[caller['block_id']]
    _need(block['id'] == route['source_block_id'] and caller['module_id'] == route['source_module_id'],
          'SAME_ROW_REQUIRED')
    cp = props[caller['id']]
    _need(cp.get('ItemType', '').upper() == 'TEXT ITEM' and
          cp.get('ValidateFromList', '').strip().lower() == 'true', 'VALIDATE_FROM_LIST_REQUIRED')
    _need(not group['source_bindings'] and not group['global_bindings'], 'UNBOUND_QUERY_REQUIRED')
    table, names = _query(group['query'])
    children = [o for o in objects.values() if o['kind'] == 'RecordGroupColumn' and
                o['parent_id'] == group['source_owner_id']]
    _need(len(children) == len(names), 'COMPLETE_SOURCE_COLUMNS_REQUIRED')
    _need(len(mappings) == len(names) and
          [(m.get('Name') or '').upper() for m in mappings] == names, 'COMPLETE_LOV_PROJECTIONS_REQUIRED')
    declared = [{'source_column_name': m.get('Name'), 'return_item': m.get('ReturnItem')}
                for m in mappings if (m.get('ReturnItem') or '').strip()]
    _need(declared == lov['return_mappings'], 'DECLARED_RETURNS_CHANGED')
    returned = {m['source_column_name'].upper() for m in lov['return_mappings']}
    _need(returned and len(returned) == len(lov['return_mappings']), 'DISTINCT_RETURNS_REQUIRED')
    columns = []
    for child, name in zip(children, names, strict=True):
        p = props[child['id']]
        dtype = p.get('ColumnDataType', '').upper()
        _need((child['name'] or '').upper() == name and dtype in ('CHARACTER', 'NUMBER'), 'EXPLICIT_PROJECTION_TYPE_REQUIRED')
        maximum = p.get('MaximumLength', '')
        _need(re.fullmatch(r'[1-9][0-9]{0,3}', maximum) and int(maximum) <= 4000, 'EXPLICIT_PROJECTION_LENGTH_REQUIRED')
        _need(dtype == 'CHARACTER' or name not in returned, 'NUMERIC_RETURN_UNSUPPORTED')
        columns.append({'name': name, 'source_column_id': child['id'],
            'data_type': 'VARCHAR2' if dtype == 'CHARACTER' else 'NUMBER', 'max_length': int(maximum),
            'length_semantics': 'BYTE' if dtype == 'CHARACTER' else None, 'display_only': name not in returned})
    targets = []
    for mapping in lov['return_mappings']:
        ref = mapping['return_item'].upper().split('.')
        _need(len(ref) == 2 and ref[0] == block['name'].upper(), 'EXPLICIT_SAME_BLOCK_RETURN_REQUIRED')
        item = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id'] and
                     (o['name'] or '').upper() == ref[1]], 'RETURN_ITEM_NOT_UNIQUE')
        p = props[item['id']]
        name = mapping['source_column_name'].upper()
        _need(name in names and p.get('ItemType', '').upper() in ('TEXT ITEM', 'DISPLAY ITEM') and
              p.get('DataType', '').upper() in ('', 'CHAR', 'VARCHAR2') and not p.get('Formula') and
              p.get('CalculateMode', '').upper() in ('', 'NONE'), 'CHARACTER_RETURN_REQUIRED')
        maximum = p.get('MaximumLength', '')
        _need(re.fullmatch(r'[1-9][0-9]{0,3}', maximum) and int(maximum) <= 4000 and
              p.get('DataLengthSemantics', '').upper() == 'BYTE', 'EXPLICIT_BYTE_FIELD_LENGTH_REQUIRED')
        _need(p.get('Required', '').lower() in ('', 'true', 'false'), 'NULL_RULE_UNRESOLVED')
        display = p['ItemType'].upper() == 'DISPLAY ITEM'
        targets.append({'source_item_id': item['id'], 'source_name': groups._label(item['name']),
            'source_block_id': block['id'], 'source_module_id': caller['module_id'],
            'column': f'F{slot:03d}', 'slot': slot, 'data_type': 'VARCHAR2', 'max_length': int(maximum),
            'length_semantics': 'BYTE', 'required': p.get('Required', '').lower() == 'true', 'display_only': display,
            'source_database_item': item.get('database_item'),
            'source_insert_allowed': _flag(p, 'InsertAllowed') and _flag(props[block['id']], 'InsertAllowed'),
            'source_update_allowed': _flag(p, 'UpdateAllowed') and _flag(props[block['id']], 'UpdateAllowed'),
            'direct_edit_allowed': False, 'programmatic_return_allowed': True,
            'source_column': name, 'projection_index': names.index(name) + 1,
            'character_type_proof': 'explicit_record_group_character', 'source_data_type_omitted': not p.get('DataType')})
        slot += 1
    _need(len({t['source_item_id'] for t in targets}) == len(targets), 'DISTINCT_RETURN_TARGETS_REQUIRED')
    caller_field = _one([t for t in targets if t['source_item_id'] == caller['id']], 'CALLER_NOT_A_RETURN_TARGET')
    target_ids = {t['source_item_id'] for t in targets}
    _need(not any(o['kind'] == 'Trigger' and o['parent_id'] in target_ids
                  for o in objects.values()), 'RETURN_EVENT_UNIMPLEMENTED')
    _policy(block, caller, targets, objects, props, units, texts)
    _dynamic_choice_policy(caller, objects, units, texts)
    omitted = []
    for unit in units:
        owner = objects[unit['owner_id']]
        if owner['block_id'] == block['id'] or (owner['kind'] == 'Trigger' and owner['parent_id'] == caller['module_id']):
            omitted.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                'source_chunk_id': texts[unit['id']]['id'], 'source_owner_id': owner['id'],
                'source_event': owner['name'], 'source_attribute': unit['source_attribute'], 'native_event_wired': False})
    c = {'schema_version': 1, 'scope': SCOPE, 'project_id': route['project_id'], 'source_binding': route['source_binding'],
        'route_contract_id': route['contract_id'], 'source_module_id': caller['module_id'],
        'source_block_id': block['id'], 'source_block_name': groups._label(block['name']),
        'source_caller_item_id': caller['id'], 'source_caller_id': caller['id'], 'source_caller_name': groups._label(caller['name']),
        'source_lov_id': lov['source_lov_id'], 'source_lov_name': groups._label(lov['source_lov_name']),
        'source_group_id': group['source_owner_id'], 'source_group_name': groups._label(objects[group['source_owner_id']]['name']),
        'source_unit_id': group['source_unit_id'], 'source_unit_sha256': group['source_unit_sha256'],
        'source_chunk_id': group['source_chunk_id'], 'record_group_operation_id': group['operation_id'],
        'query': deepcopy(group['query']), 'source_table': table, 'caller_source_table': route['caller_source_table'],
        'active_predicate': deepcopy(group['query']['predicates'][0]) if group['query']['predicates'] else None,
        'columns': columns, 'column_types': [props[o['id']]['ColumnDataType'].upper() for o in children],
        'fields': deepcopy(targets), 'returns': targets, 'caller': deepcopy(caller_field), 'inputs': [],
        'validate_from_list': True, 'query_already_counted': True, 'policy_expression_sql': '1', 'enforced_policy_effects': [],
        'unexecuted_source_events': omitted, 'omitted_source_unit_ids': [u['source_unit_id'] for u in omitted],
        'partial_scope_required': True, 'scope_note': 'Companion selection on the same synthetic draft row; only declared return fields are assigned. Other source lifecycle, permission providers, source validation and business saves remain unexecuted.',
        'original_interface_enabled': False, 'source_query_executed': False, 'customer_table_writes': False,
        'synthetic_table_writes': False, 'runtime_verified': False, 'business_accepted': False}
    c['contract_id'] = _digest(c, 'contract_id', 'rate-choice-')
    return c


def validate_rate_choices(bundle, route_contract):
    """Recheck a retained compiler bundle before native rendering.

    Structural validation is not new source proof. compile_rate_choices rebuilds
    original receipts and the route contract; hashes bind this retained result.
    """
    _need(route_contract.get('contract_id') == _digest(route_contract, 'contract_id', 'row-lookup-'), 'ROUTE_HASH')
    b = deepcopy(bundle)
    _need(type(b) is dict and b.get('schema_version') == 1 and b.get('scope') == SCOPE, 'BUNDLE')
    _need(b.get('bundle_id') == _digest(b, 'bundle_id', 'rate-choices-'), 'BUNDLE_HASH')
    for key in ('source_binding', 'project_id', 'source_block_id', 'source_module_id'):
        _need(b.get(key) == route_contract[key], 'ROUTE_BINDING')
    _need(b['route_contract_id'] == route_contract['contract_id'], 'ROUTE_CONTRACT')
    all_fields = []
    seen = {f['source_item_id'] for f in route_contract['fields']}
    callers, ids = set(), set()
    slot = len(route_contract['fields']) + 1
    for c in b['choices']:
        _need(c.get('contract_id') == _digest(c, 'contract_id', 'rate-choice-'), 'CHOICE_HASH')
        _need(c['contract_id'] not in ids and c['source_caller_item_id'] not in callers, 'DISTINCT_CHOICES_REQUIRED')
        ids.add(c['contract_id']); callers.add(c['source_caller_item_id'])
        for key in ('source_binding', 'project_id', 'source_block_id', 'source_module_id', 'route_contract_id'):
            _need(c[key] == b[key], 'CHOICE_BINDING')
        _need(c['scope'] == SCOPE and c['schema_version'] == 1 and
              c['caller_source_table'] == route_contract['caller_source_table'], 'CHOICE_SOURCE')
        _need(c['validate_from_list'] is True and c['inputs'] == [] and c['policy_expression_sql'] == '1' and
              c['enforced_policy_effects'] == [] and c['query_already_counted'] is True, 'CHOICE_POLICY')
        _need(all(c[k] is False for k in ('original_interface_enabled', 'source_query_executed',
              'customer_table_writes', 'synthetic_table_writes', 'runtime_verified', 'business_accepted')) and
              c['partial_scope_required'] is True, 'SOURCE_GATES')
        for key in ('source_block_name', 'source_caller_name', 'source_lov_name', 'source_group_name'):
            groups._label(c[key])
        _need(re.fullmatch('[a-f0-9]{64}', c['source_unit_sha256']) is not None, 'SOURCE_HASH')
        for key in ('source_module_id', 'source_block_id', 'source_caller_item_id', 'source_lov_id', 'source_group_id', 'source_unit_id'):
            _need(re.fullmatch('ff1-[a-f0-9]{24}', c[key]) is not None, 'SOURCE_IDENTITY')
        _need(c['source_caller_id'] == c['source_caller_item_id'] and
              re.fullmatch('fup1-[a-f0-9]{64}', c['source_chunk_id']) is not None and
              re.fullmatch('record-group-[a-f0-9]{20}', c['record_group_operation_id']) is not None, 'SOURCE_IDENTITY')
        table, names = _query(c['query'])
        _need(table == c['source_table'] and [v['name'] for v in c['columns']] == names and
              c['active_predicate'] == (c['query']['predicates'][0] if c['query']['predicates'] else None), 'QUERY_COLUMNS')
        _need(c['fields'] == c['returns'] and c['fields'] and c['caller'] in c['returns'] and
              c['caller']['source_item_id'] == c['source_caller_item_id'], 'COMPLETE_RETURNS')
        returned = {f['source_column'] for f in c['returns']}
        _need(len(returned) == len(c['returns']) and len(c['column_types']) == len(names), 'DISTINCT_RETURN_COLUMNS')
        for col, dtype in zip(c['columns'], c['column_types'], strict=True):
            _need(col['data_type'] in ('VARCHAR2', 'NUMBER') and dtype ==
                  ('CHARACTER' if col['data_type'] == 'VARCHAR2' else 'NUMBER'), 'PROJECTION_TYPE')
            _need(type(col['max_length']) is int and 1 <= col['max_length'] <= 4000 and
                  col['length_semantics'] == ('BYTE' if col['data_type'] == 'VARCHAR2' else None), 'PROJECTION_LENGTH')
            _need(col['display_only'] is (col['name'] not in returned) and
                  (col['data_type'] != 'NUMBER' or col['display_only']), 'DISPLAY_PROJECTION_ONLY')
        for f in c['fields']:
            _need(f['source_item_id'] not in seen and f['slot'] == slot and f['column'] == f'F{slot:03d}', 'SHARED_FIELD_IDENTITY')
            seen.add(f['source_item_id']); slot += 1
            _need(f['source_block_id'] == b['source_block_id'] and f['source_module_id'] == b['source_module_id'], 'SAME_ROW_REQUIRED')
            groups._label(f['source_name'])
            _need(f['data_type'] == 'VARCHAR2' and type(f['max_length']) is int and 1 <= f['max_length'] <= 4000 and
                  f['length_semantics'] == 'BYTE', 'RETURN_STORAGE')
            _need(all(type(f[k]) is bool for k in ('required', 'display_only', 'direct_edit_allowed', 'programmatic_return_allowed')) and
                  f['direct_edit_allowed'] is False and f['programmatic_return_allowed'] is True and
                  f['source_update_allowed'] is True, 'RETURN_POLICY')
            _need(type(f['projection_index']) is int and 1 <= f['projection_index'] <= len(names) and
                  c['columns'][f['projection_index'] - 1]['name'] == f['source_column'] and
                  c['columns'][f['projection_index'] - 1]['data_type'] == 'VARCHAR2', 'RETURN_PROJECTION')
            all_fields.append(f)
    _need(slot <= 19 and b['fields'] == all_fields, 'SHARED_FIELD_CAPACITY')
    return b


def compile_rate_choices(documents, packet, chunks, trace, files, group_receipt, lov_receipt, route_contract):
    """Compile complete eligible companions without mutating normal source gaps.

    Proof failures raise. Unsupported individual callers remain explicit bundle
    gaps and ordinary receipt gaps; no subset of their returns is emitted.
    """
    with generation_sources(documents):
        objects, props = _normal_receipts(documents, packet, chunks, trace, files, group_receipt, lov_receipt)
        routes = compile_row_lookups(documents, packet, chunks, trace, files, group_receipt, lov_receipt)
        _need(route_contract in routes, 'FRESH_ROUTE_REQUIRED')
        lov_columns = _lov_columns(documents, packet)
        units = [u for entry in packet['sources'] for u in entry['facts']['code_units']]
        texts = {c['code_unit_id']: c for c in chunks}
        candidates, gaps = [], []
        seen = {f['source_item_id'] for f in route_contract['fields']}
        for group in group_receipt['generated_operations']:
            for lov in group['associated_lovs']:
                callers = [o for o in objects.values() if o['kind'] == 'Item' and
                           o['module_id'] == route_contract['source_module_id'] and
                           props[o['id']].get('LovName', '').upper() == lov['source_lov_name'].upper()]
                same_row = [o for o in callers if o['block_id'] == route_contract['source_block_id'] and
                            o['id'] != route_contract['source_caller_item_id']]
                if not same_row:
                    continue
                try:
                    caller = _one(callers, 'CALLER_NOT_UNIQUE')
                    key = group['source_unit_id'], lov['source_lov_id']
                    omitted = any((g['source_unit_id'], g['source_lov_id']) == key
                                  and g['reason'] == 'LOV_RETURN_CALLER_BLOCK' for g in lov_receipt['gaps'])
                    existing = any((g['source_group_unit_id'], g['source_lov_id']) == key
                                   and g['source_caller_item_id'] == caller['id']
                                   for g in lov_receipt['generated_operations'])
                    _need(omitted or existing, 'EXISTING_CALLER_BINDING_REQUIRED')
                    c = _contract(group, lov, caller, route_contract, objects, props, units, texts,
                                  1, lov_columns[lov['source_lov_id']])
                    _need(not seen & {f['source_item_id'] for f in c['fields']}, 'OVERLAPPING_RETURN_TARGET')
                    candidates.append(c)
                except ValueError as error:
                    gaps.append({'source_unit_id': group['source_unit_id'], 'source_lov_id': lov['source_lov_id'],
                        'source_caller_item_ids': [o['id'] for o in same_row],
                        'declared_return_mappings': deepcopy(lov['return_mappings']), 'reason': str(error),
                        'query_reporting_retained': True, 'native_event_wired': False})
        counts = {}
        for c in candidates:
            for f in c['fields']:
                counts[f['source_item_id']] = counts.get(f['source_item_id'], 0) + 1
        choices, fields = [], []
        for c in candidates:
            reason = ('RATE_CHOICES_AMBIGUOUS_RETURN_TARGET' if any(counts[f['source_item_id']] > 1 for f in c['fields'])
                      else 'RATE_CHOICES_SHARED_FIELD_CAPACITY' if len(route_contract['fields']) + len(fields) + len(c['fields']) > 18 else None)
            if reason:
                gaps.append({'source_unit_id': c['source_unit_id'], 'source_lov_id': c['source_lov_id'],
                    'source_caller_item_ids': [c['source_caller_item_id']], 'reason': reason,
                    'query_reporting_retained': True, 'native_event_wired': False})
                continue
            for f in c['returns']:
                f['slot'] = len(route_contract['fields']) + len(fields) + 1
                f['column'] = f"F{f['slot']:03d}"
                fields.append(deepcopy(f))
            c['fields'] = deepcopy(c['returns'])
            c['caller'] = deepcopy(next(f for f in c['returns'] if f['source_item_id'] == c['source_caller_item_id']))
            c['contract_id'] = _digest(c, 'contract_id', 'rate-choice-')
            choices.append(c)
        b = {'schema_version': 1, 'scope': SCOPE, 'project_id': route_contract['project_id'],
             'source_binding': route_contract['source_binding'], 'source_block_id': route_contract['source_block_id'],
             'source_module_id': route_contract['source_module_id'], 'route_contract_id': route_contract['contract_id'],
             'choices': choices, 'fields': fields, 'gaps': gaps}
        b['bundle_id'] = _digest(b, 'bundle_id', 'rate-choices-')
        return validate_rate_choices(b, route_contract)


def _lov_columns(documents, packet):
    """Keep explicitly blank ReturnItem projections, absent from normal receipts."""
    from . import forms_facts
    result = {}
    for name, raw in documents:
        root, locations = forms_facts._safe_input(name, raw)
        nodes = {loc['path']: node for node, loc in zip(root.iter(), locations, strict=True)}
        source = next(s for s in packet['sources'] if s['source']['name'] == name)
        for obj in source['facts']['objects']:
            if obj['kind'] == 'LOV':
                result[obj['id']] = [dict(n.attrib) for n in nodes[obj['location']['path']]
                                     if forms_facts._local(n.tag) == 'LOVColumnMapping']
    return result
