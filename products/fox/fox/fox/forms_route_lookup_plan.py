"""Source-proof optional multi-column choosers for identified caller blocks.

This is a session-draft contract, never an original table mapping or permission
to execute the caller's other events. Normal reference-query/LOV receipts remain
the coverage authorities. Unsupported callers simply retain those normal gaps.
"""
from __future__ import annotations

from copy import deepcopy
import json
import re

from forms2apex import native_blueprint, native_record_groups as groups
from .forms_behavior_plan import _source_objects, decode_control_entities
from .forms_interface_inventory import _arguments, _lex
from .forms_lov_return import apply_lov_returns
from .forms_native_plan import POLICY_ID, build_native_prototype_plan
from .forms_understanding_packet import _build, generation_sources
from .forms_route_lookup_typed import compile_typed_lookup

SCOPE = 'fox-source-row-lookup-contract-v1'
OPTIONAL_CALLER_GAPS = frozenset({'LOV_RETURN_CALLER_BLOCK', 'LOV_RETURN_VALIDATE_FROM_LIST_REQUIRED'})


def _need(condition, reason):
    if not condition:
        raise ValueError('ROW_LOOKUP_' + reason)


def _one(values, reason):
    _need(len(values) == 1, reason)
    return values[0]


def _flag(props, name):
    value = props.get(name, '').strip().lower()
    _need(value in ('', 'true', 'false'), 'STATIC_PROPERTY_UNRESOLVED')
    return value != 'false'


def _normal_receipts(documents, packet, chunks, trace, files, group_receipt, lov_receipt):
    """Rebuild the ordinary 0.51 boundary instead of trusting signed metadata."""
    from .xml_mapping import _blueprint
    fresh, fresh_chunks = _build(documents)
    # local_packet adds this inert generation marker; selected/authorized
    # transfer packets and every other change must fail exact reconstruction.
    supplied_packet = deepcopy(packet)
    if supplied_packet.get('selection_status') == 'NOT_SELECTED':
        supplied_packet.pop('selection_status')
    _need(supplied_packet == fresh and chunks == fresh_chunks and
          trace.get('source_binding') == fresh['source_binding'], 'SOURCE_CHANGED')
    objects, props = _source_objects(documents, fresh)
    spec = build_native_prototype_plan(documents, _blueprint(fresh), project_id=trace['project_id'],
        project_name='Row lookup proof', approved_policy_id=POLICY_ID)['rendering_spec']
    expected_trace = native_blueprint.prototype_trace(spec)
    for block in expected_trace['blocks']:
        block['source_module_id'] = objects[block['source_block_id']]['module_id']
    _need(trace['blocks'] == expected_trace['blocks'], 'FRESH_SYNTHETIC_TRACE_REQUIRED')
    schema = native_blueprint.render_prototype_schema(spec).encode()
    _need(files.get('fox-package/supporting-schema.sql') == schema, 'SYNTHETIC_SCHEMA_CHANGED')
    _need(all(files.get('fox-package/sources/' + name) == raw for name, raw in documents), 'ORIGINAL_SOURCES_REQUIRED')
    baseline = {k: v.encode() for k, v in native_blueprint.render_native_blueprint(spec).items()}
    baseline, expected_group = groups.apply_record_groups(documents, fresh, fresh_chunks, trace, baseline)
    baseline['fox-package/record-group-receipt.json'] = groups._json(expected_group)
    baseline['fox-package/supporting-schema.sql'] = schema
    for name, raw in documents:
        baseline['fox-package/sources/' + name] = raw
    _, expected_lov = apply_lov_returns(documents, fresh, fresh_chunks, trace, baseline)
    try:
        stored_group = json.loads(files['fox-package/record-group-receipt.json'])
        stored_lov = json.loads(files['fox-package/lov-return-receipt.json'])
    except (KeyError, ValueError, TypeError, UnicodeError):
        raise ValueError('ROW_LOOKUP_NORMAL_RECEIPTS_REQUIRED') from None
    _need(stored_group == group_receipt == expected_group and
          stored_lov == lov_receipt == expected_lov, 'FRESH_NORMAL_RECEIPTS_REQUIRED')
    return objects, props


def _closed_query(group, objects, props):
    query = group['query']
    _need(set(query) == {'tables', 'projections', 'predicates', 'order'} and
          all(set(term) == {'parts', 'direction'} for term in query['order']), 'CLOSED_QUERY_SHAPE_REQUIRED')
    _need(not group['source_bindings'] and not group['global_bindings'] and
          len(query['tables']) == 1 and len(query['tables'][0]) == 1 and
          len(query['predicates']) == 1, 'UNBOUND_SINGLE_TABLE_FILTER_REQUIRED')
    table = query['tables'][0][0]
    groups._identifier(table)
    def column(parts):
        _need(len(parts) == 1 or (len(parts) == 2 and parts[0] == table), 'FOREIGN_QUERY_COLUMN')
        return groups._identifier(parts[-1])
    names = [column(p) for p in query['projections']]
    _need(2 <= len(names) <= 18 and len(names) == len(set(names)), 'COMPLETE_DISTINCT_PROJECTION_REQUIRED')
    predicate = query['predicates'][0]
    _need(set(predicate) == {'left', 'op', 'right'} and predicate['op'] == '=' and
          predicate['left']['kind'] == 'column' and predicate['right']['kind'] == 'string' and
          predicate['right']['value'] in ('1', 'Y'), 'CLOSED_STATUS_FILTER_REQUIRED')
    column(predicate['left']['parts'])
    for term in query['order']:
        _need(column(term['parts']) in names, 'ORDER_COLUMN_NOT_PROJECTED')
    children = [o for o in objects.values() if o['kind'] == 'RecordGroupColumn' and
                o['parent_id'] == group['source_owner_id']]
    _need(len(children) == len(names), 'SOURCE_COLUMNS_REQUIRED')
    columns = []
    for child, name in zip(children, names, strict=True):
        p = props[child['id']]
        _need((child['name'] or '').upper() == name and p.get('ColumnDataType', '').upper() == 'CHARACTER',
              'EXPLICIT_CHARACTER_PROJECTION_REQUIRED')
        maximum = p.get('MaximumLength', '')
        _need(re.fullmatch(r'[1-9][0-9]{0,3}', maximum) and int(maximum) <= 4000, 'EXPLICIT_COLUMN_LENGTH_REQUIRED')
        columns.append({'name': name, 'source_column_id': child['id'], 'data_type': 'VARCHAR2',
                        'max_length': int(maximum), 'length_semantics': 'BYTE'})
    return columns


def _policy(block, caller, targets, objects, props, units, chunks):
    """Static permissions only; unresolved relevant dynamic edits stay gaps.

    Inspect all local bodies, including routines invoked indirectly, with the
    existing comment/literal-aware lexer. A computed property target or object
    handle cannot establish that it excludes this caller.
    """
    relevant = {block['id'], caller['id']} | {t['source_item_id'] for t in targets}
    for oid in relevant:
        _need(_flag(props[oid], 'UpdateAllowed') and _flag(props[oid], 'Enabled'), 'STATIC_EDIT_DISABLED')
    for unit in units:
        owner = objects[unit['owner_id']]
        if owner['module_id'] != caller['module_id']:
            continue
        if owner['kind'] == 'Trigger' and (owner['name'] or '').upper() == 'WHEN-NEW-RECORD-INSTANCE':
            _need(owner['block_id'] not in (None, block['id']) and owner['parent_id'] != caller['module_id'],
                  'DYNAMIC_ENTRY_POLICY_UNPROVEN')
        semantic, _ = decode_control_entities(chunks[unit['id']]['text'])
        tokens, errors = _lex(semantic)
        _need(not errors, 'POLICY_SCAN_INCOMPLETE')
        for index, token in enumerate(tokens):
            if token[0] != 'word' or token[1].upper() not in {
                'SET_ITEM_PROPERTY', 'SET_ITEM_INSTANCE_PROPERTY', 'SET_BLOCK_PROPERTY'}:
                continue
            arguments, _, error = _arguments(tokens, index + 1)
            _need(index + 1 < len(tokens) and tokens[index + 1][1] == '(' and not error and
                  len(arguments) == 3, 'DYNAMIC_PROPERTY_TARGET_UNPROVEN')
            # Relation coordination is not an edit permission. Its source
            # helper remains unexecuted; it cannot grant this draft access.
            if (token[1].upper() == 'SET_BLOCK_PROPERTY' and len(arguments[1]) == 1 and
                    arguments[1][0][0] == 'word' and arguments[1][0][1].upper() == 'COORDINATION_STATUS'):
                continue
            _need(index + 3 < len(tokens) and tokens[index + 1][1] == '(' and
                  tokens[index + 2][0] == 'literal' and tokens[index + 3][1] == ',', 'DYNAMIC_PROPERTY_TARGET_UNPROVEN')
            literal = semantic[tokens[index + 2][2]:tokens[index + 2][3]]
            _need(re.fullmatch(r"'[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*)?'", literal),
                  'DYNAMIC_PROPERTY_TARGET_UNPROVEN')
            parts = literal[1:-1].upper().split('.')
            kind = 'Block' if token[1].upper() == 'SET_BLOCK_PROPERTY' else 'Item'
            matches = [o for o in objects.values() if o['kind'] == kind and o['module_id'] == caller['module_id']
                       and (o['name'] or '').upper() == parts[-1]
                       and (len(parts) == 1 or (kind == 'Item' and
                            objects[o['block_id']]['name'].upper() == parts[0]))]
            _need(len(matches) == 1 and matches[0]['id'] not in relevant, 'DYNAMIC_EDIT_POLICY_UNPROVEN')


def _contract(group, lov, caller, objects, props, trace, units, texts, source_binding):
    block = objects[caller['block_id']]
    rendered = [b for b in trace['blocks'] if b['source_block_id'] == block['id']]
    bp, cp = props[block['id']], props[caller['id']]
    source_table = bp.get('QueryDataSourceName', '').upper()
    groups._identifier(source_table)
    _need(bp.get('DatabaseBlock', '').lower() in ('', 'true', 'yes') and
          bp.get('QueryDataSourceType', 'TABLE').upper() == 'TABLE', 'EXPLICIT_CALLER_TABLE_REQUIRED')
    _need(cp.get('ItemType', '').upper() == 'TEXT ITEM' and
          cp.get('ValidateFromList', '').lower() == 'false', 'OPTIONAL_SOURCE_CHOOSER_REQUIRED')
    columns = _closed_query(group, objects, props)
    names = [c['name'] for c in columns]
    _need(len(lov['return_mappings']) == len(columns), 'COMPLETE_RETURN_MAPPING_REQUIRED')
    targets = []
    for mapping in lov['return_mappings']:
        reference = mapping['return_item'].upper().split('.')
        _need(len(reference) == 2 and reference[0] == block['name'].upper(), 'EXPLICIT_SAME_BLOCK_RETURN_REQUIRED')
        item = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id'] and
                     (o['name'] or '').upper() == reference[1]], 'RETURN_ITEM_NOT_UNIQUE')
        p = props[item['id']]
        name = mapping['source_column_name'].upper()
        _need(name in names and p.get('ItemType', '').upper() in ('TEXT ITEM', 'DISPLAY ITEM') and
              p.get('DataType', '').upper() in ('', 'CHAR', 'VARCHAR2') and
              not p.get('Formula') and p.get('CalculateMode', '').upper() in ('', 'NONE'), 'CHARACTER_RETURN_REQUIRED')
        maximum = p.get('MaximumLength', '')
        _need(re.fullmatch(r'[1-9][0-9]{0,3}', maximum) and int(maximum) <= 4000 and
              p.get('DataLengthSemantics', '').upper() == 'BYTE', 'EXPLICIT_BYTE_FIELD_LENGTH_REQUIRED')
        _need(p.get('Required', '').lower() in ('', 'true', 'false'), 'SOURCE_NULL_RULE_UNRESOLVED')
        display = p['ItemType'].upper() == 'DISPLAY ITEM'
        slot = names.index(name) + 1
        targets.append({'source_item_id': item['id'], 'source_name': groups._label(item['name']),
            'source_block_id': block['id'], 'source_module_id': caller['module_id'], 'column': f'F{slot:03d}',
            'slot': slot, 'data_type': 'VARCHAR2', 'max_length': int(maximum), 'length_semantics': 'BYTE',
            'required': p.get('Required', '').lower() == 'true', 'display_only': display,
            'source_database_item': item.get('database_item'),
            'source_insert_allowed': _flag(p, 'InsertAllowed') and _flag(bp, 'InsertAllowed'),
            'source_update_allowed': _flag(p, 'UpdateAllowed') and _flag(bp, 'UpdateAllowed'),
            'direct_edit_allowed': not display and _flag(p, 'Enabled') and _flag(p, 'UpdateAllowed') and _flag(bp, 'UpdateAllowed'),
            'programmatic_return_allowed': True, 'source_column': name, 'projection_index': slot,
            'character_type_proof': 'explicit_record_group_character', 'source_data_type_omitted': not p.get('DataType')})
    _need(len({t['source_item_id'] for t in targets}) == len(columns) and
          {t['source_column'] for t in targets} == set(names), 'COMPLETE_DISTINCT_RETURN_MAPPING_REQUIRED')
    caller_field = _one([t for t in targets if t['source_item_id'] == caller['id']], 'CALLER_NOT_A_RETURN_TARGET')
    if rendered:
        host = _one(rendered, 'CALLER_BLOCK_NOT_UNIQUE')
        _need(host['classification'] == 'database' and host['source_module_id'] == caller['module_id'],
              'CALLER_PROVIDER')
        for target in targets:
            field = _one([f for f in host['items'] if f['source_item_id'] == target['source_item_id']],
                         'RETURN_ITEM_NOT_RENDERED')
            _need(field['source_name'] == target['source_name'] and field['data_type'] == 'VARCHAR2',
                  'RETURN_ITEM_TYPE_MISMATCH')
    _policy(block, caller, targets, objects, props, units, texts)
    omitted = []
    for unit in units:
        owner = objects[unit['owner_id']]
        if owner['block_id'] == block['id'] or (owner['kind'] == 'Trigger' and owner['parent_id'] == caller['module_id']):
            omitted.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                'source_chunk_id': texts[unit['id']]['id'], 'source_owner_id': owner['id'],
                'source_event': owner['name'], 'source_attribute': unit['source_attribute'], 'native_event_wired': False})
    contract = {'schema_version': 1, 'scope': SCOPE, 'source_binding': source_binding,
        'project_id': trace['project_id'],
        'source_module_id': caller['module_id'], 'source_block_id': block['id'], 'source_block_name': groups._label(block['name']),
        'source_caller_item_id': caller['id'], 'source_caller_id': caller['id'], 'source_caller_name': groups._label(caller['name']),
        'source_lov_id': lov['source_lov_id'], 'source_lov_name': groups._label(lov['source_lov_name']),
        'source_unit_id': group['source_unit_id'], 'source_unit_sha256': group['source_unit_sha256'],
        'source_chunk_id': group['source_chunk_id'], 'source_group_id': group['source_owner_id'],
        'source_group_name': groups._label(objects[group['source_owner_id']]['name']),
        'record_group_operation_id': group['operation_id'], 'query_already_counted': True,
        'query': deepcopy(group['query']), 'source_table': group['query']['tables'][0][0],
        'caller_source_table': source_table, 'active_predicate': deepcopy(group['query']['predicates'][0]),
        'columns': columns, 'fields': sorted(deepcopy(targets), key=lambda t: t['slot']),
        'returns': targets, 'caller': deepcopy(caller_field), 'inputs': [], 'column_types': ['CHARACTER'] * len(columns),
        'policy_expression_sql': '1', 'enforced_policy_effects': [], 'unexecuted_source_events': omitted,
        'omitted_source_unit_ids': [u['source_unit_id'] for u in omitted], 'partial_scope_required': True,
        'scope_note': 'Session-only selected-row chooser. Other source events, record creation, validation, permissions providers and database saves are unexecuted. Original sources are preserved; explicit partial scope consent is required.',
        'original_interface_enabled': False, 'source_query_executed': False, 'customer_table_writes': False,
        'synthetic_table_writes': False, 'runtime_verified': False, 'business_accepted': False}
    contract.update(compile_typed_lookup(contract, objects, units, texts))
    if contract.get('typed_lookup'):
        typed_id = contract['typed_lookup']['source_unit_id']
        contract['unexecuted_source_events'] = [u for u in omitted if u['source_unit_id'] != typed_id]
        contract['omitted_source_unit_ids'] = [u['source_unit_id'] for u in contract['unexecuted_source_events']]
        contract['scope_note'] = ('Session-only row chooser and source POST-CHANGE adapted to explicit changed-caller Keep/Apply against an empty synthetic catalog. '
            'Other source events, record creation, permissions providers and business-table saves are unexecuted. '
            'Original sources are preserved; explicit partial scope consent is required.')
    contract['contract_id'] = 'row-lookup-' + groups._sha(groups._json(contract))[:24]
    return contract


def compile_row_lookups(documents, packet, chunks, trace, files, group_receipt, lov_receipt):
    """Return complete eligible caller contracts, preserving every normal gap.

    Global proof failures raise; unsupported individual source callers produce
    no contract. This function never edits files, receipts, trace or sources.
    Its result is not partial-scope consent or an activation permission.
    """
    with generation_sources(documents):
        objects, props = _normal_receipts(documents, packet, chunks, trace, files, group_receipt, lov_receipt)
        units = [u for entry in packet['sources'] for u in entry['facts']['code_units']]
        texts = {c['code_unit_id']: c for c in chunks}
        contracts = []
        for group in group_receipt['generated_operations']:
            for lov in group['associated_lovs']:
                if not any(g['source_unit_id'] == group['source_unit_id'] and g['source_lov_id'] == lov['source_lov_id']
                           and g['reason'] in OPTIONAL_CALLER_GAPS for g in lov_receipt['gaps']):
                    continue
                callers = [o for o in objects.values() if o['kind'] == 'Item' and o['module_id'] == group['source_module_id']
                           and props[o['id']].get('LovName', '').upper() == lov['source_lov_name'].upper()]
                try:
                    caller = _one(callers, 'CALLER_NOT_UNIQUE')
                    contracts.append(_contract(group, lov, caller, objects, props, trace, units, texts, packet['source_binding']))
                except ValueError:
                    # The normal source-bound LOV gap remains visible. No
                    # return subset or fabricated successful event is emitted.
                    continue
        return deepcopy(contracts)
