"""Source-bound numeric inputs for an existing synthetic shared rate row.

Pictures constrain input, never database precision. This compiler executes no
source event, source query or business DML and preserves unsupported fields as
gaps. Retained receipt checks are not a replacement for compilation from source.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import re

from forms2apex import native_record_groups as groups
from .forms_behavior_plan import decode_control_entities
from .forms_interface_inventory import _arguments, _lex
from .forms_route_lookup_plan import _flag, _normal_receipts, _policy, compile_row_lookups
from .forms_understanding_packet import generation_sources

SCOPE = 'fox-source-rate-numbers-v1'
NOTATION = 'ungrouped_ASCII_decimal_dot_optional_sign_no_exponent'
_DECIMAL = re.compile(r'[+-]?[0-9]+(?:\.[0-9]+)?')
_SOURCE_ID = re.compile(r'ff1-[a-f0-9]{24}')
_RULE_KEYS = ('picture', 'integer_digits', 'scale', 'max_length', 'required',
              'min_value', 'max_value', 'precision', 'input_notation',
              'conversion_nls', 'rounding_or_truncation')


def _need(value, reason):
    if not value:
        raise ValueError('RATE_NUMBERS_' + reason)


def _digest(value):
    body = deepcopy(value)
    body.pop('contract_id', None)
    return 'rate-numbers-' + groups._sha(groups._json(body))[:24]


def _bound(raw):
    if not raw:
        return None
    _need(type(raw) is str and len(raw) <= 100 and _DECIMAL.fullmatch(raw), 'EXPLICIT_DECIMAL_BOUND_REQUIRED')
    number = Decimal(raw)
    significant = ''.join(str(n) for n in number.as_tuple().digits).rstrip('0')
    _need(len(significant) <= 38, 'EXACT_BOUND_REQUIRED')
    result = format(number, 'f')
    if '.' in result:
        result = result.rstrip('0').rstrip('.')
    return '0' if number == 0 else result


def numeric_rules(properties):
    """Bounded fixed decimal pictures; no NLS inference or implicit rounding."""
    picture = properties.get('FormatMask', '').strip()
    _need(re.fullmatch(r'[90]+(?:,[90]{3})*(?:\.[90]+)?', picture), 'EXPLICIT_DECIMAL_PICTURE_REQUIRED')
    whole, _, fraction = picture.partition('.')
    digits, scale = len(whole.replace(',', '')), len(fraction)
    length = properties.get('MaximumLength', '').strip()
    _need(1 <= digits <= 38 and digits + scale <= 38 and
          re.fullmatch(r'[1-9][0-9]{0,3}', length) and int(length) <= 4000, 'NUMERIC_LIMITS')
    required = properties.get('Required', '').strip().lower()
    _need(required in ('', 'false', 'true'), 'NULL_RULE_UNRESOLVED')
    minimum = _bound(properties.get('LowestAllowedValue', '').strip())
    maximum = _bound(properties.get('HighestAllowedValue', '').strip())
    _need(minimum is None or maximum is None or Decimal(minimum) <= Decimal(maximum), 'BOUND_ORDER')
    return {'picture': picture, 'integer_digits': digits, 'scale': scale,
            'max_length': int(length), 'required': required == 'true',
            'min_value': minimum, 'max_value': maximum, 'precision': None,
            'input_notation': NOTATION, 'conversion_nls': 'NLS_NUMERIC_CHARACTERS=.,',
            'rounding_or_truncation': False}


def validate_numeric_value(value, rules):
    """Exact reference boundary for the renderer, including optional NULL."""
    if value is None or value == '':
        _need(rules['required'] is False, 'VALUE_REQUIRED')
        return None
    _need(type(value) is str and len(value) <= rules['max_length'], 'VALUE_LENGTH')
    _need(_DECIMAL.fullmatch(value), 'VALUE_NOTATION')
    whole, _, fraction = value.lstrip('+-').partition('.')
    _need(len(whole.lstrip('0') or '0') <= rules['integer_digits'] and
          len(fraction) <= rules['scale'], 'VALUE_PICTURE')
    number = Decimal(value)
    _need((rules['min_value'] is None or number >= Decimal(rules['min_value'])) and
          (rules['max_value'] is None or number <= Decimal(rules['max_value'])), 'VALUE_BOUND')
    return number


def _unit_proof(unit, texts):
    return {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
            'source_chunk_id': texts[unit['id']]['id'], 'source_owner_id': unit['owner_id'],
            'source_attribute': unit['source_attribute'], 'native_event_wired': False}


def _date_callback_shape(owner, semantic, tokens):
    """Recognize a complete external-calendar callback, without executing it."""
    pattern = ('PROCEDURE @callback IS BEGIN COPY ( TO_CHAR ( @package . @date , @format ) , '
               '@package . @target ) ; GO_ITEM ( @package . @target ) ; IF @package . @skip = TRUE '
               'THEN NEXT_ITEM ; END IF ; END ;').split()
    _need(owner['kind'] == 'ProgramUnit' and len(tokens) == len(pattern), 'DYNAMIC_REFERENCE_UNPROVEN')
    captured = {}
    for token, expected in zip(tokens, pattern, strict=True):
        value = token[1].upper()
        if expected == '@format':
            _need(token[0] == 'literal' and semantic[token[2]:token[3]].upper() == "'DD-MM-YYYY HH24:MI'",
                  'DYNAMIC_REFERENCE_UNPROVEN')
        elif expected.startswith('@'):
            _need(token[0] == 'word' and re.fullmatch('[A-Z][A-Z0-9_$#]*', value), 'DYNAMIC_REFERENCE_UNPROVEN')
            _need(expected not in captured or captured[expected] == value, 'DYNAMIC_REFERENCE_UNPROVEN')
            captured[expected] = value
        else:
            _need(value == expected, 'DYNAMIC_REFERENCE_UNPROVEN')
    _need(captured['@callback'] == owner['name'].upper() and
          len({captured[k] for k in ('@date', '@target', '@skip')}) == 3, 'DYNAMIC_REFERENCE_UNPROVEN')
    return captured


def _date_omission(unit, semantic, tokens, item, objects, props, units, texts):
    """Audit a suppressed calendar boundary, not immutable external state.

    Only literal, uniquely DATE-typed item callers and the entire known callback
    shape qualify. The external library is unavailable: its mutable return-item
    state is explicitly unproved and neither callback nor callers are wired to
    the numeric adapter. Other uses of that package invalidate this exception.
    """
    captured = _date_callback_shape(objects[unit['owner_id']], semantic, tokens)
    package = captured['@package']
    callers, getter = [], None
    for other in units:
        owner = objects[other['owner_id']]
        if other['id'] == unit['id'] or owner['module_id'] != item['module_id']:
            continue
        text, _ = decode_control_entities(texts[other['id']]['text'])
        scanned, errors = _lex(text)
        _need(not errors, 'EVENT_SCAN_INCOMPLETE')
        _need(not any(t[0] == 'literal' and package + '.' in text[t[2]:t[3]].upper()
                      for t in scanned), 'DATE_PACKAGE_USE_UNPROVEN')
        positions = [i for i, t in enumerate(scanned) if t[0] == 'word' and t[1].upper() == package]
        if not positions:
            continue
        # Each complete item trigger must consist of exactly one calendar call.
        _need(positions == [0] and len(scanned) > 4 and scanned[1][1] == '.' and
              scanned[2][0] == 'word' and scanned[3][1] == '(', 'DATE_PACKAGE_USE_UNPROVEN')
        method = scanned[2][1].upper()
        _need(method not in {captured[k] for k in ('@date', '@target', '@skip')} and
              (getter is None or method == getter), 'DATE_PACKAGE_USE_UNPROVEN')
        args, end, error = _arguments(scanned, 3)
        _need(not error and len(args) == 10 and end == len(scanned) - 2 and scanned[-1][1] == ';', 'DATE_CALLER_UNPROVEN')
        _need(len(args[0]) == 1 and args[0][0][1].upper() == 'SYSDATE' and
              len(args[1]) == 1 and args[1][0][0] == 'literal', 'DATE_CALLER_UNPROVEN')
        target = text[args[1][0][2]:args[1][0][3]]
        _need(re.fullmatch(r"'[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*)?'", target), 'DATE_CALLER_UNPROVEN')
        parts = target[1:-1].upper().split('.')
        matches = [o for o in objects.values() if o['kind'] == 'Item' and o['module_id'] == item['module_id'] and
                   (o['name'] or '').upper() == parts[-1] and
                   (len(parts) == 1 or objects[o['block_id']]['name'].upper() == parts[0])]
        _need(len(matches) == 1 and matches[0]['id'] != item['id'] and
              props[matches[0]['id']].get('DataType', '').upper() in ('DATE', 'DATETIME') and
              owner['kind'] == 'Trigger' and owner['name'].upper() == 'KEY-LISTVAL' and
              owner['parent_id'] == matches[0]['id'], 'DATE_CALLER_TYPE_UNPROVEN')
        for arg in args[2:4]:
            _need(len(arg) == 1 and arg[0][0] == 'number' and
                  re.fullmatch('[0-9]+', text[arg[0][2]:arg[0][3]]), 'DATE_CALLER_UNPROVEN')
        _need(all(len(a) == 1 and a[0][0] == 'literal' for a in args[4:7]) and
              all(len(a) == 1 and a[0][1].upper() in ('TRUE', 'FALSE') for a in args[7:]), 'DATE_CALLER_UNPROVEN')
        getter = method
        callers.append({**_unit_proof(other, texts), 'source_item_id': matches[0]['id'],
                        'source_name': matches[0]['name'], 'source_block_id': matches[0]['block_id'],
                        'data_type': props[matches[0]['id']]['DataType'].upper(), 'source_event': owner['name']})
    _need(callers and len({c['source_item_id'] for c in callers}) == len(callers), 'DATE_CALLERS_REQUIRED')
    return {'kind': 'suppressed_external_date_callback', 'callback': _unit_proof(unit, texts),
            'callers': callers, 'package_name': package, 'getter_name': getter,
            'date_member': captured['@date'], 'target_member': captured['@target'], 'skip_member': captured['@skip'],
            'target_nonoverlap_proven': False, 'native_event_wired': False,
            'runtime_verified': False, 'business_accepted': False,
            'reason': 'Legacy calendar callback and DATE callers remain unexecuted and unverified. External mutable target state is unknown. Only separate synthetic numeric actions are generated.'}


def _events(item, block, objects, props, units, texts):
    """Conservative literal/comment-aware field and indirect mutation scan."""
    _need(not any(o['kind'] == 'Trigger' and o['parent_id'] == item['id']
                  for o in objects.values()), 'ITEM_EVENT_UNIMPLEMENTED')
    proofs, omissions, identifier_mentions = [], [], []
    for unit in units:
        if objects[unit['owner_id']]['module_id'] != item['module_id']:
            continue
        semantic, _ = decode_control_entities(texts[unit['id']]['text'])
        tokens, errors = _lex(semantic)
        _need(not errors, 'EVENT_SCAN_INCOMPLETE')
        mentions = 0
        for index, token in enumerate(tokens):
            name = token[1].upper() if token[0] == 'word' else (
                token[1][1:-1].replace('""', '"').upper() if token[0] == 'quoted' else None)
            if name != item['name'].upper():
                continue
            bound = (index > 0 and tokens[index - 1][1] == ':' or
                     index >= 3 and tokens[index - 1][1] == '.' and
                     tokens[index - 2][0] in ('word', 'quoted') and tokens[index - 3][1] == ':')
            _need(not bound, 'SOURCE_REFERENCE_UNIMPLEMENTED')
            # A SELECT/INSERT column or record member is not a Forms :item bind.
            # Its source routine still remains unexecuted and unconverted.
            mentions += 1
        if mentions:
            identifier_mentions.append({**_unit_proof(unit, texts), 'occurrences': mentions,
                                        'classification': 'non_bind_identifier'})
        for index, token in enumerate(tokens):
            if token[0] != 'word' or token[1].upper() not in {'COPY', 'NAME_IN', 'DEFAULT_VALUE'}:
                continue
            arguments, _, error = _arguments(tokens, index + 1)
            target_index = 0 if token[1].upper() == 'NAME_IN' else 1
            if (token[1].upper() == 'COPY' and not error and len(arguments) == 2 and
                    len(arguments[1]) == 3 and arguments[1][1][1] == '.'):
                omissions.append(_date_omission(unit, semantic, tokens, item, objects, props, units, texts))
                continue
            _need(not error and len(arguments) > target_index and len(arguments[target_index]) == 1 and
                  arguments[target_index][0][0] == 'literal', 'DYNAMIC_REFERENCE_UNPROVEN')
            target = arguments[target_index][0]
            literal = semantic[target[2]:target[3]]
            _need(re.fullmatch(r"'[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*)?'", literal),
                  'DYNAMIC_REFERENCE_UNPROVEN')
            parts = literal[1:-1].upper().split('.')
            _need(parts[-1] != item['name'].upper() or
                  (len(parts) == 2 and parts[0] != block['name'].upper()), 'SOURCE_REFERENCE_UNIMPLEMENTED')
        proofs.append(_unit_proof(unit, texts))
    return proofs, omissions, identifier_mentions


def _properties(p, bp, route):
    _need(p.get('DatabaseItem', '').lower() in ('true', 'yes') and p.get('ItemType', '').upper() == 'TEXT ITEM' and
          p.get('DataType', '').upper() == 'NUMBER', 'EXPLICIT_STORED_NUMBER_REQUIRED')
    _need(bp.get('DatabaseBlock', '').lower() in ('true', 'yes') and
          bp.get('QueryDataSourceType', 'TABLE').upper() == 'TABLE' and
          bp.get('QueryDataSourceName', '').upper() == route['caller_source_table'], 'EXPLICIT_SOURCE_TABLE_REQUIRED')
    _need(bp.get('DMLDataTargetType', 'TABLE').upper() == 'TABLE' and
          bp.get('DMLDataTargetName', route['caller_source_table']).upper() == route['caller_source_table'] and
          not any(bp.get(k, '').strip() for k in ('InsertProcedureName', 'UpdateProcedureName', 'DeleteProcedureName')),
          'SOURCE_DML_TARGET_UNPROVEN')
    column = p.get('ColumnName', '').strip()
    _need(column and groups._identifier(column.upper()) == column.upper(), 'EXPLICIT_SOURCE_COLUMN_REQUIRED')
    _need(not p.get('Formula', '').strip() and p.get('CalculateMode', '').upper() in ('', 'NONE') and
          p.get('CalculationMode', '').upper() in ('', 'NONE') and not p.get('SummaryFunction', '').strip(), 'DERIVED_NUMBER_UNIMPLEMENTED')
    _need(not p.get('LovName', '').strip() and p.get('ValidateFromList', '').lower() in ('', 'false'), 'LIST_NUMBER_UNIMPLEMENTED')
    _need(not p.get('InitialValue', '').strip() and not p.get('CopyValueFromItem', '').strip() and
          not p.get('SynchronizeWithItem', '').strip(), 'SOURCE_DEFAULT_UNIMPLEMENTED')
    _need(not any(p.get(k, '').strip() or bp.get(k, '').strip() for k in
                  ('ImplementationClass', 'PropertyClass', 'SubclassModule', 'SubclassObjectName')),
          'INHERITED_OR_JAVA_POLICY_UNPROVEN')
    _need(all(_flag(p, name) and _flag(bp, name) for name in ('InsertAllowed', 'UpdateAllowed', 'Enabled')),
          'STATIC_EDIT_DISABLED')
    return column.upper(), numeric_rules(p)


def _field(item, block, route, objects, props, units, texts, slot):
    p, bp = props[item['id']], props[block['id']]
    _need(item['module_id'] == route['source_module_id'] and item['block_id'] == route['source_block_id'], 'SAME_ROW_REQUIRED')
    _need(item['database_item'] is True, 'EXPLICIT_STORED_NUMBER_REQUIRED')
    column, rules = _properties(p, bp, route)
    # Reuse the route's complete dynamic property scan for this additional field.
    _policy(block, item, [{'source_item_id': item['id']}], objects, props, units, texts)
    event_proofs, omissions, identifier_mentions = _events(item, block, objects, props, units, texts)
    return {'source_item_id': item['id'], 'source_name': groups._label(item['name']),
            'source_module_id': item['module_id'], 'source_block_id': block['id'],
            'source_column': column, 'label': groups._label(p.get('Prompt') or item['name']),
            'slot': slot, 'column': f'N{slot:03d}', 'data_type': 'NUMBER',
            'source_database_item': True, 'source_insert_allowed': True, 'source_update_allowed': True,
            'direct_edit_allowed': True, 'display_only': False, 'programmatic_return_allowed': False,
            'source_properties': deepcopy(p), 'source_block_properties': deepcopy(bp),
            'source_location': deepcopy(item['location']), 'source_event_scan': event_proofs,
            'omitted_legacy_date_callbacks': omissions,
            'omitted_source_identifier_references': identifier_mentions,
            'source_properties_sha256': groups._sha(groups._json(p)), **rules}


def validate_rate_numbers(receipt, route_contract):
    """Recheck a retained source-bound receipt; None preserves older renderers."""
    if receipt is None:
        return None
    r = deepcopy(receipt)
    _need(type(route_contract) is dict and route_contract.get('contract_id') ==
          'row-lookup-' + groups._sha(groups._json({k: v for k, v in route_contract.items() if k != 'contract_id'}))[:24], 'ROUTE_HASH')
    _need(type(r) is dict and r.get('schema_version') == 1 and r.get('scope') == SCOPE, 'RECEIPT')
    _need(r.get('contract_id') == _digest(r), 'RECEIPT_HASH')
    for key in ('source_binding', 'project_id', 'source_module_id', 'source_block_id'):
        _need(r.get(key) == route_contract.get(key), 'ROUTE_BINDING')
    _need(r.get('route_contract_id') == route_contract['contract_id'], 'ROUTE_CONTRACT')
    _need(type(r.get('fields')) is list and len(r['fields']) <= 8 and type(r.get('gaps')) is list, 'FIELDS')
    _need(r.get('partial_scope_required') is True and all(r.get(key) is False for key in
          ('original_interface_enabled', 'customer_table_writes', 'source_query_executed', 'runtime_verified', 'business_accepted')), 'SOURCE_GATES')
    seen = {f['source_item_id'] for f in route_contract['fields']}
    columns, names = set(), set()
    for slot, f in enumerate(r['fields'], 1):
        _need(type(f) is dict and type(f.get('source_item_id')) is str and
              _SOURCE_ID.fullmatch(f['source_item_id']) and f['source_item_id'] not in seen, 'SOURCE_ITEM')
        seen.add(f['source_item_id'])
        _need(f.get('source_block_id') == r['source_block_id'] and f.get('source_module_id') == r['source_module_id'], 'SAME_ROW_REQUIRED')
        _need(type(f.get('slot')) is int and f['slot'] == slot and f.get('column') == f'N{slot:03d}' and
              f.get('data_type') == 'NUMBER', 'FIELD_STORAGE')
        _need(all(type(f.get(key)) is int for key in ('integer_digits', 'scale', 'max_length')) and
              type(f.get('required')) is bool, 'FIELD_RULE_TYPES')
        for key in ('label', 'source_name'):
            groups._label(f[key])
        _need(f['source_name'].upper() not in names and f['source_column'] not in columns, 'DISTINCT_FIELD_REQUIRED')
        names.add(f['source_name'].upper()); columns.add(f['source_column'])
        groups._identifier(f['source_column'])
        p, bp = f['source_properties'], f['source_block_properties']
        _need(type(p) is dict and type(bp) is dict and f['source_properties_sha256'] == groups._sha(groups._json(p)), 'PROPERTY_PROOF')
        _need(p.get('Name') == f['source_name'] and (p.get('Prompt') or p['Name']) == f['label'] and
              p.get('ColumnName', '').upper() == f['source_column'] and p.get('DatabaseItem', '').lower() in ('true', 'yes') and
              p.get('ItemType', '').upper() == 'TEXT ITEM' and p.get('DataType', '').upper() == 'NUMBER', 'STORED_FIELD_PROOF')
        source_column, rules = _properties(p, bp, route_contract)
        _need(source_column == f['source_column'] and {key: f.get(key) for key in _RULE_KEYS} == rules, 'NUMERIC_RULES')
        _need(all(f.get(key) is True for key in ('source_database_item', 'source_insert_allowed', 'source_update_allowed', 'direct_edit_allowed')) and
              f.get('display_only') is False and f.get('programmatic_return_allowed') is False and
              all(_flag(p, key) and _flag(bp, key) for key in ('InsertAllowed', 'UpdateAllowed', 'Enabled')), 'EDIT_POLICY')
        _need(type(f.get('source_location')) is dict and bool(f['source_location']) and type(f.get('source_event_scan')) is list, 'SOURCE_PROOF')
        for event in f['source_event_scan']:
            _need(type(event) is dict and _SOURCE_ID.fullmatch(event['source_unit_id']) and
                  _SOURCE_ID.fullmatch(event['source_owner_id']) and re.fullmatch('[a-f0-9]{64}', event['source_unit_sha256']) and
                  re.fullmatch('fup1-[a-f0-9]{64}', event['source_chunk_id']) and event['native_event_wired'] is False, 'EVENT_PROOF')
        _need(type(f.get('omitted_legacy_date_callbacks')) is list, 'DATE_OMISSIONS')
        _need(type(f.get('omitted_source_identifier_references')) is list, 'IDENTIFIER_OMISSIONS')
        for mention in f['omitted_source_identifier_references']:
            _need(mention.get('classification') == 'non_bind_identifier' and
                  type(mention.get('occurrences')) is int and mention['occurrences'] > 0 and
                  {k: v for k, v in mention.items() if k not in ('classification', 'occurrences')} in f['source_event_scan'],
                  'IDENTIFIER_OMISSION_PROOF')
        for omission in f['omitted_legacy_date_callbacks']:
            _need(omission.get('kind') == 'suppressed_external_date_callback' and
                  all(omission.get(k) is False for k in ('target_nonoverlap_proven', 'native_event_wired', 'runtime_verified', 'business_accepted')),
                  'DATE_OMISSION_GATES')
            _need(omission['callback'] in f['source_event_scan'] and type(omission.get('callers')) is list and
                  omission['callers'] and type(omission.get('reason')) is str and bool(omission['reason']), 'DATE_OMISSION_PROOF')
            for key in ('package_name', 'getter_name', 'date_member', 'target_member', 'skip_member'):
                groups._identifier(omission[key])
            for caller in omission['callers']:
                _need({k: caller[k] for k in omission['callback']} in f['source_event_scan'] and
                      caller.get('data_type') in ('DATE', 'DATETIME') and caller.get('source_event', '').upper() == 'KEY-LISTVAL' and
                      caller.get('source_item_id') != f['source_item_id'] and _SOURCE_ID.fullmatch(caller['source_item_id']), 'DATE_CALLER_PROOF')
    for gap in r['gaps']:
        _need(type(gap) is dict and gap.get('native_event_wired') is False and
              gap.get('source_block_id') == r['source_block_id'] and
              type(gap.get('reason')) is str and gap['reason'].startswith('RATE_NUMBERS_'), 'GAP')
    return r


def compile_rate_numbers(documents, packet, chunks, trace, files, group_receipt, lov_receipt, route_contract):
    """Compile eligible stored numbers; keep unsupported numeric items visible."""
    with generation_sources(documents):
        objects, props = _normal_receipts(documents, packet, chunks, trace, files, group_receipt, lov_receipt)
        routes = compile_row_lookups(documents, packet, chunks, trace, files, group_receipt, lov_receipt)
        _need(route_contract in routes, 'FRESH_ROUTE_REQUIRED')
        block = objects[route_contract['source_block_id']]
        units = [u for source in packet['sources'] for u in source['facts']['code_units']]
        texts = {c['code_unit_id']: c for c in chunks}
        fields, gaps = [], []
        route_fields = {f['source_item_id'] for f in route_contract['fields']}
        candidates = [o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id'] and
                      o['module_id'] == route_contract['source_module_id'] and props[o['id']].get('DataType', '').upper() == 'NUMBER']
        source_columns = [props[o['id']].get('ColumnName', '').upper() for o in objects.values()
                          if o['kind'] == 'Item' and o['block_id'] == block['id'] and o.get('database_item') is True]
        for item in candidates:
            try:
                _need(item['id'] not in route_fields, 'OVERLAPPING_ROUTE_FIELD')
                _need(len(fields) < 8, 'FIELD_CAPACITY')
                field = _field(item, block, route_contract, objects, props, units, texts, len(fields) + 1)
                _need(source_columns.count(field['source_column']) == 1, 'DISTINCT_SOURCE_COLUMN_REQUIRED')
                fields.append(field)
            except ValueError as error:
                gaps.append({'source_item_id': item['id'], 'source_name': item['name'],
                             'source_block_id': block['id'], 'reason': str(error) if str(error).startswith('RATE_NUMBERS_')
                             else 'RATE_NUMBERS_' + str(error), 'native_event_wired': False})
        r = {'schema_version': 1, 'scope': SCOPE, 'source_binding': route_contract['source_binding'],
             'project_id': route_contract['project_id'], 'source_module_id': route_contract['source_module_id'],
             'source_block_id': block['id'], 'route_contract_id': route_contract['contract_id'],
             'fields': fields, 'gaps': gaps, 'partial_scope_required': True,
             'original_interface_enabled': False, 'customer_table_writes': False,
             'source_query_executed': False, 'runtime_verified': False, 'business_accepted': False,
             'scope_note': 'Source numeric input rules on a synthetic shared draft and saved row. Source events, business DML and original interfaces remain unexecuted; original database precision is unknown.'}
        r['contract_id'] = _digest(r)
        return validate_rate_numbers(r, route_contract)
