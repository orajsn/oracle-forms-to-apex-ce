"""Bounded source-proved display expressions on saved synthetic report rows.

This is a read projection, never execution of the original assignment events.
Matching writers in larger units remain supporting evidence, not converted units.
"""
from __future__ import annotations

from copy import deepcopy
import re

from forms2apex import native_blueprint
from .forms_behavior_plan import _source_objects, decode_control_entities
from forms2apex.display_expression import parse_display_expression, bind_display_expression
from .forms_interface_inventory import _arguments, _lex
from .forms_native_plan import POLICY_ID, build_native_prototype_plan
from .forms_understanding_packet import _build

SCOPE = 'fox-source-display-projection-v1'
MAX_PROJECTIONS = 16
_IDENT = re.compile(r'[A-Z][A-Z0-9_$#]{0,127}\Z')
LIMITATION = ('Read-only calculation from the current saved synthetic row. Original '
              'event timing, unsaved buffers, lookup, master-detail, calendar and commit '
              'behavior remain unexecuted; no customer-table write is generated.')


def _need(value, reason):
    if not value:
        raise ValueError('DISPLAY_PROJECTION_' + reason)


def _one(values, reason):
    _need(len(values) == 1, reason)
    return values[0]


def _proof(unit, texts):
    return {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
            'source_chunk_id': texts[unit['id']]['id'], 'source_owner_id': unit['owner_id'],
            'source_attribute': unit['source_attribute'], 'native_event_wired': False}


def _length(properties):
    raw = properties.get('MaximumLength', '')
    _need(re.fullmatch('[1-9][0-9]{0,3}', raw) and int(raw) <= 4000, 'EXPLICIT_LENGTH_REQUIRED')
    return int(raw)


def _visible(item, objects, props):
    p = props[item['id']]
    _need(p.get('Visible', '').lower() in ('', 'true') and
          p.get('Displayed', '').lower() in ('', 'true'), 'DISPLAY_HIDDEN')
    canvas = _one([o for o in objects.values() if o['kind'] == 'Canvas' and
                   o['module_id'] == item['module_id'] and o['name'] == p.get('CanvasName')],
                  'VISIBLE_CANVAS_REQUIRED')
    _need(props[canvas['id']].get('Visible', '').lower() in ('', 'true'), 'CANVAS_HIDDEN')
    tab = p.get('TabPageName', '')
    if tab:
        page = _one([o for o in objects.values() if o['kind'] == 'TabPage' and
                     o['parent_id'] == canvas['id'] and o['name'] == tab], 'TAB_OWNERSHIP_REQUIRED')
        _need(props[page['id']].get('Visible', '').lower() in ('', 'true'), 'TAB_HIDDEN')
    return {'source_canvas_id': canvas['id'], 'source_tab_page_id': page['id'] if tab else None}


def _reference(tokens, i):
    if tokens[i][1] != ':' or i + 1 >= len(tokens):
        return None, i + 1
    j, parts = i + 1, []
    while j < len(tokens):
        token = tokens[j]
        if token[0] not in ('word', 'quoted'):
            return None, j
        parts.append(token[1].strip('"').upper())
        j += 1
        if j >= len(tokens) or tokens[j][1] != '.':
            break
        j += 1
    return parts, j


def _unqualified_scope(name, owner, block, objects):
    if owner['block_id'] == block['id']:
        return True
    if owner['block_id'] is not None:
        return False
    matches = [o for o in objects.values() if o['kind'] == 'Item' and
               o['module_id'] == owner['module_id'] and (o['name'] or '').upper() == name]
    return len(matches) == 1 and matches[0]['block_id'] == block['id']


def _source_scan(objects, units, texts):
    scanned = []
    for unit in units:
        try:
            text, _ = decode_control_entities(texts[unit['id']]['text'])
            tokens, errors = _lex(text)
        except ValueError:
            text = texts[unit['id']]['text']
            tokens, errors = _lex(text)
            errors.append('control_decode_unsupported')
        scanned.append((unit, objects[unit['owner_id']], text, tokens, errors))
    return scanned


def _candidates(objects, props, scanned):
    """Witness real direct concatenation assignments once, never comment text."""
    result = set()
    displays = {}
    for item in objects.values():
        if (item['kind'] == 'Item' and item['name'] and
                props[item['id']].get('ItemType', '').upper() == 'DISPLAY ITEM' and
                props[item['id']].get('DatabaseItem', '').lower() in ('false', 'no')):
            displays.setdefault((item['module_id'], item['name'].upper()), []).append(item)
    for _, owner, _, tokens, _ in scanned:
        for i, token in enumerate(tokens):
            if token[1] != ':':
                continue
            parts, end = _reference(tokens, i)
            if not parts or len(parts) not in (1, 2) or end >= len(tokens) or tokens[end][1] != ':=':
                continue
            finish = next((j for j in range(end + 1, len(tokens)) if tokens[j][1] == ';'), len(tokens))
            if not any(t[1] == '||' for t in tokens[end + 1:finish]):
                continue
            for item in displays.get((owner['module_id'], parts[-1]), ()):
                block = objects.get(item['block_id'])
                if block is None:
                    continue
                if ((len(parts) == 2 and (block['name'] or '').upper() == parts[0]) or
                        (len(parts) == 1 and owner['block_id'] in (None, block['id']))):
                    result.add(item['id'])
    return result


def _writers(item, block, objects, props, units, texts, scanned=None):
    """Scan every same-module source unit, including indirect write boundaries."""
    whole, supporting, omissions, parsed = [], [], [], None
    for unit, owner, text, tokens, errors in (scanned if scanned is not None else _source_scan(objects, units, texts)):
        if owner['module_id'] != item['module_id']:
            continue
        _need(not errors, 'EVENT_SCAN_INCOMPLETE')
        active = [t[1].upper() for t in tokens]
        _need('DBMS_SQL' not in active and not any(a == 'EXECUTE' and b == 'IMMEDIATE'
              for a, b in zip(active, active[1:])), 'DYNAMIC_SQL_UNPROVEN')
        # A complete known calendar callback may stay suppressed. This proves
        # only its declared DATE callers, not immutable external package state.
        for i, token in enumerate(tokens):
            if token[0] != 'word' or token[1].upper() not in ('COPY', 'DEFAULT_VALUE', 'NAME_IN'):
                continue
            args, _, error = _arguments(tokens, i + 1)
            target_index = 0 if token[1].upper() == 'NAME_IN' else 1
            if (token[1].upper() == 'COPY' and not error and len(args) == 2 and
                    len(args[1]) == 3 and args[1][1][1] == '.'):
                from .forms_rate_numbers import _date_omission
                omissions.append(_date_omission(unit, text, tokens, item, objects, props, units, texts))
                continue
            _need(not error and len(args) > target_index and len(args[target_index]) == 1 and
                  args[target_index][0][0] == 'literal', 'DYNAMIC_REFERENCE_UNPROVEN')
            arg = args[target_index][0]
            value = text[arg[2]:arg[3]]
            _need(re.fullmatch(r"'[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*)?'", value),
                  'DYNAMIC_REFERENCE_UNPROVEN')
            parts = value[1:-1].upper().split('.')
            _need(parts[-1] != item['name'].upper() or
                  (len(parts) == 2 and parts[0] != block['name'].upper()), 'INDIRECT_TARGET_REFERENCE')
        for i, token in enumerate(tokens):
            if token[0] == 'literal':
                value = text[token[2]:token[3]][1:-1].replace("''", "'").upper()
                _need(value not in (item['name'].upper(), block['name'].upper() + '.' + item['name'].upper()),
                      'LITERAL_TARGET_REFERENCE')
            if token[1] != ':':
                continue
            parts, end = _reference(tokens, i)
            if not parts or parts[-1] != item['name'].upper():
                continue
            if len(parts) == 2 and parts[0] != block['name'].upper():
                continue
            if len(parts) == 1 and owner['block_id'] not in (None, block['id']):
                continue
            _need(len(parts) in (1, 2) and (len(parts) == 2 or
                  _unqualified_scope(parts[0], owner, block, objects)),
                  'TARGET_SCOPE_UNRESOLVED')
            _need(all(t[0] != 'quoted' for t in tokens[i:end]), 'QUOTED_TARGET_UNSUPPORTED')
            _need(end < len(tokens) and tokens[end][1] == ':=', 'NON_ASSIGNMENT_TARGET_REFERENCE')
            finish = next((j for j in range(end + 1, len(tokens)) if tokens[j][1] == ';'), None)
            _need(finish is not None and finish > end + 1, 'INCOMPLETE_ASSIGNMENT')
            for j in range(end + 1, finish):
                if tokens[j][1] == ':':
                    rhs_parts, _ = _reference(tokens, j)
                    _need(rhs_parts and (len(rhs_parts) == 2 or
                          _unqualified_scope(rhs_parts[0], owner, block, objects)),
                          'INPUT_OWNER_SCOPE_UNRESOLVED')
            rhs = text[tokens[end + 1][2]:tokens[finish - 1][3]]
            expression = parse_display_expression(rhs, block=block['name'].upper())
            _need(parsed is None or expression == parsed, 'CONFLICTING_WRITERS')
            parsed = expression
            leading = [t[1].upper() for t in tokens[:i]]
            trailing = [t[1].upper() for t in tokens[finish + 1:]]
            complete = ((not leading and not trailing) or
                        (leading == ['BEGIN'] and trailing == ['END', ';']))
            proof = {**_proof(unit, texts), 'source_event': owner['name']}
            if (complete and owner['kind'] == 'Trigger' and unit['source_attribute'] == 'TriggerText' and
                    owner['block_id'] == block['id'] and
                    objects.get(owner['parent_id'], {}).get('kind') == 'Item' and
                    owner['name'].upper() == 'POST-CHANGE'):
                whole.append(proof)
            else:
                supporting.append(proof)
    _need(whole and parsed is not None, 'WHOLE_ITEM_ASSIGNMENT_REQUIRED')
    return parsed, whole, supporting, omissions


def _build_projection(item, objects, props, units, texts, spec, trace, scanned=None):
    _need(item.get('block_id') in objects, 'SOURCE_BLOCK_REQUIRED')
    block = objects[item['block_id']]
    p = props[item['id']]
    _need(type(item.get('name')) is str and type(block.get('name')) is str, 'EXACT_NAME_REQUIRED')
    _need(_IDENT.fullmatch(item['name'].upper()) and _IDENT.fullmatch(block['name'].upper()), 'EXACT_NAME_REQUIRED')
    _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id'] and
          (o['name'] or '').upper() == item['name'].upper()], 'TARGET_NAME_NOT_UNIQUE')
    _need(p.get('DatabaseItem', '').lower() in ('false', 'no') and
          p.get('DataType', '').upper() in ('CHAR', 'VARCHAR2'), 'NON_DATABASE_CHARACTER_DISPLAY_REQUIRED')
    for field in ('Formula', 'InitialValue', 'InitializeValue', 'CopyValueFromItem', 'SynchronizeWithItem',
                  'SummaryFunction', 'ImplementationClass', 'PropertyClass', 'SubclassModule', 'SubclassObjectName'):
        _need(not p.get(field, '').strip(), 'OTHER_VALUE_SOURCE_UNSUPPORTED')
    _need(p.get('CalculationMode', '').upper() in ('', 'NONE') and
          p.get('CalculateMode', '').upper() in ('', 'NONE'), 'CALCULATION_UNSUPPORTED')
    visible = _visible(item, objects, props)
    native_block = _one([b for b in trace['blocks'] if b['source_block_id'] == block['id'] and
                         b['classification'] == 'database'], 'NATIVE_REPORT_REQUIRED')
    target = _one([f for f in native_block['items'] if f['source_item_id'] == item['id'] and
                   f['column'] and f['widget'] == 'display'], 'NATIVE_TARGET_REQUIRED')
    source_block = _one([b for b in spec['blocks'] if b['source_block_id'] == block['id']], 'NATIVE_BLOCK_REQUIRED')
    parsed, whole, supporting, omissions = _writers(item, block, objects, props, units, texts, scanned)
    ordered_refs = list(dict.fromkeys(o['ref'] for o in parsed['ast']['operands'] if 'ref' in o))
    bindings, descriptions = {}, []
    for ref in ordered_refs:
        name = ref.split('.')[1]
        source = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id'] and
                       (o['name'] or '').upper() == name], 'REFERENCE_NAME_NOT_UNIQUE')
        properties = props[source['id']]
        _need(source.get('database_item') is True and source['id'] != item['id'], 'DIRECT_DATABASE_INPUT_REQUIRED')
        _need(not any(properties.get(k, '').strip() for k in ('Formula', 'SummaryFunction', 'PropertyClass',
                  'ImplementationClass', 'SubclassModule', 'SubclassObjectName')), 'DERIVED_INPUT_UNSUPPORTED')
        column = properties.get('ColumnName', '').upper()
        _need(_IDENT.fullmatch(column), 'EXPLICIT_SOURCE_COLUMN_REQUIRED')
        _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id'] and
              o.get('database_item') is True and props[o['id']].get('ColumnName', '').upper() == column],
             'SOURCE_COLUMN_NOT_UNIQUE')
        field = _one([f for f in source_block['fields'] if f['source_item_id'] == source['id']], 'NATIVE_INPUT_REQUIRED')
        _need(field['data_type'] in ('VARCHAR2', 'DATE'), 'EXACT_INPUT_TYPE_REQUIRED')
        source_type = properties.get('DataType', '').upper()
        _need((field['data_type'] == 'DATE' and source_type in ('DATE', 'DATETIME')) or
              (field['data_type'] == 'VARCHAR2' and source_type in ('CHAR', 'VARCHAR2')), 'EXACT_INPUT_TYPE_REQUIRED')
        length = _length(properties) if field['data_type'] == 'VARCHAR2' else None
        semantics = properties.get('DataLengthSemantics', '').upper() if length is not None else None
        _need(semantics in (None, '', 'BYTE', 'CHAR'), 'LENGTH_SEMANTICS_UNRESOLVED')
        # No target charset evidence is supplied to this pure source compiler.
        # Bounds come only from explicit source BYTE limits, enforced by the
        # renderer's saved-value guard, never guessed target NLS semantics.
        _need(length is None or semantics == 'BYTE', 'BYTE_BOUND_UNPROVEN')
        maximum_bytes = length
        binding = {'column': field['name'], 'data_type': field['data_type'],
                   'maximum_length': length, 'maximum_bytes': maximum_bytes, 'nullable': field['nullable']}
        if length is not None:
            _need(length <= field['length'], 'SOURCE_LENGTH_EXCEEDS_NATIVE')
        bindings[ref] = binding
        descriptions.append({'reference': ref, 'source_item_id': source['id'], 'source_column': column,
                             'source_maximum_length': length, 'source_length_semantics': semantics,
                             'runtime_input_guard_required': length is not None, **binding})
    expression = bind_display_expression(parsed, bindings)
    maximum = _length(p)
    _need(p.get('DataLengthSemantics', '').upper() in ('', 'BYTE', 'CHAR'), 'TARGET_LENGTH_SEMANTICS_UNRESOLVED')
    _need(expression['maximum_bytes'] <= maximum, 'TARGET_LENGTH_EXCEEDED')
    return {'source_module_id': item['module_id'], 'source_block_id': block['id'],
            'source_item_id': item['id'], 'source_name': item['name'],
            'qualified_target': block['name'].upper() + '.' + item['name'].upper(),
            'target_column': target['column'], 'target_maximum_length': maximum,
            'report_page_id': native_block['report_page_id'], 'report_file': native_block['report_file'],
            'references': ordered_refs, 'bindings': descriptions, 'expression': expression, **visible,
            'whole_source_units': whole, 'supporting_source_units': supporting, 'non_direct_omissions': omissions,
            'native_event_wired': False, 'source_event_timing_preserved': False,
            'synthetic_read_projection': True, 'runtime_input_guards_required': True,
            'target_length_semantics': p.get('DataLengthSemantics', '').upper(), 'limitation': LIMITATION}


def build_display_projections(documents, packet, chunks, trace):
    """Rebuild all identities from original bytes; unsupported fields stay gaps."""
    from .xml_mapping import _blueprint
    # The normal generator owns the per-build source cache and freshness boundary.
    fresh, fresh_chunks = _build(documents)
    supplied = deepcopy(packet)
    if supplied.get('selection_status') == 'NOT_SELECTED':
        supplied.pop('selection_status')
    _need(supplied == fresh and chunks == fresh_chunks and
          trace.get('source_binding') == fresh['source_binding'], 'SOURCE_CHANGED')
    objects, props = _source_objects(documents, fresh)
    units = [u for entry in fresh['sources'] for u in entry['facts']['code_units']]
    texts = {c['code_unit_id']: c for c in fresh_chunks}
    scanned = _source_scan(objects, units, texts)
    candidates = _candidates(objects, props, scanned)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': fresh['source_binding'],
               'project_id': trace['project_id'], 'projections': [], 'gaps': [],
               'native_event_wired': False, 'customer_table_writes': False, 'source_query_executed': False,
               'runtime_verified': False, 'business_accepted': False, 'scope_note': LIMITATION}
    if not candidates:
        return receipt
    spec = build_native_prototype_plan(documents, _blueprint(fresh), project_id=trace['project_id'],
        project_name='Display projection proof', approved_policy_id=POLICY_ID)['rendering_spec']
    expected = native_blueprint.prototype_trace(spec)
    for block in expected['blocks']:
        block['source_module_id'] = objects[block['source_block_id']]['module_id']
    _need(trace['blocks'] == expected['blocks'], 'FRESH_SYNTHETIC_TRACE_REQUIRED')
    projections, gaps = [], []
    for item in objects.values():
        if item['id'] not in candidates:
            continue
        try:
            _need(len(projections) < MAX_PROJECTIONS, 'CAPACITY')
            projections.append(_build_projection(item, objects, props, units, texts, spec, trace, scanned))
        except ValueError as error:
            gaps.append({'source_item_id': item['id'], 'source_name': item['name'],
                         'source_block_id': item['block_id'], 'reason': str(error), 'native_event_wired': False})
    receipt.update(projections=projections, gaps=gaps)
    return receipt
