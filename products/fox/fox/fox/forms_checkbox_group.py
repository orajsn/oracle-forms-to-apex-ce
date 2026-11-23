"""Whole-event checkbox proofs for explicitly limited synthetic session drafts.

No PL/SQL is executed. A proved changed event is not a record-entry adapter,
original access-right decision, commit implementation or customer-write authority.
Unspecified source NULL/other-value widget mappings stay unspecified: the bounded
adapter accepts only the exact two declared values and rejects all other input.
"""
from __future__ import annotations

from copy import deepcopy
import re

from forms2apex import native_blueprint
from .forms_behavior_plan import _source_objects, decode_control_entities
from .forms_interface_inventory import _lex
from .forms_native_plan import POLICY_ID, build_native_prototype_plan
from .forms_understanding_packet import _build

SCOPE = 'fox-source-checkbox-group-v1'
MAX_GROUPS = 16
MAX_DEPENDENTS = 29
_IDENT = re.compile(r'[A-Z][A-Z0-9_$#]{0,127}\Z')
LIMITATION = ('Exact checkbox-change behavior on a separately initiated synthetic '
              'session draft only. Record-entry initialization, other source rules, '
              'original access rights, saved-row posting and Forms commit behavior '
              'remain separate. NULL and other values are rejected by this adapter; '
              'no missing source widget policy is inferred.')


def _need(value, reason):
    if not value:
        raise ValueError('CHECKBOX_GROUP_' + reason)


def _one(values, reason):
    _need(len(values) == 1, reason)
    return values[0]


class _Event:
    def __init__(self, text, block):
        self.text, self.decode = decode_control_entities(text)
        self.tokens, errors = _lex(self.text, token_budget=4096)
        _need(not errors and len(self.text) <= 32000, 'EVENT_LEXICAL_BOUNDARY')
        self.index, self.block = 0, block

    def peek(self):
        return self.tokens[self.index][1].upper() if self.index < len(self.tokens) else None

    def take(self, value):
        _need(self.peek() == value, 'WHOLE_EVENT_GRAMMAR')
        self.index += 1

    def string(self):
        _need(self.index < len(self.tokens), 'STRING_LITERAL_REQUIRED')
        token = self.tokens[self.index]
        raw = self.text[token[2]:token[3]]
        _need(token[0] == 'literal' and raw.startswith("'") and raw.endswith("'"),
              'STRING_LITERAL_REQUIRED')
        self.index += 1
        return raw[1:-1].replace("''", "'")

    def name(self):
        _need(self.index < len(self.tokens) and self.tokens[self.index][0] == 'word',
              'EXACT_ITEM_NAME_REQUIRED')
        name = self.peek()
        self.index += 1
        _need(_IDENT.fullmatch(name), 'EXACT_ITEM_NAME_REQUIRED')
        return name

    def target(self, literal=False):
        if literal:
            parts = self.string().upper().split('.')
        else:
            self.take(':')
            parts = [self.name()]
            if self.peek() == '.':
                self.take('.')
                parts.append(self.name())
        _need(len(parts) in (1, 2) and all(_IDENT.fullmatch(p) for p in parts), 'EXACT_ITEM_NAME_REQUIRED')
        _need(len(parts) == 1 or parts[0] == self.block, 'SAME_BLOCK_REQUIRED')
        return parts[-1]

    def property(self, expected):
        self.take('SET_ITEM_PROPERTY')
        self.take('(')
        name = self.target(literal=True)
        self.take(',')
        prop = self.name()
        _need(prop in ('ENABLED', 'UPDATE_ALLOWED'), 'PROPERTY_UNSUPPORTED')
        self.take(',')
        self.take(expected)
        self.take(')')
        self.take(';')
        return name, prop


def parse_checkbox_event(text, *, block_name, controller_name):
    """Parse the entire finite changed event; reject any additional statement.

    Case and whitespace are insignificant only for identifiers/keywords. Literal
    contents, assignment order and branch scope are retained without evaluation.
    """
    _need(type(block_name) is str and type(controller_name) is str and
          _IDENT.fullmatch(block_name.upper()) and _IDENT.fullmatch(controller_name.upper()), 'EXACT_OWNER_REQUIRED')
    parser = _Event(text, block_name.upper())
    wrapped = parser.peek() == 'BEGIN'
    if wrapped:
        parser.take('BEGIN')
    parser.take('IF')
    _need(parser.target() == controller_name.upper(), 'OWN_CONTROLLER_REQUIRED')
    parser.take('=')
    checked = parser.string()
    parser.take('THEN')
    enables = []
    while parser.peek() == 'SET_ITEM_PROPERTY':
        enables.append(parser.property('PROPERTY_TRUE'))
    parser.take('ELSE')
    assignments = []
    while parser.peek() == ':':
        name = parser.target()
        parser.take(':=')
        assignments.append((name, parser.string()))
        parser.take(';')
    disables = []
    while parser.peek() == 'SET_ITEM_PROPERTY':
        disables.append(parser.property('PROPERTY_FALSE'))
    parser.take('END')
    parser.take('IF')
    parser.take(';')
    if wrapped:
        parser.take('END')
        parser.take(';')
    _need(parser.index == len(parser.tokens), 'WHOLE_EVENT_GRAMMAR')
    names = [name for name, _ in assignments]
    _need(1 <= len(names) <= MAX_DEPENDENTS and len(names) == len(set(names)) and
          controller_name.upper() not in names, 'DEPENDENT_SET')
    _need(len(enables) == len(set(enables)) and len(disables) == len(set(disables)), 'DUPLICATE_PROPERTY')
    _need(set(disables) == {(name, 'ENABLED') for name in names}, 'EXACT_DISABLE_SET')
    enabled = {(name, 'ENABLED') for name in names}
    updates = {(name, 'UPDATE_ALLOWED') for name in names}
    _need(set(enables) in (enabled, enabled | updates), 'EXACT_ENABLE_SET')
    for name in names:
        if (name, 'UPDATE_ALLOWED') in enables:
            _need(enables.index((name, 'ENABLED')) < enables.index((name, 'UPDATE_ALLOWED')),
                  'ENABLE_BEFORE_UPDATE_REQUIRED')
    return {'controller_name': controller_name.upper(), 'checked_value': checked,
            'assignments': [{'source_name': name, 'unchecked_value': value} for name, value in assignments],
            'enable_properties': [{'source_name': name, 'property': prop} for name, prop in enables],
            'disable_properties': [{'source_name': name, 'property': prop} for name, prop in disables],
            'when_checked': {'enabled': True, 'update_allowed': True if set(enables) == enabled | updates else None},
            'otherwise': {'clear_to_unchecked': True, 'enabled': False, 'update_allowed': None,
                          'includes_null': True, 'includes_other_values': True},
            'source_decode': parser.decode}


def _proof(unit, chunks, objects):
    owner = objects[unit['owner_id']]
    parent = objects.get(owner['parent_id'], {})
    return {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
            'source_owner_id': unit['owner_id'], 'source_chunk_id': chunks[unit['id']]['id'],
            'source_attribute': unit['source_attribute'], 'source_event': owner['name'],
            'source_owner_kind': owner['kind'], 'source_parent_id': owner['parent_id'],
            'source_owner_scope': parent.get('kind') if owner['kind'] == 'Trigger' else owner['kind'],
            'source_module_id': owner['module_id'], 'source_block_id': owner['block_id'],
            'activity': 'retained_source_not_executed', 'native_event_wired': False}


def _boolean(properties, key):
    value = properties.get(key)
    _need(value is None or value.lower() in ('true', 'false'), 'PROPERTY_BOOLEAN_UNRESOLVED')
    return None if value is None else value.lower() == 'true'


def _field(name, block, objects, props, native, spec_block):
    item = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id']
                 and (o['name'] or '').upper() == name], 'UNIQUE_STORED_ITEM_REQUIRED')
    p = props[item['id']]
    _need(item.get('database_item') is True and p.get('ItemType', '').upper() == 'CHECK BOX'
          and p.get('DataType', '').upper() in ('CHAR', 'VARCHAR2'), 'STORED_CHARACTER_CHECKBOX_REQUIRED')
    _need(not any(v.strip() for k, v in p.items() if k.lower().startswith(('subclass', 'inherit')))
          and not any(p.get(k, '').strip() for k in ('Formula', 'SummaryFunction', 'PropertyClass',
              'ImplementationClass', 'CopyValueFromItem', 'SynchronizeWithItem', 'SynchronizedItemName'))
          and all(p.get(k, '').upper() in ('', 'NONE') for k in ('CalculateMode', 'CalculationMode')),
          'DIRECT_CHECKBOX_REQUIRED')
    column = p.get('ColumnName', '').upper()
    _need(_IDENT.fullmatch(column), 'EXPLICIT_SOURCE_COLUMN_REQUIRED')
    _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id']
          and o.get('database_item') is True and props[o['id']].get('ColumnName', '').upper() == column],
         'SOURCE_COLUMN_NOT_UNIQUE')
    length = p.get('MaximumLength', '')
    _need(re.fullmatch(r'[1-9][0-9]{0,3}', length) and int(length) <= 4000 and
          p.get('DataLengthSemantics', '').upper() == 'BYTE', 'EXPLICIT_BYTE_LENGTH_REQUIRED')
    _need('CheckedValue' in p and 'UncheckedValue' in p and p['CheckedValue'] != p['UncheckedValue'], 'EXACT_CHECKBOX_VALUES_REQUIRED')
    other = p.get('CheckBoxOtherValues')
    _need(other in ('Checked', 'Unchecked', 'Not Allowed'), 'EXPLICIT_OTHER_VALUES_POLICY_REQUIRED')
    for value in (p['CheckedValue'], p['UncheckedValue']):
        _need(value and len(value.encode('utf-8')) <= int(length) and
              all(32 <= ord(c) <= 126 for c in value), 'BOUNDED_ASCII_VALUES_REQUIRED')
    _need(all(p.get(k, p['UncheckedValue']) in (p['CheckedValue'], p['UncheckedValue'])
              for k in ('InitializeValue', 'InitialValue')), 'INITIAL_VALUE_UNRESOLVED')
    field = _one([f for f in spec_block['fields'] if f['source_item_id'] == item['id']], 'MAPPED_FIELD_REQUIRED')
    target = _one([f for f in native['items'] if f['source_item_id'] == item['id']], 'MAPPED_FIELD_REQUIRED')
    _need(field['data_type'] == target['data_type'] == 'VARCHAR2' and field['length'] == int(length)
          and field['name'] == target['column'] and target['database_bound'], 'EXACT_NATIVE_FIELD_REQUIRED')
    return {'source_item_id': item['id'], 'source_name': item['name'], 'source_column': column,
            'column': field['name'], 'data_type': 'VARCHAR2', 'maximum_length': int(length),
            'length_semantics': 'BYTE', 'label': p.get('Prompt') or field['label'],
            'checked_value': p['CheckedValue'], 'unchecked_value': p['UncheckedValue'],
            'source_enabled': _boolean(p, 'Enabled'), 'source_update_allowed': _boolean(p, 'UpdateAllowed'),
            'source_required': _boolean(p, 'Required'),
            'source_initial_value': p.get('InitializeValue', p.get('InitialValue')),
            'source_other_values_metadata': {k: v for k, v in p.items() if 'othervalue' in k.lower()},
            'other_values': other,
            'source_other_values_policy': {'source_property': 'CheckBoxOtherValues',
                'source_value': other, 'display_state': {'Checked': 'checked', 'Unchecked': 'unchecked',
                                                       'Not Allowed': 'reject'}[other],
                'raw_if_comparison': 'exact_checked_value_only',
                'adapter_null_other_admission': 'reject'},
            'source_null_other_policy_proven': True}


def _group(unit, event, objects, props, units, chunks, spec, trace):
    controller = objects.get(event['parent_id'], {})
    _need(controller.get('kind') == 'Item', 'ITEM_OWNED_EVENT_REQUIRED')
    block = objects.get(controller['block_id'], {})
    _need(block.get('kind') == 'Block' and block.get('classification') == 'database' and
          _IDENT.fullmatch((block.get('name') or '').upper()), 'DATABASE_BLOCK_REQUIRED')
    _one([u for u in units if u['owner_id'] == event['id']], 'UNIQUE_EVENT_UNIT_REQUIRED')
    _one([o for o in objects.values() if o['kind'] == 'Trigger' and o['parent_id'] == controller['id']
          and (o['name'] or '').upper() == 'WHEN-CHECKBOX-CHANGED'], 'UNIQUE_CHANGED_EVENT_REQUIRED')
    _need(unit['source_attribute'] == 'TriggerText', 'TRIGGER_TEXT_REQUIRED')
    parsed = parse_checkbox_event(chunks[unit['id']]['text'], block_name=block['name'], controller_name=controller['name'])
    native = _one([b for b in trace['blocks'] if b['source_block_id'] == block['id'] and
                   b['classification'] == 'database'], 'NATIVE_DATABASE_BLOCK_REQUIRED')
    spec_block = _one([b for b in spec['blocks'] if b['source_block_id'] == block['id']], 'NATIVE_DATABASE_BLOCK_REQUIRED')
    control = _field(controller['name'].upper(), block, objects, props, native, spec_block)
    _need(parsed['checked_value'] == control['checked_value'], 'EXACT_CONTROLLER_CHECKED_VALUE')
    dependents = []
    for assignment in parsed['assignments']:
        field = _field(assignment['source_name'], block, objects, props, native, spec_block)
        _need(assignment['unchecked_value'] == field['unchecked_value'], 'EXACT_DEPENDENT_UNCHECKED_VALUE')
        dependents.append(field)
    remaining = [_proof(u, chunks, objects) for u in units if u['id'] != unit['id']
                 and objects[u['owner_id']]['module_id'] == event['module_id']]
    entry = [p for p in remaining if (p['source_event'] or '').upper() in
             ('WHEN-NEW-RECORD-INSTANCE', 'WHEN-NEW-ITEM-INSTANCE')]
    group_item_ids = {control['source_item_id'], *(f['source_item_id'] for f in dependents)}
    for rule in entry:
        rule['same_group_entry_scope'] = rule['source_parent_id'] in (
            event['module_id'], block['id'], *group_item_ids)
        rule['whole_entry_rule_translated'] = False
    # All other units are retained, even those with indirect references that this
    # finite event parser cannot resolve. This is deliberately not an access proof.
    return {**_proof(unit, chunks, objects), 'project_id': trace['project_id'],
            'source_binding': trace['source_binding'], 'source_module_id': event['module_id'],
            'source_block_id': block['id'], 'source_block_name': block['name'],
            'table_name': native['table_name'], 'report_page_id': native['report_page_id'],
            'report_file': native['report_file'], 'synthetic_table_proven': True,
            'controller': control, 'dependents': dependents,
            'when_checked': parsed['when_checked'], 'otherwise': parsed['otherwise'],
            'source_event_proof': parsed, 'record_entry_rules': entry,
            'other_source_rules': remaining, 'record_entry_initialization_implemented': False,
            'original_access_rights_proven': False, 'original_save_authorized': False,
            'source_widget_equivalence_proven': False,
            'input_policy': {'allowed_values': 'exact_checked_or_unchecked_only',
                             'null_values': 'reject', 'other_values': 'reject',
                             'source_other_values_policy_proven': True,
                             'other_value_display_implemented': False},
            'limitation': LIMITATION}


def build_checkbox_groups(documents, packet, chunks, trace):
    """Rebuild source identity and the synthetic table/column trace before proof."""
    from .xml_mapping import _blueprint
    fresh, fresh_chunks = _build(documents)
    supplied = deepcopy(packet)
    if supplied.get('selection_status') == 'NOT_SELECTED':
        supplied.pop('selection_status')
    _need(supplied == fresh and chunks == fresh_chunks and
          trace.get('source_binding') == fresh['source_binding'], 'SOURCE_CHANGED')
    objects, props = _source_objects(documents, fresh)
    units = [u for entry in fresh['sources'] for u in entry['facts']['code_units']]
    texts = {c['code_unit_id']: c for c in fresh_chunks}
    events = [(u, objects[u['owner_id']]) for u in units if
              objects[u['owner_id']]['kind'] == 'Trigger' and
              (objects[u['owner_id']]['name'] or '').upper() == 'WHEN-CHECKBOX-CHANGED']
    result = {'schema_version': 1, 'scope': SCOPE, 'source_binding': fresh['source_binding'],
              'project_id': trace['project_id'], 'groups': [], 'gaps': [],
              'converted_code_unit_count': 0, 'customer_table_writes': False,
              'original_access_rights_proven': False, 'runtime_verified': False,
              'business_accepted': False, 'scope_note': LIMITATION}
    if not events:
        return result
    spec = build_native_prototype_plan(documents, _blueprint(fresh), project_id=trace['project_id'],
        project_name='Checkbox group proof', approved_policy_id=POLICY_ID)['rendering_spec']
    expected = native_blueprint.prototype_trace(spec)
    for block in expected['blocks']:
        block['source_module_id'] = objects[block['source_block_id']]['module_id']
    _need(trace['blocks'] == expected['blocks'], 'FRESH_SYNTHETIC_TRACE_REQUIRED')
    for unit, event in events:
        try:
            _need(len(result['groups']) < MAX_GROUPS, 'CAPACITY')
            result['groups'].append(_group(unit, event, objects, props, units, texts, spec, trace))
        except ValueError as error:
            result['gaps'].append({**_proof(unit, texts, objects), 'reason': str(error)})
    return result
