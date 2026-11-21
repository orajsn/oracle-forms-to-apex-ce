"""Closed XML item-entry programs with explicit current-buffer boundaries.

The reusable executor consumes trusted server adapters, never browser supplied
field values or a synthetic single-row substitute for COMMIT_FORM. Saved summary
projections are a separate, read-only adaptation of the XML summary declaration.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import inspect
import json
import re

from forms2apex.record_buffer import decode_source
from forms2apex import numeric_expression, native_buffer
from .forms_behavior_plan import _source_objects
from .forms_item_validation import _resolve
from .forms_relation_plan import parse_join_condition, _flags
from .forms_record_entry import _block
from .forms_understanding_packet import _build

SCOPE = 'fox-source-item-entry-workflow-v1'
RULE_ID = 'fox.workflow.xml-item-entry'
_IDENT = r'[A-Z][A-Z0-9_$#]{0,127}'
_COMPILED_KEYS = ('operation_id', 'rule_id', 'source_unit_id', 'source_unit_sha256', 'source_chunk_id',
                  'source_owner_id', 'source_module_id', 'source_event', 'owner_item_id', 'parsed', 'fields',
                  'summaries', 'navigation', 'stages', 'caller_evidence', 'required_boundaries')


def _need(value, reason):
    if not value:
        raise ValueError('ITEM_ENTRY_' + reason)


def _one(values, reason):
    _need(len(values) == 1, reason)
    return values[0]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(_json(value)).hexdigest()


class _Parser:
    """Finite expressions, ordered IF/assignment/navigation/message statements."""
    def __init__(self, raw):
        self.text, self.receipt = decode_source(raw)
        self.tokens, self.i = [], 0
        pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|:=|<>|" +
                             _IDENT + r'|[0-9]+|[:.,();=]', re.I | re.S)
        pos = 0
        while pos < len(self.text):
            match = pattern.match(self.text, pos)
            _need(match is not None, 'ACTIVE_TOKEN_AT_' + str(pos))
            token, pos = match[0], match.end()
            if token.isspace() or token.startswith(('--', '/*')):
                continue
            self.tokens.append(('string', token[1:-1].replace("''", "'"), match.start(), pos)
                               if token.startswith("'") else ('token', token.upper(), match.start(), pos))
            _need(len(self.tokens) <= 1200, 'TOKEN_CAPACITY')

    def peek(self, word):
        return self.i < len(self.tokens) and self.tokens[self.i][:2] == ('token', word)

    def take(self, word=None, kind='token'):
        _need(self.i < len(self.tokens) and self.tokens[self.i][0] == kind and
              (word is None or self.tokens[self.i][1] == word), 'COMPLETE_BODY_REQUIRED')
        result = self.tokens[self.i][1]
        self.i += 1
        return result

    def ident(self):
        value = self.take()
        _need(re.fullmatch(_IDENT, value), 'IDENTIFIER')
        return value

    def ref(self):
        self.take(':')
        parts = [self.ident()]
        if self.peek('.'):
            self.take('.')
            parts.append(self.ident())
        return {'kind': 'reference', 'parts': parts}

    def atom(self):
        if self.peek(':'):
            return self.ref()
        if self.peek('NVL'):
            self.take('NVL'); self.take('(')
            value = self.atom(); self.take(','); fallback = self.atom(); self.take(')')
            return {'kind': 'nvl', 'value': value, 'fallback': fallback}
        if self.peek('NULL'):
            self.take('NULL')
            return {'kind': 'literal', 'value': None}
        return {'kind': 'literal', 'value': self.take(kind='string')}

    def comparison(self):
        left = self.atom()
        if self.peek('IS'):
            self.take('IS'); negate = self.peek('NOT')
            if negate:
                self.take('NOT')
            self.take('NULL')
            return {'kind': 'is_not_null' if negate else 'is_null', 'value': left}
        op = self.take()
        _need(op in ('=', '<>'), 'COMPARISON')
        return {'kind': 'eq' if op == '=' else 'ne', 'left': left, 'right': self.atom()}

    def condition(self):
        value = self.comparison()
        while self.peek('AND'):
            self.take('AND')
            value = {'kind': 'and', 'left': value, 'right': self.comparison()}
        return value

    def body(self, depth=0):
        _need(depth <= 8, 'NESTING_CAPACITY')
        result = []
        while self.i < len(self.tokens) and not any(self.peek(x) for x in ('END', 'ELSIF', 'ELSE')):
            start = self.tokens[self.i][2]
            if self.peek('IF'):
                self.take('IF'); branches = []
                condition = self.condition(); self.take('THEN')
                branches.append({'condition': condition, 'body': self.body(depth+1)})
                while self.peek('ELSIF'):
                    self.take('ELSIF'); condition = self.condition(); self.take('THEN')
                    branches.append({'condition': condition, 'body': self.body(depth+1)})
                otherwise = []
                if self.peek('ELSE'):
                    self.take('ELSE'); otherwise = self.body(depth+1)
                self.take('END'); self.take('IF'); self.take(';')
                node = {'kind': 'if', 'branches': branches, 'else': otherwise}
            elif self.peek(':'):
                target = self.ref(); self.take(':='); value = self.atom(); self.take(';')
                node = {'kind': 'assign', 'target': target, 'value': value}
            else:
                name = self.ident()
                _need(name in ('GO_ITEM', 'GO_BLOCK', 'NEXT_ITEM', 'NEXT_RECORD', 'COMMIT_FORM', 'MESSAGE'),
                      'UNSUPPORTED_STATEMENT_' + name)
                node = {'kind': name.lower()}
                if name in ('GO_ITEM', 'GO_BLOCK', 'MESSAGE'):
                    self.take('('); node['value'] = self.take(kind='string'); self.take(')')
                    _need(len(node['value'].encode()) <= 2000 and all(c.isprintable() for c in node['value']), 'LITERAL')
                self.take(';')
            node['position'] = {'character_offset': start, 'end_character_offset': self.tokens[self.i-1][3],
                                'offset_unit': 'decoded_unicode_character'}
            result.append(node)
        return result


def parse_item_entry_source(raw, event):
    p = _Parser(raw)
    name = None
    if event == 'ProgramUnit':
        p.take('PROCEDURE'); name = p.ident(); p.take('IS'); p.take('BEGIN')
    else:
        _need(event == 'WHEN-NEW-ITEM-INSTANCE', 'EVENT')
    body = p.body()
    if event == 'ProgramUnit':
        p.take('END')
        if not p.peek(';'):
            _need(p.ident() == name, 'END_NAME')
        p.take(';')
    _need(p.i == len(p.tokens) and body, 'COMPLETE_BODY_REQUIRED')
    _need(any(n['kind'] in ('go_item', 'go_block', 'next_item', 'next_record') for n in _walk(body)), 'NAVIGATION_REQUIRED')
    return {'routine_name': name, 'body': body, 'decode_receipt': p.receipt}


def _walk(value):
    if isinstance(value, dict):
        if 'kind' in value:
            yield value
        for v in value.values():
            yield from _walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v)


def _summary(item, objects, props, trace, files):
    p = props[item['id']]
    _need(p.get('DatabaseItem', '').lower() == 'false' and p.get('DataType', '').upper() == 'NUMBER'
          and p.get('CalculateMode', '').upper() == 'SUMMARY' and p.get('SummaryFunction', '').upper() == 'SUM', 'SUMMARY_DECLARATION')
    detail = _one([o for o in objects.values() if o['kind'] == 'Block' and o['module_id'] == item['module_id']
                   and (o['name'] or '').upper() == p.get('SummaryBlockName', '').upper()], 'SUMMARY_BLOCK')
    measure = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == detail['id']
                    and (o['name'] or '').upper() == p.get('SummaryItemName', '').upper()], 'SUMMARY_ITEM')
    mp = props[measure['id']]
    _need(mp.get('DataType', '').upper() == 'NUMBER', 'SUMMARY_MEASURE_NUMBER')
    expression, input_fields = None, []
    if mp.get('CalculateMode', '').upper() == 'FORMULA':
        expression = numeric_expression.parse_expression(mp.get('Formula', ''))
        for parts in numeric_expression.validate_expression(expression):
            input_item = _resolve(parts, measure, objects)
            ip = props[input_item['id']]
            _need(input_item['block_id'] == detail['id'] and ip.get('DatabaseItem', '').lower() == 'true'
                  and ip.get('DataType', '').upper() == 'NUMBER' and not ip.get('Formula', '').strip()
                  and ip.get('CalculateMode', '').upper() in ('', 'NONE'), 'SUMMARY_FORMULA_DIRECT_INPUT')
            mapped = _block(detail['id'], objects, trace, files)
            f = deepcopy(_one([f for f in mapped['items'] if f['source_item_id'] == input_item['id']], 'SUMMARY_FORMULA_FIELD'))
            _need(f['data_type'] == 'NUMBER', 'SUMMARY_FORMULA_NUMBER')
            f.update(source_reference=parts, source_attribute_sha256=_sha(ip))
            input_fields.append(f)
    else:
        _need(mp.get('DatabaseItem', '').lower() == 'true' and not mp.get('Formula', '').strip()
              and mp.get('CalculateMode', '').upper() in ('', 'NONE'), 'DIRECT_SUMMARY_MEASURE')
    rel = _one([o for o in objects.values() if o['kind'] == 'Relation' and o['module_id'] == item['module_id']
                and props[o['id']].get('DetailBlock', '').upper() == detail['name'].upper()], 'SUMMARY_MASTER_RELATION')
    master = objects[rel['block_id']]
    rp = props[rel['id']]
    _need(rp.get('RelationType', '').upper() == 'JOIN', 'SUMMARY_JOIN')
    _flags(rp)
    pairs = parse_join_condition(rp.get('JoinCondition'), master['name'], detail['name'])
    mb, db = (_block(b['id'], objects, trace, files) for b in (master, detail))
    joins = []
    for pn, cn in pairs:
        bound = []
        for b, name in ((mb, pn), (db, cn)):
            f = _one([f for f in b['items'] if f['source_name'].upper() == name], 'SUMMARY_JOIN_FIELD')
            _need(props[f['source_item_id']].get('DatabaseItem', '').lower() == 'true', 'SUMMARY_STORED_JOIN')
            bound.append(f)
        _need(bound[0]['data_type'] == bound[1]['data_type'], 'SUMMARY_JOIN_TYPE')
        joins.append({'parent_column': bound[0]['column'], 'child_column': bound[1]['column'],
                      'parent_item_id': bound[0]['source_item_id'], 'child_item_id': bound[1]['source_item_id']})
    field = _one([f for f in db['items'] if f['source_item_id'] == measure['id']], 'SUMMARY_TARGET_MEASURE')
    _need(field['data_type'] == 'NUMBER', 'SUMMARY_NUMBER')
    return {'source_item_id': item['id'], 'source_measure_item_id': measure['id'],
            'source_attribute_sha256': _sha(p), 'source_relation_id': rel['id'],
            'source_relation_attribute_sha256': _sha(rp), 'master_block_id': master['id'],
            'detail_block_id': detail['id'], 'detail_table': db['table_name'], 'master_table': mb['table_name'],
            'measure_column': field['column'], 'join_pairs': joins, 'function': 'SUM',
            'measure_attribute_sha256': _sha(mp), 'measure_expression': expression, 'measure_input_fields': input_fields,
            'null_policy': 'ignore_null_measures_null_for_empty_or_all_null',
            'saved_scope': 'all_saved_details_of_the_exact_current_master_composite_relation',
            'draft_scope': 'trusted_effective_forms_detail_buffer_including_unposted_changes_and_deletion_marks',
            'saved_values_are_draft_values': False}


def _callers(name, module_id, owner_id, units, chunks, objects):
    """Lexical whole-source call evidence; declaration and comments are excluded."""
    sites, unresolved = [], []
    texts = {c['code_unit_id']: c for c in chunks}
    for unit in units:
        owner = objects[unit['owner_id']]
        if owner['module_id'] != module_id:
            continue
        raw = texts[unit['id']]['text']
        text, _ = decode_source(raw)
        # Match identifiers independently of unrelated PL/SQL syntax. Strings,
        # comments and their encoded line endings cannot become fake callers.
        scanner = re.compile(r"--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|" + _IDENT + r'|[^\s]', re.I | re.S)
        tokens = [(m[0].upper(), m.start(), m.end()) for m in scanner.finditer(text)
                  if not m[0].startswith(("'", '--', '/*'))]
        for i, (token, start, end) in enumerate(tokens):
            if token != name:
                continue
            previous = tokens[i-1][0] if i else None
            following = tokens[i+1][0] if i+1 < len(tokens) else None
            if previous in ('PROCEDURE', 'FUNCTION', 'END', '.'):
                continue
            site = {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                    'source_owner_id': owner['id'], 'character_offset': start, 'end_character_offset': end,
                    'offset_unit': 'decoded_unicode_character', 'control_flow_verified': False}
            (sites if following in (';', '(') else unresolved).append(site)
    return {'active_call_sites': sites, 'unresolved_references': unresolved,
            'searched_code_unit_ids': [u['id'] for u in units if objects[u['owner_id']]['module_id'] == module_id],
            'original_caller_proven': bool(sites), 'declaration_owner_id': owner_id,
            'search_scope': 'all_supplied_module_code_units_excluding_comments_strings_and_declarations'}


def _check_types(body, fields):
    def dtype(node):
        kind = node['kind']
        if kind == 'literal':
            return 'NULL' if node['value'] is None else 'VARCHAR2'
        if kind == 'reference':
            return 'VARCHAR2' if node.get('binding') == 'system_form_status' else fields[node['source_item_id']]['data_type']
        if kind == 'nvl':
            left, right = dtype(node['value']), dtype(node['fallback'])
            _need(left == right or 'NULL' in (left, right), 'MIXED_NVL_TYPES')
            return right if left == 'NULL' else left
        if kind in ('is_null', 'is_not_null'):
            dtype(node['value']); return 'BOOLEAN'
        left, right = dtype(node['left']), dtype(node['right'])
        if kind == 'and':
            _need(left == right == 'BOOLEAN', 'BOOLEAN_CONDITION_REQUIRED')
        else:
            _need(kind in ('eq', 'ne') and (left == right or 'NULL' in (left, right)), 'MIXED_COMPARISON_TYPES')
        return 'BOOLEAN'
    for node in _walk(body):
        if node['kind'] == 'assign':
            target, value = dtype(node['target']), dtype(node['value'])
            _need(target == value or value == 'NULL', 'MIXED_ASSIGNMENT_TYPES')
            _need(node['target'].get('binding') != 'system_form_status', 'SYSTEM_ASSIGNMENT_UNSUPPORTED')
        elif node['kind'] == 'if':
            for branch in node['branches']:
                _need(dtype(branch['condition']) == 'BOOLEAN', 'BOOLEAN_CONDITION_REQUIRED')


def compile_item_entry_workflows(documents, packet, chunks, trace, files):
    actual, actual_chunks = _build(documents)
    _need(actual['source_binding'] == packet.get('source_binding') and actual['sources'] == packet.get('sources')
          and actual_chunks == chunks and trace.get('source_binding') == packet['source_binding'], 'SOURCE_BINDING')
    _need(json.loads(files['fox-package/source-to-page.json']) == trace, 'STORED_TRACE')
    manifest = json.loads(files['fox-package/source-manifest.json'])
    _need(manifest.get('source_binding') == packet['source_binding']
          and manifest.get('files') == [{k: s['source'][k] for k in ('name', 'sha256', 'bytes')} for s in actual['sources']]
          and manifest.get('selected_chunk_hashes') == {c['id']: c['sha256'] for c in chunks}, 'MANIFEST_BINDING')
    for name, raw in documents:
        _need(files.get('fox-package/sources/' + name) == raw, 'ORIGINAL_SOURCE')
    objects, props = _source_objects(documents, packet)
    units = [u for s in packet['sources'] for u in s['facts']['code_units']]
    texts = {c['code_unit_id']: c for c in chunks}
    operations, gaps = [], []
    for unit in units:
        owner = objects[unit['owner_id']]
        event = owner['name'] if owner['kind'] == 'Trigger' else owner['kind']
        if event not in ('WHEN-NEW-ITEM-INSTANCE', 'ProgramUnit'):
            continue
        try:
            parsed = parse_item_entry_source(texts[unit['id']]['text'], event)
            if event == 'ProgramUnit':
                _need(parsed['routine_name'] == owner['name'].upper(), 'ROUTINE_DECLARATION')
                _need(all(n['kind'] in ('go_block', 'go_item', 'assign') for n in parsed['body'])
                      and any(n['kind'] == 'assign' for n in parsed['body']), 'LOCAL_NAVIGATION_ASSIGNMENT_ROUTINE')
            else:
                _need(objects.get(owner['parent_id'], {}).get('kind') == 'Item', 'ITEM_EVENT_OWNER')
            fields, navigation, summaries = {}, [], []
            for node in _walk(parsed['body']):
                if node['kind'] == 'reference':
                    if node['parts'] == ['SYSTEM', 'FORM_STATUS']:
                        node.update(binding='system_form_status')
                        continue
                    item = _resolve(node['parts'], owner, objects)
                    p = props[item['id']]
                    _need(p.get('DataType', '').upper() in ('NUMBER', 'CHAR', 'VARCHAR2'), 'FIELD_TYPE')
                    node.update(source_item_id=item['id'], source_block_id=item['block_id'])
                    fields[item['id']] = {'source_item_id': item['id'], 'source_block_id': item['block_id'],
                        'source_name': item['name'], 'source_database_item': p.get('DatabaseItem', '').lower() == 'true',
                        'data_type': 'NUMBER' if p.get('DataType', '').upper() == 'NUMBER' else 'VARCHAR2',
                        'maximum_length': p.get('MaximumLength'), 'length_semantics': p.get('DataLengthSemantics', '').upper(),
                        'source_attribute_sha256': _sha(p)}
                    if p.get('CalculateMode', '').upper() == 'SUMMARY':
                        summaries.append(_summary(item, objects, props, trace, files))
                if node['kind'] == 'go_item':
                    item = _resolve(node['value'].upper().split('.'), owner, objects)
                    node.update(source_item_id=item['id'], source_block_id=item['block_id'])
                    navigation.append({'kind': 'go_item', 'source_item_id': item['id'], 'source_block_id': item['block_id']})
                elif node['kind'] == 'go_block':
                    block = _one([o for o in objects.values() if o['kind'] == 'Block' and o['module_id'] == owner['module_id']
                                  and o['name'].upper() == node['value'].upper()], 'NAVIGATION_BLOCK')
                    node['source_block_id'] = block['id']
                    navigation.append({'kind': 'go_block', 'source_block_id': block['id']})
            summaries = list({s['source_item_id']: s for s in summaries}.values())
            if event == 'ProgramUnit':
                _need(summaries, 'XML_SUMMARY_ROUTINE_REQUIRED')
            _check_types(parsed['body'], fields)
            stages = []
            def ordinal(body, path=()):
                for n in body:
                    n['ordinal'] = len(stages)+1
                    stages.append({'ordinal': n['ordinal'], 'kind': n['kind'], 'conditional_path': list(path),
                                   'position': deepcopy(n['position'])})
                    if n['kind'] == 'if':
                        for i, branch in enumerate(n['branches']):
                            ordinal(branch['body'], path + (str(n['ordinal']) + ':branch:' + str(i),))
                        ordinal(n['else'], path + (str(n['ordinal']) + ':else',))
            ordinal(parsed['body'])
            caller = _callers(parsed['routine_name'], owner['module_id'], owner['id'], units, chunks, objects) if event == 'ProgramUnit' else None
            op = {'operation_id': 'item-entry-' + unit['id'], 'rule_id': RULE_ID,
                  'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                  'source_chunk_id': texts[unit['id']]['id'], 'source_owner_id': owner['id'],
                  'source_module_id': owner['module_id'], 'source_event': event,
                  'owner_item_id': owner['parent_id'] if event != 'ProgramUnit' else None,
                  'parsed': parsed, 'fields': fields, 'summaries': summaries, 'navigation': navigation,
                  'stages': stages, 'caller_evidence': caller,
                  'required_boundaries': ['trusted_current_record_and_master_context', 'source_navigation_and_record_lifecycle'],
                  'generation_status': 'encoded_not_wired', 'runtime_verified': False, 'business_accepted': False}
            if any(n['kind'] == 'commit_form' for n in _walk(parsed['body'])):
                op['required_boundaries'].append('ordered_whole_form_commit_with_validation_posting_and_failure_outcome')
            if any(not f['source_database_item'] for f in fields.values()):
                op['required_boundaries'].append('trusted_transient_fields_and_effective_draft_buffer')
            if caller is not None and not caller['original_caller_proven']:
                op['required_boundaries'].append('original_caller_absent_from_supplied_source')
            op['operation_sha256'] = _operation_digest(op)
            operations.append(op)
        except ValueError as exc:
            # Unrelated program units are not this compiler's responsibility.
            if event == 'WHEN-NEW-ITEM-INSTANCE':
                gaps.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'], 'reason': str(exc)})
    return {'scope': SCOPE, 'source_binding': packet['source_binding'], 'operations': operations, 'gaps': gaps,
            'runtime_verified': False, 'business_accepted': False}


class ItemEntryBoundary(RuntimeError):
    """A required trusted provider is missing or reported a non-success outcome."""
    def __init__(self, reason):
        super().__init__(reason)
        self.confirmed_effects = []
        self.pending_ordinal = None
        self.retry_authorized = False


def _oracle_value(value):
    return None if isinstance(value, str) and value == '' else value


def _provider_value(field, value):
    value = _oracle_value(value)
    if value is None:
        return None
    if field['data_type'] == 'NUMBER':
        if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
            raise ItemEntryBoundary('invalid_numeric_provider_value')
        try:
            number = Decimal(str(value))
            if not number.is_finite() or (number and not -130 <= number.adjusted() <= 125):
                raise ItemEntryBoundary('invalid_numeric_provider_value')
            return number
        except (InvalidOperation, ValueError) as exc:
            raise ItemEntryBoundary('invalid_numeric_provider_value') from exc
    maximum = field.get('maximum_length')
    if not isinstance(value, str) or len(value.encode()) > 4000:
        raise ItemEntryBoundary('invalid_character_provider_value')
    length = len(value.encode()) if field.get('length_semantics') == 'BYTE' else len(value)
    if maximum is not None and (not str(maximum).isdigit() or length > int(maximum)):
        raise ItemEntryBoundary('character_provider_exceeds_source_size')
    return value


def _operation_digest(operation):
    return hashlib.sha256(json.dumps({k: operation[k] for k in _COMPILED_KEYS}, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def execute_item_entry(operation, adapter, *, expected_operation_sha256=None):
    """Execute a compiled body in source order over a trusted current buffer.

    Adapter methods: context(operation), read(field, context), summary(binding,
    context), assign(field,value,context), form_status(context), navigate(node,
    context), commit_form(context), message(text,context). Context contains
    trusted=True, row_ids={source_block_id: stable_id}, scope='forms_buffer', and
    the event's current_item_id. Navigation must return a fresh trusted context;
    every other effect must explicitly return True. False/unknown/exception stops
    immediately, without retries, rollback claims or subsequent navigation.
    """
    try:
        digest = _operation_digest(operation)
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise ItemEntryBoundary('compiled_operation_invalid') from exc
    if digest != operation.get('operation_sha256') or (expected_operation_sha256 is not None and digest != expected_operation_sha256):
        raise ItemEntryBoundary('compiled_operation_digest_mismatch')
    effects = []
    pending = None
    def hook(name, *args):
        method = getattr(adapter, name, None)
        if not callable(method):
            raise ItemEntryBoundary('provider_unavailable:' + name)
        try:
            return method(*args)
        except ItemEntryBoundary:
            raise
        except Exception as exc:
            raise ItemEntryBoundary('provider_error_or_unknown_outcome:' + name) from exc
    context = hook('context', operation)
    fields = operation['fields']
    summaries = {s['source_item_id']: s for s in operation['summaries']}

    def trusted(value):
        if not isinstance(value, dict) or value.get('trusted') is not True or value.get('scope') != 'forms_buffer' or not isinstance(value.get('row_ids'), dict):
            raise ItemEntryBoundary('trusted_current_forms_buffer_context_required')
        for row in value['row_ids'].values():
            if isinstance(row, bool) or not isinstance(row, (int, str)) or (isinstance(row, int) and row < 1) or (isinstance(row, str) and (not row or len(row) > 4000)):
                raise ItemEntryBoundary('invalid_current_record_identity')
        return value

    trusted(context)
    if operation.get('owner_item_id') is not None and context.get('current_item_id') != operation['owner_item_id']:
        raise ItemEntryBoundary('event_current_item_mismatch')

    def field_context(field):
        if context['row_ids'].get(field['source_block_id']) is None:
            raise ItemEntryBoundary('current_record_identity_required:' + field['source_block_id'])

    def expression(node):
        kind = node['kind']
        if kind == 'literal':
            return _oracle_value(node['value'])
        if kind == 'reference':
            if node.get('binding') == 'system_form_status':
                value = hook('form_status', context)
                if value not in ('QUERY', 'CHANGED', 'NEW'):
                    raise ItemEntryBoundary('trusted_form_status_unavailable')
                return value
            field = fields[node['source_item_id']]
            field_context(field)
            if node['source_item_id'] in summaries:
                return _provider_value(field, hook('summary', summaries[node['source_item_id']], context))
            return _provider_value(field, hook('read', field, context))
        if kind == 'nvl':
            value = expression(node['value'])
            return expression(node['fallback']) if value is None else value
        if kind in ('is_null', 'is_not_null'):
            empty = expression(node['value']) is None
            return empty if kind == 'is_null' else not empty
        left = expression(node['left'])
        if kind == 'and' and left is False:
            return False
        right = expression(node['right'])
        if kind == 'and':
            if left is False or right is False:
                return False
            return None if left is None or right is None else True
        if left is None or right is None:
            return None
        if kind == 'eq':
            return left == right
        if kind == 'ne':
            return left != right
        raise ItemEntryBoundary('unsupported_expression')

    def perform(body):
        nonlocal context, pending
        for node in body:
            pending = node['ordinal']
            kind = node['kind']
            if kind == 'if':
                selected = next((b['body'] for b in node['branches'] if expression(b['condition']) is True), node['else'])
                perform(selected)
                continue
            effect = {'ordinal': node['ordinal'], 'kind': kind}
            if kind == 'assign':
                field = fields[node['target']['source_item_id']]
                field_context(field)
                value = _provider_value(field, expression(node['value']))
                outcome = hook('assign', field, value, context)
                effect.update(source_item_id=field['source_item_id'], value=value)
            elif kind == 'commit_form':
                # This provider is explicitly the whole Forms transaction. There
                # is no UPDATE/COMMIT fallback and no success on a void return.
                outcome = hook('commit_form', context)
            elif kind == 'message':
                outcome = hook('message', node['value'], context)
                effect['value'] = node['value']
            elif kind in ('go_item', 'go_block', 'next_item', 'next_record'):
                next_context = hook('navigate', deepcopy(node), deepcopy(context))
                trusted(next_context)
                if kind == 'go_item' and (next_context.get('current_item_id') != node['source_item_id'] or next_context.get('current_block_id') != node['source_block_id']):
                    raise ItemEntryBoundary('navigation_target_identity_mismatch')
                if kind == 'go_block' and next_context.get('current_block_id') != node['source_block_id']:
                    raise ItemEntryBoundary('navigation_target_identity_mismatch')
                if next_context['row_ids'].get(next_context.get('current_block_id')) is None:
                    raise ItemEntryBoundary('navigation_current_record_identity_missing')
                # GO_ITEM/GO_BLOCK select the target block's current record;
                # only NEXT_RECORD may advance that identity.
                if kind in ('go_item', 'go_block') and next_context['row_ids'] != context['row_ids']:
                    raise ItemEntryBoundary('navigation_changed_current_record_identity')
                context, outcome = next_context, True
                effect['context'] = deepcopy(context)
            else:
                raise ItemEntryBoundary('unsupported_statement')
            if outcome is not True:
                raise ItemEntryBoundary('effect_not_confirmed:' + kind + ':' + str(node['ordinal']))
            effects.append(effect)

    try:
        perform(operation['parsed']['body'])
    except ItemEntryBoundary as exc:
        exc.confirmed_effects = deepcopy(effects)
        exc.pending_ordinal = pending
        raise
    return {'effects': effects, 'context': deepcopy(context), 'completed': True,
            'oracle_runtime_verified': False, 'business_accepted': False}


def summary_projection(summary, master_alias):
    """SQL SUM over the current master's full declared composite detail scope."""
    _need(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', master_alias or ''), 'SUMMARY_ALIAS')
    _need(re.fullmatch(r'[A-Z][A-Z0-9_]*', summary['detail_table']) and
          re.fullmatch(r'[A-Z][A-Z0-9_]*', summary['measure_column']), 'SUMMARY_SQL_IDENTIFIERS')
    for pair in summary['join_pairs']:
        _need(all(re.fullmatch(r'[A-Z][A-Z0-9_]*', pair[k]) for k in ('parent_column', 'child_column')), 'SUMMARY_SQL_IDENTIFIERS')
    expression = summary.get('measure_expression')
    if expression:
        sql = numeric_expression.render_sql(expression, {tuple(f['source_reference']): f['column'] for f in summary['measure_input_fields']})
        # The numeric renderer permits only validated identifiers and functions;
        # qualify each independently bound input, never function names/literals.
        for field in summary['measure_input_fields']:
            sql = re.sub(r'\b' + re.escape(field['column']) + r'\b', 'fox_sum.' + field['column'], sql)
    else:
        sql = 'fox_sum.' + summary['measure_column']
    return '(select sum(' + sql + ') from ' + summary['detail_table'] + ' fox_sum where ' + ' and '.join(
        'fox_sum.' + p['child_column'] + '=' + master_alias + '.' + p['parent_column'] for p in summary['join_pairs']) + ')'


def _runtime_source(plan):
    return ('"""Source-bound item-entry executor; trusted server integration required."""\n'
            + 'from copy import deepcopy\nfrom decimal import Decimal, InvalidOperation\nimport hashlib\nimport json\n\n'
            + '_COMPILED_KEYS = ' + repr(_COMPILED_KEYS) + '\n'
            + '_KNOWN_OPERATIONS = ' + repr({o['operation_id']: o['operation_sha256'] for o in plan['operations']}) + '\n\n'
            + '\n\n'.join(inspect.getsource(f) for f in
                (ItemEntryBoundary, _oracle_value, _provider_value, _operation_digest, execute_item_entry))
            + '''\n_unchecked_execute = execute_item_entry
def execute_item_entry(operation, adapter):
    expected = _KNOWN_OPERATIONS.get(operation.get('operation_id'))
    if expected is None:
        raise ItemEntryBoundary('operation_absent_from_compiled_package')
    return _unchecked_execute(operation, adapter, expected_operation_sha256=expected)
''').encode()


def _sql_expression(node, columns):
    kind = node['kind']
    if kind == 'literal':
        return 'NULL' if node['value'] is None else native_buffer._literal(node['value'])
    if kind == 'reference':
        _need(node.get('binding') != 'system_form_status', 'NO_SAVED_FORM_STATUS')
        return columns[node['source_item_id']]
    if kind == 'nvl':
        return 'nvl(' + _sql_expression(node['value'], columns) + ',' + _sql_expression(node['fallback'], columns) + ')'
    if kind in ('is_null', 'is_not_null'):
        return '(' + _sql_expression(node['value'], columns) + (' is null)' if kind == 'is_null' else ' is not null)')
    _need(kind in ('eq', 'ne', 'and'), 'SAVED_EXPRESSION')
    return '(' + _sql_expression(node['left'], columns) + {'eq': '=', 'ne': '<>', 'and': ' and '}[kind] + _sql_expression(node['right'], columns) + ')'


def saved_entry_runtime(config):
    """Explicit read-only snapshot check; never an invented original event caller."""
    payload = json.dumps(config, separators=(',', ':'), ensure_ascii=True).replace('<', '\\u003c')
    return '''(function(){"use strict";
const c=''' + payload + ''';
function run(){
 const ready=document.getElementById(c.state_item), state=document.getElementById(c.result_item);
 const message=document.getElementById(c.message_id);
 if(!message)return false;
 if(!ready||ready.value!=="READY"||!state){message.textContent="The saved selection changed. Reopen the record.";return false;}
 if(state.value==="INVALID_FOCUS"){
  const target=document.getElementById(c.invalid_target);
  if(!target){message.textContent="The source focus target is unavailable.";return false;}
  target.focus();message.textContent="Source invalid-destination branch: focus returned to the selected consignment number. Saved snapshot only.";return true;
 }
 if(state.value==="SUMMARY_THEN_TRANSACTION"){
  const result=document.getElementById(c.preview_item), summary=document.getElementById(c.summary_item);
  if(!result||!summary)return false;
  result.value=summary.value;
  message.textContent="The saved detail total was copied into this session display. Original dirty-buffer summary, whole-form commit and subsequent Next remain pending.";return true;
 }
 message.textContent="The source selects NEXT_RECORD. This view requires explicit selection of another saved record; no record was advanced or created.";return false;
}
const button=document.getElementById(c.button_id);if(button)button.addEventListener("click",run);
window.foxSavedItemEntry={run:run};
})();'''


def _attach_saved_entry(op, screen, objects, props, trace, files):
    """Adapt the two source-local branches to a clearly scoped saved snapshot."""
    from .forms_item_commands import _chain_for, _screen
    relation = json.loads(files['fox-package/relation-plan.json'])
    commands = json.loads(files['fox-package/item-command-receipt.json'])
    _need(commands['source_binding'] == trace['source_binding'], 'COMMAND_SOURCE_BINDING')
    config = screen['runtime_config']
    source_commands = config['operations']
    # Rebuild the entire upstream signed context screen from the original source,
    # not from caller-authored SQL/field aliases in an unverified receipt.
    deepest = _one([b for b in trace['blocks'] if b['source_block_id'] == screen['path_block_ids'][-1]], 'SAVED_CONTEXT_BLOCK')
    blocks, edges = _chain_for(deepest['source_block_id'], objects, props, trace, files, relation)
    _need(screen['path_block_ids'] == [b['source_block_id'] for b in blocks], 'SAVED_FULL_CHAIN')
    rebuilt, evidence = _screen(screen['page_id'], None, blocks, edges, len(blocks), source_commands, objects, props)
    _need(files[screen['page_file']] == rebuilt and all(screen[k] == evidence[k] for k in evidence), 'EXACT_SAVED_CONTEXT_SCREEN')
    body = op['parsed']['body']
    _need(len(body) == 1 and body[0]['kind'] == 'if' and len(body[0]['branches']) == 2, 'SAVED_ENTRY_SHAPE')
    first, invalid = body[0]['branches']
    _need([n['kind'] for n in first['body']] == ['assign', 'if', 'next_item']
          and [n['kind'] for n in invalid['body']] == ['go_item']
          and [n['kind'] for n in body[0]['else']] == ['next_record'], 'SAVED_ENTRY_EFFECTS')
    summary = _one(op['summaries'], 'SAVED_ONE_SUMMARY')
    _need(first['body'][0]['value'].get('source_item_id') == summary['source_item_id'], 'SAVED_SOURCE_SUMMARY_ASSIGNMENT')
    columns = {}
    for uid in op['fields']:
        if uid == summary['source_item_id']:
            continue
        field = op['fields'][uid]
        b = _one([b for b in blocks if b['source_block_id'] == field['source_block_id']], 'SAVED_FIELD_CONTEXT')
        f = _one([f for f in b['items'] if f['source_item_id'] == uid], 'SAVED_FIELD')
        columns[uid] = screen['context_aliases'][b['source_block_id']] + '.' + f['column']
    master_alias = screen['context_aliases'][summary['master_block_id']]
    projection = summary_projection(summary, master_alias)
    page = screen['page_id']
    prefix = f'P{page}_ENTRY'
    suffix = screen['selected_record_sql'].split(' from ', 1)[1]
    source_sql = ('select ' + projection + ',case when ' + _sql_expression(first['condition'], columns)
                  + " then 'SUMMARY_THEN_TRANSACTION' when " + _sql_expression(invalid['condition'], columns)
                  + " then 'INVALID_FOCUS' else 'NEXT_RECORD_REQUIRED' end from " + suffix)
    # Subqueries in the projection contain FROM. Insert INTO immediately before
    # the separately proved outer FROM, never the first lexical FROM.
    outer = source_sql[:-len(suffix)-6]
    sql = f'''begin
:{prefix}_SUM:=null;:{prefix}_RESULT:=null;:{prefix}_PREVIEW:=null;
{outer} into :{prefix}_SUM,:{prefix}_RESULT from {suffix};
exception when no_data_found then
:{prefix}_SUM:=null;:{prefix}_RESULT:='STALE_OR_MISSING';:{prefix}_PREVIEW:=null;
end;'''
    _need(len(sql.encode()) <= 32767, 'SAVED_PROCESS_CAPACITY')
    invalid_binding = _one([f for f in screen['field_bindings'] if f['source_item_id'] == invalid['body'][0]['source_item_id']], 'SAVED_INVALID_FOCUS_CONTROL')
    ui = {'state_item': f'P{page}_STATE', 'result_item': prefix+'_RESULT', 'summary_item': prefix+'_SUM',
          'preview_item': prefix+'_PREVIEW', 'invalid_target': invalid_binding['item_name'],
          'button_id': 'fox-saved-entry-check', 'message_id': 'fox-saved-entry-status'}
    addition = ''
    for suffix_name, label, dtype in (('SUM', 'Saved detail total from XML summary (NULL when no weighted details)', 'number'),
                                      ('PREVIEW', 'Session cost-weight preview; no saved bag update', 'number'),
                                      ('RESULT', 'Saved snapshot branch; original transient destination lookup is separate', 'varchar2')):
        addition += f'''    pageItem {prefix}_{suffix_name} (
        type: textField
        label {{ label: {json.dumps(label)} }}
        layout {{ sequence: {600+len(addition)//100}
            region: @records
            slot: regionBody }}
        appearance {{ template: @/optional-floating }}
        advanced {{ customAttributes: "readonly aria-readonly=\\"true\\"" }}
        sessionState {{ storage: request
            dataType: {dtype} }}
        security {{ sessionStateProtection: restricted }}
    )
'''
    addition += native_buffer._process('load-saved-entry-summary', sql, point='beforeHeader', sequence=20)
    page_text = files[screen['page_file']].decode()
    script = saved_entry_runtime(ui)
    anchor = '        ```\n    }\n'
    _need(page_text.count(anchor) == 1 and page_text.endswith(')\n'), 'SAVED_SCRIPT_ANCHOR')
    page_text = page_text.replace(anchor, native_buffer._indent(script, 8) + '\n' + anchor, 1)
    # A separate native static region makes the adaptation explicit next to the
    # real source-bound controls. No automatic Forms lifecycle is alleged.
    html = '<p>Explicit saved snapshot entry check. The XML summary rounds each saved consignment weight before summing all details of this bag. Original transient destination values and unsaved edits are unavailable here. A NULL result stays NULL. No business row is changed.</p><button type="button" id="fox-saved-entry-check">Check saved consignment entry</button><p id="fox-saved-entry-status" role="status" aria-live="polite"></p>'
    addition += f'''    region saved-entry-scope (
        name: Saved consignment entry check
        type: staticContent
        source {{ htmlCode: {json.dumps(html)} }}
        layout {{ sequence: 900
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
'''
    files[screen['page_file']] = (page_text[:-2] + native_buffer._expand_groups(addition) + ')\n').encode()
    return {'page_file': screen['page_file'], 'page_id': page, 'source_summary': summary,
            'summary_projection_sql': projection, 'saved_entry_query_sql': source_sql, 'process_plsql': sql,
            'runtime_config': ui, 'javascript': script,
            'source_assignment_target_item_id': first['body'][0]['target']['source_item_id'],
            'preview_item': ui['preview_item'], 'invalid_focus_target': invalid_binding,
            'scope': 'explicit_read_only_saved_synthetic_snapshot_with_session_display_preview',
            'omitted_effects': ['current_original_transient_destination_lookup', 'effective_unsaved_detail_buffer',
                                'whole_form_commit', 'next_item_after_transaction', 'next_record_lifecycle', 'persisted_bag_weight_update']}


def native_routine_runtime(config):
    """A genuine callable target, intentionally without an invented UI caller."""
    payload = json.dumps(config, separators=(',', ':'), ensure_ascii=True).replace('<', '\\u003c')
    return '''(function(){"use strict";
const c=''' + payload + ''';
function invoke(operationId){
 if(operationId!==c.operation_id)throw new Error("Unknown compiled item-entry routine");
 const state=document.getElementById(c.state_item);
 if(!state||state.value!=="READY")throw new Error("Saved current-record context unavailable");
 const selection=c.identity_items.map(function(id){const e=document.getElementById(id);if(!e||!e.value)throw new Error("Current record identity unavailable");return e.value;});
 const focus=document.getElementById(c.focus_item), summary=document.getElementById(c.summary_item), output=document.getElementById(c.output_item);
 if(!focus||!summary||!output)throw new Error("Source-bound routine field unavailable");
 // GO_BLOCK retains every selected saved record. GO_ITEM then selects the
 // exact source field in that block; assignment follows successful focus.
 const context={current_block_id:c.block_id,row_ids:selection.slice()};
 focus.focus();if(document.activeElement!==focus)throw new Error("Source GO_ITEM failed; assignment did not run");
 context.current_item_id=c.focus_source_item_id;
 if(c.identity_items.some(function(id,i){return document.getElementById(id).value!==selection[i];}))throw new Error("Selected record changed during navigation");
 output.value=summary.value;
 return {completed:true,source_operation_id:operationId,context:context,scope:"saved_snapshot_session_display_only",original_caller_proven:false};
}
const previous=window.foxItemEntryRoutines;
const routines=Object.assign(Object.create(null),previous&&previous.routines?previous.routines:{});
const names=Object.assign(Object.create(null),previous&&previous.routine_names?previous.routine_names:{});
routines[c.operation_id]=invoke;names[c.operation_id]=c.routine_name;
window.foxItemEntryRoutines={routines:routines,routine_names:names,invoke:function(id){
 if(!Object.prototype.hasOwnProperty.call(routines,id))throw new Error("Unknown compiled item-entry routine");
 return routines[id](id);
}};
})();'''


def _attach_native_routine(op, adapted, screens, files):
    body = op['parsed']['body']
    _need([n['kind'] for n in body] == ['go_block', 'go_item', 'assign'], 'NATIVE_ROUTINE_SHAPE')
    block, focus, assignment = body
    _need(block['source_block_id'] == focus['source_block_id'], 'NATIVE_ROUTINE_BLOCK')
    summary = _one(op['summaries'], 'NATIVE_ROUTINE_SUMMARY')
    _need(assignment['value'].get('source_item_id') == summary['source_item_id'], 'NATIVE_ROUTINE_SOURCE_SUMMARY')
    provider = _one([a for a in adapted if a.get('saved_entry_target', {}).get('source_assignment_target_item_id') == assignment['target']['source_item_id']
                     and a['saved_entry_target']['source_summary'] == summary], 'NATIVE_ROUTINE_SUMMARY_PROVIDER')
    target = provider['saved_entry_target']
    screen = _one([s for s in screens if s['page_file'] == target['page_file']], 'NATIVE_ROUTINE_SCREEN')
    field = _one([f for f in screen['field_bindings'] if f['source_item_id'] == focus['source_item_id']
                  and f['source_block_id'] == block['source_block_id']], 'NATIVE_ROUTINE_FOCUS_FIELD')
    page = screen['page_id']
    config = {'operation_id': op['operation_id'], 'routine_name': op['parsed']['routine_name'],
              'state_item': f'P{page}_STATE', 'focus_item': field['item_name'], 'block_id': block['source_block_id'],
              'focus_source_item_id': focus['source_item_id'],
              'summary_item': target['runtime_config']['summary_item'], 'output_item': target['preview_item'],
              'identity_items': [f'P{page}_{kind}{i}' for i in range(len(screen['path_block_ids'])) for kind in ('ID','TOKEN')]}
    text = files[screen['page_file']].decode()
    anchor = '        ```\n    }\n'
    _need(text.count(anchor) == 1, 'NATIVE_ROUTINE_SCRIPT_ANCHOR')
    script = native_routine_runtime(config)
    files[screen['page_file']] = text.replace(anchor, native_buffer._indent(script, 8)+'\n'+anchor, 1).encode()
    return {'page_file': screen['page_file'], 'page_id': page, 'callable': 'window.foxItemEntryRoutines.invoke',
            'operation_id_argument': op['operation_id'], 'runtime_config': config, 'javascript': script,
            'scope': 'signed_saved_snapshot_session_display_adaptation', 'source_caller_installed': False,
            'connected_effects': ['retain_selected_record_identities', 'go_block_current_saved_context',
                                  'go_item_exact_source_control', 'copy_xml_saved_summary_to_session_display'],
            'remaining_boundaries': ['original_caller_absent_from_supplied_source', 'effective_original_dirty_detail_buffer',
                                     'original_form_buffer_cost_weight_assignment']}


def _marker_boundary_evidence(op, props, files):
    """Identify a real retained marker without pretending it supplies focus."""
    validation = json.loads(files.get('fox-package/item-validation-receipt.json', b'{}'))
    candidates = [v for v in validation.get('generated_operations', [])
                  if v.get('contract', {}).get('fields', {}).get('marker', {}).get('source_item_id') == op['owner_item_id']]
    if len(candidates) != 1:
        return {'current_marker_provider': 'not_uniquely_bound', 'native_reset_connected': False}
    v = candidates[0]; c = v['contract']
    destination = c['fields']['destination']
    focus_targets = [n['source_item_id'] for n in _walk(op['parsed']['body']) if n['kind'] == 'go_item']
    if destination['source_item_id'] not in focus_targets:
        return {'current_marker_provider': 'different_focus_target', 'native_reset_connected': False,
                'reason': 'The draft marker exists, but its destination differs from the item named by this entry event.'}
    return {'current_marker_provider': 'retained_revision_guarded_item_validation_draft',
            'draft_page_file': v['page_file'], 'draft_page_id': v['page_id'],
            'collection_namespace': c['collection_namespace'], 'marker_slot': c['slots']['marker'],
            'marker_source_item_id': c['fields']['marker']['source_item_id'],
            'code_source_item_id': c['fields']['code']['source_item_id'], 'code_slot': c['code_slot'],
            'destination_source_item_id': destination['source_item_id'],
            'destination_native_item': destination.get('native_item'),
            'destination_in_edit_form': destination.get('in_edit_form'),
            'destination_value_computation_implemented': destination.get('value_computation_implemented'),
            'destination_lov_name': props[destination['source_item_id']].get('LovName'),
            'destination_source_item_type': props[destination['source_item_id']].get('ItemType'),
            'destination_source_canvas': props[destination['source_item_id']].get('CanvasName'),
            'native_reset_connected': False,
            'blocked_order': ['clear_current_draft_code', 'focus_original_header_destination', 'clear_current_draft_marker'],
            'reason': 'The XML defines the original header destination as a canvas Text Item with a LOV. The guarded draft has the retained marker and code, but the generated destination binding is report-only: there is no shared live header-field/current-draft navigation adapter or transient LOV state. Clearing either value would begin a source sequence whose GO_ITEM continuation is unavailable. The complete reusable executor preserves this order; the normal draft is unchanged.'}


def apply_item_entry_workflows(documents, packet, chunks, trace, files):
    """Emit complete reusable callables; attach separately proved saved summaries."""
    plan = compile_item_entry_workflows(documents, packet, chunks, trace, files)
    result = dict(files)
    runtime_file = 'fox-package/item-entry-runtime.py'
    plan_file = 'fox-package/item-entry-plan.json'
    result[runtime_file] = _runtime_source(plan)
    result[plan_file] = _json(plan)
    encoded, adapted, gaps = [], [], list(plan['gaps'])
    objects, props = _source_objects(documents, packet)
    command_receipt = json.loads(files.get('fox-package/item-command-receipt.json', b'{}'))
    for value in plan['operations']:
        op = deepcopy(value)
        op.update(target={'runtime_file': runtime_file, 'callable': 'execute_item_entry', 'plan_file': plan_file,
                          'operation_id': op['operation_id']},
                  adaptation='Complete callable encoding requires trusted Forms-buffer, whole-form transaction and navigation adapters. Saved row reports do not supply transient state or an original routine caller.')
        attached = False
        if op['source_event'] == 'WHEN-NEW-ITEM-INSTANCE' and op['summaries']:
            screens = [s for s in command_receipt.get('screens', []) if s['path_block_ids']
                       and s['path_block_ids'][-1] == objects[op['owner_item_id']]['block_id'] and s.get('selected_record_sql')]
            if screens:
                try:
                    target = _attach_saved_entry(op, _one(screens, 'ONE_SAVED_SCREEN'), objects, props, trace, result)
                    op.update(generation_status='generated_wired_adapted_partial', saved_entry_target=target,
                              page_file=target['page_file'], page_id=target['page_id'], native_event='explicit_saved_snapshot_entry_check',
                              adaptation='XML saved summary, session display copy and source invalid-focus branch on explicitly selected saved synthetic snapshots. Full original item-entry transaction and dirty state remain separate.')
                    op['connected_effects'] = ['saved_detail_summary_from_xml_formula', 'session_display_weight_preview',
                                               'source_invalid_destination_focus_on_saved_snapshot']
                    op['remaining_boundaries'] = target['omitted_effects']
                    adapted.append(op); attached = True
                except (ValueError, KeyError) as exc:
                    gaps.append({'source_unit_id': op['source_unit_id'], 'reason': str(exc)})
        if not attached:
            if op['source_event'] == 'WHEN-NEW-ITEM-INSTANCE' and not op['summaries']:
                op['integration_boundary_evidence'] = _marker_boundary_evidence(op, props, files)
                op['remaining_boundaries'] = list(op['required_boundaries'])
                if op['integration_boundary_evidence']['current_marker_provider'] == 'retained_revision_guarded_item_validation_draft':
                    op['remaining_boundaries'].append('focusable_original_header_destination_with_shared_transient_lov_context')
                op['reason'] = op['integration_boundary_evidence'].get('reason', 'The current marker provider is not uniquely bound to this native event.')
            encoded.append(op)
    for op in encoded:
        if op['source_event'] == 'ProgramUnit' and adapted:
            try:
                op['native_callable_target'] = _attach_native_routine(op, adapted, command_receipt.get('screens', []), result)
                op['connected_effects'] = op['native_callable_target']['connected_effects']
                op['remaining_boundaries'] = op['native_callable_target']['remaining_boundaries']
            except (ValueError, KeyError) as exc:
                gaps.append({'source_unit_id': op['source_unit_id'], 'reason': str(exc)})
    receipt = {'scope': SCOPE, 'source_binding': packet['source_binding'], 'generated_operations': [],
               'adapted_operations': adapted, 'encoded_operations': encoded, 'gaps': gaps,
               'runtime_verified': False, 'business_accepted': False}
    result['fox-package/item-entry-receipt.json'] = _json(receipt)
    return result, receipt
