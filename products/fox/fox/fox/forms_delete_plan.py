"""Closed, source-bound Forms deletion plans and a disposable local SQL model.

DELETE_RECORD is a buffer mark. PRE-DELETE belongs to posting, not marking.
An SQL DELETE, a Forms commit, and an observed database commit are separate facts.
There are no default providers, database connections, retries or rollbacks here.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
import json
import re
from typing import Any, Literal, Protocol

from forms2apex.record_buffer import decode_source
from .forms_approval_plan import _Parser as _BaseParser, _sha
from .forms_behavior_plan import _source_objects
from .forms_item_validation import _resolve
from .forms_relation_plan import parse_join_condition
from .forms_synthetic_save import _table_proof
from .forms_understanding_packet import _build

SCOPE = 'fox-source-delete-plan-v1'
_IDENT = r'[A-Z][A-Z0-9_$#]{0,127}'


def _need(value, reason):
    if not value:
        raise ValueError('DELETE_' + reason)


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


class _Parser(_BaseParser):
    def __init__(self, raw):
        self.text, self.receipt = decode_source(raw)
        self.tokens, pos = [], 0
        pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|:=|" +
                             _IDENT + r'|[0-9]+|[:.,();=>%]', re.I | re.S)
        while pos < len(self.text):
            m = pattern.match(self.text, pos)
            _need(m is not None, 'ACTIVE_TOKEN_AT_' + str(pos))
            token, pos = m[0], m.end()
            if token.isspace() or token.startswith(('--', '/*')):
                continue
            self.tokens.append(('string', token[1:-1].replace("''", "'"), m.start(), pos)
                               if token.startswith("'") else ('token', token.upper(), m.start(), pos))
            _need(len(self.tokens) <= 1500, 'TOKEN_CAPACITY')
        self.i = 0

    def end(self):
        _need(self.i == len(self.tokens), 'EXTRA_ACTIVE_SOURCE')

    def span(self, start, end):
        breaks = list(re.finditer(r'\r\n|\r|\n', self.text[:start]))
        return {'character_offset': start, 'end_character_offset': end,
                'line': len(breaks) + 1,
                'column': start - (breaks[-1].end() if breaks else 0) + 1,
                'offset_unit': 'decoded_unicode_character'}

    def call(self):
        _need(self.i < len(self.tokens), 'EXPECTED_ROUTINE_CALL')
        start = self.tokens[self.i][2]
        callee = self.ident() + self.take('.') + self.ident()
        self.take('(')
        args = []
        while True:
            _need(self.i < len(self.tokens), 'EXPECTED_ROUTINE_ARGUMENT')
            begin = self.tokens[self.i][2]
            arg = ({'kind': 'reference', 'parts': self.ref()} if self.peek(':') else
                   {'kind': 'literal', 'value': self.take(kind='string')})
            end = self.tokens[self.i - 1][3]
            arg.update(position=self.span(begin, end), observed_source=self.text[begin:end])
            args.append(arg)
            _need(len(args) <= 30, 'CALL_ARITY')
            if not self.peek(','):
                break
            self.take(',')
        self.take(')')
        end = self.tokens[self.i - 1][3]
        return {'callee': callee, 'arguments': args, 'arity': len(args),
                'position': self.span(start, end), 'observed_source': self.text[start:end],
                'formal_types': 'unknown', 'formal_directions': 'unknown',
                'target_availability': 'unverified', 'retry_policy': 'none_in_source'}

    def message_list(self):
        result = []
        while self.peek('MESSAGE'):
            self.seq('MESSAGE (')
            value = self.take(kind='string')
            _need(0 < len(value.encode()) <= 2000, 'MESSAGE_LENGTH')
            self.seq(') ;')
            result.append(value)
            _need(len(result) <= 4, 'MESSAGE_COUNT')
        _need(result, 'MESSAGE_REQUIRED')
        return result

    def delete(self):
        self.seq('DELETE FROM')
        table = self.ident()
        alias = None if self.peek('WHERE') else self.ident()
        self.take('WHERE')
        terms = []
        while True:
            column = self.ident()
            if self.peek('.'):
                self.take('.')
                _need(column == alias, 'DELETE_ALIAS')
                column = self.ident()
            self.take('=')
            terms.append({'column': column, 'reference': self.ref()})
            _need(len(terms) <= 4, 'DELETE_PREDICATE_CAPACITY')
            if not self.peek('AND'):
                break
            self.take('AND')
        self.take(';')
        _need(len({t['column'] for t in terms}) == len(terms), 'DUPLICATE_DELETE_COLUMN')
        return {'table': table, 'alias': alias, 'predicates': terms, 'access_role': 'delete'}


def parse_delete_source(raw, event):
    """Consume every active token of one supported complete event body."""
    p = _Parser(raw)
    if event == 'ON-CHECK-DELETE-MASTER':
        p.take('DECLARE'); dummy = p.ident(); p.seq('CHAR ( 1 ) ; CURSOR')
        cursor = p.ident(); p.seq('IS SELECT 1 FROM'); table = p.ident(); alias = p.ident()
        p.take('WHERE'); p.take(alias); p.take('.'); column = p.ident()
        p.take('='); ref = p.ref(); p.seq('; BEGIN OPEN'); p.take(cursor)
        p.seq('; FETCH'); p.take(cursor); p.take('INTO'); p.take(dummy)
        p.seq('; IF ('); p.take(cursor); p.seq('% FOUND ) THEN')
        messages = p.message_list()
        p.take('CLOSE'); p.take(cursor); p.seq('; RAISE FORM_TRIGGER_FAILURE ; END IF ; CLOSE')
        p.take(cursor); p.seq('; END ;'); p.end()
        return {'kind': 'master_existence_guard', 'query': {'table': table, 'alias': alias,
                'predicates': [{'column': column, 'reference': ref}], 'access_role': 'exists'},
                'messages': messages, 'source_order': ['open', 'fetch', 'if_found_message_close_raise', 'close'],
                'exception_handler': None}, p.receipt
    if event == 'KEY-DELREC':
        p.take('IF'); call = p.call(); p.seq('> 0 THEN')
        _need(call['arity'] == 1 and call['arguments'][0]['kind'] == 'reference', 'PERMISSION_SIGNATURE')
        messages = p.message_list(); p.seq('RAISE FORM_TRIGGER_FAILURE ; ELSE DELETE_RECORD ;')
        assignment = None
        if p.peek(':'):
            target = p.ref(); p.take(':='); value = p.ref(); p.take(';')
            assignment = {'target_reference': target, 'value_reference': value}
        p.seq('COMMIT_FORM ;')
        navigation = None
        if p.peek('GO_BLOCK'):
            p.seq('GO_BLOCK ('); block = p.take(kind='string'); p.seq(') ; NEXT_RECORD ;')
            navigation = {'block': block.upper(), 'steps': ['GO_BLOCK', 'NEXT_RECORD']}
        p.seq('END IF ;'); p.end()
        return {'kind': 'key_delete', 'permission_call': call, 'permission_predicate': '>0',
                'null_permission_branch': 'else_delete_record', 'messages': messages,
                'assignment': assignment, 'navigation': navigation, 'exception_handler': None,
                'source_order': ['permission_call', 'if_positive_message_raise', 'mark_delete'] +
                    (['summary_assignment'] if assignment else []) + ['commit_form'] +
                    (['go_block', 'next_record'] if navigation else []),
                'pre_delete_timing': 'posting_during_commit_form_not_delete_record'}, p.receipt
    _need(event == 'PRE-DELETE', 'EVENT')
    p.take('BEGIN'); audit = p.call(); p.take(';')
    _need(audit['arity'] == 5 and [a['kind'] for a in audit['arguments']] ==
          ['reference', 'reference', 'reference', 'literal', 'reference'], 'AUDIT_SIGNATURE')
    flag = p.delete() if p.peek('DELETE') else None
    p.seq('END ;')
    ddl = False; cascade = None
    if p.peek('FORMS_DDL'):
        p.seq('FORMS_DDL ('); _need(p.take(kind='string').upper() == 'COMMIT', 'DDL_ONLY_COMMIT')
        p.seq(') ; BEGIN'); ddl = True; cascade = p.delete(); p.seq('END ;')
    p.end()
    _need((flag is None and not ddl and cascade is None) or
          (flag is not None and ddl and cascade is not None and len(flag['predicates']) == 2
           and len(cascade['predicates']) == 2), 'COMPLETE_PRE_DELETE_VARIANT')
    return {'kind': 'pre_delete', 'audit_call': audit, 'flag_delete': flag,
            'forms_ddl_commit': ddl, 'cascade_delete': cascade, 'exception_handler': None,
            'source_order': ['audit_call'] +
                (['flag_delete', 'forms_ddl_commit', 'cascade_delete'] if flag else []),
            'owner_delete': 'Forms posting provider after PRE-DELETE; not present as SQL in source unit'}, p.receipt


def _field(ref, owner, objects, props, trace):
    if len(ref) == 2 and ref[0] in ('GLOBAL', 'SYSTEM'):
        return {'source_reference': ref, 'binding_kind': 'trusted_forms_context',
                'source_item_id': None, 'data_type': None, 'provider_required': True}
    item = _resolve(ref, owner, objects)
    block = objects[item['block_id']]
    declared = props[item['id']]
    dtype = declared.get('DataType', '').upper()
    _need(dtype in ('NUMBER', 'CHAR', 'VARCHAR2', 'DATE'), 'UNSUPPORTED_FIELD_TYPE')
    mapped = [f for b in trace['blocks'] if b['source_block_id'] == block['id']
              for f in b['items'] if f['source_item_id'] == item['id']]
    value = deepcopy(mapped[0]) if len(mapped) == 1 else {'source_item_id': item['id'],
            'data_type': 'VARCHAR2' if dtype == 'CHAR' else dtype, 'column': None,
            'source_name': item['name'], 'binding_kind': 'forms_buffer_only', 'provider_required': True}
    _need(value['data_type'] == ('VARCHAR2' if dtype == 'CHAR' else dtype), 'TRACE_FIELD_TYPE')
    value.update(source_reference=[block['name'].upper(), item['name'].upper()],
                 source_block_id=block['id'], source_declaration=deepcopy(declared),
                 source_database_item=declared.get('DatabaseItem', '').lower() == 'true')
    return value


def _policy(block, objects, props, units, texts):
    inheritance = []
    current = block
    while current:
        pr = props[current['id']]
        inheritance.append({'source_object_id': current['id'], 'kind': current['kind'],
                            'DeleteAllowed': pr.get('DeleteAllowed'),
                            'SubclassObjectGroup': pr.get('SubclassObjectGroup'),
                            'SubclassSource': pr.get('SubclassSource'),
                            'subclass_properties': {k:v for k,v in pr.items() if 'subclass' in k.lower() or 'inherit' in k.lower()}})
        current = objects.get(current.get('parent_id'))
    declared = props[block['id']].get('DeleteAllowed')
    static = {'true': True, 'false': False}.get((declared or '').lower())
    setters = []
    # Each active lexical setter is evidence of a possible override. Its containing
    # event/control flow must be proved separately before current permission exists.
    for unit in units:
        owner = objects[unit['owner_id']]
        if owner['module_id'] != block['module_id']:
            continue
        raw = texts[unit['id']]['text']
        if not re.search(r'\b(?:SET_BLOCK_PROPERTY|DELETE_ALLOWED)\b', raw, re.I):
            continue
        try:
            p = _Parser(raw)
        except ValueError:
            # Unknown active syntax in a unit containing a relevant property is
            # retained as unresolved evidence instead of proving setter absence.
            setters.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                            'value': None, 'control_flow_verified': False, 'lexically_unresolved': True})
            continue
        for i, token in enumerate(p.tokens):
            if token[:2] != ('token', 'SET_BLOCK_PROPERTY'):
                continue
            # Split top-level arguments; expression/dynamic block/property names
            # remain potential relevant setters, never evidence of absence.
            args, active, depth, end = [], [], 0, None
            for t in p.tokens[i+2:]:
                if t[1] == '(' and t[0] == 'token':
                    depth += 1
                elif t[1] == ')' and t[0] == 'token':
                    if depth == 0:
                        args.append(active); end=t[3]; break
                    depth -= 1
                if t[1] == ',' and t[0] == 'token' and depth == 0:
                    args.append(active); active=[]
                else:
                    active.append(t)
            target = args[0] if args else []
            prop = args[1] if len(args)>1 else []
            if len(target)==1 and target[0][0]=='string' and target[0][1].upper()!=block['name'].upper():
                continue
            if len(prop)==1 and prop[0][0]=='token' and prop[0][1] in ('INSERT_ALLOWED','UPDATE_ALLOWED','QUERY_ALLOWED'):
                continue
            known_target = len(target)==1 and target[0][0]=='string' and target[0][1].upper()==block['name'].upper()
            known_prop = len(prop)==1 and prop[0][:2]==('token','DELETE_ALLOWED')
            supplied = args[2] if len(args)==3 else []
            value = {'PROPERTY_TRUE': True, 'PROPERTY_FALSE': False}.get(supplied[0][1]) if len(supplied)==1 else None
            setters.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                            'source_owner_id': owner['id'], 'value': value,
                            'position': p.span(token[2], end or token[3]),
                            'dynamic_target_unresolved': not known_target,
                            'dynamic_property_unresolved': not known_prop,
                            'control_flow_verified': False, 'current_runtime_value': 'unknown'})
    return {'static_value': static, 'static_origin': 'explicit_block_property' if declared is not None else
            'Forms_default_or_inheritance_unverified', 'inheritance': inheritance, 'dynamic_setters': setters,
            'current_permission_provider_required': True,
            'static_false_is_current_no_delete': static is False and not setters}


def _bind(parsed, owner, objects, props, trace, files, units, texts):
    block = objects.get(owner['block_id'], {})
    _need(block.get('kind') == 'Block' and owner['parent_id'] == block['id'], 'BLOCK_EVENT_OWNER')
    mapped = _one([b for b in trace['blocks'] if b['source_block_id'] == block['id']], 'TRACE_BLOCK')
    relevant = [b for b in trace['blocks'] if b.get('source_module_id') == owner['module_id']]
    refs = []
    def collect(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if k in ('reference', 'target_reference', 'value_reference') or (k == 'parts' and value.get('kind') == 'reference'):
                    refs.append(v)
                else:
                    collect(v)
        elif isinstance(value, list):
            for v in value:
                collect(v)
    collect(parsed)
    fields = [_field(ref, owner, objects, props, trace) for ref in refs]
    fields = list({tuple(f['source_reference']): f for f in fields}.values())
    relations = []; unresolved_relations = []
    for rel in objects.values():
        if rel['kind'] != 'Relation' or rel['module_id'] != owner['module_id']:
            continue
        parent = objects[rel['block_id']]
        pr = props[rel['id']]
        try:
            child = _one([b for b in objects.values() if b['kind'] == 'Block' and b['module_id'] == owner['module_id']
                          and b['name'].upper() == pr.get('DetailBlock', '').upper()], 'RELATION_CHILD')
            _need(pr.get('RelationType', '').upper() == 'JOIN', 'JOIN_RELATION_REQUIRED')
            pairs = parse_join_condition(pr.get('JoinCondition'), parent['name'], child['name'])
        except ValueError as exc:
            unresolved_relations.append({'source_relation_id':rel['id'],'reason':str(exc)})
            continue
        relations.append({'source_relation_id': rel['id'], 'parent_block_id': parent['id'],
                          'child_block_id': child['id'], 'join_pairs': [list(v) for v in pairs],
                          'source_properties': deepcopy(pr)})
    c = {'block': deepcopy(mapped), 'blocks': deepcopy(relevant), 'fields': fields,
         'relations': relations, 'unresolved_relations':unresolved_relations,
         'delete_policy': _policy(block, objects, props, units, texts),
         'current_policy_provider': None, 'external_provider': None, 'whole_form_commit_provider': None}
    def resolve(ref):
        return _field(ref, owner, objects, props, trace)
    def prove(mapped_block, projected):
        original = objects[mapped_block['source_block_id']]
        _need(original['name'] == mapped_block['name'], 'TRACE_BLOCK_NAME')
        _need(props[original['id']].get('DatabaseBlock', '').lower() == 'true', 'DATABASE_BLOCK_REQUIRED')
        _table_proof(files, mapped_block, projected)
    prove(mapped, {f['column'] for f in fields if f.get('source_block_id')==block['id'] and f.get('column')})
    for f in fields:
        if f.get('column'):
            bound_block = _one([b for b in relevant if b['source_block_id']==f['source_block_id']], 'FIELD_BLOCK')
            prove(bound_block,{f['column']})
    def child_query(query):
        child = _one([b for b in objects.values() if b['kind'] == 'Block' and b['module_id'] == owner['module_id']
                      and props[b['id']].get('QueryDataSourceName', '').upper() == query['table']
                      and props[b['id']].get('QueryDataSourceType', '').upper() == 'TABLE'], 'SQL_CHILD_TABLE')
        pairs = []
        for term in query['predicates']:
            item = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == child['id']
                         and (props[o['id']].get('ColumnName') or o['name']).upper() == term['column']
                         and props[o['id']].get('DatabaseItem', '').lower() == 'true'], 'SQL_CHILD_COLUMN')
            pairs.append({'child_field': _field([child['name'].upper(), item['name'].upper()], owner, objects, props, trace),
                          'parent_field': resolve(term['reference'])})
        rel = _one([r for r in relations if r['parent_block_id'] == block['id'] and r['child_block_id'] == child['id']
                    and set(tuple(x) for x in r['join_pairs']) ==
                    {(p['parent_field']['source_reference'][-1], p['child_field']['source_reference'][-1]) for p in pairs}], 'EXACT_SQL_RELATION')
        _need(all(p['parent_field']['source_block_id'] == block['id'] and p['child_field']['column']
                  and p['parent_field']['column'] and p['parent_field']['data_type'] == p['child_field']['data_type'] for p in pairs), 'EXACT_RELATION_TYPES')
        child_mapped = _one([b for b in relevant if b['source_block_id'] == child['id']], 'MAPPED_SQL_CHILD')
        prove(child_mapped,{p['child_field']['column'] for p in pairs})
        return {'child_block': deepcopy(child_mapped),
                'predicates': pairs, 'source_relation_id': rel['source_relation_id'],
                'delete_record': rel['source_properties'].get('DeleteRecord')}
    if parsed['kind'] == 'master_existence_guard':
        c['existence_guard'] = child_query(parsed['query'])
        _need(c['existence_guard']['delete_record'] == 'Non Isolated', 'NON_ISOLATED_RELATION_REQUIRED')
    if parsed['kind'] == 'pre_delete' and parsed['cascade_delete']:
        c['cascade'] = child_query(parsed['cascade_delete'])
        _need(c['cascade']['delete_record'] == 'Cascading', 'CASCADING_RELATION_REQUIRED')
        # Both flag keys must bind exactly to the owning composite relation keys.
        own_refs = {tuple(resolve(t['reference'])['source_reference']) for t in parsed['flag_delete']['predicates']}
        cascade_refs = {tuple(p['parent_field']['source_reference']) for p in c['cascade']['predicates']}
        _need(own_refs == cascade_refs, 'FLAG_AND_CASCADE_EXACT_SCOPE')
    if parsed['kind'] == 'key_delete':
        gate = resolve(parsed['permission_call']['arguments'][0]['parts'])
        _need(gate['source_block_id'] == block['id'] and gate['column'] is not None, 'PERMISSION_CURRENT_ROW')
        c['permission_argument'] = gate
        if parsed['assignment']:
            c['summary_assignment'] = {k: resolve(v) for k,v in parsed['assignment'].items()}
            _need(all(f['data_type'] == 'NUMBER' for f in c['summary_assignment'].values()), 'NUMERIC_SUMMARY')
        if parsed['navigation']:
            c['navigation_block'] = deepcopy(_one([b for b in relevant if b['name'].upper() == parsed['navigation']['block']], 'NAVIGATION_BLOCK'))
    return c


def build_delete_plan(documents, packet, chunks, trace, files):
    """Rebuild authority from exact XML; never infer permission from block names."""
    actual, actual_chunks = _build(documents)
    _need(type(packet) is dict and all(packet.get(k) == v for k,v in actual.items()) and chunks == actual_chunks,
          'SOURCE_BINDING')
    _need(trace.get('source_binding') == actual['source_binding'] and
          json.loads(files['fox-package/source-to-page.json']) == trace, 'TRACE_BINDING')
    manifest = json.loads(files['fox-package/source-manifest.json'])
    _need(manifest['source_binding'] == packet['source_binding'] and manifest['selected_chunk_hashes'] ==
          {c['id']:c['sha256'] for c in chunks} and manifest['files'] ==
          [{k:s['source'][k] for k in ('name','sha256','bytes')} for s in packet['sources']], 'MANIFEST_BINDING')
    for name, raw in documents:
        _need(files['fox-package/sources/' + name] == raw, 'ORIGINAL_SOURCE')
    objects, props = _source_objects(documents, actual)
    units = [u for s in actual['sources'] for u in s['facts']['code_units']]
    texts = {c['code_unit_id']: c for c in chunks}
    plan = {'schema_version': 1, 'scope': SCOPE, 'source_binding': actual['source_binding'],
            'operations': [], 'gaps': [], 'whole_source_unit_converted': False,
            'runtime_verified': False, 'customer_dml_executed': False, 'business_accepted': False}
    for unit in units:
        owner = objects[unit['owner_id']]
        event = (owner['name'] or '').upper()
        if owner['kind'] != 'Trigger' or event not in ('ON-CHECK-DELETE-MASTER','KEY-DELREC','PRE-DELETE'):
            continue
        row = {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
               'source_chunk_id': texts[unit['id']]['id'], 'source_owner_id': owner['id'],
               'source_module_id': owner['module_id'], 'source_block_id': owner['block_id'],
               'source_event': event, 'operation_id': 'fdp1-' + _sha([packet['source_binding'], unit['id']])[:24]}
        try:
            parsed, decode = parse_delete_source(texts[unit['id']]['text'], event)
            row.update(kind=parsed['kind'], parsed=parsed, decode_receipt=decode)
            row['contract'] = _bind(parsed, owner, objects, props, trace, files, units, texts)
            row['whole_source_unit_converted'] = False
            row['status'] = 'source_bound_local_model_and_native_preflight_only'
            plan['operations'].append(row)
        except ValueError as exc:
            plan['gaps'].append({**row, 'reason': str(exc), 'stage': 'complete_parse_or_binding'})
    for op in plan['operations']:
        if op['kind'] == 'key_delete':
            paired = [p for p in plan['operations'] if p['kind'] == 'pre_delete'
                      and p['source_block_id'] == op['source_block_id']]
            if len(paired) == 1:
                op.update(paired_pre_delete_unit_id=paired[0]['source_unit_id'],
                          paired_pre_delete_sha256=paired[0]['source_unit_sha256'],
                          paired_pre_delete_timing='posting_during_commit_form')
        for callname in ('permission_call', 'audit_call'):
            if callname in op['parsed']:
                call = op['parsed'][callname]
                call.update(source_unit_id=op['source_unit_id'], source_unit_sha256=op['source_unit_sha256'],
                            call_site_id='fdc1-' + _sha([op['source_unit_id'],op['source_unit_sha256'],call])[:24])
        op['external_calls'] = [{**deepcopy(op['parsed'][name]), 'role': role} for name,role in
                                (('permission_call','delete_permission'),('audit_call','delete_audit'))
                                if name in op['parsed']]
        op['table_accesses'] = [deepcopy(op['parsed'][name]) for name in
                                ('query','flag_delete','cascade_delete') if op['parsed'].get(name)]
        op['stages'] = [{'id': name, 'ordinal': i, 'source_unit_id': op['source_unit_id'],
                         'condition': 'permission_return_not_positive_including_null' if op['kind']=='key_delete' and i>2 else
                         'cursor_found' if name=='if_found_message_close_raise' else
                         'permission_return_positive' if name=='if_positive_message_raise' else 'normal_source_sequence',
                         'provider_required': name in ('permission_call','audit_call','mark_delete','summary_assignment','commit_form','forms_ddl_commit','go_block','next_record')}
                        for i,name in enumerate(op['parsed']['source_order'],1)]
        op['operation_sha256'] = _sha(op)
    plan['plan_sha256'] = _sha(plan)
    return deepcopy(plan)


@dataclass(frozen=True)
class DeleteOutcome:
    """Explicit fixture adapter result. A returned NULL is a known value."""
    status: Literal['completed', 'failed', 'unmet', 'unknown']
    value: Any = None
    committed: bool | None = None
    reason: str = ''


@dataclass(frozen=True)
class DeleteStage:
    id: str
    kind: str
    source_unit_id: str
    payload: dict


class DeleteAdapter(Protocol):
    def perform(self, stage: DeleteStage) -> DeleteOutcome: ...


class _Stop(Exception):
    pass


def execute_delete_model(operation, adapter=None, *, connection=None, references=None):
    """Execute proved predicates/DML only on an explicitly supplied disposable DB.

    Qualified routines, trusted context, buffer marking, whole-form posting,
    assignment, navigation and commits require explicit fixture-bound adapters.
    SQL failure preserves prior effects; this model never rolls back or retries.
    A key event does not invoke PRE-DELETE on marking or invent its posting order.
    The commit_form adapter is responsible for all actual posting dependencies.
    """
    _need(operation.get('operation_sha256') == _sha({k:v for k,v in operation.items() if k != 'operation_sha256'}),
          'IMMUTABLE_OPERATION_BINDING')
    parsed = operation['parsed']
    result = {'scope': 'disposable_sql_and_explicit_adapter_model', 'source_unit_id': operation['source_unit_id'],
              'events': [], 'messages': [], 'sql_effects': [], 'commit_history': [], 'pending': [],
              'status': 'running', 'marked': False, 'posted': False, 'committed': None,
              'rolled_back': False, 'runtime_verified': False, 'business_accepted': False}
    references = references or {}
    def stop(status, reason, stage):
        result['status'] = status
        result['pending'].append({'stage_id': stage, 'reason': reason})
        raise _Stop()
    def external(name, kind, payload):
        try:
            outcome = adapter.perform(DeleteStage(name, kind, operation['source_unit_id'], deepcopy(payload))) if adapter else DeleteOutcome('unmet', reason='provider_missing')
        except Exception as exc:
            outcome = DeleteOutcome('unknown', reason=type(exc).__name__)
        if not isinstance(outcome, DeleteOutcome) or outcome.status not in ('completed','failed','unmet','unknown'):
            stop('unknown', 'invalid_provider_receipt', name)
        row = {'stage_id': name, 'kind': kind, 'status': outcome.status, 'value': deepcopy(outcome.value),
               'committed': outcome.committed, 'reason': outcome.reason}
        result['events'].append(row)
        if kind in ('forms_ddl_commit','commit_form'):
            result['commit_history'].append(deepcopy(row))
            # Even a failed invocation can explicitly report earlier commit.
            if outcome.committed is not None:
                result['committed'] = outcome.committed
        if outcome.status != 'completed':
            stop(outcome.status, outcome.reason or 'provider_' + outcome.status, name)
        if kind in ('forms_ddl_commit','commit_form') and type(outcome.committed) is not bool:
            # The source has no FORM_SUCCESS check here. A normal-return status
            # cannot establish commit, but must not invent a source stop branch.
            result['pending'].append({'stage_id': name, 'reason': 'transaction_completion_unknown'})
        return outcome
    def context(ref, name):
        candidates = [tuple(ref)]
        fields = [f for f in operation['contract']['fields'] if f.get('source_item_id') and
                  f['source_reference'][-1] == ref[-1] and (len(ref)==1 or f['source_reference']==ref)]
        if len(ref)==1:
            local = [f for f in fields if f.get('source_block_id')==operation['source_block_id']]
            fields = local or fields
        if len(fields)>1:
            stop('unknown', 'ambiguous_reference_binding', name)
        candidates.extend(tuple(field['source_reference']) for field in fields)
        values = [references[k] for k in dict.fromkeys(candidates) if k in references]
        if len(values) != 1:
            stop('unmet', 'exact_current_reference_required', name)
        return None if values[0] == '' else values[0]
    def arguments(call, name):
        return [context(a['parts'], name) if a['kind'] == 'reference' else a['value'] for a in call['arguments']]
    def sql(query, name, exists=False):
        if connection is None:
            stop('unmet', 'disposable_connection_required', name)
        values = [context(t['reference'], name) for t in query['predicates']]
        terms = ' AND '.join(t['column'] + '=?' for t in query['predicates'])
        statement = ('SELECT 1 FROM ' if exists else 'DELETE FROM ') + query['table'] + ' WHERE ' + terms
        if exists:
            statement += ' LIMIT 1'
        try:
            cursor = connection.execute(statement, values)
            value = cursor.fetchone() is not None if exists else cursor.rowcount
        except Exception as exc:
            stop('failed', 'sql_' + type(exc).__name__, name)
        row = {'stage_id': name, 'kind': 'exists' if exists else 'sql_delete', 'sql': statement,
               'value': value, 'transaction_completed': False}
        result['events'].append(row)
        if not exists:
            result['sql_effects'].append(deepcopy(row))
        return value
    try:
        if parsed['kind'] == 'master_existence_guard':
            found = sql(parsed['query'], 'master_exists', True)
            result['matching_children'] = found
            if found:
                result['messages'] = deepcopy(parsed['messages'])
                result['status'] = 'form_trigger_failure'
            else:
                result['status'] = 'guard_passed_no_delete_authority'
        elif parsed['kind'] == 'key_delete':
            permission = external('permission_call', 'qualified_function', {
                'call_site': parsed['permission_call'], 'arguments': arguments(parsed['permission_call'], 'permission_call')}).value
            if permission is not None and (isinstance(permission, bool) or not isinstance(permission, (int,float,Decimal))):
                stop('unknown', 'numeric_or_known_null_permission_required', 'permission_call')
            if isinstance(permission,Decimal) and not permission.is_finite():
                stop('unknown', 'finite_permission_required', 'permission_call')
            if isinstance(permission,float) and (permission != permission or abs(permission) == float('inf')):
                stop('unknown', 'finite_permission_required', 'permission_call')
            if permission is not None and permission > 0:
                result['messages'] = deepcopy(parsed['messages']); result['status'] = 'form_trigger_failure'
            else:
                policy = external('current_delete_policy', 'current_policy', operation['contract']['delete_policy'])
                if policy.value is not True:
                    stop('blocked', 'current_delete_permission_not_proved', 'current_delete_policy')
                external('mark_delete', 'delete_record_buffer_mark', {'posting': False})
                result['marked'] = True
                if parsed['assignment']:
                    assignment = parsed['assignment']
                    value = context(assignment['value_reference'], 'summary_assignment')
                    external('summary_assignment', 'buffer_assignment', {**assignment, 'value': value})
                commit = external('commit_form', 'commit_form', {
                    'whole_form': True, 'posting_pre_delete_unit_id': operation.get('paired_pre_delete_unit_id'),
                    'posting_pre_delete_sha256': operation.get('paired_pre_delete_sha256'),
                    'all_validation_and_posting_providers_required': True})
                if type(commit.value) is not dict or type(commit.value.get('posted')) is not bool:
                    stop('unknown', 'posting_outcome_unknown', 'commit_form')
                result['posted'] = commit.value['posted']
                if parsed['navigation']:
                    external('go_block', 'forms_navigation', {'block': parsed['navigation']['block']})
                    external('next_record', 'forms_navigation', {'step': 'NEXT_RECORD'})
                result['status'] = ('completed' if result['posted'] is True and result['committed'] is True else
                                    'source_sequence_completed_deletion_unconfirmed')
        else:
            external('audit_call', 'qualified_procedure', {
                'call_site': parsed['audit_call'], 'arguments': arguments(parsed['audit_call'], 'audit_call')})
            if parsed['flag_delete']:
                sql(parsed['flag_delete'], 'flag_delete')
                external('forms_ddl_commit', 'forms_ddl_commit', {'sql': 'COMMIT', 'scope': 'all_pending_database_work'})
                sql(parsed['cascade_delete'], 'cascade_delete')
            result['status'] = 'pre_delete_completed_owner_posting_pending'
    except _Stop:
        pass
    if result['pending'] and result['status'] in ('completed','pre_delete_completed_owner_posting_pending','source_sequence_completed_deletion_unconfirmed'):
        result['status'] = 'source_sequence_completed_transaction_outcome_unknown'
    result['partial_outcome'] = bool(result['sql_effects'] or result['marked'] or result['committed'] is True) and result['status'] not in ('completed','pre_delete_completed_owner_posting_pending')
    return result
