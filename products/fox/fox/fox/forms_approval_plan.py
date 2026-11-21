"""Closed source-bound approval workflow and an adapter-driven local model.

This is an encoding of a complete Forms event, not authority to execute customer
DML. Each commit and external invocation needs its own explicit target outcome.
The model never retries an invocation or infers success from a missing provider.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Literal, Protocol, TypedDict

from .forms_behavior_plan import _source_objects
from .forms_item_validation import _resolve
from .forms_relation_plan import parse_join_condition
from .forms_synthetic_save import _table_proof
from .forms_understanding_packet import _build
from forms2apex.record_buffer import decode_source

SCOPE = 'fox-source-approval-workflow-v1'
_IDENT = r'[A-Z][A-Z0-9_$#]{0,127}'


class WorkflowStage(TypedDict):
    id: str
    kind: str
    condition: str
    ordinal: int
    source_unit_id: str
    source_unit_sha256: str
    required_capabilities: list[str]
    provider_status: str


class ApprovalContract(TypedDict):
    blocks: dict[str, dict]
    fields: dict[str, dict]
    relations: list[dict]
    authority: str
    whole_form_commit_provider: None
    external_provider: None


class ApprovalWorkflow(TypedDict, total=False):
    operation_id: str
    operation_sha256: str
    source_unit_id: str
    source_unit_sha256: str
    source_chunk_id: str
    source_owner_id: str
    source_module_id: str
    button_item_id: str
    parsed: dict
    contract: ApprovalContract
    readiness_contract: ApprovalContract
    stages: list[WorkflowStage]
    transaction_boundaries: list[dict]
    status: str


class ApprovalPlan(TypedDict):
    schema_version: int
    scope: str
    source_binding: str
    operations: list[ApprovalWorkflow]
    gaps: list[dict]
    full_event_converted: bool
    runtime_verified: bool
    customer_dml_executed: bool
    business_accepted: bool
    plan_sha256: str


def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False).encode()).hexdigest()


def _need(value, reason):
    if not value:
        raise ValueError('APPROVAL_' + reason)


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


class _Parser:
    def __init__(self, raw):
        self.text, self.receipt = decode_source(raw)
        self.tokens = []
        pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|:=|\|\||" +
                             _IDENT + r'|[0-9]+|[:.,();=>]', re.I | re.S)
        pos = 0
        while pos < len(self.text):
            match = pattern.match(self.text, pos)
            _need(match is not None, 'ACTIVE_TOKEN_AT_' + str(pos))
            token, pos = match[0], match.end()
            if token.isspace() or token.startswith(('--', '/*')):
                continue
            self.tokens.append(('string', token[1:-1].replace("''", "'"), match.start(), pos)
                               if token.startswith("'") else ('token', token.upper(), match.start(), pos))
            _need(len(self.tokens) <= 1600, 'TOKEN_CAPACITY')
        self.i = 0

    def peek(self, value):
        return self.i < len(self.tokens) and self.tokens[self.i][:2] == ('token', value)

    def take(self, value=None, kind='token'):
        offset = self.tokens[self.i][2] if self.i < len(self.tokens) else len(self.text)
        actual = self.tokens[self.i][1] if self.i < len(self.tokens) else 'EOF'
        _need(self.i < len(self.tokens) and self.tokens[self.i][0] == kind and
              (value is None or actual == value),
              f'EXPECTED_{value or kind}_AT_{offset}_FOUND_{actual[:50]}')
        self.i += 1
        return actual

    def seq(self, words):
        for word in words.split():
            self.take(word)

    def ident(self):
        result = self.take()
        _need(re.fullmatch(_IDENT, result), 'IDENTIFIER')
        return result

    def ref(self):
        self.take(':')
        parts = [self.ident()]
        if self.peek('.'):
            self.take('.')
            parts.append(self.ident())
        return parts

    def same(self, parts):
        _need(self.ref() == parts, 'REFERENCE_DIFFERS_AT_' + str(self.i))

    def messages(self, counter=None):
        result = []
        while self.peek('MESSAGE'):
            self.seq('MESSAGE (')
            message = self.take(kind='string')
            _need(0 < len(message.encode()) <= 1000 and all(c.isprintable() for c in message), 'MESSAGE_CAPACITY')
            if counter:
                self.take('||')
                self.take(counter)
            self.seq(') ;')
            result.append(message)
            _need(len(result) <= 4, 'MESSAGE_COUNT')
        _need(result, 'MESSAGE_REQUIRED')
        self.seq('RAISE FORM_TRIGGER_FAILURE ; END IF ;')
        return result

    def level(self, saved=None):
        self.same(['SYSTEM', 'MESSAGE_LEVEL'])
        self.take(':=')
        self.take(saved or '5')
        self.take(';')

    def commit(self, saved):
        self.level()
        self.seq('COMMIT_FORM ;')
        self.level(saved)

    def external(self):
        start = self.tokens[self.i][2]
        callee = self.ident() + self.take('.') + self.ident()
        self.take('(')
        args = []
        while True:
            if self.peek(':'):
                args.append({'kind': 'reference', 'parts': self.ref()})
            else:
                args.append({'kind': 'literal', 'value': self.take(kind='string')})
            if not self.peek(','):
                break
            self.take(',')
        self.seq(') ;')
        end = self.tokens[self.i - 2][3]
        return {'callee': callee, 'arguments': args, 'position': {
            'character_offset': start, 'end_character_offset': end,
            'line': self.text.count('\n',0,start)+1,
            'column': start-self.text.rfind('\n',0,start)},
            'observed_source': self.text[start:end],
            'formal_types': 'unknown', 'formal_directions': 'unknown',
            'target_availability': 'unverified', 'retry_policy': 'none_in_source'}


def parse_approval(raw):
    """Consume every active token of the finite complete approval event grammar."""
    p = _Parser(raw)
    p.take('DECLARE')
    count = p.ident(); p.seq('NUMBER := 0 ;')
    missing = p.ident(); p.seq('VARCHAR2 ('); capacity = int(p.take()); p.seq(') := NULL ;')
    saved = p.ident(); p.seq('NUMBER ;')
    weight_count = p.ident(); p.seq('NUMBER ; BEGIN SELECT COUNT ( 0 ) INTO'); p.take(weight_count)
    _need(len({count, missing, saved, weight_count}) == 4 and 1 <= capacity <= 4000, 'LOCALS')
    p.take('FROM'); bag_table = p.ident(); p.seq('WHERE NVL ('); weight = p.ident()
    p.seq(', 0 ) = 0 AND'); bag_parent = p.ident(); p.take('='); header_key = p.ref(); p.take(';')
    p.take('IF'); p.take(weight_count); p.seq('> 0 THEN')
    messages = {'weight': p.messages()}
    p.take('IF'); destination = p.ref(); p.seq('IS NULL THEN'); messages['destination'] = p.messages()
    p.seq('GO_ITEM ('); focus = p.take(kind='string'); p.seq(') ;')
    p.take(saved); p.take(':='); p.same(['SYSTEM', 'MESSAGE_LEVEL']); p.take(';')
    p.take('IF'); p.same(['SYSTEM', 'FORM_STATUS']); p.take('='); p.take('CHANGED', 'string'); p.take('THEN')
    p.commit(saved); p.seq('END IF ; IF FORM_SUCCESS THEN GO_BLOCK (')
    bag_block = p.take(kind='string'); p.seq(') ; FIRST_RECORD ; IF'); bag_key = p.ref()
    p.seq('IS NOT NULL THEN LOOP'); bag_route = p.ref(); p.take(':='); header_route = p.ref(); p.take(';')
    p.take('IF'); p.same(['SYSTEM', 'LAST_RECORD']); p.take('='); p.take('TRUE', 'string')
    p.seq('THEN EXIT ; END IF ; NEXT_RECORD ; END LOOP ; FIRST_RECORD ; END IF ;')
    p.commit(saved)
    p.seq('BEGIN SELECT COUNT ( 0 ) INTO'); p.take(count); p.take('FROM'); p.take(bag_table)
    p.take('WHERE'); p.take(bag_parent); p.take('='); p.same(header_key)
    p.seq('; EXCEPTION WHEN OTHERS THEN NULL ; END ; IF'); p.take(count); p.seq('= 0 THEN')
    messages['no_bags'] = p.messages()
    p.seq('BEGIN SELECT'); bag_projection = p.ident(); p.take('INTO'); p.take(missing)
    p.take('FROM'); p.take(bag_table); p.take('WHERE'); p.take(bag_parent); p.take('='); p.same(header_key)
    p.seq('AND NOT EXISTS ( SELECT 1 FROM'); consignment_table = p.ident(); p.take('WHERE')
    consignment_key = p.ident(); p.take('='); p.take(bag_projection); p.take('AND')
    consignment_parent = p.ident(); p.take('='); p.take(bag_parent)
    p.seq(') AND ROWNUM = 1 ; EXCEPTION WHEN OTHERS THEN NULL ; END ; IF')
    p.take(missing); p.seq('IS NOT NULL THEN'); messages['missing_consignment'] = p.messages(missing)
    p.seq('IF FORM_SUCCESS THEN'); approved = p.ref(); p.take(':='); approval_value = p.take(kind='string'); p.take(';')
    _need(approval_value and len(approval_value) <= 100, 'APPROVAL_LITERAL_CAPACITY')
    p.commit(saved)
    calls = [p.external(), p.external()]
    p.seq('END IF ; END IF ;')
    final_start = p.tokens[p.i][2]
    final_call = p.ident(); final_end = p.tokens[p.i-1][3]
    p.take(';'); p.level(saved)
    p.seq('EXCEPTION WHEN OTHERS THEN'); p.level(saved); p.seq('END ;')
    _need(p.i == len(p.tokens), 'EXTRA_ACTIVE_SOURCE_AT_' + str(p.tokens[p.i][2] if p.i < len(p.tokens) else 0))
    _need(focus.upper().split('.')[-1] == header_key[-1], 'FOCUS_HEADER_KEY')
    _need(len(bag_key) in (1, 2) and bag_key[-1] == bag_projection, 'BAG_CURSOR_KEY')
    _need(len(calls[0]['arguments']) == 2 and calls[0]['arguments'][0] == {'kind':'reference','parts':header_key}
          and calls[0]['arguments'][1]['kind'] == 'literal', 'FIRST_EXTERNAL_ARGUMENTS')
    a = calls[1]['arguments']
    _need(len(a) == 5 and a[0]['kind'] == 'reference' and len(a[0]['parts']) == 2
          and a[0]['parts'][-1] == consignment_parent and a[1] == {'kind':'reference','parts':['SYSTEM','CURRENT_FORM']}
          and a[2]['kind'] == 'reference' and len(a[2]['parts']) == 2 and a[2]['parts'][0] == 'GLOBAL'
          and all(v['kind'] == 'literal' for v in a[3:]), 'SECOND_EXTERNAL_ARGUMENTS')
    return {'refs': {'header_key': header_key, 'destination': destination, 'header_route': header_route,
                     'approved': approved, 'bag_key': bag_key, 'bag_route': bag_route},
            'bag_block': bag_block.upper(), 'focus_item': focus, 'messages': messages,
            'approval_value': approval_value, 'external_calls': calls, 'final_call': final_call,
            'final_call_site': {'callee':final_call,'arguments':[],
                'position':{'character_offset':final_start,'end_character_offset':final_end,
                            'line':p.text.count('\n',0,final_start)+1,
                            'column':final_start-p.text.rfind('\n',0,final_start)},
                'observed_source':p.text[final_start:final_end]},
            'locals': {'bag_count_initial': 0, 'missing_consignment_initial': None,
                       'missing_consignment_capacity': capacity, 'saved_message_level_initial': None},
            'queries': {
                'weight_count': {'table': bag_table, 'value_column': weight, 'parent_column': bag_parent,
                                 'bind_ref': header_key, 'predicate': 'NVL(value,0)=0', 'exception': 'outer'},
                'bag_count': {'table': bag_table, 'parent_column': bag_parent, 'bind_ref': header_key,
                              'exception': 'OTHERS_NULL', 'exception_default': 0},
                'missing_consignment': {'table': bag_table, 'projection': bag_projection,
                    'parent_column': bag_parent, 'bind_ref': header_key, 'not_exists_table': consignment_table,
                    'child_key_column': consignment_key, 'child_parent_column': consignment_parent,
                    'rownum': 1, 'ordering': None, 'exception': 'OTHERS_NULL', 'exception_default': None}},
            'outer_exception': {'when': 'OTHERS', 'action': 'restore_saved_message_level',
                                'reraises': False, 'rollback': False,
                                'before_capture_saved_value': None}}, p.receipt


def _column_item(block, column, objects, props):
    return _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id']
                 and props[o['id']].get('DatabaseItem', '').lower() == 'true'
                 and props[o['id']].get('ColumnName', '').upper() == column], 'EXACT_SOURCE_COLUMN_' + column)


def _bind(parsed, owner, objects, props, trace, files):
    button = objects.get(owner['parent_id'], {})
    _need(button.get('kind') == 'Item' and props[button['id']].get('ItemType', '').upper() == 'PUSH BUTTON', 'PUSH_BUTTON_OWNER')
    header = objects[owner['block_id']]
    _need(header['id'] == button['block_id'], 'BUTTON_HEADER')
    bag = _one([b for b in objects.values() if b['kind'] == 'Block' and b['module_id'] == owner['module_id']
                and b['name'].upper() == parsed['bag_block']], 'BAG_BLOCK')
    cq = parsed['queries']['missing_consignment']
    bag_props = props[bag['id']]
    _need(bag_props.get('QueryDataSourceType', '').upper() == 'TABLE'
          and bag_props.get('QueryDataSourceName', '').upper() == cq['table'], 'EXACT_BAG_TABLE')
    consignment = _one([b for b in objects.values() if b['kind'] == 'Block' and b['module_id'] == owner['module_id']
                       and props[b['id']].get('QueryDataSourceType', '').upper() == 'TABLE'
                       and props[b['id']].get('QueryDataSourceName', '').upper() == cq['not_exists_table']], 'EXACT_CONSIGNMENT_TABLE')
    _need(len({header['id'], bag['id'], consignment['id']}) == 3, 'THREE_DISTINCT_BLOCKS')
    items = {role: _resolve(ref, owner if not role.startswith('bag_') else bag, objects)
             for role, ref in parsed['refs'].items()}
    items.update(bag_parent=_column_item(bag, cq['parent_column'], objects, props),
                 bag_weight=_column_item(bag, parsed['queries']['weight_count']['value_column'], objects, props),
                 consignment_key=_column_item(consignment, cq['child_key_column'], objects, props),
                 consignment_parent=_column_item(consignment, cq['child_parent_column'], objects, props))
    _need(items['bag_key']['id'] == _column_item(bag, cq['projection'], objects, props)['id'], 'BAG_PROJECTION')
    for role, item in items.items():
        expected = bag if role.startswith('bag_') else consignment if role.startswith('consignment_') else header
        _need(item['block_id'] == expected['id'], 'FIELD_BLOCK_' + role)
    _need(_resolve(parsed['external_calls'][1]['arguments'][0]['parts'], owner, objects)['id'] == items['consignment_parent']['id'], 'EXTERNAL_CURRENT_CONSIGNMENT')
    blocks = {}
    fields = {}
    for role, block in (('header', header), ('bag', bag), ('consignment', consignment)):
        mapped = deepcopy(_one([b for b in trace['blocks'] if b['source_block_id'] == block['id']], 'TRACE_BLOCK'))
        _need(mapped.get('source_module_id') == owner['module_id'] and mapped['name'] == block['name'], 'TRACE_BLOCK_IDENTITY')
        _table_proof(files, mapped, {f['column'] for f in mapped['items']})
        blocks[role] = mapped
        for name, item in items.items():
            if item['block_id'] != block['id']:
                continue
            field = deepcopy(_one([f for f in mapped['items'] if f['source_item_id'] == item['id']], 'TRACE_FIELD_' + name))
            dtype = 'NUMBER' if name == 'bag_weight' else 'VARCHAR2'
            _need(field['data_type'] == dtype and field['source_name'] == item['name']
                  and props[item['id']].get('DataType', '').upper() in (('NUMBER',) if dtype == 'NUMBER' else ('CHAR','VARCHAR2')), 'FIELD_TYPE_' + name)
            field.update(source_ref=[block['name'].upper(), item['name'].upper()], source_block_id=block['id'])
            fields[name] = field
    relations = []
    for parent, child, expected in ((header, bag, {('header_key','bag_parent')}),
                                  (bag, consignment, {('bag_key','consignment_key'),('bag_parent','consignment_parent')})):
        rel = _one([r for r in objects.values() if r['kind'] == 'Relation' and r['block_id'] == parent['id']
                    and props[r['id']].get('DetailBlock','').upper() == child['name'].upper()], 'EXPLICIT_RELATION')
        _need(props[rel['id']].get('RelationType','').upper() == 'JOIN', 'JOIN_RELATION')
        pairs = parse_join_condition(props[rel['id']].get('JoinCondition'), parent['name'], child['name'])
        _need(set(pairs) == {(items[a]['name'].upper(),items[b]['name'].upper()) for a,b in expected}, 'EXACT_RELATION_KEYS')
        relations.append({'source_relation_id': rel['id'], 'parent_block_id': parent['id'],
                          'child_block_id': child['id'], 'join_pairs': [list(p) for p in pairs],
                          'source_properties': deepcopy(props[rel['id']])})
    # Stable semantic aliases support the native read-only readiness renderer.
    for alias, role in {'bag_header_key':'bag_parent','bag_number':'bag_key','weight':'bag_weight',
                        'consignment_header_key':'consignment_parent','consignment_bag_number':'consignment_key'}.items():
        fields[alias] = deepcopy(fields[role])
    return {'blocks': blocks, 'fields': fields, 'relations': relations,
            'authority': 'exact_source_items_columns_declared_relations_and_synthetic_ddl',
            'whole_form_commit_provider': None, 'external_provider': None}


STAGES = (
    ('weight_count','query','always'), ('weight_guard','guard','weight_count>0'),
    ('destination_guard','guard','destination is null'), ('focus_header','cursor','always'),
    ('capture_message_level','context','always'), ('dirty_commit','commit','form_status=CHANGED'),
    ('form_success_routes','branch','FORM_SUCCESS'), ('focus_bags','cursor','form_success_routes'),
    ('route_copy','iterate_assign','form_success_routes and first_bag_key is not null'),
    ('route_commit','commit','form_success_routes'), ('bag_count','query','form_success_routes'),
    ('bag_guard','guard','bag_count=0'), ('missing_consignment','query','form_success_routes'),
    ('consignment_guard','guard','missing_consignment is not null'),
    ('form_success_approval','branch','form_success_routes and FORM_SUCCESS'),
    ('approval_assignment','assign','form_success_approval'), ('approval_commit','commit','form_success_approval'),
    ('external_1','qualified_call','form_success_approval'), ('external_2','qualified_call','form_success_approval'),
    ('final_policy','local_call','normal path'), ('restore_message_level','context','normal path'),
    ('outer_exception','exception','OTHERS: restore only; no rollback or rethrow'),
)


CAPABILITIES = {
    'weight_count': ('saved_bag_query_exact_parent_key_and_numeric_null_semantics',),
    'destination_guard': ('current_header_destination_buffer',),
    'focus_header': ('forms_go_item_validation_and_navigation',),
    'capture_message_level': ('forms_message_level_context',),
    'dirty_commit': ('whole_form_dirty_buffers', 'indirect_validation_and_write_triggers',
                     'explicit_commit_receipt', 'forms_message_level_context'),
    'form_success_routes': ('observed_forms_success_after_navigation_or_dirty_commit',),
    'focus_bags': ('current_related_bag_block_buffer_and_cursor',),
    'route_copy': ('current_related_bag_block_buffer_and_cursor', 'current_header_route_buffer',
                   'first_last_next_record_semantics', 'typed_current_bag_route_assignment'),
    'route_commit': ('whole_form_dirty_buffers', 'indirect_validation_and_write_triggers',
                     'explicit_commit_receipt', 'forms_message_level_context'),
    'bag_count': ('saved_bag_query_exact_parent_key', 'source_query_exception_outcome'),
    'missing_consignment': ('saved_bag_consignment_query_both_relation_keys', 'rownum_one_without_invented_order',
                            'source_select_into_length_semantics', 'source_query_exception_outcome'),
    'form_success_approval': ('observed_forms_success_after_route_commit_and_queries',),
    'approval_assignment': ('current_header_approval_buffer', 'current_local_approval_policy'),
    'approval_commit': ('whole_form_dirty_buffers', 'indirect_validation_and_write_triggers',
                        'explicit_commit_receipt', 'forms_message_level_context'),
    'external_1': ('verified_qualified_routine_contract_and_authority', 'exact_observed_source_arguments',
                   'explicit_invocation_outcome_no_retry'),
    'external_2': ('verified_qualified_routine_contract_and_authority', 'current_consignment_buffer',
                   'current_form_and_trusted_global_user', 'explicit_invocation_outcome_no_retry'),
    'final_policy': ('complete_bound_local_policy_helper_and_current_context',),
    'restore_message_level': ('forms_message_level_context',),
    'outer_exception': ('forms_message_level_context_accepting_uncaptured_null',),
}


def build_approval_plan(documents, packet, chunks, trace, files) -> ApprovalPlan:
    """Rebuild source authority before binding any dormant approval operation."""
    actual, actual_chunks = _build(documents)
    _need(type(packet) is dict and all(packet.get(k) == v for k,v in actual.items())
          and actual_chunks == chunks and trace.get('source_binding') == packet['source_binding'], 'SOURCE_BINDING')
    _need(json.loads(files['fox-package/source-to-page.json']) == trace, 'TRACE_MEMBER')
    manifest = json.loads(files['fox-package/source-manifest.json'])
    _need(manifest['source_binding'] == packet['source_binding'] and
          manifest['selected_chunk_hashes'] == {c['id']:c['sha256'] for c in chunks}, 'MANIFEST')
    _need(manifest['files'] == [{k:s['source'][k] for k in ('name','sha256','bytes')} for s in packet['sources']], 'MANIFEST_SOURCES')
    for name,raw in documents:
        _need(files['fox-package/sources/'+name] == raw, 'ORIGINAL_SOURCE')
    objects, props = _source_objects(documents, packet)
    by_unit = {c['code_unit_id']:c for c in chunks}
    result = {'schema_version':1, 'scope':SCOPE, 'source_binding':packet['source_binding'],
              'operations':[], 'gaps':[], 'full_event_converted':False, 'runtime_verified':False,
              'customer_dml_executed':False, 'business_accepted':False}
    for source in packet['sources']:
        for unit in source['facts']['code_units']:
            owner = objects[unit['owner_id']]
            if owner['kind'] != 'Trigger' or (owner['name'] or '').upper() != 'WHEN-BUTTON-PRESSED':
                continue
            chunk = by_unit[unit['id']]
            row = {'source_unit_id':unit['id'], 'source_unit_sha256':unit['sha256'],
                   'source_chunk_id':chunk['id'], 'source_owner_id':owner['id'],
                   'source_module_id':owner['module_id'], 'button_item_id':owner['parent_id'],
                   'source_event':'WHEN-BUTTON-PRESSED'}
            try:
                parsed,decode = parse_approval(chunk['text'])
            except ValueError as exc:
                # Only candidate multi-commit events belong to this recognizer.
                # An altered candidate remains a precise gap rather than vanishing.
                if re.search(r'\bCOMMIT_FORM\b|\bFORM_SUCCESS\b', chunk['text'], re.I):
                    result['gaps'].append({**row,'reason':str(exc),'stage':'complete_source_parse'})
                continue
            row.update(parsed=parsed, decode_receipt=decode,
                       operation_id='fap1-'+_sha([packet['source_binding'],unit['id']])[:24])
            for index,call in enumerate(parsed['external_calls'],1):
                call['call_site_id'] = 'fac1-'+_sha([unit['id'],unit['sha256'],call['position'],call['observed_source']])[:24]
                call['source_unit_id'] = unit['id']
                call['stage_id'] = 'external_'+str(index)
            final = parsed['final_call_site']
            final['call_site_id'] = 'fac1-'+_sha([unit['id'],unit['sha256'],final['position'],final['observed_source']])[:24]
            final['source_unit_id'] = unit['id']
            row['stages'] = [{'id':name,'kind':kind,'condition':condition,'ordinal':i,
                              'source_unit_id':unit['id'], 'source_unit_sha256':unit['sha256'],
                              'required_capabilities':list(CAPABILITIES.get(name,())),
                              'provider_status':'unbound' if name in CAPABILITIES else 'local_guard_only'}
                             for i,(name,kind,condition) in enumerate(STAGES,1)]
            row['transaction_boundaries'] = [{'stage_id':name,'independent':True,'provider_required':'whole_form_commit',
                'message_level_before':5,'message_level_after':'captured_value_on_normal_return',
                'source_does_not_test_form_success_after_commit':name in ('route_commit','approval_commit')}
                for name in ('dirty_commit','route_commit','approval_commit')]
            row['full_event_converted'] = False
            try:
                row['contract'] = _bind(parsed,owner,objects,props,trace,files)
                row['readiness_contract'] = deepcopy(row['contract'])
                row['status'] = 'source_bound_dormant_workflow'
            except ValueError as exc:
                row['status'] = 'encoded_target_binding_missing'
                result['gaps'].append({**{k:v for k,v in row.items() if k.startswith('source_')},
                                       'reason':str(exc),'stage':'target_binding'})
            row['operation_sha256'] = _sha(row)
            result['operations'].append(row)
    result['plan_sha256'] = _sha(result)
    return result


@dataclass(frozen=True)
class AdapterOutcome:
    """An explicit provider receipt; completed never implies FORM_SUCCESS/commit."""
    status: Literal['completed','failed','unmet','unknown']
    value: Any = None
    reason: str = ''
    committed: bool | None = None


@dataclass(frozen=True)
class TargetOperation:
    id: str
    kind: str
    source_unit_id: str
    payload: dict


class ApprovalAdapter(Protocol):
    """Target must preserve Forms buffer, policy, current row and whole-form scope."""
    def perform(self, operation: TargetOperation) -> AdapterOutcome: ...


class _StopModel(Exception):
    pass


def execute_approval_model(operation: ApprovalWorkflow, adapter: ApprovalAdapter) -> dict:
    """Run source ordering locally through explicit adapters, with no default IO.

    Missing/unknown capabilities halt the model (including failed restoration),
    while declared source exceptions follow the original swallowed handlers.
    The result describes provider observations, never customer business approval.
    """
    parsed = operation['parsed']
    _need('contract' in operation, 'BOUND_OPERATION_REQUIRED')
    _need(operation.get('operation_sha256') == _sha({k:v for k,v in operation.items() if k != 'operation_sha256'}),
          'IMMUTABLE_OPERATION_BINDING')
    result = {'scope':'local_adapter_model', 'source_unit_id':operation['source_unit_id'],
              'events':[], 'messages':[], 'commit_history':[], 'pending':[],
              'status':'running', 'business_approved':False, 'customer_dml_executed':False,
              'adapter_outcomes_not_independently_verified':True}
    saved = None
    current_stage = 'initialize'

    def known(condition, reason):
        if not condition:
            result['pending'].append({'stage_id':current_stage,'reason':reason})
            result['status'] = 'unknown'
            raise _StopModel()

    def perform(stage, kind, payload=None, *, catch=False):
        nonlocal current_stage
        current_stage = stage
        target = TargetOperation(stage,kind,operation['source_unit_id'],deepcopy(payload or {}))
        try:
            outcome = adapter.perform(target)
        except Exception as exc:
            # An adapter transport exception cannot establish operation outcome.
            outcome = AdapterOutcome('unknown',reason=type(exc).__name__)
        known(type(outcome) is AdapterOutcome and outcome.status in ('completed','failed','unmet','unknown'),
              'invalid_adapter_receipt')
        event = {'stage_id':stage,'kind':kind,'status':outcome.status,'reason':outcome.reason,
                 'value':deepcopy(outcome.value),'committed':outcome.committed}
        result['events'].append(event)
        if kind == 'commit':
            result['commit_history'].append(deepcopy(event))
            if outcome.status == 'completed':
                known(type(outcome.committed) is bool,'commit_outcome_unknown')
        if outcome.status in ('unmet','unknown'):
            result['pending'].append({'stage_id':stage,'reason':outcome.reason or 'provider_'+outcome.status})
            result['status'] = outcome.status; raise _StopModel()
        if outcome.status == 'failed' and not catch:
            raise RuntimeError(stage)
        return outcome

    def reject(kind, suffix=''):
        nonlocal current_stage
        current_stage = {'weight':'weight_guard','destination':'destination_guard',
                         'no_bags':'bag_guard','missing_consignment':'consignment_guard'}[kind]
        result['messages'].extend(m+suffix for m in parsed['messages'][kind])
        result['status']='source_guard_rejected'
        raise RuntimeError('FORM_TRIGGER_FAILURE')

    def form_success(stage):
        value = perform(stage,'form_success').value
        known(type(value) is bool, 'explicit_form_success_required')
        return value

    def commit(stage):
        perform(stage+'_message_level','set_message_level',{'value':5})
        perform(stage,'commit',{'scope':'whole_form','effects_include_indirect_triggers':True})
        perform(stage+'_restore','set_message_level',{'value':saved})

    try:
        try:
            count = perform('weight_count','query',parsed['queries']['weight_count']).value
            known(type(count) is int and count >= 0, 'count_outcome_unknown')
            if count > 0: reject('weight')
            destination = perform('destination_guard','read_field',{'field':operation['contract']['fields']['destination']}).value
            if destination in (None,''): reject('destination')
            perform('focus_header','go_item',{'item':parsed['focus_item']})
            saved = perform('capture_message_level','read_message_level').value
            known(type(saved) is int, 'message_level_outcome_unknown')
            status = perform('form_status','read_form_status').value
            known(status in ('CHANGED','NEW','QUERY'), 'form_status_outcome_unknown')
            if status == 'CHANGED': commit('dirty_commit')
            if form_success('form_success_routes'):
                perform('focus_bags','go_block',{'block':parsed['bag_block']})
                perform('first_bag','first_record')
                key = perform('first_bag_key','read_field',{'field':operation['contract']['fields']['bag_key']}).value
                if key not in (None,''):
                    # Navigation/context providers must prove the current related
                    # bag set. Row keys and order are provider observations.
                    seen = set()
                    while True:
                        row = perform('route_current_context','current_related_bag').value
                        known(type(row) is dict and type(row.get('identity')) in (str,int)
                              and row['identity'] not in seen and row.get('related_to_current_header') is True,
                              'current_related_bag_required')
                        seen.add(row['identity']); known(len(seen) <= 10000,'bag_capacity')
                        perform('route_copy','assign_current_bag_route',{'source':operation['contract']['fields']['header_route'],
                                'target':operation['contract']['fields']['bag_route'],'row_identity':row['identity']})
                        last = perform('last_bag','read_last_record').value
                        known(type(last) is bool,'last_record_outcome_unknown')
                        if last: break
                        perform('next_bag','next_record')
                    perform('reset_first_bag','first_record')
                commit('route_commit')
                outcome = perform('bag_count','query',parsed['queries']['bag_count'],catch=True)
                count = 0 if outcome.status == 'failed' else outcome.value
                known(type(count) is int and count >= 0,'count_outcome_unknown')
                if count == 0: reject('no_bags')
                outcome = perform('missing_consignment','query',{
                    **parsed['queries']['missing_consignment'],
                    'select_into_capacity':parsed['locals']['missing_consignment_capacity'],
                    'length_semantics':'source_environment_provider_required'},catch=True)
                missing = None if outcome.status == 'failed' else outcome.value
                known(missing is None or type(missing) is str,'missing_bag_outcome_unknown')
                if missing not in (None,''): reject('missing_consignment',missing)
                if form_success('form_success_approval'):
                    perform('approval_assignment','assign_field',{'field':operation['contract']['fields']['approved'],
                                                                 'value':parsed['approval_value']})
                    commit('approval_commit')
                    for index,call in enumerate(parsed['external_calls'],1):
                        perform('external_'+str(index),'qualified_call',call)
            perform('final_policy','local_call',parsed['final_call_site'])
            perform('restore_message_level','set_message_level',{'value':saved})
            result['status']='source_path_completed_by_adapters'
        except RuntimeError:
            previous = result['status']
            result['failure_stage'] = current_stage
            try:
                perform('outer_exception','set_message_level',{'value':saved,'reraises':False,'rollback':False})
                result['status'] = previous if previous == 'source_guard_rejected' else 'source_exception_swallowed'
            except RuntimeError:
                result['status'] = 'source_exception_handler_failed'
    except _StopModel:
        pass
    result['last_stage'] = current_stage
    result['source_saved_message_level'] = saved
    return result
