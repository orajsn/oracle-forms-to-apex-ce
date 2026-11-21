"""Closed source-bound staged queries and a caller-transaction DB-API model.

Compilation never executes SQL. The model is for explicitly supplied disposable
databases; it neither commits nor rolls back, including after a failed stage.
Names do not establish temporary-table, session or transaction semantics.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import TypedDict

from .forms_behavior_plan import _Parser, _tokens, _source_objects, decode_control_entities
from .forms_manifest_filter import (_canonical, _sha, _identifier, _name,
                                    _direct_fields, parse_where_clause, _rhs)
from .forms_order_rules import parse_order
from .forms_synthetic_save import _table_proof
from .forms_understanding_packet import _build

SCOPE = 'fox-staged-query-plan-v1'
RULE_ID = 'fox.query.staged-refresh'
KEY_BIND = 'FOX_QUERY_KEY'


class StagedQueryOperation(TypedDict, total=False):
    operation_id: str
    kind: str
    source_unit_id: str
    source_unit_sha256: str
    source_chunk_id: str
    source_owner_id: str
    source_module_id: str
    source_block_id: str
    source_table: str
    staging_table: str
    source_key_column: str
    staging_key_column: str
    key_binding: dict
    projection: list[dict]
    filter_terms: list[dict]
    global_bindings: list[dict]
    source_select_sql: str
    source_sql: dict[str, str]
    target: dict
    semantic_gaps: list[dict]


class StagedQueryPlan(TypedDict):
    schema_version: int
    scope: str
    source_binding: str
    operations: list[StagedQueryOperation]
    gaps: list[dict]
    runtime_verified: bool
    business_accepted: bool
    plan_sha256: str


def _need(value, reason):
    if not value:
        raise ValueError('STAGED_QUERY_' + reason)


def parse_staged_query(raw):
    """Consume an entire finite IF/delete/insert-select/query/ELSE NULL event."""
    _need(type(raw) is str and 0 < len(raw) <= 32767, 'SOURCE_CAPACITY')
    semantic, decode = decode_control_entities(raw)
    # Export whitespace is accepted only outside string literals. This closed
    # grammar has no literal expression, and the lexer rejects any such token.
    tabs = [m.start() for m in re.finditer(r'\\t', semantic)]
    semantic = semantic.replace('\\t', '\t')
    p = _Parser(_tokens(semantic))

    def name(qualified=False):
        result = _identifier(p.take(kind='word'))
        if qualified and p.peek('.'):
            p.take('.')
            result += '.' + _identifier(p.take(kind='word'))
        return result

    def columns():
        values = [name()]
        while p.peek(','):
            p.take(',')
            values.append(name())
            _need(len(values) <= 100, 'PROJECTION_CAPACITY')
        return values

    wrapped = p.peek('BEGIN')
    if wrapped:
        p.take('BEGIN')
    p.take('IF')
    guard = p.reference()
    for token in ('IS', 'NOT', 'NULL', 'THEN', 'DELETE'):
        p.take(token)
    if p.peek('FROM'):
        p.take('FROM')
    staging = name(True)
    p.take('WHERE')
    delete_key = name()
    p.take('=')
    delete_ref = p.reference()
    for token in (';', 'INSERT', 'INTO'):
        p.take(token)
    insert_table = name(True)
    p.take('(')
    inserted = columns()
    for token in (')', 'SELECT'):
        p.take(token)
    selected = columns()
    p.take('FROM')
    original = name(True)
    p.take('WHERE')
    source_key = name()
    p.take('=')
    select_ref = p.reference()
    for token in (';', 'EXECUTE_QUERY', ';', 'ELSE', 'NULL', ';', 'END', 'IF', ';'):
        p.take(token)
    if wrapped:
        p.take('END')
        p.take(';')
    p.end()
    _need(staging == insert_table and original != staging, 'SOURCE_DESTINATION_IDENTITY')
    _need(len(inserted) == len(selected) and len(set(inserted)) == len(inserted),
          'PROJECTION_ARITY_OR_DUPLICATE_TARGET')
    _need(delete_key in inserted and selected[inserted.index(delete_key)] == source_key,
          'KEY_PROJECTION_IDENTITY')
    return {'guard_reference': guard, 'delete_reference': delete_ref,
            'select_reference': select_ref, 'staging_table': staging,
            'source_table': original, 'staging_key_column': delete_key,
            'source_key_column': source_key, 'insert_columns': inserted,
            'select_columns': selected}, {**decode, 'literal_export_tab_offsets': tabs}


def _resolve(parts, block, objects):
    _need(len(parts) in (1, 2) and
          (len(parts) == 1 or parts[0] == block['name'].upper()), 'KEY_REFERENCE_SCOPE')
    found = [o for o in objects.values() if o['kind'] == 'Item'
             and o['module_id'] == block['module_id'] and o['block_id'] == block['id']
             and o['name'].upper() == parts[-1]]
    _need(len(found) == 1, 'KEY_ITEM_NOT_UNIQUE')
    return found[0]


def _binding(field, props):
    result = deepcopy(field)
    p = props[field['source_item_id']]
    if field['data_type'] == 'VARCHAR2':
        length = p.get('MaximumLength', '')
        _need(re.fullmatch(r'[0-9]{1,4}', length) is not None
              and 0 < int(length) <= 4000, 'CHARACTER_LENGTH_NOT_PROVEN')
        result['max_length'] = int(length)
        result['length_semantics'] = p.get('DataLengthSemantics', 'unspecified').upper()
    return result


def _form_declaration(stage_column, block, objects, props, target):
    """Keep known Forms declarations distinct from unverified SQL interfaces."""
    candidates = [o for o in objects.values() if o['kind'] == 'Item'
                  and o['block_id'] == block['id'] and o['module_id'] == block['module_id']
                  and o.get('database_item') is True
                  and (props[o['id']].get('ColumnName', '').strip() or o['name']).upper() == stage_column]
    _need(len(candidates) <= 1, 'PROJECTION_DECLARATION_AMBIGUOUS')
    if not candidates:
        return None
    item = candidates[0]
    p = props[item['id']]
    native = [f for f in target['items'] if f['source_item_id'] == item['id']]
    return {'source_item_id': item['id'], 'source_item_name': item['name'],
            'data_type': p.get('DataType'), 'item_type': p.get('ItemType'),
            'format_mask': p.get('FormatMask'), 'maximum_length': p.get('MaximumLength'),
            'synthetic_data_type': native[0]['data_type'] if len(native) == 1 else None,
            'physical_sql_type_verified': False}


def _compile(unit, chunk, owner, objects, props, trace, files, units, binding):
    parsed, decode = parse_staged_query(chunk['text'])
    block = objects.get(owner['block_id'])
    _need(block is not None and block['kind'] == 'Block'
          and block['classification'] == 'database'
          and owner['module_id'] == block['module_id'], 'BLOCK_OWNING_TRIGGER_REQUIRED')
    parent = objects.get(owner['parent_id'])
    _need(parent is not None and (parent['id'] == block['id'] or
          (parent['kind'] == 'Item' and parent['block_id'] == block['id']
           and parent['module_id'] == block['module_id'])), 'BLOCK_OR_ITEM_OWNING_TRIGGER_REQUIRED')
    overrides = [o for o in objects.values() if o['kind'] == 'Trigger'
                 and o['block_id'] == block['id'] and o['name'].upper() == 'KEY-EXEQRY'
                 and o['parent_id'] == owner['parent_id']]
    _need(len(overrides) == 1, 'CONFLICTING_KEY_OVERRIDE')
    refs = [parsed[k] for k in ('guard_reference', 'delete_reference', 'select_reference')]
    resolved = [_resolve(r, block, objects) for r in refs]
    _need(len({o['id'] for o in resolved}) == 1, 'KEY_ITEM_IDENTITY')
    _need(parent['kind'] != 'Item' or parent['id'] == resolved[0]['id'],
          'OWNING_ITEM_KEY_IDENTITY')
    p = props[block['id']]
    _need(p.get('QueryDataSourceType', '').upper() == 'TABLE'
          and _name(p.get('QueryDataSourceName', '')) == parsed['staging_table'],
          'BLOCK_STAGING_TABLE_MISMATCH')
    targets = [b for b in trace['blocks'] if b['source_block_id'] == block['id']]
    _need(len(targets) == 1, 'NATIVE_BLOCK_NOT_UNIQUE')
    target = targets[0]
    _need(target.get('source_module_id') == block['module_id']
          and target.get('name') == block['name']
          and target.get('classification') == 'database'
          and re.fullmatch(r'FOX_NATIVE_[A-F0-9]+', target.get('table_name', ''))
          and target.get('report_file') in files, 'NATIVE_TARGET_MISMATCH')
    fields, omissions = _direct_fields(block, target, objects, props)
    _need('fox-package/supporting-schema.sql' in files, 'NATIVE_SCHEMA_PROOF_MISSING')
    _table_proof(files, target, {f['column'] for f in fields})
    by_column = {f['source_column']: f for f in fields}
    projection = []
    ddl = files['fox-package/supporting-schema.sql'].decode()
    native_body = re.findall(r'\bCREATE TABLE ' + re.escape(target['table_name'])
                             + r' \(\n(.*?)\n\);', ddl, re.S)[0]
    for stage, source in zip(parsed['insert_columns'], parsed['select_columns'], strict=True):
        field = (_binding(by_column[stage], props) if stage in by_column else
                 {'source_item_id': None, 'column': None, 'data_type': None,
                  'max_length': None, 'metadata_status': 'source_sql_only_interface_type_unverified'})
        if field['data_type'] == 'VARCHAR2':
            _need(re.findall(r'\b' + re.escape(field['column']) + r' VARCHAR2\(([0-9]+)\)',
                             native_body) == [str(field['max_length'])],
                  'NATIVE_CHARACTER_LENGTH_MISMATCH')
        declaration = _form_declaration(stage, block, objects, props, target)
        field['form_declaration'] = declaration
        if field['source_item_id'] is None and declaration is not None:
            field['source_item_id'] = declaration['source_item_id']
        projection.append({**field, 'staging_column': stage, 'source_column': source})
    key = next(f for f in projection if f['staging_column'] == parsed['staging_key_column'])
    _need(key['source_item_id'] == resolved[0]['id'] and key['column'] is not None
          and key['data_type'] is not None, 'KEY_COLUMN_IDENTITY')
    filter_units = [u for u in units if u['owner_id'] == block['id']
                    and u['source_attribute'] == 'WhereClause']
    _need(len(filter_units) == 1, 'BLOCK_FILTER_SOURCE_MISSING')
    terms, filter_decode = parse_where_clause(p.get('WhereClause', ''))
    for term in terms:
        _need(term['source_column'] in by_column
              and term['source_column'] in parsed['insert_columns'], 'FILTER_COLUMN_NOT_PROJECTED')
        field = by_column[term['source_column']]
        dtype, kind = field['data_type'], term['value']['kind']
        _need((dtype == 'VARCHAR2' and kind in ('string', 'global'))
              or (dtype == 'NUMBER' and kind == 'number'), 'FILTER_TYPE_NOT_PROVEN')
        term.update(column=field['column'], source_item_id=field['source_item_id'])
    globals_ = {t['value']['name']: 'FOX_RG_G_' + _sha(_canonical(
        [block['module_id'], ['GLOBAL', t['value']['name']]]))[:20].upper()
        for t in terms if t['value']['kind'] == 'global'}
    source_select = ('SELECT ' + ', '.join(parsed['select_columns']) + '\nFROM '
                     + parsed['source_table'] + '\nWHERE ' + parsed['source_key_column']
                     + ' = :' + KEY_BIND)
    delete = 'DELETE FROM ' + parsed['staging_table'] + ' WHERE ' + parsed['staging_key_column'] + ' = :' + KEY_BIND
    insert = ('INSERT INTO ' + parsed['staging_table'] + ' ('
              + ', '.join(parsed['insert_columns']) + ')\n' + source_select)
    query = ('SELECT ' + ', '.join(parsed['insert_columns']) + '\nFROM '
             + parsed['staging_table'] + '\nWHERE ' + ' AND '.join(
                 t['source_column'] + ' = ' + _rhs(t['value'], globals_) for t in terms))
    order = []
    if p.get('OrderByClause', '').strip():
        raw_order, _ = decode_control_entities(p['OrderByClause'])
        order = parse_order(raw_order)
        _need(all(t['source_name'] in parsed['insert_columns'] for t in order), 'ORDER_COLUMN_NOT_PROJECTED')
        query += '\nORDER BY ' + ', '.join(t['source_name'] + ' ' + t['direction'].upper()
                                           + ' NULLS ' + t['nulls'].upper() for t in order)
    semantic_gaps = [
        {'reason': 'original_source_interface_definition_unverified',
         'source_table': parsed['source_table'], 'required': 'Verified table/view definition, projection types, privileges and authoritative row provider.'},
        {'reason': 'staging_table_lifetime_unverified', 'required': 'DDL proving staging lifetime and transaction/session semantics; names prove none.'},
        {'reason': 'forms_transaction_and_query_runtime_provider_required',
         'required': 'Caller-owned transaction and Forms block query adapter; APEX session staging has a different lifetime.'}]
    unknown = [f['staging_column'] for f in projection if f['data_type'] is None]
    if unknown:
        semantic_gaps.append({'reason': 'projection_interface_types_unverified',
                              'staging_columns': unknown,
                              'required': 'Authoritative source interface types or fail-closed runtime describe; preserve every projected value.'})
    unrendered = [f for f in projection if f['data_type'] is None and f['form_declaration'] is not None]
    if unrendered:
        semantic_gaps.append({'reason': 'forms_field_display_type_not_supported_by_native_projection',
            'fields': [{'staging_column': f['staging_column'], **f['form_declaration']} for f in unrendered],
            'required': 'Preserve source values with runtime SQL type evidence; the declared Forms field and format do not prove the physical SQL type.'})
    absent = [f['source_item_id'] for f in fields if f['source_column'] not in parsed['insert_columns']]
    if absent:
        semantic_gaps.append({'reason': 'block_fields_not_in_source_insert',
                              'source_item_ids': absent,
                              'required': 'Target defaults and separate field behavior remain unverified; omit from adapted report.'})
    return {'operation_id': 'staged-query-' + _sha(_canonical([binding, unit['id']]))[:20],
            'kind': 'guarded_staged_block_query', 'rule_id': RULE_ID,
            'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
            'source_chunk_id': chunk['id'], 'source_owner_id': owner['id'],
            'source_module_id': owner['module_id'], 'source_block_id': block['id'],
            'trigger_parent_id': parent['id'], 'trigger_parent_kind': parent['kind'],
            **{k: parsed[k] for k in ('source_table', 'staging_table', 'source_key_column', 'staging_key_column')},
            'key_binding': {**key, 'native_column': key['column'],
                            'source_reference': [block['name'].upper(), resolved[0]['name'].upper()],
                            'bind_name': KEY_BIND},
            'projection': projection, 'projection_omissions': omissions,
            'filter_terms': terms, 'filter_source_unit_id': filter_units[0]['id'],
            'filter_source_unit_sha256': filter_units[0]['sha256'],
            'global_bindings': [{'source_reference': ['GLOBAL', name], 'app_item': app,
                                 'trusted_provider_required': True} for name, app in sorted(globals_.items())],
            'target': deepcopy(target), 'source_select_sql': source_select,
            'source_sql': {'delete': delete, 'insert': insert, 'query': query},
            'source_no_commit': True, 'transaction_owner': 'caller',
            'source_order': order, 'decode_receipt': decode, 'filter_decode_receipt': filter_decode,
            'semantic_gaps': semantic_gaps, 'source_interface_verified': False,
            'runtime_verified': False, 'business_accepted': False}


def build_staged_query_plan(documents, packet, chunks, trace, files) -> StagedQueryPlan:
    """Rebind exact source bytes/chunks and compile supported owning triggers."""
    fresh, fresh_chunks = _build(documents)
    _need(packet.get('source_binding') == fresh['source_binding']
          and packet.get('sources') == fresh['sources'] and chunks == fresh_chunks,
          'SOURCE_CHANGED')
    _need(trace.get('source_binding') == fresh['source_binding'], 'TRACE_SOURCE_CHANGED')
    for name, raw in documents:
        _need(files.get('fox-package/sources/' + name) == raw, 'ORIGINAL_SOURCE_CHANGED')
    objects, props = _source_objects(documents, fresh)
    units = [u for s in fresh['sources'] for u in s['facts']['code_units']]
    texts = {c['code_unit_id']: c for c in fresh_chunks}
    operations, gaps = [], []
    for unit in units:
        owner = objects[unit['owner_id']]
        if not (owner['kind'] == 'Trigger' and owner['name'].upper() == 'KEY-EXEQRY'
                and unit['source_attribute'] == 'TriggerText'):
            continue
        # Ordinary guarded queries are another compiler's boundary. Detect any
        # staged intent, including unsupported/malformed DELETE or INSERT text.
        if not re.search(r'\b(?:DELETE|INSERT)\b', texts[unit['id']]['text'], re.I):
            continue
        try:
            operations.append(_compile(unit, texts[unit['id']], owner, objects, props,
                                       trace, files, units, fresh['source_binding']))
        except ValueError as exc:
            gaps.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                         'source_chunk_id': texts[unit['id']]['id'], 'reason': str(exc)})
    plan = {'schema_version': 1, 'scope': SCOPE, 'source_binding': fresh['source_binding'],
            'operations': operations, 'gaps': gaps, 'runtime_verified': False,
            'business_accepted': False}
    plan['plan_sha256'] = _sha(_canonical(plan))
    return deepcopy(plan)


def execute_staged_query_model(operation, connection, key, globals_=None):
    """Execute the emitted SQL against a caller-supplied disposable DB-API DB.

    Missing globals fail before the first write; an explicitly supplied NULL
    global is known context and retains the source equality-to-NULL behavior.
    A query-stage exception leaves
    earlier DML pending in the caller's transaction, exactly as this source event
    has no exception handler, commit, rollback or recovery/retry instruction.
    """
    if key is None or key == '':
        return {'status': 'null_noop', 'completed_stages': [], 'rows': [],
                'transaction_owner': 'caller', 'committed': False, 'rolled_back': False}
    query_binds = {}
    for binding in operation['global_bindings']:
        name = binding['source_reference'][1]
        _need(globals_ is not None and name in globals_,
              'TRUSTED_GLOBAL_REQUIRED')
        query_binds[binding['app_item']] = globals_[name]
    completed, counts = [], {}
    cursor = connection.cursor()
    try:
        for stage in ('delete', 'insert'):
            cursor.execute(operation['source_sql'][stage], {KEY_BIND: key})
            counts[stage] = cursor.rowcount
            completed.append(stage)
        cursor.execute(operation['source_sql']['query'], query_binds)
        rows = cursor.fetchall()
        completed.append('query')
        return {'status': 'queried', 'completed_stages': completed, 'rows': rows,
                'affected_rows': counts, 'transaction_owner': 'caller',
                'committed': False, 'rolled_back': False}
    finally:
        cursor.close()
