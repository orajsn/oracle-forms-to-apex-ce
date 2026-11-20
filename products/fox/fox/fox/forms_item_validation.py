"""Closed item-validation event on the existing protected synthetic draft.

No original SQL is executed. The complete parsed event is retained even when a
provider cannot be proved. Navigation and the Forms transaction are separate.
"""
from __future__ import annotations

from copy import deepcopy
import json
import re

from forms2apex import native_buffer
from forms2apex.record_buffer import decode_source, validate_buffer_plan
from .forms_behavior_plan import _source_objects
from .forms_draft_policy import _compact, _literal
from .forms_synthetic_save import apply_synthetic_saves, _replace, _table_proof, REQUEST
from .forms_understanding_packet import _build

SCOPE = 'fox-bound-item-validation-v1'
SLOTS = {'marker': 'c042', 'active_route': 'c044', 'active_weight': 'n002',
         'baseline_weight': 'n003', 'baseline_route': 'c040', 'saved_identity': 'n001',
         'validation_error_state': 'c043'}
_IDENT = r'[A-Z][A-Z0-9_$#]{0,127}'


def _need(value, reason):
    if not value:
        raise ValueError('ITEM_VALIDATION_' + reason)


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


def parse_item_validation(raw):
    """Consume the entire finite nested event, retaining source message order."""
    text, receipt = decode_source(raw)
    pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|:=|<>|\|\||" +
                         _IDENT + r'|[0-9]+|[:.,();=]', re.I | re.S)
    tokens, pos = [], 0
    while pos < len(text):
        match = pattern.match(text, pos)
        _need(match is not None, 'ACTIVE_TOKEN')
        token, pos = match[0], match.end()
        if token.isspace() or token.startswith(('--', '/*')):
            continue
        tokens.append(('string', token[1:-1].replace("''", "'")) if token.startswith("'")
                      else ('token', token.upper()))
        _need(len(tokens) <= 512, 'TOKEN_CAPACITY')
    index = 0

    def take(value=None, kind='token'):
        nonlocal index
        _need(index < len(tokens) and tokens[index][0] == kind and
              (value is None or tokens[index][1] == value), 'COMPLETE_BODY_REQUIRED')
        result = tokens[index][1]
        index += 1
        return result

    def seq(words):
        for word in words.split():
            take(word)

    def ident():
        value = take()
        _need(re.fullmatch(_IDENT, value), 'IDENTIFIER')
        return value

    def ref():
        take(':')
        value = [ident()]
        if index < len(tokens) and tokens[index] == ('token', '.'):
            take('.')
            value.append(ident())
        return value

    def same(value):
        _need(ref() == value, 'REFERENCE_DIFFERS')

    def messages(counter=None):
        result = []
        while index < len(tokens) and tokens[index] == ('token', 'MESSAGE'):
            seq('MESSAGE (')
            message = take(kind='string')
            _literal(message)
            _need(len(message.encode()) <= 1000 and all(c.isprintable() for c in message), 'MESSAGE')
            if counter:
                take('||')
                take(counter)
            seq(') ;')
            result.append(message)
            _need(len(result) <= 4, 'MESSAGE_CAPACITY')
        _need(result, 'MESSAGE_REQUIRED')
        return result

    take('IF')
    destination = ref()
    seq('IS NULL AND')
    code = ref()
    seq('IS NOT NULL AND')
    _need(ref() == ['SYSTEM', 'RECORD_STATUS'], 'RECORD_STATUS_REQUIRED')
    take('<>')
    take('QUERY', 'string')
    take('THEN')
    warnings = messages()
    marker = ref()
    take(':=')
    warning_marker = take(kind='string')
    seq('; ELSE IF')
    same(code)
    seq('IS NOT NULL THEN DECLARE')
    counter = ident()
    seq('VARCHAR2 (')
    counter_length = int(take())
    _need(1 <= counter_length <= 4000, 'COUNTER_LENGTH')
    seq(') ;')
    unused = ident()
    _need(unused != counter, 'LOCAL_COLLISION')
    seq('NUMBER ; BEGIN')
    weight = ref()
    seq(':= 0 ;')
    route = ref()
    take(':=')
    parent_route = ref()
    seq('; BEGIN SELECT')
    projection = ident()
    take('INTO')
    take(counter)
    take('FROM')
    table = ident()
    take('WHERE')
    predicate = ident()
    take('=')
    same(code)
    seq('AND ROWNUM = 1 ; EXCEPTION WHEN NO_DATA_FOUND THEN NULL ; END ; IF')
    take(counter)
    seq('IS NOT NULL THEN')
    duplicates = messages(counter)
    same(code)
    seq(':= NULL ; RAISE FORM_TRIGGER_FAILURE ; ELSE')
    same(marker)
    seq(':= TO_CHAR ( SYSDATE ,')
    mask = take(kind='string')
    _need(mask == 'RRMMDDHH24MISS', 'CLOCK_MASK_UNSUPPORTED')
    seq(') ; END IF ; END ; END IF ; END IF ;')
    _need(index == len(tokens), 'EXTRA_ACTIVE_SOURCE')
    _need(warning_marker and len(warning_marker) <= 100, 'WARNING_MARKER')
    _literal(warning_marker)
    _need(sum(len(m.encode()) for m in duplicates) + counter_length*6*len(duplicates) < 3800
          and sum(len(m.encode()) for m in warnings) < 3800, 'MESSAGE_RESULT_CAPACITY')
    return {'destination_ref': destination, 'code_ref': code, 'marker_ref': marker,
            'weight_ref': weight, 'route_ref': route, 'parent_route_ref': parent_route,
            'warning_messages': warnings, 'duplicate_messages': duplicates,
            'warning_marker': warning_marker, 'clock_mask': mask,
            'query': {'table': table, 'projection': projection, 'predicate': predicate,
                      'rownum': 1, 'ordering': None, 'exception': 'NO_DATA_FOUND'},
            'counter_length': counter_length,
            'ordered_effects': ['warning_and_marker_without_raise_or_else', 'weight_zero',
                               'copy_parent_route', 'select_into_no_data_null',
                               'duplicate_message_clear_code_raise_or_clock_marker']}, receipt


def _resolve(ref, owner, objects):
    rows = [o for o in objects.values() if o['kind'] == 'Item' and o['module_id'] == owner['module_id']
            and (o['name'] or '').upper() == ref[-1]
            and (len(ref) == 1 or (objects[o['block_id']]['name'] or '').upper() == ref[0])]
    if len(ref) == 1:
        local = [o for o in rows if o['block_id'] == owner['block_id']]
        if local:
            rows = local
    return _one(rows, 'UNIQUE_SOURCE_ITEM_REQUIRED')


def _contract(parsed, owner, buffer, write, guard, objects, props, trace, files):
    refs = {name: _resolve(parsed[name + '_ref'], owner, objects)
            for name in ('destination', 'code', 'marker', 'weight', 'route', 'parent_route')}
    rel = buffer['relation']
    child = _one([b for b in trace['blocks'] if b['source_block_id'] == rel['child_block_id']], 'CHILD')
    parent = _one([b for b in trace['blocks'] if b['source_block_id'] == rel['parent_block_id']], 'PARENT')
    _need(owner['parent_id'] == refs['code']['id'] and owner['block_id'] == child['source_block_id'], 'EVENT_OWNER')
    _need(all(refs[n]['block_id'] == child['source_block_id'] for n in ('code', 'weight', 'route', 'marker'))
          and all(refs[n]['block_id'] == parent['source_block_id'] for n in ('destination', 'parent_route')), 'CROSS_BLOCK_CONTEXT')
    fields = {}
    for name, item in refs.items():
        block = parent if name in ('destination', 'parent_route') else child
        field = deepcopy(_one([f for f in block['items'] if f['source_item_id'] == item['id']], 'MAPPED_FIELD'))
        p = props[item['id']]
        maximum = p.get('MaximumLength', '')
        _need(re.fullmatch(r'[1-9][0-9]{0,3}', maximum) and int(maximum) <= 4000, 'SOURCE_LENGTH')
        dtype = p.get('DataType', '').upper()
        _need((name == 'weight' and dtype == 'NUMBER' and field['data_type'] == 'NUMBER') or
              (name != 'weight' and dtype in ('CHAR', 'VARCHAR2') and field['data_type'] == 'VARCHAR2'), 'SOURCE_TYPE')
        field.update(max_length=int(maximum), length_semantics=p.get('DataLengthSemantics', '').upper(),
                     source_database_item=p.get('DatabaseItem', '').lower() == 'true')
        fields[name] = field
    _need(not fields['marker']['source_database_item'], 'SESSION_MARKER_REQUIRED')
    _need(fields['marker']['max_length'] >= max(len(parsed['warning_marker']), 12), 'MARKER_CAPACITY')
    _need(fields['route']['column'] == write['route']['column'] and
          fields['parent_route']['column'] == write['parent_route']['column'], 'SAVE_ROUTE_CONTRACT')
    code_slot = _one([i for i, f in enumerate(buffer['key_bindings'], 1)
                      if f['source_item_id'] == refs['code']['id'] and not f.get('parent_copy')], 'REAL_DRAFT_CODE')
    _need(guard['authority'] == 'locked_current_synthetic_parent_then_fresh_policy_read'
          and guard['policy_expression_sql'] == write['policy_expression_sql'], 'CURRENT_POLICY')
    block_props = props[child['source_block_id']]
    query = parsed['query']
    _need(fields['code']['source_database_item'] and fields['weight']['source_database_item']
          and props[refs['weight']['id']].get('ColumnName'), 'EXACT_EFFECT_COLUMN_IDENTITY')
    _table_proof(files, child, {f['column'] for f in child['items']})
    _table_proof(files, parent, {f['column'] for f in parent['items']})
    select, query_reason = None, None
    try:
        _need(block_props.get('DatabaseBlock', '').lower() == 'true'
              and block_props.get('QueryDataSourceType', '').upper() == 'TABLE'
              and block_props.get('QueryDataSourceName', '').upper() == query['table'], 'EXACT_SOURCE_TABLE_IDENTITY')
        _need(props[refs['code']['id']].get('ColumnName', '').upper() == query['predicate'], 'EXACT_QUERY_PREDICATE')
        projected = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == child['source_block_id']
                          and props[o['id']].get('DatabaseItem', '').lower() == 'true'
                          and props[o['id']].get('ColumnName', '').upper() == query['projection']], 'EXACT_QUERY_PROJECTION')
        projection = _one([f for f in child['items'] if f['source_item_id'] == projected['id']], 'QUERY_PROJECTION')
        _need(projection['data_type'] == 'VARCHAR2', 'QUERY_TYPE')
        select = f"select c.{projection['column']} into item_event.l_counter from {child['table_name']} c where c.{fields['code']['column']}=item_event.l_code and ROWNUM=1;"
    except ValueError as exc:
        query_reason = str(exc)
    return {'buffer_operation_id': buffer['operation_id'], 'fields': fields, 'code_slot': code_slot,
            'query_sql': select, 'query_provider_ready': select is not None, 'query_provider_gap': query_reason,
            'source_table': query['table'], 'query_scope': 'all_persisted_synthetic_rows_all_parents',
            'parent_table': parent['table_name'], 'child_table': child['table_name'],
            'policy_expression_sql': guard['policy_expression_sql'], 'slots': deepcopy(SLOTS),
            'parent_input_provenance': 'fresh_locked_selected_parent_exact_trace_columns',
            'destination_adaptation': 'source_control_field_stored_in_selected_synthetic_parent',
            'dirty_predicate_sql': 'not (' + native_buffer._parent_match('c044', 'c040') + ") or decode(n002,n003,1,0)=0 or c043='ERROR'",
            'membership_sql': write['membership_sql']}


def _effect_body(parsed, c):
    """Only closed parsed IR contributes executable SQL; all messages are data."""
    warnings = ' || chr(10) || '.join(native_buffer._literal(m) for m in parsed['warning_messages'])
    duplicates = ' || chr(10) || '.join('(' + native_buffer._literal(m) + ' || l_counter)' for m in parsed['duplicate_messages'])
    query = c['query_sql'] or "raise_application_error(-20032,'The persisted source query provider is not proved; no lookup outcome was inferred.');"
    return f"""if l_destination is null and l_code is not null and l_status<>'QUERY' then
 l_warning:={warnings}; l_marker:={native_buffer._literal(parsed['warning_marker'])};
else
 if l_code is not null then
  l_weight:=0;
  l_route:=l_parent_route;
  begin
   {query}
  exception when no_data_found then null;
  end;
  if l_counter is not null then
   l_error:={duplicates};
   l_code:=null;
   l_failed:=true;
  else
   l_marker:=to_char(sysdate,{native_buffer._literal(parsed['clock_mask'])});
  end if;
 end if;
end if;"""


def _event_code(parsed, buffer, page, c, collection):
    declarations = native_buffer._declarations(buffer, page)
    read = native_buffer._read_parent(buffer, 'l_exists', lock=True)
    declarations = _replace(declarations, read, read + f"select {c['policy_expression_sql']} into l_exists from {c['parent_table']} where FOX_ROW_ID=l_parent;if nvl(l_exists,0)<>1 then return false;end if;")
    declarations = declarations.replace(native_buffer._name(buffer), collection)
    f, slot = c['fields'], c['code_slot']
    inherited = [f'l_value{i}' for i, field in enumerate(buffer['key_bindings'], 1) if field.get('parent_copy')]
    _need(inherited, 'INHERITED_KEY_REQUIRED')
    # A row lock plus the existing complete baseline prevents effects against a
    # replaced/deleted/reparented stored row. No submitted identity is trusted.
    equal = ' and '.join(native_buffer._parent_match('c.' + field['column'], f'd.c{20+i:03d}')
                         for i, field in enumerate(buffer['key_bindings'], 1))
    equal += ' and ' + native_buffer._parent_match('c.' + f['route']['column'], 'd.c040')
    equal += ' and decode(c.' + f['weight']['column'] + ',d.n003,1,0)=1'
    membership = c['membership_sql'].replace('l_parent', 'item_event.l_parent')
    retain = '\n'.join(f'apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>{i},p_attr_value=>l_value{i});'
                       for i, field in enumerate(buffer['key_bindings'], 1) if not field.get('parent_copy'))
    return f"""<<item_event>>
declare
l_id number;l_found number;l_changed number;l_counter varchar2({parsed['counter_length']});
l_destination varchar2(4000);l_parent_route varchar2(4000);l_route varchar2(4000);
l_code varchar2(4000);l_marker varchar2(4000);l_weight number;
l_status varchar2(10);l_error varchar2(4000);l_warning varchar2(4000);l_failed boolean:=false;
l_previous_error varchar2(30);l_runtime_error varchar2(30);
{declarations}
begin
 :P{page}_ITEM_ERROR:=null;
 if :REQUEST is null or :REQUEST not in ({native_buffer._requests()},'{REQUEST}') then return;end if;
 if not context_ok then :P{page}_ITEM_ERROR:='Draft, parent policy or revision changed. Reopen before editing.';
 else
  if {native_buffer._checks(buffer,page)} then
   :P{page}_ITEM_ERROR:='Required value or source field length is invalid.';
  else
   select c043 into l_previous_error from apex_collections where collection_name=l_name and seq_id=l_seq and c050='ROW';
   select case when {native_buffer._parent_match('l_value' + str(slot), 'l_original' + str(slot))} and nvl(l_previous_error,'OK')<>'ERROR' then 0 else 1 end into l_changed from dual;
   if l_changed=1 then
   select n001,c042,c044,n002 into l_id,l_marker,l_route,l_weight from apex_collections
    where collection_name=l_name and seq_id=l_seq and c050='ROW';
   if l_id is not null then
    select c.FOX_ROW_ID into l_found from {c['child_table']} c where c.FOX_ROW_ID=item_event.l_id
     and {membership} and exists(select 1 from apex_collections d where d.collection_name=item_event.l_name
      and d.seq_id=item_event.l_seq and d.c041='SYNTHETIC_SAVE_BASELINE_V1' and {equal}) for update nowait;
   end if;
   select {f['destination']['column']},{f['parent_route']['column']} into l_destination,l_parent_route
    from {c['parent_table']} where FOX_ROW_ID=l_parent;
   if nvl({'lengthb' if f['destination']['length_semantics']=='BYTE' else 'length'}(l_destination),0)>{f['destination']['max_length']}
    or nvl({'lengthb' if f['route']['length_semantics']=='BYTE' else 'length'}(l_parent_route),0)>{f['route']['max_length']}
    or nvl({'lengthb' if f['parent_route']['length_semantics']=='BYTE' else 'length'}(l_parent_route),0)>{f['parent_route']['max_length']} then
    raise_application_error(-20031,'Parent input exceeds its declared source field limit.');
   end if;
   l_code:=l_value{slot};l_status:=case when l_id is null then 'INSERT' else 'CHANGED' end;
   begin
    {_effect_body(parsed,c)}
   exception when others then
    apex_debug.error('Item event failed: %s',sqlerrm);
    l_error:='Item validation could not finish. Correct or reopen the draft.';l_failed:=true;l_runtime_error:='ERROR';
   end;
   l_value{slot}:=l_code;:P{page}_K{slot}:=l_code;
   {retain}
   apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>42,p_attr_value=>l_marker);
   apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>43,p_attr_value=>l_runtime_error);
   apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>44,p_attr_value=>l_route);
   apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>2,p_number_value=>l_weight);
   apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>3,p_number_value=>l_revision+1);
   :P{page}_REV:=to_char(l_revision+1,'TM9');
   if l_warning is not null then apex_application.g_print_success_message:=replace(apex_escape.html(l_warning),chr(10),'<br>');end if;
   if l_failed then :P{page}_ITEM_ERROR:=l_error;end if;
   end if;
  end if;
 end if;
 if :P{page}_ITEM_ERROR is not null then apex_error.add_error(p_message=>replace(apex_escape.html(:P{page}_ITEM_ERROR),chr(10),'<br>'),p_display_location=>apex_error.c_inline_in_notification);end if;
exception when others then
 :P{page}_ITEM_ERROR:='The stored row, policy or draft context changed. Reopen before editing.';
 apex_debug.error('Item context failed: %s',sqlerrm);
 apex_error.add_error(p_message=>:P{page}_ITEM_ERROR,p_display_location=>apex_error.c_inline_in_notification);
end;"""


def _check_capacity(text):
    """Check actual final UTF-8 bodies, including all inherited components."""
    for code in re.findall(r'    validation [\w-]+ \(.*?```plsql\n(.*?)\n\s*```',text,re.S):
        _need(len(code.strip().encode()) <= 3950, 'VALIDATION_CAPACITY')
    for code in re.findall(r'    process [\w-]+ \(.*?```plsql\n(.*?)\n\s*```',text,re.S):
        _need(len(code.strip().encode()) <= 32767, 'PROCESS_CAPACITY')


def _render(text, parsed, buffer, target, c):
    page = target['page_id']
    collection = _one(re.findall(r"'(FOX_S_[A-F0-9]{20}_)'", text)[:1], 'SAVE_COLLECTION')
    # Version the extended row schema; never reuse an older retained collection.
    new_collection = c['collection_namespace']
    text = text.replace(collection, new_collection)
    # The default APEX AJAX error path does not repaint changed page-item binds.
    # A real page reload redisplays the source-cleared code on validation failure.
    text = _replace(text, '    title: Validate draft records\n',
                    '    title: Validate draft records\n    advanced { reloadOnSubmit: always }\n')
    weight = c['fields']['weight']['column']
    route = c['fields']['route']['column']
    text = _replace(text, 'select c.' + route + ',c.FOX_ROW_ID', 'select c.' + weight + ',c.' + route + ',c.FOX_ROW_ID')
    text = _replace(text, "p_c040=>r." + route + ",", f"p_n002=>r.{weight},p_n003=>r.{weight},p_c044=>r.{route},p_c040=>r.{route},")
    # Extend the actual Save, retaining the existing fresh parent route copy.
    start = text.index('    process save-synthetic-record (')
    end = text.index('\n    )', start) + len('\n    )')
    save = text[start:end]
    save = _replace(save, 'l_changed number;', 'l_changed number;l_item_weight number;l_base_weight number;l_active_route varchar2(4000);')
    save = _replace(save, 'c040,c041 into l_id,', 'c040,c041,n002,n003,c044 into l_id,')
    save = _replace(save, 'l_base_route,l_marker', 'l_base_route,l_marker,l_item_weight,l_base_weight,l_active_route')
    save = _replace(save, _compact(' and ' + native_buffer._parent_match('c.' + route, 'l_base_route') + ' for update nowait;'),
                    _compact(' and ' + native_buffer._parent_match('c.' + route, 'l_base_route') + f' and decode(c.{weight},l_base_weight,1,0)=1 for update nowait;'))
    route_changed = 'not (' + native_buffer._parent_match('l_active_route','l_base_route') + ')'
    save = _replace(save, ')then 1 else 0 end into l_changed',
                    ' or decode(l_item_weight,l_base_weight,1,0)=0 or ' + _compact(route_changed) + ')then 1 else 0 end into l_changed')
    insert = re.search(r'insert into ' + c['child_table'] + r'\(([^)]*)\)values\(([^)]*)\)', save)
    _need(insert, 'SAVE_INSERT')
    save = save[:insert.start()] + insert[0].replace(')values(', f',{weight})values(')[:-1] + ',l_item_weight)' + save[insert.end():]
    save = _replace(save, f',{route}=l_route where FOX_ROW_ID=l_id;', f',{route}=l_route,{weight}=l_item_weight where FOX_ROW_ID=l_id;')
    sync = f"apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>40,p_attr_value=>l_route);"
    save = _replace(save, sync, sync + f"apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>44,p_attr_value=>l_route);apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>3,p_number_value=>l_item_weight);")
    # Preserve the earlier source warnings alongside the later write outcome.
    prefix = 'apex_application.g_print_success_message:='
    save = save.replace(prefix, prefix + "apex_application.g_print_success_message||case when apex_application.g_print_success_message is not null then '<br>' end||")
    text = text[:start] + save + text[end:]
    # Source failure blocks every later draft mutation independently of how APEX
    # schedules its error display. Normal validations still keep their own gates.
    for name in ('keep-draft-and-move', 'save-synthetic-record'):
        pattern = r'(    process ' + name + r' \(.*?```plsql\n)(.*?)(\n\s*```)'
        match = re.search(pattern, text, re.S)
        _need(match, 'DOWNSTREAM_PROCESS')
        code = match[2]
        code = _replace(code, 'end context_ok;begin',
                        f'end context_ok;begin if :P{page}_ITEM_ERROR is not null then return;end if;')
        text = text[:match.start(2)] + code + text[match.end(2):]
    def skip_after_failure(match):
        old = native_buffer._expand_groups('        serverSideCondition { type: requestIsContainedInValue\n'
            + '            value: ' + ','.join(native_buffer.REQUESTS) + '\n        }\n')
        condition = f':REQUEST in ({native_buffer._requests()}) and :P{page}_ITEM_ERROR is null'
        new = native_buffer._expand_groups('        serverSideCondition { type: expression\n'
            + '            language: plsql\n            plsqlExpression: ' + json.dumps(condition) + '\n        }\n')
        return _replace(match[0],old,new)
    text, count = re.subn(r'    validation [\w-]+ \(.*?\n    \)',
                          skip_after_failure,text,flags=re.S)
    _need(count == 3, 'EXACT_DRAFT_VALIDATIONS')
    # Initialization loads from the retained collection on errors. Every source
    # effect above survives that reload, including cleared code after failure.
    hidden = native_buffer._expand_groups(native_buffer._hidden(page, 'ITEM_ERROR', 88))
    process = native_buffer._expand_groups(native_buffer._process('validate-edited-item',
        _compact(_event_code(parsed,buffer,page,c,new_collection)), point='afterSubmit', sequence=5))
    _need(text.endswith(')\n'), 'PAGE_SHAPE')
    text = native_buffer._expand_groups(text[:-2] + hidden + process + ')\n')
    _check_capacity(text)
    return text.encode()


def apply_item_validations(documents, packet, chunks, trace, files):
    """Apply after synthetic Save, before downstream coordination decoration."""
    actual, actual_chunks = _build(documents)
    _need(actual['source_binding'] == packet.get('source_binding') and actual['sources'] == packet.get('sources')
          and actual_chunks == chunks and trace.get('source_binding') == packet['source_binding'], 'SOURCE_BINDING')
    manifest = json.loads(files['fox-package/source-manifest.json'])
    _need(manifest['source_binding'] == packet['source_binding'] and json.loads(files['fox-package/source-to-page.json']) == trace
          and manifest['selected_chunk_hashes'] == {c['id']: c['sha256'] for c in chunks}
          and manifest['files'] == [{k: s['source'][k] for k in ('name','sha256','bytes')}
                                    for s in actual['sources']], 'MANIFEST_TRACE')
    for name, raw in documents:
        _need(files['fox-package/sources/' + name] == raw, 'ORIGINAL_SOURCE')
    output = dict(files)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': packet['source_binding'],
               'generated_operations': [], 'adapted_operations': [], 'encoded_operations': [], 'gaps': [], 'converted_code_unit_count': 0,
               'customer_table_writes': False, 'original_reads_enabled': False,
               'oracle_compiled': False, 'runtime_verified': False, 'business_accepted': False}
    objects, props = _source_objects(documents, packet)
    by_owner = {c['code_unit_id']: c for c in chunks}
    candidates = [(u, objects[u['owner_id']]) for s in actual['sources'] for u in s['facts']['code_units']
                  if (objects[u['owner_id']].get('name') or '').upper() == 'WHEN-VALIDATE-ITEM']
    for unit, owner in candidates:
        row = {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'], 'source_event': 'WHEN-VALIDATE-ITEM',
               'kind': 'cross_block_item_lookup_validation',
               'operation_id': 'fiv1-' + native_buffer._sha(native_buffer._json([packet['source_binding'],unit['id']]))[:24],
               'source_owner_id': owner['id'], 'generation_status': 'encoded_unwired',
               'native_event_wired': False, 'event_activated': False, 'oracle_compiled': False,
               'runtime_verified': False, 'business_accepted': False}
        try:
            parsed, decode = parse_item_validation(by_owner[unit['id']]['text'])
            row.update(parsed=parsed, decode_receipt=decode)
        except ValueError:
            # Other item events remain owned by their own recognizers.
            continue
        receipt['encoded_operations'].append(deepcopy(row))
        try:
            plan = validate_buffer_plan(json.loads(files['fox-package/buffer-plan.json']))
            buffer = _one([o for o in plan['operations'] if o['relation']['child_block_id'] == owner['block_id']], 'DRAFT_PROVIDER')
            target = _one([r for r in json.loads(files['fox-package/buffer-receipt.json'])['generated_operations']
                           if r['operation_id'] == buffer['operation_id']], 'DRAFT_PAGE')
            saves = json.loads(files['fox-package/synthetic-save-receipt.json'])
            write = _one([c for c in saves['write_contracts'] if c['buffer_operation_id'] == buffer['operation_id']], 'SAVE_PROVIDER')
            guard = _one([g for g in json.loads(files['fox-package/draft-policy-receipt.json'])['adapted_operations']
                          if g['buffer_operation_id'] == buffer['operation_id']], 'POLICY_PROVIDER')
            # Reconstruct the exact upstream page, not a caller-authored receipt.
            base = dict(files)
            from .forms_draft_policy import apply_draft_policies
            rendered = json.loads(files['fox-package/buffer-receipt.json'])['generated_operations']
            buffers = {b['operation_id']: b for b in plan['operations']}
            for item in rendered:
                base[item['page_file']] = native_buffer._page(buffers[item['operation_id']],item['page_id']).encode()
            base, _ = apply_draft_policies(documents,packet,chunks,trace,base)
            expected, proof = apply_synthetic_saves(documents,packet,chunks,trace,base)
            _need(proof == saves and all(expected[item['page_file']] == files[item['page_file']]
                                        for item in rendered), 'EXACT_SAVE_PAGE')
            c = _contract(parsed,owner,buffer,write,guard,objects,props,trace,files)
            c['collection_namespace'] = 'FOX_I_' + native_buffer._sha(native_buffer._json([SCOPE,c,parsed]))[:20].upper() + '_'
            output[target['page_file']] = _render(files[target['page_file']].decode(),parsed,buffer,target,c)
            row.update(operation_id='fiv1-' + native_buffer._sha(native_buffer._json([packet['source_binding'],unit['id'],c]))[:24],
                       generation_status='generated_wired_adapted', native_event_wired=True,
                       page_file=target['page_file'], page_id=target['page_id'], contract=c,
                       adaptation='Changed real draft item on submit; synthetic persisted lookup across all parents; session marker only.',
                       failure_redisplay='reloadOnSubmit_always_server_cleared_bind_and_retained_draft',
                       message_adaptation='Repeated source MESSAGE calls retain order in one HTML-escaped notification separated by line breaks; Save appends its own outcome.',
                       unexpected_error_policy='Retain completed ordered source assignments, block later processing and require retry using c043 ERROR; never treat as NO_DATA_FOUND or FORM_TRIGGER_FAILURE.',
                       navigation_implemented=False, forms_commit_implemented=False)
            if c['query_provider_ready']:
                receipt['generated_operations'].append(row)
            else:
                row.update(generation_status='generated_wired_adapted_partial',
                           omitted_effects=['source_query', 'duplicate_outcome', 'success_clock_after_query'],
                           save_boundary='Only a path that reaches the unavailable query is blocked; prior ERROR forces retry. Warning and unchanged paths retain independent guarded Save behavior.',
                           reason=c['query_provider_gap'])
                receipt['adapted_operations'].append(row)
                receipt['gaps'].append(deepcopy(row))
        except (ValueError, KeyError) as exc:
            receipt['gaps'].append({**row, 'reason': str(exc), 'next_action': 'Prove the exact guarded draft and synthetic source column provider.'})
    receipt['converted_code_unit_count'] = len(receipt['generated_operations'])
    return output, receipt
