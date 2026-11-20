"""Source-confirmed LOV selection into one selected synthetic-row session draft.

The reference-query adapter owns RecordGroupQuery coverage. This adapter adds
caller wiring only, never another converted source unit or a database write.
Only character caller/return fields have an implemented draft storage contract.
"""
from __future__ import annotations

from copy import deepcopy
import json
import re

from forms2apex import native_blueprint, native_record_groups as groups
from forms2apex.native_buffer import _expand_groups, _parent_match
from .forms_behavior_plan import _source_objects
from .forms_draft_policy import _expression, _compact
from .forms_native_plan import build_native_prototype_plan, POLICY_ID
from .forms_policy_plan import build_policy_plan
from .forms_understanding_packet import _build

SCOPE = 'fox-source-caller-lov-return-v1'
REQUEST = 'FOX_LOV_APPLY'


def _need(value, reason):
    if not value:
        raise ValueError('LOV_RETURN_' + reason)


def _one(values, reason):
    _need(len(values) == 1, reason)
    return values[0]


def _flag(props, name):
    value = props.get(name, '').strip().lower()
    _need(value in ('', 'true', 'false'), 'STATIC_PROPERTY_UNRESOLVED')
    # Normal Forms item/block edit flags default to true when not serialized.
    return value != 'false'


def _field(item, props, block):
    field = _one([f for f in block['items'] if f['source_item_id'] == item['id']], 'FIELD_NOT_MAPPED')
    _need(field['source_name'] == item['name'] and field['data_type'] == 'VARCHAR2'
          and props.get('DataType', '').upper() in ('CHAR', 'VARCHAR2'), 'CHARACTER_DRAFT_FIELD_REQUIRED')
    maximum = props.get('MaximumLength', '')
    semantics = props.get('DataLengthSemantics', '').upper()
    _need(re.fullmatch(r'[1-9][0-9]{0,3}', maximum) and int(maximum) <= 4000
          and semantics in ('BYTE', 'CHAR'), 'EXPLICIT_FIELD_LENGTH_REQUIRED')
    _need(props.get('Required', '').strip().lower() in ('', 'true', 'false'), 'NULL_RULE')
    return {**deepcopy(field), 'max_length': int(maximum), 'length_semantics': semantics,
            'required': props.get('Required', '').lower() == 'true',
            'display_only': props.get('ItemType', '').upper() == 'DISPLAY ITEM'}


def _policy(block, caller, targets, policy, objects, props):
    """Execute the complete entry property AST; unknown initial state denies.

    This is an existing-record adapter. Static update restrictions are checked
    independently and cannot be overridden by a submitted flag or local grant.
    """
    relevant = {block['source_block_id'], caller['id']} | {f['source_item_id'] for f in targets}
    for oid in relevant:
        _need(_flag(props[oid], 'UpdateAllowed') and _flag(props[oid], 'Enabled'),
              'EXISTING_ROW_UPDATE_DISABLED_NEW_DRAFT_INPUTS_AND_PERMISSIONS_UNPROVEN')
    module = caller['module_id']
    events = [o for o in objects.values() if o['kind'] == 'Trigger' and o['module_id'] == module
              and (o['name'] or '').upper() == 'WHEN-NEW-RECORD-INSTANCE'
              and (o['parent_id'] == module or o.get('block_id') == block['source_block_id'])]
    _need(not any(o['parent_id'] != module for o in events), 'BLOCK_OR_ITEM_ENTRY_OVERRIDE_UNPROVEN')
    if not events:
        return '1', []
    event = _one(events, 'ENTRY_POLICY_NOT_UNIQUE')
    op = _one([o for o in policy['operations'] if o['source_owner_id'] == event['id']], 'COMPLETE_ENTRY_POLICY_REQUIRED')
    for key, field in op['fields'].items():
        mapped = [f for f in block['items'] if f['source_item_id'] == key]
        _need(field['binding_kind'] == 'source_item' and field['source_block_id'] == block['source_block_id']
              and field['source_database_item'] is True and len(mapped) == 1
              and mapped[0]['column'] == field['column'] and mapped[0]['data_type'] == field['data_type'],
              'CURRENT_STORED_POLICY_FIELD_REQUIRED')
    states = {(oid, name): '1' for oid in relevant for name in ('UPDATE_ALLOWED', 'ENABLED')}
    effects = []

    def walk(nodes, condition=None):
        for node in nodes:
            kind = node['kind']
            if kind == 'local_call':
                walk(node['body'], condition)
            elif kind == 'if':
                sql = _expression(node['condition'], op['fields'])
                walk(node['body'], sql if condition is None else '(' + condition + ' AND ' + sql + ')')
            elif kind == 'property':
                key = (node['target_id'], node['property'])
                if key in states:
                    value = '1' if node['value'] else '0'
                    states[key] = value if condition is None else f'CASE WHEN {condition} THEN {value} ELSE {states[key]} END'
                    effects.append(deepcopy(node))
            else:
                raise ValueError('LOV_RETURN_COMPLETE_PROPERTY_ENTRY_BODY_REQUIRED')
    walk(op['body'])
    predicates = sorted(set(states.values()) - {'1'})
    expression = '1' if not predicates else 'CASE WHEN ' + ' AND '.join('(' + s + ')=1' for s in predicates) + ' THEN 1 ELSE 0 END'
    _need(len(expression.encode()) <= 4000, 'POLICY_CAPACITY')
    return expression, effects


def _contract(group, lov, caller, objects, props, trace, policy):
    block = _one([b for b in trace['blocks'] if b['source_block_id'] == caller['block_id']], 'CALLER_BLOCK')
    _need(block['classification'] == 'database' and block['source_module_id'] == caller['module_id'], 'CALLER_PROVIDER')
    _need(props[caller['id']].get('ItemType', '').upper() == 'TEXT ITEM', 'CALLER_TEXT_ITEM_REQUIRED')
    _need(props[caller['id']].get('ValidateFromList', '').lower() == 'true', 'VALIDATE_FROM_LIST_REQUIRED')
    targets = []
    columns = [p[-1] for p in group['query']['projections']]
    _need('FOX_CHOICE' not in columns, 'RESERVED_CHOICE_COLUMN')
    children = [o for o in objects.values() if o['kind'] == 'RecordGroupColumn' and o['parent_id'] == group['source_owner_id']]
    for mapping in lov['return_mappings']:
        ref = mapping['return_item'].upper().split('.')
        item = _one([o for o in objects.values() if o['kind'] == 'Item' and o['module_id'] == caller['module_id']
                     and (o['name'] or '').upper() == ref[-1]
                     and (len(ref) == 1 or (len(ref) == 2 and objects[o['block_id']]['name'].upper() == ref[0]))],
                    'RETURN_ITEM_NOT_UNIQUE')
        _need(item['block_id'] == caller['block_id'], 'CROSS_BLOCK_RETURN_UNPROVEN')
        field = _field(item, props[item['id']], block)
        source_column = mapping['source_column_name'].upper()
        _need(columns.count(source_column) == 1, 'RETURN_COLUMN_NOT_UNIQUE')
        index = columns.index(source_column)
        _need(props[children[index]['id']].get('ColumnDataType', '').upper() == 'CHARACTER', 'RETURN_SEMANTIC_TYPE_MISMATCH')
        targets.append({**field, 'source_column': source_column, 'projection_index': index + 1})
    _need(targets and len({f['source_item_id'] for f in targets}) == len(targets), 'RETURN_TARGET_NOT_UNIQUE')
    _need(sum(f['source_item_id'] == caller['id'] for f in targets) == 1, 'CALLER_NOT_A_RETURN_TARGET')
    inputs = []
    for binding in group['source_bindings']:
        _need(binding['source_block_id'] == caller['block_id'], 'CROSS_BLOCK_CALLER_INPUT_UNPROVEN')
        item = objects[binding['source_item_id']]
        _need(item.get('database_item') is True, 'INITIAL_SOURCE_INPUT_PROVIDER_UNPROVEN')
        inputs.append({**_field(item, props[item['id']], block), 'source_reference': binding['source_reference']})
    fields = list({f['source_item_id']: f for f in inputs + targets}.values())
    _need(len(fields) <= 18, 'DRAFT_CAPACITY')
    slots = {f['source_item_id']: i for i, f in enumerate(fields, 1)}
    for field in inputs + targets + fields:
        field['slot'] = slots[field['source_item_id']]
    expression, effects = _policy(block, caller, targets, policy, objects, props)
    return {'source_lov_id': lov['source_lov_id'], 'source_caller_id': caller['id'],
            'source_caller_name': caller['name'], 'block': deepcopy(block), 'fields': fields,
            'inputs': inputs, 'returns': targets, 'policy_expression_sql': expression,
            'enforced_policy_effects': effects, 'record_group_operation_id': group['operation_id']}


def _name(contract):
    return 'FOX_L_' + groups._sha(groups._json(contract))[:18].upper() + '_'


def _frame(value, dtype):
    """Fixed-width hash of each typed value, with a separate SQL NULL marker.

    Hash before framing: JSON escaping or several wide columns cannot overflow
    the finite outer VARCHAR2 hash input. DATE uses Julian day/seconds, NUMBER
    uses an explicit decimal convention, and text retains its original bytes.
    """
    tag = {'VARCHAR2':'C','NUMBER':'N','DATE':'D'}[dtype]
    encoded = value
    if dtype=='NUMBER':
        encoded = f"to_char({value},'TM9','NLS_NUMERIC_CHARACTERS=''.,''')"
    elif dtype=='DATE':
        encoded = f"to_char({value},'J')||':'||to_char({value},'SSSSS')"
    return f"CASE WHEN {value} IS NULL THEN '{tag}:N' ELSE '{tag}:V:'||RAWTOHEX(STANDARD_HASH({encoded},'SHA256')) END"


def _fingerprint(values):
    _need(len(values)*69<=3900,'TOKEN_FRAME_CAPACITY')
    return "RAWTOHEX(STANDARD_HASH(" + "||'|'||".join(_frame(value,dtype) for value,dtype in values) + ",'SHA256'))"


def _collection_expression(contract, page, values):
    baseline = _fingerprint(values)
    return "'" + _name(contract) + f"'||to_char(:P{page}_ID0,'TM9')||'_'||" + baseline


def _collection_sql(contract, page):
    # A changed stored baseline has a fresh namespace. Existing collections are
    # never truncated: reopening can recover without discarding an older draft.
    name = _collection_expression(contract, page, [(f['column'],f['data_type']) for f in contract['fields']])
    return f"(SELECT {name} FROM {contract['block']['table_name']} WHERE FOX_ROW_ID=:P{page}_ID0)"


def _choice_query(group, contract, page, *, ordered=False):
    replacements = {tuple(b['source_reference']): ':' + b['app_item'] for b in group['global_bindings']}
    collection = _collection_sql(contract, page)
    for field in contract['inputs']:
        replacements[tuple(field['source_reference'])] = (f"(SELECT c{field['slot']:03d} FROM apex_collections "
            f"WHERE collection_name={collection} AND seq_id=1 AND n001=:P{page}_ID0 AND c050='LOV_ROW')")
    query = deepcopy(group['query'])
    query['order'] = []
    predicates = [f"NVL(V('{group['readiness_item']}'),'N')='Y'",
                  "V('APP_USER') IS NOT NULL", "UPPER(V('APP_USER'))<>'NOBODY'",
                  f"EXISTS (SELECT 1 FROM apex_collections WHERE collection_name={collection} AND seq_id=1 AND n001=:P{page}_ID0 AND c050='LOV_ROW')"]
    predicates += [f":{b['app_item']} IS NOT NULL" for b in group['global_bindings']]
    rendered = groups.render_query(query, replacements, predicates)
    names = [p[-1] for p in query['projections']]
    # Bind every projected column, caller/row/revision and trusted input. Exact
    # duplicate rows retain duplicate tokens and fail SELECT INTO at Apply.
    context = [(groups._literal(groups._sha(groups._json(contract))),'VARCHAR2'),
               (f':P{page}_ID0','NUMBER'),
               (f'(SELECT n002 FROM apex_collections WHERE collection_name={collection} AND seq_id=1)','NUMBER')]
    context += [(replacements[tuple(f['source_reference'])],f['data_type']) for f in contract['inputs']]
    context += [(':' + b['app_item'],'VARCHAR2') for b in group['global_bindings']]
    types = {'CHARACTER':'VARCHAR2','NUMBER':'NUMBER','DATE':'DATE'}
    token = _fingerprint(context + [('q.'+n,types[t]) for n,t in zip(names,contract['column_types'])])
    result = f'SELECT q.*, {token} FOX_CHOICE FROM ({rendered}) q'
    if ordered and group['query']['order']:
        terms = []
        for term in group['query']['order']:
            name = term['parts'][-1]
            _need(names.count(name)==1, 'VISIBLE_SOURCE_ORDER_NOT_PROJECTED')
            terms.append('q.'+name+(' '+term['direction'] if term['direction'] else ''))
        result += ' ORDER BY '+','.join(terms)
    _need(len(result.encode())<=32767,'CHOICE_QUERY_CAPACITY')
    return result


def _context(contract, group, page, *, check_draft):
    fields, block = contract['fields'], contract['block']
    locked_name = _collection_expression(contract, page, [(f'l_base{i}',f['data_type']) for i,f in enumerate(fields,1)])
    code = f"""if :APP_USER is null or upper(:APP_USER)='NOBODY' then raise_application_error(-20031,'Authentication required.'); end if;
if :P{page}_ID0 is null or not regexp_like(:P{page}_ID0,'^[1-9][0-9]{{0,27}}$') then raise_application_error(-20031,'Select a source record.'); end if;
select {','.join(f['column'] for f in fields)}, {contract['policy_expression_sql']}
into {','.join('l_base'+str(i) for i in range(1,len(fields)+1))},l_allowed
from {block['table_name']} where FOX_ROW_ID=:P{page}_ID0 for update nowait;
if nvl(l_allowed,0)<>1 then raise_application_error(-20031,'Current source policy makes this record read only.'); end if;
select {locked_name} into l_name from dual;
"""
    if check_draft:
        code += f"""if nvl(v('{group['readiness_item']}'),'N')<>'Y' then raise_application_error(-20031,'Source interface is not ready.'); end if;
"""
        for binding in group['global_bindings']:
            code += f"if :{binding['app_item']} is null then raise_application_error(-20031,'Trusted source input is unavailable.'); end if;\n"
        matches = ' and '.join(_parent_match(f'c{20+i:03d}', f'l_base{i}') for i in range(1,len(fields)+1))
        code += f"""select n002 into l_revision from apex_collections where collection_name=l_name and seq_id=1
and c050='LOV_ROW' and n001=:P{page}_ID0 and {matches};
if :P{page}_REV is null or not regexp_like(:P{page}_REV,'^[0-9]{{1,10}}$') or l_revision<>to_number(:P{page}_REV) then
raise_application_error(-20031,'Draft changed. Reopen this record.'); end if;
"""
        for field in contract['inputs']:
            fn = 'lengthb' if field['length_semantics']=='BYTE' else 'length'
            test = f"nvl({fn}(c{field['slot']:03d}),0)>{field['max_length']} or nvl(lengthb(c{field['slot']:03d}),0)>4000"
            if field['required']:
                test += f" or c{field['slot']:03d} is null"
            code += (f"select case when {test} then 0 else 1 end into l_allowed from apex_collections "
                     "where collection_name=l_name and seq_id=1;"
                     "if l_allowed<>1 then raise_application_error(-20031,'Current caller input violates its source constraint.'); end if;\n")
    return code


def _process_code(group, contract, page, *, apply):
    count = len(contract['fields'])
    declarations = '\n'.join(f'l_base{i} varchar2(4000);' for i in range(1,count+1))
    code = f'declare l_name varchar2(255); l_revision number; l_allowed number; l_changed number; {declarations}\n'
    if apply:
        # All projections take part in the typed token. Exact SELECT INTO
        # rejects multiple rows before any assignment to the draft.
        code += '\n'.join(f"l_return{i} varchar2(4000);" for i in range(1,len(contract['returns'])+1))
    code += '\nbegin\nsavepoint fox_lov_return;\n'
    if apply:
        code += f"if :REQUEST is null or :REQUEST<>'{REQUEST}' then raise_application_error(-20031,'Unknown LOV action.'); end if;\n"
    else:
        code += f"if :REQUEST='{REQUEST}' then return; end if;\n"
    code += _context(contract, group, page, check_draft=apply)
    if apply:
        selected = ','.join(f"choices.{f['source_column']}" for f in contract['returns'])
        into = ','.join(f'l_return{i}' for i in range(1,len(contract['returns'])+1))
        code += f"""if :P{page}_TOKEN is null or not regexp_like(:P{page}_TOKEN,'^[A-F0-9]{{64}}$') then raise_application_error(-20031,'Choose a value from the list.'); end if;
select {selected} into {into} from ({_choice_query(group,contract,page)}) choices where choices.FOX_CHOICE=:P{page}_TOKEN;
"""
        for i, field in enumerate(contract['returns'], 1):
            fn = 'lengthb' if field['length_semantics'] == 'BYTE' else 'length'
            test = f'nvl({fn}(l_return{i}),0)>{field["max_length"]} or nvl(lengthb(l_return{i}),0)>4000'
            if field['required']:
                test += f' or l_return{i} is null'
            code += f"if {test} then raise_application_error(-20031,'Choice violates a source field constraint.'); end if;\n"
        matches = ' and '.join(_parent_match(f"c{f['slot']:03d}",f'l_return{i}') for i,f in enumerate(contract['returns'],1))
        code += f"select case when {matches} then 0 else 1 end into l_changed from apex_collections where collection_name=l_name and seq_id=1;\nif l_changed=1 then\n"
        for i, field in enumerate(contract['returns'], 1):
            code += f"apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>{field['slot']},p_attr_value=>l_return{i});\n"
        code += f"""apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>2,p_number_value=>l_revision+1);
:P{page}_REV:=to_char(l_revision+1,'TM9');
apex_application.g_print_success_message:='Choice returned to the selected session draft. No record was saved.';
else
apex_application.g_print_success_message:='The selected choice already matches this draft. No draft value changed.';
end if;
:P{page}_TOKEN:=null;
"""
    else:
        args = ','.join(f'p_c{i:03d}=>l_base{i},p_c{20+i:03d}=>l_base{i}' for i in range(1,count+1))
        code += f"""if not apex_collection.collection_exists(l_name) then
apex_collection.create_collection(l_name);
l_revision:=apex_collection.add_member(p_collection_name=>l_name,p_n001=>:P{page}_ID0,p_n002=>0,p_c050=>'LOV_ROW',{args});
end if;
select n002 into l_revision from apex_collections where collection_name=l_name and seq_id=1 and c050='LOV_ROW' and n001=:P{page}_ID0;
:P{page}_REV:=to_char(l_revision,'TM9');
"""
    for i in range(1,count+1):
        code += f"select c{i:03d} into :P{page}_F{i} from apex_collections where collection_name=l_name and seq_id=1;\n"
    code += """exception
when no_data_found then rollback to fox_lov_return; raise_application_error(-20031,'Source row, draft or choice changed. Reopen the record; no choice was applied.');
when too_many_rows then rollback to fox_lov_return; raise_application_error(-20031,'The complete choice is ambiguous; no choice was applied.');
when others then rollback to fox_lov_return; raise;
end;"""
    compact = _compact(code)
    _need(len(compact.encode())<=32767,'PROCESS_CAPACITY')
    return compact


def _render(group, contract, page):
    from .forms_record_entry import _chooser
    block = contract['block']
    chooser, _ = _chooser(page, page+1, [block], [])
    chooser = chooser.replace(f'alias: FOX_ENTRY_{page}',f'alias: FOX_LOV_{page}')
    result = page+1
    specs = [{'name': p[-1], 'label': p[-1], 'data_type': {'CHARACTER':'VARCHAR2','NUMBER':'NUMBER','DATE':'DATE'}[t],
              'nullable': True, 'primary_key': False}
             for p,t in zip(group['query']['projections'], contract['column_types'])]
    specs.append({'name': 'FOX_CHOICE', 'label': 'Choice identity', 'data_type': 'VARCHAR2', 'nullable': False, 'primary_key': False})
    link = _expand_groups(f'''        link {{ linkColumn: customTarget
            target: {{ page: {result}
                items: {{ P{result}_TOKEN: "#FOX_CHOICE#" }} }}
            linkIcon: Select choice }}
''')
    condition = _expand_groups(f'''        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: {json.dumps("nvl(v('"+group['readiness_item']+"'),'N')='Y' and :P"+str(result)+"_ID0 is not null")} }}
''')
    text = groups._report(result, specs, groups._sql_source(_choice_query(group,contract,result,ordered=True)),
                          label='Choose '+contract['source_caller_name'], link=link, condition=condition)
    text = text.replace(f'alias: FOX_GROUP_{result}',f'alias: FOX_LOV_{result}')
    text = groups._append(text, _expand_groups(f'''    region editor (
        name: Selected record draft
        type: staticContent
        source {{ htmlCode: "Choose a list row, then Apply choice. Values return to this selected source record's session draft. If stored source values change, reopening starts a fresh draft and preserves the earlier session draft separately. Original reads require administrator readiness. No record is saved. Other Forms validations and workflows remain separate." }}
        layout {{ sequence: 5
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
'''))
    for i, field in enumerate(contract['fields'], 1):
        # A real source caller field, edited through the adjacent joined chooser.
        # No submitted display/caller value ever becomes server authority.
        text = groups._append(text, _expand_groups(f'''    pageItem P{result}_F{i} (
        type: textField
        settings {{ trimSpaces: none }}
        label {{ label: {json.dumps(field['source_name'])} }}
        layout {{ sequence: {10*i}
            region: @editor
            slot: regionBody }}
        appearance {{ template: @/optional-floating }}
        sessionState {{ storage: request
            dataType: varchar2 }}
        readOnly {{ type: expression
            language: plsql
            plsqlExpression: "true" }}
        security {{ sessionStateProtection: restricted }}
    )
'''))
    from .forms_record_entry import _hidden
    text = groups._append(text, _expand_groups(_hidden(result,0)))
    for suffix in ('REV','TOKEN'):
        text = groups._append(text, _expand_groups(f'''    pageItem P{result}_{suffix} (
        type: hidden
        layout {{ sequence: 90
            region: @editor
            slot: regionBody }}
        sessionState {{ storage: session
            dataType: varchar2 }}
        security {{ sessionStateProtection: checksumRequiredSessionLevel }}
    )
'''))
    for apply, name, point, sequence in ((False,'load-caller-draft','beforeHeader',10),(True,'apply-lov-choice','processing',10)):
        condition = '' if not apply else f'''        serverSideCondition {{ type: requestIsContainedInValue
            value: {REQUEST} }}
'''
        text = groups._append(text, _expand_groups(f'''    process {name} (
        name: {name}
        type: executeCode
        source {{ plsqlCode:
                ```plsql
                {_process_code(group,contract,result,apply=apply)}
                ```
        }}
        execution {{ sequence: {sequence}
            point: {point} }}
{condition}    )
'''))
    text = groups._append(text, _expand_groups(f'''    button apply-choice (
        buttonName: {REQUEST}
        label: Apply choice
        layout {{ sequence: 10
            region: @editor
            slot: change }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: submitPage
            executeValidations: false }}
    )
'''))
    return chooser.encode(), text.encode()


def apply_lov_returns(documents, packet, chunks, trace, files):
    """Add source-confirmed caller adapters, retaining original query coverage."""
    from .xml_mapping import _blueprint
    fresh, fresh_chunks = _build(documents)
    _need(packet.get('source_binding') == fresh['source_binding'] and packet.get('sources') == fresh['sources']
          and fresh_chunks == chunks and trace['source_binding'] == fresh['source_binding'], 'SOURCE_CHANGED')
    _need(not any(re.fullmatch(r'pages/p\d+-fox_lov_\d+\.apx',name) for name in files), 'ALREADY_ADAPTED')
    spec = build_native_prototype_plan(documents, _blueprint(packet), project_id=trace['project_id'],
        project_name='LOV source proof', approved_policy_id=POLICY_ID)['rendering_spec']
    expected_trace = native_blueprint.prototype_trace(spec)
    objects, props = _source_objects(documents, packet)
    for block in expected_trace['blocks']:
        block['source_module_id'] = objects[block['source_block_id']]['module_id']
    _need(trace['blocks'] == expected_trace['blocks'] and files['fox-package/supporting-schema.sql'] ==
          native_blueprint.render_prototype_schema(spec).encode(), 'FRESH_SYNTHETIC_TRACE_REQUIRED')
    _need(all(files.get('fox-package/sources/'+name) == raw for name,raw in documents), 'ORIGINAL_SOURCES_REQUIRED')
    baseline = {k:v.encode() for k,v in native_blueprint.render_native_blueprint(spec).items()}
    _, expected = groups.apply_record_groups(documents, packet, chunks, trace, baseline)
    actual = json.loads(files['fox-package/record-group-receipt.json'])
    _need(actual == expected, 'FRESH_RECORD_GROUP_RECEIPT_REQUIRED')
    app_items = files.get('shared-components/app-items.apx',b'').decode()
    for group in expected['generated_operations']:
        for name in [group['readiness_item']] + [b['app_item'] for b in group['global_bindings']]:
            _need(app_items.count(groups._app_item(name)) == 1 and len(re.findall(r'\bappItem '+re.escape(name)+r'\s*\(',app_items)) == 1,
                  'RESTRICTED_SOURCE_GATE_REQUIRED')
    policy = build_policy_plan(documents, trace)
    output = dict(files)
    receipt = {'schema_version':1,'scope':SCOPE,'source_binding':packet['source_binding'],
               'generated_operations':[],'gaps':[],'converted_code_unit_count':0,
               'original_reads_enabled':False,'customer_table_writes':False,'synthetic_table_writes':False,
               'oracle_compiled':False,'runtime_verified':False,'business_accepted':False}
    occupied = {int(m[1]) for name in files if (m:=re.fullmatch(r'pages/p(\d+)-[^/]+\.apx',name))}
    page = 8400
    for group in expected['generated_operations']:
        for lov in group['associated_lovs']:
            callers = [o for o in objects.values() if o['kind']=='Item' and o['module_id']==group['source_module_id']
                       and props[o['id']].get('LovName','').upper() == lov['source_lov_name'].upper()]
            try:
                caller = _one(callers,'DECLARED_RETURNS_WITHOUT_SOURCE_CALLER' if not callers else 'CALLER_NOT_UNIQUE')
                contract = _contract(group,lov,caller,objects,props,trace,policy)
                children = [o for o in objects.values() if o['kind']=='RecordGroupColumn' and o['parent_id']==group['source_owner_id']]
                contract['column_types'] = [props[o['id']]['ColumnDataType'].upper() for o in children]
                while page in occupied or page+1 in occupied:
                    page += 2
                _need(page+1<8900,'PAGE_CAPACITY')
                chooser,editor = _render(group,contract,page)
                paths = [f'pages/p{p:05d}-fox_lov_{p}.apx' for p in (page,page+1)]
                block = contract['block']
                parent = output[block['report_file']].decode()
                _need(parent.startswith(f"page {block['report_page_id']} (\n"),'CALLER_NAVIGATION_PAGE')
                output[paths[0]],output[paths[1]] = chooser,editor
                output[block['report_file']] = groups._append(parent,groups._button(page,len(receipt['generated_operations'])+101,'Edit '+caller['name']+' choices')).encode()
                receipt['generated_operations'].append({'kind':'source_caller_lov_return',
                    'operation_id':'lov-return-'+groups._sha(groups._json(contract))[:24],
                    'source_unit_id':group['source_unit_id'],'source_unit_sha256':group['source_unit_sha256'],
                    'source_group_unit_id':group['source_unit_id'],'source_group_unit_sha256':group['source_unit_sha256'],
                    'record_group_operation_id':group['operation_id'],'source_lov_id':lov['source_lov_id'],
                    'source_caller_id':caller['id'],'source_caller_item_id':caller['id'],'source_caller_name':caller['name'],
                    'return_mappings':deepcopy(contract['returns']),
                    'page_id':page+1,'page_file':paths[1],'chooser_file':paths[0],
                    'contract':contract,'lov_return_implemented':True,'native_event_wired':True,
                    'generation_status':'generated_wired_adapted','query_already_counted':True,
                    'oracle_compiled':False,'runtime_verified':False,'business_accepted':False})
                occupied.update((page,page+1))
                page += 2
            except ValueError as exc:
                receipt['gaps'].append({'source_unit_id':group['source_unit_id'],'source_lov_id':lov['source_lov_id'],
                    'declared_return_mappings':deepcopy(lov['return_mappings']),'query_reporting_retained':True,
                    'reason':str(exc)})
        connected = sum(len(o['return_mappings']) for o in receipt['generated_operations']
                        if o['record_group_operation_id']==group['operation_id'])
        if connected:
            total = sum(len(lov['return_mappings']) for lov in group['associated_lovs'])
            message = (f'{connected} declared return mappings are connected in source caller editors; '
                       f'{total-connected} declared return mappings remain pending. This reference report remains read only.')
            for path in (group['page_file'],group['chooser_file']):
                text = output[path].decode().replace('LOV field selection and return remain unimplemented.',
                    'Use the source block report to open the connected caller editors.')
                text = text.replace(f'{total} explicit source LOV return mappings remain unimplemented.',message)
                output[path] = text.encode()
    return output,receipt
