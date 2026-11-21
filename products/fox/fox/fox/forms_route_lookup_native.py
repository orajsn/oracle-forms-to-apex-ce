"""Native source-linked row drafts and atomic complete LOV return.

Only the private supporting draft/catalog tables are accessed. The catalog is
empty until a tester supplies synthetic values; the source SELECT predicate is
translated, never replaced with a precomputed choice list. No source lifecycle
trigger, existing business row or original database interface is executed here.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re

from forms2apex import native_buffer, native_record_groups as groups
from .forms_lov_return import _fingerprint

SCOPE = 'fox-native-row-lookup-v1'
REQUESTS = ('FOX_ROW_CREATE', 'FOX_ROW_KEEP', 'FOX_ROW_CHOOSE', 'FOX_ROW_DISCARD', 'FOX_ROW_APPLY')


def _need(value, reason):
    if not value:
        raise ValueError('ROW_LOOKUP_NATIVE_' + reason)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _label(value):
    return groups._label(value)


def _checked(contract):
    c = deepcopy(contract)
    _need(type(c) is dict and type(c.get('contract_id')) is str, 'CONTRACT')
    _need(re.fullmatch(r'row-lookup-[a-f0-9]{20,64}', c['contract_id']), 'CONTRACT_ID')
    for key in ('source_block_name', 'source_caller_name', 'source_lov_name'):
        _label(c[key])
    _need(c.get('original_interface_enabled') is False, 'ORIGINAL_INTERFACE_DISABLED_REQUIRED')
    fields, returns, columns = c['fields'], c['returns'], c['columns']
    _need(1 <= len(fields) <= 18 and 1 <= len(columns) <= 18 and len(returns) == len(fields), 'FIELD_CAPACITY')
    _need(len({f['source_item_id'] for f in fields}) == len(fields), 'FIELD_IDENTITY')
    _need(len({f['column'] for f in fields}) == len(fields), 'FIELD_COLUMNS')
    _need(len({f['name'] for f in columns}) == len(columns), 'PROJECTION_COLUMNS')
    for i, field in enumerate(fields, 1):
        _label(field['source_name'])
        _need(field['column'] == f'F{i:03d}' and field['slot'] == i and field['data_type'] == 'VARCHAR2', 'FIELD_STORAGE')
        _need(type(field['max_length']) is int and 1 <= field['max_length'] <= 4000
              and field['length_semantics'] in ('BYTE', 'CHAR'), 'FIELD_LENGTH')
        _need(all(type(field[k]) is bool for k in ('required', 'display_only', 'direct_edit_allowed')), 'FIELD_FLAGS')
        _need(not (field['display_only'] and field['direct_edit_allowed']), 'DISPLAY_EDIT_DENIED')
    for col in columns:
        groups._identifier(col['name'])
        _need(col['name'] not in ('FOX_CHOICE', 'FOX_ROW_UUID') and col['data_type'] == 'VARCHAR2', 'COLUMN_TYPE')
        _need(type(col['max_length']) is int and 1 <= col['max_length'] <= 4000
              and col['length_semantics'] in ('BYTE', 'CHAR'), 'COLUMN_LENGTH')
    for target in returns:
        field = next((f for f in fields if f['source_item_id'] == target['source_item_id']), None)
        _need(field is not None and all(field[k] == target[k] for k in field), 'RETURN_FIELD')
        _need(type(target['projection_index']) is int and 1 <= target['projection_index'] <= len(columns), 'RETURN_INDEX')
        _need(columns[target['projection_index'] - 1]['name'] == target['source_column'], 'RETURN_COLUMN')
    _need(len({r['source_item_id'] for r in returns}) == len(fields), 'COMPLETE_RETURNS')
    _need(c['caller']['source_item_id'] == c['source_caller_item_id']
          and any(f == c['caller'] for f in fields), 'CALLER')
    # Round-trip the closed grammar rather than accepting arbitrary SQL/AST.
    raw = groups.render_query(c['query'], {})
    query, bindings, _ = groups.parse_record_group_query(raw)
    _need(query == c['query'] and not bindings and len(query['tables']) == 1
          and len(query['tables'][0]) == 1, 'CLOSED_SINGLE_TABLE_QUERY')
    _need(query['tables'][0][0] == c['source_table'], 'SOURCE_TABLE')
    _need([p[-1] for p in query['projections']] == [v['name'] for v in columns], 'PROJECTION_ORDER')
    _need(len(query['predicates']) == 1 and query['predicates'][0] == c['active_predicate'], 'ACTIVE_PREDICATE')
    predicate = c['active_predicate']
    _need(predicate['op'] == '=' and predicate['left']['kind'] == 'column'
          and predicate['right']['kind'] == 'string', 'ACTIVE_LITERAL_PREDICATE')
    for parts in query['projections'] + [predicate['left']['parts']] + [o['parts'] for o in query['order']]:
        _need(len(parts) == 1 or (len(parts) == 2 and parts[0] == c['source_table']), 'COLUMN_QUALIFIER')
    return c


def _names(c):
    digest = sha256(_json(c).encode()).hexdigest()[:18].upper()
    return {'draft_table': 'FOX_RD_' + digest, 'catalog_table': 'FOX_RC_' + digest}


def _owner(alias=''):
    prefix = alias + '.' if alias else ''
    return (f"{prefix}APP_ID=to_number(v('APP_ID')) and {prefix}SESSION_ID=v('APP_SESSION') "
            f"and {prefix}OWNER_NAME=v('APP_USER') and {prefix}EXPIRES_AT>sysdate "
            "and v('APP_USER') is not null and upper(v('APP_USER'))<>'NOBODY'")


def _row(c, page, *, revision=False, alias=''):
    prefix = alias + '.' if alias else ''
    result = _owner(alias) + f' and {prefix}ROW_UUID=:P{page}_ROW'
    if revision:
        result += f' and {prefix}REVISION=:P{page}_REV'
    return result


def _catalog_query(c, names, *, ordered=False):
    query = deepcopy(c['query'])
    query['tables'] = [[names['catalog_table']]]
    for projection in query['projections']:
        if len(projection) == 2:
            projection[0] = names['catalog_table']
    parts = query['predicates'][0]['left']['parts']
    if len(parts) == 2:
        parts[0] = names['catalog_table']
    for term in query['order']:
        if len(term['parts']) == 2:
            term['parts'][0] = names['catalog_table']
    if not ordered:
        query['order'] = []
    return groups.render_query(query, {})


def choice_query(contract, page):
    """Executable Oracle SELECT, also used by the exact-one Apply process."""
    c = _checked(contract)
    names = _names(c)
    values = [(groups._literal(c['contract_id']), 'VARCHAR2'), ("v('APP_ID')", 'VARCHAR2'),
              ("v('APP_SESSION')", 'VARCHAR2'), ("v('APP_USER')", 'VARCHAR2'),
              (f':P{page}_ROW', 'VARCHAR2'), (f':P{page}_REV', 'VARCHAR2')]
    values += [('q.' + col['name'], col['data_type']) for col in c['columns']]
    token = _fingerprint(values)
    sql = (f"select q.*, {token} FOX_CHOICE from ({_catalog_query(c, names)}) q "
           f"where exists (select 1 from {names['draft_table']} where {_row(c, page, revision=True)})")
    return sql


def _ddl(c, names):
    fields = ',\n '.join(f"{f['column']} varchar2(4000 byte)" for f in c['fields'])
    cols = {col['name']: f"varchar2({col['max_length']} {col['length_semantics'].lower()})" for col in c['columns']}
    active = c['active_predicate']['left']['parts'][-1]
    # The source does not declare a record-group length for its predicate-only
    # column. This is an explicit fixture storage limit, not invented metadata.
    cols.setdefault(active, 'varchar2(4000 byte)')
    catalog = ',\n '.join(name + ' ' + dtype for name, dtype in cols.items())
    return f"""-- Private FOX synthetic supporting objects; never original business tables.
-- The catalog is intentionally empty. Supply only disposable fixture values.
-- Predicate-only columns use a fixture capacity of 4000 bytes when the source
-- has no projected type/length declaration. Source projected lengths are kept.
create table {names['catalog_table']} (
 {catalog}
);
create table {names['draft_table']} (
 APP_ID number not null,
 SESSION_ID varchar2(255 byte) not null,
 OWNER_NAME varchar2(255 byte) not null,
 ROW_UUID varchar2(32 byte) not null,
 ROW_LABEL varchar2(160 byte) not null,
 REVISION number default 0 not null,
 CREATED_AT date default sysdate not null,
 EXPIRES_AT date default sysdate+1 not null,
 {fields},
 primary key (APP_ID,SESSION_ID,OWNER_NAME,ROW_UUID)
);
-- Drafts expire after 24 hours. Create removes at most 100 expired drafts
-- for this app/session/user; Discard removes only the explicitly selected row.
-- Optional test-schema maintenance, separately scoped to these synthetic rows:
-- delete from {names['draft_table']} where EXPIRES_AT<=sysdate and rownum<=100;
"""


def _auth():
    return """if v('APP_USER') is null or upper(v('APP_USER'))='NOBODY' then
 raise_application_error(-20031,'Authentication required.'); end if;
"""


def _validate_value(field, value, *, required=True):
    fn = 'lengthb' if field['length_semantics'] == 'BYTE' else 'length'
    test = f'nvl({fn}({value}),0)>{field["max_length"]} or nvl(lengthb({value}),0)>4000'
    if required and field['required']:
        test += f' or {value} is null'
    return f"if {test} then raise_application_error(-20031,'A value violates a source field length or required constraint.'); end if;\n"


def _identity(page):
    return f"""if :P{page}_ROW is null or not regexp_like(:P{page}_ROW,'^[A-F0-9]{{32}}$')
or :P{page}_REV is null or not regexp_like(:P{page}_REV,'^[0-9]{{1,12}}$') then
 raise_application_error(-20031,'Open a current session draft.'); end if;
"""


def _load(c, names, page, *, chooser):
    fields = ','.join(f['column'] for f in c['fields'])
    into = ','.join(f':P{page}_F{f["slot"]}' for f in c['fields'])
    revision = ',REVISION' if not chooser else ''
    revision_into = f',:P{page}_REV' if not chooser else ''
    sql = f"""begin
{_auth()}
if :REQUEST is null then
"""
    if chooser:
        sql += _identity(page)
    else:
        sql += f"if :P{page}_ROW is null then :P{page}_REV:=null; :P{page}_LABEL:=null;\n"
        sql += ''.join(f':P{page}_F{f["slot"]}:=null;\n' for f in c['fields'])
        sql += 'return; end if;\n'
    sql += f"""select ROW_LABEL,{fields}{revision} into :P{page}_LABEL,{into}{revision_into}
from {names['draft_table']} where {_row(c, page, revision=chooser)};
"""
    if chooser:
        sql += ''.join(f':P{page}_PICK{i}:=null;\n' for i in range(1,len(c['returns'])+1))
        targets = ','.join('q.' + f['source_column'] for f in c['returns'])
        picks = ','.join(f':P{page}_PICK{i}' for i in range(1,len(c['returns'])+1))
        sql += f"""if :P{page}_CHOICE is not null then
 select {targets} into {picks} from ({choice_query(c,page)}) q where q.FOX_CHOICE=:P{page}_CHOICE;
end if;
"""
    sql += f"""end if;
exception
 when no_data_found then :P{page}_CHOICE:=null;
 raise_application_error(-20031,'Draft or choice changed. Reopen the draft; nothing was applied.');
 when too_many_rows then :P{page}_CHOICE:=null;
 raise_application_error(-20031,'The complete choice is duplicated. Nothing was applied.');
end;"""
    # Editor also declares CHOICE so all error paths can clear it consistently.
    return sql


def action_code(contract, page, action):
    """The complete emitted transaction boundary, exposed for target verification."""
    c = _checked(contract)
    _need(action in REQUESTS, 'ACTION')
    names = _names(c)
    table = names['draft_table']
    fields = c['fields']
    declarations = 'l_revision number; l_count number; l_uuid varchar2(32);'
    if action == 'FOX_ROW_APPLY':
        declarations += ''.join(f'l_return{i} varchar2(4000);' for i in range(1,len(c['returns'])+1))
    code = f"declare {declarations}\nbegin\nsavepoint fox_row_lookup;\n{_auth()}"
    code += f"if :REQUEST is null or :REQUEST<>'{action}' then raise_application_error(-20031,'Unknown row action.'); end if;\n"
    if action == 'FOX_ROW_CREATE':
        code += f"""if :P{page}_LABEL is null or lengthb(:P{page}_LABEL)>160 then
 raise_application_error(-20031,'Enter a draft label of at most 160 bytes.'); end if;
delete from {table} where rowid in (select rowid from {table}
 where APP_ID=to_number(v('APP_ID')) and SESSION_ID=v('APP_SESSION') and OWNER_NAME=v('APP_USER')
 and EXPIRES_AT<=sysdate and rownum<=100);
select count(*) into l_count from {table} where {_owner()};
if l_count>=100 then raise_application_error(-20031,'Discard an older session draft before creating another.'); end if;
l_uuid:=rawtohex(sys_guid());
insert into {table}(APP_ID,SESSION_ID,OWNER_NAME,ROW_UUID,ROW_LABEL,REVISION)
values(to_number(v('APP_ID')),v('APP_SESSION'),v('APP_USER'),l_uuid,:P{page}_LABEL,0);
:P{page}_ROW:=l_uuid; :P{page}_REV:='0';
"""
    else:
        code += _identity(page)
        # Lock before reading revision/choice so concurrent requests cannot both
        # apply a token derived from the same revision. CAS remains explicit.
        code += f"select REVISION into l_revision from {table} where {_row(c,page)} for update nowait;\n"
        code += f"if l_revision<>to_number(:P{page}_REV) then raise_application_error(-20031,'Draft changed. Reopen it before choosing again.'); end if;\n"
        if action == 'FOX_ROW_DISCARD':
            code += f"delete from {table} where {_row(c,page,revision=True)};\n"
            code += f':P{page}_ROW:=null; :P{page}_REV:=null; :P{page}_LABEL:=null;\n'
        elif action == 'FOX_ROW_CHOOSE':
            # Opening/cancelling a chooser must not Keep edits or consume a
            # revision. Require a separate explicit Keep before leaving edits.
            comparisons = [native_buffer._parent_match('ROW_LABEL', f':P{page}_LABEL')]
            comparisons += [native_buffer._parent_match(f['column'], f':P{page}_F{f["slot"]}')
                            for f in fields if f['direct_edit_allowed']]
            code += f"select count(*) into l_count from {table} where {_row(c,page,revision=True)} and " + ' and '.join(comparisons) + ';\n'
            code += "if l_count<>1 then raise_application_error(-20031,'Keep draft changes before opening the choice list.'); end if;\n"
        else:
            assignments = []
            if action == 'FOX_ROW_APPLY':
                code += f"if :P{page}_CHOICE is null or not regexp_like(:P{page}_CHOICE,'^[A-F0-9]{{64}}$') then raise_application_error(-20031,'Select one complete choice first.'); end if;\n"
                selected = ','.join('q.' + f['source_column'] for f in c['returns'])
                into = ','.join('l_return'+str(i) for i in range(1,len(c['returns'])+1))
                code += f'select {selected} into {into} from ({choice_query(c,page)}) q where q.FOX_CHOICE=:P{page}_CHOICE;\n'
                for i, field in enumerate(c['returns'], 1):
                    code += _validate_value(field, f'l_return{i}')
                    assignments.append(f"{field['column']}=l_return{i}")
            else:
                code += f"if :P{page}_LABEL is null or lengthb(:P{page}_LABEL)>160 then raise_application_error(-20031,'Enter a draft label of at most 160 bytes.'); end if;\n"
                assignments.append(f'ROW_LABEL=:P{page}_LABEL')
                for field in fields:
                    if field['direct_edit_allowed']:
                        value = f':P{page}_F{field["slot"]}'
                        # Partially filled drafts are allowed. Apply validates
                        # the complete mapped choice, including required fields.
                        code += _validate_value(field, value, required=False)
                        assignments.append(f"{field['column']}={value}")
            code += f"update {table} set {','.join(assignments)},REVISION=REVISION+1,EXPIRES_AT=sysdate+1 where {_row(c,page,revision=True)};\n"
            code += "if sql%rowcount<>1 then raise_application_error(-20031,'Draft changed; nothing was applied.'); end if;\n"
            code += f":P{page}_REV:=to_char(l_revision+1,'TM9');\n"
    code += f":P{page}_CHOICE:=null;\n"
    code += f"""exception
when no_data_found then rollback to fox_row_lookup;
 :P{page}_CHOICE:=null;
 raise_application_error(-20031,'Draft or choice changed. Reopen the draft; nothing was applied.');
when too_many_rows then rollback to fox_row_lookup;
 :P{page}_CHOICE:=null;
 raise_application_error(-20031,'The complete choice is duplicated. Nothing was applied.');
when others then rollback to fox_row_lookup; :P{page}_CHOICE:=null; raise;
end;"""
    _need(len(code.encode()) <= 32767, 'PROCESS_CAPACITY')
    return code


def _item(page, suffix, label, *, kind='displayOnly', protected=False, sequence=10):
    _label(label)
    settings = '        settings { trimSpaces: none }\n' if kind == 'textField' else ''
    appearance = '        appearance { template: @/optional-floating }\n' if kind == 'textField' else ''
    label_group = '' if kind == 'hidden' else f'        label {{ label: {json.dumps(label)} }}\n'
    return f'''    pageItem P{page}_{suffix} (
        type: {kind}
{settings}{label_group}        layout {{ sequence: {sequence}
            region: @editor
            slot: regionBody }}
{appearance}        sessionState {{ storage: request
            dataType: varchar2 }}
        security {{ sessionStateProtection: {'checksumRequiredSessionLevel' if protected else ('unrestricted' if kind == 'textField' else 'restricted')} }}
    )
'''


def _button(name, label, sequence):
    return f'''    button {name.lower().replace('_','-')} (
        buttonName: {name}
        label: {json.dumps(label)}
        layout {{ sequence: {sequence}
            region: @editor
            slot: change }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: submitPage
            executeValidations: false }}
    )
'''


def _process(name, code, *, action=None, point='processing'):
    process = native_buffer._process(name, code, point=point)
    if action:
        _need(process.endswith('    )\n'), 'PROCESS_TEMPLATE')
        process = process[:-6] + f'''        serverSideCondition {{ type: requestIsContainedInValue
            value: {action} }}
    )
'''
    return process


def _branch(source, destination, action, *, revision=False):
    items = f'P{destination}_ROW: "&P{source}_ROW."'
    if revision:
        items += f'\n                    P{destination}_REV: "&P{source}_REV."'
    return f'''    branch {action.lower().replace('_','-')}-return (
        name: Continue row workflow
        execution {{ sequence: 10
            point: afterProcessing }}
        behavior {{ type: pageOrUrl
            target: {{ page: {destination}
                clearCache: {destination}
                items: {{ {items} }} }} }}
        serverSideCondition {{ type: requestIsContainedInValue
            value: {action} }}
    )
'''


def _shell(page, label, description, report, body):
    text = groups._report(page, [], groups._sql_source('select 1 from dual where 1=0'), label=label)
    # Reuse the validated native shell while avoiding an empty report region.
    start = text.index('    region records (')
    text = text[:start] + ')\n'
    text = text.replace(f'alias: FOX_GROUP_{page}', f'alias: FOX_ROW_{page}')
    text = groups._append(text, f'''    region editor (
        name: {json.dumps(label)}
        type: staticContent
        source {{ htmlCode: {json.dumps(description)} }}
        layout {{ sequence: 5
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
''')
    return native_buffer._expand_groups(groups._append(text, report + body)).encode()


def _report(page, sql, columns, label, link):
    specs = [dict(name=name, label=title, data_type='VARCHAR2', nullable=True, primary_key=False)
             for name, title in columns]
    text = groups._report(page, specs, groups._sql_source(sql), label=label, link=link)
    return text[text.index('    region records ('):-2]


def render_row_lookup(contract, page, *, source_page=None):
    """Return two native pages plus separate empty supporting-object SQL.

    The integrator owns page allocation, entry links and inclusion of supporting
    SQL. Runtime/Oracle compilation and business acceptance remain unasserted.
    """
    c = _checked(contract)
    _need(type(page) is int and 1 <= page < 9998, 'PAGE')
    _need(source_page is None or (type(source_page) is int and 1 <= source_page <= 9999), 'SOURCE_PAGE')
    names = _names(c)
    chooser = page + 1
    pages = []
    for current in (page, chooser):
        choosing = current == chooser
        body = ''.join(_item(current, suffix, suffix, kind='hidden', protected=True)
                       for suffix in ('ROW','REV','CHOICE'))
        body += _item(current,'LABEL','Session draft label',kind='displayOnly' if choosing else 'textField',sequence=10)
        body += _item(current,'ROW_DISPLAY','Session draft row UUID',sequence=20)
        body += _item(current,'SESSION_OWNER','Session draft owner',sequence=21)
        # ROW_DISPLAY is set only from the trusted, checked row parameter.
        load = _load(c,names,current,chooser=choosing)
        load = load.replace('if :REQUEST is null then', f"if :REQUEST is null then\n:P{current}_ROW_DISPLAY:=:P{current}_ROW;\n:P{current}_SESSION_OWNER:=v('APP_USER');")
        for field in c['fields']:
            kind = 'textField' if field['direct_edit_allowed'] and not choosing else 'displayOnly'
            body += _item(current,f'F{field["slot"]}',field['source_name'],kind=kind,sequence=30+field['slot'])
        if choosing:
            for i, target in enumerate(c['returns'],1):
                body += _item(current,f'PICK{i}','Chosen '+target['source_name'],sequence=60+i)
            query = choice_query(c,current)
            if c['query']['order']:
                query += ' order by ' + ','.join('q.'+o['parts'][-1]+(' '+o['direction'] if o['direction'] else '') for o in c['query']['order'])
            link = f'''        link {{ linkColumn: customTarget
            target: {{ page: {current}
                clearCache: {current}
                items: {{ P{current}_ROW: "&P{current}_ROW."
                    P{current}_REV: "&P{current}_REV."
                    P{current}_CHOICE: "#FOX_CHOICE#" }} }}
            linkIcon: Select choice }}
'''
            report = _report(current,query,[(col['name'],col['name']) for col in c['columns']]+[('FOX_CHOICE','Choice identity')], 'Synthetic active choices',link)
            body += _button('FOX_ROW_APPLY','Apply choice to this draft',10)
            body += _process('apply-route',action_code(c,current,'FOX_ROW_APPLY'),action='FOX_ROW_APPLY')
            body += _branch(current,page,'FOX_ROW_APPLY',revision=True)
            body += f'''    button cancel-route (
        buttonName: FOX_ROW_CANCEL
        label: Cancel and return to draft
        layout {{ sequence: 20
            region: @editor
            slot: change }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {page}
                clearCache: {page}
                items: {{ P{page}_ROW: "&P{current}_ROW."
                    P{page}_REV: "&P{current}_REV." }} }} }}
    )
'''
            description = (f'Source block {c["source_block_name"]}; caller {c["source_caller_name"]}. '
                'Select an active synthetic choice, review all chosen values, then Apply. All declared return fields update together in this draft only. '
                'Cancel preserves this and other drafts. If a draft or choice changes, reopen and choose again. '
                'The catalog starts empty; a test administrator supplies disposable synthetic choices. Original interfaces are disabled.')
        else:
            columns = [('ROW_UUID','Draft row UUID'),('ROW_LABEL','Draft label'),('REVISION_TEXT','Revision')]
            columns += [(f['column'],f['source_name']) for f in c['fields']]
            sql = f"select ROW_UUID,ROW_LABEL,to_char(REVISION,'TM9') REVISION_TEXT," + ','.join(f['column'] for f in c['fields'])
            sql += f" from {names['draft_table']} where {_owner()} order by CREATED_AT,ROW_UUID"
            link = f'''        link {{ linkColumn: customTarget
            target: {{ page: {page}
                clearCache: {page}
                items: {{ P{page}_ROW: "#ROW_UUID#"
                    P{page}_REV: "#REVISION_TEXT#" }} }}
            linkIcon: Open draft }}
'''
            report = _report(page,sql,columns,'Your separate session drafts',link)
            actions = [('FOX_ROW_CREATE','Create a separate draft'),('FOX_ROW_KEEP','Keep draft changes'),
                       ('FOX_ROW_CHOOSE','Open choice list'),('FOX_ROW_DISCARD','Discard selected draft')]
            for sequence,(action,label) in enumerate(actions,1):
                body += _button(action,label,sequence*10)
                body += _process(action.lower(),action_code(c,page,action),action=action)
                body += _branch(page,chooser if action=='FOX_ROW_CHOOSE' else page,action,revision=True)
            description = (f'Source block {c["source_block_name"]}; caller {c["source_caller_name"]}. '
                'Enter a session draft label and Create a separate draft, or Open a draft below to switch rows. '
                'Each UUID identifies an independent draft belonging to your authenticated application session. '
                'The choice list returns every declared XML mapping to that row. Display items are not direct inputs. '
                'Keep draft changes before opening the list. Opening or cancelling the list preserves the row and revision. '
                'These private supporting-table drafts expire after 24 hours and are never saved as original business rows. '
                'Source POST-CHANGE, WHEN-CREATE-RECORD and other omitted behavior are not executed. '
                'Create uses the label only; enter permitted source inputs after opening the new draft.')
        body += _process('load-row-draft',load,point='beforeHeader')
        path = f'pages/p{current:05d}-fox_row_{current}.apx'
        pages.append({'page_id':current,'page_file':path,'text':_shell(current,
            ('Choose a value for ' if choosing else 'Session drafts for ')+c['source_block_name'],description,report,body)})
    metadata = {**names,'scope':SCOPE,'entry_page_id':page,'entry_page_file':pages[0]['page_file'],
        'chooser_page_id':chooser,'chooser_page_file':pages[1]['page_file'],
        'draft_row_key':['APP_ID','SESSION_ID','OWNER_NAME','ROW_UUID'],
        'draft_expiry_hours':24,'source_block_id':c['source_block_id'],
        'source_caller_item_id':c['source_caller_item_id'],'source_contract_id':c['contract_id'],
        'catalog_columns':deepcopy(c['columns']), 'catalog_active_predicate':deepcopy(c['active_predicate']),
        'source_query_sql':groups.render_query(c['query'],{}),
        'synthetic_query_sql':_catalog_query(c,names,ordered=True),
        'draft_fields':deepcopy(c['fields']),'return_mappings':deepcopy(c['returns']),
        'original_interface_enabled':False,'business_table_writes':False,'session_draft_table_writes':True,
        'synthetic_catalog_writes_from_ui':False,'source_post_change_executed':False,
        'source_when_create_record_executed':False,'oracle_compiled':False,'runtime_verified':False,'business_accepted':False}
    return {'pages':pages,'supporting_sql':_ddl(c,names).encode(),'metadata':metadata}
