"""Shared source-linked choices and durable, explicitly synthetic saved rows.

The original route renderer remains the fallback.  This adapter reuses its
typed-route transaction verbatim, changing only the supporting table names.
Nothing here calls the original source interfaces or implements their commits.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import re

from forms2apex import native_buffer, native_record_groups as groups
from . import forms_route_lookup_native as route
from .forms_lov_return import _fingerprint
from .forms_rate_choices import validate_rate_choices
from .forms_rate_numbers import validate_rate_numbers

SCOPE = 'fox-native-rate-workspace-v1'
SAVE = 'FOX_RATE_SAVE'
REOPEN = 'FOX_RATE_REOPEN'


def _need(ok, reason):
    if not ok:
        raise ValueError('RATE_WORKSPACE_' + reason)


def _checked(primary, bundle):
    c = route._checked(primary)
    b = validate_rate_choices(bundle, c)
    _need(type(b) is dict and b.get('schema_version') == 1, 'BUNDLE')
    for key in ('project_id', 'source_binding', 'source_block_id'):
        _need(b.get(key) == c.get(key), 'SOURCE_' + key.upper())
    _need(b.get('route_contract_id') == c['contract_id'], 'ROUTE_CONTRACT')
    _need(type(b.get('bundle_id')) is str and re.fullmatch(r'[a-z-]+[a-f0-9]{20,64}', b['bundle_id']), 'BUNDLE_ID')
    choices = b.get('choices')
    _need(type(choices) is list and 1 <= len(choices) <= 8, 'CHOICES')
    fields = deepcopy(c['fields'])
    seen = {f['source_item_id'] for f in fields}
    for choice in choices:
        _need(choice['source_block_id'] == c['source_block_id'] and choice['source_binding'] == c['source_binding'], 'CHOICE_SOURCE')
        _need(choice.get('original_interface_enabled') is False and choice.get('validate_from_list') is True, 'VFL')
        _need(re.fullmatch(r'[a-z-]+[a-f0-9]{20,64}', choice['contract_id']), 'CHOICE_ID')
        for key in ('source_lov_name', 'source_caller_name'):
            route._label(choice[key])
        raw = groups.render_query(choice['query'], {})
        query, bindings, _ = groups.parse_record_group_query(raw)
        _need(query == choice['query'] and not bindings and query['tables'] == [[choice['source_table']]], 'CLOSED_QUERY')
        columns = choice['columns']
        _need(1 <= len(columns) <= 18 and [p[-1] for p in query['projections']] == [v['name'] for v in columns], 'COLUMNS')
        _need(len({v['name'] for v in columns}) == len(columns), 'COLUMN_IDENTITY')
        for col in columns:
            groups._identifier(col['name'])
            _need(col['name'] not in ('FOX_CHOICE', 'FOX_ROW_UUID') and col['data_type'] in ('VARCHAR2', 'NUMBER'), 'COLUMN_TYPE')
            if col['data_type'] == 'VARCHAR2':
                _need(type(col['max_length']) is int and 1 <= col['max_length'] <= 4000 and col['length_semantics'] in ('BYTE', 'CHAR'), 'COLUMN_LENGTH')
        _need(choice['returns'] and choice['fields'] == choice['returns'], 'RETURNS')
        for f in choice['returns']:
            _need(f['source_item_id'] not in seen, 'OVERLAPPING_RETURN')
            seen.add(f['source_item_id'])
            slot = len(fields) + 1
            _need(f['slot'] == slot and f['column'] == f'F{slot:03d}' and f['data_type'] == 'VARCHAR2', 'FIELD_STORAGE')
            _need(type(f['max_length']) is int and 1 <= f['max_length'] <= 4000 and f['length_semantics'] in ('BYTE', 'CHAR'), 'FIELD_LENGTH')
            _need(type(f['required']) is bool and f['direct_edit_allowed'] is False, 'LIST_ONLY')
            route._label(f['source_name'])
            index = f['projection_index']
            _need(type(index) is int and 1 <= index <= len(columns) and columns[index-1]['name'] == f['source_column'] and columns[index-1]['data_type'] == 'VARCHAR2', 'RETURN_COLUMN')
            fields.append(deepcopy(f))
        _need(choice['caller']['source_item_id'] == choice['source_caller_item_id'] and any(f == choice['caller'] for f in choice['returns']), 'CALLER')
    _need(len(fields) <= 30 and b['fields'] == fields[len(c['fields']):], 'ALL_FIELDS')
    _need(len({ch['contract_id'] for ch in choices}) == len(choices), 'CHOICE_IDENTITY')
    return c, b, fields


def _names(c, b, numbers=None):
    identity = [c, b] if not numbers or not numbers['fields'] else [c, b, numbers]
    digest = sha256(route._json(identity).encode()).hexdigest()[:18].upper()
    return {'draft_table': 'FOX_WD_' + digest, 'saved_table': 'FOX_WS_' + digest,
            'catalog_table': 'FOX_WC_' + digest}


def _catalog_name(choice):
    return 'FOX_WL_' + sha256(route._json(choice).encode()).hexdigest()[:18].upper()


def _replace_route(text, c, names):
    for key, old in route._names(c).items():
        text = text.replace(old, names[key])
    return text


def _saved_owner():
    return ("APP_ID=to_number(v('APP_ID')) and OWNER_NAME=v('APP_USER') "
            "and v('APP_USER') is not null and upper(v('APP_USER'))<>'NOBODY'")


def _saved_row(page, *, baseline=False):
    return _saved_owner() + (" and SAVED_UUID=l_saved_uuid" if baseline else f' and SAVED_UUID=:P{page}_OPEN')


def _storage(field):
    # Plain NUMBER deliberately avoids NUMBER(p,s)'s implicit rounding.
    return 'number' if field['data_type'] == 'NUMBER' else 'varchar2(4000 byte)'


def _suffix(field):
    return ('N' if field['data_type'] == 'NUMBER' else 'F') + str(field['slot'])


def _local(field):
    return 'l_' + _suffix(field).lower()


def _number_input(field, page):
    return f"l_input_n{field['slot']}"


def _read_numbers(fields, page):
    return ''.join(f"{_number_input(f,page)}:=fox_n{f['slot']}(:P{page}_N{f['slot']});\n" for f in fields)


def _number_declarations(fields):
    return ''.join(f"l_input_n{f['slot']} number;" for f in fields)


def _number_match(left, right):
    # Numeric equality, rather than text formatting, defines unchanged input.
    return f'(({left}={right}) or ({left} is null and {right} is null))'


def _number_text(column):
    text = f"to_char({column},'TM9','NLS_NUMERIC_CHARACTERS=''.,''')"
    # TM9 emits .5 and -.5. The editor intentionally accepts a strict decimal
    # grammar, so make its own loaded values round-trip through that grammar.
    return f"(case when abs({column})<1 and {column}<>0 then replace({text},'.','0.') else {text} end)"


def _number_functions(fields):
    code = ''
    for f in fields:
        message = route._source_message(f['label'] + ': enter a decimal number using a dot, within the source picture and length; no rounding is applied.')
        invalid = 'invalid_number;'
        code += f"""function fox_n{f['slot']}(p_value varchar2) return number is
l_unsigned varchar2(4000);l_integer varchar2(4000);l_fraction varchar2(4000);l_dot pls_integer;l_value number;
procedure invalid_number is begin raise_application_error(-20031,{message});end;
begin
if p_value is null then return null; end if;
if lengthb(p_value)>{f['max_length']} or not regexp_like(p_value,'^[+-]?[0-9]+([.][0-9]+)?$','c') then {invalid} end if;
l_unsigned:=ltrim(p_value,'+-');l_dot:=instr(l_unsigned,'.');
if l_dot=0 then l_integer:=l_unsigned;else l_integer:=substr(l_unsigned,1,l_dot-1);l_fraction:=substr(l_unsigned,l_dot+1);end if;
l_integer:=ltrim(l_integer,'0');
if nvl(length(l_integer),0)>{f['integer_digits']} or nvl(length(l_fraction),0)>{f['scale']} then {invalid} end if;
l_value:=nvl(to_number(l_integer,'{'9'*38}','NLS_NUMERIC_CHARACTERS=''.,'''),0);
if l_fraction is not null then l_value:=l_value+to_number(l_fraction,'{'9'*38}','NLS_NUMERIC_CHARACTERS=''.,''')/power(10,length(l_fraction));end if;
if substr(p_value,1,1)='-' then l_value:=-l_value;end if;
"""
        for key, op in (('min_value', '<'), ('max_value', '>')):
            if f[key] is not None:
                code += f"if l_value{op}{f[key]} then {invalid} end if;\n"
        code += 'return l_value;\nend;\n'
    return code


def _numeric_route_action(code, c, names, page, action, fields):
    """Extend the original transaction at its declarations and atomic DML only."""
    functions = _number_functions(fields)
    code = code.replace('\nbegin\nsavepoint fox_row_lookup;', '\n'+_number_declarations(fields)+functions+'begin\nsavepoint fox_row_lookup;', 1)
    if action in ('FOX_ROW_CREATE', 'FOX_ROW_KEEP', 'FOX_ROW_CHOOSE'):
        # Validate before DML/navigation; errors leave the submitted controls intact.
        checks = _read_numbers(fields,page)
        marker = f"if :REQUEST is null or :REQUEST<>'{action}' then raise_application_error(-20031,'Unknown row action.'); end if;\n"
        _need(code.count(marker) == 1, 'NUMBER_ACTION_ANCHOR')
        code = code.replace(marker, marker+checks, 1)
    if action == 'FOX_ROW_CREATE':
        columns = ','.join(f['column'] for f in fields)
        values = ','.join(_number_input(f,page) for f in fields)
        code = code.replace('ROW_LABEL,REVISION)\nvalues(', f'ROW_LABEL,REVISION,{columns})\nvalues(', 1)
        code = code.replace(f"l_uuid,:P{page}_LABEL,0);", f"l_uuid,:P{page}_LABEL,0,{values});", 1)
    elif action == 'FOX_ROW_KEEP':
        marker = f'update {names["draft_table"]} set '
        _need(code.count(marker) == 1, 'NUMBER_KEEP_ANCHOR')
        assignments = ','.join(f"{f['column']}={_number_input(f,page)}" for f in fields)
        code = code.replace(marker, marker+assignments+',', 1)
    elif action == 'FOX_ROW_CHOOSE':
        marker = ';\nif l_count<>1 then raise_application_error(-20031,\'Keep draft changes before opening the choice list.\');'
        _need(code.count(marker) == 1, 'NUMBER_CHOOSE_ANCHOR')
        checks = ' and '.join(_number_match(f['column'], _number_input(f,page)) for f in fields)
        code = code.replace(marker, ' and '+checks+marker, 1)
    _need(len(code.encode()) <= 32767, 'PROCESS_CAPACITY')
    return code


def _ddl(c, b, fields, names):
    sql = route._ddl(c, route._names(c))
    sql = _replace_route(sql, c, names)
    marker = f" {c['fields'][0]['column']} varchar2(4000 byte)"
    extra = ' SAVED_UUID varchar2(32 byte),\n SAVED_REVISION number,\n'
    extra += ''.join(f" {f['column']} {_storage(f)},\n" for f in fields[len(c['fields']):])
    start = sql.index(f"create table {names['draft_table']} (")
    sql = sql[:start] + sql[start:].replace(marker, extra + marker, 1)
    columns = ',\n '.join(f"{f['column']} {_storage(f)}" for f in fields)
    sql += f'''\n-- Durable synthetic rows, scoped to this generated contract, application and user.
-- No session/expiry column: a new authenticated session may explicitly reopen.
create table {names['saved_table']} (
 APP_ID number not null,
 OWNER_NAME varchar2(255 byte) not null,
 SAVED_UUID varchar2(32 byte) not null,
 ROW_LABEL varchar2(160 byte) not null,
 REVISION number default 0 not null,
 CREATED_AT date default sysdate not null,
 UPDATED_AT date default sysdate not null,
 {columns},
 primary key (APP_ID,OWNER_NAME,SAVED_UUID)
);
'''
    for ch in b['choices']:
        cols = {col['name']: ('number' if col['data_type'] == 'NUMBER' else f"varchar2({col['max_length']} {col['length_semantics'].lower()})") for col in ch['columns']}
        for pred in ch['query']['predicates']:
            _need(pred['op'] == '=' and pred['left']['kind'] == 'column' and pred['right']['kind'] == 'string', 'PREDICATE')
            cols.setdefault(pred['left']['parts'][-1], 'varchar2(4000 byte)')
        sql += '\n-- Empty synthetic choice catalog; display projections are never row returns.\n'
        sql += f"create table {_catalog_name(ch)} (\n " + ',\n '.join(k+' '+v for k, v in cols.items()) + '\n);\n'
    return sql


def _companion_query(ch, names, page, *, ordered=False):
    query = deepcopy(ch['query'])
    query['tables'] = [[_catalog_name(ch)]]
    parts = query['projections'] + [p['left']['parts'] for p in query['predicates']] + [o['parts'] for o in query['order']]
    for col in parts:
        _need(len(col) == 1 or len(col) == 2 and col[0] == ch['source_table'], 'QUALIFIER')
        if len(col) == 2:
            col[0] = _catalog_name(ch)
    if not ordered:
        query['order'] = []
    values = [(groups._literal(ch['contract_id']), 'VARCHAR2'), ("v('APP_ID')", 'VARCHAR2'),
              ("v('APP_SESSION')", 'VARCHAR2'), ("v('APP_USER')", 'VARCHAR2'),
              (f':P{page}_ROW', 'VARCHAR2'), (f':P{page}_REV', 'VARCHAR2')]
    values += [('q.'+col['name'], col['data_type']) for col in ch['columns']]
    sql = f"select q.*,{_fingerprint(values)} FOX_CHOICE from ({groups.render_query(query,{})}) q where exists (select 1 from {names['draft_table']} where {route._row(None,page,revision=True)})"
    if ordered and ch['query']['order']:
        sql += ' order by ' + ','.join('q.'+o['parts'][-1]+(' '+o['direction'] if o['direction'] else '') for o in ch['query']['order'])
    return sql


def choice_query(primary, bundle, page, choice_index=0, *, ordered=False, numbers=None, parent=None):
    """Exact SELECT emitted for a chooser; zero is the existing route choice."""
    if parent is not None:
        from . import forms_rate_parent_page as linked
        return linked.bound_choice_query(primary, bundle, page, choice_index, ordered=ordered,
                                         numbers=numbers, parent=parent)
    c, b, _ = _checked(primary, bundle)
    numbers = validate_rate_numbers(numbers, c)
    names = _names(c, b, numbers)
    _need(type(choice_index) is int and 0 <= choice_index <= len(b['choices']), 'CHOICE_INDEX')
    if choice_index == 0:
        sql = _replace_route(route.choice_query(c, page), c, names)
        if ordered and c['query']['order']:
            sql += ' order by ' + ','.join('q.'+o['parts'][-1]+(' '+o['direction'] if o['direction'] else '') for o in c['query']['order'])
        return sql
    return _companion_query(b['choices'][choice_index-1], names, page, ordered=ordered)


def _dirty_check(c, names, page, numeric=()):
    checks = [native_buffer._parent_match('ROW_LABEL', f':P{page}_LABEL')]
    checks += [native_buffer._parent_match(f['column'], f':P{page}_F{f["slot"]}') for f in c['fields'] if f['direct_edit_allowed']]
    checks += [_number_match(f['column'], _number_input(f, page)) for f in numeric]
    return (f"select count(*) into l_count from {names['draft_table']} where {route._row(c,page,revision=True)} and " + ' and '.join(checks) + ';\n'
            "if l_count<>1 then raise_application_error(-20031,'Keep draft changes before saving or choosing.'); end if;\n")


def action_code(primary, bundle, page, action, choice_index=0, *, numbers=None, parent=None):
    """Complete emitted transaction; no commit, external call or business DML."""
    if parent is not None:
        from . import forms_rate_parent_page as linked
        return linked.bound_action_code(primary, bundle, page, action, choice_index,
                                        numbers=numbers, parent=parent)
    c, b, fields = _checked(primary, bundle)
    numbers = validate_rate_numbers(numbers, c)
    numeric = numbers['fields'] if numbers else []
    names = _names(c, b, numbers)
    fields += deepcopy(numeric)
    _need(type(choice_index) is int and 0 <= choice_index <= len(b['choices']), 'CHOICE_INDEX')
    if action in route.REQUESTS and (choice_index == 0 or action != 'FOX_ROW_APPLY'):
        code = _replace_route(route.action_code(c, page, action), c, names)
        return _numeric_route_action(code,c,names,page,action,numeric) if numeric else code
    _need(action in (SAVE, REOPEN, 'FOX_ROW_APPLY'), 'ACTION')
    table, saved = names['draft_table'], names['saved_table']
    declarations = 'l_revision number;l_count number;l_saved_uuid varchar2(32);l_saved_revision number;l_current number;l_uuid varchar2(32);'
    if action == 'FOX_ROW_APPLY':
        declarations += ''.join(f'l_return{i} varchar2(4000);' for i in range(1,len(b['choices'][choice_index-1]['returns'])+1))
    else:
        declarations += 'l_label varchar2(160);' + ''.join(f"{_local(f)} {_storage(f)};" for f in fields)
        # Preserve the original emitted declaration bytes for text-only contracts.
        declarations = declarations.replace('varchar2(4000 byte);', 'varchar2(4000);')
    declarations += _number_declarations(numeric)
    code = f"declare {declarations}\n{_number_functions(numeric)}begin\nsavepoint fox_rate_workspace;\n{route._auth()}"
    code += f"if :REQUEST is null or :REQUEST<>'{action}' then raise_application_error(-20031,'Unknown workspace action.'); end if;\n"
    if action in (SAVE, REOPEN):
        code += _read_numbers(numeric,page)
    cols = ','.join(f['column'] for f in fields)
    local = ','.join(_local(f) for f in fields)
    if action == REOPEN:
        code += f"if :P{page}_OPEN is null or not regexp_like(:P{page}_OPEN,'^[A-F0-9]{{32}}$') or :P{page}_SREV is null or not regexp_like(:P{page}_SREV,'^[0-9]{{1,12}}$') then raise_application_error(-20031,'Select a saved row from this application.'); end if;\n"
        code += f"select REVISION,ROW_LABEL,{cols} into l_saved_revision,l_label,{local} from {saved} where {_saved_row(page)} for update nowait;\n"
        code += f"if l_saved_revision<>to_number(:P{page}_SREV) then raise_application_error(-20031,'Saved row changed. Select it again.'); end if;\n"
        # A saved list entry is only a preview, but its permitted input controls
        # can still be edited. Never replace those submitted values silently
        # with the locked saved projection when creating the session draft.
        checks = [native_buffer._parent_match('l_label', f':P{page}_LABEL')]
        checks += [native_buffer._parent_match(f"l_f{f['slot']}", f':P{page}_F{f["slot"]}') for f in c['fields'] if f['direct_edit_allowed']]
        checks += [_number_match(_local(f), _number_input(f,page)) for f in numeric]
        code += "select count(*) into l_count from dual where " + ' and '.join(checks) + ';\n'
        code += "if l_count<>1 then raise_application_error(-20031,'Saved preview inputs changed. Copy your edits, select the saved row again, Reopen it, then apply your edits to the draft. Nothing was reopened.'); end if;\n"
        code += f"select count(*) into l_count from {table} where {route._owner()};\nif l_count>=100 then raise_application_error(-20031,'Discard an older session draft first.'); end if;\n"
        code += 'l_uuid:=rawtohex(sys_guid());\n'
        code += f"insert into {table}(APP_ID,SESSION_ID,OWNER_NAME,ROW_UUID,ROW_LABEL,REVISION,SAVED_UUID,SAVED_REVISION,{cols}) values(to_number(v('APP_ID')),v('APP_SESSION'),v('APP_USER'),l_uuid,l_label,0,:P{page}_OPEN,l_saved_revision,{local});\n"
        code += f":P{page}_ROW:=l_uuid; :P{page}_REV:='0'; :P{page}_OPEN:=null; :P{page}_SREV:=null;\n"
    else:
        code += route._identity(page)
        code += f"select REVISION into l_revision from {table} where {route._row(c,page)} for update nowait;\n"
        code += f"if l_revision<>to_number(:P{page}_REV) then raise_application_error(-20031,'Draft changed. Reopen it before trying again.'); end if;\n"
        if action == 'FOX_ROW_APPLY':
            ch = b['choices'][choice_index-1]
            code += f"if :P{page}_CHOICE is null or not regexp_like(:P{page}_CHOICE,'^[A-F0-9]{{64}}$') then raise_application_error(-20031,'Select one complete choice first.'); end if;\n"
            code += 'select ' + ','.join('q.'+f['source_column'] for f in ch['returns']) + ' into ' + ','.join('l_return'+str(i) for i in range(1,len(ch['returns'])+1))
            code += f" from ({_companion_query(ch,names,page)}) q where q.FOX_CHOICE=:P{page}_CHOICE;\n"
            for i, f in enumerate(ch['returns'], 1):
                code += route._validate_value(f, f'l_return{i}')
            assignments = ','.join(f"{f['column']}=l_return{i}" for i, f in enumerate(ch['returns'],1))
            code += f"update {table} set {assignments},REVISION=REVISION+1,EXPIRES_AT=sysdate+1 where {route._row(c,page,revision=True)};\n"
        else:
            code += _dirty_check(c,names,page,numeric)
            code += f"select SAVED_UUID,SAVED_REVISION,ROW_LABEL,{cols} into l_saved_uuid,l_saved_revision,l_label,{local} from {table} where {route._row(c,page,revision=True)};\n"
            for f in fields:
                if f['data_type'] != 'NUMBER':
                    choices = [choice['source_caller_name'] for choice in (c, *b['choices'])
                               if any(target['source_item_id'] == f['source_item_id'] for target in choice['returns'])]
                    chooser = choices[0] if len(choices) == 1 else None
                    code += route._validate_value(f, _local(f), chooser=chooser)
                elif f['required']:
                    label = route._source_message(f['label'])
                    code += f"if {_local(f)} is null then raise_application_error(-20031,{label}||' is required.'); end if;\n"
            # ValidateFromList applies when saving too: a previously selected
            # reference may have disappeared or become ambiguous. Optional
            # all-null mappings remain valid without inventing a catalog row.
            for ch in b['choices']:
                present = ' or '.join(f"l_f{f['slot']} is not null" for f in ch['returns'])
                checks = ' and '.join(native_buffer._parent_match('q.'+f['source_column'],f"l_f{f['slot']}") for f in ch['returns'])
                code += f"if {present} then\nselect count(*) into l_count from ({_companion_query(ch,names,page)}) q where {checks};\n"
                code += "if l_count<>1 then raise_application_error(-20031,'A list-validated value changed or is ambiguous. Choose it again before saving.'); end if;\nend if;\n"
            code += 'if l_saved_uuid is null then\nl_saved_uuid:=rawtohex(sys_guid());\nl_current:=0;\n'
            code += f"insert into {saved}(APP_ID,OWNER_NAME,SAVED_UUID,ROW_LABEL,REVISION,{cols}) values(to_number(v('APP_ID')),v('APP_USER'),l_saved_uuid,l_label,0,{local});\nelse\n"
            code += f"select REVISION into l_current from {saved} where {_saved_row(page,baseline=True)} for update nowait;\n"
            code += "if l_saved_revision is null or l_current<>l_saved_revision then raise_application_error(-20031,'Saved row changed. Reopen it; nothing was saved.'); end if;\n"
            assignments = ','.join(f"{f['column']}={_local(f)}" for f in fields)
            code += f"update {saved} set ROW_LABEL=l_label,{assignments},REVISION=REVISION+1,UPDATED_AT=sysdate where {_saved_row(page,baseline=True)} and REVISION=l_saved_revision;\n"
            code += "if sql%rowcount<>1 then raise_application_error(-20031,'Saved row changed; nothing was saved.'); end if;\nl_current:=l_current+1;\nend if;\n"
            code += f"update {table} set SAVED_UUID=l_saved_uuid,SAVED_REVISION=l_current,REVISION=REVISION+1,EXPIRES_AT=sysdate+1 where {route._row(c,page,revision=True)};\n"
        code += "if sql%rowcount<>1 then raise_application_error(-20031,'Draft changed; nothing was applied.'); end if;\n"
        code += f":P{page}_REV:=to_char(l_revision+1,'TM9');\n"
    code += f":P{page}_CHOICE:=null;\nexception\nwhen no_data_found then rollback to fox_rate_workspace; :P{page}_CHOICE:=null; raise_application_error(-20031,'Row or choice changed; nothing was applied.');\nwhen too_many_rows then rollback to fox_rate_workspace; :P{page}_CHOICE:=null; raise_application_error(-20031,'Choice is duplicated; nothing was applied.');\nwhen others then rollback to fox_rate_workspace; :P{page}_CHOICE:=null; raise;\nend;"
    _need(len(code.encode()) <= 32767, 'PROCESS_CAPACITY')
    return code


def _list(c, fields, names, page):
    cols = ','.join(f['column'] for f in fields)
    numeric_columns = {f['column'] for f in fields if f['data_type'] == 'NUMBER'}
    query = (f"select 'Draft' ROW_KIND,ROW_UUID,to_char(REVISION,'TM9') REVISION_TEXT,cast(null as varchar2(32)) OPEN_ID,cast(null as varchar2(32)) SAVED_REVISION_TEXT,ROW_LABEL,{cols} from {names['draft_table']} where {route._owner()} "
             f"union all select 'Saved synthetic row' ROW_KIND,cast(null as varchar2(32)) ROW_UUID,cast(null as varchar2(32)) REVISION_TEXT,SAVED_UUID OPEN_ID,to_char(REVISION,'TM9') SAVED_REVISION_TEXT,ROW_LABEL,{cols} from {names['saved_table']} where {_saved_owner()} order by ROW_KIND,ROW_LABEL")
    link = f'''        link {{ linkColumn: customTarget
            target: {{ page: {page}
                clearCache: {page}
                items: {{ P{page}_ROW: "#ROW_UUID#"
                    P{page}_REV: "#REVISION_TEXT#"
                    P{page}_OPEN: "#OPEN_ID#"
                    P{page}_SREV: "#SAVED_REVISION_TEXT#" }} }}
            linkIcon: Open row }}
'''
    columns = [('ROW_KIND', 'Row kind'), ('ROW_LABEL', 'Row label'), ('ROW_UUID', 'Session draft identity'),
               ('REVISION_TEXT', 'Draft revision'), ('OPEN_ID', 'Saved row identity'),
               ('SAVED_REVISION_TEXT', 'Saved revision')]
    columns.extend((f['column'], f['label'] if f['data_type'] == 'NUMBER' else f['source_name'])
                   for f in fields)
    return route._report(page, query, columns, 'Your session drafts and durable synthetic saved rows', link,
                         numeric_columns=numeric_columns)


def _choice_report(page, sql, ch, link):
    specs = [dict(name=col['name'],label=col['name'],data_type=col['data_type'],nullable=True,primary_key=False) for col in ch['columns']]
    specs.append(dict(name='FOX_CHOICE',label='Choice identity',data_type='VARCHAR2',nullable=False,primary_key=False))
    text = groups._report(page,specs,groups._sql_source(sql),label='Synthetic choices for '+ch['source_caller_name'],link=link)
    return text[text.index('    region records ('):-2]


def _load(c, b, fields, names, page, *, choice_index=None, numbers=None):
    cols = ','.join(_number_text(f['column']) if f['data_type'] == 'NUMBER' else f['column'] for f in fields)
    into = ','.join(f':P{page}_{_suffix(f)}' for f in fields)
    choosing = choice_index is not None
    sql = f"begin\n{route._auth()}if :REQUEST is null then\n:P{page}_ROW_DISPLAY:=:P{page}_ROW; :P{page}_SESSION_OWNER:=v('APP_USER');\n"
    if not choosing:
        sql += f"if :P{page}_ROW is null then\nif :P{page}_OPEN is not null then\n"
        sql += f"select ROW_LABEL,{cols} into :P{page}_LABEL,{into} from {names['saved_table']} where {_saved_row(page)} and REVISION=to_number(:P{page}_SREV);\nelse\n:P{page}_LABEL:=null; :P{page}_SREV:=null;\n"
        sql += ''.join(f':P{page}_{_suffix(f)}:=null;\n' for f in fields)
        sql += f'end if;\n:P{page}_REV:=null; return; end if;\n'
    else:
        sql += route._identity(page)
    sql += f"select ROW_LABEL,{cols},REVISION into :P{page}_LABEL,{into},:P{page}_REV from {names['draft_table']} where {route._row(c,page,revision=choosing)};\n"
    if choosing:
        ch = c if choice_index == 0 else b['choices'][choice_index-1]
        sql += ''.join(f':P{page}_PICK{i}:=null;\n' for i in range(1,len(ch['returns'])+1))
        sql += f"if :P{page}_CHOICE is not null then\nselect " + ','.join('q.'+f['source_column'] for f in ch['returns'])
        sql += ' into ' + ','.join(f':P{page}_PICK{i}' for i in range(1,len(ch['returns'])+1))
        sql += f" from ({choice_query(c,b,page,choice_index,numbers=numbers)}) q where q.FOX_CHOICE=:P{page}_CHOICE;\nend if;\n"
    sql += f"end if;\nexception when no_data_found then :P{page}_CHOICE:=null; raise_application_error(-20031,'Row or choice changed. Select it again.');\nwhen too_many_rows then :P{page}_CHOICE:=null; raise_application_error(-20031,'Choice is duplicated. Nothing was applied.');\nend;"
    return sql


def render_rate_workspace(primary, bundle, page, *, source_page=None, numbers=None, parent=None, block_label=None):
    """Return one editor and one chooser per source-linked LOV, plus empty DDL."""
    if parent is not None:
        from . import forms_rate_parent_page as linked
        return linked.render_bound_workspace(primary, bundle, page, source_page=source_page,
                                              numbers=numbers, parent=parent)
    c, b, fields = _checked(primary,bundle)
    numbers = validate_rate_numbers(numbers, c)
    numeric = numbers['fields'] if numbers else []
    fields += deepcopy(numeric)
    _need(type(page) is int and 1 <= page and page+1+len(b['choices']) <= 9999, 'PAGE')
    _need(source_page is None or type(source_page) is int and 1 <= source_page <= 9999, 'SOURCE_PAGE')
    names, pages = _names(c,b,numbers), []
    choices = [c] + b['choices']
    for offset in range(len(choices)+1):
        current = page+offset
        choosing = offset > 0
        index = offset-1
        body = ''.join(route._item(current,s,s,kind='hidden',protected=True) for s in ('ROW','REV','CHOICE','OPEN','SREV'))
        body += route._item(current,'LABEL','Synthetic row label',kind='displayOnly' if choosing else 'textField')
        body += route._item(current,'ROW_DISPLAY','Session draft row UUID',sequence=20)
        body += route._item(current,'SESSION_OWNER','Authenticated row owner',sequence=21)
        for f in fields:
            body += route._item(current,_suffix(f),f.get('label',f['source_name']) if f['data_type'] == 'NUMBER' else f['source_name'],kind='textField' if f['direct_edit_allowed'] and not choosing else 'displayOnly',sequence=(50 if f['data_type'] == 'NUMBER' else 30)+f['slot'])
        if choosing:
            ch = choices[index]
            for i, f in enumerate(ch['returns'],1):
                body += route._item(current,f'PICK{i}','Chosen '+f['source_name'],sequence=70+i)
            link = f'''        link {{ linkColumn: customTarget
            target: {{ page: {current}
                clearCache: {current}
                items: {{ P{current}_ROW: "&P{current}_ROW."
                    P{current}_REV: "&P{current}_REV."
                    P{current}_CHOICE: "#FOX_CHOICE#" }} }}
            linkIcon: Select choice }}
'''
            report = _choice_report(current,choice_query(c,b,current,index,ordered=True,numbers=numbers),ch,link)
            body += route._button('FOX_ROW_APPLY','Apply choice to this draft',10)
            body += route._process('apply-choice',action_code(c,b,current,'FOX_ROW_APPLY',index,numbers=numbers),action='FOX_ROW_APPLY')
            body += route._branch(current,page,'FOX_ROW_APPLY',revision=True)
            body += f'''    button cancel-choice (
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
            description = ('Select one synthetic choice, review its declared returns, then Apply to this row. '
                           'Display-only projections are not assigned to the row. Cancel preserves every draft and saved row. '
                           'Original interfaces and omitted source events are not executed.')
            label = 'Choose '+ch['source_caller_name']
        else:
            report = _list(c,fields,names,page)
            actions = [('FOX_ROW_CREATE','Create a separate draft'),('FOX_ROW_KEEP','Keep draft changes'),(SAVE,'Save synthetic row'),(REOPEN,'Reopen selected saved row'),('FOX_ROW_DISCARD','Discard selected draft')]
            for seq,(action,label) in enumerate(actions,1):
                body += route._button(action,label,seq*10)
                body += route._process(action.lower(),action_code(c,b,page,action,numbers=numbers),action=action)
                body += route._branch(page,page,action,revision=True)
            for i,ch in enumerate(choices):
                request = 'FOX_RATE_CHOOSE_'+str(i)
                code = action_code(c,b,page,'FOX_ROW_CHOOSE',numbers=numbers).replace("'FOX_ROW_CHOOSE'", "'"+request+"'")
                body += route._button(request,'Choose '+ch['source_caller_name'],70+i*10)
                body += route._process(request.lower(),code,action=request)
                body += route._branch(page,page+1+i,request,revision=True)
            description = ('Create a separate draft, Keep permitted inputs, and choose values for this same revision-checked row. '
                           'List-validated fields accept declared chooser returns only. Save synthetic row persists to private app/user storage. '
                           'Select a saved row in the list, then Reopen selected saved row to edit it in this or a new session. '
                           'Saved rows open as previews. Reopen before editing; changed preview inputs are rejected without creating a draft. '
                           'Keep changes before choosing or saving. Discard removes only the selected session draft; saved rows remain. '
                           'Original business writes, source commits, WHEN-CREATE-RECORD and other omitted events are not executed. '
                           'Only the displayed prototype projection is persisted; other source block fields and events remain unrepresented. '
                           'The existing source POST-CHANGE is wired to changed route inputs on Keep and route Apply when proved; catalogs start empty.')
            label = 'Synthetic row workspace for '+c['source_block_name']
        if block_label and block_label != c['source_block_name']:
            action = 'Choose ' + ch['source_caller_name'] if choosing else 'Rate workspace'
            label = block_label + ' / ' + action
            if len(label) > 255:
                # Keep the title distinguishable even for shared long prefixes.
                label = f'{block_label[:120]}... / {action[:110]} [page {current}]'
        if numeric:
            description += ' Source number inputs use a dot decimal separator without grouping or exponents; values outside the source picture or length are rejected without rounding.'
        body += route._process('load-shared-row',_load(c,b,fields,names,current,choice_index=index if choosing else None,numbers=numbers),point='beforeHeader')
        path = f'pages/p{current:05d}-fox_rate_{current}.apx'
        text = route._shell(current,label,description,report,body)
        text = text.replace(f'alias: FOX_ROW_{current}\n'.encode(),f'alias: FOX_RATE_{current}\n'.encode())
        pages.append({'page_id':current,'page_file':path,'text':text})
    prior = route.render_row_lookup(c,page,source_page=source_page)['metadata']
    metadata = {**prior,**names,'scope':SCOPE,'entry_page_file':pages[0]['page_file'],
                'chooser_page_file':pages[1]['page_file'],'page_count':len(pages),
                'draft_fields':deepcopy(fields),'saved_row_key':['APP_ID','OWNER_NAME','SAVED_UUID'],
                'saved_row_table_writes':True,'durable_synthetic_save':True,'saved_rows_expire':False,
                'reopen_request':REOPEN,'save_request':SAVE,'reopen_items':{'id':f'P{page}_OPEN','revision':f'P{page}_SREV'},
                'source_bundle_id':b['bundle_id'],'companion_choices':[]}
    if numeric:
        metadata['source_number_contract_id'] = numbers['contract_id']
        metadata['numeric_fields'] = deepcopy(numeric)
    metadata['synthetic_query_sql'] = _replace_route(prior['synthetic_query_sql'],c,names)
    for i,ch in enumerate(b['choices'],2):
        metadata['companion_choices'].append({**deepcopy(ch),'catalog_table':_catalog_name(ch),
            'page_id':page+i,'page_file':pages[i]['page_file'],'choice_index':i-1,
            'chooser_page_id':page+i,'chooser_page_file':pages[i]['page_file'],
            'catalog_columns':deepcopy(ch['columns']),'return_mappings':deepcopy(ch['returns']),
            'request':'FOX_ROW_APPLY','open_request':'FOX_RATE_CHOOSE_'+str(i-1),
            'synthetic_query_sql':_companion_query(ch,names,page+i,ordered=True)})
    # The original typed receipt points at the new paths but retains its source proof.
    for receipt in metadata.get('typed_lookup_receipts',[]):
        for binding in receipt['page_bindings']:
            binding['page_file'] = next(p['page_file'] for p in pages if p['page_id'] == binding['page_id'])
    return {'pages':pages,'supporting_sql':_ddl(c,b,fields,names).encode(),'metadata':metadata}
