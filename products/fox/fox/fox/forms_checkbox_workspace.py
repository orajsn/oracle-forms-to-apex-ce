"""Source-proved checkbox events on disposable, selected-row session drafts.

The native source table is read-only. Keep is an explicit synthetic action,
not Forms POST/COMMIT, durable Save, record entry or business acceptance.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import re

from forms2apex import native_buffer, native_record_groups as groups
from . import forms_route_lookup_native as route
from .forms_lov_return import _fingerprint

SCOPE = 'fox-native-checkbox-workspace-v1'
START = 'FOX_CHECKBOX_START'
KEEP = 'FOX_CHECKBOX_KEEP'
DISCARD = 'FOX_CHECKBOX_DISCARD'
REQUESTS = (START, KEEP, DISCARD)


def _need(ok, reason):
    if not ok:
        raise ValueError('CHECKBOX_WORKSPACE_' + reason)


def _checked(group):
    g = deepcopy(group)
    _need(type(g) is dict, 'GROUP')
    for key in ('project_id', 'source_binding', 'source_unit_id', 'source_block_id'):
        _need(type(g.get(key)) is str and bool(g[key]), key.upper())
    _need(type(g.get('source_unit_sha256')) is str and re.fullmatch('[a-f0-9]{64}', g['source_unit_sha256']), 'SOURCE_HASH')
    _need(type(g.get('table_name')) is str and re.fullmatch(r'FOX_NATIVE_[A-F0-9]{19}', g['table_name']), 'SYNTHETIC_TABLE')
    _need(type(g.get('report_page_id')) is int and 1 <= g['report_page_id'] <= 9999, 'SOURCE_PAGE')
    _need(g.get('when_checked', {}).get('enabled') is True and
          g.get('otherwise', {}).get('enabled') is False and
          g['otherwise'].get('clear_to_unchecked') is True, 'EVENT')
    _need(g['when_checked'].get('update_allowed') in (None, True), 'UPDATE_PERMISSION')
    _need(g['controller'].get('source_enabled') is not False and
          g['controller'].get('source_update_allowed') is not False, 'CONTROLLER_PERMISSION')
    _need(g.get('source_event') == 'WHEN-CHECKBOX-CHANGED' and
          g.get('input_policy', {}).get('allowed_values') == 'exact_checked_or_unchecked_only' and
          g['input_policy'].get('null_values') == 'reject' and
          g['input_policy'].get('other_values') == 'reject', 'NARROW_INPUT_POLICY')
    fields = [g['controller']] + g['dependents']
    _need(2 <= len(fields) <= 30, 'FIELDS')
    _need(len({f['source_item_id'] for f in fields}) == len(fields) and
          len({f['column'] for f in fields}) == len(fields), 'FIELD_IDENTITY')
    for f in fields:
        groups._identifier(f['column'])
        groups._label(f['source_name'])
        groups._label(f.get('label') or f['source_name'])
        _need(f.get('data_type') == 'VARCHAR2' and type(f.get('maximum_length')) is int and
              1 <= f['maximum_length'] <= 4000 and f.get('length_semantics') in ('BYTE', 'CHAR'), 'FIELD_TYPE')
        for key in ('checked_value', 'unchecked_value'):
            value = f.get(key)
            _need(type(value) is str and bool(value) and len(value.encode()) <= 4000 and
                  '\x00' not in value, 'LITERAL')
            size = len(value.encode()) if f['length_semantics'] == 'BYTE' else len(value)
            _need(size <= f['maximum_length'], 'LITERAL_LENGTH')
            groups._label(value)
        _need(f['checked_value'] != f['unchecked_value'], 'DISTINCT_VALUES')
        _need(f.get('source_update_allowed') is not False or
              g['when_checked'].get('update_allowed') is True, 'DEPENDENT_UPDATE_PERMISSION')
    # The source compiler owns admission. This renderer never treats its input
    # receipt as an authorization signature; the caller must rebuild it fresh.
    return g


def _fields(g):
    return [g['controller']] + g['dependents']


def _page(g, page):
    _need(type(page) is int and 1 <= page <= 9999 and page != g['report_page_id'], 'PAGE')


def _table(g):
    digest = sha256(route._json(g).encode()).hexdigest()[:18].upper()
    return 'FOX_CD_' + digest


def _value(value):
    # UNISTR avoids substitution. TO_CHAR converts the national characters to
    # the column character set before exact byte comparisons.
    encoded = value.encode('utf-16-be').hex().upper()
    return "to_char(unistr('" + ''.join('\\' + encoded[i:i+4] for i in range(0, len(encoded), 4)) + "'))"


def _same(left, right):
    # Both SQL and procedural IF accept RAW equality. The right hand side is
    # a validated nonempty checkbox literal, so NULL must explicitly be false.
    return f'({left} is not null and utl_raw.cast_to_raw({left})=utl_raw.cast_to_raw({right}))'


def _token(g, prefix='s.'):
    values = [(_value(g[k]), 'VARCHAR2') for k in
              ('project_id', 'source_binding', 'source_unit_id', 'source_unit_sha256')]
    values += [(prefix + 'FOX_ROW_ID', 'NUMBER')]
    values += [(prefix + f['column'], 'VARCHAR2') for f in _fields(g)]
    return _fingerprint(values)


def _source(g, page, *, lock=False):
    cols = ','.join('s.' + f['column'] for f in _fields(g))
    locals_ = ','.join('l_f' + str(i) for i in range(len(_fields(g))))
    return (f"select {_token(g)},{cols} into l_token,{locals_} from {g['table_name']} s "
            f"where s.FOX_ROW_ID=to_number(:P{page}_ID0)" + (' for update nowait' if lock else '') + ';\n'
            f"if l_token<>:P{page}_TOKEN then raise_application_error(-20031,'Selected source row changed. Select it again.'); end if;\n")


def _identity(page, *, draft=False):
    sql = route._auth()
    sql += f"if :P{page}_ID0 is null or not regexp_like(:P{page}_ID0,'^[0-9]{{1,18}}$') or :P{page}_TOKEN is null or not regexp_like(:P{page}_TOKEN,'^[A-F0-9]{{64}}$') then raise_application_error(-20031,'Select one synthetic source row.'); end if;\n"
    if draft:
        sql += f"if :P{page}_DRAFT is null or not regexp_like(:P{page}_DRAFT,'^[A-F0-9]{{32}}$') or :P{page}_REV is null or not regexp_like(:P{page}_REV,'^[0-9]{{1,12}}$') then raise_application_error(-20031,'Open a current checkbox session draft.'); end if;\n"
    return sql


def _owned(page, *, draft=False, revision=False):
    sql = route._owner() + f' and SOURCE_ROW_ID=to_number(:P{page}_ID0) and SOURCE_TOKEN=:P{page}_TOKEN'
    if draft:
        sql += f' and DRAFT_UUID=:P{page}_DRAFT'
    if revision:
        sql += f' and REVISION=to_number(:P{page}_REV)'
    return sql


def _decl(g):
    return ('l_token varchar2(64);l_revision number;l_uuid varchar2(32);l_count number;'
            + ''.join(f'l_f{i} varchar2(4000);l_prior_f{i} varchar2(4000);' for i in range(len(_fields(g)))))


def _permitted(field, value):
    a, b = _value(field['checked_value']), _value(field['unchecked_value'])
    return f"if not ({_same(value, a)} or {_same(value, b)}) then raise_application_error(-20031,'Only the source checked and unchecked values are permitted. NULL and other values are unavailable.'); end if;\n"


def action_code(group, page, action):
    """Expose the exact emitted PL/SQL boundary for independent Oracle gates."""
    g = _checked(group)
    _page(g, page)
    _need(action in REQUESTS, 'ACTION')
    table, fields = _table(g), _fields(g)
    sql = f'declare {_decl(g)}\nbegin\nsavepoint fox_checkbox_draft;\n'
    sql += _identity(page, draft=action != START)
    sql += f"if :REQUEST is null or :REQUEST<>'{action}' then raise_application_error(-20031,'Unknown checkbox action.'); end if;\n"
    if action == DISCARD:
        # Disposal remains possible after the source changed; it cannot alter
        # source or another draft, and still requires the current draft revision.
        sql += f'delete from {table} where {_owned(page, draft=True, revision=True)};\n'
    else:
        sql += _source(g, page, lock=True)
        if action == START:
            for i, field in enumerate(fields):
                sql += _permitted(field, f'l_f{i}')
            sql += f"select count(*) into l_count from {table} where {route._owner()};\n"
            sql += "if l_count>=100 then raise_application_error(-20031,'Discard an older checkbox draft first.'); end if;\n"
            sql += f"delete from {table} where APP_ID=to_number(v('APP_ID')) and SESSION_ID=v('APP_SESSION') and OWNER_NAME=v('APP_USER') and SOURCE_ROW_ID=to_number(:P{page}_ID0) and SOURCE_TOKEN=:P{page}_TOKEN and EXPIRES_AT<=sysdate;\n"
            sql += 'l_uuid:=rawtohex(sys_guid());\n'
            sql += f"insert into {table}(APP_ID,SESSION_ID,OWNER_NAME,SOURCE_ROW_ID,SOURCE_TOKEN,DRAFT_UUID,REVISION," + ','.join(f'C{i:03d}' for i in range(len(fields))) + ')\n'
            sql += f"values(to_number(v('APP_ID')),v('APP_SESSION'),v('APP_USER'),to_number(:P{page}_ID0),l_token,l_uuid,0," + ','.join(f'l_f{i}' for i in range(len(fields))) + ');\n'
            sql += f":P{page}_DRAFT:=l_uuid; :P{page}_REV:='0';\n"
        else:
            prior_columns = ','.join(f'C{i:03d}' for i in range(len(fields)))
            prior_values = ','.join(f'l_prior_f{i}' for i in range(len(fields)))
            sql += f"select REVISION,{prior_columns} into l_revision,{prior_values} from {table} where {_owned(page, draft=True)} for update nowait;\n"
            sql += f"if l_revision<>to_number(:P{page}_REV) then raise_application_error(-20031,'Checkbox draft changed. Reopen it before trying again.'); end if;\n"
            for i, field in enumerate(fields):
                sql += _permitted(field, f'l_prior_f{i}')
            signal = f':P{page}_OFF_CHANGED'
            sql += f"if not ({_same(signal, _value('N'))} or {_same(signal, _value('Y'))}) then raise_application_error(-20031,'Checkbox event state is invalid. Reopen the draft.'); end if;\n"
            sql += f'l_f0:=:P{page}_C0;\n' + _permitted(fields[0], 'l_f0')
            sql += f"if {_same('l_f0', _value(fields[0]['checked_value']))} then\n"
            for i, field in enumerate(fields[1:], 1):
                sql += f'l_f{i}:=:P{page}_C{i};\n' + _permitted(field, f'l_f{i}')
            sql += f"elsif {_same('l_prior_f0', _value(fields[0]['checked_value']))} or :P{page}_OFF_CHANGED='Y' then\n"
            sql += ''.join(f"l_f{i}:={_value(field['unchecked_value'])};\n" for i, field in enumerate(fields[1:], 1))
            # Record entry can disable existing checked days without clearing
            # them. An untouched OFF Keep must preserve those stored values;
            # disabled submitted controls are never an input authority.
            sql += 'else\n'
            sql += ''.join(f'l_f{i}:=l_prior_f{i};\n' for i in range(1, len(fields)))
            sql += 'end if;\n'
            assignments = ','.join(f'C{i:03d}=l_f{i}' for i in range(len(fields)))
            sql += f'update {table} set {assignments},REVISION=REVISION+1,EXPIRES_AT=sysdate+1 where {_owned(page, draft=True, revision=True)};\n'
    if action != START:
        sql += "if sql%rowcount<>1 then raise_application_error(-20031,'Checkbox draft changed; nothing was applied.'); end if;\n"
        sql += (f':P{page}_DRAFT:=null; :P{page}_REV:=null;\n' if action == DISCARD else
                f":P{page}_REV:=to_char(l_revision+1,'TM9');\n")
    sql += ("exception when no_data_found then rollback to fox_checkbox_draft; raise_application_error(-20031,'Row or draft changed; nothing was applied.');\n"
            "when dup_val_on_index then rollback to fox_checkbox_draft; raise_application_error(-20031,'A checkbox draft already exists. Reopen it; nothing was replaced.');\n"
            "when others then rollback to fox_checkbox_draft; raise;\nend;")
    _need(len(sql.encode()) <= 32767, 'PROCESS_CAPACITY')
    return sql


def load_code(group, page):
    g = _checked(group)
    _page(g, page)
    fields = _fields(g)
    sql = f'declare {_decl(g)}\nbegin\n' + _identity(page)
    sql += f":P{page}_ROW_DISPLAY:=:P{page}_ID0; :P{page}_SESSION_OWNER:=v('APP_USER');\n"
    sql += 'if :REQUEST is null then\n' + _source(g, page)
    # Reject unsupported source values before assigning any native checkbox.
    # Otherwise APEX's checkbox widget could display an invented OFF state.
    for i, field in enumerate(fields):
        sql += _permitted(field, f'l_f{i}')
    sql += 'for d in (select DRAFT_UUID,REVISION,' + ','.join(f'C{i:03d}' for i in range(len(fields)))
    sql += f' from {_table(g)} where {_owned(page)}) loop\nl_uuid:=d.DRAFT_UUID;l_revision:=d.REVISION;\n'
    sql += ''.join(f'l_f{i}:=d.C{i:03d};\n' for i in range(len(fields)))
    sql += 'end loop;\n'
    for i, field in enumerate(fields):
        sql += _permitted(field, f'l_f{i}')
    sql += f":P{page}_DRAFT:=l_uuid; :P{page}_REV:=to_char(l_revision,'TM9'); :P{page}_OFF_CHANGED:='N';\n"
    sql += ''.join(f':P{page}_C{i}:=l_f{i};\n' for i in range(len(fields)))
    sql += "end if;\nexception when no_data_found then raise_application_error(-20031,'Selected source row changed. Select it again.');\nend;"
    return sql


def _ddl(g):
    fields = ',\n '.join(f'C{i:03d} varchar2(4000 byte)' for i in range(len(_fields(g))))
    return f'''-- Disposable FOX checkbox session drafts only. Source table stays read-only.
create table {_table(g)} (
 APP_ID number not null,
 SESSION_ID varchar2(255 byte) not null,
 OWNER_NAME varchar2(255 byte) not null,
 SOURCE_ROW_ID number not null,
 SOURCE_TOKEN varchar2(64 byte) not null,
 DRAFT_UUID varchar2(32 byte) not null,
 REVISION number default 0 not null,
 EXPIRES_AT date default sysdate+1 not null,
 {fields},
 primary key (APP_ID,SESSION_ID,OWNER_NAME,SOURCE_ROW_ID,SOURCE_TOKEN)
);
'''


def _checkbox(page, index, field):
    text = route._item(page, f'C{index}', field.get('label') or field['source_name'], kind='textField', sequence=30+index)
    text = text.replace('type: textField', 'type: checkbox')
    text = text.replace('settings { trimSpaces: none }',
                        'settings { useDefaults: false\n            checkedValue: ' + json.dumps(field['checked_value']) +
                        '\n            uncheckedValue: ' + json.dumps(field['unchecked_value']) + ' }')
    return text


def client_code(group, page):
    """UI feedback only. Server independently derives permissions on every Keep."""
    g = _checked(group)
    _page(g, page)
    config = {'controller': f'P{page}_C0', 'checked': g['controller']['checked_value'],
              'offChanged': f'P{page}_OFF_CHANGED',
              'draft': f'P{page}_DRAFT', 'dependents': [
                  {'item': f'P{page}_C{i}', 'unchecked': f['unchecked_value']}
                  for i, f in enumerate(g['dependents'], 1)]}
    # Escape HTML script delimiters even though APEXlang emits a JS property.
    payload = json.dumps(config, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026').replace('`', '\\u0060')
    return '''(function () {
  const cfg = ''' + payload + ''';
  function update(changed) {
    const active = !!apex.item(cfg.draft).getValue();
    const on = apex.item(cfg.controller).getValue() === cfg.checked;
    if (active && changed && !on) apex.item(cfg.offChanged).setValue('Y', null, true);
    cfg.dependents.forEach(function (f) {
      const item = apex.item(f.item);
      if (active && changed && !on) item.setValue(f.unchecked, null, true);
      if (active && on) item.enable(); else item.disable();
    });
    if (active) apex.item(cfg.controller).enable(); else apex.item(cfg.controller).disable();
  }
  apex.jQuery('#' + cfg.controller).on('change.foxCheckboxDraft', function () { update(true); });
  update(false);
})();'''


def _target(source, destination):
    return f'''target: {{ page: {destination}
                clearCache: {destination}
                items: {{ P{destination}_ID0: "&P{source}_ID0."
                    P{destination}_TOKEN: "&P{source}_TOKEN." }} }}'''


def _field_admission(field, column):
    options = (_value(field[key]) for key in ('checked_value', 'unchecked_value'))
    hashes = ','.join("RAWTOHEX(STANDARD_HASH(" + value + ",'SHA256'))" for value in options)
    return f"({column} is not null and RAWTOHEX(STANDARD_HASH({column},'SHA256')) in ({hashes}))"


def _admission_sql(group, alias):
    return ' and '.join(_field_admission(field, alias + '.' + field['column']) for field in _fields(group))


def _status_query(group, alias, prefix, suffix):
    fields = _fields(group)
    # Keep diagnostics within Oracle's default 4000-byte VARCHAR2 result.
    # Long or repeated captions use the unique source item name.
    labels = [field.get('label') or field['source_name'] for field in fields]
    names = [field['source_name'] for field in fields]
    captions = [name if len(label.encode('utf-8')) > 80 or labels.count(label) > 1 else label
                for name, label in zip(names, labels)]
    if len({caption.casefold() for caption in captions}) != len(captions):
        captions = names
    messages, first_match = [], []
    outcomes = {'Checked': ('checked', 'Forms displays checked'),
                'Unchecked': ('unchecked', 'Forms displays unchecked'),
                'Not Allowed': ('reject', 'Forms disallows this value')}
    for field, caption in zip(fields, captions):
        column = alias + '.' + field['column']
        policy = field.get('source_other_values_policy') or {}
        outcome = outcomes.get(field.get('other_values'))
        proved = (outcome is not None and field.get('source_null_other_policy_proven') is True
                  and policy.get('source_property') == 'CheckBoxOtherValues'
                  and policy.get('source_value') == field['other_values']
                  and policy.get('display_state') == outcome[0])
        explanation = outcome[1] if proved else 'Forms setting unconfirmed'
        # Source item names in the admitted plan are bounded ASCII identifiers.
        _need(len(caption.encode('utf-8')) <= 80, 'STATUS_LABEL_CAPACITY')
        valid = _field_admission(field, column)
        detail = (f"{_value(caption)}||case when {column} is null then ': blank' else ': other code' end"
                  f"||' ({explanation})'")
        messages.append(f"case when {valid} then '' else {detail}||'; ' end")
        first_match.append(f"when not {valid} then 'Unavailable (first field): '||{detail}")
    valid = _admission_sql(group, alias)
    complete = (f"case when {valid} then 'Available' else 'Unavailable: '||"
                "rtrim(" + '||'.join(messages) + ",'; ') end")
    first = "case " + ' '.join(first_match) + " else 'Available' end"
    compact = f"case when {valid} then 'Available' else 'Unavailable: check stored checkbox codes' end"
    for status in (complete, first, compact):
        query = prefix + status + suffix
        if len(query.encode('utf-8')) <= 32767:
            return query
    raise ValueError('CHECKBOX_WORKSPACE_RECORD_QUERY_CAPACITY')


def attach_report_action(text, block, group, page):
    """Link from the current business row without replacing its existing actions."""
    from textwrap import dedent
    from forms2apex.native_display_projection import _show_column, _sql_query
    from forms2apex.native_relations import _projection_columns

    regions = list(re.finditer(r'^    region records \(\n.*?^    \)\n', text, re.M | re.S))
    _need(len(regions) == 1, 'RECORD_REGION_UNAVAILABLE')
    region = regions[0].group()
    _need('        type: interactiveReport\n' in region, 'RECORD_REGION_UNAVAILABLE')
    sources = list(re.finditer(r'^        source \{\n.*?^        \}', region, re.M | re.S))
    _need(len(sources) == 1, 'RECORD_QUERY_UNAVAILABLE')
    source = sources[0].group()
    table = group['table_name']
    _need(block['table_name'] == table and block['synthetic_key']['column'] == 'FOX_ROW_ID',
          'RECORD_IDENTITY_UNAVAILABLE')
    _need(region.count('        column FOX_ROW_ID (\n') == 1, 'RECORD_IDENTITY_UNAVAILABLE')
    if source == ('        source {\n            location: localDatabase\n            type: tableView\n'
                  f'            tableName: {table}\n        }}'):
        alias = 'r'
        names = ['FOX_ROW_ID'] + [f['column'] for f in block['items']]
        for name in names:
            groups._identifier(name)
        projection = 'select ' + ', '.join(alias + '.' + n for n in names)
        position = len(projection)
        query = projection + f'\nfrom {table} {alias}'
        trailing = ''
    else:
        match = re.fullmatch(r'        source \{\n            location: localDatabase\n            type: sqlQuery\n'
                             r'            sqlQuery:\n                \x60{3}sql\n(.*?)\n                \x60{3}\n'
                             r'((?:            pageItemsToSubmit: [A-Z0-9_, ]+\n)?)        \}', source, re.S)
        _need(match is not None, 'RECORD_QUERY_UNAVAILABLE')
        query, trailing = dedent(match[1]), match[2]
        # Match the generated base-table report only. Keep the original SQL and
        # its filters, ordering, display expressions and submitted items intact.
        main_from = list(re.finditer(r'^from ([A-Z][A-Z0-9_]*)(?: (r))?$', query, re.M))
        _need(query.startswith('select ') and len(main_from) == 1 and main_from[0][1] == table,
              'RECORD_QUERY_UNAVAILABLE')
        code = re.sub(r"'(?:[^']|'')*'", ' ', query)
        _need(not re.search(r'\b(union|intersect|minus|group\s+by|having|connect\s+by|model)\b', code, re.I)
              and not re.match(r'(?i)select\s+(?:distinct|unique)\b', query), 'RECORD_QUERY_UNAVAILABLE')
        alias = main_from[0][2] or table
        declared = re.findall(r'^        column ([A-Z][A-Z0-9_]*) \($', region, re.M)
        position = main_from[0].start() - 1
        projection = query[7:position].strip()
        expressions = re.sub(r"'(?:[^']|'')*'", ' ', projection)
        _need(not re.search(r'\b(?:count|sum|avg|min|max|listagg|stddev|variance)\s*\(', expressions, re.I),
              'RECORD_IDENTITY_UNAVAILABLE')
        slots = _projection_columns(projection, declared, row_alias=alias)
        _need(declared[0] == 'FOX_ROW_ID' and slots[0] in ('FOX_ROW_ID', alias + '.FOX_ROW_ID'),
              'RECORD_IDENTITY_UNAVAILABLE')
    token, action = f'FOX_TOKEN_{page}', f'FOX_EDIT_{page}'
    _need(all(f'        column {name} (\n' not in region for name in (token, action)), 'ROW_ACTION_COLLISION')
    # The link text is blank on unsupported rows. A separate status column
    # explains their admission without publishing a usable editor target.
    status = f'FOX_STATUS_{page}'
    _need(f'        column {status} (\n' not in region, 'ROW_ACTION_COLLISION')
    valid = _admission_sql(group, alias)
    prefix = (query[:position] + f", case when {valid} then {_token(group, alias + '.')} end as {token}, "
              f"case when {valid} then 'Open draft' end as {action}, ")
    query = _status_query(group, alias, prefix, f" as {status}" + query[position:])
    region = region[:sources[0].start()] + _sql_query(query, trailing) + region[sources[0].end():]
    anchor = '        savedReport primary (\n'
    _need(region.count(anchor) == 1, 'PRIMARY_REPORT_UNAVAILABLE')
    seq = max([int(n) for n in re.findall(r'^                sequence: (\d+)$', region, re.M)] or [0]) + 10
    title = group['controller'].get('label') or group['controller']['source_name']
    groups._label(title)
    columns = f'''        column {token} (
            type: hidden
            heading {{ heading: Row snapshot }}
            layout {{ sequence: {seq} }}
            source {{ dataType: STRING }}
        )
        column {action} (
            type: link
            heading {{ heading: {json.dumps(title + ' draft')} }}
            layout {{ sequence: {seq + 10} }}
            source {{ dataType: STRING }}
            link {{
                target: {{ page: {page}
                    clearCache: {page}
                    items: {{
                        P{page}_ID0: "#FOX_ROW_ID#"
                        P{page}_TOKEN: "#{token}#"
                    }}
                }}
                linkText: "#{action}#"
            }}
        )
        column {status} (
            type: plainText
            heading {{ heading: {json.dumps(title + ' availability')} }}
            layout {{ sequence: {seq + 20} }}
            source {{ dataType: STRING }}
            security {{ escapeSpecialChars: true }}
        )
'''
    region = region.replace(anchor, native_buffer._expand_groups(columns) + anchor, 1)
    for column in (action, status):
        region = _show_column(region, column)
    return text[:regions[0].start()] + region + text[regions[0].end():]


def render_checkbox_workspace(group, page):
    """Return one separately allocated page and an additive report entry region.

    The lead appends entry_fragment to the proved source report. Existing report
    links/choosers are retained; this function never edits any existing page.
    """
    g = _checked(group)
    _page(g, page)
    source = g['report_page_id']
    prefix = f"select s.FOX_ROW_ID FOX_SELECTED_ROW,{_token(g)} FOX_SOURCE_TOKEN,"
    suffix = f" FOX_DRAFT_STATUS from {g['table_name']} s order by s.FOX_ROW_ID"
    query = _status_query(g, 's', prefix, suffix)
    link = f'''        link {{ linkColumn: customTarget
            target: {{ page: {page}
                clearCache: {page}
                items: {{ P{page}_ID0: "#FOX_SELECTED_ROW#"
                    P{page}_TOKEN: "#FOX_SOURCE_TOKEN#" }} }}
            linkIcon: Open checkbox session draft }}
'''
    entry = route._report(source, query, [('FOX_SELECTED_ROW', 'Synthetic account row'), ('FOX_SOURCE_TOKEN', 'Source snapshot'), ('FOX_DRAFT_STATUS', 'Checkbox draft availability')], 'Account checkbox session drafts', link)
    entry = entry.replace('region records (', f'region checkbox-entry-{page} (', 1)
    body = ''.join(route._item(page, suffix, suffix, kind='hidden', protected=True)
                   for suffix in ('ID0', 'TOKEN', 'DRAFT', 'REV'))
    off_changed = route._item(page, 'OFF_CHANGED', 'Manual controller off event', kind='hidden')
    off_changed = off_changed.replace('type: hidden\n', 'type: hidden\n        settings { valueProtected: false }\n')
    body += off_changed.replace('sessionStateProtection: restricted', 'sessionStateProtection: unrestricted')
    body += route._item(page, 'ROW_DISPLAY', 'Selected synthetic account row', sequence=20)
    body += route._item(page, 'SESSION_OWNER', 'Authenticated session draft owner', sequence=21)
    for i, field in enumerate(_fields(g)):
        body += _checkbox(page, i, field)
    for seq, (action, label) in enumerate(((START, 'Start checkbox session draft'), (KEEP, 'Keep checkbox draft changes'), (DISCARD, 'Discard checkbox session draft')), 1):
        body += route._button(action, label, seq*10)
        body += route._process(action.lower(), action_code(g, page, action), action=action)
        body += f'''    branch {action.lower().replace('_', '-')}-return (
        name: Continue checkbox draft
        execution {{ sequence: 10
            point: afterProcessing }}
        behavior {{ type: pageOrUrl
            {_target(page, page)} }}
        serverSideCondition {{ type: requestIsContainedInValue
            value: {action} }}
    )
'''
    body += f'''    button return-to-source (
        buttonName: FOX_CHECKBOX_RETURN
        label: Return to account rows
        layout {{ sequence: 50
            region: @editor
            slot: change }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {source} }} }}
    )
'''
    body += route._process('load-checkbox-draft', load_code(g, page), point='beforeHeader')
    description = ('Start copies only this synthetic account row into your private application/user/session draft. '
                   'Changing the controlling checkbox immediately enables only its declared dependent controls. '
                   'Switching off clears every dependent to its source unchecked value and disables it; switching on does not restore discarded input. '
                   'Keep retains existing days when an already-off controller was untouched; disabled submissions are ignored. '
                   'Keep applies a manual checkbox change to the session draft. It never saves the account or rates. '
                   'Only exact source checked and unchecked values are accepted; NULL and other stored values are rejected. '
                   'Drafts expire after 24 hours. Other source events, record entry, original POST/COMMIT and durable persistence are not executed. '
                   'Return leaves your draft available in this session; Discard deletes only the selected draft.')
    text = route._shell(page, 'Account checkbox session draft', description, '', body).decode()
    text = text.replace(f'alias: FOX_ROW_{page}\n', f'alias: FOX_CHECKBOX_{page}\n')
    js = client_code(g, page)
    text = groups._append(text, '    javaScript {\n        executeWhenPageLoads:\n            ```javascript\n' + '\n'.join('            ' + line for line in js.splitlines()) + '\n            ```\n    }\n')
    path = f'pages/p{page:05d}-fox_checkbox_{page}.apx'
    metadata = {'scope': SCOPE, 'page_id': page, 'page_file': path, 'page_alias': f'FOX_CHECKBOX_{page}',
                'source_page_id': source, 'source_page_file': g['report_file'], 'source_unit_id': g['source_unit_id'],
                'source_unit_sha256': g['source_unit_sha256'], 'source_block_id': g['source_block_id'],
                'project_id': g['project_id'], 'source_binding': g['source_binding'], 'draft_table': _table(g),
                'source_table': g['table_name'], 'source_snapshot_sql': query, 'draft_expiry_hours': 24,
                'draft_row_key': ['APP_ID', 'SESSION_ID', 'OWNER_NAME', 'SOURCE_ROW_ID', 'SOURCE_TOKEN'],
                'fields': deepcopy(_fields(g)), 'requests': list(REQUESTS),
                'input_policy': deepcopy(g['input_policy']),
                'manual_off_signal_item': f'P{page}_OFF_CHANGED',
                'source_widget_equivalence_proven': False,
                'business_table_writes': False, 'durable_synthetic_save': False, 'session_draft_table_writes': True,
                'source_event': 'WHEN-CHECKBOX-CHANGED', 'source_record_entry_executed': False,
                'original_interface_enabled': False, 'oracle_compiled': False, 'runtime_verified': False,
                'business_accepted': False}
    return {'pages': [{'page_id': page, 'page_file': path, 'text': text.encode()}],
            'supporting_sql': _ddl(g).encode(), 'entry_fragment': native_buffer._expand_groups(entry), 'metadata': metadata}
