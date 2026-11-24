"""Explicit parent-linked synthetic drafts, separate from read navigation.

APEX signs native navigation targets. Keys are always read from native synthetic
storage under a lock on creation; browser controls never supply copied values.
This does not implement Forms posting, permissions or original business writes.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import re

from forms2apex import native_buffer, native_record_groups as groups
from . import forms_rate_workspace as workspace
from .forms_lov_return import _fingerprint

CREATE = 'FOX_RATE_PARENT_CREATE'
SCOPE = 'fox-native-rate-parent-workspace-v1'


def _need(ok, reason):
    if not ok:
        raise ValueError('RATE_PARENT_WORKSPACE_' + reason)


def _checked(primary, bundle, parent, numbers=None):
    from .forms_rate_parent import validate_rate_parent
    c, b, fields = workspace._checked(primary, bundle)
    p = validate_rate_parent(parent, c)
    n = workspace.validate_rate_numbers(numbers, c)
    return c, b, p, n, fields


def _names(c, b, p, n):
    if not p.get('binding'):
        return workspace._names(c, b, n)
    digest = sha256(workspace.route._json([c, b, n, p]).encode()).hexdigest()[:18].upper()
    return {'draft_table': 'FOX_WD_' + digest, 'saved_table': 'FOX_WS_' + digest,
            'catalog_table': 'FOX_WC_' + digest}


def _replace(text, c, b, p, n):
    for name, old in workspace._names(c, b, n).items():
        text = text.replace(old, _names(c, b, p, n)[name])
    return text


def _pairs(p):
    return p['binding']['join_pairs']


def _standalone_allowed(p):
    return p['binding']['source_attributes'].get('PreventMasterlessOperations', '').lower() == 'false'


def _stamp(p, alias='p'):
    """Durable copied-key provenance, independent of other parent attributes."""
    values = [(groups._literal('fox-rate-parent-copied-key-snapshot-v1'), 'VARCHAR2'),
              (groups._literal(p['contract_id']), 'VARCHAR2'),
              (f"{alias}.FOX_ROW_ID", 'NUMBER')]
    values += [(alias + '.' + pair['parent_column'], pair['data_type']) for pair in _pairs(p)]
    return _fingerprint(values)


def _token(p, stamp):
    return _fingerprint([(groups._literal(p['contract_id']), 'VARCHAR2'),
                         ("v('APP_ID')", 'VARCHAR2'), ("v('APP_SESSION')", 'VARCHAR2'),
                         ("v('APP_USER')", 'VARCHAR2'), (stamp, 'VARCHAR2')])


def _non_null(p, alias='p'):
    return ' and '.join(alias + '.' + pair['parent_column'] + ' is not null' for pair in _pairs(p))


def _decl(p):
    return ('l_parent_id number;l_parent_stamp varchar2(64);l_current_stamp varchar2(64);'
            + ''.join(f"l_key{i} varchar2(4000);l_current_key{i} varchar2(4000);" for i, _ in enumerate(_pairs(p), 1)))


def _cols(p):
    return 'PARENT_ID,PARENT_STAMP,' + ','.join(pair['column'] for pair in _pairs(p))


def _locals(p):
    return 'l_parent_id,l_parent_stamp,' + ','.join(f'l_key{i}' for i, _ in enumerate(_pairs(p), 1))


def _current_parent(p, *, lock=True, target='l_parent_id'):
    pairs = _pairs(p)
    cols = ','.join('p.' + pair['parent_column'] for pair in pairs)
    variables = ','.join(f'l_current_key{i}' for i, _ in enumerate(pairs, 1))
    code = (f"select {_stamp(p)},{cols} into l_current_stamp,{variables} "
            f"from {p['binding']['parent']['table']} p where p.FOX_ROW_ID={target} "
            f"and {_non_null(p)}" + (' for update nowait' if lock else '') + ';\n')
    for i, pair in enumerate(pairs, 1):
        # UNKNOWN source semantics are deliberately bounded in both bytes and
        # characters. Never truncate and never claim source-equivalent length.
        for prefix in ('', 'parent_'):
            length = pair.get(prefix + 'max_length', pair['max_length'])
            semantics = pair.get(prefix + 'length_semantics', pair['length_semantics'])
            measure = 'length' if semantics == 'CHAR' else 'lengthb'
            code += (f"if {measure}(l_current_key{i})>{length} or lengthb(l_current_key{i})>4000 then "
                     "raise_application_error(-20031,'Parent key exceeds the declared conservative copy bound. Nothing was copied.'); end if;\n")
    return code


def _guard(p, table, where):
    code = f"select {_cols(p)} into {_locals(p)} from {table} where {where};\n"
    code += 'if l_parent_id is not null then\n' + _current_parent(p)
    equal = [native_buffer._parent_match('l_parent_stamp', 'l_current_stamp')]
    equal += [native_buffer._parent_match(f'l_key{i}', f'l_current_key{i}') for i, _ in enumerate(_pairs(p), 1)]
    code += ("select count(*) into l_count from dual where " + ' and '.join(equal)
             + ";\nif l_count<>1 then raise_application_error(-20031,'Parent changed. Nothing was applied. Select the parent again.'); end if;\nelse\n")
    code += 'if l_parent_stamp is not null or ' + ' or '.join(f'l_key{i} is not null' for i, _ in enumerate(_pairs(p), 1))
    code += " then raise_application_error(-20031,'Incomplete parent binding. Nothing was applied.'); end if;\nend if;\n"
    return code


def bound_choice_query(primary, bundle, page, choice_index=0, *, ordered=False, numbers=None, parent):
    c, b, p, n, _ = _checked(primary, bundle, parent, numbers)
    return _replace(workspace.choice_query(c, b, page, choice_index, ordered=ordered, numbers=n), c, b, p, n)


def bound_action_code(primary, bundle, page, action, choice_index=0, *, numbers=None, parent, initializer=None):
    c, b, p, n, _ = _checked(primary, bundle, parent, numbers)
    code = workspace.action_code(c, b, page, action, choice_index, numbers=n, initializer=initializer)
    if not p.get('binding'):
        return code
    names = _names(c, b, p, n)
    code = _replace(code, c, b, p, n)
    if action in ('FOX_ROW_CREATE', 'FOX_ROW_DISCARD'):
        # Masterless creation remains the existing explicitly partial workflow;
        # no parent values are silently inferred from other page/session state.
        if action == 'FOX_ROW_CREATE' and not _standalone_allowed(p):
            code = code.replace(workspace.route._auth(), workspace.route._auth() +
                                "raise_application_error(-20031,'This source requires explicit parent selection before creating a draft.');\n", 1)
        return code
    _need(code.startswith('declare '), 'DECLARATION_ANCHOR')
    # PL/SQL variables must precede local function definitions.
    code = code.replace('declare ', 'declare ' + _decl(p), 1)
    if action == workspace.REOPEN:
        anchor = f"select REVISION,ROW_LABEL,"
        offset = code.index(anchor)
        guard = _guard(p, names['saved_table'], workspace._saved_row(page))
        # Lock the saved row before reading its parent snapshot. The base
        # transaction repeats the lock and performs the preview/revision checks.
        guard = guard.replace(';' , ' for update nowait;', 1)
        code = code[:offset] + guard + code[offset:]
    else:
        anchor = "if l_revision<>to_number("
        start = code.index(anchor)
        offset = code.index('\n', start) + 1
        code = code[:offset] + _guard(p, names['draft_table'], workspace.route._row(c, page, revision=True)) + code[offset:]
    if action in (workspace.SAVE, workspace.REOPEN):
        table = names['saved_table'] if action == workspace.SAVE else names['draft_table']
        pattern = rf'(insert into {table}\([^;]+?)\) values\(([^;]+?)\);'
        def insert(match):
            return match[1] + ',' + _cols(p) + ') values(' + match[2] + ',' + _locals(p) + ');'
        code, count = re.subn(pattern, insert, code)
        _need(count == 1, 'INSERT_ANCHOR')
    if action == workspace.SAVE:
        # An existing saved row retains its original parent binding forever.
        anchor = f"select REVISION into l_current from {names['saved_table']} where "
        offset = code.index(anchor)
        equal = [native_buffer._parent_match('PARENT_ID', 'l_parent_id'),
                 native_buffer._parent_match('PARENT_STAMP', 'l_parent_stamp')]
        equal += [native_buffer._parent_match(pair['column'], f'l_key{i}') for i, pair in enumerate(_pairs(p), 1)]
        check = (f"select count(*) into l_count from {names['saved_table']} where {workspace._saved_row(page, baseline=True)} and "
                 + ' and '.join(equal) + ";\nif l_count<>1 then raise_application_error(-20031,'Saved parent binding changed. Nothing was saved.'); end if;\n")
        # Place after the saved lock, never trust an unlocked saved projection.
        end = code.index('\n', offset) + 1
        code = code[:end] + check + code[end:]
    _need(len(code.encode()) <= 32767, 'PROCESS_CAPACITY')
    return code


def _extra_load(p, names, page, choosing):
    into = ','.join(f':P{page}_K{i}' for i, _ in enumerate(_pairs(p), 1))
    cols = ','.join(pair['column'] for pair in _pairs(p))
    code = f"begin\n{workspace.route._auth()}if :REQUEST is null then\n"
    code += ''.join(f':P{page}_K{i}:=null;\n' for i, _ in enumerate(_pairs(p), 1))
    code += f':P{page}_PARENT_DISPLAY:=null;\n'
    code += f"if :P{page}_ROW is not null then\nselect PARENT_ID,{cols} into :P{page}_PARENT_DISPLAY,{into} from {names['draft_table']} where {workspace.route._row(None, page, revision=True)};\n"
    if not choosing:
        code += f"elsif :P{page}_OPEN is not null then\nselect PARENT_ID,{cols} into :P{page}_PARENT_DISPLAY,{into} from {names['saved_table']} where {workspace._saved_row(page)} and REVISION=to_number(:P{page}_SREV);\n"
    return code + 'end if;\nend if;\nend;'


def render_bound_workspace(primary, bundle, page, *, source_page=None, numbers=None, parent, block_label=None, initializer=None):
    c, b, p, n, _ = _checked(primary, bundle, parent, numbers)
    result = workspace.render_rate_workspace(c, b, page, source_page=source_page, numbers=n, block_label=block_label, initializer=initializer)
    if not p.get('binding'):
        return result
    names = _names(c, b, p, n)
    sql = _replace(result['supporting_sql'].decode(), c, b, p, n)
    for table in ('draft_table', 'saved_table'):
        anchor = 'create table ' + names[table] + ' (\n'
        extra = ' PARENT_ID number,\n PARENT_STAMP varchar2(64 byte),\n'
        extra += ''.join(' ' + pair['column'] + ' varchar2(4000 byte),\n' for pair in _pairs(p))
        _need(sql.count(anchor) == 1, 'DDL_ANCHOR')
        sql = sql.replace(anchor, anchor + extra, 1)
    result['supporting_sql'] = sql.encode()
    for offset, component in enumerate(result['pages']):
        current, choosing = component['page_id'], offset > 0
        text = component['text'].decode()
        actions = [('FOX_ROW_APPLY', offset - 1)] if choosing else [
            *((action, 0) for action in ('FOX_ROW_CREATE', 'FOX_ROW_KEEP', workspace.SAVE, workspace.REOPEN, 'FOX_ROW_DISCARD')),
            *(('FOX_ROW_CHOOSE', i) for i in range(1 + len(b['choices'])))]
        for action, choice in actions:
            old = workspace.action_code(c, b, current, action, choice, numbers=n, initializer=initializer)
            new = bound_action_code(c, b, current, action, choice, numbers=n, parent=p, initializer=initializer)
            if action == 'FOX_ROW_CHOOSE':
                request = 'FOX_RATE_CHOOSE_' + str(choice)
                old = old.replace("'FOX_ROW_CHOOSE'", "'" + request + "'")
                new = new.replace("'FOX_ROW_CHOOSE'", "'" + request + "'")
            old, new = native_buffer._indent(old), native_buffer._indent(new)
            _need(text.count(old) == 1, 'ACTION_PAGE_ANCHOR')
            text = text.replace(old, new, 1)
        text = _replace(text, c, b, p, n)
        if not choosing and not _standalone_allowed(p):
            button = native_buffer._expand_groups(workspace.route._button('FOX_ROW_CREATE','Create a separate draft',10))
            _need(text.count(button) == 1, 'STANDALONE_BUTTON_ANCHOR')
            text = text.replace(button, '', 1)
        body = workspace.route._item(current, 'PARENT_DISPLAY', 'Copied parent record identity', sequence=22)
        for i, pair in enumerate(_pairs(p), 1):
            body += workspace.route._item(current, f'K{i}', 'Copied ' + pair['child_name'], sequence=22+i)
        body += workspace.route._process('load-copied-parent', _extra_load(p, names, current, choosing), point='beforeHeader')
        text = groups._append(text, native_buffer._expand_groups(body))
        text = text.replace('Create a separate draft, Keep permitted inputs,',
                            'Create a separate standalone partial draft, Keep permitted inputs,')
        text = text.replace('label: "Create a separate draft"',
                            'label: "Create a standalone partial draft"')
        text = text.replace('Original business writes, source commits,',
                            'Copied parent keys are immutable; linked drafts are created only by the explicit parent launcher. Original business writes, source commits,')
        component['text'] = text.encode()
    metadata = result['metadata']
    # Update nested query receipts as well as the top-level names.
    def replace_metadata(value):
        if type(value) is str:
            return _replace(value, c, b, p, n)
        if type(value) is dict:
            return {key: replace_metadata(val) for key, val in value.items()}
        if type(value) is list:
            return [replace_metadata(val) for val in value]
        return value
    metadata = replace_metadata(metadata)
    metadata.update(names)
    metadata.update(parent_contract_id=p['contract_id'], parent_copy_fields=deepcopy(_pairs(p)),
                    parent_id_column='PARENT_ID', parent_stamp_column='PARENT_STAMP',
                    parent_copy_immutable=True, parent_linkage_scope=SCOPE,
                    standalone_rows_allowed=_standalone_allowed(p), source_parent_binding=deepcopy(p))
    result['metadata'] = metadata
    return result


def _context(p, relation):
    _need(type(relation) is dict and relation.get('relation_id') == p['binding']['relation_id'], 'RELATION_CONTEXT')
    _need(relation == p['binding']['native_entry']['action'], 'EXACT_NATIVE_CONTEXT')
    page = relation.get('page_id')
    _need(type(page) is int and 1 <= page <= 9999, 'CONTEXT_PAGE')
    _need(relation.get('parent_item') == f'P{page}_PARENT_ID', 'CONTEXT_ITEM')
    _need(relation.get('parent_block_id') == p['binding']['parent_block_id'] and
          relation.get('child_block_id') == p['binding']['child_block_id'], 'CONTEXT_BLOCKS')
    _need(relation.get('page_file') == f'pages/p{page:05d}-fox_relation_{page}.apx', 'CONTEXT_FILE')
    return page


def _selection_guard(p, page, *, lock):
    code = (f"if :P{page}_PARENT_ID is null or not regexp_like(:P{page}_PARENT_ID,'^[1-9][0-9]{{0,27}}$') "
            f"or :P{page}_TOKEN is null or not regexp_like(:P{page}_TOKEN,'^[A-F0-9]{{64}}$') then "
            "raise_application_error(-20031,'Open the signed action for a selected parent.'); end if;\n")
    code += f'l_parent_id:=to_number(:P{page}_PARENT_ID);\n'
    code += _current_parent(p, lock=lock)
    code += (f"select {_token(p, 'l_current_stamp')} into l_token from dual;\n"
             f"if l_token<>:P{page}_TOKEN then "
             "raise_application_error(-20031,'Parent selection changed or expired. Open the parent action again.'); end if;\n")
    return code


def parent_create_code(primary, bundle, parent, editor_page, page, *, numbers=None, initializer=None):
    c, b, p, n, _ = _checked(primary, bundle, parent, numbers)
    _need(bool(p.get('binding')), 'BINDING_REQUIRED')
    names = _names(c, b, p, n)
    code = f'declare {_decl(p)}l_token varchar2(64);l_uuid varchar2(32);l_count number;\nbegin\nsavepoint fox_rate_parent;\n'
    code += workspace.route._auth()
    code += f"if :REQUEST is null or :REQUEST<>'{CREATE}' then raise_application_error(-20031,'Unknown parent action.'); end if;\n"
    code += _selection_guard(p, page, lock=True)
    code += f"if :P{page}_LABEL is null or lengthb(:P{page}_LABEL)>160 then raise_application_error(-20031,'Enter a draft label of at most 160 bytes.'); end if;\n"
    code += f"select count(*) into l_count from {names['draft_table']} where {workspace.route._owner()};\n"
    code += "if l_count>=100 then raise_application_error(-20031,'Discard an older session draft first.'); end if;\n"
    code += 'l_uuid:=rawtohex(sys_guid());\nl_parent_stamp:=l_current_stamp;\n'
    code += ''.join(f'l_key{i}:=l_current_key{i};\n' for i, _ in enumerate(_pairs(p), 1))
    code += (f"insert into {names['draft_table']}(APP_ID,SESSION_ID,OWNER_NAME,ROW_UUID,ROW_LABEL,REVISION,{_cols(p)}) "
             f"values(to_number(v('APP_ID')),v('APP_SESSION'),v('APP_USER'),l_uuid,:P{page}_LABEL,0,{_locals(p)});\n")
    code += f":P{page}_ROW:=l_uuid; :P{page}_REV:='0';\n"
    code += ("exception when no_data_found then rollback to fox_rate_parent; raise_application_error(-20031,'Parent changed or has a missing key. Nothing was created.');\n"
             "when too_many_rows then rollback to fox_rate_parent; raise_application_error(-20031,'Parent is ambiguous. Nothing was created.');\n"
             "when others then rollback to fox_rate_parent; raise;\nend;")
    if initializer:
        from .forms_rate_create_defaults import create_sql
        fields = c['fields'] + b['fields'] + (n['fields'] if n else [])
        code = create_sql(code, initializer, fields, c, names, page, parent_launcher=True)
    _need(len(code.encode()) <= 32767, 'PROCESS_CAPACITY')
    return code


def scoped_query(primary, bundle, parent, page, *, numbers=None):
    c, b, p, n, _ = _checked(primary, bundle, parent, numbers)
    _need(bool(p.get('binding')), 'BINDING_REQUIRED')
    names = _names(c, b, p, n)
    keys = ','.join('r.' + pair['column'] for pair in _pairs(p))
    base = (f"select r.SAVED_UUID OPEN_ID,to_char(r.REVISION,'TM9') SAVED_REVISION_TEXT,r.ROW_LABEL,{keys} "
            f"from {names['saved_table']} r where {workspace._saved_owner()} and r.PARENT_ID=:P{page}_PARENT_ID "
            f"and exists (select 1 from {p['binding']['parent']['table']} p where p.FOX_ROW_ID=r.PARENT_ID "
            f"and r.PARENT_STAMP={_stamp(p)} and {_non_null(p)} "
            f"and {_token(p, _stamp(p))}=:P{page}_TOKEN and "
            + ' and '.join(native_buffer._parent_match('r.' + pair['column'], 'p.' + pair['parent_column']) for pair in _pairs(p)) + ')')
    return base + ' order by r.ROW_LABEL,r.SAVED_UUID'


def render_parent_page(primary, bundle, parent, editor_page, launcher_page, relation_context, *, numbers=None, initializer=None):
    """Lead inserts entry_fragment only into the exact filtered child page.

    Allocate launcher_page separately from the editor and its choosers. Supporting
    DDL comes solely from render_rate_workspace(..., parent=parent).
    """
    c, b, p, n, _ = _checked(primary, bundle, parent, numbers)
    _need(bool(p.get('binding')), 'BINDING_REQUIRED')
    context = _context(p, relation_context)
    page = launcher_page
    _need(type(page) is int and 1 <= page <= 9999 and
          page not in range(editor_page, editor_page + 2 + len(b['choices'])) and page != context, 'PAGE')
    query = (f"select p.FOX_ROW_ID FOX_PARENT_ID,{_token(p, _stamp(p))} FOX_PARENT_TOKEN "
             f"from {p['binding']['parent']['table']} p where p.FOX_ROW_ID=:P{context}_PARENT_ID and {_non_null(p)}")
    link = f'''        link {{ linkColumn: customTarget
            target: {{ page: {page}
                clearCache: {page}
                items: {{ P{page}_PARENT_ID: "#FOX_PARENT_ID#"
                    P{page}_TOKEN: "#FOX_PARENT_TOKEN#" }} }}
            linkIcon: Create or reopen this parent's synthetic rates }}
'''
    entry = workspace.route._report(context, query, [('FOX_PARENT_ID', 'Selected parent'),
                                   ('FOX_PARENT_TOKEN', 'Selection snapshot')], 'Explicit synthetic rate action', link)
    entry = entry.replace('region records (', 'region rate-parent-entry (', 1)
    entry = entry.replace('        source {\n', f'        source {{\n            pageItemsToSubmit: P{context}_PARENT_ID\n', 1)
    # The selection token is carried in native signed links, never inferred
    # from a shared application/session item when another tab switches parents.
    body = ''.join(workspace.route._item(page, suffix, suffix, kind='hidden', protected=True)
                   for suffix in ('PARENT_ID', 'TOKEN', 'ROW', 'REV'))
    body += workspace.route._item(page, 'LABEL', 'New synthetic rate label', kind='textField')
    for i, pair in enumerate(_pairs(p), 1):
        body += workspace.route._item(page, f'K{i}', 'Will copy ' + pair['child_name'], sequence=30+i)
    load = f'declare {_decl(p)}l_token varchar2(64);\nbegin\n' + workspace.route._auth()
    load += f'if :REQUEST is null then\n' + _selection_guard(p, page, lock=False)
    load += ''.join(f':P{page}_K{i}:=l_current_key{i};\n' for i, _ in enumerate(_pairs(p), 1))
    load += "end if;\nexception when no_data_found then raise_application_error(-20031,'Parent changed or has a missing key. Select it again.');\nend;"
    body += workspace.route._process('load-selected-parent', load, point='beforeHeader')
    body += workspace.route._button(CREATE, 'Create a draft for this parent', 10)
    body += workspace.route._process('create-linked-rate', parent_create_code(c,b,p,editor_page,page,numbers=n,initializer=initializer), action=CREATE)
    body += workspace.route._branch(page, editor_page, CREATE, revision=True)
    saved_link = f'''        link {{ linkColumn: customTarget
            target: {{ page: {editor_page}
                clearCache: {editor_page}
                items: {{ P{editor_page}_OPEN: "#OPEN_ID#"
                    P{editor_page}_SREV: "#SAVED_REVISION_TEXT#" }} }}
            linkIcon: Preview saved rate and Reopen to edit }}
'''
    columns = [('OPEN_ID','Saved rate identity'),('SAVED_REVISION_TEXT','Saved revision'),('ROW_LABEL','Rate label')]
    columns += [(pair['column'], 'Copied ' + pair['child_name']) for pair in _pairs(p)]
    report = workspace.route._report(page, scoped_query(c,b,p,page,numbers=n), columns,
                                     'Your saved synthetic rates for this parent', saved_link)
    report = report.replace('        source {\n',
                            f'        source {{\n            pageItemsToSubmit: P{page}_PARENT_ID,P{page}_TOKEN\n', 1)
    description = ('Create explicitly copies all displayed parent keys into one new session draft. '
                   'Keys stay immutable through price Save and reopening in another authenticated session. '
                   'Changed, missing or incomplete parents require a fresh selection. Only your application/user saved rows appear. '
                   'This is synthetic storage; original Forms posting, permissions, triggers and business acceptance remain unconverted. '
                   'Unknown source length semantics use a conservative byte bound without truncation.')
    text = workspace.route._shell(page, 'Create or reopen a rate for the selected parent', description, report, body)
    text = text.replace(f'alias: FOX_ROW_{page}\n'.encode(), f'alias: FOX_RATE_PARENT_{page}\n'.encode())
    filename = f'pages/p{page:05d}-fox_rate_parent_{page}.apx'
    metadata = {'scope':SCOPE, 'page_id':page, 'page_file':filename, 'page_alias':f'FOX_RATE_PARENT_{page}',
                'editor_page_id':editor_page, 'editor_alias':f'FOX_RATE_{editor_page}',
                'relation_id':p['binding']['relation_id'], 'entry_page_id':context,
                'entry_page_file':relation_context['page_file'], 'parent_item':f'P{page}_PARENT_ID',
                'token_item':f'P{page}_TOKEN', 'create_request':CREATE, 'label_item':f'P{page}_LABEL',
                'parent_contract_id':p['contract_id'], 'parent_copy_fields':deepcopy(_pairs(p)),
                'runtime_verified':False, 'business_accepted':False, 'original_interface_enabled':False,
                'synthetic_query_sql':scoped_query(c,b,p,page,numbers=n)}
    return {'pages':[{'page_id':page,'page_file':filename,'text':text}],
            'entry_fragment':native_buffer._expand_groups(entry), 'metadata':metadata}
