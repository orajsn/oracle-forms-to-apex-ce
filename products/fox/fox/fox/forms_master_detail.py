"""Source-bound automatic detail population over selected synthetic records.

This adapter consumes complete trigger and local-helper bodies. Its native pages
coordinate on selection, and its optional draft region uses the existing saved
draft identity/baseline. It never clears a collection or executes source SQL.
Whole-unit coverage is deliberately separate from connected partial effects.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_blueprint, native_buffer
from .forms_behavior_plan import _source_objects, decode_control_entities
from .forms_guarded_query import _field, _projection
from .forms_relation_plan import parse_join_condition, relation_attribute_sha256
from .forms_understanding_packet import _build

SCOPE = 'fox-selected-master-details-v1'
RULE_ID = 'fox.relation.selected-master-population'
_IDENT = re.compile(r'[A-Z][A-Z0-9_]{0,127}\Z')
_LEX = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|[A-Za-z][A-Za-z0-9_$#]*|[0-9]+|:=|<>|[:.,();=]", re.S)


def _need(value, reason):
    if not value:
        raise ValueError('MASTER_DETAILS_' + reason)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


def _tokens(text):
    _need(type(text) is str and len(text) <= 16384, 'SOURCE_CAPACITY')
    semantic, receipt = decode_control_entities(text)
    values, pos = [], 0
    for match in _LEX.finditer(semantic):
        _need(match.start() == pos, 'UNSUPPORTED_ACTIVE_TOKEN')
        pos = match.end()
        value = match[0]
        if value.isspace() or value.startswith(('--', '/*')):
            continue
        values.append(value if value.startswith("'") else value.upper())
    _need(pos == len(semantic), 'UNSUPPORTED_ACTIVE_TOKEN')
    return values, receipt


def _template(actual, template, variables):
    expected, _ = _tokens(template)
    _need(len(actual) == len(expected), 'COMPLETE_SOURCE_REQUIRED')
    bindings = {}
    for a, b in zip(actual, expected):
        if b in variables:
            _need(_IDENT.fullmatch(a), 'LOCAL_IDENTIFIER_REQUIRED')
            if b in bindings:
                _need(bindings[b] == a, 'LOCAL_REFERENCE_CHANGED')
            bindings[b] = a
        else:
            _need(a == b, 'COMPLETE_SOURCE_REQUIRED')
    _need(len(set(bindings.values())) == len(bindings), 'LOCAL_IDENTIFIERS_COLLIDE')
    return bindings


_START = """DECLARE RECSTAT VARCHAR2(20) := :SYSTEM.RECORD_STATUS;
STARTITM VARCHAR2(61) := :SYSTEM.CURSOR_ITEM; REL_ID RELATION;
BEGIN IF (RECSTAT = 'NEW' OR RECSTAT = 'INSERT') THEN RETURN; END IF;"""
_END = """IF (:SYSTEM.CURSOR_ITEM <> STARTITM) THEN GO_ITEM(STARTITM);
V_CHECK; END IF; END;"""
_QUERY_HELPER = """PROCEDURE V_PROC(V_REL RELATION,V_DETAIL VARCHAR2) IS
V_MSG VARCHAR2(2); V_DEF VARCHAR2(5); BEGIN
V_DEF := GET_RELATION_PROPERTY(V_REL,DEFERRED_COORDINATION);
V_MSG := :SYSTEM.MESSAGE_LEVEL;
IF V_DEF = 'FALSE' THEN GO_BLOCK(V_DETAIL); V_CHECK;
:SYSTEM.MESSAGE_LEVEL := '10'; EXECUTE_QUERY; :SYSTEM.MESSAGE_LEVEL := V_MSG;
ELSE SET_BLOCK_PROPERTY(V_DETAIL,COORDINATION_STATUS,NON_COORDINATED); END IF;
EXCEPTION WHEN FORM_TRIGGER_FAILURE THEN :SYSTEM.MESSAGE_LEVEL := V_MSG;
RAISE; END V_PROC;"""
_CHECK_HELPER = """PROCEDURE V_PROC IS BEGIN IF NOT (FORM_SUCCESS) THEN
RAISE FORM_TRIGGER_FAILURE; END IF; END;"""


def parse_population(text):
    """Consume the whole generated Forms population trigger, including its OR."""
    tokens, receipt = _tokens(text)
    start, _ = _tokens(_START)
    names = _template(tokens[:len(start)], _START.replace('RECSTAT', 'V_STATUS').replace('STARTITM', 'V_ITEM').replace('REL_ID', 'V_REL'),
                      {'V_STATUS', 'V_ITEM', 'V_REL'})
    normalized = {names[k]: v for k, v in (('V_STATUS', 'RECSTAT'), ('V_ITEM', 'STARTITM'), ('V_REL', 'REL_ID'))}
    tokens = [normalized.get(t, t) for t in tokens]
    rest = tokens[len(start):]
    _need(rest[:1] == ['IF'], 'CALLER_PREDICATE_REQUIRED')
    end = rest.index('THEN') if 'THEN' in rest else -1
    _need(end > 0, 'CALLER_PREDICATE_REQUIRED')
    predicate = rest[1:end]
    # Parentheses may group the finite homogeneous non-null terms only.
    depth = 0
    for token in predicate:
        depth += (token == '(') - (token == ')')
        _need(depth >= 0, 'PREDICATE_PARENTHESES')
    _need(depth == 0, 'PREDICATE_PARENTHESES')
    flat = [t for t in predicate if t not in ('(', ')')]
    refs, connectors, pos = [], [], 0
    while pos < len(flat):
        _need(flat[pos:pos+1] == [':'], 'NON_NULL_PARENT_PREDICATE_REQUIRED')
        pos += 1
        parts = [flat[pos]]; pos += 1
        if flat[pos:pos+1] == ['.']:
            parts.append(flat[pos+1]); pos += 2
        _need(all(_IDENT.fullmatch(p) for p in parts) and flat[pos:pos+3] == ['IS', 'NOT', 'NULL'],
              'NON_NULL_PARENT_PREDICATE_REQUIRED')
        pos += 3
        refs.append(parts)
        if pos < len(flat):
            _need(flat[pos] in ('AND', 'OR'), 'HOMOGENEOUS_PREDICATE_REQUIRED')
            connectors.append(flat[pos]); pos += 1
    _need(1 <= len(refs) <= 4 and len(connectors) == len(refs)-1 and len({tuple(r) for r in refs}) == len(refs)
          and len(set(connectors)) <= 1, 'HOMOGENEOUS_PREDICATE_REQUIRED')
    body = rest[end+1:]
    prefix = ['REL_ID', ':=', 'FIND_RELATION', '(']
    _need(body[:4] == prefix and len(body) > 15 and body[4].startswith("'"), 'EXACT_RELATION_CALL_REQUIRED')
    relation = body[4][1:-1]
    _need(body[5:7] == [')', ';'] and _IDENT.fullmatch(body[7]), 'EXACT_HELPER_CALL_REQUIRED')
    helper = body[7]
    _need(body[8:11] == ['(', 'REL_ID', ','] and body[11].startswith("'"), 'EXACT_DETAIL_CALL_REQUIRED')
    detail = body[11][1:-1]
    _need(body[12:17] == [')', ';', 'END', 'IF', ';'], 'EXACT_DETAIL_CALL_REQUIRED')
    ending = _template(body[17:], _END, {'V_CHECK'})
    _need(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*\.[A-Za-z][A-Za-z0-9_]*', relation)
          and _IDENT.fullmatch(detail.upper()), 'QUALIFIED_RELATION_REQUIRED')
    return {'references': refs, 'connector': connectors[0] if connectors else 'AND',
            'relation_name': relation.upper(), 'detail_name': detail.upper(),
            'helper_name': helper, 'check_name': ending['V_CHECK'], 'decode_receipt': receipt}


def parse_query_helper(text):
    tokens, receipt = _tokens(text)
    result = _template(tokens, _QUERY_HELPER, {'V_PROC', 'V_REL', 'V_DETAIL', 'V_MSG', 'V_DEF', 'V_CHECK'})
    return {**result, 'decode_receipt': receipt, 'effect_contract': {
        'reads': ['GET_RELATION_PROPERTY.DEFERRED_COORDINATION', 'SYSTEM.MESSAGE_LEVEL'],
        'immediate': ['GO_BLOCK(detail)', 'CHECK_PACKAGE_FAILURE', 'MESSAGE_LEVEL=10',
                      'EXECUTE_QUERY', 'RESTORE_MESSAGE_LEVEL'],
        'deferred': ['SET_BLOCK_PROPERTY(detail,COORDINATION_STATUS,NON_COORDINATED)'],
        'exception': {'condition': 'FORM_TRIGGER_FAILURE', 'effects': ['RESTORE_MESSAGE_LEVEL', 'RERAISE']}}}


def parse_check_helper(text):
    tokens, receipt = _tokens(text)
    return {**_template(tokens, _CHECK_HELPER, {'V_PROC'}), 'decode_receipt': receipt,
            'effect_contract': {'condition': 'NOT FORM_SUCCESS', 'effects': ['RAISE FORM_TRIGGER_FAILURE']}}


def _fingerprint(fields, alias='p'):
    _need(fields, 'SNAPSHOT_FIELDS_REQUIRED')
    return " || ':' || ".join("nvl(rawtohex(standard_hash(" + alias + '.' + f['column']
                                 + ",'SHA256')),'N')" for f in fields)


def _bind(owner, parsed, objects, props, trace, files):
    parent = objects.get(owner['parent_id'])
    _need(parent is not None and parent['kind'] == 'Block' and owner['block_id'] == parent['id'],
          'BLOCK_OWNED_TRIGGER_REQUIRED')
    relations = [o for o in objects.values() if o['kind'] == 'Relation' and o['block_id'] == parent['id']]
    relation = _one(relations, 'ONE_OUTGOING_RELATION_REQUIRED')
    _need(parsed['relation_name'] == (parent['name'] + '.' + relation['name']).upper(), 'CALLER_RELATION_MISMATCH')
    attrs = props[relation['id']]
    child = _one([o for o in objects.values() if o['kind'] == 'Block' and o['module_id'] == owner['module_id']
                  and (o['name'] or '').upper() == parsed['detail_name']], 'DETAIL_BLOCK_NOT_UNIQUE')
    _need(attrs.get('DetailBlock', '').upper() == parsed['detail_name']
          and relation['parent_id'] == parent['id'] and attrs.get('RelationType', '').upper() == 'JOIN', 'RELATION_SOURCE_MISMATCH')
    plan = json.loads(files['fox-package/relation-plan.json'])
    rendered = json.loads(files['fox-package/relation-receipt.json'])
    _need(plan['source_binding'] == rendered['source_binding'] == trace['source_binding'], 'RELATION_BINDING')
    edge = _one([e for e in plan['operations'] if e['relation_id'] == relation['id']], 'GENERATED_RELATION_REQUIRED')
    target = _one([e for e in rendered['generated_operations'] if e['relation_id'] == relation['id']], 'RENDERED_RELATION_REQUIRED')
    _need(edge['source_attribute_sha256'] == relation_attribute_sha256(attrs)
          and all(e['parent_block_id'] == parent['id'] and e['child_block_id'] == child['id']
                  and e['source_module_id'] == owner['module_id'] for e in (edge, target)), 'EXACT_RELATION_IDENTITY')
    blocks = [_one([b for b in trace['blocks'] if b['source_block_id'] == o['id']], 'BLOCK_TARGET') for o in (parent, child)]
    for role, block in zip(('parent', 'child'), blocks):
        _need(edge[role] == {'table': block['table_name'], 'report_file': block['report_file'],
                            'report_page_id': block['report_page_id'], 'row_id_column': 'FOX_ROW_ID'}, 'RELATION_TARGET')
    _need(edge['source_flags'] == {k: attrs.get(k) for k in ('AutoQuery', 'Deferred', 'DeleteRecord', 'PreventMasterlessOperations')},
          'RELATION_FLAGS_CHANGED')
    joins, source_fields = [], {}
    snapshot, guards = {}, []
    for pn, cn in parse_join_condition(attrs.get('JoinCondition'), parent['name'], child['name']):
        values = []
        for obj, block, name in zip((parent, child), blocks, (pn, cn)):
            item = _one([o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == obj['id']
                         and (o['name'] or '').upper() == name], 'JOIN_ITEM')
            values.append((item, _field(item, block, props)))
            source_fields[item['id']] = {'source_item_id': item['id'], 'source_block_id': obj['id'],
                'source_attribute_sha256': relation_attribute_sha256(props[item['id']])}
        (pi, pf), (ci, cf) = values
        _need(pf['data_type'] == cf['data_type'], 'JOIN_TYPE')
        snapshot[pi['id']] = pf
        joins.append(dict(parent_item_id=pi['id'], parent_column=pf['column'], child_item_id=ci['id'],
                          child_column=cf['column'], data_type=pf['data_type']))
    _need(joins == edge['join_pairs'], 'JOIN_TARGET_MISMATCH')
    for ref in parsed['references']:
        item = _one([o for o in objects.values() if o['kind'] == 'Item' and o['module_id'] == owner['module_id']
                     and (o['name'] or '').upper() == ref[-1] and (len(ref) == 1 or
                     (objects[o['block_id']]['name'] or '').upper() == ref[0])], 'GUARD_ITEM_NOT_UNIQUE')
        _need(item['block_id'] == parent['id'], 'DIRECT_PARENT_GUARD_REQUIRED')
        field = _field(item, blocks[0], props)
        source_fields[item['id']] = {'source_item_id': item['id'], 'source_block_id': parent['id'],
            'source_attribute_sha256': relation_attribute_sha256(props[item['id']])}
        snapshot[item['id']] = field
        guards.append({'source_reference': ref, 'source_item_id': item['id'], 'column': field['column'],
                       'source_attribute_sha256': relation_attribute_sha256(props[item['id']])})
    _need(attrs.get('Deferred', '').lower() in ('true', 'false') and attrs.get('AutoQuery', '').lower() in ('true', 'false'),
          'EXPLICIT_COORDINATION_FLAGS_REQUIRED')
    projection = _projection(files[blocks[1]['report_file']].decode().replace('\r\n', '\n'), blocks[1])
    return {'relation': deepcopy(edge), 'relation_target': target, 'parent': blocks[0], 'child': blocks[1],
            'guards': guards, 'connector': parsed['connector'], 'snapshot_fields': list(snapshot.values()),
            'source_field_bindings': list(source_fields.values()),
            'original_join_condition': attrs['JoinCondition'],
            'original_child_query_properties': {k: props[child['id']][k] for k in ('QueryDataSourceType', 'QueryDataSourceName', 'WhereClause', 'OrderByClause') if k in props[child['id']]},
            'projection': projection, 'deferred': attrs['Deferred'].lower() == 'true', 'auto_query': attrs['AutoQuery'].lower() == 'true'}


def _parent_where(bound, page):
    parent, edge = bound['parent'], bound['relation']
    guard = (' ' + bound['connector'] + ' ').join('p.' + f['column'] + ' is not null' for f in bound['guards'])
    equal = ' and '.join('(s.' + p['parent_column'] + '=p.' + p['parent_column']
                         + ' or (s.' + p['parent_column'] + ' is null and p.' + p['parent_column'] + ' is null))' for p in edge['join_pairs'])
    return (f'p.FOX_ROW_ID=:P{page}_PARENT_ID and ({_fingerprint(bound["snapshot_fields"])})=:P{page}_TOKEN'
            + f' and (select count(*) from {parent["table_name"]} s where {equal})=1 and ({guard})')


def _child_query(bound, where):
    child, edge = bound['child'], bound['relation']
    cols = ['FOX_ROW_ID'] + [f['column'] for f in child['items']]
    joins = ' and '.join('p.' + p['parent_column'] + '=c.' + p['child_column'] for p in edge['join_pairs'])
    return ('select ' + ','.join('c.' + c for c in cols) + '\nfrom (select ' + bound['projection']
            + '\nfrom ' + child['table_name'] + ') c\nwhere exists (select 1 from '
            + bound['parent']['table_name'] + ' p where ' + where + ' and ' + joins + ')')


def _report(slug, title, query, fields, *, sequence=10, link=None):
    cols = [('FOX_ROW_ID', 'NUMBER', 'Selected row')] + [(f['column'], f['data_type'], f['source_name']) for f in fields]
    if link:
        cols.append(('FOX_MASTER_TOKEN', 'VARCHAR2', 'Selection fingerprint'))
    columns = ''
    for i, (name, dtype, label) in enumerate(cols, 1):
        target = ''
        if name == 'FOX_ROW_ID' and link:
            page = link
            target = f'''            link {{
                target: {{ page: {page}
                    items: {{ P{page}_PARENT_ID: "#FOX_ROW_ID#"
                        P{page}_TOKEN: "#FOX_MASTER_TOKEN#" }}
                }}
                linkText: Select master
            }}
'''
        columns += f'''        column {name} (
            type: {'link' if target else 'plainText'}
            heading {{ heading: {json.dumps(label)} }}
            layout {{ sequence: {i*10} }}
            source {{ dataType: {'NUMBER' if dtype == 'NUMBER' else 'DATE' if dtype == 'DATE' else 'STRING'} }}
            security {{ escapeSpecialChars: true }}
{target}        )
'''
    display = ''.join(f'            displayColumn {n} (\n                sequence: {i*10}\n            )\n'
                      for i, (n, _, _) in enumerate([c for c in cols if c[0] != 'FOX_MASTER_TOKEN'][:9], 1))
    return f'''    region {slug} (
        name: {json.dumps(title)}
        type: interactiveReport
        source {{ location: localDatabase
            type: sqlQuery
            sqlQuery:
                ```sql
{native_buffer._indent(query)}
                ```
        }}
        layout {{ sequence: {sequence}
            slot: body }}
        appearance {{ template: @/interactive-report
            templateOptions: #DEFAULT# }}
        searchBar {{ includeSearchBar: true
            searchField: true }}
{columns}        savedReport primary (
            visibility: primaryDefault
            view {{ default: report
                rowsPerPage: 15 }}
{display}        )
    )
'''


def _focus_script(page):
    # Retain an actual item or the clicked chooser link, never a default row.
    # Browser storage is presentation state and never server authority.
    return f'''(function(){{const k="fox-coord-focus-"+apex.env.APP_ID+"-"+apex.env.APP_SESSION+"-{page}";
try{{const href=sessionStorage.getItem(k+"-link"),id=sessionStorage.getItem(k),e=href?Array.from(document.querySelectorAll("a")).find(a=>a.href===href):id&&document.getElementById(id);if(e&&!e.disabled)e.focus();}}catch(e){{}}
document.addEventListener("focusin",function(e){{if(e.target.id&&e.target.id.startsWith("P{page}_"))try{{sessionStorage.setItem(k,e.target.id);}}catch(x){{}}}});
document.addEventListener("click",function(e){{const a=e.target.closest&&e.target.closest("a");if(a&&a.textContent.trim()==="Select master")try{{sessionStorage.setItem(k+"-link",a.href);}}catch(x){{}}}});
}})();'''


def _render(bound, page):
    where = _parent_where(bound, page)
    child = _child_query(bound, where)
    parent = bound['parent']
    context = 'select p.FOX_ROW_ID,' + ','.join('p.' + f['column'] for f in parent['items']) + '\nfrom ' + parent['table_name'] + ' p where ' + where
    chooser = ('select p.FOX_ROW_ID,' + ','.join('p.' + f['column'] for f in parent['items'])
               + ',' + _fingerprint(bound['snapshot_fields']) + ' as FOX_MASTER_TOKEN\nfrom ' + parent['table_name'] + ' p')
    # A synthetic target query failure cannot leave an old COORDINATED state.
    state = 'NON_COORDINATED' if bound['deferred'] else 'COORDINATED'
    probe = '' if bound['deferred'] else 'select count(*) into l_count from (' + child + ');'
    code = f'''declare l_count number;
begin
:P{page}_STATE:='UNSELECTED';
if :P{page}_PARENT_ID is null or :P{page}_TOKEN is null then return;end if;
select count(*) into l_count from ({context});
if l_count<>1 then :P{page}_STATE:='MISSING_STALE_NULL_OR_NONUNIQUE';return;end if;
{probe}
:P{page}_STATE:='{state}';
exception when others then
:P{page}_STATE:='FAILED';
apex_debug.error('Master detail population failed: %s',sqlerrm);
apex_error.add_error(p_message=>'Related records could not be populated. Selection and draft input are retained.',p_display_location=>apex_error.c_inline_in_notification);
end;'''
    _need(all(len(s.encode()) <= 32767 for s in (context, chooser, child, code)), 'NATIVE_SOURCE_CAPACITY')
    scope = ('Selecting a master shows its current saved context and refreshes its matching child rows together. '
             'Selection is checked again on each request. Unsaved and dirty Forms buffers are outside this saved-row selector. '
             'Session drafts are retained. Source ON-CLEAR-DETAILS and ASK_COMMIT remain pending. '
             'A deferred relation stays NON_COORDINATED and does not query here.')
    body = _report('master-choice', 'Select or change master', chooser, parent['items'], sequence=10, link=page)
    body += _report('master-context', 'Selected master context', context, parent['items'], sequence=20)
    visible_query = child + f" and :P{page}_STATE='COORDINATED'"
    body += _report('detail-records', 'Automatically populated details', visible_query, bound['child']['items'], sequence=30)
    for name, dtype, protection in (('PARENT_ID', 'number', 'checksumRequiredSessionLevel'), ('TOKEN', 'varchar2', 'checksumRequiredSessionLevel'), ('STATE', 'varchar2', 'restricted')):
        label = '        label { label: Coordination state }\n' if name == 'STATE' else ''
        body += f'''    pageItem P{page}_{name} (
        type: {'displayOnly' if name == 'STATE' else 'hidden'}
{label}        layout {{ sequence: 10
            region: @coordination-scope
            slot: regionBody }}
        sessionState {{ storage: {'request' if name == 'STATE' else 'session'}
            dataType: {dtype} }}
        security {{ sessionStateProtection: {protection} }}
    )
'''
    body += native_buffer._process('coordinate-selected-master', code, point='beforeHeader', sequence=50)
    text = f'''page {page} (
    name: Coordinated master and details
    alias: FOX_COORD_{page}
    title: Coordinated master and details
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT# }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum }}
    javaScript {{ executeWhenPageLoads:
            ```javascript
{native_buffer._indent(_focus_script(page),12)}
            ```
    }}
    region coordination-scope (
        name: Population scope
        type: staticContent
        source {{ htmlCode: {json.dumps(scope)} }}
        layout {{ sequence: 5
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
{body})
'''
    return native_buffer._expand_groups(text).encode(), {'chooser_query_sql': chooser, 'parent_context_sql': context,
            'child_query_sql': child, 'population_process_code': code, 'visible_child_query_sql': visible_query}


def _entry_button(page):
    return native_buffer._expand_groups(f'''    button coordinate-master-details (
        buttonName: FOX_COORDINATE_DETAILS
        label: Select master and details
        layout {{ sequence: 160
            region: @records
            slot: rightOfInteractiveReportSearchBar }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {page}
                clearCache: {page} }}
        }}
    )
''')


def _draft_provider(bound, documents, packet, chunks, trace, files):
    """Reprove the existing Save adapter before reading its collection slots."""
    from .forms_draft_policy import _render as policy_page, _MESSAGE
    from .forms_synthetic_save import apply_synthetic_saves, SCOPE as save_scope
    plan = json.loads(files.get('fox-package/buffer-plan.json', b'{"operations":[]}'))
    rows = [b for b in plan['operations'] if b['relation']['child_block_id'] == bound['parent']['source_block_id']]
    if not rows:
        return None
    buffer = _one(rows, 'DRAFT_PROVIDER_NOT_UNIQUE')
    targets = json.loads(files['fox-package/buffer-receipt.json'])['generated_operations']
    target = _one([t for t in targets if t['operation_id'] == buffer['operation_id']], 'DRAFT_TARGET')
    guards = json.loads(files['fox-package/draft-policy-receipt.json'])['adapted_operations']
    base = dict(files)
    for t in targets:
        op = _one([b for b in plan['operations'] if b['operation_id'] == t['operation_id']], 'DRAFT_OPERATION')
        guard = _one([g for g in guards if g['buffer_operation_id'] == op['operation_id']], 'DRAFT_POLICY')
        base[t['page_file']] = policy_page(op, t['page_id'], guard['policy_expression_sql'], _MESSAGE)
    proved, save = apply_synthetic_saves(documents, packet, chunks, trace, base)
    _need(json.loads(files['fox-package/synthetic-save-receipt.json']) == save, 'DRAFT_SAVE_PROOF')
    _need(proved[target['page_file']] == files[target['page_file']], 'DRAFT_PAGE_CHANGED')
    contract = _one([c for c in save['write_contracts'] if c['buffer_operation_id'] == buffer['operation_id']], 'SAVED_BASELINE_REQUIRED')
    fields = buffer['key_bindings']
    _need({f['source_item_id'] for f in bound['snapshot_fields']} <= {f['source_item_id'] for f in fields}, 'DRAFT_PARENT_FIELDS_UNAVAILABLE')
    page = target['page_id']
    namespace = 'FOX_S_' + _sha(_json({'buffer': buffer, 'contract': contract, 'scope': save_scope}))[:20].upper() + '_'
    name = "'" + namespace + "' || to_char(gp.FOX_ROW_ID,'TM9')"
    for _, column in native_buffer._parent_copies(buffer):
        name += " || '_' || substr(rawtohex(standard_hash(gp." + column + ",'SHA256')),1,32)"
    parent_table = buffer['relation']['parent']['table']
    joins = ' and '.join('gp.' + p['parent_column'] + '=p.' + p['child_column'] for p in buffer['relation']['join_pairs'])
    source = (f'{parent_table} gp, apex_collections m, apex_collections d'
              + f' where gp.FOX_ROW_ID=:P{page}_PARENT_ID and m.collection_name=({name})'
              + f" and m.seq_id=1 and m.c050='META' and m.c049='{_sha(_json(buffer))}'"
              + f' and m.n001=gp.FOX_ROW_ID and m.n002=:P{page}_SEQ and m.n003=:P{page}_REV'
              + " and d.collection_name=m.collection_name and d.seq_id=m.n002 and d.c050='ROW'")
    clean = []
    for i, field in enumerate(fields, 1):
        clean += [native_buffer._parent_match(f'd.c{i:03}', f'd.c{20+i:03}'),
                  native_buffer._parent_match('p.' + field['column'], f'd.c{20+i:03}')]
    clean += [native_buffer._parent_match('p.' + contract['route']['column'], 'd.c040'), "d.c041='SYNTHETIC_SAVE_BASELINE_V1'"]
    draft_where = (f"(:REQUEST is null) and exists (select 1 from {source} and d.n001=p.FOX_ROW_ID and {joins} and "
                   + ' and '.join(clean) + ')')
    # Every original guard is evaluated on the same persisted current-row proof.
    guard = (' ' + bound['connector'] + ' ').join('p.' + f['column'] + ' is not null' for f in bound['guards'])
    unique = ' and '.join('(s.' + p['parent_column'] + '=p.' + p['parent_column']
                          + ' or (s.' + p['parent_column'] + ' is null and p.' + p['parent_column'] + ' is null))' for p in bound['relation']['join_pairs'])
    draft_where += f' and ({guard}) and (select count(*) from {bound["parent"]["table_name"]} s where {unique})=1'
    query = _child_query(bound, draft_where)
    if bound['deferred']:
        query += ' and 1=0'
    # A failed submit has request-local input that may not yet be in collection.
    recheck = (f"exists (select 1 from {bound['parent']['table_name']} p where p.FOX_ROW_ID=d.n001 and {joins} and "
               + ' and '.join(clean) + ')')
    status = ("select d.seq_id as FOX_ROW_ID,case when :REQUEST is not null then 'SUBMITTED_INPUT_PENDING' "
              "when d.n001 is null then 'NEW_OR_INSERT_SKIPPED' "
              + "when not (" + ' and '.join(native_buffer._parent_match(f'd.c{i:03}', f'd.c{20+i:03}') for i in range(1, len(fields)+1))
              + ") then 'CHANGED_DRAFT_PENDING' when not (" + recheck + ") then 'STALE_OR_MISSING_RECORD' else "
              + ("'NON_COORDINATED'" if bound['deferred'] else "'PERSISTED_IDENTITY_RECHECKED'") + ' end as FOX_DRAFT_STATE from ' + source)
    return {'buffer_operation_id': buffer['operation_id'], 'page_id': page, 'page_file': target['page_file'],
            'child_query_sql': query, 'status_query_sql': status, 'current_row_source_sql': source,
            'authority': 'reproved_save_page_META_current_ROW_persisted_id_and_complete_baseline',
            'namespace': namespace, 'skip_statuses': ['NEW', 'INSERT'], 'dirty_draft_query_supported': False}


def apply_master_details(documents, packet, chunks, trace, files):
    """Return copied members and separately accounted complete/partial effects.

    Call after native relation, draft policy and synthetic Save adapters. The
    lead owns ledger integration; an adapted operation is not a converted unit.
    """
    fresh, original_chunks = _build(documents)
    _need(packet.get('source_binding') == fresh['source_binding'] == trace.get('source_binding')
          and packet.get('sources') == fresh['sources'], 'SOURCE_BINDING')
    _need(json.loads(files['fox-package/source-to-page.json']) == trace, 'TRACE_CHANGED')
    _need(chunks == original_chunks, 'CHUNKS_CHANGED')
    for name, raw in documents:
        _need(files.get('fox-package/sources/' + name) == raw, 'ORIGINAL_CHANGED')
    # Reconstruct synthetic field identities and DDL from source, not receipts.
    from .forms_native_plan import build_native_prototype_plan, POLICY_ID
    from .xml_mapping import _blueprint
    spec = build_native_prototype_plan(documents, _blueprint(packet), project_id=trace['project_id'],
        project_name='Master details source proof', approved_policy_id=POLICY_ID)['rendering_spec']
    expected = native_blueprint.prototype_trace(spec)
    objects, props = _source_objects(documents, fresh)
    for b in expected['blocks']:
        b['source_module_id'] = objects[b['source_block_id']]['module_id']
    _need(trace['blocks'] == expected['blocks'] and files['fox-package/supporting-schema.sql'] ==
          native_blueprint.render_prototype_schema(spec).encode(), 'FRESH_SYNTHETIC_SCHEMA_REQUIRED')
    by_id = {c['code_unit_id']: c for c in chunks}
    units = {u['id']: u for s in fresh['sources'] for u in s['facts']['code_units']}
    output = dict(files)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': fresh['source_binding'],
               'generated_operations': [], 'adapted_operations': [], 'partial_effects': [], 'gaps': [],
               'helper_models': [], 'converted_code_unit_count': 0, 'original_reads_enabled': False,
               'customer_table_writes': False, 'synthetic_table_writes': False, 'oracle_compiled': False,
               'runtime_verified': False, 'business_accepted': False}
    occupied = {int(m[1]) for n in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', n))}
    page = 1
    accounted_helpers = set()
    for unit in units.values():
        owner = objects[unit['owner_id']]
        if owner['kind'] != 'Trigger' or (owner['name'] or '').upper() != 'ON-POPULATE-DETAILS':
            continue
        identity = {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                    'source_owner_id': owner['id'], 'source_module_id': owner['module_id']}
        try:
            _need(len([o for o in objects.values() if o['kind'] == 'Trigger' and o['parent_id'] == owner['parent_id']
                       and (o['name'] or '').upper() == 'ON-POPULATE-DETAILS']) == 1, 'POPULATION_TRIGGER_NOT_UNIQUE')
            parsed = parse_population(by_id[unit['id']]['text'])
            def helper(name):
                obj = _one([o for o in objects.values() if o['kind'] == 'ProgramUnit' and o['module_id'] == owner['module_id']
                            and (o['name'] or '').upper() == name], 'LOCAL_HELPER_NOT_UNIQUE')
                u = _one([u for u in units.values() if u['owner_id'] == obj['id']], 'LOCAL_HELPER_UNIT')
                return u, by_id[u['id']]['text']
            qu, qt = helper(parsed['helper_name'])
            cu, ct = helper(parsed['check_name'])
            qm, cm = parse_query_helper(qt), parse_check_helper(ct)
            _need(qm['V_PROC'] == parsed['helper_name'] and qm['V_CHECK'] == cm['V_PROC'] == parsed['check_name'], 'HELPER_CALL_GRAPH')
            module_units = [u for u in units.values() if objects[u['owner_id']]['module_id'] == owner['module_id']]
            # Static flags apply only to this generated isolated application.
            # Any source-visible runtime mutation/dynamic trigger invalidates it.
            for u in module_units:
                t, _ = _tokens_for_scan(by_id[u['id']]['text'])
                _need(not ({'SET_RELATION_PROPERTY', 'EXECUTE_TRIGGER'} & set(t)), 'RUNTIME_RELATION_PROPERTIES_UNRESOLVED')
            _need(not any(o['module_id'] == owner['module_id'] and o['kind'] == 'AttachedLibrary' for o in objects.values()),
                  'ATTACHED_RELATION_MUTATION_UNRESOLVED')
            bound = _bind(owner, parsed, objects, props, trace, files)
            clears = [o for o in objects.values() if o['kind'] == 'Trigger' and (o['name'] or '').upper() == 'ON-CLEAR-DETAILS'
                      and o['module_id'] == owner['module_id'] and o['parent_id'] in (owner['module_id'], owner['block_id'])]
            _need(clears, 'APPLICABLE_ON_CLEAR_DETAILS_REQUIRED')
            while page in occupied and page < 9000:
                page += 1
            _need(page < 9000, 'PAGE_CAPACITY')
            occupied.add(page)
            filename = f'pages/p{page:05d}-fox_coord_{page}.apx'
            rendered, queries = _render(bound, page)
            parent_file = bound['parent']['report_file']
            text = output[parent_file].decode().replace('\r\n', '\n')
            _need(text.endswith(')\n') and '    button coordinate-master-details (' not in text, 'ENTRY_POINT_COLLISION')
            output[filename] = rendered
            output[parent_file] = (text[:-2] + _entry_button(page) + ')\n').encode()
            op = {**identity, 'operation_id': 'fmd1-' + _sha(_json([unit['id'], page]))[:24], 'kind': 'selected_master_population',
                  'rule_id': RULE_ID, 'generation_status': 'partial_effects_wired', 'source_event': 'ON-POPULATE-DETAILS',
                  'relation_id': bound['relation']['relation_id'], 'source_attribute_sha256': bound['relation']['source_attribute_sha256'],
                  'parent_block_id': bound['relation']['parent_block_id'], 'child_block_id': bound['relation']['child_block_id'],
                  'guard_bindings': bound['guards'], 'guard_connector': bound['connector'],
                  'source_field_bindings': bound['source_field_bindings'], 'original_join_condition': bound['original_join_condition'],
                  'original_child_query_properties': bound['original_child_query_properties'],
                  'source_flags': bound['relation']['source_flags'], 'deferred': bound['deferred'], 'auto_query': bound['auto_query'],
                  'source_helper_units': [{'source_unit_id': u['id'], 'source_unit_sha256': u['sha256']} for u in (qu, cu)],
                  'decode_receipt': parsed['decode_receipt'], 'page_id': page, 'page_file': filename,
                  'parent_item': f'P{page}_PARENT_ID', 'token_item': f'P{page}_TOKEN', 'state_item': f'P{page}_STATE',
                  'selection_region': 'master-choice', 'population_process': 'coordinate-selected-master',
                  'entry_report_file': parent_file, 'snapshot_fields': bound['snapshot_fields'],
                  'applicable_clear_trigger_ids': [o['id'] for o in clears], **queries,
                  'runtime_verified': False, 'business_accepted': False}
            receipt['adapted_operations'].append(op)
            omitted = ['dirty_forms_buffer_population', 'full_forms_cursor_and_message_level_lifecycle', 'source_clear_details_and_ASK_COMMIT']
            if bound['deferred']:
                omitted.append('deferred_detail_activation_after_NON_COORDINATED')
            try:
                draft = _draft_provider(bound, documents, packet, chunks, trace, files)
                if draft:
                    dpage = draft['page_id']
                    extra = _report('coordinated-draft-details', 'Details for the current saved draft record', draft['child_query_sql'], bound['child']['items'], sequence=40)
                    extra += _report('draft-coordination-state', 'Current draft coordination state', draft['status_query_sql'],
                                     [{'column': 'FOX_DRAFT_STATE', 'data_type': 'VARCHAR2', 'source_name': 'Draft status'}], sequence=35)
                    dtext = output[draft['page_file']].decode()
                    _need(dtext.endswith(')\n'), 'DRAFT_PAGE_END')
                    focus = _focus_script(dpage)
                    js = list(re.finditer(r'```javascript\n(.*?)\n\s*```', dtext, re.S))
                    _need(len(js) <= 1, 'DRAFT_JAVASCRIPT_AMBIGUOUS')
                    if js:
                        m = js[0]
                        dtext = dtext[:m.end(1)] + '\n' + native_buffer._indent(focus, 12) + dtext[m.end(1):]
                    else:
                        dtext = dtext.replace(f'page {dpage} (\n', f'page {dpage} (\n    javaScript {{\n        executeWhenPageLoads:\n            ```javascript\n'
                                             + native_buffer._indent(focus, 12) + '\n            ```\n    }\n', 1)
                    output[draft['page_file']] = (dtext[:-2] + native_buffer._expand_groups(extra) + ')\n').encode()
                    op['draft_provider'] = draft
                    receipt['partial_effects'].append({**identity, 'kind': 'current_saved_draft_identity_population', **draft})
            except (ValueError, KeyError, TypeError) as exc:
                receipt['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError) else 'MASTER_DETAILS_DRAFT_PROVIDER_UNAVAILABLE'})
            receipt['gaps'].append({**identity, 'reason': 'MASTER_DETAILS_PARTIAL_POPULATION_LIFECYCLE', 'unimplemented_effects': omitted})
            for u, model in ((qu, qm), (cu, cm)):
                if u['id'] not in accounted_helpers:
                    accounted_helpers.add(u['id'])
                    receipt['helper_models'].append({'source_unit_id': u['id'], 'source_unit_sha256': u['sha256'],
                        'source_module_id': owner['module_id'], 'complete_source_parsed': True, 'model': model,
                        'status': 'partial_native_call_sites', 'whole_unit_generated': False})
                    receipt['gaps'].append({'source_unit_id': u['id'], 'source_unit_sha256': u['sha256'],
                        'reason': 'MASTER_DETAILS_HELPER_OTHER_CALLERS_AND_FORMS_RUNTIME_UNCONNECTED'})
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            receipt['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError) else 'MASTER_DETAILS_SOURCE_CONTEXT_UNAVAILABLE'})
    receipt['receipt_sha256'] = _sha(_json(receipt))
    return output, receipt


def _tokens_for_scan(text):
    """Scan identifiers without interpreting the rest of an unrelated source unit."""
    semantic, receipt = decode_control_entities(text)
    semantic = re.sub(r"'(?:''|[^'])*'|--[^\r\n]*|/\*.*?\*/", ' ', semantic, flags=re.S)
    return re.findall(r'[A-Za-z][A-Za-z0-9_]*', semantic.upper()), receipt
