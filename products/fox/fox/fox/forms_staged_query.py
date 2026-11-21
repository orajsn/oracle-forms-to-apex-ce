"""Native, explicitly adapted session staging for proved KEY-EXEQRY workflows.

Only the compiler's original SELECT is executed, dynamically and with a bound
key. Original DELETE/INSERT remain source evidence, never runtime operations.
Session collection replacement has its own savepoint, unlike the caller-owned
source transaction. An exclusive DBMS_LOCK held until the request transaction
ends serializes collection updates from concurrent requests in the same session.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex.native_buffer import _expand_groups
from .forms_manifest_filter import _app_item, _report, _rhs
from .forms_staged_query_plan import build_staged_query_plan

SCOPE = 'fox-staged-query-native-v1'
MAX_ROWS = 5000
MAX_ROW_BYTES = 1048576
MAX_STAGE_CHARACTERS = 16777216


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _need(value, reason):
    if not value:
        raise ValueError('STAGED_QUERY_' + reason)


def _literal(value):
    _need(type(value) is str and len(value.encode()) < 30000
          and not any(c in value for c in '&`') and '\x00' not in value,
          'LITERAL_CONTEXT')
    return "'" + value.replace("'", "''") + "'"


def _append(text, addition):
    _need(text.endswith(')\n'), 'PAGE_ANCHOR')
    return text[:-2] + addition + ')\n'


def _render_sql(op, collection, gate):
    """Serialize every INSERT value; display only proved direct block fields."""
    projection = op['projection']
    fields = [p for p in projection if p.get('source_item_id') and p.get('column')]
    _need(fields and len({p['column'] for p in fields}) == len(fields), 'VISIBLE_PROJECTION')
    source_select = op['source_select_sql']
    # Identifiers originate in the complete deterministic compiler. Keep the
    # execution boundary closed even when called with a corrupt operation.
    for p in projection:
        _need(re.fullmatch(r'[A-Z][A-Z0-9_$#]{0,127}', p['source_column'])
              and re.fullmatch(r'[A-Z][A-Z0-9_$#]{0,127}', p['staging_column']), 'PROJECTION_IDENTIFIER')
    _need(len({p['staging_column'] for p in projection}) == len(projection), 'PROJECTION_DUPLICATE')
    source_prefix = 'SELECT ' + ', '.join(p['source_column'] for p in projection)
    source_suffix = ('\nFROM ' + op['source_table'] + '\nWHERE ' + op['source_key_column']
                     + ' = :FOX_QUERY_KEY')
    _need(source_select == source_prefix + source_suffix, 'EXACT_SOURCE_SELECT_REQUIRED')
    # Avoid an inline view with duplicate source names: SELECT X,X is legal
    # when the INSERT destinations differ, and both values must survive.
    pairs = ','.join(_literal(p['staging_column']) + ' VALUE ' + p['source_column'] for p in projection)
    json_sql = ('SELECT JSON_OBJECT(' + pairs + ' NULL ON NULL RETURNING CLOB) FOX_ROW'
                + source_suffix)
    declarations, select_fields, display = [], [], []
    for i, f in enumerate(fields, 1):
        dtype = f['data_type']
        _need(dtype in ('VARCHAR2', 'NUMBER', 'DATE'), 'VISIBLE_TYPE')
        name = 'V' + str(i)
        # Preserve time for DATE, without implicit NLS conversion. Oracle SQL/JSON
        # DATE projection otherwise truncates a timestamp's time component.
        sql_type = 'TIMESTAMP' if dtype == 'DATE' else 'VARCHAR2(4000)' if dtype == 'VARCHAR2' else 'NUMBER'
        declarations.append(name + ' ' + sql_type + ' PATH ' + _literal('$."' + f['staging_column'] + '"') + ' ERROR ON ERROR')
        expression = 'CAST(j.' + name + ' AS DATE)' if dtype == 'DATE' else 'j.' + name
        select_fields.append(expression + ' AS ' + f['column'])
        display.append({**f, 'source_item_name': f.get('source_item_name') or f.get('source_name') or f['staging_column']})
    globals_ = {b['source_reference'][1]: b['app_item'] for b in op['global_bindings']}
    predicates = ['s.' + t['column'] + ' = ' + _rhs(t['value'], globals_) for t in op['filter_terms']]
    guards = [':' + gate + " = 'Y'"] + [':' + b['app_item'] + ' IS NOT NULL' for b in op['global_bindings']]
    inner = ('SELECT ' + ', '.join(select_fields) + '\nFROM apex_collections c,\nJSON_TABLE(c.clob001, \'$\' COLUMNS ('
             + ', '.join(declarations) + ")) j\nWHERE c.collection_name = " + _literal(collection))
    report_sql = 'SELECT s.* FROM (' + inner + ') s\nWHERE ' + '\nAND '.join(predicates + guards)
    if op.get('source_order'):
        by_staging = {f['staging_column']: f for f in fields}
        _need(all(t['source_name'] in by_staging for t in op['source_order']),
              'SOURCE_ORDER_METADATA_REQUIRED')
        report_sql += '\nORDER BY ' + ', '.join('s.' + by_staging[t['source_name']]['column']
            + ' ' + t['direction'].upper() + ' NULLS ' + t['nulls'].upper() for t in op['source_order'])
    return source_select, json_sql, report_sql, display, inner


def _process(op, page, collection, source_gate, view_gate, source_select, json_sql, validation_sql):
    key = f'P{page}_QUERY_KEY'
    key_type = op['key_binding']['data_type']
    _need(key_type == 'VARCHAR2', 'CHARACTER_QUERY_KEY_REQUIRED')
    maximum = op['key_binding'].get('max_length')
    _need(type(maximum) is int and 0 < maximum <= 4000, 'QUERY_KEY_LENGTH_REQUIRED')
    length_fn = 'length' if op['key_binding'].get('length_semantics') == 'CHAR' else 'lengthb'
    globals_check = '\n'.join('if :' + b['app_item'] + " is null then raise_application_error(-20061,'Trusted source origin is unavailable.'); end if;"
                              for b in op['global_bindings'])
    # Parse/describe before opening the data cursor. Unsupported Oracle types fail
    # without staging anything. JSON preserves all source projection values, not
    # only the subset with visible Forms items. No DISTINCT or row-token key.
    checks = []
    for i, p in enumerate(op['projection'], 1):
        expected = {'VARCHAR2': '(1)', 'NUMBER': '(2)', 'DATE': '(12)'}.get(p.get('data_type'), '(1,96,2,12)')
        if p['staging_column'] == op['staging_key_column']:
            expected = '(1)'  # Session replacement requires a byte-exact VARCHAR2 key.
        checks.append(f"if l_desc({i}).col_type not in {expected} or l_desc({i}).col_name <> {_literal(p['source_column'])} then raise_application_error(-20061,'Source projection metadata does not match this adapter.'); end if;")
        checks.append(f"if l_desc({i}).col_type in (1,96) and nvl(l_desc({i}).col_charsetform,0)<>1 then raise_application_error(-20061,'National character source columns require a separate adapter.'); end if;")
        if p.get('column') and p.get('data_type') == 'VARCHAR2':
            checks.append(f"if l_desc({i}).col_max_len > 4000 then raise_application_error(-20061,'Visible source text exceeds the query renderer capacity.'); end if;")
    checks_sql = '\n'.join(checks)
    code = f'''declare
  l_key varchar2(4000) := :{key};
  l_name varchar2(255) := {_literal(collection)};
  l_candidate varchar2(255);
  l_lock_id integer;
  l_lock_result integer;
  l_cursor sys_refcursor;
  l_describe integer;
  l_count integer;
  l_desc dbms_sql.desc_tab2;
  l_row clob;
  l_row_key varchar2(4000);
  l_rows integer := 0;
  l_bytes number := 0;
  l_binary_settings integer;
begin
  if l_key is null then return; end if;
  if :APP_USER is null or upper(:APP_USER)='NOBODY' then raise_application_error(-20061,'Authentication required.'); end if;
  if nvl(:{source_gate},'N') <> 'Y' or nvl(:{view_gate},'N') <> 'Y' then raise_application_error(-20061,'Source interface or private query stage is not ready. No stage was changed.'); end if;
  {globals_check}
  if {length_fn}(l_key) > {maximum} then raise_application_error(-20061,'Query key exceeds the source length limit.'); end if;
  select count(*) into l_binary_settings from nls_session_parameters
    where (parameter='NLS_COMP' and value='BINARY') or (parameter='NLS_SORT' and value='BINARY');
  if l_binary_settings<>2 then raise_application_error(-20061,'Binary comparison settings are required for this query adapter.'); end if;
  l_lock_id := dbms_utility.get_hash_value('FOX_SQ:'||:APP_ID||':'||:APP_SESSION||':'||l_name,0,1073741823);
  execute immediate 'begin :r := dbms_lock.request(id=>:i,lockmode=>6,timeout=>0,release_on_commit=>true); end;' using out l_lock_result, in l_lock_id;
  if l_lock_result <> 0 then raise_application_error(-20061,'Another query refresh is active. Retry after it finishes.'); end if;
  savepoint fox_sq_refresh;
  begin
    l_describe := dbms_sql.open_cursor;
    dbms_sql.parse(l_describe,{_literal(source_select)},dbms_sql.native);
    dbms_sql.describe_columns2(l_describe,l_count,l_desc);
    if l_count <> {len(op['projection'])} then raise_application_error(-20061,'Source projection width changed.'); end if;
    {checks_sql}
    dbms_sql.close_cursor(l_describe);
    l_describe := null;
    l_candidate := l_name||'_'||rawtohex(sys_guid());
    apex_collection.create_collection(p_collection_name=>l_candidate);
    select count(*),nvl(sum(dbms_lob.getlength(clob001)),0) into l_rows,l_bytes from apex_collections
      where collection_name=l_name and (c001 is null or utl_raw.cast_to_raw(c001)<>utl_raw.cast_to_raw(l_key));
    open l_cursor for {_literal(json_sql)} using l_key;
    loop
      fetch l_cursor into l_row;
      exit when l_cursor%notfound;
      select json_value(l_row,{_literal('$."' + op['staging_key_column'] + '"')} returning varchar2(4000) error on error) into l_row_key from dual;
      if l_row_key is null or utl_raw.cast_to_raw(l_row_key)<>utl_raw.cast_to_raw(l_key) then raise_application_error(-20061,'Source key requires padding or collation behavior unavailable in this adapter.'); end if;
      l_rows := l_rows+1;
      l_bytes := l_bytes+dbms_lob.getlength(l_row);
      if l_rows > {MAX_ROWS} or dbms_lob.getlength(l_row) > {MAX_ROW_BYTES} or l_bytes > {MAX_STAGE_CHARACTERS} then raise_application_error(-20061,'Private stage capacity exceeded; prior stage preserved.'); end if;
      apex_collection.add_member(p_collection_name=>l_candidate,p_c001=>l_row_key,p_clob001=>l_row);
    end loop;
    close l_cursor;
    for r in ({validation_sql.replace(_literal(collection), 'l_candidate')}) loop
      null;
    end loop;
    if not apex_collection.collection_exists(p_collection_name=>l_name) then
      apex_collection.create_collection(p_collection_name=>l_name);
    end if;
    for r in (select seq_id from apex_collections where collection_name=l_name and utl_raw.cast_to_raw(c001)=utl_raw.cast_to_raw(l_key)) loop
      apex_collection.delete_member(p_collection_name=>l_name,p_seq=>r.seq_id);
    end loop;
    for r in (select c001,clob001 from apex_collections where collection_name=l_candidate order by seq_id) loop
      apex_collection.add_member(p_collection_name=>l_name,p_c001=>r.c001,p_clob001=>r.clob001);
    end loop;
    apex_collection.delete_collection(p_collection_name=>l_candidate);
  exception when others then
    if l_cursor%isopen then close l_cursor; end if;
    if l_describe is not null and dbms_sql.is_open(l_describe) then dbms_sql.close_cursor(l_describe); end if;
    rollback to fox_sq_refresh;
    raise;
  end;
end;'''
    _need(len(code.encode()) < 30000, 'PROCESS_CAPACITY')
    return code


def _page(op, page, report_sql, fields, code, source_gate, view_gate):
    label = op['target'].get('name', 'Records') + ' staged query'
    text = _report(page, fields, report_sql, label, len(op['target']['items']) - len(fields))
    start, end = text.index('    region scope ('), text.index('    region records (')
    scope = _expand_groups('''    region scope (
        name: Staged query scope
        type: staticContent
        source { htmlCode: "Enter a query key, then Execute query. A blank key does nothing. This refreshes that key's private session rows and keeps other keys. The list uses the original filter and trusted origin. An unavailable source shows an error and preserves prior rows. Administrator setup is required before original reads. Original tables are never changed. Related records and editors remain synthetic demonstrations. See the receipt for omitted fields and transaction differences." }
        layout { sequence: 5
            slot: body }
        appearance { template: @/standard
            templateOptions: #DEFAULT# }
    )
    region query-input (
        name: Query key
        type: staticContent
        source { htmlCode: "The trusted origin must be supplied by the administrator's server-side provider." }
        layout { sequence: 6
            slot: body }
        appearance { template: @/standard
            templateOptions: #DEFAULT# }
    )
''')
    text = text[:start] + scope + text[end:]
    text = text.replace(f'alias: FOX_FILTER_{page}', f'alias: FOX_STAGEQ_{page}')
    condition = ':' + view_gate + " = 'Y'" + ''.join(' and :' + b['app_item'] + ' is not null' for b in op['global_bindings'])
    text = text.replace('        savedReport primary (\n', _expand_groups('''        serverSideCondition { type: expression
            language: plsql
            plsqlExpression: %s }
''' % json.dumps(condition)) + '        savedReport primary (\n')
    controls = _expand_groups(f'''    pageItem P{page}_QUERY_KEY (
        type: textField
        settings {{ trimSpaces: none }}
        label {{ label: {json.dumps(op['key_binding']['source_reference'][-1])} }}
        layout {{ sequence: 10
            region: @query-input
            slot: regionBody }}
        appearance {{ template: @/optional-floating }}
        sessionState {{ storage: session
            dataType: varchar2 }}
        security {{ sessionStateProtection: unrestricted }}
    )
    button execute-staged-query (
        buttonName: FOX_STAGE_QUERY
        label: Execute query
        layout {{ sequence: 20
            region: @query-input
            slot: change }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: submitPage
            executeValidations: false }}
    )
    process execute-staged-query (
        name: Refresh private query stage
        type: executeCode
        source {{ plsqlCode:
                ```plsql
{chr(10).join('                ' + line for line in code.splitlines())}
                ```
        }}
        execution {{ sequence: 10
            point: processing }}
        serverSideCondition {{ type: requestIsContainedInValue
            value: FOX_STAGE_QUERY }}
    )
''')
    return _append(text, controls).encode()


def _entry(page):
    return _expand_groups(f'''    button staged-query-{page} (
        buttonName: FOX_STAGE_{page}
        label: Enter query key
        layout {{ sequence: {page}
            region: @records
            slot: rightOfInteractiveReportSearchBar }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {page} }} }}
    )
''')


def apply_staged_queries(documents, packet, chunks, trace, files):
    """Compile and wire a safe adaptation; preserve every input member."""
    plan = build_staged_query_plan(documents, packet, chunks, trace, files)
    _need(not any(re.fullmatch(r'pages/p\d+-fox_stageq_\d+\.apx', n) for n in files), 'ALREADY_APPLIED')
    result = dict(files)
    result['fox-package/staged-query-plan.json'] = _json(plan)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': plan['source_binding'],
               'generated_operations': [], 'gaps': deepcopy(plan['gaps']),
               'original_reads_enabled': False, 'customer_table_writes': False,
               'runtime_verified': False, 'business_accepted': False}
    occupied = {int(m[1]) for n in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', n))}
    page = 8700
    for op in plan['operations']:
        identity = {k: op[k] for k in ('source_unit_id', 'source_unit_sha256', 'source_owner_id', 'source_module_id')}
        try:
            while page in occupied:
                page += 1
            _need(page < 9000, 'PAGE_CAPACITY')
            slug = hashlib.sha256(_json([plan['source_binding'], op['operation_id']])).hexdigest()[:20].upper()
            collection = 'FOX_SQ_' + slug
            source_gate, view_gate = 'FOX_SQ_SRC_' + slug, 'FOX_SQ_VIEW_' + slug
            source_select, json_sql, report_sql, fields, validation_sql = _render_sql(op, collection, view_gate)
            code = _process(op, page, collection, source_gate, view_gate, source_select, json_sql, validation_sql)
            page_file = f'pages/p{page:05d}-fox_stageq_{page}.apx'
            changes = {page_file: _page(op, page, report_sql, fields, code, source_gate, view_gate)}
            entries = [op['target']['report_file']]
            entry_pages = {op['target']['report_file']: op['target']['report_page_id']}
            # The normal source query screen is another entry only when its
            # sealed receipt proves exact source-block/table provenance.
            if 'fox-package/block-filter-receipt.json' in result:
                filters = json.loads(result['fox-package/block-filter-receipt.json'])
                _need(filters.get('source_binding') == plan['source_binding'], 'FILTER_SOURCE_BINDING')
                for adapter in filters['generated_operations']:
                    if (adapter.get('source_table') == op['staging_table']
                            and adapter.get('report_files') == [op['target']['report_file']]):
                        entries.append(adapter['page_file'])
                        entry_pages[adapter['page_file']] = adapter['page_id']
            for path in sorted(set(entries)):
                old = result[path].decode()
                _need(old.startswith(f"page {entry_pages[path]} (\n")
                      and old.count('    region records (\n') == 1 and 'button staged-query-' not in old,
                      'ENTRY_PROVENANCE')
                changes[path] = _append(old, _entry(page)).encode()
            app_path = 'shared-components/app-items.apx'
            app_text = result.get(app_path, b'').decode()
            for name in [source_gate, view_gate] + [b['app_item'] for b in op['global_bindings']]:
                declaration = _app_item(name)
                if re.search(r'\bappItem\s+' + re.escape(name) + r'\b', app_text):
                    _need(app_text.count(declaration) == 1, 'RESTRICTED_APP_ITEM_REQUIRED')
                else:
                    app_text += '\n' + declaration
            changes[app_path] = app_text.encode()
            result.update(changes)
            receipt['generated_operations'].append({**identity, 'operation_id': 'staged-native-' + slug.lower(),
                'plan_operation_id': op['operation_id'], 'kind': 'guarded_staged_block_query',
                'rule_id': 'fox.query.staged-refresh', 'generation_status': 'partial_effects_wired',
                'native_event_wired': True, 'whole_source_unit_converted': False,
                'page_id': page, 'page_file': page_file, 'entry_files': sorted(set(entries)),
                'query_key_item': f'P{page}_QUERY_KEY', 'source_table': op['source_table'],
                'staging_table': op['staging_table'], 'collection_name': collection,
                'source_readiness_item': source_gate, 'stage_readiness_item': view_gate,
                'global_bindings': deepcopy(op['global_bindings']), 'source_select_sql': source_select,
                'source_json_sql': json_sql, 'session_process_plsql': code, 'session_report_sql': report_sql,
                'session_stage_validation_sql': validation_sql,
                'source_projection': deepcopy(op['projection']), 'visible_projection': fields,
                'semantic_gaps': deepcopy(op['semantic_gaps']),
                'projection_omissions': deepcopy(op['projection_omissions']),
                'source_transaction_owner': 'caller', 'source_no_commit': True,
                'adaptation': 'Private APEX-session collection with bounded atomic request refresh and an adaptation-only savepoint/rollback; original shared staging and caller transaction lifetime are not reproduced.',
                'prerequisites': ['verified distinct original SELECT table and all projected column types',
                    'separate restricted source-read and private-stage readiness providers',
                    'trusted server-side original GLOBAL provider',
                    'DBMS_LOCK.REQUEST execute privilege for same-session serialization',
                    'VARCHAR2 source key and byte-exact returned values; CHAR padding and nonexact collation matches fail closed',
                    'visible text must be database-character-set VARCHAR2 no wider than 4000 bytes; NCHAR/NVARCHAR2 rejected',
                    'administrator-verified binary original source/staging column collations and VARCHAR2 staging text semantics; DBMS_SQL does not prove declared collation',
                    'target verification of transactional APEX collection APIs'],
                'comparison_semantics': 'binary_varchar2_only_original_declared_collations_require_administrator_verification',
                'key_length_semantics': op['key_binding'].get('length_semantics', 'UNSPECIFIED'),
                'unknown_key_length_semantics_policy': 'conservative byte limit',
                'row_limit': MAX_ROWS, 'max_json_row_characters': MAX_ROW_BYTES,
                'max_stage_characters': MAX_STAGE_CHARACTERS,
                'original_interface_enabled': False, 'source_query_executed': False,
                'customer_table_writes': False, 'runtime_verified': False, 'business_accepted': False})
            receipt['gaps'].append({**identity, 'reason': 'STAGED_QUERY_PRIVATE_SESSION_ADAPTATION',
                'next_action': 'Verify original interface metadata, session APIs and serialization on the target; bind source transaction consumers separately.'})
            occupied.add(page)
            page += 1
        except (ValueError, KeyError, TypeError, UnicodeError) as exc:
            receipt['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError)
                                   else 'STAGED_QUERY_NATIVE_CONTEXT_UNAVAILABLE'})
    receipt['receipt_sha256'] = hashlib.sha256(_json(receipt)).hexdigest()
    return result, deepcopy(receipt)
