"""Native generation and disposable SQL probes; never Oracle runtime proof."""
from copy import deepcopy
import json
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_manifest_filter import apply_manifest_filters
from fox.forms_staged_query import apply_staged_queries
from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members
from fox.xml_mapping import generate_xml_package
from test_forms_staged_query_plan import source, prepare, database


def apply(docs=None, *, with_filter=True):
    docs = docs or source()
    packet, chunks, trace, files = prepare(docs)
    if with_filter:
        files, filters = apply_manifest_filters(docs, packet, chunks, trace, files)
        files['fox-package/block-filter-receipt.json'] = json.dumps(filters).encode()
    args = (packet, chunks, trace, files)
    output, receipt = apply_staged_queries(docs, *args)
    return output, receipt, args


def only(receipt):
    assert len(receipt['generated_operations']) == 1, receipt['gaps']
    return receipt['generated_operations'][0]


@pytest.mark.parametrize('renamed', [False, True])
def test_source_to_native_query_key_input_links_and_honest_adaptation(renamed):
    docs = source(renamed=renamed)
    _, _, args = apply(docs)
    before = deepcopy((docs, args))
    output, receipt = apply_staged_queries(docs, *args)
    assert (docs, args) == before
    assert (output, receipt) == apply_staged_queries(docs, *args)
    op = only(receipt)
    plan = json.loads(output['fox-package/staged-query-plan.json'])
    original_op = plan['operations'][0]
    page = output[op['page_file']].decode()
    assert op['plan_operation_id'] == original_op['operation_id']
    assert op['source_unit_id'] == original_op['source_unit_id']
    assert op['source_unit_sha256'] == original_op['source_unit_sha256']
    assert op['rule_id'] == 'fox.query.staged-refresh'
    assert f"page {op['page_id']} (\n" in page
    assert f"alias: FOX_STAGEQ_{op['page_id']}" in page
    assert f"pageItem {op['query_key_item']} (" in page and 'type: textField' in page
    assert 'trimSpaces: none' in page and 'action: submitPage' in page
    assert 'value: FOX_STAGE_QUERY' in page and 'point: processing' in page
    assert 'authentication: required' in page and 'argumentsMustHaveChecksum' in page
    assert len(op['entry_files']) == 2  # normal report and actual source-query screen
    for path in op['entry_files']:
        assert f"page: {op['page_id']}" in output[path].decode()
        assert 'label: Enter query key' in output[path].decode()
    assert len(op['source_projection']) == 17 and len(op['visible_projection']) == 13
    assert all(not op[k] for k in ('whole_source_unit_converted', 'original_interface_enabled',
        'source_query_executed', 'customer_table_writes', 'runtime_verified', 'business_accepted'))
    assert op['native_event_wired'] and op['source_no_commit']
    assert op['source_transaction_owner'] == 'caller'
    assert 'savepoint/rollback' in op['adaptation']
    assert receipt['gaps'][0]['reason'] == 'STAGED_QUERY_PRIVATE_SESSION_ADAPTATION'
    assert not receipt['original_reads_enabled']
    for name, raw in docs:
        assert output['fox-package/sources/' + name] == raw
    changed = set(op['entry_files']) | {'shared-components/app-items.apx'}
    assert all(output[n] == raw for n, raw in args[3].items() if n not in changed)


def test_actual_bound_source_select_uses_distinct_source_not_destination_and_keeps_multiplicity():
    _, receipt, args = apply()
    op = only(receipt)
    plan = json.loads(apply_staged_queries(source(), *args)[0]['fox-package/staged-query-plan.json'])
    db = database(plan['operations'][0])
    before = db.total_changes
    assert 'FROM SOURCE_ROWS' in op['source_select_sql']
    assert 'STAGE_ROWS' not in op['source_select_sql']
    for key, count in [('A', 3), ('B', 1), ('missing', 0), ("A' OR 1=1 --", 0)]:
        rows = db.execute(op['source_select_sql'], {'FOX_QUERY_KEY': key}).fetchall()
        assert len(rows) == count
        if key == 'A':
            assert rows[0] == rows[1] and len(rows[0]) == 17
    assert db.total_changes == before
    db.execute('DROP TABLE SOURCE_ROWS')
    with pytest.raises(sqlite3.DatabaseError):
        db.execute(op['source_select_sql'], {'FOX_QUERY_KEY': 'A'})


def test_process_orders_null_gate_lock_metadata_fetch_then_atomic_key_replacement():
    _, receipt, _ = apply()
    op = only(receipt)
    code = op['session_process_plsql']
    null = code.index('if l_key is null then return; end if;')
    auth = code.index('if :APP_USER is null')
    permission = code.index('if nvl(:' + op['source_readiness_item'])
    lock = code.index('dbms_lock.request')
    snapshot = code.index('savepoint fox_sq_refresh;')
    describe = code.index('dbms_sql.describe_columns2')
    read = code.index('open l_cursor for ')
    finished = code.index('close l_cursor;')
    replace = code.index('apex_collection.delete_member(')
    assert null < auth < permission < lock < snapshot < describe < read < finished < replace
    assert 'release_on_commit=>true' in code and 'timeout=>0' in code
    assert 'l_lock_result <> 0' in code
    assert "'FOX_SQ:'||:APP_ID||':'||:APP_SESSION||':'||l_name" in code
    assert 'using l_key;' in code and 'using out l_lock_result, in l_lock_id;' in code
    assert 'rollback to fox_sq_refresh;' in code and '    raise;' in code
    assert 'apex_collection.delete_collection(p_collection_name=>l_candidate)' in code
    assert 'create_or_truncate' not in code
    assert 'utl_raw.cast_to_raw(c001)=utl_raw.cast_to_raw(l_key)' in code
    assert 'p_c001=>l_row_key' in code
    assert 'utl_raw.cast_to_raw(l_row_key)<>utl_raw.cast_to_raw(l_key)' in code
    # Never invoke source DELETE/INSERT, session-state commits or lock allocation.
    assert not re.search(r'\b(?:delete\s+from|insert\s+into|update\s+\w+\s+set|commit;|allocate_unique|set_session_state)\b', code, re.I)
    assert 'where collection_name=l_candidate' in code
    assert 'where collection_name=l_name and (c001 is null or' in code
    assert 'Private stage capacity exceeded; prior stage preserved.' in code


def test_trusted_origin_and_private_view_permission_hide_report_and_gate_original_read_separately():
    output, receipt, args = apply()
    op = only(receipt)
    page = output[op['page_file']].decode()
    global_item = op['global_bindings'][0]['app_item']
    app = output['shared-components/app-items.apx'].decode()
    filters = json.loads(args[3]['fox-package/block-filter-receipt.json'])
    existing_gate = filters['generated_operations'][0]['readiness_item']
    assert len({existing_gate, op['source_readiness_item'], op['stage_readiness_item']}) == 3
    for name in (global_item, op['source_readiness_item'], op['stage_readiness_item']):
        assert f'appItem {name} (' in app
        assert f'appItem {name} (\n    scope: app\n    security {{\n        sessionStateProtection: restricted' in app
        assert f'pageItem {name} (' not in page
    report_sql = op['session_report_sql']
    native_cols = {p['staging_column']: p['column'] for p in op['visible_projection']}
    assert 's.' + native_cols['CATEGORY'] + " = 'R'" in report_sql
    assert 's.' + native_cols['DEPOT'] + ' = :' + global_item in report_sql
    assert ':' + global_item + ' IS NOT NULL' in report_sql
    assert ':' + op['stage_readiness_item'] + " = 'Y'" in report_sql
    assert 'ORDER BY s.' + native_cols['KEY_CODE'] + ' DESC NULLS FIRST' in report_sql
    assert 'serverSideCondition' in page and ':' + global_item + ' is not null' in page
    assert 'if :' + global_item + ' is null then raise_application_error' in op['session_process_plsql']
    assert 'SOURCE_ROWS' not in report_sql and 'STAGE_ROWS' not in report_sql


def test_complete_json_projection_preserves_unknown_values_nulls_numeric_and_date_types():
    _, receipt, _ = apply()
    op = only(receipt)
    query, code, report = op['source_json_sql'], op['session_process_plsql'], op['session_report_sql']
    assert 'NULL ON NULL RETURNING CLOB' in query
    for p in op['source_projection']:
        assert "'" + p['staging_column'] + "' VALUE " + p['source_column'] in query
    assert 'DISTINCT' not in query and 'rownum' not in query.lower()
    assert 'TIMESTAMP PATH' in report and 'CAST(j.' in report and ' AS DATE)' in report
    assert 'NUMBER PATH' in report and 'ERROR ON ERROR' in report
    assert 'to_char(' not in query.lower() and 'to_number(' not in report.lower()
    assert '.col_type not in (1)' in code  # key is VARCHAR2 only; no CHAR padding guess
    assert '.col_type not in (1,96,2,12)' in code  # unknown metadata checked at runtime
    assert '.col_type not in (12)' in code
    assert 'p_clob001=>l_row' in code and 'dbms_lob.getlength(l_row)' in code


def test_duplicate_source_column_projection_is_retained_with_distinct_insert_destinations():
    docs = source()
    root = ET.fromstring(docs[0][1])
    trigger = root.find('Block/Trigger')
    body = trigger.get('TriggerText')
    select, rest = body.split('SELECT ', 1)
    trigger.set('TriggerText', select + 'SELECT ' + rest.replace('FIELD_17', 'FIELD_16', 1))
    _, receipt, _ = apply([('duplicate-source.xml', ET.tostring(root))])
    op = only(receipt)
    assert "'FIELD_16' VALUE FIELD_16" in op['source_json_sql']
    assert "'FIELD_17' VALUE FIELD_16" in op['source_json_sql']
    assert ') q' not in op['source_json_sql']


def test_padded_char_national_text_and_oversize_visible_values_fail_before_stage_replacement():
    _, receipt, _ = apply()
    op = only(receipt)
    code = op['session_process_plsql']
    for i, field in enumerate(op['source_projection'], 1):
        if field.get('column') and field.get('data_type') == 'VARCHAR2':
            assert f'l_desc({i}).col_type not in (1)' in code
            assert f'l_desc({i}).col_type not in (1,96)' not in code
            assert f'l_desc({i}).col_max_len > 4000' in code
        assert f'l_desc({i}).col_type in (1,96) and nvl(l_desc({i}).col_charsetform,0)<>1' in code
    assert "parameter='NLS_COMP' and value='BINARY'" in code
    assert "parameter='NLS_SORT' and value='BINARY'" in code
    assert 'if l_binary_settings<>2 then raise_application_error' in code
    assert 'original_declared_collations_require_administrator_verification' in op['comparison_semantics']
    assert any('DBMS_SQL does not prove declared collation' in p for p in op['prerequisites'])
    validate = code.index('for r in (SELECT j.')
    assert code.index('close l_cursor;') < validate < code.index('apex_collection.delete_member(')
    assert 'WHERE c.collection_name = l_candidate' in code[validate:]


@pytest.mark.parametrize('semantics,expression', [('BYTE', 'lengthb'), ('CHAR', 'length'), ('', 'lengthb')])
def test_key_length_semantics_are_enforced_without_trimming(semantics, expression):
    docs = source()
    root = ET.fromstring(docs[0][1])
    root.find('Block/Item').set('DataLengthSemantics', semantics)
    _, receipt, _ = apply([('length.xml', ET.tostring(root))])
    code = only(receipt)['session_process_plsql']
    assert f'if {expression}(l_key) > 80 then' in code
    assert 'trim(' not in code.lower()


@pytest.mark.parametrize('change', ['source', 'trace', 'chunk', 'missing_report', 'changed_page', 'bad_filter_receipt'])
def test_missing_or_corrupt_source_table_key_report_and_link_context_fails_closed(change):
    docs = source()
    _, _, args = apply(docs)
    packet, chunks, trace, files = deepcopy(args)
    if change == 'source':
        files['fox-package/sources/staged.xml'] += b' '
    elif change == 'trace':
        trace['blocks'][0]['source_module_id'] = 'unrelated'
    elif change == 'chunk':
        chunks[0]['text'] += ' COMMIT;'
    elif change == 'missing_report':
        del files[trace['blocks'][0]['report_file']]
    elif change == 'changed_page':
        path = trace['blocks'][0]['report_file']
        files[path] = files[path].replace(b'page ', b'page 999', 1)
    else:
        value = json.loads(files['fox-package/block-filter-receipt.json'])
        value['source_binding'] = 'wrong'
        files['fox-package/block-filter-receipt.json'] = json.dumps(value).encode()
    before = deepcopy(files)
    try:
        output, receipt = apply_staged_queries(docs, packet, chunks, trace, files)
    except ValueError:
        assert change in ('source', 'chunk')
    else:
        assert not receipt['generated_operations'] and receipt['gaps']
        assert not any('fox_stageq_' in n for n in output)
    assert files == before


def test_repeat_application_is_rejected_and_multiple_modules_stay_separate():
    docs = source()
    output, receipt, args = apply(docs)
    with pytest.raises(ValueError, match='ALREADY_APPLIED'):
        apply_staged_queries(docs, *args[:3], output)
    docs += source(renamed=True)
    output, receipt, _ = apply(docs)
    assert len(receipt['generated_operations']) == 2
    for key in ('collection_name', 'source_readiness_item', 'stage_readiness_item', 'page_file', 'source_module_id'):
        assert len({op[key] for op in receipt['generated_operations']}) == 2


@pytest.mark.parametrize('renamed', [False, True])
def test_normal_package_generation_wires_adaptation_and_preserves_source(renamed):
    docs = source(renamed=renamed)
    raw, report = generate_xml_package(docs, 'staged-native', 'Staged source query', POLICY_ID)
    files = _members(raw)
    receipt = json.loads(files['fox-package/staged-query-receipt.json'])
    op = only(receipt)
    assert files[op['page_file']]
    assert json.loads(files['fox-package/staged-query-plan.json'])['operations']
    assert files['fox-package/sources/' + docs[0][0]] == docs[0][1]
    assert not op['whole_source_unit_converted'] and op['native_event_wired']
