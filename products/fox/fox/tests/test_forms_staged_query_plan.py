"""Invented identifiers and actual disposable SQLite SQL execution, no Oracle claim."""
from copy import deepcopy
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_staged_query_plan import (build_staged_query_plan,
                                         execute_staged_query_model,
                                         parse_staged_query)
from forms2apex import native_blueprint
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.xml_mapping import _blueprint
from test_forms_manifest_filter import prepare as filter_prepare


def prepare(docs):
    packet, chunks, trace, files = filter_prepare(docs)
    plan = build_native_prototype_plan(docs, _blueprint(packet), project_id='filters',
        project_name='Source filter', approved_policy_id=POLICY_ID)
    files['fox-package/supporting-schema.sql'] = native_blueprint.render_prototype_schema(plan['rendering_spec']).encode()
    return packet, chunks, trace, files


def source(*, renamed=False, body=None, filter_=None, unknown=True):
    columns = ['KEY_CODE', 'CATEGORY', 'DEPOT'] + [f'FIELD_{i:02}' for i in range(4, 18)]
    selected = ['SOURCE_ID'] + columns[1:]
    body = body or (f'IF :KEY_CODE IS NOT NULL THEN DELETE STAGE_ROWS WHERE KEY_CODE=:KEY_CODE; '
                    f'INSERT INTO STAGE_ROWS({",".join(columns)}) '
                    f'SELECT {",".join(selected)} FROM SOURCE_ROWS WHERE SOURCE_ID=:LOADS.KEY_CODE; '
                    'EXECUTE_QUERY; ELSE NULL; END IF;')
    root = ET.Element('FormModule', Name='DISPATCH_STAGE')
    block = ET.SubElement(root, 'Block', Name='LOADS', DatabaseBlock='true',
                          QueryDataSourceType='Table', QueryDataSourceName='STAGE_ROWS',
                          WhereClause=filter_ or "CATEGORY='R' AND DEPOT=:GLOBAL.HOME_SITE",
                          OrderByClause='KEY_CODE desc')
    for index, column in enumerate(columns[:13] if unknown else columns):
        ET.SubElement(block, 'Item', Name=column, ColumnName=column,
                      DataType='Number' if index == 3 else 'Date' if index == 4 else 'Char',
                      DatabaseItem='true', ItemType='Text Item', MaximumLength='80',
                      DataLengthSemantics='BYTE')
    ET.SubElement(block, 'Trigger', Name='KEY-EXEQRY', TriggerText=body)
    raw = ET.tostring(root)
    if renamed:
        for old, new in ((b'DISPATCH_STAGE', b'SHIPPING'), (b'LOADS', b'JOURNEYS'),
                         (b'STAGE_ROWS', b'WORK_COPY'), (b'SOURCE_ROWS', b'ORIGINAL_DATA'),
                         (b'KEY_CODE', b'RECORD_NO'), (b'SOURCE_ID', b'ORIGINAL_NO'),
                         (b'CATEGORY', b'TYPE_CODE'), (b'DEPOT', b'OFFICE'),
                         (b'HOME_SITE', b'START_SITE')):
            raw = raw.replace(old, new)
    return [('renamed.xml' if renamed else 'staged.xml', raw)]


def compile_source(docs=None):
    docs = docs or source()
    args = prepare(docs)
    return build_staged_query_plan(docs, *args), args


def operation():
    plan, _ = compile_source()
    assert not plan['gaps']
    return plan['operations'][0]


def database(op=None, path=':memory:'):
    op = op or operation()
    db = sqlite3.connect(path)
    for table, names in ((op['staging_table'], [f['staging_column'] for f in op['projection']]),
                         (op['source_table'], [f['source_column'] for f in op['projection']])):
        db.execute('CREATE TABLE ' + table + ' (' + ','.join(c + ' text' for c in names) + ')')
    def row(key, value, kind='R', depot='EAST'):
        return (key, kind, depot, value, '2026-01-02') + ('retained',) * 12
    binds = ','.join('?' for _ in op['projection'])
    db.executemany('INSERT INTO ' + op['staging_table'] + ' VALUES (' + binds + ')',
                   [row('A', 'old'), row('B', 'sibling'), row('H', 'hidden', 'X'),
                    row('W', 'west', depot='WEST')])
    db.executemany('INSERT INTO ' + op['source_table'] + ' VALUES (' + binds + ')',
                   [row('A', 'new'), row('A', 'new'), row('A', 'different'), row('B', 'source-b')])
    db.commit()
    return db


def rows(db, op):
    return db.execute('SELECT * FROM ' + op['staging_table'] + ' ORDER BY 1,4').fetchall()


def test_compiler_reusable_exact_order_and_unmapped_projection_metadata():
    docs = source()
    args = prepare(docs)
    before = deepcopy((docs, args))
    plan = build_staged_query_plan(docs, *args)
    assert (docs, args) == before
    assert plan == build_staged_query_plan(docs, *args)
    assert not plan['gaps'] and len(plan['operations']) == 1
    op = plan['operations'][0]
    assert len(op['projection']) == 17
    assert [f['staging_column'] for f in op['projection']][:3] == ['KEY_CODE', 'CATEGORY', 'DEPOT']
    assert op['projection'][0]['source_column'] == 'SOURCE_ID'
    assert all(f['data_type'] is None and f['column'] is None for f in op['projection'][13:])
    assert op['key_binding']['source_reference'] == ['LOADS', 'KEY_CODE']
    assert op['source_key_column'] == 'SOURCE_ID' and op['staging_key_column'] == 'KEY_CODE'
    assert op['key_binding']['max_length'] == 80
    assert [t['value']['kind'] for t in op['filter_terms']] == ['string', 'global']
    assert op['source_no_commit'] and op['transaction_owner'] == 'caller'
    assert not plan['runtime_verified'] and not plan['business_accepted']
    assert len(op['semantic_gaps']) == 4
    renamed, _ = compile_source(source(renamed=True))
    other = renamed['operations'][0]
    assert other['source_table'] == 'ORIGINAL_DATA' and other['staging_table'] == 'WORK_COPY'
    assert other['key_binding']['source_reference'] == ['JOURNEYS', 'RECORD_NO']
    assert other['operation_id'] != op['operation_id']


@pytest.mark.parametrize('key', [None, ''])
def test_null_key_is_noop_even_when_database_and_globals_unavailable(key):
    result = execute_staged_query_model(operation(), None, key)
    assert result['status'] == 'null_noop' and not result['completed_stages']
    assert not result['committed'] and not result['rolled_back']


def test_actual_emitted_sql_replaces_key_preserves_duplicates_other_keys_and_filter():
    op = operation()
    db = database(op)
    before = rows(db, op)
    result = execute_staged_query_model(op, db, 'A', {'HOME_SITE': 'EAST'})
    after = rows(db, op)
    assert result['completed_stages'] == ['delete', 'insert', 'query']
    assert result['affected_rows'] == {'delete': 1, 'insert': 3}
    assert [r for r in after if r[0] != 'A'] == [r for r in before if r[0] != 'A']
    assert len([r for r in after if r[0] == 'A' and r[3] == 'new']) == 2
    assert {r[0] for r in result['rows']} == {'A', 'B'}
    assert all(r[13:] == ('retained',) * 4 for r in result['rows'])
    repeated = execute_staged_query_model(op, db, 'A', {'HOME_SITE': 'EAST'})
    assert repeated['rows'] == result['rows'] and rows(db, op) == after
    db.rollback()
    assert rows(db, op) == before


def test_empty_source_removes_only_requested_stage_key_and_still_queries_whole_block():
    op = operation()
    db = database(op)
    db.execute('DELETE FROM ' + op['source_table'] + ' WHERE SOURCE_ID=?', ('A',))
    db.commit()
    before = rows(db, op)
    result = execute_staged_query_model(op, db, 'A', {'HOME_SITE': 'EAST'})
    assert result['affected_rows'] == {'delete': 1, 'insert': 0}
    assert {r[0] for r in result['rows']} == {'B'}
    assert rows(db, op) == [r for r in before if r[0] != 'A']


def test_injected_key_is_bound_and_cannot_change_other_keys():
    op = operation()
    db = database(op)
    before = rows(db, op)
    execute_staged_query_model(op, db, "A' OR 1=1 --", {'HOME_SITE': 'EAST'})
    assert rows(db, op) == before


@pytest.mark.parametrize('globals_', [None, {}])
def test_missing_trusted_global_fails_before_writes(globals_):
    op = operation()
    db = database(op)
    before = rows(db, op)
    with pytest.raises(ValueError, match='TRUSTED_GLOBAL_REQUIRED'):
        execute_staged_query_model(op, db, 'A', globals_)
    assert rows(db, op) == before and not db.in_transaction


def test_known_null_global_preserves_source_dml_then_returns_no_visible_rows():
    op = operation()
    db = database(op)
    result = execute_staged_query_model(op, db, 'A', {'HOME_SITE': None})
    assert result['affected_rows'] == {'delete': 1, 'insert': 3}
    assert result['rows'] == [] and db.in_transaction


def test_each_statement_receives_exact_declared_binds():
    op = operation()
    db = database(op)
    class StrictCursor:
        def __init__(self):
            self.cursor = db.cursor()
        def execute(self, sql, binds):
            assert set(re.findall(r':([A-Z_0-9]+)', sql)) == set(binds)
            self.cursor.execute(sql, binds)
        @property
        def rowcount(self):
            return self.cursor.rowcount
        def fetchall(self):
            return self.cursor.fetchall()
        def close(self):
            self.cursor.close()
    class StrictConnection:
        def cursor(self):
            return StrictCursor()
    result = execute_staged_query_model(op, StrictConnection(), 'A', {'HOME_SITE': 'EAST'})
    assert result['completed_stages'] == ['delete', 'insert', 'query']


@pytest.mark.parametrize('stage', ['delete', 'insert', 'query'])
def test_real_database_failure_at_each_stage_leaves_caller_in_control(stage):
    op = operation()
    db = database(op)
    before = rows(db, op)
    if stage == 'delete':
        db.execute('DROP TABLE ' + op['staging_table'])
        db.commit()
    elif stage == 'insert':
        db.execute('DROP TABLE ' + op['source_table'])
        db.commit()
    else:
        # Deny only the last stage's read. DELETE's earlier key read and the
        # actual original SELECT remain allowed, so both preceding DML run.
        state = {'insert': False}
        def authorize(action, name, column, schema, trigger):
            if action == sqlite3.SQLITE_INSERT and name == op['staging_table']:
                state['insert'] = True
            if action == sqlite3.SQLITE_READ and name == op['staging_table'] and state['insert']:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        db.set_authorizer(authorize)
    with pytest.raises(sqlite3.DatabaseError):
        execute_staged_query_model(op, db, 'A', {'HOME_SITE': 'EAST'})
    db.set_authorizer(None)
    if stage != 'delete':
        pending = [r for r in rows(db, op) if r[0] == 'A']
        assert len(pending) == (0 if stage == 'insert' else 3)
        assert db.in_transaction
        db.rollback()
        assert rows(db, op) == before


def test_transaction_visibility_and_commit_belong_to_caller(tmp_path):
    op = operation()
    path = str(tmp_path / 'transaction.db')
    db = database(op, path)
    observer = sqlite3.connect(path)
    before = rows(observer, op)
    result = execute_staged_query_model(op, db, 'A', {'HOME_SITE': 'EAST'})
    assert db.in_transaction and not result['committed']
    assert rows(observer, op) == before and rows(db, op) != before
    db.commit()
    assert rows(observer, op) == rows(db, op)
    observer.close()
    db.close()


@pytest.mark.parametrize('change', [
    lambda b: b + ' COMMIT;',
    lambda b: b.replace('ELSE NULL;', ''),
    lambda b: b.replace('SOURCE_ROWS', 'STAGE_ROWS'),
    lambda b: b.replace('WHERE SOURCE_ID=', 'WHERE OTHER_ID='),
    lambda b: b.replace('SELECT SOURCE_ID', 'SELECT DISTINCT SOURCE_ID'),
    lambda b: b.replace('EXECUTE_QUERY;', 'ROLLBACK; EXECUTE_QUERY;'),
    lambda b: b.replace('KEY_CODE,CATEGORY', 'KEY_CODE,KEY_CODE'),
    lambda b: b.replace('SELECT SOURCE_ID', 'SELECT UNKNOWN_FN(SOURCE_ID)'),
])
def test_unsupported_or_partial_whole_source_is_rejected(change):
    body = ET.fromstring(source()[0][1]).find('.//Trigger').get('TriggerText')
    bad = change(body)
    with pytest.raises(ValueError):
        parse_staged_query(bad)
    plan, _ = compile_source(source(body=bad))
    assert not plan['operations'] and len(plan['gaps']) == 1


@pytest.mark.parametrize('change', ['wrong_key', 'cross_scope', 'wrong_table',
    'duplicate_key', 'unmapped_filter', 'invalid_filter', 'filter_type', 'no_filter',
    'wrong_item_trigger', 'duplicate_trigger', 'unproved_length', 'computed_key'])
def test_identity_scope_metadata_and_filter_gates(change):
    docs = source()
    root = ET.fromstring(docs[0][1])
    block = root.find('Block')
    trigger = block.find('Trigger')
    if change == 'wrong_key':
        trigger.set('TriggerText', trigger.get('TriggerText').replace('WHERE KEY_CODE=:KEY_CODE', 'WHERE KEY_CODE=:CATEGORY'))
    elif change == 'cross_scope':
        trigger.set('TriggerText', trigger.get('TriggerText').replace(':LOADS.KEY_CODE', ':OTHER.KEY_CODE'))
    elif change == 'wrong_table':
        block.set('QueryDataSourceName', 'OTHER_STAGE')
    elif change == 'duplicate_key':
        block.append(deepcopy(block.find('Item')))
    elif change == 'unmapped_filter':
        block.set('WhereClause', "MISSING='R' AND DEPOT=:GLOBAL.HOME_SITE")
    elif change == 'invalid_filter':
        block.set('WhereClause', "CATEGORY='R' OR DEPOT=:GLOBAL.HOME_SITE")
    elif change == 'filter_type':
        block.set('WhereClause', "FIELD_04='R' AND DEPOT=:GLOBAL.HOME_SITE")
    elif change == 'no_filter':
        del block.attrib['WhereClause']
    elif change == 'wrong_item_trigger':
        block.remove(trigger)
        block.findall('Item')[1].append(trigger)
    elif change == 'duplicate_trigger':
        block.append(deepcopy(trigger))
    elif change == 'unproved_length':
        del block.find('Item').attrib['MaximumLength']
    elif change == 'computed_key':
        block.find('Item').set('Formula', 'CEIL(:FIELD_04)')
    if change == 'duplicate_key':
        with pytest.raises(ValueError, match='Duplicate source block or item identity'):
            compile_source([('bad.xml', ET.tostring(root))])
    else:
        plan, _ = compile_source([('bad.xml', ET.tostring(root))])
        assert not plan['operations'] and len(plan['gaps']) == (2 if change == 'duplicate_trigger' else 1)


@pytest.mark.parametrize('boundary', ['packet', 'chunks', 'trace', 'original', 'target'])
def test_changed_evidence_cannot_compile(boundary):
    docs = source()
    args = list(prepare(docs))
    if boundary == 'packet':
        args[0]['source_binding'] = 'changed'
    elif boundary == 'chunks':
        args[1][0]['text'] += 'COMMIT;'
    elif boundary == 'trace':
        args[2]['source_binding'] = 'changed'
    elif boundary == 'original':
        args[3]['fox-package/sources/staged.xml'] += b' '
    else:
        args[2]['blocks'][0]['source_module_id'] = 'other'
    if boundary == 'target':
        plan = build_staged_query_plan(docs, *args)
        assert not plan['operations'] and len(plan['gaps']) == 1
    else:
        with pytest.raises(ValueError):
            build_staged_query_plan(docs, *args)


def test_wrapped_qualified_and_export_control_entity_source():
    body = ET.fromstring(source()[0][1]).find('.//Trigger').get('TriggerText')
    body = 'BEGIN ' + body.replace('DELETE STAGE_ROWS', 'DELETE FROM STAGE_ROWS') + ' END;'
    body = body.replace('THEN ', 'THEN &#10;\\t')
    plan, _ = compile_source(source(body=body))
    assert len(plan['operations']) == 1 and not plan['gaps']
    assert plan['operations'][0]['decode_receipt']['substitutions']
    assert plan['operations'][0]['decode_receipt']['literal_export_tab_offsets']


def test_same_identifier_names_in_other_module_do_not_supply_key_or_projection():
    docs = source() + [('second.xml', source(renamed=True)[0][1])]
    plan, _ = compile_source(docs)
    assert len(plan['operations']) == 2 and not plan['gaps']
    assert len({op['source_module_id'] for op in plan['operations']}) == 2


def test_item_owned_trigger_binds_its_own_key_and_preserves_block_owned_scope():
    root = ET.fromstring(source()[0][1])
    block = root.find('Block')
    trigger = block.find('Trigger')
    block.remove(trigger)
    block.find('Item').append(trigger)
    plan, _ = compile_source([('item-owned.xml', ET.tostring(root))])
    op = plan['operations'][0]
    assert op['trigger_parent_kind'] == 'Item'
    assert op['trigger_parent_id'] == op['key_binding']['source_item_id']
    block.append(deepcopy(trigger))
    two, _ = compile_source([('separate-scope.xml', ET.tostring(root))])
    assert len(two['operations']) == 2 and not two['gaps']


def test_packet_generation_annotations_are_not_authoritative_source_changes():
    docs = source()
    args = prepare(docs)
    args[0]['generation_only_annotation'] = {'ignored': True}
    assert len(build_staged_query_plan(docs, *args)['operations']) == 1


@pytest.mark.parametrize('change', ['missing_schema', 'changed_type', 'changed_column'])
def test_native_schema_must_match_exact_trace(change):
    docs = source()
    args = prepare(docs)
    if change == 'missing_schema':
        del args[3]['fox-package/supporting-schema.sql']
    elif change == 'changed_type':
        args[3]['fox-package/supporting-schema.sql'] = args[3]['fox-package/supporting-schema.sql'].replace(b'VARCHAR2(80)', b'VARCHAR2(79)', 1)
    else:
        args[2]['blocks'][0]['items'][0]['column'] = args[2]['blocks'][0]['items'][1]['column']
    plan = build_staged_query_plan(docs, *args)
    assert not plan['operations'] and len(plan['gaps']) == 1


def test_datetime_forms_declaration_retained_without_claiming_physical_sql_type():
    root = ET.fromstring(source()[0][1])
    field = root.find('Block').findall('Item')[4]
    field.set('DataType', 'Datetime')
    field.set('ItemType', 'Display Item')
    field.set('FormatMask', 'DD-MM-YYYY HH24:MI')
    plan, _ = compile_source([('datetime.xml', ET.tostring(root))])
    assert not plan['gaps']
    op = plan['operations'][0]
    projection = op['projection'][4]
    assert projection['source_column'] == 'FIELD_05'
    assert projection['data_type'] is None and projection['column'] is None
    declaration = projection['form_declaration']
    assert declaration['source_item_id'] == projection['source_item_id']
    assert declaration['data_type'] == 'Datetime'
    assert declaration['synthetic_data_type'] == 'VARCHAR2'
    assert declaration['format_mask'] == 'DD-MM-YYYY HH24:MI'
    assert not declaration['physical_sql_type_verified']
    gap = next(g for g in op['semantic_gaps'] if g['reason'] == 'forms_field_display_type_not_supported_by_native_projection')
    assert gap['fields'][0]['source_item_id'] == projection['source_item_id']
    assert 'FIELD_05' in op['source_select_sql']
