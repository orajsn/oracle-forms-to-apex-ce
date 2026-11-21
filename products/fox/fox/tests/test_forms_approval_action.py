"""Execute emitted read-only SQL locally; this is not Oracle/APEX proof."""
from copy import deepcopy
import hashlib
import json
import re
import sqlite3

import pytest

from fox.forms_approval_action import _queries, _permission, apply_approval_actions


def contract():
    roles = {'header_key': ('REF', 'VARCHAR2'), 'destination': ('CITY', 'VARCHAR2'),
             'bag_header_key': ('PARENT_REF', 'VARCHAR2'), 'bag_number': ('CODE', 'VARCHAR2'),
             'weight': ('ACTUAL', 'NUMBER'), 'consignment_header_key': ('HEAD_REF', 'VARCHAR2'),
             'consignment_bag_number': ('BAG_REF', 'VARCHAR2')}
    return {'blocks': {role: {'table_name': table} for role, table in
                          (('header', 'HEADERS'), ('bag', 'BAGS'), ('consignment', 'NOTES'))},
            'fields': {role: {'column': column, 'source_name': column, 'data_type': dtype}
                       for role, (column, dtype) in roles.items()},
            'permission_sql': "CASE WHEN APPROVED='Y' THEN 0 ELSE 1 END",
            'messages': {'weight': ['Save actual weight', 'Save actual weight'],
                         'destination': ['Destination required', 'Destination required'],
                         'no_bags': ['Bags required', 'Bags required'],
                         'missing_consignment': ['Add note for bag ', 'Add note for bag ']}}


class Boundary:
    """Use generated SQL with explicit Oracle-to-SQLite ROWNUM adaptation.

    No locks, Oracle exception handling, APEX sessions or customer DML are
    modelled. These tests establish the query boundary and absence of writes.
    """
    def __init__(self, *, destination='TOWN', approved=None):
        self.db = sqlite3.connect(':memory:')
        self.db.create_function('nvl', 2, lambda v, fallback: fallback if v is None else v)
        self.db.create_function('chr', 1, chr)
        self.db.executescript('CREATE TABLE HEADERS(FOX_ROW_ID INTEGER PRIMARY KEY,REF TEXT,CITY TEXT,APPROVED TEXT);'
                              'CREATE TABLE BAGS(FOX_ROW_ID INTEGER PRIMARY KEY,PARENT_REF TEXT,CODE TEXT,ACTUAL NUMBER);'
                              'CREATE TABLE NOTES(FOX_ROW_ID INTEGER PRIMARY KEY,HEAD_REF TEXT,BAG_REF TEXT);')
        self.db.execute('insert into HEADERS values (1,?,?,?)', ('H1', destination, approved))
        self.db.execute("insert into HEADERS values (2,'H2','OTHER',null)")
        self.c = contract()
        self.queries = _queries(self.c, 8600, "p.FOX_ROW_ID=:P8600_PARENT_ID and :P8600_TOKEN='valid'")
        self.sql = self.queries['readiness_query_sql'].replace(' and rownum=1)', ' limit 1)')

    def rows(self, parent=1, token='valid'):
        before = list(self.db.iterdump())
        cursor = self.db.execute(self.sql, {'P8600_PARENT_ID': parent, 'P8600_TOKEN': token})
        rows = [dict(zip([c[0] for c in cursor.description], row)) for row in cursor]
        assert list(self.db.iterdump()) == before
        return rows

    def bag(self, code='B1', weight=1, parent='H1'):
        self.db.execute('insert into BAGS(PARENT_REF,CODE,ACTUAL) values (?,?,?)', (parent, code, weight))

    def note(self, code='B1', parent='H1'):
        self.db.execute('insert into NOTES(HEAD_REF,BAG_REF) values (?,?)', (parent, code))


@pytest.mark.parametrize('weight', [None, 0])
def test_weight_guard_precedes_destination_and_retains_exact_message_order(weight):
    b = Boundary(destination=None)
    b.bag(weight=weight)
    row, = b.rows()
    assert row['READINESS_STAGE'] == 'BLOCKED_WEIGHT'
    assert row['SOURCE_MESSAGES'] == 'Save actual weight\nSave actual weight'
    assert row['BLOCKING_BAG'] == 'B1' and row['BLOCKING_FIELD'] == 'ACTUAL'
    assert 'indicated weight field' in row['REQUIRED_ACTION']


def test_destination_is_second_guard_and_never_crosses_missing_commit():
    b = Boundary(destination=None)
    b.bag(weight=2)
    row, = b.rows()
    assert row['READINESS_STAGE'] == 'BLOCKED_DESTINATION'
    assert row['SOURCE_MESSAGES'] == 'Destination required\nDestination required'
    assert row['BLOCKING_FIELD'] == 'CITY'


def test_no_bags_is_explicit_post_commit_saved_state_diagnostic():
    row, = Boundary().rows()
    assert row['READINESS_STAGE'] == 'SAVED_CHECK_NO_BAGS'
    assert row['SOURCE_MESSAGES'] == 'Bags required\nBags required'
    assert 'unexecuted source commit' in row['REQUIRED_ACTION']


def test_bag_without_consignment_uses_both_source_keys_and_not_exists():
    b = Boundary()
    b.bag()
    b.note(parent='H2')
    row, = b.rows()
    assert row['READINESS_STAGE'] == 'SAVED_CHECK_EMPTY_BAG'
    assert row['SOURCE_MESSAGES'] == 'Add note for bag B1\nAdd note for bag B1'
    assert row['BLOCKING_BAG'] == 'B1'
    b.note()
    row, = b.rows()
    assert row['READINESS_STAGE'] == 'PENDING_TRANSACTION_AND_INTERFACES'


def test_complete_internal_data_remains_pending_external_and_transaction_steps():
    b = Boundary()
    b.bag()
    b.note()
    b.bag(parent='H2', code='OTHER', weight=0)
    row, = b.rows()
    assert row['READINESS_STAGE'] == 'PENDING_TRANSACTION_AND_INTERFACES'
    assert row['SOURCE_MESSAGES'] is None
    assert 'approval write' in row['REQUIRED_ACTION'] and 'external interfaces' in row['REQUIRED_ACTION']
    assert 'No approval was written' in row['TRANSACTION_STATUS']
    assert b.db.execute('select APPROVED from HEADERS where FOX_ROW_ID=1').fetchone() == (None,)


def test_parent_identity_token_key_and_current_policy_are_rechecked():
    b = Boundary()
    b.bag()
    assert b.rows(parent=99) == [] and b.rows(token='stale') == []
    b.db.execute("insert into HEADERS values (3,'H1','TOWN',null)")
    assert b.rows() == []
    b.db.execute('delete from HEADERS where FOX_ROW_ID=3')
    b.db.execute("update HEADERS set APPROVED='Y' where FOX_ROW_ID=1")
    row, = b.rows()
    assert row['READINESS_STAGE'] == 'POLICY_READ_ONLY' and row['SOURCE_MESSAGES'] is None
    b.db.execute('update HEADERS set REF=null where FOX_ROW_ID=1')
    assert b.rows() == []


def test_sql_keeps_arbitrary_rownum_selection_and_has_no_effectful_code():
    queries = _queries(contract(), 8600, 'p.FOX_ROW_ID=:P8600_PARENT_ID')
    query = queries['readiness_query_sql']
    assert query.count('and rownum=1') == 2
    assert 'not exists' in queries['missing_consignment_predicate_sql']
    assert 'n.HEAD_REF=b.PARENT_REF' in queries['missing_consignment_predicate_sql']
    active = re.sub(r"'(?:''|[^'])*'", ' ', query)
    assert not re.search(r'\b(insert|update|delete|commit|rollback|apex_collection|webhook)\b', active, re.I)


def test_missing_or_unknown_button_policy_is_fail_closed():
    button = {'id': 'button', 'module_id': 'module'}
    header = {'source_block_id': 'header', 'items': []}
    with pytest.raises(ValueError, match='EXPLICIT_BUTTON_PERMISSION'):
        _permission(header, button, {}, {'button': {}}, {'operations': []})
    assert _permission(header, button, {}, {'button': {'Enabled': 'false'}}, {'operations': []}) == ('0', [])


@pytest.mark.parametrize('renamed', [False, True])
def test_complete_source_plan_wires_readiness_keeps_source_and_conversion_partial(renamed):
    from test_forms_approval_plan import source, prepare
    args = prepare(source(renamed=renamed))
    before = deepcopy(args)
    output, receipt = apply_approval_actions(*args)
    assert args == before
    assert (output, receipt) == apply_approval_actions(*args)
    op, = receipt['adapted_operations']
    assert op['entry_kind'] == 'protected_header_report_chooser'
    assert receipt['converted_code_unit_count'] == 0 and not receipt['generated_operations']
    assert op['whole_source_unit_converted'] is False and op['source_event_partially_connected']
    assert op['source_transaction_stages']
    assert all(not receipt[k] for k in ('customer_table_writes', 'synthetic_table_writes',
        'original_reads_enabled', 'external_calls_enabled', 'forms_commit_implemented',
        'oracle_compiled', 'runtime_verified', 'business_accepted'))
    assert not op['approval_flag_written'] and not op['session_drafts_mutated']
    for name, raw in args[0]:
        assert output['fox-package/sources/' + name] == raw
    for name in args[-1]:
        if name != op['entry_file']:
            assert output[name] == args[-1][name]
    page = output[op['page_file']].decode()
    assert 'type: interactiveReport' in page
    assert 'pageAccessProtection: argumentsMustHaveChecksum' in page
    assert page.count('sessionStateProtection: checksumRequiredSessionLevel') == 2
    assert 'escapeSpecialChars: true' in page
    assert 'type: executeCode' not in page and 'type: formAutomaticRowProcessing' not in page
    review = json.loads(output['fox-package/approval-plan.json'])
    assert review['operations'][0]['source_unit_id'] == op['source_unit_id']
    assert review['operations'][0]['parsed']['external_calls']


def test_source_target_or_original_bytes_mismatch_cannot_render_readiness():
    from test_forms_approval_plan import prepare
    args = prepare()
    mutated = deepcopy(args)
    mutated[3]['blocks'][0]['table_name'] = 'CUSTOMER_TABLE'
    with pytest.raises(ValueError):
        apply_approval_actions(*mutated)
    mutated = deepcopy(args)
    name = mutated[0][0][0]
    mutated[-1]['fox-package/sources/' + name] += b'\n'
    with pytest.raises(ValueError):
        apply_approval_actions(*mutated)


def test_missing_query_provider_preserves_source_and_exposes_exact_gap():
    from test_forms_approval_plan import source, prepare
    args = prepare(source(missing_provider=True))
    output, receipt = apply_approval_actions(*args)
    assert not receipt['adapted_operations'] and not receipt['generated_operations']
    assert receipt['converted_code_unit_count'] == 0 and receipt['gaps']
    assert not any(re.fullmatch(r'pages/p\d+-fox_approval_\d+\.apx', p) for p in output)
    assert all(output[name] == raw for name, raw in args[-1].items())


@pytest.mark.parametrize('renamed', [False, True])
def test_exact_source_bound_generated_query_runs_with_real_mapped_columns(renamed):
    from test_forms_approval_plan import source, prepare
    from fox.forms_master_detail import _fingerprint
    args = prepare(source(renamed=renamed))
    output, receipt = apply_approval_actions(*args)
    op, = receipt['adapted_operations']
    c, page = op['contract'], op['page_id']
    db = sqlite3.connect(':memory:')
    db.create_function('nvl', 2, lambda v, fallback: fallback if v is None else v)
    db.create_function('chr', 1, chr)
    db.create_function('standard_hash', 2, lambda v, algorithm: None if v is None else hashlib.sha256(str(v).encode()).digest())
    db.create_function('rawtohex', 1, lambda v: None if v is None else v.hex().upper())
    for block in c['blocks'].values():
        db.execute('create table ' + block['table_name'] + ' (FOX_ROW_ID INTEGER PRIMARY KEY,'
            + ','.join(f['column'] + ' ' + ('NUMERIC' if f['data_type'] == 'NUMBER' else 'TEXT')
                       for f in block['items']) + ')')
    f = c['fields']

    def insert(role, identity, values):
        columns = ['FOX_ROW_ID'] + [f[key]['column'] for key in values]
        db.execute('insert into ' + c['blocks'][role]['table_name'] + '(' + ','.join(columns)
            + ') values (' + ','.join('?' for _ in columns) + ')', [identity] + list(values.values()))

    insert('header', 1, {'header_key': 'H1', 'destination': 'CITY'})
    insert('bag', 1, {'bag_header_key': 'H1', 'bag_number': 'B1', 'weight': None})
    token = db.execute('select ' + _fingerprint(c['blocks']['header']['items'])
                       + ' from ' + c['blocks']['header']['table_name'] + ' p').fetchone()[0]
    sql = op['readiness_query_sql'].replace(' and rownum=1)', ' limit 1)')

    def current():
        before = list(db.iterdump())
        cursor = db.execute(sql, {f'P{page}_PARENT_ID': 1, f'P{page}_TOKEN': token})
        row = dict(zip([d[0] for d in cursor.description], cursor.fetchone()))
        assert list(db.iterdump()) == before
        return row

    row = current()
    assert row['READINESS_STAGE'] == 'BLOCKED_WEIGHT' and row['BLOCKING_BAG'] == 'B1'
    assert row['BLOCKING_FIELD'] == f['weight']['source_name']
    db.execute('update ' + c['blocks']['bag']['table_name'] + ' set ' + f['weight']['column'] + '=1')
    assert current()['READINESS_STAGE'] == 'SAVED_CHECK_EMPTY_BAG'
    insert('consignment', 1, {'consignment_header_key': 'H1', 'consignment_bag_number': 'B1'})
    assert current()['READINESS_STAGE'] == 'PENDING_TRANSACTION_AND_INTERFACES'


def test_selected_coordinator_links_current_protected_identity_without_reselection():
    from xml.etree import ElementTree as ET
    from test_forms_approval_plan import source, prepare
    from test_forms_master_detail import trigger, QUERY_HELPER, CHECK_HELPER
    from fox.forms_master_detail import apply_master_details
    from fox.forms_relation_plan import parse_join_condition
    docs = source()
    root = ET.fromstring(docs[0][1])
    header = next(n for n in root.iter('Block') if n.find('Relation') is not None)
    relation = header.find('Relation')
    parent_key = parse_join_condition(relation.get('JoinCondition'), header.get('Name'),
                                      relation.get('DetailBlock'))[0][0]
    ET.SubElement(header, 'Trigger', Name='ON-POPULATE-DETAILS', TriggerText=trigger(
        header.get('Name'), relation.get('Name'), relation.get('DetailBlock'),
        ':' + header.get('Name') + '.' + parent_key + ' IS NOT NULL'))
    for name, text in (('FILL_CHILD_ROWS', QUERY_HELPER), ('ASSERT_OK', CHECK_HELPER)):
        ET.SubElement(root, 'ProgramUnit', Name=name, ProgramUnitType='Procedure', ProgramUnitText=text)
    ET.SubElement(root, 'Trigger', Name='ON-CLEAR-DETAILS', TriggerText='CLEAR_OTHER_BUFFERS;')
    args = prepare([(docs[0][0], ET.tostring(root))])
    coordinated, population = apply_master_details(*args)
    coordinated['fox-package/master-detail-receipt.json'] = json.dumps(population).encode()
    output, receipt = apply_approval_actions(*args[:-1], coordinated)
    op, = receipt['adapted_operations']
    selected, = population['adapted_operations']
    assert op['entry_kind'] == 'current_coordinated_manifest_no_reselection'
    assert op['entry_file'] == selected['page_file']
    text = output[op['entry_file']].decode()
    assert f'P{op["page_id"]}_PARENT_ID: "&P{selected["page_id"]}_PARENT_ID."' in text
    assert f'P{op["page_id"]}_TOKEN: "&P{selected["page_id"]}_TOKEN."' in text
    assert 'type: rowsReturned' in text
    assert f":P{selected['page_id']}_STATE='COORDINATED'" in text
    assert len([p for p in output if re.fullmatch(r'pages/p\d+-fox_approval_\d+\.apx', p)]) == 1
    assert output[op['entry_file']].startswith(coordinated[op['entry_file']][:-2])
