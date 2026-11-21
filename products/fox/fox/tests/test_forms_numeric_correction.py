"""Real disposable SQL boundaries; PL/SQL/session orchestration is modelled.

These checks do not establish Oracle locks, APEX execution or acceptance.
All names in committed fixtures are invented.
"""
from copy import deepcopy
from decimal import Decimal
import hashlib
import json
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_numeric_correction import (build_numeric_correction_plan,
    render_numeric_correction_sql, numeric_rules, validate_numeric_value)
from fox.forms_master_detail import _fingerprint


def source(*, renamed=False):
    """Complete sanitized correction fixture, usable by normal generation."""
    from test_forms_approval_plan import source as approval_source
    from test_forms_item_validation import BODY
    root = ET.fromstring(approval_source()[0][1])
    parent, child = list(root.iter('Block'))[:2]
    actual = next(i for i in child.findall('Item') if i.get('Name') == 'ACTUAL_WEIGHT')
    actual.set('FormatMask', '9,999,990')
    actual.set('LowestAllowedValue', '1')
    actual.set('UpdateAllowed', 'true')
    ET.SubElement(actual, 'Trigger', Name='KEY-NEXT-ITEM', TriggerText=(
        "BEGIN IF NVL(:ACTUAL_WEIGHT,0)=0 THEN MESSAGE('Actual weight required'); "
        "MESSAGE('Actual weight required'); RAISE FORM_TRIGGER_FAILURE; END IF; GO_ITEM('PIECE_CODE'); END;"))
    for event in ('KEY-ENTQRY', 'KEY-EXEQRY'):
        ET.SubElement(actual, 'Trigger', Name=event, TriggerText='BEGIN NULL; END;')
    ET.SubElement(child, 'Item', Name='COST_WEIGHT', ColumnName='COST_WEIGHT',
                  ItemType='Display Item', DatabaseItem='true', DataType='Number', MaximumLength='8')
    ET.SubElement(child, 'Item', Name='STEP_MARKER', ItemType='Text Item', DatabaseItem='false',
                  DataType='Char', MaximumLength='30', DataLengthSemantics='BYTE')
    code = next(i for i in child.findall('Item') if i.get('Name') == 'PIECE_CODE')
    ET.SubElement(code, 'Trigger', Name='WHEN-VALIDATE-ITEM', TriggerText=BODY)
    # Its unrelated focus event must not revoke the actual-weight field.
    ET.SubElement(code, 'Trigger', Name='WHEN-NEW-ITEM-INSTANCE', TriggerText='NULL;')
    raw = ET.tostring(root)
    if renamed:
        for old, new in ((b'LOADS', b'JOURNEYS'), (b'PIECES', b'CRATES'),
                         (b'LOAD_REFERENCE', b'JOURNEY_REF'), (b'PIECE_CODE', b'CRATE_CODE'),
                         (b'ACTUAL_WEIGHT', b'OBSERVED_MASS'), (b'COST_WEIGHT', b'CHARGE_MASS'),
                         (b'CONSIGNMENTS', b'RECEIPTS'), (b'NOTE_LOAD', b'NOTE_JOURNEY'),
                         (b'NOTE_PIECE', b'NOTE_CRATE'), (b'TARGET_CITY', b'END_CITY'),
                         (b'STORED_ROUTE', b'ACTIVE_PATH'), (b'PLANNED_ROUTE', b'PARENT_PATH'),
                         (b'APPROVED', b'RELEASED'), (b'AUTHORIZE', b'RELEASE'),
                         (b'POLICY', b'CHECK_RELEASE'), (b'STEP_MARKER', b'FOCUS_MARKER')):
            raw = raw.replace(old, new)
    return [('renamed-correction.xml' if renamed else 'correction.xml', raw)]


def prepare(docs=None):
    from test_forms_synthetic_save import prepare as save_prepare
    from fox.forms_synthetic_save import apply_synthetic_saves
    from fox.forms_item_validation import apply_item_validations
    from fox.forms_approval_action import apply_approval_actions
    docs = docs or source()
    packet, chunks, trace, files = save_prepare(docs)
    for name, fn in (('synthetic-save-receipt', apply_synthetic_saves),
                     ('item-validation-receipt', apply_item_validations),
                     ('approval-action-receipt', apply_approval_actions)):
        files, receipt = fn(docs, packet, chunks, trace, files)
        files['fox-package/' + name + '.json'] = json.dumps(receipt).encode()
    return docs, packet, chunks, trace, files


def operation(renamed=False):
    args = prepare(source(renamed=renamed))
    plan = build_numeric_correction_plan(*args)
    assert not plan['gaps'], plan['gaps']
    op, = plan['operations']
    return op, args


@pytest.mark.parametrize('renamed', [False, True])
def test_complete_source_contract_and_nonnumeric_drafts_remain_distinct(renamed):
    op, args = operation(renamed)
    before = deepcopy(args)
    assert build_numeric_correction_plan(*args) == build_numeric_correction_plan(*args)
    assert args == before
    assert op['source_unit_id'] == op['numeric_source_unit_id'] != op['approval_source_unit_id']
    assert len(op['harmless_item_overrides']) == 2
    assert op['fields']['weight']['source_item_id'] != op['item_layout']['fields']['weight']['source_item_id']
    assert op['rules']['integer_digits'] == 7 and op['rules']['scale'] == 0
    assert not op['converted_code_unit_count']
    assert all(not op[k] for k in ('customer_table_writes', 'oracle_compiled', 'runtime_verified', 'business_accepted'))
    sql = render_numeric_correction_sql(op, 8801)
    assert len(sql['save_code'].encode()) <= 32767
    assert sql['save_code'].index('lock table ') < sql['save_code'].index('select c001') < sql['save_code'].index(sql['update_sql'])
    assert 'rollback to fox_numeric_save' in sql['save_code']
    assert not re.search(r'\bcommit\s*;', sql['save_code'], re.I)
    assert 'p_attr_number=>44' in sql['save_code'] and 'p_number_value=>l_count+1' in sql['save_code']
    # CTC is checked, never updated: only actual numeric field plus source route.
    assert op['item_layout']['fields']['weight']['column'] not in sql['update_sql']
    assert 'p_attr_number=>2,p_number_value' not in sql['save_code']
    assert 'l_marker<>:P8801_NONCE' in sql['save_code']
    assert "p_attr_value=>'USED'" in sql['save_code']
    assert 'truncate_collection' not in sql['open_code']
    assert 'l_name:=l_name||l_marker' in sql['open_code']
    assert 'l_name:=l_name||:P8801_NONCE' in sql['save_code']
    assert 'p_d001=>sysdate+30/1440' in sql['open_code'] and 'd001>sysdate' in sql['save_code']
    assert 'rownum<=l_count-63' in sql['open_code']
    assert "STATE:=case when l_error=-20062 then 'READY' else 'BLOCKED' end" in sql['save_code']
    assert sql['save_code'].count('for update nowait;') == 2
    assert 'l_parent is null or l_id is null or l_base is null' in sql['save_code']
    from forms2apex import native_buffer
    from fox.forms_numeric_correction import _sha
    assert _sha(op['buffer']) == native_buffer._sha(native_buffer._json(op['buffer']))


@pytest.mark.parametrize('value', ['', '0', '0.0', '-1', '+1', ' 1', '1 ', '1\n', '01', '1,000',
                                  '1e2', 'NaN', 'Infinity', '1.5', '10000000', '١', '1_000'])
def test_integer_picture_rejects_lossy_or_locale_ambiguous_inputs(value):
    with pytest.raises(ValueError):
        validate_numeric_value(value, numeric_rules({'FormatMask': '9,999,990', 'MaximumLength': '8', 'LowestAllowedValue': '1'}))


def test_decimal_picture_never_rounds_and_source_minimum_is_independent_of_zero_guard():
    r = numeric_rules({'FormatMask': '990.00', 'MaximumLength': '6', 'LowestAllowedValue': '0.01', 'HighestAllowedValue': '998.99'})
    assert validate_numeric_value('0.01', r) == Decimal('0.01')
    assert validate_numeric_value('998.99', r) == Decimal('998.99')
    for value in ('0', '0.001', '999', '999.00', '1.234', '.5', '1.', '000.01'):
        with pytest.raises(ValueError):
            validate_numeric_value(value, r)
    for picture in ('', '999G990D00', '9.99E9', 'FM990', '990MI'):
        with pytest.raises(ValueError):
            numeric_rules({'FormatMask': picture, 'MaximumLength': '8', 'LowestAllowedValue': '1'})


class Boundary:
    """Execute compiler SQL with documented SQLite dialect substitutions.

    Lock/PLSQL/nonce sequencing is modelled explicitly; Oracle concurrency and
    native collection transactions remain a separate target gate.
    """
    def __init__(self, renamed=False):
        self.op, self.args = operation(renamed)
        self.sql = render_numeric_correction_sql(self.op, 8801)
        self.db = sqlite3.connect(':memory:')
        self.db.create_function('nvl', 2, lambda a, b: b if a is None else a)
        self.db.create_function('decode', 4, lambda a, b, yes, no: yes if a == b else no)
        self.db.create_function('rawtohex', 1, lambda v: v.hex().upper() if v is not None else None)
        self.db.create_function('standard_hash', 2, lambda v, alg: hashlib.sha256(str(v).encode()).digest() if v is not None else None)
        self.db.create_function('fox_raw', 1, lambda v: str(v).encode() if v is not None else None)
        self.db.create_function('to_char', -1, lambda v, *args: str(v) if v is not None else None)
        ddl = self.args[-1]['fox-package/supporting-schema.sql'].decode().replace(
            'NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY', 'INTEGER PRIMARY KEY')
        self.db.executescript(ddl)
        self.db.execute('create table apex_collections(collection_name TEXT,seq_id INTEGER,'
                        + ','.join(f'c{i:03} TEXT' for i in range(1, 51)) + ','
                        + ','.join(f'n{i:03} NUMERIC' for i in range(1, 6)) + ')')
        self.f, self.w = self.op['fields'], self.op['write_contract']
        self.head, self.bag = self.w['parent_table'], self.w['child_table']
        self.key = self.f['header_key']['column']
        self.cost = self.op['item_layout']['fields']['weight']['column']
        self.approved = next(f['column'] for f in self.op['contract']['blocks']['header']['items']
                             if f['source_name'] in ('APPROVED', 'RELEASED'))
        for identity, key in ((1, 'H1'), (2, 'H2')):
            self.db.execute(f'insert into {self.head}(FOX_ROW_ID,{self.key},{self.w["parent_route"]["column"]}) values(?,?,?)',
                            (identity, key, 'CURRENT'))
        self.add_bag(1, 'ONE', None)
        self.add_bag(2, 'TWO', 0)
        self.add_bag(3, 'OTHER', None, parent='H2')
        self.token = self.db.execute('select ' + _fingerprint(self.op['contract']['blocks']['header']['items'])
                                    + f' from {self.head} p where FOX_ROW_ID=1').fetchone()[0]
        self.params = {'P8801_PARENT_ID': 1, 'P8801_TOKEN': self.token, 'P8801_ROW_ID': 1}
        self.marker = None
        self.baselines = {}
        self.serial = 0
        self.db.commit()

    def adapt(self, sql):
        return sql.replace('utl_raw.cast_to_raw(', 'fox_raw(')

    def rows(self, key, **params):
        cursor = self.db.execute(self.adapt(self.sql[key]), {**self.params, **params})
        return [dict(zip([c[0] for c in cursor.description], row)) for row in cursor]

    def add_bag(self, identity, code, weight, parent='H1'):
        self.db.execute(f'insert into {self.bag}(FOX_ROW_ID,{self.f["bag_header_key"]["column"]},'
                        f'{self.f["bag_number"]["column"]},{self.f["weight"]["column"]},{self.w["route"]["column"]},{self.cost}) '
                        'values(?,?,?,?,?,?)', (identity, parent, code, weight, 'OLD', 12))

    def draft(self, identity=1, code='ONE', *, dirty=False, row=1):
        ns = self.op['draft_namespace']
        self.name = ns + '1_' + hashlib.sha256(b'H1').hexdigest().upper()[:32]
        if self.db.execute('select count(*) from apex_collections where seq_id=1').fetchone()[0] == 0:
            from fox.forms_numeric_correction import _sha
            self.db.execute("insert into apex_collections(collection_name,seq_id,c049,c050,n001,n002,n003) values(?,1,?,'META',1,2,7)",
                            (self.name, _sha(self.op['buffer'])))
        columns = ['collection_name', 'seq_id', 'c050', 'n001', 'c040', 'c041', 'c044', 'n002', 'n003']
        values = [self.name, row + 1, 'ROW', identity, 'OLD', 'SYNTHETIC_SAVE_BASELINE_V1', 'OLD', 12, 12]
        for i, f in enumerate(self.w['fields'], 1):
            v = 'H1' if f.get('parent_copy') else code
            columns += [f'c{i:03}', f'c{20+i:03}']
            values += [v + '-DIRTY' if dirty and not f.get('parent_copy') else v, v]
        self.db.execute('insert into apex_collections(' + ','.join(columns) + ') values('
                        + ','.join('?' for _ in values) + ')', values)
        self.db.commit()

    def open(self, row=1):
        self.params['P8801_ROW_ID'] = row
        assert self.rows('eligible_query_sql')
        current, = self.rows('context_query_sql')
        self.serial += 1
        self.marker = (str(self.serial), current['ROW_SNAPSHOT'], row, self.token)
        self.baselines[self.marker[0]] = self.marker
        return self.marker

    def save(self, value, marker=None, *, fail_after_write=False, after_check=None):
        marker = marker or self.marker
        self.db.execute('savepoint correction')
        try:
            assert marker is not None and self.baselines.get(marker[0]) == marker
            assert marker[2] == self.params['P8801_ROW_ID'] and marker[3] == self.params['P8801_TOKEN']
            assert self.rows('eligible_query_sql')
            current, = self.rows('context_query_sql')
            assert current['ROW_SNAPSHOT'] == marker[1]
            number = validate_numeric_value(value, self.op['rules'])
            if after_check:
                after_check()
            sql = re.sub(r'\bl_(value|route|id)\b', r':l_\1', self.sql['update_sql'])
            result = self.db.execute(sql, {'l_value': str(number), 'l_route': current['CURRENT_ROUTE'], 'l_id': marker[2]})
            assert result.rowcount == 1
            # Model the emitted per-row collection API statements and META bump.
            for name, seq in self.db.execute("select collection_name,seq_id from apex_collections where c050='ROW' and n001=?", (marker[2],)).fetchall():
                self.db.execute('update apex_collections set c040=?,c044=? where collection_name=? and seq_id=?',
                                (current['CURRENT_ROUTE'], current['CURRENT_ROUTE'], name, seq))
                self.db.execute('update apex_collections set n003=n003+1 where collection_name=? and seq_id=1', (name,))
            assert not fail_after_write
            del self.baselines[marker[0]]
            if self.marker == marker:
                self.marker = None
            self.db.execute('release correction')
        except (AssertionError, ValueError):
            self.db.execute('rollback to correction')
            self.db.execute('release correction')
            raise


@pytest.mark.parametrize('renamed', [False, True])
def test_exact_emitted_selection_update_recheck_and_clean_draft_reconciliation(renamed):
    b = Boundary(renamed)
    assert [r['FOX_ROW_ID'] for r in b.rows('chooser_query_sql')] == [1, 2]
    b.draft()
    b.draft(identity=2, code='TWO', dirty=True, row=2)
    sibling = b.db.execute('select * from apex_collections where seq_id=3').fetchone()
    before_ctc = b.db.execute(f'select {b.cost} from {b.bag} order by FOX_ROW_ID').fetchall()
    old_marker = b.open()
    b.save('123')
    assert b.db.execute(f'select {b.f["weight"]["column"]},{b.w["route"]["column"]} from {b.bag} where FOX_ROW_ID=1').fetchone() == (123, 'CURRENT')
    assert b.db.execute(f'select {b.cost} from {b.bag} order by FOX_ROW_ID').fetchall() == before_ctc
    assert b.db.execute('select * from apex_collections where seq_id=3').fetchone() == sibling
    assert b.db.execute('select c040,c044,n002,n003 from apex_collections where seq_id=2').fetchone() == ('CURRENT', 'CURRENT', 12, 12)
    assert b.db.execute('select n003 from apex_collections where seq_id=1').fetchone() == (8,)
    assert [r['FOX_ROW_ID'] for r in b.rows('chooser_query_sql')] == [2]
    with pytest.raises(AssertionError): b.save('124', old_marker)


@pytest.mark.parametrize('change', ['weight', 'unprojected', 'parent', 'approval', 'membership', 'duplicate', 'draft', 'draft_duplicate'])
def test_stale_membership_permission_concurrent_and_draft_conflicts_write_nothing(change):
    b = Boundary()
    mark = b.open()
    if change == 'weight':
        b.db.execute(f'update {b.bag} set {b.f["weight"]["column"]}=8 where FOX_ROW_ID=1')
    elif change == 'unprojected':
        b.db.execute(f'update {b.bag} set {b.cost}=99 where FOX_ROW_ID=1')
    elif change == 'parent':
        b.db.execute(f'update {b.head} set {b.w["parent_route"]["column"]}=? where FOX_ROW_ID=1', ('NEW',))
    elif change == 'approval':
        b.db.execute(f'update {b.head} set {b.approved}=? where FOX_ROW_ID=1', ('Y',))
    elif change == 'membership':
        b.db.execute(f'update {b.bag} set {b.f["bag_header_key"]["column"]}=? where FOX_ROW_ID=1', ('H2',))
    elif change == 'duplicate': b.add_bag(4, 'ONE', None)
    elif change == 'draft': b.draft(dirty=True)
    elif change == 'draft_duplicate': b.draft(identity=None, code='ONE')
    b.db.commit()
    before = list(b.db.iterdump())
    with pytest.raises(AssertionError): b.save('3', mark)
    assert list(b.db.iterdump()) == before


def test_duplicate_bag_names_are_real_rows_and_same_name_other_parent_does_not_block():
    b = Boundary()
    b.add_bag(4, 'ONE', None, parent='H2')
    b.db.commit()
    assert b.rows('eligible_query_sql')
    b.add_bag(5, 'ONE', None)
    assert not b.rows('eligible_query_sql')
    choices = b.rows('chooser_query_sql')
    assert [r['FOX_ROW_ID'] for r in choices] == [1, 2, 5]
    assert [r['CAN_EDIT'] for r in choices] == [0, 1, 0]


def test_two_opens_cannot_borrow_new_server_baseline_or_change_signed_row():
    b = Boundary()
    first = b.open()
    b.db.execute(f'update {b.bag} set {b.cost}=13 where FOX_ROW_ID=1')
    b.db.commit()
    second = b.open()
    with pytest.raises(AssertionError): b.save('5', first)
    b.open(2)
    with pytest.raises(AssertionError): b.save('5', second)
    b.params['P8801_ROW_ID'] = 1
    with pytest.raises(AssertionError): b.save('5')


def test_open_during_save_does_not_replace_or_consume_another_nonce_baseline():
    b = Boundary()
    first = b.open()
    newer = []
    b.save('5', first, after_check=lambda: newer.append(b.open()))
    assert first[0] not in b.baselines and newer[0][0] in b.baselines
    with pytest.raises(AssertionError): b.save('6', newer[0])


@pytest.mark.parametrize('damage', ['missing_marker', 'null_meta_hash', 'null_revision', 'fractional_revision', 'missing_current', 'stale_baseline', 'ctc_dirty', 'active_route_dirty', 'stale_namespace'])
def test_damaged_or_pending_same_row_draft_fails_closed_without_touching_siblings(damage):
    b = Boundary()
    b.draft()
    mutations = {
        'missing_marker': "update apex_collections set c041=null where seq_id=2",
        'null_meta_hash': "update apex_collections set c049=null where seq_id=1",
        'null_revision': "update apex_collections set n003=null where seq_id=1",
        'fractional_revision': "update apex_collections set n003=1.2 where seq_id=1",
        'missing_current': "update apex_collections set n002=99 where seq_id=1",
        'stale_baseline': "update apex_collections set c040='STALE' where seq_id=2",
        'ctc_dirty': "update apex_collections set n002=13 where seq_id=2",
        'active_route_dirty': "update apex_collections set c044='NEW' where seq_id=2",
        'stale_namespace': "update apex_collections set collection_name=collection_name||'_OLD'",
    }
    b.db.execute(mutations[damage])
    b.db.commit()
    before = list(b.db.iterdump())
    assert not b.rows('eligible_query_sql')
    assert b.rows('chooser_query_sql')[0]['CAN_EDIT'] == 0
    assert list(b.db.iterdump()) == before


def test_invalid_input_retry_and_rollback_after_write_keep_baseline_and_all_drafts():
    b = Boundary()
    b.draft()
    mark = b.open()
    before = list(b.db.iterdump())
    with pytest.raises(ValueError): b.save('1.5')
    assert list(b.db.iterdump()) == before and b.marker == mark
    with pytest.raises(AssertionError): b.save('5', fail_after_write=True)
    assert list(b.db.iterdump()) == before and b.marker == mark
    b.save('5')


@pytest.mark.parametrize('scope,property_', [('Item', 'QueryOnly'), ('Item', 'UpdateOnlyIfNull'),
                                          ('Item', 'SubclassModule'), ('Block', 'QueryOnly'), ('Block', 'UpdateAllowed')])
def test_static_source_restrictions_do_not_acquire_a_write_contract(scope, property_):
    docs = source()
    root = ET.fromstring(docs[0][1])
    actual = next(i for i in root.iter('Item') if i.get('Name') == 'ACTUAL_WEIGHT')
    child = next(b for b in root.iter('Block') if actual in list(b))
    node = actual if scope == 'Item' else child
    node.set(property_, 'false' if property_ == 'UpdateAllowed' else 'LIBRARY' if property_ == 'SubclassModule' else 'true')
    args = prepare([(docs[0][0], ET.tostring(root))])
    plan = build_numeric_correction_plan(*args)
    assert not plan['operations'] and plan['gaps']


@pytest.mark.parametrize('body', ['BEGIN NULL;', 'NULL; END;', 'BEGIN NULL; END; COMMIT;', 'DELETE_RECORD;'])
def test_query_override_must_be_an_entire_balanced_null_statement(body):
    docs = source()
    root = ET.fromstring(docs[0][1])
    actual = next(i for i in root.iter('Item') if i.get('Name') == 'ACTUAL_WEIGHT')
    next(t for t in actual.findall('Trigger') if t.get('Name') == 'KEY-ENTQRY').set('TriggerText', body)
    plan = build_numeric_correction_plan(*prepare([(docs[0][0], ET.tostring(root))]))
    assert not plan['operations'] and plan['gaps']


@pytest.mark.parametrize('boundary', ['source', 'readiness', 'schema', 'policy', 'guard', 'static_field', 'dynamic_field'])
def test_missing_or_changed_proof_never_enables_correction(boundary):
    docs = source()
    if boundary in ('guard', 'static_field', 'dynamic_field'):
        root = ET.fromstring(docs[0][1])
        actual = next(i for i in root.iter('Item') if i.get('Name') == 'ACTUAL_WEIGHT')
        if boundary == 'guard': actual.find('Trigger').set('TriggerText', 'NULL;')
        elif boundary == 'static_field': actual.set('UpdateAllowed', 'false')
        else:
            helper = next(x for x in root.iter('ProgramUnit') if x.get('Name') == 'POLICY')
            helper.set('ProgramUnitText', helper.get('ProgramUnitText').replace('IS BEGIN ',
                "IS BEGIN SET_ITEM_PROPERTY('PIECES.ACTUAL_WEIGHT',UPDATE_ALLOWED,PROPERTY_FALSE); "))
        docs = [(docs[0][0], ET.tostring(root))]
    args = prepare(docs)
    if boundary == 'source': args[-1]['fox-package/sources/' + docs[0][0]] += b' '
    elif boundary == 'readiness':
        ready = json.loads(args[-1]['fox-package/approval-action-receipt.json'])['adapted_operations'][0]
        args[-1][ready['page_file']] += b' '
    elif boundary == 'schema': args[-1]['fox-package/supporting-schema.sql'] = b'CREATE TABLE CUSTOMER(ID NUMBER);'
    elif boundary == 'policy': args[-1]['fox-package/draft-policy-receipt.json'] = b'{}'
    try:
        plan = build_numeric_correction_plan(*args)
    except ValueError:
        return
    assert not plan['operations'] and plan['gaps']
