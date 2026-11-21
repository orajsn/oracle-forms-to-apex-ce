"""Real generated SQL boundary checks; SQLite is not Oracle/APEX runtime proof."""
from copy import deepcopy
import hashlib
import json
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_master_detail import (apply_master_details, parse_population,
                                     parse_query_helper, parse_check_helper)
from fox.forms_synthetic_save import apply_synthetic_saves
from test_forms_synthetic_save import source as save_source, prepare as save_prepare


QUERY_HELPER = """PROCEDURE FILL_CHILD_ROWS(rel Relation,child_block VARCHAR2) IS
prior_message VARCHAR2(2); coordination VARCHAR2(5);
BEGIN
 coordination := Get_Relation_Property(rel, DEFERRED_COORDINATION);
 prior_message := :System.Message_Level;
 IF coordination = 'FALSE' THEN
   Go_Block(child_block); ASSERT_OK;
   :System.Message_Level := '10'; Execute_Query;
   :System.Message_Level := prior_message;
 ELSE
   Set_Block_Property(child_block, COORDINATION_STATUS, NON_COORDINATED);
 END IF;
EXCEPTION WHEN Form_Trigger_Failure THEN
 :System.Message_Level := prior_message; RAISE;
END FILL_CHILD_ROWS;"""
CHECK_HELPER = """PROCEDURE ASSERT_OK IS BEGIN
IF NOT (Form_Success) THEN RAISE Form_Trigger_Failure; END IF; END;"""


def trigger(parent, relation, child, guard):
    return f"""-- independently named source example
DECLARE status_at_entry VARCHAR2(20) := :SYSTEM.RECORD_STATUS;
focus_at_entry VARCHAR2(61) := :SYSTEM.CURSOR_ITEM;
chosen_relation Relation;
BEGIN
 IF (status_at_entry = 'NEW' OR status_at_entry = 'INSERT') THEN RETURN; END IF;
 IF ({guard}) THEN
   chosen_relation := Find_Relation('{parent}.{relation}');
   FILL_CHILD_ROWS(chosen_relation, '{child}');
 END IF;
 IF (:SYSTEM.CURSOR_ITEM <> focus_at_entry) THEN
   Go_Item(focus_at_entry); ASSERT_OK;
 END IF;
END;"""


def source(*, renamed=False, deferred=False, extra='', mutate=None):
    docs = save_source()
    root = ET.fromstring(docs[0][1])
    parent = next(b for b in root.iter('Block') if b.get('Name') == 'LOADS')
    middle = next(b for b in root.iter('Block') if b.get('Name') == 'PIECES')
    ET.SubElement(middle, 'Relation', Name='PIECE_SCANS', DetailBlock='SCANS', RelationType='Join',
                  JoinCondition='PIECES.LOAD_REFERENCE=SCANS.HEADER_REF AND PIECES.PIECE_CODE=SCANS.PACKAGE_REF',
                  Deferred='true' if deferred else 'false', AutoQuery='false', DeleteRecord='Cascading', PreventMasterlessOperations='false')
    last = ET.SubElement(root, 'Block', Name='SCANS', DatabaseBlock='true')
    for name in ('HEADER_REF', 'PACKAGE_REF', 'SCAN_TEXT'):
        ET.SubElement(last, 'Item', Name=name, ItemType='Text Item', DataType='Char', DatabaseItem='true', MaximumLength='30')
    for block, rel, child, guard in ((parent, 'LOAD_PIECES', 'PIECES', ':LOADS.LOAD_REFERENCE IS NOT NULL'),
            (middle, 'PIECE_SCANS', 'SCANS', '(:PIECES.LOAD_REFERENCE IS NOT NULL) OR (:PIECES.PIECE_CODE IS NOT NULL)')):
        ET.SubElement(block, 'Trigger', Name='ON-POPULATE-DETAILS', TriggerText=trigger(block.get('Name'), rel, child, guard))
    for name, text in (('FILL_CHILD_ROWS', QUERY_HELPER), ('ASSERT_OK', CHECK_HELPER)):
        ET.SubElement(root, 'ProgramUnit', Name=name, ProgramUnitType='Procedure', ProgramUnitText=text)
    # An applicable clear event is evidence, never implicit permission to clear.
    ET.SubElement(root, 'Trigger', Name='ON-CLEAR-DETAILS', TriggerText='CLEAR_OTHER_BUFFERS;')
    if extra:
        ET.SubElement(root, 'ProgramUnit', Name='OTHER_CODE', ProgramUnitType='Procedure', ProgramUnitText=extra)
    if mutate:
        mutate(root)
    raw = ET.tostring(root)
    if renamed:
        for old, new in ((b'DISPATCH_DRAFT', b'CARGO_BOARD'), (b'LOADS', b'JOBS'), (b'PIECES', b'BOXES'),
                         (b'SCANS', b'EVENTS'), (b'LOAD_REFERENCE', b'JOB_CODE'), (b'PIECE_CODE', b'BOX_CODE'),
                         (b'HEADER_REF', b'JOB_REF'), (b'PACKAGE_REF', b'BOX_REF'), (b'FILL_CHILD_ROWS', b'LOAD_EVENTS'),
                         (b'ASSERT_OK', b'REQUIRE_SUCCESS'), (b'LOAD_PIECES', b'JOB_BOXES'), (b'PIECE_SCANS', b'BOX_EVENTS')):
            raw = raw.replace(old, new)
    return [('cargo.xml' if renamed else docs[0][0], raw)]


def prepare(docs=None):
    docs = docs or source()
    packet, chunks, trace, files = save_prepare(docs)
    files, receipt = apply_synthetic_saves(docs, packet, chunks, trace, files)
    files['fox-package/synthetic-save-receipt.json'] = json.dumps(receipt).encode()
    return docs, packet, chunks, trace, files


def apply(docs=None):
    args = prepare(docs)
    out, receipt = apply_master_details(*args)
    return out, receipt, args


@pytest.mark.parametrize('renamed', [False, True])
def test_actual_native_selection_and_draft_regions_with_honest_partial_ledger(renamed):
    args = prepare(source(renamed=renamed))
    before = deepcopy(args)
    out, receipt = apply_master_details(*args)
    assert args == before and (out, receipt) == apply_master_details(*args)
    assert len(receipt['adapted_operations']) == 2
    assert len(receipt['partial_effects']) == 1
    assert not receipt['generated_operations'] and receipt['converted_code_unit_count'] == 0
    assert len(receipt['helper_models']) == 2 and all(m['complete_source_parsed'] for m in receipt['helper_models'])
    for op in receipt['adapted_operations']:
        text = out[op['page_file']].decode()
        assert 'Select or change master' in text and 'Selected master context' in text
        assert 'Automatically populated details' in text and 'linkText: Select master' in text
        assert 'coordinate-selected-master' in text and "STATE:='UNSELECTED'" in text
        assert 'checksumRequiredSessionLevel' in text and 'argumentsMustHaveChecksum' in text
        assert op['applicable_clear_trigger_ids']
        assert 'executeQuery' not in text and 'button guarded-execute-query' not in text
        assert f'P{op["page_id"]}_TOKEN: "#FOX_MASTER_TOKEN#"' in text
        for hidden in ('PARENT_ID', 'TOKEN'):
            item = re.search(r'    pageItem P' + str(op['page_id']) + '_' + hidden + r' \(.*?\n    \)', text, re.S)[0]
            assert 'type: hidden' in item and 'label {' not in item
        assert not any(word in text.lower() for word in ('delete_collection', 'create_or_truncate', 'insert into', 'update fox_native_'))
        assert all(op[k] is False for k in ('runtime_verified', 'business_accepted'))
    draft, = receipt['partial_effects']
    text = out[draft['page_file']].decode()
    assert 'coordinated-draft-details' in text and 'draft-coordination-state' in text
    assert 'NEW_OR_INSERT_SKIPPED' in text and 'CHANGED_DRAFT_PENDING' in text
    assert '_SEQ' in draft['child_query_sql'] and '_REV' in draft['child_query_sql']
    assert 'd.n001=p.FOX_ROW_ID' in draft['child_query_sql']
    assert 'sessionStorage' in text and 'document.getElementById' in text
    # Existing validators/processes/branches remain byte-identical.
    extract = lambda s: re.findall(r'    (?:process|validation|branch) [\w-]+ \(.*?\n    \)', s, re.S)
    assert extract(text) == extract(args[-1][draft['page_file']].decode())
    assert out['fox-package/sources/' + args[0][0][0]] == args[0][0][1]
    assert all(not receipt[k] for k in ('original_reads_enabled', 'customer_table_writes', 'synthetic_table_writes', 'oracle_compiled', 'runtime_verified', 'business_accepted'))


class SQLBoundary:
    def __init__(self, docs=None):
        self.out, self.receipt, args = apply(docs)
        self.trace, self.files = args[3:]
        self.db = sqlite3.connect(':memory:')
        self.db.create_function('standard_hash', 2, lambda v, alg: None if v is None else hashlib.sha256(str(v).encode()).digest())
        self.db.create_function('rawtohex', 1, lambda v: None if v is None else v.hex().upper())
        self.db.create_function('nvl', 2, lambda a, b: b if a is None else a)
        self.db.create_function('to_char', 2, lambda a, fmt: str(a) if a is not None else None)
        self.db.create_function('fox_raw', 1, lambda v: v.encode() if isinstance(v, str) else v)
        self.db.create_function('decode', 4, lambda a, b, yes, no: yes if a == b else no)
        ddl = self.files['fox-package/supporting-schema.sql'].decode().replace('NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY', 'INTEGER PRIMARY KEY')
        self.db.executescript(ddl)
        columns = ','.join(f'c{i:03} text' for i in range(1, 51)) + ',' + ','.join(f'n{i:03} number' for i in range(1, 6))
        self.db.execute('create table apex_collections(collection_name text,seq_id integer,' + columns + ')')

    def block(self, name):
        return next(b for b in self.trace['blocks'] if b['name'] == name)

    def insert(self, block, row, **fields):
        b = self.block(block)
        f = {i['source_name']: i['column'] for i in b['items']}
        keys = list(fields)
        self.db.execute('insert into ' + b['table_name'] + '(FOX_ROW_ID,' + ','.join(f[k] for k in keys) + ') values (' + ','.join('?' for _ in range(len(keys)+1)) + ')', [row] + [fields[k] for k in keys])

    def execute(self, text, values):
        # Existing calculated projections may retain unrelated app-item binds;
        # NULL models their unset state, without replacing emitted expressions.
        values = {**{n: None for n in re.findall(r':([A-Z][A-Z0-9_]*)', text)}, **values}
        return self.db.execute(text.replace('utl_raw.cast_to_raw(', 'fox_raw('), values).fetchall()

    def select(self, op, row):
        selected = next(r for r in self.execute(op['chooser_query_sql'], {}) if r[0] == row)
        page = op['page_id']
        return {f'P{page}_PARENT_ID': row, f'P{page}_TOKEN': selected[-1], f'P{page}_STATE': 'COORDINATED'}


def seeded(docs=None):
    b = SQLBoundary(docs)
    b.insert('LOADS', 1, LOAD_REFERENCE='A', PLANNED_ROUTE='R1')
    b.insert('LOADS', 2, LOAD_REFERENCE='B', PLANNED_ROUTE='R2')
    b.insert('LOADS', 3, LOAD_REFERENCE=None, PLANNED_ROUTE='R3')
    b.insert('PIECES', 11, LOAD_REFERENCE='A', PIECE_CODE='P1', STORED_ROUTE='R1')
    b.insert('PIECES', 12, LOAD_REFERENCE='A', PIECE_CODE='P2', STORED_ROUTE='R1')
    b.insert('PIECES', 21, LOAD_REFERENCE='B', PIECE_CODE='P1', STORED_ROUTE='R2')
    b.insert('SCANS', 111, HEADER_REF='A', PACKAGE_REF='P1', SCAN_TEXT='first')
    b.insert('SCANS', 112, HEADER_REF='A', PACKAGE_REF='P2', SCAN_TEXT='second')
    b.insert('SCANS', 211, HEADER_REF='B', PACKAGE_REF='P1', SCAN_TEXT='sibling')
    return b


def test_emitted_parent_switch_selects_context_and_matching_children_without_writes():
    b = seeded()
    first, second = b.receipt['adapted_operations']
    for op, selections in ((first, ((1, [11, 12]), (2, [21]), (3, []))),
                           (second, ((11, [111]), (12, [112]), (21, [211])))):
        for row, expected in selections:
            binds = b.select(op, row)
            before = b.db.total_changes
            context = b.execute(op['parent_context_sql'], binds)
            assert [r[0] for r in b.execute(op['child_query_sql'], binds)] == expected
            assert [r[0] for r in context] == ([row] if expected else [])
            assert b.db.total_changes == before
    assert second['guard_connector'] == 'OR' and first['guard_connector'] == 'AND'
    assert ' OR ' in second['child_query_sql']


@pytest.mark.parametrize('renamed', [False, True])
def test_chooser_tokens_fit_apex_item_values_and_match_every_selection_gate(renamed):
    b = seeded() if not renamed else SQLBoundary(source(renamed=True))
    if renamed:
        b.insert('JOBS', 1, JOB_CODE='A', PLANNED_ROUTE='R1')
        b.insert('BOXES', 11, JOB_CODE='A', BOX_CODE='P1', STORED_ROUTE='R1')
        b.insert('EVENTS', 111, JOB_REF='A', BOX_REF='P1', SCAN_TEXT='first')
    expected_children = ([11], [111]) if renamed else ([11, 12], [111])
    for op, row, children in zip(b.receipt['adapted_operations'], (1, 11), expected_children):
        page = op['page_id']
        binds = b.select(op, row)
        token = binds[f'P{page}_TOKEN']
        assert re.fullmatch('[0-9A-F]{64}', token)
        # f?p item values are separated from other URL fields by colons.
        url = f'f?p=100:{page}:123::NO::P{page}_PARENT_ID,P{page}_TOKEN:{row},{token}'
        assert url.split(':')[7].split(',') == [str(row), token]
        assert [r[0] for r in b.execute(op['parent_context_sql'], binds)] == [row]
        assert [r[0] for r in b.execute(op['child_query_sql'], binds)] == children
        assert op['parent_context_sql'] in op['population_process_code']
        assert op['child_query_sql'] in op['population_process_code']
        assert op['visible_child_query_sql'].startswith(op['child_query_sql'])
        assert all(line in b.out[op['page_file']].decode() for line in op['chooser_query_sql'].splitlines())
        if len(op['snapshot_fields']) == 1:
            # Existing one-field links keep their exact pre-fix value.
            assert token == hashlib.sha256(b'A').hexdigest().upper()
        else:
            legacy = ':'.join(hashlib.sha256(v).hexdigest().upper() for v in (b'A', b'P1'))
            assert token == hashlib.sha256(legacy.encode()).hexdigest().upper()
            for invalid in (legacy, legacy[:64], token[:-1], '0' * 64):
                stale = {**binds, f'P{page}_TOKEN': invalid}
                assert not b.execute(op['parent_context_sql'], stale)
                assert not b.execute(op['child_query_sql'], stale)


def test_compound_tokens_preserve_order_null_positions_and_wide_value_boundaries():
    from fox.forms_master_detail import _fingerprint
    b = SQLBoundary()
    cases = [('AB', 'C'), ('A', 'BC'), ('A', 'B'), ('B', 'A'),
             (None, 'N'), ('N', None), (None, None), ('N', 'N'),
             ('A:B,C', 'D'), ('A', 'B,C:D'), ('x' * 4000, 'y' * 4000),
             ('é' * 1000, 'z')]
    for width in (2, 4, 8):
        fields = [{'column': f'K{i}'} for i in range(width)]
        query = 'select ' + _fingerprint(fields) + ' from (select ' + ','.join(f':K{i} as K{i}' for i in range(width)) + ') p'
        tokens = []
        for first, second in cases:
            values = [first, second] + [None] * (width - 2)
            token = b.execute(query, dict(zip((f'K{i}' for i in range(width)), values)))[0][0]
            assert re.fullmatch('[0-9A-F]{64}', token)
            framed = ':'.join('N' if value is None else hashlib.sha256(value.encode()).hexdigest().upper() for value in values)
            assert token == hashlib.sha256(framed.encode()).hexdigest().upper()
            tokens.append(token)
        assert len(set(tokens)) == len(cases)


@pytest.mark.parametrize('field', ['LOAD_REFERENCE', 'PIECE_CODE'])
def test_compound_selection_rejects_stale_changes_to_either_field(field):
    b = seeded()
    op = b.receipt['adapted_operations'][1]
    binds = b.select(op, 11)
    parent = b.block('PIECES')
    column = next(f['column'] for f in parent['items'] if f['source_name'] == field)
    for changed in ('CHANGED', None):
        b.db.execute(f'update {parent["table_name"]} set {column}=? where FOX_ROW_ID=11', (changed,))
        assert not b.execute(op['parent_context_sql'], binds)
        assert not b.execute(op['child_query_sql'], binds)


def test_compound_selection_keeps_row_identity_and_null_safe_uniqueness_guards():
    b = seeded()
    op = b.receipt['adapted_operations'][1]
    page = op['page_id']
    valid = b.select(op, 11)
    sibling = b.select(op, 21)
    for row, token in ((21, valid[f'P{page}_TOKEN']), (11, sibling[f'P{page}_TOKEN']),
                       (None, valid[f'P{page}_TOKEN']), (999, valid[f'P{page}_TOKEN'])):
        binds = {f'P{page}_PARENT_ID': row, f'P{page}_TOKEN': token}
        assert not b.execute(op['parent_context_sql'], binds)
        assert not b.execute(op['child_query_sql'], binds)
    b.insert('PIECES', 41, LOAD_REFERENCE='A', PIECE_CODE='P1', STORED_ROUTE='R1')
    assert not b.execute(op['parent_context_sql'], valid)
    assert not b.execute(op['child_query_sql'], valid)
    b.insert('PIECES', 51, LOAD_REFERENCE=None, PIECE_CODE='NULL_PARENT')
    nullable = b.select(op, 51)
    assert [r[0] for r in b.execute(op['parent_context_sql'], nullable)] == [51]
    b.insert('PIECES', 52, LOAD_REFERENCE=None, PIECE_CODE='NULL_PARENT')
    assert not b.execute(op['parent_context_sql'], nullable)
    assert not b.execute(op['child_query_sql'], nullable)
    single = b.receipt['adapted_operations'][0]
    assert b.select(single, 3)[f'P{single["page_id"]}_TOKEN'] == 'N'


def test_null_missing_stale_and_nonunique_parent_never_select_default_or_sibling():
    b = seeded(); op = b.receipt['adapted_operations'][0]
    valid = b.select(op, 1)
    for row, token in ((None, None), (999, valid[f'P{op["page_id"]}_TOKEN']), (1, None), (1, 'tampered')):
        binds = {f'P{op["page_id"]}_PARENT_ID': row, f'P{op["page_id"]}_TOKEN': token}
        assert not b.execute(op['parent_context_sql'], binds)
        assert not b.execute(op['child_query_sql'], binds)
    parent = b.block('LOADS'); key = next(f['column'] for f in parent['items'] if f['source_name'] == 'LOAD_REFERENCE')
    b.db.execute(f'update {parent["table_name"]} set {key}=? where FOX_ROW_ID=1', ('CHANGED',))
    assert not b.execute(op['child_query_sql'], valid)
    b.db.execute(f'update {parent["table_name"]} set {key}=? where FOX_ROW_ID=1', ('A',))
    b.insert('LOADS', 4, LOAD_REFERENCE='A', PLANNED_ROUTE='R4')
    assert not b.execute(op['parent_context_sql'], valid) and not b.execute(op['child_query_sql'], valid)
    assert all(s not in op['child_query_sql'].lower() for s in ('min(', 'max(', 'rownum', 'fetch first', 'limit '))


def test_OR_guard_queries_empty_details_with_one_null_key_instead_of_applying_AND():
    b = seeded(); op = b.receipt['adapted_operations'][1]
    b.insert('PIECES', 31, LOAD_REFERENCE='C', PIECE_CODE=None, STORED_ROUTE='R3')
    binds = b.select(op, 31)
    assert [r[0] for r in b.execute(op['parent_context_sql'], binds)] == [31]
    assert not b.execute(op['child_query_sql'], binds)
    b.insert('PIECES', 32, LOAD_REFERENCE=None, PIECE_CODE='NULL_PARENT', STORED_ROUTE='R3')
    binds = b.select(op, 32)
    assert [r[0] for r in b.execute(op['parent_context_sql'], binds)] == [32]
    assert not b.execute(op['child_query_sql'], binds)


def test_normal_enriched_packet_is_accepted_without_trusting_changed_sources():
    args = list(prepare())
    args[1]['generation_metadata'] = {'name': 'normal-assembler'}
    _, receipt = apply_master_details(*args)
    assert len(receipt['adapted_operations']) == 2


def test_applicable_clear_trigger_is_required_before_automatic_population():
    def mutate(root):
        root.remove(next(e for e in root if e.tag == 'Trigger' and e.get('Name') == 'ON-CLEAR-DETAILS'))
    args = prepare(source(mutate=mutate))
    out, receipt = apply_master_details(*args)
    assert not receipt['adapted_operations'] and out == args[-1]
    assert all(g['reason'] == 'MASTER_DETAILS_APPLICABLE_ON_CLEAR_DETAILS_REQUIRED' for g in receipt['gaps'])


def draft_rows(b):
    draft, = b.receipt['partial_effects']
    buffer, = json.loads(b.files['fox-package/buffer-plan.json'])['operations']
    name = draft['namespace'] + '1_' + hashlib.sha256(b'A').hexdigest().upper()[:32]
    columns = ['collection_name', 'seq_id', 'c049', 'c050', 'n001', 'n002', 'n003']
    values = [name, 1, hashlib.sha256(json.dumps(buffer, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(), 'META', 1, 2, 0]
    b.db.execute('insert into apex_collections(' + ','.join(columns) + ') values (' + ','.join('?' for _ in values) + ')', values)
    b.db.execute('insert into apex_collections(collection_name,seq_id,c001,c002,c021,c022,c040,c041,c050,n001) values(?,2,?,?,?,?,?,?,?,?)',
                 (name, 'A', 'P1', 'A', 'P1', 'R1', 'SYNTHETIC_SAVE_BASELINE_V1', 'ROW', 11))
    p = draft['page_id']
    binds = {f'P{p}_PARENT_ID': 1, f'P{p}_SEQ': 2, f'P{p}_REV': 0, 'REQUEST': None}
    return draft, binds, name


def test_current_proven_draft_identity_clean_switch_unsaved_dirty_stale_and_failed_submit():
    b = seeded(); draft, binds, name = draft_rows(b)
    def ids():
        return [r[0] for r in b.execute(draft['child_query_sql'], binds)]
    def state():
        return b.execute(draft['status_query_sql'], binds)[0][1]
    assert ids() == [111] and state() == 'PERSISTED_IDENTITY_RECHECKED'
    b.db.execute("update apex_collections set c002='P2',c022='P2',n001=12 where seq_id=2")
    assert ids() == [112]
    b.db.execute('update apex_collections set n001=null where seq_id=2')
    assert not ids() and state() == 'NEW_OR_INSERT_SKIPPED'
    b.db.execute("update apex_collections set n001=12,c002='DIRTY' where seq_id=2")
    assert not ids() and state() == 'CHANGED_DRAFT_PENDING'
    b.db.execute("update apex_collections set c002='P2' where seq_id=2")
    binds['REQUEST'] = 'FOX_SYNTHETIC_SAVE'
    assert not ids() and state() == 'SUBMITTED_INPUT_PENDING'
    binds['REQUEST'] = None
    table = b.block('PIECES'); col = next(f['column'] for f in table['items'] if f['source_name']=='PIECE_CODE')
    b.db.execute(f'update {table["table_name"]} set {col}=? where FOX_ROW_ID=12', ('EXTERNAL',))
    assert not ids() and state() == 'STALE_OR_MISSING_RECORD'
    binds[f'P{draft["page_id"]}_REV'] = 99
    assert not ids() and not b.execute(draft['status_query_sql'], binds)
    assert b.db.execute('select count(*) from apex_collections where collection_name=?', (name,)).fetchone() == (2,)


def test_deferred_source_marks_noncoordinated_and_does_not_run_child_probe():
    out, receipt, _ = apply(source(deferred=True))
    op = next(o for o in receipt['adapted_operations'] if o['deferred'])
    assert op['auto_query'] is False and "STATE:='NON_COORDINATED'" in op['population_process_code']
    assert op['child_query_sql'] not in op['population_process_code']
    assert "STATE='COORDINATED'" in op['visible_child_query_sql']
    assert receipt['partial_effects'][0]['child_query_sql'].endswith(' and 1=0')
    gap = next(g for g in receipt['gaps'] if g.get('source_unit_id') == op['source_unit_id'])
    assert 'deferred_detail_activation_after_NON_COORDINATED' in gap['unimplemented_effects']


def test_query_failure_resets_state_before_probe_and_retains_selected_items():
    _, receipt, _ = apply()
    op = receipt['adapted_operations'][0]
    code = op['population_process_code']
    assert code.index("STATE:='UNSELECTED'") < code.index(op['child_query_sql']) < code.index("STATE:='COORDINATED'")
    assert "exception when others" in code and "STATE:='FAILED'" in code
    assert 'apex_error.add_error' in code and 'apex_debug.error' in code
    assert not re.search(r'_PARENT_ID\s*:=|_TOKEN\s*:=|apex_collection\.', code)
    b = seeded()
    binds = b.select(b.receipt['adapted_operations'][0], 1)
    b.db.execute('drop table ' + b.block('PIECES')['table_name'])
    with pytest.raises(sqlite3.OperationalError):
        b.execute(b.receipt['adapted_operations'][0]['child_query_sql'], binds)


@pytest.mark.parametrize('extra', [' COMMIT;', " SET_RELATION_PROPERTY(x,DEFERRED_COORDINATION,PROPERTY_TRUE);", " EXECUTE_TRIGGER('ALTER_RELATION');"])
def test_extra_executable_or_runtime_relation_mutations_do_not_gain_coverage(extra):
    if 'COMMIT' in extra:
        def mutate(root):
            node = next(e for e in root.iter('Trigger') if e.get('Name') == 'ON-POPULATE-DETAILS')
            node.set('TriggerText', node.get('TriggerText') + extra)
        docs = source(mutate=mutate)
    else:
        docs = source(extra='PROCEDURE OTHER_CODE IS BEGIN' + extra + ' END;')
    _, receipt, _ = apply(docs)
    assert not receipt['generated_operations']
    assert any('REQUIRED' in g['reason'] or 'UNRESOLVED' in g['reason'] for g in receipt['gaps'])
    if 'COMMIT' not in extra:
        assert not receipt['adapted_operations']


@pytest.mark.parametrize('target', ['trace', 'source', 'chunks', 'schema'])
def test_changed_provenance_is_rejected(target):
    args = list(prepare())
    if target == 'trace': args[3]['blocks'][0]['items'][0]['column'] = 'OTHER'
    if target == 'source': args[-1]['fox-package/sources/' + args[0][0][0]] += b' '
    if target == 'chunks': args[2][0]['text'] += ' COMMIT;'
    if target == 'schema': args[-1]['fox-package/supporting-schema.sql'] += b'\n-- changed'
    with pytest.raises(ValueError, match='MASTER_DETAILS_'):
        apply_master_details(*args)


@pytest.mark.parametrize('suffix', [' COMMIT;', ' NULL;', " EXECUTE_QUERY;"])
def test_whole_helper_grammar_rejects_unimplemented_tail(suffix):
    with pytest.raises(ValueError, match='MASTER_DETAILS_'):
        parse_query_helper(QUERY_HELPER + suffix)
    with pytest.raises(ValueError, match='MASTER_DETAILS_'):
        parse_check_helper(CHECK_HELPER + suffix)


def test_complete_helper_exception_and_restore_are_required():
    assert parse_query_helper(QUERY_HELPER)['V_CHECK'] == 'ASSERT_OK'
    for old, new in ((":System.Message_Level := prior_message; RAISE;", 'RAISE;'),
                     ('Go_Block(child_block); ASSERT_OK;', 'Go_Block(child_block);'),
                     ("coordination = 'FALSE'", "coordination = 'TRUE'")):
        with pytest.raises(ValueError, match='MASTER_DETAILS_'):
            parse_query_helper(QUERY_HELPER.replace(old, new))
    with pytest.raises(ValueError, match='MASTER_DETAILS_'):
        parse_population(trigger('LOADS', 'LOAD_PIECES', 'PIECES', ':LOADS.LOAD_REFERENCE IS NULL'))
    with pytest.raises(ValueError, match='MASTER_DETAILS_'):
        parse_population(trigger('LOADS', 'LOAD_PIECES', 'PIECES', ':LOADS.LOAD_REFERENCE IS NOT NULL OR'))
