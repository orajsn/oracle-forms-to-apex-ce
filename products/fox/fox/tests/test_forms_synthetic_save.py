"""Deterministic generated SQL boundary tests, not Oracle/APEX runtime proof."""
from copy import deepcopy
import json
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from forms2apex import native_assignments, native_buffer
from fox.forms_assignment_plan import build_assignment_plan
from fox.forms_draft_policy import apply_draft_policies
from fox.forms_synthetic_save import apply_synthetic_saves, _save_code, REQUEST
from test_forms_draft_policy import source as policy_source, prepare as policy_prepare


def source(*, renamed=False, missing_update=False, no_policy=False, route_type='Char', required_editable=False):
    docs = policy_source(renamed=renamed)
    root = ET.fromstring(docs[0][1])
    parent, child = list(root.iter('Block'))[:2]
    if required_editable:
        next(i for i in child.iter('Item') if i.get('Name') in ('PIECE_CODE', 'CRATE_CODE')).set('Required', 'true')
    for block, name in ((parent, 'PLANNED_ROUTE'), (child, 'STORED_ROUTE')):
        ET.SubElement(block, 'Item', Name=name, ItemType='Text Item', DatabaseItem='true',
                      DataType=route_type, MaximumLength='20', DataLengthSemantics='BYTE')
    ET.SubElement(child, 'Item', Name='UNEDITED_NOTE', ItemType='Text Item', DatabaseItem='true',
                  DataType='Char', MaximumLength='30')
    for event in ('PRE-INSERT', 'PRE-UPDATE'):
        if missing_update and event == 'PRE-UPDATE':
            continue
        ET.SubElement(child, 'Trigger', Name=event,
            TriggerText=f":{child.get('Name')}.STORED_ROUTE := :{parent.get('Name')}.PLANNED_ROUTE;")
    if no_policy:
        root.remove(next(e for e in root if e.tag == 'Trigger'))
    return [(docs[0][0], ET.tostring(root))]


def prepare(docs):
    packet, chunks, trace, files = policy_prepare(docs)
    plan = build_assignment_plan(docs, json.loads(files['fox-package/relation-plan.json']), trace)
    sql, receipt = native_assignments.render_assignment_code(plan)
    files['fox-package/assignment-plan.json'] = json.dumps(plan).encode()
    files['fox-package/assignment-receipt.json'] = json.dumps(receipt).encode()
    files[native_assignments.CODE_MEMBER] = sql.encode()
    files, receipt = apply_draft_policies(docs, packet, chunks, trace, files)
    files['fox-package/draft-policy-receipt.json'] = json.dumps(receipt).encode()
    return packet, chunks, trace, files


def apply(docs=None):
    docs = docs or source()
    args = prepare(docs)
    files, receipt = apply_synthetic_saves(docs, *args)
    return files, receipt, args


@pytest.mark.parametrize('renamed', [False, True])
def test_source_events_are_wired_once_to_actual_draft_with_reviews_preserved(renamed):
    docs = source(renamed=renamed)
    args = prepare(docs)
    before = deepcopy(args)
    files, receipt = apply_synthetic_saves(docs, *args)
    assert args == before and (files, receipt) == apply_synthetic_saves(docs, *args)
    assert receipt['converted_code_unit_count'] == 2 and not receipt['gaps']
    rows = receipt['generated_operations']
    assert {r['source_event'] for r in rows} == {'PRE-INSERT', 'PRE-UPDATE'}
    assert len({r['operation_id'] for r in rows}) == 2
    page = rows[0]['page_file']
    assert all(r['page_file'] == page and r['synthetic_table_writes'] is True for r in rows)
    assert all(r[k] is False for r in rows for k in ('customer_table_writes', 'oracle_compiled', 'runtime_verified', 'business_accepted'))
    assert {n for n in files if files[n] != args[-1][n]} == {page}
    assert files['fox-package/sources/' + docs[0][0]] == docs[0][1]
    assert 'label: "Save synthetic record"' in files[page].decode()


def generated(docs=None):
    files, receipt, args = apply(docs)
    buffer, = json.loads(args[-1]['fox-package/buffer-plan.json'])['operations']
    contract, = receipt['write_contracts']
    page = receipt['generated_operations'][0]['page_id']
    return _save_code(buffer, page, contract), contract, buffer, files, receipt, args


def test_guards_rechecks_and_reconciliation_share_a_single_transaction():
    code, c, _, files, receipt, _ = generated()
    body = code[code.index('  savepoint fox_synthetic_save;'):]
    assert body.index('savepoint ') < body.index('lock table ') < body.index('if not context_ok')
    assert code.index('for update nowait;') < code.index('select CASE WHEN')
    assert 'l_revision<>to_number(' in code and 'l_seq<>to_number(' in code
    assert body.index('Missing loaded-row baseline') < body.index(c['insert_sql'])
    assert body.index('Duplicate stored record') < body.index(c['insert_sql'])
    after_write = body[body.index(c['insert_sql']):]
    assert after_write.index('p_attr_number=>41') < after_write.index('p_number_value=>l_revision+1')
    assert 'rollback to fox_synthetic_save;' in code
    assert not re.search(r'\bcommit\s*;', code, re.I)
    assert 'p_commit=>false' in code
    assert 'p_message=>l_error_message' in code and 'apex_debug.error' in code
    assert 'l_error_code=-54' in code and 'l_error_code=-1403' in code
    text = files[receipt['generated_operations'][0]['page_file']].decode()
    assert text.count('p_c041=>') == 1  # loaded baseline only; blank drafts stay new
    assert 'p_c021=>r.' in text and 'p_c040=>r.' in text
    assert 'FOX_B_' not in text and 'FOX_S_' in text
    assert f"begin if :REQUEST='{REQUEST}' then return;end if;" in text
    for name, part in re.findall(r'(validation [\w-]+|process [\w-]+) \((.*?\n    \))', text, re.S):
        if name.startswith('validation'):
            assert 'value: ' + ','.join(native_buffer.REQUESTS) in part
        if name == 'process keep-draft-and-move':
            assert 'p_attr_number=>21' not in part and 'p_attr_number=>40' not in part
    assert 'Unknown synthetic save action' in body
    assert 'sqlerrm,' not in code  # never return arbitrary Oracle diagnostics


class SqlBoundary:
    """Execute emitted SQL in SQLite; model the PL/SQL control boundaries explicitly.

    Tests do not emulate row locks, APEX transactions/session state or Oracle NLS.
    Every SQL check/write below comes from the generated source, not a mock DB.
    """
    def __init__(self, *, required=False):
        self.code, self.c, self.buffer, _, self.receipt, args = generated(source(required_editable=required))
        self.db = sqlite3.connect(':memory:')
        self.db.create_function('fox_raw', 1, lambda v: None if v is None else str(v).encode())
        self.db.create_function('decode', 4, lambda a, b, yes, no: yes if a == b else no)
        self.db.create_function('nvl', 2, lambda a, b: b if a is None else a)
        self.db.create_function('lengthb', 1, lambda v: None if v is None else len(v.encode()))
        schema = args[-1]['fox-package/supporting-schema.sql'].decode()
        schema = schema.replace('NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY', 'INTEGER PRIMARY KEY')
        self.db.executescript(schema)
        p = self.c['parent_table']
        self.parent_key = self.buffer['key_bindings'][0]['parent_copy']['parent_column']
        self.parent_route = self.c['parent_route']['column']
        self.approval = next(f['column'] for b in args[2]['blocks'] for f in b['items'] if f['source_name'] == 'APPROVED')
        self.note = next(f['column'] for b in args[2]['blocks'] for f in b['items'] if f['source_name'] == 'UNEDITED_NOTE')
        self.db.execute(f'insert into {p}(FOX_ROW_ID,{self.parent_key},{self.parent_route},{self.approval}) values(1,?,?,?)', ('A', 'R1', None))
        self.db.execute(f'insert into {p}(FOX_ROW_ID,{self.parent_key},{self.parent_route},{self.approval}) values(2,?,?,?)', ('B', 'R2', None))
        self.row_id, self.baseline, self.base_route, self.rev = None, [None, None], None, 0
        self.draft = [None, None]
        self.db.commit()

    def sql(self, text, values):
        text = text.replace('utl_raw.cast_to_raw(', 'fox_raw(')
        text = re.sub(r'(?<!:)\bl_(?:value[0-9]+|base[0-9]+|parent|route|id|key)\b', lambda m: ':' + m[0], text)
        # Match Oracle's non-delimited concatenation: NULL contributes empty text.
        text = re.sub(r'(c\.F_[A-F0-9]+)(?=\s*\|\|)|(?<=\|\|)\s*(c\.F_[A-F0-9]+)',
                      lambda m: 'coalesce(' + (m[1] or m[2]) + ", '')", text)
        return self.db.execute(text, values)

    def save(self, value, *, revision=None, fail_after_write=False, draft_duplicate=False):
        # Uppercase models declared input casing. Oracle Unicode remains a target gate.
        value = value.upper() if value else None
        params = {'l_parent': 1, 'l_id': self.row_id, 'l_value1': 'A', 'l_value2': value,
                  'l_base1': self.baseline[0], 'l_base2': self.baseline[1], 'l_key': 'A' + (value or '')}
        self.db.execute('savepoint modeled_save')
        try:
            if revision is not None and revision != self.rev:
                raise ValueError('revision')
            approval = self.db.execute(f"select {self.c['policy_expression_sql']} from {self.c['parent_table']} where FOX_ROW_ID=1").fetchone()
            if approval != (1,):
                raise ValueError('policy/parent')
            key_check = re.search(r'select count\(\*\) into l_found from ' + self.c['parent_table'] + r' where (.*?);', self.code)[1]
            if self.sql(f"select count(*) from {self.c['parent_table']} where {key_check}", params).fetchone() != (1,):
                raise ValueError('ambiguous parent')
            if self.row_id is None and value is None:
                self.draft = ['A', None]
                self.rev += 1
                return 'empty'
            if self.row_id is not None:
                statement = re.search(r'select c.FOX_ROW_ID into l_found (.*?) for update nowait;', self.code, re.S)[1]
                params['l_base_route'] = self.base_route
                statement = statement.replace('l_base_route', ':l_base_route')
                if not self.sql('select c.FOX_ROW_ID ' + statement, params).fetchone():
                    raise ValueError('stale child')
            check = native_buffer._checks(self.buffer, 0)
            if self.sql('select case when ' + check + ' then 1 else 0 end', params).fetchone() == (1,):
                raise ValueError('length/required')
            duplicates = self.sql(f"select count(*) from {self.c['child_table']} c where (:l_id is null or c.FOX_ROW_ID<>:l_id) and {self.c['membership_sql']} and {self.c['duplicate_key_sql']}", params).fetchone()[0]
            if draft_duplicate or duplicates:
                raise ValueError('duplicate')
            dirty = re.search(r'select case when (.*?) then 1 else 0 end into l_changed from dual;', self.code)[1]
            if self.sql('select case when ' + dirty + ' then 1 else 0 end', params).fetchone() == (0,):
                self.draft = ['A', value]
                self.rev += 1
                return 'unchanged'
            params['l_route'] = self.db.execute(f"select {self.parent_route} from {self.c['parent_table']} where FOX_ROW_ID=1").fetchone()[0]
            check = re.search(r'if ([^;\n]*?) then raise_application_error\(-20026', self.code)[1]
            if self.sql('select case when ' + check + ' then 1 else 0 end', params).fetchone() == (1,):
                raise ValueError('route length')
            if self.row_id is None:
                query = self.c['insert_sql'].replace(' into l_id;', ';')
                row_id = self.sql(query, params).fetchone()[0]
            else:
                self.sql(self.c['update_sql'], params)
                row_id = self.row_id
            if fail_after_write:
                raise ValueError('reconciliation failed')
            self.row_id, self.baseline, self.base_route = row_id, ['A', value], params['l_route']
            self.draft = ['A', value]
            self.rev += 1
            return 'saved'
        except Exception:
            self.db.execute('rollback to modeled_save')
            raise
        finally:
            self.db.execute('release modeled_save')

    def rows(self):
        return self.db.execute(f"select * from {self.c['child_table']} order by FOX_ROW_ID").fetchall()

    def route(self, value):
        self.db.execute(f"update {self.c['parent_table']} set {self.parent_route}=? where FOX_ROW_ID=1", (value,))


def test_emitted_sql_inserts_updates_copies_fresh_parent_including_null_and_retries():
    h = SqlBoundary()
    assert h.save('bag1') == 'saved'
    assert h.row_id == 1 and h.rev == 1 and h.baseline == ['A', 'BAG1']
    old = h.rows()
    with pytest.raises(ValueError, match='revision'):
        h.save('bag1', revision=0)
    assert h.rows() == old
    h.route('R-new')
    assert h.save('bag1') == 'unchanged' and h.base_route == 'R1'
    assert h.rows() == old  # parent route change alone cannot update a child
    assert h.save('bag2') == 'saved' and h.base_route == 'R-new'
    h.route(None)
    assert h.save('bag3') == 'saved' and h.base_route is None
    assert h.save('bag3') == 'unchanged' and len(h.rows()) == 1


@pytest.mark.parametrize('blank', [None, ''])
def test_empty_new_placeholder_has_no_insert_even_with_inherited_parent_key(blank):
    h = SqlBoundary()
    assert h.save(blank) == 'empty' and h.rows() == [] and h.row_id is None and h.rev == 1
    assert h.save(' ') == 'saved'  # source whitespace is meaningful input


@pytest.mark.parametrize('failure', ['approved', 'missing_parent', 'ambiguous_parent', 'child_changed', 'child_deleted', 'reparented', 'route_changed', 'revision', 'duplicate', 'draft_duplicate', 'rollback', 'too_long', 'route_too_long'])
def test_failure_paths_preserve_persistent_data_and_loaded_baselines(failure):
    h = SqlBoundary()
    assert h.save('first') == 'saved'
    c, db = h.c, h.db
    table, parent = c['child_table'], c['parent_table']
    bag = c['fields'][1]['column']
    key = c['fields'][0]['column']
    if failure == 'approved':
        db.execute(f'update {parent} set {h.approval}=? where FOX_ROW_ID=1', ('Y',))
    elif failure == 'missing_parent':
        db.execute(f'delete from {parent} where FOX_ROW_ID=1')
    elif failure == 'ambiguous_parent':
        db.execute(f'update {parent} set {h.parent_key}=? where FOX_ROW_ID=2', ('A',))
    elif failure in ('child_changed', 'reparented', 'route_changed'):
        column = {'child_changed': bag, 'reparented': key, 'route_changed': c['route']['column']}[failure]
        db.execute(f'update {table} set {column}=? where FOX_ROW_ID=1', ('elsewhere',))
    elif failure == 'child_deleted':
        db.execute(f'delete from {table} where FOX_ROW_ID=1')
    elif failure == 'duplicate':
        db.execute(f'insert into {table}({key},{bag}) values(?,?)', ('A', 'SECOND'))
    elif failure == 'route_too_long':
        h.route('é' * 11)  # explicit BYTE length 22 > 20
    before, state = h.rows(), (h.row_id, deepcopy(h.baseline), h.base_route, h.rev)
    kwargs = {'revision': 0} if failure == 'revision' else {'fail_after_write': True} if failure == 'rollback' else {'draft_duplicate': True} if failure == 'draft_duplicate' else {}
    with pytest.raises(ValueError):
        h.save('x' * 17 if failure == 'too_long' else 'second', **kwargs)
    assert h.rows() == before
    assert (h.row_id, h.baseline, h.base_route, h.rev) == state


def test_unprojected_fields_siblings_and_other_parent_records_survive():
    h = SqlBoundary()
    h.save('first')
    table = h.c['child_table']
    key, bag = [f['column'] for f in h.c['fields']]
    h.db.execute(f'update {table} set {h.note}=? where FOX_ROW_ID=1', ('preserve me',))
    h.db.execute(f'insert into {table}({key},{bag}) values(?,?)', ('A', 'SIBLING'))
    h.db.execute(f'insert into {table}({key},{bag}) values(?,?)', ('B', 'SECOND'))
    before = h.rows()[1:]
    h.save('second')  # same bag under another parent is allowed
    assert h.rows()[1:] == before
    assert h.db.execute(f'select {h.note} from {table} where FOX_ROW_ID=1').fetchone() == ('preserve me',)
    assert 'delete from' not in h.code.lower()
    assert key + '=' not in h.c['update_sql']


@pytest.mark.parametrize('part', ['source', 'trace', 'schema', 'page', 'policy_receipt', 'assignment', 'review_sql'])
def test_mutated_source_or_package_proof_cannot_add_a_save(part):
    docs = source()
    args = list(prepare(docs))
    files = dict(args[-1])
    if part == 'source':
        files['fox-package/sources/' + docs[0][0]] += b' '
    elif part == 'trace':
        args[2] = deepcopy(args[2])
        args[2]['blocks'][0]['table_name'] = 'CUSTOMER_TABLE'
    elif part == 'schema':
        files['fox-package/supporting-schema.sql'] = files['fox-package/supporting-schema.sql'].replace(b'IDENTITY PRIMARY KEY', b'IDENTITY')
    elif part == 'page':
        path = json.loads(files['fox-package/buffer-receipt.json'])['generated_operations'][0]['page_file']
        files[path] = files[path].replace(b'if not context_ok', b'if false')
    elif part == 'policy_receipt':
        r = json.loads(files['fox-package/draft-policy-receipt.json'])
        r['adapted_operations'][0]['policy_expression_sql'] = '1'
        files['fox-package/draft-policy-receipt.json'] = json.dumps(r).encode()
    elif part == 'assignment':
        r = json.loads(files['fox-package/assignment-plan.json'])
        r['operations'][0]['source_ref']['column'] = 'UNKNOWN'
        files['fox-package/assignment-plan.json'] = json.dumps(r).encode()
    else:
        files[native_assignments.CODE_MEMBER] += b'\n'
    args[-1] = files
    before = deepcopy(files)
    with pytest.raises(ValueError):
        apply_synthetic_saves(docs, *args)
    assert files == before


@pytest.mark.parametrize('change,reason', [('missing_update', 'COMPLETE_INSERT_UPDATE_PAIR_REQUIRED'),
                                          ('no_policy', 'AUTHORITATIVE_DRAFT_POLICY_REQUIRED'),
                                          ('route_type', 'COPY_TYPE')])
def test_missing_write_event_or_guard_or_type_leaves_gap_and_unchanged_page(change, reason):
    docs = source(**{change: 'Number' if change == 'route_type' else True})
    files, receipt, args = apply(docs)
    assert files == args[-1] and receipt['converted_code_unit_count'] == 0
    assert receipt['gaps'] and all(reason in row['reason'] for row in receipt['gaps'])
    assert not receipt['generated_operations']


def test_dirty_detection_and_baseline_comparisons_use_sql_null_safe_binary_equality():
    code, _, _, _, _, _ = generated()
    assert 'l_changed boolean' not in code
    statement = re.search(r'select case when .*? into l_changed from dual;', code)[0]
    assert 'decode(utl_raw.cast_to_raw(l_value2),utl_raw.cast_to_raw(l_base2),1,0)' in statement
    assert code.index('if l_changed=1 then') < code.index('select ' + generated()[1]['parent_route']['column'] + ' into l_route')
    assert 'trim(' not in code.lower()
    assert 'No synthetic record saved: the current record has no changes.' in code
    assert 'No synthetic record saved: the new draft is empty.' in code


def test_unchanged_save_reconciles_a_previously_kept_draft_without_rewriting_row_or_baseline():
    h = SqlBoundary()
    h.save('A')
    before = h.rows(), deepcopy(h.baseline), h.base_route
    h.draft = ['A', 'B']  # Keep stored B in the collection, DB baseline is A.
    assert h.save('A') == 'unchanged'
    assert h.draft == ['A', 'A']
    assert (h.rows(), h.baseline, h.base_route) == before
    code = h.code
    current_update = 'p_seq=>l_seq,p_attr_number=>2,p_attr_value=>l_value2'
    assert code.count(current_update) == 2  # empty and successful normal paths
    dirty_end = code.index('  end if;\n  apex_collection.update_member_attribute', code.index('if l_changed=1 then'))
    assert current_update in code[dirty_end:code.index('exception when others then', dirty_end)]
    assert 'p_attr_number=>22' not in code[dirty_end:code.index('exception when others then', dirty_end)]


def test_empty_new_save_reconciles_kept_input_and_skips_required_editable_validation():
    h = SqlBoundary(required=True)
    h.draft = ['A', 'STALE KEPT INPUT']
    assert h.save(None) == 'empty'
    assert h.draft == ['A', None] and h.rows() == [] and h.row_id is None
    assert h.baseline == [None, None]
    assert h.code.index('the new draft is empty.') < h.code.index("raise_application_error(-20023")
    empty_path = h.code[h.code.index('    if l_value2 is null then'):h.code.index('      return;')]
    assert 'p_attr_number=>2,p_attr_value=>l_value2' in empty_path
    assert 'p_attr_number=>22' not in empty_path and 'insert into' not in empty_path
    _, _, _, files, receipt, _ = generated(source(required_editable=True))
    page = files[receipt['generated_operations'][0]['page_file']].decode()
    button = re.search(r'button save-synthetic-record \(.*?\n    \)', page, re.S)[0]
    assert 'executeValidations: false' in button
    assert 'valueRequired: true' in page and 'Required value or source length is invalid.' in page
    assert h.save('entered') == 'saved'
    with pytest.raises(ValueError, match='required'):
        h.save(None)  # clearing a persisted required field remains invalid


def test_clearing_optional_editable_field_is_an_update_and_preserves_oracle_null():
    h = SqlBoundary()
    h.save('entered')
    h.route(None)
    assert h.save('') == 'saved'
    assert h.baseline == ['A', None] and h.base_route is None
    assert h.save(None) == 'unchanged' and len(h.rows()) == 1
