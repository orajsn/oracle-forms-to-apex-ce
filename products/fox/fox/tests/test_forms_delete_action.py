"""Actual disposable-row SQL checks; these do not claim Oracle/APEX execution."""
from copy import deepcopy
import hashlib
import re
import sqlite3

import pytest

from fox.forms_delete_action import _context, _provider, _queries, _shell, COLLECTION
from fox.forms_delete_action import apply_delete_actions


def field(name, block):
    return dict(column=name, source_name=name, source_item_id=block + '-' + name,
                source_block_id=block, data_type='VARCHAR2')


def fixture(kind='master_existence_guard'):
    h = dict(source_block_id='h', table_name='HEADERS', items=[field('HKEY', 'h'), field('STATUS', 'h')])
    b = dict(source_block_id='b', table_name='BAGS', items=[field('PARENT', 'b'), field('BKEY', 'b')])
    n = dict(source_block_id='n', table_name='NOTES', items=[field('HPARENT', 'n'), field('BPARENT', 'n'), field('NKEY', 'n')])
    edges = [dict(parent_block_id='h', child_block_id='b', join_pairs=[dict(parent_column='HKEY', child_column='PARENT')]),
             dict(parent_block_id='b', child_block_id='n', join_pairs=[dict(parent_column='PARENT', child_column='HPARENT'),
                                                                    dict(parent_column='BKEY', child_column='BPARENT')])]
    target = h if kind == 'master_existence_guard' else b
    op = dict(kind=kind, source_unit_id='unit', source_unit_sha256='a' * 64,
              source_module_id='module', operation_id='delete-unit', parsed={'messages': ['Deletion refused', 'Deletion refused'], 'permission_call': {'qualified_name': 'EXTERNAL.CHECK', 'arguments': [':BKEY']}},
              contract=dict(block=target, fields=target['items'], permission_argument=target['items'][-1],
                            delete_policy=dict(static_value=False if kind == 'master_existence_guard' else True, dynamic_setters=[]),
                            existence_guard=dict(child_block=b, predicates=[dict(child_field=b['items'][0], parent_field=h['items'][0])])) )
    return op, {'source_binding': 'b' * 64}, {'operations': []}, {x['source_block_id']: x for x in (h, b, n)}, edges


class Rows:
    def __init__(self, kind='master_existence_guard'):
        self.args = fixture(kind)
        self.q = _queries(*self.args, 8701)
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.create_function('nvl', 2, lambda a, b: b if a is None else a)
        self.db.create_function('standard_hash', 2, lambda v, a: None if v is None else hashlib.sha256(str(v).encode()).digest())
        self.db.create_function('rawtohex', 1, lambda v: None if v is None else v.hex().upper())
        self.db.create_function('to_char', 1, str)
        self.db.create_function('chr', 1, chr)
        self.db.executescript('''create table HEADERS(FOX_ROW_ID integer primary key,HKEY text,STATUS text);
          create table BAGS(FOX_ROW_ID integer primary key,PARENT text,BKEY text);
          create table NOTES(FOX_ROW_ID integer primary key,HPARENT text,BPARENT text,NKEY text);
          create table apex_collections(collection_name text,c001 text,c002 text,c003 text,c004 text,c005 text,
            c007 text,c008 text,c009 text,c010 text,n001 numeric,n002 numeric,d001 numeric);
          insert into HEADERS values(1,'H1','OPEN'),(2,'H2','OPEN'),(3,'EMPTY','OPEN');
          insert into BAGS values(11,'H1','SAME'),(12,'H2','SAME');
          insert into NOTES values(21,'H1','SAME','ONE'),(22,'H2','SAME','TWO'),(23,'H2','OTHER','THREE');''')

    def params(self, row):
        choices = self.db.execute(self.q['chooser_query_sql']).fetchall()
        token = next((r['FOX_MASTER_TOKEN'] for r in choices if r['FOX_ROW_ID'] == row), 'missing')
        return {'P8701_PARENT_ID': row, 'P8701_TOKEN': token, 'APP_ID': 7, 'APP_USER': 'tester', 'NOW': 100}

    def rows(self, row, **overrides):
        params = {**self.params(row), **overrides}
        # Oracle DATE arithmetic model: one numeric day is one date unit.
        return self.db.execute(self.q['preflight_query_sql'].replace('sysdate', ':NOW'), params).fetchall()

    def provider(self, row=11, status='RETURNED', value=0, age=0, **changes):
        op, packet = self.args[:2]
        p = self.params(row)
        _, source, where, _ = _context(op['contract']['block'], self.args[-1], self.args[-2])
        arg = self.db.execute('select ' + self.q['argument_fingerprint_sql'] + ' from ' + source
                              + ' where ' + where + ' and p.FOX_ROW_ID=?', (row,)).fetchone()[0]
        slots = dict(collection_name=COLLECTION, c001=packet['source_binding'], c002=op['operation_id'],
                     c003=p['P8701_TOKEN'], c004=arg, c005=status, c007=op['source_unit_sha256'],
                     c008='7', c009='tester', c010=self.q['provider_contract']['call_sha256'],
                     n001=value, n002=row, d001=100-age)
        slots.update(changes)
        self.db.execute('insert into apex_collections(' + ','.join(slots) + ') values ('
                        + ','.join('?' for _ in slots) + ')', list(slots.values()))


def test_declared_no_delete_permission_is_independent_of_matching_children():
    b = Rows()
    first, = b.rows(1)
    empty, = b.rows(3)
    assert (first['MATCHING_CHILDREN'], first['GUARD_VALUE']) == (1, 1)
    assert (empty['MATCHING_CHILDREN'], empty['GUARD_VALUE']) == (0, 0)
    assert first['PREFLIGHT_STATE'] == empty['PREFLIGHT_STATE'] == 'POLICY_DENIED'
    assert not b.rows(999) and not b.rows(1, P8701_TOKEN='stale')


def test_bag_scope_uses_composite_child_relation_and_current_parent_context():
    b = Rows('key_delete')
    before = b.db.total_changes
    row, = b.rows(11)
    assert row['MATCHING_CHILDREN'] == 1 and row['PREFLIGHT_STATE'] == 'GUARD_UNAVAILABLE'
    assert b.db.total_changes == before
    assert 'c.HPARENT=p.PARENT and c.BPARENT=p.BKEY' in b.q['preflight_query_sql']
    old = b.params(11)
    b.db.execute("update HEADERS set STATUS='CLOSED' where FOX_ROW_ID=1")
    assert not b.rows(11, **old)
    b.db.execute("insert into HEADERS values(4,'H1','OTHER')")
    assert not b.rows(11)


@pytest.mark.parametrize('status,value,outcome,state', [
    ('RETURNED', 1, 'RETURNED', 'SOURCE_REFUSAL'),
    ('RETURNED', 0, 'RETURNED', 'PENDING_AUDIT_TRANSACTION_AND_SCOPE'),
    ('RETURNED', -1, 'RETURNED', 'PENDING_AUDIT_TRANSACTION_AND_SCOPE'),
    ('RETURNED_NULL', None, 'RETURNED_NULL', 'PENDING_AUDIT_TRANSACTION_AND_SCOPE'),
    ('ERROR', None, 'ERROR', 'GUARD_ERROR'),
    ('RETURNED', None, 'INVALID', 'GUARD_INVALID'),
    ('RETURNED_NULL', 0, 'INVALID', 'GUARD_INVALID'),
])
def test_exact_server_permission_outcome_preserves_gt_zero_and_sql_null(status, value, outcome, state):
    b = Rows('key_delete')
    b.provider(status=status, value=value)
    before = b.db.total_changes
    row, = b.rows(11)
    assert (row['GUARD_OUTCOME'], row['PREFLIGHT_STATE']) == (outcome, state)
    assert 'No rows marked or deleted' in row['TRANSACTION_STATUS']
    assert b.db.total_changes == before


@pytest.mark.parametrize('changes', [dict(c001='foreign'), dict(c002='foreign'), dict(c003='stale'),
    dict(c004='other-argument'), dict(c007='foreign-source'), dict(c008='8'), dict(c009='other-user'),
    dict(c010='other-call'), dict(n002=12), dict(d001=99), dict(d001=101)])
def test_provider_identity_argument_source_app_user_time_are_all_required(changes):
    b = Rows('key_delete')
    b.provider(**changes)
    row, = b.rows(11)
    assert row['PREFLIGHT_STATE'] == 'GUARD_UNAVAILABLE'


def test_duplicate_provider_result_is_ambiguous_and_current_policy_still_wins():
    b = Rows('key_delete')
    b.provider(value=0)
    b.provider(value=0)
    row, = b.rows(11)
    assert row['PREFLIGHT_STATE'] == 'GUARD_AMBIGUOUS'
    args = deepcopy(b.args)
    args[0]['contract']['delete_policy']['static_value'] = False
    b.q = _queries(*args, 8701)
    row, = b.rows(11)
    assert row['PREFLIGHT_STATE'] == 'POLICY_DENIED'


def test_no_mutation_or_browser_permission_entry_point_is_generated():
    b = Rows('key_delete')
    sql = re.sub(r"'(?:''|[^'])*'", ' ', b.q['preflight_query_sql'])
    assert not re.search(r'\b(insert|update|delete|commit|rollback)\b', sql, re.I)
    assert ':P8701_ALLOWED' not in sql and ':P8701_RESULT' not in sql
    page = _shell(8701, '').decode()
    assert 'pageAccessProtection: argumentsMustHaveChecksum' in page
    assert 'type: executeCode' not in page and 'formAutomaticRowProcessing' not in page


def test_note_context_keeps_both_composite_ancestors_and_rejects_ambiguous_parent():
    args = list(fixture('key_delete'))
    args[0]['contract']['block'] = args[-2]['n']
    args[0]['contract']['fields'] = args[-2]['n']['items']
    args[0]['contract']['permission_argument'] = args[-2]['n']['items'][-1]
    b = Rows('key_delete')
    b.args = tuple(args)
    b.q = _queries(*b.args, 8701)
    row, = b.rows(21)
    assert row['MATCHING_CHILDREN'] == 0 and row['PREFLIGHT_STATE'] == 'GUARD_UNAVAILABLE'
    b.db.execute("insert into BAGS values(13,'H1','SAME')")
    assert not b.rows(21)


@pytest.mark.parametrize('renamed', [False, True])
def test_fresh_complete_source_wires_only_executable_preflight_and_preserves_originals(renamed):
    import json
    from test_forms_delete_plan import source, prepare
    args = prepare(source(renamed=renamed))
    before = deepcopy(args)
    output, receipt = apply_delete_actions(*args)
    assert args == before
    assert (output, receipt) == apply_delete_actions(*args)
    assert len(receipt['adapted_operations']) == 3, receipt['gaps']
    assert not receipt['generated_operations'] and receipt['converted_code_unit_count'] == 0
    assert all(not receipt[k] for k in ('customer_table_writes', 'synthetic_table_writes',
        'external_calls_enabled', 'original_reads_enabled', 'forms_commit_implemented',
        'oracle_compiled', 'runtime_verified', 'business_accepted'))
    assert len(json.loads(output['fox-package/delete-plan.json'])['operations']) == 5
    for op in receipt['adapted_operations']:
        assert op['whole_source_unit_converted'] is False and op['source_event_partially_connected']
        assert not op['row_marking_implemented'] and not op['pre_delete_executed']
        assert op['source_unit_id'] and len(op['source_unit_sha256']) == 64
        page = output[op['page_file']].decode()
        assert page.count('checksumRequiredSessionLevel') == 2
        assert 'pageAccessProtection: argumentsMustHaveChecksum' in page
        assert 'type: executeCode' not in page
        assert 'Check delete requirements' in output[op['entry_file']].decode()
        assert 'SOURCE_MESSAGES' in page and 'RELATION_CHECK' in page
        assert len(op['preflight_query_sql'].encode()) <= 32767
    assert all(output['fox-package/sources/' + name] == raw for name, raw in args[0])


def test_no_delete_units_is_a_noop_with_an_explicit_empty_source_plan():
    from test_forms_synthetic_save import source, prepare
    docs = source()
    args = prepare(docs)
    output, receipt = apply_delete_actions(docs, *args)
    assert not receipt['adapted_operations'] and not receipt['gaps']
    assert all(output[n] == v for n, v in args[-1].items())
