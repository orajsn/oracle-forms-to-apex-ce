"""Source and emitted SQL checks; these are not Oracle/APEX runtime acceptance."""
from copy import deepcopy
import json
import re
import textwrap
from xml.etree import ElementTree as ET

import pytest

from fox.forms_detail_clear import (apply_detail_clear, recognize_clear_sources,
    ordered_relation_tree, first_changed_block, clear_intent, draft_status,
    _save_providers, _inspect_buffer_sql, _dirty_sql, _gate_code)
from fox.forms_master_detail import apply_master_details
from fox.forms_understanding_packet import _build
from test_forms_master_detail import (source as population_source,
    prepare as population_prepare, SQLBoundary)


# An independently named, complete Forms helper example. Production grammar is
# deliberately not imported as test source. All four cursor failure checks and
# exception restoration must survive recognition.
CLEAR_HELPER = '''PROCEDURE RESET_DETAILS IS
 leader VARCHAR2(30); action VARCHAR2(30); eventblock VARCHAR2(30);
 original_item VARCHAR2(61); formstate VARCHAR2(15); childblock VARCHAR2(30);
 relation_name VARCHAR2(30); detailblock VARCHAR2(30);
 FUNCTION FIND_DIRTY(ancestor VARCHAR2) RETURN VARCHAR2 IS
 childblock VARCHAR2(30); relation_name VARCHAR2(30); foundblock VARCHAR2(30);
 BEGIN
 childblock := ancestor;
 relation_name := Get_Block_Property(childblock,FIRST_MASTER_RELATION);
 WHILE relation_name IS NOT NULL LOOP
  childblock := Get_Relation_Property(relation_name,DETAIL_NAME);
  IF (Get_Block_Property(childblock,STATUS) = 'CHANGED') THEN
   RETURN childblock;
  ELSE
   foundblock := FIND_DIRTY(childblock);
   IF foundblock IS NOT NULL THEN RETURN foundblock;
   ELSE relation_name := Get_Relation_Property(relation_name,NEXT_MASTER_RELATION);
   END IF;
  END IF;
 END LOOP;
 RETURN NULL;
 END FIND_DIRTY;
 BEGIN
 leader := :System.Master_Block;
 action := :System.Coordination_Operation;
 eventblock := :System.Trigger_Block;
 original_item := :System.Cursor_Item;
 formstate := :System.Form_Status;
 IF action NOT IN ('CLEAR_RECORD','SYNCHRONIZE_BLOCKS') THEN
  IF leader = eventblock THEN
   IF formstate = 'CHANGED' THEN
    childblock := FIND_DIRTY(leader);
    IF childblock IS NOT NULL THEN
     Go_Block(childblock); ASSERT_OK; Clear_Block(ASK_COMMIT);
     IF NOT (:System.Form_Status = 'QUERY' OR :System.Block_Status = 'NEW') THEN
      RAISE Form_Trigger_Failure;
     END IF;
    END IF;
   END IF;
  END IF;
 END IF;
 relation_name := Get_Block_Property(eventblock,FIRST_MASTER_RELATION);
 WHILE relation_name IS NOT NULL LOOP
  detailblock := Get_Relation_Property(relation_name,DETAIL_NAME);
  IF Get_Block_Property(detailblock,STATUS) <> 'NEW' THEN
   Go_Block(detailblock); ASSERT_OK; Clear_Block(NO_VALIDATE);
   IF :System.Block_Status <> 'NEW' THEN RAISE Form_Trigger_Failure; END IF;
  END IF;
  relation_name := Get_Relation_Property(relation_name,NEXT_MASTER_RELATION);
 END LOOP;
 IF :System.Cursor_Item <> original_item THEN Go_Item(original_item); ASSERT_OK; END IF;
 EXCEPTION WHEN Form_Trigger_Failure THEN
 IF :System.Cursor_Item <> original_item THEN Go_Item(original_item); END IF;
 RAISE;
 END RESET_DETAILS;'''


def source(*, renamed=False, clear=CLEAR_HELPER, caller='BEGIN RESET_DETAILS; END;', deferred=False):
    root = ET.fromstring(population_source(renamed=renamed)[0][1])
    if deferred:
        next(root.iter('Relation')).set('Deferred', 'true')
    next(t for t in root.iter('Trigger') if t.get('Name') == 'ON-CLEAR-DETAILS').set('TriggerText', caller)
    if renamed:
        clear = clear.replace('ASSERT_OK', 'REQUIRE_SUCCESS')
    ET.SubElement(root, 'ProgramUnit', Name='RESET_DETAILS', ProgramUnitType='Procedure', ProgramUnitText=clear)
    return [('clear-cargo.xml', ET.tostring(root))]


def prepare(docs=None):
    args = population_prepare(docs or source())
    files, receipt = apply_master_details(*args)
    files['fox-package/master-detail-receipt.json'] = json.dumps(receipt).encode()
    return (*args[:-1], files)


@pytest.mark.parametrize('renamed', [False, True])
def test_complete_source_proof_and_reachable_scope_preserve_all_other_pages(renamed):
    args = prepare(source(renamed=renamed))
    before = deepcopy(args)
    out, receipt = apply_detail_clear(*args)
    assert args == before and (out, receipt) == apply_detail_clear(*args)
    op, = receipt['adapted_operations']
    assert {n for n in out if out[n] != before[-1][n]} == {op['page_file']}
    text = out[op['page_file']].decode()
    assert all(label in text for label in ('label: Save', 'label: "Discard"', 'label: "Cancel"'))
    assert 'resolve-detail-changes' in text and 'show-selected-master-after-clear' in text
    assert 'Full form commit and other descendant providers remain pending' in text
    assert 'Unknown descendants are retained' in text and 'DETAIL_CHANGES_PENDING' in text
    assert receipt['generated_operations'] == [] and receipt['converted_code_unit_count'] == 0
    assert all(not receipt[k] for k in ('customer_table_writes', 'synthetic_table_writes',
        'database_rows_deleted', 'oracle_compiled', 'runtime_verified', 'business_accepted'))
    assert any(g['reason'] == 'DETAIL_CLEAR_DESCENDANT_SESSION_PROVIDER_UNAVAILABLE' for g in receipt['gaps'])
    assert all(model[k] for model in receipt['helper_models'] for k in
        ('source_unit_id', 'caller_source_unit_id', 'failure_source_unit_id', 'ordered_relation_tree'))
    assert out['fox-package/sources/' + args[0][0][0]] == args[0][0][1]


@pytest.mark.parametrize('old,new', [
    ('action NOT IN', 'action IN'),
    ('leader = eventblock', 'leader <> eventblock'),
    ('Go_Block(childblock); ASSERT_OK;', 'Go_Block(childblock);'),
    ('Clear_Block(ASK_COMMIT)', 'Clear_Block(NO_VALIDATE)'),
    ("<> 'NEW'", "= 'NEW'"),
    ('Go_Item(original_item); END IF;\n RAISE;', 'NULL; END IF;\n RAISE;'),
    ('END RESET_DETAILS;', 'END RESET_DETAILS; COMMIT;'),
])
def test_partial_or_changed_clear_helper_does_not_authorize_hook(old, new):
    assert old in CLEAR_HELPER
    docs = source(clear=CLEAR_HELPER.replace(old, new))
    packet, chunks = _build(docs)
    models, gaps = recognize_clear_sources(docs, packet, chunks)
    assert not models and gaps


@pytest.mark.parametrize('caller', ['RESET_DETAILS;', 'BEGIN RESET_DETAILS; NULL; END;',
                                    'BEGIN MISSING; END;'])
def test_only_complete_local_caller_authorizes_helper(caller):
    docs = source(caller=caller)
    packet, chunks = _build(docs)
    models, gaps = recognize_clear_sources(docs, packet, chunks)
    assert not models and gaps


def test_block_override_prevents_assuming_module_clear_caller_runs():
    root = ET.fromstring(source()[0][1])
    block = next(b for b in root.iter('Block') if b.get('Name') == 'LOADS')
    ET.SubElement(block, 'Trigger', Name='ON-CLEAR-DETAILS', TriggerText='UNKNOWN_CLEAR;')
    args = prepare([('override.xml', ET.tostring(root))])
    out, receipt = apply_detail_clear(*args)
    assert out == args[-1] and not receipt['adapted_operations']
    assert any(g['reason'] == 'DETAIL_CLEAR_APPLICABLE_TRIGGER_OVERRIDE_UNRESOLVED' for g in receipt['gaps'])


def test_rejects_changed_sources_chunks_baseline_proof_and_save_process():
    args = prepare()
    changed = deepcopy(args)
    changed[2][0]['text'] += ' NULL;'
    with pytest.raises(ValueError, match='FRESH_SOURCE_REQUIRED'):
        apply_detail_clear(*changed)
    # Enriched normal-pipeline packet fields do not change source authority.
    enriched = deepcopy(args)
    enriched[1]['processing_approval'] = {'granted': True}
    assert apply_detail_clear(*enriched)[1]['adapted_operations']
    for member in ('fox-package/synthetic-save-receipt.json',):
        changed = deepcopy(args)
        changed[-1][member] = b'{"write_contracts":[]}'
        out, receipt = apply_detail_clear(*changed)
        assert out == changed[-1] and not receipt['adapted_operations']
    changed = deepcopy(args)
    save = json.loads(changed[-1]['fox-package/synthetic-save-receipt.json'])
    page = save['generated_operations'][0]['page_file']
    changed[-1][page] = changed[-1][page].replace(b'Synthetic save failed:', b'Unproved save failed:')
    out, receipt = apply_detail_clear(*changed)
    assert out == changed[-1] and not receipt['adapted_operations']


def test_recursive_first_changed_uses_source_order_before_next_sibling():
    tree = {'root': [{'child_block_id': 'z-first'}, {'child_block_id': 'a-next'}],
            'z-first': [{'child_block_id': 'grandchild'}]}
    statuses = {'z-first': 'QUERY', 'grandchild': 'CHANGED', 'a-next': 'CHANGED'}
    assert first_changed_block(tree, 'root', statuses) == 'grandchild'
    statuses['z-first'] = 'CHANGED'
    assert first_changed_block(tree, 'root', statuses) == 'z-first'
    statuses['z-first'] = statuses['grandchild'] = 'NEW'
    assert first_changed_block(tree, 'root', statuses) == 'a-next'
    del statuses['grandchild']
    with pytest.raises(ValueError, match='KNOWN_DESCENDANT'):
        first_changed_block(tree, 'root', statuses)


@pytest.mark.parametrize('operation,driving,triggering,form,ask', [
    ('SELECT_MASTER', 'root', 'root', 'CHANGED', True),
    ('CLEAR_RECORD', 'root', 'root', 'CHANGED', False),
    ('SYNCHRONIZE_BLOCKS', 'root', 'root', 'CHANGED', False),
    ('SELECT_MASTER', 'other', 'root', 'CHANGED', False),
    ('SELECT_MASTER', 'root', 'root', 'QUERY', False),
])
def test_source_ask_skip_rules_never_grant_implicit_dirty_discard(operation, driving, triggering, form, ask):
    tree = {'root': [{'child_block_id': 'child'}, {'child_block_id': 'empty'}]}
    result = clear_intent(tree, driving, triggering, operation, form, {'child': 'CHANGED', 'empty': 'NEW'})
    assert result['ask'] is ask and result['direct_clear_block_ids'] == ['child']
    assert result['requires_explicit_discard'] and not result['database_rows_deleted']


def test_current_noncurrent_new_changed_clean_and_baselines_are_distinct():
    fields = [{'parent_copy': {'parent_column': 'key'}}, {}]
    rows = [dict(seq_id=2, persisted_id=11, values=['A', 'one'], baseline=['A', 'one'], marker='SYNTHETIC_SAVE_BASELINE_V1'),
            dict(seq_id=3, persisted_id=None, values=['A', None])]
    assert draft_status(rows, fields, 2)['status'] == 'QUERY'
    assert draft_status(rows, fields, 2, submitted=['A', 'changed']) == {
        'status': 'CHANGED', 'changed_seq_ids': [2], 'current_changed': True}
    rows[1]['values'][1] = 'noncurrent insert'
    assert draft_status(rows, fields, 2)['changed_seq_ids'] == [3]
    assert not draft_status(rows, fields, 2)['current_changed']
    assert draft_status([dict(seq_id=2, persisted_id=None, values=['A', None])], fields, 2)['status'] == 'NEW'
    rows[0]['marker'] = None
    with pytest.raises(ValueError, match='PERSISTED_BASELINE_REQUIRED'):
        draft_status(rows, fields, 2)
    with pytest.raises(ValueError, match='STALE_REVISION'):
        draft_status(rows, fields, 2, revision=3, expected_revision=2)


def test_source_tree_declaration_order_and_cycle_failure():
    docs = source()
    packet, chunks = _build(docs)
    models, _ = recognize_clear_sources(docs, packet, chunks)
    tree = ordered_relation_tree(docs, packet, models[0]['source_module_id'])
    root_id = next(b for b in tree if len(tree) == 2 and tree[b][0]['child_block_id'] in tree)
    assert tree[tree[root_id][0]['child_block_id']][0]['child_block_id'] not in tree
    root = ET.fromstring(docs[0][1])
    parent = next(b for b in root.iter('Block') if b.get('Name') == 'LOADS')
    last = next(b for b in root.iter('Block') if b.get('Name') == 'SCANS')
    ET.SubElement(last, 'Relation', Name='LOOP_BACK', DetailBlock=parent.get('Name'))
    cycle_docs = [('cycle.xml', ET.tostring(root))]
    cycle_packet, _ = _build(cycle_docs)
    module = next(o['module_id'] for s in cycle_packet['sources'] for o in s['facts']['objects'] if o['kind'] == 'Relation')
    with pytest.raises(ValueError, match='ACYCLIC'):
        ordered_relation_tree(cycle_docs, cycle_packet, module)


def test_emitted_gate_orders_prompt_population_clear_and_restores_on_failure():
    args = prepare()
    providers = _save_providers(*args)
    population = json.loads(args[-1]['fox-package/master-detail-receipt.json'])
    op = next(o for o in population['adapted_operations'] if o['parent_block_id'] == providers[0]['buffer']['relation']['parent_block_id'])
    code = _gate_code(op, providers)
    assert code.index('savepoint fox_detail_clear') < code.index("if :REQUEST='FOX_CLEAR_CANCEL'")
    discard = 'apex_collection.delete_collection(l_names(i))'
    assert code.index('l_revisions<>l_expected') < code.index(discard)
    assert code.index('if l_dirty>0') < code.index(discard)
    assert code.index('Previous master and session drafts retained.') < code.index(discard)
    assert 'rollback to fox_detail_clear;\nrestore_selection;' in code
    assert 'for update nowait' in code and 'l_count>0 or l_persisted>0' in code
    assert "l_names(1):=null" in code  # Source NEW buffers are skipped.
    assert 'record ' in code and 'Save each changed record' in code
    assert 'CLEAR_TICKET<>l_ticket' in code and 'rawtohex(sys_guid())' in code
    assert not re.search(r'\b(?:insert into|delete from|update FOX_NATIVE_|commit\s*;)', code, re.I)
    assert 'c.c001' not in code and 'c041' in code
    assert 'procedure populate is begin declare ' in code
    assert 'procedure populate is declare ' not in code
    assert 'end; end;\nprocedure restore_selection is begin' in code
    out, receipt = apply_detail_clear(*args)
    text = out[receipt['adapted_operations'][0]['page_file']].decode()
    assert 'sessionStorage' in text and 'document.getElementById' in text
    assert text.count('savepoint fox_detail_clear') == 2  # GET and native submit.
    assert 'type: pageOrUrl\n' in text and 'language: plsql' in text
    assert 'type: plsqlExpression' not in text


def test_stale_recovery_drops_only_coordinator_state_and_invalidates_old_discard_ticket():
    args = prepare()
    providers = _save_providers(*args)
    population = json.loads(args[-1]['fox-package/master-detail-receipt.json'])
    op = next(o for o in population['adapted_operations'] if o['parent_block_id'] == providers[0]['buffer']['relation']['parent_block_id'])
    code = _gate_code(op, providers)
    recovery = code[code.index("if :REQUEST='FOX_CLEAR_FRESH' then"):code.index("if :REQUEST in ('FOX_CLEAR_DISCARD'")]
    assert 'CLEAR_TICKET<>l_recovery' in recovery
    assert re.search(r"delete_collection\('FOX_C_[A-F0-9]+'\)", recovery)
    assert 'l_names' not in recovery and providers[0]['namespace'] not in recovery
    assert 'Every previous draft buffer is retained' in recovery
    assert code.index('for update nowait;') < code.index('Selection changed in another request') < code.index('if l_dirty>0')
    failure = code[code.index('rollback to fox_detail_clear;'):]
    assert failure.index('for update nowait;') < failure.index('p_attr_number=>4,p_attr_value=>null')
    assert 'p_attr_number=>5,p_attr_value=>l_recovery' in failure
    out, receipt = apply_detail_clear(*args)
    text = out[receipt['adapted_operations'][0]['page_file']].decode()
    assert 'label: "Start fresh selection"' in text
    assert 'FOX_CLEAR_DISCARD,FOX_CLEAR_CANCEL,FOX_CLEAR_FRESH' in text


def test_initial_selection_never_appends_to_a_racing_existing_ledger():
    args = prepare()
    providers = _save_providers(*args)
    population = json.loads(args[-1]['fox-package/master-detail-receipt.json'])
    op = next(o for o in population['adapted_operations'] if o['parent_block_id'] == providers[0]['buffer']['relation']['parent_block_id'])
    code = _gate_code(op, providers)
    initial = code[code.index('if l_old is null then'):code.index('if l_new=l_old')]
    assert initial.index('if apex_collection.collection_exists(') < initial.index('raise_application_error(')
    assert initial.index('Another request selected the initial master') < initial.index('apex_collection.create_collection(')
    assert initial.index('apex_collection.create_collection(') < initial.index('apex_collection.add_member(')
    assert 'if not apex_collection.collection_exists' not in initial
    assert 'create_or_truncate' not in initial and 'p_truncate_if_exists' not in initial
    # The second creator must use CREATE_COLLECTION's duplicate rejection.
    # Subsequent reads reject multi-member state before loading seq_id=1, and
    # repeat exact member cardinality after locking and during recovery.
    read = code[:code.index('if l_old is not null then')]
    assert read.index('if l_count<>1 then') < read.index('select n001,c001,n002')
    assert 'n001 is not null and n001>0 and n001=trunc(n001) and c001 is not null' in read
    assert code.count("')=1;") == 2
    count_sql = re.search(r"select count\(\*\) into l_count (from apex_collections where collection_name='FOX_C_[A-F0-9]+');", read)[1]
    # Execute the emitted cardinality query against one, then two competing
    # selected-master members; APEX concurrency itself is an Oracle gate.
    import sqlite3
    db = sqlite3.connect(':memory:')
    db.execute('create table apex_collections(collection_name text,seq_id integer)')
    name = re.search(r"collection_name='([^']+)'", count_sql)[1]
    db.execute('insert into apex_collections values(?,1)', (name,))
    assert db.execute('select count(*) ' + count_sql).fetchone() == (1,)
    db.execute('insert into apex_collections values(?,2)', (name,))
    assert db.execute('select count(*) ' + count_sql).fetchone() == (2,)


@pytest.mark.parametrize('deferred', [False, True])
def test_pending_prompt_retains_only_immediate_revalidated_previous_parent_details(deferred):
    docs = source(deferred=deferred)
    args = prepare(docs)
    out, receipt = apply_detail_clear(*args)
    hook, = receipt['adapted_operations']
    population = json.loads(args[-1]['fox-package/master-detail-receipt.json'])
    op = next(o for o in population['adapted_operations'] if o['page_file'] == hook['page_file'])
    text = out[hook['page_file']].decode()
    region = re.search(r'    region detail-records \(\n.*?\n    \)\n', text, re.S)[0]
    query = textwrap.dedent(re.search(r'```sql\n(.*?)\n\s*```', region, re.S)[1])
    b = SQLBoundary(docs)
    b.insert('LOADS', 1, LOAD_REFERENCE='A', PLANNED_ROUTE='R1')
    b.insert('LOADS', 2, LOAD_REFERENCE='B', PLANNED_ROUTE='R2')
    b.insert('PIECES', 11, LOAD_REFERENCE='A', PIECE_CODE='ONE', STORED_ROUTE='R1')
    b.insert('PIECES', 21, LOAD_REFERENCE='B', PIECE_CODE='TWO', STORED_ROUTE='R2')
    binds = b.select(op, 1)
    binds[f'P{op["page_id"]}_STATE'] = 'DETAIL_CHANGES_PENDING'
    assert [r[0] for r in b.execute(query, binds)] == ([] if deferred else [11])
    assert ("in ('COORDINATED','DETAIL_CHANGES_PENDING')" in query) is (not deferred)
    binds[f'P{op["page_id"]}_STATE'] = 'FAILED'
    assert not b.execute(query, binds)
    binds[f'P{op["page_id"]}_STATE'] = 'DETAIL_CHANGES_PENDING'
    parent_table = next(t['table_name'] for t in args[3]['blocks'] if t['source_block_id'] == op['parent_block_id'])
    parent_key = next(t['items'][0]['column'] for t in args[3]['blocks'] if t['source_block_id'] == op['parent_block_id'])
    b.db.execute('update ' + parent_table + ' set ' + parent_key + "='STALE' where FOX_ROW_ID=1")
    assert not b.execute(query, binds)
    b.db.execute('delete from ' + parent_table + ' where FOX_ROW_ID=1')
    assert not b.execute(query, binds)
    providers = _save_providers(*args)
    code = _gate_code(op, providers)
    cancel = code[code.index("if :REQUEST='FOX_CLEAR_CANCEL' then"):code.index('l_new:=')]
    expected = 'NON_COORDINATED' if deferred else 'COORDINATED'
    assert cancel.index(f"_STATE<>'{expected}'") < cancel.index('apex_collection.update_member(')
    pending = code[code.index('if l_dirty>0'):code.index('for i in 1..l_names.count')]
    assert pending.index(f"_STATE<>'{expected}'") < pending.index("_STATE:='DETAIL_CHANGES_PENDING'")


class EmittedSQL:
    """Execute emitted inspect/dirty SQL with SQLite's bounded scalar shims.

    Oracle locks, APEX lifecycle and collection APIs remain separate gates.
    """
    def __init__(self):
        self.args = prepare()
        self.provider, = _save_providers(*self.args)
        self.boundary = SQLBoundary(source())
        self.db = self.boundary.db
        self.db.create_function('lengthb', 1, lambda value: None if value is None else len(value.encode()))
        self.db.create_function('trunc', 1, lambda value: None if value is None else int(value))
        self.boundary.insert('LOADS', 1, LOAD_REFERENCE='A', PLANNED_ROUTE='R1')
        self.boundary.insert('LOADS', 2, LOAD_REFERENCE='B', PLANNED_ROUTE='R2')
        self.boundary.insert('PIECES', 11, LOAD_REFERENCE='A', PIECE_CODE='ONE', STORED_ROUTE='R1')
        code = _inspect_buffer_sql(self.provider, 1)
        namespace = re.search(r'select (.*?) into l_name (.*?) for update nowait;', code, re.S)
        namespace_query = ('select ' + namespace[1] + ' ' + namespace[2]).replace('l_old', ':l_old')
        self.name = self.boundary.execute(namespace_query, {'l_old': 1})[0][0]
        self.sibling_name = self.boundary.execute(namespace_query, {'l_old': 2})[0][0]
        self.bad_sql = re.search(r'select count\(\*\) into l_count (from apex_collections d .*?);', code, re.S)[1]
        self.seq, self.rev = 2, 0

    def row(self, seq, value, *, persisted=11, baseline='ONE', marker='SYNTHETIC_SAVE_BASELINE_V1', namespace=None):
        self.db.execute('insert into apex_collections(collection_name,seq_id,c001,c002,c021,c022,c040,c041,c050,n001) values(?,?,?,?,?,?,?,?,?,?)',
            (namespace or self.name, seq, 'A', value, 'A' if persisted else None,
             baseline if persisted else None, 'R1' if persisted else None, marker if persisted else None, 'ROW', persisted))

    def dirty(self):
        return self.boundary.execute('select seq_id from apex_collections d where collection_name=:l_name and c050=\'ROW\' and ' + _dirty_sql(self.provider) + ' order by seq_id', {'l_name': self.name})

    def invalid(self):
        query = ('select count(*) ' + self.bad_sql).replace('l_name', ':l_name').replace('l_old', ':l_old')
        return self.boundary.execute(query, {'l_name': self.name, 'l_old': 1})[0][0]


def test_real_emitted_sql_reads_every_row_distinguishes_new_insert_and_siblings():
    b = EmittedSQL()
    b.row(2, 'ONE')
    b.row(3, None, persisted=None)
    b.row(4, 'OTHER PARENT', namespace=b.sibling_name)
    assert b.invalid() == 0 and b.dirty() == []
    b.db.execute('update apex_collections set c002=? where collection_name=? and seq_id=3', ('NEW UNSAVED', b.name))
    assert b.dirty() == [(3,)]
    b.db.execute('update apex_collections set c002=? where collection_name=? and seq_id=2', ('one ', b.name))
    assert b.dirty() == [(2,), (3,)]  # Case and whitespace are significant.
    assert b.invalid() == 0
    sibling = b.db.execute('select * from apex_collections where collection_name=?', (b.sibling_name,)).fetchall()
    b.db.execute('savepoint model_switch')
    b.db.execute('delete from apex_collections where collection_name=?', (b.name,))
    b.db.execute('rollback to model_switch')
    assert b.dirty() == [(2,), (3,)]
    assert b.db.execute('select * from apex_collections where collection_name=?', (b.sibling_name,)).fetchall() == sibling


@pytest.mark.parametrize('change', ['missing-marker', 'stale-field', 'missing-row', 'wrong-parent-key', 'invalid-stored-id'])
def test_real_emitted_sql_rejects_unknown_baseline_stale_links_and_missing_persisted_rows(change):
    b = EmittedSQL()
    b.row(2, 'ONE')
    if change == 'missing-marker':
        b.db.execute('update apex_collections set c041=null')
    elif change == 'wrong-parent-key':
        b.db.execute("update apex_collections set c001='B'")
    elif change == 'invalid-stored-id':
        b.db.execute('update apex_collections set n001=0')
    else:
        table = b.provider['contract']['child_table']
        if change == 'missing-row':
            b.db.execute('delete from ' + table)
        else:
            col = b.provider['buffer']['key_bindings'][1]['column']
            b.db.execute('update ' + table + ' set ' + col + "='REMOTE'")
    assert b.invalid() == 1


def test_real_emitted_sql_rejects_new_row_with_a_fabricated_persisted_marker():
    b = EmittedSQL()
    b.row(2, None, persisted=None)
    assert b.invalid() == 0 and b.dirty() == []
    b.db.execute("update apex_collections set c041='SYNTHETIC_SAVE_BASELINE_V1'")
    assert b.invalid() == 1
