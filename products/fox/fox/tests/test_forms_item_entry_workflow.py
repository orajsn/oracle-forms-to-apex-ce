"""Executed source programs and disposable SQL models; no Oracle/live claim."""
from copy import deepcopy
import hashlib
import json
import math
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_item_entry_workflow import (ItemEntryBoundary, apply_item_entry_workflows,
    compile_item_entry_workflows, execute_item_entry, parse_item_entry_source, summary_projection)
from fox.forms_item_commands import apply_item_commands
from test_forms_record_entry import prepare


BAG = """if :CODE is not null and :MARKER is not null and nvl(:APPROVED,'N')='N' then
 IF :MARKER <> 'X' THEN
  IF :SYSTEM.FORM_STATUS <> 'QUERY' then commit_form; end if; NEXT_ITEM;
 ELSif :MARKER = 'X' then :CODE := null; GO_ITEM('DEST'); :MARKER := null;
 else next_item; END IF; else next_item; end if;"""
NOTE = """if :NOTE_CODE is not null AND :NOTE_DEST <> 'INVALID NOTE' and nvl(:APPROVED,'N')='N' then
 :COST := :TOTAL; IF :SYSTEM.FORM_STATUS <> 'QUERY' then commit_form; end if; NEXT_ITEM;
 ELSIF :NOTE_DEST='INVALID NOTE' and nvl(:APPROVED,'N')='N' THEN GO_ITEM('NOTE_CODE');
 ELSE NEXT_RECORD; end if;"""
ROUTINE = """PROCEDURE UPDATE_DETAIL IS BEGIN
 /*GO_BLOCK('B'); GO_ITEM('CODE');*/
 GO_BLOCK('H'); GO_ITEM('NOTICE'); :COST := :TOTAL; END;"""


def source(renamed=False, extra=''):
    root = ET.Element('FormModule', Name='FLOW')
    h = ET.SubElement(root, 'Block', Name='H', DatabaseBlock='true')
    b = ET.SubElement(root, 'Block', Name='B', DatabaseBlock='true')
    n = ET.SubElement(root, 'Block', Name='N', DatabaseBlock='true')
    def item(block, name, dtype='Char', stored=True, **attrs):
        return ET.SubElement(block, 'Item', Name=name, DatabaseItem=str(stored).lower(), DataType=dtype,
            MaximumLength='40', ItemType='Text Item', **attrs)
    item(h, 'HKEY'); item(h, 'APPROVED'); item(h, 'DEST')
    notice = item(h, 'NOTICE')
    ET.SubElement(notice, 'Trigger', Name='KEY-NEXT-ITEM', TriggerText="GO_ITEM('B.CODE');")
    ET.SubElement(h, 'Relation', Name='HB', DetailBlock='B', RelationType='JOIN', JoinCondition='H.HKEY=B.HKEY')
    item(b, 'HKEY'); item(b, 'CODE')
    marker = item(b, 'MARKER', stored=False)
    ET.SubElement(marker, 'Trigger', Name='WHEN-NEW-ITEM-INSTANCE', TriggerText=BAG)
    item(b, 'COST', 'Number'); status = item(b, 'BSTATUS')
    ET.SubElement(status, 'Trigger', Name='KEY-NEXT-ITEM', TriggerText="GO_ITEM('N.NOTE_CODE');")
    ET.SubElement(b, 'Relation', Name='BN', DetailBlock='N', RelationType='JOIN', JoinCondition='B.HKEY=N.HKEY AND B.CODE=N.BKEY')
    item(n, 'HKEY'); item(n, 'BKEY'); item(n, 'NOTE_CODE')
    owner = item(n, 'GO2', stored=False)
    ET.SubElement(owner, 'Trigger', Name='WHEN-NEW-ITEM-INSTANCE', TriggerText=NOTE)
    item(n, 'NOTE_DEST', stored=False); item(n, 'WEIGHT', 'Number')
    item(n, 'NET', 'Number', False, CalculateMode='Formula', Formula='CEIL(:WEIGHT)')
    item(n, 'TOTAL', 'Number', False, CalculateMode='Summary', SummaryFunction='Sum', SummaryBlockName='N', SummaryItemName='NET')
    ET.SubElement(root, 'ProgramUnit', Name='UPDATE_DETAIL', ProgramUnitType='Procedure', ProgramUnitText=ROUTINE)
    if extra:
        ET.SubElement(root, 'Trigger', Name='EXTRA', TriggerText=extra)
    raw = ET.tostring(root)
    if renamed:
        for old, new in ((b'FLOW', b'DELIVERY'), (b'NOTE_CODE', b'PARCEL_ID'), (b'NOTE_DEST', b'PARCEL_CITY'),
                         (b'WEIGHT', b'MASS'), (b'MARKER', b'NEXT_FLAG'), (b'COST', b'CHARGE'),
                         (b'TOTAL', b'AGGREGATE'), (b'UPDATE_DETAIL', b'RECALCULATE')):
            raw = raw.replace(old, new)
    return [('entry.xml', raw)]


def apply(docs=None, commands=False):
    docs = docs or source()
    packet, chunks, trace, files = prepare(docs)
    if commands:
        files, receipt = apply_item_commands(docs, packet, chunks, trace, files)
        files['fox-package/item-command-receipt.json'] = json.dumps(receipt).encode()
    return apply_item_entry_workflows(docs, packet, chunks, trace, files), (docs, packet, chunks, trace, files)


def operations(renamed=False):
    (_, receipt), args = apply(source(renamed))
    return receipt['encoded_operations'], args


@pytest.mark.parametrize('renamed', [False, True])
def test_complete_three_bodies_and_genuine_callable_target_are_deterministic(renamed):
    (out, receipt), args = apply(source(renamed))
    before = deepcopy(args)
    assert (out, receipt) == apply_item_entry_workflows(*args) and args == before
    assert len(receipt['encoded_operations']) == 3 and not receipt['gaps']
    assert not receipt['generated_operations'] and not receipt['adapted_operations']
    routine, = [o for o in receipt['encoded_operations'] if o['source_event'] == 'ProgramUnit']
    assert not routine['caller_evidence']['active_call_sites']
    assert not routine['caller_evidence']['original_caller_proven']
    assert len(routine['caller_evidence']['searched_code_unit_ids']) == len(args[2])
    namespace = {}
    exec(compile(out['fox-package/item-entry-runtime.py'], 'item-entry-runtime.py', 'exec'), namespace)
    assert callable(namespace['execute_item_entry'])
    assert out['fox-package/sources/entry.xml'] == args[0][0][1]
    for op in receipt['encoded_operations']:
        assert op['source_unit_sha256'] and op['rule_id'] and op['operation_sha256']
        assert op['target']['callable'] == 'execute_item_entry'
        assert not op['runtime_verified'] and not op['business_accepted']
        assert [s['ordinal'] for s in op['stages']] == list(range(1, len(op['stages'])+1))


class Adapter:
    def __init__(self, op, *, values=None, status='QUERY', total=2, commit=True):
        self.values = {uid: None for uid in op['fields']}
        self.values.update({uid: value for name, value in (values or {}).items()
                            for uid, field in op['fields'].items() if field['source_name'] == name})
        self.status, self.total, self.commit = status, total, commit
        self.calls = []
        self.ctx = {'trusted': True, 'scope': 'forms_buffer', 'row_ids': {f['source_block_id']: 7 for f in op['fields'].values()},
                    'current_item_id': op['owner_item_id'], 'current_block_id': next(iter(op['fields'].values()))['source_block_id']}
        self.ctx['row_ids'].update({n['source_block_id']: 7 for n in op['navigation']})

    def context(self, op): return deepcopy(self.ctx)
    def read(self, field, ctx):
        self.calls.append(('read', field['source_name']))
        return self.values[field['source_item_id']]
    def summary(self, binding, ctx):
        self.calls.append(('summary', binding['source_item_id']))
        assert ctx['row_ids'][binding['master_block_id']] == 7
        return self.total
    def assign(self, field, value, ctx):
        self.calls.append(('assign', field['source_name'], value))
        self.values[field['source_item_id']] = value
        return True
    def form_status(self, ctx):
        self.calls.append(('status', self.status)); return self.status
    def commit_form(self, ctx):
        self.calls.append(('commit_form', self.commit)); return self.commit
    def navigate(self, node, ctx):
        self.calls.append((node['kind'], node.get('value')))
        if node['kind'] in ('go_item', 'go_block'):
            ctx['current_block_id'] = node['source_block_id']
        if node['kind'] == 'go_item': ctx['current_item_id'] = node['source_item_id']
        if node['kind'] == 'next_record':
            ctx['row_ids'][ctx['current_block_id']] += 1
        return ctx
    def message(self, message, ctx): self.calls.append(('message', message)); return True


@pytest.mark.parametrize('status,commits', [('QUERY', 0), ('CHANGED', 1), ('NEW', 1)])
def test_bag_non_x_branch_commits_whole_form_before_next(status, commits):
    ops, _ = operations(); op = ops[0]
    a = Adapter(op, values={'CODE': 'B1', 'MARKER': 'CLOCK', 'APPROVED': None}, status=status)
    result = execute_item_entry(op, a)
    assert [e['kind'] for e in result['effects']] == ['commit_form']*commits + ['next_item']
    assert not any(c[0] == 'assign' for c in a.calls)


def test_bag_x_clears_code_then_focuses_then_clears_marker_without_commit():
    op = operations()[0][0]
    a = Adapter(op, values={'CODE': 'B1', 'MARKER': 'X', 'APPROVED': 'N'})
    result = execute_item_entry(op, a)
    assert [(e['kind'], e.get('value')) for e in result['effects']] == [('assign', None), ('go_item', None), ('assign', None)]
    assert [c for c in a.calls if c[0] not in ('read',)] == [('assign', 'CODE', None), ('go_item', 'DEST'), ('assign', 'MARKER', None)]


@pytest.mark.parametrize('values', [{'CODE': None}, {'CODE': ''}, {'CODE': 'B', 'MARKER': None},
                                  {'CODE': 'B', 'MARKER': 'X', 'APPROVED': 'Y'}])
def test_inactive_bag_branch_advances_without_assign_or_commit(values):
    op = operations()[0][0]; a = Adapter(op, values=values)
    assert [e['kind'] for e in execute_item_entry(op, a)['effects']] == ['next_item']
    if not values.get('CODE'):
        assert a.calls == [('read', 'CODE'), ('next_item', None)]


@pytest.mark.parametrize('dest,code,approved,kinds', [
    ('VALID', 'N1', None, ['assign', 'next_item']),
    ('INVALID NOTE', None, 'N', ['go_item']),
    ('INVALID NOTE', 'N1', 'Y', ['next_record']),
    (None, 'N1', 'N', ['next_record']),
    ('', 'N1', 'N', ['next_record']),
    ('VALID', None, 'N', ['next_record']),
])
def test_note_guards_preserve_unknown_invalid_and_next_record(dest, code, approved, kinds):
    op = operations()[0][1]
    a = Adapter(op, values={'NOTE_CODE': code, 'NOTE_DEST': dest, 'APPROVED': approved}, total=None)
    result = execute_item_entry(op, a)
    assert [e['kind'] for e in result['effects']] == kinds
    if kinds[0] == 'assign': assert result['effects'][0]['value'] is None


@pytest.mark.parametrize('outcome', [None, False, 'UNKNOWN'])
def test_assignment_survives_unknown_or_failed_commit_without_next_or_replay(outcome):
    op = operations()[0][1]
    a = Adapter(op, values={'NOTE_CODE': 'N1', 'NOTE_DEST': 'VALID'}, status='CHANGED', commit=outcome)
    with pytest.raises(ItemEntryBoundary) as caught: execute_item_entry(op, a)
    assert [x['kind'] for x in caught.value.confirmed_effects] == ['assign']
    assert caught.value.pending_ordinal is not None and not caught.value.retry_authorized
    assert not any(c[0] == 'next_item' for c in a.calls)
    assert [v for k, v in a.values.items() if op['fields'][k]['source_name'] == 'COST'] == [2]


@pytest.mark.parametrize('status', [None, '', 'UNTRUSTED'])
def test_unavailable_form_status_cannot_silently_skip_required_transaction(status):
    op = operations()[0][1]
    a = Adapter(op, values={'NOTE_CODE': 'N1', 'NOTE_DEST': 'VALID'}, status=status)
    with pytest.raises(ItemEntryBoundary, match='trusted_form_status_unavailable') as caught:
        execute_item_entry(op, a)
    assert [x['kind'] for x in caught.value.confirmed_effects] == ['assign']
    assert not any(c[0] in ('commit_form', 'next_item') for c in a.calls)


def test_routine_is_callable_without_inventing_original_caller_and_navigation_preserves_rows():
    op = operations()[0][2]
    a = Adapter(op, total=17)
    result = execute_item_entry(op, a)
    assert [e['kind'] for e in result['effects']] == ['go_block', 'go_item', 'assign']
    assert result['context']['row_ids'] == a.ctx['row_ids']
    assert result['effects'][-1]['value'] == 17
    a = Adapter(op)
    def bad_navigation(node, ctx): ctx['row_ids'] = {}; return ctx
    a.navigate = bad_navigation
    with pytest.raises(ItemEntryBoundary, match='navigation_'): execute_item_entry(op, a)


def test_untrusted_or_wrong_record_context_fails_before_any_effect():
    op = operations()[0][0]
    for update in ({'trusted': False}, {'scope': 'saved_snapshot'}, {'current_item_id': 'wrong'}, {'row_ids': {}}):
        a = Adapter(op, values={'CODE': 'B1', 'MARKER': 'X'}); a.ctx.update(update)
        with pytest.raises(ItemEntryBoundary): execute_item_entry(op, a)
        assert not [c for c in a.calls if c[0] in ('assign', 'commit_form', 'go_item')]


@pytest.mark.parametrize('extra,sites', [("-- UPDATE_DETAIL;\nMESSAGE('UPDATE_DETAIL;');", 0),
    ('/* UPDATE_DETAIL; */ NULL;', 0), ('UPDATE_DETAIL;', 1), ('UPDATE_DETAIL();', 1)])
def test_caller_search_ignores_comments_strings_and_declaration_but_records_real_sites(extra, sites):
    ops, _ = operations_from(source(extra=extra))
    routine = next(o for o in ops if o['source_event'] == 'ProgramUnit')
    assert len(routine['caller_evidence']['active_call_sites']) == sites
    assert routine['caller_evidence']['original_caller_proven'] is bool(sites)


def operations_from(docs):
    (_, receipt), args = apply(docs)
    return receipt['encoded_operations'], args


@pytest.mark.parametrize('text', ['NEXT_ITEM; DROP TABLE X;', "GO_ITEM(:NAME);", 'IF :A IS NULL THEN NEXT_ITEM;',
                                  "IF :A='X' THEN EXTERNAL.CALL; ELSE NEXT_ITEM; END IF;", 'NEXT_ITEM; /* unterminated'])
def test_partial_or_unproved_active_bodies_are_rejected(text):
    with pytest.raises(ValueError): parse_item_entry_source(text, 'WHEN-NEW-ITEM-INSTANCE')


@pytest.mark.parametrize('renamed', [False, True])
def test_saved_native_preview_rounds_each_detail_and_isolates_current_composite_bag(renamed):
    (out, r), args = apply(source(renamed), commands=True)
    assert len(r['adapted_operations']) == 1 and len(r['encoded_operations']) == 2 and not r['gaps']
    assert len({o['source_unit_id'] for key in ('adapted_operations','encoded_operations') for o in r[key]}) == 3
    op = r['adapted_operations'][0]; target = op['saved_entry_target']; s = target['source_summary']
    assert 'sum(ceil(' in target['summary_projection_sql'].lower()
    assert 'No business row is changed.' in out[op['page_file']].decode()
    assert 'Check saved consignment entry' in out[op['page_file']].decode()
    assert 'focus()' in target['javascript'] and 'whole-form commit' in target['javascript']
    assert not any(word in target['process_plsql'].lower() for word in ('commit;', 'update ', 'delete ', 'insert '))
    db = sqlite3.connect(':memory:'); db.create_function('ceil', 1, lambda v: None if v is None else math.ceil(v))
    pcols = [p['parent_column'] for p in s['join_pairs']]; ccols = [p['child_column'] for p in s['join_pairs']]
    measure = s['measure_input_fields'][0]['column']
    db.execute('create table '+s['master_table']+'(FOX_ROW_ID integer,'+','.join(c+' text' for c in pcols)+')')
    db.execute('create table '+s['detail_table']+'('+','.join(c+' text' for c in ccols)+','+measure+' numeric)')
    db.executemany('insert into '+s['master_table']+' values(?,?,?)', [(1,'H1','SAME'),(2,'H2','SAME'),(3,'H1','OTHER'),(4,'EMPTY','NONE'),(5,'ALL','NULL')])
    db.executemany('insert into '+s['detail_table']+' values(?,?,?)', [('H1','SAME',.25),('H1','SAME',.25),('H1','SAME',None),('H2','SAME',8.1),('H1','OTHER',3.1),('ALL','NULL',None)])
    query = 'select FOX_ROW_ID,'+summary_projection(s,'m')+' from '+s['master_table']+' m order by FOX_ROW_ID'
    assert db.execute(query).fetchall() == [(1,2),(2,9),(3,4),(4,None),(5,None)]


def test_changed_source_trace_manifest_and_injected_saved_page_are_rejected():
    (_, _), args = apply(commands=True)
    for member in ('fox-package/source-manifest.json', 'fox-package/source-to-page.json', 'fox-package/sources/entry.xml'):
        bad = deepcopy(args); bad[-1][member] += b' '
        if member.endswith('.json'):
            value = json.loads(bad[-1][member]); value['source_binding'] = 'foreign'; bad[-1][member] = json.dumps(value).encode()
        with pytest.raises(ValueError): compile_item_entry_workflows(*bad)
    bad = deepcopy(args)
    c = json.loads(bad[-1]['fox-package/item-command-receipt.json']); page = c['screens'][-1]['page_file']
    bad[-1][page] += b'/* untrusted page */'
    _, r = apply_item_entry_workflows(*bad)
    assert not r['adapted_operations'] and 'EXACT_SAVED_CONTEXT_SCREEN' in r['gaps'][0]['reason']


@pytest.mark.parametrize('field,reason', [('APPROVED', 'MIXED_NVL_TYPES'), ('NOTE_DEST', 'MIXED_COMPARISON_TYPES')])
def test_number_fields_cannot_acquire_python_character_comparison_semantics(field, reason):
    docs = source(); root = ET.fromstring(docs[0][1])
    next(i for i in root.iter('Item') if i.get('Name') == field).set('DataType', 'Number')
    (_, receipt), _ = apply([('entry.xml', ET.tostring(root))])
    assert any(reason in gap['reason'] for gap in receipt['gaps'])


def test_summary_assignment_to_character_target_is_rejected():
    root = ET.fromstring(source()[0][1])
    next(i for i in root.iter('Item') if i.get('Name') == 'COST').set('DataType', 'Char')
    (_, receipt), _ = apply([('entry.xml', ET.tostring(root))])
    assert any('MIXED_ASSIGNMENT_TYPES' in gap['reason'] for gap in receipt['gaps'])


def test_compiled_ast_and_target_mutation_fail_before_provider_and_standalone_pins_hash():
    (out, receipt), _ = apply()
    original = receipt['encoded_operations'][0]
    for mutate in (lambda op: op['parsed']['body'].clear(), lambda op: op['fields'].clear(),
                   lambda op: op['navigation'][0].update(source_item_id='forged')):
        op = deepcopy(original); mutate(op); adapter = Adapter(original)
        with pytest.raises(ItemEntryBoundary, match='digest_mismatch'): execute_item_entry(op, adapter)
        assert not adapter.calls
    namespace = {}; exec(compile(out['fox-package/item-entry-runtime.py'], 'emitted.py', 'exec'), namespace)
    op = deepcopy(original); op['parsed']['body'].clear()
    op['operation_sha256'] = namespace['_operation_digest'](op)
    with pytest.raises(namespace['ItemEntryBoundary'], match='digest_mismatch'):
        namespace['execute_item_entry'](op, Adapter(original))


@pytest.mark.parametrize('value', [True, float('inf'), float('nan'), '2', {}, []])
def test_invalid_summary_provider_value_blocks_before_assignment(value):
    op = operations()[0][1]; adapter = Adapter(op, values={'NOTE_CODE': 'N1', 'NOTE_DEST': 'VALID'}, total=value)
    with pytest.raises(ItemEntryBoundary, match='invalid_numeric_provider'): execute_item_entry(op, adapter)
    assert not any(c[0] in ('assign','commit_form','next_item') for c in adapter.calls)


def test_short_circuit_does_not_request_inactive_rhs_provider():
    op = operations()[0][0]; adapter = Adapter(op)
    def read(field, ctx):
        assert field['source_name'] == 'CODE'
        return None
    adapter.read = read
    assert [e['kind'] for e in execute_item_entry(op, adapter)['effects']] == ['next_item']


def test_unknown_and_false_uses_else_and_unknown_status_does_not_run_inactive_branch():
    op = operations()[0][1]
    adapter = Adapter(op, values={'NOTE_CODE': 'N1', 'NOTE_DEST': None, 'APPROVED': 'Y'}, status=None)
    assert [e['kind'] for e in execute_item_entry(op, adapter)['effects']] == ['next_record']
    assert not any(c[0] == 'status' for c in adapter.calls)


def test_native_routine_has_real_source_target_without_installing_an_original_caller():
    (out, receipt), _ = apply(commands=True)
    routine = next(o for o in receipt['encoded_operations'] if o['source_event'] == 'ProgramUnit')
    target = routine['native_callable_target']; config = target['runtime_config']
    page = out[target['page_file']].decode()
    assert target['callable'] == 'window.foxItemEntryRoutines.invoke'
    assert config['focus_item'] in page and config['output_item'] in page and config['summary_item'] in page
    assert 'document.activeElement!==focus' in target['javascript']
    assert target['javascript'].index('focus.focus()') < target['javascript'].index('output.value=summary.value')
    assert not target['source_caller_installed'] and not routine['caller_evidence']['original_caller_proven']
    assert '<button' not in target['javascript'] and 'submit(' not in target['javascript']


def test_actual_saved_entry_query_runs_guards_on_signed_current_snapshot_and_fresh_composite_sum():
    from fox.forms_master_detail import _fingerprint
    (_, receipt), args = apply(commands=True)
    op = receipt['adapted_operations'][0]; target = op['saved_entry_target']
    db = sqlite3.connect(':memory:')
    db.create_function('nvl', 2, lambda a,b: b if a is None else a)
    db.create_function('standard_hash', 2, lambda value, algorithm: None if value is None else hashlib.sha256(str(value).encode()).digest())
    db.create_function('rawtohex', 1, lambda value: None if value is None else value.hex().upper())
    db.create_function('ceil', 1, lambda value: None if value is None else math.ceil(value))
    blocks = {b['name']: b for b in args[3]['blocks'] if b['classification'] == 'database'}
    def column(block, name): return next(f['column'] for f in blocks[block]['items'] if f['source_name'] == name)
    def insert(block, rowid, **values):
        b = blocks[block]; cols = ['FOX_ROW_ID']+[column(block,name) for name in values]
        db.execute('insert into '+b['table_name']+'('+','.join(cols)+') values('+','.join('?' for _ in cols)+')', [rowid,*values.values()])
    for b in blocks.values():
        db.execute('create table '+b['table_name']+'(FOX_ROW_ID integer,'+','.join(f['column']+' '+('numeric' if f['data_type']=='NUMBER' else 'text') for f in b['items'])+')')
    insert('H', 1, HKEY='H1', APPROVED='N'); insert('H', 2, HKEY='H2', APPROVED='N')
    insert('B', 11, HKEY='H1', CODE='SAME'); insert('B', 12, HKEY='H2', CODE='SAME')
    insert('N', 21, HKEY='H1', BKEY='SAME', NOTE_CODE='N1', NOTE_DEST='VALID', WEIGHT=.25)
    insert('N', 22, HKEY='H1', BKEY='SAME', NOTE_CODE='N2', NOTE_DEST='VALID', WEIGHT=.25)
    insert('N', 23, HKEY='H2', BKEY='SAME', NOTE_CODE='N1', NOTE_DEST='INVALID NOTE', WEIGHT=8.1)
    def params():
        result = {}; page = target['page_id']
        for i, (name,rowid) in enumerate((('H',1),('B',11),('N',21))):
            b = blocks[name]
            token = db.execute('select '+_fingerprint(b['items'],'r')+' from '+b['table_name']+' r where FOX_ROW_ID=?',(rowid,)).fetchone()[0]
            result[f'P{page}_ID{i}'] = rowid; result[f'P{page}_TOKEN{i}'] = token
        return result
    query = target['saved_entry_query_sql']; p = params()
    assert db.execute(query,p).fetchall() == [(2,'SUMMARY_THEN_TRANSACTION')]
    db.execute('update '+blocks['N']['table_name']+' set '+column('N','NOTE_DEST')+"='INVALID NOTE' where FOX_ROW_ID=21")
    assert db.execute(query,p).fetchall() == []
    assert db.execute(query,params()).fetchall() == [(2,'INVALID_FOCUS')]
    db.execute('update '+blocks['N']['table_name']+' set '+column('N','NOTE_DEST')+'=null where FOX_ROW_ID=21')
    assert db.execute(query,params()).fetchall() == [(2,'NEXT_RECORD_REQUIRED')]
    db.execute('update '+blocks['H']['table_name']+' set '+column('H','APPROVED')+"='Y' where FOX_ROW_ID=1")
    assert db.execute(query,params()).fetchall() == [(2,'NEXT_RECORD_REQUIRED')]
    insert('B', 13, HKEY='H1', CODE='SAME')
    assert db.execute(query,params()).fetchall() == []


def test_multiple_same_screen_routines_retain_distinct_callable_registrations():
    root = ET.fromstring(source()[0][1])
    ET.SubElement(root, 'ProgramUnit', Name='REFRESH_AGAIN', ProgramUnitType='Procedure',
                  ProgramUnitText=ROUTINE.replace('UPDATE_DETAIL', 'REFRESH_AGAIN'))
    (files, receipt), _ = apply([('entry.xml', ET.tostring(root))], commands=True)
    routines = [op for op in receipt['encoded_operations'] if 'native_callable_target' in op]
    assert len(routines) == 2 and len({o['operation_id'] for o in routines}) == 2
    assert len({o['native_callable_target']['page_file'] for o in routines}) == 1
    page = files[routines[0]['native_callable_target']['page_file']].decode()
    for routine in routines:
        assert routine['operation_id'] in page
        script = routine['native_callable_target']['javascript']
        assert 'previous.routines' in script and 'routines[c.operation_id]=invoke' in script
        assert not routine['caller_evidence']['original_caller_proven']
