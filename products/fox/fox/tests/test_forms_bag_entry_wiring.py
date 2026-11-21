"""Executed emitted SQL predicates and native-source contracts; no Oracle claim."""
from copy import deepcopy
import hashlib
import json
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_bag_entry_wiring import (apply_bag_entry_wiring, bag_entry_runtime,
                                        render_bag_entry_process)
from fox.forms_item_validation import apply_item_validations
from test_forms_item_validation import source as validation_source, prepare as validation_prepare


BODY = """if :{code} is not null and :{marker} is not null and nvl(:APPROVED,'N')='N' then
 IF :{marker} <> 'X' THEN
  IF :SYSTEM.FORM_STATUS <> 'QUERY' then commit_form; end if; NEXT_ITEM;
 ELSif :{marker} = 'X' then :{code} := null; GO_ITEM('{destination}'); :{marker} := null;
 else next_item; END IF; else next_item; end if;"""


def source(renamed=False, change=None):
    name, raw = validation_source(renamed=renamed)[0]
    root = ET.fromstring(raw)
    parent, child = list(root.iter('Block'))[:2]
    marker = next(i for i in child.iter('Item') if i.get('Name') in ('STEP_MARKER', 'FOCUS_STAMP'))
    code = next(i for i in child.iter('Item') if i.get('Name') in ('PIECE_CODE', 'CRATE_CODE'))
    destination = next(i for i in parent.iter('Item') if i.get('Name') in ('TARGET_CITY', 'END_TOWN'))
    text = BODY.format(code=code.get('Name'), marker=marker.get('Name'), destination=destination.get('Name'))
    if change:
        text = change(text)
    ET.SubElement(marker, 'Trigger', Name='WHEN-NEW-ITEM-INSTANCE', TriggerText=text)
    ET.SubElement(child, 'Item', Name='MASS_RECORDED' if renamed else 'ACTUAL_WEIGHT', ItemType='Text Item',
                  DatabaseItem='true', DataType='Number', MaximumLength='8', CanvasName='MAIN')
    return [(name, ET.tostring(root))]


def prepare(docs=None):
    args = list(validation_prepare(docs or source()))
    args[-1], receipt = apply_item_validations(*args)
    args[-1]['fox-package/item-validation-receipt.json'] = json.dumps(receipt).encode()
    return tuple(args)


def wired(renamed=False):
    args = prepare(source(renamed))
    files, receipt = apply_bag_entry_wiring(*args)
    assert not receipt['gaps']
    op, = receipt['adapted_operations']
    return files, op, args


@pytest.mark.parametrize('renamed', [False, True])
def test_source_bound_actual_draft_is_deterministic_and_preserves_other_members(renamed):
    args = prepare(source(renamed))
    original = deepcopy(args)
    files, receipt = apply_bag_entry_wiring(*args)
    assert args == original and (files, receipt) == apply_bag_entry_wiring(*args)
    op, = receipt['adapted_operations']
    assert not receipt['generated_operations'] and not receipt['gaps']
    assert {name for name in files if files[name] != args[-1][name]} == {op['page_file']}
    assert files['fox-package/sources/' + args[0][0][0]] == args[0][0][1]
    assert op['ordered_effects'] == ['clear_current_draft_code', 'verify_actual_header_destination_focus', 'clear_marker_after_guarded_focus_ack']
    assert op['source_unit_sha256'] and op['input_page_sha256'] != op['output_page_sha256']
    assert op['output_page_sha256'] == hashlib.sha256(files[op['page_file']]).hexdigest()
    assert op['pending_slots'] == {'nonce': 'c045', 'destination_hash': 'c046', 'scope': 'current_ROW_only'}
    assert op['relative_next']['source_name'] == ('MASS_RECORDED' if renamed else 'ACTUAL_WEIGHT')
    assert not any(receipt[k] for k in ('runtime_verified', 'business_accepted', 'oracle_compiled', 'original_reads_enabled', 'customer_table_writes', 'synthetic_table_writes'))
    page = files[op['page_file']].decode()
    assert 'type: textField' in page and 'id="fox-bag-entry-action"' in page
    assert 'process source-bag-entry (' in page and 'process save-synthetic-record (' in page
    for key in ('destination_item', 'next_item', 'state_item', 'nonce_item', 'focus_item'):
        assert 'pageItem ' + op['native_target']['runtime_config'][key] + ' (' in page
    # Original mutators gain the selected-row gate, the new continuation retains
    # its own context guard so it can consume that nonce.
    assert page.count("and c045 is not null;if l_matches<>0 then return false;") >= 3


@pytest.mark.parametrize('change', [
    lambda text: text.replace(':STEP_MARKER := null;', ':STEP_MARKER := \'Y\';'),
    lambda text: text.replace("GO_ITEM('TARGET_CITY'); :STEP_MARKER := null;", ":STEP_MARKER := null; GO_ITEM('TARGET_CITY');"),
    lambda text: text.replace("nvl(:APPROVED,'N')='N'", "nvl(:APPROVED,'N')='Y'"),
    lambda text: text.replace('commit_form;', 'NEXT_ITEM;'),
])
def test_different_active_source_cannot_inherit_this_native_action(change):
    args = prepare(source(change=change))
    files, receipt = apply_bag_entry_wiring(*args)
    assert not receipt['adapted_operations']
    assert files == args[-1]


@pytest.mark.parametrize('member', ['page', 'layout', 'source', 'trace'])
def test_changed_page_receipt_source_or_trace_refuses_before_writes(member):
    _, op, args = wired()
    bad = deepcopy(args)
    if member == 'page':
        bad[-1][op['page_file']] += b'/* injected */'
    elif member == 'layout':
        r = json.loads(bad[-1]['fox-package/item-validation-receipt.json'])
        r['generated_operations'][0]['contract']['code_slot'] = 1
        bad[-1]['fox-package/item-validation-receipt.json'] = json.dumps(r).encode()
    elif member == 'source':
        bad[-1]['fox-package/sources/' + bad[0][0][0]] += b' '
    else:
        bad[3]['source_binding'] = 'forged'
    if member in ('source', 'trace'):
        with pytest.raises(ValueError):
            apply_bag_entry_wiring(*bad)
    else:
        files, receipt = apply_bag_entry_wiring(*bad)
        assert not receipt['adapted_operations'] and receipt['gaps'] and files == bad[-1]


def test_emitted_sql_keeps_two_phase_order_nonce_revision_policy_and_transaction_boundary():
    _, op, _ = wired()
    code = op['native_target']['process_plsql']
    clear_code = 'p_attr_number=>' + str(op['contract']['code_slot']) + ',p_attr_value=>null'
    clear_marker = 'p_attr_number=>42,p_attr_value=>null'
    # ACK is a separate guarded request; its text appears before the first phase.
    first = code[code.index('if l_marker=\'X\' then'):]
    assert first.index(clear_code) < first.index('p_attr_number=>45,p_attr_value=>l_pending') < first.index("'FOCUS_PENDING'")
    ack = code[code.index("if :REQUEST='FOX_BAG_ENTRY_FOCUS'"):code.index('if l_pending is not null then')]
    for guard in ('l_pending<>', 'l_expected_hash<>l_destination_hash', 'l_code is not null', "l_marker<>'X'", 'BAG_FOCUS not in'):
        assert guard in ack
    assert ack.index('FOCUS_NOT_CONFIRMED_OR_STALE') < ack.index(clear_marker)
    assert 'l_revision<>to_number(' in code and 'for update nowait' in code
    assert 'p_seq=>l_seq,p_attr_number=>42' in code and 'p_seq=>1,p_attr_number=>3,p_number_value=>l_revision+1' in code
    assert 'savepoint fox_bag_entry' in code and 'rollback to fox_bag_entry' in code
    assert "return 'UNKNOWN'" in code and 'WHOLE_FORM_STATUS_UNAVAILABLE' in code
    assert 'host_commit_form' in code and 'FOX_SYNTHETIC_SAVE' not in code
    assert 'commit;' not in code.lower() and 'insert into ' not in code.lower() and 'delete from ' not in code.lower()
    assert 'l_status is null or l_status<>\'QUERY\'' in code
    assert not re.search(r'if\s+(?:not\s+)?\(?decode\(', code, re.I)
    assert 'select case when decode(' in code.lower()
    assert "then 'N:' else 'V:'||" in code and 'nvl(' + op['contract']['fields']['destination']['column'] + ',chr(0))' not in code


def test_unsupported_intervening_navigable_control_is_not_silently_skipped():
    docs = source(); root = ET.fromstring(docs[0][1])
    child = list(root.iter('Block'))[1]
    marker = next(i for i in child if i.get('Name') == 'STEP_MARKER')
    child.insert(list(child).index(marker)+1, ET.Element('Item', Name='DECISION', ItemType='List Item',
                  DatabaseItem='false', DataType='Char', MaximumLength='10', CanvasName='MAIN'))
    args = prepare([(docs[0][0], ET.tostring(root))])
    _, receipt = apply_bag_entry_wiring(*args)
    op, = receipt['adapted_operations']
    assert op['relative_next'] is None
    assert any('SOURCE_FOCUS_TARGET_UNAVAILABLE' in value for value in op['remaining_boundaries'])
    assert "BAG_STATE:='NEXT_ITEM_UNAVAILABLE'" in op['native_target']['process_plsql']


@pytest.mark.parametrize('code,marker,approved,expected', [
    ('B', 'X', None, 1), ('B', 'CLOCK', 'N', 1), (None, 'X', None, 0),
    ('B', None, None, 0), ('B', 'X', 'Y', 0), ('B', 'X', 'y', 0), ('B', 'X', 'N ', 0),
])
def test_actual_emitted_outer_guard_preserves_null_and_approval_semantics(code, marker, approved, expected):
    _, op, _ = wired()
    process = op['native_target']['process_plsql']
    expression = re.search(r'\n if (\(.*?\)) then\n  if l_marker=', process, re.S)[1]
    db = sqlite3.connect(':memory:')
    db.create_function('nvl', 2, lambda value, fallback: fallback if value is None else value)
    for name in ('l_code', 'l_marker', 'l_approved'):
        expression = expression.replace(name, ':' + name)
    assert db.execute('select case when ' + expression + ' then 1 else 0 end',
                      {'l_code': code, 'l_marker': marker, 'l_approved': approved}).fetchone() == (expected,)


def test_actual_emitted_row_query_rejects_siblings_changed_keys_weights_and_identity():
    _, op, args = wired()
    c = op['contract']; process = op['native_target']['process_plsql']
    query = re.search(r'(select c\.FOX_ROW_ID) into l_found (from .*?) for update nowait;', process, re.S)
    query = query[1] + ' ' + query[2]
    query = query.replace('bag_entry.l_id', ':id').replace('bag_entry.l_parent', ':parent').replace('bag_entry.l_name', ':name').replace('bag_entry.l_seq', ':seq').replace('utl_raw.cast_to_raw', 'raw_value')
    db = sqlite3.connect(':memory:'); db.create_function('raw_value', 1, lambda value: None if value is None else str(value).encode())
    db.create_function('decode', 4, lambda a,b,yes,no: yes if a == b else no)
    blocks = [b for b in args[3]['blocks'] if b.get('table_name') in (c['parent_table'], c['child_table'])]
    for block in blocks:
        db.execute('create table ' + block['table_name'] + '(FOX_ROW_ID integer,' + ','.join(f['column'] + (' numeric' if f['data_type']=='NUMBER' else ' text') for f in block['items']) + ')')
    buffer = next(b for b in json.loads(args[-1]['fox-package/buffer-plan.json'])['operations'] if b['operation_id'] == c['buffer_operation_id'])
    pcolumn = buffer['key_bindings'][0]['parent_copy']['parent_column']
    db.execute('insert into '+c['parent_table']+'(FOX_ROW_ID,'+pcolumn+') values (1,\'H1\'),(2,\'H2\')')
    keys = [f['column'] for f in buffer['key_bindings']]
    cols = keys+[c['fields']['route']['column'], c['fields']['weight']['column']]
    db.execute('insert into '+c['child_table']+'(FOX_ROW_ID,'+','.join(cols)+') values (11,\'H1\',\'SAME\',\'R\',2),(12,\'H2\',\'SAME\',\'R\',2)')
    db.execute('create table apex_collections(collection_name text,seq_id integer,c041 text,c021 text,c022 text,c040 text,n003 numeric)')
    db.execute("insert into apex_collections values('draft',2,'SYNTHETIC_SAVE_BASELINE_V1','H1','SAME','R',2)")
    params = {'id': 11, 'parent': 1, 'name': 'draft', 'seq': 2}
    assert db.execute(query, params).fetchall() == [(11,)]
    for change in ({'id': 12}, {'parent': 2}, {'seq': 3}, {'name': 'foreign'}):
        assert db.execute(query, {**params, **change}).fetchall() == []
    for column, value in ((keys[1], 'CHANGED'), (c['fields']['weight']['column'], 99), (c['fields']['route']['column'], 'OTHER')):
        db.execute('savepoint change')
        db.execute('update '+c['child_table']+' set '+column+'=? where FOX_ROW_ID=11', (value,))
        assert db.execute(query, params).fetchall() == []
        db.execute('rollback to change')


def test_emitted_browser_continuation_checks_actual_focus_and_unkept_input():
    _, op, _ = wired()
    js = op['native_target']['javascript']
    assert 'fields.every((e,i)=>e&&e.value===baseline[i])' in js
    assert js.index('if(!unchanged())') < js.index('request:c.request')
    assert 'document.activeElement===element' in js and 'element.focus()' in js
    assert js.index('const result=move(focus)') < js.index('ack.value=result') < js.index('request:c.ack_request')
    assert 'result==="FOCUSED"||result==="ALREADY_ACTIVE"' in js
    assert 'marker retained' in js and 'Whole-form commit is never replaced with a single-row Save' in js


def test_host_adapter_is_explicit_trusted_generation_seam_with_fail_closed_contract():
    from fox.forms_item_entry_workflow import compile_item_entry_workflows
    from fox.forms_bag_entry_wiring import _source_contract
    from fox.forms_behavior_plan import _source_objects
    _, op, args = wired()
    plan = compile_item_entry_workflows(*args)
    source_op = next(o for o in plan['operations'] if o['source_unit_id'] == op['source_unit_id'])
    objects, props = _source_objects(args[0], args[1])
    approved, condition = _source_contract(source_op, op['contract'], objects, props, args[3])
    buffer = next(b for b in json.loads(args[-1]['fox-package/buffer-plan.json'])['operations'] if b['operation_id'] == op['buffer_operation_id'])
    declarations = "function host_form_status return varchar2 is begin return 'QUERY';end;function host_commit_form return varchar2 is begin return 'FAILED';end;"
    code = render_bag_entry_process(buffer, op['page_id'], op['contract'], approved, condition, op['relative_next'], host_declarations=declarations)
    assert declarations in code and "return 'UNKNOWN'" not in code
    assert "l_outcome is null or l_outcome<>'COMMITTED'" in code
    assert 'STALE_AFTER_WHOLE_FORM_COMMIT' in code and 'STALE_AFTER_FINAL_FORM_STATUS' in code
