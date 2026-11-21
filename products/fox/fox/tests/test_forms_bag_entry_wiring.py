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
    assert js.index('const result=move(element)') < js.index('ack.value=result') < js.index('request:c.ack_request')
    assert 'result==="FOCUSED"||result==="ALREADY_ACTIVE"' in js
    assert 'marker retained' in js and 'Whole-form commit is never replaced with a single-row Save' in js


def test_source_focus_runs_once_after_apex_initialization_and_observes_focus_before_ack():
    _, op, _ = wired()
    js = op['native_target']['javascript']
    assert 'one("apexreadyend.foxBagEntry"' in js
    assert 'window.setTimeout(complete,0)' in js
    assert '["FOCUS_PENDING","NEXT_PENDING","MARKER_CLEARED_AFTER_FOCUS"].includes(outcome)' in js
    assert 'if(handled)return;handled=true;' in js
    assert 'window.requestAnimationFrame(function(){' in js
    held = js.index('const held=')
    ack = js.index('ack.value=result')
    assert held < js.index('if(!held)') < ack
    assert 'unchanged()&&document.activeElement===element' in js[held:ack]
    assert 'if(event.isTrusted){interrupted=true;cleanup();' in js
    assert 'document.removeEventListener("pointerdown",interrupt,true)' in js
    assert 'document.removeEventListener("keydown",interrupt,true)' in js
    assert 'submitted=true;ack.value=result;apex.submit' in js
    # Ordinary loads keep the existing APEX/native navigation policy. Only the
    # source-result continuation registers the ready handler; there is no retry
    # timer or document-wide focus lock to steal a later deliberate user focus.
    assert 'setInterval' not in js and 'cursorFocus' not in js


@pytest.mark.parametrize('renamed', [False, True])
@pytest.mark.parametrize('destination,code,status,expected', [
    (None, 'UNSAVED', 'INSERT', 1), (None, 'UNSAVED', 'CHANGED', 1),
    (None, 'UNSAVED', 'QUERY', 0), ('CITY', 'UNSAVED', 'INSERT', 0),
    (None, None, 'INSERT', 0),
])
def test_native_keep_can_establish_reset_marker_from_real_validation_condition(
        renamed, destination, code, status, expected):
    from fox.forms_item_validation import _effect_body
    _, op, args = wired(renamed)
    validation, = json.loads(args[-1]['fox-package/item-validation-receipt.json'])['generated_operations']
    body = _effect_body(validation['parsed'], validation['contract'])
    condition, warning = re.match(r'if (.*?) then\n(.*?)\nelse', body, re.S).groups()
    db = sqlite3.connect(':memory:')
    for name in ('l_destination', 'l_code', 'l_status'):
        condition = condition.replace(name, ':' + name)
    assert db.execute('select case when ' + condition + ' then 1 else 0 end',
                      {'l_destination': destination, 'l_code': code, 'l_status': status}).fetchone() == (expected,)
    assert "l_marker:='X';" in warning and 'l_failed:=' not in warning and 'l_code:=' not in warning
    text = args[-1][op['page_file']].decode()
    process = re.search(r'process validate-edited-item \(.*?```plsql\n(.*?)\n\s*```', text, re.S)[1]
    assert "'FOX_DRAFT_KEEP'" in process and "'FOX_DRAFT_NEW'" in process
    assert "l_status:=case when l_id is null then 'INSERT' else 'CHANGED' end;" in process
    compact = lambda value: re.sub(r'\s+', '', value)
    assert compact(process).index(compact(body)) < compact(process).index('p_attr_number=>42,p_attr_value=>l_marker')


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


@pytest.mark.parametrize('renamed', [False, True])
def test_explicit_native_return_carries_signed_parent_and_one_shot_result_without_changing_old_branch(renamed):
    files, op, args = wired(renamed)
    native = op['native_target']; page = op['page_id']; text = files[op['page_file']].decode()
    branch = native['return_branch']
    assert branch in text
    assert 'point: afterProcessing' in branch and 'sequence: 5' in branch
    assert 'value: FOX_BAG_ENTRY,FOX_BAG_ENTRY_FOCUS' in branch
    assert f'P{page}_PARENT_ID: "&P{page}_PARENT_ID."' in branch
    assert f'P{page}_BAG_RETURN: "&P{page}_BAG_RETURN."' in branch
    # Rendering GET URLs receive exactly the protected parent and receipt token;
    # outcome, cursor, revision and continuation nonce come from server receipt.
    arguments = re.findall(r'(P\d+_[A-Z_]+): "&([^".]+)\."', branch)
    post = {f'P{page}_PARENT_ID': '41', f'P{page}_BAG_RETURN': 'F'*32}
    rendered_get = {key: post[value] for key, value in arguments}
    assert rendered_get == post
    for name in ('PARENT_ID', 'BAG_RETURN'):
        item = re.search(r'    pageItem P'+str(page)+'_'+name+r' \(.*?\n    \)', text, re.S)[0]
        assert 'sessionStateProtection: checksumRequiredSessionLevel' in item
        assert 'storage: request' in item and 'valueProtected: false' not in item
    old = re.search(r'    branch show-current-record \(.*?\n    \)', args[-1][op['page_file']].decode(), re.S)[0]
    assert old in text


def test_return_receipt_persists_post_action_outcome_then_consumes_before_exact_selection_recheck():
    _, op, _ = wired(); native = op['native_target']; page = op['page_id']
    capture, projection = native['return_capture_plsql'], native['projection_plsql']
    assert f"p_c006=>:P{page}_BAG_STATE,p_c007=>:P{page}_BAG_NONCE" in capture
    assert f"p_c004=>:P{page}_SEQ,p_c005=>:P{page}_REV" in capture
    assert 'p_c008=>l_name,p_n001=>l_id' in capture
    assert native['return_source_digest'] in capture and native['return_source_digest'] in projection
    assert capture.index('if :REQUEST is null') < capture.index('l_ticket:=rawtohex(sys_guid())')
    assert f':P{page}_BAG_RETURN:=l_ticket' in capture
    assert projection.index(f':P{page}_BAG_STATE:=null') < projection.index('if l_ticket is not null')
    assert projection.index('apex_collection.delete_member') < projection.index('if not context_ok')
    assert projection.index('if not context_ok') < projection.index(f':P{page}_BAG_STATE:=l_return_state')
    for guard in ('l_return_parent<>to_char(l_parent', 'l_return_row<>to_char(l_seq',
                  'l_return_revision<>to_char(l_revision', 'l_return_name<>l_name',
                  'decode(l_return_id,l_id,1,0)', 'l_return_nonce<>l_pending',
                  'l_expected_hash<>l_destination_hash'):
        assert projection.index(guard) < projection.index(f':P{page}_BAG_STATE:=l_return_state')
    assert "if l_return_state='FOCUS_PENDING'" in projection
    assert "elsif l_return_state='MARKER_CLEARED_AFTER_FOCUS'" in projection
    assert "if l_code is not null or l_marker is not null or l_pending is not null then return" in projection
    assert 'if :REQUEST is not null then return' in projection
    # A new/empty draft can still render the focus continuation: no saved row
    # produces a scalar NULL projection, rather than an early NO_DATA_FOUND.
    assert re.search(r'select \(select c\.\w+ from \w+ c where c.FOX_ROW_ID=l_id\) into :P\d+_BAG_NEXT from dual;', projection)


@pytest.mark.parametrize('change,found', [({}, True), ({'ticket': 'old'}, False),
    ({'source': 'foreign'}, False), ({'collection': 'foreign'}, False), ({'created': 0}, False)])
def test_actual_emitted_return_selection_query_rejects_wrong_expired_or_foreign_receipts(change, found):
    _, op, _ = wired(); native = op['native_target']; projection = native['projection_plsql']
    match = re.search(r'(select seq_id,c003,c004,c005,c006,c007,c008,n001)\s+into .*?\s+(from apex_collections where .*?);', projection, re.S)
    query = (match[1] + ' ' + match[2]).replace('l_ticket', ':ticket').replace('sysdate', ':now')
    db = sqlite3.connect(':memory:')
    db.execute('create table apex_collections(collection_name text,seq_id integer,c001 text,c002 text,c003 text,c004 text,c005 text,c006 text,c007 text,c008 text,n001 numeric,d001 numeric)')
    values = {'collection': native['return_collection'], 'ticket': 'current', 'source': native['return_source_digest'], 'created': 100}
    values.update(change)
    db.execute('insert into apex_collections values(?,1,?,?,\'41\',\'2\',\'5\',\'FOCUS_PENDING\',\'nonce\',\'draft-41\',11,?)',
               (values['collection'], values['ticket'], values['source'], values['created']))
    rows = db.execute(query, {'ticket': 'current', 'now': 100}).fetchall()
    assert bool(rows) is found
    if found:
        assert rows == [(1, '41', '2', '5', 'FOCUS_PENDING', 'nonce', 'draft-41', 11)]
