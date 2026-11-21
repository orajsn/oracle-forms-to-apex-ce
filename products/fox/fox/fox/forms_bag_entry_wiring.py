"""Connect the closed bag entry program to the existing guarded session draft.

The two native requests preserve the source continuation: clear code, observe
actual browser focus, then clear the marker. Neither request saves a business
row. Whole-form status/commit requires a trusted host implementation, supplied
at generation time through ``render_bag_entry_process``; the default is unknown.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_buffer
from .forms_behavior_plan import _source_objects
from .forms_draft_providers import rebuild_draft_providers
from .forms_item_entry_workflow import (compile_item_entry_workflows,
                                       _sql_expression)
from .forms_item_validation import _resolve, _check_capacity

SCOPE = 'fox-source-bag-entry-wiring-v1'
REQUEST = 'FOX_BAG_ENTRY'
ACK_REQUEST = 'FOX_BAG_ENTRY_FOCUS'
PENDING_NONCE_SLOT = 'c045'
PENDING_DESTINATION_SLOT = 'c046'


def _need(value, reason):
    if not value:
        raise ValueError('BAG_ENTRY_' + reason)


def _one(values, reason):
    _need(len(values) == 1, reason)
    return values[0]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _shape(node):
    """Discard source positions, retaining every executable AST component."""
    if isinstance(node, list):
        return [_shape(n) for n in node]
    if not isinstance(node, dict):
        return node
    if node.get('kind') == 'reference':
        return {'ref': node.get('source_item_id', node.get('binding'))}
    if node.get('kind') == 'go_item':
        return {'kind': 'go_item', 'source_item_id': node['source_item_id']}
    return {k: _shape(v) for k, v in node.items() if k not in ('position', 'ordinal')}


def _source_contract(op, layout, objects, props, trace):
    f = layout['fields']
    _need(op['owner_item_id'] == f['marker']['source_item_id'], 'MARKER_OWNER')
    refs = {name: {'ref': f[name]['source_item_id']} for name in ('code', 'marker')}
    parent = _one([b for b in trace['blocks'] if b['table_name'] == layout['parent_table']], 'PARENT')
    approved = _one([v for v in op['fields'].values()
                     if v['source_block_id'] == parent['source_block_id']], 'APPROVAL_FIELD')
    a = {'ref': approved['source_item_id']}
    literal = lambda value: {'kind': 'literal', 'value': value}
    compare = lambda kind, left, right: {'kind': kind, 'left': left, 'right': right}
    next_item = {'kind': 'next_item'}
    null_assignment = lambda target: {'kind': 'assign', 'target': target, 'value': literal(None)}
    conditional = lambda condition, body, other: {
        'kind': 'if', 'branches': [{'condition': condition, 'body': body}], 'else': other}
    outer_condition = compare('and', compare('and', {'kind': 'is_not_null', 'value': refs['code']},
        {'kind': 'is_not_null', 'value': refs['marker']}),
        compare('eq', {'kind': 'nvl', 'value': a, 'fallback': literal('N')}, literal('N')))
    inner = {'kind': 'if', 'branches': [
        {'condition': compare('ne', refs['marker'], literal('X')), 'body': [
            conditional(compare('ne', {'ref': 'system_form_status'}, literal('QUERY')),
                        [{'kind': 'commit_form'}], []), next_item]},
        {'condition': compare('eq', refs['marker'], literal('X')), 'body': [
            null_assignment(refs['code']),
            {'kind': 'go_item', 'source_item_id': f['destination']['source_item_id']},
            null_assignment(refs['marker'])]}], 'else': [next_item]}
    _need(_shape(op['parsed']['body']) == [conditional(outer_condition, [inner], [next_item])],
          'COMPLETE_ORDERED_SOURCE_REQUIRED')
    mapped = _one([v for v in parent['items'] if v['source_item_id'] == approved['source_item_id']], 'APPROVAL_COLUMN')
    _need(mapped['data_type'] == 'VARCHAR2', 'APPROVAL_TYPE')
    destination = objects[f['destination']['source_item_id']]
    _need(props[destination['id']].get('DatabaseItem', '').lower() == 'false', 'TRANSIENT_DESTINATION')
    _focusable(destination, props, require_canvas=False)
    return mapped, op['parsed']['body'][0]['branches'][0]['condition']


def _focusable(item, props, *, require_canvas=True):
    p = props[item['id']]
    _need(p.get('ItemType', '').upper() == 'TEXT ITEM' and
          all(p.get(k, '').strip().lower() in ('', 'true') for k in
              ('Visible', 'Displayed', 'Enabled', 'KeyboardNavigable', 'Navigable')) and
          (not require_canvas or bool(p.get('CanvasName'))), 'SOURCE_FOCUS_TARGET_UNAVAILABLE')


def _relative_next(op, objects, props, buffer, trace):
    owner = objects[op['owner_item_id']]
    explicit = props[owner['id']].get('NextNavigationItem', '').strip()
    if explicit:
        target = _resolve(explicit.upper().split('.'), owner, objects)
        proof = 'explicit_XML_NextNavigationItem'
    else:
        # XML declaration order is used only within the same block, without
        # wrapping a record or guessing a block transition.
        items = [v for v in objects.values() if v['kind'] == 'Item' and v['block_id'] == owner['block_id']]
        after = items[items.index(owner)+1:]
        target = None
        for item in after:
            p = props[item['id']]
            if not p.get('CanvasName') or p.get('ItemType', '').upper() == 'DISPLAY ITEM' or any(
                    p.get(k, '').strip().lower() == 'false' for k in
                    ('Visible', 'Displayed', 'Enabled', 'KeyboardNavigable', 'Navigable')):
                continue
            # An unsupported navigable widget is a boundary, never permission
            # to skip it and pretend the following text field was NEXT_ITEM.
            _focusable(item, props)
            target = item
            break
        _need(target, 'RELATIVE_NEXT_REQUIRES_RECORD_OR_BLOCK_ADAPTER')
        proof = 'XML_item_declaration_order_next_canvas_text_item_same_record_no_wrap'
    _focusable(target, props, require_canvas=not bool(explicit))
    _need(target['block_id'] == owner['block_id'], 'RELATIVE_NEXT_CROSS_BLOCK')
    child = _one([b for b in trace['blocks'] if b['source_block_id'] == owner['block_id']], 'NEXT_BLOCK')
    mapped = _one([f for f in child['items'] if f['source_item_id'] == target['id']], 'NEXT_FIELD')
    return {'source_item_id': target['id'], 'source_name': target['name'], 'column': mapped['column'],
            'data_type': mapped['data_type'], 'proof': proof,
            'value_scope': 'current_saved_synthetic_row_projection_only_no_transient_value_inferred'}


def _prove_provider(documents, packet, chunks, trace, files, op):
    plan, targets, proved, saves, layouts = rebuild_draft_providers(documents, packet, chunks, trace, files)
    layout = _one([c for c in layouts.values() if c['fields']['marker']['source_item_id'] == op['owner_item_id']], 'RETAINED_MARKER_PROVIDER')
    buffer = _one([b for b in plan['operations'] if b['operation_id'] == layout['buffer_operation_id']], 'BUFFER')
    target = _one([t for t in targets if t['operation_id'] == buffer['operation_id']], 'DRAFT_PAGE')
    # Rebuild the allowed master/detail additions. Clear gates only decorate the
    # separate selection pages and cannot authorize changes to this draft page.
    from .forms_master_detail import apply_master_details, _entry_button
    population = json.loads(files.get('fox-package/master-detail-receipt.json', b'{"adapted_operations":[]}'))
    if population.get('adapted_operations'):
        clean = dict(files)
        for t in targets:
            clean[t['page_file']] = proved[t['page_file']]
        for value in population['adapted_operations']:
            clean.pop(value['page_file'], None)
            entry = _entry_button(value['page_id']).encode()
            parent = value['entry_report_file']
            _need(clean[parent].count(entry) == 1, 'POPULATION_ENTRY_CHANGED')
            clean[parent] = clean[parent].replace(entry, b'')
        expected, proof = apply_master_details(documents, packet, chunks, trace, clean)
        _need(proof == population, 'POPULATION_RECEIPT_CHANGED')
    else:
        expected = proved
    _need(expected[target['page_file']] == files[target['page_file']], 'EXACT_GUARDED_DRAFT_PAGE')
    return buffer, target, layout


def render_bag_entry_process(buffer, page, layout, approved, condition, next_binding=None,
                             *, host_declarations=''):
    """Trusted generator seam for a whole-form adapter, never browser source.

    ``host_declarations`` defines ``host_form_status return varchar2`` and
    ``host_commit_form return varchar2``. Status must be QUERY/CHANGED/NEW;
    successful commit must return COMMITTED. The host must include every form
    draft, validation and posting boundary, and must not commit this request's
    session continuation or replace COMMIT_FORM with the current-row Save.
    Unknown/failed results block Next. Recheck context after every host call.
    """
    c, f = layout, layout['fields']
    slot = c['code_slot']
    declarations = native_buffer._declarations(buffer, page)
    read = native_buffer._read_parent(buffer, 'l_exists', lock=True)
    declarations = declarations.replace(read, read + f"select {c['policy_expression_sql']} into l_exists from {c['parent_table']} where FOX_ROW_ID=l_parent;if nvl(l_exists,0)<>1 then return false;end if;")
    declarations = declarations.replace(native_buffer._name(buffer), c['collection_namespace'])
    submitted_equal = ' and '.join(native_buffer._parent_match(f'l_value{i}', f'l_original{i}')
                                   for i in range(1, len(buffer['key_bindings'])+1))
    equal = ' and '.join(native_buffer._parent_match('c.' + field['column'], f'd.c{20+i:03d}')
                         for i, field in enumerate(buffer['key_bindings'], 1))
    equal += ' and ' + native_buffer._parent_match('c.' + f['route']['column'], 'd.c040')
    equal += ' and decode(c.' + f['weight']['column'] + ',d.n003,1,0)=1'
    membership = c['membership_sql'].replace('l_parent', 'bag_entry.l_parent')
    columns = {f['code']['source_item_id']: 'l_code', f['marker']['source_item_id']: 'l_marker',
               approved['source_item_id']: 'l_approved'}
    test = _sql_expression(condition, columns)
    host = host_declarations or "function host_form_status return varchar2 is begin return 'UNKNOWN';end;function host_commit_form return varchar2 is begin return 'UNAVAILABLE';end;"
    next_state = 'NEXT_PENDING' if next_binding else 'NEXT_ITEM_UNAVAILABLE'
    attr = lambda number, value, numeric=False, seq='l_seq': (
        'apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>' + seq +
        ',p_attr_number=>' + str(number) + (',p_number_value=>' if numeric else ',p_attr_value=>') + value + ');')
    bump = attr(3, 'l_revision+1', True, '1') + f":P{page}_REV:=to_char(l_revision+1,'TM9');"
    return f"""<<bag_entry>>
declare
l_id number;l_found number;l_code varchar2(4000);l_marker varchar2(4000);l_pending varchar2(4000);
l_destination varchar2(4000);l_destination_hash varchar2(64);l_expected_hash varchar2(64);l_approved varchar2(4000);
l_status varchar2(30);l_outcome varchar2(30);l_mutating boolean:=false;
{declarations}
{host}
begin
 if :REQUEST is null or :REQUEST not in ('{REQUEST}','{ACK_REQUEST}') then return;end if;
 :P{page}_BAG_STATE:='STALE_CONTEXT';
 if not context_ok then return;end if;
 select case when {submitted_equal} then 1 else 0 end into l_found from dual;
 if l_found<>1 then :P{page}_BAG_STATE:='UNKEPT_INPUT';return;end if;
 select count(*) into l_found from {c['parent_table']} where """ + ' and '.join(
        native_buffer._parent_match(column, f'l_value{i}') for i, column in native_buffer._parent_copies(buffer)) + f""";
 if l_found<>1 then return;end if;
 select n001,c{slot:03d},c042,c045,c046 into l_id,l_code,l_marker,l_pending,l_expected_hash
  from apex_collections where collection_name=l_name and seq_id=l_seq and c050='ROW';
 if l_id is not null then
  select c.FOX_ROW_ID into l_found from {c['child_table']} c where c.FOX_ROW_ID=bag_entry.l_id
   and {membership} and exists(select 1 from apex_collections d where d.collection_name=bag_entry.l_name
    and d.seq_id=bag_entry.l_seq and d.c041='SYNTHETIC_SAVE_BASELINE_V1' and {equal}) for update nowait;
 end if;
 select {f['destination']['column']},{approved['column']},rawtohex(standard_hash(case when {f['destination']['column']} is null then 'N:' else 'V:'||{f['destination']['column']} end,'SHA256'))
  into l_destination,l_approved,l_destination_hash from {c['parent_table']} where FOX_ROW_ID=l_parent;
 :P{page}_BAG_DEST:=l_destination;
 if :REQUEST='{ACK_REQUEST}' then
  if l_pending is null or :P{page}_BAG_NONCE is null or l_pending<>:P{page}_BAG_NONCE
    or l_expected_hash is null or l_expected_hash<>l_destination_hash or l_code is not null
    or l_marker is null or l_marker<>'X' or nvl(l_approved,'N')<>'N'
    or :P{page}_BAG_FOCUS is null or :P{page}_BAG_FOCUS not in ('FOCUSED','ALREADY_ACTIVE') then
   :P{page}_BAG_STATE:='FOCUS_NOT_CONFIRMED_OR_STALE';return;end if;
  savepoint fox_bag_entry;l_mutating:=true;
  {attr(42, 'null')}{attr(45, 'null')}{attr(46, 'null')}{bump}
  :P{page}_BAG_STATE:='MARKER_CLEARED_AFTER_FOCUS';:P{page}_BAG_NONCE:=null;return;
 end if;
 if l_pending is not null then
  if l_code is null and l_marker='X' and nvl(l_approved,'N')='N' and l_expected_hash=l_destination_hash then
   :P{page}_BAG_NONCE:=l_pending;:P{page}_BAG_STATE:='FOCUS_PENDING';
  else :P{page}_BAG_STATE:='PENDING_FOCUS_CONTEXT_CHANGED';end if;return;
 end if;
 if {test} then
  if l_marker='X' then
   savepoint fox_bag_entry;l_mutating:=true;
   {attr(slot, 'null')}:P{page}_K{slot}:=null;
   l_pending:=rawtohex(sys_guid());
   {attr(45, 'l_pending')}{attr(46, 'l_destination_hash')}{bump}
   :P{page}_BAG_NONCE:=l_pending;:P{page}_BAG_STATE:='FOCUS_PENDING';return;
  end if;
  l_status:=host_form_status;
  if not context_ok then :P{page}_BAG_STATE:='STALE_AFTER_FORM_STATUS';return;end if;
  if l_status is null or l_status not in ('QUERY','CHANGED','NEW') then :P{page}_BAG_STATE:='WHOLE_FORM_STATUS_UNAVAILABLE';return;end if;
  if l_status<>'QUERY' then
   :P{page}_BAG_STATE:='WHOLE_FORM_COMMIT_OUTCOME_UNKNOWN';
   l_outcome:=host_commit_form;
   if l_outcome is null or l_outcome<>'COMMITTED' then :P{page}_BAG_STATE:='WHOLE_FORM_COMMIT_FAILED_OR_UNKNOWN';return;end if;
   if not context_ok then :P{page}_BAG_STATE:='STALE_AFTER_WHOLE_FORM_COMMIT';return;end if;
   l_status:=host_form_status;
   if l_status is null or l_status<>'QUERY' then :P{page}_BAG_STATE:='FORM_NOT_CLEAN_AFTER_COMMIT';return;end if;
   if not context_ok then :P{page}_BAG_STATE:='STALE_AFTER_FINAL_FORM_STATUS';return;end if;
  end if;
 end if;
 :P{page}_BAG_STATE:='{next_state}';
exception when others then
 if l_mutating then rollback to fox_bag_entry;end if;
 apex_debug.error('Bag entry stopped: %s',sqlerrm);
 if :P{page}_BAG_STATE<>'WHOLE_FORM_COMMIT_OUTCOME_UNKNOWN' then :P{page}_BAG_STATE:='STALE_OR_FAILED';end if;
end;"""


def bag_entry_runtime(config):
    literal = json.dumps(config, ensure_ascii=True, separators=(',', ':')).replace('<', '\\u003c')
    return r'''(function(){
"use strict";
const c=CONFIG, get=id=>document.getElementById(id);
const state=get(c.state_item), focus=get(c.destination_item), next=c.next_item&&get(c.next_item);
const status=get(c.status_id), fields=c.draft_items.map(get);
const baseline=fields.map(e=>e&&e.value);
const say=value=>{if(status)status.textContent=value;};
let submitted=false, interrupted=false, handled=false;
if(focus)focus.readOnly=true;if(next)next.readOnly=true;
function unchanged(){return fields.every((e,i)=>e&&e.value===baseline[i]);}
function move(element){
 if(!element||element.disabled||element.hidden||element.readOnly===false)return "UNAVAILABLE";
 const already=document.activeElement===element;
 try{element.focus();}catch(e){return "FAILED";}
 return document.activeElement===element?(already?"ALREADY_ACTIVE":"FOCUSED"):"FAILED";
}
function enter(){
 if(submitted)return false;
 if(!unchanged()){say("Keep the edited draft before entering this source action.");return false;}
 submitted=true;apex.submit({request:c.request,validate:false});return true;
}
const button=get(c.button_id);if(button)button.addEventListener("click",enter);
const outcome=state&&state.value;
function cleanup(){
 document.removeEventListener("pointerdown",interrupt,true);
 document.removeEventListener("keydown",interrupt,true);
}
function interrupt(event){
 if(event.isTrusted){interrupted=true;cleanup();
  say("Source focus continuation cancelled by user input; no focus acknowledgment was sent.");}
}
function complete(){
 if(handled)return;handled=true;
 if(interrupted||submitted){cleanup();return;}
 if(!state||state.value!==outcome||!unchanged()){
  cleanup();say("The draft or continuation changed; no focus acknowledgment was sent; marker retained.");return;
 }
 const element=outcome==="NEXT_PENDING"?next:focus;
 const result=move(element);
 // APEX's ready event includes delayed components. Yield once more so other
 // ready handlers finish, then observe focus across a frame before any ACK.
 window.requestAnimationFrame(function(){
  cleanup();if(interrupted||submitted)return;
  const held=(result==="FOCUSED"||result==="ALREADY_ACTIVE")&&document.activeElement===element;
  if(outcome==="NEXT_PENDING"){
   say("Source Next: "+(held?result:"FAILED")+". This control displays the saved value only.");return;
  }
  if(outcome==="MARKER_CLEARED_AFTER_FOCUS"){
   say(held?"Code cleared; destination focus confirmed; marker cleared. Original lookup remains unavailable.":
    "Code and marker were cleared; destination focus was not retained on this page. Original lookup remains unavailable.");return;
  }
  if(!held){say("Destination focus failed or was not retained; code remains cleared and marker retained. Reopen before continuing.");return;}
  const nonce=get(c.nonce_item), ack=get(c.focus_item);
  if(nonce&&nonce.value&&ack&&state.value===outcome&&unchanged()&&document.activeElement===element){
   say("Header destination focus: "+result+". The original lookup is unavailable.");
   submitted=true;ack.value=result;apex.submit({request:c.ack_request,validate:false});
  }else say("Focus succeeded, but the continuation is missing or the draft changed; marker retained.");
 });
}
if(["FOCUS_PENDING","NEXT_PENDING","MARKER_CLEARED_AFTER_FOCUS"].includes(outcome)){
 document.addEventListener("pointerdown",interrupt,true);
 document.addEventListener("keydown",interrupt,true);
 apex.jQuery(apex.gPageContext$).one("apexreadyend.foxBagEntry",function(){window.setTimeout(complete,0);});
}else if(outcome)say("Bag entry stopped: "+outcome+". Whole-form commit is never replaced with a single-row Save.");
window.foxBagEntry=Object.freeze({enter,move,config:c});
})();'''.replace('CONFIG', literal)


def _return_capture(buffer, page, layout, collection, source_digest):
    """Retain one server result for the signed POST/redirect/GET continuation."""
    values = native_buffer._value_declarations(buffer)
    read = native_buffer._read_parent(buffer, 'l_exists', lock=True).replace(
        native_buffer._name(buffer), layout['collection_namespace'])
    return f"""declare
{values}
l_parent number;l_name varchar2(255);l_exists number;l_id number;l_count number;l_ticket varchar2(64);
begin
 if :REQUEST is null or :REQUEST not in ('{REQUEST}','{ACK_REQUEST}') then return;end if;
 :P{page}_BAG_RETURN:=null;
 if :P{page}_PARENT_ID is null or not regexp_like(:P{page}_PARENT_ID,'^[1-9][0-9]{{0,27}}$')
  or :P{page}_SEQ is null or not regexp_like(:P{page}_SEQ,'^[1-9][0-9]{{0,9}}$')
  or :P{page}_REV is null or not regexp_like(:P{page}_REV,'^[0-9]{{1,15}}$')
  or :P{page}_BAG_STATE is null then raise_application_error(-20061,'Draft return context is unavailable.');end if;
 l_parent:=to_number(:P{page}_PARENT_ID);
 {read}
 select n001 into l_id from apex_collections where collection_name=l_name
  and seq_id=to_number(:P{page}_SEQ) and c050='ROW';
 if not apex_collection.collection_exists('{collection}') then apex_collection.create_collection('{collection}');end if;
 for expired in (select seq_id from apex_collections where collection_name='{collection}' and d001<sysdate-5/(24*60)) loop
  apex_collection.delete_member(p_collection_name=>'{collection}',p_seq=>expired.seq_id);end loop;
 select count(*) into l_count from apex_collections where collection_name='{collection}';
 if l_count>=100 then raise_application_error(-20062,'Too many open draft returns. Reopen after older returns expire.');end if;
 l_ticket:=rawtohex(sys_guid());
 apex_collection.add_member(p_collection_name=>'{collection}',p_c001=>l_ticket,p_c002=>'{source_digest}',
  p_c003=>to_char(l_parent,'TM9'),p_c004=>:P{page}_SEQ,p_c005=>:P{page}_REV,
  p_c006=>:P{page}_BAG_STATE,p_c007=>:P{page}_BAG_NONCE,p_c008=>l_name,p_n001=>l_id,p_d001=>sysdate);
 :P{page}_BAG_RETURN:=l_ticket;
exception when others then
 :P{page}_BAG_RETURN:=null;
 apex_debug.error('Bag entry return failed: %s',sqlerrm);
 apex_error.add_error(p_message=>'The draft return could not be prepared. Reopen the selected parent; no entry result was replayed.',
  p_display_location=>apex_error.c_inline_in_notification);
end;"""


def _return_branch(page):
    # Native page targets sign protected item arguments, exactly as the normal
    # draft return. Keep the old Keep/Next/Save branch and its condition intact.
    return f'''    branch show-bag-entry-result (
        name: Show current bag entry result
        execution {{ sequence: 5
            point: afterProcessing }}
        behavior {{ type: pageOrUrl
            target: {{ page: {page}
                items: {{
                    P{page}_PARENT_ID: "&P{page}_PARENT_ID."
                    P{page}_BAG_RETURN: "&P{page}_BAG_RETURN."
                }}
            }}
        }}
        serverSideCondition {{ type: requestIsContainedInValue
            value: {REQUEST},{ACK_REQUEST} }}
    )
'''


def _return_projection(buffer, page, layout, relative, collection, source_digest):
    c, f = layout, layout['fields']
    declarations = native_buffer._declarations(buffer, page)
    read = native_buffer._read_parent(buffer, 'l_exists', lock=True)
    declarations = declarations.replace(read, read + f"select {c['policy_expression_sql']} into l_exists from {c['parent_table']} where FOX_ROW_ID=l_parent;if nvl(l_exists,0)<>1 then return false;end if;")
    declarations = declarations.replace(native_buffer._name(buffer), c['collection_namespace'])
    equal = ' and '.join(native_buffer._parent_match('c.' + field['column'], f'd.c{20+i:03d}')
                         for i, field in enumerate(buffer['key_bindings'], 1))
    equal += ' and ' + native_buffer._parent_match('c.' + f['route']['column'], 'd.c040')
    equal += ' and decode(c.' + f['weight']['column'] + ',d.n003,1,0)=1'
    membership = c['membership_sql'].replace('l_parent', 'bag_return.l_parent')
    source = f"select {f['destination']['column']},rawtohex(standard_hash(case when {f['destination']['column']} is null then 'N:' else 'V:'||{f['destination']['column']} end,'SHA256')) into :P{page}_BAG_DEST,l_destination_hash from {c['parent_table']} where FOX_ROW_ID=l_parent;"
    if relative:
        source += f"select (select c.{relative['column']} from {c['child_table']} c where c.FOX_ROW_ID=l_id) into :P{page}_BAG_NEXT from dual;"
    return f"""<<bag_return>>
declare
l_ticket varchar2(64);l_return_seq number;l_return_parent varchar2(4000);l_return_row varchar2(4000);
l_return_revision varchar2(4000);l_return_state varchar2(4000);l_return_nonce varchar2(4000);l_return_name varchar2(4000);
l_return_id number;l_id number;l_found number;l_pending varchar2(4000);l_expected_hash varchar2(64);
l_destination_hash varchar2(64);l_code varchar2(4000);l_marker varchar2(4000);
{declarations}
begin
 l_ticket:=:P{page}_BAG_RETURN;:P{page}_BAG_RETURN:=null;
 :P{page}_BAG_STATE:=null;:P{page}_BAG_NONCE:=null;:P{page}_BAG_FOCUS:=null;
 :P{page}_BAG_DEST:=null;""" + (f':P{page}_BAG_NEXT:=null;' if relative else '') + f"""
 if l_ticket is not null then
  :P{page}_BAG_STATE:='STALE_RETURN';
  select seq_id,c003,c004,c005,c006,c007,c008,n001
   into l_return_seq,l_return_parent,l_return_row,l_return_revision,l_return_state,l_return_nonce,l_return_name,l_return_id
   from apex_collections where collection_name='{collection}' and c001=l_ticket
    and c002='{source_digest}' and d001>=sysdate-5/(24*60);
  apex_collection.delete_member(p_collection_name=>'{collection}',p_seq=>l_return_seq);
  if :REQUEST is not null then return;end if;
 end if;
 if not context_ok then return;end if;
 select n001,c045,c046,c{c['code_slot']:03d},c042 into l_id,l_pending,l_expected_hash,l_code,l_marker
  from apex_collections where collection_name=l_name and seq_id=l_seq and c050='ROW';
 if l_id is not null then
  select c.FOX_ROW_ID into l_found from {c['child_table']} c where c.FOX_ROW_ID=bag_return.l_id
   and {membership} and exists(select 1 from apex_collections d where d.collection_name=bag_return.l_name
    and d.seq_id=bag_return.l_seq and d.c041='SYNTHETIC_SAVE_BASELINE_V1' and {equal}) for update nowait;
 end if;
 {source}
 if l_ticket is null then return;end if;
 if l_return_parent is null or l_return_row is null or l_return_revision is null or l_return_name is null
  or l_return_parent<>to_char(l_parent,'TM9') or l_return_row<>to_char(l_seq,'TM9')
  or l_return_revision<>to_char(l_revision,'TM9') or l_return_name<>l_name then return;end if;
 select case when decode(l_return_id,l_id,1,0)=1 then 1 else 0 end into l_found from dual;
 if l_found<>1 then return;end if;
 if l_return_state='FOCUS_PENDING' then
  if l_return_nonce is null or l_pending is null or l_return_nonce<>l_pending or l_code is not null
   or l_marker is null or l_marker<>'X' or l_expected_hash is null or l_expected_hash<>l_destination_hash then return;end if;
 elsif l_return_state='MARKER_CLEARED_AFTER_FOCUS' then
  if l_code is not null or l_marker is not null or l_pending is not null then return;end if;
 end if;
 :P{page}_BAG_STATE:=l_return_state;:P{page}_BAG_NONCE:=l_return_nonce;
exception when no_data_found then null;
 when others then :P{page}_BAG_STATE:='STALE_RETURN';:P{page}_BAG_NONCE:=null;
 apex_debug.error('Bag entry return unavailable: %s',sqlerrm);
end;"""


def _render(files, op, buffer, target, layout, approved, condition, relative):
    page = target['page_id']
    config = {k: f'P{page}_BAG_{v}' for k, v in (
        ('state_item', 'STATE'), ('destination_item', 'DEST'), ('nonce_item', 'NONCE'), ('focus_item', 'FOCUS'))}
    config.update(request=REQUEST, ack_request=ACK_REQUEST, button_id='fox-bag-entry-action',
                  status_id='fox-bag-entry-status', draft_items=[f'P{page}_K{i}' for i in range(1, len(buffer['key_bindings'])+1)],
                  next_item=f'P{page}_BAG_NEXT' if relative else None)
    text = files[target['page_file']].decode()
    # Existing Keep/Save/item validation must not bypass a half-completed
    # ordered reset. Scope this gate to the selected ROW, leaving siblings and
    # ordinary draft namespaces intact. Our own continuation uses fresh copies
    # of the unmodified declarations below.
    old_guard = 'return l_rows between 1 and 1000;'
    pending_guard = ("select count(*) into l_matches from apex_collections where collection_name=l_name "
                     "and seq_id=l_seq and c050='ROW' and c045 is not null;"
                     "if l_matches<>0 then return false;end if;" + old_guard)
    for slug in ('keep-draft-and-move', 'save-synthetic-record', 'validate-edited-item'):
        pattern = r'(    process ' + slug + r' \(.*?\n    \))'
        match = _one(list(re.finditer(pattern, text, re.S)), 'EXISTING_MUTATOR_PROCESS')
        _need(old_guard in match[0], 'EXISTING_MUTATOR_CONTEXT_GUARD')
        text = text[:match.start()] + match[0].replace(old_guard, pending_guard) + text[match.end():]
    script = bag_entry_runtime(config)
    matches = list(re.finditer(r'```javascript\n(.*?)\n\s*```', text, re.S))
    _need(len(matches) <= 1, 'ONE_DRAFT_SCRIPT')
    if matches:
        js = matches[0]
        text = text[:js.end(1)] + '\n' + native_buffer._indent(script, 12) + text[js.end(1):]
    else:
        text = text.replace(f'page {page} (\n', f'page {page} (\n    javaScript {{\n        executeWhenPageLoads:\n            ```javascript\n'
                            + native_buffer._indent(script, 12) + '\n            ```\n    }\n', 1)
    f = layout['fields']
    extra = '''    region bag-entry-action (
        name: Source bag entry
        type: staticContent
        source { htmlCode:
            ```html
            <p>The XML entry action uses the current kept bag draft. Destination is a focusable session projection; its original lookup is unavailable.</p><button type="button" id="fox-bag-entry-action">Enter current bag</button><p id="fox-bag-entry-status" role="status"></p>
            ```
        }
        layout { sequence: 32
            slot: body }
        appearance { template: @/standard }
    )
'''
    def control(name, label):
        return f'''    pageItem P{page}_BAG_{name} (
        type: textField
        label {{ label: {json.dumps(label)} }}
        layout {{ sequence: {901 if name=='DEST' else 902}
            region: @bag-entry-action
            slot: regionBody }}
        appearance {{ template: @/optional-floating }}
        sessionState {{ storage: request
            dataType: varchar2 }}
    )
'''
    extra += control('DEST', f['destination']['source_name'] + ' (session destination; lookup unavailable)')
    if relative:
        extra += control('NEXT', relative['source_name'] + ' (saved value; source Next target)')
    for i, name in enumerate(('STATE', 'NONCE', 'FOCUS', 'RETURN'), 1):
        extra += native_buffer._hidden(page, 'BAG_' + name, 920+i, protected=name != 'FOCUS')
    process = render_bag_entry_process(buffer, page, layout, approved, condition, relative)
    extra += native_buffer._process('source-bag-entry', process, point='afterSubmit', sequence=4)
    binding = json.loads(files['fox-package/source-manifest.json'])['source_binding']
    source_digest = hashlib.sha256(_json([SCOPE, binding, op['source_unit_id'], op['source_unit_sha256'], buffer['operation_id']])).hexdigest()
    returns = 'FOX_BR_' + source_digest[:24].upper()
    capture = _return_capture(buffer, page, layout, returns, source_digest)
    projection = _return_projection(buffer, page, layout, relative, returns, source_digest)
    branch = _return_branch(page)
    extra += native_buffer._process('retain-bag-entry-return', capture, point='processing', sequence=90)
    extra += branch
    extra += native_buffer._process('project-bag-entry-controls', projection, point='beforeHeader', sequence=50)
    _need(text.endswith(')\n'), 'PAGE_END')
    text = native_buffer._expand_groups(text[:-2] + extra + ')\n')
    _check_capacity(text)
    return text.encode(), {'runtime_config': config, 'javascript': script, 'process_plsql': process,
                           'projection_plsql': projection, 'return_capture_plsql': capture,
                           'return_branch': native_buffer._expand_groups(branch),
                           'return_collection': returns, 'return_source_digest': source_digest,
                           'return_item': f'P{page}_BAG_RETURN',
                           'return_scope': 'signed_parent_and_one_shot_source_bound_exact_selection_revision_row_outcome'}


def apply_bag_entry_wiring(documents, packet, chunks, trace, files):
    plan = compile_item_entry_workflows(documents, packet, chunks, trace, files)
    objects, props = _source_objects(documents, packet)
    output = dict(files)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': packet['source_binding'],
               'generated_operations': [], 'adapted_operations': [], 'gaps': [],
               'customer_table_writes': False, 'synthetic_table_writes': False, 'session_draft_writes': True,
               'original_reads_enabled': False, 'oracle_compiled': False,
               'runtime_verified': False, 'business_accepted': False}
    for op in plan['operations']:
        if op['source_event'] != 'WHEN-NEW-ITEM-INSTANCE' or op['summaries']:
            continue
        identity = {k: op[k] for k in ('source_unit_id', 'source_unit_sha256', 'operation_id', 'source_event')}
        try:
            buffer, target, layout = _prove_provider(documents, packet, chunks, trace, files, op)
            approved, condition = _source_contract(op, layout, objects, props, trace)
            next_gap = None
            try:
                relative = _relative_next(op, objects, props, buffer, trace)
            except ValueError as exc:
                relative, next_gap = None, str(exc)
            rendered, native = _render(files, op, buffer, target, layout, approved, condition, relative)
            output[target['page_file']] = rendered
            boundaries = ['original_destination_LOV_and_transient_lookup_lifecycle_unavailable',
                          'whole_form_status_and_commit_require_trusted_host_adapter',
                          'native_focus_acknowledgment_is_browser_observed_not_server_attested',
                          'full_Forms_item_validation_and_record_lifecycle']
            if next_gap:
                boundaries.append(next_gap)
            row = {**identity, 'page_file': target['page_file'], 'page_id': target['page_id'],
                   'generation_status': 'generated_wired_adapted_partial', 'native_event_wired': True,
                   'native_event': 'explicit_entry_of_current_kept_bag_draft',
                   'buffer_operation_id': buffer['operation_id'], 'contract': deepcopy(layout),
                   'destination_source_item_id': layout['fields']['destination']['source_item_id'],
                   'relative_next': relative, 'native_target': native,
                   'pending_slots': {'nonce': PENDING_NONCE_SLOT, 'destination_hash': PENDING_DESTINATION_SLOT, 'scope': 'current_ROW_only'},
                   'ordered_effects': ['clear_current_draft_code', 'verify_actual_header_destination_focus', 'clear_marker_after_guarded_focus_ack'],
                   'connected_effects': ['current_retained_marker_and_code', 'source_X_ordered_native_draft_continuation',
                                         'focusable_XML_header_destination_session_projection'] + (['source_relative_same_record_NEXT_ITEM'] if relative else []),
                   'remaining_boundaries': boundaries, 'host_adapter': {
                       'callable': 'fox.forms_bag_entry_wiring.render_bag_entry_process',
                       'argument': 'host_declarations', 'default_form_status': 'UNKNOWN',
                       'whole_form_commit_success': 'COMMITTED', 'single_row_save_substitution': False},
                   'input_page_sha256': hashlib.sha256(files[target['page_file']]).hexdigest(),
                   'output_page_sha256': hashlib.sha256(rendered).hexdigest(),
                   'runtime_verified': False, 'business_accepted': False}
            receipt['adapted_operations'].append(row)
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            receipt['gaps'].append({**identity, 'reason': str(exc)})
    return output, receipt
