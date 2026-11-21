"""Explicit XML note entry against the selected revision-guarded bag draft.

Only synthetic saved detail state is available here. A session collection update
is not COMMIT_FORM. The normal assignment path stops at that precise boundary.
The local procedure has a callable, with no inferred original caller.
"""
from __future__ import annotations

import json

from forms2apex import native_buffer
from forms2apex.record_buffer import validate_buffer_plan
from .forms_behavior_plan import _source_objects
from .forms_item_entry_workflow import (compile_item_entry_workflows, _one, _need,
    _json, _sha, _sql_expression, summary_projection)
from .forms_item_commands import _chain_for, selection_sql, _screen, _hidden
from .forms_item_validation import _contract

SCOPE = 'fox-native-note-entry-wiring-v1'
RECEIPT = 'fox-package/note-entry-wiring-receipt.json'
ENTRY_REQUEST = 'FOX_NOTE_ENTRY'
CALL_REQUEST = 'FOX_NOTE_CALLABLE'


def _draft_contract(documents, packet, chunks, trace, files, objects, props, target):
    """Re-derive the upstream slot/policy contract; do not trust supplied SQL."""
    plan = validate_buffer_plan(json.loads(files['fox-package/buffer-plan.json']))
    validations = json.loads(files['fox-package/item-validation-receipt.json'])
    _need(validations['source_binding'] == packet['source_binding'], 'NOTE_VALIDATION_BINDING')
    # Rebuild source-derived upstream contracts without imposing old bytes on
    # the separately owned, further-decorated bag editor.
    from .forms_draft_policy import apply_draft_policies
    from .forms_synthetic_save import apply_synthetic_saves
    from .forms_item_validation import apply_item_validations
    base=dict(files)
    buffers={b['operation_id']:b for b in plan['operations']}
    for row in json.loads(files['fox-package/buffer-receipt.json'])['generated_operations']:
        base[row['page_file']]=native_buffer._page(buffers[row['operation_id']],row['page_id']).encode()
    base,policy_proof=apply_draft_policies(documents,packet,chunks,trace,base)
    _need(policy_proof==json.loads(files['fox-package/draft-policy-receipt.json']),'NOTE_FRESH_POLICY')
    base,save_proof=apply_synthetic_saves(documents,packet,chunks,trace,base)
    _need(save_proof==json.loads(files['fox-package/synthetic-save-receipt.json']),'NOTE_FRESH_SAVE')
    _,validation_proof=apply_item_validations(documents,packet,chunks,trace,base)
    _need(validation_proof==validations,'NOTE_FRESH_VALIDATION')
    v = _one([v for k in ('generated_operations', 'adapted_operations') for v in validations[k]
              if v['contract']['fields']['weight']['source_item_id'] == target], 'NOTE_COST_DRAFT')
    buffer = _one([b for b in plan['operations'] if b['operation_id'] == v['contract']['buffer_operation_id']], 'NOTE_BUFFER')
    write = _one([c for c in json.loads(files['fox-package/synthetic-save-receipt.json'])['write_contracts']
                  if c['buffer_operation_id'] == buffer['operation_id']], 'NOTE_SAVE')
    guard = _one([g for g in json.loads(files['fox-package/draft-policy-receipt.json'])['adapted_operations']
                  if g['buffer_operation_id'] == buffer['operation_id']], 'NOTE_POLICY')
    # Parsing again prevents a receipt-authored event from redefining the slots.
    from .forms_item_validation import parse_item_validation
    unit = _one([c for c in chunks if c['code_unit_id'] == v['source_unit_id']], 'NOTE_VALIDATION_UNIT')
    parsed, _ = parse_item_validation(unit['text'])
    owner = objects[v['source_owner_id']]
    c = _contract(parsed, owner, buffer, write, guard, objects, props, trace, files)
    c['collection_namespace'] = 'FOX_I_' + native_buffer._sha(native_buffer._json([
        'fox-bound-item-validation-v1', c, parsed]))[:20].upper() + '_'
    _need(c == v['contract'] and c['slots']['active_weight'] == 'n002', 'NOTE_EXACT_DRAFT_CONTRACT')
    return buffer, v, c


def _queries(op, routine, screen, objects, props, trace, files):
    summary = _one(op['summaries'], 'NOTE_SUMMARY')
    blocks, edges = _chain_for(summary['detail_block_id'], objects, props, trace, files,
                              json.loads(files['fox-package/relation-plan.json']))
    _need(len(blocks) == 3 and screen['path_block_ids'] == [b['source_block_id'] for b in blocks], 'NOTE_THREE_LEVEL_SELECTION')
    body = op['parsed']['body']
    _need(len(body) == 1 and body[0]['kind'] == 'if' and len(body[0]['branches']) == 2, 'NOTE_ENTRY_SHAPE')
    first, invalid = body[0]['branches']
    _need([n['kind'] for n in first['body']] == ['assign', 'if', 'next_item']
          and [n['kind'] for n in invalid['body']] == ['go_item']
          and [n['kind'] for n in body[0]['else']] == ['next_record'], 'NOTE_ORDERED_EFFECTS')
    transaction = first['body'][1]
    _need(transaction['else'] == [] and len(transaction['branches']) == 1
          and [n['kind'] for n in transaction['branches'][0]['body']] == ['commit_form'], 'NOTE_TRANSACTION_SHAPE')
    _need(transaction['branches'][0]['condition'] == {
        'kind': 'ne', 'left': {'kind': 'reference', 'parts': ['SYSTEM','FORM_STATUS'], 'binding': 'system_form_status'},
        'right': {'kind': 'literal', 'value': 'QUERY'}}, 'NOTE_TRANSACTION_CONDITION')
    assignment = first['body'][0]
    rbody = routine['parsed']['body'] if routine else None
    if rbody:
        _need([n['kind'] for n in rbody] == ['go_block','go_item','assign']
              and rbody[0]['source_block_id'] == rbody[1]['source_block_id']
              and rbody[2]['target'] == assignment['target'] and rbody[2]['value'] == assignment['value'], 'NOTE_ROUTINE_SHAPE')
    _need(assignment['value']['source_item_id'] == summary['source_item_id'], 'NOTE_SUMMARY_SOURCE')
    columns = {}
    for uid, field in op['fields'].items():
        if uid == summary['source_item_id']:
            continue
        i, b = _one([(i,b) for i,b in enumerate(blocks) if b['source_block_id'] == field['source_block_id']], 'NOTE_CONTEXT_FIELD')
        f = _one([f for f in b['items'] if f['source_item_id'] == uid], 'NOTE_MAPPED_FIELD')
        columns[uid] = f'r{i}.' + f['column']
    base, where = selection_sql(blocks, edges, screen['page_id'], selected=3)
    projection = summary_projection(summary, 'r1')
    query = ('select ' + projection + ',case when '+_sql_expression(first['condition'], columns)
             + " then 'ASSIGN' when "+_sql_expression(invalid['condition'], columns)
             + " then 'INVALID_FOCUS' else 'NEXT_RECORD' end from "+base+' where '+where)
    next_base, next_where = selection_sql(blocks, edges, screen['page_id'], selected=2)
    next_query = ('select min(r2.FOX_ROW_ID) from '+next_base+' where '+next_where
                  + f" and r2.FOX_ROW_ID>:P{screen['page_id']}_ID2")
    return blocks, edges, summary, assignment, invalid['body'][0], rbody, query, next_query


def note_entry_runtime(config):
    """Focus is checked before the explicit routine submits its assignment."""
    payload = json.dumps(config, separators=(',',':')).replace('<','\\u003c')
    return '''(function(){"use strict";
const c='''+payload+''';
function el(id){const e=document.getElementById(id);if(!e)throw new Error("Note entry control unavailable");return e;}
function focus(id){const e=el(id);e.focus();if(document.activeElement!==e)throw new Error("Source focus failed; assignment was not submitted");}
function invoke(id){
 if(!c.operation_id||id!==c.operation_id)throw new Error("Unknown note entry routine");
 if(el(c.state).value!=="READY")throw new Error("Open and select the matching bag draft first");
 if(apex.page.isChanged())throw new Error("Keep or discard current page edits first");
 const before=c.identities.map(id=>el(id).value);
 // Source GO_BLOCK then GO_ITEM. This selects the current header control;
 // all row identities must survive the ordered focus before assignment.
 const context={current_block_id:c.block_id};
 focus(c.focus);
 context.current_item_id=c.focus_source_item_id;
 if(c.identities.some((id,i)=>el(id).value!==before[i]))throw new Error("Selection changed during source focus");
 el(c.focus_ack).value=c.focus_source_item_id;
 apex.submit({request:c.call_request,showWait:true});
 return {submitted:true,completed:false,context:context,original_caller_installed:false};
}
window.foxNoteEntryBridge={invoke:invoke,operation_id:c.operation_id};
const status=el(c.result).value;
const message=document.getElementById("fox-note-entry-status");
if(message)message.textContent=({WHOLE_FORM_STATUS_REQUIRED:"The selected bag draft cost weight was assigned. Whole-form status and commit are unavailable; Next did not run.",WHOLE_FORM_COMMIT_FAILED:"The trusted whole-form commit failed. The ordered draft assignment is retained; Next did not run.",WHOLE_FORM_COMMIT_OUTCOME_UNKNOWN:"The whole-form commit outcome is unknown. This bag entry is blocked against replay; a trusted operator must reconcile the original outcome before continuing.",ASSIGNED_CURRENT_DRAFT:"The explicitly invoked callable assigned the current bag draft cost weight after successful header focus. No original caller was installed.",INVALID_FOCUS:"The source invalid-destination branch focused the consignment code.",NEXT_ITEM:"Focused the next source-bound item.",NEXT_SAVED_RECORD:"Selected the next saved consignment in synthetic row ID order.",END_OF_SAVED_RECORDS:"This is the last saved consignment in this bag. No new record was created.",DRAFT_ASSIGNMENT_NOT_APPLIED:"The current selection, draft, nonce or revision changed. No draft assignment was retained. Reopen this selection."})[status]||(el(c.state).value==="READY"?"The selected bag draft is ready. The local routine is available only to an explicit caller.":"Open this header's bag drafts, select the matching saved bag, then return here. An unresolved whole-form outcome requires operator reconciliation.");
if(status==="INVALID_FOCUS")focus(c.invalid_focus);
if(status==="NEXT_ITEM"&&c.next_focus)focus(c.next_focus);
const b=document.getElementById("fox-note-entry");if(b)b.addEventListener("click",function(){
 if(el(c.state).value!=="READY")throw new Error("Select the matching current bag draft first");
 if(apex.page.isChanged())throw new Error("Keep or discard current page edits first");
 apex.submit({request:c.entry_request,showWait:true});
});
})();'''


def _relative_next(op, objects, props):
    from .forms_bag_entry_wiring import _focusable
    from .forms_item_validation import _resolve
    owner = objects[op['owner_item_id']]
    _focusable(owner, props)
    explicit = props[owner['id']].get('NextNavigationItem','').strip()
    if explicit:
        parts = explicit.upper().split('.')
        _need(len(parts) in (1,2) and all(parts), 'NOTE_RELATIVE_TARGET')
        target = _resolve(parts, owner, objects)
        _need(target['block_id']==owner['block_id'], 'NOTE_RELATIVE_CROSS_BLOCK')
        _focusable(target, props)
        return dict(kind='focus',source_item_id=target['id'],source_block_id=owner['block_id'],
                    proof='explicit_XML_NextNavigationItem')
    items = [o for o in objects.values() if o['kind']=='Item' and o['block_id']==owner['block_id']]
    for item in items[items.index(owner)+1:]:
        attrs = props[item['id']]
        if (not attrs.get('CanvasName','').strip() or attrs.get('ItemType','').upper()=='DISPLAY ITEM'
                or any(attrs.get(key,'').strip().lower()=='false' for key in
                       ('KeyboardNavigable','Enabled','Visible','Displayed','Navigable'))):
            continue
        _focusable(item, props)
        return dict(kind='focus',source_item_id=item['id'],source_block_id=owner['block_id'],
                    proof='next_navigable_canvas_text_item_in_source_XML_order')
    _need(props[owner['block_id']].get('NavigationStyle','').upper()=='CHANGE RECORD','NOTE_RELATIVE_BLOCK_BOUNDARY')
    return dict(kind='next_record',source_block_id=owner['block_id'],
                proof='last_navigable_canvas_text_item_with_XML_Change_Record',source_order_unspecified=True)


def _host_provider(provider, binding):
    if provider is None:
        return "function host_form_status return varchar2 is begin return 'UNKNOWN';end;\nfunction host_commit_form return varchar2 is begin return 'UNAVAILABLE';end;",None
    _need(isinstance(provider,dict) and provider.get('trusted') is True
          and provider.get('source_binding')==binding and provider.get('scope')=='whole_forms_transaction'
          and isinstance(provider.get('provider_id'),str) and provider['provider_id']
          and isinstance(provider.get('declarations_plsql'),str), 'NOTE_TRUSTED_WHOLE_FORM_PROVIDER')
    declarations=provider['declarations_plsql']
    _need('host_form_status' in declarations.lower() and 'host_commit_form' in declarations.lower(), 'NOTE_HOST_FUNCTIONS')
    return declarations,dict(provider_id=provider['provider_id'],source_binding=binding,
                             declarations_sha256=_sha(declarations),scope=provider['scope'])


def _render_sql(buffer, contract, page, query, next_query, blocks, nonce_name, routine_focus, relative_next, host):
    """Use the real bag namespace, META cursor/revision, ROW identity and policy."""
    c = contract
    read = native_buffer._read_parent(buffer,'l_found',lock=True).replace(native_buffer._name(buffer),c['collection_namespace'])
    keys = ' and '.join(native_buffer._parent_match('d.c%03d'%i,'b.'+f['column'])
                        + ' and '+native_buffer._parent_match('d.c%03d'%(20+i),'b.'+f['column'])
                        for i,f in enumerate(buffer['key_bindings'],1))
    from .forms_master_detail import _fingerprint
    token_sql = _fingerprint(blocks[2]['items'],'t')
    selection_hash = "rawtohex(standard_hash(" + "||':'||".join(
        f":P{page}_{k}{i}" for i in range(3) for k in ('ID','TOKEN')) + ",'SHA256'))"
    declarations = f'''l_parent number; l_found number; l_name varchar2(255);l_seq number;l_rev number;
l_sum number;l_branch varchar2(40);l_next number;l_nonce varchar2(64);l_selection varchar2(64);l_nonce_seq number;l_nonce_count number;
l_form_status varchar2(30);l_commit_result varchar2(30);l_commit_started boolean:=false;l_continue boolean:=false;
l_start_note number;l_start_token varchar2(4000);
{native_buffer._value_declarations(buffer)}
{host}
procedure guard_context(p_write boolean:=false) is begin
 l_parent:=:P{page}_ID0;
 {read}
 select {c['policy_expression_sql']} into l_found from {c['parent_table']} where FOX_ROW_ID=l_parent;
 if p_write and nvl(l_found,0)<>1 then raise_application_error(-20051,'Parent draft policy is read only.');end if;
 select n002,n003 into l_seq,l_rev from apex_collections where collection_name=l_name and seq_id=1
  and n001=l_parent and c049='{native_buffer._sha(native_buffer._json(buffer))}' and c050='META';
 if l_seq is null or l_rev is null then raise_application_error(-20054,'Current draft cursor or revision is unavailable.');end if;
 select d.seq_id into l_found from apex_collections d,{c['child_table']} b
  where d.collection_name=l_name and d.seq_id=l_seq and d.c050='ROW' and d.n001=:P{page}_ID1
  and b.FOX_ROW_ID=d.n001 and {keys}
  and d.c041='SYNTHETIC_SAVE_BASELINE_V1' and d.c045 is null and nvl(d.c043,'OK')<>'ERROR'
  and {native_buffer._parent_match('b.'+c['fields']['route']['column'],'d.c040')}
  and decode(b.{c['fields']['weight']['column']},d.n003,1,0)=1;
 select FOX_ROW_ID into l_found from {c['child_table']} where FOX_ROW_ID=:P{page}_ID1 for update nowait;
 select count(*) into l_found from apex_collections where collection_name='{nonce_name}'
  and n001=:P{page}_ID1 and c003='COMMIT_UNKNOWN';
 if l_found<>0 then raise_application_error(-20059,'Unresolved whole-form outcome: operator reconciliation required; do not replay.');end if;
 select {selection_hash} into l_selection from dual;
end;'''
    # Fresh whole-chain selection is re-read on every action, including weights.
    # The outer WHERE may itself contain subqueries. Locate the exact generated base.
    outer_marker = ' from '+', '.join(f"{b['table_name']} r{i}" for i,b in enumerate(blocks))+' where '
    _need(query.count(outer_marker) == 1, 'NOTE_OUTER_SELECT')
    fresh = query.replace(outer_marker,' into l_sum,l_branch'+outer_marker,1)+';'
    init = f'''declare {declarations}
begin
 :P{page}_NOTE_STATE:='UNAVAILABLE';
 :P{page}_NOTE_RESULT:=null;
 :P{page}_NOTE_LINK:=apex_page.get_url(p_page=>{c['draft_page_id']},p_items=>'P{c['draft_page_id']}_PARENT_ID',p_values=>:P{page}_ID0);
 guard_context;
 {fresh}
 if not apex_collection.collection_exists('{nonce_name}') then apex_collection.create_collection('{nonce_name}');end if;
 for expired in (select seq_id from apex_collections where collection_name='{nonce_name}' and c003 is null and d001<sysdate-1/24 and rownum<=100) loop
  apex_collection.delete_member(p_collection_name=>'{nonce_name}',p_seq=>expired.seq_id);end loop;
 select count(*) into l_nonce_count from apex_collections where collection_name='{nonce_name}';
 if l_nonce_count>=100 then raise_application_error(-20055,'Too many open entry selections; reopen after older selections expire.');end if;
 l_nonce:=rawtohex(sys_guid());
 apex_collection.add_member(p_collection_name=>'{nonce_name}',p_c001=>l_nonce,p_c002=>l_selection,
  p_n001=>:P{page}_ID1,p_n002=>l_rev,p_n003=>l_seq,p_d001=>sysdate);
 :P{page}_NOTE_NONCE:=l_nonce;:P{page}_NOTE_REV:=to_char(l_rev,'TM9');:P{page}_NOTE_SEQ:=to_char(l_seq,'TM9');
 select n002,n001 into :P{page}_NOTE_COST,:P{page}_NOTE_BAG_ID from apex_collections
  where collection_name=l_name and seq_id=l_seq and c050='ROW';
 :P{page}_NOTE_DRAFT_SEQ:=to_char(l_seq,'TM9');:P{page}_NOTE_DRAFT_REV:=to_char(l_rev,'TM9');
 :P{page}_NOTE_STATE:='READY';
exception when no_data_found then :P{page}_NOTE_STATE:='OPEN_MATCHING_DRAFT';:P{page}_NOTE_COST:=null;
 when others then :P{page}_NOTE_STATE:='DRAFT_UNAVAILABLE';:P{page}_NOTE_COST:=null;apex_debug.error('Note draft context: %s',sqlerrm);
end;'''
    advance=f'''{next_query.replace(' from ',' into l_next from ',1)};
  if l_next is null then :P{page}_NOTE_RESULT:='END_OF_SAVED_RECORDS';
  else
   :P{page}_ID2:=l_next;
   select {token_sql} into :P{page}_TOKEN2 from {blocks[2]['table_name']} t where t.FOX_ROW_ID=l_next;
   :P{page}_NOTE_RESULT:='NEXT_SAVED_RECORD';
  end if;'''
    next_item = advance if relative_next['kind']=='next_record' else f":P{page}_NOTE_RESULT:='NEXT_ITEM';"
    callable_guard = ("raise_application_error(-20058,'No unique source procedure is bound.');"
                      if routine_focus=='NO_PROVED_ROUTINE' else '')
    process = f'''declare {declarations}
begin
 if :REQUEST is null or :REQUEST not in ('{ENTRY_REQUEST}','{CALL_REQUEST}') then return;end if;
 l_start_note:=:P{page}_ID2;l_start_token:=:P{page}_TOKEN2;
 savepoint fox_note_entry;
 :P{page}_NOTE_RESULT:=null;
 if :P{page}_NOTE_SEQ is null or :P{page}_NOTE_REV is null or :P{page}_NOTE_NONCE is null
  or not regexp_like(:P{page}_NOTE_SEQ,'^[1-9][0-9]{{0,9}}$')
  or not regexp_like(:P{page}_NOTE_REV,'^[0-9]{{1,15}}$') then
  raise_application_error(-20056,'Entry cursor, revision and nonce are required.');end if;
 guard_context;
 lock table {blocks[2]['table_name']} in share mode nowait;
 {fresh}
 guard_context(l_branch='ASSIGN' or :REQUEST='{CALL_REQUEST}');
 select seq_id,c001 into l_nonce_seq,l_nonce from apex_collections where collection_name='{nonce_name}'
  and c001=:P{page}_NOTE_NONCE and c002=l_selection and n001=:P{page}_ID1
  and n002=l_rev and n003=l_seq and c003 is null and d001>sysdate-1/24;
 if l_seq<>to_number(:P{page}_NOTE_SEQ) or l_rev<>to_number(:P{page}_NOTE_REV) then
  raise_application_error(-20052,'The current draft revision changed.');end if;
 if :REQUEST='{CALL_REQUEST}' then
  {callable_guard}
  if :P{page}_NOTE_FOCUS is null or :P{page}_NOTE_FOCUS<>'{routine_focus}' then
   raise_application_error(-20053,'Invoke the callable after successful source focus.');end if;
  l_branch:='ASSIGN';
 end if;
 if l_branch='ASSIGN' then
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>2,p_number_value=>l_sum);
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>3,p_number_value=>l_rev+1);
  :P{page}_NOTE_RESULT:=case when :REQUEST='{CALL_REQUEST}' then 'ASSIGNED_CURRENT_DRAFT' else 'WHOLE_FORM_STATUS_REQUIRED' end;
  if :REQUEST='{ENTRY_REQUEST}' then
   l_form_status:=host_form_status;
   if l_form_status='QUERY' then l_continue:=true;
   elsif l_form_status in ('CHANGED','NEW') then
    -- A one-shot intent exists before any provider that may commit or have an
    -- unknown outcome. Its session blocker has no expiry or automatic retry.
    apex_collection.update_member_attribute(p_collection_name=>'{nonce_name}',p_seq=>l_nonce_seq,p_attr_number=>3,p_attr_value=>'COMMIT_UNKNOWN');
    l_commit_started:=true;l_commit_result:=host_commit_form;
    if l_commit_result='COMMITTED' then l_continue:=true;
    elsif l_commit_result='FAILED' then :P{page}_NOTE_RESULT:='WHOLE_FORM_COMMIT_FAILED';
    else :P{page}_NOTE_RESULT:='WHOLE_FORM_COMMIT_OUTCOME_UNKNOWN';end if;
    if l_commit_result in ('COMMITTED','FAILED') then
     apex_collection.update_member_attribute(p_collection_name=>'{nonce_name}',p_seq=>l_nonce_seq,p_attr_number=>3,p_attr_value=>null);
    end if;
   end if;
   if l_continue then
    -- Providers may have changed the Forms buffer or committed. Never trust
    -- their return alone as proof this same selected bag is still current.
    guard_context(true);
    if l_rev<>to_number(:P{page}_NOTE_REV)+1 or l_seq<>to_number(:P{page}_NOTE_SEQ) then
     raise_application_error(-20057,'Host provider changed the current draft context.');end if;
    {fresh}
    {next_item}
   end if;
  end if;
 elsif l_branch='INVALID_FOCUS' then :P{page}_NOTE_RESULT:='INVALID_FOCUS';
 else
  {advance}
 end if;
 if not l_commit_started or l_commit_result in ('COMMITTED','FAILED') then
  apex_collection.delete_member(p_collection_name=>'{nonce_name}',p_seq=>l_nonce_seq);end if;
 :P{page}_NOTE_FOCUS:=null;
exception when others then
 if l_commit_started then
  apex_collection.update_member_attribute(p_collection_name=>'{nonce_name}',p_seq=>l_nonce_seq,p_attr_number=>3,p_attr_value=>'COMMIT_UNKNOWN');
  :P{page}_NOTE_RESULT:='WHOLE_FORM_COMMIT_OUTCOME_UNKNOWN';
 else rollback to fox_note_entry;:P{page}_NOTE_RESULT:='DRAFT_ASSIGNMENT_NOT_APPLIED';end if;
 :P{page}_ID2:=l_start_note;:P{page}_TOKEN2:=l_start_token;
 :P{page}_NOTE_FOCUS:=null;
 apex_debug.error('Note entry stopped: %s',sqlerrm);
end;'''
    return init, process


def _return_transfer(buffer, c, page, query, blocks, nonce_name, source_proof):
    """One-shot outcome across native POST/redirect/GET; no browser outcome input."""
    name=nonce_name.replace('FOX_N_','FOX_NR_',1)
    digest="rawtohex(standard_hash("+"||':'||".join(f":P{page}_{k}{i}" for i in range(3) for k in ('ID','TOKEN'))+",'SHA256'))"
    marker=' from '+', '.join(f"{b['table_name']} r{i}" for i,b in enumerate(blocks))+' where '
    fresh=query.replace(marker,' into l_sum,l_branch'+marker,1)+';'
    read=native_buffer._read_parent(buffer,'l_found').replace(native_buffer._name(buffer),c['collection_namespace'])
    declarations=f'''l_parent number;l_found number;l_name varchar2(255);l_seq number;l_rev number;l_sum number;
l_branch varchar2(40);l_result varchar2(50);l_digest varchar2(64);l_ticket varchar2(64);l_member number;l_count number;
{native_buffer._value_declarations(buffer)}'''
    outcomes="'WHOLE_FORM_STATUS_REQUIRED','WHOLE_FORM_COMMIT_FAILED','WHOLE_FORM_COMMIT_OUTCOME_UNKNOWN','ASSIGNED_CURRENT_DRAFT','INVALID_FOCUS','NEXT_ITEM','NEXT_SAVED_RECORD','END_OF_SAVED_RECORDS','DRAFT_ASSIGNMENT_NOT_APPLIED'"
    capture=f'''declare {declarations}
begin
 if :REQUEST is null or :REQUEST not in ('{ENTRY_REQUEST}','{CALL_REQUEST}') then return;end if;
 :P{page}_NOTE_RETURN:=null;l_result:=:P{page}_NOTE_RESULT;
 if l_result is null or l_result not in ({outcomes}) then return;end if;
 {fresh}
 select {digest} into l_digest from dual;
 begin
  l_parent:=:P{page}_ID0;{read}
  select m.n002,m.n003 into l_seq,l_rev from apex_collections m,apex_collections d
   where m.collection_name=l_name and m.seq_id=1 and m.c050='META' and m.n001=l_parent
   and m.c049='{native_buffer._sha(native_buffer._json(buffer))}' and d.collection_name=l_name
   and d.seq_id=m.n002 and d.c050='ROW' and d.n001=:P{page}_ID1;
 exception when no_data_found then l_name:=null;l_seq:=null;l_rev:=null;end;
 if l_result in ('INVALID_FOCUS','NEXT_ITEM') and (l_seq is null or l_rev is null) then return;end if;
 if not apex_collection.collection_exists('{name}') then apex_collection.create_collection('{name}');end if;
 for old in (select seq_id from apex_collections where collection_name='{name}' and d001<sysdate-1/144 and rownum<=100) loop
  apex_collection.delete_member(p_collection_name=>'{name}',p_seq=>old.seq_id);end loop;
 select count(*) into l_count from apex_collections where collection_name='{name}';
 if l_count>=100 then return;end if;
 l_ticket:=rawtohex(sys_guid());
 apex_collection.add_member(p_collection_name=>'{name}',p_c001=>l_ticket,p_c002=>l_digest,
  p_c003=>l_result,p_c004=>'{source_proof}',p_c005=>l_name,p_n001=>l_seq,p_n002=>l_rev,
  p_n003=>:P{page}_ID1,p_d001=>sysdate);
 :P{page}_NOTE_RETURN:=l_ticket;
exception when others then :P{page}_NOTE_RETURN:=null;apex_debug.error('Note return capture: %s',sqlerrm);
end;'''
    consume=f'''declare {declarations}
begin
 :P{page}_NOTE_RESULT:=null;l_ticket:=:P{page}_NOTE_RETURN;:P{page}_NOTE_RETURN:=null;
 if l_ticket is null or not regexp_like(l_ticket,'^[A-F0-9]{{32}}$') then return;end if;
 {fresh}
 select {digest} into l_digest from dual;
 select seq_id,c003,c005,n001,n002 into l_member,l_result,l_name,l_seq,l_rev from apex_collections
  where collection_name='{name}' and c001=l_ticket and c002=l_digest
  and c004='{source_proof}' and n003=:P{page}_ID1 and d001>sysdate-1/144;
 -- Consume only the exact selected return. Refresh or a different GET cannot
 -- replay a focus, and a wrong target cannot consume another tab's receipt.
 apex_collection.delete_member(p_collection_name=>'{name}',p_seq=>l_member);
 if l_seq is not null or l_rev is not null then
  if l_seq is null or l_rev is null then return;end if;
  select count(*) into l_count from apex_collections m,apex_collections d
   where m.collection_name=l_name and m.seq_id=1 and m.c050='META' and m.n001=:P{page}_ID0
   and m.c049='{native_buffer._sha(native_buffer._json(buffer))}' and m.n002=l_seq and m.n003=l_rev
   and d.collection_name=l_name and d.seq_id=l_seq and d.c050='ROW' and d.n001=:P{page}_ID1 and d.c045 is null;
  if l_count<>1 then return;end if;
 end if;
 if l_result in ('INVALID_FOCUS','NEXT_ITEM') and
  (:P{page}_NOTE_STATE is null or :P{page}_NOTE_STATE<>'READY' or l_seq is null or l_rev is null) then return;end if;
 :P{page}_NOTE_RESULT:=l_result;
exception when no_data_found then null;
 when others then :P{page}_NOTE_RESULT:=null;apex_debug.error('Note return refused: %s',sqlerrm);
end;'''
    carry='\n'.join(f'                    P{page}_{k}{i}: "&P{page}_{k}{i}."' for i in range(3) for k in ('ID','TOKEN'))
    branch=f'''    branch return-from-note-entry (
        name: Return to exact selected consignment
        execution {{ sequence: 5
            point: afterProcessing }}
        behavior {{ type: pageOrUrl
            target: {{ page: {page}
                clearCache: {page}
                items: {{
{carry}
                    P{page}_NOTE_RETURN: "&P{page}_NOTE_RETURN."
                }}
            }}
        }}
        serverSideCondition {{ type: requestIsContainedInValue
            value: {ENTRY_REQUEST},{CALL_REQUEST} }}
    )
'''
    return dict(collection_name=name,source_proof=source_proof,capture_plsql=capture,consume_plsql=consume,
                branch=branch,return_item=f'P{page}_NOTE_RETURN',scope='one_shot_exact_post_action_selection_and_source_bound_return')


def apply_note_entry_wiring(documents, packet, chunks, trace, files, *, whole_form_adapter=None):
    plan = compile_item_entry_workflows(documents, packet, chunks, trace, files)
    output = dict(files)
    receipt = dict(schema_version=1,scope=SCOPE,source_binding=packet['source_binding'],
                   generated_operations=[],adapted_operations=[],gaps=[],runtime_verified=False,
                   business_accepted=False,customer_table_writes=False,original_reads_enabled=False)
    candidates = [o for o in plan['operations'] if o['summaries'] and o['source_event']=='WHEN-NEW-ITEM-INSTANCE']
    if not candidates:
        output[RECEIPT] = _json(receipt)
        return output, receipt
    objects, props = _source_objects(documents, packet)
    host,host_receipt=_host_provider(whole_form_adapter,packet['source_binding'])
    for op in candidates:
        try:
            summary = _one(op['summaries'],'NOTE_ONE_SUMMARY')
            routines = [o for o in plan['operations'] if o['source_event']=='ProgramUnit'
                        and o['summaries']==op['summaries']]
            routine = routines[0] if len(routines)==1 else None
            commands = json.loads(files['fox-package/item-command-receipt.json'])
            screen = _one([s for s in commands['screens'] if s['path_block_ids']
                            and s['path_block_ids'][-1]==summary['detail_block_id']], 'NOTE_SCREEN')
            blocks, edges, summary, assignment, invalid, rbody, query, next_query = _queries(
                op,routine,screen,objects,props,trace,files)
            buffer, validation, c = _draft_contract(documents,packet,chunks,trace,files,objects,props,
                                                    assignment['target']['source_item_id'])
            c = dict(c,draft_page_id=validation['page_id'])
            _need(buffer['relation']['parent_block_id']==blocks[0]['source_block_id']
                  and buffer['relation']['child_block_id']==blocks[1]['source_block_id'], 'NOTE_DRAFT_CHAIN')
            # Reconstruct only the saved-navigation pages; the bag editor belongs
            # to its upstream owner and may already have additional entry wiring.
            base = dict(files)
            for s in commands['screens']:
                if s['page_id']==screen['page_id']:
                    rebuilt,evidence = _screen(s['page_id'],None,blocks,edges,3,
                        s['runtime_config']['operations'],objects,props)
                    _need(all(s[k]==evidence[k] for k in evidence),'NOTE_CANONICAL_SCREEN')
                    base[s['page_file']]=rebuilt
            from .forms_item_entry_workflow import apply_item_entry_workflows
            rebuilt,_ = apply_item_entry_workflows(documents,packet,chunks,trace,base)
            _need(rebuilt[screen['page_file']]==files[screen['page_file']], 'NOTE_EXACT_SAVED_PAGE')
            page = screen['page_id']
            binding = lambda uid: _one([f for f in screen['field_bindings'] if f['source_item_id']==uid], 'NOTE_FOCUS_CONTROL')['item_name']
            invalid_focus = binding(invalid['source_item_id'])
            focus = binding(rbody[1]['source_item_id']) if rbody else None
            relative_next=_relative_next(op,objects,props)
            if relative_next['kind']=='focus':
                relative_next['item_name']=binding(relative_next['source_item_id'])
            nonce = 'FOX_N_'+_sha([packet['source_binding'],op['operation_id']])[:24].upper()
            routine_focus=rbody[1]['source_item_id'] if rbody else 'NO_PROVED_ROUTINE'
            init, process = _render_sql(buffer,c,page,query,next_query,blocks,nonce,routine_focus,relative_next,host)
            config = dict(operation_id=routine['operation_id'] if routine else None,state=f'P{page}_NOTE_STATE',
                          result=f'P{page}_NOTE_RESULT',focus=focus,invalid_focus=invalid_focus,
                          block_id=rbody[0]['source_block_id'] if rbody else None,focus_source_item_id=routine_focus,
                          focus_ack=f'P{page}_NOTE_FOCUS',identities=[f'P{page}_{k}{i}' for i in range(3) for k in ('ID','TOKEN')],
                          call_request=CALL_REQUEST,entry_request=ENTRY_REQUEST)
            if relative_next['kind']=='focus':config['next_focus']=relative_next['item_name']
            script=note_entry_runtime(config)
            text=files[screen['page_file']].decode()
            _need(text.count('    security {\n        authentication: required')==1,'NOTE_PAGE_SECURITY_ANCHOR')
            text=text.replace('    security {\n        authentication: required',
                '    advanced {\n        reloadOnSubmit: always\n    }\n    security {\n        authentication: required',1)
            anchor='        ```\n    }\n'
            _need(text.count(anchor)==1 and text.endswith(')\n'),'NOTE_SCRIPT_ANCHOR')
            text=text.replace(anchor,native_buffer._indent(script,8)+'\n'+anchor,1)
            addition=''.join(_hidden(page,'NOTE_'+name,restricted=name in ('STATE','LINK','BAG_ID','DRAFT_SEQ','DRAFT_REV'))
                             for name in ('STATE','LINK','NONCE','REV','SEQ','FOCUS','BAG_ID','DRAFT_SEQ','DRAFT_REV'))
            return_item=_hidden(page,'NOTE_RETURN').replace('storage: session','storage: request')
            addition+=return_item
            focus_hidden=_hidden(page,'NOTE_FOCUS')
            addition=addition.replace(focus_hidden,focus_hidden.replace('        type: hidden\n',
                '        type: hidden\n        settings { valueProtected: false }\n').replace(
                    'sessionStateProtection: checksumRequiredSessionLevel','sessionStateProtection: unrestricted'))
            addition += f'''    pageItem P{page}_NOTE_RESULT (
        type: textField
        label {{ label: Current bag draft entry outcome }}
        layout {{ sequence: 970
            region: @records
            slot: regionBody }}
        advanced {{ customAttributes: "readonly" }}
        sessionState {{ storage: request
            dataType: varchar2 }}
        security {{ sessionStateProtection: restricted }}
    )
    pageItem P{page}_NOTE_COST (
        type: textField
        label {{ label: Current selected bag draft cost weight }}
        layout {{ sequence: 971
            region: @records
            slot: regionBody }}
        advanced {{ customAttributes: "readonly" }}
        sessionState {{ storage: request
            dataType: number }}
        security {{ sessionStateProtection: restricted }}
    )
'''
            html=('<p>Entry uses this selected saved header, bag and consignment. The rounded saved detail total is assigned to the current bag session draft cost weight. '
                  'Open the matching bag draft first, select this saved bag, then return here. Other bag drafts are never selected automatically. '
                  'Unposted consignment edits and original destination lookup state are unavailable. The saved synthetic destination projection is used. '
                  'The entry stops after assignment until a trusted whole-form status and commit provider exists. '
                  'Next record uses stable synthetic row ID order within this bag; it stops at the last saved record.</p>'
                  f'<a href="&P{page}_NOTE_LINK!ATTR.">Open this header\'s bag drafts</a> '
                  '<button type="button" id="fox-note-entry">Enter selected consignment into current draft</button>'
                  '<p id="fox-note-entry-status" role="status" aria-live="polite"></p>')
            addition += f'''    region note-entry-bridge (
        name: Current bag draft entry
        type: staticContent
        source {{ htmlCode: {json.dumps(html)} }}
        layout {{ sequence: 960
            slot: body }}
        appearance {{ template: @/standard }}
    )
'''
            addition += native_buffer._process('bind-current-note-draft',init,point='beforeHeader',sequence=35)
            addition += native_buffer._process('apply-current-note-entry',process,point='afterSubmit',sequence=10)
            transfer=_return_transfer(buffer,c,page,query,blocks,nonce,_sha([packet['source_binding'],op['operation_id'],op['source_unit_sha256']]))
            addition += native_buffer._process('capture-note-entry-return',transfer['capture_plsql'],point='afterSubmit',sequence=90)
            addition += native_buffer._process('consume-note-entry-return',transfer['consume_plsql'],point='beforeHeader',sequence=40)
            addition += transfer['branch']
            rendered=native_buffer._expand_groups(text[:-2]+addition+')\n')
            from .forms_item_validation import _check_capacity
            _check_capacity(rendered)
            output[screen['page_file']]=rendered.encode()
            common=dict(page_file=screen['page_file'],page_id=page,contract=c,source_summary=summary,
                        query_sql=query,next_record_query_sql=next_query,initialize_plsql=init,process_plsql=process,
                        javascript=script,runtime_config=config,native_event_wired=True,
                        generation_status='generated_wired_adapted_partial',runtime_verified=False,business_accepted=False,
                        draft_assignment_slot=c['slots']['active_weight'],summary_scope='saved_synthetic_details_only',
                        next_record_order='explicit_stable_synthetic_FOX_ROW_ID_ascending_no_wrap',
                        relative_next=relative_next,whole_form_provider=host_receipt,
                        server_draft_result_items={k:f'P{page}_NOTE_{k}' for k in ('COST','BAG_ID','DRAFT_SEQ','DRAFT_REV')},
                        nonce_collection=nonce,source_caller_installed=False,
                        native_return=transfer,
                        effective_buffer_interface={'runtime_file':'fox-package/item-entry-runtime.py',
                            'callable':'execute_item_entry','provider_method':'summary(binding, context)',
                            'contract':'Existing trusted effective Forms detail-buffer provider interface is preserved; native saved-detail SQL does not claim unposted or external detail state.'},
                        remaining_boundaries=['original_unposted_detail_and_destination_lookup_state',
                            'original_forms_validation_posting_and_record_lifecycle',
                            'whole_form_host_adapter_requires_target_verification' if host_receipt else 'trusted_whole_form_status_and_commit'])
            for value in (op,*([routine] if routine else [])):
                row=dict(common,source_unit_id=value['source_unit_id'],source_unit_sha256=value['source_unit_sha256'],
                         source_event=value['source_event'],operation_id=value['operation_id'],
                         connected_effects=(['same_current_header_bag_note_selection','xml_sum_ceil_each_saved_detail',
                                             'revision_nonce_policy_guarded_actual_bag_draft_cost_assignment',
                                             'source_invalid_focus','same_bag_next_saved_record']
                                            if value is op else ['explicit_callable_go_block_go_item_assignment']))
                if value is routine:
                    row['callable']='window.foxNoteEntryBridge.invoke'
                    row['callable_argument']=routine['operation_id']
                    row['session_setup']='Select the signed header, bag and note; open the linked header bag draft, explicitly select this same saved bag and return; invoke this callable explicitly. No source caller is installed.'
                    row['remaining_boundaries']=['original_unposted_detail_buffer','original_forms_navigation_validation_lifecycle',
                                                 'original_caller_not_installed']
                    row.pop('whole_form_provider')
                receipt['adapted_operations'].append(row)
        except (ValueError,KeyError) as exc:
            receipt['gaps'].append(dict(source_unit_id=op['source_unit_id'],source_unit_sha256=op['source_unit_sha256'],reason=str(exc)))
    output[RECEIPT]=_json(receipt)
    return output,receipt
