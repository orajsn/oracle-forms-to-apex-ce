"""Source-backed, partial session-buffer clear lifecycle for master selection.

This adapter never implements a Forms-wide COMMIT and never deletes stored rows.
Only recognized complete helper/caller bodies authorize its bounded effects.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_buffer
from .forms_behavior_plan import _source_objects, decode_control_entities
from .forms_understanding_packet import _build

SCOPE = 'fox-master-detail-session-clear-v1'

# This is a grammar template, not copied executable source. All active tokens
# must match, including failure checks, skip guards and exception restoration.
_CLEAR = '''PROCEDURE clear_helper IS
 mastblk VARCHAR2(30); coordop VARCHAR2(30); trigblk VARCHAR2(30);
 startitm VARCHAR2(61); frmstat VARCHAR2(15); curblk VARCHAR2(30);
 currel VARCHAR2(30); curdtl VARCHAR2(30);
 FUNCTION first_changed(master VARCHAR2) RETURN VARCHAR2 IS
 curblk VARCHAR2(30); currel VARCHAR2(30); retblk VARCHAR2(30);
 BEGIN curblk := master;
 currel := Get_Block_Property(curblk,FIRST_MASTER_RELATION);
 WHILE currel IS NOT NULL LOOP
 curblk := Get_Relation_Property(currel,DETAIL_NAME);
 IF (Get_Block_Property(curblk,STATUS) = 'CHANGED') THEN RETURN curblk;
 ELSE retblk := first_changed(curblk);
 IF retblk IS NOT NULL THEN RETURN retblk;
 ELSE currel := Get_Relation_Property(currel,NEXT_MASTER_RELATION);
 END IF; END IF; END LOOP; RETURN NULL; END first_changed;
 BEGIN mastblk := :System.Master_Block;
 coordop := :System.Coordination_Operation; trigblk := :System.Trigger_Block;
 startitm := :System.Cursor_Item; frmstat := :System.Form_Status;
 IF coordop NOT IN ('CLEAR_RECORD','SYNCHRONIZE_BLOCKS') THEN
 IF mastblk = trigblk THEN IF frmstat = 'CHANGED' THEN
 curblk := first_changed(mastblk);
 IF curblk IS NOT NULL THEN Go_Block(curblk); failure_helper;
 Clear_Block(ASK_COMMIT);
 IF NOT (:System.Form_Status = 'QUERY' OR :System.Block_Status = 'NEW') THEN
 RAISE Form_Trigger_Failure; END IF; END IF; END IF; END IF; END IF;
 currel := Get_Block_Property(trigblk,FIRST_MASTER_RELATION);
 WHILE currel IS NOT NULL LOOP
 curdtl := Get_Relation_Property(currel,DETAIL_NAME);
 IF Get_Block_Property(curdtl,STATUS) <> 'NEW' THEN
 Go_Block(curdtl); failure_helper; Clear_Block(NO_VALIDATE);
 IF :System.Block_Status <> 'NEW' THEN RAISE Form_Trigger_Failure; END IF;
 END IF; currel := Get_Relation_Property(currel,NEXT_MASTER_RELATION);
 END LOOP;
 IF :System.Cursor_Item <> startitm THEN Go_Item(startitm); failure_helper; END IF;
 EXCEPTION WHEN Form_Trigger_Failure THEN
 IF :System.Cursor_Item <> startitm THEN Go_Item(startitm); END IF;
 RAISE; END clear_helper;'''
_FAILURE = '''PROCEDURE failure_helper IS BEGIN
 IF NOT (Form_Success) THEN RAISE Form_Trigger_Failure; END IF; END;'''
_VARIABLES = {'CLEAR_HELPER', 'FAILURE_HELPER', 'FIRST_CHANGED', 'MASTER',
              'MASTBLK', 'COORDOP', 'TRIGBLK', 'STARTITM', 'FRMSTAT',
              'CURBLK', 'CURREL', 'CURDTL', 'RETBLK'}


def _need(value, reason):
    if not value:
        raise ValueError('DETAIL_CLEAR_' + reason)


def _json(value):
    return native_buffer._json(value)


def _lex(text):
    """Finite lexer keeps literal contents and consumes every active character."""
    text, decode = decode_control_entities(text)
    pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|"
                         r'[A-Za-z_$#][A-Za-z0-9_$#]*|[0-9]+|:=|<>|[:.,();=]', re.S)
    out, offset = [], 0
    for match in pattern.finditer(text):
        _need(match.start() == offset, 'UNSUPPORTED_SOURCE_TOKEN')
        token = match[0]
        offset = match.end()
        if token.isspace() or token.startswith(('--', '/*')):
            continue
        out.append(token if token.startswith("'") else token.upper())
    _need(offset == len(text), 'UNSUPPORTED_SOURCE_TOKEN')
    return out, decode


def _match_template(text, template):
    actual, decode = _lex(text)
    expected, _ = _lex(template)
    _need(len(actual) == len(expected), 'COMPLETE_SOURCE_BODY_REQUIRED')
    names = {}
    fixed = set(expected) - _VARIABLES
    for wanted, value in zip(expected, actual):
        if wanted in _VARIABLES:
            _need(re.fullmatch(r'[A-Z][A-Z0-9_$#]{0,127}', value)
                  and value not in fixed, 'LOCAL_IDENTIFIER_REQUIRED')
            _need(names.setdefault(wanted, value) == value, 'LOCAL_IDENTIFIER_CHANGED')
        else:
            _need(value == wanted, 'COMPLETE_SOURCE_BODY_REQUIRED')
    _need(len(set(names.values())) == len(names), 'ALIASED_LOCAL_IDENTIFIER')
    return names, decode


def recognize_clear_sources(documents, packet, chunks):
    """Bind a whole module caller, recursive helper and failure helper freshly."""
    fresh, actual_chunks = _build(documents)
    _need(packet.get('source_binding') == fresh['source_binding']
          and packet.get('sources') == fresh['sources'] and chunks == actual_chunks, 'FRESH_SOURCE_REQUIRED')
    objects, attrs = _source_objects(documents, packet)
    units = {u['owner_id']: u for s in packet['sources'] for u in s['facts']['code_units']}
    texts = {c['code_unit_id']: c['text'] for c in chunks}
    results, gaps = [], []
    for owner in objects.values():
        if owner['kind'] != 'Trigger' or (owner['name'] or '').upper() != 'ON-CLEAR-DETAILS':
            continue
        unit = units.get(owner['id'])
        if unit is None:
            continue
        try:
            _need(owner['block_id'] is None and owner['parent_id'] == owner['module_id'],
                  'MODULE_CLEAR_CALLER_REQUIRED')
            tokens, caller_decode = _lex(texts[unit['id']])
            _need(len(tokens) == 5 and tokens[0] == 'BEGIN'
                  and tokens[2:] == [';', 'END', ';'], 'COMPLETE_CALLER_REQUIRED')
        except ValueError as exc:
            gaps.append({'source_unit_id': unit['id'], 'reason': str(exc)})
            continue
        try:
            helpers = [o for o in objects.values() if o['kind'] == 'ProgramUnit'
                       and o['module_id'] == owner['module_id']
                       and (o['name'] or '').upper() == tokens[1] and o['id'] in units]
            _need(len(helpers) == 1, 'UNIQUE_LOCAL_CLEAR_HELPER_REQUIRED')
            helper = units[helpers[0]['id']]
            names, decode = _match_template(texts[helper['id']], _CLEAR)
            _need(names['CLEAR_HELPER'] == tokens[1], 'CALLER_HELPER_MISMATCH')
            failures = [o for o in objects.values() if o['kind'] == 'ProgramUnit'
                        and o['module_id'] == owner['module_id']
                        and (o['name'] or '').upper() == names['FAILURE_HELPER'] and o['id'] in units]
            _need(len(failures) == 1, 'UNIQUE_FAILURE_HELPER_REQUIRED')
            failure = units[failures[0]['id']]
            failure_names, failure_decode = _match_template(texts[failure['id']], _FAILURE)
            _need(failure_names['FAILURE_HELPER'] == names['FAILURE_HELPER'], 'FAILURE_HELPER_MISMATCH')
            results.append({'source_module_id': owner['module_id'],
                'caller_source_owner_id': owner['id'],
                'caller_source_unit_id': unit['id'], 'caller_source_unit_sha256': unit['sha256'],
                'source_unit_id': helper['id'], 'source_unit_sha256': helper['sha256'],
                'failure_source_unit_id': failure['id'], 'failure_source_unit_sha256': failure['sha256'],
                'decode_receipts': [caller_decode, decode, failure_decode]})
        except ValueError as exc:
            gaps.append({'source_unit_id': unit['id'], 'reason': str(exc)})
    return results, gaps


def ordered_relation_tree(documents, packet, module_id):
    """Preserve FIRST/NEXT relation XML declaration order, never hash order."""
    objects, attrs = _source_objects(documents, packet)
    tree, parents = {}, {}
    relations = [o for o in objects.values() if o['kind'] == 'Relation' and o['module_id'] == module_id]
    relations.sort(key=lambda o: o['location']['byte_offset'])
    for relation in relations:
        parent = objects.get(relation['block_id'])
        child = [o for o in objects.values() if o['kind'] == 'Block'
                 and o['module_id'] == module_id
                 and (o['name'] or '').upper() == attrs[relation['id']].get('DetailBlock', '').upper()]
        _need(parent and parent['module_id'] == module_id and len(child) == 1,
              'UNIQUE_DECLARED_RELATION_REQUIRED')
        child = child[0]
        _need(child['id'] not in parents, 'RELATION_TREE_REQUIRED')
        parents[child['id']] = parent['id']
        tree.setdefault(parent['id'], []).append({'relation_id': relation['id'],
            'child_block_id': child['id'], 'parent_block_id': parent['id'],
            'source_attribute_sha256': hashlib.sha256(_json(attrs[relation['id']])).hexdigest()})
    def visit(block, path):
        _need(block not in path, 'ACYCLIC_RELATION_TREE_REQUIRED')
        for edge in tree.get(block, []):
            visit(edge['child_block_id'], path + (block,))
    for block in tree:
        visit(block, ())
    return tree


def first_changed_block(tree, master, statuses):
    """Exact source pre-order: child itself, its descendants, next sibling."""
    for edge in tree.get(master, []):
        child = edge['child_block_id']
        _need(statuses.get(child) in ('NEW', 'QUERY', 'CHANGED'), 'KNOWN_DESCENDANT_STATUS_REQUIRED')
        if statuses[child] == 'CHANGED':
            return child
        changed = first_changed_block(tree, child, statuses)
        if changed is not None:
            return changed
    return None


def clear_intent(tree, driving, triggering, operation, form_status, statuses):
    """Model source ASK skip rules without authorizing silent dirty discard."""
    ask = operation not in ('CLEAR_RECORD', 'SYNCHRONIZE_BLOCKS') and driving == triggering and form_status == 'CHANGED'
    first = first_changed_block(tree, driving, statuses) if ask else None
    clear = [e['child_block_id'] for e in tree.get(triggering, [])
             if statuses.get(e['child_block_id']) != 'NEW']
    _need(all(statuses.get(e['child_block_id']) in ('NEW', 'QUERY', 'CHANGED')
              for e in tree.get(triggering, [])), 'KNOWN_DESCENDANT_STATUS_REQUIRED')
    return {'ask': first is not None, 'first_changed_block_id': first,
            'direct_clear_block_ids': clear, 'requires_explicit_discard': any(statuses[b] == 'CHANGED' for b in clear),
            'database_rows_deleted': False}


def draft_status(rows, fields, current_seq, *, submitted=None, revision=None, expected_revision=None):
    """Model the actual ROW identity and baseline slots, including noncurrent rows.

    Rows carry values/baseline for every projected field. A missing baseline on a
    persisted row is unknown, never clean. An empty new placeholder is NEW.
    """
    _need(revision == expected_revision, 'STALE_REVISION')
    _need(len({r['seq_id'] for r in rows}) == len(rows)
          and sum(r['seq_id'] == current_seq for r in rows) == 1, 'CURRENT_DRAFT_IDENTITY')
    dirty, persisted = [], False
    for row in rows:
        values = list(submitted if submitted is not None and row['seq_id'] == current_seq else row['values'])
        _need(len(values) == len(fields), 'DRAFT_PROJECTION')
        if row['persisted_id'] is None:
            changed = any(values[i] not in (None, '') for i, f in enumerate(fields) if not f.get('parent_copy'))
        else:
            persisted = True
            _need(row.get('marker') == 'SYNTHETIC_SAVE_BASELINE_V1'
                  and len(row.get('baseline', [])) == len(fields), 'PERSISTED_BASELINE_REQUIRED')
            changed = any((values[i] or None) != (row['baseline'][i] or None)
                          for i, f in enumerate(fields) if not f.get('parent_copy'))
        if changed:
            dirty.append(row['seq_id'])
    return {'status': 'CHANGED' if dirty else 'QUERY' if persisted else 'NEW',
            'changed_seq_ids': dirty, 'current_changed': current_seq in dirty}


def _save_providers(documents, packet, chunks, trace, files):
    """Rebuild normal Save authority before interpreting its private ROW slots."""
    from .forms_draft_providers import rebuild_draft_providers
    from .forms_synthetic_save import SCOPE as save_scope
    if 'fox-package/buffer-plan.json' not in files:
        return []
    plan, targets, proved, receipt, item_layouts = rebuild_draft_providers(documents, packet, chunks, trace, files)
    def one(rows):
        _need(len(rows) == 1, 'UNIQUE_SAVE_PROVIDER_REQUIRED')
        return rows[0]
    # Reconstruct A's exact permitted additions, including its focus script.
    # No prefix test, arbitrary appended content or caller-rehashed receipt is
    # accepted as authority to reinterpret a mutating Save page.
    from .forms_master_detail import apply_master_details, _entry_button
    population = json.loads(files['fox-package/master-detail-receipt.json'])
    clean = dict(files)
    for target in targets:
        clean[target['page_file']] = proved[target['page_file']]
    for op in population['adapted_operations']:
        clean.pop(op['page_file'], None)
        entry = _entry_button(op['page_id']).encode()
        parent_file = op['entry_report_file']
        _need(clean[parent_file].count(entry) == 1, 'POPULATION_ENTRY_CHANGED')
        clean[parent_file] = clean[parent_file].replace(entry, b'')
    population_files, population_proof = apply_master_details(documents, packet, chunks, trace, clean)
    _need(population == population_proof, 'POPULATION_RECEIPT_CHANGED')
    for op in population['adapted_operations']:
        _need(files[op['page_file']] == population_files[op['page_file']], 'NORMAL_POPULATION_PAGE_CHANGED')
    result = []
    for contract in receipt['write_contracts']:
        buffer = one([b for b in plan['operations'] if b['operation_id'] == contract['buffer_operation_id']])
        target = one([t for t in targets if t['operation_id'] == buffer['operation_id']])
        _need(files[target['page_file']] == population_files[target['page_file']], 'NORMAL_SAVE_PAGE_CHANGED')
        name = 'FOX_S_' + native_buffer._sha(_json({'buffer': buffer, 'contract': contract, 'scope': save_scope}))[:20].upper() + '_'
        item = item_layouts.get(buffer['operation_id'])
        result.append({'buffer': buffer, 'contract': contract, **target,
                       'namespace': item['collection_namespace'] if item else name, 'item_layout': item})
    return result


def _dirty_sql(provider, alias='d'):
    fields = provider['buffer']['key_bindings']
    editable = [i for i, f in enumerate(fields, 1) if not f.get('parent_copy')]
    nonempty = ' or '.join(f'{alias}.c{i:03} is not null' for i in editable) or '1=0'
    changed = ' or '.join('not (' + native_buffer._parent_match(f'{alias}.c{i:03}', f'{alias}.c{20+i:03}') + ')'
                          for i in editable) or '1=0'
    if provider.get('item_layout'):
        nonempty += f' or {alias}.n002 is not null or {alias}.c044 is not null or {alias}.c043 is not null'
        changed += f" or {alias}.c043 is not null or decode({alias}.n002,{alias}.n003,1,0)=0 or not (" + native_buffer._parent_match(alias+'.c044',alias+'.c040') + ')'
    return f'(({alias}.n001 is null and ({nonempty})) or ({alias}.n001 is not null and ({changed})))'


def _inspect_buffer_sql(provider, number):
    """Only the old selected parent's exact provider namespace can be touched."""
    buffer, contract = provider['buffer'], provider['contract']
    rel, fields = buffer['relation'], buffer['key_bindings']
    name = "'" + provider['namespace'] + "'||to_char(l_old,'TM9')"
    for _, column in native_buffer._parent_copies(buffer):
        name += "||'_'||substr(rawtohex(standard_hash(p." + column + ",'SHA256')),1,32)"
    prefix = "'" + provider['namespace'] + "'||to_char(l_old,'TM9')||'_'"
    equal = ' and '.join(native_buffer._parent_match('c.' + f['column'], f'd.c{20+i:03}')
                         for i, f in enumerate(fields, 1))
    equal += ' and ' + native_buffer._parent_match('c.' + contract['route']['column'], 'd.c040')
    if provider.get('item_layout'):
        equal += ' and decode(c.' + provider['item_layout']['fields']['weight']['column'] + ',d.n003,1,0)=1'
    membership = ' and '.join('p.' + p['parent_column'] + '=c.' + p['child_column'] for p in rel['join_pairs'])
    inherited = ' and '.join(native_buffer._parent_match(f'd.c{i:03}', 'p.' + f['parent_copy']['parent_column'])
                              for i, f in enumerate(fields, 1) if f.get('parent_copy')) or '1=1'
    valid = ' and '.join(f'nvl(lengthb(d.c{i:03}),0)<=4000' for i in range(1, len(fields)+1))
    dirty = _dirty_sql(provider)
    # Missing stored rows/baselines, inherited-key mismatch and stale revisions
    # are unknown states, never treated as clean or silently truncated.
    return f'''
select {name} into l_name from {rel['parent']['table']} p where p.FOX_ROW_ID=l_old for update nowait;
select count(*) into l_count from apex_collections
 where substr(collection_name,1,length({prefix}))={prefix} and collection_name<>l_name;
if l_count<>0 then raise_application_error(-20061,'A prior-key draft is retained. Reopen and reconcile it before switching.');end if;
l_names({number}):=null;
if apex_collection.collection_exists(l_name) then
 select count(*) into l_count from apex_collections where collection_name=l_name and seq_id=1
 and c050='META' and c049='{native_buffer._sha(_json(buffer))}' and n001=l_old
 and n002 is not null and n002=trunc(n002) and n002>1
 and n003 is not null and n003=trunc(n003) and n003>=0 and n003<1000000000000000;
 if l_count<>1 then raise_application_error(-20061,'Draft identity is unavailable. Reopen the draft before switching.');end if;
 select n002,n003 into l_seq,l_revision from apex_collections where collection_name=l_name and seq_id=1;
 select count(*) into l_count from apex_collections where collection_name=l_name
 and (c050 is null or not ((seq_id=1 and c050='META') or (seq_id>1 and c050='ROW')));
 if l_count<>0 then raise_application_error(-20061,'Unknown draft members are retained. Reopen before switching.');end if;
 select count(*) into l_count from apex_collections where collection_name=l_name and c050='ROW';
 if l_count<1 or l_count>{native_buffer.MAX_RECORDS} then raise_application_error(-20061,'Draft record set is incomplete.');end if;
 select count(*) into l_count from apex_collections where collection_name=l_name and seq_id=l_seq and c050='ROW';
 if l_count<>1 then raise_application_error(-20061,'Current draft identity is unavailable.');end if;
 select count(*) into l_count from apex_collections d where d.collection_name=l_name and d.c050='ROW'
 and ((not ({valid})) or (d.n001 is null and d.c041 is not null)
 or (d.n001 is not null and (d.n001<=0 or d.n001<>trunc(d.n001)))
 or not exists(select 1 from {rel['parent']['table']} p where p.FOX_ROW_ID=l_old and {inherited})
 or (d.n001 is not null and (d.c041 is null or d.c041<>'SYNTHETIC_SAVE_BASELINE_V1'
 or not exists(select 1 from {rel['child']['table']} c,{rel['parent']['table']} p
 where p.FOX_ROW_ID=l_old and c.FOX_ROW_ID=d.n001 and {membership} and {equal}))));
 if l_count<>0 then raise_application_error(-20061,'A stored baseline or parent link changed. Drafts retained; reopen before switching.');end if;
 l_revisions:=l_revisions||'/{number}:'||to_char(l_revision,'TM9');
 select count(*) into l_count from apex_collections d where d.collection_name=l_name and d.c050='ROW' and {dirty};
 select count(*) into l_persisted from apex_collections where collection_name=l_name and c050='ROW' and n001 is not null;
 if l_count>0 or l_persisted>0 then l_names({number}):=l_name;end if;
 if l_count>0 then
  l_dirty:=l_dirty+l_count;
  if l_first=0 then l_first:={number};end if;
  for r in(select seq_id from apex_collections d where d.collection_name=l_name and d.c050='ROW' and {dirty} order by seq_id)loop
   if nvl(length(l_changes),0)<2500 then l_changes:=l_changes||' editor {provider['page_id']} record '||to_char(r.seq_id-1,'TM9')||';';l_listed:=l_listed+1;end if;
  end loop;
 end if;
else l_revisions:=l_revisions||'/{number}:absent';end if;'''


def _gate_code(op, providers):
    """One savepoint covers discard, state transition and error restoration.

    Source-wide transaction providers do not exist. Save therefore opens the
    normal protected editor; it never claims to have saved sibling drafts.
    """
    page = op['page_id']
    parent, token, state = (':' + op[k] for k in ('parent_item', 'token_item', 'state_item'))
    name = 'FOX_C_' + hashlib.sha256(_json([SCOPE, op['operation_id']])).hexdigest()[:24].upper()
    inspect = '\n'.join(_inspect_buffer_sql(p, i) for i, p in enumerate(providers, 1))
    populate = op['population_process_code']
    candidate_probe = 'select count(*) into l_count from (' + op['parent_context_sql'] + ');'
    expected_state = 'NON_COORDINATED' if op['deferred'] else 'COORDINATED'
    old_table = providers[0]['buffer']['relation']['parent']['table']
    ledger_match = ' and '.join(native_buffer._parent_match('c' + f'{i:03}', variable)
        for i, variable in ((1, 'l_old_token'), (2, 'l_pending_token'), (3, 'l_expected'),
                            (4, 'l_ticket'), (5, 'l_recovery')))
    return f'''declare
type names_t is table of varchar2(255) index by binary_integer;
l_names names_t;
l_old number; l_new number; l_pending number; l_seq number; l_revision number;
l_old_token varchar2(4000); l_new_token varchar2(4000); l_pending_token varchar2(4000);
l_ticket varchar2(4000); l_recovery varchar2(4000); l_expected varchar2(4000); l_revisions varchar2(4000):='v1';
l_locked boolean:=false; l_old_missing boolean:=false;
l_count number; l_persisted number; l_dirty number:=0; l_first number:=0; l_listed number:=0;
l_name varchar2(255); l_changes varchar2(3000); l_message varchar2(4000);
procedure populate is begin {populate} end;
procedure restore_selection is begin {parent}:=l_old;{token}:=l_old_token;end;
begin
savepoint fox_detail_clear;
:P{page}_CLEAR_PENDING:=null;:P{page}_CLEAR_RECOVERY:=null;:P{page}_CLEAR_MESSAGE:=null;
if apex_collection.collection_exists('{name}') then
 select count(*) into l_count from apex_collections where collection_name='{name}';
 if l_count<>1 then raise_application_error(-20061,'Selection state has multiple or missing members. Reload before selecting a master.');end if;
 select n001,c001,n002,c002,c003,c004,c005 into l_old,l_old_token,l_pending,l_pending_token,l_expected,l_ticket,l_recovery
 from apex_collections where collection_name='{name}' and seq_id=1 and c050='{SCOPE}'
 and n001 is not null and n001>0 and n001=trunc(n001) and c001 is not null;
end if;
if l_old is not null then
 begin
  select FOX_ROW_ID into l_count from {old_table} where FOX_ROW_ID=l_old for update nowait;
  l_locked:=true;
 exception when no_data_found then l_old_missing:=true;end;
 select count(*) into l_count from apex_collections where collection_name='{name}' and seq_id=1
 and n001=l_old and decode(n002,l_pending,1,0)=1 and {ledger_match} and c050='{SCOPE}'
 and (select count(*) from apex_collections where collection_name='{name}')=1;
 if l_count<>1 then raise_application_error(-20061,'Selection changed in another request. No drafts were cleared.');end if;
end if;
if :REQUEST='FOX_CLEAR_FRESH' then
 if l_old is null or l_recovery is null or :P{page}_CLEAR_TICKET is null or :P{page}_CLEAR_TICKET<>l_recovery then
  raise_application_error(-20061,'This recovery prompt changed. No drafts were cleared.');end if;
 apex_collection.delete_collection('{name}');
 {parent}:=null;{token}:=null;populate;
 :P{page}_CLEAR_MESSAGE:='Fresh selection started. Every previous draft buffer is retained for reconciliation. No records were saved or discarded.';
 return;
end if;
if :REQUEST in ('FOX_CLEAR_DISCARD','FOX_CLEAR_CANCEL') then
 if l_pending is null or :P{page}_CLEAR_TICKET is null or :P{page}_CLEAR_TICKET<>l_ticket then
  raise_application_error(-20061,'This switch prompt changed in another request. No drafts were cleared.');end if;
 if :REQUEST='FOX_CLEAR_CANCEL' then
  restore_selection;populate;
  if {state} is null or {state}<>'{expected_state}' then
   raise_application_error(-20061,'The previous master details could not be restored. Pending selection and drafts retained.');end if;
  apex_collection.update_member(p_collection_name=>'{name}',p_seq=>1,p_n001=>l_old,p_c001=>l_old_token,p_c050=>'{SCOPE}');
  :P{page}_CLEAR_MESSAGE:='Master change canceled. Session drafts retained.';return;
 end if;
 {parent}:=l_pending;{token}:=l_pending_token;
end if;
l_new:={parent};l_new_token:={token};
if l_old is null then
 populate;
 if {state} in ('COORDINATED','NON_COORDINATED') then
  if apex_collection.collection_exists('{name}') then
   raise_application_error(-20061,'Another request selected the initial master. Reload before continuing.');end if;
  apex_collection.create_collection('{name}');
  apex_collection.add_member(p_collection_name=>'{name}',p_n001=>l_new,p_c001=>l_new_token,p_c050=>'{SCOPE}');
 end if;return;
end if;
if l_new=l_old and l_new_token=l_old_token then populate;return;end if;
if l_new is null or l_new_token is null then restore_selection;populate;return;end if;
{candidate_probe}
if l_count<>1 then raise_application_error(-20061,'The requested master is missing, stale, null or ambiguous.');end if;
restore_selection;
{candidate_probe}
if l_count<>1 then raise_application_error(-20061,'The previous master changed. Drafts retained for reconciliation.');end if;
{inspect}
{candidate_probe}
if l_count<>1 then raise_application_error(-20061,'The previous master changed while its draft was checked.');end if;
if :REQUEST='FOX_CLEAR_DISCARD' and l_revisions<>l_expected then
 raise_application_error(-20061,'A draft changed after this prompt. No drafts were cleared.');end if;
if l_dirty>0 and (:REQUEST is null or :REQUEST<>'FOX_CLEAR_DISCARD') then
 l_ticket:=rawtohex(sys_guid());
 apex_collection.update_member(p_collection_name=>'{name}',p_seq=>1,p_n001=>l_old,p_c001=>l_old_token,
  p_n002=>l_new,p_c002=>l_new_token,p_c003=>l_revisions,p_c004=>l_ticket,p_c050=>'{SCOPE}');
 :P{page}_CLEAR_TICKET:=l_ticket;:P{page}_CLEAR_PENDING:='Y';
 :P{page}_CLEAR_PARENT:=to_char(l_old,'TM9');
 :P{page}_CLEAR_EDITOR:=case l_first {' '.join(f'when {i} then {p["page_id"]}' for i,p in enumerate(providers,1))} end;
 :P{page}_CLEAR_MESSAGE:='Changed session drafts ('||to_char(l_dirty,'TM9')||' records):'||l_changes
 ||case when l_dirty>l_listed then to_char(l_dirty-l_listed,'TM9')||' additional changed records are retained; review all rows in the listed editors.' else null end
 ||' Save opens the normal editor. Save each changed record there, then return and select the master again. Discard clears only these known session buffers. Cancel keeps this master. Full form commit and other descendant providers remain pending.';
 populate;
 if {state} is null or {state}<>'{expected_state}' then
  raise_application_error(-20061,'The previous master details could not be restored for the switch prompt. Drafts retained.');end if;
 {state}:='DETAIL_CHANGES_PENDING';return;
end if;
{parent}:=l_new;{token}:=l_new_token;populate;
if {state} not in ('COORDINATED','NON_COORDINATED') or {state} is null then
 raise_application_error(-20061,'Detail population failed. Previous master and session drafts retained.');end if;
for i in 1..l_names.count loop
 if l_names(i) is not null and apex_collection.collection_exists(l_names(i)) then apex_collection.delete_collection(l_names(i));end if;
end loop;
apex_collection.update_member(p_collection_name=>'{name}',p_seq=>1,p_n001=>l_new,p_c001=>l_new_token,p_c050=>'{SCOPE}');
exception when others then
l_message:=case when sqlcode=-20061 then substr(sqlerrm,12,3500) else 'The master could not be changed. Previous selection and session drafts retained.' end;
rollback to fox_detail_clear;
restore_selection;
begin populate;exception when others then null;end;
{state}:='CLEAR_FAILED_RESTORED';
:P{page}_CLEAR_PENDING:=null;
if l_old is not null and (l_locked or l_old_missing) and apex_collection.collection_exists('{name}') then
 begin
  begin select FOX_ROW_ID into l_count from {old_table} where FOX_ROW_ID=l_old for update nowait;
  exception when no_data_found then null;end;
  select count(*) into l_count from apex_collections where collection_name='{name}' and seq_id=1
   and n001=l_old and decode(n002,l_pending,1,0)=1 and {ledger_match} and c050='{SCOPE}'
   and (select count(*) from apex_collections where collection_name='{name}')=1;
  if l_count=1 then
   l_recovery:=rawtohex(sys_guid());
   apex_collection.update_member_attribute(p_collection_name=>'{name}',p_seq=>1,p_attr_number=>4,p_attr_value=>null);
   apex_collection.update_member_attribute(p_collection_name=>'{name}',p_seq=>1,p_attr_number=>5,p_attr_value=>l_recovery);
   :P{page}_CLEAR_TICKET:=l_recovery;:P{page}_CLEAR_RECOVERY:='Y';
   l_message:=l_message||' Start fresh selection retains every stale draft buffer for reconciliation.';
  end if;
 exception when others then null;end;
end if;
:P{page}_CLEAR_MESSAGE:=l_message;
apex_debug.error('Master detail session clear failed: %s',sqlerrm);
apex_error.add_error(p_message=>l_message,p_display_location=>apex_error.c_inline_in_notification);
end;'''


def _controls(page):
    items = ''.join(native_buffer._hidden(page, name, i*10).replace('region: @editor', 'region: @coordination-scope')
                    for i, name in enumerate(('CLEAR_PENDING', 'CLEAR_TICKET', 'CLEAR_PARENT', 'CLEAR_EDITOR', 'CLEAR_RECOVERY'), 1))
    items += f'''    pageItem P{page}_CLEAR_MESSAGE (
        type: displayOnly
        label {{ label: Draft changes before switching }}
        layout {{ sequence: 60
            region: @coordination-scope
            slot: regionBody }}
        sessionState {{ storage: request
            dataType: varchar2 }}
        security {{ sessionStateProtection: restricted }}
    )
'''
    condition = f'''        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: ":P{page}_CLEAR_PENDING='Y'" }}
'''
    buttons = ''
    for slug, request, label, seq in (('discard-detail-drafts', 'FOX_CLEAR_DISCARD', 'Discard', 70),
                                     ('cancel-master-switch', 'FOX_CLEAR_CANCEL', 'Cancel', 80)):
        button = native_buffer._button(slug, request, label, seq).replace('region: @editor', 'region: @coordination-scope')
        button = button.replace('executeValidations: true', 'executeValidations: false')
        buttons += button[:-6] + condition + '    )\n'
    recovery = native_buffer._button('fresh-master-selection', 'FOX_CLEAR_FRESH', 'Start fresh selection', 90).replace('region: @editor', 'region: @coordination-scope')
    recovery = recovery.replace('executeValidations: true', 'executeValidations: false')
    buttons += recovery[:-6] + f'''        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: ":P{page}_CLEAR_RECOVERY='Y'" }}
    )
'''
    return items, buttons


def _render_gate(op, providers, files):
    page = op['page_id']
    text = files[op['page_file']].decode()
    original = native_buffer._expand_groups(native_buffer._process(op['population_process'], op['population_process_code'], point='beforeHeader', sequence=50))
    _need(text.count(original) == 1, 'EXACT_POPULATION_PROCESS_REQUIRED')
    code = _gate_code(op, providers)
    _need(len(code.encode()) <= 32767, 'NATIVE_PROCESS_CAPACITY')
    process = native_buffer._expand_groups(native_buffer._process(op['population_process'], code, point='beforeHeader', sequence=50))
    text = text.replace(original, process)
    if not op['deferred']:
        visible = op['visible_child_query_sql']
        suffix = f" and :P{page}_STATE='COORDINATED'"
        _need(visible == op['child_query_sql'] + suffix, 'EXACT_VISIBLE_CHILD_QUERY_REQUIRED')
        region = re.search(r'    region detail-records \(\n.*?\n    \)\n', text, re.S)
        _need(region is not None, 'EXACT_CHILD_REGION_REQUIRED')
        old_query = native_buffer._indent(visible)
        new_query = native_buffer._indent(op['child_query_sql']
            + f" and :P{page}_STATE in ('COORDINATED','DETAIL_CHANGES_PENDING')")
        _need(region[0].count(old_query) == 1, 'EXACT_VISIBLE_CHILD_QUERY_REQUIRED')
        text = text[:region.start()] + region[0].replace(old_query, new_query) + text[region.end():]
    items, buttons = _controls(page)
    for i, provider in enumerate(providers, 1):
        target = provider['page_id']
        buttons += f'''    button save-detail-drafts-{i} (
        buttonName: FOX_CLEAR_OPEN_SAVE_{i}
        label: Save
        layout {{ sequence: {65+i}
            region: @coordination-scope
            slot: create }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {target}
                items: {{ P{target}_PARENT_ID: "&P{page}_CLEAR_PARENT." }} }} }}
        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: ":P{page}_CLEAR_PENDING='Y' and :P{page}_CLEAR_EDITOR='{target}'" }}
    )
'''
    # Submit buttons use the same savepoint gate as GET selection. A successful
    # native branch renders the accepted master through a fresh signed request.
    submit = native_buffer._process('resolve-detail-changes', code, point='processing', sequence=10)
    submit = submit[:-6] + '''        serverSideCondition { type: requestIsContainedInValue
            value: FOX_CLEAR_DISCARD,FOX_CLEAR_CANCEL,FOX_CLEAR_FRESH
        }
    )
'''
    branch = f'''    branch show-selected-master-after-clear (
        name: Show selected master after clear
        execution {{ sequence: 20
            point: afterProcessing }}
        behavior {{ type: pageOrUrl
            target: {{ page: {page}
                items: {{ {op['parent_item']}: "&{op['parent_item']}."
                    {op['token_item']}: "&{op['token_item']}." }} }} }}
        serverSideCondition {{ type: requestIsContainedInValue
            value: FOX_CLEAR_DISCARD,FOX_CLEAR_CANCEL,FOX_CLEAR_FRESH }}
    )
'''
    text = text.replace('Session drafts are retained. Source ON-CLEAR-DETAILS and ASK_COMMIT remain pending.',
        'Master changes check all retained rows in known synthetic session buffers. Clean non-new buffers clear after successful switching. Changed known buffers require Save, Discard or Cancel. Unknown descendants are retained; full Forms ON-CLEAR-DETAILS and ASK_COMMIT remain pending. If reconciliation fails, Start fresh selection retains every prior draft buffer.')
    return (text[:-2] + native_buffer._expand_groups(items + buttons + submit + branch) + ')\n').encode()


def apply_detail_clear(documents, packet, chunks, trace, files):
    """Attach reachable partial effects after the population receipt is stored.

    Whole source units remain encoded/partial: all-form dirty providers, actual
    Forms cursor operations and transaction-wide ASK_COMMIT are unavailable.
    """
    models, gaps = recognize_clear_sources(documents, packet, chunks)
    _need(trace.get('source_binding') == packet['source_binding'], 'TRACE_SOURCE_BINDING')
    for name, raw in documents:
        _need(files.get('fox-package/sources/' + name) == raw, 'ORIGINAL_CHANGED')
    output = dict(files)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': packet['source_binding'],
        'generated_operations': [], 'adapted_operations': [], 'helper_models': models,
        'gaps': gaps, 'converted_code_unit_count': 0, 'customer_table_writes': False,
        'synthetic_table_writes': False, 'database_rows_deleted': False,
        'oracle_compiled': False, 'runtime_verified': False, 'business_accepted': False}
    population = json.loads(files.get('fox-package/master-detail-receipt.json', b'{"adapted_operations":[]}'))
    if population['adapted_operations']:
        _need(population.get('source_binding') == packet['source_binding'], 'POPULATION_SOURCE_BINDING')
    if not models or not population['adapted_operations']:
        for model in models:
            receipt['gaps'].append({'source_unit_id': model['source_unit_id'], 'reason': 'DETAIL_CLEAR_MASTER_SELECTION_HOOK_UNAVAILABLE'})
        return output, receipt
    try:
        providers = _save_providers(documents, packet, chunks, trace, files)
    except (ValueError, KeyError, TypeError) as exc:
        providers = []
        receipt['gaps'].append({'reason': str(exc) if isinstance(exc, ValueError) else 'DETAIL_CLEAR_SAVE_PROVIDER_UNAVAILABLE'})
    for model in models:
        try:
            tree = ordered_relation_tree(documents, packet, model['source_module_id'])
        except ValueError as exc:
            receipt['gaps'].append({'source_unit_id': model['source_unit_id'], 'reason': str(exc)})
            continue
        model['ordered_relation_tree'] = tree
        for op in population['adapted_operations']:
            if op['source_module_id'] != model['source_module_id']:
                continue
            if op.get('applicable_clear_trigger_ids') != [model['caller_source_owner_id']]:
                receipt['gaps'].append({'source_unit_id': model['source_unit_id'],
                    'reason': 'DETAIL_CLEAR_APPLICABLE_TRIGGER_OVERRIDE_UNRESOLVED'})
                continue
            selected = [p for edge in tree.get(op['parent_block_id'], []) for p in providers
                        if p['buffer']['relation']['relation_id'] == edge['relation_id']]
            identity = {k: model[k] for k in ('source_unit_id', 'source_unit_sha256', 'caller_source_unit_id', 'caller_source_unit_sha256', 'failure_source_unit_id')}
            if not selected:
                receipt['gaps'].append({**identity, 'parent_block_id': op['parent_block_id'],
                    'reason': 'DETAIL_CLEAR_DESCENDANT_SESSION_PROVIDER_UNAVAILABLE',
                    'preserved_unknown_descendants': True})
                continue
            try:
                output[op['page_file']] = _render_gate(op, selected, output)
                receipt['adapted_operations'].append({**identity, 'kind': 'partial_session_master_switch_clear',
                    'page_id': op['page_id'], 'page_file': op['page_file'],
                    'population_operation_id': op['operation_id'], 'parent_block_id': op['parent_block_id'],
                    'buffer_operation_ids': [p['buffer']['operation_id'] for p in selected],
                    'generation_status': 'partial_effects_wired', 'native_event_wired': True,
                    'save_action': 'open_existing_guarded_synthetic_editor_no_implicit_save',
                    'discard_scope': 'known_old_parent_session_collections_only',
                    'unknown_descendants': 'preserved', 'source_scope': 'intentional_persisted_master_selection',
                    'stale_recovery': 'explicit_fresh_selection_retains_all_draft_collections',
                    'concurrency': 'old_synthetic_parent_row_lock_then_ledger_recheck_and_prompt_revision_ticket',
                    'runtime_verified': False, 'business_accepted': False})
            except (ValueError, KeyError, TypeError) as exc:
                receipt['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError) else 'DETAIL_CLEAR_HOOK_UNAVAILABLE'})
        for key in ('source_unit_id', 'caller_source_unit_id'):
            receipt['gaps'].append({'source_unit_id': model[key], 'reason': 'DETAIL_CLEAR_PARTIAL_LIFECYCLE_ONLY',
                'unimplemented_effects': ['source_wide_form_status_and_transaction_commit',
                    'unknown_descendant_draft_providers', 'recursive_runtime_clear_outside_known_direct_session_providers',
                    'Forms_cursor_and_block_status_runtime', 'CLEAR_RECORD_and_SYNCHRONIZE_BLOCKS_native_events',
                    'unsent_browser_input_on_other_pages']})
    return output, receipt
