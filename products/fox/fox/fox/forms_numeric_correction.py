"""Source-proved, explicit correction of one existing synthetic numeric row.

This is persistence for an already translated validation, not another converted
trigger, a Forms commit, an approval, or authority to write original tables.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import hashlib
import json
import re

from forms2apex import native_buffer
from .forms_behavior_plan import _source_objects, _recognize, _bind, decode_control_entities
from .forms_approval_plan import build_approval_plan
from .forms_approval_action import _contract as approval_contract, _coordinator, _queries, _result
from .forms_draft_policy import _derive
from .forms_draft_providers import rebuild_draft_providers
from .forms_master_detail import _fingerprint
from .forms_policy_plan import build_policy_plan
from .forms_synthetic_save import _table_proof, SCOPE as SAVE_SCOPE

SCOPE = 'fox-synthetic-numeric-correction-v1'
REQUEST = 'FOX_NUMERIC_SAVE'


def _need(value, reason):
    if not value:
        raise ValueError('NUMERIC_CORRECTION_' + reason)


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _sha(value):
    return hashlib.sha256(_json(value)).hexdigest()


def numeric_rules(props):
    """Finite positive decimal pictures; input uses ungrouped ASCII dot notation.

    Never round/truncate a user value to fit the source picture. Source locale
    dependent D/G, scientific notation and implicit pictures remain unsupported.
    """
    picture = props.get('FormatMask', '').strip()
    _need(re.fullmatch(r'[90]+(?:,[90]{3})*(?:\.[90]+)?', picture), 'EXPLICIT_DECIMAL_PICTURE_REQUIRED')
    whole, _, fraction = picture.partition('.')
    digits = len(whole.replace(',', ''))
    scale = len(fraction)
    length = props.get('MaximumLength', '').strip()
    _need(1 <= digits <= 28 and scale <= 9 and digits + scale <= 38
          and re.fullmatch(r'[1-9][0-9]{0,3}', length), 'NUMERIC_LIMITS')
    minimum = props.get('LowestAllowedValue', '').strip()
    maximum = props.get('HighestAllowedValue', '').strip() or None
    for value in (minimum, maximum):
        _need(value is None or re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value), 'FINITE_NONNEGATIVE_LIMIT_REQUIRED')
    _need(minimum and Decimal(minimum) > 0, 'POSITIVE_SOURCE_MINIMUM_REQUIRED')
    _need(maximum is None or Decimal(maximum) >= Decimal(minimum), 'SOURCE_LIMIT_ORDER')
    return {'picture': picture, 'integer_digits': digits, 'scale': scale,
            'max_length': int(length), 'minimum': minimum, 'maximum': maximum,
            'input_notation': 'ungrouped_ASCII_decimal_dot_no_sign_no_exponent',
            'conversion_nls': 'NLS_NUMERIC_CHARACTERS=.,',
            'rounding_or_truncation': False}


def validate_numeric_value(value, rules):
    """Deterministic reference for the emitted server numeric boundary."""
    _need(type(value) is str and len(value) <= rules['max_length'], 'VALUE_LENGTH')
    pattern = r'(?:0|[1-9][0-9]{0,' + str(rules['integer_digits'] - 1) + '})'
    if rules['scale']:
        pattern += r'(?:\.[0-9]{1,' + str(rules['scale']) + '})?'
    _need(re.fullmatch(pattern, value), 'VALUE_PICTURE')
    number = Decimal(value)
    _need(number != 0 and number >= Decimal(rules['minimum'])
          and (rules['maximum'] is None or number <= Decimal(rules['maximum'])), 'VALUE_LIMIT')
    return number


def _approval_binding(source_op, c, documents, packet, chunks, trace, files, objects, props):
    receipt = json.loads(files.get('fox-package/approval-action-receipt.json', b'{}'))
    _need(receipt.get('source_binding') == packet['source_binding'], 'APPROVAL_SOURCE')
    actual = _one([o for o in receipt.get('adapted_operations', [])
                   if o['source_unit_id'] == source_op['source_unit_id']], 'READINESS_PROVIDER_REQUIRED')
    page = actual['page_id']
    _need(type(page) is int and 1 <= page < 9000 and actual['page_file'] == f'pages/p{page:05d}-fox_approval_{page}.apx',
          'READINESS_PAGE')
    coordinator = _coordinator(documents, packet, chunks, trace, files, c, objects, props)
    if coordinator:
        _, bound, where_fn = coordinator
        where = where_fn(bound, page)
    else:
        where = f'p.FOX_ROW_ID=:P{page}_PARENT_ID and ({_fingerprint(c["blocks"]["header"]["items"])})=:P{page}_TOKEN'
    queries = _queries(c, page, where)
    _need(actual['contract'] == c and all(actual.get(k) == v for k, v in queries.items())
          and files[actual['page_file']] == _result(page, queries['readiness_query_sql']), 'FRESH_READINESS_REQUIRED')
    return actual, where


def build_numeric_correction_plan(documents, packet, chunks, trace, files):
    """Rebuild source, table, policy, readiness, draft and before-update proof."""
    approval = build_approval_plan(documents, packet, chunks, trace, files)
    result = {'schema_version': 1, 'scope': SCOPE, 'source_binding': packet['source_binding'],
              'operations': [], 'gaps': [], 'converted_code_unit_count': 0,
              'customer_table_writes': False, 'oracle_compiled': False,
              'runtime_verified': False, 'business_accepted': False}
    objects, props = _source_objects(documents, packet)
    policy = build_policy_plan(documents, trace)
    targets = {f['source_item_id']: (b, f) for b in trace['blocks'] for f in b['items']}
    units = {u['id']: u for s in packet['sources'] for u in s['facts']['code_units']}
    by_unit = {c['code_unit_id']: c for c in chunks}
    for source_op in approval['operations']:
        identity = {k: source_op[k] for k in ('source_unit_id', 'source_unit_sha256', 'source_owner_id', 'source_module_id')}
        try:
            _need('contract' in source_op, 'SOURCE_APPROVAL_BINDING_REQUIRED')
            c = approval_contract(source_op, objects, props, policy)
            ready, where = _approval_binding(source_op, c, documents, packet, chunks, trace, files, objects, props)
            field = c['fields']['weight']
            item = objects[field['source_item_id']]
            p = props[item['id']]
            _need(item['database_item'] is True and p.get('ItemType', '').upper() == 'TEXT ITEM'
                  and p.get('DataType', '').upper() == 'NUMBER'
                  and not p.get('Formula', '').strip() and p.get('CalculateMode', '').upper() not in ('FORMULA', 'SUMMARY')
                  and all(p.get(k, '').strip().lower() in ('', 'true') for k in ('Enabled', 'UpdateAllowed'))
                  and all(p.get(k, '').strip().lower() in ('', 'false') for k in ('QueryOnly', 'UpdateOnlyIfNull'))
                  and not any(v.strip() for k, v in p.items() if k.lower().startswith(('subclass', 'inherit')))
                  and props[item['block_id']].get('UpdateAllowed', '').strip().lower() in ('', 'true')
                  and props[item['block_id']].get('QueryOnly', '').strip().lower() in ('', 'false'),
                  'EDITABLE_STORED_NUMERIC_FIELD_REQUIRED')
            rules = numeric_rules(p)
            events = [o for o in objects.values() if o['kind'] == 'Trigger' and o['parent_id'] == item['id']]
            event = _one([o for o in events if (o['name'] or '').upper() == 'KEY-NEXT-ITEM'], 'NUMERIC_SOURCE_GUARD_REQUIRED')
            harmless = []
            for other in events:
                if other['id'] == event['id']:
                    continue
                override = _one([u for u in units.values() if u['owner_id'] == other['id']], 'ITEM_OVERRIDE_UNIT')
                text, _ = decode_control_entities(by_unit[override['id']]['text'])
                _need((other['name'] or '').upper() in ('PRE-QUERY', 'POST-QUERY', 'KEY-ENTQRY', 'KEY-EXEQRY')
                      and re.fullmatch(r'\s*(?:NULL\s*;|BEGIN\s+NULL\s*;\s*END\s*;)\s*', text, re.I),
                      'OTHER_ITEM_EVENT_UNIMPLEMENTED')
                harmless.append({'source_unit_id': override['id'], 'source_unit_sha256': override['sha256'],
                                 'effect': 'complete_NULL_query_override'})
            unit = _one([u for u in units.values() if u['owner_id'] == event['id']], 'NUMERIC_SOURCE_UNIT')
            semantic, decode = decode_control_entities(by_unit[unit['id']]['text'])
            guard = _bind(_recognize(unit, event, semantic), event, objects, props, targets)
            _need(guard['kind'] == 'numeric_nonzero_then_focus' and guard['source_item_id'] == item['id']
                  and guard['minimum'] == rules['minimum'], 'EXACT_NUMERIC_GUARD')
            buffers, _, _, saves, layouts = rebuild_draft_providers(documents, packet, chunks, trace, files)
            buffer = _one([b for b in buffers['operations'] if b['relation']['child_block_id'] == item['block_id']], 'DRAFT_PROVIDER')
            write = _one([w for w in saves['write_contracts'] if w['buffer_operation_id'] == buffer['operation_id']], 'BEFORE_UPDATE_SAVE_PROOF')
            _need(write['parent_table'] == c['blocks']['header']['table_name']
                  and write['child_table'] == c['blocks']['bag']['table_name']
                  and write['route']['column'] == source_op['contract']['fields']['bag_route']['column']
                  and write['parent_route']['column'] == source_op['contract']['fields']['header_route']['column']
                  and field['column'] not in {f['column'] for f in write['fields']}, 'EXACT_UPDATE_ROUTE_AND_FIELD')
            entry = _one([o for o in objects.values() if o['kind'] == 'Trigger' and o['parent_id'] == item['module_id']
                          and (o['name'] or '').upper() == 'WHEN-NEW-RECORD-INSTANCE'], 'COMPLETE_ENTRY_POLICY')
            _need(not any(o['kind'] == 'Trigger' and o['id'] != entry['id']
                          and o['parent_id'] in (buffer['relation']['parent_block_id'], item['block_id'], item['id'])
                          and (o['name'] or '').upper() in ('WHEN-NEW-RECORD-INSTANCE', 'WHEN-NEW-ITEM-INSTANCE')
                          for o in objects.values()), 'ENTRY_POLICY_OVERRIDE')
            policy_op = _one([o for o in policy['operations'] if o['source_owner_id'] == entry['id']], 'COMPLETE_ENTRY_POLICY')
            edit_policy, effects, _, _ = _derive(policy_op, buffer, trace,
                {o['id']: o for o in buffers['source_catalog']['objects']}, update_item=item['id'])
            _need(edit_policy is not None and edit_policy != '0', 'FIELD_UPDATE_POLICY_DENIED')
            header, bag = c['blocks']['header'], c['blocks']['bag']
            _table_proof(files, header, {write['parent_route']['column']})
            _table_proof(files, bag, {field['column'], write['route']['column']})
            namespace = 'FOX_S_' + _sha({'buffer': buffer, 'contract': write, 'scope': SAVE_SCOPE})[:20].upper() + '_'
            if buffer['operation_id'] in layouts:
                namespace = layouts[buffer['operation_id']]['collection_namespace']
                _need(layouts[buffer['operation_id']]['fields']['weight']['source_item_id'] != item['id'],
                      'DRAFT_NUMERIC_FIELD_CONFLICT')
            op = {**identity, 'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                  'source_owner_id': event['id'], 'harmless_item_overrides': harmless,
                  'source_event': 'KEY-NEXT-ITEM', 'source_item_id': item['id'], 'source_block_id': item['block_id'],
                  'operation_id': 'fnc1-' + _sha([packet['source_binding'], unit['id'], ready['operation_id']])[:24],
                  'approval_source_unit_id': source_op['source_unit_id'], 'approval_page_id': ready['page_id'],
                  'approval_page_file': ready['page_file'], 'approval_where_sql': where,
                  'numeric_source_unit_id': unit['id'], 'numeric_source_unit_sha256': unit['sha256'],
                  'numeric_guard': guard, 'decode_receipt': decode, 'rules': rules, 'fields': deepcopy(c['fields']),
                  'contract': c, 'write_contract': write, 'buffer_operation_id': buffer['operation_id'],
                  'buffer': buffer, 'item_layout': layouts.get(buffer['operation_id']),
                  'draft_namespace': namespace, 'edit_policy_sql': edit_policy, 'field_policy_effects': effects,
                  'row_snapshot_sql': _fingerprint(bag['items'], 'b'),
                  'draft_strategy': 'reconcile_clean_same_row_route_and_revision_deny_conflicting_drafts_retain_siblings',
                  'converted_code_unit_count': 0, 'customer_table_writes': False,
                  'oracle_compiled': False, 'runtime_verified': False, 'business_accepted': False}
            op['operation_sha256'] = _sha(op)
            result['operations'].append(op)
        except (ValueError, LookupError, TypeError) as exc:
            result['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError)
                                   else 'NUMERIC_CORRECTION_PROVIDER_UNAVAILABLE'})
    return result


def render_numeric_correction_sql(op, page):
    """Trusted plan only. Return exact independently executable SQL boundaries."""
    _need(type(page) is int and 1 <= page < 9000, 'PAGE')
    _need(op.get('operation_sha256') == _sha({k: v for k, v in op.items() if k != 'operation_sha256'}), 'PLAN_CHANGED')
    c, w, rules = op['contract'], op['write_contract'], op['rules']
    head, bag = (c['blocks'][r]['table_name'] for r in ('header', 'bag'))
    f = c['fields']
    key, parent_key, number, weight = (f[r]['column'] for r in ('header_key', 'bag_header_key', 'bag_number', 'weight'))
    route, parent_route = w['route']['column'], w['parent_route']['column']
    prefix = f'P{page}_'
    where = op['approval_where_sql'].replace(f'P{op["approval_page_id"]}_', prefix)
    # Policy fields are unqualified generated column names. Scope policy in a
    # parent-only subquery to avoid accidental same-name child resolution.
    selected = (f'select p.* from {head} p where {where} and p.{key} is not null '
                f'and (select count(*) from {head} s where s.{key}=p.{key})=1 '
                f'and nvl(({c["permission_sql"]}),0)=1 and nvl(({op["edit_policy_sql"]}),0)=1')
    context = (f'select b.FOX_ROW_ID,p.FOX_ROW_ID as FOX_PARENT_ID,b.{number},'
               f'b.{weight},p.{parent_route} as CURRENT_ROUTE,'
               f'{op["row_snapshot_sql"]} as ROW_SNAPSHOT from {bag} b,({selected}) p '
               f'where b.{parent_key}=p.{key} and nvl(b.{weight},0)=0')
    namespace = op['draft_namespace']
    canonical = f"'{namespace}' || to_char(p.FOX_ROW_ID,'TM9')"
    for _, column in native_buffer._parent_copies(op['buffer']):
        canonical += " || '_' || substr(rawtohex(standard_hash(p." + column + ",'SHA256')),1,32)"
    draft_prefix = f"substr(d.collection_name,1,{len(namespace)})='{namespace}'"
    clean = [f'd.collection_name=({canonical})', "d.c041='SYNTHETIC_SAVE_BASELINE_V1'",
             f"exists (select 1 from apex_collections m where m.collection_name=d.collection_name and m.seq_id=1 and m.c050='META' and m.c049='{_sha(op['buffer'])}' and m.n001=p.FOX_ROW_ID and m.n003>=0 and m.n003<999999999999999 and floor(m.n003)=m.n003 and exists (select 1 from apex_collections active where active.collection_name=m.collection_name and active.seq_id=m.n002 and active.c050='ROW'))",
             native_buffer._parent_match('b.' + route, 'd.c040')]
    for i, field in enumerate(w['fields'], 1):
        clean.extend([native_buffer._parent_match(f'd.c{i:03}', f'd.c{20+i:03}'),
                      native_buffer._parent_match('b.' + field['column'], f'd.c{20+i:03}')])
    if op['item_layout']:
        clean.extend([native_buffer._parent_match('d.c044', 'd.c040'), 'decode(d.n002,d.n003,1,0)=1',
                      'd.c043 is null', 'decode(b.' + op['item_layout']['fields']['weight']['column'] + ',d.n003,1,0)=1'])
    conflict = (f"exists (select 1 from apex_collections d where {draft_prefix} and d.c050='ROW' "
                + 'and d.n001=b.FOX_ROW_ID and case when ' + ' and '.join(clean) + ' then 1 else 0 end=0)')
    # Use the exact existing Save duplicate expression: concatenation collision
    # behavior is preserved rather than silently inventing a new business key.
    key_expr = ' || '.join('b.' + field['column'] for field in w['fields'])
    duplicate = w['duplicate_key_sql'].replace('l_key', '(' + key_expr + ')')
    membership = ' and '.join('c.' + pair['child_column'] + '=p.' + pair['parent_column']
                              for pair in op['buffer']['relation']['join_pairs'])
    duplicate = (f'exists (select 1 from {bag} c where c.FOX_ROW_ID<>b.FOX_ROW_ID and '
                 + membership + ' and ' + duplicate + ')')
    draft_key = ' || '.join(f'd.c{i:03}' for i in range(1, len(w['fields']) + 1))
    draft_duplicate = (f'exists (select 1 from apex_collections d where d.collection_name=({canonical}) '
                       + "and d.c050='ROW' and (d.n001 is null or d.n001<>b.FOX_ROW_ID) and "
                       + f'(cast(({draft_key}) as varchar2(4000)) collate binary)=(cast(({key_expr}) as varchar2(4000)) collate binary))')
    # Require every inherited/key component: no null concatenation ambiguities.
    present = ' and '.join('b.' + field['column'] + ' is not null' for field in w['fields'])
    eligibility = f'not {conflict} and not {duplicate} and not {draft_duplicate} and {present}'
    chooser = (f'select q.FOX_ROW_ID,q.FOX_PARENT_ID,q.{number},q.{weight},'
               f"case when q.CAN_EDIT=1 then 'Choose this saved bag' else 'Finish or discard the draft for this bag, or resolve its duplicate key, then recheck.' end as CORRECTION_STATUS,"
               f'q.CAN_EDIT from (select b.FOX_ROW_ID,p.FOX_ROW_ID as FOX_PARENT_ID,b.{number},'
               f'b.{weight},case when {eligibility} then 1 else 0 end as CAN_EDIT '
               f'from {bag} b,({selected}) p where b.{parent_key}=p.{key} and nvl(b.{weight},0)=0) q')
    row = context + f' and b.FOX_ROW_ID=:{prefix}ROW_ID'
    eligible = (f'select b.FOX_ROW_ID from {bag} b,({selected}) p where '
                f'b.FOX_ROW_ID=:{prefix}ROW_ID and b.{parent_key}=p.{key} '
                f'and nvl(b.{weight},0)=0 and {eligibility}')
    # All table locks serialize predicate/duplicate checks with the existing
    # synthetic Save. NOWAIT failures never retry or discard a session draft.
    locks = f'lock table {head} in share row exclusive mode nowait;\nlock table {bag} in share row exclusive mode nowait;'
    collection = 'FOX_N_' + _sha([SCOPE, op['operation_id'], page])[:20].upper() + '_'
    declarations = f'''l_name varchar2(255):='{collection}';
l_count number; l_parent number; l_id number; l_base varchar2(64); l_marker varchar2(64);
l_now varchar2(64); l_route varchar2(4000); l_old number; l_value number; l_text varchar2(4000);
l_error number;'''
    check_row = (f'select FOX_PARENT_ID,FOX_ROW_ID,ROW_SNAPSHOT,CURRENT_ROUTE,{weight} into '
                 f'l_parent,l_id,l_now,l_route,l_old from ({row});\n'
                 f'select count(*) into l_count from ({eligible});\n'
                 "if l_count<>1 then raise_application_error(-20061,'Finish or discard the existing draft for this bag, or resolve its duplicate key, then recheck. All drafts are retained.'); end if;")
    route_checks = ' or '.join(f"nvl({'lengthb' if r['source_length_semantics']=='BYTE' else 'length'}(l_route),0)>{r['max_length']}"
                               for r in (w['route'], w['parent_route']))
    required_route = any(r['required'] for r in (w['route'], w['parent_route']))
    route_checks += ' or l_route is null' if required_route else ''
    pattern = '^(0|[1-9][0-9]{0,' + str(rules['integer_digits'] - 1) + '})'
    if rules['scale']:
        pattern += '([.][0-9]{1,' + str(rules['scale']) + '})?'
    pattern += '$'
    model = '9' * rules['integer_digits'] + ('D' + '9' * rules['scale'] if rules['scale'] else '')
    numeric_check = f"""l_text:=:{prefix}VALUE;
if l_text is null or length(l_text)>{rules['max_length']} or regexp_like(l_text,'[^0-9.]','c') or not regexp_like(l_text,'{pattern}','c') then
raise_application_error(-20062,'Enter actual weight in plain decimal notation within the source format.'); end if;
l_value:=to_number(l_text,'{model}','NLS_NUMERIC_CHARACTERS=''.,''');
if l_value=0 or l_value<{rules['minimum']}{' or l_value>'+rules['maximum'] if rules['maximum'] else ''} then
raise_application_error(-20062,'Actual weight is outside the source minimum or maximum.'); end if;"""
    update = (f'update {bag} set {weight}=l_value,{route}=l_route where FOX_ROW_ID=l_id '
              f'and nvl({weight},0)=0;')
    failure = f'''l_error:=sqlcode;
rollback to fox_numeric_save;
:{prefix}STATE:=case when l_error=-20062 then 'READY' else 'BLOCKED' end;
:{prefix}MESSAGE:=case when l_error=-54 then 'Saved records are busy. Input and drafts are retained; recheck before trying again.'
when l_error=-20062 then 'Enter a nonzero actual weight within the source minimum, length and decimal format.'
when l_error=-20061 then 'Finish or discard the draft for this bag, or resolve its duplicate key, then recheck. Drafts are retained.'
else 'The selection changed, permission was revoked, or this correction expired or was replaced. Reopen from readiness. Input and drafts are retained.' end;
apex_error.add_error(p_message=>:{prefix}MESSAGE,p_display_location=>apex_error.c_inline_in_notification);'''
    open_code = f"""declare
{declarations}
begin
savepoint fox_numeric_open;
:{prefix}STATE:='BLOCKED'; :{prefix}MESSAGE:=null; :{prefix}MARKER:=null; :{prefix}NONCE:=null; :{prefix}VALUE:=null;
if :REQUEST is not null then return; end if;
{check_row}
l_marker:=rawtohex(sys_guid());
for expired in (select collection_name from apex_collections where substr(collection_name,1,{len(collection)})='{collection}' and seq_id=1 and (d001 is null or d001<=sysdate or c004='USED')) loop
apex_collection.delete_collection(expired.collection_name);
end loop;
select count(*) into l_count from apex_collections where substr(collection_name,1,{len(collection)})='{collection}' and seq_id=1 and c004='OPEN';
if l_count>=64 then
for oldest in (select collection_name from (select collection_name from apex_collections where substr(collection_name,1,{len(collection)})='{collection}' and seq_id=1 order by d001,collection_name) where rownum<=l_count-63) loop
apex_collection.delete_collection(oldest.collection_name);
end loop;
end if;
l_name:=l_name||l_marker;
apex_collection.create_collection(l_name);
apex_collection.add_member(p_collection_name=>l_name,p_c001=>l_marker,p_c002=>l_now,
p_c003=>:{prefix}TOKEN,p_c004=>'OPEN',p_n001=>l_parent,p_n002=>l_id,p_d001=>sysdate+30/1440);
:{prefix}MARKER:=l_marker; :{prefix}NONCE:=l_marker; :{prefix}STATE:='READY';
:{prefix}VALUE:=to_char(l_old,'TM9','NLS_NUMERIC_CHARACTERS=''.,''');
exception when others then
rollback to fox_numeric_open;
:{prefix}STATE:='BLOCKED';
:{prefix}MESSAGE:='This saved bag is unavailable, read only, ambiguous or has a conflicting draft. Return to readiness and resolve the conflict. All drafts are retained.';
end;"""
    save_code = f'''declare
{declarations}
begin
savepoint fox_numeric_save;
:{prefix}STATE:='BLOCKED'; :{prefix}MESSAGE:=null;
if :REQUEST is null or :REQUEST<>'{REQUEST}' then raise_application_error(-20060,'Unknown correction action.'); end if;
if :{prefix}NONCE is null or length(:{prefix}NONCE)<>32 or regexp_like(:{prefix}NONCE,'[^0-9A-F]','c') then
raise_application_error(-20060,'Missing correction marker.'); end if;
l_name:=l_name||:{prefix}NONCE;
{locks}
select FOX_ROW_ID into l_count from {head} where FOX_ROW_ID=:{prefix}PARENT_ID for update nowait;
select FOX_ROW_ID into l_count from {bag} where FOX_ROW_ID=:{prefix}ROW_ID for update nowait;
select c001,c002,n001,n002 into l_marker,l_base,l_parent,l_id from apex_collections
where collection_name=l_name and seq_id=1 and c004='OPEN' and c003=:{prefix}TOKEN and d001>sysdate;
if l_marker is null or l_parent is null or l_id is null or l_base is null or l_marker<>:{prefix}NONCE
or :{prefix}PARENT_ID is null or :{prefix}ROW_ID is null or l_parent<>:{prefix}PARENT_ID or l_id<>:{prefix}ROW_ID then
raise_application_error(-20060,'Correction identity changed.'); end if;
{check_row}
if l_now is null or l_now<>l_base then raise_application_error(-20060,'Saved bag changed.'); end if;
{numeric_check}
if l_old is null or l_old<>l_value then
if {route_checks} then raise_application_error(-20060,'Current parent route violates the source copy constraint.'); end if;
{update}
if sql%rowcount<>1 then raise_application_error(-20060,'Saved bag changed.'); end if;
for r in (select d.collection_name,d.seq_id from apex_collections d where {draft_prefix} and d.c050='ROW' and d.n001=l_id) loop
apex_collection.update_member_attribute(p_collection_name=>r.collection_name,p_seq=>r.seq_id,p_attr_number=>40,p_attr_value=>l_route);
{'apex_collection.update_member_attribute(p_collection_name=>r.collection_name,p_seq=>r.seq_id,p_attr_number=>44,p_attr_value=>l_route);' if op['item_layout'] else ''}
end loop;
for m in (select distinct d.collection_name from apex_collections d where {draft_prefix} and d.c050='ROW' and d.n001=l_id) loop
select n003 into l_count from apex_collections where collection_name=m.collection_name and seq_id=1;
apex_collection.update_member_attribute(p_collection_name=>m.collection_name,p_seq=>1,p_attr_number=>3,p_number_value=>l_count+1);
end loop;
:{prefix}STATE:='SAVED';
else :{prefix}STATE:='UNCHANGED'; end if;
apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>4,p_attr_value=>'USED');
apex_collection.delete_collection(l_name);
:{prefix}MARKER:=null; :{prefix}NONCE:=null;
:{prefix}MESSAGE:='Actual weight saved. Recheck readiness; approval and external actions remain pending.';
exception when others then
{failure}
end;'''
    _need(max(len(x.encode()) for x in (chooser, row, open_code, save_code)) <= 32767, 'CODE_CAPACITY')
    return {'chooser_query_sql': chooser, 'context_query_sql': row,
            'eligible_query_sql': eligible, 'selected_parent_query_sql': selected,
            'update_sql': update, 'open_code': open_code, 'save_code': save_code,
            'collection_name': collection, 'draft_conflict_sql': conflict,
            'duplicate_predicate_sql': duplicate, 'draft_duplicate_predicate_sql': draft_duplicate,
            'draft_clean_sql': ' and '.join(clean), 'numeric_validation_sql': numeric_check}
