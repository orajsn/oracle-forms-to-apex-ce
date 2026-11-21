"""Read-only native approval readiness over source-bound saved synthetic rows.

This adapter never crosses a source transaction boundary. Later checks are
explicit saved-state diagnostics, not evidence that a Forms COMMIT succeeded.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_buffer
from .forms_behavior_plan import _source_objects
from .forms_draft_policy import _expression
from .forms_policy_plan import build_policy_plan
from .forms_master_detail import _fingerprint, _report

SCOPE = 'fox-source-approval-readiness-v1'


def _need(value, reason):
    if not value:
        raise ValueError('APPROVAL_ACTION_' + reason)


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _literal(value):
    _need(type(value) is str and len(value) <= 4000 and not any(c in value for c in '&`')
          and all(c.isprintable() for c in value), 'LITERAL_CONTEXT')
    return "'" + value.replace("'", "''") + "'"


def _messages(values, suffix=None):
    return ' || chr(10) || '.join(_literal(v) + (' || ' + suffix if suffix else '') for v in values)


def _permission(header, button, objects, props, policy):
    """Project complete module entry policy onto the selected button's ENABLED.

    Local calls are already expanded by the deterministic policy compiler.
    Missing complete entry policy or non-stored policy inputs fail closed.
    """
    static = props[button['id']].get('Enabled', '').lower()
    _need(static in ('', 'true', 'false'), 'STATIC_BUTTON_PERMISSION')
    events = [o for o in objects.values() if o['kind'] == 'Trigger'
              and o['module_id'] == button['module_id']
              and (o['name'] or '').upper() == 'WHEN-NEW-RECORD-INSTANCE'
              and o['parent_id'] in (button['module_id'], header['source_block_id'], button['id'])]
    _need(not any(o['parent_id'] != button['module_id'] for o in events), 'ENTRY_POLICY_OVERRIDE')
    if not events:
        _need(static in ('true', 'false'), 'EXPLICIT_BUTTON_PERMISSION_REQUIRED')
        return '1' if static == 'true' else '0', []
    event = _one(events, 'UNIQUE_ENTRY_POLICY')
    op = _one([o for o in policy['operations'] if o['source_owner_id'] == event['id']],
              'COMPLETE_ENTRY_POLICY_REQUIRED')
    for key, field in op['fields'].items():
        target = _one([f for f in header['items'] if f['source_item_id'] == key], 'POLICY_FIELD')
        _need(field['binding_kind'] == 'source_item' and field['source_database_item'] is True
              and field['source_block_id'] == header['source_block_id']
              and field['column'] == target['column'] and field['data_type'] == target['data_type'],
              'STORED_POLICY_FIELD_REQUIRED')
    state = '0' if static == 'false' else '1' if static == 'true' else 'NULL'
    effects = []

    def walk(nodes, inherited=None):
        nonlocal state
        for node in nodes:
            if node['kind'] == 'local_call':
                walk(node['body'], inherited)
            elif node['kind'] == 'if':
                condition = _expression(node['condition'], op['fields'])
                walk(node['body'], condition if inherited is None else '(' + inherited + ' AND ' + condition + ')')
            elif node['kind'] == 'property':
                if node['target_id'] == button['id'] and node['property'] == 'ENABLED':
                    value = '1' if node['value'] else '0'
                    state = value if inherited is None else f'CASE WHEN {inherited} THEN {value} ELSE {state} END'
                    effects.append(deepcopy(node))
            else:
                raise ValueError('APPROVAL_ACTION_COMPLETE_PROPERTY_POLICY_REQUIRED')
    walk(op['body'])
    _need(state != 'NULL', 'BUTTON_PERMISSION_UNRESOLVED')
    return state, [{'source_unit_id': op['source_unit_id'], 'source_unit_sha256': op['source_unit_sha256'],
                    'effects': effects}]


def _queries(c, page, where):
    """Exact source predicates mapped only to declared synthetic columns.

    ROWNUM has no ordering in the source. The reported matching bag is one
    arbitrary qualifying bag, not a promise of deterministic cursor order.
    """
    f = c['fields']
    head, bag, note = (c['blocks'][r]['table_name'] for r in ('header', 'bag', 'consignment'))
    key, destination = (f[r]['column'] for r in ('header_key', 'destination'))
    bag_key, bag_no, weight = (f[r]['column'] for r in ('bag_header_key', 'bag_number', 'weight'))
    note_key, note_bag = (f[r]['column'] for r in ('consignment_header_key', 'consignment_bag_number'))
    member = f'b.{bag_key}=p.{key}'
    weight_predicate = f'{member} and nvl(b.{weight},0)=0'
    missing = (f'{member} and not exists (select 1 from {note} n where '
               f'n.{note_bag}=b.{bag_no} and n.{note_key}=b.{bag_key})')
    selected = f'select p.* from {head} p where {where}'
    # Unique non-null business identity is required independently of FOX_ROW_ID.
    eligible = (selected + f' and p.{key} is not null and (select count(*) from {head} same_key '
                f'where same_key.{key}=p.{key})=1')
    permission = c['permission_sql']
    initial = f'nvl(({permission}),0)=1'
    later = initial + f' and p.{destination} is not null and not exists (select 1 from {bag} b where {weight_predicate})'
    facts = (f'select p.FOX_ROW_ID,p.{key} as SELECTED_MANIFEST,p.{destination} as SAVED_DESTINATION,'
             f'({permission}) as SOURCE_ALLOWED,\n'
             f'case when {initial} then (select count(*) from {bag} b where {weight_predicate}) end as ZERO_WEIGHT_COUNT,\n'
             f'case when {initial} then (select b.{bag_no} from {bag} b where {weight_predicate} and rownum=1) end as WEIGHT_BAG,\n'
             f'case when {later} then (select count(*) from {bag} b where {member}) end as BAG_COUNT,\n'
             f'case when {later} then (select b.{bag_no} from {bag} b where {missing} and rownum=1) end as EMPTY_BAG\n'
             f'from ({eligible}) p')
    stage = ("case when nvl(SOURCE_ALLOWED,0)<>1 then 'POLICY_READ_ONLY' "
             "when ZERO_WEIGHT_COUNT>0 then 'BLOCKED_WEIGHT' "
             "when SAVED_DESTINATION is null then 'BLOCKED_DESTINATION' "
             "when BAG_COUNT=0 then 'SAVED_CHECK_NO_BAGS' "
             "when EMPTY_BAG is not null then 'SAVED_CHECK_EMPTY_BAG' "
             "else 'PENDING_TRANSACTION_AND_INTERFACES' end")
    staged = f'select f.*, {stage} as READINESS_STAGE from ({facts}) f'
    messages = c['messages']
    message = ("case READINESS_STAGE when 'BLOCKED_WEIGHT' then " + _messages(messages['weight'])
               + " when 'BLOCKED_DESTINATION' then " + _messages(messages['destination'])
               + " when 'SAVED_CHECK_NO_BAGS' then " + _messages(messages['no_bags'])
               + " when 'SAVED_CHECK_EMPTY_BAG' then " + _messages(messages['missing_consignment'], 'EMPTY_BAG')
               + " else null end")
    field = ("case READINESS_STAGE when 'BLOCKED_WEIGHT' then " + _literal(f['weight']['source_name'])
             + " when 'BLOCKED_DESTINATION' then " + _literal(f['destination']['source_name'])
             + " when 'SAVED_CHECK_NO_BAGS' then " + _literal(f['bag_number']['source_name'])
             + " when 'SAVED_CHECK_EMPTY_BAG' then " + _literal(f['consignment_bag_number']['source_name'])
             + ' else null end')
    action = ("case READINESS_STAGE when 'POLICY_READ_ONLY' then 'The current source button policy denies approval. View the selected manifest.' "
              "when 'BLOCKED_WEIGHT' then 'The blocking bag needs a saved actual weight. Use a verified input and save path for the indicated weight field, then recheck readiness.' "
              "when 'BLOCKED_DESTINATION' then 'Supply the destination through a verified input provider, then recheck.' "
              "when 'SAVED_CHECK_NO_BAGS' then 'No saved bags. Add and save a bag; this diagnostic is after an unexecuted source commit.' "
              "when 'SAVED_CHECK_EMPTY_BAG' then 'Supply a consignment for this bag using a verified provider; this diagnostic is after an unexecuted source commit.' "
              "else 'Saved internal checks passed. Whole-form dirty state, source commit segments, approval write and external interfaces still need verified providers.' end")
    query = (f'select FOX_ROW_ID,SELECTED_MANIFEST,READINESS_STAGE,coalesce(WEIGHT_BAG,EMPTY_BAG) as BLOCKING_BAG,'
             f'{field} as BLOCKING_FIELD,{message} as SOURCE_MESSAGES,{action} as REQUIRED_ACTION,\n'
             "'No approval was written. Later checks are saved-state diagnostics; source commits, cursor traversal and external outcomes remain pending.' as TRANSACTION_STATUS\n"
             f'from ({staged}) staged')
    return {'readiness_query_sql': query, 'selected_context_sql': eligible,
            'weight_predicate_sql': weight_predicate, 'missing_consignment_predicate_sql': missing}


def _hidden(page, name):
    return f'''    pageItem P{page}_{name} (
        type: hidden
        layout {{ sequence: 10
            region: @approval-scope
            slot: regionBody }}
        sessionState {{ storage: session
            dataType: {'number' if name == 'PARENT_ID' else 'varchar2'} }}
        security {{ sessionStateProtection: checksumRequiredSessionLevel }}
    )
'''


def _shell(page, body):
    return native_buffer._expand_groups(f'''page {page} (
    name: Approval readiness
    alias: FOX_APPROVAL_{page}
    title: Approval readiness
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT# }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum }}
    region approval-scope (
        name: Read-only approval readiness
        type: staticContent
        source {{ htmlCode: "<p>Review the selected manifest and the blocking bag or field. Results use saved synthetic rows. Your session drafts are retained. This action does not save or approve the manifest. No result row means the selected identity is missing, stale, null or ambiguous; return and select it again.</p>" }}
        layout {{ sequence: 5
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
{body})
''').encode()


def _result(page, query):
    names = ['SELECTED_MANIFEST', 'READINESS_STAGE', 'BLOCKING_BAG', 'BLOCKING_FIELD',
             'SOURCE_MESSAGES', 'REQUIRED_ACTION', 'TRANSACTION_STATUS']
    fields = [{'column': n, 'source_name': n.replace('_', ' ').capitalize(), 'data_type': 'VARCHAR2'} for n in names]
    return _shell(page, _report('approval-readiness', 'Selected manifest readiness', query, fields)
                  + _hidden(page, 'PARENT_ID') + _hidden(page, 'TOKEN'))


def _entry(page, source_page=None, condition_sql=None):
    items = '' if source_page is None else f'''                items: {{ P{page}_PARENT_ID: "&P{source_page}_PARENT_ID."
                    P{page}_TOKEN: "&P{source_page}_TOKEN." }}
'''
    gate = '' if condition_sql is None else f'''        serverSideCondition {{ type: rowsReturned
            sqlQuery:
                ```sql
{native_buffer._indent(condition_sql)}
                ```
        }}
'''
    return native_buffer._expand_groups(f'''    button approval-readiness-{page} (
        buttonName: FOX_APPROVAL_READINESS_{page}
        label: Check approval readiness
        layout {{ sequence: 8500
            region: @{'coordination-scope' if source_page else 'records'}
            slot: {'regionBody' if source_page else 'rightOfInteractiveReportSearchBar'} }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {page}
                clearCache: {page}
{items}            }} }}
{gate}    )
''')


def _contract(op, objects, props, policy):
    original = op['contract']
    aliases = {'header_key': 'header_key', 'destination': 'destination',
               'bag_header_key': 'bag_parent', 'bag_number': 'bag_key', 'weight': 'bag_weight',
               'consignment_header_key': 'consignment_parent', 'consignment_bag_number': 'consignment_key'}
    c = {'blocks': deepcopy(original['blocks']),
         'fields': {role: deepcopy(original['fields'][key]) for role, key in aliases.items()},
         'messages': deepcopy(op['parsed']['messages'])}
    button = objects[op['button_item_id']]
    c['permission_sql'], c['permission_proof'] = _permission(c['blocks']['header'], button, objects, props, policy)
    return c


def _coordinator(documents, packet, chunks, trace, files, c, objects, props):
    """Rebind coordinator predicates from source; never execute receipt SQL."""
    from .forms_master_detail import _bind, _parent_where, parse_population
    population = json.loads(files.get('fox-package/master-detail-receipt.json', b'{"adapted_operations":[]}'))
    matches = [o for o in population['adapted_operations']
               if o['parent_block_id'] == c['blocks']['header']['source_block_id']]
    if not matches:
        return None
    _need(population['source_binding'] == packet['source_binding'], 'COORDINATOR_SOURCE')
    op = _one(matches, 'UNIQUE_COORDINATOR')
    unit = _one([u for s in packet['sources'] for u in s['facts']['code_units']
                 if u['id'] == op['source_unit_id']], 'COORDINATOR_UNIT')
    owner = objects[unit['owner_id']]
    chunk = _one([r for r in chunks if r['code_unit_id'] == unit['id']], 'COORDINATOR_CHUNK')
    parsed = parse_population(chunk['text'])
    bound = _bind(owner, parsed, objects, props, trace, files)
    _need((owner['name'] or '').upper() == 'ON-POPULATE-DETAILS'
          and owner['id'] == op['source_owner_id']
          and owner['module_id'] == c['blocks']['header']['source_module_id']
          and bound['parent']['source_block_id'] == c['blocks']['header']['source_block_id']
          and bound['child']['source_block_id'] == c['blocks']['bag']['source_block_id']
          and op['source_unit_sha256'] == unit['sha256'] and op['snapshot_fields'] == bound['snapshot_fields']
          and op['parent_item'] == f"P{op['page_id']}_PARENT_ID"
          and op['token_item'] == f"P{op['page_id']}_TOKEN"
          and op['state_item'] == f"P{op['page_id']}_STATE", 'COORDINATOR_BINDING')
    text = files[op['page_file']].decode()
    _need(text.startswith(f"page {op['page_id']} (\n") and text.endswith(')\n')
          and 'pageAccessProtection: argumentsMustHaveChecksum' in text
          and text.count('sessionStateProtection: checksumRequiredSessionLevel') >= 2,
          'PROTECTED_COORDINATOR_REQUIRED')
    return op, bound, _parent_where


def _chooser(c, page, result):
    header = c['blocks']['header']
    fields = header['items']
    query = ('select p.FOX_ROW_ID,' + ','.join('p.' + f['column'] for f in fields)
             + ',' + _fingerprint(fields) + ' as FOX_MASTER_TOKEN from ' + header['table_name'] + ' p'
             + ' where nvl((' + c['permission_sql'] + '),0)=1')
    body = _report('records', 'Select manifest for approval readiness', query, fields, link=result)
    # The shared chooser's signed target names PARENT_ID/TOKEN match our result.
    body = body.replace('linkText: Select master', 'linkText: Check approval readiness')
    where = f'p.FOX_ROW_ID=:P{result}_PARENT_ID and ({_fingerprint(fields)})=:P{result}_TOKEN'
    return _shell(page, body), where


def apply_approval_actions(documents, packet, chunks, trace, files):
    """Wire the source button's bounded saved-row checks, never its approval.

    The complete source model and all pending source stages remain packaged for
    review. The source event stays partially connected and counts as zero whole
    converted units even when every saved-row diagnostic passes.
    """
    from .forms_approval_plan import build_approval_plan
    plan = build_approval_plan(documents, packet, chunks, trace, files)
    output = dict(files)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': packet['source_binding'],
               'generated_operations': [], 'adapted_operations': [], 'gaps': deepcopy(plan['gaps']),
               'converted_code_unit_count': 0, 'customer_table_writes': False,
               'synthetic_table_writes': False, 'original_reads_enabled': False,
               'external_calls_enabled': False, 'forms_commit_implemented': False,
               'oracle_compiled': False, 'runtime_verified': False, 'business_accepted': False}
    objects, props = _source_objects(documents, packet)
    policy = build_policy_plan(documents, trace)
    _need(not any(re.fullmatch(r'pages/p\d+-fox_approval_\d+\.apx', n) for n in files), 'ALREADY_ADAPTED')
    occupied = {int(m[1]) for n in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', n))}
    page = 8600

    def allocate():
        nonlocal page
        while page in occupied:
            page += 1
        _need(page < 9000, 'PAGE_CAPACITY')
        occupied.add(page)
        return page

    for op in plan['operations']:
        identity = {k: op[k] for k in ('source_unit_id', 'source_unit_sha256', 'source_owner_id', 'source_module_id')}
        try:
            c = _contract(op, objects, props, policy)
            result_page = allocate()
            coordinator = _coordinator(documents, packet, chunks, trace, output, c, objects, props)
            changes = {}
            if coordinator:
                selected, bound, where_fn = coordinator
                where = where_fn(bound, result_page)
                source_page = selected['page_id']
                entry_file = selected['page_file']
                # STATE is request-local restricted output of the earlier
                # coordinator. The result independently rechecks all predicates.
                selected_context = _queries(c, source_page, where_fn(bound, source_page))['selected_context_sql']
                button_query = (f'select 1 from ({selected_context}) p where nvl(({c["permission_sql"]}),0)=1'
                                + f" and :P{source_page}_STATE='COORDINATED'")
                _need(len(button_query.encode()) <= 4000, 'BUTTON_CONDITION_CAPACITY')
                button = _entry(result_page, source_page, button_query)
                entry_kind = 'current_coordinated_manifest_no_reselection'
            else:
                chooser_page = allocate()
                chooser, where = _chooser(c, chooser_page, result_page)
                changes[f'pages/p{chooser_page:05d}-fox_approval_{chooser_page}.apx'] = chooser
                entry_file = c['blocks']['header']['report_file']
                button = _entry(chooser_page)
                entry_kind = 'protected_header_report_chooser'
            queries = _queries(c, result_page, where)
            _need(len(queries['readiness_query_sql'].encode()) <= 32767, 'QUERY_CAPACITY')
            result_file = f'pages/p{result_page:05d}-fox_approval_{result_page}.apx'
            changes[result_file] = _result(result_page, queries['readiness_query_sql'])
            text = output[entry_file].decode()
            _need(text.endswith(')\n') and 'button approval-readiness-' not in text, 'ENTRY_ANCHOR')
            changes[entry_file] = (text[:-2] + button + ')\n').encode()
            active_sql = re.sub(r"'(?:''|[^'])*'", ' ', queries['readiness_query_sql'])
            _need(not re.search(r'\b(?:insert|update|delete|commit|rollback|apex_web_service|apex_collection)\b',
                                active_sql, re.I), 'READ_ONLY_RESULT_REQUIRED')
            output.update(changes)
            adapted = {**identity, 'operation_id': 'faa1-' + hashlib.sha256(_json([packet['source_binding'], op['source_unit_id']])).hexdigest()[:24],
                       'button_item_id': op['button_item_id'], 'kind': 'source_approval_saved_readiness',
                       'generation_status': 'partial_effects_wired', 'native_event_wired': True,
                       'page_id': result_page, 'page_file': result_file, 'entry_file': entry_file,
                       'entry_kind': entry_kind, 'contract': c, **queries,
                       'stage_order': ['weight', 'destination', 'post_commit_saved_bag_count',
                                       'post_commit_saved_missing_consignment', 'pending_transaction_and_interfaces'],
                       'source_transaction_stages': deepcopy(op['stages']),
                       'pending_provider_requirements': ['whole_form_dirty_state_and_current_buffer',
                           'cursor_and_form_success_outcomes', 'dirty_commit_if_changed',
                           'route_copy_and_separate_route_commit', 'approval_write_and_separate_approval_commit',
                           'verified_external_call_contracts_and_outcomes', 'final_policy_after_effects'],
                       'source_event_partially_connected': True, 'whole_source_unit_converted': False,
                       'preview_scope': 'fresh_saved_synthetic_rows_not_customer_state_or_live_forms_buffer',
                       'later_checks': 'diagnostics_after_unexecuted_source_commit_not_source_execution',
                       'session_drafts_mutated': False, 'approval_flag_written': False,
                       'runtime_verified': False, 'business_accepted': False}
            receipt['adapted_operations'].append(adapted)
            receipt['gaps'].append({**identity, 'reason': 'APPROVAL_TRANSACTION_AND_EXTERNAL_PROVIDERS_PENDING',
                'next_action': 'Bind complete whole-form state, commit segments and exact external interfaces before enabling approval.'})
        except (ValueError, KeyError, TypeError) as exc:
            receipt['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError)
                                   else 'APPROVAL_ACTION_BOUND_PROVIDER_UNAVAILABLE'})
    output['fox-package/approval-plan.json'] = _json(plan)
    receipt['receipt_sha256'] = hashlib.sha256(_json(receipt)).hexdigest()
    return output, receipt
