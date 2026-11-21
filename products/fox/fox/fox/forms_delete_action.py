"""Read-only, source-bound delete preflight on current saved synthetic rows.

No provider is installed here. A trusted server adapter may publish one exact,
short-lived permission result in the documented APEX collection. Browser items
carry identity only; they never carry permission or an authorization decision.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_buffer
from .forms_behavior_plan import _source_objects
from .forms_draft_policy import _expression
from .forms_master_detail import _fingerprint, _report
from .forms_policy_plan import build_policy_plan
from .forms_record_entry import _block

SCOPE = 'fox-source-delete-preflight-v1'
COLLECTION = 'FOX_DELETE_GATE_V1'


def _need(value, reason):
    if not value:
        raise ValueError('DELETE_ACTION_' + reason)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def _lit(value):
    _need(type(value) is str and len(value) <= 4000 and '`' not in value and '&' not in value
          and all(c.isprintable() for c in value), 'LITERAL_CONTEXT')
    return "'" + value.replace("'", "''") + "'"


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


def _context(block, relations, blocks):
    """Recheck a unique incoming chain and expose no inferred first ancestor."""
    current = block
    path, joins, seen = [(block, 'p')], [], {block['source_block_id']}
    while True:
        incoming = [r for r in relations if r['child_block_id'] == current['source_block_id']]
        if not incoming:
            break
        edge = _one(incoming, 'AMBIGUOUS_INCOMING_RELATION')
        parent = blocks[edge['parent_block_id']]
        _need(parent['source_block_id'] not in seen and len(path) < 8, 'RELATION_CYCLE')
        seen.add(parent['source_block_id'])
        alias, child_alias = 'a' + str(len(path)), path[-1][1]
        joins.extend(f"{alias}.{p['parent_column']}={child_alias}.{p['child_column']}" for p in edge['join_pairs'])
        path.append((parent, alias))
        current = parent
    source = ','.join(b['table_name'] + ' ' + a for b, a in path)
    predicate = ' and '.join(joins) or '1=1'
    # Every ancestor tuple must identify exactly one parent row. Duplicate
    # business identities are ambiguous even when the child FOX_ROW_ID is unique.
    uniqueness = []
    for parent, alias in path[1:]:
        edge = _one([r for r in relations if r['parent_block_id'] == parent['source_block_id']
                     and r['child_block_id'] in seen], 'AMBIGUOUS_ANCESTOR_PATH')
        match = ' and '.join('same_parent.' + p['parent_column'] + '=' + alias + '.' + p['parent_column']
                             for p in edge['join_pairs'])
        uniqueness.append(f"(select count(*) from {parent['table_name']} same_parent where {match})=1")
    if uniqueness:
        predicate += ' and ' + ' and '.join(uniqueness)
    frames = [_fingerprint(b['items'], alias=a) for b, a in path]
    token = frames[0] if len(frames) == 1 else "rawtohex(standard_hash(" + " || ':' || ".join(frames) + ",'SHA256'))"
    return path, source, predicate, token


def _permission(op, policy, path, *, projection_only=False):
    """Project complete entry-policy setters in source order, or stay unknown."""
    block_id = op['contract']['block']['source_block_id']
    proof = op['contract']['delete_policy']
    static = proof['static_value']
    state = '1' if static is True else '0' if static is False else 'NULL'
    dynamic = proof.get('dynamic_setters', [])
    if not dynamic:
        return state, []
    fields = {f['source_item_id']: {**f, 'column': a + '.' + f['column']}
              for b, a in path for f in b['items']}
    # The policy compiler may omit an event label; complete module/block entry
    # events are selected by the fresh source catalog instead.
    catalog = {o['id']: o for o in policy['source_catalog']['objects']}
    candidates = [p for p in policy['operations'] if catalog[p['source_owner_id']]['name'].upper() == 'WHEN-NEW-RECORD-INSTANCE'
                  and catalog[p['source_owner_id']]['parent_id'] in {b['source_block_id'] for b, _ in path} | {op['source_module_id']}]
    def affects(nodes):
        return any((n['kind'] == 'property' and n['target_id'] == block_id and n['property'] == 'DELETE_ALLOWED')
                   or (n['kind'] in ('if', 'local_call') and affects(n['body'])) for n in nodes)
    if projection_only:
        candidates = [c for c in candidates if affects(c['body'])]
        if not candidates:
            return state, []
    if len(candidates) != 1:
        return 'NULL', []
    compiled = candidates[0]
    try:
        bound = {}
        for key, value in compiled['fields'].items():
            _need(key in fields and value['binding_kind'] == 'source_item'
                  and value['source_database_item'] is True, 'POLICY_FIELD')
            bound[key] = fields[key]
        effects = []
        visited_units = {compiled['source_unit_id']}

        def walk(nodes, condition=None):
            nonlocal state
            for node in nodes:
                kind = node['kind']
                if kind == 'local_call':
                    visited_units.add(node['source_unit_id'])
                    walk(node['body'], condition)
                elif kind == 'if':
                    term = _expression(node['condition'], bound)
                    walk(node['body'], term if condition is None else '(' + condition + ' AND ' + term + ')')
                elif kind == 'property':
                    if node['target_id'] == block_id and node['property'] == 'DELETE_ALLOWED':
                        value = '1' if node['value'] else '0'
                        state = value if condition is None else f'case when {condition} then {value} else {state} end'
                        effects.append(node)
                else:
                    raise ValueError('DELETE_ACTION_POLICY_BODY')
        walk(compiled['body'])
        if not effects or (not projection_only and any(d.get('source_unit_id') not in visited_units or d.get('value') is None for d in dynamic)):
            return 'NULL', []
        return state, [{'source_unit_id': compiled['source_unit_id'],
                        'source_unit_sha256': compiled['source_unit_sha256']}]
    except (ValueError, KeyError, TypeError):
        return 'NULL', []


def _provider(op, packet, token, argument_token):
    """Read only: no process, client setter, default result or original call."""
    call = op['parsed']['permission_call']
    call_hash = hashlib.sha256(_json(call)).hexdigest()
    where = (f"g.collection_name='{COLLECTION}' and g.c001={_lit(packet['source_binding'])}"
             + f" and g.c002={_lit(op['operation_id'])} and g.c003=({token})"
             + f" and g.c004=({argument_token}) and g.c007={_lit(op['source_unit_sha256'])}"
             + f" and g.c010={_lit(call_hash)} and g.n002=s.FOX_ROW_ID"
             + " and g.c008=to_char(:APP_ID) and g.c009=:APP_USER"
             + " and g.d001<=sysdate and g.d001>=sysdate-5/1440")
    return where, {'collection_name': COLLECTION, 'call_sha256': call_hash,
        'max_age_seconds': 300, 'server_only': True,
        'slots': {'c001': 'source_binding', 'c002': 'operation_id', 'c003': 'current_context_fingerprint',
                  'c004': 'argument_fingerprint', 'c005': 'RETURNED|RETURNED_NULL|ERROR',
                  'c007': 'source_unit_sha256', 'c008': 'application_id', 'c009': 'authenticated_user',
                  'c010': 'call_sha256', 'n001': 'returned_number', 'n002': 'selected_synthetic_row_id',
                  'd001': 'server_result_time'}}


def _relations(op, blocks):
    """Map the compiler's fresh complete source joins to typed native columns."""
    result = []
    for r in op['contract']['relations']:
        pairs = []
        for pn, cn in r['join_pairs']:
            p = _one([f for f in blocks[r['parent_block_id']]['items'] if f['source_name'].upper() == pn], 'PARENT_JOIN_FIELD')
            c = _one([f for f in blocks[r['child_block_id']]['items'] if f['source_name'].upper() == cn], 'CHILD_JOIN_FIELD')
            _need(p['data_type'] == c['data_type'], 'JOIN_TYPE')
            pairs.append(dict(parent_column=p['column'], child_column=c['column']))
        result.append(dict(parent_block_id=r['parent_block_id'], child_block_id=r['child_block_id'], join_pairs=pairs))
    return result


def _queries(op, packet, policy, blocks, relations, page):
    block = blocks[op['contract']['block']['source_block_id']]
    path, source, relation_where, token = _context(block, relations, blocks)
    permission, policy_proof = _permission(op, policy, path)
    projected_permission, projected_proof = _permission(op, policy, path, projection_only=True)
    selected = relation_where + f' and p.FOX_ROW_ID=:P{page}_PARENT_ID and ({token})=:P{page}_TOKEN'
    context = f'select p.* from {source} where {selected}'
    ancestors = [{'source_block_id': b['source_block_id'],
                  'query_sql': 'select ' + a + '.FOX_ROW_ID,' + ','.join(a + '.' + f['column'] for f in b['items'])
                      + ' from ' + source + ' where ' + selected}
                 for b, a in path[1:]]
    chooser = ('select p.FOX_ROW_ID,' + ','.join('p.' + f['column'] for f in block['items'])
               + ',' + token + ' as FOX_MASTER_TOKEN from ' + source + ' where ' + relation_where)
    counts = []
    for edge in relations:
        if edge['parent_block_id'] == block['source_block_id']:
            child = blocks[edge['child_block_id']]
            predicate = ' and '.join('c.' + p['child_column'] + '=p.' + p['parent_column'] for p in edge['join_pairs'])
            counts.append(f"(select count(*) from {child['table_name']} c where {predicate})")
    children = '+'.join(counts) or '0'
    guard_count = 'NULL'
    if op['kind'] == 'master_existence_guard':
        bound = op['contract']['existence_guard']
        child = blocks[bound['child_block']['source_block_id']]
        predicate = ' and '.join('c.' + p['child_field']['column'] + '=p.' + p['parent_field']['column']
                                 for p in bound['predicates'])
        guard_count = f"(select count(*) from {child['table_name']} c where {predicate})"
    provider = None
    argument_token = 'NULL'
    if op['kind'] == 'key_delete':
        # All exact stored argument fields are separately fingerprinted. System,
        # global or literal argument context stays in the source call digest;
        # a non-stored argument cannot acquire a trusted current value here.
        argument = op['contract']['permission_argument']
        mapped = {f['source_item_id']: (f, a) for b, a in path for f in b['items']}
        _need(argument['source_item_id'] in mapped, 'ARGUMENT_CONTEXT')
        target, alias = mapped[argument['source_item_id']]
        argument_token = _fingerprint([target], alias)
        join, provider = _provider(op, packet, 's.CONTEXT_TOKEN', 's.ARGUMENT_TOKEN')
    selected_sql = (f'select p.FOX_ROW_ID,({permission}) as SOURCE_ALLOWED,({projected_permission}) as ENTRY_POLICY_PROJECTION,({children}) as MATCHING_CHILDREN,'
                    + f'({guard_count}) as LOCAL_GUARD_COUNT,({token}) as CONTEXT_TOKEN,({argument_token}) as ARGUMENT_TOKEN'
                    + f' from {source} where {selected}')
    if provider:
        aggregate = ('select s.FOX_ROW_ID,s.SOURCE_ALLOWED,s.ENTRY_POLICY_PROJECTION,s.MATCHING_CHILDREN,count(g.collection_name) as PROVIDER_COUNT,'
                     + 'max(g.c005) as PROVIDER_STATUS,max(g.n001) as GUARD_VALUE from selected_row s '
                     + 'left join apex_collections g on ' + join
                     + ' group by s.FOX_ROW_ID,s.SOURCE_ALLOWED,s.ENTRY_POLICY_PROJECTION,s.MATCHING_CHILDREN')
        outcome = ("case when PROVIDER_COUNT=0 then 'UNAVAILABLE' when PROVIDER_COUNT<>1 then 'AMBIGUOUS' "
                   "when PROVIDER_STATUS='ERROR' then 'ERROR' when PROVIDER_STATUS='RETURNED_NULL' and GUARD_VALUE is null then 'RETURNED_NULL' "
                   "when PROVIDER_STATUS='RETURNED' and GUARD_VALUE is not null then 'RETURNED' else 'INVALID' end")
        ctes = 'with selected_row as (' + selected_sql + '),provider_rows as (' + aggregate + '),facts as ('
        facts = 'select FOX_ROW_ID,SOURCE_ALLOWED,ENTRY_POLICY_PROJECTION,MATCHING_CHILDREN,GUARD_VALUE,' + outcome + ' as GUARD_OUTCOME from provider_rows'
    else:
        ctes = 'with selected_row as (' + selected_sql + '),facts as ('
        facts = "select FOX_ROW_ID,SOURCE_ALLOWED,ENTRY_POLICY_PROJECTION,MATCHING_CHILDREN,LOCAL_GUARD_COUNT as GUARD_VALUE,'LOCAL_EXISTENCE' as GUARD_OUTCOME from selected_row"
    stage = ("case when SOURCE_ALLOWED=0 then 'POLICY_DENIED' when SOURCE_ALLOWED is null then 'POLICY_UNKNOWN' "
             "when GUARD_OUTCOME='LOCAL_EXISTENCE' and GUARD_VALUE>0 then 'BLOCKED_CHILDREN' "
             "when GUARD_OUTCOME in ('UNAVAILABLE','AMBIGUOUS','ERROR','INVALID') then 'GUARD_'||GUARD_OUTCOME "
             "when GUARD_OUTCOME='RETURNED' and GUARD_VALUE>0 then 'SOURCE_REFUSAL' "
             "else 'PENDING_AUDIT_TRANSACTION_AND_SCOPE' end")
    messages = ' || chr(10) || '.join(_lit(v) for v in op['parsed'].get('messages', [])) or 'NULL'
    refusal = ("case when (GUARD_OUTCOME='LOCAL_EXISTENCE' or GUARD_OUTCOME='RETURNED') and GUARD_VALUE>0 then " + messages + ' else null end')
    local_check = "case when GUARD_OUTCOME='LOCAL_EXISTENCE' and GUARD_VALUE>0 then 'Matching child records prevent the source master delete.' when GUARD_OUTCOME='LOCAL_EXISTENCE' then 'No matching child records; delete permission remains separate.' else 'External permission result is checked separately from related-row counts.' end"
    declared = op['contract']['delete_policy']['static_value']
    declared_sql = '1' if declared is True else '0' if declared is False else 'NULL'
    policy_detail = ("case when SOURCE_ALLOWED=0 then 'The proved saved-row entry/default policy denies deletion.' "
                     "when SOURCE_ALLOWED is null then 'Current delete policy is unresolved. Declared default, dormant setters or event hierarchy do not prove authorization.' "
                     "else 'Saved-row entry-policy projection permits continuing checks; whole-form current runtime permission is still required before deletion.' end")
    query = (ctes + facts + ') select FOX_ROW_ID,SOURCE_ALLOWED,ENTRY_POLICY_PROJECTION,' + declared_sql + ' as DECLARED_DELETE_ALLOWED,'
             + 'MATCHING_CHILDREN,GUARD_VALUE,GUARD_OUTCOME,' + stage
             + ' as PREFLIGHT_STATE,' + refusal + ' as SOURCE_MESSAGES,' + local_check + ' as RELATION_CHECK,'
             + policy_detail + ' as POLICY_DETAIL,'
             + "'No rows marked or deleted. Required authorization, audit, source staging and transaction outcomes remain unexecuted.' as TRANSACTION_STATUS from facts")
    _need(all(len(v.encode()) <= 32767 for v in (query, chooser, context)), 'QUERY_CAPACITY')
    return dict(preflight_query_sql=query, chooser_query_sql=chooser, selected_context_sql=context,
                context_fingerprint_sql=token, argument_fingerprint_sql=argument_token,
                current_policy_sql=permission, policy_proof=policy_proof, provider_contract=provider,
                entry_policy_projection_sql=projected_permission, entry_policy_projection_proof=projected_proof,
                entry_projection_scope='single_complete_entry_property_rule_over_saved_rows_not_runtime_permission_or_event_precedence',
                ancestor_context_queries=ancestors,
                path_block_ids=[b['source_block_id'] for b, _ in path])


def _shell(page, body):
    return native_buffer._expand_groups(f'''page {page} (
    name: Delete preflight
    alias: FOX_DELETE_{page}
    title: Delete preflight
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT# }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum }}
    region delete-scope (
        name: Selected saved record
        type: staticContent
        source {{ htmlCode: "<p>Read-only checks for this saved synthetic row. Source delete permission and relation checks run again on every request. Empty results mean missing, stale or ambiguous context; select the record again. No row is marked, posted or deleted. Audit, original staging and Forms commit providers remain required.</p>" }}
        layout {{ sequence: 5
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
{body})
''').encode()


def _hidden(page):
    return ''.join(f'''    pageItem P{page}_{name} (
        type: hidden
        layout {{ sequence: 10
            region: @delete-scope
            slot: regionBody }}
        sessionState {{ storage: session
            dataType: {dtype} }}
        security {{ sessionStateProtection: checksumRequiredSessionLevel }}
    )
''' for name, dtype in (('PARENT_ID', 'number'), ('TOKEN', 'varchar2')))


def apply_delete_actions(documents, packet, chunks, trace, files):
    """Connect proved preflight effects, retaining whole-event gaps and originals."""
    from .forms_delete_plan import build_delete_plan
    plan = build_delete_plan(documents, packet, chunks, trace, files)
    output = dict(files)
    receipt = dict(schema_version=1, scope=SCOPE, source_binding=packet['source_binding'],
                   generated_operations=[], adapted_operations=[], gaps=deepcopy(plan['gaps']),
                   converted_code_unit_count=0, customer_table_writes=False, synthetic_table_writes=False,
                   external_calls_enabled=False, original_reads_enabled=False, forms_commit_implemented=False,
                   oracle_compiled=False, runtime_verified=False, business_accepted=False)
    _need(not any(re.fullmatch(r'pages/p\d+-fox_delete_\d+\.apx', n) for n in files), 'ALREADY_ADAPTED')
    objects, props = _source_objects(documents, packet)
    blocks = {}
    if plan['operations']:
        blocks = {b['source_block_id']: _block(b['source_block_id'], objects, trace, files) for b in trace['blocks']
                  if b['classification'] == 'database'}
    policy = build_policy_plan(documents, trace)
    occupied = {int(m[1]) for n in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', n))}
    page = 8700
    for op in plan['operations']:
        identity = {k: op[k] for k in ('source_unit_id', 'source_unit_sha256', 'source_owner_id', 'source_module_id')}
        if op['kind'] == 'pre_delete':
            receipt['gaps'].append({**identity, 'reason': 'DELETE_ACTION_PRE_DELETE_AUDIT_STAGING_TRANSACTION_UNEXECUTED'})
            continue
        try:
            while page in occupied or page + 1 in occupied:
                page += 2
            _need(page + 1 < 9000, 'PAGE_CAPACITY')
            chooser_page, result_page = page, page + 1
            relations = _relations(op, blocks)
            q = _queries(op, packet, policy, blocks, relations, result_page)
            block = blocks[op['contract']['block']['source_block_id']]
            entry = block['report_file']
            original = output[entry].decode()
            _need(original.endswith(')\n') and 'region records (' in original, 'NORMAL_REPORT_ENTRY')
            chooser_file = f'pages/p{chooser_page:05d}-fox_delete_{chooser_page}.apx'
            result_file = f'pages/p{result_page:05d}-fox_delete_{result_page}.apx'
            chooser = _report('records', 'Select saved row for delete preflight', q['chooser_query_sql'], block['items'], link=result_page)
            chooser = chooser.replace('linkText: Select master', 'linkText: Check this row')
            fields = [{'column': n, 'data_type': dtype, 'source_name': n.replace('_', ' ').capitalize()}
                      for n, dtype in [('SOURCE_ALLOWED', 'NUMBER'), ('ENTRY_POLICY_PROJECTION', 'NUMBER'), ('MATCHING_CHILDREN', 'NUMBER'),
                                       ('GUARD_VALUE', 'NUMBER'), ('GUARD_OUTCOME', 'VARCHAR2'),
                                       ('PREFLIGHT_STATE', 'VARCHAR2'), ('DECLARED_DELETE_ALLOWED', 'NUMBER'),
                                       ('SOURCE_MESSAGES', 'VARCHAR2'), ('POLICY_DETAIL', 'VARCHAR2'),
                                       ('RELATION_CHECK', 'VARCHAR2'), ('TRANSACTION_STATUS', 'VARCHAR2')]]
            labels = {'SOURCE_ALLOWED': 'Saved-row entry permission', 'DECLARED_DELETE_ALLOWED': 'Declared delete default',
                      'ENTRY_POLICY_PROJECTION': 'One proved entry rule on saved rows (runtime precedence unresolved)',
                      'MATCHING_CHILDREN': 'Matching related saved rows', 'GUARD_VALUE': 'Source check result',
                      'GUARD_OUTCOME': 'Permission provider outcome', 'PREFLIGHT_STATE': 'Delete preflight state',
                      'SOURCE_MESSAGES': 'Source refusal messages', 'POLICY_DETAIL': 'Delete permission explanation',
                      'RELATION_CHECK': 'Related-record check', 'TRANSACTION_STATUS': 'Transaction status'}
            for f in fields:
                f['source_name'] = labels[f['column']]
            body = _report('delete-result', 'Current saved-row delete checks', q['preflight_query_sql'], fields)
            body += _report('selected-context', 'Selected saved row', q['selected_context_sql'], block['items'], sequence=20)
            for i, context in enumerate(q['ancestor_context_queries'], 1):
                ancestor = blocks[context['source_block_id']]
                body += _report('parent-context-' + str(i), 'Related saved parent: ' + ancestor['name'],
                                context['query_sql'], ancestor['items'], sequence=20 + i * 10)
            button = native_buffer._expand_groups(f'''    button delete-preflight-{chooser_page} (
        buttonName: FOX_DELETE_PREFLIGHT_{chooser_page}
        label: Check delete requirements
        layout {{ sequence: 8700
            region: @records
            slot: rightOfInteractiveReportSearchBar }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {chooser_page}
                clearCache: {chooser_page} }} }}
    )
''')
            output[entry] = (original[:-2] + button + ')\n').encode()
            output[chooser_file] = _shell(chooser_page, chooser)
            output[result_file] = _shell(result_page, body + _hidden(result_page))
            receipt['adapted_operations'].append({**identity, 'operation_id': op['operation_id'],
                'kind': 'selected_row_delete_preflight', 'source_kind': op['kind'],
                'page_id': result_page, 'page_file': result_file, 'entry_file': entry,
                'chooser_file': chooser_file, 'chooser_page_id': chooser_page, **q,
                'connected_effects': ['current_delete_policy', 'current_related_synthetic_row_counts']
                    + (['source_master_existence_predicate'] if op['kind'] == 'master_existence_guard' else ['trusted_server_permission_result_predicate']),
                'whole_source_unit_converted': False, 'source_event_partially_connected': True,
                'row_marking_implemented': False, 'pre_delete_executed': False,
                'session_drafts_mutated': False, 'runtime_verified': False, 'business_accepted': False})
            receipt['gaps'].append({**identity, 'reason': 'DELETE_ACTION_MARK_POST_AUDIT_STAGING_TRANSACTION_PROVIDERS_PENDING'})
            occupied.update((chooser_page, result_page))
            page += 2
        except (ValueError, KeyError, TypeError) as exc:
            receipt['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError) else 'DELETE_ACTION_BOUND_CONTEXT_UNAVAILABLE'})
    output['fox-package/delete-plan.json'] = _json(plan)
    receipt['receipt_sha256'] = hashlib.sha256(_json(receipt)).hexdigest()
    return output, receipt
