"""Whole literal item commands on signed, explicitly selected saved records.

The focus action and an item's NULL query overrides are complete commands.
This saved-row viewer does not emulate Forms validation, edits or lifecycle.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from html import escape
import json
import re

from forms2apex import native_blueprint, native_buffer
from .forms_behavior_plan import _Parser, _tokens, _source_objects, decode_control_entities
from .forms_guarded_query import _field
from .forms_master_detail import _fingerprint, _report
from .forms_record_entry import _block
from .forms_relation_plan import build_relation_plan
from .forms_understanding_packet import _build
from .prototype_export_only import _zip, _members

SCOPE = 'fox-item-commands-v1'
FOCUS_RULE = 'fox.item.literal-focus-command'
NULL_RULE = 'fox.item.null-query-command'
RECEIPT_MEMBER = 'fox-package/item-command-receipt.json'


def _need(value, reason):
    if not value:
        raise ValueError('ITEM_COMMAND_' + reason)


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


def parse_item_command(text, event):
    """Only a complete NULL or literal GO_ITEM body, optionally BEGIN/END."""
    _need(type(text) is str and len(text) <= 8192, 'SOURCE_CAPACITY')
    semantic, decode = decode_control_entities(text)
    parser = _Parser(_tokens(semantic))
    wrapped = parser.peek('BEGIN')
    if wrapped:
        parser.take('BEGIN')
    if event == 'KEY-NEXT-ITEM':
        parser.take('GO_ITEM'); parser.take('(')
        target = parser.take(kind='string')
        _need(re.fullmatch(r'[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*)?', target), 'LITERAL_ITEM_REQUIRED')
        parser.take(')'); parser.take(';')
        result = dict(kind='literal_item_focus', rule_id=FOCUS_RULE, target_reference=target.upper())
    else:
        _need(event in ('KEY-ENTQRY', 'KEY-EXEQRY'), 'EVENT')
        parser.take('NULL'); parser.take(';')
        result = dict(kind='item_null_query_override', rule_id=NULL_RULE)
    if wrapped:
        parser.take('END'); parser.take(';')
    parser.end()
    return {**result, 'decode_receipt': decode}


def recognize_item_commands(documents, packet, chunks):
    objects, props = _source_objects(documents, packet)
    by_unit = {c['code_unit_id']: c for c in chunks}
    operations, gaps = [], []
    for unit in (u for s in packet['sources'] for u in s['facts']['code_units']):
        owner = objects[unit['owner_id']]
        event = (owner['name'] or '').upper()
        item = objects.get(owner['parent_id'])
        if not (owner['kind'] == 'Trigger' and item and item['kind'] == 'Item'
                and event in ('KEY-NEXT-ITEM', 'KEY-ENTQRY', 'KEY-EXEQRY')):
            continue
        identity = dict(source_unit_id=unit['id'], source_unit_sha256=unit['sha256'],
                        source_owner_id=owner['id'], source_module_id=owner['module_id'],
                        owner_item_id=item['id'], source_event=event)
        try:
            _need(unit['source_attribute'] == 'TriggerText', 'TRIGGER_BODY_REQUIRED')
            trigger_props = props[owner['id']]
            _need(all(trigger_props.get(k, '').strip().upper() in ('', 'OVERRIDE')
                      for k in ('ExecutionStyle', 'ExecutionHierarchy')), 'PARENT_TRIGGER_SEQUENCE_UNSUPPORTED')
            _need(len([o for o in objects.values() if o['kind'] == 'Trigger'
                       and o['parent_id'] == item['id'] and (o['name'] or '').upper() == event]) == 1,
                  'EVENT_NOT_UNIQUE')
            parsed = parse_item_command(by_unit[unit['id']]['text'], event)
            op = {**identity, **parsed}
            if parsed['kind'] == 'literal_item_focus':
                parts = parsed['target_reference'].split('.')
                target = _one([o for o in objects.values() if o['kind'] == 'Item'
                    and o['module_id'] == item['module_id'] and (o['name'] or '').upper() == parts[-1]
                    and (len(parts) == 1 or (objects[o['block_id']]['name'] or '').upper() == parts[0])], 'TARGET_NOT_UNIQUE')
                _need(target['id'] != item['id'], 'DISTINCT_TARGET_REQUIRED')
                op['target_item_id'] = target['id']
            op['operation_id'] = 'item-command-' + hashlib.sha256((unit['id'] + unit['sha256']).encode()).hexdigest()[:24]
            operations.append(op)
        except ValueError as exc:
            # This recognizer's unsupported candidates remain outside its count.
            gaps.append({**identity, 'reason': str(exc), 'generation_status': 'unsupported'})
    return {'operations': operations, 'gaps': gaps}


def navigation_runtime(config):
    """Execute emitted handlers against real source-bound readonly inputs."""
    client = {'state_item': config['state_item'],
              'fields': [{k:f[k] for k in ('source_item_id','item_name')} for f in config['fields']],
              'operations': [{k:o[k] for k in ('owner_item_id','source_event','target_item_id') if k in o}
                             for o in config['operations']]}
    literal = json.dumps(client, ensure_ascii=True, separators=(',',':')).replace('<', '\\u003c')
    return r'''(function () {
  "use strict";
  const config = CONFIG;
  const fields = new Map(config.fields.map(f => [f.source_item_id, document.getElementById(f.item_name)]));
  const status = document.getElementById("fox-item-command-status");
  let selected = null;
  const say = message => { if (status) status.textContent = message; };
  function ready() {
    const state = document.getElementById(config.state_item);
    return state && state.value === "READY";
  }
  function move(id) {
    const op = config.operations.find(o => o.owner_item_id === id && o.source_event === "KEY-NEXT-ITEM");
    if (!op) return false;
    if (!ready()) { say("The selected saved record changed. Select it again."); return true; }
    const target = fields.get(op.target_item_id);
    if (!target || target.disabled) { say("No selected child record. Select a related record before Next."); return true; }
    target.focus();
    say("Focus moved to the selected saved record. Validation, new records and commit workflows are outside this screen.");
    return true;
  }
  function command(id, event) {
    const op = config.operations.find(o => o.owner_item_id === id && o.source_event === event);
    if (!op) return false;
    say("This field's source " + event + " command is NULL. No query or submission was run.");
    return true;
  }
  for (const [id, field] of fields) {
    if (!field) continue;
    field.readOnly = true;
    field.addEventListener("focus", () => { selected = id; });
    field.addEventListener("keydown", e => {
      if (e.defaultPrevented || e.shiftKey || e.ctrlKey || e.altKey || e.metaKey) return;
      let handled = false;
      if (e.key === "Tab" && config.operations.some(o => o.owner_item_id === id && o.source_event === "KEY-NEXT-ITEM")) {
        handled = move(id);
      } else if (e.key === "F7") { handled = command(id, "KEY-ENTQRY"); }
      else if (e.key === "F8") { handled = command(id, "KEY-EXEQRY"); }
      if (handled) { e.preventDefault(); e.stopImmediatePropagation(); }
    }, true);
  }
  document.querySelectorAll("[data-fox-item-next]").forEach(button => button.addEventListener("click", () => move(button.dataset.foxItemNext)));
  document.querySelectorAll("[data-fox-item-query]").forEach(button => button.addEventListener("click", () => {
    const id = button.dataset.foxItemOwner || selected;
    if (!command(id, button.dataset.foxItemQuery)) say("This command has no NULL override on the selected field. No query was run by this viewer.");
  }));
  window.foxItemCommands = Object.freeze({move, command, fields});
})();'''.replace('CONFIG', literal)


def _chain_for(block_id, objects, props, trace, files, relation):
    path, edges = [block_id], []
    while True:
        incoming = [o for o in objects.values() if o['kind'] == 'Relation'
                    and o['module_id'] == objects[block_id]['module_id']
                    and props[o['id']].get('DetailBlock', '').upper() == objects[path[-1]]['name'].upper()]
        if not incoming:
            break
        rel = _one(incoming, 'INCOMING_RELATION_NOT_UNIQUE')
        edge = _one([e for e in relation['operations'] if e['relation_id'] == rel['id']], 'RELATION_NOT_PROVED')
        _need(edge['child_block_id'] == path[-1] and edge['parent_block_id'] == rel['block_id']
              and edge['parent_block_id'] not in path, 'RELATION_PATH')
        edges.append(edge); path.append(edge['parent_block_id'])
        _need(len(path) <= 8, 'ANCESTOR_CAPACITY')
    return [_block(k, objects, trace, files) for k in reversed(path)], list(reversed(edges))


def selection_sql(blocks, edges, page, *, selected):
    """Bind every selected ancestor ID and fingerprint and reject ambiguous keys."""
    aliases = [f'r{i}' for i in range(len(blocks))]
    base = ', '.join(f"{b['table_name']} {a}" for a, b in zip(aliases, blocks))
    conditions = []
    for i, b in enumerate(blocks[:selected]):
        conditions += [f'r{i}.FOX_ROW_ID=:P{page}_ID{i}',
                       f"({_fingerprint(b['items'], 'r'+str(i))})=:P{page}_TOKEN{i}"]
    for i, edge in enumerate(edges):
        conditions += [f"r{i}.{p['parent_column']}=r{i+1}.{p['child_column']}" for p in edge['join_pairs']]
        same = ' and '.join(f"s.{p['parent_column']}=r{i}.{p['parent_column']}" for p in edge['join_pairs'])
        conditions.append(f"(select count(*) from {blocks[i]['table_name']} s where {same})=1")
    return base, (' and '.join(conditions) if conditions else '1=1')


def _hidden(page, name, dtype='varchar2', *, restricted=False):
    return f'''    pageItem P{page}_{name} (
        type: hidden
        layout {{ sequence: 1
            region: @records
            slot: regionBody }}
        sessionState {{ storage: {'request' if restricted else 'session'}
            dataType: {dtype} }}
        security {{ sessionStateProtection: {'restricted' if restricted else 'checksumRequiredSessionLevel'} }}
    )
'''


def _screen(page, next_page, blocks, edges, selected_count, operations, objects, props):
    """A prefix shows only actual saved ancestors; children require row selection."""
    selected_blocks = blocks[:selected_count]
    bindings, selects, targets = [], [], []
    body = ''
    wanted = {o['owner_item_id'] for o in operations} | {o.get('target_item_id') for o in operations}
    wanted.update(p[k] for e in edges for p in e['join_pairs'] for k in ('parent_item_id','child_item_id'))
    for i, b in enumerate(selected_blocks):
        for f in b['items']:
            if f['source_item_id'] not in wanted:
                continue
            source_item = objects[f['source_item_id']]
            _field(source_item, b, props)
            name = f'P{page}_F{len(bindings)}'
            bindings.append(dict(source_item_id=f['source_item_id'], source_block_id=b['source_block_id'],
                                 source_item_name=f['source_name'], item_name=name, row_index=i))
            selects.append(f"r{i}.{f['column']}"); targets.append(':'+name)
            body += f'''    pageItem {name} (
        type: textField
        label {{ label: {json.dumps(b['name']+'.'+f['source_name'])} }}
        layout {{ sequence: {100+len(bindings)}
            region: @records
            slot: regionBody }}
        appearance {{ template: @/optional-floating }}
        advanced {{ customAttributes: "readonly aria-readonly=\\"true\\"" }}
        sessionState {{ storage: request
            dataType: varchar2 }}
        security {{ sessionStateProtection: restricted }}
    )
'''
    body += ''.join(_hidden(page, f'ID{i}', 'number') + _hidden(page, f'TOKEN{i}') for i in range(selected_count))
    body += _hidden(page, 'STATE', restricted=True)
    process = ''
    selected_query = None
    if selected_count:
        base, where = selection_sql(selected_blocks, edges[:selected_count-1], page, selected=selected_count)
        # An ancestor-only chooser can have no item command of its own.
        projections = selects or ['1']
        destinations = targets or ['l_selected']
        selected_query = 'select '+','.join(projections)+' from '+base+' where '+where
        resets = '\n'.join(f'{n}:=null;' for n in targets)
        process = f"declare l_selected number; begin\n{resets}\n:P{page}_STATE:='STALE_OR_MISSING';\nselect "+','.join(projections)+' into '+','.join(destinations)+' from '+base+' where '+where+f";\n:P{page}_STATE:='READY';\nexception when no_data_found then\n{resets}\n:P{page}_STATE:='STALE_OR_MISSING';\nend;"
        body += native_buffer._process('load-selected-item-context', process, point='beforeHeader')
    chooser_query = None
    if selected_count < len(blocks):
        i = selected_count; child = blocks[i]
        base, where = selection_sql(blocks[:i+1], edges[:i], page, selected=i)
        chooser_query = ('select r'+str(i)+'.FOX_ROW_ID,'+','.join(f"r{i}.{f['column']}" for f in child['items'])
                         +','+_fingerprint(child['items'],f'r{i}')+' as FOX_MASTER_TOKEN from '+base+' where '+where)
        report = _report('children', 'Select '+child['name']+' saved record', chooser_query, child['items'], link=next_page)
        old = f'''                    items: {{ P{next_page}_PARENT_ID: "#FOX_ROW_ID#"
                        P{next_page}_TOKEN: "#FOX_MASTER_TOKEN#" }}'''
        carry = ''.join(f'                        P{next_page}_ID{j}: "&P{page}_ID{j}."\n                        P{next_page}_TOKEN{j}: "&P{page}_TOKEN{j}."\n' for j in range(i))
        new = f'''                    clearCache: {next_page}
                    items: {{
{carry}                        P{next_page}_ID{i}: "#FOX_ROW_ID#"
                        P{next_page}_TOKEN{i}: "#FOX_MASTER_TOKEN#" }}'''
        _need(report.count(old) == 1, 'LINK_TEMPLATE')
        body += report.replace(old, new).replace('linkText: Select master', 'linkText: Select saved record')
    owner_ids = {b['source_item_id'] for b in bindings}
    controls = '<p>Saved synthetic records only. Fields are read-only. Select each related record explicitly. Empty results mean no matching child; Next never creates a row. Tab or Next runs only the literal source focus command. Validation, drafts, implicit item-entry actions, new records and commit workflows remain separate.</p>'
    for op in operations:
        if op['owner_item_id'] not in owner_ids:
            continue
        label = escape(objects[op['owner_item_id']]['name'])
        owner = escape(op['owner_item_id'], quote=True)
        if op['source_event'] == 'KEY-NEXT-ITEM':
            controls += f'<button type="button" data-fox-item-next="{owner}">Next from {label}</button> '
        else:
            event = op['source_event']; label = ('Enter Query (FOX shortcut F7)' if event == 'KEY-ENTQRY' else 'Execute Query (FOX shortcut F8)')+' on '+label
            controls += f'<button type="button" data-fox-item-owner="{owner}" data-fox-item-query="{event}">{label}</button> '
    controls += '<p id="fox-item-command-status" role="status" aria-live="polite"></p>'
    config = dict(fields=bindings, operations=operations, state_item=f'P{page}_STATE')
    script = navigation_runtime(config)
    text = f'''page {page} (
    name: Saved record item commands
    alias: FOX_ITEMS_{page}
    title: Saved record item commands
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT# }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum }}
    javaScript {{ executeWhenPageLoads:
        ```javascript
{native_buffer._indent(script,8)}
        ```
    }}
    region records (
        name: Saved source field navigation
        type: staticContent
        source {{ htmlCode: {json.dumps(controls)} }}
        layout {{ sequence: 10
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
{body})
'''
    return native_buffer._expand_groups(text).encode(), dict(page_id=page, field_bindings=bindings,
        path_block_ids=[b['source_block_id'] for b in selected_blocks], selected_record_sql=selected_query,
        chooser_query_sql=chooser_query, process_plsql=process, runtime_config=config,
        context_aliases={b['source_block_id']: 'r'+str(i) for i,b in enumerate(selected_blocks)})


def apply_item_commands(documents, packet, chunks, trace, files):
    fresh, current_chunks = _build(documents)
    _need(fresh['sources'] == packet.get('sources') and fresh['source_binding'] == packet.get('source_binding')
          == trace.get('source_binding') and chunks == current_chunks, 'SOURCE_BINDING')
    _need(json.loads(files['fox-package/source-to-page.json']) == trace, 'TRACE_CHANGED')
    manifest = json.loads(files['fox-package/source-manifest.json'])
    _need(manifest.get('source_binding') == fresh['source_binding']
          and manifest.get('selected_chunk_hashes') == {c['id']: c['sha256'] for c in chunks}
          and manifest.get('files') == [{k: s['source'][k] for k in ('name', 'bytes', 'sha256')} for s in fresh['sources']], 'MANIFEST_CHANGED')
    for name, raw in documents:
        _need(files.get('fox-package/sources/'+name) == raw, 'ORIGINAL_CHANGED')
    recognized = recognize_item_commands(documents, packet, chunks)
    output = dict(files)
    receipt = dict(schema_version=1, scope=SCOPE, source_binding=fresh['source_binding'], generated_operations=[],
        gaps=recognized['gaps'], screens=[], converted_code_unit_count=0, customer_table_writes=False,
        synthetic_table_writes=False, oracle_compiled=False, runtime_verified=False, business_accepted=False)
    if not recognized['operations']:
        return output, receipt
    # Rebuild the actual synthetic table/field identities, independent of receipts.
    from .forms_native_plan import build_native_prototype_plan, POLICY_ID
    from .xml_mapping import _blueprint
    spec = build_native_prototype_plan(documents, _blueprint(packet), project_id=trace['project_id'],
        project_name='Item commands source proof', approved_policy_id=POLICY_ID)['rendering_spec']
    expected = native_blueprint.prototype_trace(spec)
    objects, props = _source_objects(documents, packet)
    for b in expected['blocks']:
        b['source_module_id'] = objects[b['source_block_id']]['module_id']
    _need(trace['blocks'] == expected['blocks'] and files['fox-package/supporting-schema.sql'] == native_blueprint.render_prototype_schema(spec).encode(), 'SCHEMA_CHANGED')
    structural = _members(native_blueprint.deterministic_prototype_zip(spec))
    structural.update({n: files[n] for n in ('fox-package/source-manifest.json',
        'fox-package/source-to-page.json', 'fox-package/supporting-schema.sql')})
    structural.update({'fox-package/sources/'+n: raw for n, raw in documents})
    relation = build_relation_plan(documents, _zip(structural))
    stored_relation = json.loads(files['fox-package/relation-plan.json'])
    _need(all(stored_relation.get(k) == relation[k] for k in ('source_binding', 'operations', 'sources', 'coverage')), 'RELATION_CHANGED')
    rendered = json.loads(files.get('fox-package/relation-receipt.json', b'{}'))
    _need(not relation['operations'] or rendered.get('source_binding') == packet['source_binding'], 'RELATION_NOT_RENDERED')
    for edge in relation['operations']:
        _need(any(r.get('relation_id') == edge['relation_id'] for r in rendered.get('generated_operations', [])), 'RELATION_NOT_RENDERED')
    # Commands are grouped by a unique source relation chain, not source names.
    groups = {}
    for op in recognized['operations']:
        try:
            ids = [op['owner_item_id']] + ([op['target_item_id']] if 'target_item_id' in op else [])
            for item_id in ids:
                b = _block(objects[item_id]['block_id'], objects, trace, files)
                _field(objects[item_id], b, props)
                field_props = props[item_id]
                _need(field_props.get('ItemType','').strip().upper() == 'TEXT ITEM'
                      and all(field_props.get(k,'').strip().lower() in ('','true') for k in
                              ('Visible','Displayed','Enabled','KeyboardNavigable','Navigable')),
                      'SOURCE_FIELD_NOT_FOCUSABLE')
            chains = [_chain_for(objects[k]['block_id'], objects, props, trace, files, relation) for k in ids]
            blocks, edges = max(chains, key=lambda pair: len(pair[0]))
            path = [b['source_block_id'] for b in blocks]
            _need(all(objects[k]['block_id'] in path for k in ids), 'UNRELATED_FOCUS_TARGET')
            groups.setdefault(tuple(path), (blocks, edges, []))[2].append(op)
        except ValueError as exc:
            receipt['gaps'].append(dict(source_unit_id=op['source_unit_id'], reason=str(exc), generation_status='unsupported'))
    # A shallower command belongs on the longest compatible chain as well.
    maximal = [k for k in groups if not any(len(p)>len(k) and p[:len(k)] == k for p in groups)]
    occupied = {int(m[1]) for n in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', n))}
    by_source_unit = {}
    for path in maximal:
        blocks, edges, _ = groups[path]
        operations = [deepcopy(op) for key, (_, _, ops) in groups.items() if path[:len(key)] == key for op in ops]
        pages = []
        for _ in range(len(blocks)+1):
            page = next((i for i in range(8100,8900) if i not in occupied), None)
            _need(page is not None, 'PAGE_CAPACITY'); occupied.add(page); pages.append(page)
        for count, page in enumerate(pages):
            raw, screen = _screen(page, pages[count+1] if count<len(blocks) else None, blocks, edges, count, operations, objects, props)
            filename = f'pages/p{page:05d}-fox_items_{page}.apx'
            output[filename] = raw; screen['page_file'] = filename; receipt['screens'].append(screen)
        # Normal source reports expose one clear route into the selection chain.
        for block in blocks:
            report = block['report_file']; text = output[report].decode()
            _need(text.endswith(')\n') and '    region records (\n' in text, 'REPORT_TEMPLATE')
            button = f'''    button source-item-commands-{pages[0]} (
        buttonName: FOX_ITEM_COMMANDS_{pages[0]}
        label: Saved record field navigation
        layout {{ sequence: 180
            region: @records
            slot: rightOfInteractiveReportSearchBar }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {pages[0]}
                clearCache: {pages[0]} }} }}
    )
'''
            output[report] = (text[:-2]+native_buffer._expand_groups(button)+')\n').encode()
        last = receipt['screens'][-1]
        by_item = {b['source_item_id']: b for b in last['field_bindings']}
        for op in operations:
            _need(op['owner_item_id'] in by_item and ('target_item_id' not in op or op['target_item_id'] in by_item), 'CONTROL_MISSING')
            uid = op['source_unit_id']
            if uid in by_source_unit:
                by_source_unit[uid]['additional_page_files'].append(last['page_file'])
                continue
            record = {**op, 'page_id': pages[-1], 'page_file': last['page_file'], 'additional_page_files': [],
                'target': {'page_id': pages[-1], 'page_file': last['page_file']},
                'owner_item': by_item[op['owner_item_id']], 'native_event': 'forward_tab_or_explicit_next' if op['source_event']=='KEY-NEXT-ITEM' else 'FOX_F7_or_item_enter_query' if op['source_event']=='KEY-ENTQRY' else 'FOX_F8_or_item_execute_query',
                'target_item': by_item.get(op.get('target_item_id')), 'entry_page_id': pages[0],
                'generation_status': 'generated_wired_adapted', 'scope': 'selected_read_only_saved_synthetic_rows',
                'implicit_validation_implemented': False, 'item_entry_lifecycle_implemented': False,
                'new_record_implemented': False, 'oracle_compiled': False, 'runtime_verified': False, 'business_accepted': False}
            by_source_unit[uid] = record
            receipt['generated_operations'].append(record)
    receipt['converted_code_unit_count'] = len(receipt['generated_operations'])
    return output, receipt
