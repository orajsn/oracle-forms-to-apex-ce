"""Account for every source item in a durable synthetic rate workspace.

This is generated-field coverage, not proof of a save, Oracle execution, or
original business persistence. Structural report columns are never receipts.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy

from .forms_behavior_plan import UnsupportedBehavior, _source_objects
from .forms_event_callables import _compile
from .forms_understanding_packet import _build

SCOPE = 'fox-rate-field-coverage-v1'
_STATUSES = ('saved', 'parent_linked', 'pending', 'control')
_RECEIPT = 'fox-package/mapping-ledger.json'


def _need(ok, reason):
    if not ok:
        raise ValueError('RATE_FIELD_COVERAGE_' + reason)


def _pointer(section, identity, path, **extra):
    # Identity selectors remain correct when other operations precede this one
    # in the final ledger. row_lookups is only a subset of lov_returns.
    return {'receipt': _RECEIPT, 'section': section, **identity, 'path': path, **extra}


def _database_item(properties):
    value = properties.get('DatabaseItem', '').strip().lower()
    return {'true': True, 'yes': True, 'false': False, 'no': False}.get(value, 'unknown')


def _counts(items):
    statuses = Counter(item['status'] for item in items)
    database = Counter(str(item['database_item']).lower() for item in items)
    return {'total': len(items), **{status: statuses[status] for status in _STATUSES},
            'database_items': {key: database[key] for key in ('true', 'false', 'unknown')}}


def _event_outputs(events, objects, properties, chunks, units):
    """Recompile supplied source-bound contracts; never execute their bodies."""
    outputs = defaultdict(list)
    if isinstance(events, dict):
        events = list(events.values())
    _need(isinstance(events, list), 'SCALAR_EVENTS')
    for event in events:
        _need(isinstance(event, dict), 'SCALAR_EVENT')
        uid = event.get('source_unit_id')
        unit, chunk = units.get(uid), chunks.get(uid)
        owner = objects.get(event.get('source_owner_id'))
        block = objects.get(event.get('source_block_id'))
        _need(unit and chunk and owner and block and block['kind'] == 'Block'
              and unit['owner_id'] == owner['id'] and owner['kind'] == 'Trigger'
              and owner['block_id'] == block['id']
              and owner['name'] == event.get('source_event')
              and unit['sha256'] == event.get('source_unit_sha256'), 'SCALAR_SOURCE')

        def resolve(source_block, reference):
            parts = reference.split(' . ')
            if len(parts) == 2 and parts[0] != (source_block['name'] or '').upper():
                return None
            matches = [item for item in objects.values() if item['kind'] == 'Item'
                       and item['block_id'] == source_block['id']
                       and (item['name'] or '').upper() == parts[-1]]
            return matches[0] if len(matches) == 1 else None

        try:
            compiled = _compile(chunk['text'], owner, block, resolve, properties)
        except UnsupportedBehavior:
            compiled = None
        _need(compiled is not None and all(event.get(k) == v for k, v in compiled.items()),
              'SCALAR_CONTRACT')
        parameters = {p['name']: p for p in compiled['parameters']}
        for parameter in compiled['parameters']:
            if parameter.get('kind') != 'current_row_output':
                continue
            inputs = []
            expressions = [a['expression'] for a in compiled['assignments'] if a['target'] == parameter['name']]
            for expression in dict.fromkeys(expressions):
                if expression == 'SYSDATE':
                    inputs.append({'kind': 'database_clock', 'reference': 'SYSDATE', 'data_type': 'DATE'})
                else:
                    binding = parameters[expression]
                    inputs.append({k: binding[k] for k in ('kind', 'reference', 'data_type') if k in binding})
            guard = compiled.get('guard')
            if guard:
                binding = parameters[guard['parameter']]
                inputs.append({k: binding[k] for k in ('kind', 'reference', 'source_item_id', 'data_type') if k in binding})
            outputs[parameter['source_item_id']].append({
                'source_unit_id': uid, 'source_event': event['source_event'],
                'required_bindings': deepcopy(inputs), 'native_event_wired': False,
                'guard': deepcopy(guard),
                'evidence': _pointer('scalar_event_procedures', {'source_unit_id': uid},
                                     'parameters', code_member=event.get('code_member'))})
    return outputs


def _pending_event_note(events):
    reasons = []
    for event in events:
        refs = [binding.get('reference', 'the source current value') for binding in event['required_bindings']
                if binding['kind'] != 'record_status']
        reason = f"The source assigns this field from {', '.join(refs)} during {event['source_event']}"
        guard = event['guard']
        if guard and guard['kind'] == 'record_status':
            reason += f" when SYSTEM.RECORD_STATUS is {guard['equals']}"
        elif guard and guard['kind'] == 'numeric_limit':
            reason += f" after the source numeric limit check ({guard['operator']} {guard['value']})"
        reasons.append(reason + '.')
    return ' '.join(reasons) + ' Its event host and saved-row binding remain pending. The event is not executed.'


def _saved_projection(operation, objects, source_binding):
    """Consume actual saved-workspace metadata, never the blueprint's items."""
    contract, native = operation.get('contract', {}), operation.get('native_target', {})
    block_id = operation.get('source_block_id')
    block = objects.get(block_id)
    _need(block and block['kind'] == 'Block'
          and contract.get('source_block_id') == block_id
          and contract.get('source_module_id') == block['module_id']
          and contract.get('source_binding') == source_binding, 'WORKSPACE_SOURCE')
    _need(native.get('source_block_id') == block_id
          and native.get('source_contract_id') == contract.get('contract_id')
          == operation.get('operation_id')
          and native.get('scope') == 'fox-native-rate-workspace-v1'
          and native.get('entry_page_file') == operation.get('page_file')
          and isinstance(operation.get('page_file'), str), 'WORKSPACE_RECEIPT')
    _need(native.get('durable_synthetic_save') is True
          and native.get('saved_row_table_writes') is True
          and native.get('session_draft_table_writes') is True
          and native.get('business_table_writes') is False
          and native.get('original_interface_enabled') is False
          and native.get('saved_row_key') == ['APP_ID', 'OWNER_NAME', 'SAVED_UUID']
          and native.get('save_request') == 'FOX_RATE_SAVE'
          and native.get('reopen_request') == 'FOX_RATE_REOPEN'
          and native.get('saved_table') and native.get('draft_table'), 'DURABLE_RECEIPT')
    fields = native.get('draft_fields')
    _need(isinstance(fields, list) and fields, 'DRAFT_FIELDS')
    projection = {}
    for index, field in enumerate(fields):
        _need(isinstance(field, dict), 'DRAFT_FIELD')
        item = objects.get(field.get('source_item_id'))
        _need(item and item['kind'] == 'Item' and item['block_id'] == block_id
              and item['id'] not in projection and field.get('column'), 'FIELD_IDENTITY')
        projection[item['id']] = ('saved', _pointer('lov_returns',
            {'operation_id': operation['operation_id']}, f'native_target.draft_fields/{index}',
            page_file=operation['page_file'], column=field['column']))
    parent_fields = native.get('parent_copy_fields', [])
    _need(isinstance(parent_fields, list), 'PARENT_FIELDS')
    if parent_fields:
        parent = native.get('source_parent_binding', {})
        binding = parent.get('binding') or {}
        _need(native.get('parent_copy_immutable') is True
              and native.get('parent_contract_id') == parent.get('contract_id')
              and parent.get('source_binding') == source_binding
              and parent.get('source_block_id') == block_id
              and binding.get('child_block_id') == block_id
              and binding.get('join_pairs') == parent_fields, 'PARENT_RECEIPT')
        for index, field in enumerate(parent_fields):
            item = objects.get(field.get('child_item_id'))
            _need(item and item['kind'] == 'Item' and item['block_id'] == block_id
                  and item['id'] not in projection and field.get('column')
                  and field.get('child_column'), 'PARENT_FIELD_IDENTITY')
            projection[item['id']] = ('parent_linked', _pointer('lov_returns',
                {'operation_id': operation['operation_id']}, f'native_target.parent_copy_fields/{index}',
                page_file=operation['page_file'], column=field['column'],
                source_report_column=field['child_column']))
    return projection


def build_rate_field_coverage(documents, packet, row_lookups, scalar_events):
    """Return a complete source denominator for each generated saved editor.

    Receipts must come from the current generation. ``saved`` means that the
    native draft/saved projection represents the item; it never means a user
    saved data or that original-table persistence has been implemented.
    """
    fresh, chunks = _build(documents)
    supplied = deepcopy(packet)
    if supplied.get('selection_status') == 'NOT_SELECTED':
        supplied.pop('selection_status')
    _need(supplied == fresh, 'SOURCE_CHANGED')
    _need(isinstance(row_lookups, list), 'ROW_LOOKUPS')
    objects, properties = _source_objects(documents, fresh)
    source_files = {obj['id']: entry['source']['name'] for entry in fresh['sources']
                    for obj in entry['facts']['objects']}
    units = {unit['id']: unit for source in fresh['sources'] for unit in source['facts']['code_units']}
    events = _event_outputs(scalar_events, objects, properties,
                            {chunk['code_unit_id']: chunk for chunk in chunks}, units)
    workspaces, seen_workspaces = [], set()
    for operation in row_lookups:
        _need(isinstance(operation, dict), 'ROW_LOOKUP')
        # Companion operations deliberately repeat the anchor's saved flags.
        # They add chooser evidence, never additional workspaces or fields.
        if (operation.get('kind') != 'source_optional_row_lookup'
                or operation.get('durable_synthetic_save') is not True):
            continue
        projection = _saved_projection(operation, objects, fresh['source_binding'])
        block = objects[operation['source_block_id']]
        identity = (block['id'], operation['page_file'])
        if identity in seen_workspaces:
            continue
        seen_workspaces.add(identity)
        items = []
        for source in objects.values():
            if source['kind'] != 'Item' or source['block_id'] != block['id']:
                continue
            props = properties[source['id']]
            database = _database_item(props)
            location = deepcopy(source['location'])
            evidence = [{'source_item_id': source['id'], 'source_file': source_files[source['id']],
                         'source_location': location}]
            required = deepcopy(events.get(source['id'], []))
            validated = props.get('ValidateFromList', '').strip().lower() == 'true'
            lov = props.get('LovName', '').strip()
            if source['id'] in projection:
                status, pointer = projection[source['id']]
                evidence.append(pointer)
                if status == 'parent_linked':
                    note = 'Copied from the selected synthetic parent and retained by Save and Reopen.'
                else:
                    note = 'Included in the native synthetic draft and saved-row projection.'
                    if database is False:
                        note += ' This was a non-database display/control item in the original form.'
                    elif database == 'unknown':
                        note += ' The original database-item property is unknown.'
            elif required:
                status = 'pending'
                note = _pending_event_note(required)
            elif validated:
                status = 'pending'
                note = ('The source requires list validation, but has no effective list name; '
                        'the list or assigning code remains unresolved. Free-text entry is not established.'
                        if not lov else
                        'The source requires list validation; its declared list or assigning code has no '
                        'native saved-field binding. Free-text entry is not established.')
            elif props.get('ItemType', '').strip().lower() in {
                    'push button', 'image', 'chart', 'ole container', 'bean area'}:
                status = 'control'
                note = 'Original display/control item with no native saved-field receipt.'
            else:
                status = 'pending'
                note = 'No native draft/saved-field receipt represents this source item.'
                if database == 'unknown':
                    note += ' Its original database-item property is unknown.'
            if required:
                evidence.extend(event['evidence'] for event in required)
            items.append({'id': source['id'], 'name': source['name'],
                          'label': props.get('Prompt') or props.get('Label') or source['name'],
                          'source_file': source_files[source['id']],
                          'source_line': location.get('line'), 'source_location': location,
                          'database_item': database, 'status': status, 'note': note,
                          'validate_from_list': validated, 'lov_name': lov or None,
                          'pending_events': required, 'evidence': evidence})
        workspaces.append({'block_id': block['id'], 'block': block['name'],
                           'page_file': operation['page_file'], 'counts': _counts(items), 'items': items})
    return {'schema_version': 1, 'scope': SCOPE, 'source_binding': fresh['source_binding'],
            'workspaces': workspaces, 'counts': _counts([item for w in workspaces for item in w['items']]),
            'coverage_boundary': 'Generated synthetic field projection only; original database saves and source event execution are not established.',
            'source_events_executed': False, 'runtime_verified': False, 'business_accepted': False}
