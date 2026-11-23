"""Pure synthetic source/receipt coverage checks, without an Oracle runtime."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from fox.forms_behavior_plan import _source_objects
from fox.forms_event_callables import build_event_callables
from fox.forms_rate_field_coverage import build_rate_field_coverage
from fox.forms_understanding_packet import _build, generation_sources


SOURCE = b'''<FormModule Name="DELIVERY">
<Block Name="ACCOUNT"><Item Name="CODE" DatabaseItem="true"/></Block>
<Block Name="TARIFF">
 <Item Name="PATH_CODE" Prompt="Path" DatabaseItem="true" LovName="PATH_LIST" ValidateFromList="true"/>
 <Item Name="FROM_CITY" ItemType="Display Item" DatabaseItem="false"/>
 <Item Name="TO_CITY" ItemType="Display Item" DatabaseItem="false"/>
 <Item Name="TIER" DatabaseItem="true" LovName="TIER_LIST" ValidateFromList="true"/>
 <Item Name="UNIT" DatabaseItem="true" LovName="UNIT_LIST" ValidateFromList="true"/>
 <Item Name="AMOUNT" DatabaseItem="true" DataType="Number">
  <Trigger Name="POST-CHANGE" TriggerText="BEGIN IF :SYSTEM.RECORD_STATUS = 'CHANGED' THEN :TOUCHED_BY := :GLOBAL.LOGIN; :TOUCHED_ON := SYSDATE; END IF; END;"/>
 </Item>
 <Item Name="ACCOUNT_CODE" DatabaseItem="true"/>
 <Item Name="BRANCH_CODE" DatabaseItem="true"/>
 <Item Name="AREA" DatabaseItem="true" ValidateFromList="true"/>
 <Item Name="CREATED_BY" DatabaseItem="true" DataType="Char"/>
 <Item Name="CREATED_ON" DatabaseItem="true" DataType="Datetime"/>
 <Item Name="TOUCHED_BY" DatabaseItem="true" DataType="Char"/>
 <Item Name="TOUCHED_ON" DatabaseItem="true" DataType="Datetime"/>
 <Trigger Name="WHEN-CREATE-RECORD" TriggerText="BEGIN :CREATED_BY := :GLOBAL.LOGIN; :CREATED_ON := SYSDATE; END;"/>
</Block>
<LOV Name="PATH_LIST"/><LOV Name="TIER_LIST"/><LOV Name="UNIT_LIST"/>
</FormModule>'''


def fixture(raw=SOURCE):
    documents = [('synthetic.xml', raw)]
    packet, chunks = _build(documents)
    objects, _ = _source_objects(documents, packet)
    block = next(o for o in objects.values() if o['kind'] == 'Block' and o['name'] == 'TARIFF')
    by_name = {o['name']: o for o in objects.values() if o['kind'] == 'Item' and o['block_id'] == block['id']}
    names = list(by_name)
    fields = [{'source_item_id': by_name[name]['id'], 'source_name': name, 'column': f'F{i:03d}'}
              for i, name in enumerate(names[:6], 1)]
    pairs = [{'child_item_id': by_name[name]['id'], 'column': f'K{i:03d}', 'child_column': f'F_REPORT_{i}'}
             for i, name in enumerate(names[6:8], 1)]
    parent = {'contract_id': 'parent-test', 'source_binding': packet['source_binding'],
              'source_block_id': block['id'], 'binding': {'child_block_id': block['id'], 'join_pairs': pairs}}
    native = {'scope': 'fox-native-rate-workspace-v1', 'source_block_id': block['id'],
              'source_contract_id': 'rate-test', 'entry_page_file': 'pages/editor.apx',
              'durable_synthetic_save': True, 'saved_row_table_writes': True,
              'session_draft_table_writes': True, 'business_table_writes': False,
              'original_interface_enabled': False, 'saved_row_key': ['APP_ID', 'OWNER_NAME', 'SAVED_UUID'],
              'save_request': 'FOX_RATE_SAVE', 'reopen_request': 'FOX_RATE_REOPEN',
              'saved_table': 'FOX_TEST_SAVED', 'draft_table': 'FOX_TEST_DRAFT', 'draft_fields': fields,
              'parent_copy_fields': pairs, 'parent_copy_immutable': True,
              'parent_contract_id': parent['contract_id'], 'source_parent_binding': parent}
    operation = {'kind': 'source_optional_row_lookup', 'operation_id': 'rate-test',
                 'source_block_id': block['id'], 'page_file': 'pages/editor.apx',
                 'durable_synthetic_save': True, 'native_target': native,
                 'contract': {'contract_id': 'rate-test', 'source_binding': packet['source_binding'],
                              'source_module_id': block['module_id'], 'source_block_id': block['id']}}
    coverage = [{'source_unit_id': u['id'], 'source_owner_id': u['owner_id'],
                 'source_unit_sha256': u['sha256'], 'status': 'unimplemented'}
                for source in packet['sources'] for u in source['facts']['code_units']]
    events, _ = build_event_callables(documents, packet, chunks, coverage, 'synthetic-coverage')
    assert len(events) == 2
    return documents, packet, [operation], events


def test_complete_denominator_and_no_duplicate_attribution_across_companions():
    args = fixture()
    anchor = args[2][0]
    for name in ('tier', 'unit'):
        args[2].append({**deepcopy(anchor), 'kind': 'source_companion_row_lookup', 'operation_id': name})
    before = deepcopy(args)
    with generation_sources(args[0]):
        result = build_rate_field_coverage(*args)
        assert result == build_rate_field_coverage(*args)
    assert args == before
    workspace, = result['workspaces']
    assert workspace['counts'] == {'total': 13, 'saved': 6, 'parent_linked': 2, 'pending': 5, 'control': 0,
                                    'database_items': {'true': 11, 'false': 2, 'unknown': 0}}
    assert len({item['id'] for item in workspace['items']}) == 13
    assert result['counts'] == workspace['counts']
    fields = {item['name']: item for item in workspace['items']}
    assert fields['PATH_CODE']['label'] == 'Path'
    assert fields['PATH_CODE']['source_line'] == 4
    assert fields['FROM_CITY']['database_item'] is False
    assert fields['FROM_CITY']['status'] == 'saved'
    assert 'non-database' in fields['FROM_CITY']['note']
    assert fields['PATH_CODE']['database_item'] is True
    assert fields['ACCOUNT_CODE']['status'] == 'parent_linked'
    assert fields['ACCOUNT_CODE']['evidence'][1]['column'] == 'K001'
    assert fields['AREA']['status'] == 'pending'
    assert 'no effective list name' in fields['AREA']['note']
    assert 'Free-text' in fields['AREA']['note']
    for name in ('CREATED_BY', 'CREATED_ON', 'TOUCHED_BY', 'TOUCHED_ON'):
        assert fields[name]['status'] == 'pending'
        event, = fields[name]['pending_events']
        kinds = {b['kind'] for b in event['required_bindings']}
        assert ('forms_global' in kinds) == name.endswith('BY')
        assert ('database_clock' in kinds) == name.endswith('ON')
        assert ('record_status' in kinds) == name.startswith('TOUCHED')
        assert ('SYSDATE' in fields[name]['note']) == name.endswith('ON')
        assert ('GLOBAL.LOGIN' in fields[name]['note']) == name.endswith('BY')
        assert ('CHANGED' in fields[name]['note']) == name.startswith('TOUCHED')
        assert event['native_event_wired'] is False
        assert any(e.get('section') == 'scalar_event_procedures' for e in fields[name]['evidence'])
    assert not result['runtime_verified'] and not result['business_accepted']
    assert not result['source_events_executed']


def test_nonexistent_declared_list_stays_pending_without_missing_file_assertion():
    raw = SOURCE.replace(b'Name="AREA"', b'Name="AREA" LovName="UNRESOLVED_LIST"')
    result = build_rate_field_coverage(*fixture(raw))
    area = next(i for i in result['workspaces'][0]['items'] if i['name'] == 'AREA')
    assert area['status'] == 'pending' and area['lov_name'] == 'UNRESOLVED_LIST'
    assert 'list or assigning code' in area['note'] and 'Free-text' in area['note']
    assert 'missing' not in area['note'].lower() and 'file' not in area['note'].lower()


def test_structural_items_and_non_durable_operations_cannot_establish_saved_fields():
    args = fixture()
    anchor = args[2][0]
    anchor['items'] = [{'source_item_id': i['id']} for s in args[1]['sources']
                       for i in s['facts']['objects'] if i['kind'] == 'Item']
    # A display value outside the saved projection remains an unresolved value.
    anchor['native_target']['draft_fields'].pop(1)
    result = build_rate_field_coverage(*args)
    assert result['counts']['saved'] == 5 and result['counts']['pending'] == 6
    anchor['durable_synthetic_save'] = False
    assert build_rate_field_coverage(*args)['workspaces'] == []


@pytest.mark.parametrize('change,reason', [
    (lambda a: a[1].update(source_binding='stale'), 'SOURCE_CHANGED'),
    (lambda a: a[2][0]['contract'].update(source_binding='stale'), 'WORKSPACE_SOURCE'),
    (lambda a: a[2][0]['native_target'].update(saved_row_table_writes=False), 'DURABLE_RECEIPT'),
    (lambda a: a[2][0]['native_target'].update(draft_fields=[]), 'DRAFT_FIELDS'),
    (lambda a: a[2][0]['native_target']['draft_fields'].append(a[2][0]['native_target']['draft_fields'][0]), 'FIELD_IDENTITY'),
    (lambda a: next(iter(a[3].values())).update(source_unit_sha256='stale'), 'SCALAR_SOURCE'),
    (lambda a: next(iter(a[3].values()))['assignments'][0].update(expression='SYSDATE'), 'SCALAR_CONTRACT'),
])
def test_stale_or_ambiguous_receipts_fail_closed(change, reason):
    args = fixture()
    change(args)
    with pytest.raises(ValueError, match='RATE_FIELD_COVERAGE_' + reason):
        build_rate_field_coverage(*args)


def test_unknown_source_properties_are_preserved_and_no_template_names_are_required():
    root = ET.fromstring(SOURCE)
    root.find("./Block/Item").set('DatabaseItem', 'false')
    root.find("./Block[@Name='TARIFF']/Item[@Name='UNIT']").attrib.pop('DatabaseItem')
    raw = ET.tostring(root).replace(b'UNIT', b'MEASURE')
    result = build_rate_field_coverage(*fixture(raw))
    field = next(i for i in result['workspaces'][0]['items'] if i['name'] == 'MEASURE')
    assert field['database_item'] == 'unknown' and 'unknown' in field['note']
    assert result['counts']['database_items']['unknown'] == 1


def test_duplicate_anchors_deduplicate_and_another_editor_on_same_block_is_allowed():
    args = fixture()
    args[2].append(deepcopy(args[2][0]))
    assert len(build_rate_field_coverage(*args)['workspaces']) == 1
    args[2][1]['page_file'] = 'pages/other-editor.apx'
    args[2][1]['native_target']['entry_page_file'] = 'pages/other-editor.apx'
    assert len(build_rate_field_coverage(*args)['workspaces']) == 2


def test_non_database_value_items_and_controls_are_distinct():
    raw = SOURCE.replace(b'<Item Name="AREA"', b'<Item Name="DISPLAY_VALUE" DatabaseItem="false"/>\n <Item Name="GO" ItemType="Push Button"/>\n <Item Name="AREA"')
    fields = {i['name']: i for i in build_rate_field_coverage(*fixture(raw))['workspaces'][0]['items']}
    assert fields['DISPLAY_VALUE']['database_item'] is False
    assert fields['DISPLAY_VALUE']['status'] == 'pending'
    assert fields['GO']['status'] == 'control'
