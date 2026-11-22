"""Actual source compilation boundaries; no Oracle execution is claimed."""
from copy import deepcopy
import os
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from fox.forms_lov_return import apply_lov_returns
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_route_lookup_plan import compile_row_lookups
from fox.forms_understanding_packet import _build, generation_sources
from fox.xml_mapping import _blueprint
from forms2apex import native_blueprint, native_record_groups as groups


SOURCE = b'''<FormModule Name="SHIPPING">
<Block Name="HEADER" DatabaseBlock="true"><Item Name="LABEL" ItemType="Text Item" DataType="Char" MaximumLength="30"/></Block>
<Block Name="LINES" QueryDataSourceName="LINE_SOURCE">
 <Item Name="VIA" ItemType="Text Item" ColumnName="VIA" MaximumLength="20" DataLengthSemantics="BYTE" LovName="VIA_PICK" ValidateFromList="false" Required="true">
  <Trigger Name="POST-CHANGE" TriggerText="BEGIN NULL; END;"/>
 </Item>
 <Item Name="START_AT" ItemType="Display Item" DatabaseItem="false" MaximumLength="10" DataLengthSemantics="BYTE"/>
 <Item Name="END_AT" ItemType="Display Item" DatabaseItem="false" MaximumLength="10" DataLengthSemantics="BYTE"/>
 <Trigger Name="WHEN-CREATE-RECORD" TriggerText="BEGIN :VIA := NULL; END;"/>
</Block>
<LOV Name="VIA_PICK" RecordGroupName="CHOICES">
 <LOVColumnMapping Name="CODE" ReturnItem="LINES.VIA"/>
 <LOVColumnMapping Name="DEPARTURE" ReturnItem="LINES.START_AT"/>
 <LOVColumnMapping Name="ARRIVAL" ReturnItem="LINES.END_AT"/>
</LOV>
<RecordGroup Name="CHOICES" RecordGroupQuery="SELECT NETWORK.CODE, NETWORK.DEPARTURE, NETWORK.ARRIVAL FROM NETWORK WHERE NETWORK.STATE = '1'">
 <RecordGroupColumn Name="CODE" ColumnDataType="Character" MaximumLength="20"/>
 <RecordGroupColumn Name="DEPARTURE" ColumnDataType="Character" MaximumLength="10"/>
 <RecordGroupColumn Name="ARRIVAL" ColumnDataType="Character" MaximumLength="10"/>
</RecordGroup>
</FormModule>'''

TYPED_BODY = """BEGIN
 SELECT NETWORK.DEPARTURE, NETWORK.ARRIVAL INTO :LINES.START_AT, :LINES.END_AT
 FROM NETWORK WHERE NETWORK.CODE = :LINES.VIA;
EXCEPTION WHEN NO_DATA_FOUND THEN MESSAGE('Invalid routing'); RAISE FORM_TRIGGER_FAILURE; END;"""


def typed_source(body=TYPED_BODY):
    root = ET.fromstring(SOURCE)
    next(n for n in root.iter() if n.get('Name') == 'POST-CHANGE').set('TriggerText', body)
    return ET.tostring(root)


def test_typed_post_change_full_source_identity_and_unfiltered_query_are_proved():
    args = prepare(typed_source())
    c, = compile_row_lookups(*args)
    t = c['typed_lookup']
    units = {u['id']:u for s in args[1]['sources'] for u in s['facts']['code_units']}
    assert t['source_unit_sha256'] == units[t['source_unit_id']]['sha256']
    assert t['source_event'] == 'POST-CHANGE' and t['source_table'] == 'NETWORK'
    assert t['key_column'] == 'CODE' and not t['active_filter_applied']
    assert t['no_data_message'] == 'Invalid routing' and t['no_data_failure'] == 'FORM_TRIGGER_FAILURE'
    assert [a['source_column'] for a in t['assignments']] == ['DEPARTURE', 'ARRIVAL']
    assert t['source_unit_id'] not in c['omitted_source_unit_ids']
    assert 'WHEN-CREATE-RECORD' in {u['source_event'] for u in c['unexecuted_source_events']}


@pytest.mark.parametrize('old,new', [
    ('FROM NETWORK', 'FROM OTHER'),
    ('NETWORK.CODE = :LINES.VIA', 'NETWORK.OTHER = :LINES.VIA'),
    ('NETWORK.CODE = :LINES.VIA', 'NETWORK.CODE = :HEADER.LABEL'),
    (':LINES.END_AT', ':HEADER.LABEL'),
    (':LINES.END_AT', ':LINES.START_AT'),
    ('NETWORK.ARRIVAL INTO', 'NETWORK.CODE INTO'),
    (';\nEXCEPTION', " AND NETWORK.STATE='1';\nEXCEPTION"),
    ('RAISE FORM_TRIGGER_FAILURE;', 'NULL;'),
    ("MESSAGE('Invalid routing')", "MESSAGE(:LINES.VIA)"),
    ('END;', 'NULL; END;'),
])
def test_nonmatching_event_gates_caller_mutation_without_losing_052_chooser(old, new):
    assert old in TYPED_BODY
    c, = compile_row_lookups(*prepare(typed_source(TYPED_BODY.replace(old,new))))
    assert not c.get('typed_lookup') and c['typed_lookup_gap']
    assert len(c['returns']) == 3 and c['query_already_counted']


def test_unrelated_fields_do_not_become_typed_targets_and_safe_literal_is_decoded():
    raw = typed_source(TYPED_BODY.replace('Invalid routing', "Invalid ''route'' & :value <tag>"))
    c, = compile_row_lookups(*prepare(raw))
    assert c['typed_lookup']['no_data_message'] == "Invalid 'route' & :value <tag>"
    assert {a['field']['source_name'] for a in c['typed_lookup']['assignments']} == {'START_AT','END_AT'}


def test_old_noop_fixture_never_claims_typed_behavior():
    c, = compile_row_lookups(*prepare())
    assert 'typed_lookup' not in c and 'typed_lookup_gap' not in c


def prepare(raw=SOURCE, *, name='shipping.xml', project_id='row-lookup-test'):
    docs = [(name, raw)]
    with generation_sources(docs):
        packet, chunks = _build(docs)
        spec = build_native_prototype_plan(docs, _blueprint(packet), project_id=project_id,
            project_name='Row lookup', approved_policy_id=POLICY_ID)['rendering_spec']
        files = {n: t.encode() for n, t in native_blueprint.render_native_blueprint(spec).items()}
        trace = native_blueprint.prototype_trace(spec)
        objects = {o['id']: o for entry in packet['sources'] for o in entry['facts']['objects']}
        for block in trace['blocks']:
            block['source_module_id'] = objects[block['source_block_id']]['module_id']
        files, group = groups.apply_record_groups(docs, packet, chunks, trace, files)
        files['fox-package/record-group-receipt.json'] = groups._json(group)
        files['fox-package/supporting-schema.sql'] = native_blueprint.render_prototype_schema(spec).encode()
        files['fox-package/sources/' + name] = raw
        files, lov = apply_lov_returns(docs, packet, chunks, trace, files)
        files['fox-package/lov-return-receipt.json'] = groups._json(lov)
    return docs, packet, chunks, trace, files, group, lov


def change(node_name, *, kind=None, **properties):
    root = ET.fromstring(SOURCE)
    node = next(n for n in root.iter() if n.get('Name') == node_name and (kind is None or n.tag == kind))
    for key, value in properties.items():
        if value is None:
            node.attrib.pop(key, None)
        else:
            node.set(key, value)
    return ET.tostring(root)


@pytest.mark.parametrize('renamed', [False, True])
def test_complete_source_contract_is_deterministic_and_name_independent(renamed):
    raw = SOURCE
    if renamed:
        for a, b in [(b'SHIPPING', b'ORDERING'), (b'LINES', b'POSITIONS'), (b'VIA', b'PATH'),
                     (b'CHOICES', b'SOURCE_OPTIONS'), (b'NETWORK', b'GRAPH'), (b'STATE', b'IS_READY'),
                     (b'START_AT', b'LEFT_END'), (b'END_AT', b'RIGHT_END')]:
            raw = raw.replace(a, b)
    args = prepare(raw)
    before = deepcopy(args)
    contract, = compile_row_lookups(*args)
    assert compile_row_lookups(*args) == [contract] and args == before
    assert contract['source_caller_item_id'] == contract['caller']['source_item_id']
    assert contract['caller_source_table'] == 'LINE_SOURCE'
    assert len(contract['fields']) == len(contract['returns']) == len(contract['columns']) == 3
    assert [f['slot'] for f in contract['fields']] == [1, 2, 3]
    assert all(f['source_data_type_omitted'] for f in contract['fields'])
    assert all(f['data_type'] == 'VARCHAR2' and f['length_semantics'] == 'BYTE' for f in contract['fields'])
    assert [f['max_length'] for f in contract['fields']] == [20, 10, 10]
    assert [f['direct_edit_allowed'] for f in contract['fields']] == [True, False, False]
    assert all(f['programmatic_return_allowed'] for f in contract['returns'])
    assert contract['query_already_counted'] and contract['partial_scope_required']
    assert contract['source_block_id'] not in {b['source_block_id'] for b in args[3]['blocks']}
    assert {u['source_event'] for u in contract['unexecuted_source_events']} == {'POST-CHANGE', 'WHEN-CREATE-RECORD'}
    assert all(not u['native_event_wired'] for u in contract['unexecuted_source_events'])
    assert contract['active_predicate']['right'] == {'kind': 'string', 'value': '1'}
    assert not any(contract[k] for k in ['source_query_executed', 'customer_table_writes',
        'synthetic_table_writes', 'runtime_verified', 'business_accepted', 'original_interface_enabled'])


@pytest.mark.parametrize('node,properties', [
    ('LINES', {'QueryDataSourceName': None}),
    ('LINES', {'DatabaseBlock': 'false'}),
    ('LINES', {'QueryDataSourceType': 'PROCEDURE'}),
    ('LINES', {'UpdateAllowed': 'false'}),
    ('VIA', {'ValidateFromList': 'true'}),
    ('VIA', {'ValidateFromList': None}),
    ('VIA', {'Enabled': 'false'}),
    ('VIA', {'UpdateAllowed': 'false'}),
    ('START_AT', {'MaximumLength': None}),
    ('START_AT', {'MaximumLength': '0'}),
    ('START_AT', {'DataLengthSemantics': 'CHAR'}),
    ('START_AT', {'DataType': 'Number'}),
    ('START_AT', {'CalculateMode': 'Formula', 'Formula': '1'}),
    ('START_AT', {'Required': 'unknown'}),
    ('START_AT', {'UpdateAllowed': 'false'}),
    ('DEPARTURE', {'ColumnDataType': 'Number'}),
    ('DEPARTURE', {'ColumnDataType': None}),
    ('DEPARTURE', {'MaximumLength': None}),
])
def test_no_contract_for_unproven_source_fields_or_permissions(node, properties):
    assert compile_row_lookups(*prepare(change(node, kind='RecordGroupColumn' if node == 'DEPARTURE' else None, **properties))) == []


@pytest.mark.parametrize('old,new', [
    (b'ReturnItem="LINES.END_AT"', b'ReturnItem="LINES.START_AT"'),
    (b'ReturnItem="LINES.END_AT"', b'ReturnItem="HEADER.LABEL"'),
    (b'ReturnItem="LINES.END_AT"', b'ReturnItem="END_AT"'),
    (b'<LOVColumnMapping Name="ARRIVAL" ReturnItem="LINES.END_AT"/>', b''),
    (b'WHERE NETWORK.STATE = \'1\'', b'WHERE NETWORK.STATE = \'0\''),
    (b'WHERE NETWORK.STATE = \'1\'', b'WHERE NETWORK.STATE &lt;&gt; \'0\''),
    (b'WHERE NETWORK.STATE = \'1\'', b'WHERE NETWORK.STATE = :VIA'),
    (b'WHERE NETWORK.STATE = \'1\'', b'WHERE NETWORK.STATE = \'1\' AND NETWORK.CODE = \'X\''),
    (b'FROM NETWORK WHERE', b'FROM NETWORK, EXTRA WHERE'),
    (b'NETWORK.ARRIVAL FROM', b'OTHER.ARRIVAL FROM'),
    (b'NETWORK.ARRIVAL FROM', b'NETWORK.CODE FROM'),
])
def test_no_partial_return_or_broadened_query_contract(old, new):
    assert old in SOURCE
    assert compile_row_lookups(*prepare(SOURCE.replace(old, new))) == []


@pytest.mark.parametrize('trigger', [
    '<Trigger Name="WHEN-NEW-RECORD-INSTANCE" TriggerText="BEGIN NULL; END;"/>',
    '<Trigger Name="OTHER" TriggerText="BEGIN SET_ITEM_PROPERTY(\'VIA\',ENABLED,PROPERTY_FALSE); END;"/>',
    '<Trigger Name="OTHER" TriggerText="BEGIN SET_BLOCK_PROPERTY(\'LINES\',UPDATE_ALLOWED,PROPERTY_FALSE); END;"/>',
    '<Trigger Name="OTHER" TriggerText="BEGIN SET_ITEM_PROPERTY(:TARGET,ENABLED,PROPERTY_FALSE); END;"/>',
])
def test_unresolved_dynamic_policy_stays_a_normal_lov_gap(trigger):
    raw = SOURCE.replace(b'</FormModule>', trigger.encode() + b'</FormModule>')
    args = prepare(raw)
    assert args[-1]['gaps'] and compile_row_lookups(*args) == []


@pytest.mark.parametrize('target', ['source', 'chunk', 'trace', 'schema', 'group', 'lov', 'original'])
def test_changed_global_proofs_raise_instead_of_silently_emitting(target):
    args = list(prepare())
    if target == 'source': args[1]['source_binding'] = 'bad'
    elif target == 'chunk': args[2][0]['text'] += ' '
    elif target == 'trace': args[3]['blocks'][0]['name'] = 'bad'
    elif target == 'schema': args[4]['fox-package/supporting-schema.sql'] += b'\n'
    elif target == 'group':
        args[5]['gaps'] = []
        args[5]['generated_operations'][0]['query']['predicates'][0]['right']['value'] = '0'
        args[4]['fox-package/record-group-receipt.json'] = groups._json(args[5])
    elif target == 'lov':
        args[6]['gaps'][0]['reason'] = 'invented'
        args[4]['fox-package/lov-return-receipt.json'] = groups._json(args[6])
    else: args[4]['fox-package/sources/shipping.xml'] += b'\n'
    with pytest.raises(ValueError, match='ROW_LOOKUP_'):
        compile_row_lookups(*args)


def test_existing_mapped_callers_remain_owned_by_normal_adapter():
    raw = SOURCE.replace(b'QueryDataSourceName="LINE_SOURCE"', b'QueryDataSourceName="LINE_SOURCE" DatabaseBlock="true"')
    raw = raw.replace(b'ValidateFromList="false"', b'ValidateFromList="true"').replace(
        b'ItemType="Text Item" ColumnName="VIA"', b'ItemType="Text Item" DataType="Char" ColumnName="VIA"')
    assert compile_row_lookups(*prepare(raw)) == []


def test_same_source_in_two_projects_has_isolated_contract_and_supporting_objects():
    from fox.forms_route_lookup_native import render_row_lookup
    first_args = prepare(project_id='project-alpha')
    second_args = prepare(project_id='project-beta')
    first, = compile_row_lookups(*first_args)
    second, = compile_row_lookups(*second_args)
    assert first['source_binding'] == second['source_binding']
    assert first['project_id'] == 'project-alpha' and second['project_id'] == 'project-beta'
    assert first['contract_id'] != second['contract_id']
    a, b = [render_row_lookup(c, 8900) for c in (first, second)]
    assert a['metadata']['draft_table'] != b['metadata']['draft_table']
    assert a['metadata']['catalog_table'] != b['metadata']['catalog_table']
    assert a['metadata']['draft_table'].encode() not in b['supporting_sql']
    assert a['metadata']['catalog_table'].encode() not in b['supporting_sql']
    # A submitted project label cannot borrow another project's trace or DDL.
    first_args[3]['project_id'] = 'project-beta'
    with pytest.raises(ValueError, match='ROW_LOOKUP_FRESH_SYNTHETIC_TRACE_REQUIRED'):
        compile_row_lookups(*first_args)
    first_args[3]['blocks'] = second_args[3]['blocks']
    with pytest.raises(ValueError, match='ROW_LOOKUP_SYNTHETIC_SCHEMA_CHANGED'):
        compile_row_lookups(*first_args)


def test_normal_local_generation_marker_is_inert_but_not_transfer_selection():
    args = prepare()
    expected = compile_row_lookups(*args)
    args[1]['selection_status'] = 'NOT_SELECTED'
    assert compile_row_lookups(*args) == expected
    for status in ['SCOPED_CONTENT_SELECTED', 'METADATA_ONLY', '', None]:
        args[1]['selection_status'] = status
        with pytest.raises(ValueError, match='ROW_LOOKUP_SOURCE_CHANGED'):
            compile_row_lookups(*args)
    args[1]['selection_status'] = 'NOT_SELECTED'
    args[1]['transfer_authorized'] = True
    with pytest.raises(ValueError, match='ROW_LOOKUP_SOURCE_CHANGED'):
        compile_row_lookups(*args)


def test_non_edit_coordination_is_unexecuted_and_never_grants_access():
    trigger = b'''<ProgramUnit Name="COORDINATE" ProgramUnitType="Procedure" ProgramUnitText="PROCEDURE COORDINATE IS BEGIN SET_BLOCK_PROPERTY(detail, COORDINATION_STATUS, NON_COORDINATED); END;"/>'''
    assert len(compile_row_lookups(*prepare(SOURCE.replace(b'</FormModule>', trigger + b'</FormModule>')))) == 1
    changed = trigger.replace(b'COORDINATION_STATUS', b'UPDATE_ALLOWED')
    assert compile_row_lookups(*prepare(SOURCE.replace(b'</FormModule>', changed + b'</FormModule>'))) == []


def test_optional_project_local_original_source():
    """Operator opt-in keeps original identities and local paths out of source."""
    value = os.environ.get('ROW_LOOKUP_SOURCE_XML')
    if not value:
        pytest.skip('Set ROW_LOOKUP_SOURCE_XML for exact project-local source proof.')
    source = Path(value)
    args = prepare(source.read_bytes(), name=source.name)
    contracts = compile_row_lookups(*args)
    assert len(contracts) == 1
    c = contracts[0]
    assert len(c['returns']) == 3 and len([f for f in c['returns'] if f['display_only']]) == 2
    from fox.forms_behavior_plan import _source_objects
    _, properties = _source_objects(args[0], args[1])
    for field in c['fields']:
        declared = properties[field['source_item_id']].get('DataType')
        assert field['source_data_type_omitted'] == (not declared)
        assert not declared or declared.upper() in {'CHAR', 'VARCHAR2'}
    assert c['typed_lookup']['source_event'] == 'POST-CHANGE'
    assert 'WHEN-CREATE-RECORD' in {u['source_event'] for u in c['unexecuted_source_events']}
    assert args[-1]['gaps'] # ordinary unsupported LOV callers remain visible
    assert len(args[-2]['generated_operations']) == 18 and not args[-2]['gaps']
