"""Small synthetic source checks; no Oracle or source-event execution claim."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from forms2apex import native_blueprint
from fox.forms_display_projection import build_display_projections
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_understanding_packet import _build, generation_sources
from fox.xml_mapping import _blueprint


ASSIGNMENT = ":DISPLAY_CODE := :AREA || :ZONE || TO_CHAR(:CHANGED_AT, 'RR') || :ROWS.CODE;"
SOURCE = b'''<FormModule Name="ACCOUNTS">
<Canvas Name="MAIN" CanvasType="Tab"><TabPage Name="GENERAL"/></Canvas>
<Block Name="ROWS" DatabaseBlock="true" QueryDataSourceName="ACCOUNTS">
 <Item Name="AREA" ColumnName="AREA_CODE" ItemType="Display Item" DataType="Char" MaximumLength="2" DatabaseItem="true"/>
 <Item Name="ZONE" ColumnName="ZONE_CODE" ItemType="Text Item" DataType="Char" MaximumLength="2" DatabaseItem="true"/>
 <Item Name="CHANGED_AT" ColumnName="CHANGED_AT" ItemType="Text Item" DataType="Date" DatabaseItem="true"/>
 <Item Name="CODE" ColumnName="ACCOUNT_CODE" ItemType="Text Item" DataType="Char" MaximumLength="10" DatabaseItem="true">
  <Trigger Name="POST-CHANGE" TriggerText=":DISPLAY_CODE := :AREA || :ZONE || TO_CHAR(:CHANGED_AT, 'RR') || :ROWS.CODE;"/>
 </Item>
 <Item Name="DISPLAY_CODE" ItemType="Display Item" DataType="Char" MaximumLength="30" DatabaseItem="false" CanvasName="MAIN" TabPageName="GENERAL"/>
</Block></FormModule>'''.replace(b'DataType="Char" MaximumLength=', b'DataType="Char" DataLengthSemantics="BYTE" MaximumLength=')


def prepare(raw=SOURCE):
    documents = [('accounts.xml', raw)]
    with generation_sources(documents):
        packet, chunks = _build(documents)
        spec = build_native_prototype_plan(documents, _blueprint(packet), project_id='display-test',
            project_name='Display test', approved_policy_id=POLICY_ID)['rendering_spec']
        trace = native_blueprint.prototype_trace(spec)
        objects = {o['id']: o for entry in packet['sources'] for o in entry['facts']['objects']}
        for block in trace['blocks']:
            block['source_module_id'] = objects[block['source_block_id']]['module_id']
    return documents, packet, chunks, trace


def compile_source(raw=SOURCE):
    return build_display_projections(*prepare(raw))


def changed(*, assignment=None, writer=None, **properties):
    root = ET.fromstring(SOURCE)
    target = root.find("./Block/Item[@Name='DISPLAY_CODE']")
    for name, value in properties.items():
        if value is None:
            target.attrib.pop(name, None)
        else:
            target.set(name, value)
    if assignment is not None:
        root.find('./Block/Item/Trigger').set('TriggerText', assignment)
    if writer is not None:
        ET.SubElement(root.find('./Block'), 'Trigger', Name='KEY-COMMIT', TriggerText=writer)
    return ET.tostring(root)


def test_deterministic_complete_source_identity_and_source_order_bindings():
    args = prepare()
    before = deepcopy(args)
    receipt = build_display_projections(*args)
    assert args == before
    assert build_display_projections(*args) == receipt
    assert receipt['gaps'] == []
    projection, = receipt['projections']
    assert projection['qualified_target'] == 'ROWS.DISPLAY_CODE'
    assert projection['references'] == ['ROWS.AREA', 'ROWS.ZONE', 'ROWS.CHANGED_AT', 'ROWS.CODE']
    assert [f['source_column'] for f in projection['bindings']] == ['AREA_CODE', 'ZONE_CODE', 'CHANGED_AT', 'ACCOUNT_CODE']
    assert projection['expression']['maximum_bytes'] == 16
    assert projection['target_maximum_length'] == 30
    assert projection['report_file'].endswith('.apx')
    assert len(projection['whole_source_units']) == 1
    assert projection['supporting_source_units'] == []
    assert projection['synthetic_read_projection']
    assert not projection['native_event_wired'] and not projection['source_event_timing_preserved']
    assert not receipt['customer_table_writes'] and not receipt['runtime_verified'] and not receipt['business_accepted']


def test_equal_conditional_writer_is_supporting_only_and_not_event_conversion():
    result = compile_source(changed(writer='BEGIN IF :CODE IS NOT NULL THEN ' + ASSIGNMENT + ' END IF; COMMIT; END;'))
    projection, = result['projections']
    assert len(projection['whole_source_units']) == len(projection['supporting_source_units']) == 1
    assert not projection['supporting_source_units'][0]['native_event_wired']


@pytest.mark.parametrize('assignment', [ASSIGNMENT, 'BEGIN ' + ASSIGNMENT + ' END;',
    '-- :DISPLAY_CODE := bad;\n' + ASSIGNMENT])
def test_whole_assignment_wrappers_and_comments(assignment):
    assert len(compile_source(changed(assignment=assignment))['projections']) == 1


@pytest.mark.parametrize('properties, reason', [
    ({'Visible': 'false'}, 'HIDDEN'), ({'CanvasName': 'UNKNOWN'}, 'CANVAS'),
    ({'TabPageName': 'UNKNOWN'}, 'TAB_OWNERSHIP'), ({'MaximumLength': '15'}, 'TARGET_LENGTH'),
    ({'MaximumLength': None}, 'EXPLICIT_LENGTH'), ({'Formula': ':AREA'}, 'OTHER_VALUE_SOURCE'),
    ({'CopyValueFromItem': 'ROWS.CODE'}, 'OTHER_VALUE_SOURCE'),
    ({'InitializeValue': 'X'}, 'OTHER_VALUE_SOURCE'), ({'PropertyClass': 'PARENT'}, 'OTHER_VALUE_SOURCE'),
    ({'DataLengthSemantics': 'UNKNOWN'}, 'TARGET_LENGTH_SEMANTICS'),
])
def test_unsupported_display_properties_remain_visible_gaps(properties, reason):
    receipt = compile_source(changed(**properties))
    assert receipt['projections'] == []
    assert reason in receipt['gaps'][0]['reason']


@pytest.mark.parametrize('writer', [
    ":DISPLAY_CODE := :AREA || 'different';", ':DISPLAY_CODE := NULL;',
    "COPY(:CODE, 'ROWS.DISPLAY_CODE');", "COPY(:CODE, 'ROWS.' || 'DISPLAY_CODE');",
    'SELECT CODE INTO :DISPLAY_CODE FROM T;',
    "SET_ITEM_PROPERTY('ROWS.DISPLAY_CODE', VISIBLE, PROPERTY_FALSE);",
    "EXECUTE IMMEDIATE 'begin null; end;';",
])
def test_conflicting_or_indirect_writers_are_rejected(writer):
    receipt = compile_source(changed(writer=writer))
    assert receipt['projections'] == [] and receipt['gaps']


@pytest.mark.parametrize('assignment', [
    'IF :CODE IS NOT NULL THEN ' + ASSIGNMENT + ' END IF;',
    'BEGIN ' + ASSIGNMENT + ' NULL; END;',
    ':DISPLAY_CODE := :AREA || TO_CHAR(SYSDATE, \'RR\');',
    ':DISPLAY_CODE := :OTHER.AREA || :CODE;',
])
def test_no_fragment_or_cross_row_claim(assignment):
    result = compile_source(changed(assignment=assignment))
    assert result['projections'] == [] and result['gaps']


def test_duplicate_target_and_reference_names_are_unresolved():
    for name in ('AREA', 'DISPLAY_CODE'):
        root = ET.fromstring(SOURCE)
        block = root.find('./Block')
        block.append(deepcopy(block.find("./Item[@Name='" + name + "']")))
        with pytest.raises(ValueError, match='Duplicate source block or item identity'):
            compile_source(ET.tostring(root))


def test_hidden_canvas_or_tab_is_not_rendered():
    for path in ('./Canvas', './Canvas/TabPage'):
        root = ET.fromstring(SOURCE)
        root.find(path).set('Visible', 'false')
        assert compile_source(ET.tostring(root))['projections'] == []


def test_missing_or_character_source_semantics_remain_a_byte_bound_gap():
    for semantics in ('', 'CHAR'):
        root = ET.fromstring(SOURCE)
        root.find("./Block/Item[@Name='CODE']").set('DataLengthSemantics', semantics)
        result = compile_source(ET.tostring(root))
        assert result['projections'] == []
        assert 'BYTE_BOUND_UNPROVEN' in result['gaps'][0]['reason']


def test_forged_packet_chunk_or_trace_is_rejected():
    for boundary in ('packet', 'chunk', 'trace'):
        args = list(prepare())
        if boundary == 'packet':
            args[1]['source_binding'] = 'forged'
        elif boundary == 'chunk':
            args[2][0]['text'] = 'NULL;'
        else:
            args[3]['blocks'][0]['items'][0]['column'] = 'FORGED_COLUMN'
        with pytest.raises(ValueError, match='SOURCE_CHANGED|FRESH_SYNTHETIC_TRACE'):
            build_display_projections(*args)


def test_rename_is_generic_and_other_module_writer_is_not_same_scope():
    raw = SOURCE.replace(b'ACCOUNTS', b'CLIENTS').replace(b'ROWS', b'ENTRIES').replace(b'DISPLAY_CODE', b'LABEL')
    projection, = compile_source(raw)['projections']
    assert projection['qualified_target'] == 'ENTRIES.LABEL'


def test_other_block_owner_cannot_rebind_unqualified_input_names():
    root = ET.fromstring(SOURCE)
    other = ET.SubElement(root, 'Block', Name='OTHER', DatabaseBlock='true')
    ET.SubElement(other, 'Trigger', Name='KEY-COMMIT', TriggerText=ASSIGNMENT.replace(':DISPLAY_CODE', ':ROWS.DISPLAY_CODE'))
    result = compile_source(ET.tostring(root))
    assert result['projections'] == []
    assert 'INPUT_OWNER_SCOPE_UNRESOLVED' in result['gaps'][0]['reason']


def test_module_owned_supporting_writer_requires_unique_unqualified_names():
    root = ET.fromstring(SOURCE)
    ET.SubElement(root, 'Trigger', Name='KEY-COMMIT', TriggerText='BEGIN ' + ASSIGNMENT + ' COMMIT; END;')
    projection, = compile_source(ET.tostring(root))['projections']
    assert len(projection['supporting_source_units']) == 1
    other = ET.SubElement(root, 'Block', Name='OTHER', DatabaseBlock='true')
    ET.SubElement(other, 'Item', Name='AREA', ItemType='Text Item', DataType='Char', MaximumLength='2', DatabaseItem='true')
    result = compile_source(ET.tostring(root))
    assert result['projections'] == []
    assert 'INPUT_OWNER_SCOPE_UNRESOLVED' in result['gaps'][0]['reason']


def test_target_beyond_existing_structural_budget_stays_a_gap():
    root = ET.fromstring(SOURCE)
    block = root.find('./Block')
    for index in range(255):
        block.insert(index, ET.Element('Item', Name='FILLER_' + str(index), ItemType='Text Item',
                                      DataType='Number', DatabaseItem='true'))
    result = compile_source(ET.tostring(root))
    assert result['projections'] == []
    assert 'NATIVE_TARGET_REQUIRED' in result['gaps'][0]['reason']


@pytest.mark.parametrize('assignment', [
    ':DISPLAY_CODE := :CODE;',
    '-- :DISPLAY_CODE := :AREA || :CODE;\nNULL;',
    "MESSAGE(':DISPLAY_CODE := :AREA || :CODE;');",
    "COPY(:CODE, 'ROWS.DISPLAY_CODE');",
])
def test_plain_lookup_or_comment_only_concatenation_has_no_projection_gap(assignment):
    receipt = compile_source(changed(assignment=assignment))
    assert receipt['projections'] == [] and receipt['gaps'] == []


def test_concat_writer_in_unrelated_block_does_not_select_display():
    root = ET.fromstring(changed(assignment='NULL;'))
    other = ET.SubElement(root, 'Block', Name='OTHER', DatabaseBlock='true')
    ET.SubElement(other, 'Trigger', Name='KEY-COMMIT', TriggerText=ASSIGNMENT)
    receipt = compile_source(ET.tostring(root))
    assert receipt['projections'] == [] and receipt['gaps'] == []
