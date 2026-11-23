"""End-to-end synthetic mapping; report value and source-event disposition are distinct."""
import json
from xml.etree import ElementTree as ET

import pytest

from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members
from fox.xml_mapping import generate_xml_package


def display_source(*, conflict=False, related=False):
    form = ET.Element('FormModule', Name='BILLING')
    ET.SubElement(form, 'Canvas', Name='MAIN')
    if related:
        header = ET.SubElement(form, 'Block', Name='REGIONS', DatabaseBlock='true')
        ET.SubElement(header, 'Item', Name='REGION', ColumnName='REGION', DatabaseItem='true',
                      DataType='Char', ItemType='Text Item', MaximumLength='3', DataLengthSemantics='BYTE')
        ET.SubElement(header, 'Relation', Name='DETAIL', DetailBlock='CHARGES', RelationType='Join',
                      JoinCondition='REGIONS.REGION=CHARGES.DISTRICT')
    block = ET.SubElement(form, 'Block', Name='CHARGES', DatabaseBlock='true',
                          QueryDataSourceType='Table', QueryDataSourceName='EXAMPLE_CHARGES')
    def field(name, datatype, length, **attrs):
        props = dict(Name=name, ColumnName=name, DataType=datatype, DatabaseItem='true',
                     MaximumLength=str(length), ItemType='Text Item', DataLengthSemantics='BYTE')
        props.update(attrs)
        return ET.SubElement(block, 'Item', **props)
    key = field('ACCOUNT', 'Char', 9)
    region = field('DISTRICT', 'Char', 3)
    field('STARTED', 'Date', 20)
    for index in range(7):
        field('SPARE' + str(index), 'Char', 10)
    field('DISPLAY_CODE', 'Char', 25, DatabaseItem='false', ItemType='Display Item', CanvasName='MAIN')
    body = ":DISPLAY_CODE := :DISTRICT || TO_CHAR(:STARTED,'RR') || :CHARGES.ACCOUNT;"
    ET.SubElement(key, 'Trigger', Name='POST-CHANGE', TriggerText=body)
    other = ":DISPLAY_CODE := 'X' || :ACCOUNT;" if conflict else body
    ET.SubElement(region, 'Trigger', Name='POST-CHANGE', TriggerText="BEGIN NULL; " + other + " END;")
    return ET.tostring(form)


@pytest.mark.parametrize('related', [False, True])
def test_projection_is_visible_only_as_saved_read_not_whole_source_events(related):
    raw, report = generate_xml_package([('billing.xml', display_source(related=related))],
                                       'display-test', 'Billing display', POLICY_ID)
    files = _members(raw)
    meta = report['metadata']['saved_display_fields']
    data = json.loads(files[meta['member']])
    applied, = data['applied']
    assert not applied['native_event_wired'] and not applied['source_event_timing_preserved']
    assert len(applied['whole_source_units']) == len(applied['supporting_source_units']) == 1
    assert len(applied['page_files']) == 1 + int(related)
    for path in applied['page_files']:
        page = files[path].decode()
        assert f"displayColumn {applied['target_column']} (" in page
        assert 'to_char(' in page.lower() and "'RR'" in page and '||' in page
        assert 'region saved-display-scope (' in page
    uid = applied['whole_source_units'][0]['source_unit_id']
    row, = [u for u in report['mapping_ledger']['code_units'] if u['source_unit_id'] == uid]
    assert row['reason'] == 'saved_display_partly_connected'
    assert row['rule_id'] == 'fox.display.saved-row-label'
    assert row['status'] != 'generated_wired_adapted'
    supporting = applied['supporting_source_units'][0]['source_unit_id']
    assert all(u['rule_id'] != 'fox.display.saved-row-label' for u in report['mapping_ledger']['code_units']
               if u['source_unit_id'] == supporting)


def test_conflicting_writers_never_add_an_expression_to_the_report():
    raw, result = generate_xml_package([('billing.xml', display_source(conflict=True))],
                                       'display-test', 'Billing display', POLICY_ID)
    files = _members(raw)
    notice = result['metadata']['saved_display_fields']
    receipt = json.loads(files[notice['member']])
    assert not receipt['applied'] and receipt['gaps']
    assert not any(b'region saved-display-scope (' in data for name, data in files.items()
                   if name.endswith('.apx'))
