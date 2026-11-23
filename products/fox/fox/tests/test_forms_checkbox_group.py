"""Small source-contract tests; no source PL/SQL, Oracle or live-flow claims."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from forms2apex import native_blueprint
from fox.forms_checkbox_group import build_checkbox_groups, parse_checkbox_event
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_understanding_packet import _build, generation_sources
from fox.xml_mapping import _blueprint


EVENT = """BEGIN
IF :SCHEDULE = 'Y' THEN
 SET_ITEM_PROPERTY('DAY_A', ENABLED, PROPERTY_TRUE);
 SET_ITEM_PROPERTY('DRAFTS.DAY_B', ENABLED, PROPERTY_TRUE);
 SET_ITEM_PROPERTY('DAY_A', UPDATE_ALLOWED, PROPERTY_TRUE);
 SET_ITEM_PROPERTY('DAY_B', UPDATE_ALLOWED, PROPERTY_TRUE);
ELSE
 :DAY_A := 'N'; :DRAFTS.DAY_B := '0';
 SET_ITEM_PROPERTY('DAY_A', ENABLED, PROPERTY_FALSE);
 SET_ITEM_PROPERTY('DAY_B', ENABLED, PROPERTY_FALSE);
END IF;
END;"""


def source(*, event=EVENT, entry=False, **changes):
    root = ET.Element('FormModule', Name='DELIVERY')
    block = ET.SubElement(root, 'Block', Name='DRAFTS', DatabaseBlock='true', QueryDataSourceName='DELIVERIES')
    for name, on, off in [('SCHEDULE', 'Y', 'N'), ('DAY_A', 'Y', 'N'), ('DAY_B', '1', '0')]:
        props = dict(Name=name, ItemType='Check Box', DatabaseItem='true', DataType='Char',
            ColumnName=name, MaximumLength='1', DataLengthSemantics='BYTE', CheckedValue=on,
            UncheckedValue=off, InitializeValue=off, CheckBoxOtherValues='Not Allowed', Prompt=name)
        if name == 'DAY_A':
            props.update(Enabled='false', Required='true')
        props.update(changes.get(name, {}))
        props = {k: v for k, v in props.items() if v is not None}
        item = ET.SubElement(block, 'Item', **props)
        if name == 'SCHEDULE':
            ET.SubElement(item, 'Trigger', Name='WHEN-CHECKBOX-CHANGED', TriggerText=event)
    if entry:
        ET.SubElement(block, 'Trigger', Name='WHEN-NEW-RECORD-INSTANCE',
                      TriggerText="IF :SCHEDULE='Y' THEN SET_ITEM_PROPERTY('DAY_A', ENABLED, PROPERTY_TRUE); END IF;")
        ET.SubElement(root, 'Trigger', Name='KEY-COMMIT', TriggerText='NULL;')
    return ET.tostring(root)


def prepare(raw=None):
    docs = [('delivery.xml', source() if raw is None else raw)]
    with generation_sources(docs):
        packet, chunks = _build(docs)
        spec = build_native_prototype_plan(docs, _blueprint(packet), project_id='checkbox-test',
            project_name='Checkbox test', approved_policy_id=POLICY_ID)['rendering_spec']
        trace = native_blueprint.prototype_trace(spec)
        objects = {o['id']: o for s in packet['sources'] for o in s['facts']['objects']}
        for block in trace['blocks']:
            block['source_module_id'] = objects[block['source_block_id']]['module_id']
    return docs, packet, chunks, trace


def compile_source(**kwargs):
    return build_checkbox_groups(*prepare(source(**kwargs)))


def test_complete_proof_is_deterministic_and_does_not_mutate_inputs():
    args = prepare()
    before = deepcopy(args)
    result = build_checkbox_groups(*args)
    assert args == before
    assert build_checkbox_groups(*args) == result
    assert result['gaps'] == [] and result['converted_code_unit_count'] == 0
    group, = result['groups']
    assert group['project_id'] == 'checkbox-test'
    assert group['source_binding'] == result['source_binding']
    assert group['controller']['checked_value'] == 'Y'
    assert [f['unchecked_value'] for f in group['dependents']] == ['N', '0']
    assert group['when_checked'] == {'enabled': True, 'update_allowed': True}
    assert group['otherwise']['includes_null'] and group['otherwise']['includes_other_values']
    assert group['synthetic_table_proven'] and group['table_name'].startswith('FOX_NATIVE_')
    assert group['dependents'][0]['source_enabled'] is False
    assert group['dependents'][0]['source_required'] is True
    assert group['controller']['source_enabled'] is None
    assert not group['original_access_rights_proven'] and not group['original_save_authorized']
    assert not group['source_widget_equivalence_proven'] and not result['runtime_verified']


def test_record_entry_and_all_other_rules_are_separately_visible():
    group, = compile_source(entry=True)['groups']
    assert len(group['record_entry_rules']) == 1
    assert group['record_entry_rules'][0]['same_group_entry_scope']
    assert group['record_entry_rules'][0]['source_owner_scope'] == 'Block'
    assert not group['record_entry_rules'][0]['whole_entry_rule_translated']
    assert len(group['other_source_rules']) == 2
    assert {x['source_event'] for x in group['other_source_rules']} == {'WHEN-NEW-RECORD-INSTANCE', 'KEY-COMMIT'}
    assert all(not x['native_event_wired'] for x in group['other_source_rules'])
    assert not group['record_entry_initialization_implemented']


def test_optional_update_allowed_and_comment_literals():
    event = EVENT.replace(" SET_ITEM_PROPERTY('DAY_A', UPDATE_ALLOWED, PROPERTY_TRUE);", '').replace(
        " SET_ITEM_PROPERTY('DAY_B', UPDATE_ALLOWED, PROPERTY_TRUE);", '')
    parsed = parse_checkbox_event('-- IF :OTHER = bad;\n' + event + '\n/* unrelated comment */',
                                  block_name='DRAFTS', controller_name='SCHEDULE')
    assert parsed['when_checked']['update_allowed'] is None
    assert len(parsed['assignments']) == 2


def test_encoded_whitespace_and_exact_escaped_literal_values():
    parsed = parse_checkbox_event(EVENT.replace('\n', '&#10;').replace("'Y'", "'y''s'", 1),
                                  block_name='DRAFTS', controller_name='SCHEDULE')
    assert parsed['checked_value'] == "y's"
    assert parsed['source_decode']['substitutions']


@pytest.mark.parametrize('event', [
    EVENT + 'COMMIT;', EVENT.replace('END IF;', 'NULL; END IF;'),
    EVENT.replace(':SCHEDULE', ':OTHER', 1), EVENT.replace(':SCHEDULE', ':ELSEWHERE.SCHEDULE', 1),
    EVENT.replace("'N';", 'NULL;', 1), EVENT.replace("'N';", "LOWER('N');", 1),
    EVENT.replace('ELSE', "ELSIF :DAY_A='Y' THEN NULL; ELSE", 1),
    EVENT.replace("'DAY_A', ENABLED, PROPERTY_FALSE", "'DAY_A', UPDATE_ALLOWED, PROPERTY_FALSE"),
    EVENT.replace("'DAY_A', ENABLED, PROPERTY_TRUE", "'DAY_A', VISIBLE, PROPERTY_TRUE"),
    EVENT.replace(" SET_ITEM_PROPERTY('DAY_A', UPDATE_ALLOWED, PROPERTY_TRUE);", ''),
    EVENT.replace(':DAY_A :=', ':SCHEDULE :='),
    EVENT.replace("'DAY_A', ENABLED, PROPERTY_FALSE", "'OTHER.DAY_A', ENABLED, PROPERTY_FALSE"),
    EVENT.replace(" :DAY_A := 'N';", " :DAY_A := 'N'; :DAY_A := 'N';"),
    EVENT.replace('END;', "END; execute immediate 'begin null; end;';"),
    EVENT.replace("'DAY_A'", "q'[DAY_A]'", 1),
    EVENT.replace("'DAY_A'", "'DAY_' || 'A'", 1),
    EVENT.replace('BEGIN', 'DECLARE x number; BEGIN', 1),
    EVENT.replace(" SET_ITEM_PROPERTY('DAY_A', ENABLED, PROPERTY_TRUE);", '').replace(
        " SET_ITEM_PROPERTY('DAY_A', UPDATE_ALLOWED, PROPERTY_TRUE);",
        " SET_ITEM_PROPERTY('DAY_A', UPDATE_ALLOWED, PROPERTY_TRUE); SET_ITEM_PROPERTY('DAY_A', ENABLED, PROPERTY_TRUE);"),
    EVENT + '/* unterminated',
])
def test_whole_event_rejects_extra_or_ambiguous_behavior(event):
    result = compile_source(event=event)
    assert not result['groups'] and result['gaps']


@pytest.mark.parametrize('changes,reason', [
    ({'SCHEDULE': {'CheckedValue': 'T'}}, 'EXACT_CONTROLLER_CHECKED'),
    ({'DAY_A': {'UncheckedValue': 'F', 'InitializeValue': 'F'}}, 'EXACT_DEPENDENT_UNCHECKED'),
    ({'DAY_A': {'DatabaseItem': 'false'}}, 'STORED_CHARACTER_CHECKBOX'),
    ({'DAY_A': {'DataType': 'Number'}}, 'STORED_CHARACTER_CHECKBOX'),
    ({'DAY_A': {'Formula': '1'}}, 'DIRECT_CHECKBOX'),
    ({'DAY_A': {'ColumnName': 'SCHEDULE'}}, 'SOURCE_COLUMN_NOT_UNIQUE'),
    ({'DAY_A': {'MaximumLength': None}}, 'EXPLICIT_BYTE_LENGTH'),
    ({'DAY_A': {'DataLengthSemantics': None}}, 'EXPLICIT_BYTE_LENGTH'),
    ({'DAY_A': {'CheckedValue': 'N'}}, 'EXACT_CHECKBOX_VALUES'),
    ({'DAY_A': {'CheckBoxOtherValues': None}}, 'EXPLICIT_OTHER_VALUES_POLICY'),
    ({'DAY_A': {'CheckBoxOtherValues': 'Something'}}, 'EXPLICIT_OTHER_VALUES_POLICY'),
    ({'DAY_A': {'InitializeValue': 'UNKNOWN'}}, 'INITIAL_VALUE_UNRESOLVED'),
])
def test_inconclusive_fields_stay_visible_gaps(changes, reason):
    result = compile_source(**changes)
    assert not result['groups'] and reason in result['gaps'][0]['reason']


def test_field_specific_other_values_never_override_raw_if_test_or_adapter_admission():
    group, = compile_source(SCHEDULE={'CheckBoxOtherValues': 'Checked'},
                            DAY_A={'CheckBoxOtherValues': 'Unchecked'})['groups']
    assert group['controller']['other_values'] == 'Checked'
    assert group['dependents'][0]['other_values'] == 'Unchecked'
    assert group['controller']['source_other_values_policy']['raw_if_comparison'] == 'exact_checked_value_only'
    assert group['input_policy']['null_values'] == group['input_policy']['other_values'] == 'reject'
    assert not group['source_widget_equivalence_proven']


@pytest.mark.parametrize('index', [1, 2, 3])
def test_packet_chunks_or_trace_tamper_is_rejected(index):
    args = list(prepare())
    if index == 1:
        args[1]['source_binding'] = 'changed'
    elif index == 2:
        args[2][0]['text'] = 'NULL;'
    else:
        args[3]['blocks'][0]['items'][0]['column'] = 'WRONG'
    with pytest.raises(ValueError, match='SOURCE_CHANGED|FRESH_SYNTHETIC_TRACE'):
        build_checkbox_groups(*args)


def test_other_values_unrelated_attribute_cannot_supply_checkbox_policy():
    result = compile_source(DAY_A={'CheckBoxOtherValues': None, 'OtherValues': 'Checked'})
    assert not result['groups'] and 'EXPLICIT_OTHER_VALUES_POLICY' in result['gaps'][0]['reason']
