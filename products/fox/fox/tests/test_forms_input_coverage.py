"""Synthetic OVERRIDDEN-style structure, not Oracle or APEX behavior proof."""
import hashlib
import json
from xml.etree import ElementTree as ET

import pytest

from fox import forms_facts
from fox.forms_facts import assess_forms_xml
from fox.forms_redaction import redact_forms_xml


def document(style, body):
    """Element namespace variants; direct attributes retain their existing policy."""
    prefix = 'f:' if style == 'prefixed' else ''
    namespace = ('xmlns:f' if prefix else 'xmlns') + '="http://xmlns.oracle.com/Forms"'
    if style == 'plain':
        namespace = ''
    return (f'\ufeff<{prefix}Module {namespace}>\n'
            f'<{prefix}FormModule Name="SYNTHETIC">\n'
            + body.replace('<', '<' + prefix).replace('<' + prefix + '/', '</' + prefix)
            + f'</{prefix}FormModule></{prefix}Module>').encode()


@pytest.mark.parametrize('style', ['plain', 'default', 'prefixed'])
def test_radio_options_are_scoped_structure_not_retained_selection_values(style):
    blocks = []
    for block in ('B1', 'B2'):
        blocks.append(f'<Block Name="{block}" DatabaseBlock="false">'
                      '<Item Name="STATUS" ItemType="Radio Group" InitialValue="PRIVATE_INITIAL">'
                      '<RadioButton Name="OPT_A" RadioButtonValue="PRIVATE_SELECTION" '
                      'Label="PRIVATE_LABEL" Value="PRIVATE_VALUE"/>'
                      '<RadioButton Name="OPT_B" RadioButtonValue="1"/>'
                      '<Trigger Name="WHEN-RADIO-CHANGED" TriggerText="BEGIN NULL; END;"/>'
                      '</Item></Block>')
    raw = document(style, ''.join(blocks))
    facts = assess_forms_xml('synthetic.xml', raw)
    radios = [row for row in facts['objects'] if row['kind'] == 'RadioButton']
    assert len(radios) == 4
    assert facts['totals']['items'] == 2 and facts['totals']['uninterpreted_elements'] == 0
    assert facts['modules'][0]['object_counts']['RadioButton'] == 4
    assert [row['item_type'] for row in facts['items']] == ['Radio Group', 'Radio Group']
    for radio, item in zip(radios, [facts['items'][0]] * 2 + [facts['items'][1]] * 2):
        assert radio['parent_id'] == item['id'] and radio['block_id'] == item['block_id']
        assert radio['module_id'] == item['module_id']
        assert radio['location']['path'].endswith('/RadioButton[1]' if radio['name'] == 'OPT_A' else '/RadioButton[2]')
        assert raw[radio['location']['byte_offset']:].startswith(b'<f:RadioButton ' if style == 'prefixed' else b'<RadioButton ')
        expected_id = 'ff1-' + hashlib.sha256(
            (hashlib.sha256(raw).hexdigest() + '\n' + radio['location']['path'] + '\n').encode()).hexdigest()[:24]
        assert radio['id'] == expected_id
    assert not any(row['code'] == 'CONFLICTING_OBJECT_NAME' for row in facts['findings'])
    assert 'PRIVATE_' not in json.dumps(facts)
    assert facts['safety']['native_generation_allowed'] is False
    result = redact_forms_xml('synthetic.xml', raw)
    assert b'PRIVATE_' not in result['redacted_xml']
    options = [node for node in ET.fromstring(result['redacted_xml']).iter()
               if node.tag.rsplit('}', 1)[-1] == 'RadioButton']
    assert [node.get('Name') for node in options] == ['OPT_A', 'OPT_B', 'OPT_A', 'OPT_B']
    assert all(not node.get('RadioButtonValue') and not node.get('Value') and not node.get('Label') for node in options)
    receipt = result['receipt']
    assert receipt['original_sha256'] == hashlib.sha256(raw).hexdigest()
    assert receipt['original_bytes'] == len(raw)
    assert receipt['object_counts']['RadioButton'] == 4
    assert receipt['safety']['native_generation_allowed'] is False
    assert len(receipt['code_units']) == 2
    for unit, mapping in zip(facts['code_units'], receipt['code_units'], strict=True):
        assert mapping['location'] == unit['location']
        assert mapping['original_sha256'] == hashlib.sha256(b'BEGIN NULL; END;').hexdigest()
    fresh = assess_forms_xml('redacted.xml', result['redacted_xml'])
    assert [(row['kind'], row['name']) for row in fresh['objects']] == [(row['kind'], row['name']) for row in facts['objects']]
    assert result == redact_forms_xml('synthetic.xml', raw)


@pytest.mark.parametrize('value', ['0', '1', 'SAFE_LOOKING_IDENTIFIER', 'PRIVATE_SELECTION'])
def test_radio_selection_literals_never_receive_technical_reference_exemption(value):
    raw = document('plain', '<Block Name="B"><Item Name="GROUP" ItemType="Radio Group">'
                   f'<RadioButton Name="OPTION" RadioButtonValue="{value}"/>'
                   '</Item></Block>')
    result = redact_forms_xml('synthetic.xml', raw)
    assert ET.fromstring(result['redacted_xml']).find('.//RadioButton').get('RadioButtonValue') == ''


def test_duplicate_radio_technical_name_conflicts_only_with_same_parent():
    raw = document('plain', '<Block Name="B"><Item Name="GROUP" ItemType="Radio Group">'
                   '<RadioButton Name="OPTION"/><RadioButton Name="OPTION"/>'
                   '</Item></Block>')
    facts = assess_forms_xml('synthetic.xml', raw)
    conflict, = [row for row in facts['findings'] if row['code'] == 'CONFLICTING_OBJECT_NAME']
    assert conflict['object_ids'] == [row['id'] for row in facts['objects'] if row['kind'] == 'RadioButton']


@pytest.mark.parametrize('style', ['plain', 'default', 'prefixed'])
@pytest.mark.parametrize('value', ['true', 'false', 'yes', 'no', 'TRUE', 'False', 'PRIVATE_VALUE', '1', ''])
def test_required_is_only_preserved_as_explicit_boolean_item_metadata(style, value):
    from fox.prototype_source import validate_redacted_prototype_source

    raw = document(style, '<Block Name="B" DatabaseBlock="true">'
                   f'<Item Name="I" DatabaseItem="false" Required="{value}"/>'
                   '<Item Name="NO_REQUIRED" DatabaseItem="true" PrimaryKey="true"/></Block>')
    result = redact_forms_xml('synthetic.xml', raw)
    items = [node for node in ET.fromstring(result['redacted_xml']).iter() if node.tag.rsplit('}', 1)[-1] == 'Item']
    assert items[0].get('Required') == (value if value.lower() in {'true', 'false', 'yes', 'no'} else '')
    assert items[1].get('Required') is None  # No DatabaseItem/PrimaryKey/DDL inference.
    assert result['receipt']['original_sha256'] == hashlib.sha256(raw).hexdigest()
    assert b'PRIVATE_VALUE' not in result['redacted_xml']
    validate_redacted_prototype_source('redacted.xml', result['redacted_xml'], result['receipt'])


@pytest.mark.parametrize('body', [
    '<x:RadioButton xmlns:x="urn:PRIVATE" Name="OPTION"/>',
    '<RadioButton xmlns:x="urn:PRIVATE" x:Name="OPTION"/>',
    '<RadioButton xmlns:f="http://xmlns.oracle.com/Forms" f:Name="OPTION"/>',
])
def test_radio_coverage_does_not_expand_existing_attribute_namespace_policy(body):
    with pytest.raises(ValueError, match='namespace') as caught:
        redact_forms_xml('synthetic.xml', document('plain', '<Block Name="B"><Item Name="GROUP">'
                         + body + '</Item></Block>'))
    assert 'PRIVATE' not in str(caught.value)


def test_safe_input_qualified_identity_boundary_is_unchanged():
    raw = b'<FormModule xmlns:f="http://xmlns.oracle.com/Forms" Name="S"><Block Name="B"><DataSourceColumn f:DSCName="COL"/></Block></FormModule>'
    root, _ = forms_facts._safe_input('synthetic.xml', raw)
    assert root.find('.//DataSourceColumn').attrib == {'{http://xmlns.oracle.com/Forms}DSCName': 'COL'}
