"""Synthetic-only effective metadata tests; no Oracle, model or file access."""
import hashlib
import json
from xml.etree import ElementTree as XML
from xml.sax.saxutils import quoteattr

import pytest

from fox import forms_effective_view as view

NS = "http://xmlns.oracle.com/Forms"
BINARY = "a" * 64


def derive(original, all_xml):
    return view.derive_effective_view("synthetic.xml", original, all_xml, binary_sha256=BINARY)


def fixture(blocks=9, items=222):
    original = ['<Module><FormModule Name="SYNTHETIC">']
    expanded = [f'<Module xmlns:SYNTHETIC_default="{NS}" xmlns:SYNTHETIC_overridden="{NS}" '
                f'xmlns:UNKNOWN_inherited="{NS}"><FormModule SYNTHETIC_overridden:Name="SYNTHETIC">']
    for block in range(blocks):
        explicit = block >= 6
        flag = "false" if block >= 7 else "true"
        original.append(f'<Block Name="B{block}"' + (f' DatabaseBlock="{flag}"' if explicit else '') + '>')
        prefix = "SYNTHETIC_overridden" if explicit else "SYNTHETIC_default"
        expanded.append(f'<Block SYNTHETIC_overridden:Name="B{block}" {prefix}:DatabaseBlock="{flag}">')
        for item in range(items // blocks + (block < items % blocks)):
            original.append(f'<Item Name="I{item}"/>')
            expanded.append(f'<Item SYNTHETIC_overridden:Name="I{item}" SYNTHETIC_default:ItemType="Text Item" '
                            'SYNTHETIC_default:DataType="Char" SYNTHETIC_default:MaximumLength="30" '
                            'SYNTHETIC_default:Prompt="Human label" SYNTHETIC_default:DatabaseItem="true" '
                            f'SYNTHETIC_default:ColumnName="C{item}" SYNTHETIC_default:PrimaryKey="false"/>')
        original.append('</Block>')
        expanded.append('</Block>')
    original.append('</FormModule></Module>')
    expanded.append('</FormModule></Module>')
    return ''.join(original).encode(), ''.join(expanded).encode()


def test_six_defaults_known_false_and_222_items_source_bound_value_free_receipt():
    original, expanded = fixture()
    original_copy = bytes(original)
    result = derive(original, expanded)
    root = XML.fromstring(result['derived_xml'])
    assert [b.get('DatabaseBlock') for b in root.iter('Block')] == ['true'] * 7 + ['false'] * 2
    items = list(root.iter('Item'))
    assert len(items) == 222
    assert all(i.get('DataType') == 'Char' and i.get('MaximumLength') == '30' and i.get('DatabaseItem') == 'true'
               and i.get('Prompt') == 'Human label' and i.get('ColumnName') and i.get('PrimaryKey') == 'false' for i in items)
    receipt = result['receipt']
    assert receipt['scope'] == 'fox-forms-effective-view-v1' and receipt['schema_version'] == 1
    assert receipt['policy_id'] == view.POLICY_ID
    assert receipt['structural_counts'] == {'elements': 233, 'modules': 1, 'blocks': 9, 'items': 222}
    assert receipt['action_counts']['copied_missing'] == 6 + 222 * 7
    assert len(receipt['changes']) == 1560
    assert receipt['unresolved_inherited'] == []
    assert receipt['original_sha256'] == hashlib.sha256(original).hexdigest()
    assert receipt['all_sha256'] == hashlib.sha256(expanded).hexdigest()
    assert receipt['derived_sha256'] == hashlib.sha256(result['derived_xml']).hexdigest()
    assert receipt['binary_sha256'] == BINARY and receipt['original_unchanged'] is True
    assert receipt['safety']['actual_tool_run_binding_required'] is True
    assert receipt['safety']['oracle_provenance_attested'] is False
    assert not any(receipt['safety'][k] for k in ['code_executed', 'model_submission_allowed', 'import_allowed', 'native_generation_allowed'])
    assert original == original_copy
    rendered = json.dumps(receipt)
    assert 'Human label' not in rendered and 'C0' not in rendered
    assert {'path', 'property', 'provenance', 'qualified_source_key'} == receipt['changes'][0].keys()
    assert derive(original, expanded) == result


def test_inherited_not_copied_or_interpreted_and_existing_explicit_not_removed():
    original = b'<FormModule Name="S"><Block Name="B" DatabaseBlock="false"><Item Name="I"/></Block></FormModule>'
    expanded = (f'<FormModule xmlns:UNKNOWN_inherited="{NS}" Name="S"><Block Name="B" '
                'UNKNOWN_inherited:DatabaseBlock="arbitrary-unresolved-value"><Item Name="I" '
                'UNKNOWN_inherited:MaximumLength="not-an-int"/></Block></FormModule>').encode()
    result = derive(original, expanded)
    root = XML.fromstring(result['derived_xml'])
    assert root.find('Block').get('DatabaseBlock') == 'false'
    assert root.find('Block/Item').get('MaximumLength') is None
    assert len(result['receipt']['unresolved_inherited']) == 2
    assert result['receipt']['changes'] == []
    assert 'arbitrary-unresolved-value' not in json.dumps(result['receipt'])


def test_code_query_unknown_elements_and_qualified_original_attributes_preserved():
    code = "BEGIN\n :B.I := 'é & original';\nEND;"
    original = (f'<Module xmlns:f="{NS}" xmlns:x="urn:private-extension"><f:FormModule Name="S">'
                '<Block Name="B" QueryDataSourceName="select arbitrary_source from custom_table">'
                f'<Trigger Name="T" TriggerText={quoteattr(code)}/><ProgramUnit Name="P"><ProgramUnitText>{code.replace("&", "&amp;")}</ProgramUnitText></ProgramUnit>'
                '<x:Custom x:Other="preserved &amp; value"><!-- keep --><x:Content>opaque text</x:Content></x:Custom>'
                '</Block></f:FormModule></Module>').encode()
    expanded = original.replace(b'Name="B"', b'Name="B" DatabaseBlock="false"').replace(
        b'select arbitrary_source from custom_table', b'other all query never copied').replace(
        b"original", b"all-changed-code-not-copied")
    result = derive(original, expanded)
    root = XML.fromstring(result['derived_xml'])
    assert root.find('.//Block').get('QueryDataSourceName') == 'select arbitrary_source from custom_table'
    assert root.find('.//Trigger').get('TriggerText') == code
    assert root.find('.//ProgramUnitText').text == code
    assert hashlib.sha256(root.find('.//Trigger').get('TriggerText').encode()).hexdigest() == hashlib.sha256(code.encode()).hexdigest()
    assert root.find('.//{urn:private-extension}Custom').get('{urn:private-extension}Other') == 'preserved & value'
    assert b'<!-- keep -->' in result['derived_xml']
    assert 'urn:private-extension' not in json.dumps(result['receipt'])
    assert 'arbitrary_source' not in json.dumps(result['receipt']) and 'original' not in json.dumps(result['receipt']['changes'])


def test_missing_code_and_unapproved_properties_never_copied():
    original = b'<FormModule Name="S"><Block Name="B"><Trigger Name="T"/></Block></FormModule>'
    expanded = (b'<FormModule Name="S" WhereClause="sensitive SQL"><Block Name="B" '
                b'QueryDataSourceName="select hidden from data" DatabaseBlock="true" '
                b'UnknownAttribute="opaque"><Trigger Name="T" TriggerText="BEGIN NULL; END;"/></Block></FormModule>')
    result = derive(original, expanded)
    root = XML.fromstring(result['derived_xml'])
    assert root.get('WhereClause') is None
    assert root.find('Block').get('QueryDataSourceName') is None
    assert root.find('Block').get('UnknownAttribute') is None
    assert root.find('Block/Trigger').get('TriggerText') is None
    assert [change['property'] for change in result['receipt']['changes']] == ['DatabaseBlock']


def test_existing_qualified_properties_preserved_and_boolean_equivalence_allowed():
    original = (f'<FormModule xmlns:S_overridden="{NS}" S_overridden:Name="S">'
                '<Block S_overridden:Name="B" S_overridden:DatabaseBlock="No"/></FormModule>').encode()
    expanded = b'<FormModule Name="S"><Block Name="B" DatabaseBlock="false"/></FormModule>'
    result = derive(original, expanded)
    block = XML.fromstring(result['derived_xml']).find('Block')
    assert block.get(f'{{{NS}}}DatabaseBlock') == 'No' and block.get('DatabaseBlock') is None
    assert result['receipt']['changes'] == []


def test_numeric_list_entry_names_are_exact_contextual_identities_with_six_defaults_and_code_preserved():
    original, expanded = fixture(blocks=9, items=9)
    code = "BEGIN :B0.I0 := 'preserved'; END;"
    original_entries = ('<Item Name="CHOICE"><ListItemElement Name="0" ListItemLabel="First"/>'
                        '<ListItemElement Name="01" ListItemLabel="Second"/></Item>'
                        f'<Trigger Name="T" TriggerText={quoteattr(code)}/>').encode()
    expanded_entries = (f'<Item SYNTHETIC_overridden:Name="CHOICE"><ListItemElement SYNTHETIC_overridden:Name="01" ListItemLabel="Second"/>'
                        '<ListItemElement SYNTHETIC_overridden:Name="0" ListItemLabel="First"/></Item>'
                        f'<Trigger SYNTHETIC_overridden:Name="T" TriggerText={quoteattr(code)}/>').encode()
    original = original.replace(b'</Block>', original_entries + b'</Block>', 1)
    expanded = expanded.replace(b'</Block>', expanded_entries + b'</Block>', 1)
    result = derive(original, expanded)
    root = XML.fromstring(result['derived_xml'])
    assert [entry.get('Name') for entry in root.iter('ListItemElement')] == ['0', '01']
    assert len([c for c in result['receipt']['changes'] if c['property'] == 'DatabaseBlock']) == 6
    assert [b.get('DatabaseBlock') for b in root.iter('Block')] == ['true'] * 7 + ['false'] * 2
    assert root.find('.//Trigger').get('TriggerText') == code
    assert hashlib.sha256(root.find('.//Trigger').get('TriggerText').encode()).hexdigest() == hashlib.sha256(code.encode()).hexdigest()
    assert any('[Name=01]' in c['path'] for c in result['receipt']['changes']) is False
    # A leading-zero difference is an identity mismatch, not numeric equality.
    with pytest.raises(ValueError, match='structures or exact names differ'):
        derive(original, expanded.replace(b':Name="01"', b':Name="1"'))


@pytest.mark.parametrize('kind', ['FormModule', 'Block', 'Item', 'Trigger', 'PropertyClass'])
def test_numeric_general_object_names_still_rejected(kind):
    raw = (f'<{kind} Name="01"/>' if kind == 'FormModule' else f'<FormModule Name="S"><{kind} Name="01"/></FormModule>').encode()
    with pytest.raises(ValueError, match='bounded property type'):
        derive(raw, raw)


def test_empty_list_entry_name_is_preserved_not_guessed_or_joined_by_position():
    original = b'<FormModule Name="S"><Item Name="I"><ListItemElement Name="" ListItemLabel="Choose"/><ListItemElement Name="1"/></Item></FormModule>'
    expanded = (f'<FormModule xmlns:S_overridden="{NS}" S_overridden:Name="S"><Item S_overridden:Name="I">'
                '<ListItemElement S_overridden:Name="1"/><ListItemElement S_overridden:Name="" ListItemLabel="Choose"/>'
                '</Item></FormModule>').encode()
    result = derive(original, expanded)
    entries = list(XML.fromstring(result['derived_xml']).iter('ListItemElement'))
    assert [entry.get('Name') for entry in entries] == ['', '1']
    assert entries[0].get('ListItemLabel') == 'Choose'
    assert result['receipt']['original_unchanged'] is True
    assert result['receipt']['changes'] == []
    with pytest.raises(ValueError, match='structures or exact names differ'):
        derive(original, expanded.replace(b'S_overridden:Name=""', b''))
    with pytest.raises(ValueError, match='ambiguous object identity'):
        duplicate = original.replace(b'Name="1"', b'Name=""')
        derive(duplicate, duplicate)


@pytest.mark.parametrize('kind', ['FormModule', 'Block', 'Item', 'Trigger', 'RadioButton', 'PropertyClass'])
def test_empty_general_object_names_still_rejected(kind):
    raw = (f'<{kind} Name=""/>' if kind == 'FormModule' else f'<FormModule Name="S"><{kind} Name=""/></FormModule>').encode()
    with pytest.raises(ValueError, match='bounded property type'):
        derive(raw, raw)


def test_numeric_list_entry_name_is_bounded():
    for value in ['12345678901', '-1', '1.5']:
        raw = f'<FormModule Name="S"><Item Name="I"><ListItemElement Name="{value}"/></Item></FormModule>'.encode()
        with pytest.raises(ValueError, match='bounded property type'):
            derive(raw, raw)


def test_datasource_columns_match_exact_dscname_not_position_and_preserve_opaque_metadata():
    code = "BEGIN :B.ID := 7; END;"
    original = (f'<FormModule Name="S"><Block Name="B"><DataSourceColumn DSCName="ID" DSCLength="22" '
                'DSCMandatory="true" DSCNochildren="0" DSCPrecision="10" DSCScale="0" DSCType="NUMBER" Type="Column"/>'
                '<DataSourceColumn DSCName="LABEL" DSCLength="80" DSCType="VARCHAR2"/>'
                f'<Trigger Name="T" TriggerText={quoteattr(code)}/></Block></FormModule>').encode()
    expanded = (f'<FormModule xmlns:S_overridden="{NS}" xmlns:S_default="{NS}" S_overridden:Name="S">'
                '<Block S_overridden:Name="B" S_default:DatabaseBlock="true">'
                '<DataSourceColumn S_overridden:DSCName="LABEL" DSCLength="different-all-value"/>'
                '<DataSourceColumn S_overridden:DSCName="ID" DSCType="different-all-value"/>'
                f'<Trigger S_overridden:Name="T" TriggerText={quoteattr(code)}/></Block></FormModule>').encode()
    result = derive(original, expanded)
    root = XML.fromstring(result['derived_xml'])
    columns = list(root.iter('DataSourceColumn'))
    assert [column.get('DSCName') for column in columns] == ['ID', 'LABEL']
    assert columns[0].attrib == {'DSCName': 'ID', 'DSCLength': '22', 'DSCMandatory': 'true',
                                 'DSCNochildren': '0', 'DSCPrecision': '10', 'DSCScale': '0',
                                 'DSCType': 'NUMBER', 'Type': 'Column'}
    assert columns[1].get('DSCLength') == '80' and columns[1].get('DSCType') == 'VARCHAR2'
    assert root.find('.//Block').get('DatabaseBlock') == 'true'
    assert root.find('.//Trigger').get('TriggerText') == code
    assert [c['property'] for c in result['receipt']['changes']] == ['DatabaseBlock']
    assert 'different-all-value' not in json.dumps(result['receipt'])
    with pytest.raises(ValueError, match='structures or exact names differ'):
        derive(original, expanded.replace(b':DSCName="ID"', b':DSCName="OTHER"'))


@pytest.mark.parametrize('body', [
    '<DataSourceColumn DSCName="ID" Name="ID"/>',
    '<DataSourceColumn DSCName="ID"/><DataSourceColumn DSCName="ID"/>',
    '<DataSourceColumn/><DataSourceColumn/>',
    '<DataSourceColumn Name="ID"/>',
    '<DataSourceColumn DSCName="bad/name"/>',
    '<DataSourceColumn DSCName="123"/>',
    '<DataSourceColumn x:DSCName="ID" xmlns:x="urn:foreign"/>',
    f'<DataSourceColumn x:DSCName="ID" xmlns:x="{NS}"/>',
    f'<DataSourceColumn DSCName="ID" S_default:DSCName="ID" xmlns:S_default="{NS}"/>',
    f'<DataSourceColumn UNKNOWN_inherited:DSCName="ID" xmlns:UNKNOWN_inherited="{NS}"/>',
    '<Item Name="I" DSCName="ID"/>',
    '<Block Name="B2" DSCName="ID"/>',
])
def test_datasource_identity_ambiguity_missing_provenance_and_wrong_context_rejected(body):
    raw = f'<FormModule Name="S"><Block Name="B">{body}</Block></FormModule>'.encode()
    with pytest.raises(ValueError):
        derive(raw, raw)


@pytest.mark.parametrize('field,value', [
    ('DatabaseBlock', 'sometimes'), ('DatabaseItem', '1'), ('PrimaryKey', 'FALSE;'),
    ('MaximumLength', '-1'), ('MaximumLength', '1000001'), ('MaximumLength', '1.5'),
    ('ItemType', 'Text Item; execute'), ('DataType', 'unknown'), ('QueryDataSourceType', 'SQL'),
    ('ColumnName', 'x; drop table x'), ('Prompt', 'x' * 2049), ('Name', 'bad/name'),
])
def test_wrong_metadata_types_rejected_without_values(field, value):
    raw = f'<FormModule Name="S"><Block {field}={quoteattr(value)}/></FormModule>'.encode()
    with pytest.raises(ValueError, match='bounded property type') as caught:
        derive(raw, raw)
    assert value not in str(caught.value)


@pytest.mark.parametrize('all_body', [
    'Name="B" DatabaseBlock="false"',  # conflicts with original true
    'Name="B" x:DatabaseBlock="true" xmlns:x="urn:foreign"',
    f'Name="B" x:DatabaseBlock="true" xmlns:x="{NS}"',
    f'Name="B" DatabaseBlock="true" S_default:DatabaseBlock="true" xmlns:S_default="{NS}"',
    f'Name="B" S_default:DatabaseBlock="true" S_overridden:DatabaseBlock="true" xmlns:S_default="{NS}" xmlns:S_overridden="{NS}"',
])
def test_conflict_foreign_alias_unsupported_prefix_and_ambiguous_property_rejected(all_body):
    original = b'<FormModule Name="S"><Block Name="B" DatabaseBlock="true"/></FormModule>'
    with pytest.raises(ValueError):
        derive(original, f'<FormModule Name="S"><Block {all_body}/></FormModule>'.encode())


def test_exact_identity_structure_not_positional_and_order_can_differ():
    original = b'<FormModule Name="S"><Block Name="A"/><Block Name="B"/></FormModule>'
    result = derive(original, b'<FormModule Name="S"><Block Name="B" DatabaseBlock="false"/><Block Name="A" DatabaseBlock="true"/></FormModule>')
    assert [(b.get('Name'), b.get('DatabaseBlock')) for b in XML.fromstring(result['derived_xml'])] == [('A', 'true'), ('B', 'false')]
    for changed in [b'<FormModule Name="S"><Block Name="A"/><Block Name="C"/></FormModule>',
                    b'<FormModule Name="S"><Block Name="A"><Item Name="B"/></Block></FormModule>',
                    b'<FormModule Name="S"><Block Name="A"/><Block Name="A"/></FormModule>']:
        with pytest.raises(ValueError):
            derive(original, changed)
    with pytest.raises(ValueError, match='ambiguous object identity'):
        derive(b'<FormModule Name="S"><Coordinate/><Coordinate/></FormModule>', b'<FormModule Name="S"><Coordinate/><Coordinate/></FormModule>')


@pytest.mark.parametrize('raw', [
    b'<!DOCTYPE x [<!ENTITY a "x">]><FormModule Name="S">&a;</FormModule>',
    b'<!DOCTYPE x SYSTEM "file:///no-read"><FormModule Name="S"/>',
    b'<FormModule Name="S"><Trigger Name="T" TriggerText="pwd := &apos;synthetic-secret&apos;;"/></FormModule>',
    b'<FormModule Name="S"><Property Name="password" Value="synthetic-secret"/></FormModule>',
    b'<FormModule Name="S" xmlns:x="urn:unknown"><Property Name="password" Value="synthetic-secret" x:Value=""/></FormModule>',
    f'<FormModule xmlns:S_default="{NS}" Name="S"><Property S_default:Name="password" Value="synthetic-secret"/></FormModule>'.encode(),
    b'<FormModule Name="S"><TriggerText>passwor<![CDATA[d := \'synthetic-secret\';]]></TriggerText></FormModule>',
    b'\xff', b'\0', b'<FormModule', b'<FormModule xmlns="urn:foreign" Name="S"/>',
    b'<?xml version="1.0" encoding="ISO-8859-1"?><FormModule Name="S"/>',
    b'<Module/>', b'<FormModule x:Name="S"/>',
])
def test_unsafe_inputs_bounded_errors_no_source_echo(raw):
    with pytest.raises(ValueError) as caught:
        derive(raw, raw)
    assert len(str(caught.value)) < 180 and 'synthetic-secret' not in str(caught.value)


def test_budget_boundaries(monkeypatch):
    raw = b'<FormModule Name="S"><Block Name="B"/></FormModule>'
    monkeypatch.setattr(view, 'MAX_FILE_BYTES', len(raw))
    with pytest.raises(ValueError, match='at most'):
        derive(raw + b' ', raw)
    monkeypatch.setattr(view, 'MAX_FILE_BYTES', 10000)
    monkeypatch.setattr(view, 'MAX_ELEMENTS', 1)
    with pytest.raises(ValueError, match='bounded element'):
        derive(raw, raw)
    monkeypatch.setattr(view, 'MAX_ELEMENTS', 100)
    monkeypatch.setattr(view, 'MAX_DEPTH', 1)
    with pytest.raises(ValueError, match='bounded element'):
        derive(raw, raw)
    monkeypatch.setattr(view, 'MAX_DEPTH', 128)
    monkeypatch.setattr(view, 'MAX_ATTRIBUTES', 1)
    with pytest.raises(ValueError, match='bounded element'):
        derive(raw.replace(b'Name="B"', b'Name="B" DatabaseBlock="true"'), raw)
    monkeypatch.setattr(view, 'MAX_ATTRIBUTES', 256)
    monkeypatch.setattr(view, 'MAX_RECEIPT_PATH_BYTES', 10)
    with pytest.raises(ValueError, match='bounded receipt'):
        derive(raw, raw)


@pytest.mark.parametrize('name,binary', [('path/a.xml', BINARY), ('../a.xml', BINARY), ('a.fmb', BINARY), ('a.xml', 'invalid')])
def test_invalid_api_identity(name, binary):
    with pytest.raises(ValueError):
        view.derive_effective_view(name, b'<FormModule Name="S"/>', b'<FormModule Name="S"/>', binary_sha256=binary)
