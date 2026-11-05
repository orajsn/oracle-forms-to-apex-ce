"""Public fabricated fixtures only; no source/customer/provider/Oracle access."""
import hashlib
import json
from xml.etree import ElementTree as ET
from xml.sax.saxutils import quoteattr

import pytest

from fox import forms_facts, forms_redaction
from fox.forms_redaction import redact_forms_xml


def document(code, attr="TriggerText"):
    return f'<FormModule Name="SYNTHETIC"><Trigger Name="WHEN-BUTTON-PRESSED" {attr}={quoteattr(code)}/></FormModule>'.encode()


def test_credentials_pii_comments_literals_and_numbers_masked_without_initial_secret_rejection():
    code = """BEGIN
    password := 'synthetic-password'; api_key := q'[synthetic-key]';
    x := 'alice@example.test'; y := 'https://example.test/private';
    z := 'C:\\private\\input.csv'; n := 987654321; one := 1; zero := 0;
    identifier987 := :B.ITEM42; -- phone +1 999 123 4567
    /* confidential business text */ CALL_FORM('OTHER_FORM');
    GO_ITEM('B.ITEM42'); SET_ITEM_PROPERTY('B.ITEM42', LABEL, 'Do not preserve');
    END;"""
    result = redact_forms_xml("synthetic.xml", document(code))
    output = result["redacted_xml"].decode()
    for private in ["synthetic-password", "synthetic-key", "alice@", "example.test", "private", "987654321", "999", "confidential", "Do not preserve"]:
        assert private not in output
        if len(private) > 3:  # Short digit sequences can coincide with SHA-256 hex.
            assert private not in json.dumps(result["receipt"])
    assert "identifier987" in output and ":B.ITEM42" in output
    assert "one := 1" in output and "zero := 0" in output
    assert "'OTHER_FORM'" in output and "'B.ITEM42'" in output
    assert "FOX_REDACTED_LITERAL_" in output and "FOX_REDACTED_NUMBER_" in output
    assert "FOX_REDACTED_COMMENT_" in output and "ANALYSIS_ONLY_NON_EXECUTABLE" in output
    safety = result["receipt"]["safety"]
    assert safety["caller_permission_required"] and not safety["model_submission_allowed"]
    assert not safety["oracle_verified"] and not safety["native_generation_allowed"]
    assert not safety["pii_detection_complete"]


@pytest.mark.parametrize("literal", [
    "'sensitive''remainder'", '"sensitive""identifier"', "q'[sensitive secret]'",
    "q'{sensitive secret}'", "q'(sensitive secret)'", "q'<sensitive secret>'",
    "Q'!sensitive secret!'", "nq'[sensitive secret]'", "NQ'<sensitive secret>'",
    "n'sensitive''national'", "N'sensitive'",
])
def test_quote_variants_never_leak(literal):
    output = redact_forms_xml("a.xml", document(f"BEGIN x := {literal}; END;"))["redacted_xml"].decode()
    assert "sensitive" not in output and "remainder" not in output
    assert "FOX_REDACTED_" in output


@pytest.mark.parametrize("code", [
    "BEGIN x := 'SENSITIVE_UNTERMINATED; END;", "BEGIN x := q'[SENSITIVE_UNTERMINATED'; END;",
    'BEGIN x := "SENSITIVE_UNTERMINATED; END;', "BEGIN /* SENSITIVE_UNTERMINATED",
    "BEGIN x := nq'{SENSITIVE_UNTERMINATED'; END;", "BEGIN x := n'SENSITIVE_UNTERMINATED;",
    "BEGIN /* outer /* SENSITIVE nested */ END;", "BEGIN x := 12SENSITIVE; END;",
    "BEGIN x := ''SENSITIVE''; END;", "BEGIN x := 'x'SENSITIVE; END;",
    "connect user/SENSITIVE@database", "BEGIN x := https://SENSITIVE.test; END;",
])
def test_malformed_or_unsafe_unit_wholly_withheld(code):
    result = redact_forms_xml("a.xml", document(code))
    output = result["redacted_xml"].decode()
    assert "SENSITIVE" not in output and "BEGIN" not in output
    assert "FOX_REDACTED_UNIT_WITHHELD" in output and "DO_NOT_RECONSTRUCT" in output
    assert result["receipt"]["code_units"][0]["status"] == "withheld"
    assert result["receipt"]["code_units"][0]["reason"]


def test_only_exact_builtin_first_arg_technical_literals_exempt():
    code = """BEGIN
    CALL_FORM('OTHER_FORM'); pkg.CALL_FORM('PRIVATE_ALIAS'); CALL_FORM('PRIVATE_EXPR'||suffix);
    arbitrary('PRIVATE_NAME'); SET_ITEM_PROPERTY('B.I', LABEL, 'PRIVATE_LABEL');
    GO_BLOCK('B'); GO_ITEM('B.I'); FIND_ITEM('B.I'); CALL_FORM('https://private.test');
    x := 'NORMAL'; x := ''; x := 'YYYY-MM-DD'; x := 'SYNTHETIC_IDENTIFIER';
    END;"""
    output = redact_forms_xml("a.xml", document(code))["redacted_xml"].decode()
    for private in ["PRIVATE_ALIAS", "PRIVATE_EXPR", "PRIVATE_NAME", "PRIVATE_LABEL", "private.test", "NORMAL", "YYYY-MM-DD", "SYNTHETIC_IDENTIFIER"]:
        assert private not in output
    assert "'OTHER_FORM'" in output and "'B.I'" in output and "'B'" in output


@pytest.mark.parametrize("number", ["222", "1.5", ".55", "2e10", "1E-20", "2.4f", "0001", "1.0", "1e0"])
def test_numeric_literals_not_identifier_digits(number):
    output = redact_forms_xml("a.xml", document(f"BEGIN item222 := :B1.I55 + {number}; END;"))["redacted_xml"].decode()
    assert "item222" in output and ":B1.I55" in output
    assert f"+ {number};" not in output
    assert "FOX_REDACTED_NUMBER_1" in output


def test_numeric_loop_range_remains_distinct_from_decimal():
    result = redact_forms_xml('a.xml', document('BEGIN FOR i IN 1..999 LOOP NULL; END LOOP; END;'))
    assert b'1..FOX_REDACTED_NUMBER_1' in result['redacted_xml']
    assert result['receipt']['code_units'][0]['status'] == 'redacted_analysis_only'


def test_structural_9_blocks_222_items_and_typed_metadata_preserved():
    parts = ['<Module xmlns="http://xmlns.oracle.com/Forms"><FormModule Name="SYNTHETIC">']
    for b in range(9):
        parts.append(f'<Block Name="B{b}" DatabaseBlock="true" QueryDataSourceName="APP.TABLE_{b}" QueryDataSourceType="Table">')
        for i in range(24 + (b < 6)):
            parts.append(f'<Item Name="I{i}" DatabaseItem="true" ItemType="Text Item" DataType="Char" MaximumLength="80" Prompt="Account code" ColumnName="COL_{i}" PrimaryKey="false" InitialValue="PRIVATE_RECORD_VALUE"><DataSourceColumn Name="C{i}" DSCName="COL_{i}" DSCLength="80" DSCPrecision="10" DSCScale="2" DSCType="VARCHAR2"/></Item>')
        parts.append('<Trigger Name="T" TriggerText="BEGIN :B0.I0 := 42; END;"/></Block>')
    parts.append('</FormModule></Module>')
    raw = ''.join(parts).encode()
    result = redact_forms_xml("a.xml", raw)
    fresh = forms_facts.assess_forms_xml("b.xml", result["redacted_xml"])
    assert fresh["totals"]["blocks"] == 9 and fresh["totals"]["items"] == 222
    assert result["receipt"]["object_counts"]["DataSourceColumn"] == 222
    assert b'PRIVATE_RECORD_VALUE' not in result["redacted_xml"]
    nodes = ET.fromstring(result["redacted_xml"])
    item = next(node for node in nodes.iter() if node.tag.endswith('}Item'))
    assert item.attrib == {"Name": "I0", "DatabaseItem": "true", "ItemType": "Text Item", "DataType": "Char", "MaximumLength": "80", "Prompt": "Account code", "ColumnName": "COL_0", "PrimaryKey": "false", "InitialValue": ""}
    assert all(row["name"].startswith('I') for row in fresh["items"])


def test_fields_text_list_choices_and_labels_cleared_no_data_records():
    raw = b'''<FormModule Name="SYNTHETIC" Title="PRIVATE_TITLE" PRIVATE_KEY="SECRET_VALUE">
    <Block Name="B" QueryDataSourceName="SELECT * FROM APP.T WHERE id = 99">
    private text<Item Name="I" Prompt="alice@example.test" InitialValue="PRIVATE_INITIAL">
    <ListItemElement Name="PRIVATE_CHOICE" Value="PRIVATE_CHOICE_VALUE" StaticItemPrompt="Choice A"/>
    <ListItemElement Name="OTHER_PRIVATE" ListItemValue="PRIVATE_RECORD" StaticItemPrompt="Call 123456789"/>
    <ListItemElement Name="Third" StaticItemPrompt="C:/private/input"/>
    </Item>private tail</Block><Property Name="password" Value="PRIVATE_PASSWORD"/>
    <Parameter Name="P" Value="PRIVATE_PARAMETER"/></FormModule>'''
    result = redact_forms_xml("a.xml", raw)
    output = result["redacted_xml"].decode()
    for secret in ["PRIVATE", "private", "alice@", "123456789", "password"]:
        assert secret not in output
    root = ET.fromstring(result["redacted_xml"])
    entries = list(root.iter('ListItemElement'))
    assert [node.get('Name') for node in entries] == ['FOX_REDACTED_ENTRY_1', 'FOX_REDACTED_ENTRY_2', 'FOX_REDACTED_ENTRY_3']
    assert entries[0].get('StaticItemPrompt') == 'Choice A'
    assert entries[1].get('StaticItemPrompt') == '' and entries[2].get('StaticItemPrompt') == ''
    assert result["receipt"]["counts"]["texts_cleared"] == 2
    assert "FOX_REDACTED_NUMBER" in root.find('Block').get('QueryDataSourceName')


def test_lov_column_mapping_metadata_structure_retained_without_private_values():
    raw = b'''<FormModule Name="SYNTHETIC"><Block Name="B" DatabaseBlock="false"><Item Name="I"/></Block>
    <LOV Name="L"><LOVColumnMapping Name="PRIVATE customer choice" ReturnItem="alice@example.test" DisplayWidth="123456789">PRIVATE customer text</LOVColumnMapping>
    <LOVColumnMapping Name="PRIVATE other choice" CUSTOMER_PRIVATE="PRIVATE record" ColumnName="COL_ID">PRIVATE other text</LOVColumnMapping></LOV>
    <Trigger Name="T" TriggerText="BEGIN :B.I := 'PRIVATE code'; END;"/></FormModule>'''
    result = redact_forms_xml('a.xml', raw)
    root = ET.fromstring(result['redacted_xml'])
    mappings = list(root.iter('LOVColumnMapping'))
    assert len(mappings) == 2
    assert mappings[0].attrib == {'Name': ''}
    assert mappings[1].attrib == {'Name': '', 'ColumnName': 'COL_ID'}
    assert not any((node.text or '').strip() for node in mappings)
    assert b'PRIVATE' not in result['redacted_xml'] and b'alice@' not in result['redacted_xml']
    assert result['receipt']['object_counts'] == {'Block': 1, 'FormModule': 1, 'Item': 1, 'LOV': 1, 'Trigger': 1}
    fresh = forms_facts.assess_forms_xml('redacted.xml', result['redacted_xml'])
    assert [(row['kind'], row['name']) for row in fresh['objects']] == [
        ('FormModule', 'SYNTHETIC'), ('Block', 'B'), ('Item', 'I'), ('LOV', 'L'), ('Trigger', 'T')]
    assert result['receipt']['original_sha256'] == hashlib.sha256(raw).hexdigest()
    assert result['receipt']['redacted_sha256'] == hashlib.sha256(result['redacted_xml']).hexdigest()
    assert result['receipt']['code_units'][0]['redacted_sha256'] == fresh['code_units'][0]['sha256']
    assert result == redact_forms_xml('a.xml', raw)


@pytest.mark.parametrize('foreign', [
    '<f:LOVColumnMapping xmlns:f="urn:PRIVATE" Name="PRIVATE"/>',
    '<LOVColumnMapping xmlns:f="urn:PRIVATE" f:Name="PRIVATE"/>',
    '<LOVColumnMapping xmlns:f="urn:PRIVATE" f:TriggerText="PRIVATE"/>',
])
def test_lov_mapping_allowlist_does_not_accept_foreign_aliases(foreign):
    with pytest.raises(ValueError) as caught:
        redact_forms_xml('a.xml', f'<FormModule Name="SYNTHETIC"><LOV Name="L">{foreign}</LOV></FormModule>'.encode())
    assert 'PRIVATE' not in str(caught.value)


def test_query_data_source_type_none_is_preserved_technical_enum():
    raw = b'<FormModule Name="SYNTHETIC"><Block Name="B" DatabaseBlock="false" QueryDataSourceType="None"><Item Name="I"/></Block></FormModule>'
    result = redact_forms_xml('a.xml', raw)
    assert ET.fromstring(result['redacted_xml']).find('Block').get('QueryDataSourceType') == 'None'
    assert result['receipt']['verification']['recognized_names_preserved']


def test_code_text_attributes_hash_receipt_and_determinism():
    code = "BEGIN x := 'PRIVATE_LITERAL'; END;"
    raw = (f'<FormModule Name="SYNTHETIC"><Trigger Name="T"><TriggerText>{code}</TriggerText></Trigger>'
           f'<ProgramUnit Name="P">{code}</ProgramUnit><RecordGroup Name="RG"><RecordGroupQuery>SELECT id FROM APP.T WHERE id=42</RecordGroupQuery></RecordGroup></FormModule>').encode()
    result = redact_forms_xml("a.xml", raw)
    assert result == redact_forms_xml("a.xml", raw)
    receipt = result["receipt"]
    assert receipt["original_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["redacted_sha256"] == hashlib.sha256(result["redacted_xml"]).hexdigest()
    fresh = forms_facts.assess_forms_xml("redacted.xml", result["redacted_xml"])
    assert {row["redacted_sha256"] for row in receipt["code_units"]} == {row["sha256"] for row in fresh["code_units"]}
    assert receipt["code_units"][0]["original_sha256"] == hashlib.sha256(code.encode()).hexdigest()
    serialized = json.dumps(receipt)
    assert "PRIVATE_LITERAL" not in serialized and "BEGIN" not in serialized and "APP.T" not in serialized
    assert len(receipt["code_units"]) == 3


@pytest.mark.parametrize("name,raw", [
    ('../PRIVATE.xml', b'<FormModule Name="A"/>'), ('PRIVATE.fmb', b'PRIVATE'), ('a.xml', b''),
    ('a.xml', b'\xffPRIVATE'), ('a.xml', b'\0PRIVATE'), ('a.xml', b'<PRIVATE'),
    ('a.xml', b'<?xml version="1.0" encoding="ISO-8859-1"?><FormModule Name="A"/>'),
    ('a.xml', b'<!DOCTYPE x [<!ENTITY e "PRIVATE">]><FormModule Name="A">&e;</FormModule>'),
    ('a.xml', b'<!DOCTYPE x SYSTEM "file:///PRIVATE"><FormModule Name="A"/>'),
    ('a.xml', b'<FormModule xmlns="urn:PRIVATE" Name="A"/>'),
    ('a.xml', b'<FormModule Name="A"><private:Trigger xmlns:private="urn:PRIVATE" Name="T"/></FormModule>'),
    ('a.xml', b'<FormModule Name="A" xmlns:p="urn:PRIVATE" p:TriggerText="PRIVATE"/>'),
    ('a.xml', b'<FormModule Name="A"><PRIVATE/></FormModule>'),
    ('a.xml', b'<FormModule Name="PRIVATE@example.test"/>'),
])
def test_bounded_errors_never_echo_input(name, raw):
    with pytest.raises(ValueError) as caught:
        redact_forms_xml(name, raw)
    assert len(str(caught.value)) < 200 and 'PRIVATE' not in str(caught.value)


def test_limits_and_independent_fresh_safety_assessment(monkeypatch):
    raw = b'<FormModule Name="A"><Block Name="B"/></FormModule>'
    monkeypatch.setattr(forms_facts, 'MAX_ELEMENTS', 1)
    with pytest.raises(ValueError, match='bounded'):
        redact_forms_xml('a.xml', raw)
    monkeypatch.setattr(forms_facts, 'MAX_ELEMENTS', 30000)
    monkeypatch.setattr(forms_facts, 'MAX_DEPTH', 1)
    with pytest.raises(ValueError, match='bounded'):
        redact_forms_xml('a.xml', raw)
    monkeypatch.setattr(forms_facts, 'MAX_DEPTH', 128)
    monkeypatch.setattr(forms_facts, 'MAX_ATTRIBUTES', 1)
    with pytest.raises(ValueError, match='bounded'):
        redact_forms_xml('a.xml', b'<FormModule Name="A" Title="B"/>')
    monkeypatch.setattr(forms_facts, 'MAX_FILE_BYTES', 10)
    with pytest.raises(ValueError, match='at most'):
        redact_forms_xml('a.xml', raw)


def test_no_external_io_or_execution(monkeypatch):
    import socket
    import subprocess

    def forbidden(*args, **kwargs):
        raise AssertionError('external access forbidden')

    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    assert redact_forms_xml('a.xml', document("BEGIN x := 'private'; END;"))["receipt"]["verification"]["fresh_assessment_passed"]


def test_code_token_budget_withholds_whole_unit(monkeypatch):
    monkeypatch.setattr(forms_redaction, 'MAX_CODE_TOKENS', 3)
    result = redact_forms_xml('a.xml', document("BEGIN x := 'PRIVATE'; END;"))
    assert result['receipt']['code_units'][0]['reason'] == 'bounded_token_limit'
    assert b'PRIVATE' not in result['redacted_xml']


def test_forms2xml_encoded_whitespace_normalized_before_analysis_not_original_hashing():
    code = "BEGIN&#13;&#10;&#9;-- PRIVATE comment&#10;password := 'PRIVATE credential';&#10;CALL_FORM('OTHER_FORM');&#10;END;"
    raw = document(code)
    saved = bytes(raw)
    result = redact_forms_xml('a.xml', raw)
    assert raw == saved
    mapping = result['receipt']['code_units'][0]
    normalized = code.replace('&#13;', '\r').replace('&#10;', '\n').replace('&#9;', '\t')
    assert mapping['status'] == 'redacted_analysis_only'
    assert mapping['original_sha256'] == hashlib.sha256(code.encode()).hexdigest()
    assert mapping['normalized_input_sha256'] == hashlib.sha256(normalized.encode()).hexdigest()
    assert mapping['original_sha256'] != mapping['normalized_input_sha256']
    assert mapping['encoded_whitespace_normalizations'] == 6
    assert result['receipt']['counts']['encoded_whitespace_normalizations'] == 6
    assert result['receipt']['original_sha256'] == hashlib.sha256(saved).hexdigest()
    assert mapping['hash_basis'] == 'xml-decoded-utf8'
    assert 'analysis-only' in mapping['normalized_input_hash_basis']
    output = result['redacted_xml'].decode()
    assert 'PRIVATE' not in output and 'credential' not in output
    assert 'FOX_REDACTED_COMMENT_1' in output and 'FOX_REDACTED_LITERAL_1' in output
    # Decoded LF must terminate the line comment so the following actual code is
    # separately sanitized, not swallowed into a purported analyzed comment.
    assert 'password :=' in output and "CALL_FORM('OTHER_FORM')" in output
    fresh = forms_facts.assess_forms_xml('redacted.xml', result['redacted_xml'])
    assert mapping['redacted_sha256'] == fresh['code_units'][0]['sha256']


def test_encoded_whitespace_inside_literals_still_fully_masked_and_counts_aggregate():
    first = "BEGIN x := 'PRIVATE&#10;literal&#9;remainder'; END;"
    second = "BEGIN&#13;NULL; END;"
    raw = (f'<FormModule Name="SYNTHETIC"><Trigger Name="T" TriggerText={quoteattr(first)}/>'
           f'<ProgramUnit Name="P" ProgramUnitText={quoteattr(second)}/></FormModule>').encode()
    result = redact_forms_xml('a.xml', raw)
    mappings = result['receipt']['code_units']
    assert [row['encoded_whitespace_normalizations'] for row in mappings] == [2, 1]
    assert result['receipt']['counts']['encoded_whitespace_normalizations'] == 3
    assert all(row['status'] == 'redacted_analysis_only' for row in mappings)
    for secret in [b'PRIVATE', b'literal', b'remainder', b'&amp;#10;', b'&amp;#9;']:
        assert secret not in result['redacted_xml']


@pytest.mark.parametrize('unsupported', ['&unknown;', '&#65;', '&#xA;', '&#00010;', '&amp;#10;', '&'])
def test_unknown_ampersands_and_nonwhitespace_entities_not_decoded(unsupported):
    code = f'BEGIN&#10;{unsupported} PRIVATE_REMAINDER; END;'
    result = redact_forms_xml('a.xml', document(code))
    mapping = result['receipt']['code_units'][0]
    assert mapping['status'] == 'withheld' and mapping['reason'] == 'unsupported_lexeme'
    assert mapping['encoded_whitespace_normalizations'] == 1
    assert b'PRIVATE_REMAINDER' not in result['redacted_xml']
    assert b'BEGIN' not in result['redacted_xml'] and b'FOX_REDACTED_UNIT_WITHHELD' in result['redacted_xml']


def test_normalization_does_not_decode_general_entities_inside_literals():
    code = "BEGIN x := '&#65;PRIVATE&#xA;'; END;"
    result = redact_forms_xml('a.xml', document(code))
    mapping = result['receipt']['code_units'][0]
    assert mapping['normalized_input_sha256'] == mapping['original_sha256']
    assert mapping['encoded_whitespace_normalizations'] == 0
    assert b'PRIVATE' not in result['redacted_xml']


@pytest.mark.parametrize('placement', ['attribute', 'body'])
@pytest.mark.parametrize('code', [
    'connect synthetic_user/SYNTHETIC_PASSWORD',
    'conn synthetic_user/SYNTHETIC_PASSWORD',
    'conne synthetic_user/SYNTHETIC_PASSWORD',
    'connec synthetic_user/SYNTHETIC_PASSWORD',
    'CoNn /* user */ synthetic_user /* slash */ / /* value */ SYNTHETIC_PASSWORD',
    'CONN&#10;synthetic_user&#10;/&#10;SYNTHETIC_PASSWORD',
    'conn -- user follows&#13;"synthetic_user" / "SYNTHETIC_PASSWORD"',
    'CONNECT synthetic_user / SYNTHETIC_PASSWORD@synthetic_db',
    'CoNnEcT "synthetic_user" / "SYNTHETIC_PASSWORD"',
    "connect 'synthetic_user' / 'SYNTHETIC_PASSWORD'",
    'connect /* username */ synthetic_user /* slash */ / /* password */ SYNTHETIC_PASSWORD',
    'connect&#10;synthetic_user&#10;/&#10;SYNTHETIC_PASSWORD',
    'connect -- username ends here&#10;synthetic_user / -- password follows&#10;SYNTHETIC_PASSWORD',
    'connect -- username ends here&#13;synthetic_user / -- password follows&#13;SYNTHETIC_PASSWORD',
    'alter user synthetic_user identified by SYNTHETIC_PASSWORD',
    'ALTER USER "synthetic_user" IDENTIFIED BY "SYNTHETIC_PASSWORD"',
    "alter user synthetic_user identified by 'SYNTHETIC_PASSWORD'",
    'ALTER USER synthetic_user IDENTIFIED /* comment */ BY SYNTHETIC_PASSWORD',
    'alter user synthetic_user identified&#13;&#10;by&#9;SYNTHETIC_PASSWORD',
    'CREATE DATABASE LINK synthetic_link CONNECT TO synthetic_user IDENTIFIED BY SYNTHETIC_PASSWORD',
    "CREATE DATABASE LINK synthetic_link CONNECT TO synthetic_user IDENTIFIED BY 'SYNTHETIC_PASSWORD'",
    'create database link synthetic_link connect to "synthetic_user" identified -- newline&#10;by "SYNTHETIC_PASSWORD"',
])
def test_credential_constructs_wholly_withheld_end_to_end(code, placement):
    if placement == 'attribute':
        raw = document(code)
    else:
        from xml.sax.saxutils import escape
        raw = f'<FormModule Name="SYNTHETIC"><Trigger Name="T">{escape(code)}</Trigger></FormModule>'.encode()
    original = bytes(raw)
    result = redact_forms_xml('a.xml', raw)
    assert raw == original
    assert b'SYNTHETIC_PASSWORD' not in result['redacted_xml']
    assert b'synthetic_user' not in result['redacted_xml']
    assert b'FOX_REDACTED_UNIT_WITHHELD' in result['redacted_xml']
    assert 'SYNTHETIC_PASSWORD' not in json.dumps(result['receipt'])
    assert 'synthetic_user' not in json.dumps(result['receipt'])
    mapping = result['receipt']['code_units'][0]
    assert mapping['status'] == 'withheld'
    assert mapping['reason'] in {'credential_construct', 'unsupported_lexeme'}
    assert mapping['original_sha256'] == hashlib.sha256(code.encode()).hexdigest()
    normalized = code.replace('&#10;', '\n').replace('&#13;', '\r').replace('&#9;', '\t')
    assert mapping['normalized_input_sha256'] == hashlib.sha256(normalized.encode()).hexdigest()
    fresh = forms_facts.assess_forms_xml('redacted.xml', result['redacted_xml'])
    assert mapping['redacted_sha256'] == fresh['code_units'][0]['sha256']


def test_credential_mentions_inside_comments_or_literals_are_masked_not_inspected_as_grammar():
    code = """BEGIN
    -- connect synthetic_user/SYNTHETIC_PASSWORD
    -- conn synthetic_user/SYNTHETIC_PASSWORD
    /* alter user synthetic_user identified by SYNTHETIC_PASSWORD */
    x := 'connect synthetic_user/SYNTHETIC_PASSWORD';
    y := q'[alter user synthetic_user identified by SYNTHETIC_PASSWORD]';
    z := 'conn synthetic_user/SYNTHETIC_PASSWORD';
    CONNECT('synthetic_user', 'SYNTHETIC_PASSWORD');
    APP.CONNECT('synthetic_user', 'SYNTHETIC_PASSWORD');
    APP.CONN('synthetic_user', 'SYNTHETIC_PASSWORD');
    END;"""
    result = redact_forms_xml('a.xml', document(code))
    mapping = result['receipt']['code_units'][0]
    assert mapping['status'] == 'redacted_analysis_only'
    assert b'SYNTHETIC_PASSWORD' not in result['redacted_xml']
    assert b'synthetic_user' not in result['redacted_xml']
    assert b'CONNECT(FOX_REDACTED_LITERAL_' in result['redacted_xml']
    assert 'SYNTHETIC_PASSWORD' not in json.dumps(result['receipt'])


@pytest.mark.parametrize('alias', ['CONNECT', 'CONN', 'CONNE', 'CONNEC'])
@pytest.mark.parametrize('suffix', [
    'synthetic_proxy[synthetic_client]/SYNTHETIC_PASSWORD',
    'synthetic_proxy /* c */ [synthetic_client] /* c */ / SYNTHETIC_PASSWORD',
    '"synthetic_proxy"["synthetic_client"] / "SYNTHETIC_PASSWORD" AS SYSDBA',
    "'synthetic_proxy'['synthetic_client'] / 'SYNTHETIC_PASSWORD'",
    'synthetic_proxy[synthetic_client]/SYNTHETIC_PASSWORD AS SYSDBA',
    '&#10;synthetic_proxy&#9;[synthetic_client]&#13;/ SYNTHETIC_PASSWORD',
    'unknown user grammar SYNTHETIC_PASSWORD',
    'synthetic_user SYNTHETIC_PASSWORD',
])
@pytest.mark.parametrize('placement', ['attribute', 'body'])
def test_connect_command_grammar_not_dependent_on_username_shape(alias, suffix, placement):
    from xml.sax.saxutils import escape

    code = f'{alias} /* command separator */ {suffix}'
    raw = document(code) if placement == 'attribute' else (
        f'<FormModule Name="SYNTHETIC"><Trigger Name="T">{escape(code)}</Trigger></FormModule>'.encode())
    result = redact_forms_xml('a.xml', raw)
    assert result['receipt']['code_units'][0]['status'] == 'withheld'
    assert result['receipt']['code_units'][0]['reason'] == 'credential_construct'
    assert b'SYNTHETIC_PASSWORD' not in result['redacted_xml']
    assert 'SYNTHETIC_PASSWORD' not in json.dumps(result['receipt'])
    assert b'synthetic_proxy' not in result['redacted_xml']
    assert b'FOX_REDACTED_UNIT_WITHHELD' in result['redacted_xml']


@pytest.mark.parametrize('hierarchy', ['CONNECT BY', 'CONNECT /* normal SQL */ BY', 'CONNECT&#10;BY NOCYCLE'])
def test_connect_by_hierarchical_queries_not_treated_as_credentials(hierarchy):
    code = f'SELECT id FROM APP.T START WITH parent_id = 0 {hierarchy} PRIOR id = parent_id'
    result = redact_forms_xml('a.xml', document(code))
    assert result['receipt']['code_units'][0]['status'] == 'redacted_analysis_only'
    assert b'PRIOR id = parent_id' in result['redacted_xml']


@pytest.mark.parametrize('alias', ['CONNECT', 'CONN', 'CONNE', 'CONNEC'])
def test_connect_abbreviation_normal_qualified_calls_remain_masked(alias):
    result = redact_forms_xml('a.xml', document(f"BEGIN APP.{alias} /* call */ ('synthetic_user', 'SYNTHETIC_PASSWORD'); END;"))
    assert result['receipt']['code_units'][0]['status'] == 'redacted_analysis_only'
    assert b'SYNTHETIC_PASSWORD' not in result['redacted_xml']


@pytest.mark.parametrize('placement', ['attribute', 'body'])
@pytest.mark.parametrize('code', [
    'connect BY/SYNTHETIC_PASSWORD',
    'connect BY[client]/SYNTHETIC_PASSWORD',
    'CONNECT /* separator */ BY /* slash */ / SYNTHETIC_PASSWORD',
    'CONNECT BY -- proxy follows&#10;[client] / SYNTHETIC_PASSWORD',
    'SELECT id FROM APP.T; connect BY/SYNTHETIC_PASSWORD',
    'SELECT id FROM APP.T CONNECT BY/SYNTHETIC_PASSWORD',
    'SELECT id FROM APP.T CONNECT BY[client]/SYNTHETIC_PASSWORD',
    'SELECT id FROM APP.T CONN BY SYNTHETIC_PASSWORD',
    'SELECT id FROM APP.T CONNE BY SYNTHETIC_PASSWORD',
    'SELECT id FROM APP.T CONNEC BY SYNTHETIC_PASSWORD',
    'CONNECT BY SYNTHETIC_PASSWORD',
    'CONNECT BY NOCYCLE SYNTHETIC_PASSWORD',
    "x := 'SELECT id FROM APP.T'; CONNECT BY/SYNTHETIC_PASSWORD",
    '/* SELECT id FROM APP.T */ CONNECT BY/SYNTHETIC_PASSWORD',
])
def test_by_username_or_missing_sql_query_context_not_hierarchical_exemption(code, placement):
    from xml.sax.saxutils import escape

    raw = document(code) if placement == 'attribute' else (
        f'<FormModule Name="SYNTHETIC"><Trigger Name="T">{escape(code)}</Trigger></FormModule>'.encode())
    result = redact_forms_xml('a.xml', raw)
    assert result['receipt']['code_units'][0]['status'] == 'withheld'
    assert result['receipt']['code_units'][0]['reason'] == 'credential_construct'
    assert b'SYNTHETIC_PASSWORD' not in result['redacted_xml']
    assert 'SYNTHETIC_PASSWORD' not in json.dumps(result['receipt'])


@pytest.mark.parametrize('placement', ['attribute', 'body'])
@pytest.mark.parametrize('code', [
    'SELECT id FROM APP.T CONNECT BY PRIOR id = parent_id',
    'SELECT id FROM APP.T START WITH parent_id = 0 CONNECT BY NOCYCLE PRIOR id = parent_id',
    'BEGIN SELECT id INTO v_id FROM APP.T CONNECT /* hierarchy */ BY&#10;NOCYCLE PRIOR id = parent_id; END;',
])
def test_hierarchy_context_preserved_in_body_and_attribute_units(code, placement):
    from xml.sax.saxutils import escape

    raw = document(code) if placement == 'attribute' else (
        f'<FormModule Name="SYNTHETIC"><Trigger Name="T">{escape(code)}</Trigger></FormModule>'.encode())
    result = redact_forms_xml('a.xml', raw)
    assert result['receipt']['code_units'][0]['status'] == 'redacted_analysis_only'
    assert b'PRIOR id = parent_id' in result['redacted_xml']
