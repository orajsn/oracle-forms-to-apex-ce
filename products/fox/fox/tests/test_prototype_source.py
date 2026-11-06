"""Fabricated masked XML only; no real/customer source fixture is published."""
from collections import Counter
from copy import deepcopy
import hashlib
from xml.etree import ElementTree as ET
from xml.sax.saxutils import quoteattr

import pytest

from fox import forms_facts, forms_redaction
from fox.intake import checked_source
from fox.prototype_source import validate_redacted_prototype_source


@pytest.mark.parametrize('payload', [b'<!-- SYNTHETIC_PRIVATE_RECORD Jane Example 123456789 -->',
                                    b'<?private SYNTHETIC_PRIVATE_RECORD Jane Example 123456789 ?>'])
@pytest.mark.parametrize('position', ['before', 'inside', 'after'])
def test_unmasked_xml_comments_and_processing_instructions_are_rejected(payload, position):
    result = forms_redaction.redact_forms_xml('demo.xml', source('BEGIN NULL; END;'))
    raw = result['redacted_xml']
    if raw.startswith(b'<?xml'):
        declaration, raw = raw.split(b'?>', 1)
        declaration += b'?>'
    else:
        declaration = b''
    if position == 'before':
        raw = payload + raw
    elif position == 'after':
        raw += payload
    else:
        offset = raw.index(b'>') + 1
        raw = raw[:offset] + payload + raw[offset:]
    raw = declaration + raw
    receipt = deepcopy(result['receipt'])
    receipt['redacted_sha256'] = hashlib.sha256(raw).hexdigest()
    receipt['redacted_bytes'] = len(raw)
    with pytest.raises(ValueError):
        validate_redacted_prototype_source('demo.xml', raw, receipt)


def source(code, extras=''):
    return (f'<FormModule Name="SYNTHETIC"><Block Name="B" DatabaseBlock="true">'
            '<Item Name="I" ItemType="Text Item" DataType="Char" MaximumLength="80" '
            'DatabaseItem="true" Prompt="Value"/>'
            f'<Trigger Name="SAVE" TriggerText={quoteattr(code)}/></Block>{extras}</FormModule>').encode()


def masked(code=None, extras=''):
    code = code or "BEGIN INSERT INTO AUDIT_LOG VALUES (:B.I, 'SYNTHETIC_PRIVATE_LITERAL', 99); GO_ITEM('B.I'); END;"
    result = forms_redaction.redact_forms_xml('synthetic.xml', source(code, extras))
    return result['redacted_xml'], result['receipt']


def forged_receipt(raw, receipt):
    """An untrusted receipt can be rehashed; literal checks must STILL reject."""
    receipt = deepcopy(receipt)
    facts = forms_facts.assess_forms_xml('synthetic.xml', raw)
    receipt.update(redacted_sha256=hashlib.sha256(raw).hexdigest(), redacted_bytes=len(raw),
                   object_counts=dict(Counter(row['kind'] for row in facts['objects'])))
    units = {(unit['location']['path'], unit['source_attribute']): unit for unit in facts['code_units']}
    for unit in receipt['code_units']:
        key = unit['location']['path'], unit['source_attribute']
        unit['redacted_sha256'] = units[key]['sha256']
    return receipt


def replace_code(raw, code):
    root = ET.fromstring(raw)
    root.find('.//Trigger').set('TriggerText', code)
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


def test_exact_existing_redactor_output_with_masked_business_dml_is_allowed_only_explicitly():
    raw, receipt = masked()
    before = deepcopy((raw, receipt))
    with pytest.raises(ValueError, match='DML cannot'):
        checked_source('synthetic.xml', raw)
    checked = validate_redacted_prototype_source('synthetic.xml', raw, receipt)
    assert set(checked) == {'name', 'sha256', 'bytes', 'text'}
    assert checked['sha256'] == hashlib.sha256(raw).hexdigest()
    assert checked['bytes'] == len(raw) and checked['text'].encode() == raw
    assert (raw, receipt) == before
    with pytest.raises(ValueError, match='DML cannot'):
        checked_source('synthetic.xml', raw)


@pytest.mark.parametrize('code', [
    "BEGIN x := 'SYNTHETIC_PRIVATE_LITERAL'; END;",
    'BEGIN x := "SYNTHETIC_PRIVATE_IDENTIFIER"; END;',
    "BEGIN x := q'[SYNTHETIC_PRIVATE_LITERAL]'; END;",
    "BEGIN x := N'SYNTHETIC_PRIVATE_LITERAL'; END;",
    'BEGIN x := 42; END;', 'BEGIN x := .01; END;', 'BEGIN x := 1e3; END;',
    "BEGIN INSERT INTO AUDIT_LOG VALUES ('SYNTHETIC_ROW'); END;",
    "BEGIN pkg.GO_ITEM('B.I'); END;", "BEGIN GO_ITEM('B.I'||suffix); END;",
    "BEGIN GO_ITEM('B.I', 'SYNTHETIC_SECOND_ARGUMENT'); END;",
    "BEGIN arbitrary('SYNTHETIC_IDENTIFIER'); END;",
    'BEGIN /* SYNTHETIC_PRIVATE_COMMENT */ NULL; END;',
    'BEGIN -- SYNTHETIC_PRIVATE_COMMENT\n NULL; END;',
])
def test_marker_and_rehashed_receipt_cannot_authorize_unmasked_literals_or_comments(code):
    raw, receipt = masked()
    raw = replace_code(raw, '/* FOX_ANALYSIS_ONLY_NON_EXECUTABLE */\n' + code)
    with pytest.raises(ValueError, match='Prepared prototype source') as error:
        validate_redacted_prototype_source('synthetic.xml', raw, forged_receipt(raw, receipt))
    assert 'SYNTHETIC_PRIVATE' not in str(error.value)


@pytest.mark.parametrize('code', [
    "BEGIN INSERT INTO AUDIT_LOG VALUES (:B.I, 0, 1, FOX_REDACTED_LITERAL_1); END;",
    "BEGIN GO_ITEM('B.I'); GO_BLOCK('B'); CALL_FORM('NEXT_FORM'); END;",
    "BEGIN SET_ITEM_PROPERTY('B.I', LABEL, FOX_REDACTED_LITERAL_1); END;",
    'BEGIN FOR i IN 1..FOX_REDACTED_NUMBER_1 LOOP NULL; END LOOP; END;',
])
def test_only_existing_redactor_preserved_technical_literals_and_zero_one_constants(code):
    raw, receipt = masked(code)
    assert validate_redacted_prototype_source('synthetic.xml', raw, receipt)['bytes'] == len(raw)


@pytest.mark.parametrize('change', ['hash', 'bytes', 'policy', 'missing-unit', 'duplicate-unit',
                                  'unit-hash', 'unit-location', 'objects', 'safety', 'extra-key'])
def test_receipt_matches_exact_bytes_complete_units_and_conservative_policy(change):
    raw, receipt = masked()
    if change == 'hash':
        receipt['redacted_sha256'] = '0' * 64
    elif change == 'bytes':
        receipt['redacted_bytes'] += 1
    elif change == 'policy':
        receipt['policy_id'] = 'unapproved-policy'
    elif change == 'missing-unit':
        receipt['code_units'].clear()
    elif change == 'duplicate-unit':
        receipt['code_units'].append(deepcopy(receipt['code_units'][0]))
    elif change == 'unit-hash':
        receipt['code_units'][0]['redacted_sha256'] = '0' * 64
    elif change == 'unit-location':
        receipt['code_units'][0]['location']['path'] = '/invented[1]'
    elif change == 'objects':
        receipt['object_counts']['Block'] += 1
    elif change == 'safety':
        receipt['safety']['model_submission_allowed'] = True
    else:
        receipt['privately_injected'] = 'SYNTHETIC_PRIVATE_VALUE'
    with pytest.raises(ValueError, match='Prepared prototype source'):
        validate_redacted_prototype_source('synthetic.xml', raw, receipt)


def test_unmarked_code_is_not_mistaken_for_masked_source_even_with_receipt_hash():
    raw, receipt = masked()
    raw = replace_code(raw, 'BEGIN INSERT INTO AUDIT_LOG VALUES (:B.I); END;')
    with pytest.raises(ValueError, match='Prepared prototype source'):
        validate_redacted_prototype_source('synthetic.xml', raw, forged_receipt(raw, receipt))


def test_credential_grammar_never_enters_prepared_prototype_assessment():
    raw, receipt = masked()
    raw = replace_code(raw, '/* FOX_ANALYSIS_ONLY_NON_EXECUTABLE */\nCONNECT user/SYNTHETIC_SECRET@database')
    receipt.update(redacted_sha256=hashlib.sha256(raw).hexdigest(), redacted_bytes=len(raw))
    with pytest.raises(ValueError, match='Prepared prototype source') as error:
        validate_redacted_prototype_source('synthetic.xml', raw, receipt)
    assert 'SYNTHETIC_SECRET' not in str(error.value)


def test_fully_withheld_units_remain_withheld_not_reconstructed():
    raw, receipt = masked("BEGIN x := 'SYNTHETIC_UNTERMINATED; END;")
    assert receipt['code_units'][0]['status'] == 'withheld'
    assert validate_redacted_prototype_source('synthetic.xml', raw, receipt)['bytes'] == len(raw)
    raw = replace_code(raw, '/* FOX_REDACTED_UNIT_WITHHELD: ANALYSIS_ONLY; DO_NOT_RECONSTRUCT */ BEGIN NULL; END;')
    with pytest.raises(ValueError):
        validate_redacted_prototype_source('synthetic.xml', raw, forged_receipt(raw, receipt))


@pytest.mark.parametrize('attribute,value', [('InitialValue', 'SYNTHETIC_RECORD'),
                                           ('Value', 'SYNTHETIC_RECORD'),
                                           ('UnknownProperty', 'SYNTHETIC_PRIVATE'),
                                           ('MaximumLength', '987654321')])
def test_forged_receipt_does_not_hide_unmasked_xml_property_values(attribute, value):
    raw, receipt = masked()
    root = ET.fromstring(raw)
    root.find('.//Item').set(attribute, value)
    raw = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    with pytest.raises(ValueError):
        validate_redacted_prototype_source('synthetic.xml', raw, forged_receipt(raw, receipt))


def test_unknown_xml_element_and_entity_payloads_are_not_allowed():
    raw, receipt = masked()
    for changed in (raw.replace(b'<Block ', b'<UnsafeData '),
                    b'<!DOCTYPE x [<!ENTITY e "SYNTHETIC_PRIVATE">]><FormModule Name="A">&e;</FormModule>'):
        with pytest.raises(ValueError):
            validate_redacted_prototype_source('synthetic.xml', changed, receipt)
