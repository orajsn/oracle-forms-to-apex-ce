"""Deterministic synthetic preservation policy checks; no provider or Oracle."""
import copy
import json
from xml.sax.saxutils import quoteattr

import pytest

from fox import development_source as dev
from fox.prototype_source import validate_prepared_source, validate_redacted_prototype_source


def xml(code):
    return ('<FormModule Name="SYNTHETIC"><Trigger Name="T" TriggerText=' + quoteattr(code) + '/></FormModule>').encode()


def test_business_literals_comments_and_code_bytes_preserved():
    code = "BEGIN -- keep this explanation\n :B.STATUS := 'APPROVED'; :B.AMOUNT := 12345.67; :B.F := 'DD-MON-YYYY'; :B.URL := 'https://example.invalid/path'; END;"
    raw = xml(code)
    result = dev.preserve_development_source('source.xml', raw)
    assert result['document']['text'].encode() == raw
    assert result['receipt']['credential_review']['finding_count'] == 0
    assert validate_prepared_source('source.xml', raw, result['receipt']) == result['document']
    with pytest.raises(ValueError):
        validate_redacted_prototype_source('source.xml', raw, result['receipt'])


@pytest.mark.parametrize('code', [
    "BEGIN password := 'SYNTHETIC_CREDENTIAL'; END;",
    'BEGIN l_password := SYNTHETIC_CREDENTIAL; END;',
    'BEGIN api_key = SYNTHETIC_CREDENTIAL; END;',
    'ALTER USER demo IDENTIFIED BY SYNTHETIC_CREDENTIAL;',
    'CONNECT demo/SYNTHETIC_CREDENTIAL@example',
    'USERID=demo/SYNTHETIC_CREDENTIAL@example',
    'jdbc:oracle:thin:demo/SYNTHETIC_CREDENTIAL@example',
    "LOGON('demo', 'SYNTHETIC_CREDENTIAL');",
    '-- Authorization: Bearer SYNTHETIC_CREDENTIAL',
    "BEGIN :B.URL := 'https://demo:SYNTHETIC_CREDENTIAL@example.invalid'; END;",
    '-- -----BEGIN RSA PRIVATE KEY----- SYNTHETIC_CREDENTIAL',
    'BEGIN password&#10;:=&#9;SYNTHETIC_CREDENTIAL; END;',
])
def test_possible_credentials_block_without_echoing_values(code):
    raw = xml(code)
    result = dev.preserve_development_source('source.xml', raw)
    review = result['receipt']['credential_review']
    assert review['status'] == dev.CREDENTIAL_REVIEW and review['finding_count']
    assert 'SYNTHETIC_CREDENTIAL' not in json.dumps(result['receipt'])
    assert set(review['findings'][0]) == {'rule', 'element', 'field', 'ordinal', 'decoded_line',
                                         'xml_line', 'xml_column', 'xml_byte_offset'}
    with pytest.raises(ValueError) as error:
        validate_prepared_source('source.xml', raw, result['receipt'])
    assert 'SYNTHETIC_CREDENTIAL' not in str(error.value)


@pytest.mark.parametrize('raw', [
    b'<FormModule Name="T"><!-- password := SYNTHETIC_CREDENTIAL --></FormModule>',
    b'<FormModule Name="T"><Property Name="password" Value="SYNTHETIC_CREDENTIAL"/></FormModule>',
    b'<FormModule Name="T"><Trigger Name="T">password<![CDATA[ := SYNTHETIC_CREDENTIAL]]></Trigger></FormModule>',
    b'<FormModule Name="T"><?note password := SYNTHETIC_CREDENTIAL?></FormModule>',
    b'<FormModule Name="T" Password="SYNTHETIC_CREDENTIAL"/>',
])
def test_decoded_fields_comments_split_text_and_pi_are_scanned(raw):
    review = dev.review_xml('source.xml', raw)
    assert review['finding_count'] and 'SYNTHETIC_CREDENTIAL' not in json.dumps(review)


@pytest.mark.parametrize('change', ['policy_id', 'preparation_mode', 'source_sha256', 'source_bytes', 'credential_review', 'extra'])
def test_forged_receipt_is_rejected(change):
    raw = xml('BEGIN NULL; END;')
    receipt = copy.deepcopy(dev.preserve_development_source('source.xml', raw)['receipt'])
    receipt[change] = 'forged'
    with pytest.raises(ValueError):
        validate_prepared_source('source.xml', raw, receipt)


def test_bounded_findings_keep_total_and_no_body():
    raw = xml('\n'.join('password := SYNTHETIC_CREDENTIAL;' for _ in range(250)))
    review = dev.review_xml('source.xml', raw)
    assert review['finding_count'] == 250
    assert len(review['findings']) == dev.MAX_FINDINGS and review['findings_truncated']


def test_comment_locations_are_distinct_and_point_into_exact_xml():
    raw = b'<FormModule Name="T">\n<!-- harmless -->\n<!-- password := SYNTHETIC_CREDENTIAL -->\n</FormModule>'
    finding = dev.review_xml('source.xml', raw)['findings'][0]
    assert finding['field'] == 'comment' and finding['ordinal'] == 2
    assert finding['xml_line'] == 3 and finding['xml_column'] == 1
    assert raw[finding['xml_byte_offset']:].startswith(b'<!-- password')


@pytest.mark.parametrize('raw', [b'<!DOCTYPE x [<!ENTITY e "password := value">]><FormModule Name="T">&e;</FormModule>', b'<broken', b'\xff'])
def test_unsafe_xml_is_rejected_body_free(raw):
    with pytest.raises(ValueError, match='preservation policy'):
        dev.review_xml('source.xml', raw)
