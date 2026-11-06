"""Explicit prepared-prototype source intake for existing redactor masked XML.

Never call this as a fallback from ordinary checked_source. A dedicated project
ingestion path must persist the validated receipt with the exact source hash.
The source-history reader must revalidate that provenance, not trust a flag.
This permits non-executing analysis of masked business DML, NOT data loading,
working business code, complete anonymization, model permission or conversion.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import re
from xml.parsers import expat

from . import forms_facts, forms_redaction
from .forms_understanding_packet import _build
from .intake import SECRETS

_ANALYSIS = '/* FOX_ANALYSIS_ONLY_NON_EXECUTABLE */'
_COMMENT = re.compile(r'/\* FOX_REDACTED_COMMENT_[1-9][0-9]* \*/\Z')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_REASONS = {'malformed_comment', 'malformed_literal', 'malformed_numeric', 'malformed_adjacent_tokens',
            'unsupported_lexeme', 'bounded_token_limit', 'credential_construct', 'unsafe_remaining_lexeme'}
_RECEIPT_KEYS = {'schema_version', 'policy_id', 'status', 'original_sha256', 'redacted_sha256',
                 'original_bytes', 'redacted_bytes', 'code_units', 'counts', 'object_counts',
                 'verification', 'safety', 'limitations'}
_UNIT_KEYS = {'location', 'source_attribute', 'original_sha256', 'redacted_sha256',
              'normalized_input_sha256', 'encoded_whitespace_normalizations', 'hash_basis',
              'normalized_input_hash_basis', 'status'}
_COUNTS = {'encoded_whitespace_normalizations', 'fields_cleared', 'texts_cleared', 'list_entries_masked',
           'technical_literals_preserved', 'literals_masked', 'identifiers_masked', 'numbers_masked',
           'comments_masked', 'withheld_units'}


def _fail():
    raise ValueError('Prepared prototype source is not exact safely masked Forms XML with matching redaction provenance.') from None


def _code(code, status):
    if status == 'withheld':
        if code != forms_redaction._WITHHELD:
            _fail()
        return
    if status != 'redacted_analysis_only' or not code.startswith(_ANALYSIS + '\n'):
        _fail()
    tokens = forms_redaction._tokens(code)
    significant = [(kind, token) for kind, token in tokens if kind not in {'space', 'comment'}]
    index = 0
    for kind, token in tokens:
        if kind == 'comment':
            if token != _ANALYSIS and not _COMMENT.fullmatch(token):
                _fail()
        elif kind == 'number' and token not in {'0', '1'}:
            _fail()
        elif kind == 'identifier_literal':
            _fail()
        elif kind == 'string':
            previous, following = significant[max(0, index - 3):index], significant[index + 1:index + 2]
            if (not token.startswith("'") or not token.endswith("'")
                    or not forms_redaction._IDENT.fullmatch(token[1:-1])
                    or len(previous) < 2 or previous[-2][0] != 'word'
                    or previous[-2][1].upper() not in forms_redaction._SAFE_CALLS
                    or previous[-1] != ('symbol', '(')
                    or len(previous) == 3 and previous[-3] == ('symbol', '.')
                    or not following or following[0] not in {('symbol', ','), ('symbol', ')')}):
                _fail()
        if kind not in {'space', 'comment'}:
            index += 1
    # The existing redactor knows credential-bearing unquoted SQL grammar and
    # unsafe lexemes too. A marked unit cannot bypass its withholding decision.
    if forms_redaction._redact_code(code)[2] is not None:
        _fail()


def validate_redacted_prototype_source(name: str, raw: bytes, receipt: dict) -> dict:
    """Return the ordinary four source fields only after exact fresh checks.

    Receipt original hashes/locations are retained provenance, not proof that
    unseen original bytes were supplied. Only redacted bytes, complete unit
    hashes and the conservative literal/metadata policy are verified here.
    """
    try:
        root, _ = forms_redaction._parse(name, raw)
        # ElementTree drops comments and processing instructions. Never retain
        # unexamined raw payload there merely because the parsed trees match.
        # The local redactor emits neither; the XML declaration remains valid.
        parser = expat.ParserCreate()
        parser.CommentHandler = lambda *args: _fail()
        parser.ProcessingInstructionHandler = lambda *args: _fail()
        parser.Parse(raw, True)
        text = raw.decode('utf-8-sig')
        if any(re.search(pattern, text) for pattern in SECRETS):
            _fail()
        if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS:
            _fail()
        # Bound untrusted body-free metadata before hashing/persisting it.
        if len(json.dumps(receipt, ensure_ascii=False, allow_nan=False).encode()) > 2_000_000:
            _fail()
        baseline = forms_redaction.redact_forms_xml('policy.xml', b'<FormModule Name="SYNTHETIC"/>')['receipt']
        fixed = ('schema_version', 'policy_id', 'status', 'safety', 'verification', 'limitations')
        if (json.dumps({key: receipt[key] for key in fixed}, sort_keys=True, allow_nan=False) !=
                json.dumps({key: baseline[key] for key in fixed}, sort_keys=True, allow_nan=False)
                or type(receipt['schema_version']) is not int
                or receipt['redacted_sha256'] != hashlib.sha256(raw).hexdigest()
                or type(receipt['redacted_bytes']) is not int or receipt['redacted_bytes'] != len(raw)
                or not isinstance(receipt['original_sha256'], str) or not _SHA.fullmatch(receipt['original_sha256'])
                or type(receipt['original_bytes']) is not int or not 1 <= receipt['original_bytes'] <= forms_facts.MAX_FILE_BYTES
                or not isinstance(receipt['counts'], dict)
                or not receipt['counts'].keys() <= _COUNTS
                or any(type(value) is not int or not 0 <= value <= forms_facts.MAX_FILE_BYTES
                       for key, value in receipt['counts'].items())):
            _fail()
        packet, chunks = _build([(name, raw)])
        facts = packet['sources'][0]['facts']
        if receipt['object_counts'] != dict(Counter(row['kind'] for row in facts['objects'])):
            _fail()
        units = {(unit['location']['path'], unit['source_attribute']): unit for unit in facts['code_units']}
        if not isinstance(receipt['code_units'], list) or len(receipt['code_units']) != len(units):
            _fail()
        mapped = {}
        for unit in receipt['code_units']:
            if (not isinstance(unit, dict) or set(unit) - {'reason'} != _UNIT_KEYS
                    or not isinstance(unit['location'], dict)
                    or set(unit['location']) != {'path', 'line', 'column', 'byte_offset'}
                    or any(type(unit['location'][key]) is not int or unit['location'][key] < (0 if key == 'byte_offset' else 1)
                           for key in ('line', 'column', 'byte_offset'))
                    or unit['hash_basis'] != 'xml-decoded-utf8'
                    or unit['normalized_input_hash_basis'] != 'xml-decoded-utf8-plus-known-encoded-whitespace-analysis-only'
                    or type(unit['encoded_whitespace_normalizations']) is not int
                    or not 0 <= unit['encoded_whitespace_normalizations'] <= forms_facts.MAX_FILE_BYTES
                    or any(not isinstance(unit[key], str) or not _SHA.fullmatch(unit[key])
                           for key in ('original_sha256', 'redacted_sha256', 'normalized_input_sha256'))):
                _fail()
            key = unit['location']['path'], unit['source_attribute']
            if key in mapped or key not in units or units[key]['sha256'] != unit['redacted_sha256']:
                _fail()
            if ((unit['status'] == 'withheld') != ('reason' in unit)
                    or 'reason' in unit and unit['reason'] not in _REASONS):
                _fail()
            mapped[key] = unit
        by_id = {unit['id']: unit for unit in facts['code_units']}
        for chunk in chunks:
            unit = by_id[chunk['code_unit_id']]
            _code(chunk['text'], mapped[(unit['location']['path'], unit['source_attribute'])]['status'])
        # Reapply the existing redactor's metadata rules to the ALREADY masked
        # XML. Ignore only executable slots (checked above), never data values.
        sanitized = forms_redaction.redact_forms_xml(name, raw)['redacted_xml']
        sanitized_root, _ = forms_redaction._parse(name, sanitized)
        for original, checked in zip(root.iter(), sanitized_root.iter(), strict=True):
            if original.tag != checked.tag or set(original.attrib) != set(checked.attrib):
                _fail()
            for key, value in original.attrib.items():
                if key not in forms_facts.CODE_ATTRIBUTES and value != checked.attrib[key]:
                    _fail()
            kind = forms_redaction._local(original.tag)
            if kind not in forms_facts.CODE_ATTRIBUTES | {'Trigger', 'ProgramUnit'} and original.text != checked.text:
                _fail()
            if original.tail != checked.tail:
                _fail()
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError, expat.ExpatError):
        _fail()
    return {'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'text': text}
