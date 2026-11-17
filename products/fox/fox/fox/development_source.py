"""Exact development XML preservation with bounded, body-free credential review.

This deterministic review is deliberately not a complete secret/PII detector or
permission to process source. Detection shadows never replace retained bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
from xml.parsers import expat

from . import forms_facts
from .forms_redaction import _parse

MODE = 'development_preserve'
LEGACY_MODE = 'legacy_masked'
MODES = (LEGACY_MODE, MODE)
POLICY_ID = 'fox-development-source-v1'
PREPARED = 'PREPARED_DEVELOPMENT_REVIEW_REQUIRED'
CREDENTIAL_REVIEW = 'CREDENTIAL_REVIEW_REQUIRED'
MAX_FINDINGS = 200
ACTION = 'Review the retained XML at the indicated element and field, correct the original development source, and upload it with a new request identifier.'
LIMITATION = 'Targeted possible-credential review only; zero findings does not establish absence of secrets or personal data. Source review and separate processing consent are still required.'

# Include common Forms variable prefixes without treating all business literals
# or all comments as sensitive. The patterns never become public diagnostics.
_CREDENTIAL = r'(?:[A-Za-z][A-Za-z0-9]*[_-])*(?:password|passwd|pwd|secret|secret[_-]key|api[_-]key|access[_-]token|auth[_-]token|client[_-]secret|credential|private[_-]key)'
_VALUE = r'''(?:q'[^\r\n]{1,512}|'(?:''|[^'])*'|"(?:""|[^"])*"|[^\s;,<>()]+)'''
_RULES = (
    ('private_key', re.compile(r'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----', re.I)),
    ('credential_assignment', re.compile(r'\b' + _CREDENTIAL + r'\b\s*(?::=|=>|=|:)\s*' + _VALUE, re.I)),
    ('oracle_identified_by', re.compile(r'\bIDENTIFIED\s+BY\s+' + _VALUE, re.I)),
    ('oracle_connect', re.compile(r'\bCONN(?:ECT)?\s+[^\s/;]+\s*/\s*[^\s;]+', re.I)),
    ('oracle_logon', re.compile(r"\bLOGON\s*\(\s*'[^']*'\s*,\s*'[^']+'", re.I)),
    ('oracle_userid', re.compile(r'\bUSER_?ID\s*=\s*[^\s/;]+/[^\s;]+', re.I)),
    ('oracle_jdbc', re.compile(r'\bjdbc:oracle:thin:[^\s/@]+/[^\s@]+@', re.I)),
    ('bearer_token', re.compile(r'\bBearer\s+[A-Za-z0-9._~+/=-]{4,}', re.I)),
    ('url_userinfo', re.compile(r'\b[a-z][a-z0-9+.-]*://[^\s/@<>]+:[^\s/@<>]+@', re.I)),
)
_SECRET_FIELD = re.compile(_CREDENTIAL + r'\Z', re.I)
_SPACE = re.compile(r'&#(?:10|13|9);')


def _fail():
    raise ValueError('Prepared development XML or its preservation policy has changed; review and upload the original source again.') from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def review_xml(name: str, raw: bytes, *, native: bool = False) -> dict:
    """Scan XML-decoded values, comments and PI bodies; return no source text.

    Locations are structural ordinals, never customer-controlled object paths.
    Attribute ordinals follow XML document order. Comments/PI use field kinds
    and ordinals on their containing element. All counters are one-based.
    """
    try:
        if native:
            # ALL XML has Oracle provenance-qualified attributes that the
            # effective-only parser correctly rejects. Retained native output
            # gets the same bounded/entity-free preflight, without rewriting.
            if type(raw) is not bytes or not 0 < len(raw) <= forms_facts.MAX_FILE_BYTES:
                _fail()
            text = raw.decode('utf-8-sig')
            declaration = re.match(r'\s*<\?xml\s+[^?]*\bencoding\s*=\s*[\'"]([^\'"]+)[\'"]', text, re.I)
            if declaration and declaration[1].lower() not in {'utf-8', 'utf8'}:
                _fail()
            forms_facts._locations(raw)
        else:
            _parse(name, raw)  # bounded preflight, no DTD/entities, allowed Forms XML
        findings, total, element, stack, ordinals = [], 0, 0, [], {}

        def coordinates():
            return {'xml_line': parser.CurrentLineNumber, 'xml_column': parser.CurrentColumnNumber + 1,
                    'xml_byte_offset': parser.CurrentByteIndex}

        def scan(value, field, ordinal=None, *, secret_field=False, location=None):
            nonlocal total
            containing = stack[-1] if stack else 1
            if ordinal is None:
                key = containing, field
                ordinals[key] = ordinal = ordinals.get(key, 0) + 1
            shadow = _SPACE.sub(lambda m: {'&#10;': '\n', '&#13;': '\r', '&#9;': '\t'}[m[0]], value)
            matches = [(rule, match.start()) for rule, pattern in _RULES for match in pattern.finditer(shadow)]
            if secret_field and shadow.strip():
                matches.append(('credential_field', 0))
            for rule, offset in sorted(set(matches), key=lambda row: (row[1], row[0])):
                total += 1
                if len(findings) < MAX_FINDINGS:
                    findings.append({'rule': rule, 'element': containing,
                                     'field': field, 'ordinal': ordinal,
                                     'decoded_line': shadow.count('\n', 0, offset) + 1,
                                     **(coordinates() if location is None else location)})

        # Expat's text callbacks can split values/entities across calls. Buffer
        # each contiguous XML text slot before detection so splits cannot hide a
        # credential; parse preflight has already bounded the entire document.
        pending = []
        pending_location = None

        def characters(value):
            nonlocal pending_location
            if not pending:
                pending_location = coordinates()
            pending.append(value)

        def flush():
            if pending:
                scan(''.join(pending), 'text', location=pending_location)
                pending.clear()

        def start(tag, attrs):
            nonlocal element
            flush()
            element += 1
            stack.append(element)
            pairs = [(key.rsplit(':', 1)[-1], value) for key, value in zip(attrs[::2], attrs[1::2])
                     if key != 'xmlns' and not key.startswith('xmlns:')]
            prop_secret = any(key == 'Name' and _SECRET_FIELD.fullmatch(value) for key, value in pairs)
            for ordinal, (key, value) in enumerate(pairs, 1):
                scan(value, 'attribute', ordinal, secret_field=bool(_SECRET_FIELD.fullmatch(key)) or prop_secret and key == 'Value')

        def end(tag):
            flush()
            stack.pop()

        def comment(value):
            flush()
            scan(value, 'comment')

        def instruction(target, value):
            flush()
            scan(target + ' ' + value, 'processing_instruction')

        parser = expat.ParserCreate()
        parser.ordered_attributes = True
        parser.StartElementHandler, parser.EndElementHandler = start, end
        parser.CharacterDataHandler, parser.CommentHandler = characters, comment
        parser.ProcessingInstructionHandler = instruction
        parser.Parse(raw, True)
        flush()
        return {'status': CREDENTIAL_REVIEW if total else PREPARED, 'finding_count': total,
                'findings': findings, 'findings_truncated': total > MAX_FINDINGS,
                'correction_action': ACTION, 'limitation': LIMITATION}
    except (ValueError, TypeError, KeyError, UnicodeError, expat.ExpatError, RecursionError):
        _fail()


def preserve_development_source(name: str, raw: bytes) -> dict:
    review = review_xml(name, raw)
    receipt = {'schema_version': 2, 'policy_id': POLICY_ID, 'preparation_mode': MODE,
               'source_sha256': hashlib.sha256(raw).hexdigest(), 'source_bytes': len(raw),
               'credential_review': review, 'source_preserved': True,
               'model_submission_allowed': False, 'business_accepted': False}
    return {'document': {'name': name, 'sha256': receipt['source_sha256'], 'bytes': len(raw),
                         'text': raw.decode('utf-8-sig')}, 'receipt': receipt}


def validate_development_source(name: str, raw: bytes, receipt: dict) -> dict:
    try:
        expected = preserve_development_source(name, raw)
        if (len(_canonical(receipt).encode()) > 2_000_000
                or _canonical(receipt) != _canonical(expected['receipt'])
                or expected['receipt']['credential_review']['status'] != PREPARED):
            _fail()
        return expected['document']
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        _fail()
