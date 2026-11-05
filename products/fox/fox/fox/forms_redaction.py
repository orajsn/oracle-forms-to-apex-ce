"""Conservative local-only Forms XML sanitization for explicitly approved analysis.

This is not a PII detector, anonymization certificate, executable source export,
Oracle attestation, or permission to transmit. Identifiers remain source evidence.
The caller must independently authorize the destination and may not reconstruct
withheld units. Only known Forms first-argument technical references retain string
literals; there are no general status, empty-string or date-format exemptions.
Before analysis only, exact remaining Forms2XML whitespace tokens ``&#10;``,
``&#13;`` and ``&#9;`` are normalized. No other entities are decoded, and this
normalization does not claim executable-source or behavioral equivalence.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import re
from xml.etree import ElementTree as Serializer

from defusedxml import ElementTree as SafeET

from . import forms_facts as facts

POLICY_ID = "fox-forms-redaction-v1"
MAX_CODE_TOKENS = 100_000
_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*){0,2}\Z")
_SOURCE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_$# .-]{0,255}\Z")
_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$#]*")
_NUMBER = re.compile(r"(?:\d+(?:\.(?!\.)\d*)?|\.\d+)(?:[eE][+-]?\d+)?[fFdD]?")
_SAFE_CALLS = frozenset({
    "CALL_FORM", "OPEN_FORM", "NEW_FORM", "GO_BLOCK", "GO_ITEM", "FIND_ITEM",
    "FIND_BLOCK", "FIND_CANVAS", "FIND_WINDOW", "FIND_LOV", "FIND_ALERT",
    "FIND_RELATION", "FIND_REPORT_OBJECT", "FIND_MENU_ITEM", "FIND_TAB_PAGE",
    "SET_ITEM_PROPERTY", "GET_ITEM_PROPERTY", "SET_BLOCK_PROPERTY",
    "GET_BLOCK_PROPERTY", "SET_CANVAS_PROPERTY", "GET_CANVAS_PROPERTY",
    "SET_WINDOW_PROPERTY", "GET_WINDOW_PROPERTY", "SET_LOV_PROPERTY",
    "GET_LOV_PROPERTY", "SET_ALERT_PROPERTY", "GET_ALERT_PROPERTY",
})
_TAGS = facts.OBJECT_KINDS | facts.CODE_ATTRIBUTES | frozenset({
    "Module", "Coordinate", "ListItemElement", "CompoundText", "TextSegment",
    "Property", "ObjectGroupChild", "Font", "Image", "MenuItemRole", "LOVColumnMapping",
})
_REFERENCES = frozenset({
    "MasterBlock", "DetailBlock", "MenuModule", "DMLDataTargetName", "DSCName",
    "ColumnName", "SubclassObjectGroup", "SubclassModule", "SubclassObject",
})
_BOOLEANS = frozenset({"DatabaseBlock", "DatabaseItem", "PrimaryKey"})
_NUMERIC_METADATA = frozenset({
    "MaximumLength", "DSCLength", "DSCPrecision", "DSCScale", "Precision", "Scale",
})
_ENUMS = {
    "ItemType": {"Text Item", "Display Item", "List Item", "Check Box", "Radio Group",
                 "Push Button", "Image", "OLE Container", "Tree", "Bean Area", "Chart"},
    "DataType": {"Char", "Number", "Date", "Datetime", "Time", "Long", "Rowid", "Rchar",
                 "Rnumber", "Rdate", "Rdatetime", "Rtime", "Integer", "VARCHAR2", "CHAR",
                 "NUMBER", "DATE", "TIMESTAMP", "RAW", "LONG", "ROWID", "NVARCHAR2"},
    "DSCType": {"VARCHAR2", "CHAR", "NUMBER", "DATE", "TIMESTAMP", "RAW", "LONG",
                "ROWID", "NVARCHAR2", "NCHAR", "CLOB", "BLOB", "Char", "Number", "Date"},
    "QueryDataSourceType": {"None", "Table", "Procedure", "Transactional Triggers", "From Clause Query"},
    "ProgramUnitType": {"Procedure", "Function", "Package Spec", "Package Body"},
}
_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9 _().&+-]{0,63}\Z")
_SENSITIVE_LABEL = re.compile(r"\b(?:password|passwd|secret|token|email|e-mail|phone|mobile|address)\b|\d{4,}|(?:\d[ ()+.-]*){7,}|://", re.I)
_WITHHELD = "/* FOX_REDACTED_UNIT_WITHHELD: ANALYSIS_ONLY; DO_NOT_RECONSTRUCT */"
_ENCODED_WHITESPACE = re.compile(r"&#(?:10|13|9);")
_WHITESPACE_VALUES = {"&#10;": "\n", "&#13;": "\r", "&#9;": "\t"}
_LINE_BREAK = re.compile(r"[\r\n]")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _local(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _plain_label(value: str) -> str:
    return value if _LABEL.fullmatch(value) and not _SENSITIVE_LABEL.search(value) else ""


def _parse(name: str, raw: bytes):
    # Deliberately do not call _safe_input: original credential literals must be
    # accepted into the bounded local redactor, never into assessment or a model.
    if (not isinstance(name, str) or not name or len(name) > 180 or ".." in name
            or any(c in name for c in "/\\:") or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or not name.lower().endswith(".xml")):
        raise ValueError("Use a simple XML filename without directory paths.")
    if not isinstance(raw, bytes) or not raw or len(raw) > facts.MAX_FILE_BYTES:
        raise ValueError("Forms XML must be nonempty and at most 5 MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("Forms XML must be UTF-8 text.") from None
    declaration = re.match(r"\s*<\?xml\s+[^?]*\bencoding\s*=\s*['\"]([^'\"]+)['\"]", text, re.I)
    if "\0" in text or declaration and declaration[1].lower() not in {"utf-8", "utf8"}:
        raise ValueError("Forms XML must be valid UTF-8 text.")
    locations = facts._locations(raw)  # Expat preflight rejects DTD/entities and bounds allocation.
    try:
        root = SafeET.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception:
        raise ValueError("Malformed or unsafe Forms XML.") from None
    if not facts._supported(root.tag) or _local(root.tag) not in facts.MODULE_KINDS | {"Module"}:
        raise ValueError("The document is not a supported Forms XML module.")
    for node in root.iter():
        if not facts._supported(node.tag) or _local(node.tag) not in _TAGS:
            raise ValueError("Unsupported Forms XML element or namespace; source withheld.")
        if any("}" in key or ":" in key for key in node.attrib):
            raise ValueError("Unsupported Forms XML attribute namespace; source withheld.")
    return root, locations


def _tokens(value: str):
    """Lex fully before emitting anything: malformed units cannot leak a remainder."""
    result, i = [], 0
    while i < len(value):
        start = i
        if value[i].isspace():
            while i < len(value) and value[i].isspace():
                i += 1
            kind = "space"
        elif value.startswith("--", i):
            end = _LINE_BREAK.search(value, i + 2)
            i, kind = (len(value) if end is None else end.start()), "comment"
        elif value.startswith("/*", i):
            end = value.find("*/", i + 2)
            if end < 0 or "/*" in value[i + 2:end]:
                raise ValueError("malformed_comment")
            i, kind = end + 2, "comment"
        elif (value[i:i + 2].lower() == "q'" or value[i:i + 3].lower() == "nq'"):
            prefix = 2 if value[i:i + 2].lower() == "q'" else 3
            pos = i + prefix
            if pos >= len(value) or value[pos].isspace() or value[pos] == "'":
                raise ValueError("malformed_literal")
            close = {"[": "]", "{": "}", "(": ")", "<": ">"}.get(value[pos], value[pos])
            end = value.find(close + "'", pos + 1)
            if end < 0:
                raise ValueError("malformed_literal")
            i, kind = end + 2, "string"
        elif value[i] in "'\"" or value[i:i + 2].lower() == "n'":
            if value[i:i + 2].lower() == "n'":
                i += 1
            quote = value[i]
            i += 1
            while True:
                end = value.find(quote, i)
                if end < 0:
                    raise ValueError("malformed_literal")
                i = end + 1
                if i < len(value) and value[i] == quote:
                    i += 1
                    continue
                break
            kind = "identifier_literal" if quote == '"' else "string"
        elif match := _WORD.match(value, i):
            i, kind = match.end(), "word"
        elif value.startswith("..", i):
            i, kind = i + 2, "symbol"
        elif match := _NUMBER.match(value, i):
            i, kind = match.end(), "number"
            if i < len(value) and (value[i].isalnum() or value[i] in "_$#"):
                raise ValueError("malformed_numeric")
        elif value[i] in "(),.;:=+-*/<>|!%[]":
            i, kind = i + 1, "symbol"
        else:
            raise ValueError("unsupported_lexeme")
        if (result and result[-1][0] in {"word", "string", "identifier_literal", "number"}
                and kind in {"word", "string", "identifier_literal", "number"}):
            raise ValueError("malformed_adjacent_tokens")
        result.append((kind, value[start:i]))
        if len(result) > MAX_CODE_TOKENS:
            raise ValueError("bounded_token_limit")
    return result


def _redact_code(value: str) -> tuple[str, dict, str | None]:
    try:
        tokens = _tokens(value)
    except ValueError as exc:
        return _WITHHELD, {"withheld_units": 1}, str(exc)
    # Credential-bearing SQL/SQL*Plus grammar can contain unquoted passwords,
    # which look like ordinary technical identifiers to a lexer. Inspect only
    # significant tokens, never the contents of strings or comments. A normal
    # CONNECT(...) function call and SQL CONNECT BY hierarchy are not SQL*Plus
    # command grammar. Everything else after a CONNECT abbreviation is withheld:
    # proxy/quoted/multi-token credentials must not depend on username lookahead.
    significant_tokens = [row for row in tokens if row[0] not in {"space", "comment"}]
    last_select = last_from = None
    for index, token in enumerate(significant_tokens):
        if token == ("symbol", ";"):
            last_select = last_from = None
        if token[0] != "word":
            continue
        if token[1].upper() == "SELECT":
            last_select = index
        elif token[1].upper() == "FROM":
            last_from = index
        following = significant_tokens[index + 1:index + 4]
        if (token[1].upper() == "IDENTIFIED" and following
                and following[0][0] == "word" and following[0][1].upper() == "BY"):
            return _WITHHELD, {"withheld_units": 1}, "credential_construct"
        if token[1].upper() in {"CONNECT", "CONNEC", "CONNE", "CONN"}:
            next_token = following[0] if following else None
            # BY can itself be a SQL*Plus username. Exempt only the full CONNECT
            # keyword in a current SELECT ... FROM statement, never abbreviations
            # or an immediate slash/proxy bracket following a purported BY.
            hierarchical = (
                token[1].upper() == "CONNECT" and next_token and next_token[0] == "word"
                and next_token[1].upper() == "BY" and last_select is not None
                and last_from is not None and last_select < last_from < index
                and len(following) > 1 and following[1] not in {("symbol", "/"), ("symbol", "[")})
            if next_token != ("symbol", "(") and not hierarchical:
                return _WITHHELD, {"withheld_units": 1}, "credential_construct"
    result, counts, significant = [], Counter(), []
    following_significant = [None] * len(tokens)
    following = None
    for index in range(len(tokens) - 1, -1, -1):
        following_significant[index] = following
        if tokens[index][0] not in {"space", "comment"}:
            following = tokens[index]
    for index, (kind, token) in enumerate(tokens):
        if kind in {"string", "identifier_literal", "number"}:
            # Only an exact first positional argument of an unqualified known
            # Forms builtin is exempt. Package aliases and expressions are not.
            previous = significant[-2:]
            safe_call = (len(previous) == 2 and previous[0][0] == "word"
                         and previous[0][1].upper() in _SAFE_CALLS and previous[1] == ("symbol", "(")
                         and (len(significant) < 3 or significant[-3] != ("symbol", ".")))
            following = following_significant[index]
            if (kind == "string" and token.startswith("'") and token.endswith("'")
                    and safe_call and following in {("symbol", ","), ("symbol", ")")}
                    and _IDENT.fullmatch(token[1:-1])):
                counts["technical_literals_preserved"] += 1
                replacement = token
            elif kind == "number" and token in {"0", "1"}:
                replacement = token
            else:
                marker_kind = {"string": "LITERAL", "identifier_literal": "IDENTIFIER", "number": "NUMBER"}[kind]
                counts[marker_kind.lower() + "s_masked"] += 1
                replacement = f"FOX_REDACTED_{marker_kind}_{counts[marker_kind.lower() + 's_masked']}"
        elif kind == "comment":
            counts["comments_masked"] += 1
            replacement = f"/* FOX_REDACTED_COMMENT_{counts['comments_masked']} */"
        else:
            replacement = token
        result.append(replacement)
        if kind not in {"space", "comment"}:
            significant.append((kind, token))
    redacted = "/* FOX_ANALYSIS_ONLY_NON_EXECUTABLE */\n" + "".join(result)
    # Raw SQL*Plus credentials and unusual unquoted payloads are never forwarded.
    if any(pattern.search(redacted) for pattern in facts._SECRET) or "://" in redacted:
        return _WITHHELD, {"withheld_units": 1}, "unsafe_remaining_lexeme"
    return redacted, dict(counts), None


def redact_forms_xml(name: str, raw: bytes) -> dict:
    """Return ``redacted_xml`` bytes plus a body-free deterministic receipt.

    Errors contain only policy messages. Filenames, attribute values, source
    snippets and malformed token contents are never echoed into errors/receipts.
    The returned XML retains technical names and therefore still requires review
    and destination-specific authorization. Withheld units remain unknown.
    """
    root, locations = _parse(name, raw)
    nodes = list(root.iter())
    originals = [(node.tag, node.get("Name")) for node in nodes if _local(node.tag) in facts.OBJECT_KINDS]
    mappings, counts = [], Counter()
    list_entry = 0

    def code(value, location, source_attribute):
        normalized, normalization_count = _ENCODED_WHITESPACE.subn(
            lambda match: _WHITESPACE_VALUES[match[0]], value)
        sanitized, markers, reason = _redact_code(normalized)
        counts.update(markers)
        counts["encoded_whitespace_normalizations"] += normalization_count
        mapping = {"location": dict(location), "source_attribute": source_attribute,
                   "original_sha256": _sha(value.encode()), "redacted_sha256": _sha(sanitized.encode()),
                   "normalized_input_sha256": _sha(normalized.encode()),
                   "encoded_whitespace_normalizations": normalization_count,
                   "hash_basis": "xml-decoded-utf8",
                   "normalized_input_hash_basis": "xml-decoded-utf8-plus-known-encoded-whitespace-analysis-only",
                   "status": "withheld" if reason else "redacted_analysis_only"}
        if reason:
            mapping["reason"] = reason
        mappings.append(mapping)
        return sanitized

    for node, location in zip(nodes, locations, strict=True):
        kind = _local(node.tag)
        for key, value in list(node.attrib.items()):
            replacement = ""
            if key == "Name" and kind in facts.OBJECT_KINDS:
                if not _SOURCE_NAME.fullmatch(value):
                    raise ValueError("A source object name is outside the bounded technical format; source withheld.")
                replacement = value
            elif key == "Name" and kind == "ListItemElement":
                list_entry += 1
                replacement = f"FOX_REDACTED_ENTRY_{list_entry}"
                counts["list_entries_masked"] += 1
            elif key == "QueryDataSourceName" and _IDENT.fullmatch(value):
                replacement = value
            elif key in facts.CODE_ATTRIBUTES and value.strip():
                replacement = code(value, location, key)
            elif key in _REFERENCES or key.endswith("Name"):
                # Only known Forms property names can carry a retained reference.
                if (key in _REFERENCES or key in {"CanvasName", "WindowName", "LovName", "RecordGroupName",
                                                 "VisualAttributeName", "TabPageName", "PropertyClassName", "FontName"}) and _IDENT.fullmatch(value):
                    replacement = value
            elif key in _BOOLEANS and value.lower() in {"true", "false", "yes", "no"}:
                replacement = value
            elif key in _NUMERIC_METADATA and re.fullmatch(r"-?\d{1,5}", value) and -127 <= int(value) <= 32767:
                replacement = value
            elif key in _ENUMS and value in _ENUMS[key]:
                replacement = value
            elif key in {"Prompt", "StaticItemPrompt"}:
                replacement = _plain_label(value)
            # Unknown attribute *names* may themselves contain private values;
            # remove them rather than copying either key or value to output.
            known = (key == "Name" or key in facts.CODE_ATTRIBUTES or key in _REFERENCES
                     or key in _BOOLEANS or key in _NUMERIC_METADATA or key in _ENUMS
                     or key in {"Prompt", "StaticItemPrompt", "InitialValue", "Value", "ListItemValue",
                                "CanvasName", "WindowName", "LovName", "RecordGroupName", "VisualAttributeName",
                                "TabPageName", "PropertyClassName", "FontName"})
            if not known:
                del node.attrib[key]
                counts["fields_cleared"] += 1
            else:
                node.set(key, replacement)
                if replacement != value and not (key in facts.CODE_ATTRIBUTES and value.strip()):
                    counts["fields_cleared"] += 1
        if (node.text or "").strip():
            if kind in facts.CODE_ATTRIBUTES | {"Trigger", "ProgramUnit"}:
                source_attribute = "#text" if kind in {"Trigger", "ProgramUnit"} else kind + ".text"
                node.text = code(node.text, location, source_attribute)
            else:
                node.text = ""
                counts["texts_cleared"] += 1
        if (node.tail or "").strip():
            node.tail = ""
            counts["texts_cleared"] += 1
    if originals != [(node.tag, node.get("Name")) for node in nodes if _local(node.tag) in facts.OBJECT_KINDS]:
        raise ValueError("Structural verification failed; source withheld.")
    output = Serializer.tostring(root, encoding="utf-8", xml_declaration=True)
    try:
        assessment = facts.assess_forms_xml("redacted.xml", output)
    except ValueError:
        raise ValueError("Redacted Forms XML did not pass fresh local safety verification; source withheld.") from None
    expected = [(_local(tag), name) for tag, name in originals]
    actual = [(row["kind"], row["name"]) for row in assessment["objects"]]
    if expected != actual:
        raise ValueError("Structural verification failed; source withheld.")
    # Cross-check redacted unit hashes using the independent fresh assessment.
    assessed_hashes = {(row["location"]["path"], row["source_attribute"]): row["sha256"] for row in assessment["code_units"]}
    if any(assessed_hashes.get((row["location"]["path"], row["source_attribute"])) != row["redacted_sha256"] for row in mappings):
        raise ValueError("Code hash verification failed; source withheld.")
    receipt = {
        "schema_version": 1, "policy_id": POLICY_ID, "status": "LOCAL_CONSERVATIVE_REDACTION_ONLY",
        "original_sha256": _sha(raw), "redacted_sha256": _sha(output),
        "original_bytes": len(raw), "redacted_bytes": len(output),
        "code_units": mappings, "counts": dict(sorted(counts.items())),
        "object_counts": dict(sorted(Counter(kind for kind, _ in expected).items())),
        "verification": {"fresh_assessment_passed": True, "recognized_objects_preserved": True,
                         "recognized_names_preserved": True, "code_hashes_matched": True},
        "safety": {"local_only": True, "code_executed": False, "model_submission_allowed": False,
                   "import_allowed": False, "native_generation_allowed": False, "oracle_verified": False,
                   "pii_detection_complete": False, "caller_permission_required": True},
        "limitations": ["Technical identifiers remain; not complete PII detection or anonymization certification.",
                        "Analysis-only non-executable code; masked values are unknown, not business facts.",
                        "Only exact encoded LF/CR/TAB whitespace is normalized before analysis; no executable-source equivalence is claimed.",
                        "Withheld units must not be reconstructed or proposed by a model.",
                        "Receipt is not transmission authority, Oracle attestation, or conversion approval."],
    }
    return {"redacted_xml": output, "receipt": receipt}
