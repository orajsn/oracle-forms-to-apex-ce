"""Extract one deliberately narrow, inert Forms count-guard specification.

This is NOT a PL/SQL interpreter or a complete trigger conversion. Only a direct
button trigger's first executable SELECT COUNT(0)/null-or-zero/IF prefix is
recognized. Later statements, exception handlers and redacted messages remain
explicitly unsupported. No source SQL or PL/SQL is executed or emitted.
"""
from __future__ import annotations

from decimal import Decimal
import hashlib
import json
import re
import xml.etree.ElementTree as ET


PROFILE_ID = "forms-null-zero-count-guard-v1"
MAX_XML_BYTES = 2_000_000
_NS = "{http://xmlns.oracle.com/Forms}"
_ID = r"[A-Za-z][A-Za-z0-9_$#]{0,127}"
_QUALIFIED = rf"{_ID}(?:\.{_ID})?"
_LITERAL = r"'(?:''|[^'])*'"
_REDACTED_MESSAGE = r"FOX_REDACTED_LITERAL_[1-9][0-9]*"
_COMMENTS = re.compile(rf"{_LITERAL}|/\*.*?\*/|--[^\r\n]*", re.S)
_DECLARATION = re.compile(
    rf"\s*(?P<name>{_ID})\s+(?P<type>NUMBER|VARCHAR2\s*\(\s*"
    rf"(?:[1-9][0-9]{{0,3}}|FOX_REDACTED_NUMBER_[1-9][0-9]*)\s*\))"
    r"\s*(?::=\s*(?:0|NULL)\s*)?;", re.I)
_PREFIX = re.compile(
    rf"\s*SELECT\s+COUNT\s*\(\s*0\s*\)\s+INTO\s+(?P<count>{_ID})"
    rf"\s+FROM\s+(?P<table>{_QUALIFIED})\s+WHERE\s+NVL\s*\(\s*"
    rf"(?P<value>{_ID})\s*,\s*0\s*\)\s*=\s*0\s+AND\s+"
    rf"(?P<key>{_ID})\s*=\s*:(?P<bind>{_QUALIFIED})\s*;\s*"
    rf"IF\s+(?P=count)\s*>\s*0\s+THEN\s+"
    rf"(?P<messages>(?:MESSAGE\s*\(\s*(?:{_LITERAL}|{_REDACTED_MESSAGE})"
    rf"\s*\)\s*;\s*){{1,2}})"
    r"RAISE\s+FORM_TRIGGER_FAILURE\s*;\s*END\s+IF\s*;", re.I)


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _identifier(value):
    _need(type(value) is str and re.fullmatch(_QUALIFIED, value) is not None
          and "FOX_REDACTED" not in value.upper(), "COUNT_GUARD_IDENTIFIER_UNPROVEN")
    return value.upper()


def _code_without_comments(code):
    # Retain character offsets, protecting quoted literals from comment removal.
    return _COMMENTS.sub(lambda m: m.group() if m.group().startswith("'")
                         else "".join("\n" if c == "\n" else " " for c in m.group()), code)


def _one(elements, code):
    _need(len(elements) == 1, code)
    return elements[0]


def _named(parent, kind, name):
    return [e for e in parent if e.tag == _NS + kind
            and e.get("Name", "").upper() == name.upper()]


def _item_binding(block, item):
    return {"block": _identifier(block.get("Name")),
            "item": _identifier(item.get("Name")),
            "column": _identifier(item.get("ColumnName")),
            "data_type": item.get("DataType")}


def _source_objects(root, source_sha256, selected):
    """Match the existing forms_facts ff1 identity for direct known ancestors.

    Selected objects all follow Module/FormModule/Block/Item/Trigger paths.
    Unknown sibling tags cannot affect these per-local-name occurrence counts.
    """
    parents = {child: node for node in root.iter() for child in node}
    paths = {}
    for node in selected.values():
        steps, current = [], node
        while current is not root:
            parent = parents[current]
            local = current.tag.rsplit("}", 1)[-1]
            preceding = list(parent)[:list(parent).index(current) + 1]
            occurrence = sum(child.tag.rsplit("}", 1)[-1] == local for child in preceding)
            steps.append(f"{local}[{occurrence}]")
            current = parent
        paths[node] = "/Module[1]/" + "/".join(reversed(steps))
    return {role: {"id": "ff1-" + _sha((source_sha256 + "\n" + paths[node] + "\n").encode())[:24],
                   "path": paths[node]} for role, node in selected.items()}


def extract_count_guard(source_bytes, *, source_sha256, module, block, item,
                        event="WHEN-BUTTON-PRESSED"):
    """Return source-bound inert metadata, or reject any unproven prefix.

    Names select original XML objects, not a guessed filename or model result.
    The caller must retain original bytes and obtain explicit partial-scope
    consent before rendering this isolated rule. Masked diagnostic presentation
    is permitted but is never recovered or treated as executable source.
    """
    _need(type(source_bytes) is bytes and 0 < len(source_bytes) <= MAX_XML_BYTES,
          "COUNT_GUARD_XML_SIZE_INVALID")
    _need(type(source_sha256) is str and re.fullmatch(r"[a-f0-9]{64}", source_sha256)
          and _sha(source_bytes) == source_sha256, "COUNT_GUARD_SOURCE_HASH_MISMATCH")
    try:
        text = source_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("COUNT_GUARD_XML_ENCODING_INVALID") from None
    _need("\x00" not in text and not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I),
          "COUNT_GUARD_XML_DECLARATION_FORBIDDEN")
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ValueError("COUNT_GUARD_XML_INVALID") from None
    _need(root.tag == _NS + "Module", "COUNT_GUARD_XML_ROOT_INVALID")
    module, block, item = map(_identifier, (module, block, item))
    _need(event == "WHEN-BUTTON-PRESSED", "COUNT_GUARD_EVENT_UNSUPPORTED")
    form = _one(_named(root, "FormModule", module), "COUNT_GUARD_MODULE_AMBIGUOUS")
    owner = _one(_named(form, "Block", block), "COUNT_GUARD_OWNER_AMBIGUOUS")
    button = _one(_named(owner, "Item", item), "COUNT_GUARD_BUTTON_AMBIGUOUS")
    _need(button.get("ItemType") == "Push Button"
          and button.get("Enabled", "true").lower() == "true",
          "COUNT_GUARD_BUTTON_UNREACHABLE")
    trigger = _one(_named(button, "Trigger", event), "COUNT_GUARD_TRIGGER_AMBIGUOUS")
    code = trigger.get("TriggerText", "")
    clean = _code_without_comments(code)
    start = re.match(r"\s*DECLARE\b", clean, re.I)
    _need(start is not None, "COUNT_GUARD_DECLARATIONS_UNSUPPORTED")
    offset, declarations, redacted_lengths = start.end(), {}, False
    while (declaration := _DECLARATION.match(clean, offset)) is not None:
        name = _identifier(declaration["name"])
        _need(name not in declarations, "COUNT_GUARD_DECLARATION_AMBIGUOUS")
        declarations[name] = declaration["type"].upper()
        redacted_lengths |= "FOX_REDACTED" in declaration["type"].upper()
        offset = declaration.end()
    begin = re.compile(r"\s*BEGIN\b", re.I).match(clean, offset)
    _need(begin is not None, "COUNT_GUARD_DECLARATIONS_UNSUPPORTED")
    prefix = _PREFIX.match(clean, begin.end())
    _need(prefix is not None, "COUNT_GUARD_PREFIX_UNSUPPORTED")
    names = {key: _identifier(prefix[key]) for key in ("count", "table", "value", "key", "bind")}
    _need(declarations.get(names["count"]) == "NUMBER", "COUNT_GUARD_COUNT_TYPE_UNPROVEN")
    _need(names["value"] != names["key"], "COUNT_GUARD_COLUMNS_AMBIGUOUS")

    # Resolve source table and columns, never assume names alone prove binding.
    blocks = [e for e in form if e.tag == _NS + "Block"]
    table_block = _one([e for e in blocks
                        if e.get("QueryDataSourceName", "").upper() == names["table"]
                        and e.get("DatabaseBlock", "").lower() == "true"
                        and e.get("QueryDataSourceType") == "Table"],
                       "COUNT_GUARD_TABLE_BINDING_UNPROVEN")
    bindings, bound_fields = {}, {}
    for key in ("value", "key"):
        field = _one([e for e in table_block if e.tag == _NS + "Item"
                      and e.get("ColumnName", "").upper() == names[key]
                      and e.get("DatabaseItem", "").lower() == "true"],
                     "COUNT_GUARD_COLUMN_BINDING_UNPROVEN")
        bindings[key] = _item_binding(table_block, field)
        bound_fields[key] = field
    _need(bindings["value"]["data_type"] == "Number", "COUNT_GUARD_VALUE_TYPE_UNPROVEN")
    bind_parts = names["bind"].split(".")
    bind_blocks = blocks if len(bind_parts) == 1 else _named(form, "Block", bind_parts[0])
    bind_item, bind_block = _one([(e, b) for b in bind_blocks
                                 for e in _named(b, "Item", bind_parts[-1])],
                                "COUNT_GUARD_BIND_AMBIGUOUS")
    _need(bind_item.get("DatabaseItem", "").lower() == "true",
          "COUNT_GUARD_BIND_SOURCE_UNPROVEN")
    bindings["bind"] = _item_binding(bind_block, bind_item)
    _need(bindings["key"]["data_type"] == bindings["bind"]["data_type"]
          and bindings["key"]["data_type"] in {"Char", "Number"},
          "COUNT_GUARD_KEY_TYPE_UNPROVEN")
    prefix_end = prefix.end()
    remainder = code[prefix_end:]
    _need(re.search(r"\bEND\s*;\s*\Z", _code_without_comments(remainder), re.I)
          is not None, "COUNT_GUARD_TRIGGER_END_UNPROVEN")
    return {
        "schema_version": 1, "profile_id": PROFILE_ID,
        "scope": "isolated_pre_action_validation_only",
        "source": {"xml_sha256": source_sha256, "module": module, "block": block,
                   "item": item, "event": event, "trigger_sha256": _sha(code.encode()),
                   "prefix_end_character": prefix_end,
                   "prefix_sha256": _sha(code[:prefix_end].encode())},
        "predicate": {"aggregate": "count_0", "source_table": names["table"],
                      "value_column": names["value"], "key_column": names["key"],
                      "bind_reference": names["bind"], "null_replacement": 0,
                      "equals": 0, "block_when_count_greater_than": 0},
        "bindings": bindings,
        "source_objects": _source_objects(root, source_sha256, {
            "module": form, "owner_block": owner, "button": button, "trigger": trigger,
            "detail_block": table_block, "value_item": bound_fields["value"],
            "key_item": bound_fields["key"], "bind_block": bind_block, "bind_item": bind_item}),
        "diagnostics": {"message_count": len(re.findall(r"\bMESSAGE\s*\(", prefix["messages"], re.I)),
                        "message_text_available": "FOX_REDACTED_LITERAL_" not in prefix["messages"].upper(),
                        "unused_declaration_length_redacted": redacted_lengths},
        "unsupported_remainder": {"sha256": _sha(remainder.encode()),
                                  "character_count": len(remainder), "converted": False,
                                  "exception_keyword_present": bool(re.search(
                                      r"\bEXCEPTION\b", re.sub(_LITERAL, "''",
                                      _code_without_comments(remainder)), re.I)),
                                  "exception_handlers_converted": False,
                                  "includes_trigger_end": True},
        "limitations": [
            "Only the first count guard is isolated; this is not the original button action.",
            "Later statements and exception handlers are not interpreted or converted.",
            "No approval, transaction, navigation, dependency or full failure propagation is proven.",
            "Negative nonzero values are not rejected by this predicate.",
            "Diagnostic text may be redacted; do not invent original message text.",
            "Source table references do not prove database existence or target schema compatibility.",
            "Partial-scope consent, native rendering, SQLcl validation, import and runtime tests remain required.",
        ],
    }


def validate_count_guard(spec, source_bytes):
    """Recompute every field against exact XML; caller metadata has no authority."""
    _need(type(spec) is dict and type(spec.get("source")) is dict,
          "COUNT_GUARD_SPEC_INVALID")
    source = spec["source"]
    _need(set(source) == {"xml_sha256", "module", "block", "item", "event", "trigger_sha256",
                          "prefix_end_character", "prefix_sha256"}, "COUNT_GUARD_SPEC_INVALID")
    actual = extract_count_guard(source_bytes, source_sha256=source["xml_sha256"],
                                 module=source["module"], block=source["block"],
                                 item=source["item"], event=source["event"])
    # JSON preserves integer/boolean distinctions that Python dict equality loses.
    try:
        supplied = json.dumps(spec, sort_keys=True, allow_nan=False, separators=(",", ":"))
        expected = json.dumps(actual, sort_keys=True, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ValueError("COUNT_GUARD_SPEC_INVALID") from None
    _need(supplied == expected, "COUNT_GUARD_SPEC_SOURCE_MISMATCH")
    return actual


def blocks_matching_numeric_rows(values):
    """Local predicate model over ALREADY SQL-matched NUMBER values, not DB proof.

    Does not model key comparison, Oracle conversion/collation, Forms buffers,
    transaction isolation or execution of any source code.
    """
    _need(type(values) is list and len(values) <= 100_000, "COUNT_GUARD_MODEL_INPUT_INVALID")
    _need(all(value is None or type(value) is int
              or type(value) is Decimal and value.is_finite() for value in values),
          "COUNT_GUARD_MODEL_VALUE_INVALID")
    return any(value is None or value == 0 for value in values)
