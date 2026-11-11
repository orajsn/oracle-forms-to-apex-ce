"""Pure, bounded source derivation from paired Forms OVERRIDDEN/ALL XML.

ALL is not a round-trippable Forms source. Only missing, typed metadata is
materialized into a separate original-based tree. Prefix spelling is provenance:
namespace expansion alone loses the distinction between default and inherited.
The caller must independently bind both real tool runs to the same FMB hash.
This receipt is not an Oracle attestation or permission to execute/submit code.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from xml.etree import ElementTree as XML
from xml.parsers import expat

from defusedxml import ElementTree as SafeXML

from .forms_facts import (
    FORMS_NAMESPACE, MAX_ATTRIBUTES, MAX_DEPTH, MAX_ELEMENTS,
    MAX_FILE_BYTES, MODULE_KINDS, _SECRET, _SECRET_NAME, _identifier,
)

POLICY_ID = "fox-forms-effective-metadata-copy-missing-v1"
MAX_RECEIPT_PATH_BYTES = 16 * 1024 * 1024
PROPERTIES = frozenset({
    "Name", "DSCName", "DatabaseBlock", "DatabaseItem", "ItemType", "DataType",
    "MaximumLength", "Prompt", "ColumnName", "PrimaryKey", "QueryDataSourceType",
})
_BOOL = frozenset({"DatabaseBlock", "DatabaseItem", "PrimaryKey"})
_IDENTITY_PROPERTIES = frozenset({"Name", "DSCName"})
_ENUMS = {
    "ItemType": {"text item", "display item", "check box", "radio group", "list item",
                 "push button", "image", "bean area", "vbx", "ole container",
                 "activex control", "user area", "chart"},
    "DataType": {"char", "varchar2", "number", "integer", "date", "datetime",
                 "long", "rowid", "rrowid", "alpha", "image", "sound", "ole", "object"},
    "QueryDataSourceType": {"table", "procedure", "transactional triggers",
                            "from clause query", "none"},
}
_PROVENANCE = re.compile(r".+_(default|overridden)\Z")
_INHERITED = re.compile(r".+_inherited\Z", re.I)
_COLUMN = re.compile(r"[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*)?\Z")


@dataclass
class _Node:
    element: XML.Element
    tag: str
    properties: dict
    children: list
    path: str = ""


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _typed(prop: str, value: str, *, element_kind: str | None = None) -> str:
    """Validate before comparison/copy; errors never echo source values."""
    if prop in _IDENTITY_PROPERTIES:
        # Oracle serializes list-entry indices as Names. They are exact XML
        # identities, not SQL/object identifiers; never coerce away leading zeroes.
        list_entry_identity = (prop == "Name" and element_kind == "ListItemElement"
                               and (value == "" or re.fullmatch(r"[0-9]{1,10}", value) is not None))
        # Oracle can emit one empty list-entry name. Preserve its exact identity;
        # _index still rejects duplicate siblings and empty/absent mismatches.
        valid = _identifier(value) is not None or list_entry_identity
    elif prop in _BOOL:
        parsed = {"true": "true", "yes": "true", "false": "false", "no": "false"}.get(value.lower())
        if parsed is not None:
            return parsed
        valid = False
    elif prop == "MaximumLength":
        valid = bool(re.fullmatch(r"[0-9]{1,7}", value)) and 0 <= int(value) <= 1_000_000
        if valid:
            return str(int(value))
    elif prop in _ENUMS:
        valid = len(value) <= 80 and value.casefold() in _ENUMS[prop]
    elif prop == "ColumnName":
        valid = len(value) <= 256 and (not value or _COLUMN.fullmatch(value) is not None)
    elif prop == "Prompt":
        valid = len(value) <= 2048 and all(ord(c) >= 32 or c in "\n\r\t" for c in value)
    else:
        valid = False
    if not valid:
        raise ValueError("Forms metadata is outside the bounded property type policy.")
    return value


def _parse(raw: bytes) -> tuple[_Node, list[_Node]]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError("Forms XML must be nonempty and at most 5 MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("Forms XML must be UTF-8 text.") from None
    declaration = re.match(r"\s*<\?xml\s+[^?]*\bencoding\s*=\s*['\"]([^'\"]+)['\"]", text, re.I)
    if "\0" in text or (declaration and declaration[1].lower() not in {"utf-8", "utf8"}):
        raise ValueError("Forms XML must be UTF-8 text without binary content.")
    if any(pattern.search(text) for pattern in _SECRET):
        raise ValueError("Possible credential detected. Redact the original locally.")

    # No namespace expansion here: module_default:X and UNKNOWN_inherited:X
    # deliberately share a URI, but do NOT mean the same thing.
    parser = expat.ParserCreate()
    builder = XML.TreeBuilder(insert_comments=True, insert_pis=True)
    nodes, stack, bindings = [], [], [{"xml": "http://www.w3.org/XML/1998/namespace"}]

    def expanded(key, scope, *, attribute=False):
        if ":" in key:
            prefix, local = key.split(":", 1)
            if prefix not in scope:
                raise ValueError("Forms XML contains an unbound namespace prefix.")
            return scope[prefix], local, prefix
        return ("" if attribute else scope.get("", "")), key, ""

    def start(tag, attributes):
        if len(stack) >= MAX_DEPTH or len(nodes) >= MAX_ELEMENTS or len(attributes) > MAX_ATTRIBUTES:
            raise ValueError("Forms XML exceeds the bounded element, depth or attribute limit.")
        scope = dict(bindings[-1])
        for key, value in attributes.items():
            if key == "xmlns":
                scope[""] = value
            elif key.startswith("xmlns:"):
                scope[key[6:]] = value
        uri, local, _ = expanded(tag, scope)
        canonical = local if uri in {"", FORMS_NAMESPACE} else f"{{{uri}}}{local}"
        props, named_secrets, property_values = {}, [], []
        for key, value in attributes.items():
            if key == "xmlns" or key.startswith("xmlns:"):
                continue
            attr_uri, field, prefix = expanded(key, scope, attribute=True)
            if field == "Name" and _SECRET_NAME.fullmatch(value):
                named_secrets.append(value)
            if field == "Value":
                property_values.append(value)
            if (_SECRET_NAME.fullmatch(field) and value and not value.startswith(":")) or any(p.search(value) for p in _SECRET):
                raise ValueError("Possible credential detected. Redact the original locally.")
            if field not in PROPERTIES:
                continue
            if attr_uri not in {"", FORMS_NAMESPACE}:
                raise ValueError("Whitelisted Forms metadata has a foreign namespace alias.")
            if field == "DSCName" and canonical != "DataSourceColumn":
                raise ValueError("DSCName identity is supported only on Forms DataSourceColumn elements.")
            if field in props:
                raise ValueError("Forms metadata has ambiguous duplicate property provenance.")
            if not prefix:
                provenance = "direct_overridden"
            elif _INHERITED.fullmatch(prefix):
                provenance = "inherited"
            else:
                match = _PROVENANCE.fullmatch(prefix)
                if match is None or len(prefix) > 256:
                    raise ValueError("Forms metadata has unsupported qualified provenance.")
                provenance = "module_" + match[1]
            # Inherited values are intentionally not interpreted, even if they
            # look plausible. Their actual meaning remains unresolved.
            typed = None if provenance == "inherited" else _typed(field, value, element_kind=canonical)
            props[field] = (value, typed, provenance, key)
        if canonical == "DataSourceColumn":
            if "Name" in props and "DSCName" in props:
                raise ValueError("Forms DataSourceColumn has ambiguous identity properties.")
            if "DSCName" not in props:
                raise ValueError("Forms DataSourceColumn is missing its exact DSCName identity.")
        if named_secrets and any(value.strip() for value in property_values):
            raise ValueError("Possible credential detected. Redact the original locally.")
        element = builder.start(tag, attributes)
        node = _Node(element, canonical, props, [])
        if stack:
            stack[-1].children.append(node)
        stack.append(node)
        bindings.append(scope)
        nodes.append(node)

    def end(tag):
        builder.end(tag)
        stack.pop()
        bindings.pop()

    def data(value):
        if any(pattern.search(value) for pattern in _SECRET):
            raise ValueError("Possible credential detected. Redact the original locally.")
        builder.data(value)

    def unsafe(*_args):
        raise ValueError("Malformed or unsafe Forms XML; DTDs and entities are not accepted.")

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler = data
    parser.CommentHandler = builder.comment
    parser.ProcessingInstructionHandler = builder.pi
    parser.StartDoctypeDeclHandler = unsafe
    parser.EntityDeclHandler = unsafe
    parser.ExternalEntityRefHandler = unsafe
    try:
        parser.Parse(raw, True)
        builder.close()
        # Independent namespace-aware well-formedness check, after bounded raw
        # preflight. The resulting expanded tree is never used for provenance.
        checked = SafeXML.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (expat.ExpatError, XML.ParseError):
        raise ValueError("Malformed or unsafe Forms XML.") from None
    root = nodes[0]
    if root.tag not in MODULE_KINDS | {"Module"} or not any(n.tag in MODULE_KINDS for n in nodes):
        raise ValueError("The document is not a supported Forms XML module.")
    # Check complete decoded text too; Expat character chunks may split a secret.
    for element in checked.iter():
        if any(p.search(element.text or "") or p.search(element.tail or "") for p in _SECRET):
            raise ValueError("Possible credential detected. Redact the original locally.")
    return root, nodes


def _index(root: _Node) -> dict[str, _Node]:
    indexed = {}
    path_bytes = 0

    def walk(node, parent_path):
        nonlocal path_bytes
        identity_key = "DSCName" if node.tag == "DataSourceColumn" else "Name"
        name = node.properties.get(identity_key)
        if name and name[2] == "inherited":
            raise ValueError("Forms object identity is inherited and cannot be matched safely.")
        # Unnamed singleton containers are safe; ambiguous same-tag anonymous
        # siblings fail closed rather than being joined by position.
        kind = node.tag if not node.tag.startswith("{") else "foreign-" + _hash(node.tag.encode())[:24]
        step = kind + (f"[{identity_key}={name[0]}]" if name else "")
        node.path = parent_path + "/" + step
        path_bytes += len(node.path.encode())
        if len(node.path) > 4096 or path_bytes > MAX_RECEIPT_PATH_BYTES:
            raise ValueError("Forms identity paths exceed the bounded receipt limit.")
        if node.path in indexed:
            raise ValueError("Forms structure has ambiguous object identity paths.")
        indexed[node.path] = node
        for child in node.children:
            walk(child, node.path)

    walk(root, "")
    return indexed


def derive_effective_view(original_name: str, original_xml: bytes, all_xml: bytes, *, binary_sha256: str) -> dict:
    """Return separate XML bytes and a value-free local derivation receipt.

    No file, Oracle, provider or network operations occur. The supplied binary
    hash is only a caller assertion; the separate actual-tool receipt must bind
    both XML inputs to that same original binary before downstream use.
    """
    if (not isinstance(original_name, str) or not original_name or len(original_name) > 180
            or ".." in original_name or any(c in original_name for c in "/\\:")
            or any(ord(c) < 32 or ord(c) == 127 for c in original_name)
            or not original_name.lower().endswith(".xml")):
        raise ValueError("Use a simple XML filename without directory paths.")
    if not isinstance(binary_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", binary_sha256):
        raise ValueError("An original binary SHA-256 is required.")
    original_root, original_nodes = _parse(original_xml)
    all_root, _ = _parse(all_xml)
    original_hash, all_hash = _hash(original_xml), _hash(all_xml)
    original_index, all_index = _index(original_root), _index(all_root)
    if original_index.keys() != all_index.keys():
        raise ValueError("Original and ALL Forms object structures or exact names differ.")
    changes, unresolved, actions, receipt_path_bytes = [], [], Counter(), 0
    for path, node in original_index.items():
        source = all_index[path]
        # The index proves parent/name identity; child sets prove the entire
        # element structure without depending on sibling positions or order.
        if node.tag != source.tag or {c.path for c in node.children} != {c.path for c in source.children}:
            raise ValueError("Original and ALL Forms object structures differ.")
        for prop, (value, typed, provenance, key) in source.properties.items():
            receipt_path_bytes += len(path.encode())
            if receipt_path_bytes > MAX_RECEIPT_PATH_BYTES:
                raise ValueError("Forms metadata exceeds the bounded receipt limit.")
            if provenance == "inherited":
                unresolved.append({"path": path, "property": prop})
                actions["unresolved_inherited"] += 1
                continue
            existing = node.properties.get(prop)
            if existing is not None:
                if existing[2] == "inherited" or existing[1] != typed:
                    raise ValueError("Original and ALL Forms metadata conflict; no overwrite is allowed.")
                actions["preserved_existing"] += 1
                continue
            if prop in _IDENTITY_PROPERTIES:
                raise ValueError("Forms object identity cannot be materialized or guessed.")
            if node.tag.startswith("{"):
                raise ValueError("Forms metadata cannot be materialized onto foreign elements.")
            node.element.set(prop, typed)
            changes.append({"path": path, "property": prop, "provenance": provenance,
                            "qualified_source_key": key})
            actions["copied_missing"] += 1
    derived = XML.tostring(original_root.element, encoding="utf-8", xml_declaration=True)
    if len(derived) > MAX_FILE_BYTES:
        raise ValueError("Derived Forms XML exceeds the bounded 5 MB limit.")
    # Serialization changes spelling only. This explicit semantic check protects
    # all original content (including unknown/code properties, text and tails).
    _, derived_nodes = _parse(derived)
    if len(original_nodes) != len(derived_nodes):
        raise ValueError("Derived Forms XML did not preserve original structure.")
    for before, after in zip(original_nodes, derived_nodes, strict=True):
        if (before.element.tag != after.element.tag or before.element.attrib != after.element.attrib
                or before.element.text != after.element.text or before.element.tail != after.element.tail):
            raise ValueError("Derived Forms XML did not preserve original content.")
    receipt = {
        "schema_version": 1, "scope": "fox-forms-effective-view-v1", "policy_id": POLICY_ID,
        "derivation_status": "LOCAL_SOURCE_DERIVATION_ONLY", "binary_sha256": binary_sha256.lower(),
        "original_sha256": original_hash, "all_sha256": all_hash, "derived_sha256": _hash(derived),
        "original_unchanged": _hash(original_xml) == original_hash,
        "structural_counts": {"elements": len(original_nodes), "modules": sum(n.tag in MODULE_KINDS for n in original_nodes),
                              "blocks": sum(n.tag == "Block" for n in original_nodes), "items": sum(n.tag == "Item" for n in original_nodes)},
        "changes": changes, "unresolved_inherited": unresolved,
        "action_counts": {key: actions[key] for key in ("copied_missing", "preserved_existing", "unresolved_inherited")},
        "safety": {"local_only": True, "code_executed": False, "model_submission_allowed": False,
                   "import_allowed": False, "native_generation_allowed": False,
                   "actual_tool_run_binding_required": True, "oracle_provenance_attested": False},
    }
    return {"derived_xml": derived, "receipt": receipt}
