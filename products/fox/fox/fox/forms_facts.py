"""Bounded, local, non-executing Forms XML facts, independent of generation gates.

This module emits identifiers and code metadata, never source bodies or arbitrary
property values. Candidate references are lexical evidence, not resolved database
objects, complete business understanding, or authority to transmit or convert.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from xml.parsers import expat

from defusedxml import ElementTree as ET

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ELEMENTS = 30_000
MAX_DEPTH = 128
MAX_ATTRIBUTES = 256
MAX_REFERENCES = 20_000
FORMS_NAMESPACE = "http://xmlns.oracle.com/Forms"
MODULE_KINDS = frozenset({"FormModule", "MenuModule", "ObjectLibrary"})
OBJECT_KINDS = MODULE_KINDS | frozenset({
    "Alert", "AttachedLibrary", "Block", "Canvas", "Item", "Trigger",
    "ProgramUnit", "PropertyClass", "RecordGroup", "RecordGroupColumn", "LOV",
    "Report", "Window", "Parameter", "Relation", "VisualAttribute", "Menu",
    "MenuItem", "TabPage", "ObjectGroup", "Graphics", "DataSourceColumn", "RadioButton",
})
CODE_ATTRIBUTES = frozenset({
    "TriggerText", "ProgramUnitText", "RecordGroupQuery", "WhereClause",
    "OrderByClause", "Formula", "ValidationTrigger", "QueryDataSourceName",
})
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_$# .-]{0,255}\Z")
_QUALIFIED = re.compile(r"[A-Za-z][A-Za-z0-9_$#]*(?:\.[A-Za-z][A-Za-z0-9_$#]*){0,2}\Z")
_SQL_IDENTIFIER = r"[A-Za-z][A-Za-z0-9_$#]*(?:\s*\.\s*[A-Za-z][A-Za-z0-9_$#]*)?"
_DATABASE_REFERENCE = re.compile(
    r"\b(?:FROM|JOIN|UPDATE|INSERT\s+INTO|MERGE\s+INTO|DELETE\s+FROM)\s+(" + _SQL_IDENTIFIER + r")", re.I)
_ROUTINE_REFERENCE = re.compile(r"(?<![\w:$#])(" + _SQL_IDENTIFIER + r")\s*\(", re.I)
_BIND_REFERENCE = re.compile(r"(?<!:):([A-Za-z][A-Za-z0-9_$#]*\.[A-Za-z][A-Za-z0-9_$#]*)", re.I)
_DYNAMIC = re.compile(r"\b(?:EXECUTE\s+IMMEDIATE|DBMS_SQL\s*\.)", re.I)
_BUILTIN = frozenset({"IF", "ELSIF", "WHILE", "LOOP", "VALUES", "IN", "SELECT", "CASE",
    "NVL", "NVL2", "COALESCE", "DECODE", "TO_CHAR", "TO_DATE", "TO_NUMBER", "TRIM",
    "UPPER", "LOWER", "SUBSTR", "LENGTH", "ROUND", "COUNT", "SUM", "MIN", "MAX"})
_SECRET = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:password|passwd|pwd|api[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token)\b\s*(?::=|=>|=|:)\s*(?:'[^'\r\n]{4,}'|\"[^\"\r\n]{4,}\")", re.I),
    re.compile(r"\bbearer\s+[A-Za-z0-9_.+/=-]{16,}", re.I),
    re.compile(r"\bconnect\s+[^\s/]+/[^\s@]+@", re.I),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", re.I),
)
_SECRET_NAME = re.compile(r"(?:password|passwd|pwd|api[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token)\Z", re.I)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _supported(tag: str) -> bool:
    return not tag.startswith("{") or tag.startswith("{" + FORMS_NAMESPACE + "}")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _identifier(value: str | None) -> str | None:
    return value if value is not None and _IDENTIFIER.fullmatch(value) else None


def _mask_code(value: str) -> str:
    """Same-length comment/literal mask; deliberately not a PL/SQL parser."""
    result, i = list(value), 0
    while i < len(value):
        start = i
        if value.startswith("--", i):
            end = value.find("\n", i + 2)
            i = len(value) if end < 0 else end
        elif value.startswith("/*", i):
            end = value.find("*/", i + 2)
            i = len(value) if end < 0 else end + 2
        elif (value[i] in "qQ" and i + 2 < len(value) and value[i + 1] == "'"
              and (i == 0 or not (value[i - 1].isalnum() or value[i - 1] in "_$#"))):
            delimiter = {"[": "]", "{": "}", "(": ")", "<": ">"}.get(value[i + 2], value[i + 2])
            end = value.find(delimiter + "'", i + 3)
            i = len(value) if end < 0 else end + 2
        elif value[i] in "'\"":
            quote = value[i]
            i += 1
            while i < len(value):
                if value[i] == quote:
                    i += 1
                    if i < len(value) and value[i] == quote:
                        i += 1
                        continue
                    break
                i += 1
        else:
            i += 1
            continue
        result[start:i] = [c if c in "\r\n" else " " for c in value[start:i]]
    return "".join(result)


def _locations(raw: bytes) -> list[dict]:
    """Preflight limits and collect exact original element-start coordinates."""
    parser = expat.ParserCreate(namespace_separator="}")
    locations, stack, counts, child_counts = [], [], [], []

    def start(tag, attributes):
        if len(stack) >= MAX_DEPTH or len(locations) >= MAX_ELEMENTS or len(attributes) > MAX_ATTRIBUTES:
            raise ValueError("Forms XML exceeds the bounded element, depth or attribute limit.")
        local = _local(tag)
        # Unknown names are never copied into metadata; byte/line locations stay exact.
        known = local in OBJECT_KINDS or local in CODE_ATTRIBUTES or local in {"Module", "Coordinate"}
        if counts:
            counts[-1][local] += 1
            index = counts[-1][local]
            child_counts[-1] += 1
        else:
            index = 1
        step = f"{local}[{index}]" if known else f"*[position()={child_counts[-1] if child_counts else 1}]"
        stack.append(step)
        counts.append(Counter())
        child_counts.append(0)
        locations.append({"path": "/" + "/".join(stack), "line": parser.CurrentLineNumber,
                          "column": parser.CurrentColumnNumber + 1, "byte_offset": parser.CurrentByteIndex})

    def end(_tag):
        stack.pop()
        counts.pop()
        child_counts.pop()

    def unsafe(*_args):
        raise ValueError("Malformed or unsafe Forms XML; DTDs and entities are not accepted.")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = unsafe
    parser.EntityDeclHandler = unsafe
    parser.ExternalEntityRefHandler = unsafe
    try:
        parser.Parse(raw, True)
    except expat.ExpatError:
        raise ValueError("Malformed or unsafe Forms XML. Export valid UTF-8 Forms XML locally.") from None
    return locations


def _safe_input(name: str, raw: bytes):
    if (not isinstance(name, str) or not name or len(name) > 180 or ".." in name
            or any(c in name for c in "/\\:") or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or not name.lower().endswith(".xml")):
        raise ValueError("Use a simple XML filename without directory paths.")
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FILE_BYTES:
        raise ValueError("Forms XML must be nonempty and at most 5 MB.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("Forms XML must be UTF-8 text, not a binary Forms module.") from None
    if "\0" in text:
        raise ValueError("Forms XML must not contain binary content.")
    declaration = re.match(r"\s*<\?xml\s+[^?]*\bencoding\s*=\s*['\"]([^'\"]+)['\"]", text, re.I)
    if declaration and declaration[1].lower() not in {"utf-8", "utf8"}:
        raise ValueError("Forms XML must declare UTF-8 encoding.")
    if any(pattern.search(text) for pattern in _SECRET):
        raise ValueError("Possible credential detected. Redact the original locally before assessment.")
    locations = _locations(raw)
    try:
        root = ET.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception:
        raise ValueError("Malformed or unsafe Forms XML. Export valid UTF-8 Forms XML locally.") from None
    for node in root.iter():
        for key, value in node.attrib.items():
            if (_SECRET_NAME.fullmatch(_local(key)) and value and not value.startswith(":")
                    or any(pattern.search(value) for pattern in _SECRET)):
                raise ValueError("Possible credential detected. Redact the original locally before assessment.")
        if any(pattern.search(node.text or "") or pattern.search(node.tail or "") for pattern in _SECRET):
            raise ValueError("Possible credential detected. Redact the original locally before assessment.")
        # Forms properties can encode a credential name and value separately.
        if _SECRET_NAME.fullmatch(node.get("Name", "")) and node.get("Value", "").strip():
            raise ValueError("Possible credential detected. Redact the original locally before assessment.")
    if not _supported(root.tag) or _local(root.tag) not in MODULE_KINDS | {"Module"}:
        raise ValueError("The document is not a supported Forms XML module.")
    return root, locations


def assess_forms_xml(name: str, raw: bytes) -> dict:
    """Return source-bound local facts; no filesystem, provider or Oracle calls.

    Rejected input raises a bounded ValueError that never contains source text.
    Hashes/byte counts identify the exact original file and decoded code units;
    code locations identify their original XML element, not guessed SQL lines.
    """
    root, locations = _safe_input(name, raw)
    source_sha = _hash(raw)
    result = {
        "schema_version": 1, "scope": "fox-forms-facts-v1", "assessment_status": "LOCAL_FACTS_ONLY",
        "source": {"name": name, "sha256": source_sha, "bytes": len(raw), "encoding": "utf-8"},
        "modules": [], "blocks": [], "items": [], "code_units": [], "objects": [],
        "links": [], "dependencies": [], "findings": [],
        "safety": {"local_only": True, "code_executed": False, "model_submission_allowed": False,
                   "import_allowed": False, "native_generation_allowed": False},
        "interpretation_boundary": "Local source inventory only. Candidate dependencies do not prove supplied implementations, database existence, business understanding or native APEX conversion.",
    }
    findings = result["findings"]

    def finding(code, message, object_ids=(), severity="review"):
        findings.append({"code": code, "severity": severity, "message": message, "object_ids": list(object_ids)})

    def stable_id(path, suffix=""):
        return "ff1-" + _hash((source_sha + "\n" + path + "\n" + suffix).encode())[:24]

    nodes = list(root.iter())
    parent = {child: node for node in nodes for child in node}
    rows, module_for, block_for, object_parent, by_name = {}, {}, {}, {}, defaultdict(list)
    duplicate_scope = defaultdict(list)
    unknown_count = 0
    for node, location in zip(nodes, locations, strict=True):
        ancestor = parent.get(node)
        module_id = module_for.get(ancestor)
        block_id = block_for.get(ancestor)
        parent_id = object_parent.get(ancestor)
        kind = _local(node.tag)
        supported = _supported(node.tag)
        recognized = supported and kind in OBJECT_KINDS
        if recognized:
            object_id = stable_id(location["path"])
            row = {"id": object_id, "kind": kind, "name": _identifier(node.get("Name")),
                   "module_id": object_id if kind in MODULE_KINDS else module_id,
                   "block_id": object_id if kind == "Block" else block_id,
                   "parent_id": parent_id, "location": dict(location)}
            rows[node] = row
            result["objects"].append(row)
            if row["name"] is None:
                finding("OBJECT_NAME_UNAVAILABLE", "Object name is missing or outside the bounded identifier format.", [object_id], "unknown")
            if kind in MODULE_KINDS:
                module_id = object_id
                row["module_id"] = object_id
                result["modules"].append(row)
                if module_for.get(ancestor):
                    finding("NESTED_MODULE", "Nested module structure needs authoritative source review.", [object_id])
            elif not module_id:
                finding("OBJECT_OUTSIDE_MODULE", "Object is outside an identified Forms module.", [object_id], "unknown")
            if kind == "Block":
                block_id = object_id
                flag = node.get("DatabaseBlock", "").strip().lower()
                row["classification"] = {"true": "database", "yes": "database", "false": "control", "no": "control"}.get(flag, "unknown")
                result["blocks"].append(row)
                if row["classification"] == "unknown":
                    finding("BLOCK_TYPE_UNKNOWN", "Database/control block type is not explicitly established by the source.", [object_id], "unknown")
            elif kind == "Item":
                flag = node.get("DatabaseItem", "").strip().lower()
                row["database_item"] = {"true": True, "yes": True, "false": False, "no": False}.get(flag)
                row["item_type"] = _identifier(node.get("ItemType"))
                result["items"].append(row)
                if not block_id:
                    finding("ITEM_WITHOUT_BLOCK", "Item has no source block ancestor.", [object_id], "unknown")
            parent_id = object_id
            if row["name"]:
                by_name[(row["module_id"], kind, block_id if kind == "Item" else None, row["name"].upper())].append(row)
                duplicate_scope[(None if kind in MODULE_KINDS else row["parent_id"], kind, row["name"].upper())].append(row)
        elif not supported or kind not in CODE_ATTRIBUTES | {"Module", "Coordinate"}:
            unknown_count += 1
        module_for[node], block_for[node], object_parent[node] = module_id, block_id, parent_id

    if not result["modules"]:
        raise ValueError("The document contains no supported Forms module.")
    if unknown_count:
        finding("UNINTERPRETED_XML_ELEMENTS", "Some XML elements or namespaces are not interpreted; their behavior is not assessed.", severity="unknown")
    for duplicates in duplicate_scope.values():
        if len(duplicates) > 1:
            finding("CONFLICTING_OBJECT_NAME", "Multiple objects share a name in the same source scope; choose authority before design.", [row["id"] for row in duplicates])
    module_targets = defaultdict(list)
    for row in result["modules"]:
        if row["name"]:
            module_targets[(row["kind"], row["name"].upper())].append(row)

    def add_link(owner, relation, target_name, target_kind, location, target_block=None):
        if not _identifier(target_name):
            finding("REFERENCE_NAME_UNAVAILABLE", "A source reference cannot be represented as a bounded identifier.", [owner["id"]], "unknown")
            return
        if target_kind in MODULE_KINDS:
            matches = module_targets.get((target_kind, target_name.upper()), [])
        else:
            matches = by_name.get((owner["module_id"], target_kind, target_block, target_name.upper()), [])
        status = "resolved" if len(matches) == 1 else "ambiguous" if matches else "unresolved"
        if len(result["dependencies"]) + len(result["links"]) >= MAX_REFERENCES:
            raise ValueError("Forms XML exceeds the bounded reference inventory limit.")
        result["links"].append({"source_id": owner["id"], "relation": relation, "target_name": target_name,
                                "target_id": matches[0]["id"] if len(matches) == 1 else None,
                                "status": status, "location": dict(location)})
        if status != "resolved":
            finding("SOURCE_LINK_" + status.upper(), "A source-declared relationship needs target-source review.", [owner["id"]], "unknown")

    def dependency(owner, kind, value, evidence, location):
        value = re.sub(r"\s*\.\s*", ".", value)
        if not _QUALIFIED.fullmatch(value):
            return
        if len(result["dependencies"]) + len(result["links"]) >= MAX_REFERENCES:
            raise ValueError("Forms XML exceeds the bounded reference inventory limit.")
        result["dependencies"].append({"source_id": owner["id"], "kind": kind, "name": value,
                                       "evidence": evidence, "confidence": "candidate", "location": dict(location)})

    link_attributes = {"CanvasName": ("uses_canvas", "Canvas"), "WindowName": ("uses_window", "Window"),
        "LovName": ("uses_lov", "LOV"), "RecordGroupName": ("uses_record_group", "RecordGroup"),
        "MasterBlock": ("master_block", "Block"), "DetailBlock": ("detail_block", "Block"),
        "MenuModule": ("uses_menu", "MenuModule"), "VisualAttributeName": ("uses_visual_attribute", "VisualAttribute")}
    location_by_node = dict(zip(nodes, locations, strict=True))
    for node in nodes:
        owner_node = node
        while owner_node not in rows and owner_node in parent:
            owner_node = parent[owner_node]
        owner = rows.get(owner_node)
        if owner is None or not _supported(node.tag):
            continue
        location = location_by_node[node]
        if node in rows:
            for attribute, (relation, target_kind) in link_attributes.items():
                if node.get(attribute):
                    add_link(owner, relation, node.get(attribute), target_kind, location)
            for attribute in ("QueryDataSourceName", "DMLDataTargetName"):
                if _QUALIFIED.fullmatch(node.get(attribute, "")):
                    dependency(owner, "database_object", node.get(attribute), "property:" + attribute, location)
            if _local(node.tag) in {"AttachedLibrary", "Report"}:
                candidate = node.get("LibraryLocation") or node.get("Filename") or node.get("Name", "")
                # Paths/URLs are not emitted. Registration is not supplied implementation.
                basename = candidate.replace("\\", "/").rsplit("/", 1)[-1]
                basename = re.sub(r"\.(?:pll|plx|rdf|rep)$", "", basename, flags=re.I)
                dependency(owner, "library" if _local(node.tag) == "AttachedLibrary" else "report", basename, "registration", location)
        sources = [(key, value, location) for key, value in node.attrib.items() if key in CODE_ATTRIBUTES and value.strip()]
        kind = _local(node.tag)
        if kind in {"Trigger", "ProgramUnit"} and (node.text or "").strip():
            sources.append(("#text", node.text, location))
        elif kind in CODE_ATTRIBUTES and (node.text or "").strip():
            sources.append((kind + ".text", node.text, location))
        for attribute, value, code_location in sources:
            if attribute == "QueryDataSourceName" and _QUALIFIED.fullmatch(value):
                continue
            code_raw = value.encode("utf-8")
            code_id = stable_id(code_location["path"], attribute)
            result["code_units"].append({"id": code_id, "owner_id": owner["id"], "kind": owner["kind"],
                "source_attribute": attribute, "sha256": _hash(code_raw), "bytes": len(code_raw),
                "lines": len(value.splitlines()) or 1, "location": dict(code_location),
                "hash_basis": "xml-decoded-utf8", "execution_status": "not_executed"})
            masked = _mask_code(value)
            database_matches = list(_DATABASE_REFERENCE.finditer(masked))
            database_positions = {match.start(1) for match in database_matches}
            for match in database_matches:
                dependency(owner, "database_object", match[1], "code:" + attribute, code_location)
            for match in _ROUTINE_REFERENCE.finditer(masked):
                candidate = re.sub(r"\s*\.\s*", ".", match[1])
                declaration = re.search(r"\b(?:PROCEDURE|FUNCTION)\s*$", masked[max(0, match.start() - 64):match.start()], re.I)
                if candidate.upper() not in _BUILTIN and match.start(1) not in database_positions and not declaration:
                    dependency(owner, "routine", candidate, "code:" + attribute, code_location)
                # Only known module-call argument slots are interpreted. Arbitrary
                # quoted business values and dynamic expressions are never copied.
                if candidate.upper() in {"CALL_FORM", "OPEN_FORM", "NEW_FORM"}:
                    literal = re.match(r"\s*'([A-Za-z][A-Za-z0-9_$#.]*)'\s*[,)]", value[match.end():])
                    if literal:
                        dependency(owner, "forms_module", literal[1], "literal_module_call:" + candidate.upper(), code_location)
                        add_link(owner, "calls_form", literal[1], "FormModule", code_location)
                    else:
                        finding("DYNAMIC_MODULE_TARGET", "A Forms module-call target is not a simple static identifier; review its runtime target.", [owner["id"]], "unknown")
            for match in _BIND_REFERENCE.finditer(masked):
                block_name, item_name = match[1].split(".")
                blocks = by_name.get((owner["module_id"], "Block", None, block_name.upper()), [])
                if len(blocks) == 1:
                    add_link(owner, "references_item", item_name, "Item", code_location, blocks[0]["id"])
                elif block_name.upper() not in {"GLOBAL", "SYSTEM", "PARAMETER"}:
                    finding("BIND_BLOCK_UNRESOLVED", "A code bind refers to an unresolved or ambiguous block; no target was invented.", [owner["id"]], "unknown")
            if _DYNAMIC.search(masked):
                finding("DYNAMIC_REFERENCE_REVIEW", "Dynamic SQL targets cannot be established by this local lexical inventory.", [owner["id"]])
    owners_with_code = {unit["owner_id"] for unit in result["code_units"]}
    for row in result["objects"]:
        if row["kind"] in {"Trigger", "ProgramUnit"} and row["id"] not in owners_with_code:
            finding("CODE_SOURCE_UNAVAILABLE", "Code object is present without a readable source unit.", [row["id"]], "unknown")
    # Preserve occurrence locations, but do not duplicate an identical fact.
    for key in ("dependencies", "links"):
        seen, unique = set(), []
        for row in result[key]:
            identity = tuple((field, tuple(sorted(value.items())) if isinstance(value, dict) else value) for field, value in row.items())
            if identity not in seen:
                unique.append(row)
                seen.add(identity)
        result[key] = unique
    kinds = Counter(row["kind"] for row in result["objects"])
    module_counts = defaultdict(Counter)
    for row in result["objects"]:
        module_counts[row["module_id"]][row["kind"]] += 1
    for row in result["modules"]:
        row["object_counts"] = dict(sorted(module_counts[row["id"]].items()))
    result["totals"] = {"modules": len(result["modules"]), "blocks": kinds["Block"], "items": kinds["Item"],
        "triggers": kinds["Trigger"], "program_units": kinds["ProgramUnit"], "code_units": len(result["code_units"]),
        "objects": len(result["objects"]), "links": len(result["links"]), "dependencies": len(result["dependencies"]),
        "uninterpreted_elements": unknown_count}
    finding("BEHAVIOR_NOT_ASSESSED", "Inventory does not establish application behavior, business acceptance or APEX conversion.", severity="unknown")
    if result["code_units"]:
        finding("CODE_REQUIRES_REVIEW", "Code was hashed and inventoried locally, not executed or semantically verified. Lexical dependency candidates are incomplete.")
    if result["dependencies"]:
        finding("DEPENDENCIES_UNVERIFIED", "Referenced database objects, routines, libraries and reports need authoritative definitions and ownership review.", severity="unknown")
    return result
