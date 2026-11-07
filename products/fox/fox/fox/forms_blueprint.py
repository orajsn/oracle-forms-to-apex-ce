"""Non-executing, source-bound application-design validation.

The caller MUST reconstruct the understanding packet from the retained originals
before calling this function. Matching packet/blueprint hashes alone cannot make
model-authored facts trustworthy. Success establishes structured design validity,
never generation readiness, Oracle metadata, conversion or business acceptance.

Dependency/link facts have no IDs in forms_facts. ``evidence_reference_id`` names
their exact occurrence as prefix + first 24 SHA256 hex characters of canonical
JSON [source SHA256, category, complete row]. Original fact rows remain unchanged.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
import re

from .forms_facts import MAX_FILE_BYTES, OBJECT_KINDS, MODULE_KINDS

PACKET_SCOPE = "fox-forms-understanding-packet-v1"
BLUEPRINT_SCOPE = "fox-forms-blueprint-v1"
MAX_ROWS = 60_000
MAX_JSON_NODES = 600_000
MAX_JSON_BYTES = 32 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}\Z")
_FACT_KEYS = {"schema_version", "scope", "assessment_status", "source", "modules",
              "blocks", "items", "objects", "code_units", "links", "dependencies",
              "findings", "safety", "interpretation_boundary", "totals"}
_OBJECT_KEYS = {"id", "kind", "name", "module_id", "block_id", "parent_id", "location"}


def _fail(message="Invalid source-bound blueprint structure."):
    # Messages deliberately never interpolate untrusted input or source text.
    raise ValueError(message)


def _keys(row, required, optional=()):
    if type(row) is not dict or not set(required) <= row.keys() or row.keys() - set(required) - set(optional):
        _fail()


def _text(value, maximum=2000):
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(c) < 32 and c not in "\n\t\r" for c in value)):
        _fail()


def _id(value):
    if type(value) is not str or not _ID.fullmatch(value):
        _fail()


def _integer(value, minimum=0, maximum=MAX_JSON_BYTES):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()


def _rows(value):
    if type(value) is not list or len(value) > MAX_ROWS:
        _fail()
    return value


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _bounded_json(value):
    remaining = MAX_JSON_NODES

    def visit(node, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 20:
            _fail("Blueprint or packet exceeds the bounded document limit.")
        if type(node) is dict:
            for key, child in node.items():
                if type(key) is not str or len(key) > 180:
                    _fail()
                visit(child, depth + 1)
        elif type(node) is list:
            if len(node) > MAX_ROWS:
                _fail()
            for child in node:
                visit(child, depth + 1)
        elif type(node) is str:
            if len(node) > MAX_FILE_BYTES:
                _fail()
        elif node is not None and type(node) not in (bool, int, float):
            _fail()
        elif type(node) is float and not math.isfinite(node):
            _fail()

    visit(value, 0)
    if len(_canonical(value).encode("utf-8")) > MAX_JSON_BYTES:
        _fail("Blueprint or packet exceeds the bounded document limit.")


def evidence_reference_id(source_sha256: str, category: str, row: dict) -> str:
    """Return an occurrence ID for an unchanged dependency or link fact row."""
    if not isinstance(source_sha256, str) or not _SHA.fullmatch(source_sha256) or category not in {"dependency", "link"}:
        _fail()
    _bounded_json(row)
    digest = hashlib.sha256(_canonical([source_sha256, category, row]).encode("utf-8")).hexdigest()[:24]
    return {"dependency": "ffdep1-", "link": "fflink1-"}[category] + digest


def _source(source):
    _keys(source, {"name", "sha256", "bytes", "encoding"})
    name = source["name"]
    _text(name, 180)
    if (".." in name or any(c in name for c in "/\\:") or not name.lower().endswith(".xml")
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or type(source["sha256"]) is not str or not _SHA.fullmatch(source["sha256"])
            or source["encoding"] != "utf-8"):
        _fail()
    _integer(source["bytes"], 1, MAX_FILE_BYTES)


def _location(location, source):
    _keys(location, {"path", "line", "column", "byte_offset"})
    _text(location["path"], 16_384)
    if not location["path"].startswith("/"):
        _fail()
    _integer(location["line"], 1, source["bytes"])
    _integer(location["column"], 1, source["bytes"])
    _integer(location["byte_offset"], 0, source["bytes"] - 1)


def _stable_id(source, location, suffix=""):
    return "ff1-" + hashlib.sha256((source["sha256"] + "\n" + location["path"] + "\n" + suffix).encode()).hexdigest()[:24]


def _facts(facts, source, objects, evidence, allowed):
    """Check extractor shape/identity; authenticity still needs original bytes."""
    _keys(facts, _FACT_KEYS)
    if (type(facts["schema_version"]) is not int or facts["schema_version"] != 1
            or facts["scope"] != "fox-forms-facts-v1" or facts["assessment_status"] != "LOCAL_FACTS_ONLY"
            or facts["source"] != source):
        _fail("Packet facts do not match their exact original-source identity.")
    if facts["safety"] != {"local_only": True, "code_executed": False, "model_submission_allowed": False,
                           "import_allowed": False, "native_generation_allowed": False}:
        _fail()
    _text(facts["interpretation_boundary"])
    local = {}

    def add_evidence(ref, owner, values):
        if ref in evidence:
            _fail("Packet contains duplicate source or evidence identifiers.")
        evidence[ref] = owner
        for kind, value in values.items():
            allowed.setdefault(owner, []).append((kind, _canonical(value), ref))

    for row in _rows(facts["objects"]):
        _keys(row, _OBJECT_KEYS, {"classification", "database_item", "item_type", "object_counts"})
        _id(row["id"])
        if row["kind"] not in OBJECT_KINDS or row["id"] in objects:
            _fail("Packet contains duplicate or invalid source object identifiers.")
        _location(row["location"], source)
        if row["id"] != _stable_id(source, row["location"]):
            _fail("Packet source object identifier does not match its source hash and location.")
        if row["name"] is not None:
            _text(row["name"], 256)
        for field in ("module_id", "block_id", "parent_id"):
            if row[field] is not None:
                _id(row[field])
        specific = set(row) - _OBJECT_KEYS
        expected = ({"classification"} if row["kind"] == "Block" else
                    {"database_item", "item_type"} if row["kind"] == "Item" else
                    {"object_counts"} if row["kind"] in MODULE_KINDS else set())
        if specific != expected:
            _fail()
        values = {"object." + key: row[key] for key in ("kind", "name", "module_id", "block_id", "parent_id")}
        if row["kind"] == "Block":
            if row["classification"] not in {"database", "control", "unknown"}:
                _fail()
            values["block.classification"] = row["classification"]
        if row["kind"] == "Item":
            if row["database_item"] is not None and type(row["database_item"]) is not bool:
                _fail()
            if row["item_type"] is not None:
                _text(row["item_type"], 256)
            values.update({"item.database_item": row["database_item"], "item.item_type": row["item_type"]})
        objects[row["id"]] = local[row["id"]] = row
        add_evidence(row["id"], row["id"], values)
    if not local:
        _fail()
    for row in local.values():
        for field, kinds in (("module_id", MODULE_KINDS), ("block_id", {"Block"}), ("parent_id", OBJECT_KINDS)):
            if row[field] is not None and (row[field] not in local or local[row[field]]["kind"] not in kinds):
                _fail("Packet contains an invalid source-object reference.")
        if row["kind"] in MODULE_KINDS:
            counts = dict(sorted(Counter(r["kind"] for r in local.values() if r["module_id"] == row["id"]).items()))
            if row["module_id"] != row["id"] or row["object_counts"] != counts:
                _fail()
        if row["kind"] == "Block" and row["block_id"] != row["id"]:
            _fail()
    for collection, kinds in (("modules", MODULE_KINDS), ("blocks", {"Block"}), ("items", {"Item"})):
        expected = [row for row in local.values() if row["kind"] in kinds]
        if _rows(facts[collection]) != expected:
            _fail("Packet inventory disagrees with its complete source-object list.")
    if not facts["modules"]:
        _fail()
    for unit in _rows(facts["code_units"]):
        _keys(unit, {"id", "owner_id", "kind", "source_attribute", "sha256", "bytes", "lines", "location", "hash_basis", "execution_status"})
        _location(unit["location"], source)
        if (unit["owner_id"] not in local or unit["kind"] != local[unit["owner_id"]]["kind"]
                or type(unit["sha256"]) is not str or not _SHA.fullmatch(unit["sha256"])
                or unit["hash_basis"] != "xml-decoded-utf8" or unit["execution_status"] != "not_executed"):
            _fail()
        _text(unit["source_attribute"], 180)
        if unit["id"] != _stable_id(source, unit["location"], unit["source_attribute"]):
            _fail("Packet code identifier does not match its source hash and location.")
        _integer(unit["bytes"], 1, MAX_FILE_BYTES)
        _integer(unit["lines"], 1, MAX_FILE_BYTES)
        add_evidence(unit["id"], unit["owner_id"], {"code." + key: unit[key] for key in
                     ("sha256", "bytes", "lines", "source_attribute", "execution_status")})
    for category, collection in (("dependency", "dependencies"), ("link", "links")):
        for row in _rows(facts[collection]):
            fields = ({"source_id", "kind", "name", "evidence", "confidence", "location"} if category == "dependency"
                      else {"source_id", "relation", "target_name", "target_id", "status", "location"})
            _keys(row, fields)
            if row["source_id"] not in local:
                _fail()
            _location(row["location"], source)
            if category == "dependency":
                if row["confidence"] != "candidate" or row["kind"] not in {"database_object", "routine", "library", "report", "forms_module"}:
                    _fail()
                _text(row["name"], 256)
                _text(row["evidence"], 180)
                values = {"dependency." + key: row[key] for key in ("kind", "confidence", "evidence")}
                values["dependency.candidate_name"] = row["name"]
            else:
                _text(row["relation"], 180)
                _text(row["target_name"], 256)
                if (row["status"] not in {"resolved", "unresolved", "ambiguous"}
                        or (row["target_id"] is not None and row["target_id"] not in local)
                        or (row["status"] == "resolved") != (row["target_id"] is not None)):
                    _fail()
                values = {"link." + key: row[key] for key in ("relation", "target_name", "target_id", "status")}
            add_evidence(evidence_reference_id(source["sha256"], category, row), row["source_id"], values)
    for finding in _rows(facts["findings"]):
        _keys(finding, {"code", "severity", "message", "object_ids"})
        _text(finding["code"], 180)
        _text(finding["severity"], 30)
        _text(finding["message"])
        if any(ref not in local for ref in _rows(finding["object_ids"])):
            _fail()
    kinds = Counter(row["kind"] for row in local.values())
    totals = {"modules": len(facts["modules"]), "blocks": kinds["Block"], "items": kinds["Item"],
              "triggers": kinds["Trigger"], "program_units": kinds["ProgramUnit"], "objects": len(local),
              **{key: len(facts[key]) for key in ("code_units", "links", "dependencies")}}
    _keys(facts["totals"], set(totals) | {"uninterpreted_elements"})
    _integer(facts["totals"]["uninterpreted_elements"], maximum=30_000)
    if any(type(facts["totals"][key]) is not int or facts["totals"][key] != value for key, value in totals.items()):
        _fail()


def _value(value):
    # No executable, nested payload/SQL fields can hide inside a claim value.
    values = value if type(value) is list else [value]
    if len(values) > 32:
        _fail()
    for part in values:
        if type(part) is str:
            _text(part, 512)
        elif part is not None and type(part) not in (bool, int):
            _fail()


def _packet_binding(packet):
    """Rebuild the full descriptor binding, including unselected code units."""
    descriptors = []
    for entry in packet["sources"]:
        source = entry["source"]
        for unit in entry["facts"]["code_units"]:
            chunk_id = "fup1-" + hashlib.sha256(_canonical([source["name"], source["sha256"], unit["id"]]).encode("utf-8")).hexdigest()
            descriptors.append({"id": chunk_id, "source_sha256": source["sha256"], "code_unit_id": unit["id"],
                                "sha256": unit["sha256"], "bytes": unit["bytes"]})
    digest = hashlib.sha256(_canonical({"sources": packet["sources"], "chunks": descriptors}).encode("utf-8")).hexdigest()
    if packet["source_binding"] != digest:
        _fail("Packet binding does not match its full source facts and code descriptors.")
    known = {row["id"]: row for row in descriptors}
    seen, selected_units = set(), []
    chunks = _rows(packet.get("chunks", []))
    for chunk in chunks:
        _keys(chunk, {"id", "source_sha256", "code_unit_id", "sha256", "bytes"}, {"text"})
        if chunk["id"] not in known or chunk["id"] in seen:
            _fail("Packet contains unknown or duplicate code chunks.")
        seen.add(chunk["id"])
        if {key: value for key, value in chunk.items() if key != "text"} != known[chunk["id"]]:
            _fail("Packet code-chunk descriptors do not match source code-unit hashes.")
        if "text" in chunk:
            if type(chunk["text"]) is not str:
                _fail()
            raw = chunk["text"].encode("utf-8")
            if len(raw) != chunk["bytes"] or hashlib.sha256(raw).hexdigest() != chunk["sha256"]:
                _fail("Selected code text does not match its exact source-unit hash.")
        selected_units.append(chunk["code_unit_id"])
    if "transfer_authorized" in packet and packet["transfer_authorized"] is not False:
        _fail()
    if "caller_must_check_processing_approval" in packet and packet["caller_must_check_processing_approval"] is not True:
        _fail()
    if "interpretation_boundary" in packet:
        _text(packet["interpretation_boundary"])
    if "safety" in packet and _canonical(packet["safety"]) != _canonical({
            "code_executed": False, "source_content_is_untrusted": True,
            "model_submission_allowed": False, "native_generation_allowed": False}):
        _fail()
    if "selection_status" in packet:
        status = packet["selection_status"]
        if status == "NOT_SELECTED":
            if (packet.get("selectable_code_unit_ids") != [row["code_unit_id"] for row in descriptors]
                    or chunks != descriptors or "selected_code_unit_ids" in packet or "no_automatic_selection" in packet):
                _fail()
        elif status in {"SCOPED_CONTENT_SELECTED", "METADATA_ONLY"}:
            if (packet.get("selected_code_unit_ids") != selected_units or packet.get("no_automatic_selection") is not True
                    or "selectable_code_unit_ids" in packet or any("text" not in chunk for chunk in chunks)
                    or (status == "SCOPED_CONTENT_SELECTED") != bool(chunks)):
                _fail()
        else:
            _fail()
    elif any(key in packet for key in ("selectable_code_unit_ids", "selected_code_unit_ids", "no_automatic_selection")):
        _fail()


def validate_blueprint(packet: dict, blueprint: dict) -> dict:
    """Validate a design against freshly recomputed local facts; return no code.

    Unknown keys, incomplete coverage, invented identities/facts and unbound
    references fail closed with bounded ValueError messages. No input is mutated.
    """
    try:
        return _validate_blueprint(packet, blueprint)
    except (TypeError, KeyError, RecursionError, OverflowError, UnicodeError):
        _fail()


def source_fact_index(packet):
    """Validate fresh packet facts and expose the SAME exact evidence whitelist.

    Caller must reconstruct packet from original bytes. This is deterministic
    source evidence, never an AI approval, generation or behavior acceptance.
    """
    _bounded_json(packet)
    _keys(packet, {"schema_version", "scope", "source_binding", "sources"}, {
        "chunks", "selectable_code_unit_ids", "selected_code_unit_ids", "transfer_authorized",
        "caller_must_check_processing_approval", "interpretation_boundary", "safety", "selection_status", "no_automatic_selection"})
    if type(packet["schema_version"]) is not int or packet["schema_version"] != 1 or packet["scope"] != PACKET_SCOPE:
        _fail()
    if type(packet["source_binding"]) is not str or not _SHA.fullmatch(packet["source_binding"]):
        _fail()
    if not packet["sources"] or len(_rows(packet["sources"])) > 4:
        _fail()
    objects, evidence, allowed, source_hashes = {}, {}, {}, set()
    for entry in packet["sources"]:
        _keys(entry, {"source", "facts"})
        _source(entry["source"])
        if entry["source"]["sha256"] in source_hashes:
            _fail("Packet contains duplicate original sources.")
        source_hashes.add(entry["source"]["sha256"])
        _facts(entry["facts"], entry["source"], objects, evidence, allowed)
    _packet_binding(packet)
    return objects, evidence, allowed


def validate_claim_evidence(claim, objects, evidence, allowed):
    """Apply the existing claim-evidence/source-fact rule, without widening it."""
    owner = claim['source_object_id']
    if owner not in objects or claim['status'] not in {'source_fact', 'proposal', 'unresolved'}:
        _fail()
    _text(claim['kind'], 100)
    _text(claim['reason'])
    _value(claim['value'])
    refs = _rows(claim['evidence_refs'])
    if (not refs or len(set(refs)) != len(refs) or any(ref not in evidence for ref in refs)
            or not any(evidence[ref] == owner for ref in refs)):
        _fail('A claim must reference exact source evidence, including its source object.')
    if claim['status'] == 'source_fact':
        matches = {ref for kind, value, ref in allowed.get(owner, [])
                   if kind == claim['kind'] and value == _canonical(claim['value'])}
        if not matches or not set(refs) <= matches:
            _fail('A source-fact claim is not an exact whitelisted machine-extracted fact.')


def _validate_blueprint(packet, blueprint):
    _bounded_json(blueprint)
    objects, evidence, allowed = source_fact_index(packet)
    _keys(blueprint, {"schema_version", "scope", "source_binding", "objects", "screens", "claims",
                      "relationships", "actions", "questions", "assumptions"})
    if (type(blueprint["schema_version"]) is not int or blueprint["schema_version"] != 1
            or blueprint["scope"] != BLUEPRINT_SCOPE or blueprint["source_binding"] != packet["source_binding"]):
        _fail("Blueprint is stale or not bound to the exact understanding packet.")
    ids = set(objects) | set(evidence)

    def index(rows, required, optional=()):
        result = {}
        for row in _rows(rows):
            _keys(row, required, optional)
            _id(row["id"])
            if row["id"] in ids:
                _fail("Blueprint contains duplicate or colliding identifiers.")
            ids.add(row["id"])
            result[row["id"]] = row
        return result

    screens = index(blueprint["screens"], {"id", "title"})
    for screen in screens.values():
        _text(screen["title"], 300)
    dispositions = {}
    for row in _rows(blueprint["objects"]):
        _keys(row, {"source_object_id", "disposition", "reason"}, {"screen_id", "native_component"})
        ref = row["source_object_id"]
        if ref not in objects or ref in dispositions:
            _fail("Blueprint contains an unknown or duplicate source disposition.")
        if row["disposition"] not in {"proposed", "omitted", "unresolved"}:
            _fail()
        _text(row["reason"])
        if row["disposition"] == "proposed":
            if row.get("screen_id") not in screens:
                _fail("A proposed object must reference an existing blueprint screen.")
            if objects[ref]["kind"] == "Block":
                components = {"database": {"form", "interactive-grid", "report"}, "control": {"page-items"}, "unknown": set()}
                if row.get("native_component") not in components[objects[ref]["classification"]]:
                    _fail("Block mapping does not match its established source classification.")
            elif "native_component" in row:
                _fail("Native component selection belongs to source blocks only.")
        elif "screen_id" in row or "native_component" in row:
            _fail("Unresolved or omitted objects cannot silently carry target mappings.")
        dispositions[ref] = row
    if dispositions.keys() != objects.keys():
        _fail("Every source object requires exactly one explicit disposition.")
    for ref, row in dispositions.items():
        source = objects[ref]
        if row["disposition"] == "proposed" and source["kind"] == "Item":
            block = dispositions.get(source["block_id"])
            if not block or block["disposition"] != "proposed" or block["screen_id"] != row["screen_id"]:
                _fail("A proposed item must retain its source block and target screen.")
    claims = index(blueprint["claims"], {"id", "source_object_id", "kind", "value", "status", "evidence_refs", "reason"})
    for claim in claims.values():
        validate_claim_evidence(claim, objects, evidence, allowed)
    for collection in ("relationships", "actions"):
        for row in index(blueprint[collection], {"id", "claim_ids"}).values():
            refs = _rows(row["claim_ids"])
            if not refs or len(set(refs)) != len(refs) or any(ref not in claims for ref in refs):
                _fail("Design actions and relationships must reference existing claims only.")
    for row in index(blueprint["questions"], {"id", "source_object_id", "text"}).values():
        if row["source_object_id"] not in objects:
            _fail()
        _text(row["text"])
    for row in index(blueprint["assumptions"], {"id", "text", "scope"}).values():
        if row["scope"] != "prototype-only":
            _fail()
        _text(row["text"])
    counts = Counter(row["disposition"] for row in dispositions.values())
    return {"schema_version": 1, "scope": "fox-forms-blueprint-validation-v1",
            "source_binding": packet["source_binding"], "structured_blueprint_valid": True,
            "source_objects": len(objects), "accounted_objects": len(dispositions),
            "source_blocks": sum(row["kind"] == "Block" for row in objects.values()),
            "proposed_objects": counts["proposed"], "omitted_objects": counts["omitted"],
            "unresolved_objects": counts["unresolved"], "source_fact_claims": sum(c["status"] == "source_fact" for c in claims.values()),
            "generation_ready": False, "native_apex_generated": False, "native_apex_validity_verified": False,
            "import_verified": False, "business_behavior_accepted": False,
            "evidence_level": "structured-source-bound-design-only"}
