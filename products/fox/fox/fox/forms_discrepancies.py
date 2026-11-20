"""Deterministic source-linked explanations, never execution or acceptance proof.

The caller supplies a freshly rebuilt understanding packet and independently
checked ledger/catalog/gaps. Retained reads need those same original source facts;
re-hashing an edited report is not a substitute. No source bodies are emitted.
"""
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
import re

from . import forms_facts
from .forms_facts import _mask_code
from .forms_behavior_plan import decode_control_entities, UnsupportedBehavior


SCOPE = "fox-source-discrepancies-v1"
DEPENDENCY_SCOPE = "fox-source-dependency-evidence-v1"
_PLSQL_SYNTAX = frozenset({"VARCHAR2", "VARCHAR", "NVARCHAR2", "CHAR", "NCHAR", "NUMBER", "NUMERIC",
    "DECIMAL", "DEC", "FLOAT", "REAL", "INTEGER", "INT", "SMALLINT", "BINARY_FLOAT", "BINARY_DOUBLE",
    "RAW", "LONG", "TIMESTAMP", "INTERVAL", "NOT", "RETURN", "AND", "OR", "EXISTS", "FROM",
    "WHERE", "HAVING", "ON", "WHEN", "THEN", "ELSE"})
_SQL_CLAUSES = frozenset({"WHERE", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "OUTER", "CROSS", "NATURAL",
    "GROUP", "ORDER", "HAVING", "CONNECT", "START", "UNION", "INTERSECT", "MINUS", "FOR", "FETCH", "OFFSET"})
# Deliberately finite. An unlisted lexical candidate is not presumed external,
# reachable, callable, or even a routine (the facts inventory is not a compiler).
FORMS_APIS = frozenset({
    "CALL_FORM", "CLEAR_BLOCK", "CLEAR_FORM", "CLEAR_RECORD", "COMMIT_FORM",
    "CREATE_RECORD", "DELETE_RECORD", "DO_KEY", "DUPLICATE_RECORD",
    "EXECUTE_QUERY", "EXIT_FORM", "FIND_ALERT", "FIND_BLOCK", "FIND_ITEM",
    "FIND_LOV", "FIND_RELATION", "FIND_REPORT_OBJECT", "FIRST_RECORD", "FORMS_DDL", "GET_BLOCK_PROPERTY",
    "GET_ITEM_PROPERTY", "GET_RECORD_PROPERTY", "GET_RELATION_PROPERTY", "GET_APPLICATION_PROPERTY",
    "GO_BLOCK", "GO_ITEM", "GO_RECORD", "HIDE_VIEW", "LAST_RECORD",
    "LIST_VALUES", "MESSAGE", "NEW_FORM", "NEXT_ITEM", "NEXT_RECORD",
    "OPEN_FORM", "POST", "PREVIOUS_ITEM", "PREVIOUS_RECORD", "RUN_PRODUCT",
    "RUN_REPORT_OBJECT", "SET_ALERT_PROPERTY", "SET_BLOCK_PROPERTY",
    "SET_ITEM_INSTANCE_PROPERTY", "SET_ITEM_PROPERTY", "SET_RECORD_PROPERTY",
    "SET_REPORT_OBJECT_PROPERTY", "SET_WINDOW_PROPERTY", "SHOW_ALERT", "SHOW_LOV", "SHOW_VIEW",
    "SYNCHRONIZE", "VALIDATE", "WEB.SHOW_DOCUMENT",
})

_NAME = r"[A-Za-z][A-Za-z0-9_$#]*"
_DOTTED = rf"{_NAME}(?:\s*\.\s*{_NAME})*"
_PAREN_CALL = re.compile(rf"(?<![\w:$#.@])({_DOTTED})\s*\(", re.I)
# A zero-argument procedure can be a whole statement without parentheses.
# Only registered same-module names, known Forms APIs or qualified references
# qualify. A lone identifier in a SQL expression is insufficient.
_BARE_CALL = re.compile(rf"(?:\A|;|\b(?:BEGIN|THEN|ELSE|LOOP)\b)\s*({_DOTTED})\s*(?=;)", re.I)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _require(condition):
    if not condition:
        raise ValueError("Discrepancy evidence does not match the source-bound mapping.")


def _unique(rows, key):
    _require(type(rows) is list)
    result = {row[key]: row for row in rows}
    _require(len(result) == len(rows))
    return result


def _semantic_mask(semantic):
    # The legacy inventory masks -- comments up to LF. Normalize only the scan
    # copy so Oracle CR, LF and CRLF line endings terminate comments alike.
    # semantic_sha256 continues to identify the exact unnormalized decoder text.
    return _mask_code(semantic.replace("\r\n", "\n").replace("\r", "\n"))


def _comma_from_candidates(masked, database_matches):
    """Recognize only contiguous simple FROM A [alias], B [alias] lists.

    No dynamic SQL, quoted identifiers, subquery expansion or reachability is
    inferred. Other supported FROM/JOIN/DML targets use the established regex.
    """
    candidates = []
    for match in database_matches:
        if not re.match(r"FROM\b", masked[match.start():], re.I):
            continue
        cursor = match.end(1)
        while True:
            tail = masked[cursor:]
            alias = re.match(r"\s+(?:AS\s+)?([A-Za-z][A-Za-z0-9_$#]*)\s*(?=,)", tail, re.I)
            if alias and alias[1].upper() not in _SQL_CLAUSES:
                cursor += alias.end()
            following = re.match(r"\s*,\s*(" + forms_facts._SQL_IDENTIFIER + r")", masked[cursor:])
            if following is None:
                break
            candidates.append(following[1])
            cursor += following.end()
    return candidates


def build_dependency_evidence(packet, chunks, ledger):
    """Add a semantic inventory without changing the original facts or binding.

    XML-decoded source sometimes contains literal numeric TAB/LF/CR entities.
    Their established decoder must run before lexical comment masking, otherwise
    an encoded newline can hide the rest of a unit behind a line comment. This
    manifest is separate from the historical mapping ledger and proves neither
    reachability nor executable interfaces. Ambiguous units retain raw candidates.
    """
    try:
        descriptors = [{k: v for k, v in row.items() if k != "text"} for row in packet["chunks"]]
        _require(packet["source_binding"] == ledger["source_binding"] == hashlib.sha256(_canonical(
            {"sources": packet["sources"], "chunks": descriptors})).hexdigest())
        available = _unique(descriptors, "code_unit_id")
        text_chunks = _unique(chunks, "code_unit_id")
        coverage = _unique(ledger["code_units"], "source_unit_id")
        units = {u["id"]: u for entry in packet["sources"] for u in entry["facts"]["code_units"]}
        _require(set(units) == set(available) == set(text_chunks) == set(coverage))
        original = [(collection, row) for entry in packet["sources"] for collection in ("dependencies", "links")
                    for row in entry["facts"][collection]]
        _require(Counter(_canonical([r["kind"], r["evidence"]]) for r in ledger["dependencies_and_links"]) ==
                 Counter(_canonical([collection, row]) for collection, row in original))
        objects = {o["id"]: o for entry in packet["sources"] for o in entry["facts"]["objects"]}
        local_names = defaultdict(set)
        for obj in objects.values():
            if obj["kind"] == "ProgramUnit" and obj["name"]:
                local_names[obj["module_id"]].add(obj["name"].upper())
        manifest_units, replacements, scanned = [], set(), []
        for uid, unit in units.items():
            chunk = text_chunks[uid]
            _require({k: v for k, v in chunk.items() if k != "text"} == available[uid])
            _require(type(chunk["text"]) is str and hashlib.sha256(chunk["text"].encode("utf-8")).hexdigest() ==
                     unit["sha256"] == coverage[uid]["source_unit_sha256"])
            _require(coverage[uid]["source_owner_id"] == unit["owner_id"] and
                     coverage[uid]["source_location"] == unit["location"])
            semantic, decoding, limitation = chunk["text"], "decoded", None
            try:
                semantic, _ = decode_control_entities(chunk["text"])
            except UnsupportedBehavior:
                decoding = "original_fallback"
                limitation = "Control-entity decoding is ambiguous or unsupported; original lexical candidates retained for this unit."
            manifest_units.append({"source_unit_id": uid, "source_unit_sha256": unit["sha256"],
                "semantic_sha256": hashlib.sha256(semantic.encode("utf-8")).hexdigest(),
                "decoding": decoding, "limitation": limitation})
            if decoding == "original_fallback":
                continue
            replacements.add((unit["owner_id"], unit["source_attribute"], _canonical(unit["location"])))
            masked = _semantic_mask(semantic)
            database_matches = list(forms_facts._DATABASE_REFERENCE.finditer(masked))
            database_positions = {match.start(1) for match in database_matches}
            candidates = [("database_object", match[1]) for match in database_matches]
            candidates.extend(("database_object", name) for name in _comma_from_candidates(masked, database_matches))
            for match in _PAREN_CALL.finditer(masked):
                candidate = re.sub(r"\s*\.\s*", ".", match[1])
                declaration = re.search(r"\b(?:PROCEDURE|FUNCTION)\s*$", masked[max(0, match.start() - 64):match.start()], re.I)
                if (candidate.upper() not in forms_facts._BUILTIN | _PLSQL_SYNTAX
                        and match.start(1) not in database_positions and not declaration):
                    candidates.append(("routine", candidate))
            if unit["source_attribute"] in {"TriggerText", "ProgramUnitText"}:
                module = objects[unit["owner_id"]]["module_id"]
                for match in _BARE_CALL.finditer(masked):
                    name = re.sub(r"\s*\.\s*", ".", match[1])
                    if "." in name or name.upper() in local_names[module] or name.upper() in FORMS_APIS:
                        candidates.append(("routine", name))
            seen = set()
            for kind, candidate in candidates:
                name = re.sub(r"\s*\.\s*", ".", candidate)
                if not forms_facts._QUALIFIED.fullmatch(name):
                    continue
                evidence = {"source_id": unit["owner_id"], "kind": kind, "name": name,
                    "evidence": "code:" + unit["source_attribute"], "confidence": "candidate", "location": deepcopy(unit["location"])}
                identity = _canonical(evidence)
                if identity in seen:
                    continue
                seen.add(identity)
                scanned.append({"source_object_id": unit["owner_id"], "kind": "dependencies", "code": "dependency_not_implemented",
                    "evidence": evidence,
                    "reason": "Source dependency/link evidence is not executed or claimed resolved by the native prototype.",
                    "next_action": "Review and implement the dependency separately; source presence is not conversion."})
        preserved = []
        for row in ledger["dependencies_and_links"]:
            evidence = row["evidence"]
            attribute = evidence.get("evidence", "")
            if row["kind"] == "dependencies" and attribute.startswith("code:") and (
                    evidence["source_id"], attribute[5:], _canonical(evidence["location"])) in replacements:
                continue
            preserved.append(deepcopy(row))
        _require(len(preserved) + len(scanned) <= 4 * forms_facts.MAX_REFERENCES)
        return {"schema_version": 1, "scope": DEPENDENCY_SCOPE, "source_binding": packet["source_binding"],
                "units": manifest_units, "references": preserved + scanned}
    except (KeyError, TypeError, AttributeError, OverflowError) as exc:
        raise ValueError("Invalid source-bound dependency evidence.") from exc


def _evidence(packet, ledger, gap_report, catalog, *, chunks=None, dependency_evidence=None):
    """Check coverage, provenance and complete reference inventory before explaining."""
    binding = packet["source_binding"]
    descriptors = [{k: v for k, v in row.items() if k != "text"} for row in packet["chunks"]]
    _require(binding == hashlib.sha256(_canonical({"sources": packet["sources"],
                                                  "chunks": descriptors})).hexdigest())
    _require(ledger["source_binding"] == gap_report["source_binding"] == binding)
    _require(ledger["scope"] == "fox-xml-source-to-target-v1"
             and gap_report["scope"] == "fox-source-mapping-gaps-v1")
    _require(ledger["runtime_verified"] is False and ledger["business_behavior_accepted"] is False)
    _require(gap_report["dependency_candidates_are_confirmed_missing_inputs"] is False)
    _require(catalog["catalog_sha256"] == hashlib.sha256(_canonical(
        {k: v for k, v in catalog.items() if k != "catalog_sha256"})).hexdigest())
    _require(ledger["catalog_sha256"] == catalog["catalog_sha256"])
    rules = _unique(catalog["rules"], "id")
    objects, units, references = {}, {}, []
    for entry in packet["sources"]:
        source, facts = entry["source"], entry["facts"]
        _require(source == facts["source"])
        for obj in facts["objects"]:
            _require(obj["id"] not in objects)
            objects[obj["id"]] = (obj, source)
        for unit in facts["code_units"]:
            _require(unit["id"] not in units)
            units[unit["id"]] = (unit, source)
        for collection in ("dependencies", "links"):
            references.extend((collection, row) for row in facts[collection])
    chunks_by_id = _unique(descriptors, "code_unit_id")
    coverage = _unique(ledger["code_units"], "source_unit_id")
    _require(set(units) == set(chunks_by_id) == set(coverage))
    for uid, (unit, source) in units.items():
        row, chunk = coverage[uid], chunks_by_id[uid]
        _require(row["source_unit_sha256"] == chunk["sha256"] == unit["sha256"])
        _require(chunk["source_sha256"] == source["sha256"] and chunk["bytes"] == unit["bytes"])
        _require(row["source_owner_id"] == unit["owner_id"]
                 and row["source_location"] == unit["location"]
                 and row["source_file"] == {k: source[k] for k in ("name", "sha256", "bytes")})
        rule = rules[row["rule_id"]]
        _require(row["rule_revision"] == rule["revision"])
        _require(row["runtime_verified"] is False and row["business_accepted"] is False)
        _require(row["status"] in {"generated_wired_adapted", "unsupported", "missing_input", "not_selected"})
        if row["status"] == "generated_wired_adapted" or row.get("encoding_status") == "generated_unwired":
            target = row["target"]
            _require(type(target) is dict and target["source_unit_id"] == uid
                     and target.get("source_unit_sha256", unit["sha256"]) == unit["sha256"])
        _require(row.get("encoding_status") in {None, "generated_unwired"})
        _require(not (row["status"] == "generated_wired_adapted" and row.get("encoding_status")))
    expected_references = Counter(_canonical([collection, row]) for collection, row in references)
    actual_references = []
    for row in ledger["dependencies_and_links"]:
        _require(row["code"] == "dependency_not_implemented"
                 and row["source_object_id"] == row["evidence"]["source_id"])
        actual_references.append(_canonical([row["kind"], row["evidence"]]))
    _require(Counter(actual_references) == expected_references)
    if dependency_evidence is not None:
        _require(_canonical(dependency_evidence) == _canonical(build_dependency_evidence(packet, chunks, ledger)))
        references = [(row["kind"], row["evidence"]) for row in dependency_evidence["references"]]
    gaps = _unique(gap_report["gaps"], "source_unit_id")
    _require(set(gaps) == {uid for uid, row in coverage.items() if row["status"] != "generated_wired_adapted"})
    _require(type(gap_report["not_yet_converted"]) is int and gap_report["not_yet_converted"] == len(gaps))
    _require(gap_report["summary"] == {kind: sum(g["category"] == kind for g in gaps.values())
             for kind in ("engine_mapping", "engine_context", "missing_source", "review_required")})
    for uid, gap in gaps.items():
        unit, source = units[uid]
        owner = objects[unit["owner_id"]][0]
        _require(gap["source_file"] == source["name"] and gap["source_line"] == unit["location"]["line"]
                 and gap["source_name"] == (owner["name"] or owner["kind"]))
    return objects, units, coverage, gaps, rules, references


def _reference_description(kind, name, status):
    if kind == "forms_api":
        return ("Known Oracle Forms API name referenced in source; its APEX adaptation is not established by this inventory.",
                "Review the original API semantics and implement or verify its target event and state adapter.")
    if kind == "local_routine":
        return (("A same-module ProgramUnit source body is present; source presence does not establish implementation or supported callers."
                 if status == "source_definition_present" else
                 "A same-module ProgramUnit is registered; its complete body presence is unverified."),
                "Review the complete local routine and each caller against its separate conversion status.")
    if kind == "database_object":
        if name.upper() in {"DUAL", "SYS.DUAL"}:
            return ("Oracle DUAL is a platform SQL reference, not evidence of a missing customer table; target SQL remains unverified.",
                    "Verify the generated query and target SQL compatibility in an authorized environment.")
        return ("Source references a database object; its definition, target binding and runtime availability are unverified.",
                "Verify the authoritative database interface and target binding when reviewing this behavior.")
    if kind == "report":
        return ("A report is registered in the Forms source; registration does not supply its query or layout definition.",
                "Verify the report definition and target reporting interface separately; keep supported conversion progressing.")
    if kind == "routine_reference":
        return ("Lexical routine candidate only; local/external ownership, executable meaning and reachability are unverified.",
                "Review its source context and authoritative interface before mapping the call; do not infer a missing file.")
    if status == "source_definition_present":
        return ("The declared source link has an identified same-module target; this does not establish its APEX implementation.",
                "Review the source relationship and its generated target binding separately.")
    return ("Source declares a link or supporting module reference; target behavior and availability are unverified.",
            "Review the authoritative relationship and target binding without treating an unresolved link as a missing file.")


def build_discrepancies(packet, ledger, gap_report, catalog, *, chunks=None, dependency_evidence=None):
    """Build the complete report from fresh source facts and checked mapping evidence.

    Optional hash-bound chunks permit conservative local body-presence checks;
    these do not establish valid PL/SQL syntax, compilation or behavior.
    No dependency finding prevents generation of independently supported parts.
    """
    try:
        objects, units, coverage, gaps, rules, references = _evidence(packet, ledger, gap_report, catalog,
            chunks=chunks, dependency_evidence=dependency_evidence)
        output_units = []
        for uid, (unit, source) in units.items():
            row, owner = coverage[uid], objects[unit["owner_id"]][0]
            if row["status"] == "generated_wired_adapted":
                status = "generated"
                message = "Generated with adaptations. " + rules[row["rule_id"]]["adaptations"]
                action = "Verify target runtime and business behavior against the original source; neither is accepted here."
            else:
                status = "encoded_unwired" if row.get("encoding_status") == "generated_unwired" else "unimplemented"
                message, action = gaps[uid]["message"], gaps[uid]["next_action"]
                if status == "encoded_unwired":
                    message += " " + rules[row["rule_id"]]["adaptations"]
            output_units.append({"source_unit_id": uid, "source_unit_sha256": unit["sha256"],
                "source_name": owner["name"] or owner["kind"], "source_file": source["name"],
                "source_line": unit["location"]["line"], "status": status,
                "message": message, "next_action": action})
        local = defaultdict(list)
        body_owners = set()
        if chunks is not None:
            text_chunks = _unique(chunks, "code_unit_id")
            _require(set(text_chunks) == set(units))
            for uid, (unit, _) in units.items():
                chunk = text_chunks[uid]
                _require(type(chunk["text"]) is str and hashlib.sha256(chunk["text"].encode("utf-8")).hexdigest() == unit["sha256"])
                owner = objects[unit["owner_id"]][0]
                if owner["kind"] != "ProgramUnit" or not owner["name"]:
                    continue
                # Conservative body-presence evidence only, not a PL/SQL parser,
                # compiler, side-effect analysis or executable behavior proof.
                try:
                    body_semantic, _ = decode_control_entities(chunk["text"])
                except UnsupportedBehavior:
                    continue
                tokens = re.findall(r"[A-Za-z][A-Za-z0-9_$#]*|;", _semantic_mask(body_semantic).upper())
                name = owner["name"].upper()
                if (len(tokens) >= 7 and tokens[0] in {"PROCEDURE", "FUNCTION"} and tokens[1] == name
                        and ("IS" in tokens or "AS" in tokens) and "BEGIN" in tokens
                        and (tokens[-2:] == ["END", ";"] or tokens[-3:] == ["END", name, ";"])):
                    body_owners.add(owner["id"])
        by_owner = defaultdict(list)
        for uid, (unit, _) in units.items():
            by_owner[unit["owner_id"]].append(unit)
        for obj, _ in objects.values():
            if obj["kind"] == "ProgramUnit" and obj["name"]:
                local[(obj["module_id"], obj["name"].upper())].append(obj["id"])
        grouped = {}
        for collection, ref in references:
            owner, source = objects[ref["source_id"]]
            name = ref["target_name"] if collection == "links" else ref["name"]
            kind, status = "source_link", "unverified"
            if collection == "dependencies" and ref["kind"] == "routine":
                definitions = local.get((owner["module_id"], name.upper()), [])
                if len(definitions) == 1:
                    kind = "local_routine"
                    if definitions[0] in body_owners:
                        status = "source_definition_present"
                else:
                    kind = "forms_api" if name.upper() in FORMS_APIS else "routine_reference"
            elif collection == "dependencies" and ref["kind"] in {"database_object", "report"}:
                kind = ref["kind"]
            key = (owner["module_id"], kind, name.upper())
            if key not in grouped:
                message, action = _reference_description(kind, name, status)
                grouped[key] = {"id": "fd1-" + hashlib.sha256(_canonical(key)).hexdigest()[:24],
                    "kind": kind, "name": name, "status": status, "message": message,
                    "next_action": action, "occurrences": []}
            group = grouped[key]
            # One occurrence per original candidate/link fact, including two
            # facts at the same XML coordinate. This preserves reference totals.
            group["occurrences"].append({"source_object_id": owner["id"], "source_file": source["name"],
                "source_line": ref["location"]["line"], "source_unit_ids": sorted(
                    u["id"] for u in by_owner[owner["id"]] if u["location"] == ref["location"]
                    and (ref.get("evidence") == "code:" + u["source_attribute"] or
                         (collection == "links" and ref["relation"] in {"references_item", "calls_form"})))})
            if group["status"] != status:
                # A group with any unresolved relationship remains unverified.
                group["status"] = "unverified"
                group["message"], group["next_action"] = _reference_description(kind, name, "unverified")
        counts = Counter(row["status"] for row in output_units)
        return {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
            "summary": {"total_units": len(output_units), "generated_units": counts["generated"],
                "encoded_unwired_units": counts["encoded_unwired"], "unimplemented_units": counts["unimplemented"],
                "dependency_groups": len(grouped), "dependency_references": len(references)},
            "units": output_units, "dependencies": list(grouped.values()),
            "runtime_verified": False, "business_behavior_accepted": False}
    except (KeyError, TypeError, AttributeError, OverflowError) as exc:
        raise ValueError("Invalid source-bound discrepancy evidence.") from exc


def _keys(value, keys):
    _require(type(value) is dict and set(value) == set(keys.split()))


def _text(value, maximum=4000):
    _require(type(value) is str and 0 < len(value) <= maximum)


def _retained_dependency_references(evidence, ledger, coverage, objects):
    """Crosslinks only; outer verifier authenticates this separate artifact SHA."""
    _keys(evidence, "schema_version scope source_binding units references")
    _require(type(evidence["schema_version"]) is int and evidence["schema_version"] == 1
             and evidence["scope"] == DEPENDENCY_SCOPE and evidence["source_binding"] == ledger["source_binding"])
    units = _unique(evidence["units"], "source_unit_id")
    _require(set(units) == set(coverage))
    for uid, unit in units.items():
        _keys(unit, "source_unit_id source_unit_sha256 semantic_sha256 decoding limitation")
        _require(unit["source_unit_sha256"] == coverage[uid]["source_unit_sha256"])
        _require(type(unit["semantic_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", unit["semantic_sha256"]) is not None)
        _require(unit["decoding"] in {"decoded", "original_fallback"})
        if unit["decoding"] == "original_fallback":
            _require(unit["semantic_sha256"] == unit["source_unit_sha256"])
            _text(unit["limitation"])
        else:
            _require(unit["limitation"] is None)
    references = evidence["references"]
    _require(type(references) is list and len(references) <= 80000)
    _require(len({_canonical(row) for row in references}) == len(references))

    def is_code(row):
        return row["kind"] == "dependencies" and row["evidence"].get("evidence", "").startswith("code:")

    # Property declarations and source links are not reconstructed or guessed.
    _require(Counter(_canonical(row) for row in references if not is_code(row)) ==
             Counter(_canonical(row) for row in ledger["dependencies_and_links"] if not is_code(row)))
    original_code = {_canonical(row) for row in ledger["dependencies_and_links"] if is_code(row)}
    units_by_location = defaultdict(list)
    for uid, row in coverage.items():
        units_by_location[(row["source_owner_id"], _canonical(row["source_location"]))].append(uid)

    def fallback_only(row):
        if not is_code(row):
            return False
        ref = row["evidence"]
        matches = units_by_location[(ref["source_id"], _canonical(ref["location"]))]
        return bool(matches) and all(units[uid]["decoding"] == "original_fallback" for uid in matches)

    _require(Counter(_canonical(row) for row in references if fallback_only(row)) ==
             Counter(_canonical(row) for row in ledger["dependencies_and_links"] if fallback_only(row)))
    for row in references:
        _keys(row, "source_object_id kind code evidence reason next_action")
        _require(row["source_object_id"] in objects and row["source_object_id"] == row["evidence"]["source_id"]
                 and row["code"] == "dependency_not_implemented")
        if not is_code(row):
            continue
        ref = row["evidence"]
        _keys(ref, "source_id kind name evidence confidence location")
        _require(ref["kind"] in {"database_object", "routine"} and ref["confidence"] == "candidate")
        _text(ref["name"], 256)
        _text(row["reason"])
        _text(row["next_action"])
        _keys(ref["location"], "path line column byte_offset")
        matches = units_by_location[(ref["source_id"], _canonical(ref["location"]))]
        _require(bool(matches))
        if not any(units[uid]["decoding"] == "decoded" for uid in matches):
            _require(_canonical(row) in original_code)
    return references


def _validate_retained(report, ledger, gap_report, catalog, *, dependency_evidence=None):
    """Structural cross-check only; requires outer immutable artifact/SHA gate.

    This path deliberately does not run today's parser, registry, generator or
    templates over historical artifacts. It cannot authenticate a caller-written
    ledger/report pair. The retained package and report bytes MUST already have
    passed the owning package verifier's authenticated immutable-artifact gate.
    """
    _keys(report, "schema_version scope source_binding summary units dependencies runtime_verified business_behavior_accepted")
    _require(type(report["schema_version"]) is int and report["schema_version"] == 1 and report["scope"] == SCOPE)
    _require(report["runtime_verified"] is False and report["business_behavior_accepted"] is False)
    _require(report["source_binding"] == ledger["source_binding"] == gap_report["source_binding"])
    _require(ledger["scope"] == "fox-xml-source-to-target-v1" and gap_report["scope"] == "fox-source-mapping-gaps-v1")
    _require(type(report["source_binding"]) is str and re.fullmatch(r"[0-9a-f]{64}", report["source_binding"]) is not None)
    _require(ledger["runtime_verified"] is False and ledger["business_behavior_accepted"] is False)
    _require(catalog["catalog_sha256"] == ledger["catalog_sha256"] == hashlib.sha256(_canonical(
        {k: v for k, v in catalog.items() if k != "catalog_sha256"})).hexdigest())
    rules = _unique(catalog["rules"], "id")
    objects = _unique(ledger["objects"], "source_object_id")
    coverage = _unique(ledger["code_units"], "source_unit_id")
    gaps = _unique(gap_report["gaps"], "source_unit_id")
    units = _unique(report["units"], "source_unit_id")
    _require(len(units) <= 240000 and set(units) == set(coverage))
    _require(set(gaps) == {uid for uid, row in coverage.items() if row["status"] != "generated_wired_adapted"})
    _require(gap_report["dependency_candidates_are_confirmed_missing_inputs"] is False)
    _require(type(gap_report["not_yet_converted"]) is int and gap_report["not_yet_converted"] == len(gaps))
    _require(gap_report["summary"] == {kind: sum(g["category"] == kind for g in gaps.values())
             for kind in ("engine_mapping", "engine_context", "missing_source", "review_required")})
    by_owner = defaultdict(list)
    for uid, unit in units.items():
        _keys(unit, "source_unit_id source_unit_sha256 source_name source_file source_line status message next_action")
        row = coverage[uid]
        owner = objects[row["source_owner_id"]]
        _require(unit["source_unit_sha256"] == row["source_unit_sha256"])
        _require(re.fullmatch(r"[0-9a-f]{64}", unit["source_unit_sha256"]) is not None)
        _require(unit["source_file"] == row["source_file"]["name"] == owner["source_file"]["name"])
        _require(type(unit["source_line"]) is int and unit["source_line"] > 0
                 and unit["source_line"] == row["source_location"]["line"])
        _require(row["source_file"] == owner["source_file"] and row["runtime_verified"] is False
                 and row["business_accepted"] is False)
        rule = rules[row["rule_id"]]
        _require(row["rule_revision"] == rule["revision"])
        _require(row["status"] in {"generated_wired_adapted", "unsupported", "missing_input", "not_selected"}
                 and row.get("encoding_status") in {None, "generated_unwired"})
        expected_status = ("generated" if row["status"] == "generated_wired_adapted" else
                           "encoded_unwired" if row.get("encoding_status") == "generated_unwired" else "unimplemented")
        _require(unit["status"] == expected_status)
        _require(not (expected_status == "generated" and row.get("encoding_status")))
        _require(unit["source_name"] == (owner["source_metadata"].get("Name") or owner["kind"]))
        for key in ("source_name", "source_file", "message", "next_action"):
            _text(unit[key], 4000 if key in {"message", "next_action"} else 256)
        if expected_status != "generated":
            gap = gaps[uid]
            _require(all(unit[key] == gap[key] for key in ("source_name", "source_file", "source_line", "next_action")))
            _require(unit["message"] == gap["message"] + (
                " " + rule["adaptations"] if expected_status == "encoded_unwired" else ""))
        else:
            _require(rule["adaptations"] in unit["message"])
        by_owner[row["source_owner_id"]].append((uid, row))

    module_rows = defaultdict(list)
    module_cache = {}
    for obj in objects.values():
        if obj["kind"] in {"FormModule", "MenuModule", "ObjectLibrary"}:
            module_rows[obj["source_file"]["sha256"]].append(obj)

    def module_identity(owner_id):
        if owner_id in module_cache:
            return module_cache[owner_id]
        owner = objects[owner_id]
        path = owner["location"]["path"]
        modules = [obj for obj in module_rows[owner["source_file"]["sha256"]]
                   if obj["source_file"] == owner["source_file"]
                   and (path == obj["location"]["path"] or path.startswith(obj["location"]["path"] + "/"))]
        _require(bool(modules))
        identity = max(modules, key=lambda obj: len(obj["location"]["path"]))["source_object_id"]
        module_cache[owner_id] = identity
        return identity

    local_definitions = defaultdict(list)
    for oid, obj in objects.items():
        if obj["kind"] == "ProgramUnit":
            local_definitions[(module_identity(oid), (obj["source_metadata"].get("Name") or "").upper())].append(oid)

    dependency_references = (ledger["dependencies_and_links"] if dependency_evidence is None else
                             _retained_dependency_references(dependency_evidence, ledger, coverage, objects))
    expected_refs = Counter()
    for row in dependency_references:
        ref = row["evidence"]
        _require(row["code"] == "dependency_not_implemented" and row["source_object_id"] == ref["source_id"])
        owner = objects[ref["source_id"]]
        collection = row["kind"]
        _require(collection in {"dependencies", "links"})
        name = ref["target_name"] if collection == "links" else ref["name"]
        original_kind = "source_link" if collection == "links" else ref["kind"]
        if original_kind not in {"database_object", "routine", "report"}:
            original_kind = "source_link"
        # The ledger omits source_attribute. Its source_location binds the
        # occurrence; permitted unit IDs are checked below rather than invented.
        expected_refs[(original_kind, name.upper(), ref["source_id"], owner["source_file"]["name"], ref["location"]["line"])] += 1
    actual_refs, group_keys, group_ids = Counter(), set(), set()
    _require(type(report["dependencies"]) is list and len(report["dependencies"]) <= 80000)
    for group in report["dependencies"]:
        _keys(group, "id kind name status message next_action occurrences")
        _require(type(group["id"]) is str and re.fullmatch(r"fd1-[0-9a-f]{24}", group["id"]) is not None
                 and group["id"] not in group_ids)
        group_ids.add(group["id"])
        kind = group["kind"]
        _require(kind in {"database_object", "routine_reference", "forms_api", "local_routine", "report", "source_link"})
        _require(group["status"] in ({"unverified", "source_definition_present"} if kind == "local_routine" else {"unverified"}))
        for key in ("name", "message", "next_action"):
            _text(group[key], 256 if key == "name" else 4000)
        _require(type(group["occurrences"]) is list and bool(group["occurrences"]))
        modules = set()
        for occurrence in group["occurrences"]:
            _keys(occurrence, "source_object_id source_file source_line source_unit_ids")
            owner_id = occurrence["source_object_id"]
            owner = objects[owner_id]
            modules.add(module_identity(owner_id))
            _require(occurrence["source_file"] == owner["source_file"]["name"])
            _require(type(occurrence["source_line"]) is int and occurrence["source_line"] > 0)
            ids = occurrence["source_unit_ids"]
            _require(type(ids) is list and len(set(ids)) == len(ids) and set(ids) <= set(units))
            _require(all(coverage[uid]["source_owner_id"] == owner_id and
                         coverage[uid]["source_location"]["line"] == occurrence["source_line"] for uid in ids))
            original_kind = "routine" if kind in {"routine_reference", "forms_api", "local_routine"} else kind
            actual_refs[(original_kind, group["name"].upper(), owner_id, occurrence["source_file"], occurrence["source_line"])] += 1
        _require(len(modules) == 1)
        key = (next(iter(modules)), kind, group["name"].upper())
        _require(group["id"] == "fd1-" + hashlib.sha256(_canonical(key)).hexdigest()[:24])
        _require(key not in group_keys)
        group_keys.add(key)
        if kind == "local_routine":
            definitions = local_definitions[(key[0], group["name"].upper())]
            _require(len(definitions) == 1)
            if group["status"] == "source_definition_present":
                _require(bool(by_owner[definitions[0]]))
    _require(expected_refs == actual_refs)
    counts = Counter(unit["status"] for unit in units.values())
    expected_summary = {"total_units": len(units), "generated_units": counts["generated"],
        "encoded_unwired_units": counts["encoded_unwired"], "unimplemented_units": counts["unimplemented"],
        "dependency_groups": len(group_ids), "dependency_references": sum(actual_refs.values())}
    _require(type(report["summary"]) is dict and all(type(v) is int for v in report["summary"].values())
             and report["summary"] == expected_summary)


def validate_discrepancies(report, ledger, gap_report, catalog, *, packet=None, chunks=None, dependency_evidence=None):
    """Defensively validate against a fresh packet and independently checked proof.

    With packet=None this performs only structural and ledger/catalog crosschecks
    on an already authenticated immutable artifact. It preserves historical labels
    and classification without running today's parser/generator. With a fresh
    packet it also requires exact reconstruction. Both require the normal owning
    package/source/renderer proof gates; consistent caller-written JSON is no proof.
    """
    try:
        _validate_retained(report, ledger, gap_report, catalog, dependency_evidence=dependency_evidence)
        if packet is not None:
            expected = build_discrepancies(packet, ledger, gap_report, catalog, chunks=chunks, dependency_evidence=dependency_evidence)
            _require(_canonical(report) == _canonical(expected))
    except (KeyError, TypeError, AttributeError, OverflowError) as exc:
        raise ValueError("Invalid discrepancy report.") from exc
    return deepcopy(report)
