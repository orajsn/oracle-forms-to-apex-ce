"""Pure focused-design merge against fresh retained Forms originals.

Focus bindings identify requests; they never authenticate caller-supplied facts.
The complete plan is reconstructed before any response is trusted. Successful
merging establishes structured source-bound design only, not code translation,
generation, external-processing authorization or human acceptance.
"""
from __future__ import annotations

from copy import deepcopy

from .forms_blueprint import (
    BLUEPRINT_SCOPE, _bounded_json, _canonical, evidence_reference_id,
    validate_blueprint,
)
from .forms_focus import build_focus_plan
from .forms_understanding_packet import local_packet

_ARRAYS = ("screens", "claims", "relationships", "actions", "questions", "assumptions")
_BLUEPRINT_KEYS = {"schema_version", "scope", "source_binding", "objects", *_ARRAYS}


def _fail(message="Invalid source-bound focus merge structure."):
    # Never echo source text or caller-authored values into failures.
    raise ValueError(message)


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        _fail()


def _rows(value):
    if type(value) is not list:
        _fail()
    return value


def merge_focus_blueprints(documents: list[tuple[str, bytes]], plan: dict,
                           responses: list[dict]) -> dict:
    """Merge exactly one independently owned response for every fresh focus.

    Arrays are concatenated in deterministic plan order, never last-wins or
    auto-renamed. References across responses are resolved by the full existing
    blueprint validator. Inputs remain unchanged; no partial output is returned.
    """
    try:
        return _merge(documents, plan, responses)
    except (TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError):
        _fail()


def _merge(documents, plan, responses):
    _bounded_json(plan)
    _bounded_json(responses)
    if type(plan) is not dict:
        _fail()
    # These values select the deterministic reconstruction; no request objects,
    # source metadata, identities or hashes are copied from the untrusted plan.
    rebuilt = build_focus_plan(
        documents, expected_source_binding=plan["source_binding"],
        approved_chunk_hashes=plan["selected_chunk_hashes"],
        max_owned_objects=plan["max_owned_objects"],
    )
    if _canonical(plan) != _canonical(rebuilt):
        _fail("Focus plan does not match its fresh original-source reconstruction.")
    packet = local_packet(documents)
    requests = {request["focus_id"]: request for request in rebuilt["requests"]}
    indexed = {}
    for response in _rows(responses):
        _keys(response, {"focus_id", "focus_binding", "blueprint"})
        focus_id = response["focus_id"]
        if type(focus_id) is not str or focus_id not in requests:
            _fail("Focus response is unknown or stale for the original-source plan.")
        if focus_id in indexed:
            _fail("Every planned focus requires exactly one response; duplicates are forbidden.")
        if response["focus_binding"] != requests[focus_id]["focus_binding"]:
            _fail("Focus response binding is stale or does not match its planned request.")
        indexed[focus_id] = response
    if indexed.keys() != requests.keys():
        _fail("Every planned focus requires exactly one response; missing focuses are forbidden.")

    merged = {"schema_version": 1, "scope": BLUEPRINT_SCOPE,
              "source_binding": packet["source_binding"], "objects": [],
              **{key: [] for key in _ARRAYS}}
    source_hashes = {row["id"]: entry["source"]["sha256"]
                     for entry in packet["sources"] for row in entry["facts"]["objects"]}
    seen_ids = set()
    for request in rebuilt["requests"]:
        blueprint = indexed[request["focus_id"]]["blueprint"]
        _keys(blueprint, _BLUEPRINT_KEYS)
        if (type(blueprint["schema_version"]) is not int or blueprint["schema_version"] != 1
                or blueprint["scope"] != BLUEPRINT_SCOPE
                or blueprint["source_binding"] != packet["source_binding"]):
            _fail("Focus blueprint is stale or not bound to the complete original inventory.")
        owned = {row["id"] for row in request["owned_objects"]}
        dispositions = set()
        for row in _rows(blueprint["objects"]):
            if type(row) is not dict:
                _fail()
            ref = row.get("source_object_id")
            if type(ref) is not str or ref not in owned or ref in dispositions:
                _fail("A focus must account for its own source objects only, exactly once.")
            dispositions.add(ref)
        if dispositions != owned:
            _fail("A focus must account for every owned source object exactly once.")
        merged["objects"].extend(deepcopy(blueprint["objects"]))

        # Source metadata may support evidence, but cannot transfer ownership of
        # another focus's claims, questions or dispositions into this response.
        evidence = {row["id"] for row in request["owned_objects"] + request["context_objects"]}
        evidence.update(row["id"] for row in request["code_units"])
        for category, collection in (("link", "links"), ("dependency", "dependencies")):
            evidence.update(evidence_reference_id(source_hashes[row["source_id"]], category, row)
                            for row in request[collection])
        for claim in _rows(blueprint["claims"]):
            if (type(claim) is not dict or claim.get("source_object_id") not in owned
                    or type(claim.get("evidence_refs")) is not list
                    or any(type(ref) is not str or ref not in evidence for ref in claim["evidence_refs"])):
                _fail("Focus claims must retain owned source objects and exact planned evidence.")
        for question in _rows(blueprint["questions"]):
            if type(question) is not dict or question.get("source_object_id") not in owned:
                _fail("Focus questions must refer to owned source objects only.")
        for key in _ARRAYS:
            for row in _rows(blueprint[key]):
                if type(row) is not dict or type(row.get("id")) is not str:
                    _fail()
                if row["id"] in seen_ids:
                    _fail("Focused blueprint arrays contain duplicate or colliding identifiers.")
                seen_ids.add(row["id"])
                merged[key].append(deepcopy(row))

    # Validate all dispositions and cross-focus design/evidence references in one
    # complete inventory; incomplete focus blueprints are not standalone packets.
    validation = validate_blueprint(packet, merged)
    objects = {row["id"]: row for entry in packet["sources"] for row in entry["facts"]["objects"]}
    dispositions = {row["source_object_id"]: row["disposition"] for row in merged["objects"]}
    supplied = {chunk["code_unit_id"] for request in rebuilt["requests"] for chunk in request["chunks"]}
    units = [unit for entry in packet["sources"] for unit in entry["facts"]["code_units"]]
    units_by_owner = {}
    for unit in units:
        units_by_owner.setdefault(unit["owner_id"], set()).add(unit["id"])
    for ref, disposition in dispositions.items():
        if disposition != "proposed":
            continue
        if objects[ref]["kind"] in {"Trigger", "ProgramUnit"}:
            owner_units = units_by_owner.get(ref, set())
            if not owner_units or not owner_units <= supplied:
                _fail("A proposed trigger or program unit requires its exact complete source code to be supplied.")
        ancestor = objects[ref]["parent_id"]
        while ancestor is not None:
            source = objects[ancestor]
            if source["kind"] in {"Block", "FormModule"} and dispositions[ancestor] == "omitted":
                _fail("A proposed source object cannot descend from an omitted source block or form module.")
            ancestor = source["parent_id"]
    # Content supplied is not behavior understood, translated or accepted. Keep
    # every unsupplied unit explicit without inventing dispositions or claims.
    validation["supplied_code_unit_ids"] = [unit["id"] for unit in units if unit["id"] in supplied]
    validation["code_units_not_supplied"] = [unit["id"] for unit in units if unit["id"] not in supplied]
    return {"blueprint": merged, "validation": validation}
