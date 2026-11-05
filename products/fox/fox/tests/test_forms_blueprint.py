"""Synthetic source-bound design tests. No model, database or code execution."""
from copy import deepcopy
import hashlib
import json

import pytest

from fox.forms_blueprint import evidence_reference_id, validate_blueprint
from fox.forms_understanding_packet import approved_packet, local_packet


def synthetic_xml(blocks=2, *, duplicate_names=False, unknown=False, items=None, triggers=None):
    items = blocks * 2 if items is None else items
    triggers = blocks if triggers is None else triggers
    parts = ['<FormModule Name="SYNTHETIC"><Canvas Name="MAIN"/><Window Name="WIN"/>']
    for block in range(blocks):
        name = "DUPLICATE" if duplicate_names else f"B{block}"
        flag = "" if unknown else f' DatabaseBlock="{"true" if block % 2 else "false"}"'
        parts.append(f'<Block Name="{name}"{flag} QueryDataSourceName="APP.T{block}">')
        for _item in range(items // blocks + (block < items % blocks)):
            parts.append('<Item Name="ID" DatabaseItem="true" ItemType="Text Item" CanvasName="MAIN"/>')
        for _trigger in range(triggers // blocks + (block < triggers % blocks)):
            parts.append('<Trigger Name="SAVE" TriggerText="BEGIN CUSTOM_API.SAVE; END;"/>')
        parts.append('</Block>')
    parts.append('<ProgramUnit Name="UTIL" ProgramUnitText="BEGIN NULL; END;"/></FormModule>')
    return "".join(parts).encode()


def design(packet, *, propose=False):
    objects = [row for entry in packet["sources"] for row in entry["facts"]["objects"]]
    rows = []
    for source in objects:
        row = {"source_object_id": source["id"], "disposition": "unresolved", "reason": "Review business meaning."}
        if propose and source["kind"] in {"Block", "Item"}:
            row.update(disposition="proposed", reason="Prototype design only.", screen_id="screen-main")
            if source["kind"] == "Block":
                row["native_component"] = "form" if source["classification"] == "database" else "page-items"
        rows.append(row)
    return {"schema_version": 1, "scope": "fox-forms-blueprint-v1", "source_binding": packet["source_binding"],
            "objects": rows, "screens": [{"id": "screen-main", "title": "Review prototype"}] if propose else [],
            "claims": [], "relationships": [], "actions": [], "questions": [], "assumptions": []}


def setup(*, blocks=2, propose=False, **kwargs):
    packet = local_packet([("synthetic.xml", synthetic_xml(blocks, **kwargs))])
    return packet, design(packet, propose=propose)


def claim(packet, *, owner=None, kind="object.name", value=None, ref=None, status="source_fact", id="claim-1"):
    source = packet["sources"][0]["facts"]["objects"][0]
    return {"id": id, "source_object_id": owner or source["id"], "kind": kind,
            "value": source["name"] if value is None else value, "status": status,
            "evidence_refs": [ref or source["id"]], "reason": "Exact extracted observation, not runtime verification."}


@pytest.mark.parametrize("blocks,items,triggers", [(9, 222, 54), (51, 414, 95)])
def test_full_broad_inventory_is_accounted_without_generation_claim(blocks, items, triggers):
    packet, blueprint = setup(blocks=blocks, propose=True, items=items, triggers=triggers)
    before = deepcopy((packet, blueprint))
    summary = validate_blueprint(packet, blueprint)
    assert summary["structured_blueprint_valid"] is True
    assert summary["source_blocks"] == blocks
    assert summary["source_objects"] == blocks + items + triggers + 4
    assert summary["accounted_objects"] == summary["source_objects"]
    assert summary["proposed_objects"] == blocks + items
    assert summary["unresolved_objects"] == triggers + 4
    assert all(summary[key] is False for key in ("generation_ready", "native_apex_generated", "native_apex_validity_verified", "import_verified", "business_behavior_accepted"))
    assert summary["evidence_level"] == "structured-source-bound-design-only"
    assert (packet, blueprint) == before


def test_all_unresolved_is_a_valid_design_not_generation_ready():
    packet, blueprint = setup(unknown=True)
    summary = validate_blueprint(packet, blueprint)
    assert summary["unresolved_objects"] == summary["source_objects"]
    assert summary["proposed_objects"] == 0
    assert summary["generation_ready"] is False


def test_full_megabyte_local_inventory_is_valid_without_transfer_or_silent_omission():
    packet, blueprint = setup(blocks=51, items=1600, triggers=100)
    assert len(json.dumps(packet).encode("utf-8")) > 1_000_000
    summary = validate_blueprint(packet, blueprint)
    assert summary["source_blocks"] == 51
    assert summary["source_objects"] == 1755
    assert summary["unresolved_objects"] == 1755
    assert packet["transfer_authorized"] is False
    assert summary["generation_ready"] is False


@pytest.mark.parametrize("kind", ["Trigger", "ProgramUnit", "Canvas", "FormModule", "Item", "Block"])
def test_every_object_kind_requires_explicit_disposition(kind):
    packet, blueprint = setup()
    ref = next(row["id"] for row in packet["sources"][0]["facts"]["objects"] if row["kind"] == kind)
    blueprint["objects"] = [row for row in blueprint["objects"] if row["source_object_id"] != ref]
    with pytest.raises(ValueError, match="Every source object"):
        validate_blueprint(packet, blueprint)


@pytest.mark.parametrize("mutation", ["unknown", "duplicate"])
def test_unknown_and_duplicate_dispositions_rejected(mutation):
    packet, blueprint = setup()
    if mutation == "unknown":
        blueprint["objects"][0]["source_object_id"] = "invented-source"
    else:
        blueprint["objects"].append(deepcopy(blueprint["objects"][0]))
    with pytest.raises(ValueError, match="unknown or duplicate"):
        validate_blueprint(packet, blueprint)


@pytest.mark.parametrize("classification,component", [("control", "form"), ("database", "page-items"), ("control", "interactive-grid")])
def test_control_and_database_mappings_cannot_be_mixed(classification, component):
    packet, blueprint = setup(propose=True)
    ref = next(row["id"] for row in packet["sources"][0]["facts"]["blocks"] if row["classification"] == classification)
    next(row for row in blueprint["objects"] if row["source_object_id"] == ref)["native_component"] = component
    with pytest.raises(ValueError, match="classification"):
        validate_blueprint(packet, blueprint)


@pytest.mark.parametrize("component", ["form", "report", "interactive-grid", "page-items"])
def test_unknown_block_is_not_silently_treated_as_known(component):
    packet, blueprint = setup(unknown=True)
    block = packet["sources"][0]["facts"]["blocks"][0]
    blueprint["screens"] = [{"id": "s", "title": "Proposal"}]
    row = next(row for row in blueprint["objects"] if row["source_object_id"] == block["id"])
    row.update(disposition="proposed", screen_id="s", native_component=component)
    with pytest.raises(ValueError, match="classification"):
        validate_blueprint(packet, blueprint)


@pytest.mark.parametrize("breakage", ["screen", "unresolved-block", "omitted-block"])
def test_proposed_item_stays_with_its_source_block_and_screen(breakage):
    packet, blueprint = setup(propose=True)
    item = packet["sources"][0]["facts"]["items"][0]
    row = next(row for row in blueprint["objects"] if row["source_object_id"] == item["id"])
    if breakage == "screen":
        blueprint["screens"].append({"id": "other-screen", "title": "Other"})
        row["screen_id"] = "other-screen"
    else:
        block = next(row for row in blueprint["objects"] if row["source_object_id"] == item["block_id"])
        block["disposition"] = "unresolved" if breakage == "unresolved-block" else "omitted"
        block.pop("screen_id")
        block.pop("native_component")
    with pytest.raises(ValueError, match="source block and target screen"):
        validate_blueprint(packet, blueprint)


def test_exact_object_code_dependency_and_link_metadata_are_source_facts():
    packet, blueprint = setup()
    facts = packet["sources"][0]["facts"]
    unit = facts["code_units"][0]
    dependency, link = facts["dependencies"][0], facts["links"][0]
    source_sha = facts["source"]["sha256"]
    blueprint["claims"] = [claim(packet),
        claim(packet, id="c2", owner=unit["owner_id"], kind="code.sha256", value=unit["sha256"], ref=unit["id"]),
        claim(packet, id="c3", owner=dependency["source_id"], kind="dependency.candidate_name", value=dependency["name"], ref=evidence_reference_id(source_sha, "dependency", dependency)),
        claim(packet, id="c4", owner=link["source_id"], kind="link.status", value=link["status"], ref=evidence_reference_id(source_sha, "link", link))]
    blueprint["relationships"] = [{"id": "rel-1", "claim_ids": ["c4"]}]
    blueprint["actions"] = [{"id": "action-1", "claim_ids": ["c2", "c3"]}]
    blueprint["questions"] = [{"id": "q1", "source_object_id": unit["owner_id"], "text": "What is the transaction boundary?"}]
    blueprint["assumptions"] = [{"id": "a1", "text": "Review a prototype first.", "scope": "prototype-only"}]
    assert validate_blueprint(packet, blueprint)["source_fact_claims"] == 4


@pytest.mark.parametrize("kind,value", [("table.exists", "APP.T0"), ("table", "APP.T0"), ("primary_key", "ID"),
                                        ("object.name", "INVENTED"), ("dependency.exists", True)])
def test_unproven_schema_or_interpretation_cannot_become_source_fact(kind, value):
    packet, blueprint = setup()
    blueprint["claims"] = [claim(packet, kind=kind, value=value)]
    with pytest.raises(ValueError, match="whitelisted"):
        validate_blueprint(packet, blueprint)


def test_candidate_name_does_not_prove_a_database_object_exists():
    packet, blueprint = setup()
    facts = packet["sources"][0]["facts"]
    dep = facts["dependencies"][0]
    ref = evidence_reference_id(facts["source"]["sha256"], "dependency", dep)
    blueprint["claims"] = [claim(packet, owner=dep["source_id"], kind="database_object.exists", value=True, ref=ref)]
    with pytest.raises(ValueError, match="whitelisted"):
        validate_blueprint(packet, blueprint)
    blueprint["claims"][0]["status"] = "unresolved"
    assert validate_blueprint(packet, blueprint)["source_fact_claims"] == 0


@pytest.mark.parametrize("status", ["proposal", "unresolved"])
def test_interpretation_requires_nonfact_status(status):
    packet, blueprint = setup()
    blueprint["claims"] = [claim(packet, kind="business.purpose", value="Order review", status=status)]
    assert validate_blueprint(packet, blueprint)["structured_blueprint_valid"] is True


@pytest.mark.parametrize("mutation", ["unknown-evidence", "unrelated-evidence", "duplicate-evidence", "wrong-row-evidence", "unknown-claim", "duplicate-claim", "unknown-question", "unknown-screen"])
def test_cross_references_and_unique_ids_are_checked(mutation):
    packet, blueprint = setup(propose=True)
    blueprint["claims"] = [claim(packet)]
    if mutation == "unknown-evidence":
        blueprint["claims"][0]["evidence_refs"] = ["invented"]
    elif mutation == "unrelated-evidence":
        blueprint["claims"][0]["evidence_refs"] = [packet["sources"][0]["facts"]["items"][0]["id"]]
    elif mutation == "duplicate-evidence":
        blueprint["claims"][0]["evidence_refs"] *= 2
    elif mutation == "wrong-row-evidence":
        unit = packet["sources"][0]["facts"]["code_units"][0]
        blueprint["claims"][0].update(source_object_id=unit["owner_id"], kind="object.name", value="SAVE", evidence_refs=[unit["id"]])
    elif mutation == "unknown-claim":
        blueprint["relationships"] = [{"id": "r1", "claim_ids": ["invented"]}]
    elif mutation == "duplicate-claim":
        blueprint["actions"] = [{"id": "claim-1", "claim_ids": ["claim-1"]}]
    elif mutation == "unknown-question":
        blueprint["questions"] = [{"id": "q1", "source_object_id": "invented", "text": "Question?"}]
    else:
        next(row for row in blueprint["objects"] if row["disposition"] == "proposed")["screen_id"] = "invented"
    with pytest.raises(ValueError):
        validate_blueprint(packet, blueprint)


def test_duplicate_names_are_accounted_by_identity_not_collapsed():
    packet, blueprint = setup(duplicate_names=True)
    assert len({row["name"] for row in packet["sources"][0]["facts"]["blocks"]}) == 1
    assert validate_blueprint(packet, blueprint)["source_blocks"] == 2
    first, second = packet["sources"][0]["facts"]["items"][:2]
    assert first["name"] == second["name"] and first["id"] != second["id"]


@pytest.mark.parametrize("mutation", ["blueprint-hash", "packet-hash", "source-hash", "code-hash", "duplicate-source-id", "inventory-drift"])
def test_stale_hashes_and_forged_packet_shapes_fail(mutation):
    packet, blueprint = setup()
    if mutation == "blueprint-hash":
        blueprint["source_binding"] = "0" * 64
    elif mutation == "packet-hash":
        packet["source_binding"] = blueprint["source_binding"] = "0" * 64
    elif mutation == "source-hash":
        packet["sources"][0]["source"]["sha256"] = "0" * 64
    elif mutation == "code-hash":
        packet["sources"][0]["facts"]["code_units"][0]["sha256"] = "0" * 64
    elif mutation == "duplicate-source-id":
        packet["sources"][0]["facts"]["objects"].append(deepcopy(packet["sources"][0]["facts"]["objects"][0]))
    else:
        packet["sources"][0]["facts"]["items"].pop()
    with pytest.raises(ValueError):
        validate_blueprint(packet, blueprint)


@pytest.mark.parametrize("place", ["blueprint", "object", "claim", "screen", "relationship", "action", "question", "assumption", "claim-value", "packet", "facts"])
def test_unknown_executable_fields_and_nested_payloads_fail_closed(place):
    packet, blueprint = setup(propose=True)
    blueprint["claims"] = [claim(packet)]
    blueprint["relationships"] = [{"id": "r1", "claim_ids": ["claim-1"]}]
    blueprint["actions"] = [{"id": "action1", "claim_ids": ["claim-1"]}]
    blueprint["questions"] = [{"id": "q1", "source_object_id": blueprint["objects"][0]["source_object_id"], "text": "Why?"}]
    blueprint["assumptions"] = [{"id": "a1", "scope": "prototype-only", "text": "Prototype."}]
    target = {"blueprint": blueprint, "object": blueprint["objects"][0], "claim": blueprint["claims"][0],
              "screen": blueprint["screens"][0], "relationship": blueprint["relationships"][0],
              "action": blueprint["actions"][0], "question": blueprint["questions"][0],
              "assumption": blueprint["assumptions"][0], "packet": packet, "facts": packet["sources"][0]["facts"]}
    if place == "claim-value":
        blueprint["claims"][0].update(status="proposal", value={"sql": "DROP TABLE SECRET_SENTINEL"})
    else:
        target[place]["sql"] = "DROP TABLE SECRET_SENTINEL"
    with pytest.raises(ValueError) as caught:
        validate_blueprint(packet, blueprint)
    assert "SECRET_SENTINEL" not in str(caught.value) and len(str(caught.value)) < 200


def test_minimal_packet_and_selected_packet_use_same_full_binding():
    raw = synthetic_xml()
    packet = local_packet([("synthetic.xml", raw)])
    blueprint = design(packet)
    minimal = {key: packet[key] for key in ("schema_version", "scope", "source_binding", "sources")}
    assert validate_blueprint(minimal, blueprint)["structured_blueprint_valid"] is True
    chunk = packet["chunks"][0]
    selected = approved_packet([("synthetic.xml", raw)], expected_source_binding=packet["source_binding"],
                               approved_chunk_hashes={chunk["id"]: chunk["sha256"]})
    assert validate_blueprint(selected, blueprint)["source_binding"] == packet["source_binding"]
    selected["chunks"][0]["text"] += " altered"
    with pytest.raises(ValueError, match="exact source-unit hash"):
        validate_blueprint(selected, blueprint)


def test_multiple_files_same_module_names_keep_source_identities():
    packet = local_packet([("first.xml", synthetic_xml(1)), ("second.xml", synthetic_xml(2))])
    blueprint = design(packet)
    assert validate_blueprint(packet, blueprint)["source_blocks"] == 3


def test_exact_occurrence_reference_id_algorithm_is_stable():
    packet, _blueprint = setup()
    facts = packet["sources"][0]["facts"]
    row = facts["dependencies"][0]
    encoded = json.dumps([facts["source"]["sha256"], "dependency", row], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    assert evidence_reference_id(facts["source"]["sha256"], "dependency", row) == "ffdep1-" + hashlib.sha256(encoded).hexdigest()[:24]


@pytest.mark.parametrize("bad", [None, [], {"source_binding": b"raw"}, {"schema_version": True}, {"source_binding": float("nan")}])
def test_bad_input_is_always_a_safe_value_error(bad):
    packet, blueprint = setup()
    with pytest.raises(ValueError) as caught:
        validate_blueprint(bad, blueprint)
    assert len(str(caught.value)) < 200


def test_circular_and_deep_documents_are_bounded():
    packet, blueprint = setup()
    blueprint["loop"] = blueprint
    with pytest.raises(ValueError, match="bounded"):
        validate_blueprint(packet, blueprint)


def test_lengths_and_unbounded_arrays_are_rejected():
    packet, blueprint = setup()
    blueprint["questions"] = [None] * 60_001
    with pytest.raises(ValueError):
        validate_blueprint(packet, blueprint)
    blueprint = design(packet)
    blueprint["objects"][0]["reason"] = "x" * 2001
    with pytest.raises(ValueError):
        validate_blueprint(packet, blueprint)
