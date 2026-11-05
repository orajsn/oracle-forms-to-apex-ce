"""Authored synthetic focused designs, not model/Oracle conversion evidence."""
from copy import deepcopy
import hashlib
import json

import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_focus_merge import merge_focus_blueprints
from fox.forms_understanding_packet import local_packet


def xml(blocks=2, *, module="SYNTHETIC", items=2):
    parts = [f'<FormModule Name="{module}"><Canvas Name="MAIN"/><Window Name="WIN"/>']
    for index in range(blocks):
        parts.append(f'<Block Name="B{index}" DatabaseBlock="true" QueryDataSourceName="APP.T{index}">')
        parts.extend('<Item Name="ID" DatabaseItem="true" ItemType="Text Item" CanvasName="MAIN"/>' for _ in range(items))
        parts.append('<Trigger Name="SAVE" TriggerText="BEGIN CUSTOM_API.SAVE; END;"/></Block>')
    parts.append('<ProgramUnit Name="UTIL" ProgramUnitText="BEGIN NULL; END;"/></FormModule>')
    return "".join(parts).encode()


def setup(*, blocks=2, selected=False, multi=False, max_owned_objects=250, items=2, raw=None):
    documents = [("first.xml", xml(blocks, items=items) if raw is None else raw)]
    if multi:
        documents.append(("second.xml", xml(1, module="SECOND")))
    packet = local_packet(documents)
    mapping = {chunk["id"]: chunk["sha256"] for chunk in packet["chunks"]} if selected else {}
    plan = build_focus_plan(documents, expected_source_binding=packet["source_binding"],
                            approved_chunk_hashes=mapping, max_owned_objects=max_owned_objects)
    responses = []
    for request in plan["requests"]:
        blueprint = {"schema_version": 1, "scope": "fox-forms-blueprint-v1", "source_binding": plan["source_binding"],
                     "objects": [{"source_object_id": row["id"], "disposition": "unresolved",
                                  "reason": "Authored fixture; business meaning still needs review."}
                                 for row in request["owned_objects"]],
                     **{key: [] for key in ("screens", "claims", "relationships", "actions", "questions", "assumptions")}}
        responses.append({"focus_id": request["focus_id"], "focus_binding": request["focus_binding"], "blueprint": blueprint})
    return documents, packet, plan, responses


def owner(plan, responses, kind, *, index=0):
    matches = [(request, response, source) for request, response in zip(plan["requests"], responses, strict=True)
               for source in request["owned_objects"] if source["kind"] == kind]
    request, response, source = matches[index]
    row = next(row for row in response["blueprint"]["objects"] if row["source_object_id"] == source["id"])
    return request, response, source, row


def propose(plan, responses, kind, *, index=0, screen=None):
    request, response, source, row = owner(plan, responses, kind, index=index)
    screen = screen or "screen-" + request["focus_id"]
    if not any(item["id"] == screen for item in response["blueprint"]["screens"]):
        response["blueprint"]["screens"].append({"id": screen, "title": "Authored prototype proposal"})
    row.update(disposition="proposed", screen_id=screen)
    if kind == "Block":
        row["native_component"] = "form"
    return request, response, source, row


def claim(source, *, id="claim-1", refs=None, kind="object.name", value=None, status="source_fact"):
    return {"id": id, "source_object_id": source["id"], "kind": kind,
            "value": source["name"] if value is None else value, "status": status,
            "evidence_refs": refs or [source["id"]], "reason": "Authored source observation, not verified behavior."}


@pytest.mark.parametrize("blocks,multi", [(9, False), (51, False), (9, True)])
def test_complete_inventory_and_unselected_code_remain_explicit_without_generation(blocks, multi):
    documents, packet, plan, responses = setup(blocks=blocks, multi=multi)
    before = deepcopy((documents, plan, responses))
    result = merge_focus_blueprints(documents, plan, list(reversed(responses)))
    summary = result["validation"]
    count = sum(len(entry["facts"]["objects"]) for entry in packet["sources"])
    assert summary["source_objects"] == summary["accounted_objects"] == count == plan["total_source_objects"]
    assert summary["unresolved_objects"] == count
    assert summary["source_blocks"] == blocks + int(multi)
    assert summary["supplied_code_unit_ids"] == []
    assert summary["code_units_not_supplied"] == [row["id"] for entry in packet["sources"] for row in entry["facts"]["code_units"]]
    assert summary["structured_blueprint_valid"] is True
    assert all(summary[key] is False for key in ("generation_ready", "native_apex_generated", "native_apex_validity_verified", "import_verified", "business_behavior_accepted"))
    assert (documents, plan, responses) == before
    assert result == merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("failure", ["dropped", "duplicate", "unknown", "stale-binding", "stale-blueprint"])
def test_response_set_is_exact_and_current(failure):
    documents, _packet, plan, responses = setup()
    if failure == "dropped":
        responses.pop()
    elif failure == "duplicate":
        responses.append(deepcopy(responses[0]))
    elif failure == "unknown":
        responses[0]["focus_id"] = "focus-invented"
    elif failure == "stale-binding":
        responses[0]["focus_binding"] = "0" * 64
    else:
        responses[0]["blueprint"]["source_binding"] = "0" * 64
    with pytest.raises(ValueError):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("failure", ["invented", "context", "duplicate", "dropped"])
def test_dispositions_belong_only_to_owned_objects(failure):
    documents, _packet, plan, responses = setup()
    request, response, _source, row = owner(plan, responses, "Block")
    if failure == "invented":
        row["source_object_id"] = "invented-owned-id"
    elif failure == "context":
        row["source_object_id"] = request["context_objects"][0]["id"]
    elif failure == "duplicate":
        response["blueprint"]["objects"].append(deepcopy(row))
    else:
        response["blueprint"]["objects"].remove(row)
    with pytest.raises(ValueError, match="owned|own source"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("failure", ["claim-owner", "question-owner", "evidence"])
def test_context_is_evidence_not_disposition_or_claim_ownership(failure):
    documents, _packet, plan, responses = setup()
    request, response, source, _row = owner(plan, responses, "Block")
    context = request["context_objects"][0]
    if failure == "claim-owner":
        response["blueprint"]["claims"] = [claim(context)]
    elif failure == "question-owner":
        response["blueprint"]["questions"] = [{"id": "q-1", "source_object_id": context["id"], "text": "Review?"}]
    else:
        other = next(source for other in plan["requests"] if other is not request for source in other["owned_objects"]
                     if source["id"] not in {row["id"] for row in request["context_objects"]})
        response["blueprint"]["claims"] = [claim(source, refs=[source["id"], other["id"]], status="proposal")]
    with pytest.raises(ValueError, match="owned|planned evidence"):
        merge_focus_blueprints(documents, plan, responses)


def test_exact_context_evidence_and_cross_focus_claim_references_are_supported():
    documents, _packet, plan, responses = setup()
    first_request, first_response, first_source, _ = owner(plan, responses, "Block", index=0)
    _, second_response, second_source, _ = owner(plan, responses, "Block", index=1)
    first_response["blueprint"]["claims"] = [claim(first_source, id="c-first", status="proposal",
        refs=[first_source["id"], first_request["context_objects"][0]["id"]])]
    second_response["blueprint"]["claims"] = [claim(second_source, id="c-second")]
    first_response["blueprint"]["relationships"] = [{"id": "rel-cross", "claim_ids": ["c-first", "c-second"]}]
    second_response["blueprint"]["actions"] = [{"id": "action-cross", "claim_ids": ["c-first"]}]
    result = merge_focus_blueprints(documents, plan, responses)
    assert result["validation"]["structured_blueprint_valid"] is True
    first_response["blueprint"]["relationships"][0]["claim_ids"].append("invented-claim")
    with pytest.raises(ValueError, match="existing claims"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("array", ["screens", "claims", "relationships", "actions", "questions", "assumptions"])
def test_no_duplicate_ids_even_when_content_is_identical(array):
    documents, _packet, plan, responses = setup()
    _, first, source, _ = owner(plan, responses, "Block")
    _, second, other, _ = owner(plan, responses, "Block", index=1)
    rows = {"screens": {"id": "same-id", "title": "Same"}, "claims": claim(source, id="same-id"),
            "relationships": {"id": "same-id", "claim_ids": ["c1"]}, "actions": {"id": "same-id", "claim_ids": ["c1"]},
            "questions": {"id": "same-id", "source_object_id": source["id"], "text": "Review?"},
            "assumptions": {"id": "same-id", "text": "Prototype", "scope": "prototype-only"}}
    first["blueprint"][array] = [rows[array]]
    second["blueprint"][array] = [deepcopy(rows[array])]
    if array in {"claims", "questions"}:
        second["blueprint"][array][0]["source_object_id"] = other["id"]
        if array == "claims":
            second["blueprint"][array][0]["evidence_refs"] = [other["id"]]
    with pytest.raises(ValueError, match="duplicate or colliding"):
        merge_focus_blueprints(documents, plan, responses)


def test_collisions_across_array_types_and_source_ids_fail_full_validation():
    documents, _packet, plan, responses = setup()
    _, response, source, _ = owner(plan, responses, "Block")
    response["blueprint"]["screens"] = [{"id": source["id"], "title": "Collision"}]
    with pytest.raises(ValueError, match="duplicate or colliding"):
        merge_focus_blueprints(documents, plan, responses)
    response["blueprint"]["screens"] = [{"id": "same-id", "title": "Collision"}]
    response["blueprint"]["assumptions"] = [{"id": "same-id", "text": "Prototype", "scope": "prototype-only"}]
    with pytest.raises(ValueError, match="duplicate or colliding"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("kind", ["Item", "Trigger", "Block", "ProgramUnit", "Canvas"])
def test_omitted_form_module_forbids_every_proposed_descendant(kind):
    documents, _packet, plan, responses = setup(selected=True)
    owner(plan, responses, "FormModule")[3]["disposition"] = "omitted"
    if kind == "Item":
        propose(plan, responses, "Block")
    propose(plan, responses, kind)
    with pytest.raises(ValueError, match="omitted source block or form module"):
        merge_focus_blueprints(documents, plan, responses)


def test_omitted_block_forbids_proposed_trigger_but_not_unrelated_canvas():
    documents, _packet, plan, responses = setup(selected=True)
    owner(plan, responses, "Block")[3]["disposition"] = "omitted"
    propose(plan, responses, "Trigger")
    with pytest.raises(ValueError, match="omitted source block or form module"):
        merge_focus_blueprints(documents, plan, responses)
    trigger = owner(plan, responses, "Trigger")[3]
    trigger.update(disposition="unresolved")
    trigger.pop("screen_id")
    propose(plan, responses, "Canvas")
    assert merge_focus_blueprints(documents, plan, responses)["validation"]["structured_blueprint_valid"] is True


@pytest.mark.parametrize("block_disposition", ["unresolved", "omitted"])
def test_proposed_item_requires_proposed_source_block(block_disposition):
    documents, _packet, plan, responses = setup()
    owner(plan, responses, "Block")[3]["disposition"] = block_disposition
    propose(plan, responses, "Item")
    with pytest.raises(ValueError, match="source block and target screen"):
        merge_focus_blueprints(documents, plan, responses)


def test_unresolved_module_and_unsupplied_block_metadata_do_not_block_ui_proposal():
    documents, _packet, plan, responses = setup()
    propose(plan, responses, "Block")
    propose(plan, responses, "Item")
    result = merge_focus_blueprints(documents, plan, responses)
    assert result["validation"]["proposed_objects"] == 2
    assert result["validation"]["code_units_not_supplied"]
    assert result["validation"]["generation_ready"] is False


@pytest.mark.parametrize("kind", ["Trigger", "ProgramUnit"])
def test_unsupplied_behavior_body_cannot_be_proposed(kind):
    documents, _packet, plan, responses = setup()
    propose(plan, responses, kind)
    with pytest.raises(ValueError, match="exact complete source code"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("kind", ["Trigger", "ProgramUnit"])
def test_behavior_object_without_readable_body_cannot_be_proposed(kind):
    raw = f'<FormModule Name="A"><{kind} Name="T"/></FormModule>'.encode()
    documents, packet, plan, responses = setup(raw=raw)
    assert packet["sources"][0]["facts"]["code_units"] == []
    assert any(row["code"] == "CODE_SOURCE_UNAVAILABLE" for row in packet["sources"][0]["facts"]["findings"])
    propose(plan, responses, kind)
    with pytest.raises(ValueError, match="exact complete source code"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("kind", ["Trigger", "ProgramUnit"])
@pytest.mark.parametrize("disposition", ["omitted", "unresolved"])
def test_behavior_object_without_readable_body_can_remain_explicitly_unmapped(kind, disposition):
    raw = f'<FormModule Name="A"><{kind} Name="T"/></FormModule>'.encode()
    documents, _packet, plan, responses = setup(raw=raw)
    owner(plan, responses, kind)[3]["disposition"] = disposition
    summary = merge_focus_blueprints(documents, plan, responses)["validation"]
    assert summary["structured_blueprint_valid"] is True
    assert summary["proposed_objects"] == 0
    assert summary["supplied_code_unit_ids"] == summary["code_units_not_supplied"] == []
    assert summary["generation_ready"] is False


@pytest.mark.parametrize("kind,attribute", [("Trigger", "TriggerText"), ("ProgramUnit", "ProgramUnitText")])
def test_every_readable_body_of_a_proposed_behavior_owner_must_be_supplied(kind, attribute):
    raw = (f'<FormModule Name="A"><{kind} Name="T" {attribute}="BEGIN NULL; END;">'
           f'BEGIN CUSTOM_API.SAVE; END;</{kind}></FormModule>').encode()
    documents, packet, plan, responses = setup(raw=raw, selected=True)
    units = packet["sources"][0]["facts"]["code_units"]
    assert len(units) == 2 and units[0]["owner_id"] == units[1]["owner_id"]
    propose(plan, responses, kind)
    assert merge_focus_blueprints(documents, plan, responses)["validation"]["proposed_objects"] == 1
    chunk = packet["chunks"][0]
    partial = build_focus_plan(documents, expected_source_binding=packet["source_binding"],
                               approved_chunk_hashes={chunk["id"]: chunk["sha256"]})
    for request, response in zip(partial["requests"], responses, strict=True):
        response["focus_binding"] = request["focus_binding"]
    with pytest.raises(ValueError, match="exact complete source code"):
        merge_focus_blueprints(documents, partial, responses)


@pytest.mark.parametrize("disposition", ["omitted", "unresolved"])
def test_unsupplied_code_can_be_explicitly_omitted_or_unresolved(disposition):
    documents, _packet, plan, responses = setup()
    owner(plan, responses, "Trigger")[3]["disposition"] = disposition
    assert merge_focus_blueprints(documents, plan, responses)["validation"]["code_units_not_supplied"]


def test_supplied_code_is_recorded_without_implying_translation():
    documents, packet, plan, responses = setup(selected=True)
    propose(plan, responses, "Trigger")
    result = merge_focus_blueprints(documents, plan, responses)
    assert result["validation"]["supplied_code_unit_ids"] == [row["id"] for entry in packet["sources"] for row in entry["facts"]["code_units"]]
    assert result["validation"]["code_units_not_supplied"] == []
    assert result["validation"]["generation_ready"] is False


def test_partial_selection_records_every_remaining_code_unit_without_claims():
    documents, packet, _plan, _responses = setup()
    chunk = packet["chunks"][0]
    plan = build_focus_plan(documents, expected_source_binding=packet["source_binding"],
                            approved_chunk_hashes={chunk["id"]: chunk["sha256"]})
    # Content selection does not change ownership or require inventing claims.
    _, _, _, responses = setup()
    for request, response in zip(plan["requests"], responses, strict=True):
        response["focus_binding"] = request["focus_binding"]
    result = merge_focus_blueprints(documents, plan, responses)
    assert result["blueprint"]["claims"] == []
    assert result["validation"]["supplied_code_unit_ids"] == [chunk["code_unit_id"]]
    assert result["validation"]["code_units_not_supplied"] == [row["code_unit_id"] for row in packet["chunks"][1:]]


def test_large_local_inventory_is_merged_without_transfer_cap_or_missing_objects():
    documents, packet, plan, responses = setup(blocks=51, items=32)
    assert len(json.dumps(packet).encode()) > 1_000_000
    result = merge_focus_blueprints(documents, plan, responses)
    assert result["validation"]["source_objects"] == 51 * 34 + 4
    assert result["validation"]["accounted_objects"] == plan["total_source_objects"]
    assert result["validation"]["generation_ready"] is False


def test_code_metadata_claim_requires_exact_owned_unit_fact():
    documents, _packet, plan, responses = setup()
    request, response, source, _row = owner(plan, responses, "Trigger")
    unit = next(unit for unit in request["code_units"] if unit["owner_id"] == source["id"])
    response["blueprint"]["claims"] = [claim(source, kind="code.sha256", value=unit["sha256"], refs=[unit["id"]])]
    assert merge_focus_blueprints(documents, plan, responses)["validation"]["source_fact_claims"] == 1
    response["blueprint"]["claims"][0]["value"] = "0" * 64
    with pytest.raises(ValueError, match="whitelisted"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("mutation", ["owned-name", "dropped-object", "code-text", "unselected", "source-index"])
def test_rehashing_a_forged_plan_does_not_authenticate_it(mutation):
    documents, _packet, plan, responses = setup(selected=True)
    request = plan["requests"][0]
    if mutation == "owned-name":
        request["owned_objects"][0]["name"] = "FORGED"
    elif mutation == "dropped-object":
        request["owned_objects"].pop()
    elif mutation == "code-text":
        request = next(row for row in plan["requests"] if row["chunks"])
        request["chunks"][0]["text"] += " altered"
    elif mutation == "unselected":
        request["unselected_code_unit_ids"].append("invented")
    else:
        request["source_index"][0]["name"] = "forged.xml"
    def binding(row, field):
        payload = {key: value for key, value in row.items() if key != field}
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    request["focus_binding"] = binding(request, "focus_binding")
    plan["plan_binding"] = binding(plan, "plan_binding")
    with pytest.raises(ValueError, match="fresh original-source reconstruction"):
        merge_focus_blueprints(documents, plan, responses)


def test_original_source_change_invalidates_plan_and_responses():
    documents, _packet, plan, responses = setup()
    documents[0] = (documents[0][0], documents[0][1].replace(b"CUSTOM_API.SAVE", b"CUSTOM_API.NEW_SAVE"))
    with pytest.raises(ValueError, match="binding"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("place", ["response", "blueprint", "object", "claim"])
def test_unknown_executable_fields_fail_without_echoing_source_text(place):
    documents, _packet, plan, responses = setup()
    _, response, source, row = owner(plan, responses, "Block")
    response["blueprint"]["claims"] = [claim(source)]
    target = {"response": response, "blueprint": response["blueprint"], "object": row,
              "claim": response["blueprint"]["claims"][0]}[place]
    target["sql"] = "SECRET_SENTINEL"
    with pytest.raises(ValueError) as caught:
        merge_focus_blueprints(documents, plan, responses)
    assert "SECRET_SENTINEL" not in str(caught.value)
    assert len(str(caught.value)) < 200


@pytest.mark.parametrize("value", [None, [], {"source_binding": b"raw"}, {"source_binding": float("nan")}])
def test_malformed_plans_are_safe_value_errors(value):
    documents, _packet, _plan, responses = setup()
    with pytest.raises(ValueError) as caught:
        merge_focus_blueprints(documents, value, responses)
    assert len(str(caught.value)) < 200


def test_circular_response_is_bounded():
    documents, _packet, plan, responses = setup()
    responses[0]["blueprint"]["loop"] = responses
    with pytest.raises(ValueError, match="bounded"):
        merge_focus_blueprints(documents, plan, responses)


@pytest.mark.parametrize("bad", [None, {}, [None], [{"focus_id": []}], ["SECRET_SENTINEL"]])
def test_malformed_responses_fail_safely(bad):
    documents, _packet, plan, _responses = setup()
    with pytest.raises(ValueError) as caught:
        merge_focus_blueprints(documents, plan, bad)
    assert "SECRET_SENTINEL" not in str(caught.value)
    assert len(str(caught.value)) < 200
