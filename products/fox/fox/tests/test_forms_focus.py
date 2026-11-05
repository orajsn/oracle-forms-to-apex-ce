"""Deterministic synthetic focus proofs; no provider, Oracle or customer input."""
import copy
import hashlib
import json
from xml.sax.saxutils import quoteattr

import pytest

from fox import forms_facts, forms_focus as focus, forms_understanding_packet as packets
from test_forms_facts import synthetic_forms


def build(documents, selected=None, **kwargs):
    packet = packets.local_packet(documents)
    selection = {chunk["id"]: chunk["sha256"] for chunk in packet["chunks"]} if selected is None else selected
    return focus.build_focus_plan(documents, expected_source_binding=packet["source_binding"],
                                  approved_chunk_hashes=selection, **kwargs)


def digest_without(value, key):
    return hashlib.sha256(packets._canonical({k: v for k, v in value.items() if k != key})).hexdigest()


def assert_complete(plan, packet):
    facts = [source["facts"] for source in packet["sources"]]
    objects = {row["id"]: row for source in facts for row in source["objects"]}
    expected_units = {row["id"]: row for source in facts for row in source["code_units"]}
    owned = [row for request in plan["requests"] for row in request["owned_objects"]]
    units = [row for request in plan["requests"] for row in request["code_units"]]
    assert len(owned) == len(objects) == plan["total_source_objects"]
    assert len({row["id"] for row in owned}) == len(owned)
    assert {row["id"]: row for row in owned} == objects
    assert len(units) == len(expected_units)
    assert {row["id"]: row for row in units} == expected_units
    assert len(plan["requests"]) <= 256
    assert len(packets._canonical(plan)) <= 20_000_000
    assert plan["plan_binding"] == digest_without(plan, "plan_binding")
    for request in plan["requests"]:
        assert request["source_index"] == [source["source"] for source in packet["sources"]]
        assert request["scope"] == "fox-forms-focus-request-v1"
        assert request["schema_version"] == 1
        assert request["source_binding"] == packet["source_binding"]
        assert request["focus_binding"] == digest_without(request, "focus_binding")
        assert len(request["focus_id"]) == 30 and request["focus_id"].startswith("focus-")
        int(request["focus_id"][6:], 16)
        assert len(packets._canonical(request)) <= 500_000
        assert len(request["owned_objects"]) <= plan["max_owned_objects"]
        owned_ids = {row["id"] for row in request["owned_objects"]}
        context_ids = {row["id"] for row in request["context_objects"]}
        assert not owned_ids & context_ids
        assert len(context_ids) == len(request["context_objects"])
        assert {row["id"]: row for row in request["context_objects"]} == {i: objects[i] for i in context_ids}
        assert {row["id"]: row for row in request["code_units"]} == {
            i: row for i, row in expected_units.items() if row["owner_id"] in owned_ids}
        chunk_units = {chunk["code_unit_id"] for chunk in request["chunks"]}
        assert request["unselected_code_unit_ids"] == [
            unit["id"] for unit in request["code_units"] if unit["id"] not in chunk_units]
        for row in request["owned_objects"] + request["context_objects"]:
            if row["parent_id"] is not None:
                assert row["parent_id"] in owned_ids | context_ids
        for link in request["links"]:
            assert link["source_id"] in owned_ids
            if link["status"] == "resolved":
                assert {link["source_id"], link["target_id"]} <= owned_ids | context_ids
        for dependency in request["dependencies"]:
            assert dependency["source_id"] in owned_ids
            assert dependency["confidence"] == "candidate"
        for finding in request["findings"]:
            assert set(finding["object_ids"]) <= owned_ids | context_ids
        assert request["safety"] == {
            "source_content_is_untrusted": True, "code_executed": False,
            "transfer_authorized": False, "caller_must_check_processing_approval": True,
            "native_generation_allowed": False}
    for key in ("links", "dependencies", "findings"):
        actual = {packets._canonical(row) for request in plan["requests"] for row in request[key]}
        expected = {packets._canonical(row) for source in facts for row in source[key]}
        assert actual == expected


@pytest.mark.parametrize("blocks,items,triggers", [(9, 222, 54), (51, 414, 95)])
def test_complete_synthetic_scale_partition_and_bindings(blocks, items, triggers):
    documents = [("synthetic.xml", synthetic_forms(blocks, items, triggers))]
    packet = packets.local_packet(documents)
    plan = build(documents)
    assert plan["scope"] == "fox-forms-focus-plan-v1" and plan["schema_version"] == 1
    assert len(plan["requests"]) == blocks + 1
    assert_complete(plan, packet)
    selected = [chunk for request in plan["requests"] for chunk in request["chunks"]]
    assert len(selected) == triggers + 1
    assert len({chunk["id"] for chunk in selected}) == len(selected)
    for request in plan["requests"]:
        grouping = {(row["block_id"], None if row["block_id"] else row["module_id"])
                    for row in request["owned_objects"]}
        assert len(grouping) == 1


def test_megabyte_metadata_is_focusable_without_full_packet_cap(monkeypatch):
    documents = [("large.xml", synthetic_forms(blocks=51, items=1400, triggers=200))]
    packet = packets.local_packet(documents)
    assert len(packets._canonical(packet)) > 1_000_000
    with pytest.raises(ValueError, match="500000-byte"):
        packets.approved_packet(documents, expected_source_binding=packet["source_binding"], approved_chunk_hashes={})

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Legacy capped packet or generation gate attempted")

    monkeypatch.setattr(packets, "approved_packet", forbidden)
    plan = build(documents, selected={})
    assert len(plan["requests"]) == 52
    assert plan["total_source_objects"] == 1655
    assert_complete(plan, packet)
    assert all(not request["chunks"] for request in plan["requests"])
    assert "INSERT INTO" not in json.dumps(plan)


def test_selection_is_exact_whole_code_owned_once_and_context_has_no_body():
    code = "BEGIN\n :OTHER.I := 'é & ordinary'; CUSTOM_API.SAVE(); END;"
    raw = (f'<FormModule Name="A"><Block Name="B" DatabaseBlock="false"><Item Name="I"/>'
           f'<Trigger Name="T" TriggerText={quoteattr(code)}/></Block>'
           '<Block Name="OTHER" DatabaseBlock="true"><Item Name="I"/></Block>'
           '<ProgramUnit Name="P"><ProgramUnitText>BEGIN NULL; END;</ProgramUnitText></ProgramUnit>'
           '</FormModule>').encode()
    documents = [("source.xml", raw)]
    packet = packets.local_packet(documents)
    selection = {packet["chunks"][0]["id"]: packet["chunks"][0]["sha256"]}
    plan = build(documents, selected=selection, max_owned_objects=1)
    assert plan["selected_chunk_hashes"] == selection
    assert_complete(plan, packet)
    selected = [chunk for request in plan["requests"] for chunk in request["chunks"]]
    assert len(selected) == 1 and selected[0]["text"] == code
    assert selected[0]["bytes"] == len(code.encode())
    trigger_focus = next(request for request in plan["requests"] if request["chunks"])
    assert {row["name"] for row in trigger_focus["context_objects"]} >= {"B", "OTHER", "I", "A"}
    assert any(link["relation"] == "references_item" and link["status"] == "resolved"
               for link in trigger_focus["links"])
    program_focus = next(request for request in plan["requests"] if request["owned_objects"][0]["kind"] == "ProgramUnit")
    assert len(program_focus["unselected_code_unit_ids"]) == 1
    assert not program_focus["chunks"]
    assert "BEGIN NULL; END;" not in json.dumps(plan)
    selection.clear()
    assert len(plan["selected_chunk_hashes"]) == 1


def test_document_and_selection_order_deterministic_and_no_arbitrary_property_leak():
    documents = [("z.xml", b'<FormModule Name="Z"><Trigger Name="T">BEGIN NULL; END;</Trigger></FormModule>'),
                 ("a.xml", b'<FormModule Name="A" Title="private unrelated property"><Trigger Name="T">BEGIN x:=1; END;</Trigger></FormModule>')]
    packet = packets.local_packet(documents)
    chosen = {chunk["id"]: chunk["sha256"] for chunk in packet["chunks"]}
    first = build(documents, selected=chosen)
    second = build(list(reversed(documents)), selected=dict(reversed(list(chosen.items()))))
    assert packets._canonical(first) == packets._canonical(second)
    assert "private unrelated property" not in json.dumps(first)
    assert "FormModule Name=" not in json.dumps(first)


def test_multi_module_globals_are_separate_and_nested_ancestry_complete():
    documents = [("modules.xml", b'<Module><FormModule Name="A"><Canvas Name="C"/><Block Name="B"><Item Name="I"><Trigger Name="T">BEGIN NULL; END;</Trigger></Item></Block></FormModule><MenuModule Name="M"><Menu Name="MAIN"><MenuItem Name="GO"/></Menu></MenuModule></Module>')]
    packet = packets.local_packet(documents)
    plan = build(documents, max_owned_objects=1)
    assert_complete(plan, packet)
    trigger_focus = next(request for request in plan["requests"] if request["owned_objects"][0]["kind"] == "Trigger")
    assert {row["kind"] for row in trigger_focus["context_objects"]} == {"FormModule", "Block", "Item"}


def test_duplicate_block_findings_include_other_focus_participants_and_ancestry():
    documents = [("duplicate-blocks.xml", b'<FormModule Name="A"><Block Name="B" DatabaseBlock="false"/><Block Name="B" DatabaseBlock="true"/></FormModule>')]
    packet = packets.local_packet(documents)
    plan = build(documents)
    assert_complete(plan, packet)
    block_ids = {row["id"] for row in packet["sources"][0]["facts"]["blocks"]}
    block_focuses = [request for request in plan["requests"]
                     if any(row["kind"] == "Block" for row in request["owned_objects"])]
    assert len(block_focuses) == 2
    for request in block_focuses:
        owned_ids = {row["id"] for row in request["owned_objects"]}
        context_ids = {row["id"] for row in request["context_objects"]}
        conflict = next(finding for finding in request["findings"]
                        if finding["code"] == "CONFLICTING_OBJECT_NAME")
        assert set(conflict["object_ids"]) == block_ids
        assert block_ids - owned_ids <= context_ids
        assert {row["kind"] for row in request["context_objects"]} == {"Block", "FormModule"}
        assert not request["code_units"] and not request["chunks"]


def test_ownership_split_findings_add_metadata_not_other_participant_code(monkeypatch):
    documents = [("duplicate-triggers.xml", b'<FormModule Name="A"><Block Name="B" DatabaseBlock="false"><Trigger Name="T">BEGIN x := 1; END;</Trigger><Trigger Name="T">BEGIN x := 2; END;</Trigger></Block></FormModule>')]
    packet = packets.local_packet(documents)
    plan = build(documents, max_owned_objects=1)
    assert_complete(plan, packet)
    trigger_focuses = [request for request in plan["requests"]
                       if request["owned_objects"][0]["kind"] == "Trigger"]
    assert len(trigger_focuses) == 2
    for request in trigger_focuses:
        assert {row["kind"] for row in request["context_objects"]} == {"Trigger", "Block", "FormModule"}
        assert len(request["code_units"]) == len(request["chunks"]) == 1
        assert request["code_units"][0]["owner_id"] == request["owned_objects"][0]["id"]
        other = next(row for row in request["context_objects"] if row["kind"] == "Trigger")
        assert other["id"] != request["code_units"][0]["owner_id"]
    # Required participant metadata remains inside the byte budget. It cannot
    # be silently removed to make an indivisible ownership unit fit.
    largest = max(len(packets._canonical(request)) for request in trigger_focuses)
    monkeypatch.setattr(focus, "MAX_REQUEST_BYTES", largest - 1)
    with pytest.raises(ValueError, match="Indivisible"):
        build(documents, max_owned_objects=1)


def test_stale_binding_chunk_hash_partial_unknown_and_wrong_types_rejected():
    documents = [("synthetic.xml", synthetic_forms(1, 1, 1))]
    packet = packets.local_packet(documents)
    chunk = packet["chunks"][0]
    for selection in (None, [], {"unknown": "0" * 64}, {chunk["code_unit_id"]: chunk["sha256"]},
                      {chunk["id"]: "0" * 64}, {chunk["id"]: chunk["sha256"][:32]}, {chunk["id"]: None}):
        with pytest.raises(ValueError):
            focus.build_focus_plan(documents, expected_source_binding=packet["source_binding"], approved_chunk_hashes=selection)
    for binding in (None, "0" * 64):
        with pytest.raises(ValueError, match="stale"):
            focus.build_focus_plan(documents, expected_source_binding=binding, approved_chunk_hashes={})
    with pytest.raises(ValueError, match="stale"):
        focus.build_focus_plan([("synthetic.xml", documents[0][1] + b" ")],
                               expected_source_binding=packet["source_binding"], approved_chunk_hashes={})
    for maximum in (False, 0, -1, 1.5, "250", None):
        with pytest.raises(ValueError, match="positive integer"):
            build(documents, max_owned_objects=maximum)


def test_payload_splits_only_objects_and_binding_counts_in_budget(monkeypatch):
    documents = [("split.xml", synthetic_forms(1, 40, 4))]
    packet = packets.local_packet(documents)
    monkeypatch.setattr(focus, "MAX_REQUEST_BYTES", 9_000)
    plan = build(documents)
    assert len(plan["requests"]) > 2
    assert all(len(packets._canonical(request)) <= 9_000 for request in plan["requests"])
    assert_complete(plan, packet)
    # A single root request fits at its exact canonical size, not one byte less.
    documents = [("tiny.xml", b'<FormModule Name="A"/>')]
    monkeypatch.setattr(focus, "MAX_REQUEST_BYTES", 500_000)
    request = build(documents)["requests"][0]
    size = len(packets._canonical(request))
    monkeypatch.setattr(focus, "MAX_REQUEST_BYTES", size)
    assert build(documents)["requests"][0] == request
    monkeypatch.setattr(focus, "MAX_REQUEST_BYTES", size - 1)
    with pytest.raises(ValueError, match="Indivisible"):
        build(documents)


def test_huge_selected_unit_refused_without_truncation_but_metadata_allowed():
    code = "BEGIN " + " " * 500_000 + "NULL; END;"
    documents = [("large.xml", f'<FormModule Name="A"><Trigger Name="T" TriggerText={quoteattr(code)}/></FormModule>'.encode())]
    with pytest.raises(ValueError, match="Indivisible.*500000-byte"):
        build(documents)
    packet = packets.local_packet(documents)
    metadata = build(documents, selected={})
    assert_complete(metadata, packet)
    assert metadata["requests"][0]["code_units"][0]["bytes"] > 500_000
    assert not any(request["chunks"] for request in metadata["requests"])


def test_indivisible_metadata_row_refused_without_dropping_findings(monkeypatch):
    real = forms_facts.assess_forms_xml

    def large_row(*args):
        facts = real(*args)
        facts["objects"][0]["name"] = "x" * 500_000
        return facts

    monkeypatch.setattr(forms_facts, "assess_forms_xml", large_row)
    with pytest.raises(ValueError, match="Indivisible"):
        build([("a.xml", b'<FormModule Name="A"/>')])


def test_request_and_aggregate_caps_cannot_be_bypassed(monkeypatch):
    documents = [("limits.xml", synthetic_forms(1, 253, 0))]
    # 258 objects: root + canvas + window + block + 253 items + program unit.
    with pytest.raises(ValueError, match="256-request"):
        build(documents, selected={}, max_owned_objects=1)
    documents = [("a.xml", b'<FormModule Name="A"/>')]
    plan = build(documents)
    size = len(packets._canonical(plan))
    monkeypatch.setattr(focus, "MAX_PLAN_BYTES", size)
    assert build(documents) == plan
    monkeypatch.setattr(focus, "MAX_PLAN_BYTES", size - 1)
    with pytest.raises(ValueError, match="aggregate"):
        build(documents)


def test_final_full_packet_node_limit_refuses_before_requests_or_inference(monkeypatch):
    items = "".join(f'<Item Name="I{index}" DatabaseItem="true" ItemType="Text Item"/>'
                    for index in range(24_000))
    documents = [("many-items.xml", ('<FormModule Name="A"><Block Name="B" DatabaseBlock="true">'
                                    + items + '</Block></FormModule>').encode())]
    packet = packets.local_packet(documents)
    assert len(documents[0][1]) < forms_facts.MAX_FILE_BYTES
    assert packet["sources"][0]["facts"]["totals"]["items"] == 24_000

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Request construction started before full-validator preflight")

    monkeypatch.setattr(focus, "_seal", forbidden)
    with pytest.raises(ValueError, match="bounded document limit"):
        focus.build_focus_plan(documents, expected_source_binding=packet["source_binding"],
                               approved_chunk_hashes={})


def test_plan_itself_uses_final_merger_document_budget(monkeypatch):
    real = focus._bounded_json
    checked_scopes = []

    def record(value):
        checked_scopes.append(value["scope"])
        real(value)

    monkeypatch.setattr(focus, "_bounded_json", record)
    build([("a.xml", b'<FormModule Name="A"/>')])
    assert checked_scopes == [packets.SCOPE, focus.PLAN_SCOPE]


def test_returned_plan_tampering_and_fresh_fact_hash_mismatch_are_detectable(monkeypatch):
    documents = [("a.xml", synthetic_forms(1, 1, 1))]
    plan = build(documents)
    tampered = copy.deepcopy(plan)
    tampered["requests"][0]["owned_objects"][0]["name"] = "invented"
    assert tampered["requests"][0]["focus_binding"] != digest_without(tampered["requests"][0], "focus_binding")
    assert tampered["plan_binding"] != digest_without(tampered, "plan_binding")
    assert build(documents) == plan
    real = forms_facts.assess_forms_xml

    def wrong_hash(*args):
        facts = real(*args)
        facts["code_units"][0]["sha256"] = "0" * 64
        return facts

    monkeypatch.setattr(forms_facts, "assess_forms_xml", wrong_hash)
    with pytest.raises(ValueError, match="hash"):
        build(documents)


def test_no_external_io_execution_or_provider(monkeypatch):
    import builtins
    import socket
    import subprocess

    documents = [("a.xml", synthetic_forms(2, 4, 2))]
    packet = packets.local_packet(documents)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("External operation attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(packets, "approved_packet", forbidden)
    plan = focus.build_focus_plan(documents, expected_source_binding=packet["source_binding"], approved_chunk_hashes={})
    assert plan["requests"]
