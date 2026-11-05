"""Synthetic local packet proofs; no provider, Oracle or filesystem source reads."""
import hashlib
import json
from xml.sax.saxutils import quoteattr

import pytest

from fox import forms_facts, forms_understanding_packet as packets


def document(code="BEGIN INSERT INTO APP.AUDIT(ID) VALUES (1); END;", *, blocks=1):
    body = "".join(f'<Block Name="B{i}" DatabaseBlock="false"><Item Name="I"/>'
                   f'<Trigger Name="T" TriggerText={quoteattr(code)}/></Block>'
                   for i in range(blocks))
    return f'<FormModule Name="SYNTHETIC">{body}</FormModule>'.encode()


def choose(packet, indexes=None):
    chunks = packet["chunks"] if indexes is None else [packet["chunks"][i] for i in indexes]
    return {chunk["id"]: chunk["sha256"] for chunk in chunks}


def approve(documents, packet=None, indexes=None):
    packet = packet or packets.local_packet(documents)
    return packets.approved_packet(documents, expected_source_binding=packet["source_binding"],
                                   approved_chunk_hashes=choose(packet, indexes))


def test_local_no_source_or_code_default_and_full_metadata_retained():
    raw = document(blocks=9)
    packet = packets.local_packet([("synthetic.xml", raw)])
    assert packet["schema_version"] == 1
    assert packet["scope"] == "fox-forms-understanding-packet-v1"
    assert packet["selection_status"] == "NOT_SELECTED"
    facts = forms_facts.assess_forms_xml("synthetic.xml", raw)
    assert packet["sources"] == [{"source": facts["source"], "facts": facts}]
    assert facts["totals"]["blocks"] == 9
    assert len(packet["chunks"]) == 9
    assert packet["selectable_code_unit_ids"] == [u["id"] for u in facts["code_units"]]
    assert all(dep["confidence"] == "candidate" for dep in facts["dependencies"])
    serialized = json.dumps(packet)
    assert "INSERT INTO" not in serialized and "FormModule Name=" not in serialized
    assert all(set(chunk) == {"id", "source_sha256", "code_unit_id", "sha256", "bytes"}
               for chunk in packet["chunks"])
    expected = {key: packet[key] for key in ("sources", "chunks")}
    assert packet["source_binding"] == hashlib.sha256(packets._canonical(expected)).hexdigest()


def test_selection_returns_only_exact_whole_decoded_units_and_never_authorizes():
    code = "BEGIN\n :B0.I := 'é & ordinary'; x := q'[a < b]';\nEND;"
    documents = [("synthetic.xml", document(code, blocks=2))]
    local = packets.local_packet(documents)
    request = approve(documents, local, [1])
    assert len(request["chunks"]) == 1
    chunk = request["chunks"][0]
    assert chunk["text"] == code
    assert chunk["bytes"] == len(code.encode())
    assert chunk["sha256"] == hashlib.sha256(code.encode()).hexdigest()
    assert request["selection_status"] == "SCOPED_CONTENT_SELECTED"
    assert request["transfer_authorized"] is False
    assert request["caller_must_check_processing_approval"] is True
    assert request["safety"]["model_submission_allowed"] is False
    assert request["safety"]["native_generation_allowed"] is False
    assert request["no_automatic_selection"] is True
    assert request["sources"] == local["sources"]
    assert request["source_binding"] == local["source_binding"]


def test_metadata_only_is_explicit_not_automatic_selection():
    documents = [("synthetic.xml", document())]
    request = approve(documents, indexes=[])
    assert request["chunks"] == [] and request["selected_code_unit_ids"] == []
    assert request["selection_status"] == "METADATA_ONLY"
    assert request["transfer_authorized"] is False
    assert "INSERT INTO" not in json.dumps(request)


def test_text_properties_cdata_attributes_namespace_and_same_owner_are_exact():
    raw = b'''<f:FormModule xmlns:f="http://xmlns.oracle.com/Forms" Name="A">
      <f:Trigger Name="T" TriggerText="BEGIN x := &apos;&amp;&lt;&gt;&quot;&apos;; END;">
      <![CDATA[BEGIN y := 'body'; END;]]><f:TriggerText>BEGIN z := 'property'; END;</f:TriggerText>
      </f:Trigger><f:RecordGroup Name="RG"><f:RecordGroupQuery>SELECT ID FROM APP.T</f:RecordGroupQuery></f:RecordGroup>
      <f:ProgramUnit Name="P">BEGIN NULL; END;</f:ProgramUnit>
    </f:FormModule>'''
    request = approve([("properties.xml", raw)])
    assert len(request["chunks"]) == 5
    assert request["chunks"][0]["text"] == 'BEGIN x := \'&<>"\'; END;'
    facts = request["sources"][0]["facts"]
    for chunk, unit in zip(request["chunks"], facts["code_units"], strict=True):
        assert chunk["code_unit_id"] == unit["id"]
        assert chunk["sha256"] == unit["sha256"]
        assert chunk["bytes"] == unit["bytes"]


def test_document_order_binding_is_stable_names_and_revisions_are_bound():
    raw = document()
    documents = [("b.xml", document("BEGIN NULL; END;")), ("a.xml", raw)]
    packet = packets.local_packet(documents)
    assert packet == packets.local_packet(list(reversed(documents)))
    assert len({c["id"] for c in packet["chunks"]}) == 2
    changed = [("b.xml", document("BEGIN NULL; END;") + b" "), ("a.xml", raw)]
    assert packet["source_binding"] != packets.local_packet(changed)["source_binding"]
    assert packet["source_binding"] != packets.local_packet([("c.xml", documents[0][1]), ("a.xml", raw)])["source_binding"]
    with pytest.raises(ValueError, match="stale"):
        approve(changed, packet)


@pytest.mark.parametrize("selection", [
    {"unknown": "0" * 64}, {"UNIT_ID": "0" * 64}, [], None,
])
def test_unknown_or_invalid_selection_fails_closed(selection):
    documents = [("a.xml", document())]
    packet = packets.local_packet(documents)
    if isinstance(selection, dict) and "UNIT_ID" in selection:
        selection = {packet["chunks"][0]["code_unit_id"]: "0" * 64}
    with pytest.raises(ValueError):
        packets.approved_packet(documents, expected_source_binding=packet["source_binding"],
                                approved_chunk_hashes=selection)


def test_partial_chunk_hash_and_old_chunk_rejected():
    documents = [("a.xml", document())]
    local = packets.local_packet(documents)
    descriptor = local["chunks"][0]
    for value in ("0" * 64, hashlib.sha256(b"BEGIN").hexdigest(), descriptor["sha256"][:32], None):
        with pytest.raises(ValueError, match="complete"):
            packets.approved_packet(documents, expected_source_binding=local["source_binding"],
                                    approved_chunk_hashes={descriptor["id"]: value})
    changed = [("a.xml", document("BEGIN NULL; END;"))]
    with pytest.raises(ValueError, match="unknown"):
        packets.approved_packet(changed, expected_source_binding=packets.local_packet(changed)["source_binding"],
                                approved_chunk_hashes=choose(local))


@pytest.mark.parametrize("documents", [[], [("a.xml", b"<FormModule")],
    [("a.xml", b'<!DOCTYPE x [<!ENTITY e "x">]><FormModule Name="A">&e;</FormModule>')],
    [("a.xml", b'<FormModule Name="A"><Trigger Name="T" TriggerText="pwd := &apos;synthetic-secret&apos;;"/></FormModule>')],
    [("../a.xml", b'<FormModule Name="A"/>')], [("a.xml", "not bytes")],
    [["a.xml", b'<FormModule Name="A"/>']],
])
def test_malformed_or_secret_inputs_rejected_without_echo(documents):
    with pytest.raises(ValueError) as caught:
        packets.local_packet(documents)
    assert "synthetic-secret" not in str(caught.value)
    assert len(str(caught.value)) < 200


def test_file_count_duplicates_and_source_limits(monkeypatch):
    raw = document()
    with pytest.raises(ValueError, match="1 and 4"):
        packets.local_packet([(f"f{i}.xml", raw) for i in range(5)])
    for name in ("a.xml", "A.XML"):
        with pytest.raises(ValueError, match="Duplicate"):
            packets.local_packet([("a.xml", raw), (name, document("BEGIN NULL; END;"))])
    with pytest.raises(ValueError, match="retain one original"):
        packets.local_packet([("a.xml", raw), ("different.xml", raw)])
    monkeypatch.setattr(forms_facts, "MAX_FILE_BYTES", len(raw) - 1)
    with pytest.raises(ValueError, match="at most"):
        packets.local_packet([("a.xml", raw)])
    monkeypatch.setattr(forms_facts, "MAX_FILE_BYTES", len(raw))
    monkeypatch.setattr(packets, "MAX_TOTAL_SOURCE_BYTES", len(raw))
    with pytest.raises(ValueError, match="total source"):
        packets.local_packet([("a.xml", raw), ("b.xml", document("BEGIN NULL; END;"))])


def test_large_51_block_local_inventory_retains_all_metadata_without_provider_cap():
    from test_forms_facts import synthetic_forms

    # Fabricated structure produces more than a megabyte of complete evidence.
    documents = [("large.xml", synthetic_forms(blocks=51, items=1400, triggers=200))]
    packet = packets.local_packet(documents)
    assert packet["sources"][0]["facts"]["totals"]["blocks"] == 51
    assert packet["sources"][0]["facts"]["totals"]["items"] == 1400
    assert len(packets._canonical(packet)) > 1_000_000
    assert len(packet["chunks"]) == 201
    assert packet["sources"][0]["facts"] == forms_facts.assess_forms_xml(*documents[0])
    for indexes in ([], [0]):
        with pytest.raises(ValueError, match="500000-byte"):
            approve(documents, packet, indexes)


def test_actual_request_budget_no_truncation_and_metadata_is_counted(monkeypatch):
    documents = [("large.xml", document("BEGIN " + " " * 500_000 + "NULL; END;"))]
    packet = packets.local_packet(documents)
    assert packet["chunks"][0]["bytes"] > 500_000
    with pytest.raises(ValueError, match="500000-byte"):
        approve(documents, packet)
    metadata = approve(documents, packet, [])
    assert metadata["sources"][0]["facts"] == packet["sources"][0]["facts"]
    size = len(packets._canonical(metadata))
    monkeypatch.setattr(packets, "MAX_REQUEST_BYTES", size)
    assert approve(documents, packet, []) == metadata
    monkeypatch.setattr(packets, "MAX_REQUEST_BYTES", size - 1)
    with pytest.raises(ValueError, match="500000-byte"):
        approve(documents, packet, [])


def test_fresh_facts_hash_mismatch_is_never_emitted(monkeypatch):
    real = forms_facts.assess_forms_xml

    def wrong_hash(*args):
        facts = real(*args)
        facts["code_units"][0]["sha256"] = "0" * 64
        return facts

    monkeypatch.setattr(forms_facts, "assess_forms_xml", wrong_hash)
    with pytest.raises(ValueError, match="hash"):
        packets.local_packet([("a.xml", document())])


def test_no_external_io_or_execution(monkeypatch):
    import builtins
    import socket
    import subprocess

    def forbidden(*_args, **_kwargs):
        raise AssertionError("External operation attempted")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert approve([("a.xml", document())])["chunks"]
