"""The optional source snapshot lives only inside one deterministic generation."""
import asyncio
from contextvars import copy_context

import pytest

from fox import forms_facts, forms_understanding_packet as packet
from fox.forms_native_plan import POLICY_ID
from fox.xml_mapping import generate_xml_package, _check_candidate

SOURCE=b'''<FormModule Name="DEMO"><Block Name="ORDERS" DatabaseBlock="true">
<Item Name="CODE" ItemType="Text Item" DataType="Char" MaximumLength="20" DatabaseItem="true"/>
<Trigger Name="CHECK_ONE" TriggerText="BEGIN NULL; END;"/>
</Block></FormModule>'''


def counters(monkeypatch):
    calls={"packets":0,"parses":0}
    build=packet._build_uncached
    parse=forms_facts._parse_checked_input
    def counted(docs):
        calls["packets"]+=1
        return build(docs)
    def checked(name,raw):
        calls["parses"]+=1
        return parse(name,raw)
    monkeypatch.setattr(packet,"_build_uncached",counted)
    monkeypatch.setattr(forms_facts,"_parse_checked_input",checked)
    return calls


def test_independent_package_build_and_verification_each_parse_once(monkeypatch):
    calls=counters(monkeypatch)
    docs=[("demo.xml",SOURCE)]
    candidate,_=generate_xml_package(docs,"example","Example",POLICY_ID)
    assert calls=={"packets":1,"parses":1}
    _check_candidate(candidate)
    assert calls=={"packets":2,"parses":2}
    assert forms_facts._generation.get() is None


def test_context_serves_defensive_copies_and_never_reuses_changed_input(monkeypatch):
    calls=counters(monkeypatch)
    docs=[("demo.xml",SOURCE)]
    with packet.generation_sources(docs):
        first,chunks=packet._build(docs)
        binding=first["source_binding"]
        first["sources"][0]["facts"]["objects"].clear()
        chunks[0]["text"]="changed"
        tree,locations=forms_facts._safe_input(*docs[0])
        tree.set("Name","WRONG");locations[0]["line"]=-1
        second,clean=packet._build(list(docs))
        tree,locations=forms_facts._safe_input(*docs[0])
        assert second["sources"][0]["facts"]["objects"] and clean[0]["text"]!="changed"
        assert tree.get("Name")=="DEMO" and locations[0]["line"]>0
        assert calls=={"packets":1,"parses":1}
        changed=[("demo.xml",SOURCE.replace(b"DEMO",b"OTHER"))]
        assert packet._build(changed)[0]["source_binding"] != binding
        with pytest.raises(ValueError):
            forms_facts._safe_input("../demo.xml",SOURCE)
        with pytest.raises(ValueError):
            packet._build([("demo.xml",b"<malformed")])
        assert packet._build(docs)[0]["source_binding"]==binding
        inherited=copy_context()
    assert inherited.run(forms_facts._generation.get)=={}
    packet._build(docs)
    assert calls["packets"]>=4


def test_oversized_snapshots_recompute_without_changing_results(monkeypatch):
    from fox import prototype_read_scope
    monkeypatch.setattr(prototype_read_scope,"MAX_DOCUMENT_BUILD_VALUE_BYTES",1)
    monkeypatch.setattr(prototype_read_scope,"MAX_DOCUMENT_BUILD_BYTES",1)
    calls=counters(monkeypatch)
    docs=[("demo.xml",SOURCE)]
    with packet.generation_sources(docs):
        assert packet._build(docs)==packet._build(docs)
    assert calls=={"packets":2,"parses":4}


def test_nested_builds_and_inherited_tasks_have_separate_source_state(monkeypatch):
    calls=counters(monkeypatch)
    docs=[("demo.xml",SOURCE)]
    async def other():
        return packet._build(docs)
    async def run():
        with packet.generation_sources(docs):
            original=packet._build(docs)
            assert await asyncio.create_task(other())==original
            with packet.generation_sources(docs):
                assert packet._build(docs)==original
            assert packet._build(docs)==original
    asyncio.run(run())
    assert calls=={"packets":3,"parses":4}


def test_generation_scope_clears_on_failure():
    with pytest.raises(ValueError):
        generate_xml_package([("demo.xml",b"<malformed")],"demo","Demo",POLICY_ID)
    assert forms_facts._generation.get() is None
