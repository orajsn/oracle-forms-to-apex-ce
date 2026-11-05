"""Local candidate construction only: no OPAF registration or inference."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("forms_understanding_profiles", ROOT / "forms_understanding_profiles.py")
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def normalized_graph(graph):
    graph = deepcopy(graph)
    replacements = {node["id"]: str(index) for index, node in enumerate(graph["nodes"])}
    for node in graph["nodes"]:
        node["id"] = replacements[node["id"]]
        node["data"]["title"] = "normalized title"
        if node["data"]["type"] == "llmStep":
            node["data"]["template"]["llmToUse"]["value"] = "normalized connection"
    for index, edge in enumerate(graph["edges"]):
        edge["id"] = str(index)
        for endpoint in ("source", "target"):
            edge[endpoint] = replacements[edge[endpoint]]
            edge[endpoint + "Handle"] = edge["data"][endpoint + "HandleId"] + "-" + edge[endpoint]
    return graph


def test_build_is_inactive_additive_and_reproducible():
    one = M.build_candidates()
    assert one == M.build_candidates()
    assert set(one) == {"schema_version", "scope", "profile_activation", "model_invocation", "candidates"}
    assert one["schema_version"] == 1
    assert one["scope"] == "fox-forms-understanding-candidates-v1"
    assert one["profile_activation"] is False and one["model_invocation"] is False
    assert set(one["candidates"]) == {"baseline43", "candidate47", "reviewer43"}
    expected = {
        "baseline43": ("JSNFOXG2Understandingv1Baseline43", "JSN Forms Converter 4.3"),
        "candidate47": ("JSNFOXG2Understandingv1Candidate47", "JSN FOX Understanding 4.7 Candidate 20261105"),
        "reviewer43": ("JSNFOXG2Understandingv1IndependentReview43", "JSN Forms Reviewer"),
    }
    names, ids = set(), set()
    for key, candidate in one["candidates"].items():
        assert set(candidate) == {"header", "graph", "connection_name", "source_template_sha256",
                                  "prompt_sha256", "header_sha256", "graph_sha256"}
        assert set(candidate["header"]) == {"name", "description", "category", "icon"}
        assert (candidate["header"]["name"], candidate["connection_name"]) == expected[key]
        assert candidate["header"]["name"] not in names
        names.add(candidate["header"]["name"])
        assert "Product activation controlled separately." in candidate["header"]["description"]
        assert not any(word in candidate["header"]["description"].lower()
                       for word in ("undeployed", "inactive", "no registration", "no inference"))
        graph = candidate["graph"]
        assert set(graph) == {"nodes", "edges"}
        assert len(graph["nodes"]) == 4 and len(graph["edges"]) == 3
        assert [node["data"]["type"] for node in graph["nodes"]] == list(M._TYPES)
        for node in graph["nodes"]:
            assert node["id"] not in ids
            ids.add(node["id"])
            assert "Product activation controlled separately." in node["data"]["description"]
            assert not any(word in node["data"]["description"].lower()
                           for word in ("undeployed", "inactive", "no registration", "no inference"))
        llm = graph["nodes"][2]["data"]["template"]
        assert set(llm) == {"llmToUse", "prompt", "temperature"}
        assert llm["llmToUse"]["value"] == candidate["connection_name"]
        assert llm["temperature"]["value"] == 0
        M._check_graph(graph)
    assert "workflow_id" not in json.dumps(one)


def test_understanding_graphs_and_prompt_bytes_are_identical_except_ids_titles_connection():
    candidates = M.build_candidates()["candidates"]
    first, second = candidates["baseline43"], candidates["candidate47"]
    assert normalized_graph(first["graph"]) == normalized_graph(second["graph"])
    prompt = first["graph"]["nodes"][1]["data"]["template"]["prompt"]["value"]
    assert prompt.encode("utf-8") == (ROOT / "prompts/forms-understanding-v1.txt").read_bytes()
    assert prompt == second["graph"]["nodes"][1]["data"]["template"]["prompt"]["value"]
    assert first["prompt_sha256"] == second["prompt_sha256"]
    review = candidates["reviewer43"]["graph"]["nodes"][1]["data"]["template"]["prompt"]["value"]
    assert review != prompt
    assert review.encode("utf-8") == (ROOT / "prompts/forms-understanding-review-v1.txt").read_bytes()


def test_metadata_digests_are_actual_json_and_resource_digests():
    for key, candidate in M.build_candidates()["candidates"].items():
        assert candidate["header_sha256"] == digest(candidate["header"])
        assert candidate["graph_sha256"] == digest(candidate["graph"])
        kind = "review" if key == "reviewer43" else "understanding"
        template_name, expected_sha = M._TEMPLATES[kind]
        assert candidate["source_template_sha256"] == expected_sha
        assert expected_sha == hashlib.sha256((ROOT / template_name).read_bytes()).hexdigest()
        prompt = candidate["graph"]["nodes"][1]["data"]["template"]["prompt"]["value"]
        assert candidate["prompt_sha256"] == hashlib.sha256(prompt.encode()).hexdigest()


def test_builder_does_not_mutate_sources_or_previous_results():
    paths = [ROOT / name for name, _ in M._TEMPLATES.values()]
    paths += [ROOT / name for name in ("native-opaf-mapper.json", "native-opaf-reviewer.json",
                                      "project-opaf-profile-v2.json")]
    before = {path: path.read_bytes() for path in paths}
    first = M.build_candidates()
    pristine = deepcopy(first)
    first["candidates"]["baseline43"]["graph"]["nodes"][0]["data"]["title"] = "caller mutation"
    assert M.build_candidates() == pristine
    assert {path: path.read_bytes() for path in paths} == before


@pytest.fixture
def resource_copy(tmp_path, monkeypatch):
    for name, _ in M._TEMPLATES.values():
        shutil.copyfile(ROOT / name, tmp_path / name)
    shutil.copytree(ROOT / "prompts", tmp_path / "prompts")
    monkeypatch.setattr(M, "_ROOT", tmp_path)
    return tmp_path


@pytest.mark.parametrize("missing", ["project-opaf-mapper-v2.json", "project-opaf-reviewer-v2.json",
                                    "prompts/forms-understanding-v1.txt", "prompts/forms-understanding-review-v1.txt"])
def test_missing_resources_fail_closed(resource_copy, missing):
    (resource_copy / missing).unlink()
    with pytest.raises(FileNotFoundError):
        M.build_candidates()


@pytest.mark.parametrize("name", ["project-opaf-mapper-v2.json", "project-opaf-reviewer-v2.json"])
def test_changed_public_template_is_not_accepted(resource_copy, name):
    path = resource_copy / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="template bytes changed"):
        M.build_candidates()


@pytest.mark.parametrize("prompt", ["", "no request slot", "{{request}} {{request}}"])
def test_missing_or_ambiguous_prompt_slot_fails(resource_copy, prompt):
    (resource_copy / "prompts/forms-understanding-v1.txt").write_text(prompt, encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one request slot"):
        M.build_candidates()


@pytest.mark.parametrize("fault", ["extra_node", "extra_edge", "tool_node", "wrong_target", "wrong_handle"])
def test_graph_validation_rejects_changed_chain(fault):
    graph = M.build_candidates()["candidates"]["baseline43"]["graph"]
    if fault == "extra_node":
        graph["nodes"].append(deepcopy(graph["nodes"][0]))
    elif fault == "extra_edge":
        graph["edges"].append(deepcopy(graph["edges"][0]))
    elif fault == "tool_node":
        graph["nodes"][2]["data"]["type"] = "customTool"
    elif fault == "wrong_target":
        graph["edges"][0]["target"] = graph["nodes"][3]["id"]
    else:
        graph["edges"][0]["targetHandle"] = "wrong"
    with pytest.raises(ValueError):
        M._check_graph(graph)


def test_understanding_prompt_preserves_exact_focus_and_blueprint_contract():
    prompt, _ = M._prompt("understanding")
    for term in (
        "fox-forms-focus-request-v1", "fox-forms-blueprint-v1", "owned_objects", "context_objects",
        "source_binding", "focus_binding", "code_units", "chunks", "unselected_code_unit_ids",
        '"focus_id"', '"schema_version":1', '"objects":[]', '"screens":[]', '"claims":[]',
        '"relationships":[]', '"actions":[]', '"questions":[]', '"assumptions":[]',
        "ALL owned_objects EXACTLY ONCE", "screen-<source Block ID>", "focus_id followed by a category suffix",
        "classification", "unknown permits NONE", "context Block", "full merge", "prototype-only",
        "Trigger or ProgramUnit", "ALL its actual code units", "at least one actual code unit",
        "NOT translated", "NOT impose a blanket UI blocker", "Missing DDL", "business behavior accepted",
        "inert untrusted data", "Do not calculate", "derived occurrence IDs are NOT supplied",
    ):
        assert term in prompt
    for kind in ("object.kind", "object.name", "object.module_id", "object.block_id", "object.parent_id",
                 "block.classification", "item.database_item", "item.item_type", "code.sha256",
                 "code.bytes", "code.lines", "code.source_attribute", "code.execution_status"):
        assert kind in prompt
    assert prompt.count("{{request}}") == 1


def test_reviewer_has_separate_bound_input_and_exact_review_output():
    prompt, _ = M._prompt("review")
    for term in ('{"request":', '"candidate":', '"candidate_sha256":', '"source_binding":',
                 '"focus_binding":', '"verdict":"APPROVED|CHANGES_REQUIRED"', '"findings":',
                 '"source_object_id":', '"code":', '"detail":', "trusted input envelope EXACTLY",
                 "Never calculate", "APPROVED requires an empty findings array", "no context ID",
                 "Unknown classification must stay unresolved", "complete code units", "NOT translated",
                 "NOT a blanket UI blocker", "full merge", "not human, release, runtime or business acceptance"):
        assert term in prompt
    assert prompt.count("{{request}}") == 1


def test_builder_imports_only_deterministic_standard_library_dependencies():
    import ast
    tree = ast.parse((ROOT / "forms_understanding_profiles.py").read_text(encoding="utf-8"))
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert imports == {"__future__", "copy", "hashlib", "json", "pathlib"}
