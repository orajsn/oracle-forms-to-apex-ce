"""Offline, additive mapped-project OPAF artifacts; no model/DB/cloud calls."""
import ast
from copy import deepcopy
import json
from pathlib import Path

import pytest

from fox.native_project_pipeline import PROJECT_MAPPING_CAPABILITY, load_project_profile
from fox.opaf import OpafClient, OpafError, canonical_hash, load_native_profile


ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT = ROOT / "deployment"
ROLE_HASHES = {
    "mapper": "897c6ff34f011fd53084623532d843a21d284308f9490ac0c1fee3a11ec3e22e",
    "reviewer": "882434ecc24994eee8945cbad7a9e14986d5e4b53b35ea0c46f473a45709bdb9",
}


def document(name):
    return json.loads((DEPLOYMENT / name).read_text(encoding="utf-8"))


def prompt(graph):
    return next(node["data"]["template"]["prompt"]["value"]
                for node in graph["nodes"] if node["data"]["type"] == "promptComponent")


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
def test_candidate_graph_is_pinned_distinct_and_tool_free(role):
    graph = document(f"project-opaf-{role}-v2.json")["data"]
    profile = document("project-opaf-profile-v2.candidate.json")
    legacy = document(f"native-opaf-{role}.json")["data"]
    assert canonical_hash(graph) == ROLE_HASHES[role] == profile[role]["graph_sha256"]
    assert canonical_hash(graph) != canonical_hash(legacy)
    assert sorted(node["data"]["type"] for node in graph["nodes"]) == sorted([
        "chatInputComponent", "promptComponent", "llmStep", "chatOutputComponent"])
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert len(nodes) == 4 and len(graph["edges"]) == 3
    assert [(edge["source"], edge["target"]) for edge in graph["edges"]] == [
        (f"project-v2-{role}-input", f"project-v2-{role}-prompt"),
        (f"project-v2-{role}-prompt", f"project-v2-{role}-llm"),
        (f"project-v2-{role}-llm", f"project-v2-{role}-output"),
    ]
    for edge in graph["edges"]:
        assert edge["sourceHandle"].endswith("-" + edge["source"])
        assert edge["targetHandle"].endswith("-" + edge["target"])
    llm = nodes[f"project-v2-{role}-llm"]["data"]["template"]
    assert llm == next(node["data"]["template"] for node in legacy["nodes"]
                       if node["data"]["type"] == "llmStep")
    assert profile[role]["model"] == "xai.grok-4.3"
    assert llm["temperature"]["value"] == 0


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
def test_candidate_prompt_keeps_original_evidence_and_explicit_mapping_separate(role):
    text = prompt(document(f"project-opaf-{role}-v2.json")["data"])
    for required in ("storage_mapping", "ddl_sources", "module_execution_binding",
                     "fox-project-storage-v1", "fox-project-module-execution-v2",
                     "source_table_name", "source_schema_sha256", "identity_sha256",
                     "target_table_name", "inventory.source_projection", "ORIGINAL",
                     "never rewrite XML/DDL", "never modify original bytes or hashes",
                     "not a source conflict" if role == "reviewer" else "never instructions"):
        assert required in text
    assert "Do not infer a storage map" in text
    assert "Do not use the v2 exception without all three explicit request records" in text
    assert "source_manifest_sha256 remain unchanged" in text
    assert "schema_version 1 remains supported" in text
    assert "sqlcl-26.1.2-fox-native-v1" in text
    assert "xai.grok-4.3" in text
    assert text.count("{{request}}") == 1


def test_candidate_profiles_are_explicitly_undeployed_and_real_loaders_fail_closed(monkeypatch):
    profile = document("project-opaf-profile-v2.candidate.json")
    target = document("project-opaf-target-profile-v2.candidate.json")
    assert profile["schema_version"] == 2
    assert profile["profile_id"] == "native-project-v1"
    assert {key: profile[key] for key in PROJECT_MAPPING_CAPABILITY} == PROJECT_MAPPING_CAPABILITY
    assert target["scope"]["project_mapping"] == PROJECT_MAPPING_CAPABILITY
    assert target["active"] is False
    assert target["scope"]["customer_deployment_authorized"] is False
    assert target["scope"]["existing_resources_only"] is True
    assert target["opaf"]["roles"] == {role: profile[role] for role in ("mapper", "reviewer")}
    assert all(profile[role]["workflow_id"] is None for role in ("mapper", "reviewer"))
    monkeypatch.setattr(OpafClient, "_request", lambda *_args, **_kwargs: pytest.fail("No network"))
    with pytest.raises(OpafError, match="not activated"):
        load_project_profile(DEPLOYMENT / "project-opaf-profile-v2.candidate.json")
    with pytest.raises(OpafError, match="Unsupported"):
        load_native_profile(DEPLOYMENT / "project-opaf-profile-v2.candidate.json")
    monkeypatch.syspath_prepend(str(ROOT / "converter"))
    from forms2apex.target_profile import TargetProfileError, validate_target_profile
    with pytest.raises(TargetProfileError, match="Inactive"):
        validate_target_profile(target)
    # A JSON active flag cannot self-register or authorize the new graphs.
    forged = deepcopy(target)
    forged["active"] = True
    with pytest.raises(TargetProfileError):
        validate_target_profile(forged)


def test_legacy_target_and_role_graphs_remain_unchanged():
    target = document("target-profile.jsn.json")
    assert canonical_hash(target) == "7c7b73d43febc9befb1d43e47449a02cc7894b879dd4bc32904cec538e5f95e6"
    profile = load_native_profile(DEPLOYMENT / "native-beta-profile.json")
    for role in ("mapper", "reviewer"):
        assert profile[role] == target["opaf"]["roles"][role]
        assert profile[role]["graph_sha256"] == canonical_hash(document(f"native-opaf-{role}.json")["data"])
    assert load_project_profile(DEPLOYMENT / "native-beta-profile.json") == profile


def test_candidate_documents_activation_gaps_without_changing_public_mcp_tools():
    contract = document("project-opaf-v2-candidate-contract.json")
    assert contract["status"] == "candidate_only_not_deployed_or_authorized"
    assert contract["model"] == "xai.grok-4.3"
    assert contract["current_blockers"] and contract["activation_requires"]
    assert contract["source_projection_scope"] == "fox-project-module-source-projection-v2"
    source = ast.parse((ROOT / "converter/forms2apex/server.py").read_text(encoding="utf-8"))
    public = [node.name for node in source.body if isinstance(node, ast.FunctionDef)
              and any(isinstance(decorator, ast.Attribute) and decorator.attr == "tool"
                      for decorator in node.decorator_list)]
    assert public == contract["mcp_tools_unchanged"]

