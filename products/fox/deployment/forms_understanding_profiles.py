"""Build inactive G2 design/review candidates from pinned public graph shapes.

This module reads only bundled public templates and versioned prompt resources.
It never registers a workflow, invokes a model, reads configuration/credentials,
activates a product profile or writes a file. Candidate digests describe local
bytes/JSON, not a remote registration, benchmark or conversion result.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path


_ROOT = Path(__file__).resolve().parent
_HEADERS = ("name", "description", "category", "icon")
_TYPES = ("chatInputComponent", "promptComponent", "llmStep", "chatOutputComponent")
_TEMPLATES = {
    "understanding": ("project-opaf-mapper-v2.json", "009e1bbd71a0ac53f268c6b63ad8ac5ec6b93d7b0bb591ff997bab6a58a69e7e"),
    "review": ("project-opaf-reviewer-v2.json", "7d79b2bc35e0dfc03b4fca3a24b7606108573e7ca3c07afec3c0b79ecbcc854c"),
}
_PROFILES = {
    "baseline43": ("JSNFOXG2Understandingv1Baseline43", "JSN Forms Converter 4.3", "understanding"),
    "candidate47": ("JSNFOXG2Understandingv1Candidate47", "JSN FOX Understanding 4.7 Candidate 20261105", "understanding"),
    "reviewer43": ("JSNFOXG2Understandingv1IndependentReview43", "JSN Forms Reviewer", "review"),
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _check_graph(graph: dict) -> None:
    """Require the observed four-node, three-edge tool-free dataflow shape."""
    if type(graph) is not dict or set(graph) != {"nodes", "edges"}:
        raise ValueError("Bundled graph shape changed.")
    nodes, edges = graph["nodes"], graph["edges"]
    if (type(nodes) is not list or type(edges) is not list
            or len(nodes) != 4 or len(edges) != 3
            or tuple(node["data"]["type"] for node in nodes) != _TYPES):
        raise ValueError("Bundled graph must remain a four-node tool-free chain.")
    if len({node["id"] for node in nodes}) != 4:
        raise ValueError("Bundled graph node identities changed.")
    for index, edge in enumerate(edges):
        source, target = nodes[index]["id"], nodes[index + 1]["id"]
        source_handle, target_handle = (
            ("user_provided_input", "request"), ("output", "prompt"), ("output", "message")
        )[index]
        if (edge["source"] != source or edge["target"] != target
                or edge["sourceHandle"] != source_handle + "-" + source
                or edge["targetHandle"] != target_handle + "-" + target
                or edge["data"] != {"sourceHandleId": source_handle, "targetHandleId": target_handle}):
            raise ValueError("Bundled graph edges changed.")


def _template(kind: str) -> tuple[dict, str]:
    name, expected = _TEMPLATES[kind]
    raw = (_ROOT / name).read_bytes()
    if _sha(raw) != expected:
        raise ValueError("Bundled graph template bytes changed.")
    document = json.loads(raw)
    if set(document) != {*_HEADERS, "data"}:
        raise ValueError("Bundled workflow header shape changed.")
    _check_graph(document["data"])
    return document, expected


def _prompt(kind: str) -> tuple[str, str]:
    filename = "forms-understanding-v1.txt" if kind == "understanding" else "forms-understanding-review-v1.txt"
    raw = (_ROOT / "prompts" / filename).read_bytes()
    prompt = raw.decode("utf-8")
    if not prompt.strip() or prompt.count("{{request}}") != 1:
        raise ValueError("Bundled prompt must contain exactly one request slot.")
    return prompt, _sha(raw)


def build_candidates() -> dict:
    """Return three additive header/graph candidates; perform no remote action.

    The two understanding candidates share the exact same prompt bytes and graph
    structure. Only node/edge identities, titles and LLM selection differ. Existing
    native workflows/profiles are neither read as configuration nor modified.
    Missing, modified or malformed resources fail before returning any candidates.
    """
    resources = {kind: (_template(kind), _prompt(kind)) for kind in _TEMPLATES}
    candidates = {}
    for key, (name, connection, kind) in _PROFILES.items():
        (template, template_sha), (prompt, prompt_sha) = resources[kind]
        graph = deepcopy(template["data"])
        old_ids = [node["id"] for node in graph["nodes"]]
        new_ids = ["g2-" + key + "-" + part for part in ("input", "prompt", "llm", "output")]
        replacements = dict(zip(old_ids, new_ids))
        for node, new_id, stage in zip(graph["nodes"], new_ids, ("request", "contract", "model", "JSON response")):
            node["id"] = new_id
            node["data"]["title"] = name + ": " + stage
            node["data"]["description"] = (
                "Versioned source-bound design role; no tools, execution, import, "
                "release or business-acceptance authority. Product activation controlled separately."
            )
        for index, edge in enumerate(graph["edges"]):
            edge["id"] = "g2-" + key + "-edge-" + str(index + 1)
            for endpoint in ("source", "target"):
                edge[endpoint] = replacements[edge[endpoint]]
                edge[endpoint + "Handle"] = edge["data"][endpoint + "HandleId"] + "-" + edge[endpoint]
        graph["nodes"][1]["data"]["template"]["prompt"]["value"] = prompt
        llm = graph["nodes"][2]["data"]["template"]
        llm["llmToUse"]["value"] = connection
        llm["temperature"]["value"] = 0
        _check_graph(graph)
        header = {field: template[field] for field in _HEADERS}
        header.update(name=name, description=(
            "Versioned G2 source-bound Forms understanding/review role. "
            "Tool-free, temperature zero; no execution, import, release or "
            "business-acceptance authority. Product activation controlled separately."
        ))
        candidates[key] = {
            "header": header, "graph": graph, "connection_name": connection,
            "source_template_sha256": template_sha, "prompt_sha256": prompt_sha,
            "header_sha256": _sha(_canonical(header)), "graph_sha256": _sha(_canonical(graph)),
        }
    return {"schema_version": 1, "scope": "fox-forms-understanding-candidates-v1",
            "profile_activation": False, "model_invocation": False, "candidates": candidates}
