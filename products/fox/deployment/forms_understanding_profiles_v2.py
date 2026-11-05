"""Build additive v2 understanding/review candidates without remote actions.

The original builder and its output remain unchanged. This adapter reuses its
pinned public templates and graph checks, but reads only v2 prompt resources
and creates distinct workflow/node/edge identities. Digests describe local
resources, not model quality, registration, activation or conversion evidence.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from deployment import forms_understanding_profiles as v1


_ROOT = Path(__file__).resolve().parent
_PROFILES = {
    "baseline43": ("JSNFOXG2Understandingv2Baseline43", "JSN Forms Converter 4.3", "understanding"),
    "candidate47": ("JSNFOXG2Understandingv2Candidate47", "JSN FOX Understanding 4.7 Candidate 20261105", "understanding"),
    "reviewer43": ("JSNFOXG2Understandingv2IndependentReview43", "JSN Forms Reviewer", "review"),
}


def _prompt(kind: str) -> tuple[str, str]:
    if kind not in ("understanding", "review"):
        raise ValueError("Unknown bundled prompt role.")
    filename = "forms-understanding-v2.txt" if kind == "understanding" else "forms-understanding-review-v2.txt"
    raw = (_ROOT / "prompts" / filename).read_bytes()
    prompt = raw.decode("utf-8")
    if not prompt.strip() or prompt.count("{{request}}") != 1:
        raise ValueError("Bundled prompt must contain exactly one request slot.")
    return prompt, v1._sha(raw)


def build_candidates() -> dict:
    """Return three inactive, tool-free v2 candidates from trusted resources.

    There are no caller-selected templates, prompts, versions or model paths.
    Both understanding roles use identical prompt bytes and graph shapes except
    for their identities, titles and the existing selected LLM connections.
    """
    resources = {kind: (v1._template(kind), _prompt(kind)) for kind in v1._TEMPLATES}
    candidates = {}
    for key, (name, connection, kind) in _PROFILES.items():
        (template, template_sha), (prompt, prompt_sha) = resources[kind]
        graph = deepcopy(template["data"])
        old_ids = [node["id"] for node in graph["nodes"]]
        new_ids = ["g2-v2-" + key + "-" + part for part in ("input", "prompt", "llm", "output")]
        replacements = dict(zip(old_ids, new_ids))
        for node, new_id, stage in zip(graph["nodes"], new_ids, ("request", "contract", "model", "JSON response")):
            node["id"] = new_id
            node["data"]["title"] = name + ": " + stage
            node["data"]["description"] = (
                "Versioned source-bound design role; no tools, execution, import, "
                "release or business-acceptance authority. Product activation controlled separately."
            )
        for index, edge in enumerate(graph["edges"]):
            edge["id"] = "g2-v2-" + key + "-edge-" + str(index + 1)
            for endpoint in ("source", "target"):
                edge[endpoint] = replacements[edge[endpoint]]
                edge[endpoint + "Handle"] = edge["data"][endpoint + "HandleId"] + "-" + edge[endpoint]
        graph["nodes"][1]["data"]["template"]["prompt"]["value"] = prompt
        llm = graph["nodes"][2]["data"]["template"]
        llm["llmToUse"]["value"] = connection
        llm["temperature"]["value"] = 0
        v1._check_graph(graph)
        header = {field: template[field] for field in v1._HEADERS}
        header.update(name=name, description=(
            "Versioned G2 source-bound Forms understanding/review role. "
            "Tool-free, temperature zero; no execution, import, release or "
            "business-acceptance authority. Product activation controlled separately."
        ))
        candidates[key] = {
            "header": header, "graph": graph, "connection_name": connection,
            "source_template_sha256": template_sha, "prompt_sha256": prompt_sha,
            "header_sha256": v1._sha(v1._canonical(header)),
            "graph_sha256": v1._sha(v1._canonical(graph)),
        }
    return {"schema_version": 1, "scope": "fox-forms-understanding-candidates-v2",
            "profile_activation": False, "model_invocation": False, "candidates": candidates}
