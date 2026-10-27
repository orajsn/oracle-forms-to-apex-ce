"""Create-only mapped-v2 fixtures from original synthetic ordinary-name sources.

Uses existing source builders, the actual planner and the neutral planner mirror.
Requires exact frozen-vector agreement before rendering or writing any output.
No SQLcl, model, database, network or import operation is provided here.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "converter", ROOT / "fox", ROOT / "fox/tests"):
    sys.path.insert(0, str(path))

from fox import intake, project_conversion as planner
from fox_source_contract import project_conversion as mirror
from forms2apex import native_project
from test_project_conversion import ddl, module, source, xml
from test_project_storage_mapping import ordinary_pair


VECTOR = ROOT / "work/source-storage-contract-20261025a.json"
VECTOR_SHA = "38894bfb346b555023b7bc860771bb5f93d4537bc3155675dc10a27cdda99567"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def source_records(case):
    if case == "ordinary":
        return ordinary_pair() + ordinary_pair("BETA", "STATUS_LOG")
    if case == "shared":
        return [source("a.xml", xml(module("ALPHA", "WORK_ITEMS", "First label"))),
                source("b.xml", xml(module("BETA", "WORK_ITEMS", "Second label"))),
                source("table.sql", ddl("WORK_ITEMS"))]
    raise ValueError("Unknown frozen fixture case")


def producer_hashes():
    paths = [Path(__file__), VECTOR,
             ROOT / "fox/tests/test_project_conversion.py",
             ROOT / "fox/tests/test_project_storage_mapping.py",
             ROOT / "fox/fox/project_conversion.py", ROOT / "fox/fox/native_source.py",
             ROOT / "fox/fox/intake.py", ROOT / "converter/forms2apex/native_project.py",
             ROOT / "converter/fox_source_contract/project_conversion.py",
             ROOT / "converter/fox_source_contract/native_source.py",
             ROOT / "converter/fox_source_contract/intake.py",
             ROOT / "converter/fox_source_contract/source-manifest.json"]
    return {path.relative_to(ROOT).as_posix(): digest(path.read_bytes()) for path in paths}


def build(case, name):
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,39}", name), "Use a simple new fixture name")
    output = ROOT / "converter/tests/fixtures/project_v2" / name
    require(output.parent.is_dir() and not output.exists() and not output.is_symlink(),
            "Keep existing evidence and select a new fixture name")
    vector_raw = VECTOR.read_bytes()
    require(digest(vector_raw) == VECTOR_SHA, "Frozen vector bytes changed")
    expected = json.loads(vector_raw)["cases"][case]
    producers = producer_hashes()
    records = source_records(case)
    original_records = deepcopy(records)
    original_bytes = {}
    for record in records:
        raw = record["text"].encode("utf-8")
        require(digest(raw) == record["sha256"] and len(raw) == record["bytes"],
                "Original source bytes do not match their exact checked-source identity")
        require(b"FOX_NATIVE_" not in raw, "Fixture must begin with ordinary-name source bytes")
        original_bytes[record["name"]] = raw
    source_hash = intake.inventory(records)["source_hash"]
    options = {"project_id": expected["rendering_spec"]["project_id"],
               "project_name": expected["rendering_spec"]["project_name"],
               "source_hash": source_hash}
    plan = planner.assess_project_conversion(records, **options)
    require(plan == mirror.assess_project_conversion(records, **options),
            "Actual and neutral-mirror planners disagree")
    require(plan["state"] == "READY" and plan["can_generate"] is True,
            "Complete ordinary-name source case is not READY")
    require(plan["plan_sha256"] == expected["plan_sha256"]
            and plan["rendering_spec"] == expected["rendering_spec"],
            "Actual planner output differs from the frozen vector")
    bindings = [planner.module_execution_binding(plan, parent_job_id="fox-" + "a" * 20,
                                                module_id=form["module_id"])
                for form in plan["forms"]]
    require(bindings == expected["module_bindings"], "Actual module bindings differ from frozen vector")
    require(records == original_records, "Planner changed original source records")
    spec = plan["rendering_spec"]
    require(spec["schema_version"] == 2, "Mapped renderer spec v2 required")
    for form in spec["forms"]:
        require(digest(original_bytes[form["source_name"]]) == form["source_sha256"],
                "Original form source identity changed")
        require(all(digest(original_bytes[ref["name"]]) == ref["sha256"]
                    for ref in form["ddl_sources"]), "Original DDL source identity changed")
    files = {"sources/" + filename: raw for filename, raw in original_bytes.items()}
    files.update({"apexlang/" + filename: text.encode("utf-8")
                  for filename, text in native_project.render_native_project(spec).items()})
    files["native-project-spec.json"] = canonical(spec)
    trace = native_project.project_trace(spec)
    files["source-to-apex.json"] = canonical(trace)
    files["source-plan.json"] = canonical(plan)
    files["module-bindings.json"] = canonical(bindings)
    files["synthetic-schema.sql"] = native_project.render_project_schema(spec).encode("utf-8")
    files["native-project-apexlang.zip"] = native_project.deterministic_project_zip(spec)
    files["source-byte-evidence.json"] = canonical({
        "scope": "fox-original-source-byte-preservation-v1", "synthetic_only": True,
        "source_hash": source_hash, "source_records_unchanged": records == original_records,
        "sources": [{"name": name, "sha256": digest(raw), "bytes": len(raw)}
                    for name, raw in sorted(original_bytes.items())]})
    files["frozen-vector-check.json"] = canonical({
        "scope": "fox-source-storage-frozen-vector-check-v1", "case": case,
        "vector_sha256": VECTOR_SHA, "actual_plan_sha256": plan["plan_sha256"],
        "actual_plan_matches_frozen_vector": True, "neutral_mirror_matches_actual_planner": True,
        "module_bindings_match_frozen_vector": True, "producer_sha256": producers})
    manifest = {"schema_version": 1, "scope": "fox-mapped-v2-original-source-fixture-v1",
        "synthetic_only": True, "case": case, "rendering_spec_schema_version": 2,
        "source_manifest_sha256": source_hash, "actual_plan_sha256": plan["plan_sha256"],
        "frozen_vector_sha256": VECTOR_SHA, "original_source_bytes_preserved": True,
        "application_count": 1, "form_count": len(spec["forms"]), "table_count": len(trace["tables"]),
        "renderer_context": native_project.context(), "producer_sha256": producers,
        "sqlcl_validated": False, "imported": False, "runtime_verified": False,
        "human_acceptance_recorded": False,
        "files": {name: digest(raw) for name, raw in sorted(files.items())}}
    require(producer_hashes() == producers, "Producer changed before fixture freeze")
    output.mkdir(mode=0o700)
    for filename, raw in sorted(files.items()):
        path = output / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    raw_manifest = canonical(manifest)
    with (output / "manifest.json").open("xb") as stream:
        stream.write(raw_manifest)
    require(all((output / name).read_bytes() == raw for name, raw in files.items()),
            "Saved fixture bytes differ from frozen output")
    return {"output": str(output), "case": case, "manifest_sha256": digest(raw_manifest),
            "source_manifest_sha256": source_hash, "actual_plan_sha256": plan["plan_sha256"],
            "form_count": len(spec["forms"]), "table_count": len(trace["tables"]),
            "original_source_bytes_preserved": True, "frozen_vector_checked": True,
            "sqlcl_validated": False, "file_count": len(files) + 1}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, choices=("ordinary", "shared"))
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.case, args.name), sort_keys=True))
