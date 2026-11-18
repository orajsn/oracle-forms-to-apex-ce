"""Sanitized executable-artifact checks; these do not claim APEX runtime proof."""
from copy import deepcopy
from decimal import Decimal
import hashlib
import io
import json
import re
import zipfile

import pytest

from forms2apex import native_behavior as renderer
from forms2apex import native_blueprint
from test_native_blueprint import spec


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def seal(plan):
    plan["plan_sha256"] = sha(canonical({k: v for k, v in plan.items() if k != "plan_sha256"}))
    return plan


def fixture():
    value = spec(12)
    for block in value["blocks"][:2]:
        block["native_component"] = "report"
        for field in block["fields"]:
            field["in_edit_form"] = False
    # Same-block NUMBER operands; the output starts outside the default eight.
    value["blocks"][0]["fields"][10]["data_type"] = "NUMBER"
    value["blocks"][0]["fields"][10]["widget"] = "number"
    files = {name: text.encode() for name, text in native_blueprint.render_native_blueprint(value).items()}
    trace = native_blueprint.prototype_trace(value)
    manifest = {"source_binding": value["source_binding"],
                "files": [{"name": "sanitized.xml", "sha256": "b" * 64, "bytes": 42}],
                "selected_chunk_hashes": {"chunk-ceil": "c" * 64, "chunk-numeric": "d" * 64,
                                          "chunk-unsupported": "e" * 64}}
    files["fox-package/source-manifest.json"] = canonical(manifest)
    files["fox-package/source-to-page.json"] = canonical(trace)
    files["fox-package/supporting-schema.sql"] = native_blueprint.render_prototype_schema(value).encode()
    files["fox-package/metadata.json"] = b'{"validation":{"passed":true},"historical":true}'
    files["fox-package/original-review.json"] = b'{"approved":true,"unchanged":true}'
    raw = pack(files)
    plan = {"schema_version": 1, "scope": renderer.SCOPE, "source_binding": value["source_binding"],
            "parent_zip_sha256": sha(raw), "source_manifest_sha256": sha(files["fox-package/source-manifest.json"]),
            "parent_trace_sha256": sha(files["fox-package/source-to-page.json"]), "sources": manifest["files"],
            "native_generated": False, "runtime_verified": False, "business_accepted": False,
            "code_unit_count": 3, "adaptations": [], "remaining_scope": "Other units remain unsupported.",
            "coverage": [], "operations": []}
    for index, kind, digest in ((0, "ceil_report_column", "c"), (1, "numeric_nonzero_then_focus", "d")):
        block = trace["blocks"][index]
        field = block["items"][10 if index == 0 else 1]
        source = block["items"][1 if index == 0 else 0]
        op = {"operation_id": f"op-{index}", "kind": kind, "source_unit_id": f"unit-{index}",
              "source_chunk_id": "chunk-ceil" if index == 0 else "chunk-numeric",
              "source_unit_sha256": digest * 64, "source_block_id": block["source_block_id"],
              "source_item_id": field["source_item_id"], "decode_receipt": {},
              "target": {"table": block["table_name"], "report_file": block["report_file"],
                         "report_page_id": block["report_page_id"]}}
        if index == 0:
            op["input_source_item_id"] = source["source_item_id"]
            op["target"].update(input_column=source["column"], output_column=field["column"])
        else:
            op.update(focus_source_item_id=source["source_item_id"], message="A nonzero value is required!",
                      message_call_count=2, minimum="1")
            op["target"].update(row_id_column=block["synthetic_key"]["column"], value_column=field["column"],
                                focus_column=source["column"], value_data_type="NUMBER", focus_data_type="VARCHAR2")
        plan["operations"].append(op)
        plan["coverage"].append({"source_unit_id": op["source_unit_id"], "source_unit_sha256": digest * 64,
                                 "source_chunk_id": "chunk-ceil" if index == 0 else "chunk-numeric",
                                 "operation_id": op["operation_id"], "runtime_verified": False, "business_accepted": False,
                                 "status": "planned_wired_adapted"})
    plan["coverage"].append({"source_unit_id": "unit-unsupported", "source_unit_sha256": "e" * 64,
                             "source_chunk_id": "chunk-unsupported", "status": "unsupported"})
    plan["coverage"][-1].update(runtime_verified=False, business_accepted=False)
    return raw, seal(plan), files


def pack(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.comment = b"preserved-parent-comment"
        for name, data in files.items():
            archive.writestr(name, data)
    return stream.getvalue()


def unpack(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_deterministic_immutable_parent_and_unrelated_originals_are_preserved():
    parent, plan, original = fixture()
    before = deepcopy(plan)
    result, receipt = renderer.render_behavior_package(parent, plan)
    assert renderer.render_behavior_package(parent, plan) == (result, receipt)
    assert plan == before
    files = unpack(result)
    assert set(original) <= set(files)
    assert {name for name in original if original[name] != files[name]} == set(receipt["changed_members"])
    assert receipt["changed_members"] == sorted(op["target"]["report_file"] for op in plan["operations"])
    for name in ("fox-package/source-manifest.json", "fox-package/source-to-page.json",
                 "fox-package/supporting-schema.sql", "fox-package/metadata.json", "fox-package/original-review.json"):
        assert files[name] == original[name]
    assert sum(bool(re.search(rb"^app ", data, re.M)) for data in files.values()) == 1
    with zipfile.ZipFile(io.BytesIO(result)) as archive:
        assert archive.comment == b"preserved-parent-comment"
    assert receipt["output_zip_sha256"] == sha(result)
    assert receipt["plan_sha256"] == plan["plan_sha256"]
    assert receipt["plan_artifact_sha256"] == sha(canonical(plan))
    assert receipt["plan_artifact_sha256"] != receipt["plan_sha256"]
    assert receipt["validation"] == {"status": "pending", "passed": False, "parent_validation_applies": False}
    assert receipt["runtime_verified"] is receipt["business_accepted"] is False
    assert [row["status"] for row in receipt["coverage"]] == ["generated_wired_adapted", "generated_wired_adapted", "unsupported"]
    assert plan["coverage"][0]["status"] == "planned_wired_adapted"


def test_ceil_replaces_only_output_projection_and_exposes_default_column():
    parent, plan, _ = fixture()
    result, _ = renderer.render_behavior_package(parent, plan)
    target = plan["operations"][0]["target"]
    page = unpack(result)[target["report_file"]].decode()
    assert "type: sqlQuery" in page and "tableName:" not in page
    assert f"ceil({target['input_column']}) as {target['output_column']}" in page
    assert f"from {target['table']}" in page
    assert f"            displayColumn {target['output_column']} (" in page
    assert page.count("ceil(") == 1
    assert "insert " not in page.lower()


def test_linked_validation_page_initializes_actual_bound_items_without_dml():
    parent, plan, _ = fixture()
    result, receipt = renderer.render_behavior_package(parent, plan)
    files = unpack(result)
    op = plan["operations"][1]
    target = op["target"]
    generated = receipt["generated_operations"][1]
    report = files[target["report_file"]].decode()
    page = files[generated["page_file"]].decode()
    pid = generated["page_id"]
    assert f'P{pid}_{target["row_id_column"]}: "#{target["row_id_column"]}#"' in report
    assert f"clearCache: {pid}" in report
    assert f"tableName: {target['table']}" in page
    assert "type: formInitialization" in page
    assert "type: numberField" in page and "type: textField" in page
    assert f"column: {target['value_column']}\n            dataType: number" in page
    assert f"nvl(:P{pid}_{target['value_column']}, 0) <> 0" in page
    assert f"nvl(:P{pid}_{target['value_column']}, 0) = 0 or :P{pid}_{target['value_column']} >= 1" in page
    trace = json.loads(files["fox-package/source-to-page.json"])
    fields = next(block["items"] for block in trace["blocks"] if block["source_block_id"] == op["source_block_id"])
    for identity in (op["source_item_id"], op["focus_source_item_id"]):
        source_name = next(field["source_name"] for field in fields if field["source_item_id"] == identity)
        assert f"label: {json.dumps(source_name)}" in page
    assert page.count("type: functionBodyReturningBoolean") == 2
    assert page.count("errorMessage:") == 2
    assert "whenButtonPressed: @continue" in page
    assert f'apex.item("P{pid}_{target["focus_column"]}").setFocus();' in page
    assert "point: processing" in page
    assert "sessionStateProtection: checksumRequiredSessionLevel" in page
    assert "authentication: required" in page
    assert "Values are not saved" in page
    for forbidden in ("formAutoRowProcessing", "databaseAction:", "commit;", "insert into", "update ", "delete from"):
        assert forbidden not in page


def test_optional_minimum_is_independent_from_nonzero_rule():
    parent, plan, _ = fixture()
    plan["operations"][1]["minimum"] = None
    result, receipt = renderer.render_behavior_package(parent, seal(plan))
    page = unpack(result)[receipt["added_pages"][0]].decode()
    assert "validation nonzero" in page
    assert "validation source-minimum" not in page
    assert " >= " not in page


@pytest.mark.parametrize("value,expected_errors", [
    (None, ["nonzero"]), (Decimal("0"), ["nonzero"]),
    (Decimal("-1"), ["source-minimum"]), (Decimal("0.5"), ["source-minimum"]),
    (Decimal("1"), []),
])
def test_exact_generated_predicates_partition_null_zero_and_minimum_errors(value, expected_errors):
    """Evaluate only the two exact emitted finite forms; not an Oracle runtime test."""
    parent, plan, _ = fixture()
    result, receipt = renderer.render_behavior_package(parent, plan)
    generated = receipt["generated_operations"][1]
    page = unpack(result)[generated["page_file"]].decode()
    item = generated["value_item"]
    predicates = re.findall(r"validation (nonzero|source-minimum) \(.*?return ([^;]+);", page, re.S)
    assert predicates == [("nonzero", f"nvl(:{item}, 0) <> 0"),
                          ("source-minimum", f"nvl(:{item}, 0) = 0 or :{item} >= 1")]
    # Bind Decimal test values to the exact emitted comparisons. These finite
    # forms cannot encounter SQL NULL ambiguity because NVL owns the first term.
    substituted = Decimal(0) if value is None else value
    errors = []
    for name, expression in predicates:
        if expression == f"nvl(:{item}, 0) <> 0":
            passed = substituted != 0
        elif expression == f"nvl(:{item}, 0) = 0 or :{item} >= 1":
            passed = substituted == 0 or value >= Decimal(1)
        else:
            raise AssertionError("Unexpected generated predicate")
        if not passed:
            errors.append(name)
    assert errors == expected_errors


@pytest.mark.parametrize("source_name,accepted", [
    ('WEIGHT "INPUT"', True), ("&APP_USER.", False), ("<script>", False), ("NAME\nCODE", False),
])
def test_source_labels_use_existing_safe_quoted_display_contract(source_name, accepted):
    _, plan, files = fixture()
    trace = json.loads(files["fox-package/source-to-page.json"])
    trace["blocks"][1]["items"][1]["source_name"] = source_name
    files["fox-package/source-to-page.json"] = canonical(trace)
    parent = pack(files)
    plan.update(parent_zip_sha256=sha(parent), parent_trace_sha256=sha(files["fox-package/source-to-page.json"]))
    if accepted:
        result, receipt = renderer.render_behavior_package(parent, seal(plan))
        page = unpack(result)[receipt["added_pages"][0]].decode()
        assert f"label: {json.dumps(source_name)}" in page
    else:
        with pytest.raises(ValueError, match="BEHAVIOR_SOURCE_LABEL_INVALID"):
            renderer.render_behavior_package(parent, seal(plan))


@pytest.mark.parametrize("mutate,code", [
    (lambda p: p.update(parent_zip_sha256="f" * 64), "PARENT_HASH_MISMATCH"),
    (lambda p: p.update(parent_trace_sha256="f" * 64), "PARENT_BINDING_MISMATCH"),
    (lambda p: p.update(source_binding="f" * 64), "SOURCE_BINDING_MISMATCH"),
    (lambda p: p.update(runtime_verified=True), "UNVERIFIED_SCOPE_REQUIRED"),
    (lambda p: p["operations"][0].update(kind="raw_plsql"), "OPERATION_FIELDS_INVALID"),
    (lambda p: p["operations"][0].update(plsql="commit;"), "OPERATION_FIELDS_INVALID"),
    (lambda p: p["operations"][0]["target"].update(table="OTHER_TABLE"), "TARGET_BINDING_MISMATCH"),
    (lambda p: p["operations"][0]["target"].update(input_column="FAKE_COLUMN"), "CEIL_BINDING_MISMATCH"),
    (lambda p: p["operations"][1]["target"].update(value_data_type="VARCHAR2"), "NUMERIC_BINDING_MISMATCH"),
    (lambda p: p["operations"][1].update(minimum="1; commit;"), "MINIMUM_INVALID"),
    (lambda p: p["operations"][1].update(message="&APP_USER."), "MESSAGE_INVALID"),
    (lambda p: p["operations"][1].update(message="```plsql"), "MESSAGE_INVALID"),
    (lambda p: p["operations"][1].update(message_call_count=True), "MESSAGE_COUNT_INVALID"),
    (lambda p: p["operations"].append(deepcopy(p["operations"][0])), "OPERATION_COLLISION"),
])
def test_finite_contract_and_exact_bindings_fail_closed(mutate, code):
    parent, plan, _ = fixture()
    mutate(plan)
    with pytest.raises(renderer.BehaviorRenderError, match=code):
        renderer.render_behavior_package(parent, seal(plan))


def test_plan_digest_and_parent_payload_tampering_fail_closed():
    parent, plan, files = fixture()
    plan["operations"][1]["minimum"] = "2"
    with pytest.raises(renderer.BehaviorRenderError, match="PLAN_HASH_MISMATCH"):
        renderer.render_behavior_package(parent, plan)
    files["application.apx"] += b"\n-- changed\n"
    with pytest.raises(renderer.BehaviorRenderError, match="PARENT_HASH_MISMATCH"):
        renderer.render_behavior_package(pack(files), seal(plan))


def test_ambiguous_archive_and_already_adapted_parent_fail_closed():
    parent, plan, files = fixture()
    files["APPLICATION.APX"] = files["application.apx"]
    with pytest.raises(renderer.BehaviorRenderError, match="DUPLICATE_MEMBER"):
        renderer.render_behavior_package(pack(files), plan)
    result, _ = renderer.render_behavior_package(parent, plan)
    with pytest.raises(renderer.BehaviorRenderError, match="ALREADY_ADAPTED"):
        renderer.render_behavior_package(result, plan)


@pytest.mark.parametrize("mutation,code", [
    (lambda p: p["coverage"].pop(), "COVERAGE_COUNT_MISMATCH"),
    (lambda p: p["coverage"][0].update(source_unit_sha256="f" * 64), "COVERAGE_CHUNK_MISMATCH"),
    (lambda p: p["coverage"][0].update(runtime_verified=True), "COVERAGE_STATUS_INVALID"),
    (lambda p: p["coverage"][0].update(status="unsupported"), "SOURCE_UNIT_HASH_MISMATCH"),
    (lambda p: p["operations"][0].update(source_chunk_id="chunk-unsupported"), "SOURCE_UNIT_HASH_MISMATCH"),
])
def test_coverage_cannot_hide_omit_or_promote_units(mutation, code):
    parent, plan, _ = fixture()
    mutation(plan)
    with pytest.raises(renderer.BehaviorRenderError, match=code):
        renderer.render_behavior_package(parent, seal(plan))


def test_same_report_composes_validation_link_and_computed_column():
    parent, plan, original = fixture()
    trace = json.loads(original["fox-package/source-to-page.json"])
    block = trace["blocks"][0]
    op = plan["operations"][1]
    op.update(source_block_id=block["source_block_id"], source_item_id=block["items"][1]["source_item_id"],
              focus_source_item_id=block["items"][0]["source_item_id"])
    op["target"].update(table=block["table_name"], report_file=block["report_file"],
                        report_page_id=block["report_page_id"], value_column=block["items"][1]["column"],
                        focus_column=block["items"][0]["column"])
    result, receipt = renderer.render_behavior_package(parent, seal(plan))
    page = unpack(result)[block["report_file"]].decode()
    assert "linkColumn: customTarget" in page
    assert "type: sqlQuery" in page
    assert page.count("ceil(") == 1
    assert receipt["changed_members"] == [block["report_file"]]


def test_unselected_source_units_remain_visible_without_authorizing_operations():
    parent, plan, _ = fixture()
    plan["coverage"].append({"source_unit_id": "outside-parent-selection", "source_chunk_id": "unselected-chunk",
        "source_unit_sha256": "f" * 64, "status": "missing_input", "runtime_verified": False, "business_accepted": False})
    plan["code_unit_count"] += 1
    _, receipt = renderer.render_behavior_package(parent, seal(plan))
    assert receipt["coverage"][-1]["status"] == "missing_input"
