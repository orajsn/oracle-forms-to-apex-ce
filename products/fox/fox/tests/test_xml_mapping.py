"""Original synthetic XML exercises real renderers; compiler doubles are labelled.

These tests establish no Oracle import, runtime behavior or business acceptance.
"""
from copy import deepcopy
import hashlib
from html import escape
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

from fox import xml_mapping as mapping
from fox.forms_native_plan import POLICY_ID
from fox.opaf import OpafError
from fox.prototype_export_only import _members, _zip


PRODUCT = Path(__file__).resolve().parents[2]
CLI = PRODUCT / "tools" / "generate_xml_apex.py"


def source(module="ORDER", block="LINES", formula="ROUND(:PRICE * :QUANTITY, 2)", extra=""):
    return (f'<FormModule Name="{module}"><Block Name="{block}" DatabaseBlock="true">'
        '<Item Name="PRICE" ItemType="Text Item" DataType="Number" DatabaseItem="true"/>'
        '<Item Name="QUANTITY" ItemType="Text Item" DataType="Number" DatabaseItem="true"/>'
        '<Item Name="TOTAL" ItemType="Display Item" DataType="Number" DatabaseItem="false"'
        + (f' Formula="{escape(formula, quote=True)}"' if formula is not None else '')
        + f'/>{extra}</Block></FormModule>').encode()


def docs(**kwargs):
    return [("order.xml", source(**kwargs))]


def generate(documents=None, **kwargs):
    return mapping.generate_xml_package(docs() if documents is None else documents,
        kwargs.pop("project_id", "xml-project"), kwargs.pop("project_name", "XML prototype"),
        kwargs.pop("approved_policy_id", POLICY_ID), **kwargs)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fake_validator(candidate, directory):
    """Author a synthetic retained log; never invoke a compiler or Oracle."""
    directory.mkdir(parents=True, exist_ok=True)
    log = b"SYNTHETIC TEST ONLY. NO SQLCL/ORACLE EXECUTION.\n" + sha(candidate).encode()
    digest = sha(log)
    (directory / f"offline-{digest}.log").write_bytes(log)
    return {"passed": True, "return_code": 0, "connection_mode": "/nolog",
            "sqlcl_version": "SYNTHETIC-TEST-ONLY", "validation_log_sha256": digest}


def test_deterministic_fresh_xml_uses_native_report_and_formula_without_parent_job():
    documents = docs()
    before = deepcopy(documents)
    candidate, report = generate(documents)
    assert (candidate, report) == generate(documents)
    assert documents == before
    files = _members(candidate)
    metadata = json.loads(files["fox-package/metadata.json"])
    assert metadata["origin"] == "deterministic_local_xml"
    assert metadata["ai_review"] == {"performed": False, "approval_recorded": False, "origin": "none"}
    assert not any("review" in name.lower() and name.endswith(".json") for name in files)
    assert metadata["application_count"] == 1
    assert metadata["native_apex_generated"] is True
    assert metadata["structural_only"] is False
    assert metadata["format_validated"] is False and metadata["validation"] is None
    assert all(metadata[key] is False for key in mapping._FALSE)
    assert files["fox-package/sources/order.xml"] == documents[0][1]
    plan = report["native_plan"]
    block = plan["rendering_spec"]["blocks"][0]
    assert block["native_component"] == "report"
    assert all(field["in_edit_form"] is False for field in block["fields"])
    operation = report["behavior_plan"]["operations"][0]
    assert operation["kind"] == "numeric_expression_report_column"
    apx = files[operation["target"]["report_file"]].decode()
    assert "round(" in apx and " * " in apx and "type: sqlQuery" in apx
    assert "automaticRowProcessing" not in apx
    assert report["renderer_receipt"]["plan_sha256"] == report["behavior_plan"]["plan_sha256"]
    assert report["candidate_sha256"] == sha(candidate)
    assert b"unsaved Forms buffer" in files["fox-package/README.md"]
    assert b"No AI reviews exist" in files["fox-package/behavior-README.md"]
    ledger = report["mapping_ledger"]
    assert len(ledger["objects"]) == plan["coverage"]["source_objects"]
    output = next(row for row in ledger["objects"] if row["target"] and row["target"].get("source_name") == "TOTAL")
    assert output["target"]["value_computation_implemented"] is True
    assert output["target"]["generated_behavior_operation_ids"] == [operation["operation_id"]]


def test_runtime_catalog_and_applied_rules_are_bound_to_actual_dispatch():
    candidate, report = generate()
    catalog = mapping.mapping_catalog()
    assert sha(mapping._bytes({key: value for key, value in catalog.items() if key != "catalog_sha256"})) == catalog["catalog_sha256"]
    assert report["metadata"]["catalog_sha256"] == catalog["catalog_sha256"]
    assert catalog["implementation_sources"]["xml_mapping.py"] == sha(Path(mapping.__file__).read_bytes())
    assert catalog["implementation_sources"]["forms2apex/numeric_expression.py"] == sha(Path(mapping.numeric_expression.__file__).read_bytes())
    assert catalog["implementation_sources"]["forms2apex/native_behavior.py"] == sha(Path(mapping.native_behavior.__file__).read_bytes())
    ledger = report["mapping_ledger"]
    applied = {row["rule_id"] for row in ledger["objects"] + ledger["code_units"]}
    assert set(report["metadata"]["applied_rule_ids"]) == applied
    assert applied <= {rule["id"] for rule in catalog["rules"]}
    assert all(row["rule_revision"] == 1 for row in ledger["objects"] + ledger["code_units"])
    catalog["rules"].clear()
    assert mapping.mapping_catalog()["rules"]
    assert json.loads(_members(candidate)["fox-package/mapping-ledger.json"]) == ledger


def test_renamed_forms_reuse_same_mappings_and_multiple_modules_share_one_app():
    a, report_a = generate()
    b, report_b = generate(docs(module="SHIPMENT", block="CARGO"))
    assert a != b and report_a["source_binding"] != report_b["source_binding"]
    assert report_a["metadata"]["applied_rule_ids"] == report_b["metadata"]["applied_rule_ids"]
    control = b'<FormModule Name="FILTERS"><Block Name="OPTIONS" DatabaseBlock="false"><Item Name="SEARCH" ItemType="Text Item" DataType="Char" DatabaseItem="false"/></Block></FormModule>'
    inputs = docs() + [("control.xml", control)]
    candidate, report = generate(inputs)
    assert (candidate, report) == generate(list(reversed(inputs)))
    assert len(report["native_plan"]["rendering_spec"]["blocks"]) == 2
    files = _members(candidate)
    assert sum(name == "application.apx" for name in files) == 1
    trace = json.loads(files["fox-package/source-to-page.json"])
    control_target = next(block for block in trace["blocks"] if block["classification"] == "control")
    assert control_target["table_name"] is None
    assert control_target["items"][0]["native_item"]
    assert "fox.xml.control-page-items" in report["metadata"]["applied_rule_ids"]


def test_structural_only_does_not_require_matching_code_and_preserves_unknown_unit():
    raw = source(formula=None, extra='<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="BEGIN UNKNOWN_API.RUN; COMMIT; END;"/>')
    candidate, report = generate([("plain.xml", raw)])
    assert report["metadata"]["structural_only"] is True
    assert report["renderer_receipt"] is None
    assert report["metadata"]["behavior_coverage"] == {"total": 1, "counts": {"unsupported": 1}}
    coverage = report["mapping_ledger"]["code_units"]
    assert len(coverage) == 1 and coverage[0]["rule_id"] == "fox.behavior.unresolved-unit"
    files = _members(candidate)
    assert files["fox-package/sources/plain.xml"] == raw
    assert all(b"UNKNOWN_API.RUN" not in content for name, content in files.items() if name.endswith(".apx"))
    assert any(row["code"] == "code_unit_not_translated" for row in report["metadata"]["omissions"])
    # Even no code units at all is a useful explicit structural candidate.
    _, empty = generate(docs(formula=None))
    assert empty["metadata"]["structural_only"] is True
    assert empty["metadata"]["behavior_coverage"] == {"total": 0, "counts": {}}


@pytest.mark.parametrize("raw", [b'<FormModule Name="EMPTY"/>',
    b'<FormModule Name="UNKNOWN"><Block Name="UNCERTAIN"><Item Name="X"/></Block></FormModule>',
    b'<FormModule Name="UNSAFE"><Block Name="DROP TABLE X" DatabaseBlock="true"/></FormModule>'])
def test_no_renderable_source_block_fails_clearly(raw):
    with pytest.raises(ValueError, match="No renderable source block"):
        generate([("empty.xml", raw)])


@pytest.mark.parametrize("bad_policy", [None, "", True, "automatic"])
def test_synthetic_scope_requires_exact_explicit_policy(bad_policy):
    with pytest.raises(ValueError, match="policy"):
        generate(approved_policy_id=bad_policy)


def test_existing_input_bounds_duplicate_sources_and_scope_collisions_rejected():
    with pytest.raises(ValueError, match="between 1 and 4"):
        generate([(f"f{i}.xml", source(module=f"F{i}")) for i in range(5)])
    with pytest.raises(ValueError, match="Duplicate source bytes"):
        generate(docs() + [("same.xml", source())])
    with pytest.raises(ValueError, match="Duplicate source filenames"):
        generate(docs() + [("ORDER.XML", source(module="OTHER"))])
    duplicate = source(extra='<Item Name="price" ItemType="Text Item" DataType="Number"/>')
    with pytest.raises(ValueError, match="Duplicate source block or item identity"):
        generate([("ambiguous.xml", duplicate)])


@pytest.mark.parametrize("formula", [":PRICE + (SELECT 1 FROM DUAL)", ":PRICE); DELETE FROM T; --", "EVIL(:PRICE)"])
def test_active_source_injection_never_enters_executable_apex(formula):
    candidate, report = generate(docs(formula=formula))
    assert report["metadata"]["structural_only"] is True
    assert report["metadata"]["behavior_coverage"]["counts"] == {"unsupported": 1}
    files = _members(candidate)
    assert all(formula.encode() not in content for name, content in files.items() if name.endswith(".apx"))


def test_sqlcl_adapter_is_called_with_exact_candidate_and_apex_bytes_are_unchanged(tmp_path):
    candidate, report = generate()
    seen = []
    def validator(raw, directory):
        seen.append(raw)
        return fake_validator(raw, directory)
    output, evidence = mapping.validate_xml_package(candidate, tmp_path, validator=validator)
    assert seen == [candidate]
    before, after = _members(candidate), _members(output)
    assert evidence["candidate_sha256"] == sha(candidate)
    assert evidence["package_sha256"] == sha(output)
    assert evidence["apex_members"] == report["apex_members"]
    assert all(after[name] == before[name] for name in evidence["apex_members"])
    assert {name for name in before if before[name] != after[name]} == {"fox-package/metadata.json"}
    assert set(after) - set(before) == {"fox-package/xml-validation.json"}
    metadata = json.loads(after["fox-package/metadata.json"])
    assert metadata["format_validated"] is True
    assert metadata["validation"]["sqlcl_version"] == "SYNTHETIC-TEST-ONLY"
    assert all(metadata[key] is False for key in mapping._FALSE)
    assert metadata["ai_review"]["performed"] is False


@pytest.mark.parametrize("mode", ["failed", "nonzero", "connected", "missing", "changed", "unknown"])
def test_failed_or_unretained_validation_cannot_publish(tmp_path, mode):
    candidate, _ = generate()
    def validator(raw, directory):
        result = fake_validator(raw, directory)
        log = directory / ("offline-" + result["validation_log_sha256"] + ".log")
        if mode == "failed": result["passed"] = False
        elif mode == "nonzero": result["return_code"] = 1
        elif mode == "connected": result["connection_mode"] = "connected"
        elif mode == "missing": log.unlink()
        elif mode == "changed": log.write_bytes(b"changed")
        elif mode == "unknown": return None
        return result
    with pytest.raises(OpafError):
        mapping.validate_xml_package(candidate, tmp_path, validator=validator)
    assert json.loads(_members(candidate)["fox-package/metadata.json"])["format_validated"] is False


@pytest.mark.parametrize("member", ["application.apx", "fox-package/sources/order.xml",
    "fox-package/mapping-ledger.json", "fox-package/metadata.json", "fox-package/source-manifest.json"])
def test_changed_candidate_source_content_or_metadata_rejected_before_compiler(tmp_path, member):
    candidate, _ = generate()
    files = _members(candidate)
    if member == "fox-package/metadata.json":
        meta = json.loads(files[member]); meta["ai_review"]["approval_recorded"] = True
        files[member] = mapping._bytes(meta)
    else:
        files[member] += b" "
    seen = []
    with pytest.raises(ValueError):
        mapping.validate_xml_package(_zip(files), tmp_path, validator=lambda *args: seen.append(args))
    assert seen == []


def test_compiler_evidence_cannot_be_rebound_to_different_candidate(tmp_path):
    candidate, _ = generate()
    validation = fake_validator(candidate, tmp_path)
    with pytest.raises(ValueError, match="another candidate"):
        mapping._seal_validated_xml_package(candidate,
            {"candidate_sha256": "0" * 64, "validation": validation}, tmp_path)


def test_cli_lists_runtime_catalog_without_generation_arguments():
    result = subprocess.run([sys.executable, str(CLI), "--list-mappings"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == mapping.mapping_catalog()


def test_cli_creates_one_package_for_repeated_xml_and_refuses_existing_output(tmp_path):
    a, b = tmp_path / "a.xml", tmp_path / "b.xml"
    a.write_bytes(source())
    b.write_bytes(source(module="STOCK", block="POSITION", formula="ABS(:PRICE - :QUANTITY)"))
    output = tmp_path / "out"
    command = [sys.executable, str(CLI), "--xml", str(a), "--xml", str(b),
        "--project-id", "cli-test", "--project-name", "CLI prototype",
        "--approved-policy-id", POLICY_ID, "--output", str(output)]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["status"] == "GENERATED_VALIDATION_PENDING"
    assert summary["behavior_coverage"] == {"total": 2, "counts": {"generated_wired_adapted": 2}}
    assert summary["provider_calls"] == summary["database_imports"] == 0
    assert summary["package_sha256"] is None
    files = {path.name: path.read_bytes() for path in output.iterdir()}
    again = subprocess.run(command, capture_output=True, text=True)
    assert again.returncode != 0 and "fresh create-only" in again.stderr
    assert {path.name: path.read_bytes() for path in output.iterdir()} == files


def test_public_examples_cover_general_formulas_guard_and_unresolved_external_call():
    inputs = [(name, (PRODUCT / "examples" / "xml-mapping" / name).read_bytes())
              for name in ("invoice.xml", "stock.xml")]
    _, report = generate(inputs)
    assert report["metadata"]["behavior_coverage"] == {"total": 5,
        "counts": {"generated_wired_adapted": 4, "unsupported": 1}}
    assert len(report["native_plan"]["rendering_spec"]["blocks"]) == 3
    assert sum(op["kind"] == "numeric_expression_report_column"
               for op in report["behavior_plan"]["operations"]) == 3


def test_cli_checks_file_bounds_before_reading_source_bytes(tmp_path, monkeypatch):
    namespace = runpy.run_path(str(CLI))
    path = tmp_path / "oversized.xml"
    with path.open("wb") as stream:
        stream.truncate(namespace["MAX_FILE_BYTES"] + 1)
    def forbidden_read(_):
        raise AssertionError("Oversized source must not be read")
    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    with pytest.raises(ValueError, match="source-byte limits"):
        namespace["main"](["--xml", str(path), "--project-id", "bounded", "--project-name", "Bounded",
            "--approved-policy-id", POLICY_ID, "--output", str(tmp_path / "out")])
    assert not (tmp_path / "out").exists()


def test_cli_failed_validation_retains_candidate_without_publishing_final(tmp_path, monkeypatch):
    namespace = runpy.run_path(str(CLI))
    path, output = tmp_path / "source.xml", tmp_path / "out"
    path.write_bytes(source())
    def fail_validation(candidate, directory):
        fake_validator(candidate, directory)
        raise OpafError("Synthetic compiler failure")
    monkeypatch.setitem(namespace["main"].__globals__, "validate_xml_package", fail_validation)
    with pytest.raises(OpafError, match="Synthetic compiler failure"):
        namespace["main"](["--xml", str(path), "--project-id", "failed", "--project-name", "Failed",
            "--approved-policy-id", POLICY_ID, "--output", str(output), "--validate-sqlcl"])
    assert (output / "candidate.zip").is_file()
    assert (output / "generation-report.json").is_file()
    assert not (output / "APEXlang-xml-package.zip").exists()
    assert not (output / "format-validation.json").exists()
    assert not (output / "result.json").exists()


def test_formula_only_package_reports_only_applicable_behavior_adaptations():
    _, report = generate(docs(formula="ROUND(:PRICE * :QUANTITY, 2)"))
    notes = report["behavior_plan"]["adaptations"]
    assert any("persisted synthetic rows" in value for value in notes)
    assert not any("Continue" in value or "MESSAGE" in value for value in notes)


def test_two_real_generator_modules_isolate_equal_named_helpers_and_controls():
    examples = Path(__file__).resolve().parents[2] / 'examples' / 'xml-mapping'
    documents = [(name, (examples/name).read_bytes()) for name in ('local_compare.xml','local_compare_second.xml')]
    candidate, report = generate(documents)
    assert report['metadata']['behavior_coverage'] == {'total':6,'counts':{'generated_wired_adapted':6}}
    assert report['gap_report']['not_yet_converted'] == 0
    operations=report['behavior_plan']['operations']
    assert len(operations)==4
    controls={b['page_item'] for op in operations for b in op.get('input_bindings',[]) if 'page_item' in b}
    assert len(controls)==2
    files=_members(candidate)
    sql='\n'.join(raw.decode() for name,raw in files.items() if name.endswith('.apx'))
    assert sql.count('button apply-control-values (') == 2
    assert "cast(('X') as varchar2(4000)) = cast(('X ') as varchar2(4000))" in sql
    assert all(':'+name in sql for name in controls)
    helper_rows=[r for r in report['mapping_ledger']['code_units'] if r['rule_id']=='fox.behavior.local-comparison-function-inlined']
    assert len(helper_rows)==2 and all(len(r['operation_ids'])==2 for r in helper_rows)


def test_gap_report_is_complete_and_never_blames_unknown_builtin_on_missing_source():
    from test_forms_behavior_plan import comparison_documents
    documents=comparison_documents(helper=False)
    documents=[(name,raw.replace(b'MATCH_TEXT(',b'INSTR(')) for name,raw in documents]
    _,report=generate(documents)
    assert report['gap_report']['not_yet_converted']==1
    assert report['gap_report']['summary']['missing_source']==0
    assert report['gap_report']['gaps'][0]['owner']=='FOX_ENGINE'
