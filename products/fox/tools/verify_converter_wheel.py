"""Build or recheck a converter wheel using already-installed, offline tools.

This creates a fresh evidence directory, never installs into an environment,
never downloads dependencies, and never calls a database, SQLcl, or cloud API.
The probe extracts the real wheel and copies only the existing defusedxml
dependency into isolation. It tests ProjectWorkflow import and deterministic
v1/v2 two-form rendering, not FastMCP server startup or live APEX compatibility.
"""
from __future__ import annotations

import argparse
import ast
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import zipfile


PACKAGES = ("forms2apex", "fox_source_contract")
DEPENDENCIES = {"fastmcp==3.4.4", "oci==2.188.0", "defusedxml==0.7.1"}
REQUIRES_PYTHON = ">=3.10"
MINIMUM_PYTHON = (3, 10)
CONTRACT_MODULES = ("intake.py", "native_source.py", "project_conversion.py")
HIDDEN_RESOURCES = {
    "forms2apex/templates/native-table-v1/.apex/apexlang.json",
    "forms2apex/templates/starter/.apex/apexlang.json",
}


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def source_python_requirement(pyproject):
    """Read the existing simple scalar without requiring Python 3.11 tomllib."""
    section, values = None, []
    for line in pyproject.decode("utf-8").splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.split("#", 1)[0].strip()
        elif section == "[project]":
            key, separator, value = line.partition("=")
            if separator and key.strip() == "requires-python":
                try:
                    values.append(ast.literal_eval(value.strip()))
                except (ValueError, SyntaxError):
                    raise ValueError("SOURCE_REQUIRES_PYTHON_CONTRACT_MISMATCH") from None
    if values != [REQUIRES_PYTHON]:
        raise ValueError("SOURCE_REQUIRES_PYTHON_CONTRACT_MISMATCH")
    return values[0]


def source_inventory(converter):
    """The wheel must include exactly the current package code and resources."""
    inventory = {}
    for package in PACKAGES:
        root = converter / package
        if not root.is_dir():
            raise ValueError("PACKAGE_SOURCE_MISSING")
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError("LINKED_PACKAGE_SOURCE")
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            name = path.relative_to(converter).as_posix()
            if path.suffix == ".py" or name.startswith("forms2apex/templates/") or name == "fox_source_contract/source-manifest.json":
                inventory[name] = path.read_bytes()
    if not HIDDEN_RESOURCES <= inventory.keys():
        raise ValueError("HIDDEN_APEX_RESOURCE_MISSING_FROM_SOURCE")
    return inventory


def verify_wheel(wheel, expected, *, tested_python=None):
    """Check exact payload, metadata, and the wheel's complete RECORD hashes."""
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("DUPLICATE_WHEEL_MEMBER")
        for info in infos:
            path = PurePosixPath(info.filename)
            if (info.orig_filename != info.filename
                    or path.is_absolute() or ".." in path.parts or "\\" in info.filename
                    or ":" in info.filename or info.is_dir()
                    or (info.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("UNSAFE_WHEEL_MEMBER")
        files = {name: archive.read(name) for name in names}
    actual = {name: raw for name, raw in files.items() if name.split("/", 1)[0] in PACKAGES}
    if not HIDDEN_RESOURCES <= actual.keys():
        raise ValueError("HIDDEN_APEX_RESOURCE_MISSING_FROM_WHEEL")
    if actual.keys() != expected.keys():
        raise ValueError("WHEEL_PACKAGE_INVENTORY_MISMATCH")
    if any(actual[name] != expected[name] for name in expected):
        raise ValueError("WHEEL_PACKAGE_CONTENT_MISMATCH")
    metadata_names = [name for name in files if name.endswith(".dist-info/METADATA")]
    if len(metadata_names) != 1:
        raise ValueError("WHEEL_METADATA_MISSING_OR_AMBIGUOUS")
    metadata_name = metadata_names[0]
    metadata_root = metadata_name.rsplit("/", 1)[0]
    if any(name.split("/", 1)[0] not in {*PACKAGES, metadata_root} for name in files):
        raise ValueError("UNEXPECTED_WHEEL_PACKAGE")
    metadata = BytesParser().parsebytes(files[metadata_name])
    dependencies = metadata.get_all("Requires-Dist", [])
    if (metadata["Name"] != "jsn-forms2apex-converter" or metadata["Version"] != "0.1.0"
            or set(dependencies) != DEPENDENCIES or len(dependencies) != len(DEPENDENCIES)):
        raise ValueError("WHEEL_METADATA_CONTRACT_MISMATCH")
    if metadata.get_all("Requires-Python", []) != [REQUIRES_PYTHON]:
        raise ValueError("WHEEL_REQUIRES_PYTHON_MISMATCH")
    tested_python = tuple(sys.version_info[:3] if tested_python is None else tested_python)
    if (len(tested_python) != 3 or any(type(value) is not int for value in tested_python)
            or tested_python[0] != 3 or tested_python[:2] < MINIMUM_PYTHON):
        raise ValueError("TESTED_PYTHON_VERSION_UNSUPPORTED")
    wheel_metadata_name = metadata_root + "/WHEEL"
    if wheel_metadata_name not in files:
        raise ValueError("WHEEL_COMPATIBILITY_METADATA_MISSING")
    wheel_metadata = BytesParser().parsebytes(files[wheel_metadata_name])
    # This artifact is deliberately a pure-Python, Python-3 universal wheel.
    # A syntactically valid RECORD does not establish installer compatibility.
    if (wheel_metadata.defects
            or wheel_metadata.get_all("Wheel-Version", []) != ["1.0"]
            or wheel_metadata.get_all("Root-Is-Purelib", []) != ["true"]
            or wheel_metadata.get_all("Tag", []) != ["py3-none-any"]):
        raise ValueError("WHEEL_COMPATIBILITY_METADATA_UNSUPPORTED")
    record_name = metadata_root + "/RECORD"
    rows = list(csv.reader(io.StringIO(files[record_name].decode("utf-8"))))
    if len(rows) != len(files) or any(len(row) != 3 for row in rows) or {row[0] for row in rows} != files.keys():
        raise ValueError("WHEEL_RECORD_INVENTORY_MISMATCH")
    for name, digest, size in rows:
        if name == record_name:
            if digest or size:
                raise ValueError("WHEEL_RECORD_SELF_HASH_INVALID")
        else:
            wanted = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(files[name]).digest()).decode().rstrip("=")
            if digest != wanted or size != str(len(files[name])):
                raise ValueError("WHEEL_RECORD_CONTENT_MISMATCH")
    manifest = json.loads(files["fox_source_contract/source-manifest.json"])
    if manifest["transformation"] != "none-byte-for-byte" or manifest["package"] != "fox_source_contract":
        raise ValueError("SOURCE_MIRROR_METADATA_MISMATCH")
    for record in [*manifest["files"], manifest["initializer"]]:
        raw = files["fox_source_contract/" + record["path"]]
        if record["sha256"] != sha256(raw) or record["bytes"] != len(raw):
            raise ValueError("SOURCE_MIRROR_HASH_MISMATCH")
    return {
        "name": metadata["Name"], "version": metadata["Version"],
        "requires_python": metadata["Requires-Python"], "requires_dist": sorted(dependencies),
        "tested_python": list(tested_python), "interpreter_compatible": True,
        "wheel_compatibility": {"wheel_version": "1.0", "root_is_purelib": True, "tags": ["py3-none-any"]},
        "wheel_sha256": sha256(Path(wheel).read_bytes()), "wheel_bytes": Path(wheel).stat().st_size,
        "members": [{"path": name, "bytes": len(raw), "sha256": sha256(raw)} for name, raw in sorted(files.items())],
        "package_file_count": len(actual),
        "template_file_count": sum(name.startswith("forms2apex/templates/") for name in actual),
        "hidden_apex_resources": sorted(HIDDEN_RESOURCES),
        "record_integrity": "PASS", "mirror_integrity": "PASS",
    }


PROBE = r'''
from copy import deepcopy
import hashlib, importlib.metadata, io, json, pathlib, re, sys, zipfile
installed, dependencies, development, output = map(pathlib.Path, sys.argv[1:])
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
sys.path[:0] = [str(installed), str(dependencies)]
def forbid_external(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn"}:
        raise RuntimeError("EXTERNAL_SIDE_EFFECT_FORBIDDEN: " + event)
sys.addaudithook(forbid_external)
from forms2apex.project_workflow import ProjectWorkflow
from forms2apex import native, native_project, project_source
from fox_source_contract.intake import checked_source, inventory
from fox_source_contract.project_conversion import assess_project_conversion
assert importlib.metadata.version("defusedxml") == "0.7.1"

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def render_case(version, destination):
    project_id = "isolated-wheel-proof" if version == 1 else "isolated-wheel-mapped-proof"
    originals = {}
    source_tables = {}
    for index, name in enumerate(("ALPHA", "BETA") if version == 1 else ("CUSTOMERS", "ORDERS")):
        table = "FOX_NATIVE_" + name if version == 1 else name
        source_tables[name.lower() + ".xml"] = table
        # v2 deliberately retains original ordinary names, CRLF and one BOM.
        # These bytes are never rewritten to satisfy the native target contract.
        newline = "\n" if version == 1 else "\r\n"
        xml = (f'<FormModule Name="{name}"><Block Name="MAIN" QueryDataSourceName="{table}">'
               '<Item Name="ID"/><Item Name="TITLE" Prompt="Title"/></Block></FormModule>' + newline).encode()
        if version == 2 and index == 0:
            xml = b"\xef\xbb\xbf" + xml
        ddl = (f'CREATE TABLE {table} (ID NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY, TITLE VARCHAR2(40) NOT NULL);' + newline).encode()
        originals[name.lower() + ".xml"] = xml
        originals[name.lower() + ".sql"] = ddl
    if version == 2:
        assert all(b"FOX_NATIVE_" not in raw for raw in originals.values())
    source_members = [{"name": name, "bytes": len(raw), "sha256": digest(raw)} for name, raw in sorted(originals.items())]
    manifest_bytes = "\n".join(row["name"] + ":" + row["sha256"] for row in source_members).encode()
    source_hash = digest(manifest_bytes)
    sources = [checked_source(name, raw) for name, raw in originals.items()]
    before = deepcopy(sources)
    assert inventory(sources)["source_hash"] == source_hash
    plan = assess_project_conversion(sources, project_id=project_id, project_name="Isolated package proof", source_hash=source_hash)
    assert plan["state"] == "READY" and plan["can_generate"] is True and plan["assessment_complete"] is True
    plan_before = deepcopy(plan)
    spec = plan["rendering_spec"]
    assert spec["schema_version"] == version and spec["source_manifest_sha256"] == source_hash
    assert project_source.validate_project_sources(spec, sources, project_id=project_id, plan_sha256=plan["plan_sha256"]) == plan
    assert {row["name"]: row["sha256"] for row in plan["source_files"]} == {row["name"]: row["sha256"] for row in source_members}
    assert all(row["disposition"] == "MAPPED" for row in plan["source_files"])
    files = native_project.render_native_project(spec)
    trace = native_project.project_trace(spec)
    schema = native_project.render_project_schema(spec)
    assert len(spec["forms"]) == trace["form_count"] == 2
    assert len([name for name in files if name.startswith("pages/")]) == 6
    assert ".apex/apexlang.json" in files
    assert len([name for name in files if name == "application.apx"]) == trace["application_count"] == 1
    assert sum(len(re.findall(r"^app ", value, re.M)) for value in files.values()) == 1
    assert trace["schema_version"] == version and trace["scope"] == f"fox-native-project-render-trace-v{version}"
    assert trace["source_manifest_sha256"] == source_hash
    assert all(trace[key] is False for key in ("source_completeness_verified", "reviewer_approval_verified", "sqlcl_validated", "imported", "runtime_verified", "human_acceptance_recorded"))
    by_module = {form["module_id"]: form for form in spec["forms"]}
    mappings = []
    for row in trace["forms"]:
        form = by_module[row["module_id"]]
        table = form["native_form"]["table_name"]
        assert row["source_name"] == form["source_name"] and row["source_sha256"] == digest(originals[form["source_name"]])
        assert row["table_name"] == table
        for filename in (row["report_file"], row["form_file"]):
            assert re.findall(r"^\s*tableName: (\w+)$", files[filename], re.M) == [table]
        assert f"CREATE TABLE {table} (" in schema
        if version == 2:
            mapping = form["storage_mapping"]
            assert trace["project_id"] == spec["project_id"] == project_id == mapping["project_id"]
            assert row["storage_mapping"] == mapping and row["ddl_sources"] == form["ddl_sources"]
            assert mapping["source_table_name"] == source_tables[form["source_name"]]
            assert mapping["target_table_name"] == table == "FOX_NATIVE_" + mapping["identity_sha256"][:19].upper()
            assert mapping["source_table_name"] != table
            assert form["ddl_sources"] == [{"name": form["source_name"].replace(".xml", ".sql"), "sha256": digest(originals[form["source_name"].replace(".xml", ".sql")])}]
            identity = {key: value for key, value in mapping.items() if key not in {"target_table_name", "identity_sha256"}}
            assert digest(encoded(identity)) == mapping["identity_sha256"]
            table_trace = next(value for value in trace["tables"] if value["table_name"] == table)
            assert table_trace["storage_mapping"] == mapping and table_trace["ddl_sources"] == form["ddl_sources"]
            mappings.append(mapping)
        else:
            assert table == source_tables[form["source_name"]] and "storage_mapping" not in form
    assert len(trace["tables"]) == schema.count("CREATE TABLE ") == 2
    single = native.render_native_form(spec["forms"][0]["native_form"])
    assert ".apex/apexlang.json" in single
    raw = native_project.deterministic_project_zip(spec)
    assert raw == native_project.deterministic_project_zip(spec)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert {name: archive.read(name).decode("utf-8") for name in archive.namelist()} == files
        assert len(archive.namelist()) == len(set(archive.namelist()))
    assert sources == before and plan == plan_before
    for source in sources:
        assert source["sha256"] == digest(originals[source["name"]]) and source["bytes"] == len(originals[source["name"]])
        assert source["text"] == originals[source["name"]].decode("utf-8-sig")
    destination.mkdir(parents=True)
    (destination / "two-form-apexlang.zip").write_bytes(raw)
    (destination / "source-to-apex.json").write_bytes(encoded(trace) + b"\n")
    (destination / "original-source-manifest.json").write_bytes(encoded({"source_hash": source_hash, "files": source_members}) + b"\n")
    (destination / "project-plan.json").write_bytes(encoded(plan) + b"\n")
    (destination / "synthetic-schema.sql").write_bytes(schema.encode())
    for name, content in files.items():
        path = destination / "apexlang" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    for name, content in originals.items():
        path = destination / "original-sources" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        assert path.read_bytes() == content
    return {"schema_version": version, "project_id": project_id, "source_hash": source_hash,
        "plan_sha256": plan["plan_sha256"], "original_sources_unchanged": True,
        "original_source_members": source_members, "original_source_names_preserved": True,
        "installed_source_adapter_recomputed_complete_plan": True,
        "form_count": 2, "application_count": 1, "page_count": 6,
        "storage_mappings": mappings, "trace": trace, "schema_sha256": digest(schema.encode()),
        "deterministic_project_zip_sha256": digest(raw),
        "rendered_members": [{"path": name, "bytes": len(content.encode("utf-8")), "sha256": digest(content.encode("utf-8"))} for name, content in sorted(files.items())]}

legacy = render_case(1, output)
mapped = render_case(2, output / "mapped-v2")
modules = {}
for name, module in sorted(sys.modules.items()):
    filename = getattr(module, "__file__", None)
    if not filename:
        continue
    path = pathlib.Path(filename).resolve()
    assert path != development and development not in path.parents, (name, str(path))
    if name.split(".")[0] in {"forms2apex", "fox_source_contract"}:
        assert installed in path.parents, (name, str(path))
        modules[name] = path.relative_to(installed).as_posix()
assert not any(name == "fox" or name.startswith("fox.") for name in sys.modules)
print(json.dumps({**legacy, "status": "PASS", "python_isolated": bool(sys.flags.isolated),
    "site_disabled": bool(sys.flags.no_site), "bytecode_disabled": bool(sys.dont_write_bytecode),
    "sys_path": sys.path, "module_origins": modules, "fox_application_imported": False,
    "workflow_import": ProjectWorkflow.__module__ + "." + ProjectWorkflow.__name__,
    "dependency_version": importlib.metadata.version("defusedxml"),
    "native_context": native.context(), "project_context": native_project.context(),
    "cases": {"legacy_v1": legacy, "mapped_v2": mapped}}, sort_keys=True))
'''


def run(command, *, cwd):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False, timeout=120)
    if result.returncode:
        raise RuntimeError(f"COMMAND_FAILED ({result.returncode}): {result.stdout}\n{result.stderr}")
    return result


def build_and_verify(*, source_root, build_python, dependency_root, output_root, existing_wheel=None):
    source_root, build_python, dependency_root, output_root = map(
        lambda path: Path(path).resolve(), (source_root, build_python, dependency_root, output_root))
    if output_root.exists():
        raise ValueError("OUTPUT_ALREADY_EXISTS")
    if existing_wheel is not None:
        existing_wheel = Path(existing_wheel).resolve(strict=True)
    converter = source_root / "converter"
    expected = source_inventory(converter)
    pyproject = (converter / "pyproject.toml").read_bytes()
    source_python_requirement(pyproject)
    canonical = {name: (source_root / "fox/fox" / name).read_bytes() for name in CONTRACT_MODULES}
    synchronizer = (source_root / "tools/sync_fox_source_contract.py").read_bytes()
    requirements = (converter / "requirements.txt").read_bytes()
    if {line.strip() for line in requirements.decode().splitlines() if line.strip() and not line.lstrip().startswith("#")} != DEPENDENCIES:
        raise ValueError("RUNTIME_REQUIREMENTS_CONTRACT_MISMATCH")
    unpackaged_cache = [
        path.relative_to(converter).as_posix()
        for path in sorted((converter / "fox_source_contract/__pycache__").glob("*")) if path.is_file()
    ]
    output_root.mkdir(parents=True)
    staging_root = output_root / "build-source"
    staging = staging_root / "converter"
    staging.mkdir(parents=True)
    (staging / "pyproject.toml").write_bytes(pyproject)
    (staging / "requirements.txt").write_bytes(requirements)
    for name, raw in expected.items():
        target = staging / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    for name, raw in canonical.items():
        target = staging_root / "fox/fox" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    staged_synchronizer = staging_root / "tools/sync_fox_source_contract.py"
    staged_synchronizer.parent.mkdir()
    staged_synchronizer.write_bytes(synchronizer)
    # Concurrent developer imports may create bytecode in the working tree.
    # Do not delete it or weaken the synchronizer: check the exact selected
    # source payload against the canonical bytes in an owned staging root.
    mirror = run([str(build_python), "-I", "-B", str(staged_synchronizer), "--check", "--source-root", str(staging_root)], cwd=staging_root)
    wheels = output_root / "dist"
    wheels.mkdir()
    backend_code = (
        "import importlib.metadata as m,json,sys; "
        "print('BUILD_TOOLS=' + json.dumps({n:m.version(n) for n in ('setuptools','wheel')})); "
        "print('BUILD_PYTHON=' + json.dumps(list(sys.version_info[:3]))); ")
    if existing_wheel is None:
        backend_code += "from setuptools.build_meta import build_wheel; "
        backend_code += f"print('BUILT_WHEEL=' + build_wheel({str(wheels)!r}))"
    else:
        shutil.copy2(existing_wheel, wheels / existing_wheel.name)
        backend_code += "print('RECHECKED_EXISTING_WHEEL_WITHOUT_REBUILD=True')"
    backend = run([str(build_python), "-I", "-B", "-c", backend_code], cwd=staging)
    (output_root / "build.log").write_text(backend.stdout + backend.stderr, encoding="utf-8")
    candidates = list(wheels.glob("*.whl"))
    if len(candidates) != 1:
        raise ValueError("BUILT_WHEEL_MISSING_OR_AMBIGUOUS")
    wheel = candidates[0]
    tested_python = json.loads(next(line.split("=", 1)[1] for line in backend.stdout.splitlines() if line.startswith("BUILD_PYTHON=")))
    wheel_report = verify_wheel(wheel, expected, tested_python=tested_python)
    installed = output_root / "installed"
    installed.mkdir()
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(installed)  # Every member was checked before extraction.
    dependencies = output_root / "isolated-dependencies"
    dependencies.mkdir()
    dependency_inventory = []
    for name in ("defusedxml", "defusedxml-0.7.1.dist-info"):
        original = dependency_root / name
        if not original.is_dir():
            raise ValueError("EXISTING_DEFUSEDXML_071_MISSING")
        shutil.copytree(original, dependencies / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for path in sorted((dependencies / name).rglob("*")):
            if path.is_file():
                raw = path.read_bytes()
                dependency_inventory.append({"path": path.relative_to(dependencies).as_posix(), "bytes": len(raw), "sha256": sha256(raw)})
    outside = output_root / "probe-cwd"
    outside.mkdir()
    probe = run([str(build_python), "-I", "-S", "-B", "-c", PROBE, str(installed), str(dependencies), str(converter), str(output_root / "rendered")], cwd=outside)
    probe_report = json.loads(probe.stdout)
    negative = []
    for missing in sorted(HIDDEN_RESOURCES):
        broken = output_root / ("missing-" + missing.split("/")[2] + ".whl")
        with zipfile.ZipFile(wheel) as archive, zipfile.ZipFile(broken, "w") as altered:
            for info in archive.infolist():
                if info.filename != missing:
                    altered.writestr(info, archive.read(info.filename))
        try:
            verify_wheel(broken, expected, tested_python=tested_python)
        except ValueError as error:
            if str(error) != "HIDDEN_APEX_RESOURCE_MISSING_FROM_WHEEL":
                raise
            negative.append({"removed": missing, "outcome": "BLOCKED", "reason": str(error)})
        else:
            raise AssertionError("INCOMPLETE_WHEEL_ACCEPTED")
    if (source_inventory(converter) != expected
            or (converter / "pyproject.toml").read_bytes() != (staging / "pyproject.toml").read_bytes()
            or (converter / "requirements.txt").read_bytes() != requirements
            or any((source_root / "fox/fox" / name).read_bytes() != raw for name, raw in canonical.items())
            or (source_root / "tools/sync_fox_source_contract.py").read_bytes() != synchronizer):
        raise ValueError("SOURCE_CHANGED_DURING_WHEEL_PROOF_RERUN_REQUIRED")
    report = {"schema_version": 2, "scope": "converter-wheel-offline-package-proof-v2", "status": "PASS",
        "build_performed": existing_wheel is None,
        "deployed": False, "startup_claimed": False,
        "existing_wheel_source": str(existing_wheel) if existing_wheel is not None else None,
        "build_python": str(build_python), "build_tools": json.loads(next(line.split("=", 1)[1] for line in backend.stdout.splitlines() if line.startswith("BUILD_TOOLS="))),
        "dependency_source": str(dependency_root), "dependency_members": dependency_inventory,
        "source_mirror_check": json.loads(mirror.stdout), "wheel": wheel_report,
        "source_mirror_check_scope": "fresh staging copy; exact selected mirror payload versus current canonical source bytes",
        "unpackaged_live_contract_bytecode_preserved": unpackaged_cache,
        "source_inputs": {
            "pyproject_sha256": sha256((staging / "pyproject.toml").read_bytes()),
            "requirements_sha256": sha256(requirements), "synchronizer_sha256": sha256(synchronizer),
            "verifier_sha256": sha256(Path(__file__).read_bytes()),
            "canonical_modules": {name: sha256(raw) for name, raw in canonical.items()},
        },
        "isolated_probe": probe_report, "missing_hidden_resource_checks": negative,
        "limits": ["No dependency resolver or FastMCP server startup tested.", "No SQLcl, database, model, network or cloud operation performed.", "Local package/rendering proof is not deployment or runtime acceptance."]}
    (output_root / "evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--build-python", type=Path, required=True)
    parser.add_argument("--dependency-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--existing-wheel", type=Path, help="Recheck and probe this existing wheel in fresh isolation without rebuilding it.")
    args = parser.parse_args()
    report = build_and_verify(**vars(args))
    print(json.dumps({"status": report["status"], "wheel_sha256": report["wheel"]["wheel_sha256"],
                      "wheel_members": len(report["wheel"]["members"]), "evidence": str(args.output_root / "evidence.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
