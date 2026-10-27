"""Build an offline, source-bound FOX/converter candidate; never deploy it.

The source bundle is independent of runtime configuration, image IDs, release
admission and private state. UI and wheel are built with already-installed
tools. No package installation, network call, credential read or cloud action
is performed. Existing outputs are never overwritten.
"""
from __future__ import annotations

import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import zipfile


BASE_IMAGES = {
    "fox": "sha256:9ce6e594cffedfbe85d3431af8ad929bb83222a2e1fd4b8521cad8edd9e52490",
    "converter": "sha256:c7fdb53bc04450e297cbbbc89fb834be714e106d5a164b1c80dc77d544db5a1b",
}
PROFILE_FILES = (
    "deployment/native-beta-profile.json", "deployment/target-profile.jsn.json",
    "deployment/project-opaf-profile-v2.json", "deployment/target-profile.jsn-project-v2.json",
)
QA_FILES = (
    "qa/package.json", "qa/package-lock.json", "qa/run-native.mjs", "qa/run-project.mjs",
    "qa/prepare-target.mjs", "qa/run-jsn-qa.sh", "qa/run-fox-journey.mjs",
    "qa/run-product-download.mjs", "qa/lib/contracts.mjs", "qa/lib/package-evidence.mjs",
    "qa/lib/assert-jsn-vm.sh", "qa/lib/project-profile.mjs", "qa/lib/project-runner-inputs.mjs",
    "qa/lib/project-runtime.mjs", "qa/lib/project-browser.mjs",
)
MAX_FILE = 8_000_000
MAX_TOTAL = 80_000_000


class BuildError(RuntimeError):
    """Fixed diagnostics only: never include source, environment or secrets."""


def need(value, code):
    if not value:
        raise BuildError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode()


def safe_name(value):
    path = PurePosixPath(value)
    need(type(value) is str and 0 < len(value) <= 512 and str(path) == value
         and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value)
         and not path.is_absolute() and "\\" not in value and ":" not in value
         and all(part not in ("", ".", "..") for part in path.parts), "UNSAFE_MEMBER_NAME")
    return value


def read(path, *, allow_empty=False, maximum=MAX_FILE, reject_key_material=True):
    path = Path(path).absolute()
    info = path.lstat()
    need(path.resolve() == path and not path.is_symlink()
         and not getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
         and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and int(not allow_empty) <= info.st_size <= maximum, "UNSAFE_SOURCE_FILE")
    raw = path.read_bytes()
    after = path.lstat()
    need((info.st_size, info.st_mtime_ns, info.st_ino) ==
         (after.st_size, after.st_mtime_ns, after.st_ino) and len(raw) == info.st_size,
         "SOURCE_CHANGED_DURING_READ")
    need(not reject_key_material or not re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", raw),
         "PRIVATE_KEY_MATERIAL_FORBIDDEN")
    return raw


def source_files(root):
    """Only runtime source trees and named public profiles/QA assets are admitted."""
    root = Path(root).resolve(strict=True)
    names = set(PROFILE_FILES) | set(QA_FILES)
    for directory in ("fox/fox", "qa/operator"):
        base = root / directory
        need(base.is_dir() and base.resolve() == base, "SOURCE_DIRECTORY_REQUIRED")
        for path in sorted(base.iterdir()):
            if path.name == "__pycache__" or path.name == "tests":
                continue
            need(not path.is_symlink(), "LINKED_RUNTIME_SOURCE_FORBIDDEN")
            if path.is_file() and path.suffix == ".py":
                names.add(path.relative_to(root).as_posix())
    names.add("fox/fox/native/FoxPllExtract.java")
    for name in ("qa/__init__.py", "qa/operator/__init__.py"):
        if (root / name).exists():
            names.add(name)
    result = {name: read(root / name, allow_empty=True) for name in sorted(names)}
    need("qa/operator/hosted_service.py" in result, "HOSTED_SERVICE_SOURCE_NOT_READY")
    return result


def ui_sources(root):
    root = Path(root).resolve(strict=True)
    names = {"package.json", "package-lock.json", "tsconfig.json", "vite.config.ts", "index.html"}
    for path in sorted((root / "fox/web").rglob("*")):
        need(not path.is_symlink(), "LINKED_UI_SOURCE_FORBIDDEN")
        if path.is_file():
            need(path.suffix in (".ts", ".tsx", ".css", ".svg", ".png", ".jpg", ".webp"),
                 "UNEXPECTED_UI_SOURCE")
            names.add(path.relative_to(root / "fox").as_posix())
    for folder in (root, root / "fox"):
        need(not any(folder.glob(".env*")), "UI_DOTENV_INPUT_FORBIDDEN")
    return {"fox/" + name: read(root / "fox" / name) for name in sorted(names)}


def defusedxml_payload(dependency_root):
    """Verify the installed pure-Python distribution against its original RECORD.

    Bytecode entries generated by pip are excluded. Every hashed RECORD member,
    metadata and license is retained byte-for-byte; no wheel provenance is claimed.
    """
    root = Path(dependency_root).resolve(strict=True)
    metadata_root = "defusedxml-0.7.1.dist-info"
    metadata = BytesParser().parsebytes(read(root / metadata_root / "METADATA"))
    need(metadata["Name"] == "defusedxml" and metadata["Version"] == "0.7.1"
         and not metadata.get_all("Requires-Dist"), "DEFUSEDXML_DISTRIBUTION_CHANGED")
    record = read(root / metadata_root / "RECORD")
    rows = list(csv.reader(io.StringIO(record.decode())))
    result = {}
    seen = set()
    for row in rows:
        need(len(row) == 3, "DEPENDENCY_RECORD_INVALID")
        name, expected_hash, expected_size = row
        safe_name(name)
        need(name not in seen and name.split("/", 1)[0] in ("defusedxml", metadata_root),
             "DEPENDENCY_RECORD_INVALID")
        seen.add(name)
        if "__pycache__" in PurePosixPath(name).parts and name.endswith(".pyc"):
            need(not expected_hash and not expected_size, "DEPENDENCY_BYTECODE_HASH_UNEXPECTED")
            continue
        raw = read(root / name, allow_empty=True)
        if name == metadata_root + "/RECORD":
            need(not expected_hash and not expected_size, "DEPENDENCY_RECORD_SELF_HASH_INVALID")
        else:
            actual = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            need(expected_hash == actual and expected_size == str(len(raw)), "DEPENDENCY_RECORD_HASH_DIFFERS")
        result[name] = raw
    need(metadata_root + "/LICENSE" in result and "defusedxml/ElementTree.py" in result,
         "DEPENDENCY_LICENSE_OR_CODE_MISSING")
    actual_names = set()
    for folder in (root / "defusedxml", root / metadata_root):
        for path in folder.rglob("*"):
            need(not path.is_symlink(), "LINKED_DEPENDENCY_FORBIDDEN")
            if path.is_file() and "__pycache__" not in path.parts:
                actual_names.add(path.relative_to(root).as_posix())
    need(actual_names == result.keys(), "DEPENDENCY_INVENTORY_DIFFERS")
    return result


def run(command, cwd, *, timeout=180):
    env = {key: value for key, value in os.environ.items()
           if not key.upper().startswith(("VITE_", "NODE_OPTIONS", "PYTHONPATH"))}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", npm_config_offline="true")
    outcome = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    need(outcome.returncode == 0, "OFFLINE_BUILD_COMMAND_FAILED")
    return outcome.stdout + outcome.stderr


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def inventory(files):
    return {"schema_version": 1, "scope": "fox-hosted-source-inventory-v1",
            "files": {name: digest(raw) for name, raw in sorted(files.items())}}


def containerfiles():
    # These removals occur only in new image layers, never in a running container
    # or mounted data. Fixed old package directories are replaced, not overlaid.
    fox = f"""FROM {BASE_IMAGES['fox']}
USER root
RUN python -I -B -c "import pathlib,shutil; roots=[pathlib.Path('/app/fox'),pathlib.Path('/app/dist')]; assert all(p.is_dir() and not p.is_symlink() and p.resolve()==p for p in roots); [shutil.rmtree(p) for p in roots]"
COPY --chown=1000:1000 fox /app/fox
COPY --chown=1000:1000 dist /app/dist
WORKDIR /app
USER 1000:1000
RUN python -B -c "import fox.project_conversion,fox.native_project_pipeline,fox.technical_release; assert fox.project_conversion.PROFILE_ID=='native-project-v1'"
"""
    converter = f"""FROM {BASE_IMAGES['converter']}
USER root
RUN python3.11 -I -B -c "import pathlib,shutil; p=pathlib.Path('/opt/forms2apex/converter/forms2apex'); assert p.is_dir() and not p.is_symlink() and p.resolve()==p; shutil.rmtree(p)"
COPY --chown=10001:10001 converter /opt/forms2apex/converter
USER 10001
RUN python3.11 -B -c "import importlib.metadata as m; import forms2apex.project_workflow,fox_source_contract.project_conversion,defusedxml.ElementTree; assert {{n:m.version(n) for n in ('oci','fastmcp','defusedxml')}}=={{'oci':'2.188.0','fastmcp':'3.4.4','defusedxml':'0.7.1'}}"
"""
    return {"fox": fox.encode(), "converter": converter.encode()}


def materialize(*, files, ui, converter, output_root, build_evidence):
    output_root = Path(output_root)
    need(not output_root.exists() and not output_root.is_symlink(), "OUTPUT_ALREADY_EXISTS")
    bundle = dict(files)
    bundle.update({"converter/" + name: raw for name, raw in converter.items()})
    bundle.update({"fox/dist/" + name: raw for name, raw in ui.items()})
    bundle.update({"deployment/Containerfile.project-" + role: raw for role, raw in containerfiles().items()})
    need(sum(map(len, bundle.values())) <= MAX_TOTAL, "SOURCE_BUNDLE_TOO_LARGE")
    for name in bundle:
        safe_name(name)
    declared = inventory(bundle)
    inventory_raw = canonical(declared)
    bundle_sha = digest(inventory_raw)
    archive_files = {"bundle/" + name: raw for name, raw in bundle.items()}
    for role, raw in containerfiles().items():
        archive_files[f"build/{role}/Containerfile"] = raw
    archive_files.update({"build/fox/fox/" + name.removeprefix("fox/fox/"): raw
                          for name, raw in files.items() if name.startswith("fox/fox/")})
    archive_files.update({"build/fox/dist/" + name: raw for name, raw in ui.items()})
    archive_files.update({"build/converter/converter/" + name: raw for name, raw in converter.items()})
    archive_files["source-inventory.json"] = inventory_raw
    archive_files["build-evidence.json"] = canonical(build_evidence)
    manifest = {"schema_version": 1, "scope": "fox-paired-build-archive-v1",
                "source_bundle_sha256": bundle_sha, "base_images": BASE_IMAGES,
                "files": {name: {"sha256": digest(raw), "bytes": len(raw)}
                          for name, raw in sorted(archive_files.items())},
                "activation_performed": False,
                "rollback_policy": "G is historical only after first project write; use a project-aware release or maintenance-read-only"}
    archive_files["manifest.json"] = canonical(manifest)
    output_root.mkdir()
    for name, raw in sorted(archive_files.items()):
        write_new(output_root / name, raw)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(archive_files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), 0o600, 0
            info.uid = info.gid = 0
            archive.addfile(info, io.BytesIO(raw))
    archive_raw = stream.getvalue()
    write_new(output_root / "paired-source.tar", archive_raw)
    result = {"status": "PREPARED_NOT_DEPLOYED", "source_bundle_sha256": bundle_sha,
              "archive_sha256": digest(archive_raw), "archive_bytes": len(archive_raw),
              "manifest_sha256": digest(canonical(manifest)), "source_file_count": len(bundle),
              "base_images": BASE_IMAGES, "activation_performed": False}
    write_new(output_root / "result.json", canonical(result))
    return result


def prepare(*, root, build_python, node, dependency_root, output):
    root, output = Path(root).resolve(strict=True), Path(output).absolute()
    need(not output.exists() and not output.is_symlink() and output.parent.is_dir(), "FRESH_OUTPUT_REQUIRED")
    initial, ui_input = source_files(root), ui_sources(root)
    dependency = defusedxml_payload(dependency_root)
    build_python, node = Path(build_python).resolve(strict=True), Path(node).resolve(strict=True)
    tools = {"python_sha256": digest(read(build_python, maximum=150_000_000, reject_key_material=False)),
             "node_sha256": digest(read(node, maximum=150_000_000, reject_key_material=False))}
    scratch = output.with_name(output.name + "-build")
    need(not scratch.exists() and not scratch.is_symlink(), "FRESH_BUILD_DIRECTORY_REQUIRED")
    scratch.mkdir()
    typescript = root / "fox/node_modules/typescript/bin/tsc"
    vite = root / "fox/node_modules/vite/bin/vite.js"
    type_log = run([str(node), str(typescript), "--noEmit", "--project", str(root / "fox/tsconfig.json")], root / "fox")
    ui_root = scratch / "ui"
    ui_log = run([str(node), str(vite), "build", "--outDir", str(ui_root)], root / "fox")
    ui = {path.relative_to(ui_root).as_posix(): read(path) for path in ui_root.rglob("*") if path.is_file()}
    need("index.html" in ui and all(name == "index.html" or re.fullmatch(r"assets/[A-Za-z0-9_.-]+\.(js|css|svg|png|jpg|webp)", name)
                                   for name in ui), "UI_BUILD_MEMBERS_INVALID")
    helper_path = root / "tools/verify_converter_wheel.py"
    spec = importlib.util.spec_from_file_location("_fox_converter_wheel_builder", helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    wheel_root = scratch / "wheel"
    proof = helper.build_and_verify(source_root=root, build_python=build_python,
                                   dependency_root=dependency_root, output_root=wheel_root)
    wheel = next((wheel_root / "dist").glob("*.whl"))
    helper.verify_wheel(wheel, helper.source_inventory(root / "converter"))
    with zipfile.ZipFile(wheel) as archive:
        converter = {name: archive.read(name) for name in archive.namelist()}
    need(not (converter.keys() & dependency.keys()), "DEPENDENCY_PACKAGE_COLLISION")
    converter.update(dependency)
    need(initial == source_files(root) and ui_input == ui_sources(root)
         and dependency == defusedxml_payload(dependency_root), "SOURCE_CHANGED_DURING_BUILD")
    evidence = {"schema_version": 1, "scope": "fox-offline-paired-build-v1", "tools": tools,
                "input_sha256": {name: digest(raw) for name, raw in sorted({**initial, **ui_input}.items())},
                "ui_sha256": {name: digest(raw) for name, raw in sorted(ui.items())},
                "typescript_log_sha256": digest(type_log), "vite_log_sha256": digest(ui_log),
                "wheel_sha256": digest(read(wheel)), "wheel_proof_sha256": digest(read(wheel_root / "evidence.json")),
                "wheel_helper_sha256": digest(read(helper_path)),
                "dependency_origin": "existing installed defusedxml0.7.1, original RECORD verified, no registry provenance claimed",
                "dependency_sha256": {name: digest(raw) for name, raw in sorted(dependency.items())},
                "build_inputs_rechecked": True, "network_or_install_requested": False}
    write_new(scratch / "typescript.log", type_log)
    write_new(scratch / "vite.log", ui_log)
    return materialize(files=initial, ui=ui, converter=converter, output_root=output, build_evidence=evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--build-python", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--dependency-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = prepare(root=args.source_root, build_python=args.build_python, node=args.node,
                     dependency_root=args.dependency_root, output=args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "NOT_PREPARED", "code": str(error) if type(error) is BuildError else "BUILD_CHECK_FAILED",
                          "existing_outputs_preserved": True}), file=sys.stderr)
        sys.exit(1)
