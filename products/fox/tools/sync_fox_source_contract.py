"""Check or explicitly refresh the standalone, deterministic FOX source contract.

Run from any directory with ``python -B tools/sync_fox_source_contract.py``;
``--check`` is the read-only default. Only ``--write`` refreshes the five fixed
members under converter/fox_source_contract. The mirror is byte-for-byte: it
does not import FOX, initialize an application, or rewrite source imports.

Use this at build/review time, not at application startup. Keep Python bytecode
outside this source package (or use -B): unexpected package members are refused,
not silently removed. This is a provenance/inventory check, not a code sandbox
or a signature establishing the trustworthiness of the canonical source tree.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


SOURCE_DIRECTORY = "fox/fox"
PACKAGE_DIRECTORY = "converter/fox_source_contract"
MODULES = ("intake.py", "native_source.py", "project_conversion.py")
MANIFEST_NAME = "source-manifest.json"
INIT_BYTES = b'"""Build-time mirror of the reviewed FOX source assessment contract."""\n'
MEMBERS = frozenset((*MODULES, "__init__.py", MANIFEST_NAME))
MAX_MODULE_BYTES = 1024 * 1024

# Exact imported names make changes to this pure contract's dependency boundary
# explicit in review. Aliases are included; no imports are executed by this tool.
IMPORTS = {
    "intake.py": frozenset({
        ("from", 0, "__future__", "annotations", None),
        ("import", 0, "hashlib", None, None),
        ("import", 0, "re", None, None),
        ("from", 0, "pathlib", "PurePosixPath", None),
        ("from", 0, "defusedxml", "ElementTree", "ET"),
    }),
    "native_source.py": frozenset({
        ("from", 0, "__future__", "annotations", None),
        ("import", 0, "hashlib", None, None),
        ("import", 0, "re", None, None),
        ("import", 0, "unicodedata", None, None),
        ("from", 0, "pathlib", "PurePosixPath", None),
        ("from", 0, "defusedxml", "ElementTree", "ET"),
        ("from", 1, "intake", "MAX_CONVERSION_BYTES", None),
        ("from", 1, "intake", "SECRETS", None),
    }),
    "project_conversion.py": frozenset({
        ("from", 0, "__future__", "annotations", None),
        ("from", 0, "collections", "Counter", None),
        ("from", 0, "collections", "defaultdict", None),
        ("from", 0, "copy", "deepcopy", None),
        ("import", 0, "hashlib", None, None),
        ("import", 0, "json", None, None),
        ("import", 0, "re", None, None),
        ("import", 0, "unicodedata", None, None),
        ("from", 0, "pathlib", "PurePosixPath", None),
        ("from", 0, "xml.etree", "ElementTree", "XML"),
        ("from", 0, "defusedxml", "ElementTree", "ET"),
        ("from", 1, None, "intake", None),
        ("from", 1, None, "native_source", None),
    }),
}
REQUIRED_DEFINITIONS = {
    "intake.py": frozenset({"checked_source", "inventory"}),
    "native_source.py": frozenset({"assess_native_source", "_assess_native_source", "_parse_ddl"}),
    "project_conversion.py": frozenset({
        "ProjectConversionInputError", "assess_project_conversion",
        "schema_fingerprint", "module_execution_binding",
        "derive_storage_mapping", "validate_storage_mapping", "validate_project_storage_mappings",
    }),
}
PROFILE_IDS = {"native_source.py": "native-table-form-v1", "project_conversion.py": "native-project-v1"}


class ContractSyncError(ValueError):
    """A bounded error code, without source contents or host-specific paths."""


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _plain_chain(path: Path) -> None:
    """Refuse existing symlinks and Windows junction/reparse-point ancestors."""
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise ContractSyncError("LINK_OR_REPARSE_POINT")


def _read_plain(path: Path) -> bytes:
    _plain_chain(path)
    try:
        info = path.stat()
    except FileNotFoundError:
        raise ContractSyncError("REQUIRED_FILE_MISSING") from None
    if not stat.S_ISREG(info.st_mode):
        raise ContractSyncError("NON_REGULAR_FILE")
    if info.st_size > MAX_MODULE_BYTES:
        raise ContractSyncError("FILE_SIZE_LIMIT")
    with path.open("rb") as handle:
        raw = handle.read(MAX_MODULE_BYTES + 1)
    if len(raw) > MAX_MODULE_BYTES:
        raise ContractSyncError("FILE_SIZE_LIMIT")
    return raw


def _validate_module(name: str, raw: bytes) -> None:
    try:
        tree = ast.parse(raw.decode("utf-8"), filename=name)
    except (SyntaxError, UnicodeError, ValueError, RecursionError):
        raise ContractSyncError("INVALID_PYTHON_SOURCE") from None
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(("import", 0, item.name, None, item.asname) for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.update(("from", node.level, node.module, item.name, item.asname) for item in node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in {
            "__import__", "eval", "exec", "compile", "open", "input",
        }:
            raise ContractSyncError("EXECUTION_OR_IO_BOUNDARY_CHANGED")
    if imports != IMPORTS[name]:
        raise ContractSyncError("IMPORT_BOUNDARY_CHANGED")
    definitions = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    if not REQUIRED_DEFINITIONS[name] <= definitions:
        raise ContractSyncError("MODULE_IDENTITY_CHANGED")
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.Assign) and all(isinstance(target, ast.Name) for target in node.targets):
            continue
        raise ContractSyncError("TOP_LEVEL_EXECUTION_CHANGED")
    if name in PROFILE_IDS:
        values = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "PROFILE_ID" for target in node.targets)
                  and isinstance(node.value, ast.Constant)]
        if values != [PROFILE_IDS[name]]:
            raise ContractSyncError("MODULE_PROFILE_CHANGED")


def _root(source_root: Path | str | None) -> Path:
    root = Path(source_root) if source_root is not None else Path(__file__).absolute().parents[1]
    root = Path(os.path.abspath(root))
    _plain_chain(root)
    if not root.is_dir():
        raise ContractSyncError("SOURCE_ROOT_NOT_DIRECTORY")
    return root


def _expected(root: Path) -> dict[str, bytes]:
    files = {name: _read_plain(root / SOURCE_DIRECTORY / name) for name in MODULES}
    for name, raw in files.items():
        _validate_module(name, raw)
    files["__init__.py"] = INIT_BYTES
    manifest = {
        "schema_version": 1,
        "scope": "fox-source-contract-mirror-v1",
        "package": "fox_source_contract",
        "synchronizer": "tools/sync_fox_source_contract.py",
        "transformation": "none-byte-for-byte",
        "files": [
            {"path": name, "source_path": f"{SOURCE_DIRECTORY}/{name}",
             "sha256": sha256(files[name]), "bytes": len(files[name])}
            for name in MODULES
        ],
        "initializer": {"path": "__init__.py", "sha256": sha256(INIT_BYTES), "bytes": len(INIT_BYTES)},
    }
    files[MANIFEST_NAME] = (json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    return files


def _inventory(package: Path) -> set[str]:
    _plain_chain(package)
    if not package.exists():
        return set()
    if not package.is_dir():
        raise ContractSyncError("PACKAGE_NOT_DIRECTORY")
    names = set()
    for member in package.iterdir():
        _plain_chain(member)
        if member.name not in MEMBERS:
            raise ContractSyncError("UNEXPECTED_PACKAGE_MEMBER")
        if not member.is_file():
            raise ContractSyncError("NON_REGULAR_FILE")
        names.add(member.name)
    return names


def synchronize(source_root: Path | str | None = None, *, write: bool = False) -> dict:
    """Check exact bytes/inventory, or refresh only the fixed generated files.

    Existing unknown members and links are refused before any write; files
    elsewhere in source_root are neither inventoried nor changed. A concurrent
    hostile filesystem writer is outside this build-time tool's isolation model.
    """
    if type(write) is not bool:
        raise ContractSyncError("WRITE_MUST_BE_EXPLICIT_BOOLEAN")
    root = _root(source_root)
    expected = _expected(root)
    package = root / PACKAGE_DIRECTORY
    names = _inventory(package)
    changed = [name for name in sorted(expected)
               if name not in names or _read_plain(package / name) != expected[name]]
    if changed and not write:
        raise ContractSyncError("MIRROR_MISSING_OR_STALE")
    if write and changed:
        # Do not publish a snapshot that changed while validation was running.
        if _expected(root) != expected:
            raise ContractSyncError("CANONICAL_SOURCE_CHANGED_DURING_SYNC")
        package.mkdir(parents=True, exist_ok=True)
        for name in changed:
            _inventory(package)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(prefix=".sync-", suffix=".tmp", dir=package, delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(expected[name])
                    handle.flush()
                    os.fsync(handle.fileno())
                _plain_chain(package / name)
                os.replace(temporary, package / name)
            finally:
                if temporary is not None and temporary.exists():
                    temporary.unlink()
    if _inventory(package) != MEMBERS or any(_read_plain(package / name) != raw for name, raw in expected.items()):
        raise ContractSyncError("MIRROR_POSTCHECK_FAILED")
    return {
        "schema_version": 1,
        "status": "SYNCHRONIZED" if write and changed else "CURRENT",
        "mode": "write" if write else "check",
        "package_path": PACKAGE_DIRECTORY,
        "changed": changed if write else [],
        "files": [{"path": f"{PACKAGE_DIRECTORY}/{name}", "sha256": sha256(raw), "bytes": len(raw)}
                  for name, raw in sorted(expected.items())],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Read-only exact inventory/hash check (default).")
    mode.add_argument("--write", action="store_true", help="Explicitly regenerate only the five fixed package members.")
    parser.add_argument("--source-root", type=Path, help="Workspace root containing fox/fox; defaults to this script's parent workspace.")
    args = parser.parse_args(argv)
    try:
        result = synchronize(args.source_root, write=args.write)
    except ContractSyncError as error:
        print(json.dumps({"status": "REFUSED", "code": str(error)}, sort_keys=True))
        return 1
    except OSError:
        # Do not echo file contents, account names or absolute host paths.
        print(json.dumps({"status": "REFUSED", "code": "FILESYSTEM_OPERATION_FAILED"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
