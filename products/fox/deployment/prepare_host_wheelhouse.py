"""Download and verify an offline OCI operator wheelhouse; never install it.

The fixed target is CPython 3.11.13, Linux x86_64, glibc 2.28 (OL8).
Only official PyPI wheels, OCI 2.188.0 and defusedxml 0.7.1 plus their complete
active dependency closure are admitted. This does not connect to OCI or a DB.
"""
from __future__ import annotations

import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from urllib.parse import quote, urlsplit
import urllib.request
import zipfile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.tags import compatible_tags, cpython_tags, parse_tag
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

ROOTS = {"oci": "2.188.0", "defusedxml": "0.7.1"}
PLATFORMS = ("manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64")
TARGET_PYTHON = "3.11.13"
MAX_WHEEL_BYTES = 100_000_000
MAX_EXPANDED_BYTES = 1_000_000_000
MAX_MEMBERS = 80_000
MAX_JSON_BYTES = 10_000_000
MAX_COLLECTION_BYTES = 600_000_000


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode()


def target_environment():
    env = default_environment()
    env.update(implementation_name="cpython", implementation_version=TARGET_PYTHON,
        os_name="posix", platform_machine="x86_64", platform_release="",
        platform_system="Linux", platform_version="", python_full_version=TARGET_PYTHON,
        platform_python_implementation="CPython", python_version="3.11", sys_platform="linux", extra="")
    return env


def supported_tags():
    return set(cpython_tags((3, 11), abis=("cp311", "abi3", "none"), platforms=PLATFORMS)) | set(
        compatible_tags((3, 11), interpreter="cp311", platforms=PLATFORMS))


def allowed_platform(value):
    if value == "any" or value in {"manylinux1_x86_64", "manylinux2010_x86_64", "manylinux2014_x86_64"}:
        return True
    match = re.fullmatch(r"manylinux_2_([0-9]+)_x86_64", value)
    return bool(match and 5 <= int(match[1]) <= 28)


def wheel_metadata(path):
    """Read all wheel bytes and verify each RECORD digest before admission."""
    path = Path(path)
    require(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= MAX_WHEEL_BYTES,
            "WHEEL_FILE_INVALID")
    name, version, _, filename_tags = parse_wheel_filename(path.name)
    require(filename_tags & supported_tags() and all(allowed_platform(tag.platform) for tag in filename_tags),
            "WHEEL_TARGET_NOT_SUPPORTED")
    raw = path.read_bytes()
    require(len(raw) <= MAX_WHEEL_BYTES, "WHEEL_FILE_INVALID")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        require(0 < len(infos) <= MAX_MEMBERS and sum(x.file_size for x in infos) <= MAX_EXPANDED_BYTES,
                "WHEEL_EXPANSION_BOUND")
        seen, members = set(), {}
        for info in infos:
            rel = PurePosixPath(info.filename)
            normalized = info.filename[:-1] if info.is_dir() else info.filename
            require(info.orig_filename == info.filename and normalized
                and str(rel) == normalized and not rel.is_absolute() and ".." not in rel.parts
                and "\\" not in info.filename and ":" not in info.filename and "\x00" not in info.filename
                and stat.S_IFMT(info.external_attr >> 16) != stat.S_IFLNK
                and normalized.casefold() not in seen and info.file_size <= MAX_WHEEL_BYTES,
                "WHEEL_MEMBER_UNSAFE")
            seen.add(normalized.casefold())
            if info.is_dir():
                require(info.file_size == 0 and not archive.read(info), "WHEEL_DIRECTORY_HAS_CONTENT")
            else:
                members[info.filename] = archive.read(info)
    metadata_names = [key for key in members if key.endswith(".dist-info/METADATA")]
    require(len(metadata_names) == 1, "WHEEL_METADATA_AMBIGUOUS")
    metadata_name = metadata_names[0]
    metadata_root = metadata_name.rsplit("/", 1)[0]
    require(all(not key.endswith(".dist-info/METADATA") or key == metadata_name for key in members),
            "WHEEL_METADATA_AMBIGUOUS")
    metadata = BytesParser().parsebytes(members[metadata_name])
    require(not metadata.defects and canonicalize_name(metadata["Name"]) == name
            and Version(metadata["Version"]) == version, "WHEEL_IDENTITY_MISMATCH")
    requirement = metadata.get("Requires-Python", "")
    require(not requirement or Version(TARGET_PYTHON) in SpecifierSet(requirement), "WHEEL_PYTHON_UNSUPPORTED")
    wheel = BytesParser().parsebytes(members[metadata_root + "/WHEEL"])
    declared_tags = set().union(*(parse_tag(value) for value in wheel.get_all("Tag", [])))
    require(not wheel.defects and wheel.get("Wheel-Version") == "1.0" and declared_tags == filename_tags,
            "WHEEL_TAG_MISMATCH")
    record_name = metadata_root + "/RECORD"
    rows = list(csv.reader(io.StringIO(members[record_name].decode("utf-8"))))
    require(len(rows) == len(members) and all(len(row) == 3 for row in rows)
            and len({row[0] for row in rows}) == len(rows) and {row[0] for row in rows} == set(members),
            "WHEEL_RECORD_INVENTORY_MISMATCH")
    for member, recorded_hash, size in rows:
        if member == record_name:
            require(not recorded_hash and not size, "WHEEL_RECORD_SELF_HASH_INVALID")
        else:
            data = members[member]
            encoded = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            require(recorded_hash == encoded and size == str(len(data)), "WHEEL_RECORD_HASH_MISMATCH")
    requirements = metadata.get_all("Requires-Dist", [])
    active = []
    for text in requirements:
        req = Requirement(text)
        require(not req.marker or not re.search(r"\bplatform_(?:release|version)\b", str(req.marker)),
                "DEPENDENCY_REQUIRES_UNOBSERVED_OS_DETAIL")
        if req.marker is None or req.marker.evaluate(target_environment()):
            require(not req.url and not req.extras, "DEPENDENCY_URL_OR_EXTRAS_NOT_ALLOWED")
            active.append(str(req))
    return {"filename": path.name, "name": str(name), "version": str(version), "bytes": len(raw),
        "sha256": digest(raw), "requires_python": requirement, "active_requires_dist": sorted(active),
        "tags": sorted(map(str, filename_tags)), "members": len(members),
        "expanded_bytes": sum(len(value) for value in members.values()), "record_integrity": "PASS"}


def dependency_closure(wheels):
    by_name = {}
    for wheel in wheels:
        require(wheel["name"] not in by_name, "DUPLICATE_DISTRIBUTION")
        by_name[wheel["name"]] = wheel
    require(all(name in by_name and by_name[name]["version"] == version for name, version in ROOTS.items()),
            "PINNED_ROOTS_MISSING")
    visited, pending = set(), list(ROOTS)
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        for text in by_name[name]["active_requires_dist"]:
            req = Requirement(text)
            dependency = canonicalize_name(req.name)
            require(dependency in by_name and Version(by_name[dependency]["version"]) in req.specifier,
                    "ACTIVE_DEPENDENCY_UNSATISFIED")
            pending.append(dependency)
    require(visited == set(by_name), "UNRELATED_DISTRIBUTION_NOT_ALLOWED")
    return sorted(visited)


def official_pypi_record(wheel):
    url = "https://pypi.org/pypi/" + quote(wheel["name"], safe="") + "/" + quote(wheel["version"], safe="") + "/json"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "FOX-offline-wheelhouse/1"})
    # No proxy, netrc or user-supplied certificates/headers are used.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=60) as response:
        require(response.status == 200 and response.url == url, "PYPI_METADATA_RESPONSE_INVALID")
        raw = response.read(MAX_JSON_BYTES + 1)
    require(len(raw) <= MAX_JSON_BYTES, "PYPI_METADATA_TOO_LARGE")
    value = json.loads(raw)
    choices = [entry for entry in value.get("urls", []) if entry.get("filename") == wheel["filename"]]
    require(len(choices) == 1, "WHEEL_NOT_IN_OFFICIAL_PYPI")
    entry = choices[0]
    parsed = urlsplit(entry.get("url", ""))
    require(entry.get("packagetype") == "bdist_wheel" and entry.get("digests", {}).get("sha256") == wheel["sha256"]
        and entry.get("size") == wheel["bytes"] and entry.get("yanked") is False
        and parsed.scheme == "https" and parsed.hostname == "files.pythonhosted.org"
        and not any((parsed.username, parsed.password, parsed.query, parsed.fragment)), "OFFICIAL_PYPI_HASH_MISMATCH")
    return {"metadata_url": url, "metadata_sha256": digest(raw), "download_url": entry["url"],
        "filename": wheel["filename"], "sha256": wheel["sha256"], "bytes": wheel["bytes"], "yanked": False}


def download_command(output):
    command = [sys.executable, "-I", "-B", "-m", "pip", "--disable-pip-version-check", "download",
        "--index-url", "https://pypi.org/simple", "--only-binary=:all:", "--no-cache-dir", "--no-input",
        "--dest", str(output), "--implementation", "cp", "--python-version", "3.11"]
    for platform in PLATFORMS:
        command += ["--platform", platform]
    for abi in ("cp311", "abi3", "none"):
        command += ["--abi", abi]
    return command + [f"{name}=={version}" for name, version in sorted(ROOTS.items())]


def prepare(output):
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and output.parent.is_dir()
        and output.parent.resolve() == output.parent, "FRESH_OUTPUT_DIRECTORY_REQUIRED")
    output.mkdir(mode=0o700)
    wheels_dir = output / "wheelhouse"
    wheels_dir.mkdir(mode=0o700)
    intent = {"schema_version": 1, "scope": "fox-host-python-wheelhouse-intent-v1", "roots": ROOTS,
        "target_python": TARGET_PYTHON, "platforms": PLATFORMS, "installed": False,
        "download_python": {"version": list(sys.version_info[:3]), "sha256": digest(Path(sys.executable).read_bytes())},
        "pip_version": importlib.metadata.version("pip"), "packaging_version": importlib.metadata.version("packaging"),
        "helper_sha256": digest(Path(__file__).read_bytes())}
    (output / "intent.json").write_bytes(canonical(intent))
    # PIP_CONFIG_FILE=NUL/devnull disables all configuration files. No inherited
    # PIP_*, proxy, token, index or arbitrary Python environment reaches pip.
    allowed = {"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATH", "PATHEXT", "TEMP", "TMP", "COMSPEC"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update(PIP_CONFIG_FILE=os.devnull, PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
    result = subprocess.run(download_command(wheels_dir), input=b"", stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=1200, env=environment, cwd=output)
    (output / "download-result.json").write_bytes(canonical({"exit_code": result.returncode,
        "stdout_sha256": digest(result.stdout), "stderr_sha256": digest(result.stderr)}))
    require(result.returncode == 0, "DOWNLOAD_FAILED_PARTIAL_DIRECTORY_PRESERVED")
    return verify_download(output)


def verify_download(output):
    """Recheck an already completed download, without running pip again."""
    output = Path(output).absolute()
    require(output.is_dir() and not output.is_symlink() and output.resolve() == output
        and not (output / "evidence.json").exists() and not (output / "requirements.lock").exists(),
        "UNPUBLISHED_DOWNLOAD_REQUIRED")
    intent = json.loads((output / "intent.json").read_bytes())
    downloaded = json.loads((output / "download-result.json").read_bytes())
    require(intent.get("roots") == ROOTS and intent.get("target_python") == TARGET_PYTHON
        and intent.get("platforms") == list(PLATFORMS) and downloaded.get("exit_code") == 0,
        "COMPLETED_PINNED_DOWNLOAD_REQUIRED")
    wheels_dir = output / "wheelhouse"
    require(wheels_dir.is_dir() and not wheels_dir.is_symlink(), "WHEELHOUSE_DIRECTORY_INVALID")
    paths = sorted(wheels_dir.iterdir())
    require(0 < len(paths) <= 40 and all(path.suffix == ".whl" for path in paths)
        and sum(path.stat().st_size for path in paths) <= MAX_COLLECTION_BYTES, "WHEELHOUSE_BOUNDS_INVALID")
    wheels = [wheel_metadata(path) for path in paths]
    closure = dependency_closure(wheels)
    official = [official_pypi_record(wheel) for wheel in wheels]
    lock = "# Linux x86_64 / glibc <=2.28 / CPython3.11; generated after PyPI and RECORD verification.\n"
    lock += "\n".join(f"{wheel['name']}=={wheel['version']} --hash=sha256:{wheel['sha256']}"
                      for wheel in sorted(wheels, key=lambda item: item["name"])) + "\n"
    with (output / "requirements.lock").open("xb") as stream:
        stream.write(lock.encode())
    report = {"schema_version": 1, "scope": "fox-host-python-wheelhouse-v1", "status": "VERIFIED_DOWNLOAD",
        "target_python": TARGET_PYTHON, "target_os": "Linux x86_64 glibc2.28", "platforms": PLATFORMS,
        "roots": ROOTS, "dependency_closure": closure, "wheels": wheels, "official_pypi": official,
        "requirements_lock_sha256": digest(lock.encode()), "download_helper_sha256": intent["helper_sha256"],
        "helper_sha256": digest(Path(__file__).read_bytes()),
        "download_python": intent["download_python"], "pip_version": intent["pip_version"],
        "packaging_version": intent["packaging_version"],
        "installed": False, "vm_contacted": False,
        "limits": ["Wheel metadata and hashes are verified; host import/runtime testing remains required.",
            "No venv or system package was installed; no OCI or database request was made."]}
    with (output / "evidence.json").open("xb") as stream:
        stream.write(canonical(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-existing", action="store_true", help="Recheck completed download; do not run pip or download again.")
    args = parser.parse_args()
    try:
        result = verify_download(args.output) if args.verify_existing else prepare(args.output)
        print(json.dumps({"status": result["status"], "distributions": result["dependency_closure"],
                          "evidence": str(args.output / "evidence.json"), "installed": False}))
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, ValueError) and re.fullmatch("[A-Z0-9_]+", str(error)) else "WHEELHOUSE_PREPARATION_FAILED"
        print(json.dumps({"status": "NOT_VERIFIED", "code": code, "partial_files_preserved": True, "installed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
