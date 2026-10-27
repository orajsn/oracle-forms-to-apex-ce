"""Install one reviewed offline operator venv on the existing JSN host.

No system package/default interpreter is changed. A fresh private directory,
exact PyPI-verified wheelhouse evidence and --apply are required. Interrupted
or failed installation is preserved for inspection and never replayed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import urllib.request


BASE_PYTHON = Path("/usr/bin/python3.11")
BASE_PYTHON_SHA256 = "c759e9b6a99538c4a37610e2268c29884594912e64af7b40fff4bf7814c02df2"
PARENT = Path("/home/opc/.local/share/fox-host-python")
EXPECTED_VERSION = [3, 11, 13]
ROOTS = {"oci": "2.188.0", "defusedxml": "0.7.1"}
BASE = {
    "fox": ("00d59808b89b0380b6a1cdd2f5d8c1656f81df83c8b9c1f25e15adf795ab556a", "9ce6e594cffedfbe85d3431af8ad929bb83222a2e1fd4b8521cad8edd9e52490"),
    "forms2apex-mcp": ("3d4294a16022444260ce242e18e7b749f967aba46e0023c7b9fc8b37ba20659a", "c7fdb53bc04450e297cbbbc89fb834be714e106d5a164b1c80dc77d544db5a1b"),
    "oracle-applied-ai-label": ("ccaa17a43d933ffc6b6917e0c79aaa1a525c3f5f9cd8ae9133261ed359436ba9", "7c7ebc1f3da055ab3887a520e25552142f0a37f6d05dd116c16a87cac59fee8f"),
}


class InstallError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise InstallError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def parsed(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(InstallError("INVALID_JSON_CONSTANT")))


def ancestors(path):
    need(path.is_absolute() and path.resolve() == path, "LINKED_INSTALL_PATH_FORBIDDEN")
    for entry in (path, *path.parents):
        info = entry.lstat()
        sticky = entry != path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid())
             and (not stat.S_IMODE(info.st_mode) & 0o022 or sticky), "INSTALL_PATH_NOT_OWNER_CONTROLLED")


def private_directory(path):
    ancestors(path)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
         "PRIVATE_INSTALL_DIRECTORY_REQUIRED")


def read(path, maximum=100_000_000, *, private=True, allow_root_hardlinks=False):
    ancestors(path)
    info = path.lstat()
    trusted_links = allow_root_hardlinks and not private and info.st_uid == 0 and info.st_nlink >= 1
    need(stat.S_ISREG(info.st_mode) and (info.st_nlink == 1 or trusted_links) and 0 < info.st_size <= maximum,
         "REGULAR_BOUNDED_INSTALL_INPUT_REQUIRED")
    if private:
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, "PRIVATE_INSTALL_INPUT_REQUIRED")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        need((opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size), "INSTALL_INPUT_CHANGED")
        raw = stream.read(maximum + 1)
    after = path.lstat()
    need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
         and len(raw) == info.st_size, "INSTALL_INPUT_CHANGED")
    return raw


def new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync_directory(path.parent)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def mkdir_new(path):
    path.mkdir(mode=0o700)
    sync_directory(path.parent)


def environment(home):
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(home), "XDG_RUNTIME_DIR": "/run/user/1000",
            "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
            "PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}


def observe_command(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=30, env=environment("/home/opc"))
    need(result.returncode == 0 and len(result.stdout) <= 2_000_000, "READ_ONLY_HOST_PROBE_FAILED")
    return result.stdout


def host_guard(destination):
    need(os.name == "posix" and os.geteuid() == 1000 and platform.machine() == "x86_64", "EXISTING_OPC_LINUX_HOST_REQUIRED")
    request = urllib.request.Request("http://169.254.169.254/opc/v2/instance/", headers={"Authorization": "Bearer Oracle"})
    with urllib.request.urlopen(request, timeout=10) as response:
        identity = parsed(response.read(100001))
    need(identity.get("id") == "ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea"
         and identity.get("compartmentId") == "ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba"
         and identity.get("canonicalRegionName", identity.get("regionInfo", {}).get("regionIdentifier")) == "us-ashburn-1",
         "EXACT_JSN_VM_REQUIRED")
    need(sha(read(BASE_PYTHON, private=False)) == BASE_PYTHON_SHA256, "REVIEWED_HOST_PYTHON_CHANGED")
    version = parsed(observe_command([str(BASE_PYTHON), "-I", "-B", "-c", "import json,sys;print(json.dumps(list(sys.version_info[:3])))"]))
    need(version == EXPECTED_VERSION, "REVIEWED_HOST_PYTHON_VERSION_CHANGED")
    libc = platform.libc_ver()
    need(libc[0] == "glibc" and tuple(int(value) for value in libc[1].split(".")) >= (2, 28), "HOST_GLIBC_TOO_OLD")
    observed, mounts = {}, []
    for item in parsed(observe_command(["podman", "inspect", *BASE])):
        name = item["Name"].lstrip("/")
        need(name in BASE and name not in observed and item["State"]["Running"] is True
             and (item["Id"], item["Image"].split(":")[-1]) == BASE[name], "BASELINE_CONTAINER_CHANGED")
        observed[name] = {"id": item["Id"], "image": item["Image"].split(":")[-1], "started_at": item["State"]["StartedAt"]}
        mounts.extend(Path(value["Source"]) for value in item.get("Mounts", []) if value.get("Source"))
    need(observed.keys() == BASE.keys(), "BASELINE_CONTAINER_INVENTORY_DIFFERS")
    for mount in [*mounts, Path("/home/opc/fox")]:
        need(destination != mount and mount not in destination.parents and destination not in mount.parents,
             "VENV_PATH_OVERLAPS_PUBLIC_MOUNT")
    system = Path("/usr/bin/python3").resolve(strict=True)
    need(system == Path("/usr/libexec/platform-python3.6"), "DEFAULT_SYSTEM_PYTHON_CHANGED")
    return {"containers": observed, "python311_sha256": BASE_PYTHON_SHA256,
            "system_python_path": str(system), "system_python_sha256": sha(read(system, private=False, allow_root_hardlinks=True)),
            "glibc": list(libc)}


def wheelhouse(root, evidence_sha256):
    root = Path(root).absolute()
    private_directory(root); private_directory(root / "wheelhouse")
    raw = read(root / "evidence.json", 10_000_000)
    need(re.fullmatch(r"[a-f0-9]{64}", evidence_sha256 or "") and sha(raw) == evidence_sha256,
         "EXACT_REVIEWED_WHEELHOUSE_REQUIRED")
    report = parsed(raw)
    need(report.get("schema_version") == 1 and report.get("scope") == "fox-host-python-wheelhouse-v1"
         and report.get("status") == "VERIFIED_DOWNLOAD" and report.get("roots") == ROOTS
         and report.get("target_python") == "3.11.13" and report.get("installed") is False,
         "WHEELHOUSE_REPORT_INVALID")
    rows = report.get("wheels")
    need(type(rows) is list and 0 < len(rows) <= 40, "WHEELHOUSE_REPORT_INVALID")
    names, distributions = set(), {}
    for row in rows:
        name = row["filename"]
        need(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]+\.whl", name) and name not in names
             and row["name"] not in distributions and row["record_integrity"] == "PASS", "WHEELHOUSE_MEMBER_INVALID")
        names.add(name); distributions[row["name"]] = row["version"]
        wheel = read(root / "wheelhouse" / name)
        need(len(wheel) == row["bytes"] and sha(wheel) == row["sha256"], "WHEELHOUSE_BYTES_CHANGED")
    need({path.name for path in (root / "wheelhouse").iterdir()} == names, "WHEELHOUSE_INVENTORY_CHANGED")
    lock = read(root / "requirements.lock", 65536)
    need(sha(lock) == report["requirements_lock_sha256"], "WHEELHOUSE_LOCK_CHANGED")
    active = [line for line in lock.decode().splitlines() if line.strip() and not line.startswith("#")]
    expected = [f"{row['name']}=={row['version']} --hash=sha256:{row['sha256']}" for row in sorted(rows, key=lambda row: row["name"])]
    need(active == expected, "WHEELHOUSE_LOCK_MEMBERS_CHANGED")
    return {"evidence_sha256": evidence_sha256, "requirements_sha256": sha(lock), "distributions": distributions}


def phase(target, name, argv, *, timeout=600):
    new(target / (name + "-intent.json"), canonical({"argv": argv, "started_at_utc": datetime.now(timezone.utc).isoformat(),
                                                  "automatic_replay_permitted": False}))
    host_guard(target)
    with (target / (name + ".stdout")).open("xb") as stdout, (target / (name + ".stderr")).open("xb") as stderr:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env=environment(target / "home"), cwd=target)
        new(target / (name + "-process.json"), canonical({"pid": process.pid, "started_at_utc": datetime.now(timezone.utc).isoformat()}))
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise InstallError("INSTALL_STILL_UNCONFIRMED_INSPECT_PID_NO_REPLAY") from None
    new(target / (name + "-exit.json"), canonical({"exit_code": code, "completed_at_utc": datetime.now(timezone.utc).isoformat()}))
    need(code == 0, "INSTALL_PHASE_FAILED_PRESERVED_NO_REPLAY")


PROBE = r'''
import importlib.metadata as m,json,pathlib,re,ssl,sys
import oci,cryptography,defusedxml.ElementTree
import aiohttp,crc32c,pkcs11,yarl,multidict,frozenlist,propcache,cffi,OpenSSL
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import hashes
digest=hashes.Hash(hashes.SHA256());digest.update(b'fox-host-runtime-probe')
assert len(digest.finalize())==32
print(json.dumps({'python':list(sys.version_info[:3]),'executable':sys.executable,'prefix':sys.prefix,'base_prefix':sys.base_prefix,'packages':{re.sub(r'[-_.]+','-',d.metadata['Name'].lower()):d.version for d in m.distributions()},'oci_imported':oci.__version__,'cryptography_imported':cryptography.__version__,'defusedxml_imported':m.version('defusedxml'),'stdlib_openssl':ssl.OPENSSL_VERSION,'crypto_backend_loaded':Binding().lib is not None,'crypto_sha256_executed':True,'native_modules_imported':['aiohttp','crc32c','pkcs11','yarl','multidict','frozenlist','propcache','cffi','OpenSSL'],'oci_or_database_request_made':False},sort_keys=True))
'''


def install(root, evidence_sha256, *, apply=False):
    need(apply is True, "EXPLICIT_VENV_INSTALL_REQUIRED")
    need(re.fullmatch(r"[a-f0-9]{64}", evidence_sha256 or ""), "EXACT_REVIEWED_WHEELHOUSE_REQUIRED")
    target = PARENT / evidence_sha256
    before = host_guard(target)
    contract = wheelhouse(root, evidence_sha256)
    need(not target.exists() and not target.is_symlink(), "EXISTING_INSTALL_PRESERVED_NO_REPLAY")
    ancestors(PARENT.parent)
    need(PARENT.parent.is_dir(), "PRIVATE_PARENT_REQUIRED")
    if not PARENT.exists(): mkdir_new(PARENT)
    private_directory(PARENT)
    mkdir_new(target); mkdir_new(target / "home")
    new(target / "install-intent.json", canonical({"scope": "fox-host-python-install-v1", "contract": contract,
        "target": str(target), "baseline": before, "helper_sha256": sha(Path(__file__).read_bytes()),
        "started_at_utc": datetime.now(timezone.utc).isoformat(), "automatic_replay_permitted": False}))
    venv = target / "venv"
    phase(target, "create-venv", [str(BASE_PYTHON), "-I", "-B", "-m", "venv", "--copies", str(venv)])
    python = venv / "bin/python3.11"
    interpreter_raw = read(python, private=False)
    need(sha(interpreter_raw) == BASE_PYTHON_SHA256, "VENV_COPIED_INTERPRETER_DIFFERS")
    phase(target, "check-pip-configuration", [str(python), "-I", "-B", "-c",
        "from pip._internal.configuration import Configuration; c=Configuration(isolated=True); c.load(); assert not dict(c.items()); print('ISOLATED_PIP_CONFIGURATION_EMPTY')"])
    # Revalidate the exact wheel bytes and lock immediately before offline pip.
    need(wheelhouse(root, evidence_sha256) == contract, "WHEELHOUSE_CHANGED_BEFORE_INSTALL")
    phase(target, "install-wheels", [str(python), "-I", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check",
        "install", "--no-index", "--no-cache-dir", "--no-input", "--no-compile", "--require-hashes", "--no-deps",
        "--find-links", str(Path(root) / "wheelhouse"), "--requirement", str(Path(root) / "requirements.lock")])
    phase(target, "check-dependencies", [str(python), "-I", "-B", "-m", "pip", "--isolated", "--disable-pip-version-check", "check"])
    phase(target, "runtime-probe", [str(python), "-I", "-B", "-c", PROBE])
    probe = parsed(read(target / "runtime-probe.stdout", 100_000))
    need(probe["python"] == EXPECTED_VERSION and probe["executable"] == str(python)
         and probe["prefix"] == str(venv) and probe["base_prefix"] != probe["prefix"]
         and all(probe["packages"].get(name) == version for name, version in contract["distributions"].items())
         and set(probe["packages"]) <= set(contract["distributions"]) | {"pip", "setuptools"}
         and probe["oci_imported"] == ROOTS["oci"] and probe["defusedxml_imported"] == ROOTS["defusedxml"]
         and probe["crypto_backend_loaded"] is True and probe["crypto_sha256_executed"] is True,
         "INSTALLED_RUNTIME_PROBE_DIFFERS")
    after = host_guard(target)
    need(after == before, "SYSTEM_PYTHON_OR_BASELINE_CHANGED")
    result = {"status": "INSTALLED_NOT_ACTIVATED", "scope": "fox-host-python-install-v1", "contract": contract,
              "python": {"path": str(python), "sha256": sha(read(python, private=False)), "version": EXPECTED_VERSION},
              "probe_sha256": sha(read(target / "runtime-probe.stdout", 100_000)), "baseline_unchanged": True,
              "instance_principal_connection_tested": False, "service_started": False,
              "completed_at_utc": datetime.now(timezone.utc).isoformat()}
    new(target / "install-complete.json", canonical(result))
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse-root", required=True)
    parser.add_argument("--evidence-sha256", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(install(Path(args.wheelhouse_root), args.evidence_sha256, apply=args.apply), sort_keys=True))


if __name__ == "__main__":
    try: main()
    except Exception as error:
        print(json.dumps({"status": "NOT_CONFIRMED", "code": str(error) if type(error) is InstallError else "INSTALL_GUARD_FAILED",
                          "automatic_replay_permitted": False}), file=sys.stderr)
        sys.exit(1)
