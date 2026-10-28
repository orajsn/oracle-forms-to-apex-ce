"""JSN-only offline image staging/build, deliberately without activation.

Run on the existing opc host after reviewing this file and the prepared archive.
No container is started/stopped/renamed, no service or network is changed, and
no configuration or secret is provisioned. An uncertain build is not replayed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import urllib.request


BASE = {
    "fox": {"id": "00d59808b89b0380b6a1cdd2f5d8c1656f81df83c8b9c1f25e15adf795ab556a",
            "image": "sha256:9ce6e594cffedfbe85d3431af8ad929bb83222a2e1fd4b8521cad8edd9e52490"},
    "forms2apex-mcp": {"id": "3d4294a16022444260ce242e18e7b749f967aba46e0023c7b9fc8b37ba20659a",
                      "image": "sha256:c7fdb53bc04450e297cbbbc89fb834be714e106d5a164b1c80dc77d544db5a1b"},
    "oracle-applied-ai-label": {"id": "ccaa17a43d933ffc6b6917e0c79aaa1a525c3f5f9cd8ae9133261ed359436ba9",
                                "image": "sha256:7c7ebc1f3da055ab3887a520e25552142f0a37f6d05dd116c16a87cac59fee8f"},
}
SCOPE = {"instance_id": "ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea",
         "compartment_id": "ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba",
         "region": "us-ashburn-1"}
PARENT = Path("/home/opc/.local/share/fox-project-builds")
MAX_ARCHIVE = 180_000_000
MAX_FILE = 8_000_000
PUBLIC_PROFILE = "bundle/deployment/project-opaf-profile-v2.json"
QA_CONTRACT_FILES = ('__init__.py','intake.py','native_source.py','project_conversion.py',
                     'native_qa_plan.py','project_qa_plan.py')


class StageError(RuntimeError):
    pass


def need(value, code):
    if not value:
        raise StageError(code)


def digest(raw):
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


def document(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(StageError("INVALID_JSON_CONSTANT")))


def safe_name(name):
    path = PurePosixPath(name)
    need(type(name) is str and 0 < len(name) <= 512 and name == path.as_posix()
         and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", name)
         and not path.is_absolute() and "\\" not in name and ":" not in name
         and all(part not in (".", "..") for part in path.parts), "UNSAFE_ARCHIVE_PATH")
    return name


def public_profile(raw):
    """The sole world-readable B file is a bounded, public-only role profile."""
    need(0 < len(raw) <= 65_536, "PUBLIC_PROFILE_INVALID")
    value = document(raw)
    fixed = {"schema_version": 2, "profile_id": "native-project-v1",
             "native_project_schema_versions": [1, 2], "storage_mapping_scope": "fox-project-storage-v1",
             "module_execution_scope": "fox-project-module-execution-v2",
             "opaf_base_url": "https://localhost:8080/agentFactory",
             "certificate_sha256": "68be4eeb6c362a46c0f1cb8bc4eda4585772a8f8a778dbace28cb60992830f93"}
    need(type(value) is dict and set(value) == set(fixed) | {"mapper", "reviewer"}
         and type(value["schema_version"]) is int and all(value[key] == expected for key, expected in fixed.items())
         and all(type(item) is int for item in value["native_project_schema_versions"]), "PUBLIC_PROFILE_INVALID")
    for role in ("mapper", "reviewer"):
        item = value[role]
        need(type(item) is dict and set(item) == {"workflow_id", "model", "graph_sha256"}
             and item["model"] == "xai.grok-4.3"
             and type(item["workflow_id"]) is str and re.fullmatch(r"[A-Fa-f0-9]{16,64}", item["workflow_id"])
             and type(item["graph_sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", item["graph_sha256"]),
             "PUBLIC_PROFILE_INVALID")
    need(value["mapper"]["workflow_id"].upper() != value["reviewer"]["workflow_id"].upper(), "PUBLIC_PROFILE_INVALID")
    return value


def load_archive(raw, expected_sha256):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE
         and re.fullmatch(r"[a-f0-9]{64}", expected_sha256 or "")
         and digest(raw) == expected_sha256, "EXACT_ARCHIVE_SHA_REQUIRED")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = safe_name(member.name)
            need(member.isfile() and not member.issparse() and not member.pax_headers
                 and name not in files and 0 <= member.size <= MAX_FILE
                 and len(files) < 2000, "UNSAFE_ARCHIVE_MEMBER")
            files[name] = archive.extractfile(member).read(MAX_FILE + 1)
            need(len(files[name]) == member.size, "ARCHIVE_MEMBER_SIZE_DIFFERS")
    return validate_files(files)


def validate_files(files):
    need("manifest.json" in files, "ARCHIVE_MANIFEST_MISSING")
    manifest = document(files["manifest.json"])
    expected_fields = {"schema_version", "scope", "source_bundle_sha256", "base_images", "files",
                       "activation_performed", "rollback_policy"}
    need(type(manifest) is dict and set(manifest) == expected_fields
         and manifest["schema_version"] == 1 and manifest["scope"] == "fox-paired-build-archive-v1"
         and manifest["activation_performed"] is False
         and manifest["base_images"] == {"fox": BASE["fox"]["image"], "converter": BASE["forms2apex-mcp"]["image"]}
         and type(manifest["files"]) is dict and manifest["files"].keys() == files.keys() - {"manifest.json"},
         "ARCHIVE_MANIFEST_INVALID")
    for name, reference in manifest["files"].items():
        need(reference == {"sha256": digest(files[name]), "bytes": len(files[name])}, "ARCHIVE_MEMBER_HASH_DIFFERS")
        need(name.startswith(("bundle/", "build/fox/", "build/converter/"))
             or name in ("source-inventory.json", "build-evidence.json"), "UNEXPECTED_ARCHIVE_MEMBER")
    inv = document(files["source-inventory.json"])
    bundle = {name[7:]: value for name, value in files.items() if name.startswith("bundle/")}
    need(inv == {"schema_version": 1, "scope": "fox-hosted-source-inventory-v1",
                 "files": {name: digest(value) for name, value in sorted(bundle.items())}}
         and canonical(inv) == files["source-inventory.json"]
         and digest(files["source-inventory.json"]) == manifest["source_bundle_sha256"], "SOURCE_INVENTORY_DIFFERS")
    need("qa/operator/hosted_service.py" in bundle
         and "converter/defusedxml/ElementTree.py" in bundle
         and "converter/fox_source_contract/source-manifest.json" in bundle
         and "fox/dist/index.html" in bundle, "REQUIRED_PAIRED_SOURCE_MISSING")
    need(PUBLIC_PROFILE in files, "PUBLIC_PROFILE_REQUIRED")
    public_profile(files[PUBLIC_PROFILE])
    # Build contexts must be byte-for-byte projections of the source bundle.
    # Rehashing a modified context/manifest cannot evade the caller-pinned B.
    contexts = {"build/fox/fox/" + name.removeprefix("fox/fox/"): raw
                for name, raw in bundle.items() if name.startswith("fox/fox/")}
    contexts.update({"build/fox/dist/" + name.removeprefix("fox/dist/"): raw
                     for name, raw in bundle.items() if name.startswith("fox/dist/")})
    contexts.update({"build/converter/converter/" + name.removeprefix("converter/"): raw
                     for name, raw in bundle.items() if name.startswith("converter/")})
    for role in ("fox", "converter"):
        recipe = "deployment/Containerfile.project-" + role
        need(recipe in bundle, "BOUND_IMAGE_RECIPE_REQUIRED")
        contexts["build/" + role + "/Containerfile"] = bundle[recipe]
    # Retained historical archives have no QA-contract COPY instruction and
    # keep their exact older context. New recipes require the full fixed pure
    # closure, projected byte-for-byte from the caller-pinned source bundle.
    if b'COPY --chown=10001:10001 qa-contract /opt/forms2apex/converter/fox\n' in bundle['deployment/Containerfile.project-converter']:
        need(all('fox/fox/'+name in bundle for name in QA_CONTRACT_FILES),'COMPLETE_QA_CONTRACT_SOURCE_REQUIRED')
        contexts.update({'build/converter/qa-contract/'+name:bundle['fox/fox/'+name] for name in QA_CONTRACT_FILES})
    need({name: raw for name, raw in files.items() if name.startswith("build/")} == contexts,
         "BUILD_CONTEXT_DIFFERS_FROM_SOURCE_BUNDLE")
    return files, manifest


def command(argv, *, timeout=30):
    outcome = subprocess.run(argv, capture_output=True, timeout=timeout, env={
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/opc", "XDG_RUNTIME_DIR": "/run/user/1000",
        "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})
    need(outcome.returncode == 0 and len(outcome.stdout) <= 2_000_000, "READ_ONLY_HOST_COMMAND_FAILED")
    return outcome.stdout


def deployment_document(reference):
    """Explicit current-lab declaration, not startup or activation authority."""
    need(type(reference) is tuple and len(reference)==2,'PINNED_DEPLOYMENT_BYTES_REQUIRED')
    raw,expected=reference
    need(type(raw)is bytes and 0<len(raw)<=65536 and type(expected)is str
         and re.fullmatch('[a-f0-9]{64}',expected) and digest(raw)==expected,'DEPLOYMENT_DIGEST_CHANGED')
    value=document(raw)
    need(type(value)is dict and set(value)=={'schema_version','scope','provider_configuration_sha256',
        'current_release_sha256','infrastructure'} and canonical(value)==raw
        and type(value['schema_version'])is int and value['schema_version']==1
        and value['scope']=='fox-hosted-admission-v1','DEPLOYMENT_DOCUMENT_INVALID')
    need(all(type(value[key])is str and re.fullmatch('[a-f0-9]{64}',value[key]) for key in
        ('provider_configuration_sha256','current_release_sha256')),'DEPLOYMENT_BINDING_INVALID')
    pins=value['infrastructure']
    need(type(pins)is dict and set(pins)==set(BASE),'EXACT_DEPLOYMENT_ROLES_REQUIRED')
    ids=set()
    for pin in pins.values():
        need(type(pin)is dict and set(pin)=={'id','image'} and type(pin['id'])is str
             and re.fullmatch('[a-f0-9]{64}',pin['id']) and type(pin['image'])is str
             and re.fullmatch('sha256:[a-f0-9]{64}',pin['image']) and pin['id'] not in ids,
             'EXACT_DEPLOYMENT_PINS_REQUIRED')
        ids.add(pin['id'])
    return value


def guarded_host(destination, *, deployment=None):
    need(os.name == "posix" and os.geteuid() == 1000, "EXISTING_OPC_HOST_REQUIRED")
    request = urllib.request.Request("http://169.254.169.254/opc/v2/instance/", headers={"Authorization": "Bearer Oracle"})
    with urllib.request.urlopen(request, timeout=10) as response:
        metadata = document(response.read(100001))
    identity = {"instance_id": metadata.get("id"), "compartment_id": metadata.get("compartmentId"),
                "region": metadata.get("canonicalRegionName", metadata.get("regionInfo", {}).get("regionIdentifier"))}
    need(identity == SCOPE, "EXACT_JSN_HOST_REQUIRED")
    declared=deployment_document(deployment) if deployment is not None else None
    pins=declared['infrastructure'] if declared is not None else BASE
    containers = document(command(["podman", "inspect", *pins]))
    result, mounts = {}, []
    for value in containers:
        name = value["Name"].lstrip("/")
        need(name in pins and name not in result and value["State"]["Running"] is True
             and value["Id"] == pins[name]["id"]
             and "sha256:" + value["Image"].split(":")[-1] == pins[name]["image"], "BASELINE_CONTAINER_CHANGED")
        result[name] = {**pins[name], "started_at": value["State"]["StartedAt"]}
        if declared is not None:
            need(type(value['State'].get('Pid'))is int and value['State']['Pid']>0,'RUNNING_DEPLOYMENT_PID_REQUIRED')
            result[name].update(pid=value['State']['Pid'],configuration_sha256=digest(canonical({
                key:value.get(key) for key in ('Config','HostConfig','Mounts','ProcessLabel','MountLabel')})))
            if name=='fox':
                pairs=value['Config'].get('Env',[])
                need(type(pairs)is list and all(type(item)is str and '=' in item for item in pairs),'FOX_ENVIRONMENT_INVALID')
                env=dict(item.split('=',1) for item in pairs)
                need(len(env)==len(pairs) and env.get('FOX_VERIFIER_RELEASE_SHA256')==declared['current_release_sha256']
                     and env.get('FOX_CONVERSION_PROFILE')=='native-project-v1','RUNNING_DEPLOYMENT_RELEASE_CHANGED')
        mounts.extend(Path(item["Source"]) for item in value.get("Mounts", []) if item.get("Source"))
    need(result.keys() == pins.keys(), "BASELINE_CONTAINER_INVENTORY_DIFFERS")
    for mount in mounts:
        need(destination != mount and mount not in destination.parents and destination not in mount.parents,
             "BUILD_PATH_OVERLAPS_LIVE_MOUNT")
    observed={"scope": identity, "containers": result}
    if declared is not None:
        observed.update(deployment_sha256=deployment[1],release_sha256=declared['current_release_sha256'],
            provider_configuration_sha256=declared['provider_configuration_sha256'])
    return observed


def _guarded_host(destination,deployment):
    # Keep the original one-argument path intact for historical callers/tests.
    return guarded_host(destination) if deployment is None else guarded_host(destination,deployment=deployment)


def build_capacity():
    graph=Path(command(['podman','info','--format','{{.Store.GraphRoot}}']).decode().strip())
    need(graph.is_absolute() and graph.resolve()==graph and graph.is_dir(),'CANONICAL_BUILD_STORAGE_REQUIRED')
    free=os.statvfs(graph)
    need(free.f_bavail*free.f_frsize>=2*1024**3,'BUILD_STORAGE_CAPACITY_LOW')
    return {'available_bytes':free.f_bavail*free.f_frsize,'minimum_bytes':2*1024**3}


def build_process_identity(pid):
    """Read a Popen-owned Linux identity, never infer liveness from a PID file."""
    need(type(pid)is int and pid>0,'OWNED_BUILD_PID_REQUIRED')
    root=Path('/proc')/str(pid)
    try:
        before=(root/'stat').read_text();fields=before[before.rfind(') ')+2:].split()
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        after=(root/'stat').read_text();again=after[after.rfind(') ')+2:].split()
    except FileNotFoundError:
        return None  # Only wait() may establish the original command's exit.
    need(len(fields)>=20 and len(again)>=20 and fields[19].isdigit() and fields[19]==again[19]
         and re.fullmatch('[a-f0-9-]{36}',boot),'BUILD_PROCESS_IDENTITY_UNCONFIRMED')
    return {'pid':pid,'start_ticks':int(fields[19]),'boot_id':boot}


def checked_ancestors(path):
    need(path.is_absolute() and path.resolve() == path, "BUILD_PATH_LINK_FORBIDDEN")
    for entry in (path, *path.parents):
        info = entry.lstat()
        sticky_parent = (entry != path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                         and bool(info.st_mode & stat.S_ISVTX))
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid())
             and (not stat.S_IMODE(info.st_mode) & 0o022 or sticky_parent), "BUILD_PATH_NOT_OWNER_CONTROLLED")


def checked_path(path, *, directory=False, public_profile_file=False):
    checked_ancestors(path)
    info = path.lstat()
    need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
         and (directory or info.st_nlink == 1)
         and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o644 if public_profile_file else 0o600),
         "PRIVATE_BUILD_PATH_REQUIRED")


def new_file(path, raw):
    need(not path.exists() and not path.is_symlink(), "BUILD_ARTIFACT_ALREADY_EXISTS")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def stage(raw, sha, *, deployment=None):
    files, manifest = load_archive(raw, sha)
    target = PARENT / manifest["source_bundle_sha256"]
    before = _guarded_host(target,deployment)
    need(not target.exists() and not target.is_symlink(), "STAGE_ALREADY_EXISTS_USE_INSPECT")
    # Never chmod/reown existing parents. Only create this bounded private root.
    checked_ancestors(PARENT.parent)
    need(PARENT.parent.is_dir(), "BUILD_PARENT_DIRECTORY_REQUIRED")
    if not PARENT.exists():
        PARENT.mkdir(mode=0o700)
    checked_path(PARENT, directory=True)
    target.mkdir(mode=0o700)
    for name, content in sorted(files.items()):
        destination = target / name
        for ancestor in reversed(destination.parent.relative_to(target).parents):
            folder = target / ancestor
            if folder != target and not folder.exists():
                folder.mkdir(mode=0o700)
        if not destination.parent.exists():
            destination.parent.mkdir(mode=0o700)
        new_file(destination, content)
        if name == PUBLIC_PROFILE:
            # This named public-only JSON is bind-mounted into FOX's existing
            # default rootless namespace. Other B files remain owner-only.
            public_profile(content)
            descriptor = os.open(destination, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    after = _guarded_host(target,deployment)
    need(before == after, "BASELINE_CHANGED_DURING_STAGE")
    receipt = {"schema_version": 1, "scope": "fox-paired-source-staged-v1", "archive_sha256": sha,
               "source_bundle_sha256": manifest["source_bundle_sha256"], "target": str(target),
               "manifest_sha256": digest(files["manifest.json"]),
               "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "baseline": after,
               "activation_performed": False}
    new_file(target / "stage-receipt.json", canonical(receipt))
    return receipt


def inspect(bundle_sha, *, deployment=None):
    need(re.fullmatch(r"[a-f0-9]{64}", bundle_sha or ""), "SOURCE_BUNDLE_SHA_REQUIRED")
    target = PARENT / bundle_sha
    baseline = _guarded_host(target,deployment)
    checked_path(target, directory=True)
    checked_path(target / "manifest.json")
    manifest_raw = (target / "manifest.json").read_bytes()
    manifest = document(manifest_raw)
    need(manifest["source_bundle_sha256"] == bundle_sha, "STAGED_BUNDLE_CHANGED")
    files = {"manifest.json": manifest_raw}
    for name, reference in manifest["files"].items():
        path = target / safe_name(name)
        checked_path(path, public_profile_file=name == PUBLIC_PROFILE)
        need(path.stat().st_size == reference["bytes"] and digest(path.read_bytes()) == reference["sha256"],
             "STAGED_MEMBER_CHANGED")
        files[name] = path.read_bytes()
    validate_files(files)
    for prefix in ("bundle", "build"):
        actual = set()
        for path in (target / prefix).rglob("*"):
            need(not path.is_symlink(), "STAGED_LINK_FORBIDDEN")
            if path.is_file():
                actual.add(path.relative_to(target).as_posix())
        need(actual == {name for name in files if name.startswith(prefix + "/")}, "STAGED_MEMBERSHIP_CHANGED")
    receipt_path = target / "stage-receipt.json"
    checked_path(receipt_path)
    receipt = document(receipt_path.read_bytes())
    need(receipt["source_bundle_sha256"] == bundle_sha and receipt["baseline"] == baseline
         and receipt["manifest_sha256"] == digest(manifest_raw),
         "STAGED_BASELINE_CHANGED")
    return {"status": "STAGED_NOT_ACTIVATED", "source_bundle_sha256": bundle_sha,
            "target": str(target), "baseline": baseline,
            "builds": {role: {"intent": (target / (role + "-build-intent.json")).exists(),
                              "complete": (target / (role + "-build-complete.json")).exists()}
                       for role in ("fox", "converter")}}


def build(bundle_sha, role, *, apply, deployment=None):
    need(apply is True and role in ("fox", "converter"), "EXPLICIT_IMAGE_BUILD_REQUIRED")
    observed = inspect(bundle_sha) if deployment is None else inspect(bundle_sha,deployment=deployment)
    target = PARENT / bundle_sha
    need(not observed["builds"][role]["intent"] and not observed["builds"][role]["complete"],
         "EXISTING_BUILD_MUST_NOT_BE_REPLAYED")
    capacity=build_capacity() if deployment is not None else None
    base = BASE["fox" if role == "fox" else "forms2apex-mcp"]["image"]
    image = document(command(["podman", "image", "inspect", base]))[0]
    need("sha256:" + image["Id"].split(":")[-1] == base
         and image["Os"] == "linux" and image["Architecture"] == "amd64", "BASE_IMAGE_DIFFERS")
    iid = target / (role + "-image.id")
    argv = ["podman", "build", "--pull=never", "--network=none", "--iidfile", str(iid),
            "--label", "com.oracle.jsn.fox.source-bundle=" + bundle_sha,
            "--file", str(target / "build" / role / "Containerfile"), str(target / "build" / role)]
    new_file(target / (role + "-build-intent.json"), canonical({"source_bundle_sha256": bundle_sha,
        "role": role, "base_image": base, "argv": argv, "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "automatic_replay_permitted": False}))
    _guarded_host(target,deployment)
    with (target / (role + "-build.stdout")).open("xb") as stdout, (target / (role + "-build.stderr")).open("xb") as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/opc", "XDG_RUNTIME_DIR": "/run/user/1000", "LANG": "C.UTF-8"})
        identity={'pid':process.pid,'recorded_at_utc':datetime.now(timezone.utc).isoformat(),'source_bundle_sha256':bundle_sha}
        if deployment is not None:identity['linux_identity']=build_process_identity(process.pid)
        new_file(target / (role + "-build-process.json"), canonical(identity))
        try:
            code = process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            raise StageError("BUILD_STILL_UNCONFIRMED_INSPECT_RECORDED_PROCESS_NO_REPLAY") from None
    if deployment is not None:
        new_file(target/(role+'-build-exit.json'),canonical({'exit_code':code,'observed_original_process':True,
            'recorded_at_utc':datetime.now(timezone.utc).isoformat()}))
    after = _guarded_host(target,deployment)
    need(code == 0 and after == observed["baseline"], "BUILD_FAILED_OR_BASELINE_CHANGED_NO_REPLAY")
    built = iid.read_text().strip()
    if re.fullmatch(r"[a-f0-9]{64}", built):
        built = "sha256:" + built
    need(re.fullmatch(r"sha256:[a-f0-9]{64}", built) and built != base, "NEW_IMAGE_ID_REQUIRED")
    actual = document(command(["podman", "image", "inspect", built]))[0]
    need("sha256:" + actual["Id"].split(":")[-1] == built
         and actual.get("Labels", {}).get("com.oracle.jsn.fox.source-bundle") == bundle_sha,
         "BUILT_IMAGE_BINDING_DIFFERS")
    result = {"status": "BUILT_NOT_ACTIVATED", "role": role, "source_bundle_sha256": bundle_sha,
              "image": built, "exit_code": code, "baseline_unchanged": True,
              "recorded_at_utc": datetime.now(timezone.utc).isoformat()}
    if deployment is not None:
        result.update(deployment_sha256=deployment[1],capacity=capacity,activation_performed=False)
    new_file(target / (role + "-build-complete.json"), canonical(result))
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("stage", "inspect", "build"))
    parser.add_argument("--archive")
    parser.add_argument("--archive-sha256")
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--role", choices=("fox", "converter"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument('--deployment-file')
    parser.add_argument('--deployment-sha256')
    args = parser.parse_args()
    need(bool(args.deployment_file)==bool(args.deployment_sha256),'EXPLICIT_DEPLOYMENT_REFERENCE_REQUIRED')
    deployment=None
    if args.deployment_file:
        path=Path(args.deployment_file);checked_path(path)
        need(path.stat().st_size<=65536,'DEPLOYMENT_DOCUMENT_TOO_LARGE')
        deployment=(path.read_bytes(),args.deployment_sha256);deployment_document(deployment)
    if args.action == "stage":
        need(args.apply and args.archive and args.archive_sha256 and not args.bundle_sha256 and not args.role,
             "EXPLICIT_STAGE_REQUIRED")
        path = Path(args.archive)
        checked_path(path)
        need(path.stat().st_size <= MAX_ARCHIVE, "ARCHIVE_TOO_LARGE")
        result = stage(path.read_bytes(), args.archive_sha256,deployment=deployment)
    elif args.action == "inspect":
        need(not args.apply and not args.archive and not args.role, "READ_ONLY_INSPECT_REQUIRED")
        result = inspect(args.bundle_sha256,deployment=deployment)
    else:
        need(not args.archive and not args.archive_sha256, "BUILD_ARGUMENTS_INVALID")
        result = build(args.bundle_sha256, args.role, apply=args.apply,deployment=deployment)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"status": "NOT_CONFIRMED", "code": str(error) if type(error) is StageError else "BUILD_GUARD_FAILED",
                          "automatic_replay_permitted": False}), file=sys.stderr)
        sys.exit(1)
