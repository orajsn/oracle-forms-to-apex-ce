"""Pure candidate packaging tests. No remote host or container is contacted."""
from __future__ import annotations

import copy
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
import tarfile

import pytest


HERE = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


p = module("prepare_project_release")
r = module("build_project_release")


def inputs():
    return {
        "files": {**{'fox/fox/'+name:b'# synthetic pure contract\n' for name in p.QA_CONTRACT_FILES},
                  "fox/fox/__init__.py": b"", "fox/fox/project_conversion.py": b"PROFILE_ID='native-project-v1'\n",
                  "qa/operator/hosted_service.py": b"# synthetic service\n",
                  "deployment/project-opaf-profile-v2.json": (HERE / "project-opaf-profile-v2.json").read_bytes()},
        "ui": {"index.html": b"<html>synthetic</html>", "assets/main-a.js": b"// synthetic"},
        "converter": {"forms2apex/__init__.py": b"", "fox_source_contract/source-manifest.json": b"{}\n",
                      "defusedxml/ElementTree.py": b"# synthetic dependency\n"},
        "build_evidence": {"synthetic": True},
    }


def prepared(tmp_path):
    output = tmp_path / "candidate"
    result = p.materialize(**inputs(), output_root=output)
    return output, result


def pack(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o600
            archive.addfile(info, io.BytesIO(raw))
    return stream.getvalue()


def reseal(files):
    files = dict(files)
    manifest = json.loads(files["manifest.json"])
    manifest["files"] = {name: {"sha256": r.digest(raw), "bytes": len(raw)}
                         for name, raw in files.items() if name != "manifest.json"}
    files["manifest.json"] = r.canonical(manifest)
    return files


def test_materialized_archive_is_accepted_with_exact_independent_inventory(tmp_path):
    output, result = prepared(tmp_path)
    raw = (output / "paired-source.tar").read_bytes()
    files, manifest = r.load_archive(raw, result["archive_sha256"])
    assert manifest["source_bundle_sha256"] == result["source_bundle_sha256"]
    inv = json.loads(files["source-inventory.json"])
    assert inv["scope"] == "fox-hosted-source-inventory-v1"
    assert p.digest(p.canonical(inv)) == result["source_bundle_sha256"]
    assert not any(name.startswith(("work/", "outputs/", ".git/", ".venv/")) for name in inv["files"])
    assert all("runtime-config" not in name and "admission" not in name for name in inv["files"])
    assert result["activation_performed"] is False


def test_bundle_and_archive_are_deterministic(tmp_path):
    one = p.materialize(**inputs(), output_root=tmp_path / "one")
    two = p.materialize(**inputs(), output_root=tmp_path / "two")
    assert one == two
    assert (tmp_path / "one/paired-source.tar").read_bytes() == (tmp_path / "two/paired-source.tar").read_bytes()


def test_existing_output_preserved(tmp_path):
    output, _ = prepared(tmp_path)
    sentinel = (output / "paired-source.tar").read_bytes()
    with pytest.raises(p.BuildError, match="OUTPUT_ALREADY_EXISTS"):
        p.materialize(**inputs(), output_root=output)
    assert (output / "paired-source.tar").read_bytes() == sentinel


@pytest.mark.parametrize("path", ["../escape", "/absolute", "C:/drive", "foo\\bar", "foo//bar", "./foo", "foo/../bar", "foo\nbar", "foo\x00bar"])
def test_unsafe_paths_blocked(path):
    with pytest.raises(p.BuildError): p.safe_name(path)
    with pytest.raises(r.StageError): r.safe_name(path)


def test_changed_archive_hash_blocked(tmp_path):
    output, result = prepared(tmp_path)
    with pytest.raises(r.StageError, match="EXACT_ARCHIVE_SHA_REQUIRED"):
        r.load_archive((output / "paired-source.tar").read_bytes(), "0" * 64)


@pytest.mark.parametrize("member", ["build/fox/Containerfile", "build/fox/fox/project_conversion.py", "build/converter/converter/defusedxml/ElementTree.py"])
def test_rehashed_changed_build_context_still_blocked(tmp_path, member):
    output, result = prepared(tmp_path)
    files, _ = r.load_archive((output / "paired-source.tar").read_bytes(), result["archive_sha256"])
    files[member] += b"# changed\n"
    raw = pack(reseal(files))
    with pytest.raises(r.StageError, match="BUILD_CONTEXT_DIFFERS_FROM_SOURCE_BUNDLE"):
        r.load_archive(raw, r.digest(raw))


def test_rehashed_changed_bundle_still_blocked(tmp_path):
    output, result = prepared(tmp_path)
    files, _ = r.load_archive((output / "paired-source.tar").read_bytes(), result["archive_sha256"])
    files["bundle/qa/operator/hosted_service.py"] += b"# changed\n"
    raw = pack(reseal(files))
    with pytest.raises(r.StageError, match="SOURCE_INVENTORY_DIFFERS"):
        r.load_archive(raw, r.digest(raw))


def test_unexpected_context_member_blocked_even_rehashed(tmp_path):
    output, result = prepared(tmp_path)
    files, _ = r.load_archive((output / "paired-source.tar").read_bytes(), result["archive_sha256"])
    files["build/fox/leaked-secret.json"] = b"synthetic forbidden extra"
    raw = pack(reseal(files))
    with pytest.raises(r.StageError, match="BUILD_CONTEXT_DIFFERS_FROM_SOURCE_BUNDLE"):
        r.load_archive(raw, r.digest(raw))


def test_duplicate_tar_member_blocked(tmp_path):
    output, result = prepared(tmp_path)
    source = (output / "paired-source.tar").read_bytes()
    stream = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(source), mode="r:") as original, tarfile.open(fileobj=stream, mode="w") as archive:
        for item in original:
            raw = original.extractfile(item).read()
            archive.addfile(item, io.BytesIO(raw))
            if item.name == "manifest.json": archive.addfile(item, io.BytesIO(raw))
    raw = stream.getvalue()
    with pytest.raises(r.StageError, match="UNSAFE_ARCHIVE_MEMBER"):
        r.load_archive(raw, r.digest(raw))


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_links_and_non_files_blocked(kind):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        info = tarfile.TarInfo("unsafe"); info.type = kind; info.linkname = "/etc/passwd"
        archive.addfile(info)
    raw = stream.getvalue()
    with pytest.raises(r.StageError, match="UNSAFE_ARCHIVE_MEMBER"):
        r.load_archive(raw, r.digest(raw))


def test_container_recipes_are_offline_and_change_only_new_layer_code():
    for role, raw in p.containerfiles().items():
        text = raw.decode()
        assert text.startswith("FROM " + p.BASE_IMAGES[role] + "\n")
        assert "pip install" not in text and "dnf" not in text and "curl" not in text
        assert "COPY --chown=" in text
        assert "/data" not in text and "wallet" not in text
    assert "defusedxml" in p.containerfiles()["converter"].decode()


def test_public_profile_rejects_secret_or_unknown_fields():
    profile = json.loads((HERE / "project-opaf-profile-v2.json").read_bytes())
    assert r.public_profile(r.canonical(profile)) == profile
    for change in ({"password": "synthetic-forbidden"}, {"opaf_base_url": "https://user:pass@example.test/agentFactory"}):
        with pytest.raises(r.StageError, match="PUBLIC_PROFILE_INVALID"):
            r.public_profile(r.canonical({**profile, **change}))
    profile["mapper"]["api_key"] = "synthetic-forbidden"
    with pytest.raises(r.StageError, match="PUBLIC_PROFILE_INVALID"):
        r.public_profile(r.canonical(profile))


def test_source_collection_does_not_admit_other_workspace_files(tmp_path):
    for name in p.PROFILE_FILES + p.QA_FILES:
        path = tmp_path / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"{}\n")
    for name in ("fox/fox/__init__.py", "fox/fox/native/FoxPllExtract.java", "qa/operator/hosted_service.py"):
        path = tmp_path / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"# source\n")
    for name in ("fox/fox/secrets.json", "outputs/customer.fmb", "work/private/admin.dpapi", ".git/config"):
        path = tmp_path / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"not admitted")
    result = p.source_files(tmp_path)
    assert "fox/fox/secrets.json" not in result
    assert not any(name.startswith(("outputs/", "work/", ".git/")) for name in result)


def test_key_material_in_allowlisted_source_is_rejected(tmp_path):
    path = tmp_path / "bad.py"; path.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
    with pytest.raises(p.BuildError, match="PRIVATE_KEY_MATERIAL_FORBIDDEN"): p.read(path)


def test_real_existing_defusedxml_record_checked_without_import_or_install():
    root = HERE.parent / "fox/.venv/Lib/site-packages"
    if not root.is_dir(): pytest.skip("existing Windows development dependency unavailable")
    payload = p.defusedxml_payload(root)
    assert "defusedxml-0.7.1.dist-info/LICENSE" in payload
    assert not any("__pycache__" in path for path in payload)
    assert len(payload) >= 17


def test_stage_does_not_touch_files_before_identity_guard(tmp_path, monkeypatch):
    output, result = prepared(tmp_path)
    monkeypatch.setattr(r, "PARENT", tmp_path / "stage-parent")
    def blocked(_): raise r.StageError("EXACT_JSN_HOST_REQUIRED")
    monkeypatch.setattr(r, "guarded_host", blocked)
    with pytest.raises(r.StageError, match="EXACT_JSN_HOST_REQUIRED"):
        r.stage((output / "paired-source.tar").read_bytes(), result["archive_sha256"])
    assert not r.PARENT.exists()


def test_existing_build_intent_never_replayed(monkeypatch):
    monkeypatch.setattr(r, "inspect", lambda _: {"builds": {"fox": {"intent": True, "complete": False}}})
    monkeypatch.setattr(r, "command", lambda *args, **kwargs: pytest.fail("must not call Podman"))
    with pytest.raises(r.StageError, match="EXISTING_BUILD_MUST_NOT_BE_REPLAYED"):
        r.build("a" * 64, "fox", apply=True)


def test_converter_context_contains_exact_six_file_pure_qa_closure(tmp_path):
    output,result=prepared(tmp_path)
    files,_=r.load_archive((output/'paired-source.tar').read_bytes(),result['archive_sha256'])
    assert p.QA_CONTRACT_FILES==r.QA_CONTRACT_FILES
    for name in p.QA_CONTRACT_FILES:
        assert files['build/converter/qa-contract/'+name]==files['bundle/fox/fox/'+name]
    recipe=p.containerfiles()['converter']
    assert b'COPY --chown=10001:10001 qa-contract /opt/forms2apex/converter/fox' in recipe
    assert b'from fox.project_qa_plan import derive_project_qa_plan,derive_project_qa_profile' in recipe


@pytest.mark.parametrize('name',p.QA_CONTRACT_FILES)
def test_missing_contract_source_rejects_before_output_creation(tmp_path,name):
    value=inputs();del value['files']['fox/fox/'+name]
    with pytest.raises(p.BuildError,match='COMPLETE_QA_CONTRACT_SOURCE_REQUIRED'):
        p.materialize(**value,output_root=tmp_path/'rejected')
    assert not (tmp_path/'rejected').exists()


def test_rehashed_context_cannot_replace_the_bound_qa_planner(tmp_path):
    output,result=prepared(tmp_path)
    files,_=r.load_archive((output/'paired-source.tar').read_bytes(),result['archive_sha256'])
    files['build/converter/qa-contract/project_qa_plan.py']+=b'# changed\n'
    with pytest.raises(r.StageError,match='BUILD_CONTEXT_DIFFERS_FROM_SOURCE_BUNDLE'):
        r.validate_files(reseal(files))


def test_actual_contract_imports_without_frontend_package_or_development_path(tmp_path):
    folder=tmp_path/'fox';folder.mkdir()
    for name in p.QA_CONTRACT_FILES:(folder/name).write_bytes((HERE.parent/'fox/fox'/name).read_bytes())
    code="""import pathlib,sys
sys.path.insert(0,sys.argv[1])
from fox.project_qa_plan import derive_project_qa_plan,derive_project_qa_profile,ProjectQaPlanError
import fox.project_qa_plan as q
assert pathlib.Path(q.__file__).resolve()==pathlib.Path(sys.argv[1])/'fox/project_qa_plan.py'
assert 'fox.app' not in sys.modules and 'fastapi' not in sys.modules
try:derive_project_qa_plan({},'a'*64,{},'b'*64)
except ProjectQaPlanError:pass
else:raise AssertionError('Invalid metadata must reject')
print('PURE_QA_CLOSURE_IMPORTED_NO_FRONTEND')
"""
    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(tmp_path)],cwd=tmp_path,capture_output=True,timeout=20)
    assert result.returncode==0,result.stderr.decode()
    assert result.stdout.strip()==b'PURE_QA_CLOSURE_IMPORTED_NO_FRONTEND'


def test_retained_original_archive_still_validates_without_new_projection():
    # This checks historical compatibility, not readiness of its missing QA
    # dependency. The public checkout intentionally excludes private bundles.
    root=HERE.parent/'work/b27a'
    if not (root/'paired-source.tar').is_file():pytest.skip('Retained private historical build fixture')
    original=json.loads((root/'result.json').read_bytes())
    files,_=r.load_archive((root/'paired-source.tar').read_bytes(),original['archive_sha256'])
    assert not any(name.startswith('build/converter/qa-contract/') for name in files)
