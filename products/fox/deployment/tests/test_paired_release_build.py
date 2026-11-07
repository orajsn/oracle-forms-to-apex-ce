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
import zipfile

import defusedxml
import pytest


HERE = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


p = module("prepare_project_release")
r = module("build_project_release")


def renderer_inputs():
    dependency = p.defusedxml_payload(Path(defusedxml.__file__).resolve().parent.parent)
    source = HERE.parent / 'converter'
    payload = {name: dependency[name] if name.startswith(('defusedxml/', 'defusedxml-'))
               else (source/name).read_bytes() for name in p.APP_RENDERER_FILES}
    for prefix in p.APP_RENDERER_TEMPLATE_ROOTS:
        for path in (source/prefix).rglob('*'):
            if path.is_file():
                payload[path.relative_to(source).as_posix()] = path.read_bytes()
    return payload


def inputs():
    return {
        "files": {**{'fox/fox/'+name:b'# synthetic pure contract\n' for name in p.QA_CONTRACT_FILES},
                  "fox/fox/__init__.py": b"", "fox/fox/project_conversion.py": b"PROFILE_ID='native-project-v1'\n",
                  "qa/operator/hosted_service.py": b"# synthetic service\n",
                  "deployment/project-opaf-profile-v2.json": (HERE / "project-opaf-profile-v2.json").read_bytes()},
        "ui": {"index.html": b"<html>synthetic</html>", "assets/main-a.js": b"// synthetic"},
        "converter": {"forms2apex/__init__.py": b"", "fox_source_contract/source-manifest.json": b"{}\n",
                      "defusedxml/ElementTree.py": b"# synthetic dependency\n", **renderer_inputs()},
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


@pytest.mark.parametrize('member', [
    'build/fox/renderer/forms2apex/native_blueprint.py',
    'build/fox/renderer/forms2apex/prototype_package.py',
    'build/fox/renderer/forms2apex/templates/blueprint-prototype-v1/control.apx.tmpl',
    'build/fox/renderer/forms2apex/templates/native-table-v1/.apex/apexlang.json',
    'build/fox/renderer/fox_source_contract/intake.py',
])
def test_rehashed_app_renderer_change_cannot_escape_exact_source_projection(tmp_path, member):
    output, result = prepared(tmp_path)
    files, _ = r.load_archive((output/'paired-source.tar').read_bytes(), result['archive_sha256'])
    files[member] += b'\nchanged renderer content\n'
    with pytest.raises(r.StageError, match='BUILD_CONTEXT_DIFFERS_FROM_SOURCE_BUNDLE'):
        r.validate_files(reseal(files))


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
    for name in ("fox/fox/__init__.py", "fox/fox/release.json", "fox/fox/native/FoxPllExtract.java", "qa/operator/hosted_service.py"):
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


def test_converter_context_contains_exact_handoff_dependency_closure(tmp_path):
    output,result=prepared(tmp_path)
    files,_=r.load_archive((output/'paired-source.tar').read_bytes(),result['archive_sha256'])
    assert p.QA_CONTRACT_FILES==r.QA_CONTRACT_FILES
    for name in p.QA_CONTRACT_FILES:
        assert files['build/converter/qa-contract/'+name]==files['bundle/fox/fox/'+name]
    recipe=p.containerfiles()['converter']
    assert b'COPY --chown=10001:10001 qa-contract /opt/forms2apex/converter/fox' in recipe
    assert b'from fox.project_qa_plan import derive_project_qa_plan,derive_project_qa_profile' in recipe


def test_app_context_contains_only_explicit_real_pure_renderer_closure(tmp_path):
    value = inputs()
    value['converter']['forms2apex/server.py'] = b'not part of the app renderer'
    value['converter']['forms2apex/sqlcl.py'] = b'not part of the app renderer'
    output = tmp_path/'r'
    result = p.materialize(**value, output_root=output)
    files, _ = r.load_archive((output/'paired-source.tar').read_bytes(), result['archive_sha256'])
    assert p.APP_RENDERER_FILES == r.APP_RENDERER_FILES
    assert p.APP_RENDERER_TEMPLATE_ROOTS == r.APP_RENDERER_TEMPLATE_ROOTS
    assert p.APP_RENDERER_REQUIRED_TEMPLATES == r.APP_RENDERER_REQUIRED_TEMPLATES
    expected = p.app_renderer_payload(value['converter'])
    actual = {name.removeprefix('build/fox/renderer/'): raw for name, raw in files.items()
              if name.startswith('build/fox/renderer/')}
    assert actual == expected
    assert all(raw == files['bundle/converter/'+name] for name, raw in actual.items())
    assert 'forms2apex/server.py' not in actual and 'forms2apex/sqlcl.py' not in actual
    assert not any(name.startswith(('oci/', 'fastmcp/')) for name in actual)
    assert 'forms2apex/templates/native-table-v1/.apex/apexlang.json' in actual
    assert 'defusedxml-0.7.1.dist-info/LICENSE' in actual
    assert b'COPY --chown=1000:1000 renderer /app' in p.containerfiles()['fox']


@pytest.mark.parametrize('name', p.APP_RENDERER_FILES + p.APP_RENDERER_REQUIRED_TEMPLATES)
def test_missing_renderer_dependency_rejects_before_creating_candidate(tmp_path, name):
    value = inputs()
    del value['converter'][name]
    with pytest.raises(p.BuildError, match='COMPLETE_APP_RENDERER_CLOSURE_REQUIRED'):
        p.materialize(**value, output_root=tmp_path/'rejected')
    assert not (tmp_path/'rejected').exists()


def test_real_frozen_app_context_renders_one_native_zip_without_development_imports(tmp_path):
    value = inputs()
    # Public checkout deliberately excludes private legacy profile files. Only
    # the actual app package is needed for this frozen lazy-render import test.
    value['files'].update({'fox/fox/'+path.name: p.read(path, allow_empty=True)
                           for path in (HERE.parent/'fox/fox').glob('*.py')})
    output = tmp_path/'frozen'
    result = p.materialize(**value, output_root=output)
    files, _ = r.load_archive((output/'paired-source.tar').read_bytes(), result['archive_sha256'])
    # Reconstruct what the app recipe COPYs, using ONLY checked frozen members.
    app = tmp_path/'app'
    app.mkdir()
    for prefix, destination in (('build/fox/fox/', app/'fox'), ('build/fox/renderer/', app)):
        for name, raw in files.items():
            if name.startswith(prefix):
                path = destination/name.removeprefix(prefix)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
    code = r'''import hashlib,io,json,pathlib,sys,zipfile
app=pathlib.Path(sys.argv[1]).resolve()
assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
sys.path.insert(0,str(app))
def reject_external(event,args):
 if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn'):
  raise AssertionError('External operation forbidden during pure app render')
sys.addaudithook(reject_external)
from fox.prototype_pipeline import NativeBlueprintRenderer
from forms2apex.prototype_package import validate_prototype_package
from fox.forms_understanding_packet import local_packet
from fox.forms_native_plan import POLICY_ID,build_native_prototype_plan
documents=[('first.xml',b'<FormModule Name="FIRST"><Block Name="BUSINESS" DatabaseBlock="true"><Item Name="VALUE" ItemType="Text Item" DataType="Char" MaximumLength="80" DatabaseItem="true" Prompt="Value"/></Block></FormModule>'),
 ('second.xml',b'<FormModule Name="SECOND"><Block Name="CONTROL" DatabaseBlock="false"><Item Name="SEARCH" ItemType="Text Item" DataType="Char" MaximumLength="80" DatabaseItem="false" Prompt="Search"/></Block></FormModule>')]
packet=local_packet(documents)
rows=[]
for entry in packet['sources']:
 for obj in entry['facts']['objects']:
  row={'source_object_id':obj['id'],'disposition':'unresolved','reason':'Synthetic structural prototype only.'}
  if obj['kind'] in ('Block','Item'):
   row.update(disposition='proposed',screen_id='synthetic-screen')
   if obj['kind']=='Block':row['native_component']='form' if obj['classification']=='database' else 'page-items'
  rows.append(row)
blueprint={'schema_version':1,'scope':'fox-forms-blueprint-v1','source_binding':packet['source_binding'],
 'objects':rows,'screens':[{'id':'synthetic-screen','title':'Synthetic prototype'}],
 **{name:[] for name in ('claims','relationships','actions','questions','assumptions')}}
spec=build_native_prototype_plan(documents,blueprint,project_id='synthetic-project',project_name='Synthetic app',approved_policy_id=POLICY_ID)['rendering_spec']
raw,trace=NativeBlueprintRenderer().render(spec)
assert raw==NativeBlueprintRenderer().render(spec)[0]
with zipfile.ZipFile(io.BytesIO(raw)) as archive:
 assert archive.namelist().count('application.apx')==1
 assert '.apex/apexlang.json' in archive.namelist()
 assert 'pages/p00001-block_1.apx' in archive.namelist()
 assert 'pages/p00002-edit_1.apx' in archive.namelist()
 assert 'pages/p00003-block_2.apx' in archive.namelist()
 assert b'form' in archive.read('pages/p00002-edit_1.apx')
 assert b'textField' in archive.read('pages/p00003-block_2.apx')
for name,module in tuple(sys.modules.items()):
 if name.split('.')[0] in ('fox','forms2apex','fox_source_contract','defusedxml') and getattr(module,'__file__',None):
  assert pathlib.Path(module.__file__).resolve().is_relative_to(app),(name,module.__file__)
assert 'fastapi' not in sys.modules and 'oci' not in sys.modules and 'forms2apex.server' not in sys.modules
try:
 validate_prototype_package(b'not a ZIP',request={},runtime_receipt={},imported={},artifact_binding={})
except (RuntimeError,ValueError,zipfile.BadZipFile):pass
else:raise AssertionError('Invalid prototype package was accepted')
assert 'forms2apex.sqlcl' not in sys.modules and 'forms2apex.runtime_preflight' not in sys.modules
(app/'candidate-apexlang.zip').write_bytes(raw)
proof={'scope':'isolated-frozen-app-renderer','source_bundle_sha256':sys.argv[2],
 'zip_sha256':hashlib.sha256(raw).hexdigest(),'zip_bytes':len(raw),
 'application_count':trace['application_count'],'block_count':trace['block_count'],
 'site_packages_disabled':True,'development_paths_used':False,'sqlcl_or_oracle_run':False}
proof['pure_prototype_package_validator_loaded']=True
(app/'renderer-proof.json').write_text(json.dumps(proof,sort_keys=True))
print(json.dumps(proof,sort_keys=True))
'''
    completed = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', code, str(app), result['source_bundle_sha256']],
                               cwd=app, capture_output=True, timeout=30)
    assert completed.returncode == 0, completed.stderr.decode()
    proof = json.loads(completed.stdout)
    assert proof['application_count'] == 1 and proof['block_count'] == 2
    assert proof['site_packages_disabled'] is True and proof['development_paths_used'] is False
    assert proof['source_bundle_sha256'] == result['source_bundle_sha256']
    assert p.digest((app/'candidate-apexlang.zip').read_bytes()) == proof['zip_sha256']
    with zipfile.ZipFile(app/'candidate-apexlang.zip') as archive:
        assert len(archive.namelist()) >= 10


def test_historical_app_context_without_renderer_marker_is_not_relabelled(tmp_path):
    output, result = prepared(tmp_path)
    files, _ = r.load_archive((output/'paired-source.tar').read_bytes(), result['archive_sha256'])
    recipe = 'bundle/deployment/Containerfile.project-fox'
    files[recipe] = files[recipe].replace(b'# fox-prototype-renderer-closure-v1\n', b'').replace(
        b'COPY --chown=1000:1000 renderer /app\n', b'')
    files['build/fox/Containerfile'] = files[recipe]
    for name in list(files):
        if name.startswith('build/fox/renderer/'):
            del files[name]
    inventory = json.loads(files['source-inventory.json'])
    inventory['files']['deployment/Containerfile.project-fox'] = r.digest(files[recipe])
    files['source-inventory.json'] = r.canonical(inventory)
    manifest = json.loads(files['manifest.json'])
    manifest['source_bundle_sha256'] = r.digest(files['source-inventory.json'])
    files['manifest.json'] = r.canonical(manifest)
    checked, _ = r.validate_files(reseal(files))
    assert not any(name.startswith('build/fox/renderer/') for name in checked)


def test_release_metadata_is_copied_into_the_backend_image_context(tmp_path):
    value=inputs();metadata=(HERE.parent/'fox/fox/release.json').read_bytes()
    value['files']['fox/fox/release.json']=metadata
    output=tmp_path/'r'
    result=p.materialize(**value,output_root=output)
    files,_=r.load_archive((output/'paired-source.tar').read_bytes(),result['archive_sha256'])
    assert files['bundle/fox/fox/release.json']==metadata
    assert files['build/fox/fox/release.json']==metadata


def test_source_collector_requires_the_release_resource(tmp_path):
    required=set(p.PROFILE_FILES)|set(p.QA_FILES)|{'fox/fox/release.json',
        'fox/fox/native/FoxPllExtract.java','qa/operator/hosted_service.py'}
    for name in required:
        path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'synthetic source file')
    assert p.source_files(tmp_path)['fox/fox/release.json']==b'synthetic source file'
    (tmp_path/'fox/fox/release.json').unlink()
    with pytest.raises(FileNotFoundError):p.source_files(tmp_path)


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
from fox.native_verification import ORDS
from fox.native_verification_policy import BoundVerificationPolicy,validate_allocation_receipt
from fox.project_verification import _validate_clean
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


@pytest.mark.parametrize('legacy',[False,True])
def test_exact_operator_handoff_contract_imports_with_only_converter_closure(tmp_path,legacy):
    # Mirror HANDOFF_READER's synthetic qa namespace, not the developer checkout.
    # No handoff data, credentials, database or remote execution is involved.
    folder=tmp_path/'fox';folder.mkdir()
    for name in (r.LEGACY_QA_CONTRACT_FILES if legacy else p.QA_CONTRACT_FILES):
        (folder/name).write_bytes((HERE.parent/'fox/fox'/name).read_bytes())
    operator=tmp_path/'operator';operator.mkdir()
    for name in ('contracts.py','project_contracts.py','project_qa_contracts.py'):
        (operator/name).write_bytes((HERE.parent/'qa/operator'/name).read_bytes())
    code="""import pathlib,sys,types
sys.path[:0]=[sys.argv[1],sys.argv[2]]
for name in ('qa','qa.operator'):
 m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m
for filename in ('contracts.py','project_contracts.py','project_qa_contracts.py'):
 name='qa.operator.'+filename[:-3];m=types.ModuleType(name);m.__package__='qa.operator';sys.modules[name]=m
 path=pathlib.Path(sys.argv[1])/'operator'/filename
 exec(compile(path.read_bytes(),filename,'exec'),m.__dict__)
assert callable(sys.modules['qa.operator.project_qa_contracts'].prepare_inputs)
assert 'fox.app' not in sys.modules and 'fastapi' not in sys.modules
for name in ('fox.native_verification','fox.project_verification'):
 assert pathlib.Path(sys.modules[name].__file__).parent==pathlib.Path(sys.argv[1])/'fox'
print('EXACT_PROJECT_HANDOFF_IMPORTS_NO_FRONTEND')
"""
    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(tmp_path),str(HERE.parent/'converter')],
                          cwd=tmp_path,capture_output=True,timeout=20)
    if legacy:
        assert result.returncode!=0
        assert b"No module named 'fox.native_verification'" in result.stderr
        return
    assert result.returncode==0,result.stderr.decode()
    assert result.stdout.strip()==b'EXACT_PROJECT_HANDOFF_IMPORTS_NO_FRONTEND'


def test_retained_six_module_archive_remains_readable_not_upgraded(tmp_path):
    output,result=prepared(tmp_path)
    files,_=r.load_archive((output/'paired-source.tar').read_bytes(),result['archive_sha256'])
    recipe='bundle/deployment/Containerfile.project-converter'
    files[recipe]=files[recipe].replace(b'# fox-qa-contract-closure-v2\n',b'')
    files['build/converter/Containerfile']=files[recipe]
    for name in set(p.QA_CONTRACT_FILES)-set(r.LEGACY_QA_CONTRACT_FILES):
        del files['build/converter/qa-contract/'+name]
    inventory=json.loads(files['source-inventory.json'])
    inventory['files']['deployment/Containerfile.project-converter']=r.digest(files[recipe])
    files['source-inventory.json']=r.canonical(inventory)
    manifest=json.loads(files['manifest.json'])
    manifest['source_bundle_sha256']=r.digest(files['source-inventory.json'])
    files['manifest.json']=r.canonical(manifest)
    checked,_=r.validate_files(reseal(files))
    assert not any('qa-contract/native_verification.py' in name for name in checked)


def test_retained_original_archive_still_validates_without_new_projection():
    # This checks historical compatibility, not readiness of its missing QA
    # dependency. The public checkout intentionally excludes private bundles.
    root=HERE.parent/'work/b27a'
    if not (root/'paired-source.tar').is_file():pytest.skip('Retained private historical build fixture')
    original=json.loads((root/'result.json').read_bytes())
    files,_=r.load_archive((root/'paired-source.tar').read_bytes(),original['archive_sha256'])
    assert not any(name.startswith('build/converter/qa-contract/') for name in files)
