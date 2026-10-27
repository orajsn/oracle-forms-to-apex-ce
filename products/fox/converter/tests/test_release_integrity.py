import hashlib
import json
import zipfile
from types import SimpleNamespace

import pytest

from forms2apex.release import finalize_release, _verify_cached_release, _verify_reimport_receipt, _tree_hashes
from forms2apex.security import alias_for_job


JOB_ID='fox-'+'a'*20
BINDING={'schema_version':1,'job_id':JOB_ID,'draft_sha256':'a'*64}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path,value):
    path.write_text(json.dumps(value,sort_keys=True),encoding='utf-8')


def seal_export(root):
    (root/'export/apexlang-validation.log').write_text('Validation successful',encoding='utf-8')
    write_json(root/'export/.export-complete.json',{
        'schema_version':1,'job_id':JOB_ID,'artifact_binding':BINDING,
        'application_id':123,'application_alias':alias_for_job(JOB_ID),
        'imported_application_sha256':digest(root/'imported-application.json'),
        'apexlang_validation_passed':True,
        'files':_tree_hashes(root/'export',('.export-complete.json',)),
    })


def make_package(root,members=None):
    if members is None:
        members={
            'sql/f123.sql':(root/'export/f123.sql').read_bytes(),
            'evidence/release-evidence.json':(root/'release-evidence.json').read_bytes(),
            'evidence/package-reimport.json':(root/'package-reimport.json').read_bytes(),
            'README.txt':b'Synthetic test fixture only',
        }
    members=dict(members)
    members['manifest.json']=json.dumps({name:hashlib.sha256(raw).hexdigest() for name,raw in members.items()}).encode()
    with zipfile.ZipFile(root/'apex-package.zip','w') as archive:
        for name,raw in members.items():
            archive.writestr(name,raw)


def reseal(root):
    write_json(root/'release-integrity.json',{
        'schema_version':1,'job_id':JOB_ID,'artifact_binding':BINDING,
        'package_sha256':digest(root/'apex-package.zip'),
        'evidence_sha256':digest(root/'release-evidence.json'),
        'sql_sha256':digest(root/'export/f123.sql'),
    })


@pytest.fixture
def cached_release(tmp_path_factory):
    root=tmp_path_factory.mktemp('integrity')/JOB_ID
    root.mkdir()
    (root/'export').mkdir()
    (root/'export/f123.sql').write_text('-- synthetic export\n'+'x'*1100)
    receipt={'passed':True,'application_id':456,'application_alias':alias_for_job(JOB_ID+'-sqlcheck'),
             'sql_sha256':digest(root/'export/f123.sql')}
    write_json(root/'package-reimport.json',receipt)
    evidence={'job_id':JOB_ID,'application_id':123,'artifact_binding':BINDING,'package_reimport':receipt}
    write_json(root/'release-evidence.json',evidence)
    make_package(root)
    reseal(root)
    return root,evidence


def fake_workflow(root):
    calls=[]
    def verify(job_id):
        calls.append(job_id)
        return dict(BINDING)
    workflow=SimpleNamespace(
        store=SimpleNamespace(require=lambda job_id:root),
        assert_artifact_binding=verify,
        status=lambda job_id:{'state':'IMPORTED','validation':{'passed':True}},
    )
    return workflow,calls


def test_cached_release_verifies_binding_before_and_after(cached_release,monkeypatch):
    root,evidence=cached_release
    workflow,calls=fake_workflow(root)
    monkeypatch.setattr('forms2apex.release._run_script',lambda *a,**k:pytest.fail('Cached release must not run SQLcl'))
    monkeypatch.setattr('forms2apex.release.runtime_login_check',lambda *a,**k:pytest.fail('Cached release must not call network'))
    before={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*') if path.is_file()}
    assert finalize_release(workflow,JOB_ID)==evidence
    assert calls==[JOB_ID,JOB_ID]
    assert before=={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*') if path.is_file()}


@pytest.mark.parametrize('name',['apex-package.zip','release-evidence.json','export/f123.sql'])
def test_cached_release_rejects_changed_artifact(cached_release,name):
    root,_=cached_release
    target=root/name
    target.write_bytes(target.read_bytes()+b'changed')
    with pytest.raises(RuntimeError):
        _verify_cached_release(root,JOB_ID,BINDING)


def test_legacy_cache_without_sidecar_is_not_backfilled(cached_release):
    root,_=cached_release
    (root/'release-integrity.json').unlink()
    workflow,_=fake_workflow(root)
    before={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*') if path.is_file()}
    with pytest.raises(RuntimeError,match='metadata'):
        finalize_release(workflow,JOB_ID)
    assert before=={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*') if path.is_file()}


def test_cached_release_rejects_binding_change(cached_release):
    root,_=cached_release
    with pytest.raises(RuntimeError,match='bound'):
        _verify_cached_release(root,JOB_ID,{**BINDING,'draft_sha256':'b'*64})


def test_cache_verifies_zip_manifest_even_with_matching_package_hash(cached_release):
    root,_=cached_release
    with zipfile.ZipFile(root/'apex-package.zip') as archive:
        members={name:archive.read(name) for name in archive.namelist()}
    members['README.txt']=b'Modified without changing manifest'
    with zipfile.ZipFile(root/'apex-package.zip','w') as archive:
        for name,raw in members.items():
            archive.writestr(name,raw)
    reseal(root)
    with pytest.raises(RuntimeError,match='package integrity'):
        _verify_cached_release(root,JOB_ID,BINDING)


def test_cache_rejects_different_packaged_evidence(cached_release):
    root,_=cached_release
    with zipfile.ZipFile(root/'apex-package.zip') as archive:
        members={name:archive.read(name) for name in archive.namelist() if name!='manifest.json'}
    members['evidence/release-evidence.json']=b'{}'
    make_package(root,members)
    reseal(root)
    with pytest.raises(RuntimeError,match='package integrity'):
        _verify_cached_release(root,JOB_ID,BINDING)


def test_sql_receipt_cannot_be_reused_after_export_changes(cached_release):
    root,_=cached_release
    (root/'export/f123.sql').write_text('-- changed SQL')
    with pytest.raises(RuntimeError,match='SQL export changed'):
        _verify_reimport_receipt(root/'export/f123.sql',root/'package-reimport.json')


def test_finalize_rejects_stale_sql_receipt_before_any_external_calls(cached_release,monkeypatch):
    root,_=cached_release
    for name in ['apex-package.zip','release-evidence.json','release-integrity.json']:
        (root/name).unlink()
    app_dir=root/'export'/alias_for_job(JOB_ID).lower()
    app_dir.mkdir()
    (app_dir/'application.apx').write_text('app TEST ()')
    write_json(root/'imported-application.json',{'application_id':123,'application_alias':alias_for_job(JOB_ID),'workspace':'FORMS2APEX_POC'})
    (root/'export/f123.sql').write_text('-- changed SQL\n'+'x'*1100)
    workflow,_=fake_workflow(root)
    workflow.settings=SimpleNamespace(apex_workspace='FORMS2APEX_POC',sqlcl_connection_name='F2A_APEX',sqlcl_path=root/'sql')
    monkeypatch.setattr('forms2apex.release._run_script',lambda *a,**k:pytest.fail('Stale SQL must not run SQLcl'))
    monkeypatch.setattr('forms2apex.release.runtime_login_check',lambda *a,**k:pytest.fail('Stale SQL must not call network'))
    with pytest.raises(RuntimeError,match='SQL export changed'):
        finalize_release(workflow,JOB_ID)


def test_new_release_writes_verified_sidecar(cached_release,monkeypatch):
    root,_=cached_release
    for name in ['apex-package.zip','release-evidence.json','release-integrity.json']:
        (root/name).unlink()
    app_dir=root/'export'/alias_for_job(JOB_ID).lower()
    app_dir.mkdir()
    (app_dir/'application.apx').write_text('app TEST ()')
    write_json(root/'imported-application.json',{'application_id':123,'application_alias':alias_for_job(JOB_ID),
        'workspace':'FORMS2APEX_POC','application_url':'https://example.invalid/ords/test'})
    seal_export(root)
    (root/'intake').mkdir()
    write_json(root/'intake/manifest.json',{'source_manifest_sha256':'b'*64})
    write_json(root/'migration-spec.json',{'reviewer':{'verdict':'approve'}})
    for name in ['normalized-forms-inventory.json','migration-and-exception-report.json','validation-results.log']:
        (root/name).write_text('{}')
    workflow,calls=fake_workflow(root)
    workflow.settings=SimpleNamespace(apex_workspace='FORMS2APEX_POC',sqlcl_connection_name='F2A_APEX',sqlcl_path=root/'sql')
    monkeypatch.setattr('forms2apex.release._run_script',lambda *a,**k:pytest.fail('Existing export/receipt should not call SQLcl'))
    monkeypatch.setattr('forms2apex.release.runtime_login_check',lambda *a,**k:{'passed':True})
    evidence=finalize_release(workflow,JOB_ID)
    assert evidence['artifact_binding']==BINDING
    assert len(calls)==4
    assert _verify_cached_release(root,JOB_ID,BINDING)==evidence
