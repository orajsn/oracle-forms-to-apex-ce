"""Release producer preserves self-contained historical proof without live AI."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from forms2apex import release
from forms2apex.clean_package import validate_native_package
from test_clean_package import members, v2_members, digest, encoded, rebind_evidence


@pytest.mark.parametrize('kind',['v1','v2'])
def test_package_copies_only_its_sealed_historical_profile(kind,request,tmp_path_factory,monkeypatch):
    source=deepcopy(request.getfixturevalue('members' if kind=='v1' else 'v2_members'))
    old=json.loads(source['evidence/release-evidence.json'])
    # The generic v2 offline fixture upgrades its sealed receipt after creating
    # the v1 materialized spec. Match real generate() behavior for this producer
    # test, which takes reviewer metadata from the materialized migration spec.
    migration=json.loads(source['evidence/migration-spec.json'])
    migration['reviewer']=old['reviewer']
    source['evidence/migration-spec.json']=encoded(migration)
    rebind_evidence(source)
    old=json.loads(source['evidence/release-evidence.json'])
    review=json.loads(source['evidence/native-review.json'])
    root=tmp_path_factory.mktemp('hp')/old['job_id'];root.mkdir()
    (root/'intake').mkdir()
    (root/'intake/manifest.json').write_text(json.dumps({'source_manifest_sha256':old['source_manifest_sha256']}),encoding='utf-8')
    alias=old['application_alias']
    for name,raw in source.items():
        if name.startswith('sql/'):
            target=root/'export'/Path(name).name
        elif name.startswith('apexlang/'):
            target=root/'export'/alias.lower()/name[len('apexlang/'):]
        elif name=='evidence/export-completion.json':
            target=root/'export/.export-complete.json'
        elif name=='evidence/export-validation.log':
            target=root/'export/apexlang-validation.log'
        elif name.startswith('evidence/') and name not in {'evidence/release-evidence.json','evidence/target-profile.json'}:
            target=root/Path(name).name
        else:
            continue
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    (root/'validation-results.log').write_text('Synthetic test validation only',encoding='utf-8')
    schema=json.loads(source['evidence/imported-application.json'])['workspace']
    workflow=SimpleNamespace(
        store=SimpleNamespace(require=lambda job_id:root),
        settings=SimpleNamespace(apex_workspace=schema,apex_parsing_schema=schema,
                                 sqlcl_connection_name='FIXTURE_ONLY',sqlcl_path=root/'sql'),
        status=lambda job_id:{'state':'IMPORTED','validation':{'passed':True}},
        assert_artifact_binding=lambda job_id:deepcopy(old['artifact_binding']),
        verify_native_review=lambda job_root,spec:deepcopy(review),
        native_target_preflight=lambda *args:pytest.fail('Completed export/reimport must not contact target again'),
    )
    monkeypatch.setattr(release,'_run_script',lambda *args,**kwargs:pytest.fail('No SQL operation permitted'))
    monkeypatch.setattr(release,'runtime_login_check',lambda url:{'passed':True,'scope':'login_page_reachability'})
    # The historical package must not be rewritten using a changed current
    # deployment profile. Registered historical documents remain available.
    monkeypatch.setattr('forms2apex.target_profile._DEPLOYABLE_TARGET_PROFILES',{})
    evidence=release.finalize_release(workflow,old['job_id'])
    raw=(root/'apex-package.zip').read_bytes()
    with zipfile.ZipFile(root/'apex-package.zip') as archive:
        if kind=='v2':
            assert archive.read('evidence/target-profile.json')==source['evidence/target-profile.json']
            assert evidence['model_environment_verified'] is True
        else:
            assert 'evidence/target-profile.json' not in archive.namelist()
            assert evidence['model_environment_verified'] is False
        assert archive.read('evidence/native-review.json')==source['evidence/native-review.json']
    checked=validate_native_package(raw,digest(raw))
    assert checked['historical_model_environment_verified'] is (kind=='v2')
    assert checked['current_target_authorized'] is False
