"""Read-only version/notes checks; no model, Oracle connection or acceptance."""
import ast
from copy import deepcopy
import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from fox.app import create_app, password_hash
from fox import release_info as r


def test_canonical_manifest_and_api_health_match_without_login(tmp_path,monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH',password_hash('synthetic-release-test-only'))
    expected=r.public_release()
    with TestClient(create_app(tmp_path/'data',enable_worker=False)) as client:
        release=client.get('/api/release')
        assert release.status_code==200 and release.json()==expected
        assert release.headers['cache-control']=='no-store'
        assert client.get('/api/health').json()['version']==expected['version']
        assert set(expected)=={'version','released_on','title','changes','limitations'}
        assert client.get('/api/projects').status_code==401


def test_invalid_or_duplicate_metadata_cannot_become_a_release():
    mutations=[lambda d:d.update(version=True),lambda d:d.update(version='0.02.0'),
        lambda d:d.update(released_on='2026-02-30'),lambda d:d.update(changes=[]),
        lambda d:d.update(title='bad\nlabel'),lambda d:d.update(secret='must not be returned')]
    for mutate in mutations:
        value=deepcopy(r.public_release());mutate(value)
        with pytest.raises(r.ReleaseMetadataError):r.validate_release(json.dumps(value).encode())
    with pytest.raises(r.ReleaseMetadataError):r.validate_release(b'{"version":"0.2.0","version":"0.3.0"}')
    assert not any(isinstance(node,ast.Assert) for node in ast.walk(ast.parse(Path(r.__file__).read_text())))


def test_product_package_lock_and_changelog_are_consistent():
    import importlib.util
    root=Path(__file__).resolve().parents[2]
    spec=importlib.util.spec_from_file_location('product_release_check',root/'tools/check_product_release.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    result=m.check(root)
    assert result['version']==r.public_release()['version'] and result['deployment_verified'] is False


@pytest.mark.parametrize('mutation',[
    lambda d:d.update(limitations=['Synthetic limitation']*13),
    lambda d:d.update(changes=['Synthetic change']*13),
    lambda d:d.update(title='Bad\nrelease title'),
    lambda d:d.update(limitations=['x'*401]),
])
def test_offline_release_gate_rejects_ui_invalid_metadata(tmp_path,mutation):
    import importlib.util
    root=Path(__file__).resolve().parents[2]
    spec=importlib.util.spec_from_file_location('product_release_schema_check',root/'tools/check_product_release.py')
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    candidate=tmp_path/'candidate';manifest=candidate/'fox/fox/release.json'
    manifest.parent.mkdir(parents=True)
    value=deepcopy(r.public_release());mutation(value)
    manifest.write_text(json.dumps(value),encoding='utf-8')
    # Reject the metadata itself, before package/changelog consistency checks.
    with pytest.raises(ValueError,match='Invalid release metadata'):
        checker.check(candidate)
