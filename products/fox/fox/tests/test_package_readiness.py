"""Real configuration/session checks; no compiler, provider or target execution."""
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fox.app import (create_app, password_hash, conversion_configuration,
                     package_conversion_configuration, reporting_configuration)
from fox.opaf import canonical_hash
from test_source_history_api import no_external_actions, upload
from test_project_conversion import pair

ORIGIN='http://127.0.0.1:8100'

@pytest.fixture
def configured(tmp_path,monkeypatch):
    for key in list(__import__('os').environ):
        if key.startswith(('FOX_','F2A_')):monkeypatch.delenv(key,raising=False)
    target=json.loads((Path(__file__).parents[2]/'deployment/target-profile.jsn-project-2616-oci-genai.json').read_text())
    profile=tmp_path/'profile.json'
    profile.write_text(json.dumps({'target_profile':target,'target_profile_sha256':canonical_hash(target)}))
    compiler=tmp_path/'sql';compiler.write_text('metadata-only fixture; never executed')
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE',str(profile))
    monkeypatch.setenv('FOX_EXPORT_SQLCL_PATH',str(compiler))
    monkeypatch.setenv('FOX_RUN_ADAPTER','oci-genai')
    monkeypatch.setenv('FOX_CONVERSION_PROFILE','native-project-v1')
    monkeypatch.setenv('FOX_ADMIN_USERNAME','format-test')
    monkeypatch.setenv('FOX_PASSWORD_HASH',password_hash('test-only'))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN',ORIGIN)
    return profile,compiler


def test_package_reporting_never_constructs_clients(configured,monkeypatch):
    import fox.opaf
    def forbidden(*a,**k):raise AssertionError('Readiness must not construct a client')
    monkeypatch.setattr(fox.opaf,'ConverterClient',forbidden)
    monkeypatch.setattr(fox.opaf,'OpafClient',forbidden)
    value=reporting_configuration()
    assert value['conversion_configured'] is True
    assert value['delivery_mode']=='apexlang_package'
    assert not any('CONVERTER' in row['code'] for row in value['configuration_checks'])


def test_package_ready_does_not_make_legacy_execution_ready(configured,monkeypatch):
    assert package_conversion_configuration()['conversion_configured'] is True
    assert conversion_configuration()['conversion_configured'] is False
    monkeypatch.setenv('FOX_DEFAULT_DELIVERY_MODE','legacy')
    assert reporting_configuration()==conversion_configuration()


def test_old_project_configuration_requires_explicit_legacy_reporting(monkeypatch):
    import fox.app as app
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.delenv('FOX_PROTOTYPE_PROFILE_FILE', raising=False)
    monkeypatch.delenv('FOX_DEFAULT_DELIVERY_MODE', raising=False)
    expected = {'conversion_configured': True, 'configured_project_schema_versions': [1, 2]}
    monkeypatch.setattr(app, 'conversion_configuration', lambda **kwargs: expected)
    package = {'conversion_configured': False, 'delivery_mode': 'apexlang_package'}
    monkeypatch.setattr(app, 'package_conversion_configuration', lambda: package)
    assert app.reporting_configuration() is package
    monkeypatch.setenv('FOX_DEFAULT_DELIVERY_MODE', 'legacy')
    assert app.reporting_configuration() is expected


@pytest.mark.parametrize('damage',['compiler','profile_hash','adapter','mode'])
def test_missing_or_changed_package_configuration_fails_closed(configured,monkeypatch,damage):
    profile,compiler=configured
    if damage=='compiler':compiler.unlink()
    elif damage=='profile_hash':
        value=json.loads(profile.read_text());value['target_profile_sha256']='0'*64;profile.write_text(json.dumps(value))
    elif damage=='adapter':monkeypatch.setenv('FOX_RUN_ADAPTER','unknown')
    else:monkeypatch.setenv('FOX_DEFAULT_DELIVERY_MODE','unknown')
    assert reporting_configuration()['conversion_configured'] is False


def test_authenticated_session_ready_but_valid_legacy_submission_is_rejected(configured,tmp_path):
    root=tmp_path/'data'
    with TestClient(create_app(root,enable_worker=False),base_url=ORIGIN) as client:
        client.headers['Origin']=ORIGIN
        assert client.post('/api/login',json={'username':'format-test','password':'test-only'}).status_code==200
        session=client.get('/api/session').json()
        assert session['conversion_configured'] is True and session['delivery_mode']=='apexlang_package'
        created=client.post('/api/projects',json={'customer':'Synthetic readiness test','name':'Format ready'})
        assert created.status_code==201;pid=created.json()['id']
        selected=upload(client,pid,[(r['name'],r['text'].encode()) for r in pair()])
        detail=client.get('/api/projects/'+pid).json();plan=detail['project_plan']
        assert plan['can_generate'] is True
        assert detail['project_capabilities']['package_delivery']['enabled'] is True
        assert detail['project_capabilities']['process']['enabled'] is False
        response=client.post(f'/api/projects/{pid}/runs',json={'source_hash':selected['source_hash'],
            'expected_current_source_set_id':selected['selected_source_set_id'],'plan_sha256':plan['plan_sha256'],
            'approved_redacted_source':True,'approved_external_ai':True,'approved_prototype_scope':True})
        assert response.status_code==503,response.text
    with sqlite3.connect(root/'fox.sqlite3') as db:assert db.execute('select count(*) from runs').fetchone()[0]==0
