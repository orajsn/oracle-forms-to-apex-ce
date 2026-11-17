"""Cold export-launch configuration without provider or database execution."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

spec=importlib.util.spec_from_file_location('export_launcher',Path(__file__).parents[1]/'run_export_preview.py')
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)

@pytest.fixture
def configured(tmp_path):
    root=tmp_path/'instance';root.mkdir(mode=0o700)
    product=tmp_path/'product';(product/'fox/fox').mkdir(parents=True);(product/'fox/dist').mkdir()
    (product/'fox/fox/app.py').write_text('# fixture');(product/'fox/dist/index.html').write_text('fixture')
    ui=tmp_path/'ui.json';ui.write_text(json.dumps({'username':'operator','password_hash':'a'*32+':'+'b'*128}));ui.chmod(0o600)
    profile=tmp_path/'profile.json';profile.write_text('{}')
    sql=tmp_path/'sql';sql.write_text('fixture')
    config=tmp_path/'config.json';value={'schema_version':1,'instance_root':str(root),'product_root':str(product),
        'api_port':18260,'ui_credentials_file':str(ui),'design_profile_file':str(profile),'sqlcl_path':str(sql),'forms':None}
    config.write_text(json.dumps(value));config.chmod(0o600)
    return config,value


def test_cold_plan_has_only_api_and_cannot_inherit_database_runtime_secrets(configured):
    config,_=configured;value,credentials=launcher.configuration(config)
    env,commands=launcher.launch_plan(value,credentials,environ={'PATH':'retained','F2A_MCP_BEARER_TOKEN':'forbidden',
        'F2A_SQLCL_CONNECTION_NAME':'forbidden','FOX_CONVERTER_CREDENTIAL_FILE':'forbidden',
        'FOX_HOSTED_FORMS_QUEUE':'old','FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED':'1','FOX_DEFAULT_DELIVERY_MODE':'legacy',
        'PYTHONHOME':'old'},python='selected-python')
    assert [name for name,_ in commands]==['api']
    assert commands[0][1][-4:]==['--host','127.0.0.1','--port','18260']
    assert env['FOX_DEFAULT_DELIVERY_MODE']=='apexlang_package'
    assert env['FOX_PUBLIC_ORIGIN']=='http://127.0.0.1:18260'
    assert env['FOX_PROTOTYPE_AUTHORITY_ENABLED']=='0'
    assert env['PATH']=='retained' and env['TMPDIR']==str(value['instance_root']/'tmp')
    assert not any(key.startswith('F2A_') for key in env)
    assert not any(key in env for key in ('FOX_CONVERTER_CREDENTIAL_FILE','FOX_HOSTED_FORMS_QUEUE',
        'FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED','PYTHONHOME'))
    assert not (value['instance_root']/'data').exists()


@pytest.mark.parametrize('origin',[
    'https://fox.example.test','https://fox.example.test:8443',
    'https://127.0.0.1:8443','https://[2001:db8::1]:8443',
])
def test_exact_https_origin_changes_only_public_origin_not_listener(configured,origin):
    config,value=configured
    baseline,credentials=launcher.configuration(config)
    old_env,old_commands=launcher.launch_plan(baseline,credentials,environ={})
    value['public_origin']=origin;config.write_text(json.dumps(value))
    parsed,credentials=launcher.configuration(config)
    env,commands=launcher.launch_plan(parsed,credentials,environ={'FOX_PUBLIC_ORIGIN':'https://untrusted.test'})
    assert parsed['public_origin']==origin and env['FOX_PUBLIC_ORIGIN']==origin
    assert commands==old_commands
    assert {**env,'FOX_PUBLIC_ORIGIN':old_env['FOX_PUBLIC_ORIGIN']}==old_env
    assert commands[0][1][-4:]==['--host','127.0.0.1','--port','18260']
    assert not (parsed['instance_root']/'data').exists()


@pytest.mark.parametrize('origin',[
    None,False,443,[],{},'', 'http://fox.example.test','http://127.0.0.1:18260',
    '//fox.example.test','https://','https:///fox.example.test',
    'https://operator@fox.example.test','https://operator:password@fox.example.test',
    'https://fox.example.test/','https://fox.example.test/path',
    'https://fox.example.test?','https://fox.example.test?key=value',
    'https://fox.example.test#','https://fox.example.test#fragment',
    ' https://fox.example.test','https://fox.example.test ',
    'https://fox.example.test\n','https://fox.exam\tple.test','https://fox.example.test\x00',
    'https://fox.example.test\\other','https://fox%2eexample.test',
    'https://fox.example.test:','https://fox.example.test:0','https://fox.example.test:65536',
    'https://fox.example.test:not-a-port','https://fox.example.test:0443',
    'HTTPS://fox.example.test','https://FOX.example.test','https://fox.example.test:443',
    'https://fox.example.test.','https://-fox.example.test','https://fox..example.test',
    'https://fox_example.test','https://fóx.example.test','https://999.1.1.1',
    'https://127.1','https://0x7f000001','https://[broken]',
    'https://[2001:0db8::1]','https://[fe80::1%25eth0]',
])
def test_invalid_or_noncanonical_public_origin_is_rejected_before_services(configured,origin):
    config,value=configured;value['public_origin']=origin;config.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='exact HTTPS public origin'):launcher.configuration(config)
    assert not (Path(value['instance_root'])/'data').exists()


@pytest.mark.parametrize('origin',[None,'https://fox.example.test:8443'])
def test_launcher_origin_matches_real_app_cookie_and_csrf_contract(configured,tmp_path,monkeypatch,origin):
    # Real in-process ASGI/SQLite only: no listener, worker, compiler or provider.
    for key in tuple(os.environ):
        if key.startswith(('FOX_','F2A_')):monkeypatch.delenv(key,raising=False)
    product=Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(product/'converter'))
    monkeypatch.syspath_prepend(str(product/'fox'))
    monkeypatch.setenv('FOX_DATA_DIR',str(tmp_path/'import-data'))
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED','0')
    from fastapi.testclient import TestClient
    from fox.app import create_app, password_hash
    def forbidden(*a,**k):raise AssertionError('No subprocess may execute in origin compatibility tests')
    monkeypatch.setattr(launcher.subprocess,'Popen',forbidden)
    monkeypatch.setattr(launcher.subprocess,'run',forbidden)
    config,value=configured
    if origin is not None:value['public_origin']=origin;config.write_text(json.dumps(value))
    parsed,credentials=launcher.configuration(config)
    credentials['password_hash']=password_hash('synthetic-origin-password')
    env,commands=launcher.launch_plan(parsed,credentials,environ={})
    for key,item in env.items():monkeypatch.setenv(key,item)
    effective_origin=env['FOX_PUBLIC_ORIGIN']
    body={'username':'operator','password':'synthetic-origin-password'}
    with TestClient(create_app(tmp_path/'app-data',enable_worker=False),base_url=effective_origin) as client:
        for invalid in (None,'https://other.example.test',effective_origin+'/',effective_origin+':1234'):
            headers={} if invalid is None else {'Origin':invalid}
            assert client.post('/api/login',json=body,headers=headers).status_code==403
        login=client.post('/api/login',json=body,headers={'Origin':effective_origin})
        assert login.status_code==200,login.text
        cookie=login.headers['set-cookie'].lower()
        assert 'httponly' in cookie and 'samesite=strict' in cookie and 'path=/' in cookie
        assert ('; secure' in cookie)==(origin is not None)
        session=client.get('/api/session')
        assert session.status_code==200 and session.json()['username']=='operator'
        assert session.json()['delivery_mode']=='apexlang_package'
        if origin is not None:
            assert client.get(effective_origin.replace('https://','http://')+'/api/session').status_code==401
        assert client.post('/api/logout').status_code==403
        assert client.get('/api/session').status_code==200
        assert client.post('/api/logout',headers={'Origin':effective_origin}).status_code==200
        assert client.get('/api/session').status_code==401
    assert [name for name,_ in commands]==['api']


def test_explicit_forms_adds_only_extraction_worker(configured,tmp_path):
    config,value=configured
    oracle=tmp_path/'oracle';oracle.mkdir();java=tmp_path/'java';java.mkdir()
    value['forms']={'oracle_home':str(oracle),'java_home':str(java)};config.write_text(json.dumps(value))
    parsed,credentials=launcher.configuration(config);env,commands=launcher.launch_plan(parsed,credentials,environ={})
    assert [name for name,_ in commands]==['api','forms']
    assert 'fox.hosted_forms_worker' in commands[1][1]
    assert 'FOX_HOSTED_FORMS_QUEUE' in env
    assert not any('forms2apex.server' in command or 'poll_direct_runtime.py' in command for _,command in commands)


@pytest.mark.parametrize('damage',['extra_config','database_secret','bad_port','missing_compiler','missing_ui'])
def test_bad_configuration_rejected_before_services(configured,damage):
    config,value=configured
    if damage=='extra_config':value['environment']={'F2A_SQLCL_CONNECTION_NAME':'forbidden'}
    elif damage=='database_secret':
        path=Path(value['ui_credentials_file']);secret=json.loads(path.read_text());secret['converter_token']='forbidden';path.write_text(json.dumps(secret))
    elif damage=='bad_port':value['api_port']=True
    elif damage=='missing_compiler':Path(value['sqlcl_path']).unlink()
    else:(Path(value['product_root'])/'fox/dist/index.html').unlink()
    config.write_text(json.dumps(value))
    with pytest.raises(ValueError):launcher.configuration(config)
    assert not (Path(value['instance_root'])/'data').exists()


@pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:0)()==0,reason='Actual nonroot Linux lock semantics')
def test_existing_supervisor_lock_prevents_any_child_or_data_start(configured,monkeypatch):
    import fcntl
    config,value=configured;root=Path(value['instance_root'])
    def forbidden(*a,**k):raise AssertionError('No child may start while instance is owned')
    monkeypatch.setattr(launcher.subprocess,'Popen',forbidden)
    with (root/'preview.lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(RuntimeError,match='Another preview supervisor'):launcher.run(config)
    assert not (root/'data').exists()
