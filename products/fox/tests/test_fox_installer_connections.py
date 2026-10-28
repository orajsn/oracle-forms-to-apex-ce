"""Real create-only private connection files; no live service/Oracle/model I/O."""
from copy import deepcopy
import hashlib
import http.client
import json
import os
from pathlib import Path
import stat
import sys
import threading
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'fox'), str(ROOT / 'converter')]
from qa.operator import installer_connections as c
from qa.operator import setup_wizard as wizard
from forms2apex.target_profile import select_target_profile, TargetProfileError

PASSWORD = 'synthetic-fox-password-only'
OPAF_PASSWORD = 'synthetic-opaf-password-only'


@pytest.fixture
def body():
    return {'target_profile_id': 'jsn-native-project-v2', 'fox_username': 'demo-operator',
            'fox_password': PASSWORD, 'opaf_username': 'synthetic-opaf', 'opaf_password': OPAF_PASSWORD}


@pytest.fixture
def store(tmp_path):
    if os.name != 'posix' or os.geteuid() == 0:pytest.skip('actual nonroot Linux required')
    tmp_path.chmod(0o700)
    plan = c.step.plan(str(tmp_path / 'instance'), owner_uid=os.geteuid()); digest = c.step.digest(plan)
    c.step.initialize(plan, expected_plan_sha256=digest, apply=True)
    return plan, digest, Path(plan['installation_root']) / c.DIRECTORY


def retained(root):
    return {p.relative_to(root).as_posix(): (p.lstat().st_ino, p.lstat().st_mtime_ns,
            stat.S_IMODE(p.lstat().st_mode), p.read_bytes() if p.is_file() else None)
            for p in [root, *root.rglob('*')]}


def test_registry_selection_is_detached_and_never_adds_customer_authority():
    value = select_target_profile('jsn-native-project-v2')
    assert value['scope']['customer_deployment_authorized'] is False
    value['opaf']['roles']['mapper']['model'] = 'altered'
    assert select_target_profile('jsn-native-project-v2')['opaf']['roles']['mapper']['model'] != 'altered'
    for value in ('unknown-customer', None, True):
        with pytest.raises(TargetProfileError):select_target_profile(value)


@pytest.mark.parametrize('change', [
    {'target_profile_id': 'customer-production'}, {'fox_username': '../name'},
    {'opaf_username': 'name\n'}, {'fox_password': 'short'}, {'opaf_password': 'bad\npassword'},
    {'fox_password': None}, {'opaf_password': 12}, {'fox_password': 'x' * 257}, {'extra': 'secret'},
])
def test_invalid_fields_are_closed_and_do_not_write(store, body, change):
    plan, digest, root = store; body.update(change)
    with pytest.raises(c.InstallerConnectionError):
        c.prepare(plan, expected_plan_sha256=digest, body=body, apply=True)
    assert not root.exists()


def test_real_files_match_runtime_formats_and_password_hash(store, body, monkeypatch):
    plan, digest, root = store
    with patch('socket.create_connection', side_effect=AssertionError('no network')):
        result = c.prepare(plan, expected_plan_sha256=digest, body=body, apply=True)
        from fox.native_project_pipeline import load_project_profile, _configuration
        profile = load_project_profile(root / 'opaf-profile.json')
        monkeypatch.setenv('FOX_NATIVE_PROFILE_FILE', str(root / 'opaf-profile.json'))
        monkeypatch.setenv('FOX_OPAF_CREDENTIAL_FILE', str(root / 'opaf/client.json'))
        monkeypatch.setenv('FOX_CONVERTER_URL', 'http://127.0.0.1:8091')
        for name in tuple(os.environ):
            if name == 'FOX_INSTALLATION_MODE' or name.startswith('FOX_FRESH_'):monkeypatch.delenv(name)
        actual, gateway, client = _configuration()
        assert actual == profile and client.username == body['opaf_username']
        assert client.password == OPAF_PASSWORD
    assert result['status'] == 'CONNECTION_INPUTS_SAVED_NOT_TESTED' and not result['conversion_ready']
    rendered = json.dumps(result)
    assert PASSWORD not in rendered and OPAF_PASSWORD not in rendered and 'password_verifier' not in rendered
    access = json.loads((root / 'private/fox-access.json').read_bytes())
    assert PASSWORD not in (root / 'private/fox-access.json').read_text()
    salt, hashed = access['password_verifier'].split(':')
    assert hashlib.scrypt(PASSWORD.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex() == hashed
    credentials = json.loads((root / 'opaf/client.json').read_bytes())
    assert len(credentials['converter_token']) >= 32
    assert (root / 'private/converter-token').read_text() == credentials['converter_token'] + '\n'
    for p in [root, *root.rglob('*')]:
        assert stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600)


def test_repeat_and_restart_preserve_credentials_identity_and_storage(store, body):
    plan, digest, root = store
    original = c.step.inspect(plan, expected_plan_sha256=digest)
    c.prepare(plan, expected_plan_sha256=digest, body=body, apply=True); before = retained(root)
    body['fox_password'] = 'a-new-value-not-a-rotation'
    result = c.prepare(plan, expected_plan_sha256=digest, body=body, apply=True)
    assert result['credentials_unchanged'] and retained(root) == before
    assert c.inspect(plan, expected_plan_sha256=digest)['read_only']
    assert c.step.inspect(plan, expected_plan_sha256=digest) == original
    restarted = wizard.Controller(); value = restarted.plan({'installation_root': plan['installation_root']})
    result = restarted.initialize({'plan_sha256': value['plan_sha256'], 'confirmed': True})
    assert result['state'] == 'CONNECTION_INPUTS_SAVED' and retained(root) == before


def test_explicit_approval_and_matching_storage_are_required(store, body):
    plan, digest, root = store
    with pytest.raises(c.InstallerConnectionError):c.prepare(plan, expected_plan_sha256=digest, body=body)
    with pytest.raises(c.step.InstallerStorageError):
        c.prepare(plan, expected_plan_sha256='0'*64, body=body, apply=True)
    assert not root.exists()


def test_real_http_save_never_echoes_or_logs_credentials(store, body, capsys):
    plan, digest, root = store; controller = wizard.Controller()
    controller.plan({'installation_root':plan['installation_root']})
    controller.initialize({'plan_sha256':digest, 'confirmed':True})
    server, token = wizard.create_server(controller=controller)
    thread = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    try:
        connection = http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
        connection.request('POST','/api/connections',body=json.dumps({
            'plan_sha256':digest, 'confirmed':True, 'settings':body}),headers={
            'Authorization':'Bearer '+token, 'Origin':'http://127.0.0.1:'+str(server.server_port),
            'Content-Type':'application/json'})
        response=connection.getresponse();raw=response.read();connection.close()
        assert response.status==200 and json.loads(raw)['state']=='CONNECTION_INPUTS_SAVED'
        assert PASSWORD.encode() not in raw and OPAF_PASSWORD.encode() not in raw
    finally:
        server.shutdown();server.server_close();thread.join(5)
    assert not thread.is_alive()
    output=capsys.readouterr();assert not output.out and not output.err


def test_partial_write_is_retained_and_cannot_be_replayed(store, body):
    plan, digest, root = store; original = c.step.storage._write
    def interrupted(path, raw):
        if path.name == 'fox-access.json':raise OSError('synthetic-secret-diagnostic')
        return original(path, raw)
    with patch.object(c.step.storage, '_write', side_effect=interrupted):
        with pytest.raises(OSError):c.prepare(plan, expected_plan_sha256=digest, body=body, apply=True)
    before = retained(root)
    with patch.object(c.step.storage, '_write', side_effect=AssertionError('no replay')):
        with pytest.raises(c.InstallerConnectionError):c.prepare(plan, expected_plan_sha256=digest, body=body, apply=True)
    assert retained(root) == before


@pytest.mark.parametrize('change', ['secret', 'receipt', 'extra', 'link'])
def test_changed_or_aliased_configuration_is_not_reused(store, body, change):
    plan, digest, root = store;c.prepare(plan, expected_plan_sha256=digest, body=body, apply=True)
    if change == 'secret':(root / 'opaf/client.json').write_bytes(b'{}')
    elif change == 'receipt':(root / 'complete.json').write_bytes(b'{"ready":true}')
    elif change == 'extra':(root / 'customer-file').write_bytes(b'preserve')
    else:
        (root / 'opaf/client.json').rename(root / 'opaf/retained.json')
        (root / 'opaf/client.json').symlink_to(root / 'opaf/retained.json')
    with pytest.raises((c.InstallerConnectionError, c.step.storage.FreshStorageError)):
        c.inspect(plan, expected_plan_sha256=digest)


def test_controller_approval_and_duplicate_submission_are_exact(tmp_path, body):
    if os.name != 'posix' or os.geteuid() == 0:pytest.skip('actual nonroot Linux required')
    tmp_path.chmod(0o700); controller = wizard.Controller()
    value = controller.plan({'installation_root': str(tmp_path / 'instance')})
    controller.initialize({'plan_sha256': value['plan_sha256'], 'confirmed': True})
    request = {'plan_sha256': value['plan_sha256'], 'confirmed': True, 'settings': body}
    bad = deepcopy(request);bad['confirmed'] = 1
    with pytest.raises(wizard.WizardError):controller.configure(bad)
    bad = deepcopy(request);bad['settings']['fox_password'] = 'short'
    with pytest.raises(c.InstallerConnectionError):controller.configure(bad)
    assert not controller.status()['connection_write_attempted']
    result = controller.configure(request)
    assert result['state'] == 'CONNECTION_INPUTS_SAVED'
    with patch.object(c, 'prepare', side_effect=AssertionError('no replay')):
        assert controller.configure(request)['state'] == 'CONNECTION_INPUTS_SAVED'
        assert controller.recheck()['state'] == 'CONNECTION_INPUTS_SAVED'
    root = tmp_path / 'instance/configuration';(root / 'private/converter-token').write_text('changed')
    result = controller.recheck()
    assert result['state'] == 'ATTENTION' and result['connections'] is None
    assert PASSWORD not in json.dumps(result) and OPAF_PASSWORD not in json.dumps(result)
