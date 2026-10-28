"""Real local discovery without application/database/credential execution."""
import importlib.util
from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fox_setup_discovery', ROOT / 'scripts/fox-setup.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def snapshot(root):
    return {p.relative_to(root).as_posix(): (p.stat().st_mtime_ns, p.read_bytes())
            for p in root.rglob('*') if p.is_file()}


def check(root, expected):
    before = snapshot(root) if root.exists() else None
    result = S.inspect_installation(root)
    assert result['status'] == expected
    assert result['read_only'] is True
    for key in ('changes_performed', 'runtime_checked', 'release_integrity_verified',
                'conversion_ready', 'installation_verified', 'automatic_install_authorized',
                'secret_references_resolved', 'network_calls_performed'):
        assert result[key] is False
    assert (snapshot(root) if root.exists() else None) == before
    return result


def test_absent_root_stays_absent(tmp_path):
    check(tmp_path / 'new', 'NOT_INSTALLED')
    assert not (tmp_path / 'new').exists()


def test_empty_root_is_not_installed(tmp_path):
    check(tmp_path, 'EMPTY_DIRECTORY_NOT_INSTALLED')


@pytest.mark.parametrize('marker', ['fox.sqlite3', 'intent.json', 'roots.json',
    'complete.json', 'projection.json', 'backend-initialization.json',
    'live-admission.json', 'installation.json'])
def test_state_is_not_replayed_or_declared_ready(tmp_path, marker):
    (tmp_path / marker).write_bytes(b'{"ready":true,"password":"synthetic-private-value"}')
    with patch.object(S, 'regular_bytes', side_effect=AssertionError('must not read state')):
        result = check(tmp_path, 'EXISTING_STATE_UNVERIFIED')
    assert 'synthetic-private-value' not in json.dumps(result)


def test_local_session_is_never_conversion_ready(tmp_path):
    (tmp_path / '.fox-local-session.json').write_bytes(b'private session metadata')
    with patch.object(S, 'regular_bytes', side_effect=AssertionError('must not read session')):
        check(tmp_path, 'ASSESSMENT_SESSION_UNVERIFIED')


def test_conflicting_markers_fail(tmp_path):
    for name in ('.fox-local-session.json', 'projection.json'):
        (tmp_path / name).write_bytes(b'')
    with pytest.raises(S.SetupError, match='CONFLICTING_INSTALLATION_MARKERS'):
        S.inspect_installation(tmp_path)


@pytest.mark.parametrize('kind,names', [
    ('PRODUCT_SOURCE_NOT_INSTALLATION', ['fox/requirements-lock.txt',
     'converter/forms2apex/target_profile.py', 'qa/operator/hosted_service.py', 'scripts/fox-setup.py']),
    ('RUNTIME_SOURCE_NOT_INSTALLATION', ['requirements-lock.txt', 'package.json',
     'scripts/start-local.ps1', 'fox/local_assessment.py']),
    ('CE_SKILL_NOT_FOX_INSTALLATION', ['install.py', 'oracle-forms-to-apex-ce/SKILL.md'])])
def test_source_is_not_installed_or_executed(tmp_path, kind, names):
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'raise AssertionError("untrusted source must not execute")')
    check(tmp_path, kind)


def test_unknown_user_files_are_untouched_and_not_echoed(tmp_path):
    (tmp_path / 'synthetic-private-filename').write_bytes(b'private content')
    result = check(tmp_path, 'UNRECOGNIZED_NONEMPTY_DIRECTORY')
    assert 'private' not in json.dumps(result)


def test_malformed_manifest_is_not_an_installation(tmp_path):
    (tmp_path / 'fox-installation.json').write_bytes(b'{"ready":true,"ready":true}')
    with pytest.raises(S.SetupError, match='DUPLICATE_JSON_FIELD'):
        S.inspect_installation(tmp_path)


@pytest.mark.parametrize('route,expected', [
    ('localhost-assessment', 'ASSESSMENT_BUNDLE_UNVERIFIED'),
    ('existing-jsn-hosted-reference', 'HOSTED_REFERENCE_NOT_INSTALLER')])
def test_manifest_route_is_not_admission(tmp_path, route, expected):
    # Self-contained synthetic metadata, not an excluded private workspace file.
    manifest = {'document_type': 'fox-installation-v1', 'schema_version': 1,
        'route': route, 'activation': {'conversion_enabled': False,
            'customer_deployment_authorized': False},
        'release': {'state': 'UNFROZEN', 'release_id': 'synthetic-discovery',
            'files': [{'path': 'fox/fox/__init__.py', 'sha256': None}],
            'python_lock': 'fox/requirements-lock.txt', 'ui_entry': 'fox/dist/index.html',
            'entrypoint': 'fox/scripts/start-local.ps1'},
        'host': {'platform': 'windows', 'python_implementation': 'CPython',
            'python_major': 3, 'python_minor': 12, 'bind_address': '127.0.0.1', 'port': 8100},
        'storage': {'session_relative_path': 'fox/work/local-assessment',
            'preserve_on_prepare': True, 'backup_reference': None, 'rollback_reference': None},
        'secret_references': {'local_login': 'prompt://local-session-password', 'hosted_runtime': None},
        'optional_tools': {'oracle_home_reference': None, 'java_reference': None}}
    (tmp_path / 'fox-installation.json').write_text(json.dumps(manifest))
    check(tmp_path, expected)


def test_existing_state_takes_priority_over_checkout(tmp_path):
    for name in ('fox.sqlite3', 'fox/requirements-lock.txt',
                 'converter/forms2apex/target_profile.py',
                 'qa/operator/hosted_service.py', 'scripts/fox-setup.py'):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'synthetic')
    check(tmp_path, 'EXISTING_STATE_UNVERIFIED')


def test_symlinked_root_is_rejected(tmp_path):
    (tmp_path / 'target').mkdir()
    alias = tmp_path / 'alias'
    try:
        alias.symlink_to(tmp_path / 'target', target_is_directory=True)
    except OSError:
        pytest.skip('host does not permit creating a test symlink')
    with pytest.raises(S.SetupError, match='LINKED_PATH_PROHIBITED'):
        S.inspect_installation(alias)


def test_root_changed_during_scan_is_rejected(tmp_path):
    scan = S.os.scandir

    @contextmanager
    def changed(path):
        before = path.stat()
        (path / 'concurrent-write').write_bytes(b'synthetic')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 500_000_000))
        with scan(path) as iterator:
            yield iterator

    with patch.object(S.os, 'scandir', changed):
        with pytest.raises(S.SetupError, match='INSTALLATION_ROOT_CHANGED_DURING_INSPECTION'):
            S.inspect_installation(tmp_path)


def test_inventory_is_bounded(tmp_path):
    for i in range(257):
        (tmp_path / str(i)).touch()
    with pytest.raises(S.SetupError, match='INSTALLATION_ROOT_INVENTORY_BOUND'):
        S.inspect_installation(tmp_path)


def test_root_must_be_a_directory(tmp_path):
    path = tmp_path / 'file'
    path.write_bytes(b'synthetic')
    with pytest.raises(S.SetupError, match='INSTALLATION_ROOT_NOT_DIRECTORY'):
        S.inspect_installation(path)


def test_cli_has_no_storage_database_network_or_application_side_effect(tmp_path):
    program = r'''
import importlib.util, pathlib, socket, sqlite3, subprocess, sys
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('setup_discovery',sys.argv[1])
module=importlib.util.module_from_spec(spec)
def denied(*a,**k):raise AssertionError('unexpected side effect')
with patch.object(pathlib.Path,'mkdir',side_effect=denied), patch.object(sqlite3,'connect',side_effect=denied), patch.object(socket.socket,'connect',side_effect=denied), patch.object(subprocess,'run',side_effect=denied), patch.object(subprocess,'Popen',side_effect=denied):
 spec.loader.exec_module(module)
 assert module.main(['inspect','--installation-root',sys.argv[2]])==0
assert 'fox.app' not in sys.modules
'''
    result = subprocess.run([sys.executable, '-I', '-B', '-c', program,
        str(ROOT / 'scripts/fox-setup.py'), str(tmp_path / 'absent')],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['status'] == 'NOT_INSTALLED'
    assert not (tmp_path / 'absent').exists()


@pytest.mark.parametrize('args', [[], ['private-token'], ['--output','private-token'],
    ['--source-root','private-token'], ['--installation-root','unused','extra-private-token']])
def test_invalid_cli_never_echoes_supplied_values(args, capsys):
    with pytest.raises(S.SetupError):
        S.main(['inspect', *args])
    assert 'private-token' not in capsys.readouterr().out
