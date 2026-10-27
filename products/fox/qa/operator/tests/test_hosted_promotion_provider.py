"""Promotion/provider seam tests with real receipt and private-file checks.

Fixtures build real synthetic packages and source-bound receipts. Only the
external host-execution boundary is substituted; receipt/profile/provenance
and native ACL or POSIX mode checks execute normally. No live host is contacted.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox', ROOT / 'fox/tests', ROOT / 'qa/operator/tests'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from qa.operator import promote_native as native, promote_project as project
from qa.operator import project_qa_dispatch
from test_promote_native import collection as native_collection
from test_promote_native import v2_case, proof_case, valid_package, harness, client
from test_promote_project import collection as project_collection, case, actual_release


NATIVE_PRIVATE_INPUTS = native.private_inputs
PROJECT_PRIVATE_INPUTS = project_qa_dispatch.private_inputs
LEGACY_LOADER = "python3 -B -c 'import base64,sys;exec(base64.b64decode(sys.stdin.buffer.readline()))'"


def protect(paths):
    """Make only the supplied synthetic fixture paths owner-private."""
    if os.name != 'nt':
        for path in paths:
            path.chmod(0o700 if path.is_dir() else 0o600)
        return
    script = r'''$ErrorActionPreference='Stop'
$v=([Console]::In.ReadToEnd()|ConvertFrom-Json)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
foreach($p in $v.paths) {
 if([IO.Directory]::Exists($p)) {
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
 } else {
  $acl=New-Object Security.AccessControl.FileSecurity
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','Allow')
 }
 $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false); $acl.SetAccessRule($rule)
 if([IO.Directory]::Exists($p)){[IO.Directory]::SetAccessControl($p,$acl)}else{[IO.File]::SetAccessControl($p,$acl)}
}
Write-Output 'SYNTHETIC_PATHS_PROTECTED'
'''
    result = subprocess.run(['powershell', '-NoProfile', '-Command', script],
        input=json.dumps({'paths': [str(path) for path in paths]}).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode == 0 and result.stdout.strip() == b'SYNTHETIC_PATHS_PROTECTED'


def checked(cli, collection, monkeypatch):
    directory, options, expected = collection
    protect([directory, *directory.iterdir()])
    # The reused fixture normally isolates platform ACL tests. Restore the real
    # checker here after giving its actual local files private ownership/modes.
    monkeypatch.setattr(cli, 'private_inputs', NATIVE_PRIVATE_INPUTS if cli is native else PROJECT_PRIVATE_INPUTS)
    response = {'status': 'READY_NOT_APPLIED', 'job_id': expected['binding']['job_id'],
        'human_acceptance_recorded': False, 'host_scope_verified': True,
        'expected_image': expected['expected_image'], 'module_sha256': expected['module_sha256']}
    return directory, options, expected, response


def provider_dispatch(cli, collection, monkeypatch):
    directory, options, expected, response = checked(cli, collection, monkeypatch)
    calls = []
    def execute(program, encoded_packet, *, timeout, legacy_loader):
        calls.append((program, encoded_packet, timeout, legacy_loader))
        assert program == cli.host_source()
        assert json.loads(encoded_packet)['receipts'] == expected['receipts']
        assert encoded_packet.endswith(b'\n')
        assert timeout == 180 and legacy_loader == LEGACY_LOADER
        return json.dumps(response).encode()
    monkeypatch.setattr(cli.transport, 'execute_host', execute)
    original = cli.transport.run_process
    def no_ssh(args, **kwargs):
        assert args[0] != 'ssh', 'Promotion must not bypass the selected provider'
        return original(args, **kwargs)  # Real Windows ACL check only.
    monkeypatch.setattr(cli.transport, 'run_process', no_ssh)
    assert cli.dispatch('check', directory, **options) == response
    assert len(calls) == 1


def test_native_dispatch_uses_selected_provider_with_real_private_inputs(native_collection, monkeypatch):
    provider_dispatch(native, native_collection, monkeypatch)


def test_project_dispatch_uses_selected_provider_with_real_private_inputs(project_collection, monkeypatch):
    provider_dispatch(project, project_collection, monkeypatch)


def legacy_dispatch(cli, collection, monkeypatch):
    directory, options, expected, response = checked(cli, collection, monkeypatch)
    calls = []
    original = cli.transport.run_process
    def boundary(args, **kwargs):
        if args[0] != 'ssh':
            return original(args, **kwargs)  # Real Windows ACL check only.
        calls.append((args, kwargs))
        program, body = kwargs['data'].split(b'\n', 1)
        assert base64.b64decode(program).decode() == cli.host_source()
        assert json.loads(body)['receipts'] == expected['receipts']
        assert kwargs['timeout'] == 180
        return json.dumps(response).encode()
    monkeypatch.setattr(cli.transport, 'run_process', boundary)
    assert cli.dispatch('check', directory, **options) == response
    assert len(calls) == 1
    assert calls[0][0] == [*cli.transport.SSH, LEGACY_LOADER]
    assert all(encoded not in repr(calls[0][0]) for encoded in expected['receipts'].values())


def test_native_default_provider_preserves_exact_legacy_argv(native_collection, monkeypatch):
    legacy_dispatch(native, native_collection, monkeypatch)


def test_project_default_provider_preserves_exact_legacy_argv(project_collection, monkeypatch):
    legacy_dispatch(project, project_collection, monkeypatch)


def bounded_dispatch(cli, collection, monkeypatch):
    directory, options, _, _ = checked(cli, collection, monkeypatch)
    monkeypatch.setattr(cli.transport, 'MAX_WIRE', 100)
    monkeypatch.setattr(cli.transport, 'execute_host', lambda *args, **kwargs: pytest.fail('No oversized transport'))
    with pytest.raises(ValueError, match='PROTECTED_(PROJECT_)?REQUEST_TOO_LARGE'):
        cli.dispatch('check', directory, **options)


def test_native_original_wire_bound_rejects_before_provider(native_collection, monkeypatch):
    bounded_dispatch(native, native_collection, monkeypatch)


def test_project_original_wire_bound_rejects_before_provider(project_collection, monkeypatch):
    bounded_dispatch(project, project_collection, monkeypatch)


def test_project_selected_handoff_root_does_not_adopt_legacy_work_root(project_collection, case, monkeypatch):
    original, options, expected, _ = checked(project, project_collection, monkeypatch)
    workspace = case.root.parent / 'separate-workspace'
    legacy = workspace / 'work'
    selected = case.root.parent / 'hosted-state' / 'handoffs'
    legacy.mkdir(parents=True)
    selected.mkdir(parents=True)
    copied = selected / 'project-harvest-1'
    old_copy = legacy / 'project-harvest-1'
    shutil.copytree(original, copied)
    shutil.copytree(original, old_copy)
    protect([selected, copied, *copied.iterdir(), old_copy, *old_copy.iterdir()])
    monkeypatch.setattr(project, 'ROOT', workspace)
    def handoff_root(*, legacy_root=None):
        assert legacy_root == legacy
        return selected
    monkeypatch.setattr(project.transport, 'handoff_root', handoff_root)
    result = project.payload('check', copied, **options)
    assert result['receipts'] == expected['receipts']
    with pytest.raises(ValueError, match='EXACT_PRIVATE_PROJECT_COLLECTION_REQUIRED'):
        project.payload('check', old_copy, **options)


def reject_extra_reader(cli, collection, monkeypatch):
    directory, options, _, _ = checked(cli, collection, monkeypatch)
    path = directory / 'qa-result.json'
    if os.name == 'nt':
        script = r'''$ErrorActionPreference='Stop'
$p=([Console]::In.ReadToEnd()|ConvertFrom-Json).path
$acl=[IO.File]::GetAccessControl($p)
$sid=New-Object Security.Principal.SecurityIdentifier('S-1-1-0')
$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'Read','Allow')
$acl.AddAccessRule($rule); [IO.File]::SetAccessControl($p,$acl)
Write-Output 'SYNTHETIC_EXTRA_READER_ADDED'
'''
        result = subprocess.run(['powershell', '-NoProfile', '-Command', script],
            input=json.dumps({'path': str(path)}).encode(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30)
        assert result.returncode == 0 and result.stdout.strip() == b'SYNTHETIC_EXTRA_READER_ADDED'
    else:
        path.chmod(0o644)
    monkeypatch.setattr(cli.transport, 'execute_host', lambda *args, **kwargs: pytest.fail('No unsafe transport'))
    with pytest.raises((ValueError, RuntimeError)):
        cli.dispatch('check', directory, **options)


def test_native_real_acl_rejects_extra_reader_before_provider(native_collection, monkeypatch):
    reject_extra_reader(native, native_collection, monkeypatch)


def test_project_real_acl_rejects_extra_reader_before_provider(project_collection, monkeypatch):
    reject_extra_reader(project, project_collection, monkeypatch)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX mode rejection requires a POSIX filesystem')
def test_native_collection_permissions_are_not_bypassed_by_provider(native_collection, monkeypatch):
    directory, options, _, _ = checked(native, native_collection, monkeypatch)
    (directory / 'qa-result.json').chmod(0o644)
    monkeypatch.setattr(native.transport, 'execute_host', lambda *args, **kwargs: pytest.fail('No unsafe transport'))
    with pytest.raises(ValueError, match='PRIVATE_COLLECTION_PERMISSIONS_REQUIRED'):
        native.dispatch('check', directory, **options)
