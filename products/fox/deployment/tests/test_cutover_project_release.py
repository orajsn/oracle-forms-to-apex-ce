"""Leased-cutover guards only; no live JSN operations.

Service observations below are synthetic IO. Backup tests use the actual
private-copy/archive/receipt validators in an actual rootless user namespace.
An internal backup-method fixture does not represent cutover/admission authority.
"""
from copy import deepcopy
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import ast
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import py_compile
import selectors
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
for directory in (ROOT, ROOT / 'fox', ROOT / 'converter'):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
SPEC = importlib.util.spec_from_file_location('leased_cutover_tests', ROOT / 'deployment/cutover_project_release.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)


def packet():
    return {'schema_version': 1, 'scope': M.SCOPE, 'phase': 'stop', 'plan': {}, 'plan_sha256': 'a' * 64,
        'installation': {}, 'snapshot_configuration': '', 'snapshot_configuration_sha256': 'b' * 64,
        'backup_operation': None, 'backup_completion_sha256': None,
        'restore_operation': None, 'restore_completion_sha256': None,
        'helper_sha256': M.sha(Path(M.__file__).read_bytes())}


@pytest.mark.parametrize('mutation', ['fields', 'bool', 'scope', 'phase', 'helper'])
def test_invalid_host_packet_stops_before_candidate_import(monkeypatch, mutation):
    value = packet()
    if mutation == 'fields': value['caller_approved'] = True
    if mutation == 'bool': value['schema_version'] = True
    if mutation == 'scope': value['scope'] = 'unknown'
    if mutation == 'phase': value['phase'] = 'delete'
    if mutation == 'helper': value['helper_sha256'] = '0' * 64
    monkeypatch.setattr(M, '_candidate_module', lambda *_: pytest.fail('must not import candidate or observe host'))
    with pytest.raises(M.CutoverError): M.HostCutover(value)


@pytest.mark.parametrize('context', [None, True, {'held': True}, SimpleNamespace(require_active=lambda: True)])
@pytest.mark.parametrize('phase', ['stop', 'activate', 'release', 'recover'])
def test_declared_held_context_is_not_real_windows_authority(monkeypatch, context, phase):
    monkeypatch.setattr(M.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('transport forbidden'))
    raw = M.canonical({})
    with pytest.raises(M.CutoverError, match='REAL_PREACTIVATION_CONTEXT_REQUIRED'):
        M.execute_under_lock(context, None, plan_raw=raw, plan_sha256=M.sha(raw),
            installation_reference={}, phase=phase, expected_source_sha256=M.sha(Path(M.__file__).read_bytes()), apply=True)


def test_subclass_cannot_replace_exact_windows_context(monkeypatch):
    from qa.operator.preactivation_retirement import PreActivationRetirementContext
    class FakeContext(PreActivationRetirementContext):
        def require_active(self): pytest.fail('fake authority must not run')
    fake = object.__new__(FakeContext)
    raw = M.canonical({})
    with pytest.raises(M.CutoverError, match='REAL_PREACTIVATION_CONTEXT_REQUIRED'):
        M.execute_under_lock(fake, None, plan_raw=raw, plan_sha256=M.sha(raw), installation_reference={},
            phase='activate', expected_source_sha256=M.sha(Path(M.__file__).read_bytes()), apply=True)


@pytest.mark.parametrize('capture', [None, True, SimpleNamespace(owner=None)])
def test_exact_class_without_real_snapshot_authority_still_stops(capture, monkeypatch):
    from qa.operator.preactivation_retirement import PreActivationRetirementContext
    context = object.__new__(PreActivationRetirementContext)  # Uninitialized, negative case only.
    raw = M.canonical({})
    monkeypatch.setattr(M.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('transport forbidden'))
    with pytest.raises(M.CutoverError, match='REAL_SNAPSHOT_AUTHORITY_REQUIRED'):
        M.execute_under_lock(context, capture, plan_raw=raw, plan_sha256=M.sha(raw), installation_reference={},
            phase='stop', expected_source_sha256=M.sha(Path(M.__file__).read_bytes()), apply=True)


@pytest.mark.parametrize('path', ['/home/opc/private/installation.json', '/home/opc/private folder/installation.json'])
def test_remote_helper_remains_posix_when_called_from_windows(path):
    assert M.remote_helper_path(path) == path.rsplit('/', 1)[0] + '/cutover_project_release.py'
    assert '\\' not in M.remote_helper_path(path)


@pytest.mark.parametrize('path', ['', 'relative/file.json', 'C:/private/file.json', '/home/opc/../file.json',
                               '/home\\opc/file.json', '/home/opc\n/file.json', None])
def test_remote_helper_rejects_noncanonical_or_wrong_platform_path(path):
    with pytest.raises(M.CutoverError, match='REMOTE_INSTALLATION_PATH_INVALID'):
        M.remote_helper_path(path)


@pytest.mark.parametrize('stamp', ['2026-10-27T00:00:00', '2026-10-27T07:00:00+07:00', None, True, '2026-10-27'])
def test_receipt_time_requires_explicit_utc(stamp):
    with pytest.raises(M.CutoverError, match='EXACT_UTC_TIMESTAMP_REQUIRED'): M.utc(stamp)


def test_direct_script_cannot_expose_service_actions():
    outcome = subprocess.run([sys.executable, '-I', '-B', str(Path(M.__file__)), '--apply'],
                             capture_output=True, text=True, timeout=10)
    assert outcome.returncode != 0 and not outcome.stdout
    assert 'no direct service-action CLI' in outcome.stderr


def test_candidate_executes_measured_source_not_matching_timestamp_bytecode(tmp_path, monkeypatch):
    source = tmp_path / 'activate_project_release.py'
    cached, reviewed = b'VALUE = "cached"\n', b'VALUE = "source"\n'
    assert len(cached) == len(reviewed)
    source.write_bytes(cached)
    saved = source.stat()
    # Deliberately create a stale, otherwise loader-valid cache in this isolated
    # test directory. No real deployment or repository cache is modified.
    py_compile.compile(str(source), doraise=True)
    source.write_bytes(reviewed)
    os.utime(source, ns=(saved.st_atime_ns, saved.st_mtime_ns))
    monkeypatch.setattr(M, '__file__', str(tmp_path / 'cutover_project_release.py'))
    previous = sys.modules.get('_reviewed_paired_candidate')
    try:
        loaded = M._candidate_module({'helper_sha256': M.sha(reviewed)})
        assert loaded.VALUE == 'source'
    finally:
        if previous is None:
            sys.modules.pop('_reviewed_paired_candidate', None)
        else:
            sys.modules['_reviewed_paired_candidate'] = previous


@pytest.mark.parametrize('mutation', ['none', 'fox_id', 'converter_image', 'report_release', 'admission_release',
                                    'admission_hash', 'missing_role', 'extra_record_field'])
def test_created_candidates_must_match_independently_pinned_destination(mutation):
    release = 'a' * 64
    admission = {'schema_version': 1, 'scope': 'fox-hosted-admission-v1',
        'provider_configuration_sha256': 'b' * 64, 'current_release_sha256': release,
        'infrastructure': {'fox': {'id': '1' * 64, 'image': 'sha256:' + 'c' * 64},
            'forms2apex-mcp': {'id': '2' * 64, 'image': 'sha256:' + 'd' * 64},
            'oracle-applied-ai-label': {'id': '3' * 64, 'image': 'sha256:' + 'e' * 64}}}
    created = {'release_sha256': release, 'admission_sha256': M.sha(M.canonical(admission)),
        'candidates': {'fox': {**admission['infrastructure']['fox'], 'name': 'fox-project-' + release[:16]},
            'converter': {**admission['infrastructure']['forms2apex-mcp'], 'name': 'forms2apex-project-' + release[:16]}}}
    if mutation == 'fox_id': created['candidates']['fox']['id'] = '4' * 64
    elif mutation == 'converter_image': created['candidates']['converter']['image'] = 'sha256:' + '5' * 64
    elif mutation == 'report_release': created['release_sha256'] = '6' * 64
    elif mutation == 'admission_release':
        admission['current_release_sha256'] = '7' * 64
        created['admission_sha256'] = M.sha(M.canonical(admission))
    elif mutation == 'admission_hash': created['admission_sha256'] = '8' * 64
    elif mutation == 'missing_role': del created['candidates']['converter']
    elif mutation == 'extra_record_field': created['candidates']['fox']['adopted'] = True
    if mutation == 'none':
        assert M.validate_created_destination(created, M.canonical(admission), release) == admission
    else:
        with pytest.raises(M.CutoverError):
            M.validate_created_destination(created, M.canonical(admission), release)


from deployment.tests import test_activate_project_release as candidate_tests


def snapshot_boundary_fixture():
    a = candidate_tests.M
    old = {'fox': candidate_tests.baseline_item('fox'),
           'forms2apex-mcp': candidate_tests.baseline_item('converter')}
    config = {'role_paths': {'fox-data': '/home/opc/fox/data',
                           'converter-jobs': '/home/opc/forms2apex/outputs/jobs'},
        'protected_sources': {name: {'path': path} for name, path in {
            'opaf-client': '/home/opc/fox/secure/opaf-client',
            'baseline-fox-profile': a.BASE_PROFILES['fox'],
            'baseline-target-profile': a.BASE_PROFILES['converter'],
            'sqlcl-connections': '/home/opc/forms2apex/sqlcl-user',
            'wallet': '/home/opc/opaf-secure/JSNF2APEX_wallet_single',
            'fox-unit': a.UNITS['fox.service'][0],
            'converter-unit': a.UNITS['forms2apex-mcp.service'][0],
            'tls-unit': a.UNITS['fox-https.service'][0],
        }.items()}}
    return a, config, old


def test_snapshot_references_match_actual_saved_g_mounts_without_io(monkeypatch):
    a, config, old = snapshot_boundary_fixture()
    before = deepcopy((config, old))
    monkeypatch.setattr(a, 'command', lambda *_args, **_kwargs: pytest.fail('pure binding must not contact host'))
    M.validate_snapshot_bindings(a, config, old)
    assert (config, old) == before


@pytest.mark.parametrize('group,key', [
    ('role_paths', 'fox-data'), ('role_paths', 'converter-jobs'),
    *[('protected_sources', name) for name in ('opaf-client', 'baseline-fox-profile', 'baseline-target-profile',
        'sqlcl-connections', 'wallet', 'fox-unit', 'converter-unit', 'tls-unit')],
])
def test_snapshot_wrong_source_or_unit_is_rejected_before_stopping_services(group, key):
    a, config, old = snapshot_boundary_fixture()
    if group == 'role_paths': config[group][key] = '/unrelated/different'
    else: config[group][key]['path'] = '/unrelated/different'
    with pytest.raises(M.CutoverError): M.validate_snapshot_bindings(a, config, old)


def never_started_candidate():
    return {'Id': '1' * 64, 'Name': '/fox-project-synthetic', 'Image': 'sha256:' + '2' * 64,
        'Created': (datetime.now(timezone.utc) - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%S') + '.123456789Z',
        'State': {'Status': 'created', 'Running': False, 'Pid': 0, 'ExitCode': 0,
                  'StartedAt': '0001-01-01T00:00:00Z', 'FinishedAt': '0001-01-01T00:00:00Z'}}


def test_actual_classifier_recognizes_only_created_never_started():
    candidate = never_started_candidate(); before = deepcopy(candidate)
    M.require_never_started(candidate)
    assert candidate == before


@pytest.mark.parametrize('change', ['started', 'finished', 'running', 'pid', 'exit_code', 'configured',
                                  'initialized', 'exited', 'future', 'missing', 'boolean_pid'])
def test_candidate_cannot_be_treated_as_never_started_from_status_alone(change):
    candidate = never_started_candidate()
    now = datetime.now(timezone.utc).isoformat()
    if change == 'started': candidate['State']['StartedAt'] = now
    elif change == 'finished': candidate['State']['FinishedAt'] = now
    elif change == 'running': candidate['State']['Running'] = True
    elif change == 'pid': candidate['State']['Pid'] = 2
    elif change == 'exit_code': candidate['State']['ExitCode'] = 1
    elif change in ('configured', 'initialized'): candidate['State']['Status'] = change
    elif change == 'exited': candidate['State'].update(Status='exited', StartedAt=now, FinishedAt=now)
    elif change == 'future': candidate['Created'] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    elif change == 'missing': del candidate['State']['StartedAt']
    elif change == 'boolean_pid': candidate['State']['Pid'] = False
    with pytest.raises(Exception): M.require_never_started(candidate)


G_MANIFEST = ROOT / 'work/product-history-transport-bind-20261019a/operator-release/current-release-manifest.json'


@pytest.mark.skipif(not G_MANIFEST.is_file(), reason='requires retained exact G lab manifest, not invented history')
@pytest.mark.parametrize('change', ['none', 'g_manifest', 'fox_profile', 'converter_profile'])
def test_original_profile_checks_bind_actual_retained_bytes(monkeypatch, change):
    a = candidate_tests.M
    original = G_MANIFEST.read_bytes()
    assert M.sha(original) == a.G_RELEASE
    manifest = json.loads(original)
    fox = (ROOT / 'deployment/native-beta-profile.json').read_bytes()
    converter = (ROOT / 'deployment/target-profile.jsn.json').read_bytes()
    assert M.sha(fox) == manifest['native_profile_sha256']
    files = {'/synthetic/archive/manifests/idle.json': original,
        a.BASE_PROFILES['fox']: fox, a.BASE_PROFILES['converter']: converter,
        '/synthetic/bundle/deployment/target-profile.jsn.json': converter}
    if change == 'g_manifest': files['/synthetic/archive/manifests/idle.json'] += b'\n'
    elif change == 'fox_profile': files[a.BASE_PROFILES['fox']] += b'\n'
    elif change == 'converter_profile':
        value = json.loads(converter); value['oci']['region'] = 'unrelated-region'
        files[a.BASE_PROFILES['converter']] = M.canonical(value)
    reads = []
    def read(path, **kwargs):
        key = Path(path).as_posix(); reads.append(key); return files[key]
    monkeypatch.setattr(a, 'read', read)  # Only filesystem IO is substituted.
    monkeypatch.setattr(a, 'command', lambda *_args, **_kwargs: pytest.fail('profile checks must not contact host'))
    cutover = object.__new__(M.HostCutover)  # Internal pure/content check, not authority.
    cutover.A = a
    cutover.admission = SimpleNamespace(archive=SimpleNamespace(root=Path('/synthetic/archive')))
    cutover.plan = {'bundle_root': '/synthetic/bundle'}
    if change == 'none':
        cutover.old_profile_sources()
        assert set(reads) == set(files)
    else:
        with pytest.raises(M.CutoverError): cutover.old_profile_sources()


def execute_local_recovery_scan(jobs):
    """Run the actual scan with only its fixed IO root mapped to a fixture."""
    tree = ast.parse(M.LIVE_ROLLBACK_SCAN)
    roots = [node for node in ast.walk(tree) if isinstance(node, ast.Constant)
             and node.value == '/home/opc/fox/data/jobs']
    assert len(roots) == 1
    roots[0].value = str(jobs)
    output = io.StringIO()
    with redirect_stdout(output):
        exec(compile(tree, '<actual-recovery-scan-with-test-io-root>', 'exec'), {'__name__': 'local_scan_test'})
    return json.loads(output.getvalue())


@pytest.mark.skipif(os.name != 'posix', reason='production fixed scan requires POSIX O_NOFOLLOW')
@pytest.mark.parametrize('profile', ['native-table-form-v1', 'legacy-html-prototype-v1'])
def test_recovery_scan_allows_explicit_supported_legacy_without_modifying_bytes(tmp_path, profile):
    jobs = tmp_path / 'jobs'; job = jobs / 'fox-synthetic'; job.mkdir(parents=True)
    source = job / 'source-snapshot.json'
    original = b'\xef\xbb\xbf' + json.dumps({'conversion_profile': profile}, indent=2).encode() + b'\r\n'
    source.write_bytes(original)
    before = {p.relative_to(jobs).as_posix(): p.read_bytes() for p in jobs.rglob('*') if p.is_file()}
    result = execute_local_recovery_scan(jobs)
    assert result['project_history_present'] is False and result['read_only'] is True
    assert result['jobs_checked'] == 1 and len(result['source_state_sha256']) == 64
    assert before == {p.relative_to(jobs).as_posix(): p.read_bytes() for p in jobs.rglob('*') if p.is_file()}


@pytest.mark.skipif(os.name != 'posix', reason='production fixed scan requires POSIX O_NOFOLLOW')
@pytest.mark.parametrize('source,marker', [
    (b'{"conversion_profile":"native-project-v1"}', None),
    (b'{"conversion_profile":"native-table-form-v1","native_project":null}', None),
    (b'{"conversion_profile":"legacy-html-prototype-v1","native_project":{}}', None),
    (b'{"conversion_profile":"native-project-v1","conversion_profile":"native-table-form-v1"}', None),
    (b'{}', None), (b'{"conversion_profile":null}', None), (b'{"conversion_profile":"unknown"}', None),
    (b'[]', None), (b'{broken', None),
    (b'{"conversion_profile":"native-table-form-v1"}', 'native-project-pipeline'),
    (b'{"conversion_profile":"native-table-form-v1"}', 'project-technical-verification'),
])
def test_recovery_scan_refuses_project_ambiguous_or_unknown_history(tmp_path, source, marker):
    jobs = tmp_path / 'jobs'; job = jobs / 'fox-synthetic'; job.mkdir(parents=True)
    path = job / 'source-snapshot.json'; path.write_bytes(source)
    if marker: (job / marker).mkdir()
    with pytest.raises(Exception): execute_local_recovery_scan(jobs)
    assert path.read_bytes() == source


@pytest.mark.skipif(os.name != 'posix', reason='requires actual local symlink creation')
@pytest.mark.parametrize('link', ['job', 'source', 'broken-marker'])
def test_recovery_scan_does_not_follow_links(tmp_path, link):
    jobs = tmp_path / 'jobs'; jobs.mkdir()
    target = tmp_path / 'target'; target.mkdir()
    raw = b'{"conversion_profile":"native-table-form-v1"}'
    (target / 'source-snapshot.json').write_bytes(raw)
    if link == 'job': (jobs / 'fox-synthetic').symlink_to(target, target_is_directory=True)
    else:
        job = jobs / 'fox-synthetic'; job.mkdir()
        if link == 'source': (job / 'source-snapshot.json').symlink_to(target / 'source-snapshot.json')
        else:
            (job / 'source-snapshot.json').write_bytes(raw)
            (job / 'native-project-pipeline').symlink_to(tmp_path / 'absent')
    with pytest.raises(Exception): execute_local_recovery_scan(jobs)


@pytest.mark.skipif(os.name != 'posix', reason='production fixed scan requires POSIX O_NOFOLLOW')
def test_recovery_scan_rejects_membership_change_between_reads(tmp_path, monkeypatch):
    jobs = tmp_path / 'jobs'; job = jobs / 'fox-synthetic'; job.mkdir(parents=True)
    raw = b'{"conversion_profile":"native-table-form-v1"}'
    (job / 'source-snapshot.json').write_bytes(raw)
    original = Path.iterdir
    calls = []
    def concurrent_writer(path):
        if path == jobs:
            calls.append(1)
            if len(calls) == 2:
                added = jobs / 'fox-concurrent'; added.mkdir()
                (added / 'source-snapshot.json').write_bytes(raw)
        return original(path)
    monkeypatch.setattr(Path, 'iterdir', concurrent_writer)  # A separate filesystem writer is simulated.
    with pytest.raises(RuntimeError, match='LIVE_SOURCE_NOT_SAFE_FOR_G_RECOVERY'):
        execute_local_recovery_scan(jobs)
    assert len(calls) == 2


@pytest.mark.parametrize('change', ['none', 'project', 'not_readonly', 'boolean_count', 'bad_hash', 'extra'])
def test_recovery_observation_requires_exact_namespace_result(change):
    value = {'project_history_present': False, 'jobs_checked': 1,
             'source_state_sha256': 'a' * 64, 'read_only': True}
    if change == 'project': value['project_history_present'] = True
    elif change == 'not_readonly': value['read_only'] = False
    elif change == 'boolean_count': value['jobs_checked'] = True
    elif change == 'bad_hash': value['source_state_sha256'] = 'invalid'
    elif change == 'extra': value['override'] = True
    calls = []
    def observed(argv, **kwargs):
        calls.append((argv, kwargs)); return M.canonical(value)
    cutover = object.__new__(M.HostCutover)  # Observation/parser method only, not recovery authority.
    cutover.A = SimpleNamespace(command=observed, parse=json.loads)
    cutover.provider = {'python': {'path': '/reviewed/private/python3.11'}}
    if change == 'none': assert cutover.live_rollback_guard() == value
    else:
        with pytest.raises(M.CutoverError, match='ACTUAL_SOURCE_COMPATIBILITY_UNCONFIRMED'):
            cutover.live_rollback_guard()
    assert calls == [(['/usr/bin/podman', 'unshare', '/reviewed/private/python3.11', '-I', '-B', '-c', M.LIVE_ROLLBACK_SCAN],
                      {'timeout': 120, 'maximum': 65536})]


@pytest.mark.parametrize('phase,apply', [('stop', False), ('activate', None), ('delete', True), ('release', False)])
def test_no_implicit_or_unknown_phase_dispatch(monkeypatch, phase, apply):
    monkeypatch.setattr(M.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('transport forbidden'))
    raw = M.canonical({})
    with pytest.raises(M.CutoverError, match='EXPLICIT_REVIEWED_PHASE_REQUIRED'):
        M.execute_under_lock(None, None, plan_raw=raw, plan_sha256=M.sha(raw), installation_reference={},
            phase=phase, expected_source_sha256=M.sha(Path(M.__file__).read_bytes()), apply=apply)


def test_service_observation_is_read_only_and_root_namespace_explicit():
    calls = []
    response = b'LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nFragmentPath=/exact/unit\n'
    def command(argv): calls.append(argv); return response
    adapter = SimpleNamespace(command=command)
    assert M.service_state(adapter, 'fox.service')['MainPID'] == '0'
    assert M.service_state(adapter, 'fox-https.service', rootful=True)['ActiveState'] == 'inactive'
    assert calls == [
        ['/usr/bin/systemctl', '--user', 'show', 'fox.service', '--property=LoadState,ActiveState,SubState,MainPID,FragmentPath'],
        ['sudo', '-n', '/usr/bin/systemctl', 'show', 'fox-https.service', '--property=LoadState,ActiveState,SubState,MainPID,FragmentPath']]
    assert not {'start', 'stop', 'restart'} & set(sum(calls, []))


@pytest.mark.parametrize('extra', [b'MainPID=9\n', b'Unknown=true\n'])
def test_duplicate_or_extra_service_fields_are_not_trusted(extra):
    response = b'LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nFragmentPath=/exact/unit\n' + extra
    adapter = SimpleNamespace(command=lambda *_: response)
    with pytest.raises(M.CutoverError): M.service_state(adapter, 'fox.service')


def test_tls_inspection_uses_rootful_podman_and_never_actions():
    calls = []
    value = {'Name': '/fox-https', 'HostConfig': {'AutoRemove': False}}
    adapter = SimpleNamespace(parse=json.loads, command=lambda argv: (calls.append(argv), M.canonical([value]))[1])
    assert M.tls_container(adapter) == value
    assert calls == [['sudo', '-n', '/usr/bin/podman', 'inspect', 'fox-https']]
    value['HostConfig']['AutoRemove'] = True
    with pytest.raises(M.CutoverError, match='EXACT_RETAINED_TLS_REQUIRED'): M.tls_container(adapter)


def test_renames_and_start_state_do_not_change_configuration_signature():
    value = {'Id': 'a' * 64, 'Image': 'b' * 64, 'Name': '/candidate',
        'Config': {'User': '1000:1000'}, 'HostConfig': {'Privileged': False},
        'Mounts': [{'Source': '/data'}], 'ProcessLabel': 'original', 'MountLabel': 'original',
        'State': {'Running': False, 'Pid': 0}, 'NetworkSettings': {'dynamic': ''}}
    changed = deepcopy(value)
    changed.update(Name='/fox', State={'Running': True, 'Pid': 1234}, NetworkSettings={'dynamic': 'assigned'})
    assert M.configuration_signature(None, value) == M.configuration_signature(None, changed)
    for key in ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'ProcessLabel', 'MountLabel'):
        changed = deepcopy(value); changed[key] = 'changed'
        assert M.configuration_signature(None, value) != M.configuration_signature(None, changed)


from qa.operator.tests import test_hosted_snapshot as snapshot_tests


@pytest.fixture
def real_backup():
    if not snapshot_tests.rootless_namespace():
        pytest.skip('requires actual UID0 mapped only from UID1000 rootless namespace')
    case = snapshot_tests.NamespaceAssemblyTests(methodName='runTest')
    case.setUp()
    try:
        case.config = snapshot_tests.config(mode='pre-hosted-g', base=str(case.root))
        case.packet = dict(snapshot_tests.packet(case.config, operation=case.stage.name), stage=str(case.stage))
        receipt = case.completed_capture()
        now = datetime.now(timezone.utc)
        receipt['completed_at_utc'] = now.isoformat()
        for name, offset in (('before.json', 4), ('after.json', 1)):
            path = case.stage / name
            observed = json.loads(path.read_bytes())
            observed['observed_at_utc'] = (now - timedelta(seconds=offset)).isoformat()
            path.write_bytes(M.canonical(observed))
            receipt['writer_observations_sha256'][name] = M.sha(path.read_bytes())
        (case.stage / 'completion.json').write_bytes(M.canonical(receipt))
        from qa.operator import hosted_snapshot as h, snapshot as s
        case.restore_stage = case.stage.parent / 'restore-one'; case.restore_stage.mkdir(mode=0o700)
        restore_packet = dict(snapshot_tests.packet(case.config, action='restore', operation=case.restore_stage.name),
            stage=str(case.restore_stage), backup=str(case.stage / 'snapshot'),
            backup_completion_sha256=M.sha(M.canonical(receipt)))
        restored = h._worker(restore_packet, s)
        case.restore_receipt = case.completion(case.restore_stage, 'restore', restored,
            backup=case.stage / 'snapshot', backup_sha=M.sha(M.canonical(receipt)))
        case.restore_receipt['completed_at_utc'] = datetime.now(timezone.utc).isoformat()
        (case.restore_stage / 'completion.json').write_bytes(M.canonical(case.restore_receipt))
        cutover = object.__new__(M.HostCutover)  # Internal receipt validator fixture, not authority.
        cutover.A = SimpleNamespace(parse=h.parse, read=lambda path, **_: s._read(path))
        cutover.snapshot, cutover.snapshot_engine = h, s
        cutover.snapshot_config = case.config
        cutover.R = 'e' * 64
        cutover.stage = case.root / 'cutover'; cutover.stage.mkdir(mode=0o700)
        cutover.p = {'backup_operation': case.stage.name,
            'backup_completion_sha256': M.sha(M.canonical(receipt)),
            'restore_operation': case.restore_stage.name,
            'restore_completion_sha256': M.sha(M.canonical(case.restore_receipt)),
            'installation': {'sha256': 'd' * 64},
            'snapshot_configuration_sha256': M.sha(M.canonical(case.config))}
        stopped = {'status': 'G_STOPPED_TLS_HELD', 'release_sha256': cutover.R,
            'installation_sha256': cutover.p['installation']['sha256'],
            'snapshot_configuration_sha256': cutover.p['snapshot_configuration_sha256'],
            'stopped_at_utc': (now - timedelta(seconds=5)).isoformat()}
        (cutover.stage / 'cutover-stopped.json').write_bytes(M.canonical(stopped))
        yield case, cutover, receipt, stopped
    finally:
        case.doCleanups()


def test_cutover_accepts_exact_actual_snapshot_receipt(real_backup):
    case, cutover, receipt, stopped = real_backup
    assert cutover._backup() == receipt


@pytest.mark.parametrize('change', ['wrong_hash', 'old_stop', 'wrong_installation', 'wrong_configuration',
                                  'future_completion', 'before_stop', 'tampered_archive', 'unsafe_operation'])
def test_cutover_rejects_unbound_stale_or_changed_backup(real_backup, change):
    case, cutover, receipt, stopped = real_backup
    if change == 'wrong_hash': cutover.p['backup_completion_sha256'] = '0' * 64
    elif change == 'old_stop':
        stopped['stopped_at_utc'] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        (cutover.stage / 'cutover-stopped.json').write_bytes(M.canonical(stopped))
    elif change == 'wrong_installation': cutover.p['installation']['sha256'] = '0' * 64
    elif change == 'wrong_configuration': cutover.p['snapshot_configuration_sha256'] = '0' * 64
    elif change == 'future_completion':
        receipt['completed_at_utc'] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        raw = M.canonical(receipt); (case.stage / 'completion.json').write_bytes(raw)
        cutover.p['backup_completion_sha256'] = M.sha(raw)
    elif change == 'before_stop':
        path = case.stage / 'before.json'; observed = json.loads(path.read_bytes())
        observed['observed_at_utc'] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        path.write_bytes(M.canonical(observed)); receipt['writer_observations_sha256']['before.json'] = M.sha(path.read_bytes())
        raw = M.canonical(receipt); (case.stage / 'completion.json').write_bytes(raw)
        cutover.p['backup_completion_sha256'] = M.sha(raw)
    elif change == 'tampered_archive':
        path = case.stage / 'snapshot/roles.tar'; path.write_bytes(path.read_bytes() + b'changed')
    elif change == 'unsafe_operation': cutover.p['backup_operation'] = '../other'
    with pytest.raises(Exception): cutover._backup()


@pytest.mark.parametrize('change', ['missing', 'same_capture', 'hash', 'capture_link', 'future', 'predates', 'restored_bytes'])
def test_isolated_restore_must_match_the_exact_capture(real_backup, change):
    case, cutover, receipt, stopped = real_backup
    if change == 'missing': cutover.p['restore_operation'] = None
    elif change == 'same_capture': cutover.p['restore_operation'] = case.stage.name
    elif change == 'hash': cutover.p['restore_completion_sha256'] = '0' * 64
    elif change == 'capture_link':
        path = case.restore_stage / 'intent.json'; value = json.loads(path.read_bytes())
        value['backup_completion_sha256'] = '0' * 64; path.write_bytes(M.canonical(value))
    elif change in ('future', 'predates'):
        case.restore_receipt['completed_at_utc'] = (datetime.now(timezone.utc) +
            timedelta(days=1 if change == 'future' else -1)).isoformat()
        raw = M.canonical(case.restore_receipt); (case.restore_stage / 'completion.json').write_bytes(raw)
        cutover.p['restore_completion_sha256'] = M.sha(raw)
    elif change == 'restored_bytes':
        files = [p for p in (case.restore_stage / 'restored-copy').rglob('*') if p.is_file()]
        assert files; files[0].write_bytes(files[0].read_bytes() + b'tampered')
    with pytest.raises(Exception): cutover._backup()


def test_ordered_unit_uses_actual_service_template_without_changing_runtime_settings():
    from qa.operator import hosted_service
    admission = SimpleNamespace(provider=SimpleNamespace(configuration={'python': {'path': '/private/venv/bin/python3.11'}}),
        source_root=PurePosixPath('/private/release-B'), sha256='a' * 64)
    path = PurePosixPath('/private/config/installation.json')
    original = hosted_service.service_unit(admission, path)
    ordered = M.ordered_service_unit(hosted_service, admission, path)
    inserted = b'After=fox.service forms2apex-mcp.service\nRequires=fox.service forms2apex-mcp.service\n'
    assert ordered.count(inserted) == 1 and ordered.replace(inserted, b'') == original
    assert b'Restart=no\n' in ordered and b'UMask=0077\n' in ordered
    assert b'"-I" "-B"' in ordered and b'"--installation-sha256" "' + b'a' * 64 + b'"' in ordered


def test_unknown_service_template_cannot_be_silently_rewritten():
    service = SimpleNamespace(service_unit=lambda *_: b'[Unit]\nDescription=unreviewed\n')
    with pytest.raises(M.CutoverError, match='REVIEWED_UNIT_TEMPLATE_CHANGED'):
        M.ordered_service_unit(service, None, None)


@pytest.mark.skipif(os.name != 'posix', reason='requires actual Linux process metadata')
def test_actual_process_identity_is_bound_to_exact_executable_and_arguments():
    executable = str(Path(sys.executable).resolve())
    argv = [executable, '-I', '-B', '-c', 'import sys;sys.stdin.buffer.read(1)']
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        value = M.runtime_identity(child.pid, executable, argv)
        assert value['pid'] == child.pid and value['start_ticks'] > 0 and len(value['boot_id']) == 36
        assert M.runtime_identity(child.pid, executable, argv) == value
        for wrong_python, wrong_args in (('/different/python', argv), (executable, argv + ['unexpected'])):
            with pytest.raises(M.CutoverError, match='OPERATOR_PROCESS_COMMAND_CHANGED'):
                M.runtime_identity(child.pid, wrong_python, wrong_args)
    finally:
        child.communicate(b'x', timeout=10)
    assert child.returncode == 0
    with pytest.raises((OSError, M.CutoverError)): M.runtime_identity(child.pid, executable, argv)


@pytest.mark.skipif(os.name != 'posix', reason='requires actual Linux process metadata')
def test_process_replacement_during_identity_read_is_rejected(monkeypatch):
    executable = str(Path(sys.executable).resolve())
    argv = [executable, '-I', '-B', '-c', 'import sys;sys.stdin.buffer.read(1)']
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    target = Path('/proc') / str(child.pid) / 'stat'
    original, reads = Path.read_text, []
    def changed(path, *args, **kwargs):
        raw = original(path, *args, **kwargs)
        if path == target:
            reads.append(1)
            if len(reads) == 2:
                boundary = raw.rfind(') ') + 2; fields = raw[boundary:].split()
                fields[19] = str(int(fields[19]) + 1)
                return raw[:boundary] + ' '.join(fields)
        return raw
    monkeypatch.setattr(Path, 'read_text', changed)  # Only the second process observation is substituted.
    try:
        with pytest.raises(M.CutoverError, match='OPERATOR_PROCESS_IDENTITY_CHANGED'):
            M.runtime_identity(child.pid, executable, argv)
    finally:
        child.communicate(b'x', timeout=10)


JOURNAL_CHILD = r'''
import json,pathlib,sys
config_path=pathlib.Path(sys.argv[sys.argv.index('--installation')+1])
cfg=json.loads(config_path.read_bytes());repo=pathlib.Path(cfg['repository'])
sys.path[:0]=[str(repo),str(repo/'fox'),str(repo/'converter')]
sys.path.append(str(repo/'fox/.venv/Lib/site-packages'))
from qa.operator import product_verifier as product,clean_install as clean
clean.PRIVATE=pathlib.Path(cfg['private']);product.JOURNAL_ROOT=clean.PRIVATE/'product-verifier'
names=iter(['0'*24,'f'*24]);product.secrets.token_hex=lambda count:next(names)
journal=product.PrivateJournal(cfg['release'])
with journal.lock():
 directory=journal.new(cfg['bounds'])
 if cfg['mode']!='no-claim':
  intent=journal.intent(directory,'p0001-claim')
  if cfg['mode']=='malformed':journal.write(directory,'p0001-claim.complete.json',{})
  else:journal.completed(directory,'p0001-claim','9'*64 if cfg['mode']=='wrong-intent' else intent,{'status':'IDLE'})
 if cfg['mode'] in ('attention-late','unknown-late'):
  journal.seal(directory,'complete.json',{'status':'SESSION_COMPLETE','release_sha256':cfg['release'],
   'completed_jobs':[],'automatic_replay_permitted':False})
  if cfg['mode']=='attention-late':
   second=journal.new(cfg['bounds']);journal.write(second,'attention.json',{'status':'ATTENTION'})
  else:(journal.root/'zzz-unexpected').write_bytes(b'unexpected metadata')
 print(json.dumps({'ready':True,'session':directory.name}),flush=True)
 sys.stdin.buffer.read(1)
'''


@pytest.fixture
def idle_process(request, monkeypatch):
    if os.name != 'posix' or os.geteuid() == 0:
        pytest.skip('requires ordinary unprivileged POSIX process and home-private input checks')
    mode = getattr(request, 'param', 'valid')
    executable = str(Path(sys.executable).resolve())
    with tempfile.TemporaryDirectory(prefix='.fox-idle-witness-', dir=Path.home()) as temporary:
        root = Path(temporary); bundle = root / 'bundle'
        script = bundle / 'qa/operator/hosted_service.py'; script.parent.mkdir(parents=True, mode=0o700)
        script.write_text(JOURNAL_CHILD)
        private = root / 'private'; private.mkdir(mode=0o700)
        bounds = {'max_jobs': 1, 'max_polls': 1, 'max_seconds': 60, 'poll_seconds': 1}
        release = 'a' * 64
        config = root / 'installation.json'
        config.write_bytes(M.canonical({'repository': str(ROOT), 'private': str(private),
            'release': release, 'bounds': bounds, 'mode': mode}))
        cutover = object.__new__(M.HostCutover)  # Startup-reader fixture, not admission or service activation.
        cutover.R = release
        cutover.provider = {'python': {'path': executable}}
        cutover.plan = {'bundle_root': str(bundle)}
        cutover.p = {'installation': {'path': str(config), 'sha256': 'b' * 64}}
        cutover.admission = SimpleNamespace(document={'bounds': bounds},
            provider=SimpleNamespace(path=lambda kind: private / 'product-verifier'))
        argv = cutover._operator_argv()
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                assert selector.select(20), 'owned journal producer did not publish readiness'
            line = child.stdout.readline()
            assert line and json.loads(line)['ready'] is True, child.stderr.read().decode()
            a = candidate_tests.M
            def service_observation(command, **kwargs):
                assert command == ['/usr/bin/systemctl', '--user', 'show', 'fox-product-verifier.service',
                    '--property=LoadState,ActiveState,SubState,MainPID,FragmentPath']
                return ('LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=' + str(child.pid)
                    + '\nFragmentPath=/home/opc/.config/systemd/user/fox-product-verifier.service\n').encode()
            monkeypatch.setattr(a, 'command', service_observation)  # External systemd observation only.
            cutover.A = a
            yield cutover, child, private / 'product-verifier' / release[:16]
        finally:
            if child.poll() is None:
                try:
                    child.communicate(b'x', timeout=10)
                except subprocess.TimeoutExpired:
                    child.terminate(); child.communicate(timeout=10)
                    pytest.fail('owned local journal test process required termination')
            assert child.returncode == 0


def test_first_idle_uses_real_process_and_actual_producer_journal(idle_process):
    cutover, child, journal = idle_process
    result = cutover.first_idle(timeout=5)
    assert result['identity']['pid'] == child.pid and result['status'] == 'MATCHED_FIRST_IDLE_CLAIM'
    assert result['continuous_service_liveness_guaranteed'] is False
    directory = journal / result['session']
    assert result['intent_sha256'] == M.sha((directory / 'p0001-claim.intent.json').read_bytes())
    assert result['completion_sha256'] == M.sha((directory / 'p0001-claim.complete.json').read_bytes())


@pytest.mark.parametrize('idle_process', ['attention-late', 'unknown-late', 'wrong-intent', 'malformed'], indirect=True)
def test_first_idle_rejects_other_attention_unknown_members_and_false_claims(idle_process):
    cutover, child, journal = idle_process
    with pytest.raises(M.CutoverError): cutover.first_idle(timeout=3)
    assert child.poll() is None  # The reader does not terminate or replay a producer.


def test_first_idle_retries_only_bounded_publication_read_change(idle_process, monkeypatch):
    cutover, child, journal = idle_process
    original = cutover.A.read
    attempts = []
    def changing(path, **kwargs):
        if Path(path).name == 'p0001-claim.intent.json':
            attempts.append(1)
            if len(attempts) == 1:
                raise cutover.A.ActivationError('INPUT_CHANGED_DURING_READ')
        return original(path, **kwargs)
    monkeypatch.setattr(cutover.A, 'read', changing)  # A transient filesystem observation, never a validator result.
    clock = SimpleNamespace(value=0)
    monkeypatch.setattr(M, 'time', SimpleNamespace(monotonic=lambda: clock.value,
        sleep=lambda seconds: setattr(clock, 'value', clock.value + seconds)))
    assert cutover.first_idle(timeout=3)['status'] == 'MATCHED_FIRST_IDLE_CLAIM'
    assert len(attempts) == 2


def test_first_idle_does_not_retry_private_input_failure(idle_process, monkeypatch):
    cutover, child, journal = idle_process
    original, attempts = cutover.A.read, []
    def refused(path, **kwargs):
        if Path(path).name == 'p0001-claim.intent.json':
            attempts.append(1); raise cutover.A.ActivationError('PRIVATE_INPUT_REQUIRED')
        return original(path, **kwargs)
    monkeypatch.setattr(cutover.A, 'read', refused)
    with pytest.raises(cutover.A.ActivationError, match='PRIVATE_INPUT_REQUIRED'):
        cutover.first_idle(timeout=3)
    assert len(attempts) == 1


@pytest.mark.parametrize('idle_process', ['no-claim'], indirect=True)
def test_missing_first_claim_times_out_without_guessing_or_replay(idle_process, monkeypatch):
    cutover, child, journal = idle_process
    clock = SimpleNamespace(value=0)
    monkeypatch.setattr(M, 'time', SimpleNamespace(monotonic=lambda: clock.value,
        sleep=lambda seconds: setattr(clock, 'value', clock.value + seconds)))
    with pytest.raises(M.CutoverError, match='OPERATOR_FIRST_IDLE_UNCONFIRMED_STATUS_ONLY'):
        cutover.first_idle(timeout=3)
    assert clock.value == 3 and child.poll() is None
    assert not list(journal.glob('session-*/p0001-claim.complete.json'))


@pytest.mark.parametrize('change', ['load', 'active', 'substate', 'path', 'pid'])
def test_unknown_service_is_not_a_running_operator(idle_process, monkeypatch, change):
    cutover, child, journal = idle_process
    state = {'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running',
             'MainPID': str(child.pid), 'FragmentPath': '/home/opc/.config/systemd/user/fox-product-verifier.service'}
    key, value = {'load': ('LoadState', 'not-found'), 'active': ('ActiveState', 'inactive'),
        'substate': ('SubState', 'dead'), 'path': ('FragmentPath', '/unknown/unit'), 'pid': ('MainPID', '0')}[change]
    state[key] = value
    monkeypatch.setattr(cutover.A, 'command', lambda *_args, **_kwargs:
        ''.join(name + '=' + value + '\n' for name, value in state.items()).encode())
    with pytest.raises(M.CutoverError): cutover.operator_identity()


@pytest.mark.parametrize('change', ['none', 'redirected', 'status', 'large', 'disabled', 'unhealthy', 'boolean', 'product'])
def test_public_health_uses_exact_https_origin_and_explicit_worker_booleans(monkeypatch, change):
    value = {'product': 'FOX', 'status': 'ok', 'worker': {'enabled': True, 'healthy': True}}
    if change == 'disabled': value['worker']['enabled'] = False
    if change == 'unhealthy': value['worker']['healthy'] = False
    if change == 'boolean': value['worker']['healthy'] = 1
    if change == 'product': value['product'] = 'unrelated'
    body = b'x' * 65537 if change == 'large' else M.canonical(value)
    calls = []
    class Response:
        status = 503 if change == 'status' else 200
        url = 'https://unrelated.invalid/api/health' if change == 'redirected' else 'https://fox.129.213.189.48.sslip.io/api/health'
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, limit): assert limit == 65537; return body
    def opener(*handlers):
        assert any(isinstance(item, M.urllib.request.ProxyHandler) and item.proxies == {} for item in handlers)
        redirects = [item for item in handlers if isinstance(item, M.urllib.request.HTTPRedirectHandler)]
        assert len(redirects) == 1 and redirects[0].redirect_request(None, None, 302, None, None, None) is None
        def open_(url, timeout): calls.append((url, timeout)); return Response()
        return SimpleNamespace(open=open_)
    monkeypatch.setattr(M.urllib.request, 'build_opener', opener)  # No real HTTP request is made.
    if change == 'none':
        assert M.public_health() == {'url': Response.url, 'https_verified': True, 'worker_healthy': True}
    else:
        with pytest.raises(M.CutoverError): M.public_health()
    assert calls == [('https://fox.129.213.189.48.sslip.io/api/health', 15)]


def stopped_reader_program(database):
    source = ast.parse(Path(M.__file__).read_text())
    methods = [node for node in ast.walk(source) if isinstance(node, ast.FunctionDef) and node.name == 'stopped_idle']
    assert len(methods) == 1
    literals = [node.value for node in ast.walk(methods[0]) if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'program' for target in node.targets)]
    assert len(literals) == 1
    tree = ast.parse(ast.literal_eval(literals[0]))
    roots = [node for node in ast.walk(tree) if isinstance(node, ast.Constant)
             and node.value == '/home/opc/fox/data/fox.sqlite3']
    assert len(roots) == 1
    roots[0].value = str(database)  # Only the external SQLite fixture location is remapped.
    return compile(tree, '<actual-stopped-reader-with-test-io-root>', 'exec')


@pytest.mark.parametrize('state', ['REVIEW_REQUIRED', 'QUEUED', 'PROCESSING', 'QA_REQUIRED'])
def test_stopped_reader_blocks_late_work_with_actual_read_only_sqlite(tmp_path, monkeypatch, state):
    from fox.verification_queue import VerificationQueue
    database = tmp_path / 'fox.sqlite3'
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE runs(id TEXT PRIMARY KEY,project TEXT,source_hash TEXT,state TEXT,message TEXT,created REAL,updated REAL,artifact TEXT)')
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', ('fox-' + '1' * 20, 'synthetic-project', 'a' * 64,
            state, 'SYNTHETIC_PRIVATE_TEXT_NOT_FOR_OUTPUT', 1, 1, None))
    db.close()
    VerificationQueue(database, enabled=True, verifier_release_sha256='b' * 64).initialize()
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
    monkeypatch.setattr(sys, 'argv', ['local-read-only-probe', str(ROOT)])
    monkeypatch.setattr(sys, 'path', list(sys.path))
    output = io.StringIO()
    with redirect_stdout(output):
        if state == 'REVIEW_REQUIRED':
            exec(stopped_reader_program(database), {'__name__': 'stopped_read_only_test'})
        else:
            with pytest.raises(RuntimeError, match='ACTIVE_OR_UNRESOLVED_WORK'):
                exec(stopped_reader_program(database), {'__name__': 'stopped_read_only_test'})
    if state == 'REVIEW_REQUIRED':
        assert json.loads(output.getvalue()) == {'idle': True, 'observed_jobs': 1, 'read_only': True}
    assert 'SYNTHETIC_PRIVATE_TEXT_NOT_FOR_OUTPUT' not in output.getvalue()
    assert before == {path.name: path.read_bytes() for path in tmp_path.iterdir() if path.is_file()}
