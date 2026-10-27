"""Controller-only tests: Podman/IMDS/container observations are synthetic.

Positive paths do not claim an Oracle package, real Chromium, live deployment
or business acceptance. Parent contract tests separately exercise the genuine
producer/retained readers. POSIX cases use real private files and fsync.
"""
from copy import deepcopy
import base64
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import selectors
import time
from types import SimpleNamespace

import pytest

import host as H
import contract as C

POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0


def binding():
    return {'job_id': 'fox-' + '1' * 20, 'project_id': '2' * 32, 'source_hash': '3' * 64,
            'package_sha256': '4' * 64, 'proof_sha256': '5' * 64,
            'fox_image': 'sha256:' + '6' * 64, 'release_sha256': '7' * 64}


def declaration():
    return {'schema_version': 1, 'scope': H.SCOPE, 'attempt_id': 'delivery-' + '8' * 24,
        'input': {'path': '/private/export/input.json', 'sha256': 'a' * 64}, 'binding': binding(),
        'deployment': {'path': '/private/deployment/D.json', 'sha256': 'b' * 64},
        'harness': {'directory': '/private/harness', 'files': {name: 'c' * 64 for name in H.HARNESS}}}


def deployment(plan):
    return {'schema_version': 1, 'scope': 'fox-hosted-admission-v1', 'provider_configuration_sha256': 'c' * 64,
        'current_release_sha256': plan['binding']['release_sha256'], 'infrastructure': {
            name: {'id': character * 64, 'image': plan['binding']['fox_image'] if name == 'fox' else 'sha256:' + character * 64}
            for name, character in (('fox', 'a'), ('forms2apex-mcp', 'b'), ('oracle-applied-ai-label', 'c'))}}


@pytest.mark.parametrize('change', ['valid', 'scope', 'extra', 'bool', 'attempt', 'path', 'image', 'hash', 'harness'])
def test_plan_is_exact_and_canonical(change):
    value = declaration()
    if change == 'scope': value['scope'] = 'other'
    if change == 'extra': value['ready'] = True
    if change == 'bool': value['schema_version'] = True
    if change == 'attempt': value['attempt_id'] = 'fox'
    if change == 'path': value['input']['path'] = '/private/../live/data'
    if change == 'image': value['binding']['fox_image'] = 'fox:latest'
    if change == 'harness': value['harness']['files']['extra.py'] = 'c' * 64
    raw = C.canonical(value)
    expected = C.sha(raw) if change != 'hash' else '0' * 64
    if change == 'valid':
        assert H.plan_document(raw, expected) == value
        with pytest.raises(Exception): H.plan_document(raw.rstrip(), C.sha(raw.rstrip()))
    else:
        with pytest.raises(Exception): H.plan_document(raw, expected)


@pytest.mark.parametrize('change', ['valid', 'release', 'image', 'extra', 'id', 'duplicate'])
def test_deployment_binds_three_exact_container_identities(change):
    plan = declaration(); value = deployment(plan)
    if change == 'release': value['current_release_sha256'] = '0' * 64
    if change == 'image': value['infrastructure']['fox']['image'] = 'sha256:' + '0' * 64
    if change == 'extra': value['infrastructure']['extra'] = value['infrastructure']['fox']
    if change == 'id': value['infrastructure']['fox']['id'] = 'fox'
    raw = C.canonical(value)
    if change == 'duplicate': raw = raw.replace(b'{', b'{"schema_version":1,', 1)
    if change == 'valid': assert H.deployment_document(raw, C.sha(raw), plan['binding']) == value
    else:
        with pytest.raises(Exception): H.deployment_document(raw, C.sha(raw), plan['binding'])


def test_container_commands_never_publish_or_mount_live_data():
    plan, target = declaration(), Path('/private/new-test')
    backend = H.container_args(plan, target, 'backend')
    assert '--network=none' in backend and '--userns=keep-id:uid=1000,gid=1000' in backend
    assert '--cidfile' in backend and str(target / 'backend.cid') in backend
    assert '--memory=512m' in backend and '--read-only' in backend and '--pull=never' in backend
    browser = H.container_args(plan, target, 'browser', 'd' * 64)
    assert '--network=container:' + 'd' * 64 in browser
    assert '--userns=container:' + 'd' * 64 in browser
    assert '--entrypoint' in browser and H.QA_IMAGE in browser
    for command in (backend, browser):
        assert not any(x in command for x in ('--rm', '--replace', '--privileged', '--publish', '-p'))
        assert not any('/home/opc/fox' in x or 'opaf-secure' in x or '.ssh' in x for x in command)
        assert not any(x.endswith((':Z', ':z', ':U')) for x in command)
        assert not any('password' in x.lower() for x in command)


def fixture_and_report():
    expected = binding()
    fixture = {'project_id': expected['project_id'], 'project_name': 'Two Forms', 'run_id': expected['job_id'],
        'source_hash': expected['source_hash'], 'package_sha256': expected['package_sha256'], 'package_bytes': 22,
        'proof_sha256': expected['proof_sha256'], 'form_count': 2, 'notes': C.NOTES,
        'ui': {'index.html': 'd' * 64, 'assets/index-x.js': 'e' * 64, 'assets/index-x.css': 'f' * 64}}
    report = {'schema_version': 1, 'scope': 'fox-isolated-project-delivery-browser-v1', 'origin': H.ORIGIN,
        'synthetic_owner': C.OWNER, 'fixture_sha256': C.sha(C.canonical(fixture)[:-1]), 'job_id': expected['job_id'],
        'package_sha256': expected['package_sha256'], 'retained_proof_sha256': expected['proof_sha256'],
        'passed': True, 'browser_closed': True, 'blocked_requests': 0,
        **{name: False for name in ('live_acceptance_recorded', 'conversion_invoked', 'model_invoked',
            'database_connection_opened', 'raw_retained_proof_verified_by_browser', 'personal_profile_used', 'screenshots_or_traces_saved')},
        'requests': {'login': 1, 'acceptance_attempts': 3, 'allowed_gets': 12}, 'served_ui': fixture['ui'],
        'technical_evidence_before_sha256': '0' * 64, 'technical_evidence_after_sha256': '0' * 64,
        'tests': [{'name': name, 'status': 'PASSED'} for name in (
            'exact_built_ui_and_normal_synthetic_login', 'incomplete_review_does_not_unlock_package',
            'normal_ui_records_only_synthetic_review', 'normal_ui_download_returns_exact_genuine_zip',
            'duplicate_review_blocked_and_technical_proof_unchanged')]}
    return expected, fixture, report


@pytest.mark.parametrize('change', ['valid', 'fixture', 'job', 'proof', 'scope', 'owner', 'requests', 'blocked', 'ui', 'tests', 'evidence', 'claim'])
def test_browser_report_is_bound_to_exact_fixture_and_actions(change):
    expected, fixture, report = fixture_and_report()
    if change == 'fixture': report['fixture_sha256'] = 'a' * 64
    if change == 'job': report['job_id'] = 'fox-' + 'a' * 20
    if change == 'proof': report['retained_proof_sha256'] = 'a' * 64
    if change == 'scope': report['scope'] = 'other'
    if change == 'owner': report['synthetic_owner'] = 'jason'
    if change == 'requests': report['requests']['acceptance_attempts'] = 2
    if change == 'blocked': report['blocked_requests'] = 1
    if change == 'ui': report['served_ui'] = {'index.html': fixture['ui']['index.html']}
    if change == 'tests': report['tests'] = report['tests'][:-1]
    if change == 'evidence': report['technical_evidence_after_sha256'] = 'a' * 64
    if change == 'claim': report['live_acceptance_recorded'] = True
    if change == 'valid': H.check_browser_report(report, fixture, expected)
    else:
        with pytest.raises(H.HostError): H.check_browser_report(report, fixture, expected)


def observed_owned(plan, target, role, *, running=True, backend_id=None):
    expected_mounts = [('harness', '/harness', False), ('proof', '/proof', True)]
    if role == 'backend': expected_mounts += [('input', '/fixture', False), ('data', '/data', True)]
    return {'Id': ('d' if role == 'backend' else 'e') * 64, 'Name': H.container_name(plan['attempt_id'], role),
        'Image': plan['binding']['fox_image'] if role == 'backend' else H.QA_IMAGE,
        'Config': {'Labels': {H.LABEL: plan['attempt_id']}, 'User': '1000:1000'},
        'State': {'Running': running, 'Status': 'running' if running else 'exited', 'ExitCode': 0,
                  'StartedAt': '2026-10-27T00:00:00Z', 'FinishedAt': '' if running else '2026-10-27T00:00:01Z'},
        'Mounts': [{'Type': 'bind', 'Source': str(target / name), 'Destination': dest, 'RW': rw}
                   for name, dest, rw in expected_mounts],
        'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'PortBindings': {},
                      'NetworkMode': 'none' if role == 'backend' else 'container:' + backend_id},
        'NetworkSettings': {'Ports': {'8100/tcp': None}}}


@pytest.mark.parametrize('change', ['valid', 'id', 'image', 'label', 'mount', 'publish', 'network', 'privileged', 'volume'])
def test_owned_container_check_accepts_unpublished_exposed_port_only(monkeypatch, change):
    plan, target = declaration(), Path('/private/test')
    value = observed_owned(plan, target, 'backend')
    if change == 'id': value['Id'] = 'f' * 64
    if change == 'image': value['Image'] = H.QA_IMAGE
    if change == 'label': value['Config']['Labels'][H.LABEL] = 'other'
    if change == 'mount': value['Mounts'][0]['Source'] = '/home/opc/fox/data'
    if change == 'publish': value['NetworkSettings']['Ports']['8100/tcp'] = [{'HostIp': '0.0.0.0', 'HostPort': '8123'}]
    if change == 'network': value['HostConfig']['NetworkMode'] = 'host'
    if change == 'privileged': value['HostConfig']['Privileged'] = True
    if change == 'volume': value['Mounts'].append({'Type': 'volume', 'Source': 'unknown', 'Destination': '/other', 'RW': True})
    monkeypatch.setattr(H, 'command', lambda *args, **kwargs: C.canonical([value]))
    if change == 'valid': assert H._inspect_owned(plan, target, 'backend', 'd' * 64)['running'] is True
    else:
        with pytest.raises(H.HostError): H._inspect_owned(plan, target, 'backend', 'd' * 64)


@pytest.mark.skipif(not POSIX, reason='Actual POSIX private-file and fsync contract')
def test_private_io_and_create_only_cid(tmp_path):
    target = tmp_path / 'private'; H.mkdir_new(target)
    H.new(target / 'backend.cid', ('d' * 64 + '\n').encode())
    assert H.container_id(target, 'backend') == 'd' * 64
    assert stat.S_IMODE((target / 'backend.cid').stat().st_mode) == 0o600
    with pytest.raises(FileExistsError): H.new(target / 'backend.cid', b'changed')
    assert H.container_id(target, 'browser', required=False) is None
    (target / 'backend.cid').chmod(0o644)
    with pytest.raises(H.HostError): H.container_id(target, 'backend')


@pytest.mark.skipif(not POSIX, reason='Actual owner-private journal files')
def test_launch_preserves_original_process_handle_on_stdin_failure(monkeypatch, tmp_path):
    plan, deployment_value = declaration(), deployment(declaration())
    baseline = {'unchanged': True}; processes = {}
    class BrokenInput:
        closed = False
        def write(self, raw): raise BrokenPipeError()
        def flush(self): pass
        def close(self): self.closed = True
    process = SimpleNamespace(pid=123, stdin=BrokenInput(), poll=lambda: 1)
    monkeypatch.setattr(H, 'host_guard', lambda *args: baseline)
    monkeypatch.setattr(H, 'command', lambda *args, **kwargs: None)
    monkeypatch.setattr(H, 'process_identity', lambda pid: None)
    monkeypatch.setattr(H.subprocess, 'Popen', lambda *args, **kwargs: process)
    def failed_input(*args, **kwargs):
        raise H.HostError('INPUT_DELIVERY_UNCONFIRMED')
    monkeypatch.setattr(H, 'bounded_stdin', failed_input)
    with pytest.raises(H.HostError, match='^INPUT_DELIVERY_UNCONFIRMED$'):
        H.launch(plan, deployment_value, baseline, tmp_path, 'backend',
                 {'username': C.OWNER, 'password': 'not-persisted-secret'}, processes=processes)
    assert processes['backend'] is process and not process.stdin.closed
    assert (tmp_path / 'backend-stdin-unconfirmed.json').is_file()
    assert all(b'not-persisted-secret' not in path.read_bytes() for path in tmp_path.iterdir() if path.is_file())


@pytest.mark.skipif(not POSIX, reason='Actual owner-private journal files')
def test_inspection_discovers_original_cid_without_identity_receipt(monkeypatch, tmp_path):
    plan = declaration(); raw = C.canonical(plan)
    parent = tmp_path / 'attempts'; H.mkdir_new(parent)
    target = parent / plan['attempt_id']; H.mkdir_new(target)
    H.new(target / 'plan.json', raw); H.new(target / 'backend.cid', b'd' * 64)
    monkeypatch.setattr(H, 'PARENT', parent)
    monkeypatch.setattr(H, 'identity_guard', lambda: None)
    item = observed_owned(plan, target, 'backend')
    monkeypatch.setattr(H, 'command', lambda *args, **kwargs: C.canonical([item]))
    before = {p.name: p.read_bytes() for p in target.iterdir()}
    result = H.inspect(raw, C.sha(raw))
    assert result['containers']['backend']['id'] == 'd' * 64
    assert result['containers']['backend']['read_only_discovery'] is True
    assert result['terminal'] is None and result['automatic_replay_permitted'] is False
    assert {p.name: p.read_bytes() for p in target.iterdir()} == before


@pytest.mark.skipif(not POSIX, reason='Actual native Linux process observation')
def test_current_process_identity_and_absence_are_observations_only():
    observed = H.process_identity(os.getpid())
    assert observed['pid'] == os.getpid() and observed['start_ticks'].isdigit()
    assert observed == H.process_identity(os.getpid())
    # The Linux pid_max value is never an allocated PID (valid IDs are lower).
    upper = int(Path('/proc/sys/kernel/pid_max').read_text())
    assert H.process_identity(upper) is None


def test_run_requires_explicit_authority_before_read_or_effect(monkeypatch):
    monkeypatch.setattr(H, 'load_inputs', lambda *args: (_ for _ in ()).throw(AssertionError('must not read')))
    with pytest.raises(H.HostError, match='EXPLICIT'):
        H.run(b'{}', 'a' * 64)


def test_direct_isolated_cli_bootstrap_has_local_helper_import():
    result = subprocess.run([sys.executable, '-I', '-B', str(Path(H.__file__)), '--help'],
                            capture_output=True, timeout=15)
    assert result.returncode == 0, result.stderr.decode()
    assert b'--plan-sha256' in result.stdout and b'run,inspect' in result.stdout


def test_diagnostics_never_echo_provider_or_input_content():
    assert H.public_code(H.HostError('EXACT_DEPLOYMENT_BINDING_REQUIRED')) == 'EXACT_DEPLOYMENT_BINDING_REQUIRED'
    assert H.public_code(C.DeliveryError('EXPORTED_FILE_HASH_CHANGED')) == 'EXPORTED_FILE_HASH_CHANGED'
    assert H.public_code(H.HostError('Password=secret-value')) == 'ISOLATED_DELIVERY_OUTCOME_UNCONFIRMED'
    assert H.public_code(OSError('secret-user/path')) == 'ISOLATED_DELIVERY_OUTCOME_UNCONFIRMED'


def test_oversized_input_is_rejected_before_any_host_probe_or_launch(monkeypatch, tmp_path):
    def forbidden(*args, **kwargs): raise AssertionError('No effect is allowed')
    monkeypatch.setattr(H, 'host_guard', forbidden)
    monkeypatch.setattr(H.subprocess, 'Popen', forbidden)
    with pytest.raises(H.HostError, match='^INPUT_PACKET_BOUND_EXCEEDED$'):
        H.launch(declaration(), deployment(declaration()), {}, tmp_path, 'backend', {'password': 'x' * 4096})
    assert list(tmp_path.iterdir()) == []


def stop_owned_child(process):
    """Test cleanup uses only its retained original Popen handle."""
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=5)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()
    assert process.poll() is not None


def child_output(process, timeout=3):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout.fileno(), selectors.EVENT_READ)
        assert selector.select(timeout), 'Owned test child did not produce its bounded reply'
        return os.read(process.stdout.fileno(), 4096)


@pytest.mark.skipif(not POSIX, reason='Real owned POSIX pipe and child process')
@pytest.mark.parametrize('initial_blocking', [True, False])
def test_nonreading_child_stdin_times_out_and_restores_fd_mode(initial_blocking):
    import fcntl
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(30)'],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, bufsize=0)
    try:
        fd = process.stdin.fileno()
        fcntl.fcntl(fd, fcntl.F_SETPIPE_SZ, 4096)  # Only this newly owned pipe.
        os.set_blocking(fd, initial_blocking)
        started = time.monotonic()
        with pytest.raises(H.HostError, match='^INPUT_DELIVERY_UNCONFIRMED$'):
            H.bounded_stdin(process, b'x' * 262144, maximum=262144, timeout=0.15, close_after=True)
        elapsed = time.monotonic() - started
        assert 0.10 <= elapsed < 3.0
        assert process.poll() is None and process.stdin.closed is False
        assert os.get_blocking(fd) is initial_blocking
    finally:
        stop_owned_child(process)


@pytest.mark.skipif(not POSIX, reason='Real partial pipe writes, child readback and EOF')
def test_partial_writes_complete_exactly_and_only_success_sends_browser_eof(monkeypatch):
    import fcntl
    program = "import hashlib,json,sys,time;time.sleep(.1);d=sys.stdin.buffer.read();print(json.dumps({'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}))"
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', program], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        fd = process.stdin.fileno(); fcntl.fcntl(fd, fcntl.F_SETPIPE_SZ, 4096)
        raw = b'bounded-owned-pipe-' * 4096
        actual_write, actual_set = os.write, os.set_blocking
        writes, modes = [], []
        def tracked_write(number, value):
            result = actual_write(number, value)
            if number == fd: writes.append((len(value), result))
            return result
        def tracked_mode(number, mode):
            if number == fd: modes.append(mode)
            return actual_set(number, mode)
        monkeypatch.setattr(H.os, 'write', tracked_write)
        monkeypatch.setattr(H.os, 'set_blocking', tracked_mode)
        H.bounded_stdin(process, raw, maximum=262144, timeout=3, close_after=True)
        assert process.stdin.closed and modes == [False, True]
        assert any(written < requested for requested, written in writes)
        assert sum(written for _, written in writes) == len(raw)
        assert process.wait(timeout=3) == 0
        assert json.loads(process.stdout.read()) == {'bytes': len(raw), 'sha256': C.sha(raw)}
        assert process.stderr.read() == b''
    finally:
        stop_owned_child(process)


@pytest.mark.skipif(not POSIX, reason='Real backend pipe remains open after one packet')
@pytest.mark.parametrize('initial_blocking', [True, False])
def test_successful_backend_packet_preserves_open_stdin_and_original_mode(initial_blocking):
    program = "import hashlib,json,sys,time;d=sys.stdin.buffer.readline();print(json.dumps({'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()}),flush=True);time.sleep(30)"
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', program], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        fd = process.stdin.fileno(); os.set_blocking(fd, initial_blocking)
        raw = b'one-owned-backend-packet\n'
        H.bounded_stdin(process, raw, maximum=4096, timeout=3, close_after=False)
        assert process.stdin.closed is False and os.get_blocking(fd) is initial_blocking
        assert json.loads(child_output(process)) == {'bytes': len(raw), 'sha256': C.sha(raw)}
        assert process.poll() is None
    finally:
        stop_owned_child(process)


@pytest.mark.skipif(not POSIX, reason='Real EPIPE after owned child closes only its reader')
def test_dead_reader_epipe_is_bounded_and_leaves_pipe_for_owned_cleanup():
    program = "import os,sys,time;os.close(0);print('READER_CLOSED',flush=True);time.sleep(30)"
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', program], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        assert child_output(process).strip() == b'READER_CLOSED'
        fd = process.stdin.fileno(); started = time.monotonic()
        with pytest.raises(H.HostError, match='^INPUT_DELIVERY_UNCONFIRMED$'):
            H.bounded_stdin(process, b'cannot-deliver\n', maximum=4096, timeout=0.5, close_after=True)
        assert time.monotonic() - started < 2
        assert not process.stdin.closed and os.get_blocking(fd) is True
    finally:
        stop_owned_child(process)


@pytest.mark.skipif(not POSIX, reason='Real regular FileIO must not bypass FIFO requirement')
def test_regular_file_is_rejected_before_nonblocking_mode_change(tmp_path):
    path = tmp_path / 'not-a-pipe'
    with path.open('wb', buffering=0) as stream:
        process = SimpleNamespace(stdin=stream, poll=lambda: None)
        original = os.get_blocking(stream.fileno())
        with pytest.raises(H.HostError, match='^INPUT_DELIVERY_UNCONFIRMED$'):
            H.bounded_stdin(process, b'x', maximum=4096, timeout=1)
        assert not stream.closed and os.get_blocking(stream.fileno()) == original
    assert path.read_bytes() == b''


def controller_export():
    """Structural test input only; fake child responses are NOT Oracle proof."""
    expected = binding()
    package = b'authored controller test bytes, not an Oracle export'
    proof = C.canonical({'scope': 'fox-project-technical-verification-v1', 'human_acceptance_recorded': False})
    expected.update(package_sha256=C.sha(package), proof_sha256=C.sha(proof))
    snapshot = C.canonical({'project': expected['project_id'], 'project_id': expected['project_id'],
        'project_name': 'Two Forms', 'conversion_profile': 'native-project-v1', 'source_hash': expected['source_hash'],
        'native_project': {'profile_id': 'native-project-v1', 'data_mode': 'synthetic_test_only', 'forms': [{}, {}]}})
    files = {name: b'{}\n' for name in C.FILES}
    files.update({'source-snapshot.json': snapshot, 'project-technical-verification/verification.json': proof,
                  'apex-package.zip': package})
    value = {'schema_version': 1, 'scope': C.SCOPE, 'read_only': True, 'binding': expected,
        'project': {'id': expected['project_id'], 'owner': 'synthetic-source', 'customer': 'Synthetic',
                    'name': 'Two Forms', 'description': '', 'created': 1.0},
        'run': {'id': expected['job_id'], 'project': expected['project_id'], 'source_hash': expected['source_hash'],
                'state': 'VERIFIED', 'message': 'Authored controller observation only', 'created': 1.0, 'updated': 2.0,
                'artifact': 'jobs/' + expected['job_id'] + '/apex-package.zip'},
        'technical_verification': {'run': expected['job_id'], 'source_hash': expected['source_hash'],
            'artifact_sha256': expected['package_sha256'], 'proof_sha256': expected['proof_sha256'],
            'proof_json': proof.decode(), 'created': 2.0},
        'files': {name: {'bytes': len(raw), 'sha256': C.sha(raw), 'base64': base64.b64encode(raw).decode()}
                  for name, raw in files.items()},
        'live_acceptance_count': 0, 'source_scope': 'caller-approved-labelled-synthetic-project',
        'authority': 'caller-must-independently-verify-live-deployment', 'exported_at_utc': '2026-10-27T00:00:00+00:00'}
    raw = C.canonical(value)
    C.validate_export(raw, expected_sha256=C.sha(raw), expected_binding=expected)
    return expected, raw, package


@pytest.mark.skipif(not POSIX or os.geteuid() != 1000, reason='Real POSIX UID1000 private files with fake external containers')
@pytest.mark.parametrize('scenario', ['passed', 'browser_failed', 'backend_input_failed', 'browser_input_failed'])
def test_controller_lifecycle_real_private_files_fake_external_io(monkeypatch, tmp_path, scenario):
    browser_code = 1 if scenario == 'browser_failed' else 0
    expected, raw, package = controller_export()
    plan = declaration(); plan['binding'] = expected
    inputs = tmp_path / 'inputs'; H.mkdir_new(inputs)
    harness = tmp_path / 'harness'; H.mkdir_new(harness)
    H.new(inputs / 'input.json', raw)
    plan['input'] = {'path': str(inputs / 'input.json'), 'sha256': C.sha(raw)}
    sources = {name: (Path(H.__file__).parent / name).read_bytes() for name in H.HARNESS}
    for name, content in sources.items(): H.new(harness / name, content)
    plan['harness'] = {'directory': str(harness), 'files': {name: C.sha(content) for name, content in sources.items()}}
    deployed = deployment(plan); draw = C.canonical(deployed); H.new(inputs / 'D.json', draw)
    plan['deployment'] = {'path': str(inputs / 'D.json'), 'sha256': C.sha(draw)}
    parent = tmp_path / 'attempts'; monkeypatch.setattr(H, 'PARENT', parent)
    target = parent / plan['attempt_id']
    commands, children, captured, attempted_input = [], {}, {}, {}

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, maximum):
            return C.canonical({'id': H.VM, 'compartmentId': H.COMPARTMENT, 'canonicalRegionName': 'us-ashburn-1'})
    monkeypatch.setattr(H.urllib.request, 'build_opener', lambda *args: SimpleNamespace(open=lambda *a, **k: Response()))

    def live():
        return [{'Name': name, 'Id': value['id'], 'Image': value['image'],
            'State': {'Running': True, 'StartedAt': 'unchanged'}, 'Mounts': [],
            'Config': {'Env': ['FOX_VERIFIER_RELEASE_SHA256=' + expected['release_sha256'],
                               'FOX_CONVERSION_PROFILE=native-project-v1']}}
                for name, value in deployed['infrastructure'].items()]

    def fake_command(argv, **kwargs):
        commands.append(argv)
        if argv[1] == 'info': return b'true\n'
        if argv[1:3] == ['image', 'inspect']:
            return C.canonical([{'Id': H.QA_IMAGE, 'Os': 'linux', 'Architecture': 'amd64'}]) if argv[3] == H.QA_IMAGE else H.QA_BASE.encode()
        if argv[1:3] == ['container', 'exists']: return None
        if argv[1] == 'inspect':
            if len(argv) > 3: return C.canonical(live())
            role = next(name for name, child in children.items() if argv[2] in (child.cid, H.container_name(plan['attempt_id'], name)))
            observed = observed_owned(plan, target, role, running=children[role].returncode is None,
                                      backend_id=children.get('backend', SimpleNamespace(cid=None)).cid)
            observed['State']['ExitCode'] = children[role].returncode or 0
            return C.canonical([observed])
        if argv[1] == 'exec':
            if '-c' in argv: return b'ISOLATED_HEALTH_OK\n'
            assert 'audit' in argv and '/harness/runtime.py' in argv
            return C.canonical({'status': 'ISOLATED_ACCEPTANCE_VERIFIED', 'producer_bytes_unchanged': True,
                'technical_proof_unchanged': True, 'live_acceptance_recorded': False, 'synthetic_acceptance_count': 1,
                'oracle_database_contacted': False, 'model_invoked': False, 'isolated_sqlite_used': True,
                'package_sha256': expected['package_sha256'], 'proof_sha256': expected['proof_sha256']})
        if argv[1] == 'stop':
            role = next(name for name, child in children.items() if child.cid == argv[-1])
            children[role].returncode = 0
            return argv[-1].encode()
        raise AssertionError('Unexpected command: ' + repr(argv))
    monkeypatch.setattr(H, 'command', fake_command)
    def fake_process_identity(pid):
        child = next((value for value in children.values() if value.pid == pid), None)
        if child is None or child.returncode is not None: return None
        return {'pid': pid, 'start_ticks': '42',
            'boot_id': '00000000-0000-0000-0000-000000000000', 'executable': '/usr/bin/podman'}
    monkeypatch.setattr(H, 'process_identity', fake_process_identity)

    class Pipe:
        def __init__(self, role): self.role, self.closed = role, False
        def write(self, data):
            packet = json.loads(data); captured[self.role] = packet
            if self.role == 'backend':
                _, fixture, _ = fixture_and_report()
                fixture.update(package_sha256=expected['package_sha256'], proof_sha256=expected['proof_sha256'],
                    package_bytes=len(package), owner=C.OWNER, input_sha256=C.sha(raw), fox_image=expected['fox_image'],
                    release_sha256=expected['release_sha256'], worker_enabled=False, integration_configured=False)
                H.new(target / 'proof/runtime/fixture.json', fixture)
            else:
                _, _, report = fixture_and_report()
                fixture = packet['fixture']
                normalized = {key: fixture[key] for key in ('project_id', 'project_name', 'run_id', 'source_hash',
                    'package_sha256', 'package_bytes', 'proof_sha256', 'form_count', 'notes', 'ui')}
                report.update(fixture_sha256=C.sha(C.canonical(normalized)[:-1]), package_sha256=expected['package_sha256'],
                    retained_proof_sha256=expected['proof_sha256'],
                    download={'name': 'accepted-apex.zip', 'bytes': len(package), 'sha256': C.sha(package)})
                H.new(target / 'proof/browser/browser-result.json', report)
                H.new(target / 'proof/browser/accepted-apex.zip', package)
            return len(data)
        def flush(self): pass
        def close(self):
            self.closed = True
            if self.role == 'browser': children['browser'].returncode = browser_code

    class Process:
        def __init__(self, argv, **kwargs):
            commands.append(argv)
            role = 'backend' if argv[argv.index('--name') + 1].endswith('-backend') else 'browser'
            self.role = role
            self.pid = 100 + len(children); self.cid = ('d' if role == 'backend' else 'e') * 64
            self.returncode = None; self.stdin = Pipe(role); children[role] = self
            assert kwargs['umask'] == 0o077
            H.new(Path(argv[argv.index('--cidfile') + 1]), self.cid.encode())
        def poll(self): return self.returncode
        def wait(self, timeout):
            assert self.returncode is not None
            return self.returncode
    monkeypatch.setattr(H.subprocess, 'Popen', Process)
    def fake_stdin(process, payload, *, maximum, timeout=H.INPUT_TIMEOUT_SECONDS, close_after=False):
        # This fixture's child transport is synthetic. Actual FIFO/deadline
        # behavior is exercised above with real owned POSIX child processes.
        assert len(payload) <= maximum
        attempted_input[process.role] = json.loads(payload)
        if scenario == process.role + '_input_failed':
            raise H.HostError('INPUT_DELIVERY_UNCONFIRMED')
        process.stdin.write(payload); process.stdin.flush()
        if close_after: process.stdin.close()
    monkeypatch.setattr(H, 'bounded_stdin', fake_stdin)

    plan_raw = C.canonical(plan)
    result = H.run(plan_raw, C.sha(plan_raw), apply=True)
    assert result['status'] == ('ISOLATED_DELIVERY_PASSED' if scenario == 'passed' else 'NOT_CONFIRMED')
    assert result['live_acceptance_recorded'] is False and result['new_public_port'] is False
    assert result['oracle_database_contacted'] is False
    assert all(item['running'] is False for item in result['cleanup'].values())
    if scenario.endswith('_input_failed'):
        assert result['code'] == 'INPUT_DELIVERY_UNCONFIRMED'
        role = scenario.split('_')[0]
        assert C.parsed((target / (role + '-stdin-unconfirmed.json')).read_bytes()) == {
            'status': 'INPUT_DELIVERY_UNCONFIRMED', 'automatic_replay_permitted': False}
        assert not any('audit' in argv for argv in commands)
        if role == 'backend':
            assert 'browser' not in children
            assert not any(argv[1] == 'exec' for argv in commands)
        else:
            assert not (target / 'proof/browser/browser-result.json').exists()
    if 'browser' in attempted_input:
        assert attempted_input['backend']['password'] == attempted_input['browser']['password']
    secret = attempted_input['backend']['password'].encode()
    assert all(secret not in p.read_bytes() for p in target.rglob('*') if p.is_file())
    assert sum(argv[1] == 'run' for argv in commands) == (1 if scenario == 'backend_input_failed' else 2)
    assert all(argv[-1] in {'d' * 64, 'e' * 64} for argv in commands if argv[1] == 'stop')
    with pytest.raises(H.HostError, match='EXISTING_ATTEMPT'):
        H.run(plan_raw, C.sha(plan_raw), apply=True)
    inspected = H.inspect(plan_raw, C.sha(plan_raw))
    assert inspected['read_only'] is True and inspected['terminal'] == result
