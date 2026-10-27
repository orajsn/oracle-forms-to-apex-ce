"""Offline contracts and actual local OS ownership; no live request is sent."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import journey_contracts as c
import private_io
import preflight
from process_owner import OwnedJob, inspect_identity


@pytest.fixture
def plan(tmp_path):
    base = ROOT / 'work/b27a'
    source = ROOT / 'work/hosted-declaration-20261027a'
    if not base.is_dir() or not source.is_dir():
        pytest.skip('This development fixture uses retained actual B/C/R declarations; no live state is accessed.')
    provider, release = (c.object_bytes((source / (name + '.json')).read_bytes()) for name in ('provider', 'release'))
    provider_sha, release_sha = c.sha(c.canonical(provider)), c.sha(c.canonical(release))
    inventory = c.object_bytes((base / 'source-inventory.json').read_bytes())
    containers = {name: {'id': c.sha(('synthetic-' + name).encode()),
        'image': release['images'][role] if role else 'sha256:' + 'c' * 64}
        for name, role in [('fox', 'fox'), ('forms2apex-mcp', 'converter'), ('oracle-applied-ai-label', None)]}
    admission = {'schema_version': 1, 'scope': 'fox-hosted-admission-v1',
        'provider_configuration_sha256': provider_sha, 'current_release_sha256': release_sha,
        'infrastructure': containers}
    attempt = 'live-' + 'a' * 24
    return {'schema_version': 1, 'scope': c.SCOPE, 'attempt_id': attempt, 'origin': c.ORIGIN,
        'project': {'customer': 'Synthetic FOX internal QA', 'name': 'Synthetic FOX ' + attempt,
                    'description': 'Synthetic automated conversion proof. No customer data or human acceptance.'},
        'files': c.source_files(HERE / 'fixtures/ordinary-two-form.json'),
        'source_manifest_sha256': c.SOURCE_HASH, 'expected_forms': ['ALPHA', 'BETA'],
        'deployment': {'provider': provider, 'provider_sha256': provider_sha, 'release': release, 'release_sha256': release_sha,
            'admission': admission, 'admission_sha256': c.sha(c.canonical(admission)),
            'inventory': inventory, 'source_bundle_sha256': c.sha(c.canonical(inventory)), 'bundle_root': str((base / 'bundle').resolve()),
            'ui_assets': {name.removeprefix('fox/dist/'): value for name, value in inventory['files'].items() if name.startswith('fox/dist/')}},
        'browser': {'playwright_module': str((tmp_path / 'playwright/index.mjs').absolute()),
            'index_sha256': 'a' * 64, 'version': '1.62.1', 'channel': 'msedge'},
        'node': {'path': str((tmp_path / 'node.exe').absolute()), 'sha256': 'b' * 64},
        'harness': {name: c.sha((HERE / name).read_bytes()) for name in
            ('cli.py', 'journey_contracts.py', 'preflight.py', 'private_io.py', 'process_owner.py', 'live.mjs')},
        'max_wait_seconds': 1800, 'poll_seconds': 5, 'plan_directory': str(tmp_path.absolute())}


def observed(plan):
    dep = plan['deployment']
    value = {'schema_version': 1, 'scope': 'fox-live-project-preflight-v1',
        'observed_at_utc': datetime.now(timezone.utc).isoformat(),
        **{name: dep[name] for name in ('source_bundle_sha256', 'release_sha256', 'provider_sha256', 'admission_sha256')},
        'images': dep['release']['images'], 'containers': dep['admission']['infrastructure'],
        'instance': {'id': c.INSTANCE, 'compartment_id': c.COMPARTMENT, 'region': c.REGION},
        'database': {'id': c.DATABASE, 'compartment_id': c.COMPARTMENT, 'lifecycle_state': 'AVAILABLE', 'db_name': 'JSNF2APEX'},
        'active_conversion_count': 0, 'application_profile': 'native-project-v1',
        'operator_service': {'unit': 'fox-product-verifier.service', 'pid': 123, 'start_ticks': '456', 'state': 'running'}}
    value['receipt_sha256'] = c.sha(c.canonical(value))
    return value


def test_actual_original_four_sources_and_pure_plan(plan):
    assert c.validate_plan(plan) == plan
    assert len(plan['files']) == 4
    assert c.validate_preflight(observed(plan), plan)['active_conversion_count'] == 0
    assert c.source_files(HERE / 'fixtures/ordinary-two-form.json') == c.source_files(ROOT / 'work/qa-storage-v1/fixture/sources')


@pytest.mark.parametrize('change', ['origin', 'source', 'credentials', 'project', 'bool', 'hash', 'scope', 'ui', 'path'])
def test_mutated_plan_rejected(plan, change):
    if change == 'origin': plan['origin'] = 'https://unrelated.example'
    if change == 'source': plan['files'][0]['base64'] += 'AAAA'
    if change == 'credentials': plan['credentials'] = {'password': 'must-not-enter-plan'}
    if change == 'project': plan['project']['customer'] = 'Customer records'
    if change == 'bool': plan['max_wait_seconds'] = True
    if change == 'hash': plan['deployment']['provider_sha256'] = 'e' * 64
    if change == 'scope': plan['deployment']['provider']['target_profile']['oci']['compartment_id'] = 'other'
    if change == 'ui': plan['deployment']['ui_assets']['index.html'] = 'e' * 64
    if change == 'path': plan['plan_directory'] = '../moved'
    with pytest.raises(c.JourneyError):
        c.validate_plan(plan)


@pytest.mark.parametrize('change', ['stale', 'future', 'busy', 'db', 'instance', 'image', 'pid', 'service', 'receipt', 'extra'])
def test_preflight_cannot_be_refreshed_by_rehashing(plan, change):
    value = observed(plan)
    if change == 'stale': value['observed_at_utc'] = (datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat()
    if change == 'future': value['observed_at_utc'] = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat()
    if change == 'busy': value['active_conversion_count'] = 1
    if change == 'db': value['database']['id'] = 'unapproved'
    if change == 'instance': value['instance']['compartment_id'] = 'unapproved'
    if change == 'image': value['images'] = {**value['images'], 'fox': 'sha256:' + 'e' * 64}
    if change == 'pid': value['operator_service']['pid'] = True
    if change == 'service': value['operator_service']['state'] = 'stopped'
    if change == 'extra': value['credential'] = 'Synthetic forbidden field'
    value['receipt_sha256'] = c.sha(c.canonical({key: item for key, item in value.items() if key != 'receipt_sha256'}))
    if change == 'receipt': value['receipt_sha256'] = '0' * 64
    with pytest.raises(c.JourneyError):
        c.validate_preflight(value, plan)


def test_read_only_observer_boundary_checks_real_contract(plan, tmp_path):
    folder = private_io.new_directory(tmp_path / 'private-ref')
    key = folder / 'not-a-real-key'; key.write_bytes(b'Synthetic reference never sent')
    if os.name != 'nt': key.chmod(0o600)
    calls = []
    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=c.canonical(observed(plan)), stderr=b'')
    actual = preflight.observe(plan, key, runner=runner)
    assert actual['operator_service']['pid'] == 123
    argv, kwargs = calls[0]
    assert argv[:5] == ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes']
    packet = c.object_bytes(kwargs['input'])
    assert set(packet) == {'deployment', 'program_base64', 'program_sha256'}
    assert 'credentials' not in packet
    compile(preflight.HOST, '<readonly-host>', 'exec')
    compile(preflight.LAUNCHER, '<readonly-launcher>', 'exec')


def test_observer_withholds_provider_error(plan, tmp_path):
    folder = private_io.new_directory(tmp_path / 'private-ref')
    key = folder / 'key'; key.write_bytes(b'Synthetic reference')
    if os.name != 'nt': key.chmod(0o600)
    def runner(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout=b'', stderr=b'credential sentinel must never be copied')
    with pytest.raises(c.JourneyError, match='LIVE_PREFLIGHT_UNCONFIRMED_NO_UI_ACTION') as error:
        preflight.observe(plan, key, runner=runner)
    assert 'sentinel' not in str(error.value)


def test_private_create_only_and_credential_file(tmp_path):
    root = private_io.new_directory(tmp_path / 'owned')
    private_io.save(root / 'credentials.json', {'username': 'synthetic-reviewer', 'password': 'Synthetic fixture only 123'})
    assert private_io.credentials(root / 'credentials.json')['username'] == 'synthetic-reviewer'
    with pytest.raises(FileExistsError):
        private_io.save(root / 'credentials.json', {'replacement': True})
    with pytest.raises(c.JourneyError):
        private_io.new_directory(root)
    private_io.save(root / 'invalid.json', {'username': 'synthetic', 'password': 'sample', 'token': 'forbidden'})
    with pytest.raises(c.JourneyError):
        private_io.credentials(root / 'invalid.json')


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows handle ownership')
def test_actual_windows_owned_child_is_stopped_without_pid_guessing():
    job = OwnedJob()
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c',
        'import sys,time;sys.stdin.buffer.read();time.sleep(60)'], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        job.assign(process)
        assert job.active() == 1
        identity = job.identity(process)
        assert inspect_identity(identity)['state'] == 'running'
        changed = {**identity, 'creation_filetime': str(int(identity['creation_filetime']) + 1)}
        assert inspect_identity(changed)['state'] == 'different_process'
        job.stop()
        assert process.wait(timeout=10) is not None
        assert job.active() == 0
        assert inspect_identity(identity)['state'] in {'terminated', 'absent'}
    finally:
        if process.poll() is None:
            process.terminate(); process.wait(timeout=10)
        process.stdin.close(); job.close()


def test_plan_location_and_harness_bindings(plan, tmp_path):
    import cli
    raw = c.canonical(plan); path = tmp_path / 'plan.json'; path.write_bytes(raw)
    args = SimpleNamespace(plan=str(path), plan_sha256=c.sha(raw))
    assert cli.load_plan(args) == plan
    copied = tmp_path / 'copied.json'; copied.write_bytes(raw)
    with pytest.raises(c.JourneyError, match='PLAN_LOCATION_CHANGED'):
        cli.load_plan(SimpleNamespace(plan=str(copied), plan_sha256=c.sha(raw)))


def test_actual_packaged_declaration_prepares_without_remote_calls_and_matches_node(plan, tmp_path):
    """Real B/C/R, explicitly synthetic D, real Python/Node validators only."""
    node = Path('C:/Program Files/nodejs/node.exe')
    playwright = Path.home() / '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs'
    if os.name != 'nt' or not node.is_file() or not playwright.is_file():
        pytest.skip('Actual Windows installed runtime fixture')
    dep = plan['deployment']; declaration = tmp_path / 'synthetic-D.json'
    declaration.write_bytes(c.canonical(dep['admission']))
    output = tmp_path / 'prepared'
    args = [sys.executable, '-I', '-B', str(HERE / 'cli.py'), 'prepare',
        '--provider', str(ROOT / 'work/hosted-declaration-20261027a/provider.json'), '--provider-sha256', dep['provider_sha256'],
        '--release', str(ROOT / 'work/hosted-declaration-20261027a/release.json'), '--release-sha256', dep['release_sha256'],
        '--admission', str(declaration), '--admission-sha256', dep['admission_sha256'],
        '--bundle-root', dep['bundle_root'], '--bundle-sha256', dep['source_bundle_sha256'],
        '--inventory', str(ROOT / 'work/b27a/source-inventory.json'),
        '--sources', str(HERE / 'fixtures/ordinary-two-form.json'), '--node', str(node),
        '--playwright-module', str(playwright), '--output', str(output)]
    result = subprocess.run(args, capture_output=True, timeout=60, creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stdout.decode()
    summary = c.object_bytes(result.stdout)
    assert summary['status'] == 'PREPARED_NOT_PREFLIGHTED' and summary['live_requests_made'] is False
    saved = c.validate_plan(c.object_bytes((output / 'plan.json').read_bytes()))
    assert not (output / 'live-dispatch.json').exists()
    data = {'schema_version': 1, 'scope': 'fox-live-project-journey-input-v1', 'mode': 'live', 'apply': True,
        'origin': saved['origin'], 'attempt_id': saved['attempt_id'], 'output_dir': str(output / 'browser'),
        'credentials': {'username': 'synthetic-unused', 'password': 'Synthetic unused validation only'},
        'project': saved['project'], 'files': saved['files'], 'source_manifest_sha256': saved['source_manifest_sha256'],
        'expected_forms': saved['expected_forms'], 'preflight': observed(saved), 'ui_assets': saved['deployment']['ui_assets'],
        'browser': saved['browser'], 'max_wait_seconds': saved['max_wait_seconds'], 'poll_seconds': saved['poll_seconds']}
    program = ('import {validateInput} from ' + json.dumps((HERE / 'live.mjs').as_uri()) + ';'
               'let raw="";for await(const x of process.stdin)raw+=x;'
               'validateInput(JSON.parse(raw));process.stdout.write("VALIDATED_NO_BROWSER");')
    checked = subprocess.run([str(node), '--input-type=module', '-e', program], input=c.canonical(data),
        capture_output=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
    assert checked.returncode == 0, checked.stderr.decode()
    assert checked.stdout == b'VALIDATED_NO_BROWSER' and not (output / 'browser').exists()


@pytest.mark.skipif(os.name != 'nt', reason='Actual Windows anonymous-pipe bound')
def test_nonreading_owned_child_cannot_block_stdin_forever():
    import cli
    job = OwnedJob()
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(60)'],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW)
    started = time.monotonic()
    try:
        job.assign(process)
        with pytest.raises(c.JourneyError, match='STDIN_DELIVERY_TIMEOUT_OUTCOME_UNCONFIRMED'):
            cli.deliver_stdin(process, job, b'Synthetic fixture ' * 8192,
                              deadline=time.monotonic() + 10, write_timeout=0.2)
        assert time.monotonic() - started < 10
        assert process.wait(timeout=5) is not None and job.active() == 0
    finally:
        if process.poll() is None:
            job.stop(); process.wait(timeout=5)
        try:
            if not process.stdin.closed: process.stdin.close()
        except OSError:
            pass
        job.close()


def test_inspect_cannot_mix_plan_and_another_attempt(plan, tmp_path):
    import cli
    plan_root = private_io.new_directory(tmp_path / 'plan-home')
    plan['plan_directory'] = str(plan_root)
    private_io.save(plan_root / 'plan.json', plan)
    actual = private_io.new_directory(tmp_path / 'actual')
    wrong = private_io.new_directory(tmp_path / 'wrong')
    private_io.save(actual / 'plan.json', plan)
    changed = deepcopy(plan); changed['attempt_id'] = 'live-' + 'b' * 24
    private_io.save(wrong / 'plan.json', changed)
    args = SimpleNamespace(plan=str(plan_root / 'plan.json'), plan_sha256=c.sha(c.canonical(plan)),
                           attempt_output=str(wrong), remote=False)
    with pytest.raises(c.JourneyError, match='ATTEMPT_PLAN_BINDING_CHANGED'):
        cli.inspect(args)
    copied = private_io.new_directory(tmp_path / 'copied')
    private_io.save(copied / 'plan.json', plan)
    private_io.save(plan_root / 'live-dispatch.json', {'attempt_id': plan['attempt_id'],
        'plan_sha256': args.plan_sha256, 'output_directory': str(actual)})
    args.attempt_output = str(copied)
    with pytest.raises(c.JourneyError, match='ATTEMPT_OUTPUT_BINDING_CHANGED'):
        cli.inspect(args)


@pytest.mark.skipif(os.name != 'nt', reason='Live CLI is Windows-only')
def test_same_plan_is_not_rerun_by_selecting_new_output(plan, tmp_path, monkeypatch):
    import cli
    plan_root = private_io.new_directory(tmp_path / 'plan-home')
    plan['plan_directory'] = str(plan_root)
    private_io.save(plan_root / 'plan.json', plan)
    private_io.save(plan_root / 'live-dispatch.json', {'attempt_id': plan['attempt_id'], 'outcome': 'unknown'})
    def forbidden(*args, **kwargs):
        raise AssertionError('No production declaration, remote probe, credential or browser action is permitted')
    monkeypatch.setattr(cli, 'production_deployment', forbidden)
    monkeypatch.setattr(preflight, 'observe', forbidden)
    args = SimpleNamespace(apply=True, plan=str(plan_root / 'plan.json'), plan_sha256=c.sha(c.canonical(plan)),
                           output=str(tmp_path / 'another-output'))
    with pytest.raises(c.JourneyError, match='PRIOR_LIVE_ATTEMPT_RETAINED_INSPECT_ONLY'):
        cli.run(args)
    assert not (tmp_path / 'another-output').exists()


def test_cli_argument_error_does_not_echo_misplaced_credential():
    sentinel = 'SYNTHETIC_DO_NOT_ECHO_ARGUMENT'
    result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'cli.py'), 'run', '--password', sentinel],
        capture_output=True, timeout=15)
    assert result.returncode == 1
    assert sentinel.encode() not in result.stdout + result.stderr
    assert c.object_bytes(result.stdout)['code'] == 'JOURNEY_ARGUMENTS_INVALID'
