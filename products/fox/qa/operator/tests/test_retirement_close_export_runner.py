"""Once-only runner tests; never launch the real retirement/context/export.

Happy-path orchestration substitutes only the original-history context and
export boundary. Its returned synthetic C/F/G bundle is still checked by the
genuine retirement validator. Native tests touch only pytest-owned temporary
paths and query this test process, never a historical producer.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / 'work/close-export-retirement-20261027a.py'


def load_runner():
    spec = importlib.util.spec_from_file_location('_test_retirement_close_export_runner', RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def runner():
    return load_runner()


def arguments(module, mode='--launch', **changes):
    values = {'idle': module.IDLE_PLAN, 'handoff': module.HANDOFF_PLAN,
              'runner': module.digest(RUNNER.read_bytes())}
    values.update(changes)
    argv = [mode, '--apply', '--idle-plan-sha256', values['idle'],
            '--handoff-plan-sha256', values['handoff'], '--runner-sha256', values['runner']]
    if mode == '--run':
        argv += ['--nonce', 'd' * 64]
    return argv


def forbidden(*args, **kwargs):
    raise AssertionError('TEST_MUST_NOT_LAUNCH_OR_ACCESS_REAL_RETIREMENT')


def test_import_is_source_only(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    loaded = load_runner()
    assert callable(loaded.main)
    assert loaded.OUTPUT == ROOT / 'work/private/rx27a'


@pytest.mark.parametrize('mode', ['--launch', '--run'])
def test_explicit_argument_contract(runner, mode):
    args = runner.parse_args(arguments(runner, mode))
    assert args.apply is True
    assert args.idle_plan_sha256 == runner.IDLE_PLAN
    assert args.handoff_plan_sha256 == runner.HANDOFF_PLAN
    assert args.launch is (mode == '--launch')
    assert args.run is (mode == '--run')


@pytest.mark.parametrize('fault', ['apply', 'idle', 'handoff', 'runner-format', 'runner-missing',
                                  'both-modes', 'launch-nonce', 'run-no-nonce', 'run-bad-nonce'])
def test_missing_or_changed_authority_rejected_without_effects(runner, monkeypatch, fault):
    monkeypatch.setattr(runner, 'preflight', forbidden)
    monkeypatch.setattr(runner, 'private_directory', forbidden)
    monkeypatch.setattr(runner, 'launch', forbidden)
    monkeypatch.setattr(runner, 'run', forbidden)
    argv = arguments(runner, '--run' if fault.startswith('run-') else '--launch')
    if fault == 'apply': argv.remove('--apply')
    elif fault in {'idle', 'handoff'}:
        argv[argv.index('--' + fault + '-plan-sha256') + 1] = 'f' * 64
    elif fault == 'runner-format': argv[argv.index('--runner-sha256') + 1] = 'not-a-hash'
    elif fault == 'runner-missing':
        index = argv.index('--runner-sha256'); del argv[index:index + 2]
    elif fault == 'both-modes': argv += ['--run']
    elif fault == 'launch-nonce': argv += ['--nonce', 'd' * 64]
    elif fault == 'run-no-nonce': del argv[-2:]
    else: argv[-1] = 'invalid'
    with pytest.raises((runner.RunnerError, SystemExit)):
        runner.main(argv)


def test_nonisolated_process_refused_before_preflight(runner, monkeypatch):
    monkeypatch.setattr(runner, 'sys', SimpleNamespace(flags=SimpleNamespace(isolated=False),
                                                     dont_write_bytecode=True))
    monkeypatch.setattr(runner, 'preflight', forbidden)
    with pytest.raises(runner.RunnerError, match='ISOLATED_WINDOWS_NO_BYTECODE_REQUIRED'):
        runner.main(arguments(runner))


@pytest.fixture
def synthetic_preflight(runner, tmp_path, monkeypatch):
    root = tmp_path / 'source-fixture'; root.mkdir()
    monkeypatch.setattr(runner, 'ROOT', root)
    wrapper = root / 'runner.py'; wrapper.write_bytes(b'# synthetic runner bytes\n')
    monkeypatch.setattr(runner, '__file__', str(wrapper))
    source = root / 'preactivation.py'; source.write_bytes(b'# synthetic preactivation bytes\n')
    native = root / 'native.py'; native.write_bytes(b'# synthetic native bytes\n')
    for name, path in [('SOURCE', source), ('NATIVE', native)]:
        monkeypatch.setattr(runner, name, path)
        monkeypatch.setattr(runner, name + '_SHA', runner.digest(path.read_bytes()))
    bundle_root = root / 'bundle'; bundle_root.mkdir()
    code = {}
    for name in ('retirement_handoff.py', 'retirement_remote.py', 'preactivation_retirement.py',
                 'product_queue_transport.py'):
        raw = ('# synthetic ' + name + '\n').encode()
        (bundle_root / name).write_bytes(raw); code[name] = runner.digest(raw)
    monkeypatch.setattr(runner, 'HANDOFF', bundle_root / 'retirement_handoff.py')
    monkeypatch.setattr(runner, 'HANDOFF_SHA', code['retirement_handoff.py'])
    declaration = root / 'declaration'; declaration.mkdir()
    monkeypatch.setattr(runner, 'DECLARATION', declaration)
    release = {'schema_version': 3, 'hosted_runtime_configuration_sha256': 'c' * 64, 'code': code}
    release_raw = runner.canonical(release)
    monkeypatch.setattr(runner, 'R', runner.digest(release_raw))
    admission = {'current_release_sha256': runner.R, 'provider_configuration_sha256': 'c' * 64}
    admission_raw = runner.canonical(admission)
    monkeypatch.setattr(runner, 'D', runner.digest(admission_raw))
    (declaration / 'release.json').write_bytes(release_raw)
    (declaration / 'admission.json').write_bytes(admission_raw)
    idle_plan = {'scope': 'synthetic-idle-plan'}
    handoff_plan = {'destination': {'release_sha256': runner.R, 'configuration_sha256': runner.D}}
    monkeypatch.setattr(runner, 'IDLE_PLAN', runner.digest(runner.canonical(idle_plan)))
    monkeypatch.setattr(runner, 'HANDOFF_PLAN', runner.digest(runner.canonical(handoff_plan)))
    idle_review = {'closure_written': False, 'replay_attempted': False, 'reader_sha256': runner.SOURCE_SHA,
                   'observation': {'plan_sha256': runner.IDLE_PLAN, 'plan': idle_plan}}
    handoff_review = {'status': 'REVIEW_PLAN_ONLY', 'plan_sha256': runner.HANDOFF_PLAN,
        'plan': handoff_plan, 'reviewed_idle_plan_sha256': runner.IDLE_PLAN,
        'reader_sha256': runner.SOURCE_SHA, 'handoff_sha256': runner.HANDOFF_SHA,
        'closure_written': False, 'archive_exported': False, 'replay_attempted': False}
    for name, value in [('IDLE_REVIEW', idle_review), ('HANDOFF_REVIEW', handoff_review)]:
        path = root / (name.lower() + '.json'); path.write_bytes(runner.canonical(value))
        monkeypatch.setattr(runner, name, path)
    config = {'current_release_sha256': 'a' * 64, 'scope': 'synthetic-input-config'}
    config_path = root / 'work/product-operator-integrated-20261024a/runtime-configuration.input.json'
    config_path.parent.mkdir(parents=True)
    # Original reviewed input is pretty JSON; only the normalized config is pinned.
    config_path.write_text(json.dumps(config, indent=2), encoding='utf-8')
    config['current_release_sha256'] = runner.AUTHORITY_SHA
    monkeypatch.setattr(runner, 'CONFIG_SHA', runner.digest(runner.canonical(config)))
    monkeypatch.setattr(runner, 'private_directory', forbidden)
    monkeypatch.setattr(runner, 'load', forbidden)
    monkeypatch.setattr(runner.subprocess, 'Popen', forbidden)
    args = runner.parse_args(arguments(runner, runner=runner.digest(wrapper.read_bytes())))
    return SimpleNamespace(module=runner, args=args, root=root, code=code,
                           release=release, admission=admission, config_path=config_path)


def test_preflight_measures_every_pinned_input_without_execution(synthetic_preflight):
    test = synthetic_preflight
    result = test.module.preflight(test.args)
    assert result['runner_sha256'] == test.args.runner_sha256
    assert test.module.digest(result['release_raw']) == test.module.R
    assert test.module.digest(result['admission_raw']) == test.module.D
    assert test.module.digest(result['config_raw']) == test.module.CONFIG_SHA


@pytest.mark.parametrize('fault', ['runner', 'source', 'handoff', 'native', 'release', 'admission',
                                  'bundled-reader', 'idle-plan', 'handoff-plan', 'config'])
def test_changed_preflight_pin_rejected_before_effects(synthetic_preflight, fault):
    test, module = synthetic_preflight, synthetic_preflight.module
    paths = {'runner': Path(module.__file__), 'source': module.SOURCE, 'handoff': module.HANDOFF,
        'native': module.NATIVE, 'release': module.DECLARATION / 'release.json',
        'admission': module.DECLARATION / 'admission.json',
        'bundled-reader': module.HANDOFF.with_name('retirement_remote.py'),
        'idle-plan': module.IDLE_REVIEW, 'handoff-plan': module.HANDOFF_REVIEW, 'config': test.config_path}
    path = paths[fault]
    if fault in {'idle-plan', 'handoff-plan'}:
        value = json.loads(path.read_bytes()); value['closure_written'] = True
        path.write_bytes(module.canonical(value))
    else:
        path.write_bytes(path.read_bytes() + b'\n# changed')
    with pytest.raises((module.RunnerError, ValueError)):
        module.preflight(test.args)
    assert not (test.root / 'work/private').exists()


def bundle(members=(('evidence/data.json', b'{"synthetic":true}\n'),), attestation=b'{"synthetic":true}\n'):
    return SimpleNamespace(members=members, attestation_raw=attestation)


def test_zip_is_deterministic_private_regular_and_byte_exact(runner):
    value = bundle((('z/file.json', b'Z'), ('a/file.json', b'A')))
    first = runner.deterministic_zip(value)
    assert first == runner.deterministic_zip(value)
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert archive.namelist() == ['a/file.json', 'attestation.json', 'z/file.json']
        assert archive.testzip() is None
        assert archive.read('z/file.json') == b'Z'
        for item in archive.infolist():
            assert item.date_time == (1980, 1, 1, 0, 0, 0)
            assert item.compress_type == zipfile.ZIP_STORED
            assert stat.S_IFMT(item.external_attr >> 16) == stat.S_IFREG
            assert stat.S_IMODE(item.external_attr >> 16) == 0o600


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'a/../b', 'a//b', 'a/./b',
                                 'C:/drive', 'a\\b', 'trailing/', '', 'x' * 501, 'nul\x00suffix'])
def test_zip_rejects_unsafe_names(runner, name):
    with pytest.raises(runner.RunnerError):
        runner.deterministic_zip(bundle(((name, b'X'),)))


@pytest.mark.parametrize('fault', ['duplicate', 'reserved', 'empty', 'empty-data', 'text-data',
                                  'file-bound', 'total-bound', 'member-bound'])
def test_zip_rejects_bad_inventory_and_bounds(runner, monkeypatch, fault):
    value = bundle()
    if fault == 'duplicate': value.members = (('x', b'X'), ('x', b'Y'))
    elif fault == 'reserved': value.members = (('attestation.json', b'X'),)
    elif fault == 'empty': value.members = ()
    elif fault == 'empty-data': value.members = (('x', b''),)
    elif fault == 'text-data': value.members = (('x', 'text'),)
    elif fault == 'file-bound': monkeypatch.setattr(runner, 'MAX_FILE', 2)
    elif fault == 'total-bound': monkeypatch.setattr(runner, 'MAX_TOTAL', 2)
    else: monkeypatch.setattr(runner, 'MAX_MEMBERS', 1)
    with pytest.raises(runner.RunnerError):
        runner.deterministic_zip(value)


def test_create_only_output_refuses_replay_and_preserves_bytes(runner, tmp_path):
    path = tmp_path / 'once.json'
    runner.private_write(path, b'original')
    with pytest.raises(runner.RunnerError, match='OUTPUT_EXISTS_NO_REPLAY'):
        runner.private_write(path, b'replacement')
    assert path.read_bytes() == b'original'


@pytest.mark.skipif(os.name != 'nt', reason='actual Windows private temporary directory')
def test_windows_private_output_has_real_owner_only_acl(runner, tmp_path):
    path = tmp_path / 'owner-only'
    runner.private_directory(path)
    runner.private_write(path / 'synthetic.json', b'{"synthetic":true}\n')
    checker = runner.load('_test_runner_acl_check', runner.SOURCE, runner.SOURCE_SHA)
    checker.private_inputs([path, path / 'synthetic.json'])
    with pytest.raises(runner.RunnerError, match='FRESH_PRIVATE_DESTINATION_REQUIRED'):
        runner.private_directory(path)
    assert (path / 'synthetic.json').read_bytes() == b'{"synthetic":true}\n'


@pytest.mark.skipif(os.name != 'nt', reason='actual Windows current-process native identity')
def test_native_identity_queries_current_owned_process_only(runner):
    first = runner.process_identity(os.getpid())
    assert set(first) == {'pid', 'created_ticks', 'executable'}
    assert first['pid'] == os.getpid() and first['created_ticks'] > 0
    assert first == runner.process_identity(os.getpid())
    assert Path(first['executable']).is_file()


@pytest.mark.skipif(os.name != 'nt', reason='actual Windows venv redirector child identity')
def test_minimal_hidden_python_child_preserves_executable_and_parent_identity():
    # This is not the retirement runner: no context import, files, network,
    # closure or export. Its only effect is printing this child identity.
    script = ('import json,os,sys;print(json.dumps({"pid":os.getpid(),'
              '"parent_pid":os.getppid(),"executable":sys.executable}))')
    with subprocess.Popen([sys.executable, '-I', '-B', '-c', script],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW) as child:
        try:
            stdout, stderr = child.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(timeout=10)
            pytest.fail('Owned synthetic identity child timed out')
        assert child.returncode == 0 and not stderr
        assert 0 < len(stdout) <= 4096
        identity = json.loads(stdout)
        assert set(identity) == {'pid', 'parent_pid', 'executable'}
        assert identity['executable'] == sys.executable
        assert child.pid in {identity['pid'], identity['parent_pid']}


@pytest.fixture
def synthetic_flow(runner, tmp_path, monkeypatch):
    # Reuse the full genuine synthetic C/F/G archive validator fixture, not a
    # mock-positive validate_bundle. The context/export remain simulated IO.
    from qa.operator.tests import test_retirement_handoff as fixture
    case = fixture.case.__wrapped__(tmp_path, monkeypatch)
    attestation = fixture.finalize(case)
    output = tmp_path / 'runner-output'; output.mkdir()
    plan = deepcopy(case['value']['plan'])
    monkeypatch.setattr(runner, 'HANDOFF_PLAN', runner.digest(runner.canonical(plan)))
    monkeypatch.setattr(runner, 'R', case['destination']['release_sha256'])
    monkeypatch.setattr(runner, 'D', case['destination']['configuration_sha256'])
    actual_bundle = fixture.h.RetirementBundle(attestation, tuple(sorted(case['members'].items())))
    events = []
    state = SimpleNamespace(held=False, closed=0, exported=0, fault=None)

    class Context:
        @contextmanager
        def hold(self):
            assert not state.held
            state.held = True; events.append('hold')
            try: yield self
            finally: state.held = False; events.append('release')

        def close_idle_under_lock(self, *, apply, authorized_plan_sha256):
            assert state.held and apply is True and authorized_plan_sha256 == runner.IDLE_PLAN
            state.closed += 1; events.append('close')
            assert state.closed == 1, 'UNCERTAIN_CLOSURE_MUST_NOT_BE_REPLAYED'
            if state.fault == 'closure': raise RuntimeError('SYNTHETIC_CLOSURE_OUTCOME_UNCONFIRMED')
            return {'status': 'INTERRUPTED_IDLE_CLOSED', 'successful_native_exit_confirmed': False,
                'human_acceptance_recorded': False, 'automatic_replay_permitted': False,
                'closure_sha256': 'e' * 64}

    class Handoff:
        def retirement_plan(self, context, **kwargs):
            assert state.held and kwargs == {'destination_manifest_raw': case['members']['destination/manifest.json'],
                'destination_configuration_raw': case['members']['destination/configuration.json']}
            events.append('plan')
            return {**plan, 'changed': True} if state.fault == 'plan' else deepcopy(plan)

        def export_retirement_under_lock(self, context, *, authorized_plan_sha256, **kwargs):
            assert state.held and state.closed == 1 and authorized_plan_sha256 == runner.HANDOFF_PLAN
            assert kwargs == {'destination_manifest_raw': case['members']['destination/manifest.json'],
                'destination_configuration_raw': case['members']['destination/configuration.json']}
            state.exported += 1; events.append('export')
            if state.fault == 'export': raise RuntimeError('SYNTHETIC_EXPORT_OUTCOME_UNCONFIRMED')
            return actual_bundle

        def validate_bundle(self, *args, **kwargs):
            assert state.held
            events.append('validate')
            return fixture.h.validate_bundle(*args, **kwargs)

    return SimpleNamespace(runner=runner, output=output, plan=plan, state=state, events=events,
        context=Context(), handoff=Handoff(), bundle=actual_bundle,
        material={'release_raw': case['members']['destination/manifest.json'],
                  'admission_raw': case['members']['destination/configuration.json'], 'reviewed_plan': plan})


def test_once_only_closure_export_checks_real_synthetic_bundle(synthetic_flow):
    test = synthetic_flow
    result = test.runner.close_and_export(test.context, test.handoff, test.material, test.runner.Records(test.output))
    assert result['status'] == 'RETIREMENT_EXPORTED'
    assert result['closure_status'] == result['export_status'] == 'CONFIRMED'
    assert result['automatic_replay_permitted'] is result['human_acceptance_recorded'] is result['deployment_authorized'] is False
    assert test.events == ['hold', 'plan', 'close', 'export', 'validate', 'release']
    assert test.runner.digest((test.output / 'retirement.zip').read_bytes()) == result['archive_sha256']
    assert (test.output / 'attestation.json').read_bytes() == test.bundle.attestation_raw
    again = test.runner.close_and_export(test.context, test.handoff, test.material, test.runner.Records(test.output))
    assert again['status'] == 'ATTENTION'
    assert test.state.closed == test.state.exported == 1


@pytest.mark.parametrize('fault', ['plan', 'closure', 'export'])
def test_unknown_or_changed_outcome_is_not_replayed(synthetic_flow, fault):
    test = synthetic_flow; test.state.fault = fault
    result = test.runner.close_and_export(test.context, test.handoff, test.material, test.runner.Records(test.output))
    assert result['status'] == 'ATTENTION'
    assert result['automatic_replay_permitted'] is False
    assert not (test.output / 'retirement.zip').exists()
    assert result['closure_status'] == {'plan': 'NOT_ATTEMPTED', 'closure': 'OUTCOME_UNCONFIRMED', 'export': 'CONFIRMED'}[fault]
    assert result['export_status'] == ('OUTCOME_UNCONFIRMED' if fault == 'export' else 'NOT_ATTEMPTED')
    first_counts = (test.state.closed, test.state.exported)
    again = test.runner.close_and_export(test.context, test.handoff, test.material, test.runner.Records(test.output))
    assert again['status'] == 'ATTENTION' and again['automatic_replay_permitted'] is False
    assert (test.state.closed, test.state.exported) == first_counts
    assert not test.state.held


def test_partial_archive_write_preserves_unknown_outcome_without_retry(synthetic_flow, monkeypatch):
    test = synthetic_flow
    original = test.runner.private_write
    def interrupted(path, raw):
        if path.name == 'retirement.zip':
            original(path, raw[:10])
            raise OSError('synthetic disk interruption')
        return original(path, raw)
    monkeypatch.setattr(test.runner, 'private_write', interrupted)
    result = test.runner.close_and_export(test.context, test.handoff, test.material, test.runner.Records(test.output))
    assert result['status'] == 'ATTENTION' and result['closure_status'] == 'CONFIRMED'
    assert result['export_status'] == 'OUTCOME_UNCONFIRMED'
    assert (test.output / 'retirement.zip').stat().st_size == 10
    assert not (test.output / 'attestation.json').exists()
    assert test.state.closed == test.state.exported == 1


@pytest.fixture
def synthetic_launcher(runner, tmp_path, monkeypatch):
    """Actual private files/ACL; only process creation/native identity are fake."""
    if os.name != 'nt':
        pytest.skip('launcher uses actual Windows owner-only temporary ACL')
    root = tmp_path / 'launcher'; (root / 'work/private').mkdir(parents=True)
    monkeypatch.setattr(runner, 'ROOT', root)
    monkeypatch.setattr(runner, 'OUTPUT', root / 'work/private/rx27a')
    args = runner.parse_args(arguments(runner))
    material = {'review_sha256': {'idle': '1' * 64, 'handoff': '2' * 64},
                'config_raw': b'{"synthetic":true}\n'}
    original_popen, original_load = subprocess.Popen, runner.load
    calls = []
    state = SimpleNamespace(fail_launch=False, wrong_identity=False)

    @dataclass(frozen=True)
    class Identity:
        pid: int
        created_ticks: int
        executable: str

    identity = Identity(os.getpid(), 1234567, 'c:\\synthetic\\python.exe')
    child = SimpleNamespace(wait=forbidden, communicate=forbidden)

    class Owned:
        def __enter__(self): calls.append(('owned-enter',)); return self
        def __exit__(self, *_): calls.append(('owned-exit',))
        def identity(self): return identity
        def poll(self): calls.append(('poll-once',)); return None
        wait = forbidden

    def fake_popen(argv, **kwargs):
        # The real fixed ACL helper is allowed; the retirement worker never is.
        if Path(argv[0]).name.lower() in {'powershell', 'powershell.exe'}:
            return original_popen(argv, **kwargs)
        assert argv[0] == sys.executable and '--run' in argv
        assert (runner.OUTPUT / 'dispatch-intent.json').is_file()
        intent = runner.parse((runner.OUTPUT / 'dispatch-intent.json').read_bytes())
        assert runner.digest(runner.canonical(argv)) == intent['argv_sha256']
        assert not (runner.OUTPUT / 'dispatch.json').exists()
        calls.append(('popen', list(argv), kwargs, intent))
        if state.fail_launch:
            raise OSError('synthetic launch failed')
        return child

    def duplicate(value):
        assert value is child
        calls.append(('duplicate-exact-popen',))
        return Owned()

    def loader(name, path, expected):
        if name == '_runner_native_launch':
            assert path == runner.NATIVE and expected == runner.NATIVE_SHA
            return SimpleNamespace(duplicate_popen_handle=duplicate)
        loaded = original_load(name, path, expected)
        if name == '_runner_reviewed_preactivation':
            # Negative worker-binding tests must fail before this real-world
            # boundary; retaining a fail-fast spy prevents accidental contact.
            loaded.open_context = forbidden
        return loaded

    def process(pid):
        assert pid in {os.getpid(), os.getppid()}
        return {'pid': pid, 'created_ticks': identity.created_ticks + int(state.wrong_identity),
                'executable': identity.executable}

    monkeypatch.setattr(runner.subprocess, 'Popen', fake_popen)
    monkeypatch.setattr(runner, 'load', loader)
    monkeypatch.setattr(runner, 'process_identity', process)
    return SimpleNamespace(runner=runner, args=args, material=material, calls=calls, state=state)


def test_launcher_persists_intent_then_hidden_once_only_owned_dispatch(synthetic_launcher):
    test = synthetic_launcher; module = test.runner
    result = module.launch(test.args, test.material)
    created = [row for row in test.calls if row[0] == 'popen']
    assert len(created) == 1
    _, argv, kwargs, intent = created[0]
    assert argv[:5] == [sys.executable, '-I', '-B', str(RUNNER.absolute()), '--run']
    assert '--apply' in argv
    assert argv[argv.index('--idle-plan-sha256') + 1] == module.IDLE_PLAN
    assert argv[argv.index('--handoff-plan-sha256') + 1] == module.HANDOFF_PLAN
    assert argv[argv.index('--runner-sha256') + 1] == test.args.runner_sha256
    assert argv[argv.index('--nonce') + 1] == intent['nonce'] and len(intent['nonce']) == 64
    assert kwargs['creationflags'] == subprocess.CREATE_NO_WINDOW
    assert kwargs['stdin'] == subprocess.DEVNULL and kwargs['cwd'] == module.ROOT
    assert kwargs['env']['PYTHONDONTWRITEBYTECODE'] == '1'
    assert Path(kwargs['stdout'].name) == module.OUTPUT / 'stdout.log'
    assert Path(kwargs['stderr'].name) == module.OUTPUT / 'stderr.log'
    assert kwargs['stdout'].closed and kwargs['stderr'].closed
    assert [row[0] for row in test.calls] == ['popen', 'duplicate-exact-popen', 'owned-enter', 'poll-once', 'owned-exit']
    dispatch = module.parse((module.OUTPUT / 'dispatch.json').read_bytes())
    assert dispatch['intent_sha256'] == module.digest(module.canonical(intent))
    assert dispatch['exit_code_at_dispatch'] is None
    assert result['wrapper'] == dispatch['wrapper']
    assert result['status'] == 'DISPATCHED' and result['completion_not_confirmed'] is True
    assert result['automatic_replay_permitted'] is False


def test_existing_output_blocks_second_launch_before_popen(synthetic_launcher):
    test = synthetic_launcher; module = test.runner
    module.launch(test.args, test.material)
    before = {path.name: path.read_bytes() for path in module.OUTPUT.iterdir() if path.is_file()}
    with pytest.raises(module.RunnerError, match='FRESH_PRIVATE_DESTINATION_REQUIRED'):
        module.launch(test.args, test.material)
    assert len([row for row in test.calls if row[0] == 'popen']) == 1
    assert before == {path.name: path.read_bytes() for path in module.OUTPUT.iterdir() if path.is_file()}


def test_launch_failure_retains_intent_and_cannot_be_replayed(synthetic_launcher):
    test = synthetic_launcher; module = test.runner
    test.state.fail_launch = True
    with pytest.raises(OSError, match='synthetic launch failed'):
        module.launch(test.args, test.material)
    intent = (module.OUTPUT / 'dispatch-intent.json').read_bytes()
    assert not (module.OUTPUT / 'dispatch.json').exists()
    with pytest.raises(module.RunnerError, match='FRESH_PRIVATE_DESTINATION_REQUIRED'):
        module.launch(test.args, test.material)
    assert (module.OUTPUT / 'dispatch-intent.json').read_bytes() == intent
    assert len([row for row in test.calls if row[0] == 'popen']) == 1


@pytest.mark.parametrize('fault,code', [('nonce', 'DISPATCH_INTENT_CHANGED'),
    ('scope', 'DISPATCH_INTENT_CHANGED'), ('argv', 'DISPATCH_INTENT_CHANGED'),
    ('parent', 'OWNED_WORKER_PARENT_CHANGED'), ('dispatch', 'OWNED_DISPATCH_NOT_LIVE'),
    ('identity', 'OWNED_WORKER_PARENT_CHANGED')])
def test_worker_rejects_changed_binding_before_context(synthetic_launcher, fault, code):
    test = synthetic_launcher; module = test.runner
    module.launch(test.args, test.material)
    intent = module.parse((module.OUTPUT / 'dispatch-intent.json').read_bytes())
    dispatch_path = module.OUTPUT / 'dispatch.json'
    dispatch = module.parse(dispatch_path.read_bytes())
    argv = arguments(module, '--run'); argv[-1] = intent['nonce']
    args = module.parse_args(argv)
    if fault == 'nonce': args.nonce = '0' * 64
    elif fault in {'scope', 'argv'}:
        if fault == 'scope': intent['scope'] = 'synthetic-unknown-dispatch'
        else: intent['argv_sha256'] = '0' * 64
        raw = module.canonical(intent)
        (module.OUTPUT / 'dispatch-intent.json').write_bytes(raw)
        # Keep the dispatch link internally consistent: the new exact scope/
        # child-argv gate, not a stale intent hash, must reject this mutation.
        dispatch['intent_sha256'] = module.digest(raw)
        dispatch_path.write_bytes(module.canonical(dispatch))
    elif fault == 'parent':
        dispatch['wrapper']['pid'] = max(os.getpid(), os.getppid()) + 100000
        dispatch_path.write_bytes(module.canonical(dispatch))
    elif fault == 'dispatch':
        dispatch['exit_code_at_dispatch'] = 0
        dispatch_path.write_bytes(module.canonical(dispatch))
    else: test.state.wrong_identity = True
    with pytest.raises(module.RunnerError, match=code):
        module.run(args, test.material)
    assert not (module.OUTPUT / 'worker.json').exists()
    assert not list(module.OUTPUT.glob('p*.json'))
    assert not (module.OUTPUT / 'closure.json').exists()
    assert not (module.OUTPUT / 'retirement.zip').exists()
