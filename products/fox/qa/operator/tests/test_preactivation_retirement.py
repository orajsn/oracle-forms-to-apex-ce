"""Synthetic local tests only. Source composition is real; no remote dispatch.

Tests deliberately replace observation boundaries only in synthetic fixtures.
Production open_context exposes no callback, PID-probe, or lease injection.
"""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
PATH = ROOT / 'qa/operator/preactivation_retirement.py'
SPEC = importlib.util.spec_from_file_location('_preactivation_test', PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
AUTHORITY = ROOT / 'work/product-operator-integrated-20261024a/operator-release-i'


@pytest.fixture
def tmp_path(tmp_path_factory):
    # Keep the frozen journal's portable path bound intact on Windows.
    return tmp_path_factory.mktemp('p')


def arguments():
    authority_sha = M.sha((AUTHORITY / 'current-release-manifest.json').read_bytes())
    config = json.loads((ROOT / 'work/product-operator-integrated-20261024a/runtime-configuration.input.json').read_bytes())
    config['current_release_sha256'] = authority_sha
    raw = M.canonical(config)
    return dict(workspace=ROOT, authority_root=AUTHORITY, expected_authority_sha256=authority_sha,
        configuration_raw=raw, expected_configuration_sha256=M.sha(raw), expected_source_sha256=M.sha(PATH.read_bytes()))


@pytest.fixture
def context(monkeypatch):
    if os.name != 'nt':
        pytest.skip('The real frozen G source context requires Windows')
    # Pytest may also import this fixture through its package-qualified name.
    # Bind this fixture's actual module, not another copy with the same alias.
    monkeypatch.setitem(sys.modules, SPEC.name, M)
    prefixes = ('qa', 'fox', 'forms2apex')
    names = lambda name: any(name == prefix or name.startswith(prefix + '.') for prefix in prefixes)
    saved = {name: value for name, value in sys.modules.items() if names(name)}
    for name in saved:
        sys.modules.pop(name)
    monkeypatch.setattr(sys, 'dont_write_bytecode', True)
    def forbidden(*args, **kwargs):
        raise AssertionError('SYNTHETIC_TEST_EXTERNAL_ACTION_FORBIDDEN')
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    try:
        with M.open_context(**arguments()) as result:
            monkeypatch.setattr(result.components.clean, 'oci_scope', forbidden)
            monkeypatch.setattr(result.components.clean, 'ssh_json', forbidden)
            yield result
    finally:
        for name in tuple(sys.modules):
            if names(name):
                sys.modules.pop(name)
        sys.modules.update(saved)


def test_source_only_real_g_composition(context):
    assert context.release == M.G_RELEASE
    assert context.authority_release != context.release
    assert context.idle_reader.remote.runtime_release == M.G_RELEASE
    assert context.idle_reader.native._test_open is None
    assert context.qa_provider is context.components.qa
    assert context.components.resolver.privacy_check is M.private_inputs
    assert context.current is context.journals['idle']
    assert context.current._historical == (context.journals['failure'], context.journals['retry'])
    assert len(context.source_files()) >= 130
    assert context.idle_reader.remote.runtime_manifest == context.manifest
    assert sys.modules['qa.operator.preactivation_retirement'].PreActivationRetirementContext is M.PreActivationRetirementContext
    assert all(not journal._held for journal in context.journals.values())


def test_generated_remote_sources_compile_and_pin_g(context):
    helper = context.helpers['idle_remote']
    source = helper.container_source(context.components.bridge, context.release)
    host = helper.host_source(context.components.bridge, context.components.clean, context.release)
    compile(source, '<synthetic-review-container>', 'exec')
    compile(host, '<synthetic-review-host>', 'exec')
    assert "os.environ.get('FOX_VERIFIER_RELEASE_SHA256')==request['release_sha256']" in source
    assert "value['apply'] is False" in source
    assert "db.execute('PRAGMA query_only=ON')" in source
    assert M.G_RELEASE in source
    assert context.authority_release not in source


def test_no_lease_boolean_can_authorize_read(context):
    context._held = True
    for journal in context.journals.values():
        journal._held = True
    with pytest.raises(M.PreActivationError, match='ACTUAL_LEASE'):
        context._leases()


def test_no_implicit_closure(context):
    for value in (False, None, 1, 'true'):
        with pytest.raises(M.PreActivationError, match='EXPLICIT_REVIEWED_PLAN'):
            context.close_idle_under_lock(apply=value, authorized_plan_sha256='a' * 64)


def test_closure_hash_required(context):
    with pytest.raises(M.PreActivationError, match='EXPLICIT_REVIEWED_PLAN'):
        context.close_idle_under_lock(apply=True)


def test_context_does_not_expose_pump_or_callback_injection():
    import inspect
    signature = inspect.signature(M.open_context)
    assert not {'native', 'observer', 'executor', 'transport', '_open_process', 'lease'} & set(signature.parameters)
    assert not hasattr(M.PreActivationRetirementContext, 'pump')


def test_non_factory_construction_rejected():
    with pytest.raises(M.PreActivationError, match='FACTORY_REQUIRED'):
        M.PreActivationRetirementContext(None, workspace=None, source_root=None, authority_root=None,
            authority_raw=None, configuration_raw=None, source_files=None, helpers=None)


def test_native_test_hook_rejected(context):
    context.idle_reader.native._test_open = lambda _: None
    with pytest.raises(M.PreActivationError, match='REAL_OBSERVERS_REQUIRED'):
        context.ready()


def test_privacy_always_true_rejected(context, monkeypatch):
    monkeypatch.setattr(context.components.product.promotion, 'private_inputs', lambda _: True)
    with pytest.raises(M.PreActivationError, match='REAL_OBSERVERS_REQUIRED'):
        context.ready()


def test_resolver_captured_or_replaced_privacy_callback_rejected(context, monkeypatch):
    monkeypatch.setattr(context.components.resolver, 'privacy_check', lambda _: True)
    with pytest.raises(M.PreActivationError, match='REAL_OBSERVERS_REQUIRED'):
        context.ready()


def test_current_g_configuration_drift_rejected(context):
    context.configuration['current_release_sha256'] = context.authority_release
    with pytest.raises(M.PreActivationError, match='CONFIGURATION_CHANGED'):
        context.ready()


@pytest.mark.parametrize('name', ['../x', '/x', 'x/../y', 'x//y', 'C:/x', 'x\\y'])
def test_unsafe_source_names_rejected(name):
    with pytest.raises(M.PreActivationError):
        M.relative(name)


@pytest.mark.parametrize('raw', [b'{"a":1,"a":1}\n', b'{"a": 1}\n', b'{"a":1}'])
def test_json_must_be_unique_and_canonical(raw):
    with pytest.raises(M.PreActivationError):
        M.parse(raw)


@pytest.fixture
def synthetic_journals(context, tmp_path, monkeypatch):
    api = context.components.product
    private = tmp_path / 'p'
    private.mkdir()
    root = private / 'j'
    root.mkdir()
    # These replacements exist only in the test's synthetic root.
    monkeypatch.setattr(api.clean, 'PRIVATE', private)
    monkeypatch.setattr(api, 'JOURNAL_ROOT', root)
    monkeypatch.setattr(api.promotion, 'private_inputs', lambda _: None)
    monkeypatch.setattr(api.clean, 'private_directory', lambda path: path.mkdir(mode=0o700))
    context.journals = {role: api.PrivateJournal(entry['release_sha256']) for role, entry in context.history.items()}
    context.current = context.journals['idle']
    context.current._historical = (context.journals['failure'], context.journals['retry'])
    for journal in context.journals.values():
        journal.root.mkdir()
        (journal.root / 'release.json').write_bytes(M.canonical({
            'scope': 'fox-product-verifier-journal-v1', 'release_sha256': journal.release}))
        (journal.root / 'worker.lock').write_bytes(b'0')
    return context


def test_real_three_os_leases(synthetic_journals):
    context = synthetic_journals
    before = {p: p.read_bytes() for p in context.components.product.JOURNAL_ROOT.rglob('*') if p.is_file()}
    with ExitStack() as stack:
        for journal in sorted(context.journals.values(), key=lambda j: str(j.root)):
            stack.enter_context(journal._lock_one(existing=True))
        context._held = True
        context._leases()
    context._held = False
    assert all(journal._held is False for journal in context.journals.values())
    assert before == {p: p.read_bytes() for p in context.components.product.JOURNAL_ROOT.rglob('*') if p.is_file()}


def test_missing_lock_is_not_created(synthetic_journals):
    journal = synthetic_journals.current
    lock = journal.root / 'worker.lock'
    lock.unlink()  # synthetic test tree only
    with pytest.raises(Exception, match='HISTORY_LOCK_MISSING'):
        with journal._lock_one(existing=True):
            pytest.fail('missing lock must not admit')
    assert not lock.exists()


def test_unknown_journal_release_blocks(synthetic_journals):
    context = synthetic_journals
    (context.components.product.JOURNAL_ROOT / ('f' * 16)).mkdir()
    with pytest.raises(Exception, match='UNRECOGNIZED_JOURNAL_RELEASE'):
        context.current._check_history_inventory()


def test_actual_parser_does_not_promote_unmatched_intent(synthetic_journals):
    context = synthetic_journals
    api, journal, idle = context.components.product, context.current, context.helpers['idle_recovery']
    with ExitStack() as stack:
        for item in sorted(context.journals.values(), key=lambda j: str(j.root)):
            stack.enter_context(item._lock_one(existing=True))
        directory = journal.new({'max_jobs': 2, 'max_polls': 3, 'max_seconds': 100, 'poll_seconds': 1})
        intent = journal.intent(directory, 'p0001-claim')
        journal.completed(directory, 'p0001-claim', intent, {'status': 'IDLE'})
        result = idle.transcript(api, journal, directory, context.manifest, admission_journal=journal)
        assert result['claim_count'] == 1
        journal.intent(directory, 'p0002-claim')
        with pytest.raises(Exception, match='IDLE_UNMATCHED_OPERATION'):
            idle.transcript(api, journal, directory, context.manifest, admission_journal=journal)
        assert not (directory / 'closed-idle.json').exists()


def test_absence_and_idle_without_original_a1_are_insufficient(synthetic_journals, monkeypatch):
    context = synthetic_journals
    for role, journal in context.journals.items():
        (journal.root / context.history[role]['session_id']).mkdir()
    monkeypatch.setattr(context, 'require_active', lambda: None)
    monkeypatch.setattr(context.components.resolver, '_validated_closed_under_lock', lambda _: {
        'status': 'FAILED_QA_RECORDED', 'disposition_sha256': context.history['failure']['disposition_sha256']})
    monkeypatch.setattr(context.helpers['idle_recovery'], 'transcript', lambda *a, **kw: {'completed_jobs': []})
    with pytest.raises(M.PreActivationError, match='ORIGINAL_A1_REQUIRED'):
        context._transcript()


def test_empty_directory_drift_is_not_invisible(synthetic_journals, monkeypatch):
    context = synthetic_journals
    monkeypatch.setattr(M, 'private_inputs', lambda _: None)
    for role, journal in context.journals.items():
        (journal.root / context.history[role]['session_id']).mkdir()
    with ExitStack() as stack:
        for journal in sorted(context.journals.values(), key=lambda j: str(j.root)):
            stack.enter_context(journal._lock_one(existing=True))
        context._held = True
        assert context._journal_bytes()
        directory = context.current.root / context.history['idle']['session_id'] / 'unexpected-empty'
        directory.mkdir()
        with pytest.raises(M.PreActivationError, match='JOURNAL_DIRECTORY_FORBIDDEN'):
            context._journal_bytes()
    context._held = False


def test_journal_inventory_reads_actual_owning_lock_fds_without_unlocking(synthetic_journals, monkeypatch):
    context = synthetic_journals
    monkeypatch.setattr(M, 'private_inputs', lambda _: None)
    for role, journal in context.journals.items():
        (journal.root / context.history[role]['session_id']).mkdir()
    before = {path: path.read_bytes() for path in context.components.product.JOURNAL_ROOT.rglob('*') if path.is_file()}
    with ExitStack() as stack:
        for journal in sorted(context.journals.values(), key=lambda j: str(j.root)):
            stack.enter_context(journal._lock_one(existing=True))
        context._held = True
        positions = {role: journal._held._stream.tell() for role, journal in context.journals.items()}
        if os.name == 'nt':
            # This is the actual Windows failure mode found in the read-only
            # live diagnosis, reproduced with synthetic files and real locks.
            for journal in context.journals.values():
                with pytest.raises(PermissionError):
                    (journal.root / 'worker.lock').read_bytes()
        for role, journal in context.journals.items():
            fd = os.fstat(journal._held._stream.fileno())
            path = (journal.root / 'worker.lock').stat()
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_nlink')
            assert tuple(getattr(fd, key) for key in fields) == tuple(getattr(path, key) for key in fields), role
        observed = context._journal_bytes()
        for role, journal in context.journals.items():
            assert observed[role + '/worker.lock'] == M.sha(b'0')
            assert journal._held._stream.tell() == positions[role]
            journal._held.require_active(journal.release, journal.root)
        assert len(observed) == 6
    context._held = False
    assert before == {path: path.read_bytes() for path in before}
    with pytest.raises(M.PreActivationError, match='ACTUAL_HOLD'):
        context._journal_bytes()


def test_released_or_foreign_lock_cannot_supply_inventory_bytes(synthetic_journals):
    context = synthetic_journals
    journal = context.current
    with pytest.raises(M.PreActivationError, match='ACTUAL_LEASE'):
        context._held_lock_bytes(journal)
    with journal._lock_one(existing=True):
        lease = journal._held
        expected = lease._release
        lease._release = 'f' * 64
        with pytest.raises(Exception, match='ACTIVE_MATCHING_OPERATOR_LEASE'):
            context._held_lock_bytes(journal)
        lease._release = expected
        lease._active = False
        with pytest.raises(Exception, match='ACTIVE_MATCHING_OPERATOR_LEASE'):
            context._held_lock_bytes(journal)
        lease._active = True


@pytest.fixture
def synthetic_closure(tmp_path, monkeypatch):
    # Pure closure-state machine tests, explicitly not a live-capable context.
    context = object.__new__(M.PreActivationRetirementContext)
    context.release, context.authority_release = M.G_RELEASE, 'a' * 64
    context.configuration_sha256, context.bound_container_id = 'b' * 64, 'c' * 64
    context.history = {'idle': {'session_id': 'session-' + 'd' * 24, 'release_sha256': M.G_RELEASE}}
    directory = tmp_path / context.history['idle']['session_id']
    directory.mkdir()
    value = {'session_id': directory.name, 'release_sha256': M.G_RELEASE, 'claim_count': 2,
        'completed_jobs': [{'binding': {'job_id': M.A1['job_id'], 'package_sha256': M.A1['package_sha256'],
            'source_manifest_sha256': 'e' * 64, 'verifier_release_sha256': M.G_RELEASE},
            'proof_sha256': M.A1['proof_sha256']}], 'retained_sha256': {'session.json': 'f' * 64}}
    native_identity = {'source_sha256': '1' * 64, 'verifier_release_sha256': M.G_RELEASE,
        'native_profile': 'recorded-legacy-g-v1', 'attempt_id': None, 'retained_sha256': {'source.json': '2' * 64}}
    counts = {'observe': 0, 'write': 0}
    def observe(_):
        counts['observe'] += 1
        native = {**native_identity, 'observed_at_utc': datetime.now(timezone.utc).isoformat()}
        return {'native_before': native, 'native_after': dict(native),
                'remote': {'observed_at_utc': native['observed_at_utc']}}
    def write(path, name, obj):
        counts['write'] += 1
        with (path / name).open('xb') as stream:
            stream.write(M.canonical(obj))
    context.current = SimpleNamespace(write=write, raw=lambda p, name: (p / name).read_bytes())
    native = SimpleNamespace(retained_identity=lambda _: deepcopy(native_identity))
    context.idle_reader = SimpleNamespace(directory=directory, native=native, _read_under_lock=lambda: None)
    context.source_files = lambda: {'preactivation/preactivation_retirement.py': b'synthetic only'}
    context.require_active = lambda: None
    context._transcript = lambda: deepcopy(value)
    context._observe, context._closed_once = observe, False
    monkeypatch.setattr(M, 'private_inputs', lambda paths: None)
    return SimpleNamespace(context=context, directory=directory, counts=counts, value=value)


def test_review_plan_is_read_only(synthetic_closure):
    h = synthetic_closure
    result = h.context.plan_under_lock()
    assert result['plan_sha256'] == M.sha(M.canonical(result['plan']))
    assert h.counts == {'observe': 1, 'write': 0}
    assert list(h.directory.iterdir()) == []


def test_wrong_authorized_plan_never_writes(synthetic_closure):
    h = synthetic_closure
    with pytest.raises(M.PreActivationError, match='PLAN_NOT_AUTHORIZED'):
        h.context.close_idle_under_lock(apply=True, authorized_plan_sha256='0' * 64)
    assert h.counts['write'] == 0


def test_explicit_additive_closure_never_claims_clean_exit(synthetic_closure):
    h = synthetic_closure
    plan = h.context.plan_under_lock()
    result = h.context.close_idle_under_lock(apply=True, authorized_plan_sha256=plan['plan_sha256'])
    closure = M.parse((h.directory / 'closed-idle.json').read_bytes())
    assert closure['scope'] == M.CLOSURE_SCOPE
    assert closure['source_context'] == M.SOURCE_CONTEXT
    assert closure['authorized_plan_sha256'] == plan['plan_sha256']
    assert result['successful_native_exit_confirmed'] is result['human_acceptance_recorded'] is False
    assert closure['automatic_replay_permitted'] is False
    assert h.counts == {'observe': 2, 'write': 1}
    with pytest.raises(M.PreActivationError, match='EXISTING_CLOSURE_READ_ONLY'):
        h.context.close_idle_under_lock(apply=True, authorized_plan_sha256=plan['plan_sha256'])
    assert h.counts['write'] == 1


def test_fresh_observation_failure_never_closes(synthetic_closure):
    h = synthetic_closure
    plan = h.context.plan_under_lock()
    def failed(_):
        raise M.PreActivationError('SYNTHETIC_REMOTE_UNRESOLVED_WORK')
    h.context._observe = failed
    with pytest.raises(M.PreActivationError, match='REMOTE_UNRESOLVED'):
        h.context.close_idle_under_lock(apply=True, authorized_plan_sha256=plan['plan_sha256'])
    assert h.counts['write'] == 0


def test_transcript_change_invalidates_reviewed_plan(synthetic_closure):
    h = synthetic_closure
    plan = h.context.plan_under_lock()
    h.value['claim_count'] += 1
    with pytest.raises(M.PreActivationError, match='PLAN_NOT_AUTHORIZED'):
        h.context.close_idle_under_lock(apply=True, authorized_plan_sha256=plan['plan_sha256'])
    assert h.counts['write'] == 0


def test_unknown_write_outcome_is_not_replayed(synthetic_closure):
    h = synthetic_closure
    plan = h.context.plan_under_lock()
    def uncertain(*args):
        raise OSError('synthetic uncertain write')
    h.context.current.write = uncertain
    with pytest.raises(OSError):
        h.context.close_idle_under_lock(apply=True, authorized_plan_sha256=plan['plan_sha256'])
    with pytest.raises(M.PreActivationError, match='EXISTING_CLOSURE_READ_ONLY'):
        h.context.close_idle_under_lock(apply=True, authorized_plan_sha256=plan['plan_sha256'])


def test_no_startup_admission_capability(synthetic_closure):
    with pytest.raises(M.PreActivationError, match='STARTUP_FORBIDDEN'):
        synthetic_closure.context.history_read_under_lock(for_startup=True)


def test_observation_expiring_after_review_never_writes(synthetic_closure):
    h = synthetic_closure
    checked = h.context.plan_under_lock()
    checked['observation']['native_after']['observed_at_utc'] = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()
    h.context.plan_under_lock = lambda: checked
    with pytest.raises(M.PreActivationError, match='EXPIRED_BEFORE_WRITE'):
        h.context.close_idle_under_lock(apply=True, authorized_plan_sha256=checked['plan_sha256'])
    assert h.counts['write'] == 0
    assert not (h.directory / 'closed-idle.json').exists()


@pytest.mark.parametrize('part', ['native_before', 'remote', 'native_after'])
def test_each_observation_must_be_fresh_before_commit(part):
    now = datetime.now(timezone.utc)
    observation = {key: {'observed_at_utc': now.isoformat()} for key in ('native_before', 'remote', 'native_after')}
    observation[part]['observed_at_utc'] = (now - timedelta(seconds=31)).isoformat()
    with pytest.raises(M.PreActivationError, match='EXPIRED_BEFORE_WRITE'):
        M.fresh_observation(observation, now)


def test_native_timestamp_order_is_checked_before_commit():
    now = datetime.now(timezone.utc)
    observation = {key: {'observed_at_utc': now.isoformat()} for key in ('native_before', 'remote', 'native_after')}
    observation['native_after']['observed_at_utc'] = (now + timedelta(seconds=1)).isoformat()
    with pytest.raises(M.PreActivationError, match='OBSERVATION_ORDER_INVALID'):
        M.fresh_observation(observation, now)
    observation['native_after']['observed_at_utc'] = (now - timedelta(seconds=1)).isoformat()
    with pytest.raises(M.PreActivationError, match='OBSERVATION_ORDER_INVALID'):
        M.fresh_observation(observation, now)


def test_measured_loader_ignores_bytecode_and_rejects_unpinned_import(tmp_path):
    path = tmp_path / 'sample.py'
    path.write_bytes(b'VALUE = 7\n')
    loader = M._MeasuredSourceLoader(tmp_path, {'qa/operator/sample.py': (path, M.sha(path.read_bytes()))})
    spec = loader.find_spec('qa.operator.sample')
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    assert module.VALUE == 7
    with pytest.raises(M.PreActivationError, match='UNMEASURED_IMPORT'):
        loader.find_spec('qa.operator.unreviewed')
    path.write_bytes(b'VALUE = 8\n')
    with pytest.raises(M.PreActivationError, match='SOURCE_CHANGED'):
        loader.exec_module(module)
