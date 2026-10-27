"""Local supervisor tests; no real host, secret, model or database access.

POSIX tests use real owner-private files, the genuine archive/proof validators,
concrete reader and fd lease. Only external observation/queue IO is synthetic;
path roots are remapped to the temporary source tree, never readiness booleans.
"""
from copy import deepcopy
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox', ROOT / 'converter'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import hosted_service as service
from qa.operator import runtime_provider as runtime
from qa.operator import product_verifier as product
from qa.operator import failed_verification as failure
from qa.operator.tests.test_product_verifier import Harness

POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0
cb, sha = runtime._canonical, service.C.digest


@pytest.fixture(autouse=True)
def isolated_process_runtime_selection():
    # Production deliberately selects one runtime per process. Each independent
    # unit test gets a fresh module selection, never a provider whose private
    # temporary directory was removed by a preceding POSIX test.
    importlib.reload(runtime)
    yield
    importlib.reload(runtime)


def declaration():
    ref = lambda name: {'path': '/private/' + name, 'sha256': 'a' * 64}
    return {'schema_version': 1, 'scope': service.SCOPE, 'provider': ref('C.json'),
        'release': ref('R.json'), 'admission': ref('D.json'),
        'retirement': {'path': '/state/handoffs/X', 'attestation_sha256': 'b' * 64},
        'layout': {'release_root': '/releases/B', 'inventory': ref('inventory.json')},
        'bounds': {'max_jobs': 1, 'max_polls': 1, 'max_seconds': 60, 'poll_seconds': 1},
        'batch_pause_seconds': 1}


@pytest.mark.parametrize('mutation', ['none', 'hash', 'unknown', 'bool', 'path', 'overlap', 'bounds'])
def test_exact_installation_declaration(mutation):
    value = declaration()
    if mutation == 'unknown': value['ready'] = True
    if mutation == 'bool': value['schema_version'] = True
    if mutation == 'path': value['provider']['path'] = '/private/../C.json'
    if mutation == 'overlap': value['release']['path'] = '/releases/B/R.json'
    if mutation == 'bounds': value['bounds']['max_jobs'] = 2
    raw = cb(value)
    if mutation == 'none':
        assert service.installation_document(raw, expected_sha256=sha(raw)) == value
    else:
        with pytest.raises(Exception):
            service.installation_document(raw, expected_sha256='0' * 64 if mutation == 'hash' else sha(raw))


def test_script_uses_canonical_module_main(monkeypatch):
    # Runs the same direct-file bootstrap used by the unit, avoiding the
    # __main__.HostedAdmission versus package.HostedAdmission type split.
    monkeypatch.setattr(service, 'main', lambda: 23)
    with pytest.raises(SystemExit) as exited:
        runpy.run_path(str(ROOT / 'qa/operator/hosted_service.py'), run_name='__main__')
    assert exited.value.code == 23


@pytest.mark.parametrize('during', ['poll-heartbeat', 'phase-heartbeat', 'phase'])
def test_stop_never_starts_next_claim_or_phase(during):
    h = Harness()
    try:
        h.add_job()
        stop = service.StopRequest()
        transport, perform = h.transport, h.phases.perform
        count = 0
        def wire(operation, *args, **kwargs):
            nonlocal count
            result = transport(operation, *args, **kwargs)
            if operation == 'heartbeat':
                count += 1
                if count == (1 if during == 'poll-heartbeat' else 2) and during != 'phase':
                    stop.request()
            return result
        def phase(*args):
            result = perform(*args)
            stop.request()
            return result
        if during == 'phase': h.phases.perform = phase
        verifier = h.verifier(stop_requested=stop.requested)
        verifier.transport = wire
        result = verifier.pump(apply=True)
        if during == 'poll-heartbeat':
            assert result['status'] == 'SESSION_COMPLETE'
            assert 'claim' not in transport.calls and not h.phases.calls
        else:
            assert result['status'] == 'ATTENTION'
            assert len(h.phases.calls) == (1 if during == 'phase' else 0)
            with pytest.raises(product.ProductVerifierError, match='UNRESOLVED_SESSION'):
                h.verifier().pump(apply=True)
    finally:
        h.close()


@pytest.mark.skipif(not POSIX, reason='actual POSIX private-file and fd capability checks')
def test_real_lock_lifetime_and_nonblocking_second_owner(tmp_path, monkeypatch):
    from qa.operator.tests.hosted_provider_fixture import create_hosted_fixture, configure_fixture
    importlib.reload(runtime)
    config = create_hosted_fixture(tmp_path / 'provider')
    configure_fixture(config, runtime)
    monkeypatch.setattr(runtime.HostedProvider, 'execute_host', lambda *args, **kwargs: b'{"safe":true}')
    journal = product.PrivateJournal('e' * 64)
    with journal.lock() as lease:
        assert type(lease) is failure.HeldOperatorLock
        lease.require_active(journal.release, journal.root)
        with pytest.raises(product.ProductVerifierError, match='ANOTHER_PRODUCT'):
            with journal.lock(create=False): pass
    with pytest.raises(failure.FailureResolutionError, match='ACTIVE_MATCHING'):
        lease.require_active(journal.release, journal.root)
    assert (journal.root / 'worker.lock').stat().st_mode & 0o777 == 0o600
    importlib.reload(runtime)


@pytest.mark.skipif(not POSIX, reason='actual POSIX zero-byte, link and >64KiB source inventory')
def test_exact_inventory_empty_and_large(tmp_path):
    source = tmp_path / 'B'; source.mkdir(mode=0o700)
    files = {}
    for index in range(800):
        name = 'member-' + str(index).zfill(4) + '.py'
        path = source / name
        path.write_bytes(b'')
        path.chmod(0o600)
        files[name] = sha(b'')
    raw = cb({'schema_version': 1, 'scope': service.INVENTORY_SCOPE, 'files': files})
    assert len(raw) > 65536
    assert service.verify_inventory(source, raw)['files'] == files
    first = source / next(iter(files))
    first.unlink(); first.symlink_to(source / list(files)[1])
    with pytest.raises(service.HostedServiceError, match='LINK_FORBIDDEN'):
        service.verify_inventory(source, raw)


@pytest.fixture
def installed(tmp_path, monkeypatch):
    if not POSIX: pytest.skip('genuine POSIX installation fixture')
    from qa.operator.tests import test_retirement_handoff as old
    from qa.operator.tests import test_retirement_remote as wire
    from qa.operator.tests.hosted_provider_fixture import create_hosted_fixture
    from qa.operator.tests.test_hosted_release_binding import operator_configuration, IMAGES
    from forms2apex import target_profile
    importlib.reload(runtime)
    seed = tmp_path / 'history'; seed.mkdir(mode=0o700)
    # Existing synthetic historical fixture runs real failure/proof validators.
    # Its temporary transport prohibitions do not replace our local interpreter.
    with monkeypatch.context() as patch:
        case = old.case.__wrapped__(seed, patch)
    config = create_hosted_fixture(tmp_path / 'provider', secret=None)
    source = tmp_path / 'B'; source.mkdir(mode=0o700)
    for name in runtime._SOURCE_FILES:
        path = source / 'converter' / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(ROOT / 'converter' / name, path)
        path.chmod(0o600)
    profile = source / 'deployment/project-opaf-profile-v2.json'
    profile.parent.mkdir(mode=0o700)
    shutil.copyfile(ROOT / 'deployment/project-opaf-profile-v2.json', profile)
    profile.chmod(0o600)
    config.update(schema_version=2, scope='fox-hosted-operator-runtime-v2', images=IMAGES,
        converter_root=str(source / 'converter'), target_profile=deepcopy(target_profile._PROFILE_JSN_PROJECT_20261025))
    config['target_profile_sha256'] = target_profile.target_profile_sha256(config['target_profile'])
    raw_c = cb(config)
    manifest = product.build_manifest(operator_configuration(config), hosted_configuration=raw_c)
    raw_r = cb(manifest); release = sha(raw_r)
    infrastructure = case['destination']['infrastructure']
    raw_d = cb(service.remote.admission_configuration(release, sha(raw_c), infrastructure))
    case['members']['destination/manifest.json'] = raw_r
    case['members']['destination/configuration.json'] = raw_d
    case['destination'] = old.h._destination(raw_r, raw_d,
        [case['members']['source/manifest.json'], *[case['members']['manifests/' + role + '.json'] for role in old.h.ROLES]])
    case['value']['plan']['destination'] = case['destination']
    case['value']['authorized_plan_sha256'] = sha(cb(case['value']['plan']))
    archive = old.write_archive(case, Path(config['state_root']) / 'handoffs/archive')
    private = tmp_path / 'config'; private.mkdir(mode=0o700)
    raw_inventory = cb({'schema_version': 1, 'scope': service.INVENTORY_SCOPE,
        'files': {p.relative_to(source).as_posix(): sha(p.read_bytes()) for p in source.rglob('*') if p.is_file()}})
    for name, raw in {'C': raw_c, 'R': raw_r, 'D': raw_d, 'inventory': raw_inventory}.items():
        path = private / (name + '.json'); path.write_bytes(raw); path.chmod(0o600)
    value = declaration()
    for name, letter in (('provider', 'C'), ('release', 'R'), ('admission', 'D')):
        path = private / (letter + '.json')
        value[name] = {'path': str(path), 'sha256': sha(path.read_bytes())}
    value['layout'] = {'release_root': str(source), 'inventory': {'path': str(private / 'inventory.json'), 'sha256': sha(raw_inventory)}}
    value['retirement'] = {'path': str(archive.root), 'attestation_sha256': archive.attestation_sha256}
    raw_i = cb(value); path_i = private / 'I.json'; path_i.write_bytes(raw_i); path_i.chmod(0o600)
    monkeypatch.setattr(service, 'ROOT', source)  # equivalent filesystem mount, no validator replacement
    admission = service.HostedAdmission(path_i, expected_sha256=sha(raw_i))
    observations = {'busy': 0, 'calls': 0, 'mounts': 0}
    def host(self, program, data, *, timeout):
        observations['mounts'] += 1
        return b'{"safe":true}'
    def external(program, packet):
        observations['calls'] += 1
        request = packet['request']
        return wire.snapshot((manifest, release, infrastructure, sha(raw_d)), request['history'],
            observed=datetime.now(timezone.utc), busy=observations['busy'])
    monkeypatch.setattr(runtime.HostedProvider, 'execute_host', host)
    monkeypatch.setattr(product.clean, 'oci_scope', lambda **kwargs: {'synthetic': 'scope'})
    monkeypatch.setattr(product.clean, 'ssh_json', external)
    yield admission, observations
    importlib.reload(runtime)


def test_actual_admission_wait_no_new_session_and_check_read_only(installed):
    admission, observations = installed
    before = {str(p): p.read_bytes() for p in Path(admission.provider.configuration['state_root']).rglob('*') if p.is_file()}
    assert admission.check()['status'] == 'CHECKED_NOT_STARTED'
    supervisor = service.HostedSupervisor(admission)
    assert supervisor.status()['status'] == 'NOT_STARTED'
    assert {str(p): p.read_bytes() for p in Path(admission.provider.configuration['state_root']).rglob('*') if p.is_file()} == before
    observations['busy'] = 1
    assert supervisor.verifier.pump(apply=True)['status'] == 'WAIT'
    assert not list(supervisor.verifier.journal.root.glob('session-*'))
    assert observations['calls'] >= 2 and observations['mounts'] >= 2


def test_two_genuine_batches_then_stop_and_no_unknown_replay(installed):
    admission, observations = installed
    supervisor = service.HostedSupervisor(admission)
    count = 0
    def queue(operation, manifest, **kwargs):
        nonlocal count
        if operation == 'heartbeat':
            return {'status': 'CONTACT_RECORDED', 'verifier_release_sha256': admission.release}
        assert operation == 'claim'
        count += 1
        if count == 2: supervisor.stop.request()
        return {'status': 'IDLE', 'verifier_release_sha256': admission.release}
    supervisor.verifier.transport = queue
    result = supervisor.run(apply=True)
    assert result['status'] == 'STOPPED' and result['completed_batches'] == 2
    assert len(list(supervisor.verifier.journal.root.glob('session-*/complete.json'))) == 2
    assert observations['calls'] >= 4
    with supervisor.verifier.journal.lock():
        supervisor.verifier.journal.new(admission.document['bounds'])
    before = count
    with pytest.raises(product.ProductVerifierError, match='UNRESOLVED_SESSION'):
        supervisor.verifier.pump(apply=True)
    assert count == before


def test_package_dry_create_only_and_safe_unit(installed, tmp_path):
    admission, _ = installed
    output = tmp_path / 'new-package'
    assert service.package(admission, output)['status'] == 'PACKAGE_PLAN_ONLY' and not output.exists()
    assert service.package(admission, output, apply=True)['status'] == 'PACKAGED_NOT_INSTALLED'
    unit = (output / 'fox-product-verifier.service').read_text()
    assert 'Restart=no' in unit and 'UMask=0077' in unit and 'SendSIGKILL=no' in unit
    assert 'NoNewPrivileges' not in unit and '"-I" "-B"' in unit
    assert 'systemctl' not in unit and 'ADMIN' not in unit
    with pytest.raises(service.HostedServiceError, match='NEW_DESTINATION'):
        service.package(admission, output, apply=True)


@pytest.mark.skipif(not POSIX, reason='actual subprocess SIGTERM')
def test_real_sigterm_stops_before_next_poll(tmp_path):
    code = """
import os, signal
from qa.operator.hosted_service import StopRequest
from qa.operator.tests.test_product_verifier import Harness
h = Harness(); stop = StopRequest(); original = h.transport
def transport(operation, *args, **kwargs):
    result = original(operation, *args, **kwargs)
    if operation == 'heartbeat': os.kill(os.getpid(), signal.SIGTERM)
    return result
try:
    verifier = h.verifier(stop_requested=stop.requested)
    verifier.transport = transport
    with stop.signals(): result = verifier.pump(apply=True)
    assert result['status'] == 'SESSION_COMPLETE' and 'claim' not in original.calls
    print('COOPERATIVE_STOP_CONFIRMED')
finally: h.close()
"""
    result = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'COOPERATIVE_STOP_CONFIRMED'


@pytest.mark.skipif(not POSIX, reason='actual subprocess canonical direct-file bootstrap')
def test_subprocess_direct_file_uses_canonical_entrypoint():
    code = """
import runpy
from qa.operator import hosted_service as service
def probe():
    from qa.operator.product_verifier import ProductVerifier
    assert service.HostedAdmission.__module__ == 'qa.operator.hosted_service'
    print('CANONICAL_ENTRYPOINT_CONFIRMED')
    return 0
service.main = probe
runpy.run_path(str(service.ROOT / 'qa/operator/hosted_service.py'), run_name='__main__')
"""
    result = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'CANONICAL_ENTRYPOINT_CONFIRMED'
