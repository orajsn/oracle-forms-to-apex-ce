"""Synthetic transport/projection checks; no host, OCI, DB or secret access."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import inspect
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from qa.operator import product_verifier as product
from qa.operator import retirement_remote as remote
from qa.operator.tests.test_hosted_release_binding import (
    offline_configuration, operator_configuration, canonical_bytes)

NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('Retirement unit tests may not contact or execute outside the local fixture')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(subprocess, 'run', blocked)
    monkeypatch.setattr(subprocess, 'Popen', blocked)


def configuration():
    declared = offline_configuration()
    declared_raw = canonical_bytes(declared)
    manifest = product.build_manifest(operator_configuration(declared), hosted_configuration=declared_raw)
    current = remote.bridge.release_sha256(manifest)
    infrastructure = {
        'fox': {'id': '1' * 64, 'image': manifest['images']['fox']},
        'forms2apex-mcp': {'id': '2' * 64, 'image': manifest['images']['converter']},
        'oracle-applied-ai-label': {'id': '3' * 64, 'image': 'sha256:' + 'e' * 64},
    }
    admission = remote.admission_configuration(current, remote._digest(declared_raw), infrastructure)
    return manifest, current, infrastructure, remote._digest(remote._canonical(admission))


def selected_declaration(monkeypatch):
    """Synthetic selection seam only; this is not POSIX private-host admission.

    The release/source/configuration validators remain real. Actual selected
    provider ownership/runtime checks have separate local-POSIX coverage.
    """
    runtime = remote.bridge.runtime_provider
    raw = canonical_bytes(offline_configuration())
    digest = remote._digest(raw)
    runtime.configuration_document(raw, expected_sha256=digest)
    monkeypatch.setattr(runtime, '_selected', runtime.HostedProvider(raw, digest))


def history():
    binding = {'job_id': 'fox-' + '1' * 20, 'source_manifest_sha256': '8' * 64,
               'package_sha256': '9' * 64, 'verifier_release_sha256': 'a' * 64}
    document = {'binding': binding, 'automatic_retry_permitted': False, 'human_acceptance_recorded': False}
    return {'failure': {'release_sha256': 'a' * 64, 'session_id': 'session-' + '1' * 24,
                       'job_id': binding['job_id'], 'disposition_sha256': remote._digest(remote._canonical(document)),
                       'disposition': document},
            'retry': {'release_sha256': 'b' * 64, 'session_id': 'session-' + '2' * 24,
                      'job_id': binding['job_id'], 'attempt_id': 'attempt-' + '1' * 32, 'proof_sha256': '7' * 64},
            'idle': {'release_sha256': 'c' * 64, 'session_id': 'session-' + '3' * 24,
                     'completed_jobs': [{'binding': {**binding, 'job_id': 'fox-' + '2' * 20,
                         'verifier_release_sha256': 'c' * 64}, 'proof_sha256': '6' * 64}]}}


def inventory(infrastructure, *, observed=NOW):
    return sorted([{'id': value['id'], 'name': name, 'image': value['image'],
        'status': 'running', 'running': True, 'pid': 100 + index, 'exit_code': 0,
        'created_at': (observed - timedelta(hours=1)).isoformat(),
        'started_at': (observed - timedelta(minutes=50)).isoformat(),
        'finished_at': '0001-01-01T00:00:00Z'}
        for index, (name, value) in enumerate(infrastructure.items())], key=lambda row: row['id'])


def snapshot(config, retained, *, observed=NOW, startup=True, waiting=0, busy=0):
    manifest, current, infrastructure, digest = config
    old, retry = retained['failure'], retained['retry']
    return {'schema_version': 1, 'scope': remote.SCOPE, 'status': 'RETIRED_HISTORY_OBSERVED',
        'current_release_sha256': current, 'configuration_sha256': digest, 'images': manifest['images'],
        'provider_configuration_sha256': manifest['hosted_runtime_configuration_sha256'],
        'history_sha256': remote._digest(remote._canonical(retained)), 'for_startup': startup,
        'read_only': True, 'automatic_replay_permitted': False,
        'failure_acknowledgement': {'status': 'FAILED_QA_RECORDED',
            'disposition_sha256': old['disposition_sha256'], 'disposition': old['disposition']},
        'completed_retry': {key: retry[key] for key in ('release_sha256', 'job_id', 'attempt_id', 'proof_sha256')},
        'completed_idle_jobs': retained['idle']['completed_jobs'], 'waiting_verification_count': waiting,
        'busy_conversion_count': busy, 'admission_state': 'WAIT' if busy else 'READY',
        'backend_snapshot_sha256': '5' * 64, 'inventory': inventory(infrastructure, observed=observed),
        'observed_at_utc': observed.isoformat(), 'host_scope_verified': True, 'fox_image': manifest['images']['fox']}


def validate(value, config, retained, *, startup=True, now=NOW):
    manifest, current, infrastructure, digest = config
    return remote.validate_snapshot(value, history=retained, current_release=current,
        configuration_sha256=digest, images=manifest['images'], infrastructure=infrastructure,
        provider_configuration_sha256=manifest['hosted_runtime_configuration_sha256'],
        for_startup=startup, now=now)


def test_exact_snapshot_preserves_failure_retry_and_idle_distinctions():
    config, retained = configuration(), history()
    value = snapshot(config, retained)
    result = validate(value, config, retained)
    assert result == value and result is not value
    result['completed_idle_jobs'][0]['proof_sha256'] = '0' * 64
    assert value['completed_idle_jobs'][0]['proof_sha256'] == '6' * 64
    assert 'ready' not in value and value['automatic_replay_permitted'] is False


def test_real_hosted_v3_builder_binds_reader_sources_configuration_and_profile():
    manifest, release, infrastructure, digest = configuration()
    assert manifest['schema_version'] == 3
    assert manifest['scope'] == remote.bridge.HOSTED_SCOPE
    assert manifest['hosted_runtime_configuration_sha256'] != digest
    admission = remote.admission_configuration(release, manifest['hosted_runtime_configuration_sha256'], infrastructure)
    assert remote._digest(remote._canonical(admission)) == digest
    assert set(manifest['code']) == set(remote.bridge.HOSTED_CODE)
    assert {'retirement_handoff.py', 'retirement_remote.py'} <= set(manifest['code'])
    for name, expected in manifest['code'].items():
        assert remote._digest((ROOT / 'qa/operator' / name).read_bytes()) == expected
    profile = manifest['opaf_profile']
    assert profile['sha256'] == manifest['native_profile_sha256']
    assert profile['host_path'].endswith('/' + profile['path'])
    assert remote.RetiredHistoryRemoteReader(manifest, release, infrastructure, digest).current_release == release
    assert remote.bridge.validate_release(manifest) == manifest
    with pytest.raises(remote.RetirementRemoteError, match='ADMISSION_CONFIGURATION_CHANGED'):
        remote.RetiredHistoryRemoteReader(manifest, release, infrastructure, '0' * 64)
    altered = deepcopy(infrastructure); altered['fox']['id'] = '4' * 64
    with pytest.raises(remote.RetirementRemoteError, match='ADMISSION_CONFIGURATION_CHANGED'):
        remote.RetiredHistoryRemoteReader(manifest, release, altered, digest)


@pytest.mark.parametrize('version', [1, 2])
def test_legacy_release_can_be_built_but_cannot_be_a_retirement_destination(version):
    config = product.read_config()
    config.update(schema_version=version,
        scope='fox-product-verifier-operator-config-v' + str(version), enabled=True)
    manifest = product.build_manifest(config)
    infrastructure = configuration()[2]
    infrastructure['fox']['image'] = manifest['images']['fox']
    infrastructure['forms2apex-mcp']['image'] = manifest['images']['converter']
    with pytest.raises(remote.RetirementRemoteError, match='NEW_CURRENT_RELEASE_REQUIRED'):
        remote.RetiredHistoryRemoteReader(manifest, remote.bridge.release_sha256(manifest),
                                         infrastructure, 'f' * 64)


@pytest.mark.parametrize('version', [True, 4, 30])
def test_unknown_or_boolean_release_version_never_admits_a_reader(version):
    manifest, _, infrastructure, digest = configuration()
    manifest['schema_version'] = version
    with pytest.raises(Exception):
        remote.RetiredHistoryRemoteReader(manifest, remote._digest(remote._canonical(manifest)),
                                         infrastructure, digest)


@pytest.mark.parametrize('field,changed', [
    ('schema_version', True), ('scope', 'old'), ('status', 'READY'),
    ('current_release_sha256', '0' * 64), ('configuration_sha256', '0' * 64),
    ('provider_configuration_sha256', '0' * 64),
    ('history_sha256', '0' * 64), ('for_startup', False), ('read_only', False),
    ('host_scope_verified', False), ('automatic_replay_permitted', True),
    ('backend_snapshot_sha256', 'bad'), ('waiting_verification_count', True),
    ('waiting_verification_count', -1), ('waiting_verification_count', 10001),
    ('busy_conversion_count', True), ('busy_conversion_count', -1), ('busy_conversion_count', 10001),
    ('busy_conversion_count', 1), ('admission_state', 'WAIT'), ('admission_state', 'UNKNOWN'),
    ('observed_at_utc', '2026-10-25T12:00:31+00:00'),
    ('observed_at_utc', '2026-10-25T11:59:29+00:00'),
])
def test_snapshot_tamper_refused(field, changed):
    config, retained = configuration(), history()
    value = snapshot(config, retained); value[field] = changed
    with pytest.raises(Exception):
        validate(value, config, retained)


@pytest.mark.parametrize('target', ['failure_acknowledgement', 'completed_retry', 'completed_idle_jobs', 'images', 'fox_image'])
def test_full_proof_payload_and_pair_are_compared(target):
    config, retained = configuration(), history()
    value = snapshot(config, retained); value[target] = None
    with pytest.raises(remote.RetirementRemoteError):
        validate(value, config, retained)


def test_no_unknown_ready_flag_or_missing_proof_fields():
    config, retained = configuration(), history()
    for mutation in ('extra', 'missing'):
        value = snapshot(config, retained)
        if mutation == 'extra': value['ready'] = True
        else: value.pop('completed_retry')
        with pytest.raises(remote.RetirementRemoteError): validate(value, config, retained)


def test_original_acknowledgement_is_byte_canonical_not_python_boolean_equivalence():
    config, retained = configuration(), history()
    value = deepcopy(snapshot(config, retained))
    value['failure_acknowledgement']['disposition']['human_acceptance_recorded'] = 0
    with pytest.raises(remote.RetirementRemoteError, match='PROOF_RESPONSE_CHANGED'):
        validate(value, config, retained)


@pytest.mark.parametrize('change', ['duplicate_id', 'duplicate_name', 'missing', 'wrong_id', 'wrong_image', 'not_live', 'reversed'])
def test_infrastructure_must_be_exact(change):
    config, retained = configuration(), history()
    value = snapshot(config, retained); rows = value['inventory']
    if change == 'duplicate_id': rows[1]['id'] = rows[0]['id']
    elif change == 'duplicate_name': rows[1]['name'] = rows[0]['name']
    elif change == 'missing': rows.pop()
    elif change == 'wrong_id': rows[0]['id'] = '0' * 64
    elif change == 'wrong_image': rows[0]['image'] = 'sha256:' + '0' * 64
    elif change == 'not_live': rows[0].update(status='exited', running=False, pid=0)
    else: rows.reverse()
    with pytest.raises(Exception): validate(value, config, retained)


@pytest.mark.parametrize('state', ['running', 'paused', 'restarting', 'unknown', 'configured'])
def test_noninfrastructure_live_or_unknown_refused(state):
    config, retained = configuration(), history()
    value = snapshot(config, retained)
    row = deepcopy(value['inventory'][0]); row.update(id='4' * 64, name='unapproved-producer', status=state,
        running=state == 'running', pid=0, started_at='0001-01-01T00:00:00Z')
    value['inventory'].append(row)
    with pytest.raises(remote.RetirementRemoteError): validate(value, config, retained)


@pytest.mark.parametrize('kind', ['created', 'exited'])
def test_retained_nonlive_producer_not_adopted_or_deleted(kind):
    config, retained = configuration(), history()
    value = snapshot(config, retained)
    row = deepcopy(value['inventory'][0]); row.update(id='4' * 64, name='retained-old-producer', status=kind,
        running=False, pid=0, started_at='0001-01-01T00:00:00Z' if kind == 'created' else '2026-10-25T11:10:00Z',
        finished_at='0001-01-01T00:00:00Z' if kind == 'created' else '2026-10-25T11:20:00Z')
    value['inventory'].append(row)
    assert validate(value, config, retained)['inventory'][-1] == row


def test_waiting_is_only_a_typed_startup_observation():
    config, retained = configuration(), history()
    assert validate(snapshot(config, retained, waiting=2), config, retained)['waiting_verification_count'] == 2
    with pytest.raises(remote.RetirementRemoteError):
        validate(snapshot(config, retained, startup=False, waiting=2), config, retained, startup=False)


def test_busy_conversion_is_only_read_only_wait_never_ready_or_nonstartup():
    config, retained = configuration(), history()
    value = snapshot(config, retained, waiting=2, busy=1)
    assert validate(value, config, retained)['admission_state'] == 'WAIT'
    assert value['automatic_replay_permitted'] is False and value['read_only'] is True
    changed = deepcopy(value); changed['admission_state'] = 'READY'
    with pytest.raises(remote.RetirementRemoteError): validate(changed, config, retained)
    with pytest.raises(remote.RetirementRemoteError):
        validate(snapshot(config, retained, startup=False, busy=1), config, retained, startup=False)


@pytest.mark.parametrize('mutation', ['current', 'shared_release', 'shared_session', 'no_idle_jobs', 'wrong_retry_job',
                                     'proof', 'disposition', 'wrong_idle_release', 'duplicate_idle', 'failure_is_idle'])
def test_retained_history_schema_cannot_rebind(mutation):
    config, retained = configuration(), history()
    if mutation == 'current': retained['idle']['release_sha256'] = config[1]
    elif mutation == 'shared_release': retained['idle']['release_sha256'] = retained['retry']['release_sha256']
    elif mutation == 'shared_session': retained['idle']['session_id'] = retained['retry']['session_id']
    elif mutation == 'no_idle_jobs': retained['idle']['completed_jobs'] = []
    elif mutation == 'wrong_retry_job': retained['retry']['job_id'] = 'fox-' + '3' * 20
    elif mutation == 'proof': retained['retry']['proof_sha256'] = 'BAD'
    elif mutation == 'disposition': retained['failure']['disposition']['automatic_retry_permitted'] = True
    elif mutation == 'wrong_idle_release': retained['idle']['completed_jobs'][0]['binding']['verifier_release_sha256'] = 'a' * 64
    elif mutation == 'duplicate_idle': retained['idle']['completed_jobs'] *= 2
    else: retained['idle']['completed_jobs'][0]['binding']['job_id'] = retained['failure']['job_id']
    with pytest.raises(remote.RetirementRemoteError): remote.validate_history(retained, config[1])


def test_generated_programs_keep_current_bridge_guards_and_proof_readers():
    config = configuration()
    container = remote.container_source(config[1], config[3])
    host = remote.host_source(config[1], config[3], config[2])
    compile(container, '<synthetic-container>', 'exec'); compile(host, '<synthetic-host>', 'exec')
    for text in ('FOX_EFFECTIVE_USER_INVALID', 'FOX_QUEUE_CONFIG_MISMATCH', 'FOX_NATIVE_PROFILE_CHANGED',
                 'FOX_INSTALLED_MODULE_CHANGED', 'CheckedFinder', 'PRAGMA query_only=ON',
                 'verify_existing_native_run', 'normal_claim_allowed', '_validated_proof'):
        assert text in container
    for text in ('PINNED_HOST_GUARD_FAILED', 'ReadonlyRootfs', 'inventory_before==inventory_after',
                 config[2]['fox']['id'], "['podman','exec','-i',container"):
        assert text in host
    for text in ('PowerShell', 'win_process', 'RecordedNativeObserver', 'close_idle', 'complete_retry('):
        assert text not in container + host


def test_template_drift_fails_closed(monkeypatch):
    monkeypatch.setattr(remote.bridge, 'container_source', lambda: 'changed template')
    with pytest.raises(remote.RetirementRemoteError, match='TEMPLATE_CHANGED'):
        remote.container_source('d' * 64, 'e' * 64)


def test_generated_request_rejects_wrong_installation_and_mutation():
    config, retained = configuration(), history()
    namespace = {'EXPECTED_RELEASE': config[1], 'EXPECTED_CONFIGURATION': config[3],
                 'validate_release': remote.bridge.validate_release, **remote.__dict__}
    exec(inspect.getsource(remote._retirement_validate_request), namespace)
    request = {'operation': 'retired_history_read', 'apply': False, 'manifest': config[0],
        'release_sha256': config[1], 'configuration_sha256': config[3],
        'provider_configuration_sha256': config[0]['hosted_runtime_configuration_sha256'],
        'history': retained, 'for_startup': True}
    assert namespace['_retirement_validate_request'](request) == request
    for field, value in [('apply', True), ('operation', 'claim'), ('configuration_sha256', '0' * 64),
                         ('provider_configuration_sha256', '0' * 64),
                         ('release_sha256', '0' * 64), ('for_startup', 1)]:
        changed = deepcopy(request); changed[field] = value
        with pytest.raises(remote.RetirementRemoteError): namespace['_retirement_validate_request'](changed)


@pytest.mark.parametrize('change', ['legacy2', 'configuration', 'profile_hash', 'profile_path', 'extra_code', 'future4'])
def test_emitted_helper_enforces_exact_hosted_v3_and_configuration_profile_binding(change):
    config, retained = configuration(), history()
    manifest, expected_release, _, config_hash = config
    provider_hash = manifest['hosted_runtime_configuration_sha256']
    if change == 'legacy2':
        legacy = product.read_config()
        legacy.update(schema_version=2, scope='fox-product-verifier-operator-config-v2', enabled=True)
        manifest = product.build_manifest(legacy)
    elif change == 'configuration':
        provider_hash = '0' * 64  # D is distinct; the packet's C must still match exact-current manifest C.
    elif change == 'profile_hash': manifest['opaf_profile']['sha256'] = '0' * 64
    elif change == 'profile_path': manifest['opaf_profile']['host_path'] = '/synthetic-only/../unsafe/' + manifest['opaf_profile']['path']
    elif change == 'extra_code': manifest['code']['unapproved.py'] = '0' * 64
    else: manifest['schema_version'] = 4
    expected_release = remote._digest(remote._canonical(manifest))
    namespace = {}
    # Execute the actual same helper body that is embedded into the bridge.
    exec(remote.bridge._helper_source(), namespace)
    for item in (remote.RetirementRemoteError, remote._need, remote._canonical, remote._digest,
                 remote._hash, remote._identifier, remote._history_binding, remote.validate_history,
                 remote._retirement_validate_request):
        exec(inspect.getsource(item), namespace)
    namespace.update(EXPECTED_RELEASE=expected_release, EXPECTED_CONFIGURATION=config_hash,
                     MAX_PACKET=remote.MAX_PACKET, hashlib=remote.hashlib)
    request = {'operation': 'retired_history_read', 'apply': False, 'manifest': manifest,
        'release_sha256': expected_release, 'configuration_sha256': config_hash,
        'provider_configuration_sha256': provider_hash, 'history': retained, 'for_startup': True}
    with pytest.raises(Exception): namespace['_retirement_validate_request'](request)


def test_concrete_reader_checks_real_current_source_and_only_uses_read_transport(monkeypatch):
    config, retained = configuration(), history()
    selected_declaration(monkeypatch)
    reader = remote.RetiredHistoryRemoteReader(*config)
    calls = []
    monkeypatch.setattr(remote.bridge.clean, 'oci_scope', lambda *, require_database_available:
                        calls.append(('scope', require_database_available)) or {'synthetic': True})
    def fake_remote(program, packet):
        calls.append(('transport', packet))
        assert packet['request']['operation'] == 'retired_history_read'
        assert packet['request']['apply'] is False
        return snapshot(config, retained, observed=datetime.now(timezone.utc))
    monkeypatch.setattr(remote.bridge.clean, 'ssh_json', fake_remote)
    result = reader.read(retained)
    assert result['completed_idle_jobs'] == retained['idle']['completed_jobs']
    assert len(calls) == 2 and calls[0] == ('scope', False)
    reader.source_sha256 = '0' * 64
    with pytest.raises(remote.RetirementRemoteError, match='SOURCE_CHANGED'): reader.read(retained)
    assert len(calls) == 2
    reader.source_sha256 = remote._digest(Path(remote.__file__).read_bytes())
    changed = reader.infrastructure
    changed['fox']['id'] = '4' * 64
    reader.infrastructure_raw = remote._canonical(changed)
    with pytest.raises(remote.RetirementRemoteError, match='ADMISSION_CONFIGURATION_CHANGED'):
        reader.read(retained)
    assert len(calls) == 2


def test_provider_output_is_not_disclosed(monkeypatch):
    config, retained = configuration(), history()
    selected_declaration(monkeypatch)
    reader = remote.RetiredHistoryRemoteReader(*config)
    monkeypatch.setattr(remote.bridge.clean, 'oci_scope', lambda **kwargs: {})
    def broken(*args): raise RuntimeError('private provider detail')
    monkeypatch.setattr(remote.bridge.clean, 'ssh_json', broken)
    with pytest.raises(remote.RetirementRemoteError) as error: reader.read(retained)
    assert str(error.value) == 'RETIREMENT_REMOTE_READ_UNCONFIRMED'
