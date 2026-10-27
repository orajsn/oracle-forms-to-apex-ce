"""Synthetic export/archive contracts. Never reads private historical state.

Original failure evidence uses the genuine backend validator; G transcript
results are explicitly synthetic phase fixtures, not an APEX/runtime claim.
POSIX cases exercise actual owner/private modes and no-follow archive reads.
"""
from copy import deepcopy
from datetime import datetime, timezone
import importlib
import json
import os
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[3]
for path in (ROOT, ROOT / 'fox', ROOT / 'fox/tests'):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
from qa.operator import retirement_handoff as h

cb, sha = h.canonical, h.sha
I_ROOT = ROOT / 'work/product-operator-integrated-20261024a/operator-release-i'


@pytest.mark.parametrize('fault', ['none', 'released', 'foreign', 'badbyte', 'extra-byte',
                                  'ctime-offset', 'ctime-changed'])
def test_export_lock_read_uses_real_owning_fd_and_preserves_lease(tmp_path, monkeypatch, fault):
    from qa.operator import failed_verification as failure
    root = tmp_path / 'locked-journal'
    root.mkdir()
    lock = root / 'worker.lock'
    raw = b'1' if fault == 'badbyte' else b'00' if fault == 'extra-byte' else b'0'
    lock.write_bytes(raw)
    release = 'a' * 64
    with lock.open('r+b') as stream:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease = failure.HeldOperatorLock(failure._LEASE_KEY, release, root, stream)
        journal = types.SimpleNamespace(_held=lease, release=release, root=root)
        stream.seek(1)
        try:
            if os.name == 'nt':
                with pytest.raises(PermissionError): lock.read_bytes()
            if fault == 'released': lease._active = False
            elif fault == 'foreign': journal.release = 'b' * 64
            if fault in {'ctime-offset', 'ctime-changed'}:
                actual, calls = os.fstat, []
                def metadata_api(fd):
                    value = actual(fd)
                    if fd != stream.fileno(): return value
                    calls.append(fd)
                    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
                    values = {key: getattr(value, key) for key in fields}
                    # OS metadata boundary only; the real fd, lock, bytes and
                    # production validation remain in use. A fixed Windows
                    # representation offset is valid; an in-read change is not.
                    values['st_ctime_ns'] += 1000000 + (1 if fault == 'ctime-changed' and len(calls) >= 4 else 0)
                    return types.SimpleNamespace(**values)
                monkeypatch.setattr(os, 'fstat', metadata_api)
            if fault in {'none', 'ctime-offset'}:
                assert h._held_journal_lock_read(journal) == b'0'
                lease.require_active(release, root)
                assert stream.tell() == 1
            else:
                with pytest.raises(Exception): h._held_journal_lock_read(journal)
        finally:
            lease._active = False
            stream.seek(0)
            if os.name == 'nt': msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else: fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    assert lock.read_bytes() == raw


def test_export_lock_read_never_accepts_a_boolean_lease(tmp_path):
    with pytest.raises(h.RetirementError, match='ACTUAL_SOURCE_LEASE'):
        h._held_journal_lock_read(types.SimpleNamespace(_held=True, release='a' * 64, root=tmp_path))


@pytest.fixture
def case(tmp_path, monkeypatch):
    stub = types.ModuleType('test_fox')
    def forbidden(*args, **kwargs):
        raise AssertionError('LIVE_ACTION_FORBIDDEN')
    stub.client = stub.signed_in = stub.project = forbidden
    monkeypatch.setitem(sys.modules, 'test_fox', stub)
    f = importlib.import_module('test_verification_recovery')
    f.no_external_actions.__wrapped__(monkeypatch)
    old_raw = {role: (I_ROOT / 'historical-manifests' / (letter + '.json')).read_bytes()
               for role, letter in zip(h.ROLES, ('c', 'f', 'g'))}
    old = {role: json.loads(raw) for role, raw in old_raw.items()}
    configuration = json.loads((I_ROOT.parent / 'runtime-configuration.input.json').read_bytes())
    source_raw = (I_ROOT / 'current-release-manifest.json').read_bytes()
    configuration['current_release_sha256'] = sha(source_raw)
    fc = configuration['history']['failure']
    monkeypatch.setattr(f, 'OLD_RELEASE', sha(old_raw['failure']))
    monkeypatch.setattr(f, 'QA_SOURCE', fc['qa_source_sha256'])
    monkeypatch.setattr(f, 'IMAGE', fc['qa_image_id'])
    monkeypatch.setattr(f, 'SESSION', fc['session_id'])
    harness = f.harness.__wrapped__(tmp_path, monkeypatch)
    package = f.valid_package.__wrapped__(harness)
    proof = f.proof_case.__wrapped__(package, harness)
    original = f.failed_bundle(f.v2_case.__wrapped__(proof))
    bundle = f.synchronous_bundle((original,))
    # Construct genuine normal-journal shapes and bind the independent backend
    # summary to exactly those bytes, not synthetic placeholders for hashes.
    c_records = {'session.json': cb({'scope': 'fox-product-verifier-session-v1',
        'release_sha256': fc['release_sha256'], 'started_at_utc': '2026-10-19T00:00:00+00:00',
        'startup_authorized': True, 'bounds': {'max_jobs': 3, 'max_polls': 120,
                                             'max_seconds': 7200, 'poll_seconds': 60}}),
        'attention.json': cb({'status': 'ATTENTION', 'release_sha256': fc['release_sha256'],
            'known_claim': True, 'code': 'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE',
            'automatic_replay_permitted': False})}
    claim = {'binding': bundle['binding'].payload(), 'attempt_token': 'a' * 32}
    def c_step(label, result, binding=None):
        intent = cb({'scope': 'fox-product-verifier-step-v1', 'release_sha256': fc['release_sha256'],
            'step': label, 'binding_sha256': sha(cb(binding)) if binding else None})
        complete = cb({'scope': 'fox-product-verifier-step-result-v1', 'release_sha256': fc['release_sha256'],
            'intent_sha256': sha(intent), 'result': result})
        c_records[label + '.intent.json'], c_records[label + '.complete.json'] = intent, complete
        return {'intent_sha256': sha(intent), 'completion_sha256': sha(complete), 'result': result}
    c_step('p0001-claim', {'status': 'CLAIMED', 'claim': claim})
    for phase, record in bundle['journal_summary']['phases'].items():
        bundle['journal_summary']['phases'][phase] = c_step('p0001-' + phase.replace('_', '-'),
                                                          record['result'], claim['binding'])
    bundle['journal_summary']['claim_sha256'] = sha(cb(claim))
    bundle['journal_summary']['retained_sha256'] = {name: sha(raw) for name, raw in c_records.items()}
    for key, field in (('qa_run_intent_sha256', 'intent_sha256'), ('qa_run_completion_sha256', 'completion_sha256')):
        bundle['producer'][key] = bundle['journal_summary']['phases']['qa_run'][field]
    document = f.recovery.validate_failed_evidence(**f.arguments(bundle))
    fc.update(job_id=bundle['binding'].job_id, disposition_sha256=sha(cb(document)),
              collection_sha256=sha(bundle['collection_raw']),
              wrapper_sha256=sha(bundle['wrapper_raw']),
              original_wrapper_sha256=bundle['reviewed_synchronous_launch'].original_wrapper_sha256)
    rc = configuration['history']['retry']
    rc.update(job_id=fc['job_id'])
    members = {}
    def put(path, value):
        members[path] = value if type(value) is bytes else cb(value)
    def header(release):
        return {'scope': 'fox-product-verifier-session-v1', 'release_sha256': release,
            'started_at_utc': '2026-10-19T00:00:00+00:00', 'startup_authorized': True,
            'bounds': {'max_jobs': 3, 'max_polls': 120, 'max_seconds': 7200, 'poll_seconds': 60}}
    for role in h.ROLES:
        entry = configuration['history'][role]
        put('manifests/' + role + '.json', old_raw[role])
        put('journals/' + role + '/worker.lock', b'0')
        put('journals/' + role + '/release.json', {'scope': 'fox-product-verifier-journal-v1',
            'release_sha256': entry['release_sha256']})
        put('journals/' + role + '/' + entry['session_id'] + '/session.json', header(entry['release_sha256']))
    def seal(prefix, name, value):
        put(prefix + '/' + name, {**value, 'retained_sha256': {
            path[len(prefix) + 1:]: sha(raw) for path, raw in members.items() if path.startswith(prefix + '/')}})
    cp = 'journals/failure/' + fc['session_id']
    for name, raw in c_records.items():
        put(cp + '/' + name, raw)
    ack = {'status': 'FAILED_QA_RECORDED', 'disposition_sha256': fc['disposition_sha256'], 'disposition': document}
    put(cp + '/failed-resolution.intent.json', {'scope': 'fox-verification-failed-resolution-intent-v1',
        'release_sha256': fc['release_sha256'], 'disposition_sha256': fc['disposition_sha256'], 'disposition': document})
    put(cp + '/failed-resolution.complete.json', {'scope': 'fox-verification-failed-resolution-complete-v1',
        'intent_sha256': sha(members[cp + '/failed-resolution.intent.json']), 'acknowledgement': ack})
    seal(cp, 'closed-failed.json', {'scope': 'fox-product-verifier-closed-failed-v1', 'status': 'FAILED_QA_CLOSED',
        'release_sha256': fc['release_sha256'], 'disposition_sha256': fc['disposition_sha256'],
        'technical_verification_passed': False, 'human_acceptance_recorded': False, 'automatic_replay_permitted': False})
    for name, raw in {'plan.json': bundle['plan_raw'], 'apex-package.zip': bundle['package'],
        'collection-manifest.json': bundle['collection_raw'], 'journal-summary.json': cb(bundle['journal_summary']),
        'reviewed-wrapper.sh': bundle['wrapper_raw']}.items():
        put('failure-evidence/' + name, raw)
    for name, raw in bundle['files'].items():
        put('failure-evidence/collection/' + name, raw)
    rp = 'journals/retry/' + rc['session_id']
    terminal = {'status': 'PROOF_RECONCILED', 'automatic_replay_permitted': False,
        **{key: rc[key] for key in ('release_sha256', 'job_id', 'attempt_id', 'proof_sha256')}}
    def step(prefix, release, label, result, binding=None):
        put(prefix + '/' + label + '.intent.json', {'scope': 'fox-product-verifier-step-v1',
            'release_sha256': release, 'step': label, 'binding_sha256': sha(cb(binding)) if binding else None})
        put(prefix + '/' + label + '.complete.json', {'scope': 'fox-product-verifier-step-result-v1',
            'release_sha256': release, 'intent_sha256': sha(members[prefix + '/' + label + '.intent.json']), 'result': result})
    step(rp, rc['release_sha256'], 'proof-reconcile', terminal)
    step(rp, rc['release_sha256'], 'p0001-continuation-promotion-apply', {'status': 'VERIFIED',
        'job_id': rc['job_id'], 'human_acceptance_recorded': False, 'proof_sha256': rc['proof_sha256']})
    seal(rp, 'reconciled.json', terminal)
    rc['seal_sha256'] = sha(members[rp + '/reconciled.json'])
    gc = configuration['history']['idle']
    gp = 'journals/idle/' + gc['session_id']
    binding = {'job_id': 'fox-' + '7' * 20, 'source_manifest_sha256': '8' * 64,
               'package_sha256': '9' * 64, 'verifier_release_sha256': gc['release_sha256']}
    gproof, plan_sha = '1' * 64, '2' * 64
    step(gp, gc['release_sha256'], 'p0001-claim', {'status': 'CLAIMED',
        'claim': {'binding': binding, 'attempt_token': '3' * 32}})
    results = {'prepare': {'plan_sha256': plan_sha, **{key: binding[key] for key in
        ('job_id', 'source_manifest_sha256', 'package_sha256')}, 'operator_code_sha256': old['idle']['clean_operator_code_sha256']},
        'clean_check': {'state': 'PREPARED', 'plan_sha256': plan_sha},
        'qa_stage': {'status': 'STAGED', 'plan_sha256': plan_sha, 'source_sha256': old['idle']['qa_source_sha256'],
            'allocation_receipt_sha256': '4' * 64, 'image_id': 'sha256:' + '5' * 64},
        'qa_run': {'status': 'PASSED', 'exit_code': 0, 'plan_sha256': plan_sha,
            'source_sha256': old['idle']['qa_source_sha256'], 'image_id': 'sha256:' + '5' * 64},
        'qa_collect': {'status': 'COLLECTED', 'plan_sha256': plan_sha,
            'source_sha256': old['idle']['qa_source_sha256'], 'collection_manifest_sha256': '6' * 64},
        'promotion_check': {'status': 'READY_NOT_APPLIED', 'job_id': binding['job_id'], 'human_acceptance_recorded': False},
        'promotion_apply': {'status': 'VERIFIED', 'job_id': binding['job_id'], 'human_acceptance_recorded': False, 'proof_sha256': gproof},
        'queue_complete': {'status': 'COMPLETED', 'job_id': binding['job_id'], 'proof_sha256': gproof}}
    for phase in ('allocate', 'schema', 'import', 'verify'):
        results[phase] = {'state': 'QA_READY' if phase == 'verify' else 'PHASE_COMPLETE',
            'action': 'COMPLETED_ONCE', 'plan_sha256': plan_sha, 'evidence_sha256': 'a' * 64}
    for phase, result in results.items():
        step(gp, gc['release_sha256'], 'p0001-' + phase.replace('_', '-'), result, binding)
    step(gp, gc['release_sha256'], 'p0002-claim', {'status': 'IDLE'})
    for name in h.NATIVE_RECORDS:
        put('native/' + name, {'synthetic_retained_record': name})
    native_hashes = {name: sha(members['native/' + name]) for name in h.NATIVE_RECORDS}
    gc['native_source_sha256'] = native_hashes['source.json']
    observed = {'source_sha256': native_hashes['source.json'], 'verifier_release_sha256': gc['release_sha256'],
        'observed_at_utc': '2026-10-19T01:00:00+00:00', 'retained_sha256': native_hashes,
        'successful_exit_confirmed': False, 'processes': {'worker': 'ABSENT_UNCONFIRMED', 'watchdog': 'ABSENT_UNCONFIRMED'}}
    jobs = [{'binding': binding, 'proof_sha256': gproof}]
    seal(gp, 'closed-idle.json', {'schema_version': 1, 'scope': 'fox-interrupted-idle-closure-v1',
        'status': 'INTERRUPTED_IDLE_CLOSED', 'session_id': gc['session_id'], 'release_sha256': gc['release_sha256'],
        'claim_count': 2, 'completed_jobs': jobs, 'successful_native_exit_confirmed': False,
        'automatic_replay_permitted': False, 'human_acceptance_recorded': False,
        'closed_at_utc': '2026-10-19T01:00:01+00:00',
        'observation': {'native_before': observed, 'native_after': observed,
                        'remote': {'completed_jobs': jobs, 'require_idle': True, 'read_only': True}}})
    source = json.loads(source_raw)
    sources = {**{'qa/operator/' + name: digest for name, digest in source['code'].items()},
               **{'fox/fox/' + name: digest for name, digest in source['modules'].items()}}
    for name in sources:
        put('source/' + name, (I_ROOT / name).read_bytes())
    put('source/manifest.json', source_raw)
    put('source/authority-manifest.json', source_raw)
    put('source/configuration.json', configuration)
    from qa.operator.tests import test_hosted_release_binding as hosted
    provider_configuration = hosted.offline_configuration()
    destination_manifest = hosted.verifier.build_manifest(hosted.operator_configuration(provider_configuration),
        hosted_configuration=cb(provider_configuration))
    put('destination/manifest.json', destination_manifest)
    put('destination/configuration.json', {'schema_version': 1, 'scope': 'fox-hosted-admission-v1',
        'provider_configuration_sha256': sha(cb(provider_configuration)),
        'current_release_sha256': sha(members['destination/manifest.json']),
        'infrastructure': {'fox': {'id': '1' * 64, 'image': destination_manifest['images']['fox']},
            'forms2apex-mcp': {'id': '2' * 64, 'image': destination_manifest['images']['converter']},
            'oracle-applied-ai-label': {'id': '3' * 64, 'image': 'sha256:' + 'c' * 64}}})
    destination = h._destination(members['destination/manifest.json'], members['destination/configuration.json'],
                                [source_raw, *old_raw.values()])
    plan = {'schema_version': 1, 'scope': h.PLAN_SCOPE, 'source_release_sha256': sha(source_raw),
        'source_context': 'installed-i-v1', 'source_authority_release_sha256': sha(source_raw),
        'source_configuration_sha256': sha(members['source/configuration.json']), 'source_reader_files': sources,
        'history': configuration['history'], 'destination': destination,
        'source_provenance': {role: 'C:\\opaque\\' + role for role in (*h.ROLES, 'native')},
        'deployment_authorized': False, 'human_acceptance_recorded': False, 'automatic_replay_permitted': False}
    history = {'failure': {**{key: fc[key] for key in ('release_sha256', 'session_id', 'job_id', 'disposition_sha256')},
                           'disposition': document},
        'retry': {key: rc[key] for key in ('release_sha256', 'session_id', 'job_id', 'attempt_id', 'proof_sha256')},
        'idle': {'release_sha256': gc['release_sha256'], 'session_id': gc['session_id'], 'completed_jobs': jobs}}
    attestation = {'schema_version': 1, 'scope': h.SCOPE, 'plan': plan,
        'authorized_plan_sha256': sha(cb(plan)), 'issued_at_utc': '2026-10-19T01:01:00+00:00', 'history': history,
        'original_typed_checks': {'status': 'INSTALLED_HISTORY_READY', 'release_sha256': sha(source_raw), 'for_startup': False},
        'inventory': {}, 'windows_successful_exit_confirmed': False, 'deployment_authorized': False,
        'human_acceptance_recorded': False, 'automatic_replay_permitted': False}
    return {'value': attestation, 'members': members, 'destination': destination, 'gp': gp, 'rp': rp}


def finalize(case):
    value = deepcopy(case['value'])
    value['inventory'] = {name: {'sha256': sha(raw), 'bytes': len(raw)} for name, raw in case['members'].items()}
    return cb(value)


def validate(case, raw=None, **options):
    raw = finalize(case) if raw is None else raw
    return h.validate_bundle(raw, case['members'], expected_attestation_sha256=options.get('attestation', sha(raw)),
        expected_release_sha256=options.get('release', case['destination']['release_sha256']),
        expected_configuration_sha256=options.get('config', case['destination']['configuration_sha256']))


def test_exact_archive_preserves_failed_retry_and_idle_separately(case):
    value = validate(case)
    assert value['history']['failure']['release_sha256'] != value['history']['retry']['release_sha256']
    assert value['history']['idle']['completed_jobs'] == case['value']['history']['idle']['completed_jobs']
    assert value['plan']['source_provenance']['idle'] == 'C:\\opaque\\idle'
    assert value['deployment_authorized'] is value['human_acceptance_recorded'] is False


def test_destination_is_real_hosted_v3_with_distinct_provider_and_admission_hashes(case):
    from qa.operator import product_queue_transport as bridge
    manifest = bridge.validate_release(json.loads(case['members']['destination/manifest.json']))
    assert manifest['schema_version'] == 3
    assert set(manifest['code']) == set(bridge.HOSTED_CODE)
    assert manifest['code']['preactivation_retirement.py'] == h._reader_sources()['preactivation_retirement.py']
    assert manifest['hosted_runtime_configuration_sha256'] == case['destination']['provider_configuration_sha256']
    assert case['destination']['configuration_sha256'] != case['destination']['provider_configuration_sha256']
    assert h._destination_manifest(manifest) == manifest


@pytest.mark.parametrize('version', [1, 2, 4, True])
def test_nonhosted_or_unknown_destination_versions_are_refused(case, version):
    from qa.operator import product_queue_transport as bridge, product_verifier as product
    if type(version) is int and version in (1, 2):
        config = product.read_config()
        config.update(schema_version=version, scope='fox-product-verifier-operator-config-v' + str(version), enabled=True)
        manifest = product.build_manifest(config)
        assert bridge.validate_release(manifest)['schema_version'] == version
    else:
        manifest = json.loads(case['members']['destination/manifest.json'])
        manifest['schema_version'] = version
    with pytest.raises(h.RetirementError):
        h._destination_manifest(manifest)


def test_v3_provider_reference_cannot_be_rebound_by_envelope(case):
    configuration = json.loads(case['members']['destination/configuration.json'])
    configuration['provider_configuration_sha256'] = '0' * 64
    with pytest.raises(h.RetirementError, match='HOSTED_CONFIGURATION_REQUIRED'):
        h._destination(case['members']['destination/manifest.json'], cb(configuration),
                       [case['members']['manifests/idle.json']])


@pytest.mark.parametrize('mutation', ['hash', 'duplicate', 'unknowncall', 'import', 'decorator', 'unbound-helper',
    'attribute-write', 'subscript-write', 'dunder', 'default-callback', 'nested-definition'])
def test_source_bound_pure_validator_rejects_changed_authority_and_boundaries(case, monkeypatch, mutation):
    manifest = json.loads(case['members']['destination/manifest.json'])
    path = Path(h.__file__).with_name('product_queue_transport.py')
    raw = path.read_bytes()
    if mutation == 'hash':
        manifest['code']['product_queue_transport.py'] = '0' * 64
    elif mutation == 'duplicate':
        raw += b'\ndef validate_release(manifest):\n return manifest\n'
    elif mutation == 'unknowncall':
        raw = raw.replace(b'def validate_release(manifest):', b'def validate_release(manifest):\n    arbitrary_callback()')
    elif mutation == 'import':
        raw = raw.replace(b'def validate_release(manifest):', b'def validate_release(manifest):\n    import subprocess')
    elif mutation == 'decorator':
        raw = raw.replace(b'def validate_release(manifest):', b'@arbitrary_callback\ndef validate_release(manifest):')
    elif mutation in ('attribute-write', 'subscript-write', 'dunder', 'nested-definition'):
        code = {'attribute-write': b'    re._retirement_review_probe = True',
            'subscript-write': b"    C.FIXED_TARGET['region'] = 'poison'",
            'dunder': b"    result = __builtins__; result['open'] = 0",
            'nested-definition': b'    def injected():\n        return True'}[mutation]
        raw = raw.replace(b'def validate_release(manifest):', b'def validate_release(manifest):\n' + code)
    elif mutation == 'default-callback':
        raw = raw.replace(b'def validate_release(manifest):', b'def validate_release(manifest, callback=None):')
    else:
        manifest['code'].pop('preactivation_retirement.py')
    if mutation not in ('hash', 'unbound-helper'):
        manifest['code']['product_queue_transport.py'] = sha(raw)
        original = h._source_read
        monkeypatch.setattr(h, '_source_read', lambda candidate: raw if candidate == path else original(candidate))
    with pytest.raises(h.RetirementError):
        h._destination_manifest(manifest)
    assert not hasattr(h.re, '_retirement_review_probe')


def test_validator_never_calls_request_object_or_target_callbacks(case, monkeypatch):
    from qa.operator import contracts
    class Poison:
        def get(self, *_):
            raise AssertionError('UNTRUSTED_REQUEST_CALLBACK_CALLED')
    with pytest.raises(h.RetirementError, match='MANIFEST_INVALID'):
        h._destination_manifest(Poison())
    nested = json.loads(case['members']['destination/manifest.json'])
    nested['target']['region'] = Poison()
    with pytest.raises(h.RetirementError, match='MANIFEST_INVALID'):
        h._destination_manifest(nested)
    monkeypatch.setattr(contracts, 'FIXED_TARGET', {**contracts.FIXED_TARGET,
        'region': lambda: (_ for _ in ()).throw(AssertionError('TARGET_CALLBACK_CALLED'))})
    with pytest.raises(h.RetirementError, match='TARGET_CONTRACT_INVALID'):
        h._destination_manifest(json.loads(case['members']['destination/manifest.json']))


@pytest.mark.skipif(os.name != 'nt', reason='real Windows source-only G namespace')
def test_hosted_destination_validator_does_not_replace_frozen_g_namespace(case, monkeypatch):
    from qa.operator.tests import test_preactivation_retirement as original
    context = original.context.__wrapped__(monkeypatch)
    try:
        runtime = next(context)
        old_bridge = sys.modules['qa.operator.product_queue_transport']
        assert runtime.components.bridge is old_bridge
        manifest = json.loads(case['members']['destination/manifest.json'])
        with pytest.raises(Exception):
            old_bridge.validate_release(manifest)
        result = h._destination_manifest(manifest)
        assert result['schema_version'] == 3
        assert sys.modules['qa.operator.product_queue_transport'] is old_bridge
        assert old_bridge.validate_release(runtime.manifest) == runtime.manifest
        assert runtime.release == original.M.G_RELEASE
    finally:
        context.close()


@pytest.mark.parametrize('part', ['source/qa/operator/installed_runtime.py', 'native/source.json',
    'failure-evidence/collection/qa-result.json', 'failure-evidence/apex-package.zip'])
def test_raw_tamper_even_with_updated_inventory_fails_semantic_seals(case, part):
    case['members'][part] += b' '
    with pytest.raises(Exception):
        validate(case)


@pytest.mark.parametrize('change', ['remove', 'extra', 'relative', 'wrongrelease', 'wrongconfig', 'attestation'])
def test_installation_pin_and_exact_tree(case, change):
    raw = finalize(case)
    if change == 'remove':
        case['members'].pop('native/intent.json')
    elif change == 'extra':
        case['members']['native/unmatched-intent.json'] = b'{}\n'
    elif change == 'relative':
        case['members']['../escape.json'] = b'{}\n'
    options = {'wrongrelease': {'release': '0' * 64}, 'wrongconfig': {'config': '0' * 64},
               'attestation': {'attestation': '0' * 64}}.get(change, {})
    with pytest.raises(h.RetirementError):
        validate(case, raw, **options)


@pytest.mark.parametrize('field', ['proof', 'unmatched', 'live', 'unknownsession', 'closure'])
def test_resealed_malformed_historical_state_is_refused(case, field):
    gp = case['gp']
    if field == 'proof':
        value = json.loads(case['members'][case['rp'] + '/reconciled.json'])
        value['proof_sha256'] = '0' * 64
        case['members'][case['rp'] + '/reconciled.json'] = cb(value)
    elif field == 'unmatched':
        case['members'].pop(gp + '/p0002-claim.complete.json')
    elif field == 'unknownsession':
        case['members']['journals/idle/session-' + 'f' * 24 + '/session.json'] = b'{}\n'
    else:
        value = json.loads(case['members'][gp + '/closed-idle.json'])
        if field == 'live':
            value['observation']['native_after']['processes']['worker'] = 'LIVE'
        else:
            value['successful_native_exit_confirmed'] = True
        case['members'][gp + '/closed-idle.json'] = cb(value)
    with pytest.raises(Exception):
        validate(case)


def write_archive(case, root):
    root.mkdir(mode=0o700)
    raw = finalize(case)
    for name, content in {**case['members'], 'attestation.json': raw}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(content)
        path.chmod(0o600)
    for path in root.rglob('*'):
        if path.is_dir():
            path.chmod(0o700)
    return h.RetirementArchive(root, attestation_sha256=sha(raw),
        release_sha256=case['destination']['release_sha256'], configuration_sha256=case['destination']['configuration_sha256'])


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX private archive test')
@pytest.mark.parametrize('mutation', ['none', 'file-mode', 'directory-mode', 'link', 'extra-dir', 'extra-file'])
def test_actual_posix_archive_modes_and_inventory(case, tmp_path, mutation):
    archive = write_archive(case, tmp_path / 'archive')
    path = archive.root / 'native/source.json'
    if mutation == 'file-mode':
        path.chmod(0o644)
    elif mutation == 'directory-mode':
        path.parent.chmod(0o755)
    elif mutation == 'link':
        raw = path.read_bytes()
        path.unlink()
        target = tmp_path / 'source.json'
        target.write_bytes(raw)
        path.symlink_to(target)
    elif mutation == 'extra-dir':
        (archive.root / 'unknown').mkdir(mode=0o700)
    elif mutation == 'extra-file':
        (archive.root / 'unknown.json').write_bytes(b'{}\n')
        (archive.root / 'unknown.json').chmod(0o600)
    if mutation == 'none':
        assert archive.read()['scope'] == h.SCOPE
    else:
        with pytest.raises(Exception):
            archive.read()


def test_no_boolean_lock_or_callback_admission(case, tmp_path):
    archive = h.RetirementArchive(tmp_path, attestation_sha256='a' * 64,
        release_sha256='b' * 64, configuration_sha256='c' * 64)
    with pytest.raises(h.RetirementError, match='ACTUAL_CURRENT_LEASE_REQUIRED'):
        archive.require_admission_under_lock(True, current_root=tmp_path,
            current_release='b' * 64, reader=lambda: True)


@pytest.mark.parametrize('change', ['missingphase', 'session', 'claim'])
def test_failure_summary_cannot_float_free_of_original_journal(case, change):
    failed = case['value']['history']['failure']
    prefix = 'journals/failure/' + failed['session_id']
    if change == 'missingphase':
        case['members'].pop(prefix + '/p0001-qa-run.complete.json')
    elif change == 'session':
        summary = json.loads(case['members']['failure-evidence/journal-summary.json'])
        summary['session_id'] = 'session-' + 'e' * 24
        case['members']['failure-evidence/journal-summary.json'] = cb(summary)
    else:
        claimed = json.loads(case['members'][prefix + '/p0001-claim.complete.json'])
        claimed['result']['claim']['attempt_token'] = 'b' * 32
        case['members'][prefix + '/p0001-claim.complete.json'] = cb(claimed)
    closed = json.loads(case['members'][prefix + '/closed-failed.json'])
    closed['retained_sha256'] = {name[len(prefix) + 1:]: sha(raw) for name, raw in case['members'].items()
        if name.startswith(prefix + '/') and name != prefix + '/closed-failed.json'}
    case['members'][prefix + '/closed-failed.json'] = cb(closed)
    with pytest.raises(h.RetirementError, match='FAILED_JOURNAL_SUMMARY_UNBOUND'):
        validate(case)


@pytest.mark.parametrize('image', ['fox', 'converter'])
def test_both_destination_images_must_be_distinct(case, image):
    manifest = json.loads(case['members']['destination/manifest.json'])
    old = json.loads(case['members']['manifests/idle.json'])
    manifest['images'][image] = old['images'][image]
    config = json.loads(case['members']['destination/configuration.json'])
    config['current_release_sha256'] = sha(cb(manifest))
    config['infrastructure']['fox' if image == 'fox' else 'forms2apex-mcp']['image'] = manifest['images'][image]
    with pytest.raises(h.RetirementError, match='DISTINCT_PAIRED_RELEASE_REQUIRED'):
        h._destination(cb(manifest), cb(config), [case['members']['manifests/idle.json']])


@pytest.mark.skipif(os.name != 'posix', reason='actual POSIX fd capability and private archive')
@pytest.mark.parametrize('fault', ['none', 'wrongroot', 'wrongrelease', 'released', 'provider',
                                  'infrastructure', 'source', 'mutated', 'stale'])
def test_admission_owns_real_current_lock_and_exact_installed_bindings(case, tmp_path, monkeypatch, fault):
    """Boundary orchestration only; remote transport has separate genuine-proof tests.

    The concrete reader's external read is replaced, not the archive, source,
    ownership or fd checks. No result here is a live historical-proof claim.
    """
    import fcntl
    from qa.operator import failed_verification as failure, runtime_provider, retirement_remote
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    handoffs = state / 'handoffs'
    handoffs.mkdir(mode=0o700)
    archive = write_archive(case, handoffs / 'archive')
    journal_root = state / 'product-verifier'
    journal_root.mkdir(mode=0o700)
    current = journal_root / archive.release_sha256[:16]
    current.mkdir(mode=0o700)
    lock = current / 'worker.lock'
    lock.write_bytes(b'0')
    lock.chmod(0o600)
    provider = runtime_provider.HostedProvider(cb({'state_root': str(state)}),
                                               case['destination']['provider_configuration_sha256'])
    monkeypatch.setattr(runtime_provider, 'hosted', lambda: provider)
    reader = retirement_remote.RetiredHistoryRemoteReader.__new__(retirement_remote.RetiredHistoryRemoteReader)
    reader.current_release = archive.release_sha256
    reader.configuration_sha256 = archive.configuration_sha256
    reader.infrastructure_raw = cb(case['destination']['infrastructure'])
    calls = []
    def remote_read(self, history, *, for_startup):
        calls.append(history)
        lease.require_active(archive.release_sha256, current)
        with lock.open('r+b') as second:
            with pytest.raises(BlockingIOError):
                fcntl.flock(second.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        if fault == 'mutated':
            (archive.root / 'native/source.json').write_bytes(b'{}\n')
        stamp = '2020-01-01T00:00:00+00:00' if fault == 'stale' else datetime.now(timezone.utc).isoformat()
        return {'observed_at_utc': stamp, 'history': history, 'read_only': True,
            'admission_state': 'READY', 'busy_conversion_count': 0, 'waiting_verification_count': 0}
    monkeypatch.setattr(retirement_remote.RetiredHistoryRemoteReader, 'read', remote_read)
    with lock.open('r+b') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease = failure.HeldOperatorLock(failure._LEASE_KEY, archive.release_sha256, current, stream)
        kwargs = {'current_root': current, 'current_release': archive.release_sha256, 'reader': reader}
        if fault == 'wrongroot':
            kwargs['current_root'] = state
        elif fault == 'wrongrelease':
            kwargs['current_release'] = '0' * 64
        elif fault == 'released':
            lease._active = False
        elif fault == 'provider':
            provider = runtime_provider.HostedProvider(provider.raw, '0' * 64)
        elif fault == 'infrastructure':
            changed = reader.infrastructure
            changed['fox']['id'] = '0' * 64
            reader.infrastructure_raw = cb(changed)
        elif fault == 'source':
            original_sources = h._reader_sources()
            monkeypatch.setattr(h, '_reader_sources', lambda: {**original_sources, 'retirement_handoff.py': '0' * 64})
        if fault == 'none':
            receipt = archive.require_admission_under_lock(lease, **kwargs)
            assert receipt['scope'] == 'fox-retired-history-admission-v1'
            assert receipt['deployment_authorized'] is False
            assert receipt['admission_state'] == 'READY' and receipt['busy_conversion_count'] == 0
            assert len(calls) == 1
        else:
            with pytest.raises(Exception):
                archive.require_admission_under_lock(lease, **kwargs)
        lease._active = False
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


@pytest.fixture
def preactivation_case(case, tmp_path, monkeypatch):
    """Exercise the real additive closure serializer and full archive reader.

    Native/remote observations are explicit synthetic boundaries. This fixture
    is not a source-acquisition/export-authority or real Windows-retirement test.
    """
    from qa.operator import preactivation_retirement as pre
    source_root = ROOT / 'work/product-history-transport-bind-20261019a/operator-release'
    source_raw = case['members']['manifests/idle.json']
    source = json.loads(source_raw)
    authority_raw = case['members']['source/manifest.json']
    authority = json.loads(authority_raw)
    authority_config_raw = case['members']['source/configuration.json']
    authority_config = json.loads(authority_config_raw)
    source_files = {}
    for group, path in (('code', 'qa/operator'), ('modules', 'fox/fox')):
        for name in source[group]:
            source_files[path + '/' + name] = (source_root / path / name).read_bytes()
        for name in authority[group]:
            source_files['authority/' + path + '/' + name] = (I_ROOT / path / name).read_bytes()
    source_files['preactivation/preactivation_retirement.py'] = Path(pre.__file__).read_bytes()
    for name in list(case['members']):
        if name.startswith('source/'):
            del case['members'][name]
    for name, raw in source_files.items():
        case['members']['source/' + name] = raw
    config = {'schema_version': 1, 'scope': pre.SCOPE, 'source_context': pre.SOURCE_CONTEXT,
        'current_release_sha256': sha(source_raw), 'authority_release_sha256': sha(authority_raw),
        'authority_configuration_sha256': sha(authority_config_raw), 'history': authority_config['history'],
        'infrastructure': authority_config['infrastructure'], 'automatic_replay_permitted': False}
    case['members'].update({'source/manifest.json': source_raw, 'source/authority-manifest.json': authority_raw,
        'source/configuration.json': cb(config), 'source/authority-configuration.json': authority_config_raw})
    plan = case['value']['plan']
    plan.update(source_context=pre.SOURCE_CONTEXT, source_release_sha256=sha(source_raw),
        source_authority_release_sha256=sha(authority_raw), source_configuration_sha256=sha(cb(config)),
        source_reader_files={name: sha(raw) for name, raw in source_files.items()})
    case['value']['authorized_plan_sha256'] = sha(cb(plan))
    case['value']['original_typed_checks'] = {'status': 'PREACTIVATION_HISTORY_READY',
        'release_sha256': sha(source_raw), 'runtime_release_sha256': sha(source_raw),
        'source_context': pre.SOURCE_CONTEXT, 'current_container_id': config['infrastructure']['fox']['id'],
        'for_startup': False, 'read_count': 1, 'automatic_replay_permitted': False}
    closure = json.loads(case['members'][case['gp'] + '/closed-idle.json'])
    transcript = {key: closure[key] for key in ('session_id', 'release_sha256',
                  'claim_count', 'completed_jobs', 'retained_sha256')}
    directory = tmp_path / 'synthetic-preactivation'
    directory.mkdir()
    context = pre.PreActivationRetirementContext.__new__(pre.PreActivationRetirementContext)
    context.release, context.authority_release = sha(source_raw), sha(authority_raw)
    context.configuration_sha256, context.history = sha(cb(config)), config['history']
    context.bound_container_id = config['infrastructure']['fox']['id']
    context.source_files = lambda: deepcopy(source_files)
    context.require_active = lambda: None
    context._transcript = lambda: deepcopy(transcript)
    native = closure['observation']['native_before']
    native.update(native_profile='recorded-legacy-g-v1', attempt_id=None)
    stable = {key: native[key] for key in ('source_sha256', 'verifier_release_sha256',
              'native_profile', 'attempt_id', 'retained_sha256')}
    def observe(_):
        stamp = datetime.now(timezone.utc).isoformat()
        observed = {**deepcopy(native), 'observed_at_utc': stamp}
        return {'native_before': observed, 'native_after': deepcopy(observed),
                'remote': {**closure['observation']['remote'], 'observed_at_utc': stamp}}
    context._observe = observe
    context._closed_once = False
    context.current = types.SimpleNamespace(
        write=lambda folder, name, value: (folder / name).write_bytes(cb(value)),
        raw=lambda folder, name: (folder / name).read_bytes())
    context.idle_reader = types.SimpleNamespace(directory=directory,
        native=types.SimpleNamespace(retained_identity=lambda _: deepcopy(stable)), _read_under_lock=lambda: None)
    monkeypatch.setattr(pre, 'private_inputs', lambda _: None)
    proposed = context.plan_under_lock()
    context.close_idle_under_lock(apply=True, authorized_plan_sha256=proposed['plan_sha256'])
    case['members'][case['gp'] + '/closed-idle.json'] = (directory / 'closed-idle.json').read_bytes()
    case['value']['issued_at_utc'] = datetime.now(timezone.utc).isoformat()
    return case


def test_actual_preactivation_closure_shape_roundtrips_genuine_retained_archive(preactivation_case):
    value = validate(preactivation_case)
    assert value['plan']['source_context'] == 'preactivation-g-v1'
    assert value['plan']['source_release_sha256'] == value['history']['idle']['release_sha256']
    assert value['plan']['source_authority_release_sha256'] != value['plan']['source_release_sha256']
    assert value['history']['idle']['completed_jobs'] == preactivation_case['value']['history']['idle']['completed_jobs']


@pytest.mark.parametrize('field', ['authority', 'transcript', 'source', 'originalconfig', 'closureplan'])
def test_preactivation_source_and_closure_authority_cannot_be_relabelled(preactivation_case, field):
    case = preactivation_case
    closure_path = case['gp'] + '/closed-idle.json'
    value = json.loads(case['members'][closure_path])
    if field == 'authority':
        value['retirement_plan']['authority_release_sha256'] = '0' * 64
    elif field == 'transcript':
        value['retirement_plan']['transcript_sha256'] = '0' * 64
    elif field == 'source':
        value['retirement_plan']['source_reader_files']['preactivation/preactivation_retirement.py'] = '0' * 64
    elif field == 'originalconfig':
        original = json.loads(case['members']['source/authority-configuration.json'])
        original['infrastructure']['fox']['id'] = '0' * 64
        case['members']['source/authority-configuration.json'] = cb(original)
    else:
        value['authorized_plan_sha256'] = '0' * 64
    if field in ('authority', 'transcript', 'source'):
        value['authorized_plan_sha256'] = sha(cb(value['retirement_plan']))
    case['members'][closure_path] = cb(value)
    with pytest.raises(h.RetirementError):
        validate(case)
