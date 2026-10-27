"""Local-only wrapper tests; remote transport is mocked, real gate uses temp SQLite."""
from copy import deepcopy
import ast
import base64
import builtins
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
for folder in (ROOT, ROOT / 'fox', ROOT / 'fox/tests'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import promote_native as cli
from fox import native_verification as gate, native_verification_policy as policy_module
from test_native_verification import proof_case, promotion_case, raw, sha, NOW
from test_native_verification_policy import v2_case, v2_promotion
from test_native_pipeline import harness, valid_package
from test_fox import client

_TEMPORARY_DIRECTORY = tempfile.TemporaryDirectory


def packet(case, command='check'):
    receipts = {name: raw(case[key]) for name, key in zip(gate.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile'))}
    receipts.update({'verification-profile.json': case['verification_policy'].raw,
                     'allocation-receipt.json': case['allocation_raw']})
    return {'command': command, 'apply': command == 'apply', 'expected_image': 'sha256:' + 'a' * 64,
            'module_sha256': 'b' * 64, 'collection_manifest_sha256': 'c' * 64,
            'binding': case['verification_policy'].binding,
            'receipt_sha256': {name: sha(value) for name, value in receipts.items()},
            'receipts': {name: base64.b64encode(value).decode() for name, value in receipts.items()}}


def tree(path):
    return {str(item.relative_to(path)): sha(item.read_bytes()) if item.is_file() else None
            for item in path.rglob('*') if not str(item).endswith(('.sqlite3-wal', '.sqlite3-shm'))}


def run_container(value, case, *, now=NOW):
    return cli.container_execute(value, gate, root=str(case[1]), operator_root=str(case[5].parent), now=now)


def mocked_cli(monkeypatch, *, now=NOW, calls=None):
    def run(command):
        assert '--policy-file' in command and '--apply' in command and '--profile' not in command
        if calls is not None:
            calls.append(command)
        def option(name):
            return command[command.index(name) + 1]
        root = Path(option('--data-dir')); operator = Path(option('--receipt-dir'))
        policy = gate.load_verification_profile(Path(option('--policy-file')), root=root, operator_receipt_dir=operator,
                                               historical='--resume-retained' in command)
        try:
            result = gate.promote_native_run(root=root, run_id=option('--run-id'), operator_receipt_dir=operator, policy=policy, now=now)
        except OSError:
            print('private diagnostic must not escape')
            return 1
        print(json.dumps(result))
        return 0
    monkeypatch.setattr(gate, 'main', run)


@pytest.fixture
def collection(v2_case, tmp_path, monkeypatch):
    value = packet(v2_case)
    temporary = _TEMPORARY_DIRECTORY(prefix='fox-promotion-test-')
    private = Path(temporary.name)
    monkeypatch.setattr(cli.transport, 'PRIVATE', private)
    directory = private / ('4' * 64) / ('qa-' + '5' * 16)
    directory.mkdir(parents=True)
    receipts = {}
    for canonical, collected in cli.FILES.items():
        content = base64.b64decode(value['receipts'][canonical])
        (directory / collected).write_bytes(content)
        receipts[collected] = sha(content)
    manifest = {'status': 'COLLECTED', 'credentials_and_logs_excluded': True,
                'plan_sha256': '4' * 64, 'source_sha256': '5' * 64, 'sha256': receipts}
    manifest_raw = raw(manifest)
    (directory / 'collection-manifest.json').write_bytes(manifest_raw)
    # Native Windows ACL enforcement has a separate read-only transport test.
    monkeypatch.setattr(cli, 'private_inputs', lambda paths: None)
    options = {'collection_sha256': sha(manifest_raw), 'expected_image': value['expected_image'],
               'module_sha256': value['module_sha256']}
    yield directory, options, value
    temporary.cleanup()


def test_collection_aliases_preserve_exact_raw_bytes_without_outputs(collection):
    directory, options, value = collection
    before = tree(directory.parent)
    actual = cli.payload('check', directory, **options)
    assert actual['receipts'] == value['receipts']
    assert actual['receipt_sha256'] == value['receipt_sha256']
    assert tree(directory.parent) == before
    assert not (directory / 'clean-install.json').exists()
    assert not (directory / 'qa-target.json').exists()


@pytest.mark.parametrize('mutation', ['short_source_hash', 'uppercase_source_hash', 'changed_full_hash_tail',
                                    'wrong_short_name', 'legacy_long_name', 'wrong_private_parent'])
def test_short_collection_name_keeps_full_hash_and_private_parent_binding(collection, mutation):
    directory, options, _ = collection
    manifest_path = directory / 'collection-manifest.json'
    if mutation in ('short_source_hash', 'uppercase_source_hash', 'changed_full_hash_tail'):
        manifest = json.loads(manifest_path.read_bytes())
        if mutation == 'short_source_hash': manifest['source_sha256'] = '5' * 16
        if mutation == 'uppercase_source_hash': manifest['source_sha256'] = 'A' * 64
        if mutation == 'changed_full_hash_tail': manifest['source_sha256'] = '5' * 16 + '6' * 48
        changed = raw(manifest); manifest_path.write_bytes(changed)
        # Even a newly approved malformed manifest cannot reduce the full hash
        # to its directory prefix. A tail change must fail the original hash.
        if mutation != 'changed_full_hash_tail': options['collection_sha256'] = sha(changed)
    else:
        name = 'qa-' + '6' * 16 if mutation == 'wrong_short_name' else 'qa-evidence-' + '5' * 64
        destination = directory.with_name(name) if mutation != 'wrong_private_parent' else directory.parent.parent / directory.name
        directory.rename(destination); directory = destination
    with pytest.raises(ValueError):
        cli.payload('check', directory, **options)


@pytest.mark.parametrize('mutation', ['manifest', 'profile', 'allocation', 'clean', 'qa', 'target', 'hash', 'image', 'module', 'apply'])
def test_local_changes_fail_before_transport(collection, monkeypatch, mutation):
    directory, options, _ = collection
    selected = {'manifest': 'collection-manifest.json', 'profile': 'verification-profile.json',
                'allocation': 'allocation-receipt.json', 'clean': 'clean-import-receipt.json',
                'qa': 'qa-result.json', 'target': 'target-receipt.json'}
    if mutation in selected:
        path = directory / selected[mutation]; path.write_bytes(path.read_bytes() + b'\n')
    if mutation == 'hash': options['collection_sha256'] = 'd' * 64
    if mutation == 'image': options['expected_image'] = 'latest'
    if mutation == 'module': options['module_sha256'] = None
    if mutation == 'apply': options['apply'] = True
    monkeypatch.setattr(cli.transport, 'run_process', lambda *a, **k: pytest.fail('No process may start'))
    with pytest.raises((ValueError, TypeError)):
        cli.dispatch('check', directory, **options)


def test_check_reuses_real_gate_without_logical_or_receipt_writes(v2_promotion, monkeypatch):
    value = packet(v2_promotion[6])
    before = tree(v2_promotion[1].parent)
    monkeypatch.setattr(gate, '_save_once', lambda *a: pytest.fail('check must never retain files'))
    monkeypatch.setattr(gate, 'main', lambda *a: pytest.fail('check must never invoke CLI'))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('check must never invoke CLI'))
    result = run_container(value, v2_promotion)
    assert result['status'] == 'READY_NOT_APPLIED' and result['read_only'] is True
    assert result['event_count'] == result['proof_count'] == 0
    # Real app fixture uses WAL. Normal read-only WAL/shared-memory bookkeeping
    # is allowed; main DB state and every receipt/proof/file remain unchanged.
    assert tree(v2_promotion[1].parent) == before


def test_apply_uses_v2_cli_once_then_replays_verified_readonly(v2_promotion, monkeypatch):
    value = packet(v2_promotion[6], 'apply')
    calls = []; mocked_cli(monkeypatch, calls=calls)
    first = run_container(value, v2_promotion)
    assert first['status'] == 'VERIFIED' and first['idempotent'] is False and len(calls) == 1
    assert first['event_count'] == first['proof_count'] == 1
    assert first['human_acceptance_recorded'] is False
    before = tree(v2_promotion[1].parent)
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('existing proof must not rerun CLI'))
    monkeypatch.setattr(gate, 'main', lambda *a: pytest.fail('existing proof must not rerun CLI'))
    second = run_container(value, v2_promotion, now=datetime(2027, 1, 1, tzinfo=timezone.utc))
    assert second['idempotent'] is True and second['read_only'] is True
    assert tree(v2_promotion[1].parent) == before
    with sqlite3.connect(v2_promotion[1] / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


def test_apply_invokes_verified_real_cli_without_reimporting_hostile_pythonpath(v2_promotion, monkeypatch, tmp_path):
    hostile = tmp_path / 'hostile' / 'fox'; hostile.mkdir(parents=True)
    (hostile / '__init__.py').write_text('raise AssertionError("HOSTILE_PACKAGE_INITIALIZER_EXECUTED")', encoding='utf-8')
    monkeypatch.setenv('PYTHONPATH', str(hostile.parent))
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('No child interpreter or unchecked package reimport'))
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz else NOW.replace(tzinfo=None)
    monkeypatch.setattr(gate, 'datetime', FrozenDateTime)
    assert run_container(packet(v2_promotion[6], 'apply'), v2_promotion)['status'] == 'VERIFIED'
    with sqlite3.connect(v2_promotion[1] / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM technical_verifications').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


@pytest.mark.parametrize('mutation', ['raw_receipt', 'missing_receipt', 'job_binding', 'allocation', 'failed_qa', 'wrong_apply'])
def test_container_rejects_changed_receipts_without_copies_or_cli(v2_promotion, monkeypatch, mutation):
    value = packet(v2_promotion[6], 'apply')
    if mutation == 'raw_receipt': value['receipts']['qa-result.json'] = base64.b64encode(b'{}').decode()
    if mutation == 'missing_receipt': del value['receipts']['allocation-receipt.json']
    if mutation == 'job_binding': value['binding']['job_id'] = 'fox-' + 'f' * 20
    if mutation in ('allocation', 'failed_qa'):
        name = 'allocation-receipt.json' if mutation == 'allocation' else 'qa-result.json'
        item = json.loads(base64.b64decode(value['receipts'][name]))
        item['passed' if mutation == 'allocation' else 'status'] = False if mutation == 'allocation' else 'FAILED'
        value['receipts'][name] = base64.b64encode(raw(item)).decode(); value['receipt_sha256'][name] = sha(raw(item))
    if mutation == 'wrong_apply': value['apply'] = False
    before = tree(v2_promotion[1].parent)
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: pytest.fail('No CLI after failed preflight'))
    monkeypatch.setattr(gate, 'main', lambda *a: pytest.fail('No CLI after failed preflight'))
    with pytest.raises((RuntimeError, gate.VerificationError, ValueError)):
        run_container(value, v2_promotion)
    assert tree(v2_promotion[1].parent) == before


def test_durable_matching_attempt_resumes_original_decision_after_freshness(v2_promotion, monkeypatch):
    value = packet(v2_promotion[6], 'apply')
    original_save = gate._save_once
    def interrupted(path, content):
        if path.name == 'verification.json': raise OSError('synthetic interruption')
        original_save(path, content)
    monkeypatch.setattr(gate, '_save_once', interrupted)
    mocked_cli(monkeypatch)
    with pytest.raises(RuntimeError, match='GATE_OUTCOME_UNCONFIRMED'):
        run_container(value, v2_promotion)
    original_attempt = (v2_promotion[4] / 'technical-verification/attempt.json').read_bytes()
    monkeypatch.setattr(gate, '_save_once', original_save)
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    later = datetime(2027, 1, 1, tzinfo=timezone.utc)
    checked = run_container({**value, 'command': 'check', 'apply': False}, v2_promotion, now=later)
    assert checked['read_only'] and checked['resume_retained_attempt']
    calls = []; mocked_cli(monkeypatch, now=later, calls=calls)
    assert run_container(value, v2_promotion, now=later)['status'] == 'VERIFIED'
    assert '--resume-retained' in calls[0]
    assert (v2_promotion[4] / 'technical-verification/attempt.json').read_bytes() == original_attempt
    with sqlite3.connect(v2_promotion[1] / 'fox.sqlite3') as db:
        assert db.execute('SELECT created FROM technical_verifications').fetchone()[0] == NOW.timestamp()


def test_current_source_or_frozen_download_mismatch_blocks_readonly_check(v2_promotion):
    download = v2_promotion[4] / 'native-pipeline/download.json'
    download.write_bytes(raw({'package_sha256': 'f' * 64, 'source_hash': v2_promotion[6]['snapshot']['source_hash']}))
    with pytest.raises(RuntimeError, match='FROZEN_JOB_CHECKPOINT'):
        run_container(packet(v2_promotion[6]), v2_promotion)


def test_framed_transport_is_fixed_host_no_oci_or_commandline_receipts(collection, monkeypatch):
    directory, options, value = collection
    result = {'status': 'READY_NOT_APPLIED', 'job_id': value['binding']['job_id'], 'human_acceptance_recorded': False,
              'host_scope_verified': True, 'expected_image': value['expected_image'], 'module_sha256': value['module_sha256']}
    calls = []
    def process(args, **kwargs):
        calls.append((args, kwargs))
        program, body = kwargs['data'].split(b'\n', 1)
        assert base64.b64decode(program).decode() == cli.host_source()
        assert json.loads(body)['receipts'] == value['receipts']
        return raw(result)
    monkeypatch.setattr(cli.transport, 'run_process', process)
    monkeypatch.setattr(cli.transport, 'oci_scope', lambda **k: pytest.fail('No OCI calls'))
    assert cli.dispatch('check', directory, **options) == result
    assert len(calls) == 1 and calls[0][0][:-1] == cli.transport.SSH
    assert calls[0][0][-1].startswith('python3 -B -c')
    assert all(encoded not in repr(calls[0][0]) for encoded in value['receipts'].values())


@pytest.mark.parametrize('reported_image', ['bare', 'prefixed', 'foreign', 'repeated_prefix', 'uppercase', 'tag', 'newline'])
def test_host_program_python36_guards_and_framing_are_effective(v2_case, monkeypatch, reported_image):
    value = packet(v2_case)
    source = cli.host_source()
    ast.parse(source, feature_version=(3, 6))
    assert not any(isinstance(item, ast.Assert) for item in ast.walk(ast.parse(source)))
    metadata = {'id': C_INSTANCE, 'compartmentId': policy_module.COMPARTMENT, 'canonicalRegionName': 'us-ashburn-1'}
    images = {'bare': 'a' * 64, 'prefixed': 'sha256:' + 'a' * 64, 'foreign': 'b' * 64,
              'repeated_prefix': 'sha256:sha256:' + 'a' * 64, 'uppercase': 'SHA256:' + 'a' * 64,
              'tag': 'localhost/fox:latest', 'newline': 'a' * 64 + '\n'}
    inspected = {'Id': 'e' * 64, 'State': {'Running': True}, 'Image': images[reported_image], 'Config': {'User': '1000:1000'},
                 'HostConfig': {}, 'Mounts': [{'Destination': '/data'}]}
    calls = []
    def process(args, **kwargs):
        calls.append(args)
        if args == ['podman', 'inspect', 'fox']:
            return SimpleNamespace(returncode=0, stdout=raw([inspected]))
        assert args[:7] == ['podman', 'exec', '-i', inspected['Id'], 'python', '-I', '-B']
        code, body = kwargs['input'].split(b'\n', 1)
        assert base64.b64decode(code).decode() == cli.container_source()
        assert json.loads(body) == value
        return SimpleNamespace(returncode=0, stdout=raw({'status': 'READY_NOT_APPLIED'}))
    monkeypatch.setattr(subprocess, 'run', process)
    monkeypatch.setattr(urllib.request, 'urlopen', lambda *a, **k: io.BytesIO(raw(metadata)))
    for wrong in (False, True):
        if wrong: metadata['id'] = 'wrong-instance'
        output = io.StringIO()
        monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw(value))))
        monkeypatch.setattr(sys, 'stdout', output)
        previous = len(calls)
        exec(compile(source, '<host-test>', 'exec', optimize=2), {})
        result = json.loads(output.getvalue())
        accepted = not wrong and reported_image in ('bare', 'prefixed')
        assert result['status'] == ('READY_NOT_APPLIED' if accepted else 'BLOCKED')
        if accepted: assert result['expected_image'] == value['expected_image']
        else: assert not any(args[:2] == ['podman', 'exec'] for args in calls[previous:])
        if wrong: assert len(calls) == previous


def test_deployed_module_hash_is_checked_before_any_gate_or_package_execution(v2_case, monkeypatch):
    source = cli.container_source()
    value = packet(v2_case)
    fixed = Path('/app/fox/native_verification.py')
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, 'read_bytes', lambda path: b'raise AssertionError("UNVERIFIED_MODULE_EXECUTED")'
                        if path == fixed else original_read(path))
    original_resolve = Path.resolve
    monkeypatch.setattr(Path, 'resolve', lambda path, **options: fixed if path == fixed else original_resolve(path, **options))
    monkeypatch.setattr(cli.os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(cli.os, 'getegid', lambda: 1000, raising=False)
    imports = []
    original_import = builtins.__import__
    def observed_import(name, *args, **kwargs):
        if name == 'fox' or name.startswith('fox.'):
            imports.append(name)
            raise AssertionError('UNVERIFIED_PACKAGE_IMPORTED')
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', observed_import)
    output = io.StringIO()
    monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw(value))))
    monkeypatch.setattr(sys, 'stdout', output)
    exec(compile(source, '<container-guard-test>', 'exec', optimize=2), {})
    assert json.loads(output.getvalue())['status'] == 'BLOCKED'
    assert imports == []


def test_module_and_packet_failures_do_not_echo_raw_diagnostics(collection, monkeypatch, capsys):
    directory, options, _ = collection
    marker = 'PRIVATE_RECEIPT_DIAGNOSTIC_DO_NOT_ECHO'
    def fail(*args, **kwargs):
        raise RuntimeError(marker)
    monkeypatch.setattr(cli, 'dispatch', fail)
    result = cli.main(['check', '--evidence-dir', str(directory), '--collection-sha256', options['collection_sha256'],
                      '--expected-image', options['expected_image'], '--module-sha256', options['module_sha256']])
    output = capsys.readouterr().out
    assert result == 2 and marker not in output
    assert json.loads(output)['automatic_replay_permitted'] is False


C_INSTANCE = policy_module.INSTANCE
