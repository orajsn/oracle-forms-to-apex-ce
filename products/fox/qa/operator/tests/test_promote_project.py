"""Local fixture promotion only; all process/network boundaries stay fake.

Real generated project package and proof validators are reused. Authored test
observations are not live browser evidence. POSIX ownership checks are isolated
by the confined Windows fixture; production ACL/owner checks remain unchanged.
"""
import ast
import base64
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import urllib.request
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
for folder in (ROOT, ROOT / 'fox', ROOT / 'fox/tests'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import promote_project as cli
from qa.operator import project_qa_dispatch as qa_dispatch
from fox import project_verification_runtime as gate
from fox import native_verification_policy as policy_module
from test_project_verification_runtime import actual_release, case, counts, raw, sha, NOW, change_sources


def packet(case, command='check'):
    receipts = case.observed.receipts
    return {'command': command, 'apply': command == 'apply', 'expected_image': 'sha256:' + 'a' * 64,
            'module_sha256': {name: 'b' * 64 for name in cli.MODULES},
            'collection_manifest_sha256': 'c' * 64, 'binding': deepcopy(case.policy.binding),
            'receipt_sha256': {name: sha(value) for name, value in receipts.items()},
            'receipts': {name: base64.b64encode(value).decode() for name, value in receipts.items()}}


def tree(root):
    return {str(path.relative_to(root)): sha(path.read_bytes()) if path.is_file() else None
            for path in root.rglob('*') if not str(path).endswith(('.sqlite3-wal', '.sqlite3-shm'))}


def execute(value, case, now=NOW):
    return cli.container_execute(value, gate, root=case.root, operator_root=case.operator.parent, now=now)


@pytest.fixture
def collection(case, monkeypatch):
    private = case.operator.parent / 'collections'
    sources, _, _, source_sha = qa_dispatch.bundle()
    plan_sha, image, run_id = 'e' * 64, 'sha256:' + '6' * 64, 'FPQ-20261025T000400-12345678'
    directory = private / plan_sha / ('qa-' + source_sha[:16])
    directory.mkdir(parents=True)
    monkeypatch.setattr(cli.transport, 'PRIVATE', private)
    files = {}
    for name, collected in cli.FILES.items():
        files[collected] = case.observed.receipts[name]
    files['package.zip'] = case.built.package
    with zipfile.ZipFile(io.BytesIO(case.built.package)) as archive:
        for name in ('native-project-spec.json', 'source-to-apex.json'):
            files[name] = archive.read(name)
    stage_path = '/home/opc/.config/fox-qa/project-v1-stages/' + plan_sha + '/' + source_sha
    tag = 'localhost/fox-project-qa:v1-' + plan_sha[:16] + '-' + source_sha[:16]
    bindings = {'source/' + name: sha(content) for name, content in sources.items()}
    containerfile = ('FROM ' + tag + '-base\nUSER root\nCOPY lib /opt/fox-qa/lib\nCOPY run-project.mjs /opt/fox-qa/\n'
                     'RUN chmod -R a+rX /opt/fox-qa\nUSER pwuser\n').encode()
    bindings['source/Containerfile'] = sha(containerfile)
    mapping = {'inputs/package.zip': 'package.zip', 'inputs/native-project-spec.json': 'native-project-spec.json',
        'inputs/source-to-apex.json': 'source-to-apex.json', 'inputs/allocate.evidence.json': 'allocation-receipt.json',
        'inputs/verification-profile.json': 'verification-profile.json', 'inputs/verify.evidence.json': 'clean-import-receipt.json',
        'prepared/profile.json': 'qa-profile.json', 'prepared/target.json': 'target-receipt.json'}
    bindings.update({name: sha(files[collected]) for name, collected in mapping.items()})
    bindings['inputs/runtime-credentials.json'] = sha(b'Synthetic credential identity only; no credentials are collected')
    allocation_sha = sha(files['allocation-receipt.json'])
    files['stage-receipt.json'] = raw({'status': 'STAGED', 'plan_sha256': plan_sha, 'source_sha256': source_sha,
        'allocation_receipt_sha256': allocation_sha, 'image_id': image, 'image_tag': tag, 'stage': stage_path,
        'bound_files': bindings})
    files['launch-intent.json'] = raw({'scope': 'fox-project-qa-launch-v1', 'allocation_receipt_sha256': allocation_sha,
        'plan_sha256': plan_sha, 'source_sha256': source_sha, 'image_id': image,
        'state': 'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY'})
    files['launch-receipt.json'] = raw({'status': 'PASSED', 'exit_code': 0, 'plan_sha256': plan_sha,
        'source_sha256': source_sha, 'image_id': image, 'result_directory': stage_path + '/results',
        'automatic_replay_permitted': False})
    target = json.loads(files['target-receipt.json'])
    qa = json.loads(files['qa-result.json'])
    qa.update(run_id=run_id, runtime_image_id=image, dispatch_state='ATTEMPT_COMPLETED',
              write_attempts=[{'sequence': 1, 'module_id': qa['forms'][0]['module_id'], 'button': 'Create'}])
    files['qa-result.json'] = raw(qa)
    files['dispatch-receipt.json'] = raw({'schema_version': 1, 'scope': 'fox-project-qa-dispatch-v1', 'run_id': run_id,
        'job_id': case.run_id, 'allocation_receipt_sha256': allocation_sha,
        'verification_profile_sha256': case.policy.sha256, 'target_receipt_sha256': sha(files['target-receipt.json']),
        'test_plan_sha256': qa['test_plan_sha256'], 'package_sha256': case.policy.binding['package_sha256'],
        'image_id': image, 'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY', 'started_at': qa['started_at']})
    for name, content in files.items():
        (directory / name).write_bytes(content)
    manifest = {'status': 'COLLECTED', 'credentials_and_logs_excluded': True,
        'plan_sha256': plan_sha, 'source_sha256': source_sha, 'sha256': {name: sha(content) for name, content in files.items()},
        'report_path': stage_path + '/results/' + run_id + '/qa-result.json'}
    (directory / 'collection-manifest.json').write_bytes(raw(manifest))
    monkeypatch.setattr(cli, 'private_inputs', lambda paths: None)
    value = packet(case)
    value['receipts']['qa-result.json'] = base64.b64encode(files['qa-result.json']).decode()
    value['receipt_sha256']['qa-result.json'] = sha(files['qa-result.json'])
    return directory, {'collection_sha256': sha(raw(manifest)), 'expected_image': value['expected_image'],
                       'module_sha256': value['module_sha256']}, value


def test_check_is_real_proof_validation_without_logical_or_receipt_writes(case, monkeypatch):
    before = tree(case.root.parent)
    monkeypatch.setattr(gate, 'promote_project_run', lambda **kwargs: pytest.fail('check must not promote'))
    monkeypatch.setattr(gate.native_io, '_save_once', lambda *args: pytest.fail('check must not copy receipts'))
    result = execute(packet(case), case)
    assert result['status'] == 'READY_NOT_APPLIED' and result['read_only'] is True
    assert result['event_count'] == result['proof_count'] == 0
    assert result['human_acceptance_recorded'] is False
    assert counts(case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}
    assert tree(case.root.parent) == before


def test_apply_calls_project_gate_once_and_existing_proof_is_readonly(case, monkeypatch):
    original = gate.promote_project_run
    calls = []
    def observed(**options):
        calls.append(options)
        return original(**options)
    monkeypatch.setattr(gate, 'promote_project_run', observed)
    value = packet(case, 'apply')
    result = execute(value, case)
    assert result['status'] == 'VERIFIED' and result['idempotent'] is False
    assert result['event_count'] == result['proof_count'] == 1 and len(calls) == 1
    assert calls[0]['policy'].historical is False
    assert counts(case) == {'proofs': 1, 'technical_events': 1, 'acceptances': 0}
    before = tree(case.root.parent)
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    again = execute(value, case, datetime(2027, 1, 1, tzinfo=timezone.utc))
    assert again['read_only'] is True and again['idempotent'] is True and len(calls) == 1
    assert again['proof_sha256'] == result['proof_sha256']
    assert tree(case.root.parent) == before


@pytest.mark.parametrize('mutation', ['raw_receipt', 'missing_receipt', 'changed_binding', 'failed_qa',
                                    'wrong_apply', 'source_changed', 'extra_packet_key'])
def test_invalid_evidence_never_copies_or_promotes(case, monkeypatch, mutation):
    value = packet(case, 'apply')
    if mutation == 'raw_receipt': value['receipts']['qa-result.json'] = base64.b64encode(b'{}').decode()
    if mutation == 'missing_receipt': del value['receipts']['allocation-receipt.json']
    if mutation == 'changed_binding': value['binding']['package_sha256'] = 'f' * 64
    if mutation == 'failed_qa':
        qa = json.loads(base64.b64decode(value['receipts']['qa-result.json']))
        qa['status'] = 'FAILED'
        changed = raw(qa)
        value['receipts']['qa-result.json'] = base64.b64encode(changed).decode()
        value['receipt_sha256']['qa-result.json'] = sha(changed)
    if mutation == 'wrong_apply': value['apply'] = False
    if mutation == 'source_changed': change_sources(case)
    if mutation == 'extra_packet_key': value['unsafe'] = True
    before = tree(case.root.parent)
    monkeypatch.setattr(gate, 'promote_project_run', lambda **kwargs: pytest.fail('No invalid promotion'))
    monkeypatch.setattr(gate.native_io, '_save_once', lambda *args: pytest.fail('No invalid copy'))
    with pytest.raises((RuntimeError, ValueError, gate.ProjectVerificationError)):
        execute(value, case)
    assert tree(case.root.parent) == before


def test_uncertain_technical_attempt_uses_exact_original_decision_only(case, monkeypatch):
    value = packet(case, 'apply')
    original = gate.native_io._save_once
    def interrupted(path, content):
        if path == case.retained / 'verification.json':
            raise OSError('Synthetic local interruption')
        return original(path, content)
    monkeypatch.setattr(gate.native_io, '_save_once', interrupted)
    with pytest.raises(gate.ProjectVerificationError):
        execute(value, case)
    attempt = (case.retained / 'attempt.json').read_bytes()
    assert counts(case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}
    monkeypatch.setattr(gate.native_io, '_save_once', original)
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    later = datetime(2027, 1, 1, tzinfo=timezone.utc)
    checked = execute({**value, 'command': 'check', 'apply': False}, case, later)
    assert checked['read_only'] and checked['resume_retained_attempt']
    result = execute(value, case, later)
    assert result['status'] == 'VERIFIED'
    assert (case.retained / 'attempt.json').read_bytes() == attempt
    assert counts(case) == {'proofs': 1, 'technical_events': 1, 'acceptances': 0}


def test_collection_aliases_preserve_raw_bytes_and_closed_module_map(collection):
    directory, options, expected = collection
    before = tree(directory.parent)
    result = cli.payload('check', directory, **options)
    assert result['receipts'] == expected['receipts']
    assert result['receipt_sha256'] == expected['receipt_sha256']
    assert set(result['module_sha256']) == set(cli.MODULES)
    assert tree(directory.parent) == before
    assert not (directory / 'clean-install.json').exists()


@pytest.fixture
def short_collection(collection, case, monkeypatch):
    """Exact complete collection copied into a confined workspace/work child."""
    original, options, expected = collection
    workspace = case.root.parent / 'workspace'
    work = workspace / 'work'
    work.mkdir(parents=True)
    destination = work / 'project-harvest-1'
    shutil.copytree(original, destination)
    monkeypatch.setattr(cli, 'ROOT', workspace)
    return destination, options, expected, original


def test_short_collection_payload_and_explicit_check_apply_use_same_real_gate(short_collection, case, monkeypatch):
    directory, options, expected, original = short_collection
    before_collection, before_original = tree(directory), tree(original)
    payload = cli.payload('check', directory, **options)
    assert payload['receipts'] == expected['receipts']
    calls = []
    def fake_transport(args, **kwargs):
        calls.append(args)
        program, body = kwargs['data'].split(b'\n', 1)
        assert base64.b64decode(program).decode() == cli.host_source()
        value = json.loads(body)
        result = execute(value, case)
        result.update(host_scope_verified=True, expected_image=value['expected_image'], module_sha256=value['module_sha256'])
        return raw(result)
    monkeypatch.setattr(cli.transport, 'run_process', fake_transport)
    checked = cli.dispatch('check', directory, **options)
    assert checked['status'] == 'READY_NOT_APPLIED' and checked['read_only']
    assert counts(case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}
    promoted = cli.dispatch('apply', directory, **options, apply=True)
    assert promoted['status'] == 'VERIFIED' and promoted['event_count'] == promoted['proof_count'] == 1
    assert counts(case) == {'proofs': 1, 'technical_events': 1, 'acceptances': 0}
    assert len(calls) == 2 and tree(directory) == before_collection and tree(original) == before_original


@pytest.mark.parametrize('mutation', ['uppercase', 'long_name', 'nested', 'sibling', 'dot_component', 'hash',
                                    'unknown_member', 'source', 'plan', 'dispatch', 'reparse', 'owner_acl'])
def test_short_collection_never_weakens_path_hash_or_provenance(short_collection, monkeypatch, mutation):
    directory, options, _, _ = short_collection
    if mutation in {'uppercase', 'long_name', 'nested', 'sibling'}:
        destination = (directory.with_name('Project') if mutation == 'uppercase' else directory.with_name('a' * 41)
            if mutation == 'long_name' else directory.parent / 'nested-parent' / directory.name if mutation == 'nested'
            else directory.parent.parent / 'sibling' / directory.name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(directory, destination)
        directory = destination
    if mutation == 'dot_component': directory = directory.parent / '..' / 'work' / directory.name
    if mutation == 'hash': options['collection_sha256'] = 'f' * 64
    if mutation == 'unknown_member': (directory / 'unknown.json').write_bytes(b'{}')
    if mutation in {'source', 'plan', 'dispatch'}:
        manifest_path = directory / 'collection-manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        if mutation == 'source': manifest['source_sha256'] = 'f' * 64
        if mutation == 'plan': manifest['plan_sha256'] = 'f' * 64
        if mutation == 'dispatch':
            path = directory / 'dispatch-receipt.json'
            receipt = json.loads(path.read_bytes()); receipt['image_id'] = 'sha256:' + 'f' * 64
            path.write_bytes(raw(receipt)); manifest['sha256'][path.name] = sha(raw(receipt))
        manifest_path.write_bytes(raw(manifest)); options['collection_sha256'] = sha(raw(manifest))
    if mutation == 'reparse':
        original_lstat = Path.lstat
        def reparse(path):
            result = original_lstat(path)
            if path != directory: return result
            attrs = {name: getattr(result, name) for name in dir(result) if name.startswith('st_')}
            attrs['st_file_attributes'] = attrs.get('st_file_attributes', 0) | 0x400
            return SimpleNamespace(**attrs)
        monkeypatch.setattr(Path, 'lstat', reparse)
    if mutation == 'owner_acl':
        def denied(paths):
            raise ValueError('Synthetic owner ACL mismatch')
        monkeypatch.setattr(cli, 'private_inputs', denied)
    monkeypatch.setattr(cli.transport, 'run_process', lambda *a, **k: pytest.fail('No external call for rejected short collection'))
    with pytest.raises((ValueError, FileNotFoundError)):
        cli.dispatch('check', directory, **options)


def test_short_harvest_does_not_bypass_freshness_for_new_decision(short_collection, case):
    directory, options, _, _ = short_collection
    value = cli.payload('check', directory, **options)
    before = tree(case.root.parent)
    with pytest.raises(gate.ProjectVerificationError):
        execute(value, case, datetime(2027, 1, 1, tzinfo=timezone.utc))
    assert tree(case.root.parent) == before
    assert counts(case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}


@pytest.mark.parametrize('mutation', ['collection', 'receipt', 'module_missing', 'module_extra', 'module_hash',
                                    'source_hash', 'source_dir', 'plan', 'profile', 'image', 'action'])
def test_local_mutation_blocks_before_external_transport(collection, monkeypatch, mutation):
    directory, options, _ = collection
    if mutation == 'collection': options['collection_sha256'] = 'f' * 64
    if mutation == 'receipt':
        path = directory / 'qa-result.json'; path.write_bytes(path.read_bytes() + b'\n')
    if mutation == 'module_missing': options['module_sha256'].pop(cli.MODULES[0])
    if mutation == 'module_extra': options['module_sha256']['unexpected.py'] = 'f' * 64
    if mutation == 'module_hash': options['module_sha256'][cli.MODULES[0]] = 'F' * 64
    if mutation in {'source_hash', 'source_dir', 'plan', 'profile'}:
        manifest = json.loads((directory / 'collection-manifest.json').read_bytes())
        if mutation == 'source_hash': manifest['source_sha256'] = '5' * 16
        if mutation == 'source_dir': manifest['source_sha256'] = '6' * 64
        if mutation == 'plan': manifest['plan_sha256'] = 'a' * 64
        if mutation == 'profile':
            path = directory / 'clean-import-receipt.json'
            clean = json.loads(path.read_bytes()); clean['profile_id'] = 'native-table-form-v1'
            path.write_bytes(raw(clean)); manifest['sha256'][path.name] = sha(raw(clean))
        (directory / 'collection-manifest.json').write_bytes(raw(manifest))
        options['collection_sha256'] = sha(raw(manifest))
    if mutation == 'image': options['expected_image'] = 'latest'
    if mutation == 'action': options['apply'] = True
    monkeypatch.setattr(cli.transport, 'run_process', lambda *a, **k: pytest.fail('No external transport'))
    with pytest.raises((ValueError, TypeError)):
        cli.dispatch('check', directory, **options)


def test_dispatch_keeps_six_receipts_off_commandline_and_pins_host(collection, monkeypatch):
    directory, options, value = collection
    response = {'status': 'READY_NOT_APPLIED', 'job_id': value['binding']['job_id'],
        'human_acceptance_recorded': False, 'host_scope_verified': True,
        'expected_image': value['expected_image'], 'module_sha256': value['module_sha256']}
    calls = []
    def process(args, **kwargs):
        calls.append(args)
        program, body = kwargs['data'].split(b'\n', 1)
        assert base64.b64decode(program).decode() == cli.host_source()
        assert json.loads(body)['receipts'] == value['receipts']
        return raw(response)
    monkeypatch.setattr(cli.transport, 'run_process', process)
    assert cli.dispatch('check', directory, **options) == response
    assert tuple(calls[0][:-1]) == cli.transport.SSH
    assert all(encoded not in repr(calls[0]) for encoded in value['receipts'].values())


@pytest.mark.parametrize('mutation', ['missing_stage', 'missing_launch_intent', 'missing_launch_complete', 'missing_dispatch',
    'extra_member', 'stage_source', 'stage_path', 'stage_input', 'stage_runner', 'launch_image', 'launch_failed',
    'launch_bool_exit', 'qa_image', 'qa_run', 'qa_state', 'qa_no_writes', 'report_path', 'dispatch_job', 'dispatch_run',
    'dispatch_target', 'dispatch_package', 'dispatch_time', 'dispatch_image', 'dispatch_plan'])
def test_reapproved_collection_still_requires_exact_one_shot_provenance(collection, monkeypatch, mutation):
    directory, options, _ = collection
    manifest_path = directory / 'collection-manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    missing = {'missing_stage': 'stage-receipt.json', 'missing_launch_intent': 'launch-intent.json',
        'missing_launch_complete': 'launch-receipt.json', 'missing_dispatch': 'dispatch-receipt.json'}
    if mutation in missing:
        (directory / missing[mutation]).unlink()
        del manifest['sha256'][missing[mutation]]
    elif mutation == 'extra_member':
        (directory / 'unexpected.json').write_bytes(b'{}')
    elif mutation == 'report_path':
        manifest['report_path'] += '.different'
    else:
        name = ('stage-receipt.json' if mutation.startswith('stage_') else 'launch-intent.json' if mutation == 'launch_image'
                else 'launch-receipt.json' if mutation.startswith('launch_') else 'qa-result.json'
                if mutation.startswith('qa_') else 'dispatch-receipt.json')
        path = directory / name
        item = json.loads(path.read_bytes())
        if mutation == 'stage_source': item['source_sha256'] = 'a' * 64
        if mutation == 'stage_path': item['stage'] += '/other'
        if mutation == 'stage_input': item['bound_files']['inputs/package.zip'] = 'a' * 64
        if mutation == 'stage_runner': item['bound_files']['source/run-project.mjs'] = 'a' * 64
        if mutation in {'launch_image', 'qa_image', 'dispatch_image'}:
            item['runtime_image_id' if mutation == 'qa_image' else 'image_id'] = 'sha256:' + 'a' * 64
        if mutation == 'launch_failed': item['status'] = 'QA_FAILED_OR_INCOMPLETE'
        if mutation == 'launch_bool_exit': item['exit_code'] = False
        if mutation in {'qa_run', 'dispatch_run'}: item['run_id'] = 'FPQ-20261025T000400-ffffffff'
        if mutation == 'qa_state': item['dispatch_state'] = 'ATTEMPT_INCOMPLETE'
        if mutation == 'qa_no_writes': item['write_attempts'] = []
        if mutation == 'dispatch_job': item['job_id'] = 'fox-' + 'f' * 20
        if mutation == 'dispatch_target': item['target_receipt_sha256'] = 'f' * 64
        if mutation == 'dispatch_package': item['package_sha256'] = 'f' * 64
        if mutation == 'dispatch_time': item['started_at'] = '2027-01-01T00:00:00Z'
        if mutation == 'dispatch_plan': item['test_plan_sha256'] = 'f' * 64
        changed = raw(item); path.write_bytes(changed); manifest['sha256'][name] = sha(changed)
    changed_manifest = raw(manifest)
    manifest_path.write_bytes(changed_manifest)
    options['collection_sha256'] = sha(changed_manifest)
    monkeypatch.setattr(cli.transport, 'run_process', lambda *a, **k: pytest.fail('No promotion after provenance loss'))
    with pytest.raises((ValueError, FileNotFoundError)):
        cli.dispatch('check', directory, **options)


def test_source_closure_hashes_are_exact_and_host_is_python36_compatible():
    assert cli.module_hashes() == {name: sha((ROOT / 'fox/fox' / name).read_bytes()) for name in cli.MODULES}
    source = cli.host_source()
    ast.parse(source, feature_version=(3, 6))
    assert not any(isinstance(item, ast.Assert) for item in ast.walk(ast.parse(source)))
    assert repr(cli.container_source()) in source


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'bad_hash'])
def test_container_loader_rejects_dependencies_before_any_fox_execution(case, monkeypatch, mutation):
    value = packet(case)
    if mutation == 'missing': value['module_sha256'].pop(cli.MODULES[0])
    if mutation == 'extra': value['module_sha256']['unexpected.py'] = 'b' * 64
    fixed = Path('/app/fox') / cli.MODULES[0]
    original_read = Path.read_bytes
    monkeypatch.setattr(Path, 'read_bytes', lambda path: b'raise AssertionError("UNCHECKED")'
                        if path == fixed else original_read(path))
    original_resolve = Path.resolve
    monkeypatch.setattr(Path, 'resolve', lambda path, **kwargs: path if path == fixed else original_resolve(path, **kwargs))
    original_file, original_stat = Path.is_file, Path.stat
    monkeypatch.setattr(Path, 'is_file', lambda path: True if path == fixed else original_file(path))
    monkeypatch.setattr(Path, 'is_symlink', lambda path: False)
    monkeypatch.setattr(Path, 'stat', lambda path, **kwargs: SimpleNamespace(st_nlink=1, st_size=36)
                        if path == fixed else original_stat(path, **kwargs))
    monkeypatch.setattr(os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(os, 'getegid', lambda: 1000, raising=False)
    output = io.StringIO()
    monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw(value))))
    monkeypatch.setattr(sys, 'stdout', output)
    before = sys.modules['fox.project_verification_runtime']
    exec(compile(cli.container_source(), '<project-container-test>', 'exec', optimize=2), {})
    assert json.loads(output.getvalue())['status'] == 'BLOCKED'
    assert sys.modules['fox.project_verification_runtime'] is before


def test_container_loader_imports_entire_reviewed_closure_from_checked_snapshots(case, monkeypatch):
    value = packet(case)
    snapshots = {Path('/app/fox') / name: (ROOT / 'fox/fox' / name).read_bytes() for name in cli.MODULES}
    value['module_sha256'] = {path.name: sha(content) for path, content in snapshots.items()}
    original_read, original_resolve = Path.read_bytes, Path.resolve
    original_file, original_link, original_stat = Path.is_file, Path.is_symlink, Path.stat
    monkeypatch.setattr(Path, 'read_bytes', lambda path: snapshots[path] if path in snapshots else original_read(path))
    monkeypatch.setattr(Path, 'resolve', lambda path, **kwargs: path if path in snapshots else original_resolve(path, **kwargs))
    monkeypatch.setattr(Path, 'is_file', lambda path: True if path in snapshots else original_file(path))
    monkeypatch.setattr(Path, 'is_symlink', lambda path: False if path in snapshots else original_link(path))
    monkeypatch.setattr(Path, 'stat', lambda path, **kwargs: SimpleNamespace(st_nlink=1, st_size=len(snapshots[path]))
                        if path in snapshots else original_stat(path, **kwargs))
    monkeypatch.setattr(os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(os, 'getegid', lambda: 1000, raising=False)
    output = io.StringIO()
    monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(raw(value))))
    monkeypatch.setattr(sys, 'stdout', output)
    # Loading only: no database, file-retention, network or browser operation.
    source = cli.container_source().replace(' result=container_execute(value,gate)',
        " from fox import native_project_pipeline\n result={'status':'LOADED','scope':gate.ATTEMPT_SCOPE}")
    saved = {name: module for name, module in sys.modules.items() if name == 'fox' or name.startswith('fox.')}
    finders = list(sys.meta_path)
    try:
        exec(compile(source, '<project-closure-test>', 'exec', optimize=2), {})
        assert json.loads(output.getvalue()) == {'status': 'LOADED', 'scope': 'fox-project-technical-attempt-v1'}
        assert all('fox.' + name[:-3] in sys.modules for name in cli.MODULES)
        with pytest.raises(ImportError, match='UNCHECKED_PROJECT_DEPENDENCY'):
            __import__('fox.unreviewed', fromlist=['missing'])
    finally:
        for name in list(sys.modules):
            if name == 'fox' or name.startswith('fox.'):
                del sys.modules[name]
        sys.modules.update(saved)
        sys.meta_path[:] = finders
