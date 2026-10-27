"""Read-only harvest recovery with real project package/proof validators.

SQLcl/browser observations are authored fixtures, not live execution evidence.
Only SSH/OCI, confined OS ACL checks and an intentional partial local write are
isolated. All plan, digest, receipt, provenance and promotion readers are real.
"""
import base64
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock
import uuid

import pytest

from qa.operator import contracts as c, project_contracts as pc
from qa.operator import project_clean_install as clean, clean_install as native_clean
from qa.operator import project_qa_dispatch as qa, harvest_project_qa as harvest
from qa.operator import promote_project as promotion
from fox import technical_release
from fox.native_verification_policy import BoundVerificationPolicy
from test_promote_project import collection, case, actual_release, gate, counts, NOW, change_sources


ROOT = Path(__file__).resolve().parents[3]
STAMP = '2026-10-25T00:00:00Z'


def snapshot(directory):
    return {path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob('*') if path.is_file()}


def replace_json(files, name, **updates):
    value = c.load_json(files[name])
    value.update(updates)
    files[name] = c.canonical_bytes(value)
    return value


@pytest.fixture
def retained(collection, case, monkeypatch):
    """Rebind authored observations to a real immutable project clean plan."""
    original, _, _ = collection
    original_bytes = snapshot(original)
    files = {name: original_bytes[name] for name in qa.ALLOWED}
    _, remote, descriptor, source_sha = qa.bundle()
    package = pc.load_package(case.built.package, c.digest(case.built.package))
    source = {'schema_version': 1, 'scope': c.SOURCE_SCOPE, 'observed_at_utc': STAMP,
        'instance_id': c.INSTANCE, 'compartment_id': c.COMPARTMENT, 'region': c.REGION,
        'job_id': case.run_id, 'run_state': 'QA_REQUIRED', 'package_sha256': c.digest(case.built.package),
        'package_bytes': len(case.built.package), 'source_manifest_sha256': case.snapshot['source_hash']}
    plan = pc.make_plan(source, package, case.policy.target['workspace'], STAMP,
                        operator_code_sha256=descriptor['clean_operator_code_sha256'])
    plan_raw = c.canonical_bytes(plan)
    plan_sha = c.digest(plan_raw)
    plan_dir = clean.PRIVATE / plan_sha
    plan_dir.mkdir(mode=0o700)
    plan_path = plan_dir / 'plan.json'
    plan_path.write_bytes(plan_raw); plan_path.chmod(0o600)
    allocation = replace_json(files, 'allocation-receipt.json', plan_sha256=plan_sha)
    pc.validate_allocation(files['allocation-receipt.json'], plan)
    files['verification-profile.json'] = c.canonical_bytes(pc.make_verification_profile(plan, files['allocation-receipt.json']))
    policy = BoundVerificationPolicy(files['verification-profile.json'])
    changed = {'allocation_receipt_sha256': c.digest(files['allocation-receipt.json']),
               'verification_profile_sha256': policy.sha256}
    replace_json(files, 'clean-import-receipt.json', **changed)
    target = replace_json(files, 'target-receipt.json', **changed,
                          import_receipt_sha256=c.digest(files['clean-import-receipt.json']))
    runtime = c.load_json(files['qa-result.json'])
    runtime.update(target=target, target_receipt_sha256=c.digest(files['target-receipt.json']))
    runtime['input_sha256'].update(**changed,
        import_receipt_sha256=c.digest(files['clean-import-receipt.json']),
        target_receipt_sha256=c.digest(files['target-receipt.json']))
    files['qa-result.json'] = c.canonical_bytes(runtime)
    stage_path = '/home/opc/.config/fox-qa/project-v1-stages/' + plan_sha + '/' + source_sha
    tag = 'localhost/fox-project-qa:v1-' + plan_sha[:16] + '-' + source_sha[:16]
    stage = c.load_json(files['stage-receipt.json'])
    stage.update(plan_sha256=plan_sha, allocation_receipt_sha256=changed['allocation_receipt_sha256'],
                 image_tag=tag, stage=stage_path)
    containerfile = ('FROM ' + tag + '-base\nUSER root\nCOPY lib /opt/fox-qa/lib\nCOPY run-project.mjs /opt/fox-qa/\n'
                     'RUN chmod -R a+rX /opt/fox-qa\nUSER pwuser\n').encode()
    stage['bound_files']['source/Containerfile'] = c.digest(containerfile)
    for name, collected in {
        'inputs/allocate.evidence.json': 'allocation-receipt.json',
        'inputs/verification-profile.json': 'verification-profile.json',
        'inputs/verify.evidence.json': 'clean-import-receipt.json',
        'prepared/target.json': 'target-receipt.json'}.items():
        stage['bound_files'][name] = c.digest(files[collected])
    files['stage-receipt.json'] = c.canonical_bytes(stage)
    replace_json(files, 'launch-intent.json', plan_sha256=plan_sha,
                 allocation_receipt_sha256=changed['allocation_receipt_sha256'])
    replace_json(files, 'launch-receipt.json', plan_sha256=plan_sha, result_directory=stage_path + '/results')
    replace_json(files, 'dispatch-receipt.json', **changed,
                 target_receipt_sha256=c.digest(files['target-receipt.json']))
    manifest = {'status': 'COLLECTED', 'credentials_and_logs_excluded': True,
        'plan_sha256': plan_sha, 'source_sha256': source_sha,
        'sha256': {name: c.digest(content) for name, content in files.items()},
        'report_path': stage_path + '/results/' + runtime['run_id'] + '/qa-result.json'}
    # Exercise all provenance checks before making a wire response; no digest
    # or positive validator is mocked, including the independent package gate.
    promotion.collection_provenance(files, manifest, policy)
    wire = {**manifest, 'files': {name: base64.b64encode(content).decode() for name, content in files.items()}}
    source_dir = case.operator.parent / 'retained-source'
    source_dir.mkdir()
    descriptor_path, remote_path, helper_path = (source_dir / name for name in ('descriptor.json', 'remote.py', 'helper.py'))
    descriptor_path.write_bytes(c.canonical_bytes(descriptor))
    remote_path.write_bytes(remote)
    helper_path.write_bytes((qa.HERE / 'native_qa_remote.py').read_bytes())
    output = ROOT / 'work' / ('project-harvest-test-' + uuid.uuid4().hex[:8])
    assert not output.exists()
    calls, scopes, promoted = [], [], []

    def fake_ssh(program, packet):
        calls.append((program, deepcopy(packet)))
        assert packet['plan_sha256'] == plan_sha and packet['source_sha256'] == source_sha
        return deepcopy(wire)

    def fake_scope(**kwargs):
        scopes.append(kwargs)
        assert kwargs == {'require_database_available': False}
        return {'fixture': 'JSN read-only transport'}

    def acl_or_promotion(args, **kwargs):
        if args[0] == 'powershell':
            script = args[-1]
            if 'PRIVATE_PATH_VERIFIED' in script:
                return b'PRIVATE_PATH_VERIFIED'
            if 'PRIVATE_DIRECTORY_PROTECTED' in script:
                return b'PRIVATE_DIRECTORY_PROTECTED'
            if 'PRIVATE_PROJECT_EVIDENCE_VERIFIED' in script:
                return b'PRIVATE_PROJECT_EVIDENCE_VERIFIED'
            pytest.fail('Unexpected OS ACL request')
        # The transport host is fake, but payload parsing and the project
        # container gate are production code over fresh local fixture storage.
        program, body = kwargs['data'].split(b'\n', 1)
        assert base64.b64decode(program).decode() == promotion.host_source()
        request = c.load_json(body)
        promoted.append(deepcopy(request))
        result = promotion.container_execute(request, gate, root=case.root,
            operator_root=case.operator.parent, now=NOW)
        result.update(host_scope_verified=True, expected_image=request['expected_image'],
                      module_sha256=request['module_sha256'])
        return c.canonical_bytes(result)

    monkeypatch.setattr(clean, 'ssh_json', fake_ssh)
    monkeypatch.setattr(clean, 'oci_scope', fake_scope)
    monkeypatch.setattr(clean, 'run_process', acl_or_promotion)
    monkeypatch.setattr(native_clean, 'run_process', acl_or_promotion)
    monkeypatch.setattr(clean, 'dispatch', Mock(side_effect=AssertionError('Harvest must not check or apply SQL')))
    monkeypatch.setattr(clean, 'admin_secret', Mock(side_effect=AssertionError('No secret access')))
    monkeypatch.setattr(subprocess, 'run', Mock(side_effect=AssertionError('No external process')))
    monkeypatch.setattr(socket.socket, 'connect', Mock(side_effect=AssertionError('No external connection')))
    options = {'expected_image': 'sha256:' + 'a' * 64, 'module_sha256': promotion.module_hashes()}
    value = SimpleNamespace(case=case, original=original, original_bytes=original_bytes,
        files=files, wire=wire, plan_path=plan_path, plan_sha=plan_sha, source_sha=source_sha,
        descriptor_path=descriptor_path, remote_path=remote_path, helper_path=helper_path,
        output=output, calls=calls, scopes=scopes, promoted=promoted, options=options)
    yield value
    # Remove only this test's new disposable work output, never any original,
    # plan directory, partial collection, retained proof or live evidence.
    if output.exists():
        assert output.parent == ROOT / 'work' and output.resolve() == output
        assert output.name.startswith('project-harvest-test-') and len(output.name) == 29
        shutil.rmtree(output)


def recover(value, **overrides):
    arguments = {'plan_path': value.plan_path, 'descriptor_path': value.descriptor_path,
        'remote_path': value.remote_path, 'helper_path': value.helper_path,
        'source_sha': value.source_sha, 'output': value.output}
    return harvest.harvest(**(arguments | overrides))


def test_partial_collect_then_harvest_and_real_proof(retained, monkeypatch):
    value = retained
    written, save = [], qa.save_evidence
    def interrupt_after_first(path, content):
        if written:
            raise OSError('Synthetic local collection interruption')
        save(path, content); written.append(path)
    with monkeypatch.context() as boundary:
        boundary.setattr(qa, 'save_evidence', interrupt_after_first)
        with pytest.raises(OSError):
            qa.dispatch('collect', value.plan_path, value.plan_sha, value.source_sha, apply=False)
    partial = value.plan_path.parent / ('qa-' + value.source_sha[:16])
    partial_bytes = snapshot(partial)
    assert len(partial_bytes) == 1 and 'collection-manifest.json' not in partial_bytes
    assert next(iter(partial_bytes.values())) == value.files[written[0].name]
    with pytest.raises(clean.OperatorError):
        qa.dispatch('collect', value.plan_path, value.plan_sha, value.source_sha, apply=False)
    recovered = recover(value)
    assert recovered['remote_writes'] is False
    assert recovered['plan_sha256'] == value.plan_sha and recovered['source_sha256'] == value.source_sha
    assert all((value.output / name).read_bytes() == content for name, content in value.files.items())
    assert snapshot(partial) == partial_bytes and snapshot(value.original) == value.original_bytes
    collection_raw = (value.output / 'collection-manifest.json').read_bytes()
    options = {**value.options, 'collection_sha256': c.digest(collection_raw)}
    checked = promotion.dispatch('check', value.output, **options)
    assert checked['status'] == 'READY_NOT_APPLIED' and checked['read_only'] is True
    assert counts(value.case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}
    promoted = promotion.dispatch('apply', value.output, **options, apply=True)
    assert promoted['status'] == 'VERIFIED' and promoted['event_count'] == promoted['proof_count'] == 1
    assert counts(value.case) == {'proofs': 1, 'technical_events': 1, 'acceptances': 0}
    historical = gate.verify_existing_project_run(root=value.case.root, run_id=value.case.run_id)
    assert historical['read_only'] and historical['idempotent']
    assert historical['proof_sha256'] == promoted['proof_sha256']
    with closing(sqlite3.connect(value.case.root / 'fox.sqlite3')) as db:
        db.row_factory = sqlite3.Row
        row = dict(db.execute('SELECT * FROM runs WHERE id=?', (value.case.run_id,)).fetchone())
        proof = technical_release.checked_release(db, value.case.root, row)
    assert proof['package'] == value.files['package.zip'] and proof['proof']['human_acceptance_recorded'] is False
    assert snapshot(partial) == partial_bytes and snapshot(value.original) == value.original_bytes
    assert len(value.promoted) == 2 and all(scope == {'require_database_available': False} for scope in value.scopes)
    with pytest.raises(clean.OperatorError):
        recover(value)
    assert snapshot(partial) == partial_bytes


@pytest.mark.parametrize('mutation', ['source_sha', 'descriptor', 'reader', 'helper', 'wire_bytes', 'wire_plan', 'wire_missing'])
def test_counterfeit_harvest_stops_before_output(retained, mutation):
    value, overrides = retained, {}
    if mutation == 'source_sha': overrides['source_sha'] = '0' * 64
    elif mutation == 'descriptor':
        descriptor = c.load_json(value.descriptor_path.read_bytes()); descriptor['wrapper_sha256'] = '0' * 64
        value.descriptor_path.write_bytes(c.canonical_bytes(descriptor))
    elif mutation in ('reader', 'helper'):
        path = value.remote_path if mutation == 'reader' else value.helper_path
        path.write_bytes(path.read_bytes() + b'\n# counterfeit fixture\n')
    elif mutation == 'wire_bytes': value.wire['files']['qa-result.json'] = base64.b64encode(b'{}').decode()
    elif mutation == 'wire_plan': value.wire['plan_sha256'] = '0' * 64
    else:
        value.wire['files'].pop('qa-result.json'); value.wire['sha256'].pop('qa-result.json')
    with pytest.raises((clean.OperatorError, c.ContractError)):
        recover(value, **overrides)
    assert not value.output.exists()
    assert snapshot(value.original) == value.original_bytes
    assert counts(value.case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}
    assert value.promoted == []
    if mutation in ('source_sha', 'descriptor', 'reader', 'helper'):
        assert value.calls == [] and value.scopes == []


@pytest.mark.parametrize('mutation', ['failed_receipt', 'stale_receipt', 'stale_selected_source'])
def test_harvested_but_unproven_inputs_cannot_promote(retained, mutation):
    value = retained
    if mutation != 'stale_selected_source':
        runtime = c.load_json(value.files['qa-result.json'])
        runtime.update({'status': 'FAILED'} if mutation == 'failed_receipt' else {'finished_at': '2020-01-01T00:00:00Z'})
        content = c.canonical_bytes(runtime)
        value.wire['files']['qa-result.json'] = base64.b64encode(content).decode()
        value.wire['sha256']['qa-result.json'] = c.digest(content)
    recover(value)
    if mutation == 'stale_selected_source':
        change_sources(value.case)
    options = {**value.options, 'collection_sha256': c.digest((value.output / 'collection-manifest.json').read_bytes())}
    before = snapshot(value.output)
    with pytest.raises((RuntimeError, ValueError, gate.ProjectVerificationError)):
        promotion.dispatch('apply', value.output, **options, apply=True)
    assert snapshot(value.output) == before and snapshot(value.original) == value.original_bytes
    assert counts(value.case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}
