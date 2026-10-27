"""Local-only project QA orchestration with real package/contract readers.

Authored SQLcl and browser observations are test data, not live installation or
QA evidence. External transport, POSIX ownership and process calls are fake.
"""
import ast
import base64
from copy import deepcopy
import json
import shutil
import subprocess
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[3]
for location in (ROOT, ROOT / 'converter', ROOT / 'converter/tests', ROOT / 'fox'):
    sys.path.insert(0, str(location))
from qa.operator import contracts as c, project_contracts as pc, project_remote as clean_remote
from qa.operator import project_qa_dispatch as cli, project_qa_remote as remote, project_qa_contracts as preparation
from qa.operator import harvest_project_qa as harvest
from qa.operator.tests.test_project_clean_operator import case, project_job, vendor_sql, table_markers
from fox.native_qa_plan import qa_plan_sha256
from fox.project_qa_plan import derive_project_qa_plan, derive_project_qa_profile
from fox.project_verification import ProjectVerificationError


@pytest.fixture
def qa_case(case):
    plan, package, package_raw = case
    sources, code, descriptor, source_hash = cli.bundle()
    plan = deepcopy(plan)
    plan['operator_code_sha256'] = descriptor['clean_operator_code_sha256']
    raw = c.canonical_bytes(plan)
    allocation = clean_remote._allocation(plan, {'workspace_id': '12345', 'application_id': 444}, dict(c.VERSIONS))
    allocation_raw = c.canonical_bytes(allocation)
    policy_raw = c.canonical_bytes(pc.make_verification_profile(plan, allocation_raw))
    tables = clean_remote.verify_tables(table_markers(package), package, plan['target']['parsing_schema'])
    compiled = clean_remote.verify_compiled(package, vendor_sql(package['project'], plan['target']['parsing_schema'],
        '12345', 444, plan['target']['application_alias'], 100000), allocation)
    imported = clean_remote.clean_receipt(plan, allocation, allocation_raw, policy_raw, tables, compiled, '2026-10-25T01:01:00Z')
    inputs = {'package.zip': package_raw, 'native-project-spec.json': package['project_raw'],
        'source-to-apex.json': package['trace_raw'], 'allocate.evidence.json': allocation_raw,
        'verification-profile.json': policy_raw, 'verify.evidence.json': c.canonical_bytes(imported),
        'runtime-credentials.json': c.canonical_bytes({'username': 'FOX_QA_A', 'password': 'SyntheticPrimary9!',
            'second_username': 'FOX_QA_B', 'second_password': 'SyntheticSecondary8!'})}
    prepared = preparation.prepare_inputs(raw, inputs, operator_code_sha256=plan['operator_code_sha256'])
    packet = {'command': 'stage', 'apply': True, 'plan_sha256': c.digest(raw), 'plan_b64': base64.b64encode(raw).decode(),
        'source_sha256': source_hash, 'descriptor': descriptor, 'files': {name: base64.b64encode(value).decode() for name, value in sources.items()},
        'remote_b64': base64.b64encode(code).decode(), 'helpers': {name: base64.b64encode((cli.HERE / name).read_bytes()).decode() for name in cli.HELPERS},
        'clean_code': {name: base64.b64encode(value).decode() for name, value in cli.clean.code_bundle()[0].items()}}
    return packet, {**inputs, **prepared}, package


def test_manifest_readonly_exact_runner_closure(monkeypatch):
    for name in ('oci_scope', 'ssh_json', 'admin_secret', 'run_process'):
        monkeypatch.setattr(cli.clean, name, Mock(side_effect=AssertionError('external action')))
    files, remote_raw, descriptor, digest = cli.bundle()
    assert set(files) == remote.FILES
    assert digest == c.digest(c.canonical_bytes(descriptor))
    assert c.digest(remote_raw) == descriptor['remote_sha256']
    assert set(descriptor['helpers']) == {'native_qa_remote.py', 'project_qa_contracts.py'}
    assert 'run-native.mjs' not in files
    ast.parse(remote_raw.decode(), feature_version=(3, 6))
    for program in (cli.HOST, remote.HANDOFF_READER):
        assert not any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(program)))


def test_real_project_inputs_derive_every_form_and_physical_table(qa_case):
    packet, inputs, package = qa_case
    plan = derive_project_qa_plan(package['project'], c.digest(package['project_raw']), package['trace'], c.digest(package['trace_raw']))
    assert c.load_json(inputs['profile.json']) == derive_project_qa_profile(package['project'], plan)
    target = c.load_json(inputs['target.json'])
    assert target['test_plan_sha256'] == qa_plan_sha256(plan)
    assert target['url'].endswith('/fox_qa_261025_abcd1234/f2a_qa_261025_abcd1234/')
    assert remote.validate_handoff(packet, inputs) == c.digest(inputs['allocate.evidence.json'])
    assert len(plan['forms']) == 2 and len(plan['tables']) == 2


def test_python_prepared_inputs_pass_actual_javascript_preflight_without_browser(qa_case):
    node = shutil.which('node')
    if node is None:pytest.skip('Local Node runtime unavailable')
    _, inputs, _ = qa_case
    names = {'targetRaw': 'target.json', 'profileRaw': 'profile.json', 'projectRaw': 'native-project-spec.json',
        'traceRaw': 'source-to-apex.json', 'importRaw': 'verify.evidence.json', 'verificationRaw': 'verification-profile.json',
        'allocationRaw': 'allocate.evidence.json', 'packageRaw': 'package.zip', 'credentialRaw': 'runtime-credentials.json'}
    encoded = {key: base64.b64encode(inputs[name]).decode() for key, name in names.items()}
    script = """import {readFileSync} from 'node:fs';
import {validateProjectRunnerInputs} from './qa/lib/project-runner-inputs.mjs';
const data=JSON.parse(readFileSync(0,'utf8'));
const result=validateProjectRunnerInputs(Object.fromEntries(Object.entries(data).map(([k,v])=>[k,Buffer.from(v,'base64')])),
 {now:Date.parse('2026-10-25T01:02:00Z')});
console.log(JSON.stringify({forms:result.plan.form_count,app:result.target.target.application_id}));
"""
    completed = subprocess.run([node, '--input-type=module', '-e', script], cwd=ROOT,
        input=json.dumps(encoded).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert completed.returncode == 0, completed.stderr.decode()
    assert json.loads(completed.stdout) == {'forms': 2, 'app': 444}


@pytest.mark.parametrize('name', ['package.zip', 'native-project-spec.json', 'source-to-apex.json',
    'allocate.evidence.json', 'verification-profile.json', 'verify.evidence.json'])
def test_input_bytes_cannot_change_or_be_omitted(qa_case, name):
    packet, inputs, _ = qa_case
    exact = {key: raw for key, raw in inputs.items() if key in preparation.HANDOFF}
    broken = dict(exact);broken[name] += b'\x00'
    with pytest.raises((ValueError, RuntimeError)):
        preparation.prepare_inputs(base64.b64decode(packet['plan_b64']), broken,
            operator_code_sha256=packet['descriptor']['clean_operator_code_sha256'])
    del exact[name]
    with pytest.raises((ValueError, RuntimeError)):
        preparation.prepare_inputs(base64.b64decode(packet['plan_b64']), exact,
            operator_code_sha256=packet['descriptor']['clean_operator_code_sha256'])


@pytest.mark.parametrize('member', ['table_metadata', 'module_metadata', 'navigation'])
def test_missing_clean_table_form_or_navigation_rejected(qa_case, member):
    packet, inputs, _ = qa_case
    clean = c.load_json(inputs['verify.evidence.json']);clean[member].pop()
    exact = {key: raw for key, raw in inputs.items() if key in preparation.HANDOFF}
    exact['verify.evidence.json'] = c.canonical_bytes(clean)
    with pytest.raises(ProjectVerificationError):
        preparation.prepare_inputs(base64.b64decode(packet['plan_b64']), exact,
            operator_code_sha256=packet['descriptor']['clean_operator_code_sha256'])


@pytest.mark.parametrize('mutation', ['source', 'helper', 'plan', 'apply', 'base'])
def test_source_changes_fail_before_process_or_private_write(qa_case, monkeypatch, mutation):
    packet, _, _ = qa_case;packet = deepcopy(packet)
    if mutation == 'source':packet['files']['run-project.mjs'] = base64.b64encode(b'changed').decode()
    if mutation == 'helper':packet['helpers']['native_qa_remote.py'] = base64.b64encode(b'changed').decode()
    if mutation == 'plan':packet['plan_b64'] = base64.b64encode(b'changed').decode()
    if mutation == 'apply':packet['apply'] = False
    if mutation == 'base':packet['descriptor']['base_qa_image'] = 'sha256:' + 'a' * 64
    boundary = Mock(side_effect=AssertionError('must fail before boundary'))
    monkeypatch.setattr(remote, 'inspect_baselines', boundary)
    monkeypatch.setattr(remote, 'create', boundary)
    with pytest.raises(RuntimeError):remote.execute(packet)
    boundary.assert_not_called()


@pytest.fixture
def workflow(qa_case, monkeypatch):
    packet, inputs, _ = qa_case
    storage, commands = {}, []
    image = 'sha256:' + 'd' * 64
    stage = remote.ROOT / 'project-v1-stages' / packet['plan_sha256'] / packet['source_sha256']
    def create(path, raw):
        if str(path) in storage:raise RuntimeError('CREATE_ONLY_NO_REPLAY')
        storage[str(path)] = raw
    def command(args, **options):
        commands.append((args, options))
        if args[:3] == ['podman', 'image', 'exists']:return SimpleNamespace(returncode=1, stdout=b'')
        if args[:3] == ['podman', 'image', 'inspect']:return SimpleNamespace(returncode=0, stdout=image.encode())
        if '-e' in args:
            return SimpleNamespace(returncode=0, stdout=c.canonical_bytes({'version': '1.64.0',
                **{name: packet['descriptor']['files'][name] for name in ('package.json', 'package-lock.json')}}))
        return SimpleNamespace(returncode=0, stdout=b'')
    monkeypatch.setattr(remote, 'inspect_baselines', Mock())
    monkeypatch.setattr(remote, 'handoff', Mock(return_value=inputs))
    monkeypatch.setattr(remote, 'private_dir', lambda path, **options: Path(path))
    monkeypatch.setattr(remote, 'create', create)
    monkeypatch.setattr(remote, 'read_private', lambda path, **options: storage[str(path)])
    monkeypatch.setattr(remote, 'command', command)
    monkeypatch.setattr(remote.os, 'getuid', lambda: 1000, raising=False)
    monkeypatch.setattr(remote.os, 'getgid', lambda: 1000, raising=False)
    monkeypatch.setattr(Path, 'exists', lambda path: str(path) in storage)
    return SimpleNamespace(packet=packet, inputs=inputs, stage=stage, storage=storage, commands=commands, image=image, command=command)


def test_stage_offline_overlay_and_one_private_browser_launch(workflow):
    f = workflow
    assert remote.execute(f.packet)['status'] == 'STAGED'
    build = next(args for args, _ in f.commands if args[:2] == ['podman', 'build'])
    assert '--pull=never' in build and '--network=none' in build
    assert not any('npm' in str(args) for args, _ in f.commands)
    f.packet['command'] = 'run'
    assert remote.execute(f.packet)['status'] == 'PASSED'
    calls = [args for args, _ in f.commands if '/opt/fox-qa/run-project.mjs' in args]
    assert len(calls) == 1
    args = calls[0]
    assert '--read-only' in args and '--pull=never' in args and '--cap-drop=all' in args
    assert args[-2:] == [f.image, '/opt/fox-qa/run-project.mjs']
    assert 'FOX_QA_PROJECT_TRACE=/inputs/source-to-apex.json' in args
    assert 'FOX_QA_ALLOCATION_RECEIPT=/inputs/allocate.evidence.json' in args
    assert 'SyntheticPrimary9!' not in str(args)
    assert not any('/dispatch-project-v1/' in path for path in f.storage), 'Only runner writes its dispatch receipt'
    with pytest.raises(RuntimeError, match='CREATE_ONLY_NO_REPLAY'):remote.execute(f.packet)
    assert sum('/opt/fox-qa/run-project.mjs' in args for args, _ in f.commands) == 1


def test_uncertain_browser_never_gets_completion_and_cannot_replay(workflow, monkeypatch):
    f = workflow;remote.execute(f.packet);f.packet['command'] = 'run'
    def timeout(args, **options):
        if '/opt/fox-qa/run-project.mjs' in args:raise RuntimeError('QA_TIMEOUT_UNCERTAIN_NO_REPLAY')
        return f.command(args, **options)
    monkeypatch.setattr(remote, 'command', timeout)
    with pytest.raises(RuntimeError, match='TIMEOUT'):remote.execute(f.packet)
    assert str(f.stage / 'launch.complete.json') not in f.storage
    with pytest.raises(RuntimeError, match='CREATE_ONLY_NO_REPLAY'):remote.execute(f.packet)


def test_retained_collection_after_run_has_no_live_handoff_or_browser(workflow, monkeypatch):
    f = workflow;remote.execute(f.packet);f.packet['command'] = 'run';remote.execute(f.packet)
    report = f.stage / 'results/FPQ-20261025T010203-0123abcd/qa-result.json'
    f.storage[str(report)] = c.canonical_bytes({'run_id': report.parent.name, 'status': 'FAILED', 'write_attempts': [],
                                               'dispatch_state': 'PREFLIGHT_BLOCKED'})
    monkeypatch.setattr(Path, 'glob', lambda *args: [report])
    f.packet.update(command='collect', apply=False)
    boundary = Mock(side_effect=AssertionError('collection cannot re-run'))
    monkeypatch.setattr(remote, 'handoff', boundary);monkeypatch.setattr(remote, 'command', boundary)
    collected = remote.execute(f.packet)
    assert collected['status'] == 'COLLECTED' and collected['credentials_and_logs_excluded'] is True
    assert 'runtime-credentials.json' not in collected['files']
    assert set(collected['files']) == set(collected['sha256'])
    boundary.assert_not_called()
    f.storage[str(report)] = c.canonical_bytes({'run_id': report.parent.name, 'write_attempts': [1]})
    with pytest.raises(RuntimeError, match='DISPATCH_RECEIPT_MISSING'):remote.execute(f.packet)


def test_no_action_flag_or_wrong_exact_hash_reaches_external_transport(qa_case, monkeypatch):
    packet, _, _ = qa_case
    boundary = Mock(side_effect=AssertionError('external call'))
    monkeypatch.setattr(cli.clean, 'read_plan', boundary)
    with pytest.raises(RuntimeError):cli.dispatch('run', 'irrelevant', 'a' * 64, 'b' * 64)
    boundary.assert_not_called()
    raw = base64.b64decode(packet['plan_b64'])
    monkeypatch.setattr(cli.clean, 'read_plan', lambda _: (raw, c.load_json(raw)))
    monkeypatch.setattr(cli.clean, 'oci_scope', boundary);monkeypatch.setattr(cli.clean, 'dispatch', boundary)
    with pytest.raises(RuntimeError):cli.dispatch('run', 'irrelevant', packet['plan_sha256'], 'b' * 64, apply=True)
    boundary.assert_not_called()


def test_collection_corruption_rejected_before_local_directory(qa_case, monkeypatch):
    packet, _, _ = qa_case
    result = {'status': 'COLLECTED', 'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'],
        'credentials_and_logs_excluded': True, 'files': {name: base64.b64encode(b'{}').decode() for name in cli.REQUIRED},
        'sha256': {name: c.digest(b'{}') for name in cli.REQUIRED}}
    result['files']['qa-result.json'] = base64.b64encode(b'changed').decode()
    create = Mock(side_effect=AssertionError('no write before validation'))
    monkeypatch.setattr(cli, 'private_collection', create)
    with pytest.raises(RuntimeError):cli.save_collection(result, Path('unused'), packet['plan_sha256'], packet['source_sha256'])
    create.assert_not_called()


def test_real_local_collection_writes_exact_receipts_once(tmp_path, monkeypatch):
    # Exercise the actual directory restrictions and create-only file writes.
    # ACL implementation is local-only; no remote or secret boundary is used.
    monkeypatch.setattr(cli.clean, 'PRIVATE', tmp_path)
    plan_sha, source_sha = 'a' * 64, 'b' * 64
    plan_dir = tmp_path / plan_sha;cli.clean.private_directory(plan_dir)
    result = {'status': 'COLLECTED', 'plan_sha256': plan_sha, 'source_sha256': source_sha,
        'credentials_and_logs_excluded': True, 'files': {name: base64.b64encode(b'{}').decode() for name in cli.REQUIRED},
        'sha256': {name: c.digest(b'{}') for name in cli.REQUIRED}}
    destination = plan_dir / ('qa-' + source_sha[:16])
    value = cli.save_collection(result, destination, plan_sha, source_sha)
    assert value['local_directory'] == str(destination)
    assert all((destination / name).read_bytes() == b'{}' for name in cli.REQUIRED)
    assert c.load_json((destination / 'collection-manifest.json').read_bytes())['sha256'] == result['sha256']
    with pytest.raises(RuntimeError):cli.save_collection(result, destination, plan_sha, source_sha)
    with pytest.raises(RuntimeError):cli.save_evidence(destination / 'runtime-credentials.json', b'not allowed')
    with pytest.raises(RuntimeError):cli.save_evidence(destination / 'qa-result.json', b'cannot overwrite')


def test_harvest_reader_mismatch_stops_before_oci(qa_case, tmp_path, monkeypatch):
    packet, _, _ = qa_case
    descriptor = tmp_path / 'descriptor.json';descriptor.write_bytes(c.canonical_bytes(packet['descriptor']))
    code = tmp_path / 'remote.py';code.write_bytes(b'changed')
    helper = tmp_path / 'helper.py';helper.write_bytes(base64.b64decode(packet['helpers']['native_qa_remote.py']))
    raw = base64.b64decode(packet['plan_b64'])
    monkeypatch.setattr(cli.clean, 'read_plan', lambda _: (raw, c.load_json(raw)))
    boundary = Mock(side_effect=AssertionError('no external call'))
    monkeypatch.setattr(cli.clean, 'oci_scope', boundary)
    with pytest.raises(RuntimeError):harvest.harvest('unused', descriptor, code, helper, packet['source_sha256'], 'unused')
    boundary.assert_not_called()
