"""Local protocol isolation only; authored Oracle/browser replies are not live proof."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from forms2apex import prototype_gateway as gateway
from forms2apex.project_reviews import canonical, digest, read_object
from forms2apex.prototype_routes import attach_prototype_routes
from test_prototype_gateway import case, advance
from test_prototype_release import imported_case
from test_prototype_routes import MCP

NONCE = 'a' * 64


def witness(case, job=None):
    return case.adapter.isolation_witness(job or case.request['job_id'], NONCE)


def retained(case):
    return {p.relative_to(case.settings.jobs_root).as_posix(): p.read_bytes()
            for p in case.settings.jobs_root.rglob('*') if p.is_file()}


def seal_import(case):
    """Author the durable SQLcl records that the older modelled importer omits."""
    root = case.root
    imported = case.request['prior_receipts']['import']
    alias = imported['application_alias']
    app = root / '.import-capture-test' / alias.lower()
    for name, text in case.renderer.render_native_blueprint(case.request['rendering_spec']).items():
        path = app / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8', newline='\n')
    reservation = gateway.sqlcl._immutable_record(root / 'import-reservation.json', {
        'schema_version': 1, 'kind': 'sqlcl-apexlang-import-reservation',
        'job_id': case.request['job_id'], 'target_database': gateway.sqlcl._TARGET_DATABASE,
        'connection_name': 'F2A_APEX', 'workspace': 'FORMS2APEX_POC',
        'application_id': imported['application_id'], 'application_alias': alias,
        'artifact_binding': read_object(root / 'snapshot.json'),
        'input': gateway.sqlcl._input_members(root / 'candidate-apexlang.zip')})
    gateway.sqlcl._immutable_record(root / 'import-reservation-receipt.json', {
        'schema_version': 1, 'kind': 'sqlcl-apexlang-import-confirmation',
        'intent_sha256': reservation['record_sha256'], 'sqlcl_import_confirmed': True,
        'compiled_metadata': {'format': 'APEXLANG', 'scope': 'complete_compiled_export_exact_bytes',
            'validated': True, 'snapshot_directory': app.relative_to(root).as_posix(),
            **gateway.sqlcl._input_members(app)}})
    imported['import_intent_sha256'] = reservation['record_sha256']
    imported['log'] = str(root / 'import.log')
    (root / 'import.log').write_bytes(b'authored import completion log')
    (root / 'import.json').write_bytes(canonical(imported))


@pytest.fixture
def stopped(imported_case):
    case = imported_case
    seal_import(case)
    (case.root / 'verify_runtime-request.json').write_bytes(canonical(case.request))
    (case.root / 'verify_runtime-intent.json').write_bytes(canonical({'request_sha256': digest(case.request)}))
    return case


def test_true_absence_two_independent_jobs_no_writes_or_authorization(case):
    case.adapter.authorize = lambda _: pytest.fail('authority callback forbidden')
    for job in (case.request['job_id'], 'fox-' + 'f' * 20):
        value = witness(case, job)
        assert value['boundary'] == 'receiver_absent' and value['job_id'] == job
        assert value['request_sha256'] is None and value['challenge'] == NONCE
        assert value['execution_authorized'] is value['retry_authorized'] is value['closure_claimed'] is False
    assert retained(case) == {} and case.calls == []


def test_runtime_nondispatch_is_read_only_and_never_current_authority(stopped):
    before, calls = retained(stopped), list(stopped.calls)
    stopped.adapter.authorize = lambda _: pytest.fail('authority callback forbidden')
    stopped.adapter._request = lambda *args: pytest.fail('execution request forbidden')
    value = witness(stopped)
    assert value['boundary'] == 'runtime_not_dispatched'
    assert value['request_sha256'] == digest(stopped.request)
    assert value['source_binding'] == stopped.request['source_binding']
    assert value['business_behavior_accepted'] is False
    assert witness(stopped) == value
    assert retained(stopped) == before and stopped.calls == calls


@pytest.mark.parametrize('name', ['runtime-request.json', 'runtime-claim.json', 'runtime-result.json',
    'runtime-receipt.json', 'runtime-evidence', 'verify_runtime.json', 'export-request.json',
    'export-intent.json', 'export-attempt.json', 'export.json', 'prototype-package.zip', 'unknown'])
@pytest.mark.parametrize('directory', [False, True])
def test_dispatch_later_unknown_or_directory_marker_refuses(stopped, name, directory):
    path = stopped.root / name
    path.mkdir() if directory else path.write_bytes(b'preserved')
    before = retained(stopped)
    with pytest.raises((RuntimeError, ValueError)):
        witness(stopped)
    assert retained(stopped) == before


@pytest.mark.parametrize('name', ['verify_runtime-intent.json', 'import.json', 'snapshot.json',
    'prepare_schema.json', 'import-reservation-receipt.json', 'schema-write-intent.json'])
def test_corrupt_retained_stage_refuses(stopped, name):
    (stopped.root / name).write_bytes(b'{}')
    with pytest.raises((RuntimeError, ValueError, KeyError)):
        witness(stopped)


def test_lock_busy_nonblocking_even_for_absence(case):
    with gateway._LOCK:
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(RuntimeError, match='BUSY'):
                pool.submit(witness, case).result(timeout=2)
        with pytest.raises(RuntimeError, match='BUSY'):
            witness(case)


def test_http_auth_challenge_and_no_store(case):
    mcp = MCP()
    attach_prototype_routes(mcp, case.adapter, SimpleNamespace(bearer_token='synthetic-isolation'))
    path = '/fox/prototype/jobs/' + case.request['job_id'] + '/isolation-witness'
    headers = {'Authorization': 'Bearer synthetic-isolation'}
    with TestClient(Starlette(routes=mcp.routes)) as client:
        assert client.get(path, params={'challenge': NONCE}).status_code == 401
        for nonce in ('', 'A' * 64, 'a' * 63, '../escape'):
            assert client.get(path, params={'challenge': nonce}, headers=headers).status_code == 409
        result = client.get(path, params={'challenge': NONCE}, headers=headers)
        assert result.status_code == 200 and result.headers['cache-control'] == 'no-store'
        assert client.get(path, params=[('challenge', NONCE), ('challenge', NONCE)], headers=headers).status_code == 409


def test_partial_receiver_and_bad_job_refuse(case):
    (case.settings.jobs_root / case.request['job_id']).mkdir()
    with pytest.raises(RuntimeError):
        witness(case)
    for job in ('../escape', 'fox-' + 'a' * 20 + '/child'):
        with pytest.raises((ValueError, RuntimeError)):
            witness(case, job)


def test_completed_export_validates_all_retained_outputs(imported_case):
    seal_import(imported_case)
    advance(imported_case, 'verify_runtime')
    advance(imported_case, 'export')
    case = imported_case
    before, calls = retained(case), list(case.calls)
    case.adapter.authorize = lambda _: pytest.fail('authority callback forbidden')
    assert witness(case)['boundary'] == 'export_complete'
    assert retained(case) == before and case.calls == calls
    (case.root / 'runtime-result.json').write_bytes(b'{}')
    with pytest.raises(RuntimeError):
        witness(case)


def test_completed_export_label_without_prior_completion_refuses(imported_case):
    seal_import(imported_case)
    advance(imported_case, 'verify_runtime')
    advance(imported_case, 'export')
    (imported_case.root / 'prepare_schema.json').write_bytes(b'{"status":"COMPLETE"}')
    with pytest.raises(RuntimeError):
        witness(imported_case)


def test_hardlinked_marker_refuses(stopped):
    original = stopped.root / 'verify_runtime-intent.json'
    os.link(original, stopped.root / 'linked.json')
    with pytest.raises(RuntimeError):
        witness(stopped)


@pytest.mark.parametrize('directory', [False, True])
def test_malformed_authority_marker_refuses(stopped, directory):
    path = stopped.root / 'authority-manifest.json'
    path.mkdir() if directory else path.write_bytes(b'{}')
    with pytest.raises((RuntimeError, ValueError, KeyError)):
        witness(stopped)


def test_linked_absent_receiver_refuses(case):
    job = case.settings.jobs_root / case.request['job_id']
    try:
        job.symlink_to(case.settings.jobs_root / 'missing', target_is_directory=True)
    except OSError:
        pytest.skip('Host cannot create symlinks without elevation')
    with pytest.raises(RuntimeError):
        witness(case)


def test_mid_observation_namespace_mutation_refuses(stopped):
    original = stopped.adapter._snapshot
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        (stopped.settings.jobs_root / 'new-peer').mkdir()
        return result
    stopped.adapter._snapshot = changed
    with pytest.raises(RuntimeError):
        witness(stopped)


def test_unrelated_absent_job_does_not_modify_stopped_project(stopped):
    before = retained(stopped)
    assert witness(stopped, 'fox-' + 'e' * 20)['boundary'] == 'receiver_absent'
    assert retained(stopped) == before


def test_known_completed_recovery_markers_and_logs_are_validated(stopped):
    case = stopped
    for prefix, stage, scope in (
        ('validate-recovery-attempt-', 'validate', 'one-retained-validation-maintenance-attempt-v1'),
        ('schema-continuation-attempt-', 'prepare_schema', 'one-retained-schema-continuation-attempt-v1')):
        historical = read_object(case.root / (stage + '-request.json'))
        record = {'scope': scope, 'plan_sha256': 'a' * 64, 'request_sha256': digest(historical),
            'operator': 'synthetic-operator', 'started_at': 1700000000.0}
        (case.root / (prefix + 'a' * 20 + '.json')).write_bytes(canonical(record))
    # Rebind the later envelopes to a genuine recovery-log location.
    log = case.root / ('validation-recovery-' + 'a' * 20 + '.log')
    log.write_bytes(b'authored successful validation log')
    validation = case.request['prior_receipts']['validate']
    validation['validation']['log'] = str(log)
    (case.root / 'validate.json').write_bytes(canonical(validation))
    schema_request = read_object(case.root / 'prepare_schema-request.json')
    schema_request['prior_receipts']['validate'] = validation
    (case.root / 'prepare_schema-request.json').write_bytes(canonical(schema_request))
    (case.root / 'prepare_schema-intent.json').write_bytes(canonical({'request_sha256': digest(schema_request)}))
    schema = case.request['prior_receipts']['prepare_schema']
    schema['request_sha256'] = digest(schema_request)
    (case.root / 'prepare_schema.json').write_bytes(canonical(schema))
    (case.root / 'schema-write-intent.json').write_bytes(canonical({'request_sha256': digest(schema_request),
        'ddl_sha256': schema['schema_ddl_sha256']}))
    marker = case.root / ('schema-continuation-attempt-' + 'a' * 20 + '.json')
    record = read_object(marker)
    record['request_sha256'] = digest(schema_request)
    marker.write_bytes(canonical(record))
    import_request = read_object(case.root / 'import-request.json')
    import_request['prior_receipts'] = {k: case.request['prior_receipts'][k] for k in ('validate', 'prepare_schema')}
    (case.root / 'import-request.json').write_bytes(canonical(import_request))
    (case.root / 'import-intent.json').write_bytes(canonical({'request_sha256': digest(import_request)}))
    case.request['prior_receipts']['import']['request_sha256'] = digest(import_request)
    (case.root / 'import.json').write_bytes(canonical(case.request['prior_receipts']['import']))
    (case.root / 'verify_runtime-request.json').write_bytes(canonical(case.request))
    (case.root / 'verify_runtime-intent.json').write_bytes(canonical({'request_sha256': digest(case.request)}))
    assert witness(case)['boundary'] == 'runtime_not_dispatched'
    record['request_sha256'] = 'f' * 64
    marker.write_bytes(canonical(record))
    with pytest.raises(RuntimeError):
        witness(case)


def test_known_confirmed_import_recovery_and_extra_capture(stopped):
    import shutil
    case = stopped
    imported = case.request['prior_receipts']['import']
    capture = case.root / '.import-capture-reconciled'
    shutil.copytree(case.root / '.import-capture-test', capture)
    log = case.root / ('confirmed-import-reconcile-' + 'b' * 20 + '.log')
    proof = {k: imported[k] for k in ('application_id', 'application_alias', 'workspace',
        'import_intent_sha256', 'compiled_metadata_sha256')}
    proof.update(log=str(log), reconciled=True, reconciliation_scope='exact_identity_and_complete_compiled_metadata', target_writes=False)
    log.write_bytes(canonical(proof))
    imported.update(proof)
    (case.root / 'import.json').write_bytes(canonical(imported))
    additions = {'prototype-converter/' + log.name: hashlib.sha256(log.read_bytes()).hexdigest()}
    additions.update({'prototype-converter/' + p.relative_to(case.root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in capture.rglob('*') if p.is_file()})
    record = {'schema_version': 1, 'scope': 'fox-confirmed-import-readonly-proof-v1',
        'plan_sha256': 'b' * 64, 'proof': proof,
        'request_sha256': digest(read_object(case.root / 'import-request.json')),
        'artifact_binding': read_object(case.root / 'snapshot.json'),
        'converter_additions': additions, 'observed_at_epoch': 1700000000.0}
    (case.root / ('confirmed-import-proof-' + 'b' * 20 + '.json')).write_bytes(canonical(record))
    (case.root / 'verify_runtime-request.json').write_bytes(canonical(case.request))
    (case.root / 'verify_runtime-intent.json').write_bytes(canonical({'request_sha256': digest(case.request)}))
    assert witness(case)['boundary'] == 'runtime_not_dispatched'
    (capture / imported['application_alias'].lower() / 'application.apx').write_bytes(b'changed')
    with pytest.raises(RuntimeError):
        witness(case)
