"""Integration boundary tests for native recovery; never contact a database."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from forms2apex import sqlcl
from forms2apex.fox_gateway import attach_routes
from forms2apex.security import alias_for_job
from test_native_workflow import make_job


@pytest.fixture
def recovery(tmp_path_factory, monkeypatch):
    w, root, spec = make_job(tmp_path_factory.mktemp('nr'))
    monkeypatch.setattr(w,'native_target_preflight',lambda *args:{'scope':'isolated-test-preflight'})
    w.generate(root.name, json.dumps(spec))
    monkeypatch.setattr('forms2apex.workflow.validate_apexlang', lambda *a: {'passed': True})
    w.validate(root.name)
    binding = w.assert_artifact_binding(root.name)
    intent = {'job_id': root.name, 'workspace': w.settings.apex_workspace, 'artifact_binding': binding}
    (root / 'import-intent.json').write_text(json.dumps(intent), encoding='utf-8')
    w.store.transition(root.name, 'FAILED', {'import_reconciliation_required': True})
    calls = []
    schema = {'passed': True, 'table_name': spec['native_form']['table_name'], 'columns': spec['native_form']['columns']}
    proof = {'application_id': 123456, 'application_alias': alias_for_job(root.name),
             'workspace': w.settings.apex_workspace, 'reconciled': True, 'target_writes': False,
             'reconciliation_scope': 'exact_identity_and_complete_compiled_metadata',
             'import_intent_sha256': '1' * 64, 'compiled_metadata_sha256': '2' * 64}

    def forbidden(*args, **kwargs):
        pytest.fail('Recovery must never invoke an import or real SQLcl')

    def verify_schema(*args):
        calls.append('schema')
        return dict(schema)

    def reconcile(*args, **kwargs):
        calls.append('reconcile')
        assert args[4] == root / 'apexlang'
        assert kwargs['intent_path'] == root / 'sqlcl-import-intent.json'
        assert kwargs['artifact_binding'] == binding
        assert kwargs['expected_draft_sha256'] == binding['draft_sha256']
        return dict(proof)

    monkeypatch.setattr('forms2apex.workflow.import_apexlang', forbidden)
    monkeypatch.setattr('forms2apex.workflow.import_apexlang_durable', forbidden)
    monkeypatch.setattr(sqlcl, '_run_script', forbidden)
    monkeypatch.setattr('forms2apex.native_target.verify_native_schema', verify_schema)
    monkeypatch.setattr('forms2apex.workflow.reconcile_apexlang_import', reconcile)
    monkeypatch.setattr('forms2apex.workflow.runtime_login_check', lambda url: {'passed': True, 'url': url, 'scope': 'login_only'})
    return SimpleNamespace(w=w, root=root, spec=spec, binding=binding, proof=proof,
                           schema=schema, calls=calls, reconcile=reconcile)


def write_status(case, **changes):
    value = case.w.status(case.root.name)
    value.update(changes)
    case.w.store.write(case.root.name, value)


def imported_receipt(case):
    return {**case.proof, 'job_id': case.root.name, 'artifact_binding': case.binding,
            'application_url': f"{case.w.settings.apex_base_url}/r/{case.w.settings.apex_workspace.lower()}/{case.proof['application_alias'].lower()}/",
            'native_schema_verification': case.schema, 'reconciled': False,
            'log': str(case.root / 'original-import.log')}


def test_failed_native_job_recovers_only_through_read_only_proof(recovery):
    result = recovery.w.reconcile_import(recovery.root.name)
    assert recovery.calls == ['schema', 'reconcile']
    status = recovery.w.status(recovery.root.name)
    assert status['state'] == 'IMPORTED'
    assert status['import_reconciliation_required'] is False
    assert status['import_recovery']['target_writes'] is False
    assert status['import']['artifact_binding'] == recovery.binding
    assert result['application_id'] == recovery.proof['application_id']
    assert (recovery.root / 'import-intent.json').exists()
    assert (recovery.root / 'import-recovery.json').exists()
    recovery.w.assert_artifact_binding(recovery.root.name)


def test_valid_state_after_receipt_before_status_can_recover(recovery):
    write_status(recovery, state='VALID')
    assert recovery.w.reconcile_import(recovery.root.name)['recovery']['reconciled'] is True
    assert recovery.w.status(recovery.root.name)['state'] == 'IMPORTED'


def test_completed_recovery_cannot_be_replayed(recovery):
    recovery.w.reconcile_import(recovery.root.name)
    recovery.calls.clear()
    original = (recovery.root / 'imported-application.json').read_bytes()
    with pytest.raises(RuntimeError, match='recoverable import intent'):
        recovery.w.reconcile_import(recovery.root.name)
    assert recovery.calls == []
    assert (recovery.root / 'imported-application.json').read_bytes() == original


@pytest.mark.parametrize('state', ['VALID', 'FAILED'])
def test_existing_intent_never_reaches_new_import(recovery, state):
    write_status(recovery, state=state)
    with pytest.raises(RuntimeError):
        recovery.w.import_draft(recovery.root.name)
    assert recovery.calls == []


@pytest.mark.parametrize('change', ['failed_validation', 'missing_validation', 'null_validation', 'validation_binding', 'draft', 'native_review', 'intent'])
def test_missing_or_changed_prerequisites_block_before_target_checks(recovery, change):
    if change == 'failed_validation':
        write_status(recovery, validation={'passed': False, 'artifact_binding': recovery.binding})
    elif change == 'missing_validation':
        write_status(recovery, validation={})
    elif change == 'null_validation':
        write_status(recovery, validation=None)
    elif change == 'validation_binding':
        write_status(recovery, validation={'passed': True, 'artifact_binding': {'draft_sha256': 'a' * 64}})
    elif change == 'draft':
        path = recovery.root / 'apexlang/pages/p00002-record.apx'
        path.write_bytes(path.read_bytes() + b'changed')
    elif change == 'native_review':
        (recovery.root / 'native-review.json').unlink()
    else:
        path = recovery.root / 'import-intent.json'
        value = json.loads(path.read_text())
        value['workspace'] = 'UNRELATED_WORKSPACE'
        path.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises((RuntimeError, FileNotFoundError)):
        recovery.w.reconcile_import(recovery.root.name)
    assert recovery.calls == []
    assert recovery.w.status(recovery.root.name)['state'] == 'FAILED'


def test_existing_matching_import_receipt_is_preserved_byte_for_byte(recovery):
    path = recovery.root / 'imported-application.json'
    path.write_text(json.dumps(imported_receipt(recovery), indent=4) + '\n', encoding='utf-8')
    original = path.read_bytes()
    recovery.w.reconcile_import(recovery.root.name)
    assert path.read_bytes() == original
    assert recovery.w.status(recovery.root.name)['import']['reconciled'] is False
    assert recovery.w.status(recovery.root.name)['import_recovery']['reconciled'] is True


def test_existing_schema_proof_timestamp_can_differ_without_rewriting_original(recovery):
    value = imported_receipt(recovery)
    value['native_schema_verification'] = {**value['native_schema_verification'], 'verified_at_utc': '2026-10-16T00:00:00Z'}
    recovery.schema['verified_at_utc'] = '2026-10-16T00:01:00Z'
    path = recovery.root / 'imported-application.json'
    path.write_text(json.dumps(value), encoding='utf-8')
    original = path.read_bytes()
    recovery.w.reconcile_import(recovery.root.name)
    assert path.read_bytes() == original


def test_native_import_receipt_mutation_after_recovery_blocks_release_binding(recovery):
    recovery.w.reconcile_import(recovery.root.name)
    path = recovery.root / 'imported-application.json'
    value = json.loads(path.read_text())
    value['compiled_metadata_sha256'] = 'f' * 64
    path.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises(RuntimeError, match='completion evidence'):
        recovery.w.assert_artifact_binding(recovery.root.name)


@pytest.mark.parametrize('field', ['application_id', 'application_alias', 'workspace', 'application_url',
                                  'compiled_metadata_sha256', 'import_intent_sha256', 'native_schema_verification'])
def test_changed_existing_import_receipt_is_not_blessed(recovery, field):
    value = imported_receipt(recovery)
    value[field] = 999 if field == 'application_id' else 'CHANGED'
    path = recovery.root / 'imported-application.json'
    path.write_text(json.dumps(value), encoding='utf-8')
    original = path.read_bytes()
    with pytest.raises(RuntimeError, match='receipt|changed|differs'):
        recovery.w.reconcile_import(recovery.root.name)
    assert path.read_bytes() == original
    assert recovery.w.status(recovery.root.name)['state'] == 'FAILED'


def test_validation_changed_during_read_only_reconciliation_blocks_promotion(recovery, monkeypatch):
    def mutate(*args, **kwargs):
        result = recovery.reconcile(*args, **kwargs)
        write_status(recovery, validation={'passed': False, 'artifact_binding': recovery.binding})
        return result
    monkeypatch.setattr('forms2apex.workflow.reconcile_apexlang_import', mutate)
    with pytest.raises(RuntimeError, match='validation|Validation|changed'):
        recovery.w.reconcile_import(recovery.root.name)
    assert recovery.w.status(recovery.root.name)['state'] == 'FAILED'
    assert not (recovery.root / 'imported-application.json').exists()


def test_recovery_requires_https_runtime_base_before_any_target_call(recovery):
    recovery.w.settings = replace(recovery.w.settings, apex_base_url='http://example.invalid/ords')
    with pytest.raises(RuntimeError, match='HTTPS'):
        recovery.w.reconcile_import(recovery.root.name)
    assert recovery.calls == []


@pytest.mark.parametrize('proof_change', [{'reconciled': False}, {'target_writes': True},
                                       {'reconciliation_scope': 'identity_only'}])
def test_incomplete_read_only_proof_never_publishes_import_receipt(recovery, proof_change):
    recovery.proof.update(proof_change)
    with pytest.raises(RuntimeError):
        recovery.w.reconcile_import(recovery.root.name)
    assert recovery.w.status(recovery.root.name)['state'] == 'FAILED'
    assert not (recovery.root / 'imported-application.json').exists()


def install_durable_records(case, with_receipt):
    intent_path = case.root / 'sqlcl-import-intent.json'
    intent = sqlcl._immutable_record(intent_path, {
        'schema_version': 1, 'kind': 'sqlcl-apexlang-import-reservation', 'job_id': case.root.name,
        'target_database': 'ASZ8EQWFM8UNCA2_JSNF2APEX', 'connection_name': case.w.settings.sqlcl_connection_name,
        'workspace': case.w.settings.apex_workspace, 'application_id': case.proof['application_id'],
        'application_alias': case.proof['application_alias'], 'artifact_binding': case.binding,
        'input': sqlcl._input_members(case.root / 'apexlang'),
    })
    if with_receipt:
        directory = case.root / '.import-capture-fixture' / case.proof['application_alias'].lower()
        directory.mkdir(parents=True)
        (directory / 'application.apx').write_text('app SYNTHETIC_COMPILED ()', encoding='utf-8')
        compiled = {'format': 'APEXLANG', 'scope': 'complete_compiled_export_exact_bytes',
                    'snapshot_directory': directory.relative_to(case.root).as_posix(), 'validated': True,
                    **sqlcl._input_members(directory)}
        sqlcl._immutable_record(sqlcl._receipt_path(intent_path), {'schema_version': 1,
            'kind': 'sqlcl-apexlang-import-confirmation', 'intent_sha256': intent['record_sha256'],
            'sqlcl_import_confirmed': True, 'compiled_metadata': compiled})
        return directory


@pytest.mark.parametrize('missing', ['confirmation_receipt', 'compiled_snapshot'])
def test_real_low_level_helper_refuses_missing_compiled_proof_without_import(recovery, monkeypatch, missing):
    directory = install_durable_records(recovery, missing == 'compiled_snapshot')
    if directory is not None:
        (directory / 'application.apx').unlink()
    monkeypatch.setattr('forms2apex.workflow.reconcile_apexlang_import', sqlcl.reconcile_apexlang_import)
    with pytest.raises(RuntimeError):
        recovery.w.reconcile_import(recovery.root.name)
    assert recovery.calls == ['schema']
    assert recovery.w.status(recovery.root.name)['state'] == 'FAILED'
    assert not (recovery.root / 'imported-application.json').exists()


@pytest.mark.parametrize('details', [None, {}, {'import': {'application_id': 123}},
    {'import_recovery': {'reconciled': True, 'target_writes': False}},
    {'import_recovery': {'reconciled': True, 'target_writes': False,
        'reconciliation_scope': 'identity_only', 'artifact_binding': 'not-current'}}])
def test_normal_failed_to_imported_transition_remains_invalid(recovery, details):
    original = (recovery.root / 'job-status.json').read_bytes()
    with pytest.raises(RuntimeError, match='invalid job transition'):
        recovery.w.store.transition(recovery.root.name, 'IMPORTED', details)
    assert (recovery.root / 'job-status.json').read_bytes() == original


def test_reconciliation_gateway_requires_bearer_and_returns_blocked_status(recovery):
    routes = []
    class MCP:
        def custom_route(self, path, methods, **kwargs):
            def decorate(function):
                routes.append(Route(path, function, methods=methods))
                return function
            return decorate
    attach_routes(MCP(), recovery.w, recovery.w.settings)
    path = f'/fox/jobs/{recovery.root.name}/actions/reconcile-import'
    with TestClient(Starlette(routes=routes)) as client:
        assert client.post(path, json={}).status_code == 401
        assert recovery.calls == []
        write_status(recovery, validation={})
        result = client.post(path, json={}, headers={'Authorization': 'Bearer ' + recovery.w.settings.bearer_token})
    assert result.status_code == 409
    assert recovery.calls == []
