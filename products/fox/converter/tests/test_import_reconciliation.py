"""Durable import and read-only recovery; all SQLcl execution is mocked."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from forms2apex import sqlcl
from forms2apex.provenance import tree_digest
from forms2apex.security import alias_for_job


JOB = 'fox-' + 'c' * 20
ALIAS = alias_for_job(JOB)
WORKSPACE = 'FORMS2APEX_POC'


@pytest.fixture
def case(tmp_path_factory, monkeypatch):
    root = tmp_path_factory.mktemp('i')
    draft = root / 'draft'
    draft.mkdir()
    (draft / 'application.apx').write_text('app NATIVE_DRAFT ()', encoding='utf-8')
    (draft / 'form.apx').write_text('page 2 ( region record ( type: form ) )', encoding='utf-8')
    binding = {'schema_version': 1, 'job_id': JOB, 'draft_sha256': tree_digest(draft), 'draft_zip_sha256': 'a' * 64}
    data = SimpleNamespace(root=root, draft=draft, binding=binding, intent=root / 'intent.json',
        receipt=root / 'intent-receipt.json', calls=[], mismatch=False, identity='1')

    def run(path, args, commands, cwd, **kwargs):
        script = '\n'.join(commands)
        if 'F2A_ALIAS_COUNT=' in script:
            data.calls.append('precheck')
            first = sqlcl._candidate_application_ids(JOB)[0]
            return subprocess.CompletedProcess([], 0, f'F2A_ALIAS_COUNT=0\nF2A_USED_ID={first}', '')
        if 'apex import ' in script:
            data.calls.append('import')
            assert data.intent.is_file()
            reservation = sqlcl._read_immutable_record(data.intent)
            assert reservation['application_id'] == sqlcl._candidate_application_ids(JOB)[1]
            assert reservation['input']['sha256'] == data.binding['draft_sha256']
            assert reservation['application_alias'] == ALIAS
            assert reservation['workspace'] == WORKSPACE
            assert "FOX reserved application already exists" in script
            assert 'FOX target identity mismatch' in script
            return subprocess.CompletedProcess([], 0, 'Import successful', '')
        if 'apex export ' in script:
            data.calls.append('capture')
            assert 'apex import' not in script
            assert all(command.startswith(('select ', 'apex export ', 'begin if sys_context')) for command in commands)
            app = cwd / ALIAS.lower()
            app.mkdir()
            (app / 'application.apx').write_text(f'app {ALIAS} ()', encoding='utf-8')
            (app / 'form.apx').write_text('compiled-native-form' + ('-different' if data.mismatch else ''), encoding='utf-8')
            return subprocess.CompletedProcess([], 0,
                f'F2A_CAPTURE_IDENTITY={data.identity}\nF2A_CAPTURE_ALIAS=1\nF2A_CAPTURE_IDENTITY_AFTER=1', '')
        if 'apex validate ' in script:
            data.calls.append('validate')
            assert args == ['-S', '/nolog']
            return subprocess.CompletedProcess([], 0, 'Validation successful', '')
        pytest.fail('Unexpected SQLcl command')

    monkeypatch.setattr(sqlcl, '_run_script', run)
    data.run = run
    return data


def invoke(case, reconcile=False, **overrides):
    kwargs = dict(intent_path=case.intent, expected_draft_sha256=case.binding['draft_sha256'], artifact_binding=case.binding)
    kwargs.update(overrides)
    function = sqlcl.reconcile_apexlang_import if reconcile else sqlcl.import_apexlang_durable
    return function(Path('/sql'), 'F2A_APEX', WORKSPACE, JOB, case.draft,
                    case.root / ('reconcile.log' if reconcile else 'import.log'), **kwargs)


def no_calls(monkeypatch):
    monkeypatch.setattr(sqlcl, '_run_script', lambda *a, **k: pytest.fail('No SQLcl call permitted'))


def test_import_reserves_id_and_exact_input_before_mutation(case):
    result = invoke(case)
    assert case.calls == ['precheck', 'import', 'capture', 'validate']
    intent = sqlcl._read_immutable_record(case.intent)
    receipt = sqlcl._read_immutable_record(case.receipt)
    assert result['application_id'] == intent['application_id']
    assert intent['artifact_binding'] == case.binding
    assert intent['target_database'] == 'ASZ8EQWFM8UNCA2_JSNF2APEX'
    assert receipt['intent_sha256'] == result['import_intent_sha256']
    assert receipt['compiled_metadata']['files']['form.apx']
    assert result['reconciled'] is False


def test_new_api_never_replays_existing_success(case, monkeypatch):
    invoke(case)
    no_calls(monkeypatch)
    with pytest.raises(RuntimeError, match='automatic replay is blocked'):
        invoke(case)


@pytest.mark.parametrize('phase', ['import', 'capture', 'receipt_write'])
def test_uncertain_or_incompletely_attested_import_stays_blocked(case, monkeypatch, phase):
    if phase == 'receipt_write':
        original = sqlcl._immutable_record
        def record(path, payload):
            if path == case.receipt:
                raise OSError('receipt disk failure')
            return original(path, payload)
        monkeypatch.setattr(sqlcl, '_immutable_record', record)
    else:
        def interrupted(*args, **kwargs):
            script = '\n'.join(args[2])
            if ('apex import ' if phase == 'import' else 'apex export ') in script:
                raise subprocess.TimeoutExpired('mock-sqlcl', 1)
            return case.run(*args, **kwargs)
        monkeypatch.setattr(sqlcl, '_run_script', interrupted)
    with pytest.raises((OSError, subprocess.TimeoutExpired)):
        invoke(case)
    assert case.intent.is_file()
    assert not case.receipt.exists()
    no_calls(monkeypatch)
    with pytest.raises(RuntimeError, match='automatic replay'):
        invoke(case)
    with pytest.raises(RuntimeError, match='operator reconciliation'):
        invoke(case, reconcile=True)


def test_reconciliation_is_read_only_and_requires_exact_compiled_metadata(case):
    result = invoke(case)
    originals = {p: p.read_bytes() for p in (case.intent, case.receipt, case.root / 'import.log')}
    case.calls.clear()
    recovered = invoke(case, reconcile=True)
    assert case.calls == ['capture', 'validate']
    assert recovered['application_id'] == result['application_id']
    assert recovered['compiled_metadata_sha256'] == result['compiled_metadata_sha256']
    assert recovered['target_writes'] is False
    assert recovered['reconciled'] is True
    assert {p: p.read_bytes() for p in originals} == originals


def test_live_application_component_change_cannot_recover(case):
    invoke(case)
    case.mismatch = True
    case.calls.clear()
    with pytest.raises(RuntimeError, match='differs from confirmed metadata'):
        invoke(case, reconcile=True)
    assert case.calls == ['capture', 'validate']


@pytest.mark.parametrize('identity', ['0', '2', '1\nF2A_CAPTURE_IDENTITY=1'])
def test_missing_duplicate_or_mismatched_identity_cannot_recover(case, identity):
    invoke(case)
    case.identity = identity
    with pytest.raises(RuntimeError, match='identity is not proven'):
        invoke(case, reconcile=True)


@pytest.mark.parametrize('changed', ['draft', 'intent', 'receipt', 'compiled_snapshot'])
def test_changed_local_evidence_is_rejected_before_sqlcl(case, monkeypatch, changed):
    invoke(case)
    if changed == 'draft':
        path = case.draft / 'form.apx'
    elif changed == 'intent':
        path = case.intent
    elif changed == 'receipt':
        path = case.receipt
    else:
        receipt = sqlcl._read_immutable_record(case.receipt)
        path = case.root / receipt['compiled_metadata']['snapshot_directory'] / 'form.apx'
    path.write_bytes(path.read_bytes() + b'changed')
    no_calls(monkeypatch)
    with pytest.raises(RuntimeError):
        invoke(case, reconcile=True)


def test_parent_binding_change_cannot_recover(case, monkeypatch):
    invoke(case)
    no_calls(monkeypatch)
    with pytest.raises(RuntimeError, match='does not match'):
        invoke(case, reconcile=True, artifact_binding={**case.binding, 'reviewed_spec_sha256': 'f' * 64})


def test_partial_intent_file_blocks_even_read_only_guessing(case, monkeypatch):
    case.intent.write_text('{', encoding='utf-8')
    no_calls(monkeypatch)
    with pytest.raises(RuntimeError, match='automatic replay'):
        invoke(case)
    with pytest.raises(RuntimeError, match='operator reconciliation'):
        invoke(case, reconcile=True)


def test_unvalidated_input_is_rejected_before_any_call(case, monkeypatch):
    no_calls(monkeypatch)
    case.draft.joinpath('form.apx').write_text('changed', encoding='utf-8')
    with pytest.raises(RuntimeError, match='differs from the validated'):
        invoke(case)
    assert not case.intent.exists()


def test_input_changed_during_precheck_does_not_reserve_or_import(case, monkeypatch):
    def change(*args, **kwargs):
        result = case.run(*args, **kwargs)
        (case.draft / 'form.apx').write_text('changed', encoding='utf-8')
        return result
    monkeypatch.setattr(sqlcl, '_run_script', change)
    with pytest.raises(RuntimeError, match='changed during reservation'):
        invoke(case)
    assert case.calls == ['precheck']
    assert not case.intent.exists()


def test_input_changed_during_import_retains_intent_without_receipt(case, monkeypatch):
    def change(*args, **kwargs):
        result = case.run(*args, **kwargs)
        if 'apex import ' in '\n'.join(args[2]):
            (case.draft / 'form.apx').write_text('changed', encoding='utf-8')
        return result
    monkeypatch.setattr(sqlcl, '_run_script', change)
    with pytest.raises(RuntimeError, match='changed during execution'):
        invoke(case)
    assert case.intent.exists()
    assert not case.receipt.exists()


def test_intent_write_failure_prevents_import(case, monkeypatch):
    monkeypatch.setattr(sqlcl, '_immutable_record', lambda *a, **k: (_ for _ in ()).throw(OSError('disk full')))
    with pytest.raises(OSError, match='disk full'):
        invoke(case)
    assert case.calls == ['precheck']


def test_failed_validation_of_compiled_export_does_not_issue_receipt(case, monkeypatch):
    def invalid(*args, **kwargs):
        if 'apex validate ' in '\n'.join(args[2]):
            return subprocess.CompletedProcess([], 0, 'APEXLang Compile Errors', '')
        return case.run(*args, **kwargs)
    monkeypatch.setattr(sqlcl, '_run_script', invalid)
    with pytest.raises(RuntimeError, match='did not remain valid'):
        invoke(case)
    assert case.intent.exists()
    assert not case.receipt.exists()


def test_digest_matches_provenance_for_unicode_filenames(case):
    (case.draft / 'résumé.apx').write_text('synthetic Unicode filename', encoding='utf-8')
    assert sqlcl._input_members(case.draft)['sha256'] == tree_digest(case.draft)


def test_local_reservation_does_not_claim_database_lock(case):
    result = invoke(case)
    assert 'database_lock' not in result
    assert 'business_acceptance' not in result


@pytest.mark.parametrize('target', ['intent', 'receipt', 'draft'])
def test_log_cannot_overwrite_durability_or_frozen_input(case, monkeypatch, target):
    no_calls(monkeypatch)
    path = {'intent': case.intent, 'receipt': case.receipt, 'draft': case.draft / 'application.apx'}[target]
    with pytest.raises(ValueError, match='must not overwrite|outside the frozen'):
        sqlcl.import_apexlang_durable(Path('/sql'), 'F2A_APEX', WORKSPACE, JOB, case.draft, path,
            intent_path=case.intent, expected_draft_sha256=case.binding['draft_sha256'], artifact_binding=case.binding)


def test_freshness_check_runs_after_precheck_and_again_immediately_before_write(case):
    checks=[]
    def fresh():checks.append((list(case.calls),case.intent.exists()))
    invoke(case,pre_write_check=fresh)
    assert checks==[(['precheck'],False),(['precheck'],True)]
    assert case.calls==['precheck','import','capture','validate']


@pytest.mark.parametrize('fail_at',[1,2])
def test_expired_preflight_after_wait_never_reaches_import(case,fail_at):
    checked=[]
    def expired():
        checked.append(True)
        if len(checked)==fail_at:raise RuntimeError('Target preflight expired')
    with pytest.raises(RuntimeError,match='expired'):invoke(case,pre_write_check=expired)
    assert case.calls==['precheck']
    assert case.intent.exists() is (fail_at==2)
    assert not case.receipt.exists()
