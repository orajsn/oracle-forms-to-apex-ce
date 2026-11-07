"""Synthetic sealed epoch-three rejection; actual local readers, not live proof.

Sources, analysis and review outputs are authored. No model endpoint, Oracle,
provider replay or business acceptance is part of these admission-only tests.
"""
import builtins
from copy import deepcopy
from datetime import datetime
import hashlib
import inspect
import io
import json
import os
import pathlib
from pathlib import Path
import re
import sqlite3
import sys
from types import SimpleNamespace

import pytest

from fox import verification_recovery as recovery, worker
from fox import prototype_mapping_epochs as epochs, prototype_clause_epoch as clause
from fox.opaf import canonical_hash
from test_prototype_clause_epoch import clause_case, next_body
from test_prototype_mapping_epochs import epochs_case, tmp_path, api
from test_prototype_epoch_terminal import classify, settings
from test_source_history_api import client, no_external_actions
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read, _snapshot


EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_container_review_terminal',
            'retry_eligible': False}


@pytest.fixture
def rejection_case(clause_case, monkeypatch):
    """Exactly one authored projection review rejects the shared-screen design."""
    case = clause_case
    plan, body = next_body(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    invoke = case[7].invoke
    count = len(case[7].calls)
    def rejected(role, payload):
        output, invocation = invoke(role, payload)
        if payload.get('review_context', {}).get('operation') == 'projection_review':
            output.update(verdict='CHANGES_REQUIRED', findings=[
                {'source_object_id': None, 'code': 'MISSING_SCREEN_DECLARATION',
                 'detail': 'Authored synthetic objection to absent local screen declaration.'},
                {'source_object_id': None, 'code': 'INVALID_OBJECT_SCREEN_REF',
                 'detail': 'Authored synthetic objection to context screen references.'}])
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(case[7], 'invoke', rejected)
    worker.process_one(case[9], case[1])
    assert len(case[7].calls) == count + 1 and case[7].calls[-1][0] == 'reviewer'
    assert case[8].calls == []
    with case[9]() as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (case[3],)).fetchone()[0] == 'ATTENTION'
    result = json.loads((case[4] / 'prototype-result.json').read_bytes())
    assert result['status'] == 'CHANGES_REQUIRED'
    def forbidden(*args, **kwargs):
        pytest.fail('Terminal classification must never invoke provider or converter')
    monkeypatch.setattr(case[7], 'invoke', forbidden)
    monkeypatch.setattr(case[8], 'run_stage', forbidden)
    return case


def inventory(case):
    return {path.relative_to(case[4]).as_posix(): path.read_bytes()
            for path in case[4].rglob('*') if path.is_file()}


def review_directory(case):
    record = json.loads((case[4] / clause.RECORD).read_bytes())
    return case[4] / 'prototype-pipeline' / clause.PREFIX / record['plan']['projection_focus_id']


def edit(path, change):
    value = json.loads(path.read_bytes()); change(value)
    path.write_text(json.dumps(value), encoding='utf-8')


def test_exact_synthetic_rejection_is_read_only_and_grants_no_retry_or_success(rejection_case, monkeypatch):
    before, calls = inventory(rejection_case), deepcopy((rejection_case[7].calls, rejection_case[8].calls))
    def forbidden(*args, **kwargs):
        pytest.fail('Read-only classifier attempted to mutate a file')
    for name in ('write_text', 'write_bytes', 'mkdir', 'unlink', 'rename', 'touch'):
        monkeypatch.setattr(Path, name, forbidden)
    assert classify(rejection_case) == EXPECTED
    assert inventory(rejection_case) == before
    assert (rejection_case[7].calls, rejection_case[8].calls) == calls
    with rejection_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (rejection_case[3],)).fetchone())
        assert recovery.terminal_prototype_container_review(rejection_case[1] / 'fox.sqlite3', db, run)
        assert not recovery.terminal_prototype_clause_repair(rejection_case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0 and run['artifact'] is None and run['state'] == 'ATTENTION'


def test_no_mutable_epoch_head_or_runtime_selector_is_used(rejection_case, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Admission must not dispatch through mutable epoch/runtime helpers')
    for module, names in ((epochs, ('validate_epoch_chain', '_validated_epoch_record', 'technical_record', 'active_focus')),
                          (clause, ('validate_record', 'technical_record', 'active_focus', 'model_fence', '_proof'))):
        for name in names:
            monkeypatch.setattr(module, name, forbidden)
    assert classify(rejection_case) == EXPECTED


def test_standalone_terminal_classifier_imports_only_stdlib(rejection_case):
    real_import = builtins.__import__
    def stdlib_only(name, *args, **kwargs):
        assert name in ('math', 'os'), 'No semantic/runtime module may be imported for admission'
        return real_import(name, *args, **kwargs)
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': stdlib_only}}
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' + inspect.getsource(recovery.terminal_prototype_container_review)
    exec(compile(source, '<stdlib-sealed-rejection>', 'exec'), namespace)
    with rejection_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (rejection_case[3],)).fetchone())
        assert namespace['terminal_prototype_container_review'](rejection_case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0


@pytest.mark.parametrize('mutation', [
    'owner', 'source', 'source-set', 'snapshot', 'origin-event', 'epoch1-event', 'epoch2-event',
    'epoch3-event', 'epoch3-owner', 'epoch3-consent', 'epoch3-predecessor', 'epoch3-checkpoint', 'epoch3-baseline',
    'epoch3-copy', 'epoch3-descriptor', 'proof-byte', 'proof-missing', 'analysis-pending', 'clause-review-pending',
    'candidate', 'projection', 'review-request', 'review-output-sha', 'review-environment', 'review-role',
    'review-missing', 'review-intent-missing', 'review-receipt', 'fact-receipt', 'other-finding', 'approved-review',
    'result', 'result-history', 'later-focus', 'new-mapper-intent', 'sqlcl', 'schema', 'import', 'runtime', 'export',
    'epoch4-record', 'epoch4-directory', 'epoch4-event', 'unknown-event', 'unknown-file', 'wrong-state', 'artifact'])
def test_other_unsealed_unknown_tampered_or_future_work_blocks(rejection_case, mutation):
    case, job = rejection_case, rejection_case[4]
    directory = review_directory(case)
    base = job / 'prototype-pipeline' / clause.PREFIX
    pipeline = job / 'prototype-pipeline'
    if mutation in ('owner', 'source', 'origin-event', 'epoch1-event', 'epoch2-event',
                    'epoch3-event', 'epoch4-event', 'unknown-event', 'wrong-state', 'artifact'):
        with case[9]() as db:
            if mutation == 'owner': db.execute("UPDATE projects SET owner='foreign' WHERE id=?", (case[2],))
            elif mutation == 'source': db.execute("UPDATE sources SET text=text||' '")
            elif mutation == 'origin-event': db.execute('DELETE FROM events WHERE object_id=?', (case[3],))
            elif mutation == 'epoch1-event': db.execute("DELETE FROM events WHERE action='approved_prototype_mapping_continuation'")
            elif mutation in ('epoch2-event', 'epoch3-event'):
                number = '000002' if mutation == 'epoch2-event' else '000003'
                db.execute("DELETE FROM events WHERE action='approved_prototype_mapping_epoch' AND object_id LIKE ?",
                           (case[3] + ':epoch:' + number + ':%',))
            elif mutation in ('epoch4-event', 'unknown-event'):
                db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                    (case[5]['approvals']['owner'], 'approved_prototype_mapping_epoch' if mutation == 'epoch4-event'
                     else 'unknown_provider_operation', case[3] + ':epoch:000004:' + 'a' * 64, 1))
            elif mutation == 'wrong-state': db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (case[3],))
            else: db.execute("UPDATE runs SET artifact='invented.zip' WHERE id=?", (case[3],))
    elif mutation == 'snapshot': edit(job / 'source-snapshot.json', lambda v: v.update(source_hash='0' * 64))
    elif mutation == 'source-set': edit(job / 'source-snapshot.json', lambda v: v.update(selected_source_set_id='ss-' + '0' * 32))
    elif mutation in ('epoch3-owner', 'epoch3-consent', 'epoch3-predecessor', 'epoch3-checkpoint', 'epoch3-baseline'):
        key = {'epoch3-owner': 'owner', 'epoch3-consent': 'approvals', 'epoch3-predecessor': 'predecessor_sha256',
               'epoch3-checkpoint': 'checkpoint_sha256', 'epoch3-baseline': 'before_files'}[mutation]
        edit(job / clause.RECORD, lambda v: v.update({key: {} if type(v[key]) is dict else '0' * 64}))
    elif mutation == 'epoch3-copy': edit(base / 'epoch-record.json', lambda v: v.update(owner='foreign'))
    elif mutation == 'epoch3-descriptor': edit(base / 'clause-proof-descriptor.json', lambda v: v.update(candidate_sha256='0' * 64))
    elif mutation == 'proof-byte': (base / 'clause-proof/derived-candidate.json').write_bytes(b'{}')
    elif mutation == 'proof-missing': (base / 'clause-proof/result.json').unlink()
    elif mutation == 'analysis-pending': (base / 'clause-proof/analysis/mapper.json').unlink()
    elif mutation == 'clause-review-pending': (base / 'clause-proof/review/reviewer.json').unlink()
    elif mutation == 'candidate': edit(directory / 'projection-candidate.json', lambda v: v['blueprint']['objects'][0].update(reason='Changed'))
    elif mutation == 'projection': edit(directory / 'projection-receipt.json', lambda v: v['projection'].update(prior_active_proof_sha256='0' * 64))
    elif mutation == 'review-request': edit(directory / 'reviewer-request.json', lambda v: v['review_context'].update(operation='repair_review'))
    elif mutation in ('review-output-sha', 'review-environment', 'review-role', 'other-finding', 'approved-review'):
        def change(v):
            if mutation == 'review-output-sha': v['output_sha256'] = '0' * 64
            elif mutation == 'review-environment': v['model_environment']['job_id'] = 'fox-' + '0' * 20
            elif mutation == 'review-role': v['invocation']['workflow_id'] = 'F' * 32
            else:
                if mutation == 'other-finding': v['output']['findings'][0]['code'] = 'UNKNOWN_FAILURE'
                else: v['output'].update(verdict='APPROVED', findings=[])
                v['output_sha256'] = canonical_hash(v['output'])
                v['invocation']['response_sha256'] = canonical_hash(v['output'])
        edit(directory / 'reviewer.json', change)
    elif mutation == 'review-missing': (directory / 'reviewer.json').unlink()
    elif mutation == 'review-intent-missing': (directory / 'reviewer-intent.json').unlink()
    elif mutation == 'review-receipt': edit(directory / 'review-receipt.json', lambda v: v.update(approved_structured_design=True))
    elif mutation == 'fact-receipt': next((base / 'source-facts').glob('*.json')).unlink()
    elif mutation == 'result': edit(job / 'prototype-result.json', lambda v: v['facts'].update(native_apex_generated=True))
    elif mutation == 'result-history': next((job / 'prototype-results').glob('*.json')).unlink()
    elif mutation == 'later-focus': (base / ('focus-' + 'f' * 24)).mkdir()
    elif mutation == 'new-mapper-intent': (directory / 'mapper-intent.json').write_text('{}')
    elif mutation in ('sqlcl', 'schema', 'import', 'runtime', 'export'):
        stage = {'sqlcl': 'validate', 'schema': 'prepare_schema', 'import': 'import',
                 'runtime': 'verify_runtime', 'export': 'export'}[mutation]
        (pipeline / (stage + '-intent.json')).write_text('{}')
    elif mutation == 'epoch4-record': (job / 'mapping-epochs/epoch-000004.json').write_text('{}')
    elif mutation == 'epoch4-directory': (pipeline / 'epochs/epoch-000004').mkdir()
    else: (job / 'unknown-provider-output.json').write_text('{}')
    before, calls = inventory(case), deepcopy((case[7].calls, case[8].calls))
    assert classify(case)['blocks_admission'] is True
    assert inventory(case) == before and (case[7].calls, case[8].calls) == calls


def combine(case, historical):
    import shutil
    historical.root.chmod(0o700)
    shutil.copytree(case[4], historical.root / 'jobs' / case[3])
    with case[9]() as source, sqlite3.connect(historical.database) as destination:
        for table in ('projects', 'sources', 'source_sets', 'source_set_members', 'project_source_selection', 'runs', 'events'):
            columns = [row[1] for row in destination.execute('PRAGMA table_info(' + table + ')')]
            rows = source.execute('SELECT ' + ','.join(columns) + ' FROM ' + table).fetchall()
            destination.executemany('INSERT INTO ' + table + '(' + ','.join(columns) + ') VALUES(' +
                                    ','.join('?' for _ in columns) + ')', [tuple(row) for row in rows])


@pytest.mark.parametrize('startup', [False, True])
def test_actual_local_retirement_reader_preserves_failure_and_old_completed_proofs(rejection_case, historical_case, startup):
    combine(rejection_case, historical_case)
    before = _snapshot(historical_case)
    result = _read(historical_case, startup=startup)
    assert result['admission_state'] == 'READY'
    assert result['busy_conversion_count'] == result['waiting_verification_count'] == 0
    assert result['completed_retry']['job_id'] != rejection_case[3]
    assert result['completed_idle_jobs'] == historical_case.history['idle']['completed_jobs']
    assert _snapshot(historical_case) == before


def test_retirement_rejects_state_label_without_independent_evidence(rejection_case, historical_case, monkeypatch):
    from qa.operator.retirement_remote import RetirementRemoteError
    combine(rejection_case, historical_case)
    original = recovery.VerificationRecovery._eligibility
    monkeypatch.setattr(recovery.VerificationRecovery, '_eligibility',
        lambda self, db, rid: EXPECTED.copy() if rid == rejection_case[3] else original(self, db, rid))
    monkeypatch.setattr(recovery, 'terminal_prototype_container_review', lambda *args: False)
    with pytest.raises(RetirementRemoteError, match='CLAUSE_TERMINAL_UNCONFIRMED'):
        _read(historical_case)


def generated_reader(case, monkeypatch, *, source_tamper=False, legacy=None):
    """Execute the untouched emitted helper with its REAL measured CheckedFinder.

    Only container paths, UID/GID, environment and stdio are modeled. Production
    source hashes, import loader, SQL/proof readers and history gates run intact.
    No extra module inventory or imported semantic validator is injected.
    """
    from qa.operator import retirement_remote as remote, product_verifier as product
    from qa.operator.tests.test_retirement_remote import configuration
    root = Path(__file__).resolve().parents[2]
    manifest, release, _, config_hash = configuration()
    profile = root / manifest['opaf_profile']['path']
    provider_hash = manifest['hosted_runtime_configuration_sha256']
    if legacy is not None:
        config = product.read_config()
        if legacy == 2:
            config.update(schema_version=2, scope='fox-product-verifier-operator-config-v2', enabled=True)
        manifest = product.build_manifest(config)
        assert manifest['schema_version'] == legacy
        # Historical declarations remain valid, never a hosted destination.
        assert remote.bridge.validate_release(manifest) == manifest
        release = remote.bridge.release_sha256(manifest)
    else:
        assert remote.bridge.validate_release(manifest) == manifest
    program = remote.container_source(release, config_hash)
    assert 'class CheckedFinder' in program and 'FOX_UNBOUND_DEPENDENCY' in program
    request = {'operation': 'retired_history_read', 'apply': False, 'manifest': manifest,
        'release_sha256': release, 'configuration_sha256': config_hash,
        'provider_configuration_sha256': provider_hash, 'history': case.history, 'for_startup': True}
    before = _snapshot(case)
    def mapped_path(*parts):
        path = Path(*parts)
        text = str(parts[0]).replace('\\', '/') if len(parts) == 1 else path.as_posix()
        for prefix, destination in {'/app/fox': root / 'fox/fox', '/data': case.root,
                                   '/run/fox-native/profile.json': profile}.items():
            if text == prefix or text.startswith(prefix + '/'):
                return destination / text[len(prefix):].lstrip('/') if text != prefix else destination
        return path
    real_import, real_open, real_connect = builtins.__import__, Path.open, sqlite3.connect
    imported, exceptions, writes = set(), [], []
    def mapped_import(name, globals=None, locals=None, fromlist=(), level=0):
        filename = str((globals or {}).get('__file__', ''))
        if name == 'pathlib' and (filename == '<generated-container-terminal>' or filename.startswith('/app/fox/')):
            return SimpleNamespace(**{**vars(pathlib), 'Path': mapped_path})
        return real_import(name, globals, locals, fromlist, level)
    def readonly_open(path, mode='r', *args, **kwargs):
        assert not any(char in mode for char in 'wax+'), 'Generated reader attempted a file write'
        stream = real_open(path, mode, *args, **kwargs)
        if source_tamper and path == root / 'fox/fox/verification_recovery.py':
            with stream:
                return io.BytesIO(stream.read() + b'\n# synthetic mismatched source')
        return stream
    denied = {getattr(sqlite3, name) for name in ('SQLITE_INSERT', 'SQLITE_UPDATE', 'SQLITE_DELETE',
        'SQLITE_CREATE_INDEX', 'SQLITE_CREATE_TABLE', 'SQLITE_CREATE_TRIGGER', 'SQLITE_CREATE_VIEW',
        'SQLITE_DROP_INDEX', 'SQLITE_DROP_TABLE', 'SQLITE_DROP_TRIGGER', 'SQLITE_DROP_VIEW',
        'SQLITE_ALTER_TABLE', 'SQLITE_ATTACH', 'SQLITE_DETACH')}
    def readonly_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        connection.execute('PRAGMA query_only=ON')
        def authorize(operation, *details):
            if operation in denied:
                writes.append(operation)
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        connection.set_authorizer(authorize)
        return connection
    modules_before = dict(sys.modules)
    path_before, meta_before = list(sys.path), list(sys.meta_path)
    trace_before, bytecode_before = sys.gettrace(), sys.dont_write_bytecode
    output = io.StringIO()
    def trace(frame, event, arg):
        filename = frame.f_code.co_filename
        if event == 'call' and filename.startswith('/app/fox/'):
            imported.add(filename.rsplit('/', 1)[-1])
        if event == 'exception' and (filename == '<generated-container-terminal>' or filename.startswith('/app/fox/')):
            exceptions.append((filename, frame.f_lineno, type(arg[1]).__name__, str(arg[1])))
        return trace
    try:
        with monkeypatch.context() as patch:
            patch.setattr(builtins, '__import__', mapped_import)
            patch.setattr(Path, 'open', readonly_open)
            patch.setattr(sqlite3, 'connect', readonly_connect)
            patch.setattr(os, 'geteuid', lambda: 1000, raising=False)
            patch.setattr(os, 'getegid', lambda: 1000, raising=False)
            patch.setenv('FOX_VERIFICATION_ENABLED', '1')
            patch.setenv('FOX_VERIFIER_RELEASE_SHA256', release)
            patch.setattr(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(remote._canonical(request))))
            patch.setattr(sys, 'stdout', output)
            sys.settrace(trace)
            exec(compile(program, '<generated-container-terminal>', 'exec', optimize=2),
                 {'__name__': '_generated_container_terminal', '__file__': '<generated-container-terminal>'})
    finally:
        sys.settrace(trace_before)
        sys.path[:] = path_before; sys.meta_path[:] = meta_before
        sys.dont_write_bytecode = bytecode_before
        for name in list(sys.modules):
            if name not in modules_before: sys.modules.pop(name, None)
        sys.modules.update(modules_before)
    assert _snapshot(case) == before and writes == []
    assert not imported & {'prototype_clause_proof.py', 'prototype_clause_analysis.py',
        'prototype_focus_projection.py', 'prototype_pipeline.py', 'prototype_clause_epoch.py',
        'prototype_container_epoch.py'}, 'No unmeasured semantic/runtime source may be imported'
    assert set(sys.modules) == set(modules_before)
    return json.loads(output.getvalue()), imported, exceptions


@pytest.mark.parametrize('mutation', [None, 'tampered-output', 'missing-completion', 'unknown-intent',
                                    'epoch4', 'source-tamper', 'legacy1', 'legacy2'])
def test_actual_generated_reader_checkedfinder_and_readonly_history(rejection_case, historical_case, monkeypatch, mutation):
    combine(rejection_case, historical_case)
    job = historical_case.root / 'jobs' / rejection_case[3]
    record = json.loads((job / clause.RECORD).read_bytes())
    directory = job / 'prototype-pipeline' / clause.PREFIX / record['plan']['projection_focus_id']
    if mutation == 'tampered-output': edit(directory / 'reviewer.json', lambda v: v.update(output_sha256='0' * 64))
    elif mutation == 'missing-completion': (directory / 'reviewer.json').unlink()
    elif mutation == 'unknown-intent': (directory / 'mapper-intent.json').write_text('{}')
    elif mutation == 'epoch4': (job / 'mapping-epochs/epoch-000004.json').write_text('{}')
    result, imported, exceptions = generated_reader(historical_case, monkeypatch,
        source_tamper=mutation == 'source-tamper',
        legacy=int(mutation[-1]) if mutation in ('legacy1', 'legacy2') else None)
    if mutation is None:
        assert result.get('status') == 'RETIRED_HISTORY_OBSERVED', exceptions[-8:]
        assert result['admission_state'] == 'READY'
        assert result['read_only'] is True and result['automatic_replay_permitted'] is False
        assert result['completed_idle_jobs'] == historical_case.history['idle']['completed_jobs']
        assert {'verification_recovery.py', 'verification_queue.py', 'technical_release.py'} <= imported
    else:
        assert result == {'status': 'STOPPED', 'code': 'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY',
                          'automatic_replay_permitted': False}, exceptions[-8:]
