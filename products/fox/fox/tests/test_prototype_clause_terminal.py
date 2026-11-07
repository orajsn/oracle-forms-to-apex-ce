"""Synthetic retained epoch-two failure; actual local reader, never live proof.

All model replies and source are authored fixtures. Classification must perform
zero model/converter calls, file writes, database writes or external actions.
"""
import builtins
from copy import deepcopy
from datetime import datetime
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
from types import SimpleNamespace

import pytest

from fox import verification_recovery as recovery, worker
from fox.opaf import canonical_hash
from fox.prototype_mapping_epochs import RECORD, PREFIX
from test_prototype_mapping_epochs import EpochModel, PROFILE, epochs_case, tmp_path, submission, api
from test_prototype_epoch_terminal import classify, settings
from test_source_history_api import client, no_external_actions
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read, _snapshot


EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_clause_repair_terminal',
            'retry_eligible': False}


@pytest.fixture(autouse=True)
def authored_unrelated_design(monkeypatch):
    """Ensure preserved arrays and unrelated claims/actions are nonempty."""
    invoke = EpochModel.invoke
    def enrich(self, role, request):
        output, invocation = invoke(self, role, request)
        if role == PROFILE['mapper'] and 'repair_context' not in request and any(
                unit['source_attribute'] == 'WhereClause' for unit in request['code_units']):
            blueprint = output['blueprint']
            owner = request['code_units'][0]['owner_id']
            ref = request['focus_id'] + '-unrelated'
            blueprint['claims'].append({'id': ref, 'source_object_id': owner,
                'kind': 'behavior.intent', 'status': 'proposal', 'value': 'Authored navigation proposal.',
                'evidence_refs': [owner], 'reason': 'Synthetic unrelated design, not clause coverage.'})
            blueprint['actions'].append({'id': ref + '-action', 'claim_ids': [ref]})
            blueprint['questions'].append({'id': ref + '-question', 'source_object_id': owner,
                'text': 'Synthetic review question.'})
            blueprint['assumptions'].append({'id': ref + '-assumption', 'scope': 'prototype-only',
                'text': 'Synthetic prototype assumption.'})
            self.special = deepcopy(output)
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(EpochModel, 'invoke', enrich)


@pytest.fixture
def clause_case(epochs_case, monkeypatch):
    """Author exactly one sealed synthetic repair that only deletes bad claims."""
    case = epochs_case
    plan, body = submission(case)
    assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
    model = case[7]
    invoke = model.invoke
    calls = len(model.calls)
    def deletion_only(role, request):
        output, invocation = invoke(role, request)
        if 'repair_context' in request:
            output = deepcopy(request['repair_context']['raw_candidate'])
            removed = {row['defective_claim_id'] for row in request['repair_context']['requirements']['required_behavior_units']}
            output['blueprint']['claims'] = [row for row in output['blueprint']['claims'] if row['id'] not in removed]
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(model, 'invoke', deletion_only)
    worker.process_one(case[9], case[1])
    assert len(model.calls) == calls + 1
    assert case[8].calls == []
    with case[9]() as db:
        row = db.execute('SELECT state,message FROM runs WHERE id=?', (case[3],)).fetchone()
        assert row['state'] == 'ATTENTION'
    from fox.prototype_focus_projection import validate_repair
    directory = repair_directory(case)
    payload = json.loads((directory / 'mapper-request.json').read_bytes())
    packet = json.loads((case[4] / 'prototype-pipeline' / 'packet.json').read_bytes())
    with pytest.raises(ValueError, match='Repaired clause needs evidenced behavior.intent and an action reference'):
        validate_repair(packet, {key: value for key, value in payload.items() if key != 'repair_context'},
                        payload['repair_context']['raw_candidate'], json.loads((directory / 'mapper.json').read_bytes())['output'],
                        payload['repair_context']['requirements'])
    def forbidden(*args, **kwargs):
        pytest.fail('Classification must never invoke a model or converter')
    monkeypatch.setattr(model, 'invoke', forbidden)
    monkeypatch.setattr(case[8], 'run_stage', forbidden)
    return case


def files(case):
    return {path.relative_to(case[4]).as_posix(): path.read_bytes()
            for path in case[4].rglob('*') if path.is_file()}


def edit(path, mutate):
    value = json.loads(path.read_bytes())
    mutate(value)
    path.write_text(json.dumps(value), encoding='utf-8')


def repair_directory(case):
    record = json.loads((case[4] / RECORD).read_bytes())
    return case[4] / 'prototype-pipeline' / PREFIX / record['plan']['repair_focus_id']


def test_synthetic_sealed_deletion_only_stop_is_read_only_not_retry_or_success(clause_case, monkeypatch):
    before, calls = files(clause_case), deepcopy((clause_case[7].calls, clause_case[8].calls))
    def forbidden(*args, **kwargs):
        pytest.fail('Classifier attempted a file write')
    for name in ('write_bytes', 'write_text', 'mkdir', 'unlink', 'rename', 'touch'):
        monkeypatch.setattr(Path, name, forbidden)
    assert classify(clause_case) == EXPECTED
    assert files(clause_case) == before
    assert (clause_case[7].calls, clause_case[8].calls) == calls
    with clause_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (clause_case[3],)).fetchone())
        assert recovery.terminal_prototype_clause_repair(clause_case[1] / 'fox.sqlite3', db, run)
        assert not recovery.terminal_empty_prototype_mapping(clause_case[1] / 'fox.sqlite3', db, run,
                                                            analysis_epoch_failure=True)
        assert db.total_changes == 0
        assert run['state'] == 'ATTENTION' and run['artifact'] is None


def test_historical_source_pointer_does_not_grant_processing_authority(clause_case):
    with clause_case[9]() as db:
        db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (clause_case[2],))
    assert classify(clause_case) == EXPECTED


@pytest.mark.parametrize('mutation', [
    'missing-record', 'missing-technical', 'missing-predecessor', 'missing-request', 'missing-output',
    'missing-intent', 'missing-target', 'missing-fact-receipt', 'epoch-owner', 'epoch-consent',
    'epoch-predecessor', 'epoch-baseline', 'epoch-checkpoint', 'epoch-plan', 'epoch-policy',
    'epoch-event-missing', 'epoch-event-owner', 'epoch-event-time', 'epoch-event-extra', 'unknown-operation-event',
    'epoch1-event', 'epoch1-baseline', 'epoch1-copy', 'source', 'output-sha', 'output-invocation',
    'output-environment', 'target', 'request', 'unrelated-design', 'unrelated-claim', 'unrelated-action',
    'unrelated-question', 'unrelated-assumption', 'behavior-added', 'one-claim-left',
    'pending-review', 'projection-review', 'downstream-intent', 'downstream-result', 'future-epoch',
    'unknown-file', 'empty-future-directory', 'wrong-state', 'artifact', 'verification-queue', 'acceptance'])
def test_missing_tampered_pending_or_other_failure_blocks(clause_case, mutation):
    case = clause_case
    job, directory = case[4], repair_directory(case)
    epoch_root = job / 'prototype-pipeline' / PREFIX
    path = job / RECORD
    missing = {'missing-record': path, 'missing-technical': epoch_root / 'epoch-record.json',
        'missing-predecessor': epoch_root / 'predecessor-record.json',
        'missing-request': directory / 'mapper-request.json', 'missing-output': directory / 'mapper.json',
        'missing-intent': directory / 'mapper-intent.json', 'missing-target': directory / 'mapper-target.json',
        'missing-fact-receipt': next((epoch_root / 'source-facts').glob('*.json'))}
    if mutation in missing:
        missing[mutation].unlink()
    elif mutation.startswith('epoch-') and not mutation.startswith('epoch-event'):
        key = {'epoch-owner': 'owner', 'epoch-consent': 'approvals', 'epoch-predecessor': 'predecessor_sha256',
               'epoch-baseline': 'before_files', 'epoch-checkpoint': 'checkpoint_sha256',
               'epoch-plan': 'plan', 'epoch-policy': 'normalization_policy'}[mutation]
        edit(path, lambda v: v.update({key: {} if type(v[key]) is dict else '0' * 64}))
    elif mutation == 'epoch1-baseline': edit(job / 'mapping-continuation.json', lambda v: v.update(files={}))
    elif mutation == 'epoch1-copy': edit(epoch_root / 'predecessor-record.json', lambda v: v.update(owner='foreign'))
    elif mutation in ('output-sha', 'output-invocation', 'output-environment'):
        def mutate(v):
            if mutation == 'output-sha': v['output_sha256'] = '0' * 64
            elif mutation == 'output-invocation': v['invocation']['request_sha256'] = '0' * 64
            else: v['model_environment']['job_id'] = 'fox-' + '0' * 20
        edit(directory / 'mapper.json', mutate)
    elif mutation == 'target': edit(directory / 'mapper-target.json', lambda v: v.update(active=False))
    elif mutation == 'request': edit(directory / 'mapper-request.json', lambda v: v['repair_context'].update(requirements={}))
    elif mutation in ('unrelated-design', 'unrelated-claim', 'unrelated-action', 'unrelated-question',
                       'unrelated-assumption', 'behavior-added', 'one-claim-left'):
        payload = json.loads((directory / 'mapper-request.json').read_bytes())
        def mutate(v):
            blueprint = v['output']['blueprint']
            raw = payload['repair_context']['raw_candidate']['blueprint']['claims'][0]
            if mutation == 'unrelated-design': blueprint['objects'][0]['reason'] = 'Changed unrelated design'
            elif mutation == 'unrelated-claim': blueprint['claims'][0]['value'] = 'Changed unrelated claim'
            elif mutation == 'unrelated-action': blueprint['actions'][0]['claim_ids'] = []
            elif mutation == 'unrelated-question': blueprint['questions'][0]['text'] = 'Changed unrelated question'
            elif mutation == 'unrelated-assumption': blueprint['assumptions'][0]['text'] = 'Changed unrelated assumption'
            elif mutation == 'one-claim-left': blueprint['claims'].append(raw)
            else:
                row = deepcopy(raw); row.update(kind='behavior.intent', status='proposal', value='Authored interpretation')
                blueprint['claims'].append(row)
            v['output_sha256'] = canonical_hash(v['output'])
            v['invocation']['response_sha256'] = canonical_hash(v['output'])
        edit(directory / 'mapper.json', mutate)
    elif mutation == 'pending-review': (directory / 'reviewer-intent.json').write_text('{}')
    elif mutation == 'projection-review':
        record = json.loads(path.read_bytes()); later = epoch_root / record['plan']['projection_focus_id']
        later.mkdir(); (later / 'reviewer-request.json').write_text('{}')
    elif mutation == 'downstream-intent': (job / 'prototype-pipeline' / 'prepare_schema-intent.json').write_text('{}')
    elif mutation == 'downstream-result': (job / 'prototype-pipeline' / 'export.json').write_text('{}')
    elif mutation == 'future-epoch': (job / 'mapping-epochs' / 'epoch-000003.json').write_text('{}')
    elif mutation == 'unknown-file': (job / 'unrecognized.json').write_text('{}')
    elif mutation == 'empty-future-directory': (epoch_root / ('focus-' + 'f' * 24)).mkdir()
    else:
        with case[9]() as db:
            if mutation == 'epoch-event-missing': db.execute("DELETE FROM events WHERE action='approved_prototype_mapping_epoch'")
            elif mutation == 'epoch-event-owner': db.execute("UPDATE events SET owner='foreign' WHERE action='approved_prototype_mapping_epoch'")
            elif mutation == 'epoch-event-time': db.execute("UPDATE events SET created=created+1 WHERE action='approved_prototype_mapping_epoch'")
            elif mutation == 'epoch-event-extra': db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                ('synthetic', 'approved_prototype_mapping_epoch', case[3] + ':epoch:000003:' + 'a' * 64, 1))
            elif mutation == 'unknown-operation-event': db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                ('synthetic', 'unknown_future_operation', case[3] + ':future', 1))
            elif mutation == 'epoch1-event': db.execute("DELETE FROM events WHERE action='approved_prototype_mapping_continuation'")
            elif mutation == 'source': db.execute("UPDATE sources SET text=text||' '")
            elif mutation == 'wrong-state': db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (case[3],))
            elif mutation == 'artifact': db.execute("UPDATE runs SET artifact='invented.zip' WHERE id=?", (case[3],))
            elif mutation == 'acceptance': db.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)',
                (case[3], 'synthetic', case[6]['source_hash'], 'a' * 64, 'Authored conflicting acceptance', 1))
            else: db.execute('INSERT INTO verification_queue(job_id,source_manifest_sha256,package_sha256,verifier_release_sha256,binding_sha256,state,created_at_utc,updated_at_utc,record_sha256) VALUES(?,?,?,?,?,?,?,?,?)',
                (case[3], case[6]['source_hash'], 'a' * 64, 'd' * 64, 'b' * 64, 'queued', '2026-11-06T00:00:00Z', '2026-11-06T00:00:00Z', 'c' * 64))
    before, calls = files(case), deepcopy((case[7].calls, case[8].calls))
    assert classify(case)['blocks_admission'] is True
    assert files(case) == before and (case[7].calls, case[8].calls) == calls


def test_self_contained_classifier_works_without_epoch_modules(clause_case):
    original_import = builtins.__import__
    def stdlib_only(name, *args, **kwargs):
        assert name in ('math', 'os'), 'No application or execution modules may be imported'
        return original_import(name, *args, **kwargs)
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': stdlib_only}}
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' + inspect.getsource(recovery.terminal_prototype_clause_repair)
    exec(compile(source, '<stdlib-clause-terminal>', 'exec'), namespace)
    with clause_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (clause_case[3],)).fetchone())
        assert namespace['terminal_prototype_clause_repair'](clause_case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0


@pytest.mark.parametrize('reader_uid,data_uid,mutation,expected', [
    (1000, 1000, None, True), (0, 1000, None, True), (0, 1001, None, False),
    (0, 1000, 'mixed-owner', False), (0, 1000, 'writable', False), (0, 1000, 'hardlink', False),
    (0, 1000, 'symlink', False), (0, 1000, 'linked-ancestor', False)])
def test_stdlib_reader_modeled_posix_metadata(clause_case, reader_uid, data_uid, mutation, expected):
    """Actual local bytes/query-only SQL; POSIX metadata is explicitly modeled."""
    root = clause_case[1]
    class MetadataPath(type(Path())):
        def is_symlink(self):
            return (mutation == 'symlink' and self.name == 'epoch-record.json' or
                    mutation == 'linked-ancestor' and self.name == 'epochs' or super().is_symlink())

        def stat(self, *args, **kwargs):
            actual = super().stat(*args, **kwargs); values = list(actual)
            values[4] = data_uid
            permission = 0o700 if self == root else 0o755 if stat.S_ISDIR(actual.st_mode) else 0o644
            if self.name == 'epoch-record.json':
                if mutation == 'mixed-owner': values[4] += 1
                if mutation == 'writable': permission = 0o666
                if mutation == 'hardlink': values[3] = 2
            values[0] = stat.S_IFMT(actual.st_mode) | permission
            return os.stat_result(values)
    original_import = builtins.__import__
    def isolated(name, *args, **kwargs):
        if name == 'os': return SimpleNamespace(name='posix', geteuid=lambda: reader_uid)
        assert name == 'math'
        return original_import(name, *args, **kwargs)
    namespace = {'Path': MetadataPath, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': isolated}}
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' + inspect.getsource(recovery.terminal_prototype_clause_repair)
    exec(compile(source, '<modeled-posix-clause-terminal>', 'exec'), namespace)
    with clause_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        row = dict(db.execute('SELECT * FROM runs WHERE id=?', (clause_case[3],)).fetchone())
        assert namespace['terminal_prototype_clause_repair'](MetadataPath(root / 'fox.sqlite3'), db, row) is expected
        assert db.total_changes == 0


def combine_history(case, historical):
    historical.root.chmod(0o700)
    shutil.copytree(case[4], historical.root / 'jobs' / case[3])
    with case[9]() as source, sqlite3.connect(historical.database) as destination:
        for table in ('projects', 'sources', 'source_sets', 'source_set_members', 'project_source_selection', 'runs', 'events'):
            columns = [row[1] for row in destination.execute('PRAGMA table_info(' + table + ')')]
            rows = source.execute('SELECT ' + ','.join(columns) + ' FROM ' + table).fetchall()
            destination.executemany('INSERT INTO ' + table + '(' + ','.join(columns) + ') VALUES(' +
                                    ','.join('?' for _ in columns) + ')', [tuple(row) for row in rows])


@pytest.mark.parametrize('startup', [False, True])
def test_actual_local_retirement_reader_keeps_synthetic_clause_failure_distinct(clause_case, historical_case, startup):
    combine_history(clause_case, historical_case)
    before = _snapshot(historical_case)
    result = _read(historical_case, startup=startup)
    assert result['admission_state'] == 'READY'
    assert result['busy_conversion_count'] == result['waiting_verification_count'] == 0
    assert result['completed_retry']['job_id'] != clause_case[3]
    assert result['completed_idle_jobs'] == historical_case.history['idle']['completed_jobs']
    assert _snapshot(historical_case) == before


def test_retirement_reader_rejects_label_without_independent_evidence(clause_case, historical_case, monkeypatch):
    from qa.operator.retirement_remote import RetirementRemoteError
    combine_history(clause_case, historical_case)
    eligibility = recovery.VerificationRecovery._eligibility
    def forged(self, db, job_id):
        return EXPECTED.copy() if job_id == clause_case[3] else eligibility(self, db, job_id)
    monkeypatch.setattr(recovery.VerificationRecovery, '_eligibility', forged)
    monkeypatch.setattr(recovery, 'terminal_prototype_clause_repair', lambda *args: False)
    with pytest.raises(RetirementRemoteError, match='CLAUSE_TERMINAL_UNCONFIRMED'):
        _read(historical_case)
