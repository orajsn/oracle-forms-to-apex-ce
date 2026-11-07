"""Read-only upgrade admission; authored model evidence, never live-flow proof."""
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

from fox import verification_recovery as recovery
from test_prototype_mapping_epochs import epochs_case, tmp_path
from test_source_history_api import client, settings as baseline_settings, no_external_actions
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read, _snapshot


EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_mapping_analysis_terminal',
            'retry_eligible': False}


@pytest.fixture
def settings(monkeypatch):
    baseline_settings.__wrapped__(monkeypatch)
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'd' * 64)


def classify(case):
    _, root, _, rid, _, _, _, _, _, db, _ = case
    with db() as connection:
        connection.execute('PRAGMA query_only=ON')
        result = recovery.VerificationRecovery(root / 'fox.sqlite3', enabled=True)._eligibility(connection, rid)
        assert connection.total_changes == 0
        return result


def test_sealed_analysis_stop_admits_upgrade_without_retry_or_fact_truth(epochs_case):
    case = epochs_case
    before = {p.relative_to(case[4]): p.read_bytes() for p in case[4].rglob('*') if p.is_file()}
    calls = deepcopy((case[7].calls, case[8].calls))
    assert classify(case) == EXPECTED
    assert calls == (case[7].calls, case[8].calls)
    assert before == {p.relative_to(case[4]): p.read_bytes() for p in case[4].rglob('*') if p.is_file()}
    # A historical source need not remain selected for no-execution proof.
    with case[9]() as db:
        db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (case[2],))
    assert classify(case) == EXPECTED


def test_original_owner_failure_contract_remains_compatible(epochs_case):
    """Restore only the authored fixture's exact immutable pre-continuation set."""
    job = epochs_case[4]
    original = json.loads((job / 'mapping-continuation.json').read_bytes())['files']
    for path in sorted(job.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        if path.is_file() and path.relative_to(job).as_posix() not in original:
            path.unlink()
        elif path.is_dir() and not any(path.iterdir()):
            path.rmdir()
    with epochs_case[9]() as db:
        db.execute("DELETE FROM events WHERE action='approved_prototype_mapping_continuation'")
    assert classify(epochs_case) == {'blocks_admission': False,
        'recovery_state': 'prototype_mapping_owner_resolution_pending', 'retry_eligible': False}


@pytest.mark.parametrize('change', ['unknown', 'pending-review', 'missing-mapper', 'tampered-mapper',
    'environment', 'target', 'snapshot', 'source', 'origin', 'event', 'orphan-event', 'checkpoint',
    'resolution', 'later-db', 'result', 'epoch2', 'epoch2-event', 'acceptance', 'queue', 'wrong-state',
    'context-drift', 'alias-drift'])
def test_unknown_unsealed_changed_or_later_work_blocks(epochs_case, change):
    case = epochs_case
    _, _, _, rid, job, _, _, _, _, db, _ = case
    pipeline = job / 'prototype-pipeline'
    focuses = sorted(pipeline.glob('focus-*'), key=lambda p: json.loads((p / 'request.json').read_bytes())['owned_objects'][0]['location']['byte_offset'])
    last = focuses[-1]
    def edit(path, mutate):
        value = json.loads(path.read_bytes()); mutate(value); path.write_text(json.dumps(value))
    if change == 'unknown': (job / 'unexpected.json').write_text('{}')
    elif change == 'pending-review': (last / 'reviewer-intent.json').write_text('{}')
    elif change == 'missing-mapper': (last / 'mapper.json').unlink()
    elif change == 'tampered-mapper': edit(last / 'mapper.json', lambda v: v.update(output_sha256='0' * 64))
    elif change == 'environment': edit(last / 'mapper.json', lambda v: v['model_environment'].update(job_id='fox-' + '0' * 20))
    elif change == 'target': edit(last / 'mapper-target.json', lambda v: v.update(active=False))
    elif change == 'snapshot': edit(job / 'source-snapshot.json', lambda v: v.update(source_hash='0' * 64))
    elif change == 'checkpoint': edit(job / 'mapping-continuation.json', lambda v: v.update(checkpoint_sha256='0' * 64))
    elif change == 'resolution':
        path = next(pipeline.glob('focus-*/mapper-resolution.json'))
        edit(path, lambda v: v.update(candidate_sha256='0' * 64))
    elif change == 'later-db': (pipeline / 'prepare_schema-intent.json').write_text('{}')
    elif change == 'result': (job / 'prototype-result.json').write_text('{}')
    elif change == 'epoch2':
        (job / 'mapping-epochs').mkdir(); (job / 'mapping-epochs' / 'epoch-0002.json').write_text('{}')
    elif change in ('context-drift', 'alias-drift'):
        def mutate(v):
            blueprint = v['output']['blueprint']
            if change == 'context-drift': blueprint['objects'][-1]['native_component'] = 'report'
            else: blueprint['claims'][-1]['value'] = 'Invented item type'
            from fox.opaf import canonical_hash
            v['output_sha256'] = canonical_hash(v['output'])
        edit(last / 'mapper.json', mutate)
    else:
        with db() as connection:
            if change == 'source': connection.execute("UPDATE sources SET text=text||' '")
            elif change == 'origin': connection.execute('DELETE FROM events WHERE object_id=?', (rid,))
            elif change == 'event': connection.execute("UPDATE events SET owner='foreign' WHERE action='approved_prototype_mapping_continuation'")
            elif change == 'orphan-event': connection.execute("DELETE FROM events WHERE action='approved_prototype_mapping_continuation'")
            elif change == 'epoch2-event': connection.execute("INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)",
                ('synthetic', 'approved_prototype_mapping_epoch', rid + ':' + 'a' * 64, 1))
            elif change == 'wrong-state': connection.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (rid,))
            elif change == 'acceptance': connection.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)',
                (rid, 'synthetic', case[6]['source_hash'], 'a' * 64, 'Authored conflict', 1))
            else: connection.execute('INSERT INTO verification_queue(job_id,source_manifest_sha256,package_sha256,verifier_release_sha256,binding_sha256,state,created_at_utc,updated_at_utc,record_sha256) VALUES(?,?,?,?,?,?,?,?,?)',
                (rid, case[6]['source_hash'], 'a' * 64, 'd' * 64, 'b' * 64, 'queued', '2026-11-06T00:00:00Z', '2026-11-06T00:00:00Z', 'c' * 64))
    assert classify(case)['blocks_admission'] is True


@pytest.mark.parametrize('reader_uid,data_uid,mutation,expected', [
    (1000, 1000, None, True), (0, 1000, None, True), (0, 1001, None, False),
    (0, 1000, 'mixed-owner', False), (0, 1000, 'writable', False), (0, 1000, 'hardlink', False),
    (0, 1000, 'symlink', False)])
def test_old_namespace_stdlib_only_and_modeled_posix_contract(epochs_case, reader_uid, data_uid, mutation, expected):
    """Modeled POSIX metadata, actual local bytes/SQL. Not a live POSIX claim."""
    _, root, _, rid, _, _, _, _, _, db, _ = epochs_case
    class MetadataPath(type(Path())):
        def is_symlink(self):
            return mutation == 'symlink' and self.name == 'mapping-continuation.json' or super().is_symlink()

        def stat(self, *args, **kwargs):
            actual = super().stat(*args, **kwargs); values = list(actual)
            values[4] = data_uid
            permission = 0o700 if self == root else 0o755 if stat.S_ISDIR(actual.st_mode) else 0o644
            if self.name == 'mapping-continuation.json':
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
    exec(compile(inspect.getsource(recovery.terminal_empty_prototype_mapping), '<old-namespace-analysis-stop>', 'exec'), namespace)
    with db() as connection:
        connection.execute('PRAGMA query_only=ON')
        row = dict(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
        assert namespace['terminal_empty_prototype_mapping'](MetadataPath(root / 'fox.sqlite3'), connection, row,
            analysis_epoch_failure=True) is expected
        assert connection.total_changes == 0


@pytest.mark.parametrize('startup', [False, True])
def test_real_retirement_reader_keeps_analysis_distinct_from_completed_proofs(epochs_case, historical_case, startup):
    """Combine authored local histories; production reader validates every row."""
    case, historical = epochs_case, historical_case
    historical.root.chmod(0o700)
    shutil.copytree(case[4], historical.root / 'jobs' / case[3])
    with case[9]() as source, sqlite3.connect(historical.database) as destination:
        for table in ('projects', 'sources', 'source_sets', 'source_set_members',
                      'project_source_selection', 'runs', 'events'):
            columns = [row[1] for row in destination.execute('PRAGMA table_info(' + table + ')')]
            # The application has extra project/run display columns; the old
            # reader's fixture intentionally holds only its required contract.
            selected = ','.join(columns)
            rows = source.execute('SELECT ' + selected + ' FROM ' + table).fetchall()
            destination.executemany('INSERT INTO ' + table + '(' + selected + ') VALUES(' +
                ','.join('?' for _ in columns) + ')', [tuple(row) for row in rows])
    before = _snapshot(historical)
    result = _read(historical, startup=startup)
    assert result['admission_state'] == 'READY'
    assert result['busy_conversion_count'] == result['waiting_verification_count'] == 0
    assert result['completed_retry']['job_id'] != case[3]
    assert result['completed_idle_jobs'] == historical.history['idle']['completed_jobs']
    assert _snapshot(historical) == before
