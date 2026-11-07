"""Local read-only admission classification, not inference or execution proof."""
import ast
import builtins
from copy import deepcopy
from datetime import datetime
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from types import SimpleNamespace

import pytest

from fox import verification_recovery as recovery
from fox.opaf import canonical_hash
from test_prototype_mapping_recovery import recoverable as original_recoverable, url, parent_bytes
from test_prototype_pipeline import TARGET
from test_source_history_api import client, no_external_actions, settings as baseline_settings


EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_mapping_incomplete', 'retry_eligible': False}


@pytest.fixture
def settings(monkeypatch):
    baseline_settings.__wrapped__(monkeypatch)
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'd' * 64)


@pytest.fixture(autouse=True)
def target_contract(monkeypatch):
    monkeypatch.setitem(TARGET, 'active', True)
    monkeypatch.setitem(TARGET, 'scope', {'data_mode': 'synthetic_test_only',
        'existing_resources_only': True, 'customer_deployment_authorized': False})


@pytest.fixture
def recoverable(client, monkeypatch, request, target_contract):
    case = original_recoverable.__wrapped__(client, monkeypatch, request)
    # Model the deployment-owned protected /data root, preserving ordinary
    # historical job755/source644 modes rather than chmodding job originals.
    case[1].chmod(0o700)
    return case


def eligibility(case):
    _, root, _, rid, _, _, _, _, _ = case
    store = recovery.VerificationRecovery(root / 'fox.sqlite3', enabled=True)
    with store._db(False) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        before = db.total_changes
        result = store._eligibility(db, rid)
        assert db.total_changes == before
        return result


def test_enabled_real_admission_accepts_only_terminal_parent_then_queues_distinct_child(recoverable):
    c, root, _, rid, _, _, body, _, model = recoverable
    before, calls = parent_bytes(recoverable), deepcopy(model.calls)
    assert eligibility(recoverable) == EXPECTED
    response = c.post(url(recoverable, 'retry-mapping'), json=body)
    assert response.status_code == 202, response.text
    assert response.json()['id'] != rid
    assert parent_bytes(recoverable) == before and model.calls == calls
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state,artifact FROM runs WHERE id=?', (rid,)).fetchone() == ('ATTENTION', None)
        assert db.execute('SELECT COUNT(*) FROM verification_queue').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    # The newly queued child is genuinely active and still blocks admission.
    store = recovery.VerificationRecovery(root / 'fox.sqlite3', enabled=True)
    with store._db(True) as db:
        assert store.admission_allowed(db) is False


def test_historical_terminal_source_need_not_remain_selected_but_retry_stays_source_bound(recoverable):
    c, root, pid, rid, _, _, body, _, _ = recoverable
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
    before = parent_bytes(recoverable)
    assert eligibility(recoverable) == EXPECTED
    store = recovery.VerificationRecovery(root / 'fox.sqlite3', enabled=True)
    with store._db(True) as db:
        assert store.admission_allowed(db) is True
    assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == 409
    assert parent_bytes(recoverable) == before


@pytest.mark.parametrize('mutation', ['snapshot-hash', 'source-file', 'stored-source', 'retained-member',
    'owner', 'profile', 'invocation-hash', 'environment-hash', 'request-hash', 'binding',
    'object-type', 'object-nonempty', 'claims-nonempty', 'reviewer', 'converter', 'human-review',
    'diagnostics', 'missing-checkpoint', 'wrong-phase', 'nonfinite', 'duplicate-key', 'generic-attention'])
def test_uncertain_stale_tampered_or_later_work_remains_blocking(recoverable, mutation):
    _, root, pid, rid, job, snapshot, _, _, _ = recoverable
    pipeline = job / 'prototype-pipeline'
    mapper = next(pipeline.glob('focus-*/mapper.json'))
    if mutation == 'snapshot-hash':
        snapshot['source_hash'] = '0' * 64
        (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    elif mutation == 'source-file': (pipeline / 'sources' / 'source-000.xml').write_bytes(b'changed')
    elif mutation in ('stored-source', 'owner', 'retained-member'):
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            if mutation == 'owner': db.execute("UPDATE projects SET owner='foreign' WHERE id=?", (pid,))
            elif mutation == 'stored-source': db.execute('UPDATE sources SET text=text||?', (' ',))
            else:
                db.execute('DROP TRIGGER source_set_members_no_update')
                db.execute('UPDATE source_set_members SET sha256=?', ('0' * 64,))
    elif mutation == 'profile':
        target = json.loads((mapper.parent / 'mapper-target.json').read_bytes())
        target['opaf']['roles']['mapper']['model'] = 'different-model'
        (mapper.parent / 'mapper-target.json').write_text(json.dumps(target))
    elif mutation in ('invocation-hash', 'environment-hash', 'object-type', 'object-nonempty', 'claims-nonempty', 'wrong-phase'):
        saved = json.loads(mapper.read_bytes())
        if mutation == 'invocation-hash': saved['invocation']['request_sha256'] = '0' * 64
        elif mutation == 'environment-hash': saved['model_environment_sha256'] = '0' * 64
        elif mutation == 'wrong-phase':
            saved['model_environment']['role'] = 'reviewer'
            saved['model_environment_sha256'] = canonical_hash(saved['model_environment'])
        else:
            field = 'claims' if mutation == 'claims-nonempty' else 'objects'
            saved['output']['blueprint'][field] = {} if mutation == 'object-type' else [{'not': 'empty'}]
            saved['output_sha256'] = canonical_hash(saved['output'])
        mapper.write_text(json.dumps(saved))
    elif mutation == 'request-hash':
        value = json.loads((mapper.parent / 'request.json').read_bytes())
        value['focus_binding'] = '0' * 64
        (mapper.parent / 'request.json').write_text(json.dumps(value))
    elif mutation == 'binding':
        value = json.loads((pipeline / 'binding.json').read_bytes())
        value['focus_plan_sha256'] = '0' * 64
        (pipeline / 'binding.json').write_text(json.dumps(value))
    elif mutation == 'reviewer': (mapper.parent / 'reviewer-intent.json').write_text('{}')
    elif mutation == 'converter': (pipeline / 'import-intent.json').write_text('{}')
    elif mutation == 'human-review': (job / 'prototype-result.json').write_text('{"status":"CHANGES_REQUIRED"}')
    elif mutation == 'diagnostics':
        (job / 'prototype-diagnostics').mkdir()
        (job / 'prototype-diagnostics' / 'terminal.json').write_text('{"terminal":true}')
    elif mutation == 'missing-checkpoint': mapper.unlink()
    elif mutation == 'nonfinite': mapper.write_text('{"value":NaN}')
    elif mutation == 'duplicate-key': mapper.write_text('{"output":{},"output":{}}')
    else: (job / 'source-snapshot.json').write_text('{}')
    before = parent_bytes(recoverable)
    assert eligibility(recoverable)['blocks_admission'] is True
    assert eligibility(recoverable)['retry_eligible'] is False
    assert parent_bytes(recoverable) == before


@pytest.mark.parametrize('namespace_name', ['serving_0100_legacy', 'candidate_current'])
def test_classifier_runs_in_isolated_stdlib_namespace_without_new_prototype_imports(recoverable, namespace_name):
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping)
    imports = [node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert [alias.name for node in imports for alias in node.names] == ['math', 'os']
    original_import = builtins.__import__
    def only_stdlib(name, *args, **kwargs):
        assert name in ('math', 'os'), 'Legacy classifier tried to import a non-stdlib dependency'
        return original_import(name, *args, **kwargs)
    namespace = {'__name__': namespace_name, 'Path': Path, 'json': json, 'hashlib': hashlib,
        're': re, 'datetime': datetime, '__builtins__': {**vars(builtins), '__import__': only_stdlib}}
    exec(compile(source, '<isolated-legacy-classifier>', 'exec'), namespace)
    _, root, _, rid, _, _, _, _, _ = recoverable
    before = parent_bytes(recoverable)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        row = dict(db.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
        assert namespace['terminal_empty_prototype_mapping'](root / 'fox.sqlite3', db, row) is True
        assert db.total_changes == 0
    assert parent_bytes(recoverable) == before


@pytest.mark.skipif(os.name != 'posix', reason='POSIX owner/mode semantics require POSIX; Windows ACLs differ')
@pytest.mark.parametrize('target,mode', [('root', 0o755), ('job', 0o777), ('snapshot', 0o666)])
def test_unprotected_root_or_other_writable_proof_is_not_terminal(recoverable, target, mode):
    path = {'root': recoverable[1], 'job': recoverable[4],
            'snapshot': recoverable[4] / 'source-snapshot.json'}[target]
    path.chmod(mode)
    assert eligibility(recoverable)['blocks_admission'] is True


@pytest.mark.parametrize('reader_uid,data_uid,mutation,expected', [
    (0, 1000, None, True), (1000, 1000, None, True), (0, 1001, None, False),
    (1000, 1000, 'mixed-owner', False), (0, 1000, 'writable', False),
    (0, 1000, 'link', False)])
def test_isolated_posix_owner_contract_supports_stopped_namespace_reader(
        recoverable, reader_uid, data_uid, mutation, expected):
    """Model POSIX metadata only; exact real local bytes/DB remain validated.

    This runs on Windows too. It is not a claim of actual POSIX filesystem QA;
    the separate real-POSIX mode scenarios above run on a POSIX host.
    """
    _, root, _, rid, _, _, _, _, _ = recoverable
    class MetadataPath(type(Path())):
        def stat(self, *args, **kwargs):
            actual = super().stat(*args, **kwargs)
            values = list(actual)
            values[4] = data_uid
            permission = 0o700 if self == root else 0o755 if stat.S_ISDIR(actual.st_mode) else 0o644
            if self.name == 'source-snapshot.json':
                if mutation == 'mixed-owner': values[4] = data_uid + 1
                if mutation == 'writable': permission = 0o666
                if mutation == 'link': values[3] = 2
            values[0] = stat.S_IFMT(actual.st_mode) | permission
            return os.stat_result(values)
    original_import = builtins.__import__
    def posix_import(name, *args, **kwargs):
        if name == 'os':
            return SimpleNamespace(name='posix', geteuid=lambda: reader_uid)
        assert name == 'math'
        return original_import(name, *args, **kwargs)
    namespace = {'Path': MetadataPath, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': posix_import}}
    exec(compile(inspect.getsource(recovery.terminal_empty_prototype_mapping),
                 '<isolated-posix-owner-contract>', 'exec'), namespace)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        row = dict(db.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
        assert namespace['terminal_empty_prototype_mapping'](MetadataPath(root / 'fox.sqlite3'), db, row) is expected
        assert db.total_changes == 0
