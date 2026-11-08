"""Authored epoch-four rejection; admission only, not live conversion proof."""
import builtins
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime
import hashlib
import inspect
import json
from pathlib import Path
import re
import sqlite3
from types import SimpleNamespace

import pytest

from fox import verification_recovery as recovery, worker
from fox.opaf import canonical_hash
from test_prototype_container_epoch import container_case, container_source_model, next_body, process
from test_prototype_clause_epoch import clause_case
from test_prototype_mapping_epochs import epochs_case, EpochModel, tmp_path, api, PROFILE
from test_prototype_epoch_terminal import classify, settings
from test_source_history_api import client, no_external_actions
from test_prototype_container_terminal import inventory, edit, combine, generated_reader
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read, _snapshot


EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_partition_review_terminal',
            'retry_eligible': False}
_CASE_CACHE = None  # Immutable authored bytes only, never shared mutable job state.


@pytest.fixture(autouse=True)
def authored_two_screen_findings(container_source_model, monkeypatch):
    import test_prototype_container_epoch as synthetic_container
    sealed = synthetic_container.sealed_role
    def independent_root(*args, **kwargs):
        invocation = sealed(*args, **kwargs)
        invocation['room_id'] = 'authored-independent-root-review'
        path = args[0] / args[1] / (args[2] + '.json')
        value = json.loads(path.read_bytes())
        value['invocation'] = invocation
        path.write_text(json.dumps(value), encoding='utf-8')
        return invocation
    monkeypatch.setattr(synthetic_container, 'sealed_role', independent_root)
    invoke = EpochModel.invoke
    def reviewed(self, role, payload):
        output, invocation = invoke(self, role, payload)
        if role == PROFILE['reviewer'] and payload.get('review_context', {}).get('operation') == 'projection_review':
            output.update(verdict='CHANGES_REQUIRED', findings=[
                {'source_object_id': None, 'code': 'MISSING_SCREEN_DECLARATION',
                 'detail': 'Authored objection to local screen declarations.'},
                {'source_object_id': None, 'code': 'INVALID_OBJECT_SCREEN_REF',
                 'detail': 'Authored objection to context screen references.'}])
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(EpochModel, 'invoke', reviewed)


@pytest.fixture
def partition_case(request, tmp_path, settings, monkeypatch):
    # Produce one real local authored API/worker fixture, then copy its immutable
    # sealed bytes and consistent SQLite image into a fresh per-test root. This
    # avoids rerunning the deterministic synthetic mapper chain for every guard.
    global _CASE_CACHE
    if _CASE_CACHE is None:
        case = request.getfixturevalue('container_case')
        _, body = next_body(case)
        count = len(case[7].calls)
        assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
        state, errors = process(case, monkeypatch)
        assert errors == [] and state[0] == 'ATTENTION'
        assert len(case[7].calls) == count + 1 and case[7].calls[-1][0] == 'reviewer'
        assert case[8].calls == []
        result = json.loads((case[4] / 'prototype-result.json').read_bytes())
        assert result['status'] == 'CHANGES_REQUIRED' and 'mapping_epoch_sha256' in result
        with case[9]() as source, sqlite3.connect(':memory:') as memory:
            source.backup(memory)
            database_image = memory.serialize()
        _CASE_CACHE = (inventory(case), database_image,
            deepcopy((case[2], case[3], case[5], case[6], case[7].calls, case[8].calls, case[10])))
    files, database_image, metadata = _CASE_CACHE
    project, run_id, snapshot, body, model_calls, converter_calls, envelope = deepcopy(metadata)
    root = tmp_path / 'sealed'
    job = root / 'jobs' / run_id
    job.mkdir(parents=True)
    root.chmod(0o700)
    for name, raw in files.items():
        path = job / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (root / 'fox.sqlite3').write_bytes(database_image)
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3')
        connection.row_factory = sqlite3.Row
        try:
            with connection: yield connection
        finally: connection.close()
    def forbidden(*args, **kwargs): pytest.fail('Admission must never invoke a model or converter.')
    model = SimpleNamespace(calls=model_calls, invoke=forbidden)
    converter = SimpleNamespace(calls=converter_calls, run_stage=forbidden)
    return None, root, project, run_id, job, snapshot, body, model, converter, db, envelope


def directory(case, epoch=4):
    record = json.loads((case[4] / 'mapping-epochs' / ('epoch-%06d.json' % epoch)).read_bytes())
    return case[4] / 'prototype-pipeline' / ('epochs/epoch-%06d' % epoch) / record['plan']['projection_focus_id']


def test_exact_sealed_four_admits_only_preservation_not_retry_or_success(partition_case, monkeypatch):
    before, calls = inventory(partition_case), deepcopy((partition_case[7].calls, partition_case[8].calls))
    def forbidden(*args, **kwargs): pytest.fail('Admission attempted a file write.')
    for name in ('write_text', 'write_bytes', 'mkdir', 'unlink', 'rename', 'touch'):
        monkeypatch.setattr(Path, name, forbidden)
    assert classify(partition_case) == EXPECTED
    assert inventory(partition_case) == before and (partition_case[7].calls, partition_case[8].calls) == calls
    with partition_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (partition_case[3],)).fetchone())
        assert recovery.terminal_prototype_partition_review(partition_case[1] / 'fox.sqlite3', db, run)
        assert not recovery.terminal_prototype_container_review(partition_case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0 and run['state'] == 'ATTENTION' and run['artifact'] is None


def test_standalone_four_imports_only_stdlib_and_no_mutable_head(partition_case):
    original = builtins.__import__
    def stdlib(name, *args, **kwargs):
        assert name in ('math', 'os')
        return original(name, *args, **kwargs)
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': stdlib}}
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' + inspect.getsource(recovery.terminal_prototype_partition_review)
    exec(compile(source, '<stdlib-partition-terminal>', 'exec'), namespace)
    with partition_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (partition_case[3],)).fetchone())
        assert namespace['terminal_prototype_partition_review'](partition_case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0


def test_historical_source_selection_semantics_unchanged(partition_case):
    with partition_case[9]() as db:
        db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (partition_case[2],))
    assert classify(partition_case) == EXPECTED


@pytest.mark.parametrize('mutation', ['owner', 'source', 'source-set', 'origin-event', 'epoch1-event',
    'epoch2-event', 'epoch3-event', 'epoch4-event', 'extra-event', 'epoch4-owner', 'epoch4-time',
    'epoch4-before', 'epoch4-copy', 'epoch4-predecessor', 'root-descriptor', 'root-member',
    'root-review', 'root-pending', 'root-proposal', 'old-three-review', 'current-request', 'current-candidate',
    'current-receipt', 'current-facts', 'current-pending', 'current-role', 'current-environment', 'current-time',
    'current-approval', 'same-room', 'publication', 'archive', 'history', 'latest', 'schema', 'later-focus',
    'epoch5-record', 'epoch5-directory', 'extra-file', 'wrong-state', 'artifact'])
def test_unknown_incomplete_tampered_or_later_work_stays_blocked(partition_case, mutation):
    case, job = partition_case, partition_case[4]
    current = directory(case)
    fourth = job / 'prototype-pipeline/epochs/epoch-000004'
    root = fourth / 'container-proof'
    if mutation in ('owner', 'origin-event', 'epoch1-event', 'epoch2-event', 'epoch3-event', 'epoch4-event',
                    'extra-event', 'wrong-state', 'artifact'):
        with case[9]() as db:
            if mutation == 'owner': db.execute("UPDATE projects SET owner='foreign' WHERE id=?", (case[2],))
            elif mutation == 'origin-event': db.execute('DELETE FROM events WHERE object_id=?', (case[3],))
            elif mutation == 'epoch1-event': db.execute("DELETE FROM events WHERE action='approved_prototype_mapping_continuation'")
            elif mutation.endswith('-event') and mutation != 'extra-event':
                number = int(mutation[5])
                db.execute('DELETE FROM events WHERE action=? AND object_id LIKE ?',
                    ('approved_prototype_mapping_epoch', case[3] + ':epoch:%06d:%%' % number))
            elif mutation == 'extra-event': db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                (case[5]['approvals']['owner'], 'unknown_operation', case[3] + ':unexpected', 1))
            elif mutation == 'wrong-state': db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (case[3],))
            else: db.execute("UPDATE runs SET artifact='invented.zip' WHERE id=?", (case[3],))
    elif mutation in ('source', 'source-set'):
        edit(job / 'source-snapshot.json', lambda v: v.update({
            'source_hash' if mutation == 'source' else 'selected_source_set_id': '0' * 64 if mutation == 'source' else 'ss-' + '0' * 32}))
    elif mutation in ('epoch4-owner', 'epoch4-time', 'epoch4-before'):
        edit(job / 'mapping-epochs/epoch-000004.json', lambda v: v.update({
            'owner' if mutation == 'epoch4-owner' else 'approved_at' if mutation == 'epoch4-time' else 'before_files':
            'foreign' if mutation == 'epoch4-owner' else 0 if mutation == 'epoch4-time' else {}}))
    elif mutation == 'epoch4-copy': edit(fourth / 'epoch-record.json', lambda v: v.update(owner='foreign'))
    elif mutation == 'epoch4-predecessor': edit(fourth / 'predecessor-record.json', lambda v: v.update(owner='foreign'))
    elif mutation == 'root-descriptor': edit(fourth / 'container-proof-descriptor.json', lambda v: v.update(candidate_sha256='0' * 64))
    elif mutation == 'root-member': (root / 'prefix-check.json').write_bytes(b'{}')
    elif mutation == 'root-review': edit(root / 'review/reviewer.json', lambda v: v.update(output_sha256='0' * 64))
    elif mutation == 'root-pending': (root / 'review/reviewer.json').unlink()
    elif mutation == 'root-proposal': edit(root / 'container-proposal.json', lambda v: v.update(proposal_status='APPROVED'))
    elif mutation == 'old-three-review': edit(directory(case, 3) / 'reviewer.json', lambda v: v.update(output_sha256='0' * 64))
    elif mutation == 'current-request': edit(current / 'reviewer-request.json', lambda v: v['design_context'].update(structural_prefix_valid=True))
    elif mutation == 'current-candidate': edit(current / 'projection-candidate.json', lambda v: v['blueprint']['objects'][0].update(reason='Changed'))
    elif mutation == 'current-receipt': edit(current / 'review-receipt.json', lambda v: v.update(approved_structured_design=True))
    elif mutation == 'current-facts': next((fourth / 'source-facts').glob('*.json')).unlink()
    elif mutation == 'current-pending': (current / 'reviewer.json').unlink()
    elif mutation in ('current-role', 'current-environment', 'current-time', 'current-approval', 'same-room'):
        def change(v):
            if mutation == 'current-role': v['invocation']['workflow_id'] = 'F' * 32
            elif mutation == 'current-environment': v['model_environment']['job_id'] = 'fox-' + '0' * 20
            elif mutation == 'current-time': v['invocation']['completed_at_utc'] = 'not-a-time'
            elif mutation == 'same-room': v['invocation']['room_id'] = json.loads((directory(case, 3) / 'reviewer.json').read_bytes())['invocation']['room_id']
            else:
                v['output'].update(verdict='APPROVED', findings=[])
                v['output_sha256'] = canonical_hash(v['output'])
        edit(current / 'reviewer.json', change)
    elif mutation == 'publication': edit(job / 'prototype-result-publications/epoch-000004/publication.json', lambda v: v.update(active_proofs_sha256='0' * 64))
    elif mutation == 'archive': (job / 'prototype-result-publications/epoch-000004/previous-result.json').write_bytes(b'{}')
    elif mutation == 'history':
        latest = json.loads((job / 'prototype-result.json').read_bytes())
        (job / ('prototype-results/' + canonical_hash(latest) + '.json')).unlink()
    elif mutation == 'latest': edit(job / 'prototype-result.json', lambda v: v['facts'].update(native_apex_generated=True))
    elif mutation == 'schema': (job / 'prototype-pipeline/prepare_schema-intent.json').write_bytes(b'{}')
    elif mutation == 'later-focus': (fourth / ('focus-' + 'f' * 24)).mkdir()
    elif mutation == 'epoch5-record': (job / 'mapping-epochs/epoch-000005.json').write_bytes(b'{}')
    elif mutation == 'epoch5-directory': (job / 'prototype-pipeline/epochs/epoch-000005').mkdir()
    else: (job / 'unrecognised.json').write_bytes(b'{}')
    before, calls = inventory(case), deepcopy((case[7].calls, case[8].calls))
    assert classify(case)['blocks_admission'] is True
    assert inventory(case) == before and (case[7].calls, case[8].calls) == calls


def test_outside_job_compact_diagnostic_is_ignored(partition_case):
    outside = partition_case[1] / 'prototype-partition-review-proofs' / partition_case[3]
    outside.mkdir(parents=True)
    (outside / 'result.json').write_text('{"review_approved":true,"proposal_adopted":false}')
    assert classify(partition_case) == EXPECTED


@pytest.mark.parametrize('mutation', [None, 'tampered-output', 'missing-completion', 'unknown-intent',
                                    'epoch5', 'source-tamper', 'legacy1', 'legacy2'])
def test_generated_checkedfinder_four_reader_is_queryonly_and_legacy_safe(partition_case, historical_case, monkeypatch, mutation):
    combine(partition_case, historical_case)
    job = historical_case.root / 'jobs' / partition_case[3]
    record = json.loads((job / 'mapping-epochs/epoch-000004.json').read_bytes())
    current = job / 'prototype-pipeline/epochs/epoch-000004' / record['plan']['projection_focus_id']
    if mutation == 'tampered-output': edit(current / 'reviewer.json', lambda v: v.update(output_sha256='0' * 64))
    elif mutation == 'missing-completion': (current / 'reviewer.json').unlink()
    elif mutation == 'unknown-intent': (current / 'mapper-intent.json').write_bytes(b'{}')
    elif mutation == 'epoch5': (job / 'mapping-epochs/epoch-000005.json').write_bytes(b'{}')
    result, imported, exceptions = generated_reader(historical_case, monkeypatch,
        source_tamper=mutation == 'source-tamper', legacy=int(mutation[-1]) if mutation in ('legacy1', 'legacy2') else None)
    assert not imported & {'prototype_partition_review.py', 'prototype_partition_review_proof.py',
        'prototype_partition_review_epoch.py', 'prototype_design_context.py', 'prototype_container_proof.py'}
    if mutation is None:
        assert result.get('status') == 'RETIRED_HISTORY_OBSERVED', exceptions[-8:]
        assert result['admission_state'] == 'READY' and result['read_only'] is True
        assert result['automatic_replay_permitted'] is False
    else:
        assert result == {'status': 'STOPPED', 'code': 'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY',
                          'automatic_replay_permitted': False}, exceptions[-8:]


def test_retirement_state_label_requires_independent_classifier(partition_case, historical_case, monkeypatch):
    from qa.operator.retirement_remote import RetirementRemoteError
    combine(partition_case, historical_case)
    original = recovery.VerificationRecovery._eligibility
    monkeypatch.setattr(recovery.VerificationRecovery, '_eligibility', lambda self, db, rid:
        EXPECTED.copy() if rid == partition_case[3] else original(self, db, rid))
    monkeypatch.setattr(recovery, 'terminal_prototype_partition_review', lambda *args: False)
    with pytest.raises(RetirementRemoteError, match='CLAUSE_TERMINAL_UNCONFIRMED'):
        _read(historical_case)
