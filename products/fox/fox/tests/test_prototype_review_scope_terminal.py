"""Authored exact head-six invalid attribution; local admission, not live proof.

Provider responses and source are synthetic. The real API/worker builds the
167-file stop; classification and the generated CheckedFinder must only read it.
"""
import builtins
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
import hashlib
import inspect
import json
from pathlib import Path
import re
import sqlite3
from types import SimpleNamespace

import pytest

from fox import verification_recovery as recovery
from fox.forms_blueprint import evidence_reference_id
from fox.opaf import canonical_hash
from test_prototype_context_screen_terminal import authored_duplicate_mapper
from test_prototype_partition_terminal import authored_two_screen_findings
from test_prototype_partition_review_epoch import partition_case, next_body, process
from test_prototype_container_epoch import container_case, container_source_model
from test_prototype_clause_epoch import clause_case
from test_prototype_mapping_epochs import epochs_case, EpochModel, tmp_path, api, PROFILE
from test_prototype_epoch_terminal import classify, settings
from test_source_history_api import client, no_external_actions
from test_prototype_container_terminal import inventory, edit, combine, generated_reader
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read


EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_review_scope_terminal', 'retry_eligible': False}
_CASE_CACHE = None


@pytest.fixture(autouse=True)
def authored_exact_nine(authored_duplicate_mapper, monkeypatch):
    """29 Items + 3 selected whole Triggers; context Block is not owned."""
    import test_prototype_mapping_epochs as synthetic
    upload, pipeline, invoke = synthetic.upload, synthetic.run_prototype_pipeline, EpochModel.invoke
    def enlarged(documents):
        marker = b'</Block><Block Name="LAST"'
        extra = b''.join(f'<Item Name="V{i}" ItemType="Text Item" DatabaseItem="true"/>'.encode() for i in range(66, 92))
        result = []
        for name, raw in documents:
            assert raw.count(marker) == 1
            result.append((name, raw.replace(marker, extra + marker)))
        return result
    monkeypatch.setattr(synthetic, 'upload', lambda c, p, docs: upload(c, p, enlarged(docs)))
    monkeypatch.setattr(synthetic, 'run_prototype_pipeline', lambda job, docs, **kw: pipeline(job, enlarged(docs), **kw))
    def response(self, role, payload):
        output, invocation = invoke(self, role, payload)
        request = payload.get('request', payload)
        nine = (len(request.get('owned_objects', [])) == 32
                and request['owned_objects'][0]['kind'] == 'Item'
                and sum(o['kind'] == 'Trigger' for o in request['owned_objects']) == 3)
        if nine and role == PROFILE['mapper']:
            owned, bp = {o['id'] for o in request['owned_objects']}, output['blueprint']
            bp['objects'] = [row for row in bp['objects'] if row['source_object_id'] in owned]
            for row in bp['objects']: row['disposition'] = 'proposed'
            bp['claims'], bp['actions'], bp['relationships'] = [], [], []
            for unit in request['code_units']:
                ref = request['focus_id'] + '-authored-' + str(len(bp['claims']))
                bp['claims'].append({'id': ref, 'source_object_id': unit['owner_id'], 'kind': 'behavior.intent',
                    'status': 'proposal', 'value': 'Authored selected trigger; semantics unverified.',
                    'evidence_refs': [unit['owner_id'], unit['id']], 'reason': 'Complete authored selected unit.'})
                bp['actions'].append({'id': ref + '-action', 'claim_ids': [ref]})
            for kind, collection in (('link', 'links'), ('dependency', 'dependencies')):
                for fact in request[collection]:
                    ref = evidence_reference_id(request['source_index'][0]['sha256'], kind, fact)
                    bp['claims'].append({'id': request['focus_id'] + '-occurrence-' + str(len(bp['claims'])),
                        'source_object_id': fact['source_id'], 'kind': 'design.note', 'status': 'proposal',
                        'value': 'Authored occurrence evidence only.', 'evidence_refs': [ref], 'reason': 'Synthetic occurrence.'})
            assert len(bp['screens']) == 1
        if nine and role == PROFILE['reviewer']:
            block = next(o for o in request['context_objects'] if o['kind'] == 'Block')
            output.update(verdict='CHANGES_REQUIRED', findings=[{'source_object_id': block['id'],
                'code': 'MISSING_SCREEN_DECLARATION', 'detail': 'Authored false attribution: context Block treated as owned.'}])
        invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(EpochModel, 'invoke', response)


@pytest.fixture
def review_scope_case(request, tmp_path, settings, monkeypatch):
    global _CASE_CACHE
    if _CASE_CACHE is None:
        case = request.getfixturevalue('partition_case')
        _, body = next_body(case)
        assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
        row, errors = process(case, monkeypatch)
        assert row['state'] == 'ATTENTION' and errors
        before = inventory(case)
        assert len(before) == 153
        from test_prototype_context_screen_epoch import next_body as six_body
        plan, body = six_body(case)
        assert plan['epoch_number'] == 6
        count = len(case[7].calls)
        assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
        row, errors = process(case, monkeypatch)
        assert row['state'] == 'ATTENTION' and errors
        assert [role for role, _ in case[7].calls[count:]] == ['reviewer']
        assert case[8].calls == []
        assert len(inventory(case)) == 167 and all((case[4] / name).read_bytes() == raw for name, raw in before.items())
        with case[9]() as db, sqlite3.connect(':memory:') as memory:
            db.backup(memory); image = memory.serialize()
        _CASE_CACHE = (inventory(case), image, deepcopy((case[2], case[3], case[5], case[6], case[7].calls, case[8].calls, case[10])))
    files, image, metadata = _CASE_CACHE
    project, rid, snapshot, body, calls, converter_calls, envelope = deepcopy(metadata)
    root = tmp_path / 'sealed'; job = root / 'jobs' / rid
    job.mkdir(parents=True); root.chmod(0o700)
    for name, raw in files.items():
        path = job / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    (root / 'fox.sqlite3').write_bytes(image)
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3'); connection.row_factory = sqlite3.Row
        try:
            with connection: yield connection
        finally: connection.close()
    def forbidden(*args, **kwargs): pytest.fail('Admission invoked a provider/converter.')
    return (None, root, project, rid, job, snapshot, body, SimpleNamespace(calls=calls, invoke=forbidden),
        SimpleNamespace(calls=converter_calls, run_stage=forbidden), db, envelope)


def six_dir(case):
    return next((case[4] / 'prototype-pipeline/epochs/epoch-000006').glob('focus-*'))


def test_exact_sealed_six_invalid_review_is_readonly_not_semantic_approval(review_scope_case, monkeypatch):
    case = review_scope_case
    before, calls = inventory(case), deepcopy((case[7].calls, case[8].calls))
    directory = six_dir(case)
    task = json.loads((directory / 'reviewer-request.json').read_bytes())
    saved = json.loads((directory / 'reviewer.json').read_bytes())
    assert len(task['request']['owned_objects']) == 32
    assert {o['kind'] for o in task['request']['owned_objects']} == {'Item', 'Trigger'}
    assert task['candidate']['blueprint']['screens'] == []
    from fox.forms_design_review import validate_design_review
    with pytest.raises(ValueError): validate_design_review(task['request'], task['candidate'], saved['output'])
    def forbidden(*args, **kwargs): pytest.fail('Admission attempted a filesystem write.')
    for name in ('write_text', 'write_bytes', 'mkdir', 'unlink', 'rename', 'touch'):
        monkeypatch.setattr(Path, name, forbidden)
    assert classify(case) == EXPECTED
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (case[3],)).fetchone())
        assert recovery.terminal_prototype_review_scope(case[1] / 'fox.sqlite3', db, run)
        assert not recovery.terminal_prototype_context_screen(case[1] / 'fox.sqlite3', db, run)
        assert not recovery.terminal_prototype_partition_review(case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0
    assert inventory(case) == before and (case[7].calls, case[8].calls) == calls
    assert len(before) == 167 and not (directory / 'review-receipt.json').exists()
    assert not (case[4] / 'prototype-result-publications/epoch-000006/publication.json').exists()


def test_standalone_stdlib_no_mutable_helper_or_import_workaround(review_scope_case):
    original = builtins.__import__
    def stdlib(name, *args, **kwargs):
        assert name in ('math', 'os')
        return original(name, *args, **kwargs)
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': stdlib}}
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' + inspect.getsource(recovery.terminal_prototype_review_scope)
    exec(compile(source, '<stdlib-review-scope-terminal>', 'exec'), namespace)
    case = review_scope_case
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (case[3],)).fetchone())
        assert namespace['terminal_prototype_review_scope'](case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0


@pytest.mark.parametrize('mutation', ['owner', 'source', 'epoch5-event', 'epoch6-event', 'extra-event', 'correction-event',
    'epoch6-owner', 'epoch6-consent', 'epoch6-target', 'epoch6-checkpoint', 'epoch6-before', 'epoch6-copy', 'epoch6-predecessor',
    'epoch5-copy', 'epoch5-previous', 'epoch6-previous', 'latest', 'projection-input', 'projection-candidate',
    'projection-receipt', 'root-projection-receipt', 'audit', 'request', 'target', 'intent', 'output-hash',
    'role', 'environment', 'time', 'room', 'pending', 'receipt', 'source-facts', 'publication', 'fifth-publication',
    'correction-child', 'correction-dir', 'later-focus', 'extra-file', 'empty-dir', 'stage', 'future-epoch', 'wrong-state', 'artifact'])
def test_unknown_changed_pending_corrected_or_later_work_blocks(review_scope_case, mutation):
    case = review_scope_case; job = case[4]; directory = six_dir(case); base = directory.parent
    if mutation in ('owner', 'source', 'epoch5-event', 'epoch6-event', 'extra-event', 'correction-event', 'wrong-state', 'artifact'):
        with case[9]() as db:
            if mutation == 'owner': db.execute("UPDATE projects SET owner='foreign'")
            elif mutation == 'source': db.execute("UPDATE sources SET text=text||' '")
            elif mutation in ('epoch5-event', 'epoch6-event'):
                number = '000005' if mutation == 'epoch5-event' else '000006'
                db.execute('DELETE FROM events WHERE object_id LIKE ?', (case[3] + ':epoch:' + number + ':%',))
            elif mutation in ('extra-event', 'correction-event'):
                db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                    (case[5]['approvals']['owner'], 'unknown' if mutation == 'extra-event' else 'approved_prototype_review_correction', case[3] + ':child:unknown', 1))
            elif mutation == 'wrong-state': db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (case[3],))
            else: db.execute("UPDATE runs SET artifact='invented.zip' WHERE id=?", (case[3],))
    elif mutation.startswith('epoch6-') and mutation.split('-')[1] in ('owner', 'consent', 'target', 'checkpoint', 'before'):
        key = {'owner': 'owner', 'consent': 'approvals', 'target': 'target_profile_sha256', 'checkpoint': 'checkpoint_sha256', 'before': 'before_files'}[mutation.split('-')[1]]
        edit(job / 'mapping-epochs/epoch-000006.json', lambda v: v.update({key: {} if isinstance(v[key], dict) else '0' * 64}))
    elif mutation in ('epoch6-copy', 'epoch6-predecessor', 'epoch5-copy'):
        path = base / ('predecessor-record.json' if mutation == 'epoch6-predecessor' else 'epoch-record.json')
        if mutation == 'epoch5-copy': path = base.parent / 'epoch-000005/epoch-record.json'
        edit(path, lambda v: v.update(owner='foreign'))
    elif mutation in ('epoch5-previous', 'epoch6-previous'):
        (job / 'prototype-result-publications' / ('epoch-000005' if mutation == 'epoch5-previous' else 'epoch-000006') / 'previous-result.json').write_bytes(b'{}')
    elif mutation == 'latest': (job / 'prototype-result.json').write_bytes(b'{}')
    elif mutation in ('projection-input', 'projection-candidate'):
        edit(directory / ('screen-input-candidate.json' if mutation == 'projection-input' else 'projection-candidate.json'),
             lambda v: v['blueprint']['objects'][0].update(reason='Changed non-screen field'))
    elif mutation in ('projection-receipt', 'root-projection-receipt'):
        edit((base if mutation == 'root-projection-receipt' else directory) / 'screen-projection-receipt.json',
             lambda v: v.update(prior_references_sha256='0' * 64))
    elif mutation == 'audit': edit(directory / 'full-audit-context.json', lambda v: v['prefix_check'].update(structural_prefix_valid=False))
    elif mutation == 'request': edit(directory / 'reviewer-request.json', lambda v: v['design_context']['tables']['sources'].clear())
    elif mutation == 'target': edit(directory / 'reviewer-target.json', lambda v: v.update(active=False))
    elif mutation == 'intent': edit(directory / 'reviewer-intent.json', lambda v: v.update(request_sha256='0' * 64))
    elif mutation in ('output-hash', 'role', 'environment', 'time', 'room'):
        def change(v):
            if mutation == 'output-hash': v['output_sha256'] = '0' * 64
            elif mutation == 'role': v['invocation']['workflow_id'] = 'F' * 32
            elif mutation == 'environment': v['model_environment']['role'] = 'mapper'
            elif mutation == 'time': v['invocation']['completed_at_utc'] = '2001-01-01T00:00:00+00:00'
            else: v['invocation']['room_id'] = json.loads((base.parent / 'epoch-000005' / directory.name / 'mapper.json').read_bytes())['invocation']['room_id']
        edit(directory / 'reviewer.json', change)
    elif mutation == 'pending': (directory / 'reviewer.json').unlink()
    elif mutation == 'receipt': (directory / 'review-receipt.json').write_bytes(b'{}')
    elif mutation == 'source-facts':
        path = base / 'source-facts'; path.mkdir(); (path / (directory.name + '.json')).write_bytes(b'{}')
    elif mutation in ('publication', 'fifth-publication'):
        (job / 'prototype-result-publications' / ('epoch-000005' if mutation == 'fifth-publication' else 'epoch-000006') / 'publication.json').write_bytes(b'{}')
    elif mutation == 'correction-child': (base / 'review-correction.json').write_bytes(b'{}')
    elif mutation in ('correction-dir', 'later-focus', 'empty-dir'):
        (base / ('review-correction' if mutation == 'correction-dir' else 'focus-' + 'f' * 24 if mutation == 'later-focus' else 'empty')).mkdir()
    elif mutation == 'extra-file': (job / 'unknown.json').write_bytes(b'{}')
    elif mutation == 'stage': (job / 'prototype-pipeline/import-intent.json').write_bytes(b'{}')
    elif mutation == 'future-epoch': (job / 'mapping-epochs/epoch-000007.json').write_bytes(b'{}')
    else: pytest.fail('Unhandled mutation')
    before = inventory(case)
    assert classify(case)['blocks_admission'] is True
    assert inventory(case) == before


@pytest.mark.parametrize('mutation', ['owned', 'global', 'unknown', 'mixed-owned', 'mixed-global', 'other-code',
    'approved', 'empty', 'duplicate-finding', 'extra-field', 'extra-output-field', 'blank-detail', 'long-detail', 'wrong-candidate', 'wrong-focus'])
def test_resealed_review_must_be_only_known_nonowned_context_block_defect(review_scope_case, mutation):
    case = review_scope_case; directory = six_dir(case)
    task = json.loads((directory / 'reviewer-request.json').read_bytes())
    def change(v):
        output = v['output']; finding = output['findings'][0]
        owned = task['request']['owned_objects'][0]['id']
        if mutation == 'owned': finding['source_object_id'] = owned
        elif mutation == 'global': finding['source_object_id'] = None
        elif mutation == 'unknown': finding['source_object_id'] = 'ff1-' + '0' * 24
        elif mutation.startswith('mixed-'):
            output['findings'].append({**finding, 'source_object_id': owned if mutation == 'mixed-owned' else None})
        elif mutation == 'other-code': finding['code'] = 'GENUINE_DEFECT'
        elif mutation == 'approved': output.update(verdict='APPROVED', findings=[])
        elif mutation == 'empty': output['findings'] = []
        elif mutation == 'duplicate-finding': output['findings'].append(deepcopy(finding))
        elif mutation == 'extra-field': finding['scope'] = 'owned'
        elif mutation == 'extra-output-field': output['approved'] = True
        elif mutation == 'blank-detail': finding['detail'] = ' '
        elif mutation == 'long-detail': finding['detail'] = 'x' * 2001
        elif mutation == 'wrong-candidate': output['candidate_sha256'] = '0' * 64
        elif mutation == 'wrong-focus': output['focus_binding'] = '0' * 64
        v['output_sha256'] = canonical_hash(output); v['invocation']['response_sha256'] = canonical_hash(output)
    edit(directory / 'reviewer.json', change)
    assert classify(case)['blocks_admission'] is True


@pytest.mark.parametrize('mutation', [None, 'pending', 'receipt', 'correction', 'source-tamper', 'legacy1', 'legacy2'])
def test_actual_generated_checkedfinder_queryonly_and_legacy_safe(review_scope_case, historical_case, monkeypatch, mutation):
    combine(review_scope_case, historical_case)
    job = historical_case.root / 'jobs' / review_scope_case[3]
    directory = next((job / 'prototype-pipeline/epochs/epoch-000006').glob('focus-*'))
    if mutation == 'pending': (directory / 'reviewer.json').unlink()
    elif mutation == 'receipt': (directory / 'review-receipt.json').write_bytes(b'{}')
    elif mutation == 'correction': (directory.parent / 'review-correction.json').write_bytes(b'{}')
    result, imported, errors = generated_reader(historical_case, monkeypatch,
        source_tamper=mutation == 'source-tamper', legacy=int(mutation[-1]) if mutation in ('legacy1', 'legacy2') else None)
    assert not imported & {'prototype_review_correction.py', 'prototype_context_screen_epoch.py',
        'prototype_context_screen_projection.py', 'prototype_partition_review.py',
        'prototype_partition_review_proof.py', 'prototype_partition_review_epoch.py', 'prototype_design_context.py'}
    if mutation is None:
        assert result.get('status') == 'RETIRED_HISTORY_OBSERVED', errors[-8:]
        assert result['admission_state'] == 'READY' and result['read_only'] is True and result['automatic_replay_permitted'] is False
    else:
        assert result == {'status': 'STOPPED', 'code': 'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY', 'automatic_replay_permitted': False}, errors[-8:]


def test_retirement_rechecks_scope_not_state_label(review_scope_case, historical_case, monkeypatch):
    from qa.operator.retirement_remote import RetirementRemoteError
    combine(review_scope_case, historical_case)
    original = recovery.VerificationRecovery._eligibility
    monkeypatch.setattr(recovery.VerificationRecovery, '_eligibility', lambda self, db, rid:
        EXPECTED.copy() if rid == review_scope_case[3] else original(self, db, rid))
    monkeypatch.setattr(recovery, 'terminal_prototype_review_scope', lambda *args: False)
    with pytest.raises(RetirementRemoteError, match='CLAUSE_TERMINAL_UNCONFIRMED'): _read(historical_case)
