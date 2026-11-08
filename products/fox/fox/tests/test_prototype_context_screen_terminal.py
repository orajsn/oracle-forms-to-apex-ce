"""Authored sealed head-five pre-review stop; no live/provider acceptance."""
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
from fox.forms_blueprint import evidence_reference_id, source_fact_index
from fox.opaf import canonical_hash
from test_prototype_partition_review_epoch import partition_case, next_body, process
from test_prototype_container_epoch import container_case, container_source_model
from test_prototype_clause_epoch import clause_case
from test_prototype_mapping_epochs import epochs_case, EpochModel, tmp_path, api, PROFILE
from test_prototype_partition_terminal import authored_two_screen_findings
from test_prototype_epoch_terminal import classify, settings
from test_source_history_api import client, no_external_actions
from test_prototype_container_terminal import inventory, edit, combine, generated_reader
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read


EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_context_screen_terminal', 'retry_eligible': False}
_CASE_CACHE = None


@pytest.fixture(autouse=True)
def authored_duplicate_mapper(authored_two_screen_findings, monkeypatch):
    import test_prototype_mapping_epochs as synthetic_epochs
    upload = synthetic_epochs.upload
    pipeline = synthetic_epochs.run_prototype_pipeline
    def documents_with_triggers(documents):
        changed = []
        for name, raw in documents:
            marker = b'</Block><Block Name="LAST"'
            extra = b''.join(f'<Trigger Name="AUTH_T{i}" TriggerText="BEGIN AUTHORED_API.RUN(1); END;"/>'.encode() for i in range(3))
            assert raw.count(marker) == 1
            raw = raw.replace(b'<Item Name="V65" ItemType=', b'<Item Name="V65" CanvasName="AUTH_UNRESOLVED_CANVAS" ItemType=')
            changed.append((name, raw.replace(marker, extra + marker)))
        return changed
    def with_triggers(c, project, documents):
        return upload(c, project, documents_with_triggers(documents))
    def matching_pipeline(job, documents, **kwargs):
        # The legacy fixture also passes its local source variable directly to
        # the first authored pipeline call; keep it identical to the upload.
        return pipeline(job, documents_with_triggers(documents), **kwargs)
    monkeypatch.setattr(synthetic_epochs, 'upload', with_triggers)
    monkeypatch.setattr(synthetic_epochs, 'run_prototype_pipeline', matching_pipeline)
    original = EpochModel.invoke
    def invoke(self, role, payload):
        output, invocation = original(self, role, payload)
        # Only the small third SPECIAL-block partition is the authored mapper9.
        if (role == PROFILE['mapper'] and payload['owned_objects'][0]['kind'] == 'Item'
                and len(payload['owned_objects']) < 32):
            owned = {obj['id'] for obj in payload['owned_objects']}
            bp = output['blueprint']
            bp['objects'] = [row for row in bp['objects'] if row['source_object_id'] in owned]
            for row in bp['objects']: row['disposition'] = 'proposed'
            bp['claims'], bp['actions'], bp['relationships'] = [], [], []
            for unit in payload['code_units']:
                ref = payload['focus_id'] + '-authored-' + str(len(bp['claims']))
                bp['claims'].append({'id': ref, 'source_object_id': unit['owner_id'], 'kind': 'behavior.intent',
                    'status': 'proposal', 'value': 'Authored selected trigger interpretation, semantics unverified.',
                    'evidence_refs': [unit['owner_id'], unit['id']], 'reason': 'Complete authored selected unit.'})
                bp['actions'].append({'id': ref + '-action', 'claim_ids': [ref]})
            assert len(payload['source_index']) == 1 and payload['links'] and payload['dependencies']
            for category, collection in (('link', 'links'), ('dependency', 'dependencies')):
                for fact in payload[collection]:
                    assert 'id' not in fact
                    ref = evidence_reference_id(payload['source_index'][0]['sha256'], category, fact)
                    bp['claims'].append({'id': payload['focus_id'] + '-occurrence-' + str(len(bp['claims'])),
                        'source_object_id': fact['source_id'], 'kind': 'design.note', 'status': 'proposal',
                        'value': 'Authored occurrence evidence only; no implementation or behavior approval.',
                        'evidence_refs': [ref], 'reason': 'Synthetic canonical occurrence reference.'})
            assert len(bp['screens']) == 1
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(EpochModel, 'invoke', invoke)


@pytest.fixture
def context_case(request, tmp_path, settings, monkeypatch):
    global _CASE_CACHE
    if _CASE_CACHE is None:
        case = request.getfixturevalue('partition_case')
        before = inventory(case)
        _, body = next_body(case)
        count = len(case[7].calls)
        assert case[0].post(api(case, 'mapping-epochs'), json=body).status_code == 202
        row, errors = process(case, monkeypatch)
        assert row['state'] == 'ATTENTION' and errors
        new_calls = case[7].calls[count:]
        assert len(new_calls) == 1 and new_calls[0][0] == 'mapper'
        assert case[8].calls == [] and all((case[4] / name).read_bytes() == raw for name, raw in before.items())
        assert not (case[4] / 'prototype-result-publications/epoch-000005/publication.json').exists()
        assert (case[4] / 'prototype-result-publications/epoch-000005/previous-result.json').read_bytes() == before['prototype-result.json']
        assert len(inventory(case)) == len(before) + 18
        with case[9]() as source, sqlite3.connect(':memory:') as memory:
            source.backup(memory)
            image = memory.serialize()
        _CASE_CACHE = (inventory(case), image,
            deepcopy((case[2], case[3], case[5], case[6], case[7].calls, case[8].calls, case[10])))
    files, image, metadata = _CASE_CACHE
    project, run_id, snapshot, body, model_calls, converter_calls, envelope = deepcopy(metadata)
    root, job = tmp_path / 'sealed', tmp_path / 'sealed/jobs' / run_id
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
    def forbidden(*args, **kwargs): pytest.fail('Admission invoked a model/converter.')
    return (None, root, project, run_id, job, snapshot, body,
        SimpleNamespace(calls=model_calls, invoke=forbidden),
        SimpleNamespace(calls=converter_calls, run_stage=forbidden), db, envelope)


def mapper_dir(case):
    return next((case[4] / 'prototype-pipeline/epochs/epoch-000005').glob('focus-*'))


def test_exact_sealed_five_mapper_stop_preserves_absent_review_and_publication(context_case, monkeypatch):
    before, calls = inventory(context_case), deepcopy((context_case[7].calls, context_case[8].calls))
    assert len(before) == 153
    raw = json.loads((mapper_dir(context_case) / 'mapper.json').read_bytes())['output']
    request = json.loads((mapper_dir(context_case) / 'mapper-request.json').read_bytes())
    assert {obj['kind'] for obj in request['owned_objects']} == {'Item', 'Trigger'} and len(raw['blueprint']['screens']) == 1
    assert request['links'] and request['dependencies'] and all('id' not in fact for fact in request['links'] + request['dependencies'])
    packet = json.loads((context_case[4] / 'prototype-pipeline/packet.json').read_bytes())
    _, evidence, _ = source_fact_index(packet)
    notes = [claim for claim in raw['blueprint']['claims'] if claim['kind'] == 'design.note']
    assert any(claim['evidence_refs'][0].startswith('fflink1-') for claim in notes)
    assert any(claim['evidence_refs'][0].startswith('ffdep1-') for claim in notes)
    assert all(evidence[claim['evidence_refs'][0]] == claim['source_object_id'] for claim in notes)
    def forbidden(*args, **kwargs): pytest.fail('Admission attempted a file write.')
    for name in ('write_text', 'write_bytes', 'mkdir', 'unlink', 'rename', 'touch'):
        monkeypatch.setattr(Path, name, forbidden)
    assert classify(context_case) == EXPECTED
    with context_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (context_case[3],)).fetchone())
        assert recovery.terminal_prototype_context_screen(context_case[1] / 'fox.sqlite3', db, run)
        assert not recovery.terminal_prototype_partition_review(context_case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0
    assert inventory(context_case) == before and (context_case[7].calls, context_case[8].calls) == calls


def test_stdlib_only_no_formatter_projector_or_current_fence(context_case):
    original = builtins.__import__
    def stdlib(name, *args, **kwargs):
        assert name in ('math', 'os')
        return original(name, *args, **kwargs)
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': stdlib}}
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' + inspect.getsource(recovery.terminal_prototype_context_screen)
    exec(compile(source, '<stdlib-context-screen-terminal>', 'exec'), namespace)
    with context_case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (context_case[3],)).fetchone())
        assert namespace['terminal_prototype_context_screen'](context_case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0


@pytest.mark.parametrize('mutation', ['owner', 'source', 'epoch5-event', 'extra-event', 'epoch6-event',
    'epoch5-owner', 'epoch5-before', 'epoch5-copy', 'epoch5-previous', 'descriptor', 'compact-member',
    'compact-role', 'compact-pending', 'mapper-request', 'mapper-target', 'mapper-intent', 'mapper-pending',
    'mapper-role', 'mapper-environment', 'mapper-time', 'mapper-output', 'reviewer-intent', 'reviewer-output',
    'derived-candidate', 'fifth-publication', 'latest-result', 'fifth-archive', 'database-stage', 'later-focus',
    'epoch6-record', 'epoch6-directory', 'unknown-file', 'wrong-state', 'artifact'])
def test_other_incomplete_tampered_pending_or_later_work_remains_blocking(context_case, mutation):
    case, job = context_case, context_case[4]
    base, directory = job / 'prototype-pipeline/epochs/epoch-000005', mapper_dir(case)
    if mutation in ('owner', 'epoch5-event', 'extra-event', 'epoch6-event', 'wrong-state', 'artifact'):
        with case[9]() as db:
            if mutation == 'owner': db.execute("UPDATE projects SET owner='foreign' WHERE id=?", (case[2],))
            elif mutation == 'epoch5-event': db.execute('DELETE FROM events WHERE object_id LIKE ?', (case[3] + ':epoch:000005:%',))
            elif mutation in ('extra-event', 'epoch6-event'):
                db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                    (case[5]['approvals']['owner'], 'unknown_operation' if mutation == 'extra-event' else 'approved_prototype_mapping_epoch',
                     case[3] + ':epoch:000006:' + 'a' * 64, 1))
            elif mutation == 'wrong-state': db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (case[3],))
            else: db.execute("UPDATE runs SET artifact='invented.zip' WHERE id=?", (case[3],))
    elif mutation == 'source': edit(job / 'source-snapshot.json', lambda v: v.update(selected_source_set_id='ss-' + '0' * 32))
    elif mutation in ('epoch5-owner', 'epoch5-before'):
        edit(job / 'mapping-epochs/epoch-000005.json', lambda v: v.update({'owner' if mutation == 'epoch5-owner' else 'before_files':
            'foreign' if mutation == 'epoch5-owner' else {}}))
    elif mutation == 'epoch5-copy': edit(base / 'epoch-record.json', lambda v: v.update(owner='foreign'))
    elif mutation == 'epoch5-previous': edit(base / 'predecessor-record.json', lambda v: v.update(owner='foreign'))
    elif mutation == 'descriptor': edit(base / 'partition-proof-descriptor.json', lambda v: v.update(review_task_sha256='0' * 64))
    elif mutation == 'compact-member': (base / 'partition-proof/full-audit-context.json').write_bytes(b'{}')
    elif mutation == 'compact-role': edit(base / 'partition-proof/review/reviewer.json', lambda v: v['invocation'].update(model='foreign'))
    elif mutation == 'compact-pending': (base / 'partition-proof/review/reviewer.json').unlink()
    elif mutation == 'mapper-request': edit(directory / 'mapper-request.json', lambda v: v.update(context_objects=[]))
    elif mutation == 'mapper-target': edit(directory / 'mapper-target.json', lambda v: v.update(active=False))
    elif mutation == 'mapper-intent': (directory / 'mapper-intent.json').unlink()
    elif mutation == 'mapper-pending': (directory / 'mapper.json').unlink()
    elif mutation in ('mapper-role', 'mapper-environment', 'mapper-time', 'mapper-output'):
        def change(v):
            if mutation == 'mapper-role': v['invocation']['workflow_id'] = 'F' * 32
            elif mutation == 'mapper-environment': v['model_environment']['job_id'] = 'fox-' + '0' * 20
            elif mutation == 'mapper-time': v['invocation']['completed_at_utc'] = 'not-a-time'
            else: v['output_sha256'] = '0' * 64
        edit(directory / 'mapper.json', change)
    elif mutation in ('reviewer-intent', 'reviewer-output', 'derived-candidate'):
        (directory / {'reviewer-intent': 'reviewer-intent.json', 'reviewer-output': 'reviewer.json',
            'derived-candidate': 'projection-candidate.json'}[mutation]).write_bytes(b'{}')
    elif mutation == 'fifth-publication': (job / 'prototype-result-publications/epoch-000005/publication.json').write_bytes(b'{}')
    elif mutation == 'latest-result': edit(job / 'prototype-result.json', lambda v: v.update(mapping_epoch_sha256='0' * 64))
    elif mutation == 'fifth-archive': (job / 'prototype-result-publications/epoch-000005/previous-result.json').write_bytes(b'{}')
    elif mutation == 'database-stage': (job / 'prototype-pipeline/prepare_schema-intent.json').write_bytes(b'{}')
    elif mutation == 'later-focus': (base / ('focus-' + 'f' * 24)).mkdir()
    elif mutation == 'epoch6-record': (job / 'mapping-epochs/epoch-000006.json').write_bytes(b'{}')
    elif mutation == 'epoch6-directory': (job / 'prototype-pipeline/epochs/epoch-000006').mkdir()
    else: (job / 'unknown.json').write_bytes(b'{}')
    before = inventory(case)
    assert classify(case)['blocks_admission'] is True
    assert inventory(case) == before


@pytest.mark.parametrize('mutation', ['changed-title', 'wrong-id', 'two-screens', 'no-screen', 'wrong-reference',
    'unresolved', 'native-component', 'source-fact', 'missing-behavior', 'missing-action', 'foreign-evidence'])
def test_complete_resealed_mapper_must_still_have_only_known_duplicate_eligibility(context_case, mutation):
    path = mapper_dir(context_case) / 'mapper.json'
    def change(v):
        bp = v['output']['blueprint']
        if mutation == 'changed-title': bp['screens'][0]['title'] = 'Not identical'
        elif mutation == 'wrong-id': bp['screens'][0]['id'] = 'screen-foreign'
        elif mutation == 'two-screens': bp['screens'].append(deepcopy(bp['screens'][0]))
        elif mutation == 'no-screen': bp['screens'] = []
        elif mutation == 'wrong-reference': bp['objects'][0]['screen_id'] = 'screen-foreign'
        elif mutation == 'unresolved': bp['objects'][0]['disposition'] = 'unresolved'
        elif mutation == 'native-component': bp['objects'][0]['native_component'] = 'form'
        elif mutation == 'source-fact': bp['claims'][0]['status'] = 'source_fact'
        elif mutation == 'missing-behavior': bp['claims'].pop(0)
        elif mutation == 'missing-action': bp['actions'].pop()
        else: bp['claims'][0]['evidence_refs'] = ['foreign']
        v['output_sha256'] = canonical_hash(v['output'])
        v['invocation']['response_sha256'] = canonical_hash(v['output'])
    edit(path, change)
    assert classify(context_case)['blocks_admission'] is True


@pytest.mark.parametrize('kind,mutation', [('link', 'invalid-id'), ('dependency', 'invalid-id'),
                                         ('link', 'rebound-owner'), ('dependency', 'rebound-owner')])
def test_occurrence_evidence_invalid_or_rebound_refs_fail_closed(context_case, kind, mutation):
    directory = mapper_dir(context_case)
    request = json.loads((directory / 'mapper-request.json').read_bytes())
    prefix = 'fflink1-' if kind == 'link' else 'ffdep1-'
    def change(v):
        note = next(claim for claim in v['output']['blueprint']['claims']
                    if claim['kind'] == 'design.note' and claim['evidence_refs'][0].startswith(prefix))
        if mutation == 'invalid-id': note['evidence_refs'] = [prefix + '0' * 24]
        else: note['source_object_id'] = next(obj['id'] for obj in request['owned_objects'] if obj['id'] != note['source_object_id'])
        v['output_sha256'] = canonical_hash(v['output'])
        v['invocation']['response_sha256'] = canonical_hash(v['output'])
    edit(directory / 'mapper.json', change)
    before = inventory(context_case)
    assert classify(context_case)['blocks_admission'] is True
    assert inventory(context_case) == before


@pytest.mark.parametrize('mutation', [None, 'mapper-pending', 'reviewer-intent', 'epoch6', 'source-tamper', 'legacy1', 'legacy2'])
def test_generated_real_checkedfinder_context_stop_queryonly_and_legacy_safe(context_case, historical_case, monkeypatch, mutation):
    combine(context_case, historical_case)
    job = historical_case.root / 'jobs' / context_case[3]
    directory = next((job / 'prototype-pipeline/epochs/epoch-000005').glob('focus-*'))
    if mutation == 'mapper-pending': (directory / 'mapper.json').unlink()
    elif mutation == 'reviewer-intent': (directory / 'reviewer-intent.json').write_bytes(b'{}')
    elif mutation == 'epoch6': (job / 'mapping-epochs/epoch-000006.json').write_bytes(b'{}')
    result, imported, errors = generated_reader(historical_case, monkeypatch,
        source_tamper=mutation == 'source-tamper', legacy=int(mutation[-1]) if mutation in ('legacy1', 'legacy2') else None)
    assert not imported & {'prototype_context_screen_projection.py', 'prototype_partition_review.py',
        'prototype_partition_review_proof.py', 'prototype_partition_review_epoch.py', 'prototype_design_context.py'}
    if mutation is None:
        assert result.get('status') == 'RETIRED_HISTORY_OBSERVED', errors[-8:]
        assert result['admission_state'] == 'READY' and result['read_only'] is True and result['automatic_replay_permitted'] is False
    else:
        assert result == {'status': 'STOPPED', 'code': 'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY', 'automatic_replay_permitted': False}, errors[-8:]


def test_retirement_does_not_trust_context_screen_state_label(context_case, historical_case, monkeypatch):
    from qa.operator.retirement_remote import RetirementRemoteError
    combine(context_case, historical_case)
    original = recovery.VerificationRecovery._eligibility
    monkeypatch.setattr(recovery.VerificationRecovery, '_eligibility', lambda self, db, run:
        EXPECTED.copy() if run == context_case[3] else original(self, db, run))
    monkeypatch.setattr(recovery, 'terminal_prototype_context_screen', lambda *args: False)
    with pytest.raises(RetirementRemoteError, match='CLAUSE_TERMINAL_UNCONFIRMED'): _read(historical_case)
