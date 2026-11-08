"""Fixed251 terminal admission only; authored provider, no live/model authority.

Reuse the proven DSC case, with the existing32-owned/3-trigger historical shape.
An optional bounded JSON test cache avoids repeating that setup across runs; it
contains only synthetic bytes and is always rechecked by the real classifier.
"""
import base64
import builtins
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import sqlite3
from types import SimpleNamespace

import pytest

from fox import verification_recovery as recovery
from fox.forms_blueprint import evidence_reference_id
from fox.opaf import canonical_hash
from test_prototype_dsc_identity_repair import (dsc_case, historical_dsc_source, correction_case, screen_case,
    partition_case, container_case, container_source_model, clause_case, epochs_case,
    tmp_path, client, settings, no_external_actions)
from test_prototype_epoch_terminal import classify, settings
from test_prototype_container_terminal import inventory, edit, combine, generated_reader
from qa.operator.tests.test_retirement_remote_backend import historical_case, _read
from test_prototype_pipeline import PROFILE

EXPECTED = {'blocks_admission': False, 'recovery_state': 'prototype_post_correction_review_terminal', 'retry_eligible': False}
_CACHE = None


@pytest.fixture(autouse=True)
def exact_historical_nine(historical_dsc_source, container_source_model, monkeypatch, request):
    if _CACHE is not None or os.environ.get('DSC191_TEST_CACHE') and Path(os.environ['DSC191_TEST_CACHE']).is_file():
        return
    # dsc_case is requested lazily only when the saved synthetic cache is absent.
    # Activate its existing source fixture explicitly for that lazy dependency.
    import test_prototype_dsc_identity_repair as proven_fixture
    proven_fixture.historical_dsc_source.__wrapped__(monkeypatch, container_source_model, SimpleNamespace(fixturenames=['dsc_case']))
    import test_prototype_mapping_epochs as fixtures
    import test_prototype_container_epoch as historical_container
    sealed = historical_container.sealed_role
    def independent_root(*args, **kwargs):
        invocation = sealed(*args, **kwargs)
        invocation['room_id'] = 'authored-independent-root-review'
        path = args[0] / args[1] / (args[2] + '.json')
        value = json.loads(path.read_bytes()); value['invocation'] = invocation
        path.write_text(json.dumps(value), encoding='utf-8')
        return invocation
    monkeypatch.setattr(historical_container, 'sealed_role', independent_root)
    upload, pipeline, invoke = fixtures.upload, fixtures.run_prototype_pipeline, fixtures.EpochModel.invoke
    def shaped(documents):
        result = []
        for name, raw in documents:
            anchor = b'<Block Name="SPECIAL"'
            assert raw.count(anchor) == 1
            begin = raw.index(anchor); end = raw.index(b'</Block>', begin)
            raw = raw.replace(b'<Item Name="V65" ItemType=', b'<Item Name="V65" CanvasName="AUTH_UNRESOLVED_CANVAS" ItemType=')
            end = raw.index(b'</Block>', begin)
            extra = b''.join(f'<Item Name="V{i}" ItemType="Text Item" DatabaseItem="true"/>'.encode() for i in range(66, 92))
            extra += b''.join(f'<Trigger Name="SHAPE_T{i}" TriggerText="BEGIN AUTHORED_API.RUN(1); END;"/>'.encode() for i in range(3))
            result.append((name, raw[:end] + extra + raw[end:]))
        return result
    monkeypatch.setattr(fixtures, 'upload', lambda c, pid, docs: upload(c, pid, shaped(docs)))
    monkeypatch.setattr(fixtures, 'run_prototype_pipeline', lambda job, docs, **kw: pipeline(job, shaped(docs), **kw))
    def mapped(self, role, payload):
        output, invocation = invoke(self, role, payload)
        if (role == PROFILE['reviewer'] and self.changes_role is True
                and payload.get('review_context', {}).get('operation') == 'projection_review'):
            output.update(verdict='CHANGES_REQUIRED', findings=[
                {'source_object_id': None, 'code': 'MISSING_SCREEN_DECLARATION', 'detail': 'Authored historical local-screen objection.'},
                {'source_object_id': None, 'code': 'INVALID_OBJECT_SCREEN_REF', 'detail': 'Authored historical context-screen objection.'}])
            invocation['response_sha256'] = canonical_hash(output)
        if (role == PROFILE['mapper'] and len(payload['owned_objects']) == 32
                and payload['owned_objects'][0]['kind'] == 'Item'
                and sum(row['kind'] == 'Trigger' for row in payload['owned_objects']) == 3):
            bp = output['blueprint']; owned = {row['id'] for row in payload['owned_objects']}
            bp['objects'] = [row for row in bp['objects'] if row['source_object_id'] in owned]
            bp['claims'], bp['actions'], bp['relationships'] = [], [], []
            for row in bp['objects']: row['disposition'] = 'proposed'
            for unit in payload['code_units']:
                ref = payload['focus_id'] + '-unit-' + str(len(bp['claims']))
                bp['claims'].append({'id': ref, 'source_object_id': unit['owner_id'], 'kind': 'behavior.intent',
                    'status': 'proposal', 'value': 'Authored complete trigger proposal; not verified business behavior.',
                    'evidence_refs': [unit['owner_id'], unit['id']], 'reason': 'Synthetic whole unit.'})
                bp['actions'].append({'id': ref + '-action', 'claim_ids': [ref]})
            for kind, key in (('link', 'links'), ('dependency', 'dependencies')):
                for fact in payload[key]:
                    ref = evidence_reference_id(payload['source_index'][0]['sha256'], kind, fact)
                    bp['claims'].append({'id': payload['focus_id'] + '-occurrence-' + str(len(bp['claims'])),
                        'source_object_id': fact['source_id'], 'kind': 'design.note', 'status': 'proposal',
                        'value': 'Authored occurrence evidence only.', 'evidence_refs': [ref], 'reason': 'Synthetic occurrence.'})
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation
    monkeypatch.setattr(fixtures.EpochModel, 'invoke', mapped)


@pytest.fixture
def terminal_case(request, tmp_path):
    global _CACHE
    cache_name = os.environ.get('DSC191_TEST_CACHE')
    cache = Path(cache_name).resolve() if cache_name else None
    if cache is not None:
        workspace = Path(__file__).resolve().parents[6]
        assert cache.is_relative_to((workspace / 'work').resolve()) and cache.suffix == '.json'
    if _CACHE is None:
        if cache is not None and cache.is_file():
            assert cache.stat().st_size <= 20_000_000
            value = json.loads(cache.read_bytes())
            assert value['schema_version'] == 1
            files = {name: base64.b64decode(raw, validate=True) for name, raw in value['files'].items()}
            assert len(files) == 251 and {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()} == value['sha256']
            _CACHE = files, base64.b64decode(value['database_image'], validate=True), value['metadata']
        else:
            case = request.getfixturevalue('dsc_case')
            files = inventory(case); assert len(files) == 251
            first = json.loads((case[4] / 'prototype-pipeline/epochs/epoch-000005').glob('focus-*/mapper-request.json').__next__().read_bytes())
            assert len(first['owned_objects']) == 32 and sum(row['kind'] == 'Trigger' for row in first['owned_objects']) == 3
            with case[9]() as db, sqlite3.connect(':memory:') as memory:
                db.backup(memory); image = memory.serialize()
            metadata = deepcopy([case[2], case[3], case[5], case[6], case[7].calls, case[8].calls, case[10]])
            _CACHE = files, image, metadata
            if cache is not None:
                value = {'schema_version': 1, 'files': {name: base64.b64encode(raw).decode() for name, raw in files.items()},
                    'sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
                    'database_image': base64.b64encode(image).decode(), 'metadata': metadata}
                with cache.open('x', encoding='utf-8') as stream: json.dump(value, stream)
    files, image, metadata = _CACHE
    project, rid, snapshot, body, calls, converter_calls, envelope = deepcopy(metadata)
    root = tmp_path / 'sealed'; job = root / 'jobs' / rid
    job.mkdir(parents=True); root.chmod(0o700)
    for name, raw in files.items():
        assert not name.startswith('/') and ':' not in name and '\\' not in name and not set(name.split('/')) & {'', '.', '..'}
        path = job / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    (root / 'fox.sqlite3').write_bytes(image)
    # dsc_case intentionally disables verifier startup. Add only the normal
    # empty local ledgers to this fresh test clone before readonly admission.
    from fox.verification_queue import initialize_schema as queue_schema
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        queue_schema(connection); recovery.initialize_schema(connection)
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3'); connection.row_factory = sqlite3.Row
        try:
            with connection: yield connection
        finally: connection.close()
    def forbidden(*args, **kwargs): pytest.fail('Admission invoked a provider/converter.')
    return (None, root, project, rid, job, snapshot, body, SimpleNamespace(calls=calls, invoke=forbidden),
        SimpleNamespace(calls=converter_calls, run_stage=forbidden), db, envelope)


def test_positive_exact251_old167_distinct_and_readonly(terminal_case, monkeypatch):
    case = terminal_case; before = inventory(case)
    def forbidden(*args, **kwargs): pytest.fail('Admission attempted a filesystem write.')
    for name in ('write_text', 'write_bytes', 'mkdir', 'unlink', 'rename', 'touch'):
        monkeypatch.setattr(Path, name, forbidden)
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (case[3],)).fetchone())
        assert not recovery.terminal_prototype_review_scope(case[1] / 'fox.sqlite3', db, run)
        assert recovery.terminal_prototype_post_correction_review(case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0
    assert classify(case) == EXPECTED and inventory(case) == before


def test_standalone_stdlib_no_mutable_runtime_import(terminal_case):
    original = builtins.__import__
    def stdlib(name, *args, **kwargs):
        assert name in ('math', 'os')
        return original(name, *args, **kwargs)
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
        '__builtins__': {**vars(builtins), '__import__': stdlib}}
    source = inspect.getsource(recovery.terminal_empty_prototype_mapping) + '\n' + inspect.getsource(recovery.terminal_prototype_post_correction_review)
    exec(compile(source, '<stdlib-post-correction-terminal>', 'exec'), namespace)
    case = terminal_case
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON')
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (case[3],)).fetchone())
        assert namespace['terminal_prototype_post_correction_review'](case[1] / 'fox.sqlite3', db, run)
        assert db.total_changes == 0


@pytest.mark.parametrize('mutation', ['correction', 'correction-event', 'acceptance-event', 'pending', 'orphan',
    'future-focus', 'active-dsc', 'transport', 'render', 'sql-stage', 'latest', 'history', 'publication',
    'later-request', 'negative-receipt', 'task-policy', 'source', 'owner'])
def test_changed_or_future_work_blocks(terminal_case, mutation):
    case = terminal_case; job = case[4]; base = job / 'prototype-pipeline/epochs/epoch-000006'
    final = next(path for path in base.glob('focus-*') if (path / 'review-receipt.json').is_file()
        and json.loads((path / 'review-receipt.json').read_bytes())['verdict'] == 'CHANGES_REQUIRED')
    if mutation in ('correction-event', 'acceptance-event', 'source', 'owner'):
        with case[9]() as db:
            if mutation == 'correction-event': db.execute("DELETE FROM events WHERE action='approved_prototype_review_scope_correction'")
            elif mutation == 'acceptance-event': db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                (case[5]['approvals']['owner'], 'accepted_business_behavior', case[3], 1.0))
            elif mutation == 'source': db.execute("UPDATE sources SET text=text||' '")
            else: db.execute("UPDATE projects SET owner='foreign'")
    elif mutation == 'correction': edit(base / 'review-correction/authorization.json', lambda value: value.update(checkpoint_sha256='0' * 64))
    elif mutation == 'pending': (final / 'reviewer.json').unlink()
    elif mutation == 'orphan':
        path = base / 'review-correction/attempt-000002'; path.mkdir(); (path / 'reviewer-intent.json').write_bytes(b'{}')
    elif mutation == 'future-focus':
        path = base / ('focus-' + 'f' * 24); path.mkdir(); (path / 'mapper-intent.json').write_bytes(b'{}')
    elif mutation == 'active-dsc': (base / 'dsc-identity-repair').mkdir()
    elif mutation == 'transport': (job / 'prototype-transport').mkdir()
    elif mutation == 'render': (job / 'prototype-pipeline/rendered.json').write_bytes(b'{}')
    elif mutation == 'sql-stage': (job / 'prototype-pipeline/import-intent.json').write_bytes(b'{}')
    elif mutation == 'latest': (job / 'prototype-result.json').write_bytes(b'{}')
    elif mutation == 'history':
        publication = json.loads((job / 'prototype-result-publications/epoch-000006/publication.json').read_bytes())
        (job / publication['history_path']).write_bytes(b'{}')
    elif mutation == 'publication': edit(job / 'prototype-result-publications/epoch-000006/publication.json',
        lambda value: value.update(stage_files={'import.json': '0' * 64}))
    elif mutation == 'later-request': edit(final / 'reviewer-request.json', lambda value: value['design_context']['tables']['sources'].clear())
    elif mutation == 'negative-receipt': edit(final / 'review-receipt.json', lambda value: value.update(approved_structured_design=True))
    else: edit(job / 'prototype-pipeline/binding.json', lambda value: value.update(metadata_task_policy='unknown'))
    before = inventory(case)
    assert classify(case)['blocks_admission'] is True and inventory(case) == before


def test_generated_checkedfinder_and_independent_retirement_recheck(terminal_case, historical_case, monkeypatch):
    combine(terminal_case, historical_case)
    result, imported, errors = generated_reader(historical_case, monkeypatch)
    assert not imported & {'prototype_review_correction.py', 'prototype_context_screen_epoch.py', 'prototype_dsc_identity_repair.py'}
    assert result.get('status') == 'RETIRED_HISTORY_OBSERVED', errors[-8:]
    assert result['admission_state'] == 'READY' and result['automatic_replay_permitted'] is False
    assert _read(historical_case)['admission_state'] == 'READY'
    original = recovery.VerificationRecovery._eligibility
    monkeypatch.setattr(recovery.VerificationRecovery, '_eligibility', lambda self, db, rid:
        EXPECTED.copy() if rid == terminal_case[3] else original(self, db, rid))
    monkeypatch.setattr(recovery, 'terminal_prototype_post_correction_review', lambda *args: False)
    from qa.operator.retirement_remote import RetirementRemoteError
    with pytest.raises(RetirementRemoteError, match='CLAUSE_TERMINAL_UNCONFIRMED'): _read(historical_case)
