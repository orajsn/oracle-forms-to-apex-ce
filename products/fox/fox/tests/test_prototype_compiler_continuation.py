"""Frozen six-review proof tests; shared synthetic seed avoids repeated setup."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time

import pytest

from fox import prototype_compiler_continuation as compiler
from fox import prototype_provider_reexecution as provider
from fox import prototype_prose_continuation as prose
from fox.oci_genai import OciGenAiClient
from fox.opaf import OpafError, canonical_hash
from fox.provider_reexecution_routes import _private, _create
from fox.prototype_job import read_prototype_snapshot
from test_prototype_prose_continuation import (runtime as prose_runtime, stopped,
    install as install_prose, unknown, provider_runtime, followup_runtime, reference_runtime,
    configured, client, no_external_actions, settings, base_settings, tmp_path)
from test_development_reference_flow import process, requests, tree_bytes

ERRORS = (OpafError, ValueError, KeyError, TypeError, OSError)
_SEED = pytest.StashKey[dict]()


def session_seed(pytestconfig):
    """Return detached JSON metadata; retained evidence is opt-in only."""
    if _SEED in pytestconfig.stash:
        return deepcopy(pytestconfig.stash[_SEED])
    explicit = os.environ.get('COMPILER_TEST_SEED')
    if not explicit:
        return None
    root = Path(explicit).resolve()
    saved = json.loads((root / 'case.json').read_bytes())
    metadata = {**saved, 'seed_root': str(root), 'target': deepcopy(saved['target'])}
    pytestconfig.stash[_SEED] = json.loads(json.dumps(metadata))
    return deepcopy(pytestconfig.stash[_SEED])


def publish_session_seed(case, pytestconfig, tmp_path_factory):
    """Freeze one consistent seed inside this pytest session's temporary root."""
    cached = session_seed(pytestconfig)
    if cached is not None:
        return cached
    _, root, pid, rid, _, _, target, service = case
    seed = tmp_path_factory.mktemp('s')
    shutil.copytree(root, seed / 'data', ignore=shutil.ignore_patterns(
        'fox.sqlite3', 'fox.sqlite3-wal', 'fox.sqlite3-shm'))
    with sqlite3.connect(root / 'fox.sqlite3') as source:
        with sqlite3.connect(seed / 'data/fox.sqlite3') as destination:
            source.backup(destination)
    metadata = {'seed_root': str(seed), 'rid': rid, 'pid': pid,
                'target': deepcopy(target), 'runtime_calls': len(service.calls)}
    # Round-trip guarantees no client, fixture configuration or mutable target
    # reference is retained after the producing test's teardown.
    pytestconfig.stash[_SEED] = json.loads(json.dumps(metadata))
    with (seed / 'case.json').open('x', encoding='utf-8') as stream:
        json.dump(pytestconfig.stash[_SEED], stream)
    print('G6 session seed built once: ' + str(seed), flush=True)
    return deepcopy(pytestconfig.stash[_SEED])


@pytest.fixture
def runtime(prose_runtime, monkeypatch):
    """Exported to QA: actual local history/SQLite, all SDK replies authored."""
    import test_development_intake_routes as intake
    original_pair = intake.pair
    monkeypatch.setattr(intake, 'pair', lambda code: {
        key: raw.replace(b'<Item Name="FINAL_VALUE"',
            b'<Item Name="FINAL_SECOND" ItemType="Text Item"/><Item Name="FINAL_VALUE"')
        for key, raw in original_pair(code).items()})
    original_alter = prose_runtime.alter
    def absent_last_item_screens(body):
        original_alter(body)
        request = requests(prose_runtime)[-1]
        if 'candidate' in request:
            return
        ids = list(dict.fromkeys(row['focus_id'] for row in requests(prose_runtime) if 'candidate' not in row))
        if ids.index(request['focus_id']) != 5:
            return
        part = body['chat_response']['choices'][0]['message']['content'][0]
        value = json.loads(part['text'])
        value.pop('source_binding', None)
        items = {row['id'] for row in request['owned_objects'] if row['kind'] == 'Item'}
        assert len(items) == 2
        for row in value['blueprint']['objects']:
            if row['source_object_id'] in items:
                row.pop('screen_id')
        units = {row['id']: row['code_unit_id'] for row in request['chunks']}
        for claim in value['blueprint']['claims']:
            claim['evidence_refs'] = [units.get(ref, ref) for ref in claim['evidence_refs']]
        part['text'] = json.dumps(value)
    prose_runtime.alter = absent_last_item_screens
    return prose_runtime


@pytest.fixture
def reviewed(stopped, configured, runtime):
    """QA-shared tuple8: c,root,pid,rid,snapshot,original,target,runtime."""
    c, root, pid, rid, *_ = stopped
    job = root / 'jobs' / rid
    snapshot, original = read_prototype_snapshot(job)
    case = c, root, pid, rid, snapshot, original, configured, runtime
    install_prose(case)
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        connection.execute("UPDATE runs SET state='QUEUED' WHERE id=? AND state='ATTENTION' AND artifact IS NULL", (rid,))
    row = process(root)
    assert row['state'] == 'ATTENTION', runtime.failures
    assert len(runtime.calls) == 13
    assert len(list(job.rglob('reviewer.json'))) == 6
    assert len(tree_bytes(job)) == 82
    assert len(list(provider.paths(job)['receipts'].glob('*.json'))) == 12
    assert not any((job / 'prototype-pipeline' / name).exists() for name in (
        'merged-blueprint.json', 'native-plan.json', 'review-index.json', 'rendered.json', 'apexlang-package.zip'))
    return case


@pytest.fixture
def copied_seed(tmp_path, request, pytestconfig, tmp_path_factory):
    """Standalone proof tests build once, then read independent retained copies."""
    metadata = session_seed(pytestconfig)
    if metadata is None:
        metadata = publish_session_seed(request.getfixturevalue('reviewed'), pytestconfig, tmp_path_factory)
    # The lazy reviewed fixture already owns tmp_path/data in a standalone run.
    root = tmp_path / 'retained'
    shutil.copytree(Path(metadata['seed_root']) / 'data', root)
    job = root / 'jobs' / metadata['rid']
    snapshot, original = read_prototype_snapshot(job)
    return root, job, snapshot, original, deepcopy(metadata['target'])


def test_frozen_originals_zero_model_reconstruction_owner_event_and_tamper(copied_seed, monkeypatch):
    root, job, snapshot, original, target = copied_seed
    before = tree_bytes(job)
    receipts = tree_bytes(provider.paths(job)['receipts'])
    external = {kind: provider.paths(job)[kind].read_bytes() for kind in ('authority', 'consumed', 'adoption')}
    external['prose'] = prose.path(job).read_bytes()
    def forbidden(*a, **k): pytest.fail('Compilation proof must perform zero model operations.')
    monkeypatch.setattr(OciGenAiClient, '_client', forbidden)
    monkeypatch.setattr(OciGenAiClient, 'invoke_prepared', forbidden)
    plan = compiler.inspect(job, snapshot, original, target)
    assert len(plan['before_files']) == 82 and len(plan['before_receipt_files']) == 12
    assert len(plan['original_proofs_sha256']) == len(plan['original_candidate_sha256']) == 6
    assert plan['completion_count'] == 2 and plan['new_model_operations'] == 0
    assert plan['remaining_operations'] == [{'stage': stage} for stage in ('render', 'offline_validate', 'package')]
    record = compiler.records(plan, snapshot['approvals']['owner'], time.time())
    _private(compiler.path(job).parent.parent)
    _private(compiler.path(job).parent)
    _create(compiler.path(job), record)
    with sqlite3.connect(root / 'fox.sqlite3') as connection:
        connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (record['owner'], compiler.EVENT, job.name + ':' + canonical_hash(record), record['approved_at']))
        connection.commit()
        assert compiler.validate_owner(job, snapshot, original, connection) == record
        bundle = compiler.reconstruction(job / 'prototype-pipeline')
        assert bundle['record'] == record and len(bundle['views']) == len(bundle['responses']) == 6
        assert [canonical_hash(view['candidate']) for view in bundle['views']] == plan['original_candidate_sha256']
        assert [canonical_hash(row) for row in bundle['responses']] == plan['completed_candidate_sha256']
        assert len(bundle['receipt']['changes']) == 2 and bundle['merged']['validation']
        assert bundle['receipt']['historical_reviews_relabelled'] is False
        evidence = compiler.index_evidence(job / 'prototype-pipeline')
        assert evidence['new_model_operations'] == 0 and evidence['review_authority_granted'] is False
        assert evidence['historical_reviews_relabelled'] is False and evidence['business_behavior_accepted'] is False
        # Normal compile artifacts may appear; a restarted reader must retain
        # the exact proof rather than rescan a moving model-operation frontier.
        (job / 'prototype-pipeline/merged-blueprint.json').write_text(json.dumps(bundle['merged']))
        assert compiler.technical(job / 'prototype-pipeline') == record
        for location in (job / next(name for name in before if name.endswith('/reviewer.json')),
                         provider.paths(job)['receipts'] / next(iter(receipts)),
                         prose.path(job)):
            saved = location.read_bytes()
            try:
                location.write_bytes(saved + b' ')
                with pytest.raises(ERRORS): compiler.technical(job / 'prototype-pipeline')
            finally:
                location.write_bytes(saved)
        extra = job / 'prototype-pipeline' / plan['focus_ids'][5] / 'mapper-resolution.json'
        extra.write_text('{}')
        with pytest.raises(ERRORS): compiler.technical(job / 'prototype-pipeline')
        extra.unlink()
        extra = provider.paths(job)['receipts'] / ('f' * 64 + '.intent.json')
        extra.write_text('{}')
        with pytest.raises(ERRORS): compiler.technical(job / 'prototype-pipeline')
        extra.unlink()
        connection.execute('DELETE FROM events WHERE action=?', (compiler.EVENT,))
        with pytest.raises(ERRORS): compiler.validate_owner(job, snapshot, original, connection)
    assert all((job / name).read_bytes() == raw for name, raw in before.items())
    assert tree_bytes(provider.paths(job)['receipts']) == receipts
    assert all(provider.paths(job)[key].read_bytes() == raw for key, raw in external.items() if key != 'prose')
    assert prose.path(job).read_bytes() == external['prose']


def test_absent_record_and_event_are_legacy_safe(tmp_path):
    job = tmp_path / 'legacy-job'
    assert compiler.reconstruction(job / 'prototype-pipeline') is None
    assert compiler.index_evidence(job / 'prototype-pipeline') is None
    with sqlite3.connect(':memory:') as connection:
        connection.execute('CREATE TABLE events(owner TEXT,action TEXT,object_id TEXT,created REAL)')
        assert compiler.validate_owner(job, {}, b'', connection) is None
        connection.execute('INSERT INTO events VALUES(?,?,?,?)', ('owner', compiler.EVENT, job.name + ':orphan', 1.0))
        with pytest.raises(ERRORS): compiler.validate_owner(job, {}, b'', connection)


def test_record_requires_exact_zero_model_operation_scope():
    plan = {'scope': compiler.SCOPE, 'policy': compiler.POLICY, 'owner': 'owner',
            'new_model_operations': 0, 'historical_reviews_relabelled': False}
    assert compiler.records(plan, 'owner', 1.0)['plan_sha256'] == canonical_hash(plan)
    for field, invalid in (('new_model_operations', True), ('new_model_operations', 1),
                           ('historical_reviews_relabelled', True), ('policy', 'other')):
        changed = {**plan, field: invalid}
        with pytest.raises(ERRORS): compiler.records(changed, 'owner', 1.0)
    for invalid in (True, 0, float('nan')):
        with pytest.raises(ERRORS): compiler.records(plan, 'owner', invalid)
