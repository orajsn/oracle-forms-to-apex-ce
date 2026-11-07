"""Actual local API/SQLite/filesystem; authored model cache, never live proof."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from fox.opaf import OpafError, canonical_hash
from fox.prototype_admission import prepare_prototype_admission
from fox.prototype_mapping_recovery import retry_run_id
from fox.prototype_pipeline import run_prototype_pipeline
from fox.prototype_project_routes import source_documents
from test_source_history_api import client, settings, no_external_actions
from test_prototype_project_routes import prepare
from test_prototype_pipeline import PROFILE, TARGET, SyntheticOpaf, SyntheticConverter


class EmptyMapper(SyntheticOpaf):
    def invoke(self, role, request):
        output, invocation = super().invoke(role, request)
        if role == PROFILE['mapper']:
            for key, value in output['blueprint'].items():
                if type(value) is list:
                    value.clear()
            invocation['response_sha256'] = canonical_hash({'message': output})
        return output, invocation


@pytest.fixture
def recoverable(client, monkeypatch, request):
    envelope = {'target_profile': deepcopy(TARGET), 'target_profile_sha256': canonical_hash(TARGET)}
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', 'synthetic-no-secret-profile')
    monkeypatch.setattr('fox.prototype_job.load_prototype_profile', lambda _: deepcopy(envelope))
    c, root, pid, assessment, body = prepare(client)
    if hasattr(request, 'param'):
        body['approved_chunk_hashes'] = request.param
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    rid = response.json()['id']
    job = root / 'jobs' / rid
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    docs = source_documents(snapshot['files'])
    # Represent a real legacy-schema parent without copying customer evidence.
    snapshot['prototype'] = prepare_prototype_admission(docs,
        expected_source_binding=body['source_binding'], approved_chunk_hashes=body['approved_chunk_hashes'],
        target_profile_sha256=body['target_profile_sha256'], approved_redacted_source=True,
        approved_external_ai=True, approved_prototype_scope=True)['prototype']
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    model = EmptyMapper()
    with pytest.raises(ValueError):
        run_prototype_pipeline(job, docs, project_id=pid, project_name=snapshot['project_name'],
            expected_source_binding=body['source_binding'], approved_chunk_hashes=body['approved_chunk_hashes'],
            approved_policy_id=snapshot['prototype']['approved_policy_id'], opaf_client=model,
            profile=PROFILE, target_profile_loader=lambda: deepcopy(TARGET), processing_approval_check=lambda _: True)
    assert [name for name, _ in model.calls] == ['mapper']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='ATTENTION' WHERE id=?", (rid,))
    return c, root, pid, rid, job, snapshot, body, envelope, model


def url(case, operation='mapping-recovery'):
    return f'/api/projects/{case[2]}/prototype-runs/{case[3]}/{operation}'


def parent_bytes(case):
    return {path.relative_to(case[4]): path.read_bytes() for path in case[4].rglob('*') if path.is_file()}


def test_readonly_counts_and_idempotent_child_preserve_original_bytes(recoverable):
    c, root, pid, rid, job, snapshot, body, _, model = recoverable
    original = parent_bytes(recoverable)
    calls = deepcopy((model.calls, model.observations))
    response = c.get(url(recoverable))
    assert response.status_code == 200, response.text
    proof = response.json()
    assert proof['eligible'] is True and proof['returned_objects'] == 0 and proof['expected_objects'] > 0
    assert proof['parent_snapshot_sha256'] == hashlib.sha256((job / 'source-snapshot.json').read_bytes()).hexdigest()
    assert proof['approved_chunk_hashes'] == body['approved_chunk_hashes']
    assert proof['source_binding'] == body['source_binding']
    assert proof['target_profile_changed'] is False
    assert proof['target_profile_sha256'] == proof['parent_target_profile_sha256']
    assert 'MISSING_API' not in response.text and 'blueprint' not in response.text
    assert response.headers['cache-control'] == 'no-store'
    assert parent_bytes(recoverable) == original
    assert (model.calls, model.observations) == calls
    first = c.post(url(recoverable, 'retry-mapping'), json=body)
    assert first.status_code == 202, first.text
    child_id = first.json()['id']
    assert child_id == retry_run_id(rid) and first.json()['retry_of'] == rid
    child_raw = (root / 'jobs' / child_id / 'source-snapshot.json').read_bytes()
    child = json.loads(child_raw)
    assert child['retry_of'] == rid and child['prototype']['schema_version'] == 2
    assert child['prototype']['max_owned_objects'] == 32
    assert child['files'] == snapshot['files'] and child['source_hash'] == snapshot['source_hash']
    assert child['prototype']['approved_chunk_hashes'] == snapshot['prototype']['approved_chunk_hashes']
    second = c.post(url(recoverable, 'retry-mapping'), json=body)
    assert second.status_code == 200 and second.json() == first.json()
    assert (root / 'jobs' / child_id / 'source-snapshot.json').read_bytes() == child_raw
    assert parent_bytes(recoverable) == original
    assert (model.calls, model.observations) == calls
    inspected = c.get(url(recoverable)).json()
    assert inspected['eligible'] is False and inspected['existing_retry_run_id'] == child_id
    assert c.get(f'/api/projects/{pid}').status_code == 200
    history = c.get(f'/api/projects/{pid}/source-sets')
    assert history.status_code == 200, history.text
    assert history.json()['source_sets'][0]['run_ids'] == [rid, child_id]
    sid = snapshot['selected_source_set_id']
    detail = c.get(f'/api/projects/{pid}/source-sets/{sid}')
    assert detail.status_code == 200 and detail.json()['source_set']['run_ids'] == [rid, child_id]
    selected = c.post(f'/api/projects/{pid}/source-sets/{sid}/select',
                      json={'expected_current_source_set_id': sid})
    assert selected.status_code == 200, selected.text
    assert selected.json()['source_set']['run_ids'] == [rid, child_id]
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        rows = db.execute('SELECT id,source_hash,state FROM runs ORDER BY created').fetchall()
        assert rows == [(rid, snapshot['source_hash'], 'ATTENTION'), (child_id, snapshot['source_hash'], 'QUEUED')]
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='approved_prototype_mapping_retry'").fetchone()[0] == 1
    # The normal generation guard remains unchanged even after retry migration.
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 409


@pytest.mark.parametrize('key,value', [('source_hash', 'f' * 64), ('source_binding', 'f' * 64),
    ('expected_current_source_set_id', 'ss-' + 'f' * 32), ('target_profile_sha256', 'f' * 64),
    ('approved_chunk_hashes', {}), ('approved_redacted_source', False),
    ('approved_external_ai', False), ('approved_prototype_scope', False)])
def test_post_requires_exact_parent_scope_and_three_fresh_consents(recoverable, key, value):
    body = deepcopy(recoverable[6])
    body[key] = value
    assert recoverable[0].post(url(recoverable, 'retry-mapping'), json=body).status_code == 409
    assert not (recoverable[1] / 'jobs' / retry_run_id(recoverable[3])).exists()


@pytest.mark.parametrize('artifact', ['unknown-mapper', 'reviewer-intent', 'converter-intent',
    'human-review', 'output-hash', 'wrong-object', 'bad-shape', 'source-bytes', 'binding', 'consent'])
def test_unsafe_unknown_or_noncoverage_failure_never_authorizes_retry(recoverable, artifact):
    c, _, _, _, job, snapshot, body, _, _ = recoverable
    pipeline = job / 'prototype-pipeline'
    mapper = next(pipeline.glob('focus-*/mapper.json'))
    if artifact == 'unknown-mapper':
        mapper.unlink()
    elif artifact == 'reviewer-intent':
        (mapper.parent / 'reviewer-intent.json').write_text('{}')
    elif artifact == 'converter-intent':
        (pipeline / 'import-intent.json').write_text('{}')
    elif artifact == 'human-review':
        (job / 'prototype-result.json').write_text(json.dumps({'status': 'CHANGES_REQUIRED', 'stage': 'reviewing'}))
    elif artifact in ('output-hash', 'wrong-object', 'bad-shape'):
        saved = json.loads(mapper.read_bytes())
        if artifact == 'output-hash':
            saved['output_sha256'] = '0' * 64
        elif artifact == 'wrong-object':
            saved['output']['blueprint']['objects'] = [{'source_object_id': 'invented',
                'disposition': 'unresolved', 'reason': 'Authored invalid owner'}]
            saved['output_sha256'] = canonical_hash(saved['output'])
        else:
            saved['output']['blueprint']['claims'] = 'invalid'
            saved['output_sha256'] = canonical_hash(saved['output'])
        mapper.write_text(json.dumps(saved))
    elif artifact == 'source-bytes':
        (pipeline / 'sources' / 'source-000.xml').write_bytes(b'<FormModule Name="OTHER"/>')
    elif artifact == 'binding':
        saved = json.loads((pipeline / 'binding.json').read_bytes())
        saved['focus_plan_sha256'] = '0' * 64
        (pipeline / 'binding.json').write_text(json.dumps(saved))
    else:
        snapshot['approvals']['external_ai'] = False
        (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    assert c.get(url(recoverable)).status_code == 409
    assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == 409


@pytest.mark.parametrize('change', ['owner', 'selection', 'source', 'state', 'artifact'])
def test_current_state_and_owner_are_checked_before_recovery(recoverable, change):
    c, root, pid, rid, _, _, body, _, _ = recoverable
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        if change == 'owner': db.execute('UPDATE projects SET owner=? WHERE id=?', ('foreign', pid))
        elif change == 'selection': db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
        elif change == 'source': db.execute('UPDATE sources SET text=text||?', (' ',))
        elif change == 'state': db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?", (rid,))
        else: db.execute('UPDATE runs SET artifact=? WHERE id=?', ('retained.zip', rid))
    status = 404 if change == 'owner' else 409
    assert c.get(url(recoverable)).status_code == status
    assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == status


def test_foreign_and_missing_run_are_not_disclosed(recoverable):
    c, root, pid, rid, _, _, body, _, _ = recoverable
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('foreign', 'other', 'Synthetic', 'Private', '', 1))
    for path in (f'/api/projects/foreign/prototype-runs/{rid}',
                 f'/api/projects/{pid}/prototype-runs/fox-' + '0' * 20):
        assert c.get(path + '/mapping-recovery').status_code == 404
        assert c.post(path + '/retry-mapping', json=body).status_code == 404


@pytest.mark.parametrize('change', ['destination', 'model', 'scope', 'numeric-type', 'roles'])
def test_only_explicit_role_graph_replacement_keeps_execution_destination(recoverable, change):
    c, root, _, rid, _, _, body, envelope, _ = recoverable
    if change == 'destination': envelope['target_profile']['opaf']['base_url'] = 'https://other.invalid/agentFactory'
    elif change == 'model': envelope['target_profile']['opaf']['roles']['mapper']['model'] = 'different-model'
    elif change == 'scope': envelope['target_profile']['scope'] = {'data_mode': 'other'}
    elif change == 'numeric-type': envelope['target_profile']['opaf']['version_number'] = 26.4
    else:
        for name, marker in [('mapper', 'C'), ('reviewer', 'D')]:
            envelope['target_profile']['opaf']['roles'][name].update(workflow_id=marker * 32, graph_sha256=marker.lower() * 64)
    envelope['target_profile_sha256'] = canonical_hash(envelope['target_profile'])
    inspected = c.get(url(recoverable))
    if change != 'roles':
        assert inspected.status_code == 409
        assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == 409
        return
    assert inspected.status_code == 200, inspected.text
    assert inspected.json()['target_profile_changed'] is True
    assert inspected.json()['parent_target_profile_sha256'] == body['target_profile_sha256']
    assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == 409
    fresh = {**body, 'target_profile_sha256': envelope['target_profile_sha256']}
    created = c.post(url(recoverable, 'retry-mapping'), json=fresh)
    assert created.status_code == 202, created.text
    child = json.loads((root / 'jobs' / created.json()['id'] / 'source-snapshot.json').read_bytes())
    assert child['prototype']['target_profile_sha256'] == envelope['target_profile_sha256']
    assert child['retry_of'] == rid


@pytest.mark.parametrize('orphan', ['filesystem', 'database', 'changed-child', 'uncertain-child'])
def test_duplicate_or_orphan_child_is_never_replayed(recoverable, orphan):
    c, root, pid, rid, _, snapshot, body, _, _ = recoverable
    child_id = retry_run_id(rid)
    child = root / 'jobs' / child_id
    if orphan == 'filesystem':
        child.mkdir()
    elif orphan == 'database':
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                (child_id, pid, snapshot['source_hash'], 'QUEUED', 'Unknown', 4, 4, None))
    else:
        assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == 202
        if orphan == 'changed-child':
            value = json.loads((child / 'source-snapshot.json').read_bytes())
            value['mapping_recovery']['parent_snapshot_sha256'] = '0' * 64
            (child / 'source-snapshot.json').write_text(json.dumps(value))
        else:
            (child / 'mapper-intent.json').write_text('{}')
    assert c.get(url(recoverable)).status_code == 409
    assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == 409


def test_serialized_duplicate_posts_make_only_one_child(recoverable):
    c, root, _, rid, _, _, body, _, _ = recoverable
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: c.post(url(recoverable, 'retry-mapping'), json=body), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 202]
    assert len({response.json()['id'] for response in responses}) == 1
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 2
        assert db.execute('SELECT COUNT(*) FROM runs WHERE id=?', (retry_run_id(rid),)).fetchone()[0] == 1


def test_child_connects_to_existing_worker_with_schema2_and_no_parent_replay(recoverable, monkeypatch):
    from fox import prototype_job, worker
    c, root, _, rid, _, parent, body, _, old_model = recoverable
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.delenv('FOX_INSTALLATION_MODE', raising=False)
    response = c.post(url(recoverable, 'retry-mapping'), json=body)
    assert response.status_code == 202
    child_id = response.json()['id']
    before = parent_bytes(recoverable)
    old_calls = deepcopy(old_model.calls)
    model, converter = SyntheticOpaf(), SyntheticConverter()
    monkeypatch.setattr(prototype_job, '_configuration', lambda *a, **kw: {
        'profile': deepcopy(PROFILE), 'opaf_client': model,
        'target_profile_loader': lambda: deepcopy(TARGET), 'converter_adapter': converter})
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3')
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    worker.process_one(db, root)
    with db() as connection:
        assert connection.execute('SELECT state FROM runs WHERE id=?', (child_id,)).fetchone()[0] == 'GENERATED'
        assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    binding = json.loads((root / 'jobs' / child_id / 'prototype-pipeline' / 'binding.json').read_bytes())
    assert binding['schema_version'] == 2 and binding['max_owned_objects'] == 32
    assert model.calls and converter.calls  # Authored transports, not live proof.
    assert old_model.calls == old_calls and parent_bytes(recoverable) == before
    repeated = c.post(url(recoverable, 'retry-mapping'), json=body)
    assert repeated.status_code == 200 and repeated.json()['state'] == 'GENERATED'
    child_path = f'/api/projects/{parent["project_id"]}/prototype-runs/{child_id}'
    assert c.post(child_path + '/retry-mapping', json=body).status_code == 409


def test_complete_first_mapping_is_not_misclassified_as_missing_coverage(recoverable):
    c, _, _, _, job, _, body, _, _ = recoverable
    mapper = next((job / 'prototype-pipeline').glob('focus-*/mapper.json'))
    request = json.loads((mapper.parent / 'request.json').read_bytes())
    saved = json.loads(mapper.read_bytes())
    output, invocation = SyntheticOpaf().invoke(PROFILE['mapper'], request)
    saved.update(output=output, output_sha256=canonical_hash(output), invocation=invocation)
    mapper.write_text(json.dumps(saved))
    inspected = c.get(url(recoverable))
    assert inspected.status_code == 200, inspected.text
    assert inspected.json()['eligible'] is False
    assert inspected.json()['returned_objects'] == inspected.json()['expected_objects']
    assert c.post(url(recoverable, 'retry-mapping'), json=body).status_code == 409


@pytest.mark.parametrize('recoverable', [{}], indirect=True)
def test_metadata_only_parent_is_not_silently_expanded_to_all_code(recoverable):
    c, root, _, _, _, _, body, _, _ = recoverable
    inspected = c.get(url(recoverable))
    assert inspected.status_code == 200 and inspected.json()['approved_chunk_hashes'] == {}
    created = c.post(url(recoverable, 'retry-mapping'), json=body)
    assert created.status_code == 202, created.text
    child = json.loads((root / 'jobs' / created.json()['id'] / 'source-snapshot.json').read_bytes())
    assert child['prototype']['approved_chunk_hashes'] == {}
    assert created.json()['summary']['metadata_only'] is True
