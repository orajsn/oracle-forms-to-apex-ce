"""Real isolated API/SQLite/worker, injected direct protocol, authored compiler only."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import time
import uuid

import pytest

from fox import prototype_job, prototype_export_only as package, source_history, worker
from fox.development_processing import describe_development_processing, prepare_development_processing
from fox.design_provider import roles
from fox.oci_genai import OciGenAiClient
from fox.opaf import canonical_hash
from fox.prototype_admission import prepare_prototype_admission
from fox.prototype_chunk_evidence import POLICY
from fox.prototype_job import validate_prototype_snapshot
from fox.source_processing_policy import DEVELOPMENT_EVENT
from test_development_generation_routes import development_case, queued_case
from test_development_intake_routes import settings
from test_source_history_api import client, no_external_actions, settings as base_settings, new_project
from test_prototype_export_only import authored_validator, tree_bytes
from test_oci_genai import InjectedService, fake_sdk, target


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp('r')


@pytest.fixture
def configured(monkeypatch):
    destination = target()
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', 'synthetic-not-opened')
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.setattr(prototype_job, 'load_prototype_profile', lambda path: {
        'target_profile_sha256': canonical_hash(destination), 'target_profile': deepcopy(destination)})
    return destination


@pytest.fixture
def runtime(configured, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    import test_development_intake_routes as intake
    original_pair = intake.pair
    def with_first_focus_code(code):
        outputs = original_pair(code)
        return {key: raw.replace(b'<Block ', b'<Trigger Name="START" TriggerText="BEGIN APP.START(123); END;"/><Block ', 1)
                for key, raw in outputs.items()}
    monkeypatch.setattr(intake, 'pair', with_first_focus_code)
    service = InjectedService()
    def alter(body):
        part = body['chat_response']['choices'][0]['message']['content'][0]
        output = json.loads(part['text'])
        request = json.loads(service.calls[-1][0]['chat_request']['messages'][1]['content'][0]['text'])
        if 'blueprint' in output:
            for row in output['blueprint']['objects']:
                source = next(o for o in request['owned_objects'] if o['id'] == row['source_object_id'])
                if source['kind'] == 'FormModule' and getattr(service, 'omit_container', False):
                    row['disposition'] = 'omitted'
                if source['kind'] == 'Block' and source['classification'] == 'control':
                    row['native_component'] = 'page-items'
            if request['chunks']:
                chunk = request['chunks'][0]
                unit = next(u for u in request['code_units'] if u['id'] == chunk['code_unit_id'])
                output['blueprint']['claims'] = [{'id': 'intent-' + request['focus_id'],
                    'source_object_id': unit['owner_id'], 'kind': 'behavior.intent', 'status': 'proposal',
                    'value': 'Preserve source intent.', 'reason': 'Synthetic proposal needs business review.',
                    'evidence_refs': [unit['owner_id'], chunk['id']]}]
        part['text'] = json.dumps(output)
    service.alter = alter
    direct = OciGenAiClient(configured, client=service, sdk=fake_sdk())
    monkeypatch.setattr(package, 'package_configuration', lambda *a, **k: {
        'profile': roles(configured), 'opaf_client': direct,
        'target_profile_loader': lambda: deepcopy(configured), 'offline_validator': authored_validator})
    return service


def process(root):
    @contextmanager
    def db():
        c = sqlite3.connect(root / 'fox.sqlite3')
        c.row_factory = sqlite3.Row
        try:
            with c:
                yield c
        finally:
            c.close()
    worker.process_one(db, root)
    with db() as c:
        return dict(c.execute('SELECT * FROM runs ORDER BY created DESC LIMIT 1').fetchone())


def requests(service):
    return [json.loads(d['chat_request']['messages'][1]['content'][0]['text']) for d, _ in service.calls]


def assert_download(c, root, pid, rid):
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/output')
    assert response.status_code == 200, response.text
    output = response.json()
    assert output['format_validated'] is True
    assert output['technically_verified'] is False
    assert output['runtime_verified'] is False
    assert output['business_behavior_accepted'] is False
    before = tree_bytes(root / 'jobs' / rid)
    downloaded = c.get(output['download_path'])
    assert downloaded.status_code == 200, downloaded.text
    assert hashlib.sha256(downloaded.content).hexdigest() == output['package_sha256']
    assert downloaded.content == (root / 'jobs' / rid / 'prototype-pipeline/apexlang-package.zip').read_bytes()
    assert tree_bytes(root / 'jobs' / rid) == before
    return output


@pytest.mark.parametrize('container', [False, True])
def test_fresh_chunk_policy_direct_worker_and_download(client, configured, runtime, container):
    runtime.omit_container = container
    c, root, pid, rid, snapshot = queued_case(client)
    assert snapshot['prototype']['chunk_evidence_policy'] == POLICY
    assert snapshot['prototype']['development_processing']['chunk_evidence_policy'] == POLICY
    row = process(root)
    assert row['state'] == 'GENERATED', row
    projected = []
    for request in requests(runtime):
        if 'candidate' not in request:
            continue
        for claim in request['candidate']['blueprint']['claims']:
            units = {u['id']: u for u in request['request']['code_units']}
            assert claim['evidence_refs'][0] == claim['source_object_id']
            assert units[claim['evidence_refs'][1]]['owner_id'] == claim['source_object_id']
            projected.append(claim)
    assert projected
    receipts = [json.loads(p.read_bytes()) for p in
                (root / 'jobs' / rid).rglob('projection-receipt.json')]
    assert any(r.get('chunk_evidence') for r in receipts)
    if container:
        assert any(r.get('chunk_evidence') and r.get('container_retention') for r in receipts)
    calls = deepcopy(runtime.calls)
    assert_download(c, root, pid, rid)
    assert runtime.calls == calls


def seed_old(client, destination):
    """Build original pre-policy consent from current genuine selected-source history."""
    c, root, pid, assessment, body = development_case(client)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        sources = source_history.selected_sources(db, pid)
        docs = [(s['name'], source_history.readable_source_bytes(s)) for s in sources]
        owner, name = db.execute('SELECT owner,name FROM projects WHERE id=?', (pid,)).fetchone()
        context = describe_development_processing(docs, project_id=pid,
            selected_source_set_id=assessment['selected_source_set_id'], source_hash=assessment['source_hash'],
            source_provenance=source_history.source_provenance(db, pid, sources),
            target_profile_sha256=canonical_hash(destination), delivery_mode='apexlang_package')
        selected = prepare_prototype_admission(docs,
            expected_source_binding=assessment['source_binding'], approved_chunk_hashes=body['approved_chunk_hashes'],
            target_profile_sha256=canonical_hash(destination), approved_redacted_source=False,
            approved_unredacted_development_source=True, approved_external_ai=True, approved_prototype_scope=True,
            processing_mode='development', development_processing=prepare_development_processing(docs,
                context=context, approved_chunk_hashes=body['approved_chunk_hashes']),
            schema_version=2, metadata_task_policy='same-byte-dsc-identity-metadata-v1',
            candidate_format_policy='exact-source-envelope-and-item-fact-aliases-v1',
            delivery_mode='apexlang_package')['prototype']
        now, rid = time.time(), 'fox-' + uuid.uuid4().hex[:20]
        snapshot = {'project': pid, 'project_id': pid, 'project_name': name,
            'source_hash': assessment['source_hash'], 'conversion_profile': 'native-blueprint-prototype-v1',
            'selected_source_set_id': assessment['selected_source_set_id'], 'files': sources, 'prototype': selected,
            'approvals': {'redacted_source': False, 'external_ai': True, 'synthetic_prototype': True,
                'owner': owner, 'approved_at': now, 'unredacted_development_source': True}}
        assert validate_prototype_snapshot(snapshot) == docs
        job = root / 'jobs' / rid
        job.mkdir(parents=True)
        (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
            (rid, pid, snapshot['source_hash'], 'QUEUED', 'Synthetic retained old admission', now, now, None))
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (owner, DEVELOPMENT_EVENT, rid, now))
    return c, root, pid, rid, snapshot


@pytest.fixture
def stopped(client, configured, runtime):
    value = seed_old(client, configured)
    c, root, pid, rid, snapshot = value
    row = process(root)
    assert row['state'] == 'ATTENTION', row
    calls = requests(runtime)
    assert len(calls) == 1 and 'candidate' not in calls[0]
    assert calls[0]['chunks'], 'First mapper must exercise a genuine selected chunk.'
    assert len(list((root / 'jobs' / rid).rglob('mapper.json'))) == 1
    assert not list((root / 'jobs' / rid).rglob('reviewer.json'))
    return value


def test_old_same_run_retains_mapper_and_independently_reviews(stopped, runtime):
    c, root, pid, rid, snapshot = stopped
    job = root / 'jobs' / rid
    before = tree_bytes(job)
    url = f'/api/projects/{pid}/prototype-runs/{rid}/development-reference-resume'
    response = c.get(url)
    assert response.status_code == 200, response.text
    plan = response.json()
    assert plan['eligible'] and plan['reference_corrections'] > 0
    body = {'plan_sha256': plan['plan_sha256'], 'approved_source_reference_correction': True}
    response = c.post(url, json=body)
    assert response.status_code == 202, response.text
    assert len(runtime.calls) == 1
    row = process(root)
    assert row['state'] == 'GENERATED', row
    for name, raw in before.items():
        assert (job / name).read_bytes() == raw, name
    calls = requests(runtime)
    assert 'candidate' in calls[1], 'First new call must review the retained first mapper.'
    mappers = [r for r in calls if 'candidate' not in r]
    reviewers = [r for r in calls if 'candidate' in r]
    assert len(mappers) == len(reviewers)
    assert len({r['focus_id'] for r in mappers}) == len(mappers)
    assert [r['request']['focus_id'] for r in reviewers] == [r['focus_id'] for r in mappers]
    assert_download(c, root, pid, rid)
    sealed, call_count = tree_bytes(job), len(runtime.calls)
    duplicate = c.post(url, json=body)
    assert duplicate.status_code == 202, duplicate.text
    assert duplicate.json()['already_recorded'] is True
    assert duplicate.json()['state'] == 'GENERATED'
    assert tree_bytes(job) == sealed and len(runtime.calls) == call_count
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'GENERATED'
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
        event = db.execute("SELECT owner,action,object_id,created FROM events WHERE action='approved_prototype_development_reference_resume'").fetchone()
        db.execute('DELETE FROM events WHERE object_id=?', (event[2],))
    for suffix in ('output', 'download'):
        assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/{suffix}').status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', event)
    technical = job / 'prototype-pipeline/development-reference-resume.json'
    original = technical.read_bytes()
    technical.write_text('{}')
    for suffix in ('output', 'download'):
        assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/{suffix}').status_code == 409
    technical.write_bytes(original)
    assert_download(c, root, pid, rid)
    assert len(runtime.calls) == call_count


@pytest.mark.parametrize('mutation', ['plan', 'missing-consent', 'owner', 'event', 'source', 'target', 'mapper', 'unknown', 'project'])
def test_old_resume_rejects_changed_or_missing_evidence(stopped, configured, runtime, mutation):
    c, root, pid, rid, snapshot = stopped
    url = f'/api/projects/{pid}/prototype-runs/{rid}/development-reference-resume'
    response = c.get(url)
    assert response.status_code == 200, response.text
    body = {'plan_sha256': response.json()['plan_sha256'], 'approved_source_reference_correction': True}
    if mutation == 'plan': body['plan_sha256'] = 'f' * 64
    elif mutation == 'project': url = f'/api/projects/{new_project(c)}/prototype-runs/{rid}/development-reference-resume'
    elif mutation == 'missing-consent': body.pop('approved_source_reference_correction')
    elif mutation == 'target': configured['profile_id'] += '-changed'
    elif mutation in ('mapper', 'unknown'):
        job = root / 'jobs' / rid
        if mutation == 'mapper': next(job.rglob('mapper.json')).write_text('{}')
        else: (job / 'prototype-pipeline/unknown.json').write_text('{}')
    else:
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            if mutation == 'owner': db.execute('UPDATE projects SET owner=? WHERE id=?', ('synthetic-other', pid))
            elif mutation == 'event': db.execute('DELETE FROM events WHERE object_id=?', (rid,))
            else: db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', (pid,))
    before = tree_bytes(root / 'jobs' / rid)
    response = c.post(url, json=body)
    assert response.status_code in (404, 409, 422), response.text
    assert len(runtime.calls) == 1 and tree_bytes(root / 'jobs' / rid) == before
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
