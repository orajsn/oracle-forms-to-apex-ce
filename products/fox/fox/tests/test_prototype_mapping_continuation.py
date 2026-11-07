"""Actual local API/checkpoints; all model/converter evidence is authored."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from fox import prototype_pipeline as pipeline, prototype_job, worker
from fox.opaf import canonical_hash, OpafError
from fox.prototype_mapping_continuation import RECORD, EVENT
from fox.prototype_transport import build_authority_bundle
from test_source_history_api import client, settings as baseline_settings, no_external_actions, upload
from test_prototype_pipeline import SyntheticOpaf, SyntheticConverter, PROFILE, TARGET


class ConfusedMapper(SyntheticOpaf):
    def invoke(self, role, request):
        output, invocation = super().invoke(role, request)
        if role == PROFILE['mapper'] and len([name for name, _ in self.calls if name == 'mapper']) == 6:
            unit = request['code_units'][0]
            output['blueprint']['claims'] = [{'id': 'behavior-six', 'source_object_id': unit['id'],
                'kind': 'behavior', 'value': 'Requires business review', 'status': 'proposal',
                'evidence_refs': [unit['id']], 'reason': 'Authored synthetic source claim, not working business logic.'}]
            invocation['response_sha256'] = canonical_hash(output)
        return output, invocation


@pytest.fixture
def settings(monkeypatch):
    baseline_settings.__wrapped__(monkeypatch)
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'd' * 64)


@pytest.fixture
def continuation(client, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    monkeypatch.delenv('FOX_INSTALLATION_MODE', raising=False)
    monkeypatch.setitem(TARGET, 'active', True)
    monkeypatch.setitem(TARGET, 'scope', {'data_mode': 'synthetic_test_only', 'existing_resources_only': True,
                                      'customer_deployment_authorized': False})
    envelope = {'target_profile': TARGET, 'target_profile_sha256': canonical_hash(TARGET)}
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', 'synthetic-public-metadata')
    monkeypatch.setattr(prototype_job, 'load_prototype_profile', lambda _: deepcopy(envelope))
    c, root, pid = client
    raw = ('<FormModule Name="SYNTHETIC">' + ''.join(
        f'<Block Name="B{i}" DatabaseBlock="true"><Item Name="VALUE" ItemType="Text Item" DatabaseItem="true"/>'
        '<Trigger Name="SAVE" TriggerText="BEGIN NULL; END;"/></Block>' for i in range(8)) + '</FormModule>').encode()
    upload(c, pid, [('synthetic.xml', raw)])
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment').json()
    body = {key: assessment[key] for key in ('source_hash', 'source_binding', 'target_profile_sha256')}
    body.update(expected_current_source_set_id=assessment['selected_source_set_id'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in assessment['chunks']},
        approved_redacted_source=True, approved_external_ai=True, approved_prototype_scope=True)
    queued = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert queued.status_code == 202, queued.text
    rid = queued.json()['id']
    job = root / 'jobs' / rid
    root.chmod(0o700)
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    model, converter = ConfusedMapper(), SyntheticConverter()
    with monkeypatch.context() as old:
        # Create the old released failure faithfully; no candidate is repaired
        # or new reviewer invoked while building this synthetic fixture.
        old.setattr(pipeline, 'resolved_mapper', lambda directory, request, candidate, **kwargs: (candidate, None))
        with pytest.raises(ValueError):
            pipeline.run_prototype_pipeline(job, [('synthetic.xml', raw)], project_id=pid,
                project_name=snapshot['project_name'], expected_source_binding=body['source_binding'],
                approved_chunk_hashes=body['approved_chunk_hashes'], approved_policy_id=snapshot['prototype']['approved_policy_id'],
                opaf_client=model, profile=PROFILE, target_profile_loader=lambda: deepcopy(TARGET),
                processing_approval_check=lambda _: True, focus_schema_version=2)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='ATTENTION' WHERE id=?", (rid,))
    @contextmanager
    def db():
        connection = sqlite3.connect(root / 'fox.sqlite3')
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()
    monkeypatch.setattr(prototype_job, '_configuration', lambda *a, **kw: {'profile': PROFILE,
        'opaf_client': model, 'target_profile_loader': lambda: deepcopy(TARGET), 'converter_adapter': converter})
    return c, root, pid, rid, job, body, model, converter, db, envelope


def url(case, action='mapping-continuation'):
    return f'/api/projects/{case[2]}/prototype-runs/{case[3]}/{action}'


def test_same_run_continues_without_repeating_completed_calls_or_editing_originals(continuation):
    c, root, pid, rid, job, body, model, converter, db, _ = continuation
    originals = {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    old_calls = deepcopy(model.calls)
    response = c.get(url(continuation))
    assert response.status_code == 200, response.text
    projection = response.json()
    assert projection['eligible'] is True and projection['completed_focuses'] == 5
    assert projection['resolved_claim_owners'] == 1 and projection['continuation_recorded'] is False
    assert model.calls == old_calls and converter.calls == []
    request = {**body, 'checkpoint_sha256': projection['checkpoint_sha256']}
    first = c.post(url(continuation, 'continue-mapping'), json=request)
    assert first.status_code == 202, first.text
    assert first.json() == {'id': rid, 'state': 'QUEUED', 'conversion_profile': 'native-blueprint-prototype-v1', 'continued': True}
    assert c.post(url(continuation, 'continue-mapping'), json=request).status_code == 200
    stage = converter.run_stage
    def completed(stage_name, stage_request):
        receipt = stage(stage_name, stage_request)
        receipt.update(status='COMPLETE', business_behavior_accepted=False)
        return receipt
    converter.run_stage = completed
    worker.process_one(db, root)
    with db() as connection:
        row = connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()
        assert row['state'] == 'GENERATED', connection.execute('SELECT message FROM runs WHERE id=?', (rid,)).fetchone()[0]
        assert connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM events WHERE action=?', (EVENT,)).fetchone()[0] == 1
    assert model.calls[:len(old_calls)] == old_calls
    assert model.calls[len(old_calls)][0] == 'reviewer'
    assert len([name for name, _ in model.calls if name == 'mapper']) == 9
    assert all((job / name).read_bytes() == raw for name, raw in originals.items())
    assert len(list(job.rglob('mapper-resolution.json'))) == 1
    before = deepcopy((model.calls, converter.calls))
    again = c.post(url(continuation, 'continue-mapping'), json=request)
    assert again.status_code == 200 and again.json()['state'] == 'GENERATED'
    assert (model.calls, converter.calls) == before
    # Full existing source/reviewer authority reconstructs normalized receipt.
    converter_request = converter.requests[0]
    pipeline.authorize_prototype_request(job, converter_request)
    bundle = build_authority_bundle(job, converter_request)
    assert len([row for row in bundle['files'] if row['path'].endswith('mapper-resolution.json')]) == 1
    from fox.prototype_download import retained_export_request
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    retained_export_request(job, snapshot, continuation[-1])
    from types import SimpleNamespace
    from forms2apex.prototype_gateway import PrototypeGateway
    remote_jobs = root / 'receiver-jobs'
    remote_jobs.mkdir()
    remote_job = remote_jobs / rid
    receiver = PrototypeGateway(SimpleNamespace(jobs_root=remote_jobs),
        authorize=lambda value: pipeline.authorize_prototype_request(remote_job, value))
    receipt = receiver.stage_source_authority(rid, bundle)
    assert receipt['staged'] is True and receipt['source_review_authorized'] is False
    receiver._authorize(converter_request)  # Real callback, not an authored boolean.
    before = {path.relative_to(remote_job): path.read_bytes() for path in remote_job.rglob('*') if path.is_file()}
    assert receiver.recover_source_authority(rid) == receipt
    assert before == {path.relative_to(remote_job): path.read_bytes() for path in remote_job.rglob('*') if path.is_file()}
    normalized = next(remote_job.rglob('mapper-resolved.json'))
    value = json.loads(normalized.read_bytes()); value['blueprint']['schema_version'] = True
    normalized.write_text(json.dumps(value))
    with pytest.raises(OpafError):
        receiver._authorize(converter_request)


@pytest.mark.parametrize('change', ['owner', 'source', 'target', 'checkpoint', 'consent', 'selection', 'unknown-reviewer',
                                   'later-stage', 'review-changes', 'tampered-mapper', 'orphan-record', 'origin', 'acceptance', 'queue'])
def test_continuation_refuses_stale_or_uncertain_operations(continuation, change):
    c, _, pid, rid, job, body, _, _, db, envelope = continuation
    projection = c.get(url(continuation)).json()
    request = {**body, 'checkpoint_sha256': projection['checkpoint_sha256']}
    blocked = job / 'prototype-pipeline' / projection['blocked_focus_id']
    if change in ('owner', 'source', 'selection', 'origin', 'acceptance', 'queue'):
        with db() as connection:
            if change == 'owner': connection.execute("UPDATE projects SET owner='foreign' WHERE id=?", (pid,))
            elif change == 'source': connection.execute('UPDATE sources SET text=text||?', (' ',))
            elif change == 'selection': connection.execute('UPDATE project_source_selection SET current_source_set_id=NULL')
            elif change == 'origin': connection.execute('DELETE FROM events WHERE action=? AND object_id=?', ('approved_prototype_conversion', rid))
            elif change == 'acceptance': connection.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)',
                (rid, 'synthetic', body['source_hash'], 'a' * 64, 'Authored conflict', 1))
            else:
                # Deliberately inconsistent foreign phase; no claim may be adopted.
                connection.execute('INSERT INTO verification_queue(job_id,source_manifest_sha256,package_sha256,verifier_release_sha256,binding_sha256,state,created_at_utc,updated_at_utc,record_sha256) VALUES(?,?,?,?,?,?,?,?,?)',
                    (rid, body['source_hash'], 'a' * 64, 'd' * 64, 'b' * 64, 'queued', '2026-11-06T00:00:00Z', '2026-11-06T00:00:00Z', 'c' * 64))
    elif change == 'target': envelope['target_profile_sha256'] = '0' * 64
    elif change == 'checkpoint': request['checkpoint_sha256'] = '0' * 64
    elif change == 'consent': request['approved_external_ai'] = False
    elif change == 'unknown-reviewer': (blocked / 'reviewer-intent.json').write_text('{}')
    elif change == 'later-stage': (job / 'prototype-pipeline' / 'import-intent.json').write_text('{}')
    elif change == 'review-changes': (job / 'prototype-result.json').write_text('{"status":"CHANGES_REQUIRED"}')
    elif change == 'tampered-mapper':
        path = blocked / 'mapper.json'
        value = json.loads(path.read_bytes()); value['output_sha256'] = '0' * 64
        path.write_text(json.dumps(value))
    else: (job / RECORD).write_text('{}')
    response = c.post(url(continuation, 'continue-mapping'), json=request)
    assert response.status_code == (404 if change == 'owner' else 409), response.text
    with db() as connection:
        assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'


def test_failed_transaction_preserves_orphan_record_and_never_requeues(continuation):
    c, _, _, rid, job, body, _, _, db, _ = continuation
    projection = c.get(url(continuation)).json()
    with db() as connection:
        connection.execute("CREATE TRIGGER test_fail_continuation BEFORE INSERT ON events WHEN NEW.action='" + EVENT +
                           "' BEGIN SELECT RAISE(ABORT,'Synthetic transaction failure'); END")
    request = {**body, 'checkpoint_sha256': projection['checkpoint_sha256']}
    assert c.post(url(continuation, 'continue-mapping'), json=request).status_code == 409
    assert (job / RECORD).is_file()
    with db() as connection:
        assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    assert c.post(url(continuation, 'continue-mapping'), json=request).status_code == 409


def test_self_contained_legacy_classifier_proves_prefix_terminal_without_new_imports(continuation):
    import builtins, hashlib, inspect, re
    from datetime import datetime
    from fox.verification_recovery import terminal_empty_prototype_mapping, VerificationRecovery
    _, root, _, rid, job, _, _, _, db, _ = continuation
    source = inspect.getsource(terminal_empty_prototype_mapping)
    real_import = builtins.__import__
    def isolated(name, *args, **kwargs):
        assert name in ('math', 'os')
        return real_import(name, *args, **kwargs)
    namespace = {'Path': Path, 'json': json, 'hashlib': hashlib, 're': re, 'datetime': datetime,
                 '__builtins__': {**vars(builtins), '__import__': isolated}}
    exec(compile(source, '<old-container-read-only-classifier>', 'exec'), namespace)
    original = {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    with db() as connection:
        connection.execute('PRAGMA query_only=ON')
        row = dict(connection.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone())
        assert namespace['terminal_empty_prototype_mapping'](root / 'fox.sqlite3', connection, row, claim_owner_failure=True)
        assert VerificationRecovery(root / 'fox.sqlite3', enabled=True)._eligibility(connection, rid) == {
            'blocks_admission': False, 'recovery_state': 'prototype_mapping_owner_resolution_pending', 'retry_eligible': False}
        assert connection.total_changes == 0
    assert original == {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}


def test_worker_never_falls_back_when_record_is_lost_after_queueing(continuation, monkeypatch):
    c, _, _, rid, job, body, model, converter, db, _ = continuation
    proof = c.get(url(continuation)).json()
    request = {**body, 'checkpoint_sha256': proof['checkpoint_sha256']}
    assert c.post(url(continuation, 'continue-mapping'), json=request).status_code == 202
    (job / RECORD).unlink()  # Explicit test-only loss of the durable file.
    calls = deepcopy((model.calls, converter.calls))
    configurations = []
    monkeypatch.setattr(prototype_job, '_configuration', lambda *a, **kw: configurations.append(True))
    worker.process_one(db, job.parent.parent)
    assert configurations == [] and (model.calls, converter.calls) == calls
    with db() as connection:
        assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'
    assert c.get(url(continuation)).status_code == 409


def test_record_loss_after_new_reviewer_stops_before_any_following_model(continuation):
    c, _, _, rid, job, body, model, converter, db, _ = continuation
    proof = c.get(url(continuation)).json()
    assert c.post(url(continuation, 'continue-mapping'), json={**body, 'checkpoint_sha256': proof['checkpoint_sha256']}).status_code == 202
    before = len(model.calls)
    original = model.invoke
    def lose_record(role, request):
        value = original(role, request)
        (job / RECORD).unlink()
        return value
    model.invoke = lose_record
    worker.process_one(db, job.parent.parent)
    assert len(model.calls) == before + 1 and model.calls[-1][0] == 'reviewer'
    assert converter.calls == []
    with db() as connection:
        assert connection.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'ATTENTION'


@pytest.mark.parametrize('change', ['reviewer-intent', 'prefix-review', 'unknown-file', 'unit-ref', 'shape'])
def test_upgrade_classifier_remains_blocking_for_unknown_or_nonresolvable_work(continuation, change):
    from fox.verification_recovery import VerificationRecovery
    _, root, _, rid, job, _, _, _, db, _ = continuation
    with db() as connection:
        assert not VerificationRecovery(root / 'fox.sqlite3', enabled=True)._eligibility(connection, rid)['blocks_admission']
    folders = [path for path in (job / 'prototype-pipeline').iterdir() if path.is_dir() and path.name.startswith('focus-')]
    blocked = next(path for path in folders if not (path / 'reviewer.json').exists())
    if change == 'reviewer-intent': (blocked / 'reviewer-intent.json').write_text('{}')
    elif change == 'prefix-review':
        path = next(path / 'reviewer.json' for path in folders if (path / 'reviewer.json').exists())
        value = json.loads(path.read_bytes()); value['output']['verdict'] = 'CHANGES_REQUIRED'
        value['output_sha256'] = canonical_hash(value['output']); path.write_text(json.dumps(value))
    elif change == 'unknown-file': (job / 'diagnostics.json').write_text('{}')
    else:
        path = blocked / 'mapper.json'; value = json.loads(path.read_bytes())
        if change == 'unit-ref': value['output']['blueprint']['claims'][0]['evidence_refs'] = ['unknown']
        else: value['output']['blueprint']['objects'].pop()
        value['output_sha256'] = canonical_hash(value['output']); path.write_text(json.dumps(value))
    with db() as connection:
        assert VerificationRecovery(root / 'fox.sqlite3', enabled=True)._eligibility(connection, rid)['blocks_admission'] is True


@pytest.mark.parametrize('field,value', [('approved_at', True), ('approved_at', float('inf')),
    ('completed_focuses', False), ('resolved_claim_owners', 0), ('checkpoint_sha256', 'wrong')])
def test_record_scalar_types_are_not_python_equality_shortcuts(continuation, field, value):
    from fox.prototype_mapping_continuation import validate_continuation_record
    c, _, _, _, job, body, _, _, _, _ = continuation
    proof = c.get(url(continuation)).json()
    request = {**body, 'checkpoint_sha256': proof['checkpoint_sha256']}
    assert c.post(url(continuation, 'continue-mapping'), json=request).status_code == 202
    record = json.loads((job / RECORD).read_bytes()); record[field] = value
    raw = (job / 'source-snapshot.json').read_bytes()
    with pytest.raises(OpafError):
        validate_continuation_record(job, json.loads(raw), raw, record)


def test_retry_marker_cannot_adopt_original_event_as_retry_origin(continuation):
    c, _, _, _, job, body, model, converter, _, _ = continuation
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    snapshot.update(retry_of='fox-' + 'a' * 20, mapping_recovery={'schema_version': 1,
        'strategy': 'repartition-32-v1', 'parent_snapshot_sha256': 'b' * 64})
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    before = deepcopy((model.calls, converter.calls))
    assert c.get(url(continuation)).status_code == 409
    assert (model.calls, converter.calls) == before
