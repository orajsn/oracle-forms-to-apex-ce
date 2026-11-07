"""Authenticated synthetic API guards; package/Oracle execution is not claimed."""
from copy import deepcopy
import json
import sqlite3

import pytest

from test_source_history_api import client, settings, no_external_actions, upload
from test_prototype_project_routes import configured, prepare
from test_prototype_pipeline import SyntheticOpaf, SyntheticConverter, PROFILE, TARGET
from fox.opaf import ConverterClient, canonical_hash


@pytest.fixture
def generated(client, configured, monkeypatch):
    from fox.prototype_pipeline import run_prototype_pipeline
    from fox.prototype_download import retained_export_request
    c, root, pid, _, body = prepare(client)
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202
    rid = response.json()['id']; job = root / 'jobs' / rid
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    # Real source/reviewer artifacts, synthetic external invocations/stages only.
    class CompleteSyntheticConverter(SyntheticConverter):
        def run_stage(self, stage, request):
            receipt = super().run_stage(stage, request)
            receipt.update(status='COMPLETE', business_behavior_accepted=False)
            return receipt
    from fox.prototype_project_routes import source_documents
    selected = snapshot['prototype']
    result = run_prototype_pipeline(job, source_documents(snapshot['files']),
        project_id=pid, project_name=snapshot['project_name'],
        expected_source_binding=selected['source_binding'], approved_chunk_hashes=selected['approved_chunk_hashes'],
        approved_policy_id=selected['approved_policy_id'], opaf_client=SyntheticOpaf(),
        profile=deepcopy(PROFILE), target_profile_loader=lambda: deepcopy(TARGET),
        processing_approval_check=lambda _: True, converter_adapter=CompleteSyntheticConverter(), focus_schema_version=selected['schema_version'])
    assert result['status'] == 'APEX_GENERATED'
    (job / 'prototype-result.json').write_text(json.dumps(result), encoding='utf-8')
    # The API configuration fixture uses a synthetic approved target hash. Bind
    # its complete metadata consistently for the real retained-authority check.
    digest = canonical_hash(TARGET)
    snapshot['prototype']['target_profile_sha256'] = digest
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    monkeypatch.setattr('fox.prototype_job.load_prototype_profile',
                        lambda _: {'target_profile_sha256': digest, 'target_profile': deepcopy(TARGET)})
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='GENERATED' WHERE id=?", (rid,))
    calls = []
    client = ConverterClient('http://127.0.0.1:8091', 'SYNTHETIC-TEST-ONLY')
    monkeypatch.setattr('fox.prototype_download.configured_download_client',
                        lambda *args, **kwargs: calls.append(('configuration', args, kwargs)) or client)
    # Isolate route/authority checks: exact-package validation is covered by the
    # converter export fixture tests, not represented by these synthetic bytes.
    def read(adapter, request, receipt):
        calls.append(('package', deepcopy(request)))
        return b'SYNTHETIC-ROUTE-BYTES-NOT-AN-APEX-PACKAGE'
    monkeypatch.setattr('fox.prototype_transport.PrototypeHttpConverterAdapter.read_package', read)
    return c, root, pid, rid, job, snapshot, calls, retained_export_request


def test_generated_route_repeated_get_preserves_nonaccepted_state(generated):
    c, root, pid, rid, job, _, calls, _ = generated
    before = {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    for _ in range(2):
        result = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/download')
        assert result.status_code == 200, result.text
        assert 'generated-prototype.zip' in result.headers['content-disposition']
        assert result.headers['x-fox-output-scope'] == 'generated-synthetic-prototype-not-business-accepted'
    assert [row[0] for row in calls] == ['configuration', 'package'] * 2
    assert {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()} == before
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state,artifact FROM runs WHERE id=?', (rid,)).fetchone() == ('GENERATED', None)
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    assert c.get(f'/api/projects/{pid}/runs/{rid}/download').status_code != 200


def test_generated_output_is_local_source_bound_and_never_invokes_transport(generated):
    c, root, pid, rid, job, snapshot, calls, _ = generated
    before = {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/output')
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    assert response.json() == {
        'schema_version': 1, 'scope': 'fox-generated-prototype-output-v1',
        'project_id': pid, 'run_id': rid, 'source_hash': snapshot['source_hash'],
        'selected_source_set_id': snapshot['selected_source_set_id'],
        'source_binding': snapshot['prototype']['source_binding'], 'status': 'APEX_GENERATED',
        'download_path': f'/api/projects/{pid}/prototype-runs/{rid}/download',
        'business_behavior_accepted': False, 'clean_schema_install_passed': False,
        'package_reimport_passed': False,
    }
    assert calls == []
    assert {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('route', ['download', 'output'])
@pytest.mark.parametrize('change', ['owner', 'source', 'snapshot_consent', 'stage', 'result', 'runtime_missing', 'target'])
def test_stale_unapproved_or_uncertain_proof_blocks_before_transport(generated, change, route, monkeypatch):
    c, root, pid, rid, job, snapshot, calls, _ = generated
    if change == 'owner':
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('UPDATE projects SET owner=? WHERE id=?', ('other-owner', pid))
    elif change == 'source':
        upload(c, pid, [('changed.xml', b'<FormModule Name="CHANGED"/>')])
    elif change == 'snapshot_consent':
        snapshot['approvals']['synthetic_prototype'] = False
        (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    elif change == 'stage':
        path = job / 'prototype-pipeline/export.json'
        receipt = json.loads(path.read_bytes()); receipt['status'] = 'UNKNOWN'
        path.write_text(json.dumps(receipt), encoding='utf-8')
    elif change == 'result':
        (job / 'prototype-result.json').write_text('{}', encoding='utf-8')
    elif change == 'runtime_missing':
        (job / 'prototype-pipeline/verify_runtime.json').unlink()
    else:
        monkeypatch.setattr('fox.prototype_job.load_prototype_profile', lambda _: {'target_profile_sha256': 'b' * 64})
    result = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/{route}')
    assert result.status_code in (404, 409), result.text
    assert calls == []


def test_authentication_required_before_any_prototype_download(generated):
    c, _, pid, rid, _, _, calls, _ = generated
    c.cookies.clear()
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/download').status_code == 401
    assert calls == []


def test_source_change_during_remote_read_blocks_response(generated, monkeypatch):
    c, root, pid, rid, _, _, calls, _ = generated
    def changed(*args):
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('UPDATE projects SET owner=? WHERE id=?', ('other-owner', pid))
        return b'SYNTHETIC'
    monkeypatch.setattr('fox.prototype_transport.PrototypeHttpConverterAdapter.read_package', changed)
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/download').status_code == 404
