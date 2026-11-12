"""Authenticated, bounded advisory GETs; authored metadata is never technical proof."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3

import pytest

from test_source_history_api import client, settings, no_external_actions
from test_prototype_project_routes import configured, prepare
from fox.opaf import canonical_hash
from fox.prototype_progress import STAGES


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp('p')


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


@pytest.fixture
def active(client, configured):
    c, root, pid, _, body = prepare(client)
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    rid = response.json()['id']; job = root/'jobs'/rid
    snapshot = json.loads((job/'source-snapshot.json').read_bytes())
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='PROCESSING',message='SYNTHETIC_PROVIDER_TEXT_NOT_FOR_PROGRESS' WHERE id=?", (rid,))
    return c, root, pid, rid, job, snapshot


def metadata(active):
    _, _, pid, rid, job, snapshot = active
    selected = snapshot['prototype']; binding = {
        'schema_version': selected['schema_version'], 'job_id': rid, 'project_id': pid,
        'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256']}
    pipeline = job/'prototype-pipeline'; save(pipeline/'binding.json', binding)
    # Synthetic local progress metadata only, not a reviewed/generated application.
    native = {'source_binding': selected['source_binding'],
              'rendering_spec': {'project_id': pid, 'source_binding': selected['source_binding'], 'blocks': []}}
    native['plan_sha256'] = canonical_hash(native)
    rendered = {'source_binding': selected['source_binding'], 'plan_sha256': native['plan_sha256'], 'zip_sha256': 'd'*64}
    manifest = {'source_binding': selected['source_binding'], 'files': []}
    reviews = {'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256']}
    for name, value in (('native-plan', native), ('rendered', rendered), ('sources-manifest', manifest), ('review-index', reviews)):
        save(pipeline/(name+'.json'), value)
    return {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1', 'job_id': rid,
            'project_id': pid, 'source_binding': selected['source_binding'], 'plan_sha256': native['plan_sha256'],
            'rendering_spec': native['rendering_spec'], 'rendered_zip_sha256': rendered['zip_sha256'],
            'source_authority': {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
                'binding_sha256': canonical_hash(binding), 'sources_manifest_sha256': canonical_hash(manifest),
                'review_index_sha256': canonical_hash(reviews)}, 'prior_receipts': {}}


def stage(active, request, name, *, recorded):
    request = deepcopy(request); pipeline = active[4]/'prototype-pipeline'
    save(pipeline/(name+'-intent.json'), {'request_sha256': canonical_hash(request)})
    if not recorded:
        return request
    value = {'schema_version': 1, 'scope': 'fox-prototype-converter-receipt-v1', 'stage': name,
             'request_sha256': canonical_hash(request), 'source_binding': request['source_binding'],
             'plan_sha256': request['plan_sha256'], 'status': 'COMPLETE', 'business_behavior_accepted': False,
             'validate': True}
    gates = {'validate': {'passed': True}, 'prepare_schema': {'ready_for_import': True},
             'import': {'imported': True, 'application_id': 123},
             'verify_runtime': {'passed': True, 'authenticated': True, 'business_pages_tested': True},
             'export': {'exported': True, 'package_sha256': 'e'*64}}
    value.update(gates[name]); save(pipeline/(name+'.json'), value)
    request['prior_receipts'][name] = value
    return request


def get(active):
    c, _, pid, rid, _, _ = active
    response = c.get(f'/api/projects/{pid}/prototype-runs/{rid}/progress')
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    value = response.json()
    assert type(value['progress_available']) is bool
    assert value['advisory'] is True and value['technically_verified'] is False and value['business_behavior_accepted'] is False
    assert [row['id'] for row in value['stages']] == list(STAGES)
    assert 'SYNTHETIC_PROVIDER_TEXT' not in response.text
    assert 'download' not in response.text and 'source_binding' not in value
    return value


def test_pending_and_recorded_receipts_are_ordered_advisory_only(active):
    request = metadata(active)
    request = stage(active, request, 'validate', recorded=True)
    stage(active, request, 'prepare_schema', recorded=False)
    value = get(active)
    assert value['progress_available'] is True
    assert [row['status'] for row in value['stages']] == ['recorded', 'recorded', 'working', 'not_observed', 'not_observed', 'not_observed']
    assert value['current_stage'] == 'prepare_schema'


def test_processing_gap_ignores_stale_historical_rejection(active):
    stage(active, metadata(active), 'validate', recorded=True)
    save(active[4]/'prototype-result.json', {'status': 'CHANGES_REQUIRED', 'reason': 'SYNTHETIC_PROVIDER_TEXT_STALE'})
    value = get(active)
    assert value['progress_available'] is True
    assert value['state'] == 'PROCESSING' and value['current_stage'] is None
    assert [row['status'] for row in value['stages']][:3] == ['recorded', 'recorded', 'not_observed']
    assert value['message'] == 'Checking saved work / waiting for next recorded step.'


@pytest.mark.parametrize('state,expected', [('QUEUED', 'not_observed'), ('ATTENTION', 'attention')])
def test_pending_marker_is_not_active_while_queued_and_attention_needs_current_state(active, state, expected):
    stage(active, metadata(active), 'validate', recorded=False)
    with sqlite3.connect(active[1]/'fox.sqlite3') as db:
        db.execute('UPDATE runs SET state=? WHERE id=?', (state, active[3]))
    value = get(active)
    assert value['progress_available'] is True
    assert value['stages'][1]['status'] == expected
    assert value['current_stage'] == ('validate' if state == 'ATTENTION' else None)


def test_bound_initial_model_intent_reports_mapping_request_not_execution_proof(active):
    metadata(active)
    pipeline = active[4]/'prototype-pipeline'; (pipeline/'native-plan.json').unlink()
    save(pipeline/('focus-'+'a'*24)/'mapper-intent.json', {'job_id': active[3],
        'source_hash': active[5]['prototype']['source_binding'], 'request_sha256': 'a'*64})
    value = get(active)
    assert value['progress_available'] is True
    assert value['current_stage'] == 'mapping' and value['stages'][0]['status'] == 'working'


@pytest.mark.parametrize('fault', ['binding-project', 'snapshot-source', 'receipt-source', 'intent', 'out-of-order', 'gate', 'duplicate', 'oversized', 'hardlink'])
def test_invalid_metadata_is_static_unknown_with_no_stage_proof(active, fault):
    request = metadata(active); stage(active, request, 'validate', recorded=True)
    pipeline = active[4]/'prototype-pipeline'
    if fault == 'snapshot-source':
        value = deepcopy(active[5]); value['source_hash'] = 'f'*64; save(active[4]/'source-snapshot.json', value)
    elif fault == 'binding-project':
        path = pipeline/'binding.json'; value = json.loads(path.read_bytes()); value['project_id'] = 'other'; save(path, value)
    elif fault == 'receipt-source':
        path = pipeline/'validate.json'; value = json.loads(path.read_bytes()); value['source_binding'] = 'f'*64; save(path, value)
    elif fault == 'intent':save(pipeline/'validate-intent.json', {'request_sha256': 'f'*64})
    elif fault == 'out-of-order':
        (pipeline/'validate.json').unlink(); stage(active, request, 'prepare_schema', recorded=True)
    elif fault == 'gate':
        path = pipeline/'validate.json'; value = json.loads(path.read_bytes()); value['passed'] = False; save(path, value)
    elif fault == 'duplicate':(pipeline/'binding.json').write_bytes(b'{"job_id":"one","job_id":"two"}')
    elif fault == 'oversized':(pipeline/'binding.json').write_bytes(b' '*65_537)
    else:os.link(pipeline/'binding.json', pipeline/'hardlinked-copy.json')
    value = get(active)
    assert value['progress_available'] is False
    assert value['current_stage'] is None and all(row['status'] == 'not_observed' for row in value['stages'])
    assert value['message'] == 'Progress is not currently available. Saved work is unchanged.'


def test_linked_metadata_is_never_followed(active):
    metadata(active); path = active[4]/'prototype-pipeline/binding.json'; original = path.with_name('original.json'); path.rename(original)
    try:path.symlink_to(original)
    except OSError:pytest.skip('Actual symlink creation unavailable without privilege changes')
    value = get(active)
    assert value['progress_available'] is False and all(row['status'] == 'not_observed' for row in value['stages'])


def test_actual_windows_junction_is_rejected_without_privilege_changes():
    from fox.prototype_progress import _Metadata
    location = os.environ.get('PROGRESS_JUNCTION_FIXTURE', '')
    if os.name != 'nt' or not location:
        pytest.skip('Optional existing Windows junction fixture not supplied')
    path = Path(location)
    assert path.lstat().st_file_attributes & 0x400
    with pytest.raises(ValueError):
        _Metadata().read(path/'metadata.json')


def test_owner_cross_project_missing_and_legacy_boundaries_precede_job_reads(active, monkeypatch):
    c, root, pid, rid, job, snapshot = active
    assert c.get(f'/api/projects/{pid}/prototype-runs/../../else/progress').status_code == 404
    assert c.get(f'/api/projects/{pid}/prototype-runs/fox-{"f"*20}/progress').status_code == 404
    other = c.post('/api/projects', json={'customer': 'Synthetic', 'name': 'Other'}).json()['id']
    assert c.get(f'/api/projects/{other}/prototype-runs/{rid}/progress').status_code == 404
    with sqlite3.connect(root/'fox.sqlite3') as db:db.execute('UPDATE projects SET owner=? WHERE id=?', ('other-owner', pid))
    monkeypatch.setattr('fox.prototype_progress.prototype_progress', lambda *a:pytest.fail('owner check bypassed'))
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/progress').status_code == 404
    c.cookies.clear(); assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/progress').status_code == 401


def test_legacy_snapshot_uses_existing_not_found_response(active):
    snapshot = deepcopy(active[5]); snapshot['conversion_profile'] = 'legacy-html-prototype-v1'; save(active[4]/'source-snapshot.json', snapshot)
    assert active[0].get(f'/api/projects/{active[2]}/prototype-runs/{active[3]}/progress').status_code == 404


def test_repeated_get_is_local_no_post_no_writes_or_acceptance(active, monkeypatch):
    stage(active, metadata(active), 'validate', recorded=False)
    for name in ('fox.prototype_job.validate_prototype_snapshot', 'fox.prototype_job.load_prototype_profile',
                 'fox.prototype_pipeline.authorize_prototype_request', 'fox.prototype_authority.authorize_current'):
        monkeypatch.setattr(name, lambda *a, **kw:pytest.fail('expensive authority/configuration called'))
    before = {path.relative_to(active[4]): path.read_bytes() for path in active[4].rglob('*') if path.is_file()}
    with sqlite3.connect(active[1]/'fox.sqlite3') as db:rows = list(db.iterdump())
    for _ in range(3):assert get(active)['stages'][1]['status'] == 'working'
    assert before == {path.relative_to(active[4]): path.read_bytes() for path in active[4].rglob('*') if path.is_file()}
    with sqlite3.connect(active[1]/'fox.sqlite3') as db:
        assert list(db.iterdump()) == rows
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    assert active[0].post(f'/api/projects/{active[2]}/prototype-runs/{active[3]}/progress').status_code == 405


def test_all_matching_local_receipts_do_not_grant_output_authority(active):
    request = metadata(active)
    for name in STAGES[1:]:request = stage(active, request, name, recorded=True)
    value = get(active)
    assert value['progress_available'] is True
    assert [row['status'] for row in value['stages']] == ['recorded']*6
    assert value['current_stage'] is None


def test_available_waiting_metadata_is_distinct_from_unavailable_observation(active):
    value = get(active)
    assert value['progress_available'] is True and value['current_stage'] is None
    assert all(row['status'] == 'not_observed' for row in value['stages'])
    assert value['message'] == 'Checking saved work / waiting for next recorded step.'
