"""Fresh worker fail-closed queue tests; all external services are synthetic."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from fox import native_project_pipeline as pipeline
from fox import opaf, worker
from fox import verification_runtime as runtime
from fox.opaf import OpafError
from test_fresh_app_projection import projection
from test_fresh_project_transport import (
    ENV_MISMATCHES, INVALID_PROJECTIONS, change_environment, configure_harness,
    forbidden, fresh_environment, offline_boundary,
)
from test_project_worker_queue import RELEASE, worker_case, worker_row


@pytest.fixture(autouse=True)
def local_verification(monkeypatch):
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', RELEASE)


def assert_rejected_before_claim(case, monkeypatch, *, supplied, value=None):
    before = worker_row(case)
    before_files = {path: path.read_bytes() for path in case.harness.job.rglob('*') if path.is_file()}
    opened = []

    def forbidden_db():
        opened.append(True)
        pytest.fail('Fresh configuration must be validated before opening or claiming the queue.')

    monkeypatch.setattr(pipeline, 'run_native_project_job', forbidden)
    monkeypatch.setattr(opaf, 'run_job', forbidden)
    with pytest.raises(RuntimeError):
        if supplied:
            worker.process_one(forbidden_db, case.root, installation_projection=value)
        else:
            worker.process_one(forbidden_db, case.root)
    assert opened == []
    assert worker_row(case) == before and before['state'] == 'QUEUED'
    assert {path: path.read_bytes() for path in before_files} == before_files
    assert case.harness.actions == [] and case.harness.model_calls == []


@pytest.mark.parametrize('value', INVALID_PROJECTIONS)
def test_invalid_explicit_projection_never_claims_queued_job(worker_case, monkeypatch, value):
    fresh_environment(monkeypatch, projection())
    assert_rejected_before_claim(worker_case, monkeypatch, supplied=True, value=value)


@pytest.mark.parametrize('key,value', ENV_MISMATCHES)
def test_fresh_environment_mismatch_never_claims_queued_job(worker_case, monkeypatch, key, value):
    projected = projection()
    fresh_environment(monkeypatch, projected)
    change_environment(monkeypatch, key, value)
    assert_rejected_before_claim(worker_case, monkeypatch, supplied=True, value=projected)


@pytest.mark.parametrize('mode,extra', [
    ('fresh', None), ('', None), ('unknown', None), ('FRESH', None),
    (None, 'FOX_FRESH_PROJECTION_FILE'), ('legacy', 'FOX_FRESH_UNKNOWN'),
])
def test_omitted_projection_never_downgrades_inherited_fresh_or_invalid_settings(
        worker_case, monkeypatch, mode, extra):
    fresh_environment(monkeypatch, projection())
    change_environment(monkeypatch, 'FOX_INSTALLATION_MODE', mode)
    if extra:
        monkeypatch.setenv(extra, '')
    assert_rejected_before_claim(worker_case, monkeypatch, supplied=False)


@pytest.mark.parametrize('profile', [None, 'native-table-form-v1', 'legacy-html-prototype-v1',
                                    'unknown', {'profile': 'native-project-v1'}])
def test_fresh_claimed_nonproject_snapshot_requires_attention_without_fallback(
        worker_case, monkeypatch, profile):
    harness = worker_case.harness
    configure_harness(harness, monkeypatch, projection())
    snapshot = deepcopy(harness.snapshot)
    snapshot.pop('native_project')  # No retained project marker may be needed.
    if profile is None:
        snapshot.pop('conversion_profile')
    else:
        snapshot['conversion_profile'] = profile
    path = harness.job / 'source-snapshot.json'
    path.write_text(json.dumps(snapshot), encoding='utf-8')
    before = path.read_bytes()
    monkeypatch.setattr(pipeline, 'run_native_project_job', forbidden)
    monkeypatch.setattr(opaf, 'run_job', forbidden)

    worker.process_one(worker_case.db, worker_case.root, installation_projection=projection())

    result = worker_row(worker_case)
    assert result['state'] == 'ATTENTION' and result['artifact'] is None
    assert harness.actions == [] and harness.model_calls == []
    assert path.read_bytes() == before
    assert not (harness.job / 'apex-package.zip').exists()
    assert not (harness.job / 'native-pipeline').exists()
    assert not harness.checkpoints.exists()
    assert runtime.configured_queue(worker_case.root).get(harness.job.name) is None


def test_fresh_worker_forwards_projection_through_complete_real_project_pipeline(worker_case, monkeypatch):
    harness = worker_case.harness
    projected = projection()
    original = deepcopy(projected)
    snapshot_before = (harness.job / 'source-snapshot.json').read_bytes()
    observed = configure_harness(harness, monkeypatch, projected)

    worker.process_one(worker_case.db, worker_case.root, installation_projection=projected)

    result = worker_row(worker_case)
    assert result['state'] == 'QA_REQUIRED', result['message']
    assert result['artifact'] == str((harness.job / 'apex-package.zip').relative_to(worker_case.root))
    assert observed == [(projected['converter_endpoint'], original)]
    assert projected == original
    assert [role for role, _ in harness.model_calls] == ['mapper', 'reviewer'] * 2
    assert harness.actions.count('prepare-schema') == harness.actions.count('import') == 1
    assert (harness.job / 'source-snapshot.json').read_bytes() == snapshot_before
    queued = runtime.configured_queue(worker_case.root).get(harness.job.name)
    assert queued is not None and queued['state'] == 'queued'
    assert queued['source_manifest_sha256'] == harness.snapshot['source_hash']
    evidence = json.loads((harness.job / 'release-evidence.json').read_text())
    assert evidence['conversion_profile'] == 'native-project-v1'
    assert evidence['application_count'] == 1 and evidence['form_count'] == 2
    assert evidence['human_acceptance_recorded'] is False
    with worker_case.db() as db:
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    actions, models = deepcopy(harness.actions), deepcopy(harness.model_calls)
    worker.process_one(worker_case.db, worker_case.root, installation_projection=projected)
    assert harness.actions == actions and harness.model_calls == models
    assert runtime.configured_queue(worker_case.root).get(harness.job.name) == queued


@pytest.mark.parametrize('mode', [None, 'legacy'])
def test_legacy_worker_project_dispatch_omits_new_keyword(worker_case, monkeypatch, mode):
    change_environment(monkeypatch, 'FOX_INSTALLATION_MODE', mode)
    original = pipeline.run_native_project_job
    calls = []

    def old_signature(job):
        calls.append(job)
        return original(job)

    monkeypatch.setattr(pipeline, 'run_native_project_job', old_signature)
    worker.process_one(worker_case.db, worker_case.root)
    assert calls == [worker_case.harness.job]
    assert worker_row(worker_case)['state'] == 'QA_REQUIRED'


def test_legacy_nonproject_dispatch_keeps_old_adapter_call(worker_case, monkeypatch):
    harness = worker_case.harness
    snapshot = deepcopy(harness.snapshot)
    snapshot['conversion_profile'] = 'legacy-html-prototype-v1'
    snapshot.pop('native_project')
    (harness.job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    calls = []

    def old_signature(job):
        calls.append(job)
        raise OpafError('Synthetic adapter stopped; no external execution.')

    monkeypatch.setattr(opaf, 'run_job', old_signature)
    monkeypatch.setattr(pipeline, 'run_native_project_job', forbidden)
    worker.process_one(worker_case.db, worker_case.root)
    assert calls == [harness.job]
    assert worker_row(worker_case)['state'] == 'ATTENTION'
    assert harness.actions == [] and harness.model_calls == []


@pytest.mark.parametrize('mode', [None, 'legacy'])
def test_legacy_external_adapter_dispatch_keeps_existing_arguments(worker_case, monkeypatch, mode):
    harness = worker_case.harness
    change_environment(monkeypatch, 'FOX_INSTALLATION_MODE', mode)
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'synthetic-external-adapter-not-executed')
    snapshot = deepcopy(harness.snapshot)
    snapshot['conversion_profile'] = 'legacy-html-prototype-v1'
    snapshot.pop('native_project')
    (harness.job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    calls = []

    def external_adapter(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(worker.subprocess, 'run', external_adapter)
    monkeypatch.setattr(pipeline, 'run_native_project_job', forbidden)
    monkeypatch.setattr(opaf, 'run_job', forbidden)
    worker.process_one(worker_case.db, worker_case.root)

    assert calls == [((['synthetic-external-adapter-not-executed', str(harness.job)],),
                     {'capture_output': True, 'text': True, 'timeout': 600, 'check': False})]
    assert worker_row(worker_case)['state'] == 'ATTENTION'
    assert harness.actions == [] and harness.model_calls == []
