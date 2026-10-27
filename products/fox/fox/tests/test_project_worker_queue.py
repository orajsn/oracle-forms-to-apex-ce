"""Local project worker/queue integration, not live conversion or acceptance.

The worker uses the real project pipeline with synthetic external transports.
Queue/proof tests use the real generated project-package fixture and retained
technical gate. No positive source, package, plan, hash or proof validator is
replaced. The shared case fixture confines the platform-specific private-file
boundary to a fresh temporary tree; it makes no Windows ACL/POSIX ownership
claim. SQLcl, HTTP, APEX and model execution remain outside this test scope.
"""
from contextlib import closing, contextmanager
from copy import deepcopy
import json
import socket
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from fox import verification_runtime as runtime
from fox import worker
from fox.opaf import canonical_hash
from fox.verification_queue import QueueError, TechnicalProofResult, VerificationBinding
from fox.verification_recovery import RecoveryError, VerificationRecovery
from test_native_project_pipeline import Harness
from test_project_verification_runtime import (actual_release, case as project_case, counts, promote,
                                               put, row, sha)
from test_source_history_store import SCHEMA


RELEASE = 'a' * 64
CONFIG = runtime.VerificationConfig(True, RELEASE)


def forbidden(*args, **kwargs):
    pytest.fail('External network or process execution is forbidden in project worker/queue tests')


@pytest.fixture(autouse=True)
def local_only(monkeypatch):
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', RELEASE)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)


@pytest.fixture
def case(project_case):
    # The converter-layer fixture predates the FOX upload authorization fields.
    # Supply the explicit synthetic approvals that a real app snapshot retains.
    project_case.snapshot['approvals'] = dict.fromkeys(
        ('redacted_source', 'external_ai', 'synthetic_prototype'), True)
    put(project_case.job / 'source-snapshot.json', project_case.snapshot)
    return project_case


@pytest.fixture
def worker_case(tmp_path, monkeypatch):
    root = tmp_path / 'worker-data'
    jobs = root / 'jobs'
    jobs.mkdir(parents=True)
    harness = Harness(jobs, monkeypatch)
    harness.snapshot['project'] = harness.snapshot['project_id']
    put(harness.job / 'source-snapshot.json', harness.snapshot)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.executescript(SCHEMA)
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                   (harness.snapshot['project_id'], 'synthetic-owner', 'Synthetic',
                    harness.snapshot['project_name'], '', 1.0))
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                   (harness.job.name, harness.snapshot['project_id'], harness.snapshot['source_hash'],
                    'QUEUED', 'Synthetic conversion requested', 1.0, 1.0, None))
    runtime.initialize(root, CONFIG)
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')

    @contextmanager
    def connection():
        with closing(sqlite3.connect(root / 'fox.sqlite3')) as db, db:
            db.row_factory = sqlite3.Row
            yield db

    return SimpleNamespace(root=root, harness=harness, db=connection)


def worker_row(context):
    with context.db() as db:
        return dict(db.execute('SELECT * FROM runs WHERE id=?', (context.harness.job.name,)).fetchone())


@pytest.mark.parametrize('environment_profile', [None, 'legacy-html-prototype-v1', 'native-table-form-v1'])
def test_actual_worker_dispatch_uses_frozen_project_profile_and_enqueues(worker_case, monkeypatch,
                                                                      environment_profile):
    if environment_profile is None:
        monkeypatch.delenv('FOX_CONVERSION_PROFILE', raising=False)
    else:
        monkeypatch.setenv('FOX_CONVERSION_PROFILE', environment_profile)
    harness = worker_case.harness
    snapshot_before = (harness.job / 'source-snapshot.json').read_bytes()

    worker.process_one(worker_case.db, worker_case.root)
    result = worker_row(worker_case)
    assert result['state'] == 'QA_REQUIRED', result['message']
    assert result['artifact'] == str((harness.job / 'apex-package.zip').relative_to(worker_case.root))
    assert [role for role, _ in harness.model_calls] == ['mapper', 'reviewer'] * 2
    assert len({request['job_id'] for _, request in harness.model_calls}) == 2
    assert harness.actions.count('prepare-schema') == harness.actions.count('import') == 1
    release = json.loads((harness.job / 'release-evidence.json').read_bytes())
    assert release['conversion_profile'] == 'native-project-v1'
    assert release['application_count'] == 1 and release['form_count'] == 2
    assert release['human_acceptance_recorded'] is False

    queued = runtime.configured_queue(worker_case.root, CONFIG).get(harness.job.name)
    assert queued is not None and queued['state'] == 'queued'
    assert queued['source_manifest_sha256'] == harness.snapshot['source_hash']
    assert queued['package_sha256'] == sha((harness.job / 'apex-package.zip').read_bytes())
    assert queued['verifier_release_sha256'] == RELEASE
    assert not (harness.job / 'native-pipeline').exists()
    assert (harness.job / 'source-snapshot.json').read_bytes() == snapshot_before
    with worker_case.db() as db:
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0

    actions, model_calls = deepcopy(harness.actions), deepcopy(harness.model_calls)
    worker.process_one(worker_case.db, worker_case.root)
    assert harness.actions == actions and harness.model_calls == model_calls
    assert runtime.configured_queue(worker_case.root, CONFIG).get(harness.job.name) == queued


@pytest.mark.parametrize('profile', [None, 'native-table-form-v1', 'legacy-html-prototype-v1',
                                    'unknown-project-profile', {'profile': 'native-project-v1'}])
def test_project_cache_cannot_downgrade_worker_on_missing_or_malformed_profile(worker_case,
                                                                           monkeypatch, profile):
    harness = worker_case.harness
    harness.checkpoints.mkdir()
    put(harness.checkpoints / 'binding.json', {'marker': 'retained project attempt must not downgrade'})
    snapshot = deepcopy(harness.snapshot)
    # The retained cache must remain sufficient to prevent legacy dispatch,
    # even if the snapshot has lost its otherwise redundant project marker.
    snapshot.pop('native_project')
    if profile is None:
        snapshot.pop('conversion_profile')
    else:
        snapshot['conversion_profile'] = profile
    put(harness.job / 'source-snapshot.json', snapshot)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'legacy-html-prototype-v1')
    before = {path: path.read_bytes() for path in harness.job.rglob('*') if path.is_file()}

    worker.process_one(worker_case.db, worker_case.root)

    assert worker_row(worker_case)['state'] == 'ATTENTION'
    assert harness.actions == [] and harness.model_calls == []
    assert not (harness.job / 'apex-package.zip').exists()
    assert not (harness.job / 'native-pipeline').exists()
    assert runtime.configured_queue(worker_case.root, CONFIG).get(harness.job.name) is None
    assert {path: path.read_bytes() for path in before} == before


def test_real_project_package_queue_claim_promotion_and_dispatcher_completion(case):
    runtime.initialize(case.root, CONFIG)
    before = {path: path.read_bytes() for path in case.job.rglob('*') if path.is_file()}
    queued = runtime.enqueue_native(case.root, case.run_id, CONFIG)
    assert queued['state'] == 'queued'
    assert queued['source_manifest_sha256'] == case.snapshot['source_hash']
    assert queued['package_sha256'] == sha(case.built.package)
    assert runtime.enqueue_native(case.root, case.run_id, CONFIG) == queued
    assert row(case)['state'] == 'QA_REQUIRED'
    assert counts(case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}
    assert {path: path.read_bytes() for path in before} == before

    queue = runtime.configured_queue(case.root, CONFIG)
    claim = queue.claim_next()
    assert claim is not None and claim.binding.job_id == case.run_id
    promoted = promote(case)
    completed = queue.complete(claim, TechnicalProofResult(promoted['proof_sha256']))
    assert completed['state'] == 'completed'
    assert completed['proof_sha256'] == promoted['proof_sha256']
    assert row(case)['state'] == 'VERIFIED'
    assert counts(case) == {'proofs': 1, 'technical_events': 1, 'acceptances': 0}
    assert (case.job / 'apex-package.zip').read_bytes() == case.built.package
    assert queue.complete(claim, TechnicalProofResult(promoted['proof_sha256'])) == completed


@pytest.mark.parametrize('mutation', [
    'missing_target', 'malformed_target', 'target_hash', 'resealed_other_target',
    'missing_download', 'download_hash', 'download_extra', 'source_text',
    'plan_hash', 'rendering_spec', 'release_profile', 'missing_profile',
    'native_downgrade', 'legacy_downgrade',
])
def test_project_queue_admission_fails_closed_for_changed_frozen_bindings(case, mutation):
    runtime.initialize(case.root, CONFIG)
    target_path = case.job / 'native-project-pipeline/target-profile.json'
    download_path = case.job / 'native-project-pipeline/download.json'
    snapshot, release = deepcopy(case.snapshot), deepcopy(case.built.evidence)
    target = json.loads(target_path.read_bytes())
    download = json.loads(download_path.read_bytes())
    if mutation == 'missing_target':
        target_path.unlink()
    elif mutation == 'malformed_target':
        target_path.write_bytes(b'{')
    elif mutation == 'target_hash':
        target['target_profile_sha256'] = 'f' * 64
        put(target_path, target)
    elif mutation == 'resealed_other_target':
        target['target_profile']['database']['parsing_schema'] = 'UNRELATED_SYNTHETIC_SCHEMA'
        target['target_profile_sha256'] = canonical_hash(target['target_profile'])
        put(target_path, target)
    elif mutation == 'missing_download':
        download_path.unlink()
    elif mutation == 'download_hash':
        download['package_sha256'] = 'f' * 64
        put(download_path, download)
    elif mutation == 'download_extra':
        put(download_path, {**download, 'profile': 'native-project-v1'})
    elif mutation == 'source_text':
        snapshot['files'][0]['text'] += '\n'
    elif mutation == 'plan_hash':
        snapshot['plan_sha256'] = 'f' * 64
    elif mutation == 'rendering_spec':
        snapshot['native_project']['forms'].pop()
    elif mutation == 'release_profile':
        release['conversion_profile'] = 'native-table-form-v1'
    elif mutation == 'missing_profile':
        snapshot.pop('conversion_profile')
    elif mutation in {'native_downgrade', 'legacy_downgrade'}:
        profile = ('native-table-form-v1' if mutation == 'native_downgrade'
                   else 'legacy-html-prototype-v1')
        snapshot['conversion_profile'] = release['conversion_profile'] = profile
        snapshot.pop('native_project')
        # A plausible fallback download must not hide the retained project
        # cache or let these unchanged project-package bytes take that route.
        put(case.job / 'native-pipeline/download.json', download)
    put(case.job / 'source-snapshot.json', snapshot)
    put(case.job / 'release-evidence.json', release)

    with pytest.raises(runtime.VerificationRuntimeError):
        runtime.enqueue_native(case.root, case.run_id, CONFIG)
    assert runtime.configured_queue(case.root, CONFIG).get(case.run_id) is None
    assert row(case)['state'] == 'QA_REQUIRED'
    assert counts(case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}


@pytest.mark.parametrize('mutation', ['proof_bytes', 'missing_proof', 'receipt_bytes', 'stored_digest'])
def test_invalid_retained_project_proof_never_completes_queue(case, mutation):
    runtime.initialize(case.root, CONFIG)
    runtime.enqueue_native(case.root, case.run_id, CONFIG)
    queue = runtime.configured_queue(case.root, CONFIG)
    claim = queue.claim_next()
    promoted = promote(case)
    if mutation == 'proof_bytes':
        proof = json.loads((case.retained / 'verification.json').read_bytes())
        proof['scope'] = 'fox-native-technical-verification-v2'
        put(case.retained / 'verification.json', proof)
    elif mutation == 'missing_proof':
        (case.retained / 'verification.json').unlink()
    elif mutation == 'receipt_bytes':
        put(case.retained / 'qa-result.json', {'status': 'PASSED'})
    else:
        with sqlite3.connect(case.root / 'fox.sqlite3') as db:
            db.execute('UPDATE technical_verifications SET proof_sha256=? WHERE run=?',
                       ('f' * 64, case.run_id))

    with pytest.raises(QueueError):
        queue.complete(claim, TechnicalProofResult(promoted['proof_sha256']))
    assert queue.get(case.run_id)['state'] == 'attention'
    assert queue.get(case.run_id)['proof_sha256'] is None
    assert row(case)['state'] == 'VERIFIED'
    assert counts(case) == {'proofs': 1, 'technical_events': 1, 'acceptances': 0}


@pytest.mark.parametrize('state', ['QA_REQUIRED', 'VERIFIED', 'ACCEPTED'])
def test_recovery_reader_preserves_real_project_package_and_retained_proof(case, state):
    runtime.initialize(case.root, CONFIG)
    queued = runtime.enqueue_native(case.root, case.run_id, CONFIG)
    binding = VerificationBinding(**{key: queued[key] for key in
        ('job_id', 'source_manifest_sha256', 'package_sha256', 'verifier_release_sha256')})
    if state != 'QA_REQUIRED':
        promote(case)
    if state == 'ACCEPTED':
        # Simulate a previously human-accepted historical state only. Recovery
        # neither creates acceptance nor asks for current source selection.
        with sqlite3.connect(case.root / 'fox.sqlite3') as db:
            db.execute("UPDATE runs SET state='ACCEPTED' WHERE id=?", (case.run_id,))
    recovery = VerificationRecovery(case.root / 'fox.sqlite3', enabled=True)
    before = {path: path.read_bytes() for path in case.job.rglob('*') if path.is_file()}
    with recovery._db() as db:
        checked = recovery._server_run(db, binding, unverified=state == 'QA_REQUIRED')
    assert checked['state'] == state and checked['id'] == case.run_id
    assert {path: path.read_bytes() for path in before} == before
    assert counts(case)['acceptances'] == 0


@pytest.mark.parametrize('mutation', ['target_hash', 'download_hash', 'profile_downgrade', 'proof_bytes'])
def test_recovery_reader_rejects_changed_project_cache_or_retained_proof(case, mutation):
    runtime.initialize(case.root, CONFIG)
    queued = runtime.enqueue_native(case.root, case.run_id, CONFIG)
    binding = VerificationBinding(**{key: queued[key] for key in
        ('job_id', 'source_manifest_sha256', 'package_sha256', 'verifier_release_sha256')})
    if mutation == 'target_hash':
        path = case.job / 'native-project-pipeline/target-profile.json'
        target = json.loads(path.read_bytes())
        target['target_profile_sha256'] = 'f' * 64
        put(path, target)
    elif mutation == 'download_hash':
        put(case.job / 'native-project-pipeline/download.json',
            {'source_hash': case.snapshot['source_hash'], 'package_sha256': 'f' * 64})
    elif mutation == 'profile_downgrade':
        snapshot = deepcopy(case.snapshot)
        snapshot['conversion_profile'] = 'native-table-form-v1'
        put(case.job / 'source-snapshot.json', snapshot)
    else:
        promote(case)
        put(case.retained / 'verification.json', {'scope': 'fox-native-technical-verification-v2'})
    recovery = VerificationRecovery(case.root / 'fox.sqlite3', enabled=True)
    with recovery._db() as db, pytest.raises(RecoveryError):
        recovery._server_run(db, binding, unverified=mutation != 'proof_bytes')
    assert runtime.configured_queue(case.root, CONFIG).get(case.run_id)['state'] == 'queued'
    assert counts(case)['acceptances'] == 0
