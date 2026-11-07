"""Labelled synthetic browser command fixture; never runs Podman or Oracle."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from forms2apex import native_blueprint
from forms2apex import prototype_runtime_bridge as bridge_module
from forms2apex.project_reviews import canonical, digest, read_object
from forms2apex.prototype_gateway import PrototypeGateway
from forms2apex.prototype_runtime_bridge import (
    CLAIM, RECEIPT, REQUEST, RESULT, LocalJobIO, code_sha256, packet_for,
)
from qa.operator import prototype_runtime_worker as worker
from qa.operator.tests.test_prototype_browser import runtime_case


@pytest.fixture
def bridge_case(runtime_case):
    case = runtime_case
    request = case.request
    request.update(schema_version=1, scope="fox-prototype-converter-request-v1", prior_receipts={},
                   source_authority={"schema_version": 1, "scope": "fox-prototype-source-authority-v1",
                       "binding_sha256": "a"*64, "sources_manifest_sha256": "b"*64, "review_index_sha256": "c"*64})
    archive = native_blueprint.deterministic_prototype_zip(request["rendering_spec"])
    request["rendered_zip_sha256"] = hashlib.sha256(archive).hexdigest()
    for stage, result in (("validate", {"passed": True}), ("prepare_schema", {"ready_for_import": True}),
                          ("import", case.args["imported"])):
        receipt = PrototypeGateway._receipt(stage, request, "COMPLETE", **result)
        request["prior_receipts"][stage] = receipt
        (case.root / (stage + ".json")).write_bytes(canonical(receipt))
    imported = request["prior_receipts"]["import"]
    binding = {"schema_version": 1, "job_id": request["job_id"], "project_id": request["project_id"],
               "source_binding": request["source_binding"], "plan_sha256": request["plan_sha256"],
               "rendering_spec_sha256": digest(request["rendering_spec"]), "source_authority": request["source_authority"],
               "draft_zip_sha256": request["rendered_zip_sha256"], "template": native_blueprint.context()}
    for name, value in (("snapshot.json", binding), ("verify_runtime-request.json", request),
                        ("verify_runtime-intent.json", {"request_sha256": digest(request)})):
        (case.root / name).write_bytes(canonical(value))
    (case.root / "candidate-apexlang.zip").write_bytes(archive)
    staging = case.config.jobs_root.parent / "host-jobs"
    staging.mkdir(mode=0o700)
    browser = case.adapter
    browser.config = replace(case.config, jobs_root=staging)
    calls = []
    def synthetic_command(args, **kwargs):
        calls.append((args, kwargs))
        if args[2] == "info":
            return SimpleNamespace(stdout=b"true", stderr=b"", returncode=0)
        if args[2] == "image":
            return SimpleNamespace(stdout=browser.config.image_id.encode(), stderr=b"", returncode=0)
        assert args[2] == "run" and kwargs["timeout"] <= 420
        target = read_object(next(case.config.qa_root.glob("prototype-*/target.json")))
        now = datetime.now(timezone.utc).isoformat()
        report = {**target["binding"], "passed": True, "authenticated": True, "business_pages_tested": True,
                  "business_behavior_accepted": False, "started_at_utc": now, "completed_at_utc": now,
                  "data_retention": "synthetic_test_rows_retained",
                  "retained_rows": [{"source_block_id": block["source_block_id"], "table_name": block["table_name"],
                      "primary_key": str(index+1), "marker": "FPQ-"+"a"*12, "created": True, "updated": True, "deleted": False}
                      for index, block in enumerate(request["rendering_spec"]["blocks"]) if block["native_component"] == "form"],
                  "runner": {"kind": "authenticated_browser", "tool": "playwright", "code_sha256": target["code_sha256"],
                             "image_id": browser.config.image_id},
                  "pages": [{"page_id": page["page_id"], "source_block_id": page["source_block_id"], "passed": True,
                      "authenticated": True, "checks": {key: True for key in page["checks"]}} for page in target["pages"]]}
        (staging / request["job_id"] / "prototype-converter/runtime-evidence/browser-report.json").write_bytes(canonical(report))
        return SimpleNamespace(stdout=b'{"status":"PASSED","business_behavior_accepted":false}', stderr=b"", returncode=0)
    browser.command = synthetic_command
    authority_calls = []
    def authorize(value):
        authority_calls.append(deepcopy(value))
        return deepcopy(request)
    io = LocalJobIO(case.config.jobs_root)
    config = worker.RuntimeWorkerConfig(io, staging, browser, authorize)
    packet = packet_for(request, imported, native_blueprint.prototype_trace(request["rendering_spec"]), binding)
    return SimpleNamespace(config=config, root=case.root, request=request, imported=imported, packet=packet,
                           io=io, staging=staging, calls=calls, authority_calls=authority_calls)


def dispatch(case):
    case.io.create(case.request["job_id"], REQUEST, canonical(case.packet))


def test_actual_callback_and_exact_bytes_roundtrip_with_synthetic_browser(bridge_case):
    case = bridge_case
    dispatch(case)
    assert worker.run_once(case.config, case.request["job_id"])["state"] == "PUBLISHED"
    receipt = read_object(case.root / RECEIPT)
    assert receipt["passed"] is True and receipt["business_behavior_accepted"] is False
    assert all(row["deleted"] is False for row in receipt["retained_rows"])
    assert len(case.calls) == 3 and len(case.authority_calls) >= 5
    for row in receipt["artifacts"]:
        assert (case.root / row["path"]).read_bytes() == (case.staging / case.request["job_id"] / "prototype-converter" / row["path"]).read_bytes()
    assert read_object(case.root / RESULT)["worker_sha256"] == code_sha256(worker.__file__)
    assert not list(case.staging.rglob("*.xml")) and not list(case.staging.rglob("*.zip"))
    assert worker.run_once(case.config, case.request["job_id"])["state"] == "UNKNOWN_NO_REPLAY"
    assert len(case.calls) == 3


def test_crash_after_claim_stays_unknown_without_retry(bridge_case):
    case = bridge_case
    dispatch(case)
    case.config.browser.command = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("SYNTHETIC_CRASH"))
    with pytest.raises(RuntimeError, match="SYNTHETIC_CRASH"):
        worker.run_once(case.config, case.request["job_id"])
    assert (case.root / CLAIM).exists() and not (case.root / RESULT).exists()
    assert worker.run_once(case.config, case.request["job_id"])["state"] == "UNKNOWN_NO_REPLAY"


def test_current_authority_failure_prevents_browser_writes(bridge_case):
    case = bridge_case
    dispatch(case)
    config = replace(case.config, authorize=lambda value: {})
    with pytest.raises(RuntimeError, match="CURRENT_AUTHORITY_CHANGED"):
        worker.run_once(config, case.request["job_id"])
    assert not case.calls and not (case.root / CLAIM).exists()


def test_authority_revoked_at_last_fence_never_runs_browser(bridge_case):
    case = bridge_case
    dispatch(case)
    checks = []
    def authorize(value):
        checks.append(1)
        return deepcopy(case.request) if len(checks) < 6 else {}
    with pytest.raises(RuntimeError, match='CURRENT_AUTHORITY_CHANGED'):
        worker.run_once(replace(case.config, authorize=authorize), case.request['job_id'])
    assert len(case.calls) == 2 and all(args[2] != 'run' for args, _ in case.calls)
    assert (case.root / CLAIM).exists() and not (case.root / RESULT).exists()


def test_browser_launch_uncertainty_is_not_replayed(bridge_case):
    case = bridge_case
    dispatch(case)
    original = case.config.browser.command
    def uncertain(args, **kwargs):
        if args[2] == 'run':
            raise RuntimeError('SYNTHETIC_BROWSER_OUTCOME_UNKNOWN')
        return original(args, **kwargs)
    case.config.browser.command = uncertain
    with pytest.raises(RuntimeError, match='BROWSER_OUTCOME_UNKNOWN'):
        worker.run_once(case.config, case.request['job_id'])
    assert list(case.config.browser.config.qa_root.glob('prototype-*/launch-intent.json'))
    assert worker.run_once(case.config, case.request['job_id'])['state'] == 'UNKNOWN_NO_REPLAY'
    assert not (case.root / RESULT).exists()


def test_worker_does_not_open_credential_contents(bridge_case, monkeypatch):
    case = bridge_case
    dispatch(case)
    original = Path.read_bytes
    def read(path):
        assert path != case.config.browser.config.credentials_file, 'Worker must never open credentials'
        return original(path)
    monkeypatch.setattr(Path, 'read_bytes', read)
    assert worker.run_once(case.config, case.request['job_id'])['state'] == 'PUBLISHED'


@pytest.mark.parametrize("name", ["snapshot.json", "import.json", "candidate-apexlang.zip", "verify_runtime-intent.json"])
def test_stale_retained_context_cannot_launch(bridge_case, name):
    case = bridge_case
    dispatch(case)
    (case.root / name).write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="RETAINED"):
        worker.run_once(case.config, case.request["job_id"])
    assert not case.calls


def test_namespace_adapter_uses_only_fixed_argv_and_bounded_bytes(tmp_path):
    calls = []
    def command(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"1", stderr=b"")
    io = worker.PodmanNamespaceJobIO(tmp_path, python_executable="/trusted/python", command=command)
    assert io.exists("fox-synthetic", REQUEST)
    assert calls[0][0][:4] == ["podman", "--remote=false", "unshare", "/trusted/python"]
    assert calls[0][1]["timeout"] == 30 and "shell" not in calls[0][1]
    with pytest.raises(RuntimeError, match="PATH_INVALID"):
        io.read("fox-synthetic", "../../credentials.json", 100)
    assert len(calls) == 1


def test_cli_requires_explicit_trusted_factory_and_invokes_config(bridge_case, monkeypatch, capsys):
    case = bridge_case
    dispatch(case)
    monkeypatch.setattr(worker.importlib, "import_module", lambda name: SimpleNamespace(configure=lambda: case.config))
    assert worker.main(["run", "--factory", "private_operator:configure", "--job-id", case.request["job_id"]]) == 0
    assert '"state":"PUBLISHED"' in capsys.readouterr().out


def subprocess_configure():
    """Trusted synthetic CLI factory; every IO/command method fails closed.

    Import the production class canonically, just as a real operator factory
    does. This catches python -m accidentally using a second __main__ class.
    """
    from qa.operator.prototype_browser import PrototypeBrowser, PrototypeBrowserConfig
    from qa.operator.prototype_runtime_worker import RuntimeWorkerConfig
    root = Path(os.environ['FOX_TEST_RUNTIME_ROOT'])
    staging = root / 'host-jobs'
    def forbidden(*args, **kwargs):
        raise AssertionError('Synthetic CLI test must never invoke a browser command or credentials')
    browser = PrototypeBrowser(PrototypeBrowserConfig(staging, root / 'qa', 'sha256:'+'f'*64,
        root / 'protected-apex.json', 1001, 1001), command=forbidden, credential_authorizer=forbidden)
    class NoJobIO:
        def read(self, *args):
            raise RuntimeError('SYNTHETIC_CLI_CANONICAL_CONFIG_VALIDATED_NO_JOB_IO')
        create = exists = forbidden
    return RuntimeWorkerConfig(NoJobIO(), staging, browser, forbidden)


def test_real_module_cli_accepts_canonical_factory_config_without_browser_writes(tmp_path):
    (tmp_path / 'jobs').mkdir(mode=0o700)
    (tmp_path / 'host-jobs').mkdir(mode=0o700)
    env = os.environ.copy()
    env['FOX_TEST_RUNTIME_ROOT'] = str(tmp_path)
    completed = subprocess.run([sys.executable, '-m', 'qa.operator.prototype_runtime_worker', 'run',
        '--factory', 'qa.operator.tests.test_prototype_runtime_worker:subprocess_configure',
        '--job-id', 'fox-command-free-cli-test'], cwd=Path(__file__).resolve().parents[3], env=env,
        capture_output=True, timeout=30, check=False)
    assert completed.returncode == 1 and not completed.stdout
    assert b'SYNTHETIC_CLI_CANONICAL_CONFIG_VALIDATED_NO_JOB_IO' in completed.stderr
    assert b'ACTUAL_EXECUTOR_REQUIRED' not in completed.stderr
    assert not list((tmp_path / 'jobs').iterdir())
    assert not list(tmp_path.rglob(CLAIM)) and not list(tmp_path.rglob(RESULT))


def test_worker_requires_actual_browser_not_generic_success_callback(bridge_case):
    with pytest.raises(RuntimeError, match="ACTUAL_EXECUTOR_REQUIRED"):
        worker.run_once(replace(bridge_case.config, browser=lambda *a, **kw: {"passed": True}), bridge_case.request["job_id"])


def test_expired_dispatch_does_not_claim_or_launch(bridge_case):
    case = bridge_case
    now = datetime.now(timezone.utc)
    case.packet['issued_at_utc'] = (now - timedelta(seconds=500)).isoformat()
    case.packet['deadline_at_utc'] = (now - timedelta(seconds=20)).isoformat()
    dispatch(case)
    with pytest.raises(RuntimeError, match='EXPIRED_UNKNOWN_NO_REPLAY'):
        worker.run_once(case.config, case.request['job_id'])
    assert not case.calls and not (case.root / CLAIM).exists()


def test_exact_claim_has_only_one_cross_thread_winner(bridge_case):
    case = bridge_case
    def claim(index):
        try:
            case.io.create(case.request['job_id'], CLAIM, canonical({'synthetic_claim': index}))
            return 'claimed'
        except FileExistsError:
            return 'retained'
    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(claim, (1, 2)))
    assert sorted(outcomes) == ['claimed', 'retained']
    assert not case.calls


def test_single_worker_lock_does_not_start_second_job(bridge_case):
    case = bridge_case
    dispatch(case)
    with worker.single_worker(case.staging):
        with pytest.raises(RuntimeError, match='WORKER_BUSY'):
            worker.run_once(case.config, case.request['job_id'])
    assert not case.calls and not (case.root / CLAIM).exists()


@pytest.mark.parametrize('field', ['producer', 'binding', 'target', 'trace'])
def test_tampered_dispatch_never_reaches_browser(bridge_case, field):
    case = bridge_case
    case.packet[field] = {}
    dispatch(case)
    with pytest.raises(RuntimeError, match='(?:PACKET|TRACE)_CHANGED'):
        worker.run_once(case.config, case.request['job_id'])
    assert not case.calls and not (case.root / CLAIM).exists()


def test_runtime_evidence_never_overwrites_retained_original(bridge_case):
    case = bridge_case
    dispatch(case)
    evidence = case.root / 'runtime-evidence'
    evidence.mkdir()
    sentinel = evidence / 'browser-report.json'
    sentinel.write_bytes(b'SYNTHETIC RETAINED ORIGINAL')
    with pytest.raises(FileExistsError):
        worker.run_once(case.config, case.request['job_id'])
    assert sentinel.read_bytes() == b'SYNTHETIC RETAINED ORIGINAL'
    assert (case.root / CLAIM).exists() and not (case.root / RESULT).exists()


def test_receipt_validation_prevents_publication_after_browser_tamper(bridge_case):
    case = bridge_case
    dispatch(case)
    original = case.config.browser.command
    def changed(args, **kwargs):
        result = original(args, **kwargs)
        if args[2] == 'run':
            report = case.staging / case.request['job_id'] / 'prototype-converter/runtime-evidence/browser-report.json'
            value = read_object(report)
            value['retained_rows'][0]['deleted'] = True
            report.write_bytes(canonical(value))
        return result
    case.config.browser.command = changed
    with pytest.raises(RuntimeError, match='RETENTION_LEDGER_REQUIRED'):
        worker.run_once(case.config, case.request['job_id'])
    assert not (case.root / RESULT).exists() and not (case.root / RECEIPT).exists()


def test_namespace_duplicate_claim_is_not_a_success(tmp_path):
    def command(*args, **kwargs):
        return SimpleNamespace(returncode=17, stdout=b'', stderr=b'')
    io = worker.PodmanNamespaceJobIO(tmp_path, command=command)
    with pytest.raises(FileExistsError):
        io.create('fox-synthetic', CLAIM, b'{}')


def pending_job(root, name):
    context = root / name / 'prototype-converter'
    context.mkdir(parents=True)
    (context / REQUEST).write_bytes(b'{}')
    return context


def test_pending_is_bounded_metadata_only_and_excludes_claimed_or_unknown(tmp_path, monkeypatch):
    io = LocalJobIO(tmp_path)
    expected = ['fox-' + f'{index:020x}' for index in range(1, 5)]
    contexts = [pending_job(tmp_path, name) for name in expected]
    (contexts[1] / CLAIM).write_bytes(b'SYNTHETIC UNKNOWN CLAIM')
    (contexts[2] / RESULT).write_bytes(b'SYNTHETIC AMBIGUOUS RETAINED RESULT')
    (contexts[3] / RECEIPT).write_bytes(b'SYNTHETIC AMBIGUOUS RETAINED RECEIPT')
    for invalid in ('fox-invalid', 'native-123', 'FOX-'+'a'*20, 'fox-'+'a'*19, 'fox-'+'a'*21):
        pending_job(tmp_path, invalid)
    pending_job(tmp_path / 'nested-ignore', 'fox-'+'f'*20)
    def forbidden(*args, **kwargs):
        raise AssertionError('Discovery must not read request contents or recursively scan')
    monkeypatch.setattr(Path, 'read_bytes', forbidden)
    monkeypatch.setattr(Path, 'rglob', forbidden)
    monkeypatch.setattr(Path, 'glob', forbidden)
    assert io.pending(limit=100) == expected[:1]
    assert (contexts[1] / CLAIM).stat().st_size > 0


@pytest.mark.parametrize('limit', [0, -1, 101, True, 1.0])
def test_pending_rejects_invalid_return_limit(tmp_path, limit):
    with pytest.raises(RuntimeError, match='PENDING_LIMIT_INVALID'):
        LocalJobIO(tmp_path).pending(limit=limit)


def test_pending_sorted_return_count_and_hard_scan_bound(tmp_path, monkeypatch):
    for index in (3, 1, 2):
        pending_job(tmp_path, 'fox-'+f'{index:020x}')
    io = LocalJobIO(tmp_path)
    assert io.pending(limit=1) == ['fox-'+f'{1:020x}']
    assert io.pending(limit=2) == ['fox-'+f'{index:020x}' for index in (1, 2)]
    monkeypatch.setattr(bridge_module, 'MAX_PENDING_ENTRIES', 2)
    with pytest.raises(RuntimeError, match='PENDING_SCAN_LIMIT'):
        io.pending(limit=1)


@pytest.mark.parametrize('component', ['job', 'context', 'request', 'claim', 'junction'])
def test_pending_rejects_linked_metadata_without_following(tmp_path, monkeypatch, component):
    name = 'fox-'+'a'*20
    context = pending_job(tmp_path, name)
    target = {'job': context.parent, 'context': context, 'request': context / REQUEST,
              'claim': context / CLAIM, 'junction': context}[component]
    original = Path.lstat
    def linked(path, *args, **kwargs):
        if path == target:
            return SimpleNamespace(st_mode=(stat.S_IFDIR if component == 'junction' else stat.S_IFLNK)|0o700,
                st_file_attributes=getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400) if component == 'junction' else 0)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', linked)
    assert LocalJobIO(tmp_path).pending(limit=1) == []


def test_pending_excludes_hardlinked_requests(tmp_path):
    context = pending_job(tmp_path, 'fox-'+'a'*20)
    os.link(context / REQUEST, tmp_path / 'synthetic-request-hardlink')
    assert LocalJobIO(tmp_path).pending(limit=1) == []


def test_pending_excludes_unclaimed_retained_evidence(tmp_path):
    context = pending_job(tmp_path, 'fox-'+'a'*20)
    (context / 'runtime-evidence').mkdir()
    assert LocalJobIO(tmp_path).pending(limit=1) == []


def test_pending_rejects_linked_root(tmp_path, monkeypatch):
    original = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda path: path == tmp_path or original(path))
    with pytest.raises(RuntimeError, match='LINKED_PATH'):
        LocalJobIO(tmp_path).pending(limit=1)


def test_namespace_pending_uses_fixed_root_without_job_paths(tmp_path):
    jobs = ['fox-'+'a'*20]
    calls = []
    def command(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=canonical({'jobs': jobs}), stderr=b'')
    io = worker.PodmanNamespaceJobIO(tmp_path, command=command)
    assert io.pending(limit=1) == jobs
    argv, kwargs = calls[0]
    assert argv[:3] == ['podman', '--remote=false', 'unshare']
    assert argv[argv.index('--operation')+1] == 'pending'
    assert argv[argv.index('--jobs-root')+1] == str(tmp_path)
    assert '--job-id' not in argv and '--name' not in argv and kwargs['input'] is None
    assert kwargs['timeout'] == 30


@pytest.mark.parametrize('jobs', [['fox-invalid'], ['fox-'+'a'*20]*2, ['../outside'], 'not-a-list'])
def test_namespace_pending_rejects_invalid_or_duplicate_ids(tmp_path, jobs):
    def command(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=canonical({'jobs': jobs}), stderr=b'')
    io = worker.PodmanNamespaceJobIO(tmp_path, command=command)
    with pytest.raises(RuntimeError, match='PENDING_RESPONSE_INVALID'):
        io.pending(limit=2)


def test_namespace_pending_response_has_hard_byte_bound(tmp_path):
    def command(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=b' '*4097, stderr=b'')
    with pytest.raises(RuntimeError, match='NAMESPACE_IO_UNCONFIRMED'):
        worker.PodmanNamespaceJobIO(tmp_path, command=command).pending(limit=1)


def test_pending_cli_only_discovers_and_never_claims_or_runs(bridge_case, monkeypatch, capsys):
    case = bridge_case
    dispatch(case)
    monkeypatch.setattr(worker.importlib, 'import_module', lambda name: SimpleNamespace(configure=lambda: case.config))
    def forbidden(*args, **kwargs):
        raise AssertionError('Pending CLI must not run or claim jobs')
    monkeypatch.setattr(worker, 'run_once', forbidden)
    assert worker.main(['pending', '--factory', 'private_operator:configure', '--limit', '1']) == 0
    assert capsys.readouterr().out.strip() == canonical({'jobs': [case.request['job_id']]}).decode()
    assert not case.calls and not (case.root / CLAIM).exists()
    case.io.create(case.request['job_id'], CLAIM, b'SYNTHETIC UNKNOWN CLAIM')
    assert worker.main(['pending', '--factory', 'private_operator:configure', '--limit', '1']) == 0
    assert capsys.readouterr().out.strip() == '{"jobs":[]}'
