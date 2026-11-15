"""Synthetic host command transport only. No Podman/browser/credential read."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from forms2apex.project_reviews import canonical, digest, read_object
from forms2apex import native_blueprint, native_blueprint_required, blueprint_profiles
from forms2apex.prototype_release import runtime_binding, expected_runtime_pages
from forms2apex.security import alias_for_job
from qa.operator import prototype_browser as module


@pytest.fixture(params=["v1", "required-v1"])
def runtime_case(tmp_path_factory, monkeypatch, request):
    base = tmp_path_factory.mktemp("pb")
    jobs, qa = base / "jobs", base / "qa"
    jobs.mkdir();qa.mkdir()
    job_id = "fox-0123456789abcdefabcd"
    root = jobs / job_id / "prototype-converter"
    root.mkdir(parents=True)
    # This sentinel is never opened by the host adapter or synthetic transport.
    credential = base / "protected-apex.json"
    credential.write_bytes(b"DO NOT READ THIS SYNTHETIC SECRET FIXTURE")
    value = {"schema_version": 1, "profile_id": native_blueprint.PROFILE_ID, "data_mode": "synthetic_test_only",
             "project_id": "synthetic-project:1", "project_name": "Synthetic host transport fixture",
             "source_binding": "a" * 64, "blocks": []}
    for index, classification in enumerate(("database", "database", "control"), start=1):
        source_id = "ff1-" + f"{index:024x}"
        field_id = "ff1-" + f"{1000+index:024x}"
        value["blocks"].append({"source_block_id": source_id, "name": f"BLOCK_{index}", "sequence": index,
            "classification": classification, "native_component": "form" if classification == "database" else "page-items",
            "table_name": native_blueprint._table(value["project_id"], value["source_binding"], source_id)
                          if classification == "database" else None,
            "fields": [{"source_item_id": field_id, "source_name": f"ITEM_{index}",
                        "name": native_blueprint._field_name(field_id), "label": f"Synthetic field {index}",
                        "data_type": "VARCHAR2", "widget": "text", "nullable": True, "length": 120,
                        "in_edit_form": classification == "database"}]})
    if request.param == "required-v1":
        value.update(schema_version=2, profile_id=native_blueprint_required.PROFILE_ID,
                     input_validation_policy=native_blueprint_required.INPUT_VALIDATION_POLICY)
        for block in value["blocks"]:
            for field in block["fields"]:
                field["value_required"] = block["native_component"] == "form"
    if request.param == "count-v1":
        monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[3] / "converter/tests"))
        from test_native_blueprint_count_guard import spec
        value = spec()
        value["blocks"][0]["fields"][0]["value_required"] = True
        # Mirror the source's report-only detail. QA never makes it editable.
        value["blocks"][1]["native_component"] = "report"
        for field in value["blocks"][1]["fields"]:
            field["in_edit_form"] = False
    renderer = blueprint_profiles.select(value)
    request = {"job_id": job_id, "project_id": value["project_id"], "source_binding": value["source_binding"],
               "plan_sha256": "b" * 64, "rendered_zip_sha256": "c" * 64, "rendering_spec": value}
    if value["schema_version"] == 3:
        from forms2apex import count_guard_fixture
        plan = count_guard_fixture.plan(request)
        request["prior_receipts"] = {"prepare_schema": {"status": "COMPLETE", "ready_for_import": True,
            "request_sha256": "e" * 64, "count_guard_fixture": {"plan": plan,
                "plan_sha256": digest(plan), "request_sha256": "e" * 64,
                "fixture_sql_sha256": hashlib.sha256(count_guard_fixture.insert_sql(request).encode()).hexdigest(),
                "prepared": True, "rows": [{"case": row["case"], "primary_key": str(index + 100)}
                                           for index, row in enumerate(plan["cases"])]}}}
    imported = {"imported": True, "application_id": 12345, "application_alias": alias_for_job(job_id),
                "workspace": "FORMS2APEX_POC", "import_intent_sha256": "d" * 64, "compiled_metadata_sha256": "e" * 64}
    authority = {"schema_version": 1, "scope": "fox-prototype-runtime-credentials-target-v1",
                 "workspace": "FORMS2APEX_POC", "db_name": module.DB_NAME, "ords_origin": module.ORIGIN,
                 "credentials_sha256": "a" * 64, "username_sha256": "b" * 64,
                 "authorization_reference_sha256": "c" * 64}
    config = module.PrototypeBrowserConfig(jobs, qa, "sha256:" + "f" * 64, credential, 1001, 1001,
        request_deadline_at_utc=(datetime.now(timezone.utc) + timedelta(seconds=480)).isoformat(),
        execution_deadline_at_utc=(datetime.now(timezone.utc) + timedelta(seconds=420)).isoformat())
    monkeypatch.setattr(module.os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(module.os, "getgid", lambda: 1001, raising=False)
    inspected = []
    def private(path, **kwargs):
        assert Path(path).exists()
        inspected.append((Path(path), kwargs))
        return Path(path)
    monkeypatch.setattr(module, "private", private)
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        if args[2] == "info":
            return SimpleNamespace(stdout=b"true\n", stderr=b"", returncode=0)
        if args[2] == "image":
            return SimpleNamespace(stdout=(config.image_id + "\n").encode(), stderr=b"", returncode=0)
        assert args[2] == "run"
        attempt = next(qa.glob("prototype-*"))
        packet = read_object(attempt / "target.json")
        now = datetime.now(timezone.utc).isoformat()
        report = {**packet["binding"], "passed": True, "authenticated": True, "business_pages_tested": True,
                  "business_behavior_accepted": False, "started_at_utc": now, "completed_at_utc": now,
                  "data_retention": "synthetic_test_rows_retained",
                  "retained_rows": [{"source_block_id": block["source_block_id"], "table_name": block["table_name"],
                     "primary_key": str(index+1), "marker": "FPQ-"+"a"*12, "created": True, "updated": True, "deleted": False}
                     for index, block in enumerate(value["blocks"]) if block["native_component"] == "form"],
                  "runner": {"kind": "authenticated_browser", "tool": "playwright", "code_sha256": packet["code_sha256"],
                             "image_id": config.image_id},
                  "pages": [{"page_id": page["page_id"], "source_block_id": page["source_block_id"], "passed": True,
                             "authenticated": True, "checks": {name: "PASSED" if name == "additional_required_input_validation"
                                 else True for name in page["checks"]}} for page in packet["pages"]]}
        (root / "runtime-evidence/browser-report.json").write_bytes(canonical(report))
        return SimpleNamespace(stdout=b'{"status":"PASSED","business_behavior_accepted":false}', stderr=b"", returncode=0)
    adapter = module.PrototypeBrowser(config, command=command,
        credential_authorizer=lambda req, **kwargs: deepcopy(authority))
    args = {"root": root, "imported": imported, "trace": renderer.prototype_trace(value),
            "artifact_binding": {"job_id": job_id, "draft_zip_sha256": request["rendered_zip_sha256"],
                                 "template": renderer.context()},
            "freshness_check": lambda: None}
    return SimpleNamespace(adapter=adapter, request=request, args=args, config=config, authority=authority,
                           calls=calls, root=root, inspected=inspected)


@pytest.mark.parametrize("runtime_case", ["v1", "required-v1", "count-v1"], indirect=True)
def test_host_adapter_uses_exact_cached_rootless_image_private_mounts_and_retained_rows(runtime_case):
    case = runtime_case
    receipt = case.adapter(case.request, **case.args)
    assert receipt["passed"] is True and receipt["data_retention"] == "synthetic_test_rows_retained"
    assert len(receipt["retained_rows"]) == sum(block["native_component"] == "form"
        for block in case.request["rendering_spec"]["blocks"])
    assert all(row["deleted"] is False for row in receipt["retained_rows"])
    launch = case.calls[-1]
    assert "--pull=never" in launch and "--read-only" in launch and "--cap-drop=all" in launch
    assert "--privileged" not in launch and "--publish" not in launch and "--network=host" not in launch
    credential_mount = next(value for value in launch if ":/inputs/credentials.json:" in value)
    assert credential_mount.endswith(":ro") and ",Z" not in credential_mount
    assert all(value != str(case.config.credentials_file.parent) for value in launch)
    assert any(kwargs.get("secret") is True for _, kwargs in case.inspected)
    assert len(case.calls) == 3
    packet = read_object(next(case.config.qa_root.glob("prototype-*/target.json")))
    if case.request["rendering_spec"]["schema_version"] == 3:
        assert set(packet["runner_files"]) == {"run-count-guard-v1.mjs", "lib/contracts.mjs", "lib/count-guard.mjs"}
        assert packet["runner_files"]["lib/count-guard.mjs"] == module.file_digest(module._ROOT / "lib/count-guard.mjs")
        assert launch[-1] == "/opt/fox-qa/run-count-guard-v1.mjs"
        assert any(":/opt/fox-qa/lib/count-guard.mjs:ro,Z" in arg for arg in launch)
        assert packet["count_guard_fixture"] == case.request["prior_receipts"]["prepare_schema"]["count_guard_fixture"]
        assert packet["binding"]["count_guard_fixture_sha256"] == digest(packet["count_guard_fixture"])
    else:
        assert set(packet["runner_files"]) == {"run-prototype.mjs", "lib/contracts.mjs"}
        assert launch[-1] == "/opt/fox-qa/run-prototype.mjs"
        assert not any(":/opt/fox-qa/lib/count-guard.mjs:" in arg for arg in launch)
    before = list(case.calls)
    recover_args = {key: value for key, value in case.args.items() if key != "freshness_check"}
    assert case.adapter.recover(case.request, **recover_args) == receipt
    assert case.calls == before
    with pytest.raises(RuntimeError, match="ALREADY_EXISTS_NO_REPLAY"):
        case.adapter(case.request, **case.args)


def test_absent_configuration_or_credential_authorizer_is_unavailable(runtime_case):
    case = runtime_case
    for adapter in (module.PrototypeBrowser(), module.PrototypeBrowser(case.config, command=case.adapter.command)):
        with pytest.raises(RuntimeError, match="CONFIGURATION_UNAVAILABLE"):
            adapter(case.request, **case.args)
    assert not case.calls


@pytest.mark.parametrize("key,value", [("workspace", "CLEAN_OTHER"), ("ords_origin", "https://example.test"),
                                      ("scope", "fox-clean-allocation-v2"), ("credentials_sha256", "invalid")])
def test_clean_credentials_wrong_target_or_unbound_identity_never_launches(runtime_case, key, value):
    case = runtime_case
    case.authority[key] = value
    with pytest.raises(RuntimeError, match="ORIGINAL_WORKSPACE_CREDENTIAL_AUTHORITY"):
        case.adapter(case.request, **case.args)
    assert not case.calls


@pytest.mark.parametrize("runtime_case", ["v1", "required-v1", "count-v1"], indirect=True)
def test_image_drift_and_unknown_launch_outcome_are_not_replayed(runtime_case):
    case = runtime_case
    original = case.adapter.command
    def drift(args, **kwargs):
        if args[2] == "image":
            return SimpleNamespace(stdout=("sha256:" + "0"*64).encode())
        return original(args, **kwargs)
    case.adapter.command = drift
    with pytest.raises(RuntimeError, match="MEASURED_IMAGE_CHANGED"):
        case.adapter(case.request, **case.args)
    def uncertain(args, **kwargs):
        if args[2] == "run":
            raise RuntimeError("QA_TIMEOUT_UNCERTAIN_NO_REPLAY")
        return original(args, **kwargs)
    case.adapter.command = uncertain
    with pytest.raises(RuntimeError, match="TIMEOUT_UNCERTAIN"):
        case.adapter(case.request, **case.args)
    with pytest.raises(RuntimeError, match="ALREADY_EXISTS_NO_REPLAY"):
        case.adapter(case.request, **case.args)
    assert not (case.root / "runtime-evidence/browser-report.json").exists()


@pytest.mark.parametrize('prefix', [b'', b'sha256:'])
def test_exact_pinned_image_accepts_only_optional_sha256_prefix(runtime_case, prefix):
    case = runtime_case
    original = case.adapter.command
    inspected = []
    def command(args, **kwargs):
        if args[2] == 'image':
            inspected.append(args)
            return SimpleNamespace(stdout=prefix + case.config.image_id.removeprefix('sha256:').encode() + b'\n',
                                   stderr=b'', returncode=0)
        return original(args, **kwargs)
    case.adapter.command = command
    receipt = case.adapter(case.request, **case.args)
    assert receipt['runner']['image_id'] == case.config.image_id
    assert inspected[0][4] == case.config.image_id
    assert case.config.image_id in case.calls[-1] and case.calls[-1][2] == 'run'


@pytest.mark.parametrize('output', [
    b'', b'f'*63, b'f'*65, b'F'*64, b'0'*64, b'sha256:'+b'0'*64,
    b'sha512:'+b'f'*64, b'sha256:sha256:'+b'f'*64, b'\xff'*64,
    b'f'*64+b'\n'+b'f'*64, b'sha256:'+b'f'*63+b'g',
])
def test_malformed_or_wrong_image_digest_never_launches(runtime_case, output):
    case = runtime_case
    original = case.adapter.command
    def command(args, **kwargs):
        if args[2] == 'image':
            return SimpleNamespace(stdout=output, stderr=b'', returncode=0)
        return original(args, **kwargs)
    case.adapter.command = command
    with pytest.raises(RuntimeError, match='MEASURED_IMAGE_CHANGED'):
        case.adapter(case.request, **case.args)
    assert all(args[2] != 'run' for args in case.calls)
    assert not list(case.config.qa_root.iterdir())


def test_forms_without_labelled_marker_policy_stop_before_browser(runtime_case):
    case = runtime_case
    for block in case.request["rendering_spec"]["blocks"]:
        for field in block["fields"]:
            if field["data_type"] == "VARCHAR2":
                field["length"] = 1
    case.args["trace"] = blueprint_profiles.select(case.request["rendering_spec"]).prototype_trace(case.request["rendering_spec"])
    expected = ("COUNT_GUARD_FIXTURE_LABELLED_KEY_TOO_SHORT" if case.request["rendering_spec"]["schema_version"] == 3
                else "LABELLED_FORM_INPUT_POLICY_UNAVAILABLE")
    with pytest.raises(RuntimeError, match=expected):
        case.adapter(case.request, **case.args)
    assert not case.calls


def test_other_profile_trace_never_launches_or_recovers_browser(runtime_case):
    case = runtime_case
    selected = blueprint_profiles.select(case.request["rendering_spec"])
    other = native_blueprint_required if selected is native_blueprint else native_blueprint
    case.args["trace"] = {**case.args["trace"], "scope": other.PROFILE_ID + "-trace"}
    with pytest.raises(RuntimeError, match="TRACE_CHANGED"):
        case.adapter(case.request, **case.args)
    recover_args = {key: value for key, value in case.args.items() if key != "freshness_check"}
    with pytest.raises(RuntimeError, match="TRACE_CHANGED"):
        case.adapter.recover(case.request, **recover_args)
    assert not case.calls


def test_host_never_opens_credentials_and_recovery_rejects_tampering(runtime_case, monkeypatch):
    case = runtime_case
    original = Path.read_bytes
    def protected(path):
        assert path != case.config.credentials_file, "Host must not read credential contents"
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", protected)
    case.adapter(case.request, **case.args)
    report = case.root / "runtime-evidence/browser-report.json"
    value = read_object(report)
    value["retained_rows"][0]["deleted"] = True
    report.write_bytes(canonical(value))
    recover_args = {key: value for key, value in case.args.items() if key != "freshness_check"}
    with pytest.raises(RuntimeError, match="RETENTION_LEDGER_REQUIRED"):
        case.adapter.recover(case.request, **recover_args)


def test_actual_container_lifetime_is_below_client_observation_budget(runtime_case):
    case = runtime_case
    original = case.adapter.command
    launches = []
    def command(args, **kwargs):
        if args[2] == 'run':
            lifetime = int(args[args.index('--timeout') + 1])
            assert 1 <= lifetime <= 405
            assert int(args[args.index('--stop-timeout') + 1]) == 1
            assert kwargs['timeout'] == lifetime + module.OBSERVATION_MARGIN_SECONDS
            packet = read_object(next(case.config.qa_root.glob('prototype-*/target.json')))
            assert packet['request_deadline_at_utc'] == case.config.request_deadline_at_utc
            assert datetime.fromisoformat(packet['deadline_at_utc']) < datetime.fromisoformat(packet['request_deadline_at_utc'])
            launches.append(lifetime)
        return original(args, **kwargs)
    case.adapter.command = command
    case.adapter(case.request, **case.args)
    assert len(launches) == 1


@pytest.mark.parametrize('deadline', [None, 'bad-date', '2026-01-01T00:00:00', '2026-01-01T00:00:00+00:00'])
@pytest.mark.parametrize("runtime_case", ["v1", "required-v1", "count-v1"], indirect=True)
def test_missing_malformed_or_expired_deadline_never_launches(runtime_case, deadline):
    case = runtime_case
    case.adapter.config = replace(case.config, request_deadline_at_utc=deadline)
    with pytest.raises(RuntimeError, match='(?:DEADLINE|EXPIRED)'):
        case.adapter(case.request, **case.args)
    assert not case.calls and not list(case.config.qa_root.iterdir())


def test_expiry_at_final_fence_never_dispatches_container(runtime_case, monkeypatch):
    case = runtime_case
    original = case.adapter.command
    class Clock:
        instant = datetime.now(timezone.utc)
        @classmethod
        def now(cls, tz=None):
            return cls.instant
        fromisoformat = datetime.fromisoformat
    monkeypatch.setattr(module, 'datetime', Clock)
    def command(args, **kwargs):
        result = original(args, **kwargs)
        if args[2] == 'image':
            Clock.instant += timedelta(seconds=480)
        return result
    case.adapter.command = command
    with pytest.raises(RuntimeError, match='EXPIRED_UNKNOWN_NO_REPLAY'):
        case.adapter(case.request, **case.args)
    assert len(case.calls) == 2 and all(args[2] != 'run' for args in case.calls)


def test_client_timeout_remains_unknown_not_container_termination_proof(runtime_case):
    case = runtime_case
    original = case.adapter.command
    def timeout(args, **kwargs):
        if args[2] == 'run':
            assert '--timeout' in args
            raise subprocess.TimeoutExpired('SYNTHETIC_PODMAN_CLIENT_ONLY', kwargs['timeout'])
        return original(args, **kwargs)
    case.adapter.command = timeout
    with pytest.raises(subprocess.TimeoutExpired):
        case.adapter(case.request, **case.args)
    assert list(case.config.qa_root.glob('prototype-*/launch-intent.json'))
    assert not (case.root / 'runtime-evidence/browser-report.json').exists()
    with pytest.raises(RuntimeError, match='ALREADY_EXISTS_NO_REPLAY'):
        case.adapter(case.request, **case.args)


def test_lifetime_is_recomputed_after_slow_final_authority_check(runtime_case, monkeypatch):
    case = runtime_case
    original = case.adapter.command
    class Clock:
        instant = datetime.now(timezone.utc)
        @classmethod
        def now(cls, tz=None):
            return cls.instant
        fromisoformat = datetime.fromisoformat
    monkeypatch.setattr(module, 'datetime', Clock)
    calls = []
    def fresh():
        calls.append(1)
        if len(calls) == 4:
            Clock.instant += timedelta(seconds=120)
    def command(args, **kwargs):
        if args[2] == 'run':
            lifetime = int(args[args.index('--timeout') + 1])
            assert 280 <= lifetime <= 285
            assert kwargs['timeout'] == lifetime + 15
        return original(args, **kwargs)
    case.adapter.command = command
    case.args['freshness_check'] = fresh
    case.adapter(case.request, **case.args)


@pytest.mark.parametrize("mutation", ["missing", "wrong_prepare", "wrong_plan", "duplicate_id"])
@pytest.mark.parametrize("runtime_case", ["count-v1"], indirect=True)
def test_count_fixture_must_match_original_prepare_before_any_host_command(runtime_case, mutation):
    case = runtime_case
    prepared = case.request["prior_receipts"]["prepare_schema"]
    if mutation == "missing":
        prepared.pop("count_guard_fixture")
    elif mutation == "wrong_prepare":
        prepared["request_sha256"] = "f" * 64
    elif mutation == "wrong_plan":
        prepared["count_guard_fixture"]["plan"]["project_id"] = "other-project"
    else:
        prepared["count_guard_fixture"]["rows"][1]["primary_key"] = prepared["count_guard_fixture"]["rows"][0]["primary_key"]
    with pytest.raises(RuntimeError, match="FIXTURE"):
        case.adapter(case.request, **case.args)
    assert case.calls == [] and not list(case.config.qa_root.iterdir())


@pytest.mark.parametrize("runtime_case", ["count-v1"], indirect=True)
def test_count_recovery_rejects_changed_packet_fixture_without_commands(runtime_case):
    case = runtime_case
    case.adapter(case.request, **case.args)
    target = next(case.config.qa_root.glob("prototype-*/target.json"))
    packet = read_object(target)
    packet["count_guard_fixture"]["rows"][0]["primary_key"] = "999"
    target.write_bytes(canonical(packet))
    before = list(case.calls)
    with pytest.raises(RuntimeError, match="RETAINED_FIXTURE_CHANGED"):
        case.adapter.recover(case.request, **{key: value for key, value in case.args.items() if key != "freshness_check"})
    assert case.calls == before


@pytest.mark.parametrize("runtime_case", ["count-v1"], indirect=True)
def test_count_recovery_binds_exact_physical_helper_bytes(runtime_case):
    case = runtime_case
    case.adapter(case.request, **case.args)
    helper = next(case.config.qa_root.glob("prototype-*/source/lib/count-guard.mjs"))
    helper.write_bytes(helper.read_bytes() + b"\n// synthetic drift\n")
    before = list(case.calls)
    with pytest.raises(RuntimeError, match="RETAINED_SOURCE_CHANGED"):
        case.adapter.recover(case.request, **{key: value for key, value in case.args.items() if key != "freshness_check"})
    assert case.calls == before


@pytest.mark.parametrize("runtime_case", ["count-v1"], indirect=True)
def test_missing_versioned_driver_never_falls_back_to_historical_runner(runtime_case, monkeypatch, tmp_path):
    case = runtime_case
    (tmp_path / "run-prototype.mjs").write_bytes(b"throw Error('legacy fallback forbidden')")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib/contracts.mjs").write_bytes(b"// synthetic contracts")
    monkeypatch.setattr(module, "_ROOT", tmp_path)
    with pytest.raises(RuntimeError, match="Required evidence file is missing or linked"):
        case.adapter(case.request, **case.args)
    assert case.calls == [] and not list(case.config.qa_root.iterdir())
