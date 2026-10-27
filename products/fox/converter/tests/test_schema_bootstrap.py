"""Local registry/OS-lock tests with a synthetic database adapter only."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from forms2apex import schema_bootstrap as bootstrap
from forms2apex import schema_probe as probe
from forms2apex.native_contract import validate_native_spec
from forms2apex.native_schema import render_native_schema
from forms2apex.target_profile import _JSN_PROFILE


def form(table="FOX_NATIVE_ALPHA", label="Description"):
    return validate_native_spec({
        "profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
        "table_name": table, "columns": [
            {"name": "ROW_KEY", "data_type": "NUMBER", "nullable": False,
             "label": "Row key", "primary_key": True, "identity": True},
            {"name": "DESCRIPTION", "data_type": "VARCHAR2", "length": 100,
             "nullable": False, "label": label}]})


def bound(job="schema_job_1", source="a"):
    return {"job_id": job, "source_manifest_sha256": source * 64,
            "artifact_binding_sha256": "b" * 64, "review_receipts_sha256": "c" * 64,
            "validated_draft_sha256": "d" * 64}


def capabilities(ready=True):
    return {"create_table": ready, "create_sequence": ready, "unlimited_tablespace": False,
            "default_tablespace": "DATA", "quota_record_present": True, "quota_used_bytes": 0,
            "quota_max_bytes": 20_000_000, "quota_available": True, "creation_ready": ready,
            "allocation_guaranteed": False}


class Gate:
    def __init__(self):
        self.calls = []
        self.fail = None

    def __call__(self, operation, request):
        self.calls.append((operation, deepcopy(request)))
        if operation == self.fail:
            raise RuntimeError("not exposed private provider detail")
        return deepcopy(request)


class Database:
    def __init__(self):
        self.objects = {}
        self.rows = {}
        self.capability = capabilities()
        self.reads = []
        self.ddl = []
        self.next_id = 9009446931169100
        self.before_failure = False
        self.after_failure = False
        self.post_failure = False
        self.replace_after_create = False
        self.race = False

    def observation(self, settings, spec):
        value = {"schema_version": 1, "scope": "fox-native-schema-observation-v1",
                 "target": probe.target(settings), "table_name": spec["table_name"],
                 "schema_sha256": probe.schema_sha256(spec), "capabilities": deepcopy(self.capability),
                 "data_rows_read": False, "business_behavior_verified": False,
                 "state": "ABSENT", "object_identity": None, "metadata_sha256": None}
        if spec["table_name"] in self.objects:
            value.update(deepcopy(self.objects[spec["table_name"]]))
        return value

    def observe(self, settings, spec, root):
        self.reads.append(spec["table_name"])
        if self.post_failure and self.ddl:
            raise RuntimeError("not exposed private database message")
        return self.observation(settings, spec)

    def add(self, spec):
        self.next_id += 1
        value = {"state": "EXACT", "schema_sha256": probe.schema_sha256(spec),
                 "object_identity": {"object_id": str(self.next_id),
                                     "created": "2026-10-25T01:00:00",
                                     "last_ddl_time": "2026-10-25T01:00:00"},
                 "metadata_sha256": sha256(("metadata:" + probe.schema_sha256(spec)).encode()).hexdigest()}
        self.objects[spec["table_name"]] = value
        self.rows.setdefault(spec["table_name"], ["synthetic retained row"])
        return deepcopy(value)

    def create(self, settings, spec, root, token, before_dispatch):
        if self.before_failure:
            raise OSError("private SQLcl path must not escape")
        before_dispatch()
        self.ddl.append((spec["table_name"], token))
        if self.race:
            self.add(spec)
            raise RuntimeError("simulated collision")
        assert spec["table_name"] not in self.objects
        value = self.add(spec)
        if self.after_failure:
            raise RuntimeError("simulated lost create response")
        if self.replace_after_create:
            self.add(spec)
        return {"schema_version": 1, "scope": "fox-native-schema-create-observation-v1",
                "target": probe.target(settings), "table_name": spec["table_name"],
                "schema_sha256": probe.schema_sha256(spec), "intent_token": token,
                "object_identity": value["object_identity"],
                "ddl_sha256": sha256(render_native_schema(spec).encode()).hexdigest(),
                "created_in_this_sqlcl_execution": True, "metadata_verification_still_required": True}


@pytest.fixture
def setup(tmp_path_factory):
    # Short explicit fixture prefix preserves unchanged Windows path guards.
    base = tmp_path_factory.mktemp("s")
    jobs = base / "jobs"
    jobs.mkdir()
    profile = deepcopy(_JSN_PROFILE)
    profile_path = base / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    sqlcl = base / "never-execute.exe"
    sqlcl.write_bytes(b"synthetic unused executable fixture")
    settings = SimpleNamespace(
        jobs_root=jobs, target_profile_path=profile_path, sqlcl_path=sqlcl,
        sqlcl_connection_name="F2A_APEX", apex_workspace="FORMS2APEX_POC",
        apex_parsing_schema="FORMS2APEX_POC",
        apex_base_url=profile["apex"]["ords_origin"] + "/ords",
        generator_model=profile["opaf"]["roles"]["mapper"]["model"],
        reviewer_model=profile["opaf"]["roles"]["reviewer"]["model"],
        opaf_mapper_workflow_id=profile["opaf"]["roles"]["mapper"]["workflow_id"],
        opaf_reviewer_workflow_id=profile["opaf"]["roles"]["reviewer"]["workflow_id"])
    root = jobs / "schema_job_1"
    root.mkdir()
    return settings, root, Gate(), Database()


def prepare(setup, specs=None, binding=None, mappings=None):
    settings, root, gate, db = setup
    return bootstrap.prepare_schemas(settings, specs or [form()], root,
                                     binding=binding or bound(root.name), authorize=gate, executor=db,
                                     mapping_identities=mappings)


def reconcile(setup, specs=None, binding=None, mappings=None):
    settings, root, gate, db = setup
    return bootstrap.reconcile_schemas(settings, specs or [form()], root,
                                       binding=binding or bound(root.name), authorize=gate, executor=db,
                                       mapping_identities=mappings)


def files(root):
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def test_new_schema_creates_once_then_reuses_exact_unchanged_receipt(setup):
    first = prepare(setup)
    settings, root, gate, db = setup
    assert first["state"] == "READY" and first["database_writes_this_call"] == 1
    assert first["tables"][0]["state"] == "CREATED"
    assert first["tables"][0]["object_identity"]["object_id"] == "9009446931169101"
    assert first["apex_import_performed_by_operation"] is first["human_acceptance_recorded"] is False
    before = files(settings.jobs_root)
    second = prepare(setup)
    assert second["receipt_sha256"] == first["receipt_sha256"]
    assert second["database_writes_this_call"] == 0
    assert len(db.ddl) == 1 and files(settings.jobs_root) == before
    assert {call[0] for call in gate.calls} >= {"prepare", "create", "continue", "complete"}


def test_multi_table_project_and_shared_schema_are_deterministic(setup):
    specs = [form("FOX_NATIVE_BETA"), form("FOX_NATIVE_ALPHA"),
             form("FOX_NATIVE_ALPHA", "Different display label")]
    result = prepare(setup, specs)
    assert [item["table_name"] for item in result["tables"]] == ["FOX_NATIVE_ALPHA", "FOX_NATIVE_BETA"]
    assert len(setup[3].ddl) == 2
    assert prepare(setup, list(reversed(specs)))["receipt_sha256"] == result["receipt_sha256"]


def test_new_job_reuses_registered_physical_table_without_reading_or_altering_rows(setup):
    prepare(setup)
    settings, _, gate, db = setup
    root = settings.jobs_root / "schema_job_2"
    root.mkdir()
    rows = deepcopy(db.rows)
    result = prepare((settings, root, gate, db), [form(label="New UI label")])
    assert result["tables"][0]["state"] == "REUSED"
    assert result["database_writes_this_call"] == 0
    assert db.rows == rows and len(db.ddl) == 1


def test_conflicting_shared_specs_block_before_any_target_observation(setup):
    changed = form()
    changed["columns"][1]["length"] = 101
    with pytest.raises(bootstrap.SchemaPreparationError, match="SHARED_TABLE_CONFLICT"):
        prepare(setup, [form(), changed])
    assert setup[3].reads == setup[3].ddl == []
    assert setup[2].calls == []


@pytest.mark.parametrize("change", [
    lambda s: s.update(table_name="OTHER_TABLE"),
    lambda s: s.update(table_name="FOX_NATIVE_X; DROP TABLE X"),
    lambda s: s.update(unknown="SELECT password FROM credentials"),
    lambda s: s["columns"][0].update(identity=False),
    lambda s: s["columns"][1].update(data_type="CLOB"),
    lambda s: s["columns"][1].update(nullable="false"),
])
def test_invalid_spec_never_authorizes_or_executes(setup, change):
    spec = form()
    change(spec)
    with pytest.raises(bootstrap.SchemaPreparationError, match="NATIVE_SPEC_INVALID"):
        prepare(setup, [spec])
    assert setup[2].calls == setup[3].reads == setup[3].ddl == []


@pytest.mark.parametrize("key", sorted(bootstrap._BINDING_KEYS))
def test_missing_bound_source_review_or_validation_field_blocks(setup, key):
    value = bound()
    del value[key]
    with pytest.raises(bootstrap.SchemaPreparationError, match="SOURCE_BINDING"):
        prepare(setup, binding=value)
    assert not setup[3].ddl


@pytest.mark.parametrize("operation", ["prepare", "create"])
def test_source_review_validation_or_preflight_gate_failure_never_creates(setup, operation):
    setup[2].fail = operation
    with pytest.raises(bootstrap.SchemaPreparationError):
        prepare(setup)
    assert not setup[3].ddl
    assert not list(setup[0].jobs_root.rglob("*.intent.json"))


@pytest.mark.parametrize("gate", [None, lambda operation, request: True,
                                 lambda operation, request: {"passed": True},
                                 lambda operation, request: {**request, "schema_plan_sha256": "0" * 64}])
def test_no_boolean_or_changed_request_can_authorize_create(setup, gate):
    settings, root, _, db = setup
    with pytest.raises(bootstrap.SchemaPreparationError):
        bootstrap.prepare_schemas(settings, [form()], root, binding=bound(), authorize=gate, executor=db)
    assert not db.ddl


def test_all_target_tables_are_checked_before_first_create(setup):
    settings, _, _, db = setup
    db.add(form("FOX_NATIVE_BETA"))
    with pytest.raises(bootstrap.SchemaPreparationError, match="EXISTING_TABLE_NOT_MANAGED") as error:
        prepare(setup, [form("FOX_NATIVE_ALPHA"), form("FOX_NATIVE_BETA")])
    assert error.value.table_name == "FOX_NATIVE_BETA"
    assert not db.ddl
    assert "FOX_NATIVE_ALPHA" not in db.objects


def test_missing_creation_privileges_block_but_do_not_prevent_later_registered_reuse(setup):
    setup[3].capability = capabilities(False)
    with pytest.raises(bootstrap.SchemaPreparationError, match="PREREQUISITES_MISSING"):
        prepare(setup)
    assert not setup[3].ddl
    setup[3].capability = capabilities()
    prepare(setup)
    setup[3].capability = capabilities(False)
    assert prepare(setup)["database_writes_this_call"] == 0


def test_provider_failure_before_dispatch_leaves_no_create_intent(setup):
    setup[3].before_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError, match="CREATE_NOT_STARTED") as error:
        prepare(setup)
    assert "private" not in str(error.value)
    assert not list(setup[0].jobs_root.rglob("*.intent.json"))
    assert not setup[3].ddl


@pytest.mark.parametrize("race", [False, True])
def test_unknown_create_response_is_never_replayed_or_adopted(setup, race):
    settings, _, _, db = setup
    db.after_failure = not race
    db.race = race
    with pytest.raises(bootstrap.SchemaPreparationError, match="CREATE_OUTCOME_UNCONFIRMED"):
        prepare(setup)
    before = files(settings.jobs_root)
    result = reconcile(setup)
    assert result["ready_for_import"] is False
    assert result["tables"][0]["state"] == "CREATE_OUTCOME_UNCONFIRMED"
    assert files(settings.jobs_root) == before and len(db.ddl) == 1
    db.after_failure = db.race = False
    with pytest.raises(bootstrap.SchemaPreparationError, match="CREATE_OUTCOME_UNCONFIRMED"):
        prepare(setup)
    assert len(db.ddl) == 1


def test_confirmed_create_can_be_read_then_finalized_without_replaying_ddl(setup):
    settings, _, _, db = setup
    db.post_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError, match="OBSERVATION_UNCONFIRMED"):
        prepare(setup)
    db.post_failure = False
    before = files(settings.jobs_root)
    result = reconcile(setup)
    assert result["tables"][0]["state"] == "CONTINUATION_AVAILABLE"
    assert result["ready_for_import"] is False and files(settings.jobs_root) == before
    result = prepare(setup)
    assert result["state"] == "READY" and result["database_writes_this_call"] == 0 and len(db.ddl) == 1
    before = files(settings.jobs_root)
    assert reconcile(setup)["ready_for_import"] is True
    assert files(settings.jobs_root) == before


def test_other_job_cannot_adopt_an_unfinished_original_create(setup):
    settings, _, gate, db = setup
    db.post_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError):
        prepare(setup)
    db.post_failure = False
    root = settings.jobs_root / "schema_job_2"
    root.mkdir()
    with pytest.raises(bootstrap.SchemaPreparationError, match="OTHER_JOB_RECONCILIATION_REQUIRED"):
        prepare((settings, root, gate, db))
    assert len(db.ddl) == 1


def test_drop_recreate_after_create_response_cannot_receive_ownership(setup):
    setup[3].replace_after_create = True
    with pytest.raises(bootstrap.SchemaPreparationError, match="POST_CREATE_IDENTITY_MISMATCH"):
        prepare(setup)
    assert not list(setup[0].jobs_root.rglob("*.ownership.json"))


@pytest.mark.parametrize("field,value", [("object_id", "1234"), ("created", "2026-10-25T02:00:00"),
                                        ("last_ddl_time", "2026-10-25T02:00:00")])
def test_registered_table_identity_changes_block_without_ddl(setup, field, value):
    prepare(setup)
    setup[3].objects[form()["table_name"]]["object_identity"][field] = value
    with pytest.raises(bootstrap.SchemaPreparationError, match="MANAGED_TABLE_CHANGED"):
        prepare(setup)
    assert len(setup[3].ddl) == 1


def test_registered_metadata_change_blocks_without_ddl(setup):
    prepare(setup)
    setup[3].objects[form()["table_name"]]["metadata_sha256"] = "f" * 64
    with pytest.raises(bootstrap.SchemaPreparationError, match="MANAGED_TABLE_CHANGED") as error:
        reconcile(setup)
    assert error.value.table_name == "FOX_NATIVE_ALPHA"


def test_existing_ready_receipt_with_missing_registry_never_recreates(setup, tmp_path_factory):
    prepare(setup)
    settings, root, _, db = setup
    # Simulate a partial restore by retaining the old directory under another
    # name; never delete original evidence.
    registry = settings.jobs_root / bootstrap.REGISTRY_NAME
    registry.rename(settings.jobs_root / "retained-registry")
    db.objects.clear()
    before = files(settings.jobs_root)
    for action in (prepare, reconcile):
        with pytest.raises(bootstrap.SchemaPreparationError, match="REGISTRY_EVIDENCE_MISSING"):
            action(setup)
    assert len(db.ddl) == 1 and files(settings.jobs_root) == before


def test_existing_ready_receipt_with_missing_ownership_never_recreates(setup):
    prepare(setup)
    settings, _, _, db = setup
    path = next((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*.ownership.json"))
    path.rename(path.with_suffix(".retained"))
    db.objects.clear()
    for action in (prepare, reconcile):
        with pytest.raises(bootstrap.SchemaPreparationError, match="REGISTRY_EVIDENCE_MISSING"):
            action(setup)
    assert len(db.ddl) == 1


@pytest.mark.parametrize("suffix", ["intent", "created", "observed", "ownership"])
def test_corrupt_registry_records_block_without_new_ddl(setup, suffix):
    prepare(setup)
    path = next((setup[0].jobs_root / bootstrap.REGISTRY_NAME).glob("*." + suffix + ".json"))
    path.write_bytes(path.read_bytes() + b"corrupt")
    with pytest.raises(bootstrap.SchemaPreparationError):
        prepare(setup)
    assert len(setup[3].ddl) == 1


def test_changed_source_binding_cannot_reuse_same_job_receipt(setup):
    prepare(setup)
    with pytest.raises(bootstrap.SchemaPreparationError, match="JOB_RECEIPT_CHANGED"):
        prepare(setup, binding=bound(source="e"))
    assert len(setup[3].ddl) == 1


def test_reconcile_before_start_is_read_only_and_does_not_create_registry(setup):
    before = files(setup[0].jobs_root)
    result = reconcile(setup)
    assert result["state"] == "NOT_STARTED" and result["ready_for_import"] is False
    assert files(setup[0].jobs_root) == before and not setup[3].reads and not setup[3].ddl


def test_real_registry_lock_contention_blocks_second_prepare(setup):
    registry = setup[0].jobs_root / bootstrap.REGISTRY_NAME
    with bootstrap._lease(registry, create=True):
        before = (registry / "registry.lock").read_bytes() if __import__("os").name != "nt" else None
        with pytest.raises(bootstrap.SchemaPreparationError, match="BUSY_OR_LOCK"):
            prepare(setup)
        if before is not None:
            assert (registry / "registry.lock").read_bytes() == before
    assert not setup[3].ddl
    assert (registry / "registry.lock").read_bytes() == b"0"


def test_explicit_registration_is_read_only_for_database_and_does_not_invent_review(setup):
    settings, root, _, db = setup
    spec = form()
    identity = db.add(spec)["object_identity"]
    rows = deepcopy(db.rows)
    calls = []
    def authorize(value):
        calls.append(deepcopy(value))
        return deepcopy(value)
    result = bootstrap.register_existing_schema(
        settings, spec, root, registration_id="approved-fixture-v1", evidence_sha256="e" * 64,
        expected_object_identity=identity, authorize=authorize, apply=True, executor=db)
    assert result["state"] == "REGISTERED" and result["database_writes"] is False
    assert len(calls) == 2 and db.rows == rows and not db.ddl
    registration = next((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*.registration.json")).read_text()
    assert "review_receipts" not in registration and "validated_draft" not in registration
    assert prepare(setup)["tables"][0]["state"] == "REUSED"


@pytest.mark.parametrize("apply,identity", [(False, None), (True, {"object_id": "1", "created": "bad",
                                                                "last_ddl_time": "bad"})])
def test_registration_requires_explicit_authority_and_exact_prior_identity(setup, apply, identity):
    settings, root, _, db = setup
    actual = db.add(form())["object_identity"]
    with pytest.raises(bootstrap.SchemaPreparationError):
        bootstrap.register_existing_schema(
            settings, form(), root, registration_id="approved-fixture-v1", evidence_sha256="e" * 64,
            expected_object_identity=identity or actual, authorize=lambda value: value, apply=apply, executor=db)
    assert not db.ddl and not (settings.jobs_root / bootstrap.REGISTRY_NAME).exists()


def test_no_default_prefix_adoption(setup):
    setup[3].add(form())
    with pytest.raises(bootstrap.SchemaPreparationError, match="EXISTING_TABLE_NOT_MANAGED"):
        prepare(setup)
    assert not list(setup[0].jobs_root.rglob("*.ownership.json"))


def test_job_root_outside_configured_jobs_is_rejected(setup, tmp_path_factory):
    settings, _, gate, db = setup
    other = tmp_path_factory.mktemp("outside")
    with pytest.raises(bootstrap.SchemaPreparationError, match="EXACT_JOB_ROOT"):
        bootstrap.prepare_schemas(settings, [form()], other, binding=bound(), authorize=gate, executor=db)
    assert not db.ddl


def test_uncertain_job_with_lost_registry_never_becomes_not_started(setup):
    settings, _, _, db = setup
    db.after_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError, match="OUTCOME_UNCONFIRMED"):
        prepare(setup)
    registry = settings.jobs_root / bootstrap.REGISTRY_NAME
    registry.rename(settings.jobs_root / "retained-lost-registry")
    db.objects.clear()
    before = files(settings.jobs_root)
    for action in (prepare, reconcile):
        with pytest.raises(bootstrap.SchemaPreparationError, match="REGISTRY_EVIDENCE_MISSING"):
            action(setup)
    assert len(db.ddl) == 1 and files(settings.jobs_root) == before


def test_new_job_cannot_reset_deleted_registry_when_prior_job_start_survives(setup):
    settings, _, gate, db = setup
    db.after_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError):
        prepare(setup)
    (settings.jobs_root / bootstrap.REGISTRY_NAME).rename(settings.jobs_root / "retained-registry")
    (settings.jobs_root / bootstrap.INDEX_NAME).rename(settings.jobs_root / "retained-index.json")
    root = settings.jobs_root / "schema_job_2"
    root.mkdir()
    db.objects.clear()
    with pytest.raises(bootstrap.SchemaPreparationError, match="REGISTRY_EVIDENCE_MISSING"):
        prepare((settings, root, gate, db))
    assert len(db.ddl) == 1


def test_changed_registry_generation_blocks_without_database_actions(setup):
    prepare(setup)
    settings, _, _, db = setup
    index = settings.jobs_root / bootstrap.INDEX_NAME
    payload, _ = bootstrap._read(index)
    payload["registry_id"] = "f" * 32
    index.rename(settings.jobs_root / "retained-index.json")
    bootstrap._new(index, payload)
    with pytest.raises(bootstrap.SchemaPreparationError, match="REGISTRY_EVIDENCE_MISSING"):
        reconcile(setup)
    assert len(db.ddl) == 1


def test_later_table_creation_drift_is_detected_before_project_ready(setup, monkeypatch):
    settings, root, _, db = setup
    original = db.create
    def changed(*args):
        result = original(*args)
        if len(db.ddl) == 2:
            db.objects["FOX_NATIVE_ALPHA"]["metadata_sha256"] = "f" * 64
        return result
    monkeypatch.setattr(db, "create", changed)
    with pytest.raises(bootstrap.SchemaPreparationError, match="MANAGED_TABLE_CHANGED"):
        prepare(setup, [form(), form("FOX_NATIVE_BETA")])
    assert len(db.ddl) == 2 and not (root / bootstrap.RECEIPT_NAME).exists()
    assert len(list((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*.ownership.json"))) == 2


@pytest.mark.parametrize("member", ["aggregate", "ownership"])
def test_dangling_member_is_not_absent_create_authority(setup, member):
    settings, root, gate, db = setup
    if member == "aggregate":
        path = root / bootstrap.RECEIPT_NAME
    else:
        work = bootstrap._Preparation(settings, [form()], root, bound(), gate, db)
        work.registry.mkdir()
        path = work.path(form(), "ownership")
    try:
        path.symlink_to(root / "does-not-exist")
    except OSError:
        pytest.skip("Native symlink fixture requires platform permission")
    with pytest.raises(bootstrap.SchemaPreparationError, match="LINKED_STORAGE"):
        prepare(setup)
    assert not db.ddl


@pytest.mark.parametrize("uid,mode", [(1001, 0o100600), (1000, 0o100620), (1000, 0o100602)])
def test_posix_wrong_owner_or_writable_record_is_rejected(monkeypatch, uid, mode):
    import types
    real_os = bootstrap.os
    fake_os = types.SimpleNamespace(name="posix", getuid=lambda: 1000)
    monkeypatch.setattr(bootstrap, "os", fake_os)
    fake_path = types.SimpleNamespace(stat=lambda: types.SimpleNamespace(st_uid=uid, st_mode=mode))
    with pytest.raises(bootstrap.SchemaPreparationError, match="OWNER_REQUIRED"):
        bootstrap._owner(fake_path)
    monkeypatch.setattr(bootstrap, "os", real_os)


def register(setup, *, evidence="e", registration_id="approved-fixture-v1", authorize=None):
    settings, root, _, db = setup
    return bootstrap.register_existing_schema(
        settings, form(), root, registration_id=registration_id, evidence_sha256=evidence * 64,
        expected_object_identity=db.objects[form()["table_name"]]["object_identity"],
        authorize=authorize or (lambda value: deepcopy(value)), apply=True, executor=db)


def test_created_owner_rejects_conflicting_registration_record(setup):
    prepare(setup)
    registry = setup[0].jobs_root / bootstrap.REGISTRY_NAME
    created = next(registry.glob("*.intent.json"))
    key = created.name.split(".")[0]
    bootstrap._new(registry / (key + ".registration.json"), {"foreign": "record"})
    with pytest.raises(bootstrap.SchemaPreparationError, match="CONFLICTING_REGISTRY"):
        reconcile(setup)
    assert len(setup[3].ddl) == 1


def test_registered_owner_rejects_even_an_unresolved_create_record(setup):
    setup[3].add(form())
    register(setup)
    registry = setup[0].jobs_root / bootstrap.REGISTRY_NAME
    registered = next(registry.glob("*.registration.json"))
    key = registered.name.split(".")[0]
    bootstrap._new(registry / (key + ".intent.json"), {"unresolved": True})
    with pytest.raises(bootstrap.SchemaPreparationError, match="CONFLICTING_REGISTRY"):
        prepare(setup)
    assert not setup[3].ddl


def test_explicit_registration_resumes_local_ownership_only(setup, monkeypatch):
    setup[3].add(form())
    original = bootstrap._new
    def fail_owner(path, value):
        if path.name.endswith(".ownership.json"):
            raise OSError("synthetic interruption after registration")
        return original(path, value)
    monkeypatch.setattr(bootstrap, "_new", fail_owner)
    with pytest.raises(OSError):
        register(setup)
    registry = setup[0].jobs_root / bootstrap.REGISTRY_NAME
    recorded = next(registry.glob("*.registration.json"))
    before = recorded.read_bytes()
    monkeypatch.setattr(bootstrap, "_new", original)
    result = register(setup)
    assert result["state"] == "REGISTERED" and result["database_writes"] is False
    assert recorded.read_bytes() == before and not setup[3].ddl


def test_changed_registration_cannot_take_over_an_incomplete_record(setup, monkeypatch):
    setup[3].add(form())
    original = bootstrap._new
    def fail_owner(path, value):
        if path.name.endswith(".ownership.json"):
            raise OSError("synthetic interruption")
        return original(path, value)
    monkeypatch.setattr(bootstrap, "_new", fail_owner)
    with pytest.raises(OSError):
        register(setup)
    monkeypatch.setattr(bootstrap, "_new", original)
    with pytest.raises(bootstrap.SchemaPreparationError, match="REGISTRATION_RECORD_CHANGED"):
        register(setup, evidence="f")
    assert not setup[3].ddl


def test_registration_uses_detached_normalized_spec(setup):
    settings, root, _, db = setup
    original_spec = form()
    identity = db.add(original_spec)["object_identity"]
    def authorize(request):
        original_spec["table_name"] = "FOX_NATIVE_OTHER"
        original_spec["columns"][1]["length"] = 101
        return deepcopy(request)
    bootstrap.register_existing_schema(
        settings, original_spec, root, registration_id="approved-fixture-v1", evidence_sha256="e" * 64,
        expected_object_identity=identity, authorize=authorize, apply=True, executor=db)
    assert prepare(setup)["tables"][0]["table_name"] == "FOX_NATIVE_ALPHA"
    assert not db.ddl


def test_default_executor_uses_saved_connection_and_invokes_intent_before_sqlcl(setup, monkeypatch):
    import subprocess
    settings, root, _, db = setup
    events = []
    token = "a" * 32
    spec = form()
    target = probe.target(settings)
    output = ("FOX_SCHEMA_CREATE_BEGIN=1\n"
              + "|".join(["D", target["db_name"], target["session_user"], target["session_user"],
                           target["parsing_schema"], target["apex_version"], target["workspace_id"], "1", "BYTE"])
              + "\nCREATED|FOX_NATIVE_ALPHA|" + token
              + "|123|2026-10-25T01:00:00|2026-10-25T01:00:00\nFOX_SCHEMA_CREATE_END=1\n")
    def run(path, args, commands, cwd, *, timeout):
        assert events == ["intent"]
        assert path == settings.sqlcl_path and args == ["-S", "-L", "-name", "F2A_APEX"]
        assert cwd == root and timeout == 120
        assert commands == probe.create_commands(settings, spec, token)
        events.append("sqlcl")
        return subprocess.CompletedProcess([], 0, output, "")
    monkeypatch.setattr(bootstrap, "_run_script", run)
    result = bootstrap.SqlclSchemaExecutor().create(settings, spec, root, token,
                                                    lambda: events.append("intent"))
    assert events == ["intent", "sqlcl"] and result["object_identity"]["object_id"] == "123"
    assert not db.ddl  # The fake subprocess is not the synthetic database adapter.


@pytest.mark.parametrize("code,stderr,output", [(1, "", "arbitrary private text"),
                                               (0, "provider warning", "arbitrary"),
                                               (0, "", "malformed protocol")])
def test_default_executor_uncertain_output_is_fixed_error_only(setup, monkeypatch, code, stderr, output):
    import subprocess
    settings, root, _, _ = setup
    monkeypatch.setattr(bootstrap, "_run_script",
                        lambda *args, **kwargs: subprocess.CompletedProcess([], code, output, stderr))
    calls = []
    with pytest.raises(bootstrap.SchemaPreparationError, match="CREATE_OUTCOME_UNCONFIRMED") as error:
        bootstrap.SqlclSchemaExecutor().create(settings, form(), root, "a" * 32,
                                               lambda: calls.append("intent"))
    assert calls == ["intent"] and "private" not in str(error.value) and "provider" not in str(error.value)


@pytest.mark.parametrize("new_job", [False, True])
def test_selectively_lost_create_intent_is_not_fresh_dispatch_authority(setup, new_job):
    settings, root, gate, db = setup
    db.after_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError, match="OUTCOME_UNCONFIRMED"):
        prepare(setup)
    registry = settings.jobs_root / bootstrap.REGISTRY_NAME
    intent = next(registry.glob("*.intent.json"))
    intent.rename(intent.with_suffix(".retained"))
    db.objects.clear()
    db.after_failure = False
    if new_job:
        root = settings.jobs_root / "schema_job_2"
        root.mkdir()
    candidate = (settings, root, gate, db)
    before = files(settings.jobs_root)
    result = reconcile(candidate)
    assert result["tables"][0]["state"] == "DISPATCH_HISTORY_INCOMPLETE"
    assert result["ready_for_import"] is False
    with pytest.raises(bootstrap.SchemaPreparationError, match="DISPATCH_HISTORY_INCOMPLETE"):
        prepare(candidate)
    assert len(db.ddl) == 1 and files(settings.jobs_root) == before


def test_lost_alpha_intent_does_not_block_independent_beta_table(setup):
    settings, _, gate, db = setup
    db.after_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError):
        prepare(setup)
    registry = settings.jobs_root / bootstrap.REGISTRY_NAME
    intent = next(registry.glob("*.intent.json"))
    intent.rename(intent.with_suffix(".retained"))
    db.after_failure = False
    root = settings.jobs_root / "schema_job_2"
    root.mkdir()
    result = prepare((settings, root, gate, db), [form("FOX_NATIVE_BETA")])
    assert result["state"] == "READY"
    assert [item[0] for item in db.ddl] == ["FOX_NATIVE_ALPHA", "FOX_NATIVE_BETA"]


def test_known_failure_before_dispatch_can_be_retried_safely(setup):
    setup[3].before_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError, match="CREATE_NOT_STARTED"):
        prepare(setup)
    setup[3].before_failure = False
    result = prepare(setup)
    assert result["state"] == "READY" and len(setup[3].ddl) == 1


def test_completed_first_table_and_undispatched_second_can_continue(setup, monkeypatch):
    settings, root, _, db = setup
    original = db.create
    def stop_second(*args):
        if args[1]["table_name"] == "FOX_NATIVE_BETA":
            raise RuntimeError("synthetic interruption before callback")
        return original(*args)
    monkeypatch.setattr(db, "create", stop_second)
    specs = [form(), form("FOX_NATIVE_BETA")]
    with pytest.raises(bootstrap.SchemaPreparationError, match="CREATE_NOT_STARTED") as error:
        prepare(setup, specs)
    assert error.value.table_name == "FOX_NATIVE_BETA" and len(error.value.completed_tables) == 1
    alpha_identity = deepcopy(db.objects["FOX_NATIVE_ALPHA"]["object_identity"])
    monkeypatch.setattr(db, "create", original)
    result = prepare(setup, specs)
    assert result["state"] == "READY" and result["database_writes_this_call"] == 1
    assert [item[0] for item in db.ddl] == ["FOX_NATIVE_ALPHA", "FOX_NATIVE_BETA"]
    assert db.objects["FOX_NATIVE_ALPHA"]["object_identity"] == alpha_identity


def test_missing_dispatch_anchor_blocks_owned_table_reuse(setup):
    prepare(setup)
    anchor = next(setup[1].glob("*.schema-dispatch.json"))
    anchor.rename(anchor.with_suffix(".retained"))
    with pytest.raises(bootstrap.SchemaPreparationError):
        prepare(setup)
    assert len(setup[3].ddl) == 1


def test_registration_cannot_mask_a_lost_unknown_create_intent(setup):
    settings, _, _, db = setup
    db.after_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError):
        prepare(setup)
    intent = next((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*.intent.json"))
    intent.rename(intent.with_suffix(".retained"))
    with pytest.raises(bootstrap.SchemaPreparationError, match="EXISTING_ATTEMPT_REQUIRES_RECONCILIATION"):
        register(setup)
    assert not list((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*.ownership.json"))
    assert len(db.ddl) == 1


def mapped_form(project="project_alpha", source="ORDERS", *, label="Description", length=100):
    spec = form(label=label)
    spec["table_name"] = source
    spec["columns"][1]["length"] = length
    mapping = bootstrap.storage_contract.derive_storage_mapping(project, spec)
    spec["table_name"] = mapping["target_table_name"]
    return spec, {spec["table_name"]: mapping}


def next_job(setup, name="schema_job_2"):
    settings, _, gate, db = setup
    root = settings.jobs_root / name
    root.mkdir()
    return settings, root, gate, db


def test_mapped_schema_binds_full_identity_in_every_record_and_authorization(setup):
    spec, mappings = mapped_form()
    result = prepare(setup, [spec], mappings=mappings)
    mapping = mappings[spec["table_name"]]
    expected = {"storage_mapping": mapping, "storage_mapping_sha256": bootstrap._digest(mapping)}
    settings, root, gate, db = setup
    for suffix in ("intent", "created", "observed", "ownership"):
        record, _ = bootstrap._read(next((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*." + suffix + ".json")))
        assert {key: record[key] for key in expected} == expected
    anchor, _ = bootstrap._read(next(root.glob("*.schema-dispatch.json")))
    started, _ = bootstrap._read(root / bootstrap.STARTED_NAME)
    receipt, _ = bootstrap._read(root / bootstrap.RECEIPT_NAME)
    for record in (anchor, started["schema_plan"][0], receipt["tables"][0], result["tables"][0]):
        assert {key: record[key] for key in expected} == expected
    for _, request in gate.calls:
        assert {key: request["schema_plan"][0][key] for key in expected} == expected
        assert request["schema_plan_sha256"] == bootstrap._digest(request["schema_plan"])
    assert reconcile(setup, [spec], mappings=mappings)["ready_for_import"] is True
    assert len(db.ddl) == 1


def test_mapped_label_change_reuses_exact_object_and_retained_rows(setup):
    spec, mappings = mapped_form()
    prepare(setup, [spec], mappings=mappings)
    objects, rows = deepcopy(setup[3].objects), deepcopy(setup[3].rows)
    changed, unchanged = mapped_form(label="Updated display label")
    assert unchanged == mappings
    result = prepare(next_job(setup), [changed], mappings=unchanged)
    assert result["tables"][0]["state"] == "REUSED" and result["database_writes_this_call"] == 0
    assert setup[3].objects == objects and setup[3].rows == rows and len(setup[3].ddl) == 1


@pytest.mark.parametrize("revision", ["structural", "project", "source"])
def test_storage_identity_change_creates_new_table_without_touching_old_data(setup, revision):
    spec, mappings = mapped_form()
    prepare(setup, [spec], mappings=mappings)
    original = deepcopy(setup[3].objects[spec["table_name"]])
    rows = deepcopy(setup[3].rows[spec["table_name"]])
    changed, changed_mappings = mapped_form(
        project="project_beta" if revision == "project" else "project_alpha",
        source="INVOICES" if revision == "source" else "ORDERS",
        length=101 if revision == "structural" else 100)
    assert changed["table_name"] != spec["table_name"]
    result = prepare(next_job(setup), [changed], mappings=changed_mappings)
    assert result["database_writes_this_call"] == 1 and len(setup[3].ddl) == 2
    assert setup[3].objects[spec["table_name"]] == original and setup[3].rows[spec["table_name"]] == rows


@pytest.mark.parametrize("collision", ["truncated", "full", "full_and_payload_hash"])
def test_mapping_collision_blocks_before_any_sql_under_physical_registry_key(setup, monkeypatch, collision):
    def collision_hash(identity):
        suffix = "a" if identity["project_id"] == "project_alpha" else "b"
        return "f" * 19 + (suffix * 45 if collision == "truncated" else "c" * 45)
    monkeypatch.setattr(bootstrap.storage_contract, "_storage_identity_sha", collision_hash)
    if collision == "full_and_payload_hash":
        original_digest = bootstrap._digest
        monkeypatch.setattr(bootstrap, "_digest", lambda value:
            "e" * 64 if type(value) is dict and value.get("scope") == "fox-project-storage-v1"
            else original_digest(value))
    spec, mappings = mapped_form()
    prepare(setup, [spec], mappings=mappings)
    other, other_mappings = mapped_form(project="project_beta")
    assert other["table_name"] == spec["table_name"]
    assert other_mappings != mappings
    next_setup = next_job(setup)
    reads, retained = list(setup[3].reads), files(setup[0].jobs_root)
    for action in (prepare, reconcile):
        with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING_CONFLICT"):
            action(next_setup, [other], mappings=other_mappings)
    assert setup[3].reads == reads and len(setup[3].ddl) == 1
    assert files(setup[0].jobs_root) == retained


@pytest.mark.parametrize("first_mapped", [False, True])
@pytest.mark.parametrize("retained", ["ownership", "intent", "orphan_anchor"])
def test_mapped_and_legacy_domains_never_cross_adopt(setup, first_mapped, retained):
    spec, mappings = mapped_form()
    if retained != "ownership":
        setup[3].after_failure = True
        with pytest.raises(bootstrap.SchemaPreparationError, match="OUTCOME_UNCONFIRMED"):
            prepare(setup, [spec], mappings=mappings if first_mapped else None)
        setup[3].after_failure = False
        if retained == "orphan_anchor":
            intent = next((setup[0].jobs_root / bootstrap.REGISTRY_NAME).glob("*.intent.json"))
            intent.rename(intent.with_suffix(".retained"))
            setup[3].objects.clear()
    else:
        prepare(setup, [spec], mappings=mappings if first_mapped else None)
    next_setup = next_job(setup)
    reads, retained_files = list(setup[3].reads), files(setup[0].jobs_root)
    for action in (prepare, reconcile):
        with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING_CONFLICT"):
            action(next_setup, [spec], mappings=None if first_mapped else mappings)
    assert setup[3].reads == reads and len(setup[3].ddl) == 1
    assert files(setup[0].jobs_root) == retained_files


def test_all_mapping_ownership_conflicts_are_checked_before_any_table_observation(setup, monkeypatch):
    # The absent table sorts first, but it still must not be observed or created.
    def collision_hash(identity):
        return ("f" if identity["source_table_name"] == "ORDERS" else "0") * 64
    monkeypatch.setattr(bootstrap.storage_contract, "_storage_identity_sha", collision_hash)
    owned, own_mapping = mapped_form()
    prepare(setup, [owned], mappings=own_mapping)
    absent, absent_mapping = mapped_form(project="project_beta", source="INVOICES")
    collide, collide_mapping = mapped_form(project="project_beta")
    reads = list(setup[3].reads)
    with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING_CONFLICT"):
        prepare(next_job(setup), [absent, collide], mappings={**absent_mapping, **collide_mapping})
    assert setup[3].reads == reads and len(setup[3].ddl) == 1


@pytest.mark.parametrize("change", [
    lambda m, n: m.clear(),
    lambda m, n: m.update(EXTRA=deepcopy(m[n])),
    lambda m, n: m[n].update(schema_version=True),
    lambda m, n: m[n].update(project_id="different-project"),
    lambda m, n: m[n].update(source_table_name="INVOICES"),
    lambda m, n: m[n].update(source_schema_sha256="f" * 64),
    lambda m, n: m[n].update(identity_sha256="f" * 64),
    lambda m, n: m[n].update(target_table_name="FOX_NATIVE_OTHER"),
    lambda m, n: m[n].update(extra="untrusted"),
])
def test_invalid_mapping_never_authorizes_or_observes(setup, change):
    spec, mappings = mapped_form()
    change(mappings, spec["table_name"])
    with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING"):
        prepare(setup, [spec], mappings=mappings)
    assert setup[2].calls == setup[3].reads == setup[3].ddl == []
    assert not (setup[0].jobs_root / bootstrap.REGISTRY_NAME).exists()


def test_mapping_collection_cannot_mix_projects(setup):
    first, mappings = mapped_form()
    second, more = mapped_form(project="project_beta")
    with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_PROJECT_MISMATCH"):
        prepare(setup, [first, second], mappings={**mappings, **more})
    assert setup[2].calls == setup[3].reads == setup[3].ddl == []


def test_one_plan_cannot_map_conflicting_structures_for_same_source_table(setup):
    first, mappings = mapped_form()
    second, more = mapped_form(length=101)
    with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING_CONFLICT"):
        prepare(setup, [first, second], mappings={**mappings, **more})
    assert setup[2].calls == setup[3].reads == setup[3].ddl == []


def test_matching_physical_table_without_mapping_ownership_is_not_adopted(setup):
    spec, mappings = mapped_form()
    setup[3].add(spec)
    rows = deepcopy(setup[3].rows)
    with pytest.raises(bootstrap.SchemaPreparationError, match="EXISTING_TABLE_NOT_MANAGED"):
        prepare(setup, [spec], mappings=mappings)
    assert setup[3].rows == rows and not setup[3].ddl
    assert not list((setup[0].jobs_root / bootstrap.REGISTRY_NAME).glob("*.ownership.json"))


def test_mapping_does_not_replace_exact_database_object_identity(setup):
    spec, mappings = mapped_form()
    prepare(setup, [spec], mappings=mappings)
    setup[3].add(spec)  # Same structure, different Oracle object identity.
    with pytest.raises(bootstrap.SchemaPreparationError, match="MANAGED_TABLE_CHANGED"):
        prepare(next_job(setup), [spec], mappings=mappings)
    assert len(setup[3].ddl) == 1


def test_mapping_is_detached_before_authorization(setup):
    settings, root, gate, db = setup
    spec, mappings = mapped_form()
    retained = deepcopy(mappings)
    def authorize(operation, request):
        mappings[spec["table_name"]]["project_id"] = "mutated-by-caller"
        return deepcopy(request)
    result = bootstrap.prepare_schemas(settings, [spec], root, binding=bound(), authorize=authorize,
                                       executor=db, mapping_identities=mappings)
    assert result["tables"][0]["storage_mapping"] == retained[spec["table_name"]]
    assert len(db.ddl) == 1


@pytest.mark.parametrize("missing", ["index", "registry", "ownership", "anchor", "intent"])
def test_mapped_missing_evidence_never_recreates_a_table(setup, missing):
    spec, mappings = mapped_form()
    prepare(setup, [spec], mappings=mappings)
    settings, root, _, db = setup
    if missing == "index":
        path = settings.jobs_root / bootstrap.INDEX_NAME
    elif missing == "registry":
        path = settings.jobs_root / bootstrap.REGISTRY_NAME
    elif missing == "anchor":
        path = next(root.glob("*.schema-dispatch.json"))
    else:
        path = next((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*." + missing + ".json"))
    path.rename(path.with_name(path.name + ".retained"))
    db.objects.clear()
    retained = files(settings.jobs_root)
    for action in (prepare, reconcile):
        with pytest.raises(bootstrap.SchemaPreparationError):
            action(setup, [spec], mappings=mappings)
    assert len(db.ddl) == 1 and files(settings.jobs_root) == retained


def test_mapped_lost_create_response_never_replays_even_when_table_disappears(setup):
    spec, mappings = mapped_form()
    setup[3].after_failure = True
    with pytest.raises(bootstrap.SchemaPreparationError, match="OUTCOME_UNCONFIRMED"):
        prepare(setup, [spec], mappings=mappings)
    setup[3].objects.clear()
    setup[3].after_failure = False
    for _ in range(2):
        result = reconcile(setup, [spec], mappings=mappings)
        assert result["tables"][0]["state"] == "CREATE_OUTCOME_UNCONFIRMED"
        assert result["tables"][0]["storage_mapping"] == mappings[spec["table_name"]]
        with pytest.raises(bootstrap.SchemaPreparationError, match="OUTCOME_UNCONFIRMED"):
            prepare(setup, [spec], mappings=mappings)
    assert len(setup[3].ddl) == 1


def test_mapped_registry_lease_blocks_concurrent_job_before_sql(setup):
    spec, mappings = mapped_form()
    registry = setup[0].jobs_root / bootstrap.REGISTRY_NAME
    with bootstrap._lease(registry, create=True):
        with pytest.raises(bootstrap.SchemaPreparationError, match="BUSY_OR_LOCK"):
            prepare(setup, [spec], mappings=mappings)
    assert setup[3].reads == setup[3].ddl == []
    assert (registry / "registry.lock").read_bytes() == b"0"


def test_legacy_registration_cannot_be_adopted_as_mapped_ownership(setup):
    spec, mappings = mapped_form()
    settings, root, _, db = setup
    identity = db.add(spec)["object_identity"]
    bootstrap.register_existing_schema(
        settings, spec, root, registration_id="approved-fixture-v1", evidence_sha256="e" * 64,
        expected_object_identity=identity, authorize=lambda value: value, apply=True, executor=db)
    reads = list(db.reads)
    with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING_CONFLICT"):
        prepare(setup, [spec], mappings=mappings)
    assert db.reads == reads and not db.ddl


def test_manual_registration_cannot_strip_mapping_from_managed_table(setup):
    spec, mappings = mapped_form()
    prepare(setup, [spec], mappings=mappings)
    settings, root, _, db = setup
    reads = list(db.reads)
    with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING_CONFLICT"):
        bootstrap.register_existing_schema(
            settings, spec, root, registration_id="approved-fixture-v1", evidence_sha256="e" * 64,
            expected_object_identity=db.objects[spec["table_name"]]["object_identity"],
            authorize=lambda value: value, apply=True, executor=db)
    assert db.reads == reads and len(db.ddl) == 1


def test_legacy_record_and_request_shapes_remain_unmapped(setup):
    result = prepare(setup)
    for raw in files(setup[0].jobs_root).values():
        assert b"storage_mapping" not in raw
    assert "storage_mapping" not in json.dumps(result)
    assert "storage_mapping" not in json.dumps(setup[2].calls)


def test_mapped_not_started_reconciliation_binds_plan_without_creating_registry(setup):
    spec, mappings = mapped_form()
    before = files(setup[0].jobs_root)
    result = reconcile(setup, [spec], mappings=mappings)
    assert result["state"] == "NOT_STARTED" and result["ready_for_import"] is False
    assert result["schema_plan_sha256"] == bootstrap._digest(bootstrap._plan([spec], mappings)[1])
    assert files(setup[0].jobs_root) == before and setup[3].reads == setup[3].ddl == []


@pytest.mark.parametrize("kind", ["intent", "created", "observed", "ownership", "anchor"])
@pytest.mark.parametrize("change", ["payload", "hash", "remove"])
def test_retained_mapping_change_blocks_before_database_observation(setup, kind, change):
    spec, mappings = mapped_form()
    prepare(setup, [spec], mappings=mappings)
    settings, root, _, db = setup
    path = (next(root.glob("*.schema-dispatch.json")) if kind == "anchor" else
            next((settings.jobs_root / bootstrap.REGISTRY_NAME).glob("*." + kind + ".json")))
    record, _ = bootstrap._read(path)
    if change == "payload":
        record["storage_mapping"]["project_id"] = "different-project"
    elif change == "hash":
        record["storage_mapping_sha256"] = "0" * 64
    else:
        del record["storage_mapping"]
        del record["storage_mapping_sha256"]
    path.rename(path.with_name(path.name + ".retained"))
    bootstrap._new(path, record)
    reads, retained = list(db.reads), files(settings.jobs_root)
    for action in (prepare, reconcile):
        with pytest.raises(bootstrap.SchemaPreparationError, match="STORAGE_MAPPING_CONFLICT"):
            action(setup, [spec], mappings=mappings)
    assert db.reads == reads and len(db.ddl) == 1 and files(settings.jobs_root) == retained
