"""Pure/fake-SQLcl schema probe tests. Never connect to Oracle or run SQLcl."""
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest

from forms2apex import schema_probe as probe
from forms2apex.native_schema import render_native_schema
from forms2apex.target_profile import _JSN_PROFILE, TargetProfileError


@pytest.fixture
def spec():
    return {"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
            "table_name": "FOX_NATIVE_ORDERS", "columns": [
                {"name": "ORDER_ID", "data_type": "NUMBER", "nullable": False,
                 "label": "Order ID", "primary_key": True, "identity": True},
                {"name": "DESCRIPTION", "data_type": "VARCHAR2", "nullable": False,
                 "label": "Description", "length": 100},
                {"name": "ORDER_DATE", "data_type": "DATE", "nullable": True,
                 "label": "Order date"},
            ]}


@pytest.fixture
def settings(tmp_path):
    profile = deepcopy(_JSN_PROFILE)
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(profile), encoding="utf-8")
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    (jobs / "synthetic-probe").mkdir()
    return SimpleNamespace(
        target_profile_path=path, sqlcl_path=Path("/not-a-real-sqlcl"), jobs_root=jobs,
        apex_workspace=profile["apex"]["workspace"],
        apex_parsing_schema=profile["database"]["parsing_schema"],
        sqlcl_connection_name=profile["sqlcl"]["saved_connection"],
        apex_base_url=profile["apex"]["ords_origin"] + profile["apex"]["ords_base_path"],
        generator_model=profile["opaf"]["roles"]["mapper"]["model"],
        reviewer_model=profile["opaf"]["roles"]["reviewer"]["model"],
        opaf_mapper_workflow_id=profile["opaf"]["roles"]["mapper"]["workflow_id"],
        opaf_reviewer_workflow_id=profile["opaf"]["roles"]["reviewer"]["workflow_id"],
    )


def identity(settings):
    target = probe.target(settings)
    return "|".join(["D", target["db_name"], target["session_user"], target["session_user"],
                     target["parsing_schema"], target["apex_version"], target["workspace_id"], "1", "BYTE"])


def observed(settings, *, present=True, privileges="P|1|1|0", quota="Q|DATA|1|0|20971520"):
    header = ["FOX_SCHEMA_BEGIN=1", identity(settings), privileges, quota]
    if not present:
        return "\n".join([*header, "T|FOX_NATIVE_ORDERS|ABSENT", "FOX_SCHEMA_END=1"]) + "\n"
    return "\n".join([*header,
        "T|FOX_NATIVE_ORDERS|PRESENT|9007199254740993|2026-10-25T01:00:00|2026-10-25T01:00:00|0|1|3|3|1|0|0",
        "C|1|1|ORDER_ID|NUMBER|22|0|-|N|YES|YES|NO|NO|YES|NONE|-|-|IDENTITY_NEXTVAL",
        "C|2|2|DESCRIPTION|VARCHAR2|100|100|B|N|NO|NO|NO|NO|YES|NONE|-|-|NONE",
        "C|3|3|ORDER_DATE|DATE|7|0|-|Y|NO|NO|NO|NO|YES|NONE|-|-|NONE",
        "I|ORDER_ID|BY DEFAULT|SYSTEM",
        "K|1|C|ENABLED|VALIDATED|NOT DEFERRABLE|IMMEDIATE|-|ORDER_ID|NOT_NULL|ORDER_ID",
        "K|2|C|ENABLED|VALIDATED|NOT DEFERRABLE|IMMEDIATE|-|DESCRIPTION|NOT_NULL|DESCRIPTION",
        "K|3|P|ENABLED|VALIDATED|NOT DEFERRABLE|IMMEDIATE|-|ORDER_ID|OTHER|-",
        "X|NORMAL|UNIQUE|VALID|NO|1|ORDER_ID|0",
        "FOX_SCHEMA_END=1",
    ]) + "\n"


@pytest.fixture
def runner(monkeypatch, settings):
    state = {"code": 0, "stderr": "", "stdout": observed(settings), "calls": [], "exception": None}

    def run(*args, **kwargs):
        state["calls"].append((args, kwargs))
        if state["exception"] is not None:
            raise state["exception"]
        return subprocess.CompletedProcess([], state["code"], state["stdout"], state["stderr"])

    monkeypatch.setattr(probe, "_run_script", run)
    return state


def test_schema_identity_ignores_labels_but_not_columns(spec):
    renamed = deepcopy(spec)
    renamed["columns"][1]["label"] = 'Renamed "display"'
    assert probe.schema_sha256(renamed) == probe.schema_sha256(spec)
    assert render_native_schema(renamed) == render_native_schema(spec)
    assert "label" not in json.dumps(probe.schema_contract(spec))
    changed = deepcopy(spec)
    changed["columns"][1]["length"] = 99
    assert probe.schema_sha256(changed) != probe.schema_sha256(spec)
    changed = deepcopy(spec)
    changed["columns"].reverse()
    assert probe.schema_sha256(changed) != probe.schema_sha256(spec)


def test_exact_observation_keeps_large_object_identity_as_string(spec, settings):
    result = probe.parse_observation(observed(settings), spec, probe.target(settings))
    assert result["state"] == "EXACT"
    assert result["object_identity"] == {"object_id": "9007199254740993", "created": "2026-10-25T01:00:00",
                                         "last_ddl_time": "2026-10-25T01:00:00"}
    assert result["schema_sha256"] == probe.schema_sha256(spec)
    assert re.fullmatch("[a-f0-9]{64}", result["metadata_sha256"])
    assert result["data_rows_read"] is result["business_behavior_verified"] is False
    assert result["capabilities"]["creation_ready"] is True


def test_absence_is_not_creation_authority(spec, settings):
    result = probe.parse_observation(observed(settings, present=False), spec, probe.target(settings))
    assert result["state"] == "ABSENT"
    assert result["object_identity"] is result["metadata_sha256"] is None
    assert "created_in_this_sqlcl_execution" not in result
    assert result["capabilities"]["allocation_guaranteed"] is False


@pytest.mark.parametrize("privileges,quota,ready", [
    ("P|0|1|0", "Q|DATA|1|0|20971520", False),
    ("P|1|0|0", "Q|DATA|1|0|20971520", False),
    ("P|1|1|0", "Q|DATA|0|-|-", False),
    ("P|1|1|0", "Q|DATA|1|100|100", False),
    ("P|1|1|0", "Q|DATA|1|101|100", False),
    ("P|1|1|0", "Q|DATA|1|100|-1", True),
    ("P|1|1|1", "Q|DATA|0|-|-", True),
    ("P|1|1|0", "Q|OTHER_SPACE|1|0|100", False),
])
def test_existing_matching_table_does_not_require_create_capability(spec, settings, privileges, quota, ready):
    result = probe.parse_observation(observed(settings, privileges=privileges, quota=quota), spec, probe.target(settings))
    assert result["state"] == "EXACT"
    assert result["capabilities"]["creation_ready"] is ready


@pytest.mark.parametrize("bad", ["P|1|1", "P|1|1|2", "P|true|1|0", "P|01|1|0", "P|1|1|0|EXTRA"])
def test_malformed_privileges_fail(spec, settings, bad):
    with pytest.raises(probe.ProbeError):
        probe.parse_observation(observed(settings, privileges=bad), spec, probe.target(settings))


@pytest.mark.parametrize("bad", ["Q|DATA|0|0|0", "Q|DATA|1|-|100", "Q|DATA|1|0|-2", "Q|DATA|1|0|01",
                                "Q|DATA|1|0|1.5", "Q|DATA;SECRET|1|0|100", "Q|DATA|2|0|100", "Q|DATA|1|0"])
def test_malformed_quotas_fail(spec, settings, bad):
    with pytest.raises(probe.ProbeError):
        probe.parse_observation(observed(settings, quota=bad), spec, probe.target(settings))


@pytest.mark.parametrize("old,new", [
    ("|0|1|3|3|1|0|0", "|1|1|3|3|1|0|0"),
    ("|0|1|3|3|1|0|0", "|0|1|3|3|1|1|0"),
    ("|0|1|3|3|1|0|0", "|0|1|3|3|1|0|1"),
    ("|0|1|3|3|1|0|0", "|0|2|3|3|1|0|0"),
    ("|0|1|3|3|1|0|0", "|0|1|3|3|2|0|0"),
    ("|NUMBER|22|0|-|N|YES|YES", "|NUMBER|22|0|-|Y|YES|YES"),
    ("|NONE|-|-|IDENTITY_NEXTVAL", "|NONE|10|2|IDENTITY_NEXTVAL"),
    ("|VARCHAR2|100|100|B", "|VARCHAR2|100|100|C"),
    ("|VARCHAR2|100|100|B", "|VARCHAR2|101|100|B"),
    ("|VARCHAR2|100|100|B", "|VARCHAR2|100|99|B"),
    ("|VARCHAR2|100|100|B", "|CLOB|100|100|B"),
    ("|NO|NO|YES|NONE", "|YES|NO|YES|NONE"),
    ("|NO|NO|YES|NONE", "|NO|YES|YES|NONE"),
    ("|NO|NO|YES|NONE", "|NO|NO|NO|NONE"),
    ("|NONE|-|-|NONE", "|NONE|-|-|OTHER"),
    ("I|ORDER_ID|BY DEFAULT|SYSTEM", "I|ORDER_ID|ALWAYS|SYSTEM"),
    ("I|ORDER_ID|BY DEFAULT|SYSTEM", "I|ORDER_ID|BY DEFAULT|OTHER"),
    ("K|3|P|ENABLED", "K|3|P|DISABLED"),
    ("NOT DEFERRABLE|IMMEDIATE", "DEFERRABLE|IMMEDIATE"),
    ("|VALIDATED|", "|NOT VALIDATED|"),
    ("K|2|C|ENABLED", "K|2|R|ENABLED"),
    ("|DESCRIPTION|NOT_NULL|DESCRIPTION", "|DESCRIPTION|OTHER|-"),
    ("X|NORMAL|UNIQUE|VALID|NO|1|ORDER_ID|0", "X|NORMAL|UNIQUE|VALID|NO|1|DESCRIPTION|0"),
    ("X|NORMAL|UNIQUE|VALID|NO|1|ORDER_ID|0", "X|NORMAL|NONUNIQUE|VALID|NO|1|ORDER_ID|0"),
    ("X|NORMAL|UNIQUE|VALID|NO|1|ORDER_ID|0", "X|NORMAL|UNIQUE|VALID|YES|1|ORDER_ID|0"),
    ("X|NORMAL|UNIQUE|VALID|NO|1|ORDER_ID|0", "X|NORMAL|UNIQUE|VALID|NO|1|ORDER_ID|1"),
    ("2026-10-25T01:00:00", "2026-02-31T01:00:00"),
    ("9007199254740993", "0"),
])
def test_metadata_drift_is_not_exact(spec, settings, old, new):
    with pytest.raises(probe.ProbeError):
        probe.parse_observation(observed(settings).replace(old, new), spec, probe.target(settings))


@pytest.mark.parametrize("operation", ["remove", "duplicate"])
def test_every_protocol_row_is_required_and_unique(spec, settings, operation):
    lines = observed(settings).splitlines()
    for index in range(len(lines)):
        altered = lines[:index] + (lines[index:index + 1] * 2 if operation == "duplicate" else []) + lines[index + 1:]
        with pytest.raises(probe.ProbeError):
            probe.parse_observation("\n".join(altered), spec, probe.target(settings))


@pytest.mark.parametrize("extra", ["SQL> ", "ORA-00000 secret", "FOX_SCHEMA_UNKNOWN=1", "C|bad", "é"])
def test_unknown_output_is_not_evidence(spec, settings, extra):
    with pytest.raises(probe.ProbeError):
        probe.parse_observation(observed(settings).replace("FOX_SCHEMA_END=1", extra + "\nFOX_SCHEMA_END=1"),
                                spec, probe.target(settings))


@pytest.mark.parametrize("output", [None, "", "x" * 100001, "FOX_SCHEMA_BEGIN=1\nFOX_SCHEMA_END=1"],
                         ids=["non-string", "empty", "oversized", "incomplete"])
def test_incomplete_output_is_rejected(spec, settings, output):
    with pytest.raises(probe.ProbeError):
        probe.parse_observation(output, spec, probe.target(settings))


def test_target_marker_drift_and_extra_metadata_after_absence_fail(spec, settings):
    output = observed(settings)
    for old, new in [("ASZ8EQWFM8UNCA2_JSNF2APEX", "OTHER_DB"), ("FORMS2APEX_POC", "ADMIN"),
                     ("26.1.5", "26.1.6"), ("9009446931169094", "1"), ("|1|BYTE", "|2|BYTE")]:
        with pytest.raises(probe.ProbeError):
            probe.parse_observation(output.replace(old, new), spec, probe.target(settings))
    with pytest.raises(probe.ProbeError):
        probe.parse_observation(observed(settings, present=False).replace("FOX_SCHEMA_END=1", "X|extra\nFOX_SCHEMA_END=1"),
                                spec, probe.target(settings))


def test_observe_uses_saved_connection_and_safe_read_only_transaction(spec, settings, runner):
    root = settings.jobs_root / "synthetic-probe"
    result = probe.observe(settings, spec, root)
    assert result["state"] == "EXACT" and len(runner["calls"]) == 1
    args, kwargs = runner["calls"][0]
    assert args[0] == settings.sqlcl_path
    assert args[1] == ["-S", "-L", "-name", "F2A_APEX"] and args[3] == root
    assert kwargs == {"timeout": 120}
    commands = args[2]
    text = "\n".join(commands)
    assert commands.index("set transaction read only;") < next(i for i, s in enumerate(commands) if "target identity mismatch" in s)
    assert "mapping_total=1" in text and "r_owner=user" in text
    assert text.index("rollback;") < text.index("object_id=oid") < text.index("FOX_SCHEMA_END=1")
    assert "created=created_value and last_ddl_time=ddl_value" in text
    assert "from FOX_NATIVE_ORDERS" not in text
    assert "execute immediate" not in text.lower()
    assert not re.search(r"(?im)^\s*(create|alter|drop|insert|update|delete|grant|truncate)\s", text)
    assert list(root.iterdir()) == []  # Fake runner; probe does not persist provider output.


@pytest.mark.parametrize("code,stderr", [(1, ""), (-1, ""), (False, ""), (0, "sensitive-provider-text"), (0, None)])
def test_unsuccessful_sqlcl_cannot_supply_evidence(spec, settings, runner, code, stderr):
    runner.update(code=code, stderr=stderr)
    with pytest.raises(probe.ProbeError, match="^SCHEMA_OBSERVATION_UNCONFIRMED$"):
        probe.observe(settings, spec, settings.jobs_root / "synthetic-probe")


def test_provider_exception_is_not_exposed(spec, settings, runner):
    runner["exception"] = RuntimeError("provider credentials secret")
    with pytest.raises(probe.ProbeError) as caught:
        probe.observe(settings, spec, settings.jobs_root / "synthetic-probe")
    assert str(caught.value) == "SCHEMA_OBSERVATION_UNCONFIRMED"
    assert caught.value.__suppress_context__ is True


def test_invalid_target_spec_or_job_path_never_runs_sql(spec, settings, runner, tmp_path):
    with pytest.raises(probe.ProbeError, match="SCHEMA_JOB_ROOT_UNSAFE"):
        probe.observe(settings, spec, tmp_path)
    bad = deepcopy(spec)
    bad["table_name"] = "FOX_NATIVE_X'; DROP TABLE USERS;--"
    with pytest.raises(ValueError):
        probe.observe(settings, bad, settings.jobs_root / "synthetic-probe")
    settings.apex_workspace = "OTHER"
    with pytest.raises(TargetProfileError):
        probe.observe(settings, spec, settings.jobs_root / "synthetic-probe")
    assert runner["calls"] == []


def test_capability_api_is_read_only_and_separate_from_write_authority(settings, runner):
    runner["stdout"] = "\n".join(["FOX_SCHEMA_CAPABILITIES_BEGIN=1", identity(settings),
                                    "P|1|1|0", "Q|DATA|1|0|20971520", "FOX_SCHEMA_CAPABILITIES_END=1"])
    result = probe.capabilities(settings, settings.jobs_root / "synthetic-probe")
    assert result["read_only"] is True
    assert result["write_authorized"] is result["data_rows_read"] is False
    assert result["capabilities"]["creation_ready"] is True
    commands = runner["calls"][0][0][2]
    assert "set transaction read only;" in commands and commands[-1] == "rollback;"
    assert "execute immediate" not in "\n".join(commands).lower()


def test_create_builder_uses_only_canonical_ddl_and_sql_time_guards(spec, settings):
    commands = probe.create_commands(settings, spec, "a" * 32)
    text = "\n".join(commands)
    assert "set transaction read only;" not in commands
    assert "exact(n=0 and t=0 and public_count=0)" in text
    assert "table_priv=1 and sequence_priv=1 and default_space='DATA'" in text
    assert "mapping_total=1" in text
    assert text.index("target identity mismatch") < text.index("execute immediate")
    statements = re.findall(r"execute immediate '([^']*)';", text)
    expected = "CREATE TABLE " + render_native_schema(spec).split("CREATE TABLE ", 1)[1][:-2]
    assert statements == [expected]
    assert "CREATED|FOX_NATIVE_ORDERS|" + "a" * 32 in text
    assert not re.search(r"(?im)^\s*(alter|drop|insert|update|delete|grant|truncate)\s", text)
    changed = deepcopy(spec)
    changed["columns"][1]["label"] = 'Friendly "label"'
    assert probe.create_commands(settings, changed, "a" * 32) == commands


@pytest.mark.parametrize("token", [None, "", "A" * 32, "a" * 31, "a" * 33, "'; DROP TABLE X;--"])
def test_invalid_create_token_is_rejected(spec, settings, token):
    with pytest.raises(probe.ProbeError):
        probe.create_commands(settings, spec, token)


def creation_output(settings, token="a" * 32):
    return "\n".join(["FOX_SCHEMA_CREATE_BEGIN=1", identity(settings),
        "CREATED|FOX_NATIVE_ORDERS|" + token + "|9007199254740993|2026-10-25T01:00:00|2026-10-25T01:00:00",
        "FOX_SCHEMA_CREATE_END=1"]) + "\n"


def test_create_receipt_is_exact_and_still_requires_metadata_verification(spec, settings):
    result = probe.parse_create_output(creation_output(settings), spec, "a" * 32, settings)
    assert result["object_identity"]["object_id"] == "9007199254740993"
    assert result["created_in_this_sqlcl_execution"] is True
    assert result["metadata_verification_still_required"] is True
    assert result["schema_sha256"] == probe.schema_sha256(spec)


@pytest.mark.parametrize("old,new", [("a" * 32, "b" * 32), ("FOX_NATIVE_ORDERS", "FOX_NATIVE_OTHER"),
    ("9007199254740993", "01"), ("2026-10-25T01:00:00", "2026-99-25T01:00:00"),
    ("FOX_SCHEMA_CREATE_END=1", "FOX_SCHEMA_CREATE_END=1\nORA-00000 secret"),
    ("CREATED|", "NOT_CREATED|")])
def test_create_protocol_mismatch_is_not_success(spec, settings, old, new):
    with pytest.raises(probe.ProbeError):
        probe.parse_create_output(creation_output(settings).replace(old, new), spec, "a" * 32, settings)


def test_changed_object_identity_changes_the_observed_receipt(spec, settings):
    first = probe.parse_observation(observed(settings), spec, probe.target(settings))
    second = probe.parse_observation(observed(settings).replace("9007199254740993", "9007199254740994"),
                                     spec, probe.target(settings))
    assert first["object_identity"] != second["object_identity"]
    assert first["metadata_sha256"] == second["metadata_sha256"]
    # The registry must compare BOTH identity and metadata, not metadata alone.


@pytest.mark.parametrize("count,key_last", [(2, False), (20, False), (20, True)],
                         ids=["minimum-two", "maximum-twenty", "key-last"])
def test_column_count_and_key_position_boundaries(spec, settings, count, key_last):
    value = deepcopy(spec)
    value["columns"] = value["columns"][:count]
    for number in range(len(value["columns"]) + 1, count + 1):
        value["columns"].append({"name": "VALUE_" + str(number), "label": "Value " + str(number),
                                 "data_type": "NUMBER" if number % 2 else "DATE", "nullable": True})
    if key_last:
        value["columns"] = value["columns"][1:] + value["columns"][:1]
    original = observed(settings).splitlines()
    head = original[4].split("|")
    head[9] = str(count)
    columns = []
    for position, column in enumerate(value["columns"], 1):
        identity_column = column.get("identity", False)
        dtype = column["data_type"]
        columns.append("|".join(["C", str(position), str(position), column["name"], dtype,
            str(column.get("length", 22 if dtype == "NUMBER" else 7)), str(column.get("length", 0)),
            "B" if dtype == "VARCHAR2" else "-", "Y" if column["nullable"] else "N",
            "YES" if identity_column else "NO", "YES" if identity_column else "NO",
            "NO", "NO", "YES", "NONE", "-", "-", "IDENTITY_NEXTVAL" if identity_column else "NONE"]))
    result = probe.parse_observation("\n".join([*original[:4], "|".join(head), *columns, *original[8:]]),
                                     value, probe.target(settings))
    assert result["state"] == "EXACT"
    assert result["schema_sha256"] == probe.schema_sha256(value)
