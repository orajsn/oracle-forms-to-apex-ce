"""Read-only pre-import comparison of a native contract with the JSN schema.

The result is a point-in-time check of the listed table properties. It is not a
business-flow test, complete schema certification, or protection against a DDL
change after this check. No table data, passwords, trigger bodies, or arbitrary
source text is queried or persisted here. The caller may persist the safe return
value as import evidence and must still perform the guarded APEX import.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from .native_contract import validate_native_spec
from .sqlcl import _run_script, _target_guard


_WORKSPACE = "FORMS2APEX_POC"
_PREFIX = "FOX_NATIVE_"
_SCALARS = {"BEGIN", "TABLE_COUNT", "PK_COUNT", "ENABLED_TRIGGER_COUNT", "OK"}


def _parse_output(output):
    """Parse only complete protocol lines; never return untrusted output text."""
    if not isinstance(output, str) or len(output) > 100_000:
        raise RuntimeError("Native schema verification returned invalid output")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines or lines[0] != "FOX_NATIVE_BEGIN=1" or lines[-1] != "FOX_NATIVE_OK=1":
        raise RuntimeError("Native schema verification did not complete its marker protocol")
    scalars = {}
    columns = []
    primary_keys = []
    for line in lines:
        if not line.startswith(_PREFIX) or "=" not in line:
            raise RuntimeError("Native schema verification returned unrecognized output")
        key, value = line[len(_PREFIX):].split("=", 1)
        if key in _SCALARS:
            if key in scalars or not re.fullmatch(r"0|[1-9][0-9]*", value):
                raise RuntimeError("Native schema verification has duplicate or malformed marker counts")
            scalars[key] = int(value)
        elif key == "COLUMN":
            fields = value.split("|")
            if len(fields) != 5:
                raise RuntimeError("Native schema verification returned malformed column metadata")
            name, data_type, nullable, char_length, identity = fields
            if (not re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", name)
                    or data_type not in {"NUMBER", "VARCHAR2", "DATE"}
                    or nullable not in {"Y", "N"}
                    or not re.fullmatch(r"0|[1-9][0-9]*", char_length)
                    or identity not in {"YES", "NO"}):
                raise RuntimeError("Native schema verification returned unsupported column metadata")
            columns.append({"name": name, "data_type": data_type, "nullable": nullable == "Y",
                            "char_length": int(char_length), "identity": identity == "YES"})
        elif key == "PK":
            fields = value.split("|")
            if (len(fields) != 4 or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", fields[0])
                    or fields[1:] != ["1", "ENABLED", "VALIDATED"]):
                raise RuntimeError("Native schema verification requires one enabled and validated primary-key column")
            primary_keys.append(fields[0])
        else:
            raise RuntimeError("Native schema verification returned an unknown marker")
    if set(scalars) != _SCALARS or scalars["BEGIN"] != 1 or scalars["OK"] != 1:
        raise RuntimeError("Native schema verification is missing required completion markers")
    return scalars, columns, primary_keys


def verify_native_schema(settings, spec, job_root) -> dict:
    """Compare existing JSN table metadata; return a safe receipt or fail closed.

    Only the configured saved connection is used, never a supplied password or
    connection URL. The existing JSN database guard is retained and this initial
    proof additionally pins the parsing schema to FORMS2APEX_POC.
    """
    normalized = validate_native_spec(spec)
    workspace = settings.apex_workspace
    connection_name = settings.sqlcl_connection_name
    if workspace != _WORKSPACE:
        raise ValueError("Native schema verification is restricted to FORMS2APEX_POC in JSN")
    if not isinstance(connection_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", connection_name):
        raise ValueError("Native schema verification requires a named saved SQLcl connection")
    root = Path(job_root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Native schema verification requires an existing regular job directory")
    table_name = normalized["table_name"]  # Strict unquoted identifier validated above.
    commands = [
        "set sqlformat default",
        "set pagesize 0",
        "set linesize 32767",
        "set trimout on",
        "set define off",
        "whenever oserror exit failure rollback",
        _target_guard(workspace),
        "select 'FOX_NATIVE_BEGIN=1' from dual;",
        "select 'FOX_NATIVE_TABLE_COUNT=' || to_char(count(*), 'TM9') from user_tables "
        f"where table_name = '{table_name}';",
        "select 'FOX_NATIVE_COLUMN=' || column_name || '|' || data_type || '|' || nullable || '|' "
        "|| to_char(nvl(char_length, 0), 'TM9') || '|' || identity_column "
        f"from user_tab_columns where table_name = '{table_name}' order by column_id;",
        "select 'FOX_NATIVE_PK_COUNT=' || to_char(count(*), 'TM9') from user_constraints "
        f"where table_name = '{table_name}' and constraint_type = 'P';",
        "select 'FOX_NATIVE_PK=' || cc.column_name || '|' || to_char(cc.position, 'TM9') || '|' "
        "|| c.status || '|' || c.validated from user_constraints c join user_cons_columns cc "
        "on cc.constraint_name = c.constraint_name and cc.table_name = c.table_name "
        f"where c.table_name = '{table_name}' and c.constraint_type = 'P' "
        "order by c.constraint_name, cc.position;",
        "select 'FOX_NATIVE_ENABLED_TRIGGER_COUNT=' || to_char(count(*), 'TM9') from user_triggers "
        f"where table_name = '{table_name}' and table_owner = user and status = 'ENABLED';",
        "select 'FOX_NATIVE_OK=1' from dual;",
    ]
    result = _run_script(
        settings.sqlcl_path, ["-S", "-L", "-name", connection_name], commands, root, timeout=120,
    )
    if result.returncode != 0 or not isinstance(result.stderr, str) or result.stderr.strip():
        raise RuntimeError("Native schema verification SQLcl execution failed; no import is permitted")
    scalars, columns, primary_keys = _parse_output(result.stdout)
    if scalars["TABLE_COUNT"] != 1:
        raise RuntimeError("The native target table was not proven to exist exactly once")
    expected_columns = [
        {"name": column["name"], "data_type": column["data_type"], "nullable": column["nullable"],
         "char_length": column.get("length", 0), "identity": column["identity"]}
        for column in normalized["columns"]
    ]
    if columns != expected_columns:
        raise RuntimeError("The native target columns do not exactly match the reviewed contract")
    expected_key = next(column["name"] for column in normalized["columns"] if column["primary_key"])
    if scalars["PK_COUNT"] != 1 or primary_keys != [expected_key]:
        raise RuntimeError("The native target primary key does not exactly match the reviewed contract")
    if scalars["ENABLED_TRIGGER_COUNT"] != 0:
        raise RuntimeError("Enabled table triggers are outside the native proof profile")
    spec_hash = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":"),
                                          ensure_ascii=False).encode("utf-8")).hexdigest()
    return {
        "passed": True,
        "scope": "native_table_metadata_preimport",
        "profile_id": normalized["profile_id"],
        "data_mode": normalized["data_mode"],
        "workspace": workspace,
        "table_name": table_name,
        "spec_sha256": spec_hash,
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "columns": columns,
        "primary_key": {"columns": [expected_key], "status": "ENABLED", "validated": "VALIDATED"},
        "enabled_trigger_count": 0,
        "target_guard": "existing_jsn_database_and_parsing_schema",
        "business_behavior_verified": False,
    }
