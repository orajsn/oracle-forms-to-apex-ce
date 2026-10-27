"""Strict metadata contract for the first synthetic native APEX table-form proof.

Accepted JSON shape::

    {
        "profile_id": "native-table-form-v1",
        "data_mode": "synthetic_test_only",
        "table_name": "FOX_NATIVE_ORDERS",
        "columns": [
            {"name": "ORDER_ID", "data_type": "NUMBER", "nullable": false,
             "label": "Order ID", "primary_key": true, "identity": true},
            {"name": "DESCRIPTION", "data_type": "VARCHAR2", "nullable": false,
             "label": "Description", "length": 100}
        ]
    }

All shown fields are required except primary_key and identity, which default to
false. VARCHAR2 requires length; NUMBER and DATE must not supply it. Exactly one
column must be a non-null NUMBER identity primary key. No arbitrary SQL, PL/SQL,
HTML, customer data, or other schema metadata is accepted. The optional root
supported_operations field must exactly equal ["query", "insert", "update"].
The normalized result always includes it, so validation is idempotent.

This validates a proposed synthetic schema contract, NOT supplied/live DDL, a
database connection, customer compatibility, or business behavior. Renderers
must still encode labels for their output syntax; this is not an SQL escaper.
"""

import re
import unicodedata


PROFILE_ID = "native-table-form-v1"
DATA_MODE = "synthetic_test_only"
SUPPORTED_OPERATIONS = ("query", "insert", "update")

_IDENTIFIER = re.compile(r"[A-Z][A-Z0-9_]{0,29}\Z")
# Conservative profile exclusions, not a claim to implement Oracle's full SQL
# parser. Canonical generation and SQLcl validation are separate required steps.
_EXCLUDED_IDENTIFIERS = frozenset(
    "ACCESS ADD ALL ALTER AND ANY AS ASC AUDIT BETWEEN BY CHAR CHECK CLUSTER "
    "COLUMN COMMENT COMPRESS CONNECT CREATE CURRENT DATE DECIMAL DEFAULT DELETE "
    "DESC DISTINCT DROP ELSE EXCLUSIVE EXISTS FILE FLOAT FOR FROM GRANT GROUP "
    "HAVING IDENTIFIED IMMEDIATE IN INCREMENT INDEX INITIAL INSERT INTEGER "
    "INTERSECT INTO IS LEVEL LIKE LOCK LONG MAXEXTENTS MINUS MLSLABEL MODE "
    "MODIFY NOAUDIT NOCOMPRESS NOT NOWAIT NULL NUMBER OF OFFLINE ON ONLINE "
    "OPTION OR ORDER PCTFREE PRIOR PRIVILEGES PUBLIC RAW RENAME RESOURCE REVOKE "
    "ROW ROWID ROWNUM ROWS SELECT SESSION SET SHARE SIZE SMALLINT START "
    "SUCCESSFUL SYNONYM SYSDATE TABLE THEN TO TRIGGER UID UNION UNIQUE UPDATE "
    "USER VALIDATE VALUES VARCHAR VARCHAR2 VIEW WHENEVER WHERE WITH "
    "PRIMARY KEY IDENTITY CONSTRAINT".split()
)
_ROOT_REQUIRED = {"profile_id", "data_mode", "table_name", "columns"}
_ROOT_OPTIONAL = {"supported_operations"}
_COLUMN_REQUIRED = {"name", "data_type", "nullable", "label"}
_COLUMN_OPTIONAL = {"primary_key", "identity", "length"}
_LABEL_SQL = re.compile(
    r"\b(?:SELECT\b.+\bFROM|INSERT\s+INTO|UPDATE\b.+\bSET|DELETE\s+FROM|"
    r"(?:CREATE|ALTER|DROP)\s+(?:TABLE|VIEW|PROCEDURE|FUNCTION|USER|INDEX)|"
    r"EXECUTE\s+IMMEDIATE|BEGIN\b.+\bEND)\b",
    re.IGNORECASE,
)


def _fields(value, required, optional, location):
    if not isinstance(value, dict):
        raise ValueError(f"{location} must be a JSON object")
    if not required.issubset(value):
        raise ValueError(f"{location} is missing required metadata")
    if set(value) - required - optional:
        raise ValueError(f"{location} has unsupported metadata")


def _identifier(value, location):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{location} must be an uppercase unquoted identifier of at most 30 characters")
    if value in _EXCLUDED_IDENTIFIERS:
        raise ValueError(f"{location} is excluded by the native identifier profile")
    return value


def _boolean(value, location):
    if type(value) is not bool:
        raise ValueError(f"{location} must be an explicit JSON boolean")
    return value


def _label(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 80 or not value.strip():
        raise ValueError("Column label must be plain text of 1 to 80 characters")
    if any(unicodedata.category(char).startswith("C") or unicodedata.category(char) in ("Zl", "Zp")
           for char in value):
        raise ValueError("Column label must not contain control or formatting characters")
    if any(token in value for token in ("<", ">", "`", ";", "--", "/*", "*/", "{", "}")):
        raise ValueError("Column label must not contain markup or executable text")
    if _LABEL_SQL.search(value):
        raise ValueError("Column label must not contain SQL or procedural text")
    return value.strip()


def validate_native_spec(value):
    """Return normalized synthetic metadata or raise ValueError; perform no I/O.

    Omitted keys, unknown fields, unsupported types, or ambiguous key metadata
    fail closed. Success is only contract validation, never live-schema proof.
    """
    _fields(value, _ROOT_REQUIRED, _ROOT_OPTIONAL, "Native spec")
    if value["profile_id"] != PROFILE_ID:
        raise ValueError("Unsupported native profile")
    if value["data_mode"] != DATA_MODE:
        raise ValueError("The native proof requires synthetic_test_only data mode")
    table_name = _identifier(value["table_name"], "Table name")
    if not table_name.startswith("FOX_NATIVE_"):
        raise ValueError("Synthetic native table names must begin with FOX_NATIVE_")
    if "supported_operations" in value and (
        not isinstance(value["supported_operations"], list)
        or value["supported_operations"] != list(SUPPORTED_OPERATIONS)
    ):
        raise ValueError("The native proof supports only query, insert and update, in that order")
    source_columns = value["columns"]
    if not isinstance(source_columns, list) or not 2 <= len(source_columns) <= 20:
        raise ValueError("Native spec requires between 2 and 20 columns")

    columns = []
    names = set()
    key_count = 0
    for source in source_columns:
        _fields(source, _COLUMN_REQUIRED, _COLUMN_OPTIONAL, "Column")
        name = _identifier(source["name"], "Column name")
        if name in names:
            raise ValueError("Native column names must be unique")
        names.add(name)
        data_type = source["data_type"]
        if not isinstance(data_type, str) or data_type not in ("NUMBER", "VARCHAR2", "DATE"):
            raise ValueError("Native columns support only NUMBER, VARCHAR2 and DATE")
        nullable = _boolean(source["nullable"], "Column nullable")
        primary_key = _boolean(source.get("primary_key", False), "Column primary_key")
        identity = _boolean(source.get("identity", False), "Column identity")
        label = _label(source["label"])
        if primary_key != identity or (primary_key and (data_type != "NUMBER" or nullable)):
            raise ValueError("A primary key must be a non-null NUMBER identity column; no other identities are supported")
        if primary_key:
            key_count += 1
        column = {
            "name": name,
            "data_type": data_type,
            "nullable": nullable,
            "label": label,
            "primary_key": primary_key,
            "identity": identity,
        }
        if data_type == "VARCHAR2":
            length = source.get("length")
            if type(length) is not int or not 1 <= length <= 4000:
                raise ValueError("VARCHAR2 requires an integer length from 1 to 4000")
            column["length"] = length
        elif "length" in source:
            raise ValueError("Length is supported only for VARCHAR2 columns")
        columns.append(column)

    if key_count != 1:
        raise ValueError("Native spec requires exactly one explicit NUMBER identity primary key")
    return {
        "profile_id": PROFILE_ID,
        "data_mode": DATA_MODE,
        "table_name": table_name,
        "columns": columns,
        "supported_operations": list(SUPPORTED_OPERATIONS),
    }
