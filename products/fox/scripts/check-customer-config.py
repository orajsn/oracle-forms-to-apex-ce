#!/usr/bin/env python3
"""Offline customer draft linting. No connection, activation or apply capability.

Only the explicitly selected config and optional non-secret local evidence files
are read. All configuration paths, URLs, connection names and secret references
are inert strings. The embedded schema avoids implicit schema/network reads.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit


DOCUMENT_TYPE = "fox-customer-installation-draft-v1"
MAX_BYTES = 1_048_576
LAB_VERSIONS = {
    "apex": "26.1.5", "database": "23.26.4.1.0", "sqlcl": "26.1.2.0",
    "apexlang_mmd": "26.1.0+3102", "opaf": "26.4.0.0.0",
}


def obj(**properties):
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def text_field(kind="identifier", **extra):
    return {"type": ["string", "null"], "minLength": 1, "maxLength": 512,
            "x-check": kind, **extra}


def choice(*values):
    return {"type": ["string", "null"], "enum": [*values, None]}


def fixed(value):
    return {"type": {bool: "boolean", int: "integer", str: "string"}[type(value)], "const": value}


def role():
    return obj(workflow_id=text_field(), model=text_field(), graph_sha256=text_field("sha256"))


SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:fox:customer-installation-draft:v1",
    "title": "Inactive FOX customer installation preparation (not a runtime profile)",
    **obj(
        document_type=fixed(DOCUMENT_TYPE), schema_version=fixed(1),
        active=fixed(False), deployment_authorized=fixed(False),
        customer=obj(name=text_field("label"), customer_owner=text_field("label"),
                     technical_owner=text_field("label"), dba_owner=text_field("label"),
                     approver_owner=text_field("label")),
        scope=obj(conversion_profile=fixed("native-table-form-v1"),
                  data_mode=fixed("synthetic_test_only"),
                  customer_deployment_authorized=fixed(False), existing_resources_only=fixed(True)),
        oci=obj(tenancy_id=text_field("tenancy_ocid"), compartment_id=text_field("compartment_ocid"),
                database_id=text_field("database_ocid"), instance_id=text_field("instance_ocid"),
                region=text_field("region")),
        database=obj(deployment_type=choice("autonomous_database", "oci_base_database",
                     "exadata_cloud_service", "exadata_cloud_at_customer", "existing_oracle_database"),
                     db_name=text_field(), session_user=text_field(), parsing_schema=text_field()),
        apex=obj(workspace=text_field(), workspace_id=text_field("decimal"),
                 ords_origin=text_field("origin"), ords_base_path=text_field("url_path"),
                 certificate_sha256=text_field("sha256")),
        versions=obj(**{name: text_field("version") for name in LAB_VERSIONS},
                     forms=text_field("version"), java=text_field("version"), ords=text_field("version")),
        forms=obj(extraction_route=choice("local_oracle_forms", "preconverted_oracle_forms", "approved_oracle_worker"),
                  platform=choice("windows", "linux", "macos"),
                  oracle_home_reference=text_field(), entitlement_review_reference=text_field(),
                  platform_review_reference=text_field(), extraction_evidence_reference=text_field()),
        sqlcl=obj(saved_connection=text_field(), wallet_reference=text_field("secret_ref"),
                  credential_reference=text_field("secret_ref")),
        opaf=obj(base_url=text_field("url"), certificate_sha256=text_field("sha256"),
                 model_authentication=choice("oci_instance_principal", "oci_resource_principal", "opaque_secret_reference"),
                 model_credential_reference=text_field("secret_ref"),
                 authentication_secret_reference=text_field("secret_ref"),
                 version_number={"type": ["integer", "null"], "minimum": 1},
                 build_id={"type": ["integer", "null"], "minimum": 1},
                 processing_approval_reference=text_field(), roles=obj(mapper=role(), reviewer=role())),
        operations=obj(owner=text_field("label"),
                       persistent_locations=obj(fox_data=text_field("local_path"), converter_jobs=text_field("local_path"),
                                                evidence=text_field("local_path"), logs=text_field("local_path"), backups=text_field("local_path")),
                       release_hashes=obj(fox_sha256=text_field("sha256"), converter_sha256=text_field("sha256"),
                                          opaf_graph_bundle_sha256=text_field("sha256")),
                       backup_reference=text_field(), backup_evidence_reference=text_field(),
                       rollback_owner=text_field("label"), rollback_reference=text_field(),
                       maintenance_approval_reference=text_field()),
    ),
}

# x-check is a deliberately small, embedded semantic-validation vocabulary, not
# arbitrary code or JSON Schema remote-reference evaluation. Standard validators
# can check structure; this checker also applies x-check and cross-field rules.
PATTERNS = {
    "identifier": r"[A-Za-z0-9][A-Za-z0-9_.:@+\-]{0,127}",
    "label": r"[^\x00-\x1f\x7f=;/\\]{1,160}",
    "sha256": r"[0-9a-f]{64}",
    "version": r"[0-9]+(?:\.[0-9]+)*(?:\+[0-9]+)?",
    "decimal": r"[1-9][0-9]{0,29}",
    "region": r"[a-z]{2,3}-[a-z0-9]+-[1-9][0-9]*",
    "secret_ref": r"secret://[A-Za-z0-9][A-Za-z0-9._\-]*(?:/[A-Za-z0-9][A-Za-z0-9._\-]*)+",
    "url_path": r"/(?:[A-Za-z0-9_\-]+/?)*",
}
SECRET_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:password|passwd|pwd|token|api[_ -]?key|client[_ -]?secret)\s*[:=]|"
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_\-.]+|https?://[^\s/]+@|\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    re.IGNORECASE,
)


def _local_path(value, *, absolute=False):
    # Reject UNC, URI, device and drive-relative paths before any file operation.
    if not isinstance(value, str) or not value or re.search(r"[\x00-\x1f\x7f]", value):
        return False
    if value.startswith(("\\", "//", "~")) or "://" in value or "%" in value or "$" in value:
        return False
    normalized = value.replace("\\", "/")
    if normalized in ("/dev", "/proc", "/sys") or normalized.startswith(("/dev/", "/proc/", "/sys/")):
        return False
    for component in normalized.split("/"):
        if re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", component.split(".", 1)[0].rstrip(" "), re.IGNORECASE):
            return False
    if re.match(r"^[A-Za-z]:", value):
        return bool(re.fullmatch(r"[A-Za-z]:[\\/][^:*?<>|\"]+", value))
    if ":" in value:
        return False
    return not absolute or normalized.startswith("/")


def _semantic(value, kind):
    if SECRET_PATTERN.search(value):
        return False
    if kind in PATTERNS:
        return bool(re.fullmatch(PATTERNS[kind], value, re.ASCII)) and value == value.strip()
    if kind == "local_path":
        return _local_path(value, absolute=True)
    if kind.endswith("_ocid"):
        resource = {"tenancy_ocid": "tenancy", "compartment_ocid": "compartment",
                    "database_ocid": "(?:autonomousdatabase|database)", "instance_ocid": "instance"}[kind]
        return bool(re.fullmatch(r"ocid1\." + resource + r"\.oc[1-9][0-9]*\.[a-z0-9]*\.[a-z0-9]{8,}", value))
    if kind in ("url", "origin"):
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname or ""
            try:
                ipaddress.ip_address(hostname)
                host_valid = True
            except ValueError:
                host_valid = len(hostname) <= 253 and all(
                    re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?", part)
                    for part in hostname.split("."))
            valid = (parsed.scheme == "https" and parsed.hostname and parsed.username is None
                     and parsed.password is None and not parsed.query and not parsed.fragment
                     and host_valid and not re.search(r"[\s\\%]", value) and parsed.port != 0
                     and re.fullmatch(r"/(?:[A-Za-z0-9_.\-]+/?)*|", parsed.path))
            return bool(valid and (kind != "origin" or parsed.path in ("", "/")))
        except ValueError:
            return False
    return False


def _validate(value, schema, path, errors, missing):
    types = schema["type"]
    types = types if isinstance(types, list) else [types]
    actual = {dict: "object", str: "string", int: "integer", bool: "boolean", type(None): "null"}.get(type(value))
    if actual not in types:
        errors.append({"field": path, "action": "Use the documented JSON type; unknown values must be null."})
        return
    if "const" in schema and value != schema["const"]:
        errors.append({"field": path, "action": "Restore the fixed inactive draft value; activation is not supported."})
    if "enum" in schema and value not in schema["enum"]:
        errors.append({"field": path, "action": "Choose a documented enum value or null."})
    if actual == "object":
        props = schema["properties"]
        if set(value) - set(props):
            # Never echo untrusted unknown keys, which may themselves hold secrets.
            errors.append({"field": path, "action": "Remove unsupported fields; do not include credentials or free-form commands."})
        for name, child in props.items():
            location = f"{path}.{name}" if path else name
            if name not in value:
                errors.append({"field": location, "action": "Add the required field; use null if unknown."})
            else:
                _validate(value[name], child, location, errors, missing)
    elif value is None:
        missing.append({"field": path, "action": "Record the customer-confirmed value or non-secret reference; do not invent it."})
    elif actual == "integer" and value < schema.get("minimum", value):
        errors.append({"field": path, "action": "Use a positive integer or null."})
    elif actual == "string" and (not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", MAX_BYTES)
                                  or ("x-check" in schema and not _semantic(value, schema["x-check"]))):
        errors.append({"field": path, "action": "Use a valid non-secret value in the documented format, or null."})


def _plan():
    install = [
        "Confirm customer, technical, DBA and approver ownership; review all missing fields and evidence.",
        "Obtain separate written authorization for the exact existing resources, work window and any later connection or change.",
        "Have authorized owners verify target ownership, versions, platform and Forms entitlement references; separately validate version differences.",
        "Have authorized owners confirm Oracle Forms extraction route, source approval and model data-processing approval before any source processing.",
        "Have authorized operators verify backup and recovery evidence, release hashes, persistent locations, TLS pins and distinct OPAF roles.",
        "Prepare a separately reviewed customer deployment design and execution procedure; this draft cannot become an active JSN profile.",
        "Only under new explicit execution approval, validate saved connections and secret bindings through approved tools, then stage the approved release.",
        "Only under that approval, run agreed synthetic acceptance checks and obtain customer sign-off before any real workload.",
    ]
    rollback = [
        "Obtain rollback-owner authorization and confirm the exact affected resources and recovery point.",
        "Preserve diagnostic evidence and stop only the explicitly approved workload using a separately reviewed procedure.",
        "Have authorized operators restore the approved release and backup using the reviewed recovery procedure; this checklist performs no restore.",
        "Have the DBA and customer owner verify recovery criteria and record the outcome before resuming work.",
    ]
    return {name: [{"order": index, "executable": False, "authorization": "SEPARATE_APPROVAL_REQUIRED", "task": task}
                   for index, task in enumerate(tasks, 1)] for name, tasks in (("installation", install), ("rollback", rollback))}


def _result(errors, missing, *, include_plan=False):
    result = {"document_type": DOCUMENT_TYPE, "status": "INVALID" if errors else "INCOMPLETE" if missing else "CONFIGURATION_COMPLETE_NOT_AUTHORIZED",
              "connection_authorized": False, "apply_available": False, "changes_performed": False,
              "customer_compatibility_certified": False, "errors": errors, "missing_fields": missing,
              "evidence_files": [], "scope": "offline_syntax_and_completeness_only"}
    if include_plan:
        result["plan"] = _plan()
    return result


def check_config(value, *, include_plan=False):
    """Pure validation. Never resolves URLs, paths, secrets, connections or IDs."""
    errors, missing = [], []
    _validate(value, SCHEMA, "", errors, missing)
    if not errors:
        opaf = value["opaf"]
        if opaf["model_authentication"] in ("oci_instance_principal", "oci_resource_principal"):
            missing = [item for item in missing if item["field"] != "opaf.model_credential_reference"]
            if opaf["model_credential_reference"] is not None:
                errors.append({"field": "opaf.model_credential_reference", "action": "Use null for principal-based authentication; this checker never resolves credentials."})
        roles = opaf["roles"]
        for key in ("workflow_id", "graph_sha256"):
            if roles["mapper"][key] is not None and roles["mapper"][key] == roles["reviewer"][key]:
                errors.append({"field": f"opaf.roles.reviewer.{key}", "action": "Record the distinct reviewer workflow and graph, not the mapper workflow."})
        if value["forms"]["extraction_route"] == "local_oracle_forms" and value["forms"]["platform"] == "macos":
            errors.append({"field": "forms.extraction_route", "action": "Record a reviewed Oracle extraction route; do not claim local binary extraction on macOS."})
    result = _result(errors, missing, include_plan=include_plan)
    versions = value.get("versions", {}) if type(value) is dict else {}
    if type(versions) is not dict:
        versions = {}
    different = [key for key, expected in LAB_VERSIONS.items() if isinstance(versions.get(key), str) and versions[key] != expected]
    unknown = [key for key in LAB_VERSIONS if not isinstance(versions.get(key), str)]
    result["version_review"] = {"tested_lab_tuple": dict(LAB_VERSIONS),
        "lab_version_match": not errors and not different and not unknown,
        "different_components": different, "unknown_components": unknown,
        "separate_validation_required": True,
        "meaning": "A declared lab-version match is not customer compatibility certification; customer-specific validation is always required."}
    return result


class InputError(ValueError):
    """Bounded message; never include supplied values or file contents."""


def _read_local_file(raw_path, *, evidence=False):
    if not _local_path(str(raw_path)):
        raise InputError("Use an explicit local regular file; remote, secret, UNC and device paths are not allowed.")
    path = Path(raw_path).absolute()
    suffixes = (".json", ".md", ".txt") if evidence else (".json",)
    if path.suffix.lower() not in suffixes:
        raise InputError("Use JSON configuration or explicitly selected non-secret JSON, Markdown or text evidence; never wallet/key files.")
    try:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise InputError("Linked file paths are not allowed.")
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise InputError("Input must be a regular file within the 1 MiB limit.")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise InputError("Input changed while opening; retry with a stable local file.")
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InputError("Input exceeds the 1 MiB limit.")
        text = raw.decode("utf-8")
        if evidence and SECRET_PATTERN.search(text):
            raise InputError("Evidence contains credential-like content; select a redacted non-secret copy.")
        return raw
    except (OSError, UnicodeError, RuntimeError):
        raise InputError("Input is unavailable or not readable UTF-8; use a bounded non-secret local file.") from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON fields are not allowed.")
        result[key] = value
    return result


def _nonfinite(_value):
    raise InputError("Non-finite JSON numbers are not allowed.")


def check_file(config_path, *, evidence_paths=(), include_plan=False):
    """Only these explicit input files may be opened; no config refs are followed."""
    try:
        raw = _read_local_file(config_path)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_nonfinite)
        result = check_config(value, include_plan=include_plan)
        # Do not read further input for an invalid document.
        if result["status"] != "INVALID":
            for index, path in enumerate(evidence_paths, 1):
                evidence = _read_local_file(path, evidence=True)
                result["evidence_files"].append({"input_index": index, "sha256": hashlib.sha256(evidence).hexdigest(),
                                                 "bytes": len(evidence), "meaning": "local content integrity only; not approval or authenticity"})
        return result
    except InputError as error:
        return _result([{"field": "input", "action": str(error)}], [], include_plan=include_plan)
    except (ValueError, TypeError, RecursionError):
        return _result([{"field": "input", "action": "Use well-formed bounded JSON without duplicate fields or non-finite numbers."}], [], include_plan=include_plan)


class OfflineArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse's default error echoes unknown arguments, potentially secrets.
        raise InputError("Use a config path with optional --plan and --evidence only; no connection, activation or apply mode exists.")


def main(argv=None):
    parser = OfflineArgumentParser(description=__doc__)
    parser.add_argument("config", help="Inactive customer draft JSON; never a runtime profile")
    parser.add_argument("--plan", action="store_true", help="Include ordered non-executable installation and rollback checklists")
    parser.add_argument("--evidence", action="append", default=[], metavar="LOCAL_FILE", help="Explicit non-secret local evidence to hash only; repeatable")
    try:
        args = parser.parse_args(argv)
        result = check_file(args.config, evidence_paths=args.evidence, include_plan=args.plan)
    except InputError as error:
        result = _result([{"field": "arguments", "action": str(error)}], [])
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return {"INVALID": 2, "INCOMPLETE": 1, "CONFIGURATION_COMPLETE_NOT_AUTHORIZED": 0}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
