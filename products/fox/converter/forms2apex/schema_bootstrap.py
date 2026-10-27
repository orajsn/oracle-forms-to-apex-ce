"""Managed, create-only synthetic schema preparation.

This is an internal converter API, not an endpoint or a general SQL executor.
The caller supplies a trusted authorization function which verifies the real
source, sealed review, successful APEXlang validation and fresh target receipt.
It must return the exact request after checking it; booleans are not authority.
No credentials, uploaded SQL or model-produced code are accepted here.

Registry files live under the existing jobs volume. An OS lease serializes all
table preparation, including different jobs naming the same physical table.
Unknown CREATE outcomes are retained and never replayed. A complete CREATE
response can be checked read-only and then finalized by a subsequent explicit
prepare call without executing DDL again. A missing response cannot establish
ownership merely because a matching table happens to exist.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from fox_source_contract import project_conversion as storage_contract

from . import schema_probe as probe
from .native_contract import validate_native_spec
from .native_schema import render_native_schema
from .security import validate_job_id
from .sqlcl import _run_script


MAX_TABLES = 50
MAX_RECORD_BYTES = 1_000_000
REGISTRY_NAME = ".native-schema"
RECEIPT_NAME = "schema-preparation.json"
STARTED_NAME = "schema-preparation-started.json"
INDEX_NAME = ".native-schema-index.json"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_BINDING_KEYS = {"job_id", "source_manifest_sha256", "artifact_binding_sha256",
                 "review_receipts_sha256", "validated_draft_sha256"}
_PHYSICAL_KEYS = ("compartment_id", "database_id", "region", "db_name",
                  "session_user", "parsing_schema", "workspace", "workspace_id")


class SchemaPreparationError(RuntimeError):
    """A bounded diagnostic; never embed SQLcl output or connection details."""
    def __init__(self, code, *, table_name=None, completed_tables=()):
        super().__init__(code)
        self.code = code
        self.table_name = table_name
        self.completed_tables = tuple(completed_tables)
        self.automatic_replay_permitted = False


def _need(ok, code):
    if not ok:
        raise SchemaPreparationError(code)


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise SchemaPreparationError("SCHEMA_RECORD_INVALID") from None


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _hash(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _same(left, right):
    return _canonical(left) == _canonical(right)


def _safe(path, *, exists=True):
    path = Path(os.path.abspath(path))
    _need(not str(path).startswith(("\\\\", "//")), "SCHEMA_LOCAL_STORAGE_REQUIRED")
    for member in (path, *path.parents):
        try:
            info = member.lstat()
        except FileNotFoundError:
            continue
        _need(not stat.S_ISLNK(info.st_mode)
              and not getattr(info, "st_file_attributes", 0) & 0x400,
              "SCHEMA_LINKED_STORAGE_FORBIDDEN")
        _need(stat.S_ISDIR(info.st_mode) or
              stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
              "SCHEMA_STORAGE_TYPE_INVALID")
    _need(not exists or path.exists(), "SCHEMA_STORAGE_UNAVAILABLE")
    return path


def _directory(path):
    path = _safe(path, exists=False)
    _need(path.parent.is_dir(), "SCHEMA_STORAGE_PARENT_UNAVAILABLE")
    try:
        path.mkdir(mode=0o700)
        _sync(path.parent)
    except FileExistsError:
        pass
    _need(_safe(path).is_dir(), "SCHEMA_REGISTRY_DIRECTORY_REQUIRED")
    _owner(path)
    return path


def _owner(path):
    if os.name != "nt":
        info = path.stat()
        _need(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022,
              "SCHEMA_REGISTRY_OWNER_REQUIRED")


def _present(path):
    """Dangling links are unsafe evidence, never an absent operation."""
    _safe(path, exists=False)
    return os.path.lexists(path)


def _sync(path):
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _new(path, value):
    """Exclusive, durable record. A partial record is preserved and blocks use."""
    path = _safe(path, exists=False)
    raw = _canonical({**value, "record_sha256": _digest(value)}) + b"\n"
    _need(len(raw) <= MAX_RECORD_BYTES, "SCHEMA_RECORD_TOO_LARGE")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _sync(path.parent)
    except FileExistsError:
        raise SchemaPreparationError("SCHEMA_RECORD_ALREADY_EXISTS") from None
    except OSError:
        raise SchemaPreparationError("SCHEMA_RECORD_WRITE_UNCONFIRMED") from None
    return hashlib.sha256(raw).hexdigest()


def _pairs(values):
    result = {}
    for key, value in values:
        _need(key not in result, "SCHEMA_DUPLICATE_RECORD_FIELD")
        result[key] = value
    return result


def _read(path):
    path = _safe(path)
    _owner(path)
    info = path.stat()
    _need(path.is_file() and info.st_nlink == 1 and 0 < info.st_size <= MAX_RECORD_BYTES,
          "SCHEMA_RECORD_UNSAFE")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            _need((opened.st_dev, opened.st_ino, opened.st_size) ==
                  (info.st_dev, info.st_ino, info.st_size), "SCHEMA_RECORD_CHANGED")
            raw = stream.read(MAX_RECORD_BYTES + 1)
    except OSError:
        raise SchemaPreparationError("SCHEMA_RECORD_UNAVAILABLE") from None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _need(type(value) is dict and _hash(value.get("record_sha256")),
              "SCHEMA_RECORD_INVALID")
        payload = {key: item for key, item in value.items() if key != "record_sha256"}
        _need(len(raw) == info.st_size and raw == _canonical(value) + b"\n"
              and value["record_sha256"] == _digest(payload), "SCHEMA_RECORD_CHANGED")
        return payload, hashlib.sha256(raw).hexdigest()
    except (UnicodeError, ValueError, TypeError):
        raise SchemaPreparationError("SCHEMA_RECORD_INVALID") from None


@contextmanager
def _lease(registry, *, create):
    """Real byte-zero Windows lock or POSIX flock; no stale-lock deletion."""
    registry = _directory(registry) if create else _safe(registry)
    _need(registry.is_dir(), "SCHEMA_REGISTRY_DIRECTORY_REQUIRED")
    _owner(registry)
    path = registry / "registry.lock"
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    locked = False
    try:
        try:
            if create:
                try:
                    descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
                    os.write(descriptor, b"0")
                    os.fsync(descriptor)
                    _sync(registry)
                except FileExistsError:
                    descriptor = os.open(_safe(path), flags)
            else:
                descriptor = os.open(_safe(path), flags)
            info = os.fstat(descriptor)
            _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 1,
                  "SCHEMA_LOCK_UNSAFE")
            _owner(path)
            _need((path.stat().st_dev, path.stat().st_ino) == (info.st_dev, info.st_ino),
                  "SCHEMA_LOCK_CHANGED")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            raise SchemaPreparationError("SCHEMA_PREPARATION_BUSY_OR_LOCK_UNAVAILABLE") from None
        yield
    finally:
        if locked:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        if descriptor is not None:
            os.close(descriptor)


def _binding(value):
    _need(type(value) is dict and set(value) == _BINDING_KEYS,
          "SCHEMA_SOURCE_BINDING_REQUIRED")
    try:
        validate_job_id(value["job_id"])
    except (TypeError, ValueError):
        raise SchemaPreparationError("SCHEMA_SOURCE_BINDING_REQUIRED") from None
    _need(all(_hash(value[key]) for key in _BINDING_KEYS - {"job_id"}),
          "SCHEMA_SOURCE_BINDING_REQUIRED")
    return deepcopy(value)


def _scope(target):
    _need(type(target) is dict and all(type(target.get(key)) is str and target[key]
                                     for key in _PHYSICAL_KEYS),
          "SCHEMA_TARGET_BINDING_REQUIRED")
    return {key: target[key] for key in _PHYSICAL_KEYS}


def _identity(value):
    _need(type(value) is dict and set(value) == {"object_id", "created", "last_ddl_time"}
          and type(value["object_id"]) is str
          and re.fullmatch(r"[1-9][0-9]{0,19}", value["object_id"]),
          "SCHEMA_OBJECT_IDENTITY_INVALID")
    for key in ("created", "last_ddl_time"):
        try:
            _need(type(value[key]) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", value[key]),
                  "SCHEMA_OBJECT_IDENTITY_INVALID")
            datetime.strptime(value[key], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            raise SchemaPreparationError("SCHEMA_OBJECT_IDENTITY_INVALID") from None
    return deepcopy(value)


def _storage_mapping(value, spec):
    """Recompute source ownership from typed metadata, not declared digests."""
    try:
        _need(type(value) is dict, "SCHEMA_STORAGE_MAPPING_INVALID")
        return storage_contract.validate_storage_mapping(
            deepcopy(value), project_id=value.get("project_id"), native_form=deepcopy(spec))
    except (TypeError, ValueError, KeyError):
        raise SchemaPreparationError("SCHEMA_STORAGE_MAPPING_INVALID") from None


def _storage_fields(mapping):
    if mapping is None:
        return {}
    return {"storage_mapping": deepcopy(mapping), "storage_mapping_sha256": _digest(mapping)}


def _plan(specs, mapping_identities=None):
    _need(type(specs) is list and 1 <= len(specs) <= MAX_TABLES, "SCHEMA_SPEC_LIST_REQUIRED")
    selected = {}
    try:
        normalized = [validate_native_spec(value) for value in specs]
    except (TypeError, ValueError):
        raise SchemaPreparationError("SCHEMA_NATIVE_SPEC_INVALID") from None
    for value in normalized:
        name = value["table_name"]
        if name in selected:
            _need(probe.schema_sha256(selected[name]) == probe.schema_sha256(value),
                  "SCHEMA_SHARED_TABLE_CONFLICT")
        else:
            selected[name] = value
    mappings = {}
    if mapping_identities is not None:
        _need(type(mapping_identities) is dict and set(mapping_identities) == set(selected),
              "SCHEMA_STORAGE_MAPPING_COVERAGE_REQUIRED")
        mappings = {name: _storage_mapping(mapping_identities[name], spec)
                    for name, spec in selected.items()}
        _need(len({value["project_id"] for value in mappings.values()}) == 1,
              "SCHEMA_STORAGE_PROJECT_MISMATCH")
        sources, identities = {}, {}
        for value in mappings.values():
            for seen, key, expected in (
                (sources, value["source_table_name"], value["source_schema_sha256"]),
                (identities, value["identity_sha256"], value)):
                _need(key not in seen or _same(seen[key], expected), "SCHEMA_STORAGE_MAPPING_CONFLICT")
                seen[key] = expected
    result = []
    for name, spec in sorted(selected.items()):
        result.append({"table_name": name, "bootstrap_schema_sha256": probe.schema_sha256(spec),
                       "ddl_sha256": hashlib.sha256(render_native_schema(spec).encode()).hexdigest(),
                       "schema_contract": probe.schema_contract(spec),
                       **_storage_fields(mappings.get(name))})
    return selected, result


class SqlclSchemaExecutor:
    """Existing saved parsing-schema connection; no ADMIN/password arguments.

    before_dispatch is invoked exactly once after local command construction,
    immediately before SQLcl. Only that hook records the durable CREATE intent.
    """
    def observe(self, settings, spec, job_root):
        return probe.observe(settings, spec, job_root)

    def create(self, settings, spec, job_root, intent_token, before_dispatch):
        expected = probe.target(settings)
        commands = probe.create_commands(settings, spec, intent_token)
        _need(Path(settings.sqlcl_path).is_file(), "SCHEMA_SQLCL_UNAVAILABLE")
        before_dispatch()
        try:
            result = _run_script(settings.sqlcl_path, ["-S", "-L", "-name", expected["saved_connection"]],
                                 commands, job_root, timeout=120)
            _need(result.returncode == 0 and type(result.stderr) is str and not result.stderr.strip(),
                  "SCHEMA_CREATE_OUTCOME_UNCONFIRMED")
            return probe.parse_create_output(result.stdout, spec, intent_token, settings)
        except Exception:
            raise SchemaPreparationError("SCHEMA_CREATE_OUTCOME_UNCONFIRMED") from None


class _Preparation:
    def __init__(self, settings, specs, job_root, binding, authorize, executor, mapping_identities=None):
        self.settings = settings
        self.binding = _binding(binding)
        self.specs, self.plan = _plan(specs, mapping_identities)  # Validate the whole project before I/O.
        self.mappings = {item["table_name"]: item["storage_mapping"] for item in self.plan
                         if "storage_mapping" in item}
        self.plan_sha = _digest(self.plan)
        self.job = _safe(job_root)
        jobs = _safe(settings.jobs_root)
        _need(self.job.is_dir() and jobs.is_dir() and self.job.parent == jobs
              and self.job.name == self.binding["job_id"], "SCHEMA_EXACT_JOB_ROOT_REQUIRED")
        _need(callable(authorize), "SCHEMA_AUTHORIZATION_CALLBACK_REQUIRED")
        self.authorize = authorize
        self.executor = SqlclSchemaExecutor() if executor is None else executor
        _need(callable(getattr(self.executor, "observe", None))
              and callable(getattr(self.executor, "create", None)), "SCHEMA_EXECUTOR_REQUIRED")
        self.target = probe.target(settings)
        self.scope = _scope(self.target)
        self.jobs = jobs
        self.registry = jobs / REGISTRY_NAME
        self.index = jobs / INDEX_NAME
        self.registry_id = None
        self.receipt = self.job / RECEIPT_NAME
        self.started = self.job / STARTED_NAME
        self.validate_members()

    def validate_members(self):
        _safe(self.registry, exists=False)
        _safe(self.index, exists=False)
        _safe(self.receipt, exists=False)
        _safe(self.started, exists=False)
        for spec in self.specs.values():
            for kind in ("intent", "created", "observed", "ownership", "registration"):
                _safe(self.path(spec, kind), exists=False)

    def prior_preparation(self):
        """Fresh registry creation must not reset retained conversion history."""
        for index, child in enumerate(self.jobs.iterdir()):
            _need(index < 10000, "SCHEMA_JOB_INVENTORY_BOUND_EXCEEDED")
            if child.name == REGISTRY_NAME or not child.is_dir():
                continue
            if _present(child / STARTED_NAME) or _present(child / RECEIPT_NAME):
                return True
        return False

    def registry_before_lock(self, *, create):
        indexed, exists = _present(self.index), _present(self.registry)
        if indexed and not exists:
            raise SchemaPreparationError("SCHEMA_REGISTRY_EVIDENCE_MISSING")
        if not indexed and not exists:
            _need(not self.prior_preparation(), "SCHEMA_REGISTRY_EVIDENCE_MISSING")
            return create
        return True

    def registry_identity(self, *, create):
        identity_path = self.registry / "identity.json"
        identity = checksum = None
        if _present(identity_path):
            identity, checksum = _read(identity_path)
            _need(set(identity) == {"scope", "schema_version", "registry_name", "registry_id"}
                  and identity["scope"] == "fox-native-schema-registry-v1"
                  and type(identity["schema_version"]) is int and identity["schema_version"] == 1
                  and identity["registry_name"] == REGISTRY_NAME
                  and type(identity["registry_id"]) is str
                  and re.fullmatch("[a-f0-9]{32}", identity["registry_id"]), "SCHEMA_REGISTRY_IDENTITY_CHANGED")
        if _present(self.index):
            indexed, index_sha = _read(self.index)
            _need(identity is not None and indexed == identity and index_sha == checksum,
                  "SCHEMA_REGISTRY_EVIDENCE_MISSING")
        else:
            _need(create and not self.prior_preparation(), "SCHEMA_REGISTRY_EVIDENCE_MISSING")
            members = {path.name for path in self.registry.iterdir()}
            _need(members <= {"registry.lock", "identity.json"}, "SCHEMA_UNINDEXED_HISTORY_BLOCKS_INITIALIZATION")
            if identity is None:
                identity = {"schema_version": 1, "scope": "fox-native-schema-registry-v1",
                            "registry_name": REGISTRY_NAME, "registry_id": secrets.token_hex(16)}
                _new(identity_path, identity)
            _new(self.index, identity)
        self.registry_id = identity["registry_id"]

    def preparation_started(self, *, write):
        expected = {"schema_version": 1, "scope": "fox-native-schema-preparation-started-v1",
                    "registry_id": self.registry_id, "binding": self.binding,
                    "target": self.target, "schema_plan_sha256": self.plan_sha,
                    "schema_plan": self.plan}
        if _present(self.started):
            saved, _ = _read(self.started)
            _need(saved == expected, "SCHEMA_JOB_STARTED_RECORD_CHANGED")
        elif write:
            _new(self.started, expected)

    def started_record(self, child):
        started, _ = _read(child / STARTED_NAME)
        _need(set(started) == {"schema_version", "scope", "registry_id", "binding",
                              "target", "schema_plan_sha256", "schema_plan"}
              and type(started["schema_version"]) is int and started["schema_version"] == 1
              and started["scope"] == "fox-native-schema-preparation-started-v1"
              and started["registry_id"] == self.registry_id
              and _binding(started["binding"])["job_id"] == child.name,
              "SCHEMA_STARTED_HISTORY_CHANGED")
        plan = started["schema_plan"]
        _need(type(plan) is list and 1 <= len(plan) <= MAX_TABLES
              and _digest(plan) == started["schema_plan_sha256"], "SCHEMA_STARTED_HISTORY_CHANGED")
        names, specs, mappings = [], [], {}
        for item in plan:
            _need(type(item) is dict, "SCHEMA_STARTED_HISTORY_CHANGED")
            mapped = "storage_mapping" in item or "storage_mapping_sha256" in item
            _need(set(item) == {"table_name", "bootstrap_schema_sha256", "ddl_sha256", "schema_contract"}
                  | ({"storage_mapping", "storage_mapping_sha256"} if mapped else set()),
                  "SCHEMA_STARTED_HISTORY_CHANGED")
            contract = item["schema_contract"]
            try:
                reconstructed = validate_native_spec({
                    "profile_id": contract["profile_id"], "data_mode": contract["data_mode"],
                    "table_name": contract["table_name"],
                    "columns": [{**column, "label": column["name"]} for column in contract["columns"]]})
                _need(probe.schema_contract(reconstructed) == contract
                      and item["table_name"] == reconstructed["table_name"]
                      and item["bootstrap_schema_sha256"] == probe.schema_sha256(reconstructed)
                      and item["ddl_sha256"] == hashlib.sha256(render_native_schema(reconstructed).encode()).hexdigest(),
                      "SCHEMA_STARTED_HISTORY_CHANGED")
            except (KeyError, TypeError, ValueError):
                raise SchemaPreparationError("SCHEMA_STARTED_HISTORY_CHANGED") from None
            names.append(item["table_name"])
            specs.append(reconstructed)
            if mapped:
                mappings[item["table_name"]] = item["storage_mapping"]
        _need(names == sorted(set(names)), "SCHEMA_STARTED_HISTORY_CHANGED")
        _, expected = _plan(specs, mappings if mappings else None)
        _need(_same(expected, plan), "SCHEMA_STARTED_HISTORY_CHANGED")
        return started

    def storage_fields(self, spec):
        return _storage_fields(self.mappings.get(spec["table_name"]))

    def mapping_result_fields(self):
        return {"schema_plan_sha256": self.plan_sha} if self.mappings else {}

    def check_storage_fields(self, value, spec):
        expected = self.storage_fields(spec)
        actual = {key: value[key] for key in ("storage_mapping", "storage_mapping_sha256") if key in value}
        _need(_same(actual, expected), "SCHEMA_STORAGE_MAPPING_CONFLICT")

    def validate_storage_records(self):
        """Lease-held, whole-plan ownership check before any database observation.

        Physical target/table remains the registry key. A shortened name or even
        an equal full digest never replaces equality of the retained payload.
        Independent dispatch anchors retain this boundary after intent loss.
        """
        for spec in self.specs.values():
            for kind in ("intent", "created", "observed", "ownership", "registration"):
                path = self.path(spec, kind)
                if _present(path):
                    value, _ = _read(path)
                    self.check_storage_fields(value, spec)
            for index, child in enumerate(self.jobs.iterdir()):
                _need(index < 10000, "SCHEMA_JOB_INVENTORY_BOUND_EXCEEDED")
                if child.name == REGISTRY_NAME or not child.is_dir():
                    continue
                path = self.anchor_path(spec, child)
                if not _present(path):
                    continue
                anchor, _ = _read(path)
                self.check_storage_fields(anchor, spec)
                started = self.started_record(child)
                matching = [item for item in started["schema_plan"]
                            if item["table_name"] == spec["table_name"]]
                _need(len(matching) == 1, "SCHEMA_DISPATCH_ANCHOR_CHANGED")
                self.check_storage_fields(matching[0], spec)

    def anchor_path(self, spec, job=None):
        return (job or self.job) / (self.key(spec) + ".schema-dispatch.json")

    def anchor_payload(self, spec, intent, intent_sha, started):
        return {"schema_version": 1, "scope": "fox-native-schema-dispatch-anchor-v1",
                "registry_id": self.registry_id, "binding": intent["binding"],
                "target_scope": self.scope, "schema_plan_sha256": started["schema_plan_sha256"],
                "table_key": self.key(spec), "table_name": spec["table_name"],
                "bootstrap_schema_sha256": probe.schema_sha256(spec),
                "intent_token": intent["intent_token"], "intent_sha256": intent_sha,
                **self.storage_fields(spec)}

    def prior_table_dispatched(self, spec):
        """Use independent per-table dispatch anchors, not mere planned work."""
        for index, child in enumerate(self.jobs.iterdir()):
            _need(index < 10000, "SCHEMA_JOB_INVENTORY_BOUND_EXCEEDED")
            if child.name == REGISTRY_NAME or not child.is_dir():
                continue
            path = self.anchor_path(spec, child)
            if not _present(path):
                continue
            anchor, _ = _read(path)
            started = self.started_record(child)
            _need(set(anchor) == {"schema_version", "scope", "registry_id", "binding",
                      "target_scope", "schema_plan_sha256", "table_key", "table_name",
                      "bootstrap_schema_sha256", "intent_token", "intent_sha256", *self.storage_fields(spec)}
                  and type(anchor["schema_version"]) is int and anchor["schema_version"] == 1
                  and anchor["scope"] == "fox-native-schema-dispatch-anchor-v1"
                  and anchor["registry_id"] == self.registry_id
                  and anchor["binding"] == started["binding"]
                  and anchor["schema_plan_sha256"] == started["schema_plan_sha256"]
                  and anchor["target_scope"] == _scope(started["target"]) == self.scope
                  and anchor["table_key"] == self.key(spec)
                  and anchor["table_name"] == spec["table_name"]
                  and _hash(anchor["intent_sha256"])
                  and type(anchor["intent_token"]) is str and re.fullmatch("[a-f0-9]{32}", anchor["intent_token"])
                  and any(item["table_name"] == spec["table_name"]
                          and item["bootstrap_schema_sha256"] == anchor["bootstrap_schema_sha256"]
                          for item in started["schema_plan"]), "SCHEMA_DISPATCH_ANCHOR_CHANGED")
            self.check_storage_fields(anchor, spec)
            self.check_storage_fields(next(item for item in started["schema_plan"]
                                           if item["table_name"] == spec["table_name"]), spec)
            return True
        return False

    def gate(self, operation):
        self.validate_members()
        request = {"binding": self.binding, "target": self.target,
                   "schema_plan_sha256": self.plan_sha, "schema_plan": self.plan}
        try:
            result = self.authorize(operation, deepcopy(request))
            _need(type(result) is dict and _same(result, request), "SCHEMA_AUTHORIZATION_FAILED")
            _need(_same(probe.target(self.settings), self.target), "SCHEMA_TARGET_CHANGED")
        except Exception:
            raise SchemaPreparationError("SCHEMA_AUTHORIZATION_FAILED") from None

    def key(self, spec):
        return _digest({"target": self.scope, "table_name": spec["table_name"]})

    def path(self, spec, kind):
        _need(kind in {"intent", "created", "observed", "ownership", "registration"},
              "SCHEMA_RECORD_KIND_INVALID")
        return self.registry / (self.key(spec) + "." + kind + ".json")

    def observe(self, spec):
        try:
            value = self.executor.observe(self.settings, deepcopy(spec), self.job)
        except Exception:
            raise SchemaPreparationError("SCHEMA_OBSERVATION_UNCONFIRMED",
                                         table_name=spec["table_name"]) from None
        keys = {"schema_version", "scope", "target", "table_name", "schema_sha256", "capabilities",
                "data_rows_read", "business_behavior_verified", "state", "object_identity", "metadata_sha256"}
        _need(type(value) is dict and set(value) == keys and type(value["schema_version"]) is int
              and value["schema_version"] == 1 and value["scope"] == "fox-native-schema-observation-v1"
              and _same(value["target"], self.target) and value["table_name"] == spec["table_name"]
              and value["schema_sha256"] == probe.schema_sha256(spec)
              and value["data_rows_read"] is value["business_behavior_verified"] is False
              and value["state"] in ("ABSENT", "EXACT"), "SCHEMA_OBSERVATION_BINDING_CHANGED")
        if value["state"] == "ABSENT":
            _need(value["object_identity"] is value["metadata_sha256"] is None, "SCHEMA_OBSERVATION_BINDING_CHANGED")
        else:
            _identity(value["object_identity"])
            _need(_hash(value["metadata_sha256"]), "SCHEMA_OBSERVATION_BINDING_CHANGED")
        capability = value["capabilities"]
        keys = {"create_table", "create_sequence", "unlimited_tablespace", "default_tablespace",
                "quota_record_present", "quota_used_bytes", "quota_max_bytes", "quota_available",
                "creation_ready", "allocation_guaranteed"}
        _need(type(capability) is dict and set(capability) == keys
              and all(type(capability[key]) is bool for key in
                      ("create_table", "create_sequence", "unlimited_tablespace", "quota_record_present",
                       "quota_available", "creation_ready", "allocation_guaranteed"))
              and capability["allocation_guaranteed"] is False, "SCHEMA_CAPABILITY_INVALID")
        available = capability["unlimited_tablespace"]
        if capability["quota_record_present"]:
            used, maximum = capability["quota_used_bytes"], capability["quota_max_bytes"]
            _need(type(used) is int and used >= 0 and type(maximum) is int and maximum >= -1,
                  "SCHEMA_CAPABILITY_INVALID")
            available = available or maximum == -1 or maximum > used
        else:
            _need(capability["quota_used_bytes"] is capability["quota_max_bytes"] is None,
                  "SCHEMA_CAPABILITY_INVALID")
        ready = capability["create_table"] and capability["create_sequence"] and \
            capability["default_tablespace"] == "DATA" and available
        _need(capability["quota_available"] is available and capability["creation_ready"] is ready,
              "SCHEMA_CAPABILITY_INVALID")
        return deepcopy(value)

    def common(self, spec):
        return {"schema_version": 1, "registry_id": self.registry_id,
                "table_key": self.key(spec), "target_scope": self.scope,
                "table_name": spec["table_name"], "bootstrap_schema_sha256": probe.schema_sha256(spec),
                "ddl_sha256": hashlib.sha256(render_native_schema(spec).encode()).hexdigest(),
                **self.storage_fields(spec)}

    def intent(self, spec):
        value, checksum = _read(self.path(spec, "intent"))
        common = self.common(spec)
        _need(set(value) == {*common, "scope", "binding", "target", "native_spec", "intent_token", "created_at_utc"}
              and value["scope"] == "fox-native-schema-create-intent-v1"
              and all(_same(value[key], expected) for key, expected in common.items()),
              "SCHEMA_INTENT_CHANGED")
        _binding(value["binding"])
        _need(_scope(value["target"]) == self.scope
              and probe.schema_sha256(value["native_spec"]) == common["bootstrap_schema_sha256"]
              and type(value["intent_token"]) is str and re.fullmatch("[a-f0-9]{32}", value["intent_token"]),
              "SCHEMA_INTENT_CHANGED")
        original_job = self.jobs / value["binding"]["job_id"]
        started = self.started_record(original_job)
        _need(started["binding"] == value["binding"] and _scope(started["target"]) == self.scope,
              "SCHEMA_INTENT_CHANGED")
        anchor, _ = _read(self.anchor_path(spec, original_job))
        _need(anchor == self.anchor_payload(spec, value, checksum, started), "SCHEMA_DISPATCH_ANCHOR_CHANGED")
        return value, checksum

    def created(self, spec, intent, intent_sha):
        value, checksum = _read(self.path(spec, "created"))
        _need(set(value) == {"scope", "intent_sha256", "observation", *self.storage_fields(spec)}
              and value["scope"] == "fox-native-schema-created-record-v1"
              and value["intent_sha256"] == intent_sha, "SCHEMA_CREATE_RECORD_CHANGED")
        self.check_storage_fields(value, spec)
        observation = value["observation"]
        keys = {"schema_version", "scope", "target", "table_name", "schema_sha256", "intent_token",
                "object_identity", "ddl_sha256", "created_in_this_sqlcl_execution",
                "metadata_verification_still_required"}
        _need(type(observation) is dict and set(observation) == keys
              and type(observation["schema_version"]) is int and observation["schema_version"] == 1
              and observation["scope"] == "fox-native-schema-create-observation-v1"
              and _same(observation["target"], intent["target"])
              and observation["table_name"] == spec["table_name"]
              and observation["schema_sha256"] == probe.schema_sha256(spec)
              and observation["intent_token"] == intent["intent_token"]
              and observation["ddl_sha256"] == self.common(spec)["ddl_sha256"]
              and observation["created_in_this_sqlcl_execution"] is True
              and observation["metadata_verification_still_required"] is True, "SCHEMA_CREATE_RECORD_CHANGED")
        _identity(observation["object_identity"])
        return observation, checksum

    def ownership(self, spec):
        value, checksum = _read(self.path(spec, "ownership"))
        common = self.common(spec)
        _need(set(value) == {*common, "scope", "origin", "object_identity", "metadata_sha256",
                            "records_sha256", "recorded_at_utc"}
              and value["scope"] == "fox-managed-native-table-v1"
              and all(_same(value[key], expected) for key, expected in common.items()),
              "SCHEMA_OWNERSHIP_CHANGED")
        _identity(value["object_identity"])
        _need(_hash(value["metadata_sha256"]) and type(value["origin"]) is dict,
              "SCHEMA_OWNERSHIP_CHANGED")
        if value["origin"].get("kind") == "created":
            _need(not _present(self.path(spec, "registration")), "SCHEMA_CONFLICTING_REGISTRY_RECORDS")
            intent, intent_sha = self.intent(spec)
            created, created_sha = self.created(spec, intent, intent_sha)
            observed, observed_sha = _read(self.path(spec, "observed"))
            _need(value["origin"] == {"kind": "created", "binding": intent["binding"],
                                     "intent_token": intent["intent_token"]}
                  and value["records_sha256"] == {"intent": intent_sha, "created": created_sha, "observed": observed_sha}
                  and observed == {"scope": "fox-native-schema-verified-record-v1",
                                   "created_sha256": created_sha, "object_identity": created["object_identity"],
                                   "metadata_sha256": value["metadata_sha256"], **self.storage_fields(spec)}
                  and value["object_identity"] == created["object_identity"], "SCHEMA_OWNERSHIP_CHANGED")
        elif value["origin"].get("kind") == "registered":
            _need(not any(_present(self.path(spec, kind)) for kind in ("intent", "created", "observed")),
                  "SCHEMA_CONFLICTING_REGISTRY_RECORDS")
            _need(not self.prior_table_dispatched(spec), "SCHEMA_CONFLICTING_REGISTRY_RECORDS")
            registered, registered_sha = _read(self.path(spec, "registration"))
            _need(set(registered) == {*common, "scope", "registration_id", "evidence_sha256",
                                     "object_identity", "metadata_sha256", "target", "recorded_at_utc"}
                  and registered["scope"] == "fox-native-schema-registration-v1"
                  and all(_same(registered[key], expected) for key, expected in common.items())
                  and _scope(registered["target"]) == self.scope
                  and _hash(registered["evidence_sha256"])
                  and value["origin"] == {"kind": "registered", "registration_id": registered["registration_id"],
                                         "evidence_sha256": registered["evidence_sha256"]}
                  and value["records_sha256"] == {"registration": registered_sha}
                  and value["object_identity"] == registered["object_identity"]
                  and value["metadata_sha256"] == registered["metadata_sha256"], "SCHEMA_OWNERSHIP_CHANGED")
        else:
            raise SchemaPreparationError("SCHEMA_OWNERSHIP_CHANGED")
        return value, checksum

    def match_owner(self, spec, observation):
        owner, owner_sha = self.ownership(spec)
        if not (observation["state"] == "EXACT"
                and observation["object_identity"] == owner["object_identity"]
                and observation["metadata_sha256"] == owner["metadata_sha256"]):
            raise SchemaPreparationError("SCHEMA_MANAGED_TABLE_CHANGED", table_name=spec["table_name"])
        return owner, owner_sha

    def finalize(self, spec, observation):
        intent, intent_sha = self.intent(spec)
        _need(_same(intent["binding"], self.binding), "SCHEMA_OTHER_JOB_RECONCILIATION_REQUIRED")
        created, created_sha = self.created(spec, intent, intent_sha)
        _need(observation["state"] == "EXACT"
              and observation["object_identity"] == created["object_identity"],
              "SCHEMA_POST_CREATE_IDENTITY_MISMATCH")
        self.gate("continue")
        record = {"scope": "fox-native-schema-verified-record-v1", "created_sha256": created_sha,
                  "object_identity": observation["object_identity"], "metadata_sha256": observation["metadata_sha256"],
                  **self.storage_fields(spec)}
        observed_path = self.path(spec, "observed")
        if _present(observed_path):
            existing, observed_sha = _read(observed_path)
            _need(existing == record, "SCHEMA_POST_CREATE_RECORD_CHANGED")
        else:
            observed_sha = _new(observed_path, record)
        _new(self.path(spec, "ownership"), {**self.common(spec), "scope": "fox-managed-native-table-v1",
             "origin": {"kind": "created", "binding": intent["binding"], "intent_token": intent["intent_token"]},
             "object_identity": observation["object_identity"], "metadata_sha256": observation["metadata_sha256"],
             "records_sha256": {"intent": intent_sha, "created": created_sha, "observed": observed_sha},
             "recorded_at_utc": _now()})
        return self.match_owner(spec, observation)

    def receipt_table(self, spec, owner, owner_sha):
        created_here = owner["origin"].get("kind") == "created" and \
            _same(owner["origin"]["binding"], self.binding)
        return {"table_name": spec["table_name"], "bootstrap_schema_sha256": probe.schema_sha256(spec),
                "table_key": self.key(spec), "state": "CREATED" if created_here else "REUSED",
                "ownership_sha256": owner_sha, "object_identity": owner["object_identity"],
                **self.storage_fields(spec)}

    def aggregate(self, tables, *, write):
        expected = {"schema_version": 1, "scope": "fox-native-schema-preparation-v1",
                    "registry_id": self.registry_id, "binding": self.binding,
                    "target": self.target, "schema_plan_sha256": self.plan_sha,
                    "tables": tables, "all_ready": True, "business_behavior_verified": False,
                    "automatic_replay_permitted": False}
        if _present(self.receipt):
            saved, checksum = _read(self.receipt)
            _need(set(saved) == {*expected, "prepared_at_utc"}
                  and all(_same(saved[key], value) for key, value in expected.items()),
                  "SCHEMA_JOB_RECEIPT_CHANGED")
            return checksum
        if write:
            return _new(self.receipt, {**expected, "prepared_at_utc": _now()})
        return None

    def retained_receipt(self):
        """A prior READY result may never become permission to recreate data."""
        if not _present(self.receipt):
            return
        _need(self.registry.is_dir() and not self.registry.is_symlink(),
              "SCHEMA_REGISTRY_EVIDENCE_MISSING")
        tables = []
        for name, spec in sorted(self.specs.items()):
            _need(self.path(spec, "ownership").is_file(), "SCHEMA_REGISTRY_EVIDENCE_MISSING")
            owner, checksum = self.ownership(spec)
            tables.append(self.receipt_table(spec, owner, checksum))
        self.aggregate(tables, write=False)

    def preparation_observation(self, spec):
        current = self.observe(spec)
        if _present(self.path(spec, "ownership")):
            self.match_owner(spec, current)
        elif _present(self.path(spec, "intent")):
            intent, intent_sha = self.intent(spec)
            _need(_same(intent["binding"], self.binding), "SCHEMA_OTHER_JOB_RECONCILIATION_REQUIRED")
            _need(_present(self.path(spec, "created")), "SCHEMA_CREATE_OUTCOME_UNCONFIRMED")
            created, _ = self.created(spec, intent, intent_sha)
            _need(current["state"] == "EXACT" and current["object_identity"] == created["object_identity"],
                  "SCHEMA_POST_CREATE_IDENTITY_MISMATCH")
        else:
            _need(not any(_present(self.path(spec, kind)) for kind in ("created", "observed", "registration")),
                  "SCHEMA_INCOMPLETE_REGISTRY_RECORD")
            _need(not self.prior_table_dispatched(spec), "SCHEMA_DISPATCH_HISTORY_INCOMPLETE")
            _need(current["state"] == "ABSENT", "SCHEMA_EXISTING_TABLE_NOT_MANAGED")
            _need(current["capabilities"]["creation_ready"], "SCHEMA_CREATION_PREREQUISITES_MISSING")
        return current


def prepare_schemas(settings, specs, job_root, *, binding, authorize, executor=None, mapping_identities=None):
    """Prepare all project tables, or stop without starting an APEX import.

    authorization(operation, request) is installation-owned executable code.
    It must verify source/review/VALID and fresh target preflight, then return
    the identical request. It is never selected by uploaded JSON or HTTP data.
    executor is an in-process testing seam, not a request field.
    mapping_identities optionally binds every physical table to a recomputed
    project/source storage identity. Omission preserves the legacy domain; it
    cannot adopt a mapped record or cause mapped work to adopt legacy ownership.
    """
    work = _Preparation(settings, specs, job_root, binding, authorize, executor, mapping_identities)
    work.gate("prepare")
    work.registry_before_lock(create=True)
    completed, writes = [], 0
    with _lease(work.registry, create=True):
        work.registry_identity(create=True)
        work.validate_storage_records()
        work.retained_receipt()
        work.preparation_started(write=False)
        observations = {}
        # Detect every existing collision, missing capability and conflicting
        # retained intent before creating any newly absent project table.
        for name, spec in sorted(work.specs.items()):
            try:
                observations[name] = work.preparation_observation(spec)
            except SchemaPreparationError as error:
                raise SchemaPreparationError(error.code, table_name=name) from None
        work.preparation_started(write=True)
        for name, spec in sorted(work.specs.items()):
            try:
                current = observations[name]
                if _present(work.path(spec, "ownership")):
                    owner, checksum = work.match_owner(spec, current)
                elif _present(work.path(spec, "intent")):
                    owner, checksum = work.finalize(spec, current)
                else:
                    token = secrets.token_hex(16)
                    dispatched = False
                    def before_dispatch():
                        nonlocal dispatched
                        _need(not dispatched, "SCHEMA_DUPLICATE_DISPATCH_CALLBACK")
                        work.gate("create")
                        intent = {**work.common(spec),
                             "scope": "fox-native-schema-create-intent-v1", "binding": work.binding,
                             "target": work.target, "native_spec": spec, "intent_token": token,
                             "created_at_utc": _now()}
                        intent_sha = _new(work.path(spec, "intent"), intent)
                        _new(work.anchor_path(spec),
                             work.anchor_payload(spec, intent, intent_sha, work.started_record(work.job)))
                        dispatched = True
                    try:
                        result = work.executor.create(settings, deepcopy(spec), work.job, token, before_dispatch)
                    except Exception:
                        code = ("SCHEMA_CREATE_OUTCOME_UNCONFIRMED" if dispatched or
                                _present(work.path(spec, "intent")) else "SCHEMA_CREATE_NOT_STARTED")
                        raise SchemaPreparationError(code) from None
                    _need(dispatched, "SCHEMA_CREATE_WITHOUT_DISPATCH_RECORD")
                    intent, intent_sha = work.intent(spec)
                    _new(work.path(spec, "created"), {"scope": "fox-native-schema-created-record-v1",
                                                    "intent_sha256": intent_sha, "observation": result,
                                                    **work.storage_fields(spec)})
                    work.created(spec, intent, intent_sha)
                    writes += 1
                    current = work.observe(spec)
                    owner, checksum = work.finalize(spec, current)
                completed.append(work.receipt_table(spec, owner, checksum))
            except SchemaPreparationError as error:
                raise SchemaPreparationError(error.code, table_name=name,
                                             completed_tables=completed) from None
        # Re-observe every table after all CREATE operations. A later table's
        # work must not make an earlier cached metadata observation READY.
        completed = []
        for name, spec in sorted(work.specs.items()):
            try:
                owner, checksum = work.match_owner(spec, work.observe(spec))
                completed.append(work.receipt_table(spec, owner, checksum))
            except SchemaPreparationError as error:
                raise SchemaPreparationError(error.code, table_name=name,
                                             completed_tables=completed) from None
        work.gate("complete")
        checksum = work.aggregate(completed, write=True)
    return {"schema_version": 1, "scope": "fox-native-schema-preparation-result-v1", "state": "READY",
            "job_id": work.binding["job_id"], "schema_plan_sha256": work.plan_sha,
            "receipt_sha256": checksum, "tables": completed, "database_writes_this_call": writes,
            "apex_import_performed_by_operation": False, "human_acceptance_recorded": False}


def reconcile_schemas(settings, specs, job_root, *, binding, authorize, executor=None, mapping_identities=None):
    """Read existing records/metadata only; never adopt an uncertain table."""
    work = _Preparation(settings, specs, job_root, binding, authorize, executor, mapping_identities)
    work.gate("reconcile")
    if not work.registry_before_lock(create=False):
        return {"schema_version": 1, "scope": "fox-native-schema-reconciliation-v1", "state": "NOT_STARTED",
                "job_id": work.binding["job_id"], "tables": [], "ready_for_import": False,
                "database_writes": False, "registry_writes": False, "automatic_replay_permitted": False,
                **work.mapping_result_fields()}
    tables, prepared = [], []
    with _lease(work.registry, create=False):
        work.registry_identity(create=False)
        work.validate_storage_records()
        work.retained_receipt()
        work.preparation_started(write=False)
        for name, spec in sorted(work.specs.items()):
            current = work.observe(spec)
            if _present(work.path(spec, "ownership")):
                owner, checksum = work.match_owner(spec, current)
                item = work.receipt_table(spec, owner, checksum)
                prepared.append(item)
                tables.append(item)
            elif _present(work.path(spec, "intent")):
                intent, intent_sha = work.intent(spec)
                if _present(work.path(spec, "created")):
                    created, _ = work.created(spec, intent, intent_sha)
                    _need(current["state"] == "EXACT" and current["object_identity"] == created["object_identity"],
                          "SCHEMA_POST_CREATE_IDENTITY_MISMATCH")
                    state = ("CONTINUATION_AVAILABLE" if _same(intent["binding"], work.binding)
                             else "OTHER_JOB_RECONCILIATION_REQUIRED")
                else:
                    state = "CREATE_OUTCOME_UNCONFIRMED"
                tables.append({"table_name": name, "state": state,
                               "bootstrap_schema_sha256": probe.schema_sha256(spec),
                               "observed_state": current["state"], **work.storage_fields(spec)})
            else:
                _need(not any(_present(work.path(spec, kind)) for kind in ("created", "observed", "registration")),
                      "SCHEMA_INCOMPLETE_REGISTRY_RECORD")
                tables.append({"table_name": name, "bootstrap_schema_sha256": probe.schema_sha256(spec),
                               **work.storage_fields(spec),
                               "state": ("DISPATCH_HISTORY_INCOMPLETE" if work.prior_table_dispatched(spec) else
                                         "NOT_STARTED" if current["state"] == "ABSENT" else "EXISTING_TABLE_NOT_MANAGED")})
        checksum = work.aggregate(prepared, write=False) if len(prepared) == len(work.specs) else None
    return {"schema_version": 1, "scope": "fox-native-schema-reconciliation-v1",
            "state": "READY" if checksum else "ATTENTION", "job_id": work.binding["job_id"],
            "tables": tables, "receipt_sha256": checksum, "ready_for_import": checksum is not None,
            "database_writes": False, "registry_writes": False, "automatic_replay_permitted": False,
            **work.mapping_result_fields()}


def register_existing_schema(settings, spec, job_root, *, registration_id, evidence_sha256,
                             expected_object_identity, authorize, apply=False, executor=None):
    """Explicit installation-only adoption; never called automatically by prepare.

    A deployment operator must bind reviewed synthetic ownership evidence and a
    fresh prior object identity. This does not grant privileges or alter data.
    No business-user/MCP route should expose this installation action.
    """
    _need(apply is True and callable(authorize), "SCHEMA_EXPLICIT_REGISTRATION_REQUIRED")
    _need(type(registration_id) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,63}", registration_id)
          and _hash(evidence_sha256), "SCHEMA_REGISTRATION_EVIDENCE_REQUIRED")
    spec = validate_native_spec(spec)
    identity = _identity(expected_object_identity)
    # Registration has its own authority domain, not fabricated AI/SQLcl review.
    context = {"registration_id": registration_id, "evidence_sha256": evidence_sha256,
               "expected_object_identity": identity, "target": probe.target(settings),
               "native_spec": spec}
    try:
        authorized = authorize(deepcopy(context))
    except Exception:
        raise SchemaPreparationError("SCHEMA_REGISTRATION_AUTHORIZATION_FAILED") from None
    _need(type(authorized) is dict and _same(authorized, context),
          "SCHEMA_REGISTRATION_AUTHORIZATION_FAILED")
    job = _safe(job_root)
    _need(job.parent == _safe(settings.jobs_root) and job.is_dir(), "SCHEMA_EXACT_JOB_ROOT_REQUIRED")
    synthetic_binding = {"job_id": job.name, **{key: "0" * 64 for key in _BINDING_KEYS - {"job_id"}}}
    work = _Preparation(settings, [spec], job, synthetic_binding,
                        lambda operation, request: request, executor)
    _need(_same(work.target, context["target"]), "SCHEMA_REGISTRATION_AUTHORIZATION_FAILED")
    work.registry_before_lock(create=True)
    with _lease(work.registry, create=True):
        work.registry_identity(create=True)
        work.validate_storage_records()
        current = work.observe(work.specs[spec["table_name"]])
        _need(current["state"] == "EXACT" and current["object_identity"] == identity,
              "SCHEMA_REGISTRATION_OBJECT_CHANGED")
        if _present(work.path(spec, "ownership")):
            owner, checksum = work.match_owner(spec, current)
            return {"state": "ALREADY_MANAGED", "ownership_sha256": checksum, "database_writes": False}
        _need(not any(_present(work.path(spec, kind)) for kind in ("intent", "created", "observed")),
              "SCHEMA_EXISTING_ATTEMPT_REQUIRES_RECONCILIATION")
        _need(not work.prior_table_dispatched(spec), "SCHEMA_EXISTING_ATTEMPT_REQUIRES_RECONCILIATION")
        try:
            approved = authorize(deepcopy(context))
            _need(_same(approved, context) and _same(probe.target(settings), context["target"]),
                  "SCHEMA_REGISTRATION_AUTHORIZATION_FAILED")
        except Exception:
            raise SchemaPreparationError("SCHEMA_REGISTRATION_AUTHORIZATION_FAILED") from None
        registered = {**work.common(spec), "scope": "fox-native-schema-registration-v1",
                      **{key: context[key] for key in ("registration_id", "evidence_sha256", "target")},
                      "object_identity": identity, "metadata_sha256": current["metadata_sha256"],
                      "recorded_at_utc": _now()}
        if _present(work.path(spec, "registration")):
            existing, registration_sha = _read(work.path(spec, "registration"))
            _need(set(existing) == set(registered)
                  and all(_same(existing[key], value) for key, value in registered.items()
                          if key != "recorded_at_utc"), "SCHEMA_REGISTRATION_RECORD_CHANGED")
        else:
            registration_sha = _new(work.path(spec, "registration"), registered)
        checksum = _new(work.path(spec, "ownership"), {**work.common(spec), "scope": "fox-managed-native-table-v1",
             "origin": {"kind": "registered", "registration_id": registration_id, "evidence_sha256": evidence_sha256},
             "object_identity": identity, "metadata_sha256": current["metadata_sha256"],
             "records_sha256": {"registration": registration_sha}, "recorded_at_utc": _now()})
        work.match_owner(spec, current)
    return {"state": "REGISTERED", "ownership_sha256": checksum, "database_writes": False,
            "human_acceptance_recorded": False}
