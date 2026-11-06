"""Internal, source-authorized prototype adapter; never a public converter API.

The caller supplies a trusted ``authorize(request)`` which rereads the retained
source packet, plan, mapper invocation/environment and independent reviewer
receipt, then returns the unchanged request. Hashes in a request are NOT that
authority. The default is deliberately unavailable. No model/source SQL is run.

Only the new strict blueprint profile is accepted. Runtime/browser verification
requires an injected trusted new-profile executor: historical native-project
proof cannot be relabelled as prototype proof.
"""
from __future__ import annotations

from copy import deepcopy
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import zipfile

from . import native_blueprint, native_target, runtime_preflight, sqlcl
from .project_reviews import canonical, digest, publish, read_object, publish_directory, cleanup_temporary
from .provenance import file_digest, tree_digest
from .review_receipts import _unique_keys
from .security import validate_job_id


STAGES = ("validate", "prepare_schema", "import", "verify_runtime", "export")
_REQUEST = {"schema_version", "scope", "job_id", "project_id", "source_binding",
            "plan_sha256", "rendering_spec", "rendered_zip_sha256", "prior_receipts", "source_authority"}
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_LOCK = threading.RLock()
_AUTHORITY_ROOT_FILES = {"binding.json", "sources-manifest.json", "packet.json", "review-index.json",
                         "merged-blueprint.json", "native-plan.json", "rendered.json", "candidate-apexlang.zip"}
_FOCUS_FILES = ("request", "mapper", "mapper-target", "reviewer", "reviewer-target", "review-receipt")
_AUTHORITY_PATH = re.compile(r"(?:sources/source-00[0-3]\.xml|focus-[a-f0-9]{24}/(?:"
                             + "|".join(_FOCUS_FILES) + r")\.json)\Z")


def _authority_json(raw):
    try:
        result = json.loads(raw, object_pairs_hook=_unique_keys)
    except (ValueError, UnicodeError):
        raise RuntimeError("PROTOTYPE_AUTHORITY_JSON_INVALID") from None
    _need(type(result) is dict, "PROTOTYPE_AUTHORITY_JSON_INVALID")
    return result


def _authority_descriptor(bundle, *, encoded):
    keys = {"schema_version", "scope", "job_id", "source_binding", "source_authority", "files", "manifest_sha256"}
    _need(type(bundle) is dict and set(bundle) == keys, "PROTOTYPE_AUTHORITY_BUNDLE_FIELDS_INVALID")
    _need(type(bundle["schema_version"]) is int and bundle["schema_version"] == 1
          and bundle["scope"] == "fox-prototype-authority-bundle-v1", "PROTOTYPE_AUTHORITY_BUNDLE_SCOPE_INVALID")
    _need(type(bundle["job_id"]) is str, "PROTOTYPE_AUTHORITY_JOB_INVALID")
    validate_job_id(bundle["job_id"])
    _need(type(bundle["source_binding"]) is str and _SHA.fullmatch(bundle["source_binding"]),
          "PROTOTYPE_AUTHORITY_BINDING_INVALID")
    authority = bundle["source_authority"]
    _need(type(authority) is dict and set(authority) == {"schema_version", "scope", "binding_sha256",
          "sources_manifest_sha256", "review_index_sha256"} and type(authority["schema_version"]) is int
          and authority["schema_version"] == 1 and authority["scope"] == "fox-prototype-source-authority-v1"
          and all(type(authority[key]) is str and _SHA.fullmatch(authority[key])
                  for key in ("binding_sha256", "sources_manifest_sha256", "review_index_sha256")),
          "PROTOTYPE_SOURCE_AUTHORITY_FIELDS_INVALID")
    _need(type(bundle["files"]) is list and 1 <= len(bundle["files"]) <= 2048,
          "PROTOTYPE_AUTHORITY_FILE_COUNT_INVALID")
    rows, names, total = [], [], 0
    for row in bundle["files"]:
        _need(type(row) is dict and set(row) == ({"path", "sha256", "bytes", "content_base64"} if encoded
                                              else {"path", "sha256", "bytes"}),
              "PROTOTYPE_AUTHORITY_FILE_FIELDS_INVALID")
        name = row["path"]
        _need(type(name) is str and (name in _AUTHORITY_ROOT_FILES or _AUTHORITY_PATH.fullmatch(name)),
              "PROTOTYPE_AUTHORITY_PATH_NOT_ALLOWED")
        _need(type(row["bytes"]) is int and 0 < row["bytes"] <= 20_000_000
              and type(row["sha256"]) is str and _SHA.fullmatch(row["sha256"]),
              "PROTOTYPE_AUTHORITY_FILE_IDENTITY_INVALID")
        names.append(name)
        total += row["bytes"]
        rows.append({key: row[key] for key in ("path", "sha256", "bytes")})
    _need(names == sorted(names) and len(names) == len(set(names)) and total <= 64 * 1024 * 1024,
          "PROTOTYPE_AUTHORITY_MANIFEST_INVALID")
    descriptor = {key: bundle[key] for key in ("schema_version", "scope", "job_id", "source_binding", "source_authority")}
    descriptor["files"] = rows
    _need(type(bundle["manifest_sha256"]) is str and bundle["manifest_sha256"] == digest(descriptor),
          "PROTOTYPE_AUTHORITY_MANIFEST_HASH_MISMATCH")
    return descriptor


def _check_authority_members(descriptor, members):
    """Structural byte binding only, NOT model/source/reviewer authorization."""
    _need(_AUTHORITY_ROOT_FILES <= set(members), "PROTOTYPE_AUTHORITY_ROOT_FILES_MISSING")
    authority = descriptor["source_authority"]
    binding = _authority_json(members["binding.json"])
    sources = _authority_json(members["sources-manifest.json"])
    index = _authority_json(members["review-index.json"])
    _need(digest(binding) == authority["binding_sha256"] and digest(sources) == authority["sources_manifest_sha256"]
          and digest(index) == authority["review_index_sha256"], "PROTOTYPE_AUTHORITY_ARTIFACT_BINDING_MISMATCH")
    _need(binding.get("job_id") == descriptor["job_id"]
          and all(value.get("source_binding") == descriptor["source_binding"] for value in (binding, sources, index)),
          "PROTOTYPE_AUTHORITY_SOURCE_BINDING_MISMATCH")
    _need(type(sources.get("files")) is list and 1 <= len(sources["files"]) <= 4
          and type(index.get("focuses")) is list and 1 <= len(index["focuses"]) <= 340,
          "PROTOTYPE_AUTHORITY_INDEX_INVALID")
    expected = set(_AUTHORITY_ROOT_FILES)
    for number, row in enumerate(sources["files"]):
        name = f"sources/source-{number:03}.xml"
        _need(type(row) is dict and type(row.get("bytes")) is int and name in members
              and len(members[name]) == row["bytes"] and len(members[name]) <= 5 * 1024 * 1024
              and hashlib.sha256(members[name]).hexdigest() == row.get("sha256"),
              "PROTOTYPE_AUTHORITY_SOURCE_BYTES_CHANGED")
        expected.add(name)
    focuses = set()
    for row in index["focuses"]:
        _need(type(row) is dict and type(row.get("focus_id")) is str
              and re.fullmatch(r"focus-[a-f0-9]{24}", row["focus_id"]) and row["focus_id"] not in focuses,
              "PROTOTYPE_AUTHORITY_FOCUS_INVALID")
        focuses.add(row["focus_id"])
        for kind in _FOCUS_FILES:
            name = row["focus_id"] + "/" + kind + ".json"
            _need(name in members and digest(_authority_json(members[name])) == row.get(kind + "_sha256"),
                  "PROTOTYPE_AUTHORITY_FOCUS_BYTES_CHANGED")
            expected.add(name)
    _need(set(members) == expected, "PROTOTYPE_AUTHORITY_MEMBERSHIP_MISMATCH")


def _need(condition, code):
    if not condition:
        raise RuntimeError(code)


def _new_bytes(path, raw):
    if path.exists() or path.is_symlink():
        _need(not path.is_symlink() and path.is_file() and path.read_bytes() == raw,
              "PROTOTYPE_SNAPSHOT_CHANGED")
        return
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class PrototypeGateway:
    """Attach run_stage/recover_stage behind the existing internal bearer route.

    External dependencies are injectable for controlled tests, not evidence of a
    live flow. Production defaults use real SQLcl validation, durable unique
    import and exact JSN action preflight. ``runner`` handles schema/export SQLcl.
    ``preflight`` returns a callable which rechecks freshness immediately before
    writes; the default uses collect/verify_action_preflight, not a boolean.
    ``runtime_verifier`` must implement prototype_release.verify_runtime's
    trusted browser callback contract; no default can impersonate that proof.
    """

    def __init__(self, settings, *, authorize=None, validator=None, importer=None,
                 runner=None, preflight=None, runtime_verifier=None, target_profile_loader=None):
        self.settings = settings
        self.authorize = authorize
        self.validator = validator or sqlcl.validate_apexlang
        self.importer = importer or sqlcl.import_apexlang_durable
        self.runner = runner or sqlcl._run_script
        self.preflight = preflight or self._target_preflight
        self.runtime_verifier = runtime_verifier
        self.target_profile_loader = target_profile_loader

    def supports(self, stage):
        return stage in STAGES[:3] or (stage in STAGES[3:] and callable(self.runtime_verifier))

    def stage_source_authority(self, job_id, bundle):
        """Receive exact private artifacts, never execute or authorize them.

        Publication is immutable and fixed under the configured jobs root.
        Main's trusted ``authorize`` callback must call the real
        fox.prototype_pipeline.authorize_prototype_request on this staged job,
        in addition to its persisted owner/destination/synthetic-scope consent.
        """
        with _LOCK:
            descriptor = _authority_descriptor(bundle, encoded=True)
            _need(descriptor["job_id"] == job_id, "PROTOTYPE_AUTHORITY_JOB_MISMATCH")
            members = {}
            for row in bundle["files"]:
                encoded = row["content_base64"]
                _need(type(encoded) is str and len(encoded) <= 4 * ((row["bytes"] + 2) // 3),
                      "PROTOTYPE_AUTHORITY_BASE64_INVALID")
                try:
                    raw = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error):
                    raise RuntimeError("PROTOTYPE_AUTHORITY_BASE64_INVALID") from None
                _need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
                      "PROTOTYPE_AUTHORITY_BYTES_CHANGED")
                members[row["path"]] = raw
            _check_authority_members(descriptor, members)
            root = self._root({"job_id": job_id}, create=True)
            target = root.parent / "prototype-pipeline"
            _need(not target.is_symlink(), "PROTOTYPE_AUTHORITY_DIRECTORY_LINKED")
            manifest = {**descriptor, "manifest_sha256": bundle["manifest_sha256"]}
            if target.exists():
                _need(read_object(root / "authority-manifest.json") == manifest,
                      "PROTOTYPE_AUTHORITY_ALREADY_EXISTS_PRESERVED")
                result = self.recover_source_authority(job_id)
                _need(result is not None, "PROTOTYPE_AUTHORITY_INCOMPLETE")
                return result
            staging = Path(tempfile.mkdtemp(prefix=".proto-auth-", dir=root.parent))
            try:
                for name, raw in members.items():
                    path = staging / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    _new_bytes(path, raw)
                publish(root / "authority-manifest.json", manifest)
                publish_directory(staging, target)
            finally:
                cleanup_temporary(staging, root.parent, ".proto-auth-")
            return self.recover_source_authority(job_id)

    def recover_source_authority(self, job_id):
        """GET-safe byte receipt; no filesystem writes, database or model call."""
        validate_job_id(job_id)
        with _LOCK:
            root = self._root({"job_id": job_id}, create=False)
            manifest_path = root / "authority-manifest.json"
            target = root.parent / "prototype-pipeline"
            if not manifest_path.exists() and not manifest_path.is_symlink():
                return None
            manifest = read_object(manifest_path)
            descriptor = _authority_descriptor(manifest, encoded=False)
            _need(descriptor["job_id"] == job_id and not target.is_symlink(), "PROTOTYPE_AUTHORITY_JOB_MISMATCH")
            if not target.exists():
                return None
            _need(target.is_dir(), "PROTOTYPE_AUTHORITY_DIRECTORY_INVALID")
            actual = {}
            allowed_directories = {row["path"].rsplit("/", 1)[0] for row in descriptor["files"] if "/" in row["path"]}
            retained_bytes = 0
            for path in target.rglob("*"):
                _need(not path.is_symlink() and (path.is_file() or path.is_dir()),
                      "PROTOTYPE_AUTHORITY_ENTRY_UNSAFE")
                if path.is_file():
                    name = path.relative_to(target).as_posix()
                    _need(name in {row["path"] for row in descriptor["files"]},
                          "PROTOTYPE_AUTHORITY_PATH_NOT_ALLOWED")
                    _need(path.stat().st_size <= 20_000_000, "PROTOTYPE_AUTHORITY_FILE_IDENTITY_INVALID")
                    retained_bytes += path.stat().st_size
                    _need(retained_bytes <= 64 * 1024 * 1024 and len(actual) < 2048,
                          "PROTOTYPE_AUTHORITY_MANIFEST_INVALID")
                    actual[name] = path.read_bytes()
                else:
                    _need(path.relative_to(target).as_posix() in allowed_directories,
                          "PROTOTYPE_AUTHORITY_PATH_NOT_ALLOWED")
            _need(set(actual) == {row["path"] for row in descriptor["files"]},
                  "PROTOTYPE_AUTHORITY_MEMBERSHIP_MISMATCH")
            for row in descriptor["files"]:
                raw = actual[row["path"]]
                _need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
                      "PROTOTYPE_AUTHORITY_BYTES_CHANGED")
            _check_authority_members(descriptor, actual)
            return {"schema_version": 1, "scope": "fox-prototype-authority-staging-receipt-v1",
                    "job_id": job_id, "source_binding": descriptor["source_binding"],
                    "source_authority": descriptor["source_authority"],
                    "manifest_sha256": manifest["manifest_sha256"], "staged": True,
                    "source_review_authorized": False}

    def _authorize(self, request):
        _need(callable(self.authorize), "PROTOTYPE_SOURCE_REVIEW_AUTHORIZATION_UNAVAILABLE")
        value = deepcopy(request)
        _need(self.authorize(value) == request and value == request,
              "PROTOTYPE_SOURCE_REVIEW_AUTHORIZATION_FAILED")

    def _request(self, stage, request):
        _need(stage in STAGES, "PROTOTYPE_STAGE_INVALID")
        _need(type(request) is dict and set(request) == _REQUEST,
              "PROTOTYPE_REQUEST_FIELDS_INVALID")
        _need(type(request["schema_version"]) is int and request["schema_version"] == 1
              and request["scope"] == "fox-prototype-converter-request-v1",
              "PROTOTYPE_REQUEST_SCOPE_INVALID")
        _need(type(request["job_id"]) is str, "PROTOTYPE_JOB_INVALID")
        validate_job_id(request["job_id"])
        _need(all(type(request[key]) is str and _SHA.fullmatch(request[key])
                  for key in ("source_binding", "plan_sha256", "rendered_zip_sha256")),
              "PROTOTYPE_REQUEST_HASH_INVALID")
        authority = request["source_authority"]
        _need(type(authority) is dict and set(authority) == {"schema_version", "scope",
              "binding_sha256", "sources_manifest_sha256", "review_index_sha256"}
              and type(authority["schema_version"]) is int and authority["schema_version"] == 1
              and authority["scope"] == "fox-prototype-source-authority-v1"
              and all(type(authority[key]) is str and _SHA.fullmatch(authority[key])
                      for key in ("binding_sha256", "sources_manifest_sha256", "review_index_sha256")),
              "PROTOTYPE_SOURCE_AUTHORITY_FIELDS_INVALID")
        spec = native_blueprint.validate_prototype_spec(request["rendering_spec"])
        _need(spec == request["rendering_spec"] and spec["source_binding"] == request["source_binding"]
              and spec["project_id"] == request["project_id"], "PROTOTYPE_SOURCE_BINDING_MISMATCH")
        raw = native_blueprint.deterministic_prototype_zip(spec)
        _need(hashlib.sha256(raw).hexdigest() == request["rendered_zip_sha256"],
              "PROTOTYPE_RENDERED_ZIP_MISMATCH")
        prior = STAGES[:STAGES.index(stage)]
        _need(type(request["prior_receipts"]) is dict and set(request["prior_receipts"]) == set(prior),
              "PROTOTYPE_PRIOR_STAGES_INVALID")
        self._authorize(request)
        return spec, raw

    def _root(self, request, *, create):
        jobs = Path(self.settings.jobs_root).absolute()
        _need(not jobs.is_symlink() and jobs.is_dir(), "PROTOTYPE_JOBS_ROOT_INVALID")
        job = jobs / request["job_id"]
        _need(not job.is_symlink(), "PROTOTYPE_JOB_LINKED")
        if create:
            job.mkdir(exist_ok=True)
        elif not job.exists():
            return job / "prototype-converter"
        _need(job.is_dir() and job.resolve().parent == jobs.resolve(), "PROTOTYPE_JOB_ROOT_INVALID")
        root = job / "prototype-converter"
        _need(not root.is_symlink(), "PROTOTYPE_EVIDENCE_LINKED")
        if create:
            root.mkdir(exist_ok=True)
        return root

    def _check_prior(self, root, request):
        for stage, supplied in request["prior_receipts"].items():
            path = root / (stage + ".json")
            _need(read_object(path) == supplied, "PROTOTYPE_PRIOR_RECEIPT_MISMATCH")
            _need(supplied.get("status") == "COMPLETE", "PROTOTYPE_PRIOR_STAGE_NOT_PASSED")
            original = {**request, "prior_receipts": {key: request["prior_receipts"][key]
                        for key in STAGES[:STAGES.index(stage)]}}
            self._check_receipt(stage, original, supplied)
            if stage == "verify_runtime":
                from .prototype_release import validate_runtime_receipt
                validate_runtime_receipt(root, request, request["prior_receipts"]["import"],
                                         read_object(root / "snapshot.json"), supplied["runtime_receipt"])

    @staticmethod
    def _check_receipt(stage, request, receipt):
        expected = {"stage": stage, "request_sha256": digest(request),
                    "source_binding": request["source_binding"], "plan_sha256": request["plan_sha256"]}
        _need(type(receipt) is dict and all(receipt.get(k) == v for k, v in expected.items()),
              "PROTOTYPE_RECEIPT_BINDING_MISMATCH")
        gates = {"validate": "passed", "prepare_schema": "ready_for_import", "import": "imported",
                 "verify_runtime": "passed", "export": "exported"}
        if receipt.get("status") == "COMPLETE" and stage in gates:
            _need(receipt.get(gates[stage]) is True, "PROTOTYPE_RECEIPT_GATE_INVALID")
            if stage == "import":
                _need(type(receipt.get("application_id")) is int and receipt["application_id"] > 0
                      and all(type(receipt.get(key)) is str and _SHA.fullmatch(receipt[key])
                              for key in ("import_intent_sha256", "compiled_metadata_sha256")),
                      "PROTOTYPE_IMPORT_COMPLETION_PROOF_REQUIRED")
            if stage == "verify_runtime":
                _need(receipt.get("authenticated") is True and receipt.get("business_pages_tested") is True
                      and type(receipt.get("runtime_receipt")) is dict
                      and digest(receipt["runtime_receipt"]) == receipt.get("runtime_receipt_sha256"),
                      "PROTOTYPE_AUTHENTICATED_RUNTIME_REQUIRED")
            if stage == "export":
                _need(type(receipt.get("package_sha256")) is str and _SHA.fullmatch(receipt["package_sha256"]),
                      "PROTOTYPE_EXPORT_PACKAGE_HASH_REQUIRED")
        _need(receipt.get("business_behavior_accepted") is False, "PROTOTYPE_ACCEPTANCE_FORBIDDEN")

    def _snapshot(self, root, request, spec, raw, *, create):
        archive = root / "candidate-apexlang.zip"
        binding = {"schema_version": 1, "job_id": request["job_id"],
                   "project_id": request["project_id"], "source_binding": request["source_binding"],
                   "plan_sha256": request["plan_sha256"], "rendering_spec_sha256": digest(spec),
                   "source_authority": request["source_authority"],
                   "draft_zip_sha256": request["rendered_zip_sha256"],
                   "template": native_blueprint.context()}
        if create:
            _new_bytes(archive, raw)
            publish(root / "snapshot.json", binding)
        _need(read_object(root / "snapshot.json") == binding and file_digest(archive) == binding["draft_zip_sha256"]
              and archive.read_bytes() == raw, "PROTOTYPE_SNAPSHOT_CHANGED")
        return archive, binding

    def _target_preflight(self, request, action, root):
        profile = runtime_preflight.bound_target_profile(self.settings)
        value = runtime_preflight.collect_deterministic_preflight(
            self.settings, root.parent, job_id=request["job_id"], action=action,
            source_manifest_sha256=request["source_binding"])
        def check():
            self._authorize(request)
            runtime_preflight.verify_action_preflight(value, profile, job_id=request["job_id"],
                action=action, source_manifest_sha256=request["source_binding"],
                now=datetime.now(timezone.utc))
        check()
        return check

    def _saved_connection(self):
        _need(self.settings.sqlcl_connection_name == "F2A_APEX"
              and self.settings.apex_workspace == "FORMS2APEX_POC"
              and getattr(self.settings, "apex_parsing_schema", "FORMS2APEX_POC") == "FORMS2APEX_POC",
              "PROTOTYPE_EXACT_SAVED_JSN_TARGET_REQUIRED")

    def _sql(self, root, commands):
        self._saved_connection()
        result = self.runner(self.settings.sqlcl_path, ["-S", "-L", "-name", "F2A_APEX"],
            ["set sqlformat default", "set pagesize 0", "set linesize 32767", "set trimout on",
             "set define off", "whenever oserror exit failure rollback",
             sqlcl._target_guard("FORMS2APEX_POC"), *commands], root, timeout=120)
        _need(result.returncode == 0 and isinstance(result.stderr, str) and not result.stderr.strip(),
              "PROTOTYPE_SCHEMA_SQLCL_FAILED_NO_REPLAY")
        return result.stdout

    def _observe(self, root, spec):
        """Exact bounded dictionary metadata, without the old 20-column gate."""
        for block in spec["blocks"]:
            if block["classification"] != "database":
                continue
            table = block["table_name"]  # Derived and strict-validated, never uploaded SQL.
            output = self._sql(root, [
                "select 'FOX_NATIVE_BEGIN=1' from dual;",
                f"select 'FOX_NATIVE_TABLE_COUNT='||count(*) from user_tables where table_name='{table}';",
                "select 'FOX_NATIVE_COLUMN='||column_name||'|'||data_type||'|'||nullable||'|'||"
                "to_char(nvl(char_length,0),'TM9')||'|'||identity_column from user_tab_columns "
                f"where table_name='{table}' order by column_id;",
                f"select 'FOX_NATIVE_PK_COUNT='||count(*) from user_constraints where table_name='{table}' and constraint_type='P';",
                "select 'FOX_NATIVE_PK='||cc.column_name||'|'||to_char(cc.position,'TM9')||'|'||c.status||'|'||c.validated "
                "from user_constraints c join user_cons_columns cc on cc.constraint_name=c.constraint_name "
                f"and cc.table_name=c.table_name where c.table_name='{table}' and c.constraint_type='P' order by cc.position;",
                f"select 'FOX_NATIVE_ENABLED_TRIGGER_COUNT='||count(*) from user_triggers where table_name='{table}' and status='ENABLED';",
                "select 'FOX_NATIVE_OK=1' from dual;"])
            counts, columns, keys = native_target._parse_output(output)
            expected = [{"name": col["name"], "data_type": col["data_type"], "nullable": col["nullable"],
                         "char_length": col.get("length", 0), "identity": col["identity"]}
                        for col in native_blueprint._columns(block)]
            _need(counts["TABLE_COUNT"] == counts["PK_COUNT"] == 1
                  and counts["ENABLED_TRIGGER_COUNT"] == 0 and columns == expected
                  and keys == [native_blueprint.KEY], "PROTOTYPE_SCHEMA_METADATA_MISMATCH")

    def _prepare_schema(self, root, request, spec, check):
        tables = [block["table_name"] for block in spec["blocks"] if block["classification"] == "database"]
        ddl = native_blueprint.render_prototype_schema(spec)
        _new_bytes(root / "synthetic-schema.sql", ddl.encode("utf-8"))
        if tables:
            names = ",".join("'" + table + "'" for table in tables)
            # A pre-existing object of ANY kind is never adopted or replaced.
            output = self._sql(root, [f"select 'FOX_PROTO_ABSENT='||count(*) from user_objects where object_name in ({names});"])
            _need(output.strip() == "FOX_PROTO_ABSENT=0", "PROTOTYPE_EXISTING_OBJECT_PRESERVED")
            check()
            publish(root / "schema-write-intent.json", {"request_sha256": digest(request), "ddl_sha256": hashlib.sha256(ddl.encode()).hexdigest()})
            check()
            # Repeat absence guard in the same guarded session as the only DDL.
            output = self._sql(root, [
                f"declare n number; begin select count(*) into n from user_objects where object_name in ({names}); "
                "if n<>0 then raise_application_error(-20084,'FOX existing prototype object preserved'); end if; end;\n/",
                ddl, "select 'FOX_PROTO_CREATED=1' from dual;"])
            _need(output.strip() == "FOX_PROTO_CREATED=1", "PROTOTYPE_SCHEMA_OUTCOME_UNCONFIRMED")
            self._observe(root, spec)
        return {"ready_for_import": True, "tables": tables,
                "schema_ddl_sha256": hashlib.sha256(ddl.encode()).hexdigest(), "database_writes": bool(tables)}

    def run_stage(self, stage, request):
        request = deepcopy(request)
        with _LOCK:
            spec, raw = self._request(stage, request)
            if not self.supports(stage):
                return self._receipt(stage, request, "UNAVAILABLE", code="PROTOTYPE_STAGE_PROOF_NOT_IMPLEMENTED")
            root = self._root(request, create=True)
            self._check_prior(root, request)
            archive, binding = self._snapshot(root, request, spec, raw, create=stage == "validate")
            intent = root / (stage + "-intent.json")
            _need(not intent.exists() and not intent.is_symlink() and not (root / (stage + ".json")).exists(),
                  "PROTOTYPE_STAGE_ALREADY_ATTEMPTED_RECOVER_ONLY")
            publish(root / (stage + "-request.json"), request)
            # Exclusive claim: identical simultaneous requests must not both
            # reach a side effect, even from independent converter processes.
            with intent.open("xb") as stream:
                stream.write(canonical({"request_sha256": digest(request)}) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            def unchanged():
                self._authorize(request)
                self._snapshot(root, request, spec, raw, create=False)
                self._check_prior(root, request)
            if stage == "validate":
                # SQLcl validates an actual app directory extracted from the
                # exact deterministic ZIP, never a string or design surrogate.
                # Keep the checked directory shallow on Windows (SQLcl's theme
                # files are deep). The immutable ZIP remains in the job root.
                with tempfile.TemporaryDirectory(prefix=".p-", dir=Path(self.settings.jobs_root).parent) as temporary:
                    app = Path(temporary) / "apexlang"
                    app.mkdir()
                    with zipfile.ZipFile(io.BytesIO(raw)) as archive_input:
                        archive_input.extractall(app)  # Trusted renderer bytes only.
                    before = tree_digest(app)
                    result = self.validator(self.settings.sqlcl_path, app, root / "validation.log")
                    _need(tree_digest(app) == before, "PROTOTYPE_VALIDATION_INPUT_CHANGED")
                    unchanged()
                passed = result.get("passed") is True and result.get("return_code") == 0
                receipt = self._receipt(stage, request, "COMPLETE" if passed else "FAILED", passed=passed,
                    validation=result, draft_sha256=before, artifact_binding=binding)
            else:
                self._saved_connection()
                action = "prepare-schema" if stage == "prepare_schema" else ("import" if stage == "import" else "release")
                fresh = self.preflight(request, action, root)
                _need(callable(fresh), "PROTOTYPE_FRESH_TARGET_AUTHORITY_REQUIRED")
                def check():
                    unchanged()
                    fresh()
                check()
                if stage == "prepare_schema":
                    result = self._prepare_schema(root, request, spec, check)
                elif stage == "import":
                    self._observe(root, spec)
                    result = self.importer(self.settings.sqlcl_path, "F2A_APEX", "FORMS2APEX_POC",
                        request["job_id"], archive, root / "import.log", intent_path=root / "import-reservation.json",
                        expected_draft_sha256=request["rendered_zip_sha256"], artifact_binding=binding,
                        pre_write_check=check)
                    _need(type(result.get("application_id")) is int and result["application_id"] > 0
                          and type(result.get("import_intent_sha256")) is str and _SHA.fullmatch(result["import_intent_sha256"])
                          and type(result.get("compiled_metadata_sha256")) is str and _SHA.fullmatch(result["compiled_metadata_sha256"]),
                          "PROTOTYPE_IMPORT_COMPLETION_PROOF_REQUIRED")
                    result = {**result, "imported": True}
                else:
                    from .prototype_release import verify_runtime, export_prototype
                    imported = request["prior_receipts"]["import"]
                    self._observe(root, spec)
                    if stage == "verify_runtime":
                        result = verify_runtime(self.settings, root, request, imported=imported,
                            artifact_binding=binding, verifier=self.runtime_verifier, freshness_check=check)
                    else:
                        result = export_prototype(self.settings, root, request, imported=imported,
                            artifact_binding=binding,
                            runtime_receipt=request["prior_receipts"]["verify_runtime"]["runtime_receipt"],
                            freshness_check=check, runner=self.runner, validator=self.validator,
                            target_profile_loader=self.target_profile_loader)
                unchanged()
                receipt = self._receipt(stage, request, "COMPLETE", **result)
            publish(root / (stage + ".json"), receipt)
            return receipt

    execute_stage = run_stage

    @staticmethod
    def _receipt(stage, request, status, **result):
        return {"schema_version": 1, "scope": "fox-prototype-converter-receipt-v1", "stage": stage,
                "request_sha256": digest(request), "source_binding": request["source_binding"],
                "plan_sha256": request["plan_sha256"], "status": status,
                "business_behavior_accepted": False, **result}

    def recover_stage(self, stage, request):
        """Read retained completion only; never allocate/import/repair or replay.

        An incomplete import may be reconciled separately by the existing
        reconcile_apexlang_import helper, but never guessed successful here.
        """
        request = deepcopy(request)
        with _LOCK:
            spec, raw = self._request(stage, request)
            root = self._root(request, create=False)
            if not root.exists():
                return None
            path = root / (stage + ".json")
            if not path.exists() and not path.is_symlink():
                return None
            self._check_prior(root, request)
            self._snapshot(root, request, spec, raw, create=False)
            _need(read_object(root / (stage + "-request.json")) == request,
                  "PROTOTYPE_STAGE_REQUEST_CHANGED")
            _need(read_object(root / (stage + "-intent.json")) == {"request_sha256": digest(request)},
                  "PROTOTYPE_STAGE_INTENT_CHANGED")
            receipt = read_object(path)
            self._check_receipt(stage, request, receipt)
            if stage == "verify_runtime":
                from .prototype_release import validate_runtime_receipt
                validate_runtime_receipt(root, request, request["prior_receipts"]["import"],
                                         read_object(root / "snapshot.json"), receipt["runtime_receipt"])
            if stage == "export":
                from .prototype_release import validate_prototype_package
                package = root / "prototype-package.zip"
                _need(file_digest(package) == receipt["package_sha256"], "PROTOTYPE_EXPORT_PACKAGE_CHANGED")
                validate_prototype_package(package.read_bytes(), request=request,
                    runtime_receipt=request["prior_receipts"]["verify_runtime"]["runtime_receipt"],
                    imported=request["prior_receipts"]["import"], artifact_binding=read_object(root / "snapshot.json"),
                    export_receipt=receipt)
            return receipt

    def recover_stage_for_job(self, job_id, stage):
        """Request-free internal GET route, bound to its exact saved envelope."""
        validate_job_id(job_id)
        _need(stage in STAGES, "PROTOTYPE_STAGE_INVALID")
        with _LOCK:
            root = self._root({"job_id": job_id}, create=False)
            path = root / (stage + "-request.json")
            if not path.exists() and not path.is_symlink():
                return None
            request = read_object(path)
            _need(request.get("job_id") == job_id, "PROTOTYPE_STAGE_REQUEST_CHANGED")
            return self.recover_stage(stage, request)
