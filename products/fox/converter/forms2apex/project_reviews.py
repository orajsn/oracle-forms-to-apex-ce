"""Complete-source project reviews assembled from independently sealed form reviews.

This is an executor trust boundary, not a vendor attestation. No model-produced
SQL/APEXlang enters the renderer. Legacy single-form receipts are never upgraded.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from . import native_project, review_receipts
from .forms_inventory import inspect_intake
from .provenance import tree_digest
from .security import validate_job_id


_CANDIDATE_FIELDS = {"job_id", "template_id", "data_classification", "generator",
                     "native_project", "remediation_items", "mapping_summary"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read_object(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4_000_000:
        raise RuntimeError("Project evidence is missing, linked, or exceeds its bound")
    value = json.loads(path.read_bytes(), object_pairs_hook=review_receipts._unique_keys)
    if type(value) is not dict:
        raise ValueError("Project evidence must be an object")
    return value


def publish(path, value):
    """Immutable publication; an exact replay is allowed, replacement is not."""
    path = Path(path)
    raw = canonical(value) + b"\n"
    if path.exists() or path.is_symlink():
        if read_object(path) != value:
            raise RuntimeError("Different project evidence already exists; use a new job")
        return value
    fd, name = tempfile.mkstemp(prefix=".project-evidence-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if read_object(path) != value:
                raise RuntimeError("Different project evidence already exists; use a new job")
        review_receipts._sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return value


def publish_directory(source, target):
    """Retry only a Windows transient rename lock; never replace a target."""
    for attempt in range(5):
        if target.exists() or target.is_symlink():
            raise FileExistsError("Project directory already exists; preserved")
        try:
            source.rename(target)
            return
        except PermissionError:
            if os.name != "nt" or attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))


def cleanup_temporary(path, parent, prefix):
    """Remove only a checked, newly-created direct temporary child directory."""
    path, parent = Path(path), Path(parent)
    if not path.exists() and not path.is_symlink():
        return
    resolved_parent = parent.resolve(strict=True)
    if (path.is_symlink() or not path.is_dir() or path.resolve(strict=True).parent != resolved_parent
            or not path.name.startswith(prefix) or path.name == prefix):
        raise RuntimeError("Unsafe temporary cleanup target; directory preserved")
    shutil.rmtree(path.resolve(strict=True))


def child_root(root, module_id, plan=None):
    from .project_source import module_execution_binding
    root = Path(root)
    plan = project_from_intake(root, return_plan=True) if plan is None else plan
    binding = module_execution_binding(plan, parent_job_id=root.name, module_id=module_id)
    return root / "form-reviews" / binding["child_job_id"]


def project_from_intake(root, *, return_plan=False):
    """Recheck frozen source membership and the complete conservative source plan."""
    root = Path(root)
    manifest = read_object(root / "intake/manifest.json")
    if manifest.get("job_id") != root.name or manifest.get("conversion_profile") != native_project.PROFILE_ID:
        raise ValueError("An exact native project intake is required")
    project = native_project.validate_project_spec(manifest.get("native_project"))
    files, names = [], set()
    for entry in manifest.get("files", []):
        name = entry.get("packaged_name")
        if (not isinstance(name, str) or name in names or any(token in name for token in ("/", "\\", ":", ".."))
                or name == "manifest.json"):
            raise ValueError("Project source membership is invalid")
        names.add(name)
        path = root / "intake" / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Project source is missing or linked")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry.get("sha256"):
            raise ValueError("Project source hash changed")
        files.append({"name": name, "sha256": entry["sha256"], "text": raw.decode("utf-8")})
    if {path.name for path in (root / "intake").iterdir()} != names | {"manifest.json"}:
        raise ValueError("Project source membership changed")
    source_hash = hashlib.sha256("\n".join(file["name"] + ":" + file["sha256"]
                                          for file in sorted(files, key=lambda f: f["name"])).encode()).hexdigest()
    if source_hash != manifest.get("source_manifest_sha256") or source_hash != project["source_manifest_sha256"]:
        raise ValueError("Project source manifest hash changed")
    from .project_source import validate_project_sources
    plan = validate_project_sources(project, files, project_id=manifest["project_id"], plan_sha256=manifest["plan_sha256"])
    return plan if return_plan else project


def stage_project_snapshot(jobs_root, job_id, snapshot):
    """Reuse the established bounded source intake before atomically publishing."""
    from .fox_gateway import stage_snapshot
    if type(snapshot) is not dict or set(snapshot) != {"source_hash", "files", "conversion_profile", "native_project",
                                                    "project_id", "project_name", "plan_sha256"}:
        raise ValueError("Project snapshot fields are invalid")
    if snapshot["conversion_profile"] != native_project.PROFILE_ID:
        raise ValueError("Project profile is required")
    project = native_project.validate_project_spec(snapshot["native_project"])
    if snapshot["project_name"] != project["project_name"]:
        raise ValueError("Project name binding changed")
    root = Path(jobs_root)
    target = root / job_id
    validate_job_id(job_id)
    if target.exists() or target.is_symlink():
        raise FileExistsError("Job already exists; reconcile instead of replaying")
    temporary = Path(tempfile.mkdtemp(prefix=".project-intake-", dir=root))
    try:
        stage_snapshot(temporary, job_id, {"source_hash": snapshot["source_hash"], "files": snapshot["files"]})
        staged = temporary / job_id
        manifest_path = staged / "intake/manifest.json"
        manifest = read_object(manifest_path)
        manifest.update(conversion_profile=native_project.PROFILE_ID, native_project=project,
                        project_id=snapshot["project_id"], plan_sha256=snapshot["plan_sha256"])
        manifest_path.write_bytes(canonical(manifest) + b"\n")
        project_from_intake(staged)
        publish_directory(staged, target)
    finally:
        cleanup_temporary(temporary, root, ".project-intake-")
    return {"job_id": job_id, "state": "INTAKE_READY", "conversion_profile": native_project.PROFILE_ID,
            "source_manifest_sha256": snapshot["source_hash"], "form_count": len(project["forms"])}


def project_inventory_rows(plan, parent_job_id, shared_inventory):
    """Pure source-plan projection shared by live intake and package readers."""
    from .project_source import module_execution_binding
    project = plan["rendering_spec"]
    results = []
    for form in project["forms"]:
        execution = module_execution_binding(plan, parent_job_id=parent_job_id, module_id=form["module_id"])
        mapped = project["schema_version"] == 2
        trusted = ({"storage_mapping": form["storage_mapping"], "ddl_sources": form["ddl_sources"],
                    "module_execution_binding": execution} if mapped else {})
        sources = [{"name": source["name"], "sha256": source["sha256"]}
                   for source in plan["source_files"] if form["module_id"] in source["module_ids"]]
        projection = {"scope": "fox-project-module-source-projection-v2" if mapped else "fox-project-module-source-projection-v1",
            "module_id": form["module_id"], "source_manifest_sha256": project["source_manifest_sha256"],
            "sources": sorted(sources, key=lambda source: source["name"]), **trusted}
        inventory = {"job_id": execution["child_job_id"], "shared_inventory_sha256": digest(shared_inventory),
            "source_projection": projection, "source_projection_sha256": digest(projection),
            "approved_native_form": form["native_form"], "remediation_items": shared_inventory["remediation_items"],
            "project_module": {key: form[key] for key in ("module_id", "form_name", "source_name", "source_sha256")},
            **trusted}
        results.append({"module_id": form["module_id"], "child_job_id": execution["child_job_id"],
            "source_hash": project["source_manifest_sha256"], "inventory": inventory, "binding": execution})
    return results


def ensure_form_intakes(root, shared_inventory=None):
    from .project_source import module_execution_binding
    root = Path(root)
    plan = project_from_intake(root, return_plan=True)
    project = plan["rendering_spec"]
    manifest = read_object(root / "intake/manifest.json")
    if shared_inventory is None:
        shared_inventory = {key: value for key, value in inspect_intake(root).items() if key != "job_id"}
    results = project_inventory_rows(plan, root.name, shared_inventory)
    children = root / "form-reviews"
    if children.is_symlink():
        raise RuntimeError("Project review directory cannot be linked")
    children.mkdir(exist_ok=True)
    for form in project["forms"]:
        child = child_root(root, form["module_id"], plan)
        execution = module_execution_binding(plan, parent_job_id=root.name, module_id=form["module_id"])
        mapped = project["schema_version"] == 2
        child_manifest = {"job_id": child.name, "source_manifest_sha256": project["source_manifest_sha256"],
                          "conversion_profile": "native-table-form-v1", "native_form": form["native_form"],
                          "files": manifest["files"]}
        trusted_mapping = ({"storage_mapping": form["storage_mapping"], "ddl_sources": form["ddl_sources"],
                            "module_execution_binding": execution} if mapped else {})
        # The original source files are copied byte-for-byte. The mapping is
        # separate, deterministic executor metadata sealed by the intake hash.
        child_manifest.update(trusted_mapping)
        if child.exists() or child.is_symlink():
            if child.is_symlink() or read_object(child / "intake/manifest.json") != child_manifest:
                raise RuntimeError("Per-form intake changed")
        else:
            temporary = Path(tempfile.mkdtemp(prefix=".form-intake-", dir=children))
            try:
                shutil.copytree(root / "intake", temporary / "intake")
                (temporary / "intake/manifest.json").write_bytes(canonical(child_manifest) + b"\n")
                publish_directory(temporary, child)
            finally:
                cleanup_temporary(temporary, children, ".form-intake-")
        review_receipts._source_binding(child, child.name, project["source_manifest_sha256"], form["native_form"])
    return results


def project_model_request(root, row, shared_inventory=None):
    """Reconstruct the exact trusted per-form request, without rewriting source.

    The independent reviewer receives this same source/mapping context plus
    the candidate. Sealing only a physical schema is insufficient for v2.
    """
    root = Path(root) if root is not None else None
    shared = ({key: value for key, value in inspect_intake(root).items() if key != "job_id"}
              if shared_inventory is None else shared_inventory)
    compact = row["inventory"]
    if digest(shared) != compact["shared_inventory_sha256"]:
        raise ValueError("Shared source inventory changed before independent review")
    selected = {source["name"] for source in compact["source_projection"]["sources"]}
    inventory = {**shared, **compact,
        "modules": [module for module in shared["modules"] if module["file"] in selected],
        "complete_source_manifest": {"scope": "fox-project-complete-source-manifest-v1",
            "source_manifest_sha256": row["source_hash"], "files": [
                {"name": module["file"], "sha256": module["sha256"], "bytes": module["bytes"]}
                for module in sorted(shared["modules"], key=lambda value: value["file"])]}}
    trusted = {key: compact[key] for key in ("storage_mapping", "ddl_sources", "module_execution_binding")
               if key in compact}
    return {"job_id": row["child_job_id"], "source_hash": row["source_hash"],
            "inventory": inventory, "native_form": compact["approved_native_form"], **trusted}


def _verify_mapping_request(payload, request):
    if (payload.get("mapper_invocation", {}).get("request_sha256") != digest(request)
            or payload.get("reviewer_invocation", {}).get("request_sha256") != digest({
                **request, "candidate": payload.get("candidate"), "candidate_sha256": digest(payload.get("candidate"))})):
        raise ValueError("Mapped form review must bind the exact original-source and verified-storage requests")


def record_project_form_review(root, module_id, payload, *identity, target_profile=None):
    project = project_from_intake(root)
    if module_id not in {form["module_id"] for form in project["forms"]}:
        raise ValueError("Review refers to an unselected form")
    rows = ensure_form_intakes(root)
    if target_profile is None:
        raise ValueError("New project reviews require a registered target profile and version 2 environment proof")
    if project["schema_version"] == 2:
        from .workflow_router import project_mapping_profile_supported
        if not project_mapping_profile_supported(target_profile):
            raise ValueError("Mapped-storage projects require a new registered paired project-v2 mapper/reviewer profile")
        row = next(row for row in rows if row["module_id"] == module_id)
        _verify_mapping_request(payload, project_model_request(root, row))
    receipt = review_receipts.record_review(child_root(root, module_id), payload, *identity, target_profile=target_profile)
    if receipt["schema_version"] != 2:
        raise ValueError("Legacy single-form evidence cannot authorize a new project")
    return receipt


def _aggregate(root, payload, identity):
    plan = project_from_intake(root, return_plan=True)
    project = plan["rendering_spec"]
    request_rows = ({row["module_id"]: row for row in ensure_form_intakes(root)}
                    if project["schema_version"] == 2 else {})
    if type(payload) is not dict or set(payload) != {"job_id", "source_hash", "form_reviews"}:
        raise ValueError("Project aggregate review fields invalid")
    if payload["job_id"] != root.name or payload["source_hash"] != project["source_manifest_sha256"]:
        raise ValueError("Project aggregate source binding invalid")
    expected = {form["module_id"] for form in project["forms"]}
    supplied = payload["form_reviews"]
    if (type(supplied) is not list or len(supplied) != len(expected)
            or any(type(row) is not dict or set(row) != {"module_id", "receipt_sha256"} for row in supplied)
            or {row["module_id"] for row in supplied} != expected):
        raise ValueError("Every selected form requires exactly one review")
    refs = {row["module_id"]: row["receipt_sha256"] for row in supplied}
    rows, remediation, summaries, models = [], [], [], set()
    for form in project["forms"]:
        module = form["module_id"]
        child = child_root(root, module, plan)
        recorded = read_object(child / "native-review.json")
        receipt = review_receipts.verify_review(child, recorded["candidate"], *identity)
        if receipt["schema_version"] != 2 or receipt["receipt_sha256"] != refs[module]:
            raise ValueError("Project requires the exact version 2 form review")
        if project["schema_version"] == 2:
            from .workflow_router import project_mapping_profile_supported
            if not project_mapping_profile_supported(receipt.get("historical_target_profile")):
                raise ValueError("Mapped project review requires its registered paired project-v2 profile")
            from .project_source import module_execution_binding
            execution = module_execution_binding(plan, parent_job_id=root.name, module_id=module)
            child_manifest = read_object(child / "intake/manifest.json")
            if any(child_manifest.get(key) != value for key, value in {
                    "storage_mapping": form["storage_mapping"], "ddl_sources": form["ddl_sources"],
                    "module_execution_binding": execution}.items()):
                raise ValueError("Per-form review intake changed its verified source-to-storage binding")
            _verify_mapping_request(receipt, project_model_request(root, request_rows[module]))
        if native_project.schema_contract(receipt["candidate"]["native_form"]) != native_project.schema_contract(form["native_form"]):
            raise ValueError("Reviewed form differs from project schema")
        # Labels are part of the approved behavior as well as schema metadata.
        from .native_contract import validate_native_spec
        if validate_native_spec(receipt["candidate"]["native_form"]) != form["native_form"]:
            raise ValueError("Reviewed form differs from the exact project mapping")
        required = {(item.get("file"), item.get("kind")) for item in inspect_intake(child)["remediation_items"]}
        supplied_items = receipt["candidate"]["remediation_items"]
        if not required.issubset({(item.get("file"), item.get("kind")) for item in supplied_items}):
            raise ValueError("Per-form review omitted source remediation")
        remediation.extend({**item, "module_id": module} for item in supplied_items)
        summaries.append(form["form_name"] + ": " + receipt["candidate"]["mapping_summary"])
        models.add(receipt["candidate"]["generator"]["model"])
        rows.append({"module_id": module, "child_job_id": child.name,
                     "candidate_sha256": receipt["candidate_sha256"], "receipt_sha256": receipt["receipt_sha256"],
                     **({"execution_binding": execution} if project["schema_version"] == 2 else {})})
    if len(models) != 1:
        raise ValueError("Project mapper model identity must be consistent")
    candidate = {"job_id": root.name, "template_id": native_project.TEMPLATE_ID,
                 "data_classification": "synthetic_or_stub_only", "generator": {"model": models.pop()},
                 "native_project": project, "remediation_items": remediation, "mapping_summary": "\n".join(summaries)}
    version = project["schema_version"]
    content = {"schema_version": version, "scope": "fox-native-project-review-v" + str(version),
               "trust_boundary": "authenticated_fox_executor_not_vendor_attestation",
               "job_id": root.name, "source_hash": project["source_manifest_sha256"],
               "intake_sha256": tree_digest(root / "intake"), "candidate": candidate,
               "candidate_sha256": digest(candidate), "form_reviews": rows, "verdict": "approve"}
    if version == 2:
        content.update(project_id=project["project_id"], plan_sha256=plan["plan_sha256"])
    receipt = {**content, "receipt_sha256": digest(content)}
    if len(canonical(receipt)) + 1 > 4_000_000:
        raise ValueError("Project review exceeds the protected evidence limit; no partial form set is accepted")
    return receipt


def aggregate_project_review(root, payload, *identity):
    root = Path(root)
    receipt = _aggregate(root, payload, identity)
    return publish(root / "project-review.json", receipt)


def verify_project_review(root, candidate, *identity):
    root = Path(root)
    if type(candidate) is not dict or set(candidate) != _CANDIDATE_FIELDS:
        raise ValueError("Project candidate accepts only the approved metadata envelope")
    recorded = read_object(root / "project-review.json")
    payload = {"job_id": root.name, "source_hash": recorded.get("source_hash"),
               "form_reviews": [{"module_id": row["module_id"], "receipt_sha256": row["receipt_sha256"]}
                                for row in recorded.get("form_reviews", [])]}
    expected = _aggregate(root, payload, identity)
    if recorded != expected or candidate != expected["candidate"]:
        raise ValueError("Project review no longer binds every selected form and exact candidate")
    return recorded
