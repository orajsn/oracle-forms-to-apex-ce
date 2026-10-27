"""One complete reviewed Forms project -> one deterministic native APEX app.

The public MCP surface remains unchanged. The gateway dispatches by the frozen
intake profile. Schema preparation is a distinct guarded internal operation,
never hidden in the APEX import or replayed after uncertain database outcomes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid

from . import native_project, project_reviews
from .forms_inventory import inspect_intake
from .provenance import inspection_binding, tree_digest, file_digest, draft_snapshot
from .release import _atomic_json, runtime_login_check
from .sqlcl import validate_apexlang, import_apexlang_durable, reconcile_apexlang_import
from .workflow import ConverterWorkflow, serialized


class ProjectWorkflow(ConverterWorkflow):
    def verify_project_review(self, root, spec):
        return project_reviews.verify_project_review(root, spec, *self.review_identity())

    @serialized
    def inspect(self, job_id):
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        if status["state"] not in {"INTAKE_READY", "INSPECTED"} or (root / "import-intent.json").exists():
            raise RuntimeError("Project inspection is blocked after materialization")
        project = project_reviews.project_from_intake(root)
        before = tree_digest(root / "intake")
        shared = {key: value for key, value in inspect_intake(root).items() if key != "job_id"}
        inventory = {"schema_version": 1, "inspection_format": "shared-source-inventory-v1",
                     "job_id": job_id, "source_hash": project["source_manifest_sha256"],
                     "conversion_profile": native_project.PROFILE_ID,
                     "native_project": project, "native_project_profile": native_project.context(),
                     "shared_inventory": shared, "shared_inventory_sha256": project_reviews.digest(shared),
                     "remediation_items": shared["remediation_items"],
                     "forms": project_reviews.ensure_form_intakes(root, shared)}
        report = {"job_id": job_id, "conversion_profile": native_project.PROFILE_ID,
                  "remediation_items": inventory["remediation_items"],
                  "unsupported_count": len(inventory["remediation_items"]),
                  "production_database_connected": False,
                  "data_policy": "Synthetic schema only; no customer business meaning inferred."}
        if tree_digest(root / "intake") != before:
            raise RuntimeError("Project source changed during inspection")
        if status["state"] == "INSPECTED":
            if inspection_binding(root) != status.get("inspection_binding"):
                raise RuntimeError("Project inspection evidence changed")
            return project_reviews.read_object(root / "normalized-forms-inventory.json")
        _atomic_json(root / "normalized-forms-inventory.json", inventory)
        _atomic_json(root / "migration-and-exception-report.json", report)
        self.store.transition(job_id, "INSPECTED", {"inspection_binding": inspection_binding(root)})
        return inventory

    def _binding(self, root):
        return {"schema_version": 1, "job_id": root.name, **inspection_binding(root),
                "reviewed_spec_sha256": file_digest(root / "migration-spec.json"),
                "template_id": native_project.TEMPLATE_ID, "template_sha256": native_project.context()["sha256"],
                "draft_sha256": tree_digest(root / "apexlang"),
                "draft_zip_sha256": file_digest(root / f"{root.name}-apexlang.zip"),
                "project_review_sha256": file_digest(root / "project-review.json"),
                "project_trace_sha256": file_digest(root / "source-to-apex.json")}

    @serialized
    def generate(self, job_id, migration_spec):
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        spec = json.loads(migration_spec, object_pairs_hook=project_reviews.review_receipts._unique_keys)
        self.verify_project_review(root, spec)
        if status["state"] == "DRAFTED":
            self.assert_artifact_binding(job_id)
            if project_reviews.read_object(root / "migration-spec.json") != spec:
                raise RuntimeError("A different project draft already exists")
            return {"job_id": job_id, "draft": str(root / "apexlang"), "zip": str(root / f"{job_id}-apexlang.zip"),
                    "files": len(native_project.render_native_project(spec["native_project"]))}
        if status["state"] != "INSPECTED" or (root / "import-intent.json").exists():
            raise RuntimeError("Project generation requires unchanged inspected evidence")
        if inspection_binding(root) != status.get("inspection_binding"):
            raise RuntimeError("Project source or inspection changed")
        files = native_project.render_native_project(spec["native_project"])
        staging = Path(tempfile.mkdtemp(prefix=".project-draft-", dir=root))
        try:
            for name, content in files.items():
                path = staging / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="\n")
            if (root / "apexlang").exists():
                raise RuntimeError("Unbound project draft exists; operator reconciliation required")
            project_reviews.publish_directory(staging, root / "apexlang")
        finally:
            project_reviews.cleanup_temporary(staging, root, ".project-draft-")
        project_reviews.publish(root / "migration-spec.json", spec)
        project_reviews.publish(root / "source-to-apex.json", native_project.project_trace(spec["native_project"]))
        with (root / f"{job_id}-apexlang.zip").open("xb") as stream:
            stream.write(native_project.deterministic_project_zip(spec["native_project"]))
            stream.flush()
            os.fsync(stream.fileno())
        self.verify_project_review(root, spec)
        if inspection_binding(root) != status["inspection_binding"]:
            raise RuntimeError("Source changed during project materialization")
        self.store.transition(job_id, "DRAFTED", {"artifact_binding": self._binding(root), "validation": None})
        return {"job_id": job_id, "draft": str(root / "apexlang"), "zip": str(root / f"{job_id}-apexlang.zip"),
                "files": len(files), "form_count": len(spec["native_project"]["forms"]), "application_count": 1}

    def assert_artifact_binding(self, job_id):
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        binding = status.get("artifact_binding")
        if not binding or self._binding(root) != binding:
            raise RuntimeError("Project artifact evidence changed or is unbound")
        spec = project_reviews.read_object(root / "migration-spec.json")
        self.verify_project_review(root, spec)
        expected_files = native_project.render_native_project(spec["native_project"])
        actual = {path.relative_to(root / "apexlang").as_posix(): path.read_text(encoding="utf-8")
                  for path in (root / "apexlang").rglob("*") if path.is_file()}
        if actual != expected_files or (root / f"{job_id}-apexlang.zip").read_bytes() != native_project.deterministic_project_zip(spec["native_project"]):
            raise RuntimeError("Project files differ from the trusted deterministic renderer")
        if project_reviews.read_object(root / "source-to-apex.json") != native_project.project_trace(spec["native_project"]):
            raise RuntimeError("Project source-to-APEX trace changed")
        if status["state"] in {"VALID", "IMPORTED"} and status.get("validation", {}).get("artifact_binding") != binding:
            raise RuntimeError("Project validation is not bound to this complete artifact")
        if status["state"] == "IMPORTED" and project_reviews.read_object(root / "imported-application.json") != status.get("import"):
            raise RuntimeError("Project import receipt changed")
        return binding

    def native_target_preflight(self, job_id, action):
        from .runtime_preflight import collect_deterministic_preflight
        root = self.store.require(job_id)
        binding = self.assert_artifact_binding(job_id)
        project = project_reviews.project_from_intake(root)
        receipt = collect_deterministic_preflight(self.settings, root, job_id=job_id, action=action,
                                                  source_manifest_sha256=project["source_manifest_sha256"])
        if self.assert_artifact_binding(job_id) != binding:
            raise RuntimeError("Project changed during target preflight")
        name = "target-check-" + action + "-" + uuid.uuid4().hex[:16] + ".json"
        record = {"schema_version": 1, "artifact_binding": binding, "preflight": receipt}
        project_reviews.publish(root / name, record)
        return {"file": name, "sha256": file_digest(root / name), "action": action,
                "profile_sha256": receipt["profile_sha256"], "receipt_sha256": receipt["receipt_sha256"]}

    @serialized
    def validate(self, job_id):
        root = self.store.require(job_id)
        if self.store.read(job_id)["state"] != "DRAFTED":
            raise RuntimeError("Only a newly drafted project can be validated")
        binding = self.assert_artifact_binding(job_id)
        preflight = self.native_target_preflight(job_id, "validate")
        with draft_snapshot(root, binding["draft_sha256"]) as snapshot:
            result = validate_apexlang(self.settings.sqlcl_path, snapshot, root / "validation-results.log")
            if self.assert_artifact_binding(job_id) != binding or tree_digest(snapshot) != binding["draft_sha256"]:
                raise RuntimeError("Project changed during whole-application validation")
        result.update(job_id=job_id, artifact_binding=binding, target_preflight=preflight,
                      conversion_profile=native_project.PROFILE_ID, validation_scope="complete_project")
        self.store.transition(job_id, "VALID" if result["passed"] else "INVALID", {"validation": result})
        return result

    def _schema_arguments(self, job_id, *, read_only=False):
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        binding = self.assert_artifact_binding(job_id)
        validation = status.get("validation")
        if (status["state"] not in ({"VALID", "FAILED", "IMPORTED"} if read_only else {"VALID"})
                or not isinstance(validation, dict) or validation.get("passed") is not True
                or validation.get("artifact_binding") != binding):
            raise RuntimeError("Schema preparation requires exact successful project validation")
        if not read_only and (root / "import-intent.json").exists():
            raise RuntimeError("Schema writes are blocked after APEX import intent")
        spec = project_reviews.read_object(root / "migration-spec.json")
        review = self.verify_project_review(root, spec)
        project = spec["native_project"]
        # Recompute from the frozen ORIGINAL sources before deriving ownership.
        # Neither a caller-supplied target name nor a model's mapping is trusted.
        source_plan = project_reviews.project_from_intake(root, return_plan=True)
        if source_plan["rendering_spec"] != project:
            raise RuntimeError("Schema preparation differs from the frozen project source plan")
        specs = [form["native_form"] for form in project["forms"]]
        mappings = ({form["native_form"]["table_name"]: form["storage_mapping"]
                     for form in project["forms"]} if project["schema_version"] == 2 else None)
        from .schema_bootstrap import _plan
        _, expected_schema_plan = _plan(specs, mapping_identities=mappings)
        schema_binding = {"job_id": job_id, "source_manifest_sha256": spec["native_project"]["source_manifest_sha256"],
                          "artifact_binding_sha256": project_reviews.digest(binding),
                          "review_receipts_sha256": project_reviews.digest(review["form_reviews"]),
                          "validated_draft_sha256": binding["draft_sha256"]}
        action = "reconcile-schema" if read_only else "prepare-schema"
        preflight = self.native_target_preflight(job_id, action)
        def authorize(operation, request):
            if self.assert_artifact_binding(job_id) != binding or self.store.read(job_id).get("validation") != validation:
                raise RuntimeError("Project review or validation changed during schema preparation")
            self.assert_native_preflight_fresh(job_id, preflight, action)
            if request.get("binding") != schema_binding:
                raise RuntimeError("Schema operation binding differs from the project")
            if (request.get("schema_plan") != expected_schema_plan
                    or request.get("schema_plan_sha256") != project_reviews.digest(expected_schema_plan)):
                raise RuntimeError("Schema operation changed the complete validated storage mapping")
            if not read_only and (root / "import-intent.json").exists():
                raise RuntimeError("APEX import intent forbids schema writes")
            return request
        return root, specs, schema_binding, authorize, mappings

    @serialized
    def prepare_schema(self, job_id):
        from .schema_bootstrap import prepare_schemas, SchemaPreparationError
        root, specs, binding, authorize, mappings = self._schema_arguments(job_id)
        project_reviews.publish(root / "schema-preparation-intent.json",
                                {"scope": "fox-project-schema-operation-v1", "binding": binding})
        try:
            result = prepare_schemas(self.settings, specs, root, binding=binding, authorize=authorize,
                                     **({"mapping_identities": mappings} if mappings is not None else {}))
        except SchemaPreparationError as error:
            self.store.transition(job_id, "VALID", {"schema_preparation": {
                "state": "ATTENTION", "code": error.code, "table_name": error.table_name,
                "completed_tables": error.completed_tables, "automatic_replay_permitted": False,
                "apex_import_performed_by_operation": False}})
            raise
        self.assert_artifact_binding(job_id)
        self.store.transition(job_id, "VALID", {"schema_preparation": result})
        return result

    @serialized
    def reconcile_schema(self, job_id):
        from .schema_bootstrap import reconcile_schemas
        root, specs, binding, authorize, mappings = self._schema_arguments(job_id, read_only=True)
        result = reconcile_schemas(self.settings, specs, root, binding=binding, authorize=authorize,
                                   **({"mapping_identities": mappings} if mappings is not None else {}))
        self.assert_artifact_binding(job_id)
        if result.get("state") == "READY":
            result["schema_preparation"] = self._retained_schema_preparation(root)
        return result

    def _retained_schema_preparation(self, root):
        """Recover local completion after a crash, without claiming a live probe."""
        from .schema_bootstrap import _read
        saved, checksum = _read(root / "schema-preparation.json")
        binding = self.assert_artifact_binding(root.name)
        review = project_reviews.read_object(root / "project-review.json")
        project = review["candidate"]["native_project"]
        expected = {"job_id": root.name, "source_manifest_sha256": project["source_manifest_sha256"],
                    "artifact_binding_sha256": project_reviews.digest(binding),
                    "review_receipts_sha256": project_reviews.digest(review["form_reviews"]),
                    "validated_draft_sha256": binding["draft_sha256"]}
        if saved.get("binding") != expected or saved.get("all_ready") is not True:
            raise RuntimeError("Retained schema preparation is not bound to this project")
        if {table["table_name"] for table in saved["tables"]} != {form["native_form"]["table_name"] for form in project["forms"]}:
            raise RuntimeError("Retained schema preparation omitted a project table")
        if project["schema_version"] == 2:
            expected_mappings = {form["native_form"]["table_name"]: form["storage_mapping"] for form in project["forms"]}
            for table in saved["tables"]:
                mapping = expected_mappings[table["table_name"]]
                if (table.get("storage_mapping") != mapping
                        or table.get("storage_mapping_sha256") != project_reviews.digest(mapping)):
                    raise RuntimeError("Retained schema preparation changed project storage ownership")
        return {"schema_version": 1, "scope": "fox-native-schema-preparation-result-v1", "state": "READY",
                "job_id": root.name, "schema_plan_sha256": saved["schema_plan_sha256"],
                "receipt_sha256": checksum, "tables": saved["tables"], "database_writes_this_call": 0,
                "apex_import_performed_by_operation": False, "human_acceptance_recorded": False}

    def _schema_ready(self, job_id):
        result = self.reconcile_schema(job_id)
        if result.get("state") != "READY" or result.get("ready_for_import") is not True:
            raise RuntimeError("All reviewed project schemas must be READY before APEX import")
        return result

    def status(self, job_id):
        result = self.store.read(job_id)
        root = self.store.require(job_id)
        result["import_intent_exists"] = (root / "import-intent.json").exists()
        result["schema_intent_exists"] = (root / "schema-preparation.json").exists() or (root / "schema-preparation-intent.json").exists()
        if (root / "schema-preparation.json").exists():
            result["schema_preparation"] = self._retained_schema_preparation(root)
        return result

    def _import_result(self, job_id, result, binding, schema, preflight):
        result.update(job_id=job_id, artifact_binding=binding,
                      project_schema_verification=schema, target_preflight=preflight,
                      conversion_profile=native_project.PROFILE_ID, parsing_schema=self.settings.apex_parsing_schema)
        result["application_url"] = (f"{self.settings.apex_base_url}/r/{self.settings.apex_workspace.lower()}/"
                                     f"{result['application_alias'].lower()}/")
        return result

    @serialized
    def import_draft(self, job_id):
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        if status["state"] != "VALID" or status.get("validation", {}).get("passed") is not True:
            raise RuntimeError("A successful complete project validation is required")
        if not self.settings.apex_base_url.startswith("https://"):
            raise RuntimeError("The APEX base URL must be HTTPS")
        if (root / "import-intent.json").exists():
            raise RuntimeError("Prior project import requires read-only reconciliation; replay blocked")
        binding = self.assert_artifact_binding(job_id)
        schema = self._schema_ready(job_id)
        preflight = self.native_target_preflight(job_id, "import")
        def before_write():
            self.assert_artifact_binding(job_id)
            self._schema_ready(job_id)
            self.assert_native_preflight_fresh(job_id, preflight, "import")
        with draft_snapshot(root, binding["draft_sha256"]) as snapshot:
            project_reviews.publish(root / "import-intent.json", {"job_id": job_id,
                                     "workspace": self.settings.apex_workspace, "artifact_binding": binding})
            try:
                result = import_apexlang_durable(self.settings.sqlcl_path, self.settings.sqlcl_connection_name,
                    self.settings.apex_workspace, job_id, snapshot, root / "import.log",
                    intent_path=root / "sqlcl-import-intent.json", expected_draft_sha256=binding["draft_sha256"],
                    artifact_binding=binding, pre_write_check=before_write)
                if self.assert_artifact_binding(job_id) != binding or tree_digest(snapshot) != binding["draft_sha256"]:
                    raise RuntimeError("Project changed during import; reconciliation required")
            except Exception:
                self.store.transition(job_id, "FAILED", {"import_reconciliation_required": True})
                raise
        result = self._import_result(job_id, result, binding, schema, preflight)
        project_reviews.publish(root / "imported-application.json", result)
        smoke = runtime_login_check(result["application_url"])
        _atomic_json(root / "smoke-test-report.json", smoke)
        self.store.transition(job_id, "IMPORTED", {"import": result, "smoke_test": smoke})
        return {**result, "smoke_test": smoke}

    @serialized
    def reconcile_import(self, job_id):
        root = self.store.require(job_id)
        status = self.store.read(job_id)
        if status["state"] not in {"VALID", "FAILED"} or not self.settings.apex_base_url.startswith("https://"):
            raise RuntimeError("No recoverable validated project import")
        binding = self.assert_artifact_binding(job_id)
        expected = {"job_id": job_id, "workspace": self.settings.apex_workspace, "artifact_binding": binding}
        if project_reviews.read_object(root / "import-intent.json") != expected:
            raise RuntimeError("Project import intent changed")
        schema = self._schema_ready(job_id)
        preflight = self.native_target_preflight(job_id, "reconcile")
        result = reconcile_apexlang_import(self.settings.sqlcl_path, self.settings.sqlcl_connection_name,
            self.settings.apex_workspace, job_id, root / "apexlang", root / "import-reconciliation.log",
            intent_path=root / "sqlcl-import-intent.json", expected_draft_sha256=binding["draft_sha256"], artifact_binding=binding)
        if (result.get("reconciled") is not True or result.get("target_writes") is not False
                or result.get("reconciliation_scope") != "exact_identity_and_complete_compiled_metadata"):
            raise RuntimeError("Exact read-only project recovery proof is required")
        if self.assert_artifact_binding(job_id) != binding or self.store.read(job_id) != status:
            raise RuntimeError("Project changed during read-only reconciliation")
        result = self._import_result(job_id, result, binding, schema, preflight)
        receipt = root / "imported-application.json"
        if receipt.exists():
            imported = project_reviews.read_object(receipt)
            for key in ("job_id", "artifact_binding", "application_id", "application_alias", "workspace",
                        "application_url", "import_intent_sha256", "compiled_metadata_sha256"):
                if imported.get(key) != result.get(key):
                    raise RuntimeError("Existing project import receipt differs; preserved")
        else:
            imported = project_reviews.publish(receipt, result)
        _atomic_json(root / "import-recovery.json", result)
        smoke = runtime_login_check(result["application_url"])
        _atomic_json(root / "smoke-test-report.json", smoke)
        self.store.transition(job_id, "IMPORTED", {"import": imported, "smoke_test": smoke,
                             "import_recovery": result, "import_reconciliation_required": False})
        return {**imported, "recovery": result, "smoke_test": smoke}
