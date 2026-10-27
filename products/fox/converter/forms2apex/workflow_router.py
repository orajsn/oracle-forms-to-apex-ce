"""Choose conversion behavior only from the frozen, server-validated intake.

This adapter preserves the five public MCP tools. An action payload cannot
change a job's profile, and historical single-form jobs retain their reader.
"""
from __future__ import annotations

from .workflow import ConverterWorkflow
from .project_workflow import ProjectWorkflow
from . import native_project, project_reviews


PROJECT_MAPPING_CAPABILITY = {
    "native_project_schema_versions": [1, 2],
    "storage_mapping_scope": "fox-project-storage-v1",
    "module_execution_scope": "fox-project-module-execution-v2",
}


def project_mapping_profile_supported(profile):
    """Mapping requires an explicit paired profile, never a global bypass.

    Registration and active/historical trust are enforced by target_profile
    before callers reach this check. This declaration is additional evidence,
    not a substitute for registered workflow IDs and immutable graph hashes.
    """
    return (isinstance(profile, dict) and profile.get("active") is True
            and isinstance(profile.get("scope"), dict)
            and profile["scope"].get("project_mapping") == PROJECT_MAPPING_CAPABILITY)


class WorkflowRouter:
    def __init__(self, settings, *, legacy=None):
        self.settings = settings
        self.legacy = legacy if legacy is not None else ConverterWorkflow(settings)
        self.project = ProjectWorkflow(settings)
        self.store = self.legacy.store

    def select(self, job_id):
        root = self.store.require(job_id)
        manifest = project_reviews.read_object(root / "intake/manifest.json")
        profile = manifest.get("conversion_profile")
        if profile == native_project.PROFILE_ID:
            project_reviews.project_from_intake(root)
            return self.project
        if profile not in {None, "read-only-html-prototype", "native-table-form-v1"}:
            raise ValueError("The frozen conversion profile is not supported")
        if manifest.get("native_project") is not None:
            raise ValueError("Project metadata requires its exact frozen profile")
        return self.legacy

    def target_profile(self):
        return self.legacy.target_profile()

    def inspect(self, job_id):
        return self.select(job_id).inspect(job_id)

    def generate(self, job_id, migration_spec):
        return self.select(job_id).generate(job_id, migration_spec)

    def validate(self, job_id):
        return self.select(job_id).validate(job_id)

    def import_draft(self, job_id):
        return self.select(job_id).import_draft(job_id)

    def status(self, job_id):
        return self.select(job_id).status(job_id)

    def reconcile_import(self, job_id):
        return self.select(job_id).reconcile_import(job_id)


def capabilities(target_profile=None):
    """Advertise only the actual installed implementation, not environment flags."""
    from .project_release import finalize_project_release, validate_project_package
    from .schema_bootstrap import prepare_schemas, reconcile_schemas
    from .project_source import module_execution_binding, validate_project_sources
    required = (finalize_project_release, validate_project_package, prepare_schemas,
                reconcile_schemas, module_execution_binding, validate_project_sources,
                native_project.render_native_project, ProjectWorkflow.prepare_schema,
                ProjectWorkflow.reconcile_schema)
    if not all(callable(value) for value in required):
        raise RuntimeError("Installed project conversion capability is incomplete")
    native_project.context()  # Requires the actual renderer/template assets.
    return {"schema_version": 1,
            "conversion_profiles": ["read-only-html-prototype", "native-table-form-v1", native_project.PROFILE_ID],
            "project_protocol": native_project.PROFILE_ID, "schema_preparation": True,
            "project_mapping": {**PROJECT_MAPPING_CAPABILITY,
                "paired_profile_ready": project_mapping_profile_supported(target_profile)}}
