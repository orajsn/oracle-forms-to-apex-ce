from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


PINNED_COMPARTMENT_OCID = (
    "ocid1.compartment.oc1.."
    "aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba"
)


@dataclass(frozen=True)
class Settings:
    jobs_root: Path
    sqlcl_path: Path
    sqlcl_connection_name: str
    apex_workspace: str
    apex_base_url: str
    generator_model: str
    reviewer_model: str
    host: str
    port: int
    bearer_token: str
    opaf_mapper_workflow_id: str = ''
    opaf_reviewer_workflow_id: str = ''
    target_profile_path: Path | None = None
    apex_parsing_schema: str = 'FORMS2APEX_POC'

    @classmethod
    def from_env(cls) -> "Settings":
        root = Path(os.environ.get("F2A_JOBS_ROOT", "/opt/forms2apex/outputs/jobs")).resolve()
        token = os.environ.get("F2A_MCP_BEARER_TOKEN", "")
        if len(token) < 32:
            raise RuntimeError("F2A_MCP_BEARER_TOKEN must contain at least 32 characters")
        connection_name = os.environ.get("F2A_SQLCL_CONNECTION_NAME", "")
        target_profile_path = os.environ.get('F2A_TARGET_PROFILE_PATH', '')
        settings = cls(
            jobs_root=root,
            sqlcl_path=Path(os.environ.get("F2A_SQLCL_PATH", "/opt/sqlcl/bin/sql")).resolve(),
            sqlcl_connection_name=connection_name,
            apex_workspace=os.environ.get("F2A_APEX_WORKSPACE", "FORMS2APEX_POC"),
            apex_base_url=os.environ.get("F2A_APEX_BASE_URL", "").rstrip("/"),
            generator_model=os.environ.get("F2A_GENERATOR_MODEL", "xai.grok-4.3"),
            reviewer_model=os.environ.get("F2A_REVIEWER_MODEL", "xai.grok-4.3"),
            host=os.environ.get("F2A_MCP_HOST", "127.0.0.1"),
            port=int(os.environ.get("F2A_MCP_PORT", "8090")),
            bearer_token=token,
            opaf_mapper_workflow_id=os.environ.get('F2A_OPAF_MAPPER_WORKFLOW_ID',''),
            opaf_reviewer_workflow_id=os.environ.get('F2A_OPAF_REVIEWER_WORKFLOW_ID',''),
            target_profile_path=Path(target_profile_path).absolute() if target_profile_path else None,
            apex_parsing_schema=os.environ.get('F2A_APEX_PARSING_SCHEMA', 'FORMS2APEX_POC'),
        )
        if settings.target_profile_path is not None:
            from .runtime_preflight import bound_target_profile
            bound_target_profile(settings)
        return settings
