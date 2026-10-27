from __future__ import annotations

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

from .config import Settings
from .workflow_router import WorkflowRouter
from .fox_gateway import attach_routes


settings = Settings.from_env()
auth = StaticTokenVerifier(
    tokens={
        settings.bearer_token: {
            "client_id": "jsn-opaf-workflow",
            "scopes": ["forms2apex:execute"],
        }
    },
    required_scopes=["forms2apex:execute"],
)
mcp = FastMCP(name="JSN Forms-to-APEX Converter", auth=auth)
workflow = WorkflowRouter(settings)
attach_routes(mcp,workflow,settings)


@mcp.tool
def inspect_forms_job(job_id: str) -> dict:
    """Inspect redacted Forms XML/text and write a normalized inventory and exception report."""
    return workflow.inspect(job_id)


@mcp.tool
def generate_apex_draft(job_id: str, migration_spec: str) -> dict:
    """Materialize independently reviewed APEXlang files from the OPAF workflow contract."""
    return workflow.generate(job_id, migration_spec)


@mcp.tool
def validate_apex_draft(job_id: str) -> dict:
    """Run read-only target checks and SQLcl validation of the complete draft; do not import."""
    return workflow.validate(job_id)


@mcp.tool
def import_validated_draft(job_id: str) -> dict:
    """Import only a valid draft as a new application with a collision-checked ID and job alias."""
    return workflow.import_draft(job_id)


@mcp.tool
def get_job_status(job_id: str) -> dict:
    """Return the durable state and evidence paths for a conversion job."""
    return workflow.status(job_id)


def main() -> None:
    mcp.run(transport="http", host=settings.host, port=settings.port, path="/mcp")


if __name__ == "__main__":
    main()
