import asyncio
import importlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastmcp import Client


class McpContractTests(unittest.TestCase):
    def test_expected_tools_are_discoverable(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            env = {
                "F2A_JOBS_ROOT": str(Path(value) / "jobs"),
                "F2A_MCP_BEARER_TOKEN": "test-token-" + ("x" * 32),
                "F2A_SQLCL_CONNECTION_NAME": "F2A_APEX",
            }
            with patch.dict(os.environ, env, clear=False):
                module = importlib.import_module("forms2apex.server")

                async def names() -> set[str]:
                    async with Client(module.mcp) as client:
                        return {tool.name for tool in await client.list_tools()}

                discovered = asyncio.run(names())
        self.assertEqual(
            discovered,
            {
                "inspect_forms_job",
                "generate_apex_draft",
                "validate_apex_draft",
                "import_validated_draft",
                "get_job_status",
            },
        )


if __name__ == "__main__":
    unittest.main()

