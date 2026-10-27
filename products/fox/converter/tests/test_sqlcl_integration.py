from pathlib import Path
import json
import shutil
import tempfile
import unittest
import hashlib

from forms2apex.config import Settings
from forms2apex.workflow import ConverterWorkflow
from forms2apex.starter import TEMPLATE_ID


class SqlclIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("sql.exe") or shutil.which("sql"), "SQLcl is not installed")
    def test_invalid_apexlang_cannot_reach_import(self) -> None:
        sqlcl = Path(shutil.which("sql.exe") or shutil.which("sql") or "")
        with tempfile.TemporaryDirectory() as value:
            jobs = Path(value)
            intake = jobs / "invalid-apexlang" / "intake"
            intake.mkdir(parents=True)
            (intake / "sample.xml").write_text('<Module Name="SAMPLE"/>', encoding="utf-8")
            (intake / "manifest.json").write_text(
                json.dumps(
                    {
                        "job_id": "invalid-apexlang",
                        "source_policy": "redacted",
                        "files": [
                            {
                                "packaged_name": "sample.xml",
                                "source_kind": "forms2xml",
                                "sha256": hashlib.sha256((intake/'sample.xml').read_bytes()).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            settings = Settings(
                jobs_root=jobs,
                sqlcl_path=sqlcl,
                sqlcl_connection_name="F2A_APEX",
                apex_workspace="FORMS2APEX_POC",
                apex_base_url="https://example.invalid/ords",
                generator_model="xai.grok-4.20-0309-reasoning",
                reviewer_model="xai.grok-4.3",
                host="127.0.0.1",
                port=8090,
                bearer_token="x" * 32,
            )
            workflow = ConverterWorkflow(settings)
            workflow.inspect("invalid-apexlang")
            workflow.generate(
                "invalid-apexlang",
                json.dumps(
                    {
                        "data_classification": "synthetic_or_stub_only",
                        "generator": {"model": "xai.grok-4.20-0309-reasoning"},
                        "reviewer": {"model": "xai.grok-4.3", "verdict": "approve"},
                        "template_id": TEMPLATE_ID,
                        "apexlang_files": {"pages/p00001-home.apx": "this is not valid APEXlang"},
                    }
                ),
            )
            result = workflow.validate("invalid-apexlang")
            self.assertFalse(result["passed"])
            self.assertEqual(result["job_id"], "invalid-apexlang")
            self.assertEqual(workflow.status("invalid-apexlang")["state"], "INVALID")
            with self.assertRaisesRegex(RuntimeError, "blocked"):
                workflow.import_draft("invalid-apexlang")


if __name__ == "__main__":
    unittest.main()
