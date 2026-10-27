from pathlib import Path
import json
import hashlib
import tempfile
import unittest

from forms2apex.config import Settings
from forms2apex.workflow import ConverterWorkflow
from forms2apex.starter import TEMPLATE_ID, template_files


def settings(root: Path) -> Settings:
    return Settings(
        jobs_root=root,
        sqlcl_path=root / "missing-sqlcl",
        sqlcl_connection_name="F2A_APEX",
        apex_workspace="FORMS2APEX_POC",
        apex_base_url="https://example.invalid/ords",
        generator_model="xai.grok-4.20-0309-reasoning",
        reviewer_model="xai.grok-4.3",
        host="127.0.0.1",
        port=8090,
        bearer_token="x" * 32,
    )


class WorkflowTests(unittest.TestCase):
    def create_job(self, root: Path, job_id: str = "job-123") -> Path:
        job = root / job_id
        intake = job / "intake"
        intake.mkdir(parents=True)
        (intake / "sample.xml").write_text(
            '<Module Name="SAMPLE"><Block Name="EMP"><Item Name="EMPNO"/></Block></Module>',
            encoding="utf-8",
        )
        (intake / "manifest.json").write_text(
            json.dumps(
                {
                    "job_id": job_id,
                    "source_policy": "redacted",
                    "files": [
                        {
                            "packaged_name": "sample.xml",
                            "source_kind": "forms2xml",
                            "sha256": hashlib.sha256((intake / "sample.xml").read_bytes()).hexdigest(),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return job

    def test_inspect_and_materialize_reviewed_draft(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            self.create_job(root)
            workflow = ConverterWorkflow(settings(root))
            inventory = workflow.inspect("job-123")
            self.assertEqual(inventory["modules"][0]["named_objects"]["Block"], ["EMP"])
            self.assertIn('<Block Name="EMP">', inventory["modules"][0]["readable_source"])
            spec = {
                "data_classification": "synthetic_or_stub_only",
                "generator": {"model": "xai.grok-4.20-0309-reasoning"},
                "reviewer": {"model": "xai.grok-4.3", "verdict": "approve"},
                "template_id": TEMPLATE_ID,
                "prototype_html": "<p>Synthetic sample</p>",
            }
            result = workflow.generate("job-123", json.dumps(spec))
            self.assertEqual(result["job_id"], "job-123")
            self.assertEqual(result["files"], len(template_files()))
            self.assertEqual(workflow.status("job-123")["state"], "DRAFTED")

    def test_import_is_blocked_before_validation(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            self.create_job(root)
            workflow = ConverterWorkflow(settings(root))
            workflow.inspect("job-123")
            with self.assertRaisesRegex(RuntimeError, "blocked"):
                workflow.import_draft("job-123")

    def test_review_rejection_blocks_draft(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            self.create_job(root)
            workflow = ConverterWorkflow(settings(root))
            workflow.inspect("job-123")
            spec = {
                "data_classification": "synthetic_or_stub_only",
                "generator": {"model": "xai.grok-4.20-0309-reasoning"},
                "reviewer": {"model": "xai.grok-4.3", "verdict": "reject"},
                "apexlang_files": {"application.apx": "app X ()"},
            }
            with self.assertRaisesRegex(ValueError, "approval"):
                workflow.generate("job-123", json.dumps(spec))

    def test_required_remediation_cannot_be_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            job = self.create_job(root)
            (job / "intake" / "sample.xml").write_text(
                '<Module Name="SAMPLE"><Trigger Name="X">HOST(\'calc\');</Trigger></Module>',
                encoding="utf-8",
            )
            manifest_path = job / "intake" / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["files"][0]["sha256"] = hashlib.sha256((job / "intake" / "sample.xml").read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            workflow = ConverterWorkflow(settings(root))
            workflow.inspect("job-123")
            spec = {
                "data_classification": "synthetic_or_stub_only",
                "generator": {"model": "xai.grok-4.20-0309-reasoning"},
                "reviewer": {"model": "xai.grok-4.3", "verdict": "approve"},
                "remediation_items": [],
                "template_id": TEMPLATE_ID,
                "prototype_html": "<p>Synthetic sample</p>",
            }
            with self.assertRaisesRegex(ValueError, "omitted required remediation"):
                workflow.generate("job-123", json.dumps(spec))

    def test_changed_source_cannot_reach_model(self):
        with tempfile.TemporaryDirectory() as value:
            root=Path(value)
            job=self.create_job(root)
            (job/'intake/sample.xml').write_text('<Module Name="CHANGED"/>')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                ConverterWorkflow(settings(root)).inspect('job-123')


if __name__ == "__main__":
    unittest.main()
