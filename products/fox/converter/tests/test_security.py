from pathlib import Path
import tempfile
import unittest

from forms2apex.security import (
    alias_for_job,
    assert_no_secrets,
    assert_safe_generated_content,
    job_path,
    safe_relative_path,
)


class SecurityTests(unittest.TestCase):
    def test_job_path_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            with self.assertRaises(ValueError):
                job_path(Path(value), "../bad")

    def test_safe_draft_path_rejects_parent(self) -> None:
        with self.assertRaises(ValueError):
            safe_relative_path("pages/../../secret.apx")

    def test_secret_scan_blocks_private_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "private_key"):
            assert_no_secrets("-----BEGIN PRIVATE KEY-----", "x.apx")

    def test_alias_is_scoped_to_job(self) -> None:
        self.assertEqual(alias_for_job("job-123"), "F2A_JOB_123")

    def test_generated_external_call_is_blocked(self) -> None:
        with self.assertRaisesRegex(ValueError, "external_network_call"):
            assert_safe_generated_content("begin utl_http.begin_request('https://x'); end;", "page.apx")

    def test_sql_dml_requires_synthetic_marker(self) -> None:
        with self.assertRaisesRegex(ValueError, "SYNTHETIC_DATA_ONLY"):
            assert_safe_generated_content("insert into demo values (1);", "seed.sql")


if __name__ == "__main__":
    unittest.main()
