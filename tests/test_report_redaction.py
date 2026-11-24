import csv
import tempfile
import unittest
import zipfile
from pathlib import Path

from collector_fixture import make_collector
from reporting import write_report


class ReportRedactionTests(unittest.TestCase):
    def test_object_redaction_covers_diagnostics_in_report_and_zip(self):
        collector = make_collector()
        collector.args.redact = True
        collector.args.redact_objects = True
        private_name = "confidential_customer_forecast"
        collector.sections["workspace"] = [{"path": "/Shared/" + private_name}]
        collector.section_notes["workspace"] = ["Cannot browse " + private_name]
        collector.probes = [
            {
                "section": "workspace", "operation": "list_workspace_path",
                "endpoint_or_query": "GET /workspace/list?path=/Shared/" + private_name,
                "outcome": "DENIED", "http_or_error_code": "403",
                "error_message": "Permission denied on " + private_name,
            },
            {
                "section": "uc", "operation": "show_grants_catalog",
                "endpoint_or_query": "SHOW GRANTS ON CATALOG " + private_name,
                "outcome": "ALLOWED", "http_or_error_code": "",
                "error_message": "",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            collector.report_dir = Path(directory) / "report"
            collector.report_dir.mkdir()
            _, archive = write_report(collector)
            with zipfile.ZipFile(archive) as bundle:
                for name in bundle.namelist():
                    self.assertNotIn(private_name.encode(), bundle.read(name), name)
            with (collector.report_dir / "probe_log.csv").open() as handle:
                probe = next(csv.DictReader(handle))
            self.assertEqual(probe["outcome"], "DENIED")
            self.assertEqual(probe["http_or_error_code"], "403")
            self.assertEqual(probe["operation"], "list_workspace_path")
            self.assertTrue(probe["endpoint_or_query"].startswith("sha256:"))

    def test_diagnostics_remain_readable_without_object_redaction(self):
        collector = make_collector()
        collector.args.redact = True
        collector.probes = [{
            "section": "uc", "operation": "read_table", "outcome": "ERROR",
            "endpoint_or_query": "SELECT * FROM catalog.schema.table",
            "error_message": "Cannot read catalog.schema.table",
        }]
        with tempfile.TemporaryDirectory() as directory:
            collector.report_dir = Path(directory)
            write_report(collector)
            log = (collector.report_dir / "probe_log.csv").read_text()
            self.assertIn("SELECT * FROM catalog.schema.table", log)
            self.assertIn("Cannot read catalog.schema.table", log)
