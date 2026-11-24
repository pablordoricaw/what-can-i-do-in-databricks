import unittest
from unittest.mock import Mock

from collector_fixture import make_collector
from databricks.sdk.errors import NotFound, PermissionDenied


class ProbeResultTests(unittest.TestCase):
    def test_warehouse_capability_uses_probe_evidence(self):
        for error, outcome, value in (
            (None, "ALLOWED", True),
            (PermissionDenied("denied", error_code="PERMISSION_DENIED"), "DENIED", False),
            (NotFound("unavailable", error_code="NOT_FOUND"), "NOT_SUPPORTED", None),
            (RuntimeError("unexpected failure"), "ERROR", None),
        ):
            with self.subTest(outcome=outcome):
                collector = make_collector()
                collector.client.current_user.me.return_value = {}
                collector.client.warehouses.list.return_value = iter([])
                collector.client.warehouses.list.side_effect = error
                collector.collect_entitlements()
                capability = collector.sections["entitlements"][-1]
                self.assertIs(capability["value"], value)
                self.assertEqual(capability["outcome"], outcome)
                self.assertEqual(capability["visible_count"], 0 if error is None else None)

    def test_system_table_results_preserve_attempted_and_skipped_outcomes(self):
        for error, has_spark, outcome in (
            (None, True, "ALLOWED"),
            (PermissionDenied("denied", error_code="PERMISSION_DENIED"), True, "DENIED"),
            (NotFound("unavailable", error_code="NOT_FOUND"), True, "NOT_SUPPORTED"),
            (RuntimeError("unexpected failure"), True, "ERROR"),
            (None, False, "SKIPPED"),
        ):
            with self.subTest(outcome=outcome):
                collector = make_collector()
                collector.client.warehouses.list.return_value = []
                collector.client.serving_endpoints.list.return_value = []
                collector.client.apps.list.return_value = []
                collector.client.genie.list_spaces.return_value = {"spaces": []}
                collector.client.workspace_conf.get_status.return_value = {}
                if has_spark:
                    collector.spark = Mock()
                    collector.spark.sql.side_effect = error
                    collector.spark.sql.return_value.collect.return_value = []
                collector.collect_features()
                tables = [
                    row for row in collector.sections["features"]
                    if row["feature"].startswith("system.")
                ]
                self.assertEqual(len(tables), 2)
                self.assertEqual({row["outcome"] for row in tables}, {outcome})
                for row in tables:
                    recorded = [
                        probe["outcome"] for probe in collector.probes
                        if probe["operation"] == "feature_" + row["feature"]
                    ]
                    self.assertEqual(recorded, [] if outcome == "SKIPPED" else [outcome])
