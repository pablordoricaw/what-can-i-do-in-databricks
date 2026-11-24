import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


from collector_fixture import make_collector
from reporting import write_report


class UnityCatalogEffectiveAccessTests(unittest.TestCase):
    make_collector = staticmethod(make_collector)

    def test_visible_grants_stay_in_inventory_but_only_caller_grants_are_exported(self):
        rows = [
            {
                "grantee": grantee,
                "privilege_type": "SELECT",
                "table_catalog": "catalog",
                "table_schema": "schema",
                "table_name": "table",
            }
            for grantee in (
                "alice@example.com",
                "engineering",
                "finance",
                "bob@example.com",
                "",
            )
        ]
        for groups in ({"engineering"}, {"engineering", "admins"}):
            with self.subTest(groups=groups):
                collector = self.make_collector(groups)

                def query(section, operation, statement):
                    return rows if operation.endswith("_privileges") else []

                with (
                    patch.object(collector, "probe", return_value=None),
                    patch.object(collector, "run_sql", side_effect=query),
                ):
                    collector.collect_uc()

                with tempfile.TemporaryDirectory() as directory:
                    collector.report_dir = Path(directory)
                    write_report(collector)
                    effective = json.loads(
                        (collector.report_dir / "my_effective_access.json").read_text()
                    )
                    inventory = json.loads(
                        (collector.report_dir / "uc.json").read_text()
                    )
                self.assertEqual(
                    {row["granted_to"] for row in effective},
                    {"alice@example.com", "engineering"},
                )
                for row in effective:
                    self.assertEqual(
                        row["via_group"], row["granted_to"] == "engineering"
                    )
                record_types = {row["record_type"] for row in inventory}
                self.assertEqual(len(record_types), 9)
                self.assertEqual(len(effective), 2 * len(record_types))
                for record_type in record_types:
                    visible = [
                        row for row in inventory if row["record_type"] == record_type
                    ]
                    self.assertEqual(len(visible), len(rows))

    def test_unknown_group_membership_does_not_confer_access(self):
        collector = self.make_collector(set())
        rows = [{"grantee": "finance", "privilege_type": "SELECT"}]
        with (
            patch.object(collector, "probe", return_value=None),
            patch.object(collector, "run_sql", return_value=rows),
        ):
            collector.collect_uc()
        self.assertEqual(collector.effective_access, [])
        self.assertTrue(collector.sections["uc"])

    def test_show_grants_requires_a_caller_principal(self):
        collector = self.make_collector({"engineering"})
        rows = [
            {"Principal": "alice@example.com", "ActionType": "USE CATALOG"},
            {"grantee": "engineering", "privilege": "SELECT"},
            {"Principal": "finance", "ActionType": "SELECT"},
            {"Principal": "bob@example.com", "ActionType": "SELECT"},
            {"ActionType": "SELECT"},
        ]
        collector._record_show_grants(rows, "CATALOG", "catalog")
        self.assertEqual(len(collector.sections["uc"]), len(rows))
        self.assertEqual(
            [(row["granted_to"], row["via_group"]) for row in collector.effective_access],
            [("alice@example.com", False), ("engineering", True)],
        )


if __name__ == "__main__":
    unittest.main()
