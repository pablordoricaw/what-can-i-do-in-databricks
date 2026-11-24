import unittest

from collector_fixture import make_collector
from databricks.sdk.errors import PermissionDenied
from databricks.sdk.service.jobs import Job, JobRunAs, JobSettings
from databricks.sdk.service.ml import GetModelResponse, Model, ModelDatabricks


class ResourceDetailTests(unittest.TestCase):
    def test_model_list_name_is_resolved_to_workspace_permission_id(self):
        collector = make_collector()
        collector.client.model_registry.get_model.return_value = GetModelResponse(
            registered_model_databricks=ModelDatabricks(name="forecast", id="model-42")
        )
        collector.client.permissions.get.return_value = {
            "access_control_list": [{
                "user_name": collector.current_username,
                "all_permissions": [{"permission_level": "CAN_READ"}],
            }]
        }
        collector._record_workspace_objects(
            "registered_model", [Model(name="forecast").as_dict()], ("id", "name")
        )
        collector.client.model_registry.get_model.assert_called_once_with("forecast")
        collector.client.permissions.get.assert_called_once_with("registered-models", "model-42")
        self.assertEqual(collector.sections["workspace"][0]["id"], "model-42")
        self.assertTrue(any(row["permission"] == "CAN_READ" for row in collector.effective_access))

    def test_denied_or_incomplete_model_details_preserve_visibility(self):
        for denied in (True, False):
            with self.subTest(denied=denied):
                collector = make_collector()
                collector.client.model_registry.get_model.side_effect = (
                    PermissionDenied("denied", error_code="PERMISSION_DENIED") if denied else None
                )
                collector.client.model_registry.get_model.return_value = GetModelResponse()
                collector._record_workspace_objects(
                    "registered_model", [Model(name="forecast").as_dict()], ("id", "name")
                )
                collector.client.permissions.get.assert_not_called()
                self.assertEqual(collector.effective_access[0]["permission"], "VISIBLE")
                if denied:
                    self.assertEqual(collector.probes[0]["outcome"], "DENIED")
                else:
                    self.assertTrue(collector.section_notes["workspace"])

    def test_job_run_as_uses_resolved_identity_and_detail_fallback(self):
        collector = make_collector()
        collector.client.tokens.list.return_value = []
        collector.client.secrets.list_scopes.return_value = []
        collector.client.pipelines.list_pipelines.return_value = []
        collector.client.jobs.list.return_value = [
            Job(job_id=1, settings=JobSettings(name="implicit")),
            Job(job_id=2, run_as_user_name=collector.current_username),
            Job(job_id=3, run_as_user_name="bob@example.com", settings=JobSettings(
                run_as=JobRunAs(user_name=collector.current_username)
            )),
            Job(job_id=4, settings=JobSettings(name="unreadable")),
            Job(job_id=5, settings=JobSettings(
                run_as=JobRunAs(user_name=collector.current_username)
            )),
        ]

        def details(job_id):
            if job_id == 4:
                raise PermissionDenied("denied", error_code="PERMISSION_DENIED")
            return Job(job_id=job_id, run_as_user_name=collector.current_username)

        collector.client.jobs.get.side_effect = details
        collector.collect_credentials()
        jobs = collector.sections["credentials"]
        self.assertEqual({row["job_id"] for row in jobs}, {1, 2, 5})
        self.assertEqual(collector.client.jobs.get.call_count, 2)
        self.assertTrue(any(
            probe["operation"] == "get_job_for_run_as" and probe["outcome"] == "DENIED"
            for probe in collector.probes
        ))
