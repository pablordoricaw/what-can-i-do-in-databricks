# /// script
# requires-python = ">=3.10"
# dependencies = ["databricks-sdk==0.170.0"]
# ///
# ruff: noqa: BLE001, I001

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from databricks.sdk import WorkspaceClient

from reporting import write_report


ALL_SECTIONS = (
    "identity",
    "entitlements",
    "uc",
    "compute",
    "workspace",
    "credentials",
    "features",
)
READ_ONLY_SQL = re.compile(r"^\s*(SELECT|SHOW|DESCRIBE)\b", re.IGNORECASE)
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PERMISSION_OBJECT_TYPES = {
    "cluster_policy": "cluster-policies",
    "cluster": "clusters",
    "warehouse": "warehouses",
    "instance_pool": "instance-pools",
    "repo": "repos",
    "job": "jobs",
    "pipeline": "pipelines",
    "query": "queries",
    "alert": "alerts",
    "dashboard": "dashboards",
    "genie_space": "genie",
    "app": "apps",
    "experiment": "experiments",
    "registered_model": "registered-models",
    "serving_endpoint": "serving-endpoints",
    "vector_search_endpoint": "vector-search-endpoints",
    "DIRECTORY": "directories",
    "NOTEBOOK": "notebooks",
    "FILE": "files",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a read-only report of the current Databricks user's access."
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--sections",
        default=",".join(ALL_SECTIONS),
        help=f"Comma-separated sections: {','.join(ALL_SECTIONS)}",
    )
    parser.add_argument("--max-objects", type=int, default=500)
    parser.add_argument("--max-depth", type=int, default=3)
    parser.add_argument("--redact", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--redact-objects", action="store_true")
    args = parser.parse_args()
    selected = tuple(part.strip() for part in args.sections.split(",") if part.strip())
    unknown = sorted(set(selected) - set(ALL_SECTIONS))
    if unknown:
        parser.error(f"Unknown sections: {', '.join(unknown)}")
    if args.max_objects < 1:
        parser.error("--max-objects must be at least 1")
    if args.max_depth < 0:
        parser.error("--max-depth cannot be negative")
    args.sections = selected
    return args


def as_data(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): as_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [as_data(item) for item in value]
    if hasattr(value, "as_dict"):
        return as_data(value.as_dict())
    return str(value)


def enum_text(value: Any) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    return str(value or "")


def hash_value(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"


def sql_identifier(value: str) -> str:
    return f"`{value.replace('`', '``')}`"


def sql_literal(value: str) -> str:
    return f"'{value.replace(chr(39), chr(39) * 2)}'"


def nested_get(data: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = data
        for part in path.split("."):
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(part)
        if current not in (None, ""):
            return current
    return None


class AccessCollector:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.client = WorkspaceClient()
        self.sdk_version = importlib.metadata.version("databricks-sdk")
        self.runtime = self._runtime_label()
        self.started_at = datetime.now(UTC)
        self.probes: list[dict[str, Any]] = []
        self.sections: dict[str, list[dict[str, Any]]] = {
            section: [] for section in ALL_SECTIONS
        }
        self.section_notes: dict[str, list[str]] = {
            section: [] for section in ALL_SECTIONS
        }
        self.effective_access: list[dict[str, Any]] = []
        self.current_user: dict[str, Any] = {}
        self.current_username = "unknown-user"
        self.current_user_id = ""
        self.groups: set[str] = set()
        self.group_method = "unavailable"
        self.warehouses: list[dict[str, Any]] | None = None
        self.sql_warehouse_id: str | None = None
        self.spark = globals().get("spark")
        self.report_dir: Path | None = None
        self.workspace_id = self._workspace_id()
        self.email_pattern = EMAIL
        self.hash_value = hash_value
        self.as_data = as_data
        self.now_utc = lambda: datetime.now(UTC)

    def _runtime_label(self) -> str:
        if os.environ.get("UV_RUN_RECURSION_DEPTH"):
            try:
                return subprocess.run(
                    [os.environ.get("UV", "uv"), "--version"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                return "uv"
        if os.environ.get("DATABRICKS_RUNTIME_VERSION") or "/Workspace" in str(
            Path.cwd()
        ):
            return "preinstalled SDK"
        return "python without uv"

    def _workspace_id(self) -> str:
        try:
            return str(self.client.get_workspace_id())
        except Exception:
            host = str(getattr(self.client.config, "host", "workspace"))
            match = re.search(r"(?:adb-)?(\d+)", host)
            return match.group(1) if match else hash_value(host).split(":", 1)[1]

    def _error_details(self, error: Exception) -> tuple[str, str, str]:
        status = str(
            getattr(error, "status_code", "") or getattr(error, "http_status_code", "")
        )
        code = str(getattr(error, "error_code", "") or status)
        message = str(error)
        upper = f"{code} {message}".upper()
        if "IS DISABLED FOR THE CURRENT" in upper:
            outcome = "NOT_SUPPORTED"
        elif status == "403" or any(
            marker in upper
            for marker in (
                "PERMISSION_DENIED",
                "INSUFFICIENT_PERMISSIONS",
                "FORBIDDEN",
                "UNAUTHENTICATED",
            )
        ):
            outcome = "DENIED"
        elif status == "404" or any(
            marker in upper
            for marker in (
                "NOT_FOUND",
                "RESOURCE_DOES_NOT_EXIST",
                "UNKNOWN OBJECT TYPE",
                "ENDPOINT NOT FOUND",
                "NOT SUPPORTED",
            )
        ):
            outcome = "NOT_SUPPORTED"
        else:
            outcome = "ERROR"
        return outcome, code, message

    def _is_rate_limit(self, error: Exception) -> bool:
        outcome, code, message = self._error_details(error)
        combined = f"{outcome} {code} {message}".upper()
        return "429" in combined or "RESOURCE_EXHAUSTED" in combined

    def probe(
        self,
        section: str,
        operation: str,
        endpoint: str,
        action: Callable[[], Any],
    ) -> Any | None:
        started = time.monotonic()
        for attempt in range(4):
            try:
                result = action()
                self.probes.append(
                    {
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                        "section": section,
                        "operation": operation,
                        "endpoint_or_query": endpoint,
                        "outcome": "ALLOWED",
                        "http_or_error_code": "",
                        "error_message": "",
                        "attempts": attempt + 1,
                        "duration_ms": round((time.monotonic() - started) * 1000),
                        "runtime": self.runtime,
                        "databricks_sdk_version": self.sdk_version,
                    }
                )
                return result
            except Exception as error:
                if self._is_rate_limit(error) and attempt < 3:
                    time.sleep(2**attempt)
                    continue
                outcome, code, message = self._error_details(error)
                self.probes.append(
                    {
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                        "section": section,
                        "operation": operation,
                        "endpoint_or_query": endpoint,
                        "outcome": outcome,
                        "http_or_error_code": code,
                        "error_message": message,
                        "attempts": attempt + 1,
                        "duration_ms": round((time.monotonic() - started) * 1000),
                        "runtime": self.runtime,
                        "databricks_sdk_version": self.sdk_version,
                    }
                )
                return None
        return None

    def probe_list(
        self,
        section: str,
        operation: str,
        endpoint: str,
        action: Callable[[], Iterable[Any]],
        limit: int | None = None,
    ) -> list[dict[str, Any]] | None:
        maximum = limit or self.args.max_objects

        def collect() -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            iterator = iter(action())
            for _ in range(maximum + 1):
                try:
                    rows.append(as_data(next(iterator)))
                except StopIteration:
                    break
            if len(rows) > maximum:
                rows = rows[:maximum]
                self.section_notes[section].append(
                    f"{operation} was capped at --max-objects={maximum}."
                )
            return rows

        return self.probe(section, operation, endpoint, collect)

    def bootstrap_identity(self) -> None:
        user = self.probe(
            "identity",
            "current_user",
            "GET current-user/SCIM Me",
            lambda: as_data(self.client.current_user.me()),
        )
        if isinstance(user, dict):
            self.current_user = user
            self.current_username = str(
                nested_get(user, "user_name", "userName", "display_name", "displayName")
                or "unknown-user"
            )
            self.current_user_id = str(user.get("id") or "")
        else:
            self.section_notes["identity"].append(
                "The current-user probe failed; identity-dependent results are incomplete."
            )
        self._discover_groups()
        self._prepare_output()

    def _discover_groups(self) -> None:
        direct_groups = self.current_user.get("groups") or []
        for group in direct_groups:
            group_data = as_data(group)
            if isinstance(group_data, dict):
                name = group_data.get("display") or group_data.get("display_name")
                if name:
                    self.groups.add(str(name))
        if self.groups:
            self.group_method = "current-user/SCIM Me"
            return

        groups = self.probe_list(
            "identity",
            "groups_fallback",
            "GET groups list with members",
            lambda: self.client.groups.list(attributes="id,displayName,members"),
        )
        if groups is None:
            return
        for group in groups:
            members = group.get("members") or []
            member_ids = {
                str(member.get("value"))
                for member in members
                if isinstance(member, dict)
            }
            if self.current_user_id and self.current_user_id in member_ids:
                name = group.get("display_name") or group.get("displayName")
                if name:
                    self.groups.add(str(name))
        self.group_method = "groups list fallback"

    def _prepare_output(self) -> None:
        if self.args.output:
            base = self.args.output.expanduser()
        elif os.environ.get("DATABRICKS_RUNTIME_VERSION") or "/Workspace" in str(
            Path.cwd()
        ):
            base = Path("/Workspace/Users") / self.current_username
        else:
            base = Path.cwd()
        timestamp = self.started_at.strftime("%Y%m%d_%H%M")
        user_hash = hashlib.sha256(self.current_username.encode("utf-8")).hexdigest()[
            :12
        ]
        self.report_dir = (
            base / "what_can_i_do" / f"{user_hash}_{self.workspace_id}_{timestamp}"
        )
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def ensure_warehouses(self, section: str) -> list[dict[str, Any]]:
        if self.warehouses is None:
            result = self.probe_list(
                section,
                "list_warehouses",
                "GET /api/2.0/sql/warehouses",
                self.client.warehouses.list,
            )
            self.warehouses = result or []
            for warehouse in self.warehouses:
                state = enum_text(warehouse.get("state")).upper()
                if state == "RUNNING" and not self.sql_warehouse_id:
                    self.sql_warehouse_id = str(
                        warehouse.get("id") or warehouse.get("warehouse_id") or ""
                    )
        return self.warehouses

    def _sdk_sql(self, statement: str) -> list[dict[str, Any]]:
        if not self.sql_warehouse_id:
            raise RuntimeError("No already-running SQL warehouse is available")
        response = self.client.statement_execution.execute_statement(
            statement=statement,
            warehouse_id=self.sql_warehouse_id,
            wait_timeout="50s",
        )
        while enum_text(response.status.state).upper() in {
            "PENDING",
            "RUNNING",
        }:
            time.sleep(1)
            response = self.client.statement_execution.get_statement(
                response.statement_id
            )
        state = enum_text(response.status.state).upper()
        if state != "SUCCEEDED":
            error = as_data(getattr(response.status, "error", None))
            raise RuntimeError(f"SQL statement ended in {state}: {error}")
        columns = [column.name for column in (response.manifest.schema.columns or [])]
        result = response.result
        data_rows = list(result.data_array or [])
        next_chunk = result.next_chunk_index
        while next_chunk is not None:
            chunk = self.client.statement_execution.get_statement_result_chunk_n(
                response.statement_id, next_chunk
            )
            data_rows.extend(chunk.data_array or [])
            next_chunk = chunk.next_chunk_index
        if getattr(response.manifest, "truncated", False):
            raise RuntimeError("SQL result was truncated by Statement Execution")
        return [dict(zip(columns, row, strict=False)) for row in data_rows]

    def _spark_sql(self, statement: str) -> list[dict[str, Any]]:
        return [
            row.asDict(recursive=True) for row in self.spark.sql(statement).collect()
        ]

    def run_sql(
        self, section: str, operation: str, statement: str
    ) -> list[dict[str, Any]] | None:
        if not READ_ONLY_SQL.match(statement):
            raise ValueError(f"Refusing non-read-only SQL: {statement}")
        if self.spark is not None:
            return self.probe(
                section,
                operation,
                statement,
                lambda: self._spark_sql(statement),
            )
        self.ensure_warehouses(section)
        if not self.sql_warehouse_id:
            self.section_notes[section].append(
                f"Skipped {operation}: no in-process Spark session or already-running SQL warehouse."
            )
            return None
        return self.probe(
            section, operation, statement, lambda: self._sdk_sql(statement)
        )

    def collect_identity(self) -> None:
        self.sections["identity"].append(
            {
                "record_type": "user",
                "user_id": self.current_user_id,
                "user_name": self.current_username,
                "display_name": nested_get(
                    self.current_user, "display_name", "displayName"
                ),
                "active": self.current_user.get("active"),
                "group_discovery_method": self.group_method,
                "raw": self.current_user,
            }
        )
        for group in sorted(self.groups):
            self.sections["identity"].append(
                {
                    "record_type": "group",
                    "group_name": group,
                    "group_discovery_method": self.group_method,
                }
            )
        sql_user = self.run_sql(
            "identity", "sql_current_user", "SELECT current_user() AS current_user"
        )
        for row in sql_user or []:
            self.sections["identity"].append({"record_type": "sql_identity", **row})
        for group in sorted(self.groups):
            rows = self.run_sql(
                "identity",
                "confirm_group_membership",
                "SELECT "
                f"{sql_literal(group)} AS group_name, "
                f"is_account_group_member({sql_literal(group)}) AS is_member",
            )
            for row in rows or []:
                self.sections["identity"].append(
                    {"record_type": "group_confirmation", **row}
                )
        self.section_notes["identity"].append(
            "Nested and inherited groups, including users and account users, may not be fully visible."
        )

    def collect_entitlements(self) -> None:
        user = self.probe(
            "entitlements",
            "current_user_entitlements",
            "GET current-user/SCIM Me",
            lambda: as_data(self.client.current_user.me()),
        )
        entitlement_user = user if isinstance(user, dict) else self.current_user
        entitlements = entitlement_user.get("entitlements") or []
        for entitlement in entitlements:
            data = as_data(entitlement)
            if isinstance(data, dict):
                value = data.get("value")
                self.sections["entitlements"].append(
                    {
                        "record_type": "current_user_entitlement",
                        "entitlement": value,
                        "source": "current_user_endpoint",
                        "raw": data,
                    }
                )
        warehouses = self.probe_list(
            "entitlements",
            "infer_warehouse_list_access",
            "GET /api/2.0/sql/warehouses",
            self.client.warehouses.list,
        )
        self.sections["entitlements"].append(
            {
                "record_type": "inferred_capability",
                "entitlement": "can_list_sql_warehouses",
                "value": True,
                "visible_count": len(warehouses or []),
                "source": "list_probe",
            }
        )

    def collect_uc(self) -> None:
        inventory_views = {
            "catalogs": "catalog_owner",
            "schemata": "schema_owner",
            "tables": "table_owner",
            "volumes": "volume_owner",
            "routines": "routine_owner",
        }
        privilege_views = (
            "catalog_privileges",
            "schema_privileges",
            "table_privileges",
            "volume_privileges",
            "routine_privileges",
            "connection_privileges",
            "external_location_privileges",
            "storage_credential_privileges",
            "credential_privileges",
        )
        principals = {self.current_username, *self.groups}
        inventory: dict[str, list[dict[str, Any]]] = {}
        for view, owner_column in inventory_views.items():
            rows = self.run_sql(
                "uc",
                f"information_schema_{view}",
                f"SELECT * FROM system.information_schema.{view} LIMIT {self.args.max_objects}",
            )
            inventory[view] = rows or []
            for row in rows or []:
                owner = str(row.get(owner_column) or "")
                self.sections["uc"].append({"record_type": view, **row})
                if owner in principals:
                    self.effective_access.append(
                        {
                            "securable_type": view.rstrip("s").upper(),
                            "securable_name": self._uc_object_name(view, row),
                            "permission": "OWN",
                            "granted_to": owner,
                            "via_group": owner in self.groups,
                            "source": "information_schema",
                        }
                    )
        for view in privilege_views:
            rows = self.run_sql(
                "uc",
                f"information_schema_{view}",
                f"SELECT * FROM system.information_schema.{view}",
            )
            for row in rows or []:
                self.sections["uc"].append({"record_type": view, **row})
                grantee = str(row.get("grantee") or "")
                self.effective_access.append(
                    {
                        "securable_type": view.removesuffix("_privileges").upper(),
                        "securable_name": self._uc_object_name(view, row),
                        "permission": row.get("privilege_type"),
                        "granted_to": grantee,
                        "via_group": grantee in self.groups,
                        "source": "information_schema",
                    }
                )
        catalog_rows = inventory.get("catalogs", [])
        for row in catalog_rows:
            catalog = str(row.get("catalog_name") or "")
            if not catalog:
                continue
            grants = self.run_sql(
                "uc",
                "show_grants_catalog",
                f"SHOW GRANTS {sql_identifier(self.current_username)} "
                f"ON CATALOG {sql_identifier(catalog)}",
            )
            self._record_show_grants(grants or [], "CATALOG", catalog)
        schema_rows = inventory.get("schemata", [])[: self.args.max_objects]
        for row in schema_rows:
            catalog = str(row.get("catalog_name") or "")
            schema = str(row.get("schema_name") or "")
            if not catalog or not schema:
                continue
            full_name = f"{catalog}.{schema}"
            grants = self.run_sql(
                "uc",
                "show_grants_schema",
                f"SHOW GRANTS {sql_identifier(self.current_username)} ON SCHEMA "
                f"{sql_identifier(catalog)}.{sql_identifier(schema)}",
            )
            self._record_show_grants(grants or [], "SCHEMA", full_name)

    def _uc_object_name(self, view: str, row: dict[str, Any]) -> str:
        keys_by_view = {
            "catalogs": ("catalog_name",),
            "catalog_privileges": ("catalog_name",),
            "schemata": ("catalog_name", "schema_name"),
            "schema_privileges": ("catalog_name", "schema_name"),
            "tables": ("table_catalog", "table_schema", "table_name"),
            "table_privileges": ("table_catalog", "table_schema", "table_name"),
            "volumes": ("volume_catalog", "volume_schema", "volume_name"),
            "volume_privileges": ("volume_catalog", "volume_schema", "volume_name"),
            "routines": ("routine_catalog", "routine_schema", "routine_name"),
            "routine_privileges": ("routine_catalog", "routine_schema", "routine_name"),
        }
        keys = keys_by_view.get(view, ())
        if keys:
            return ".".join(str(row.get(key) or "") for key in keys)
        for suffix in ("_name", "_url"):
            values = [
                str(value)
                for key, value in row.items()
                if key.endswith(suffix) and value
            ]
            if values:
                return ".".join(values)
        return view

    def _record_show_grants(
        self, rows: list[dict[str, Any]], securable_type: str, securable_name: str
    ) -> None:
        for row in rows:
            normalized = {str(key).lower(): value for key, value in row.items()}
            principal = str(
                normalized.get("principal")
                or normalized.get("grantee")
                or self.current_username
            )
            permission = (
                normalized.get("actiontype")
                or normalized.get("action_type")
                or normalized.get("privilege")
            )
            self.sections["uc"].append(
                {"record_type": "show_grants", "scope": securable_name, **row}
            )
            self.effective_access.append(
                {
                    "securable_type": securable_type,
                    "securable_name": securable_name,
                    "permission": permission,
                    "granted_to": principal,
                    "via_group": principal in self.groups,
                    "source": "show_grants",
                }
            )

    def get_permissions(
        self,
        section: str,
        resource_type: str,
        resource_id: Any,
        securable_name: str,
    ) -> str:
        object_type = PERMISSION_OBJECT_TYPES.get(resource_type, resource_type)
        if resource_id in (None, ""):
            return ""
        result = self.probe(
            section,
            f"get_permissions_{resource_type}",
            f"GET permissions/{object_type}/{resource_id}",
            lambda: as_data(self.client.permissions.get(object_type, str(resource_id))),
        )
        if not isinstance(result, dict):
            return ""
        levels: list[str] = []
        principals = {self.current_username, *self.groups}
        for acl in result.get("access_control_list") or []:
            principal = str(
                acl.get("user_name")
                or acl.get("group_name")
                or acl.get("service_principal_name")
                or ""
            )
            if principal not in principals:
                continue
            for permission in acl.get("all_permissions") or []:
                level = str(permission.get("permission_level") or "")
                if level:
                    levels.append(level)
                    self.effective_access.append(
                        {
                            "securable_type": resource_type.upper(),
                            "securable_name": securable_name,
                            "permission": level,
                            "granted_to": principal,
                            "via_group": principal in self.groups,
                            "source": "permissions_api",
                        }
                    )
        return ",".join(sorted(set(levels)))

    def collect_compute(self) -> None:
        policies = self.probe_list(
            "compute",
            "list_cluster_policies",
            "GET /api/2.0/policies/clusters/list",
            self.client.cluster_policies.list,
        )
        for policy in policies or []:
            policy_id = policy.get("policy_id")
            details = self.probe(
                "compute",
                "get_cluster_policy",
                f"GET /api/2.0/policies/clusters/get?policy_id={policy_id}",
                lambda policy_id=policy_id: as_data(
                    self.client.cluster_policies.get(str(policy_id))
                ),
            )
            permission = self.get_permissions(
                "compute",
                "cluster_policy",
                policy_id,
                str(policy.get("name") or policy_id),
            )
            self.sections["compute"].append(
                {
                    "record_type": "cluster_policy",
                    "id": policy_id,
                    "name": policy.get("name"),
                    "definition": (details or policy).get("definition"),
                    "permission_level": permission,
                    "list_may_be_filtered": True,
                    "raw": details or policy,
                }
            )
        clusters = self.probe_list(
            "compute",
            "list_clusters",
            "GET /api/2.0/clusters/list",
            self.client.clusters.list,
        )
        for cluster in clusters or []:
            cluster_id = cluster.get("cluster_id")
            name = str(cluster.get("cluster_name") or cluster_id)
            permission = self.get_permissions("compute", "cluster", cluster_id, name)
            self.sections["compute"].append(
                {
                    "record_type": "cluster",
                    "id": cluster_id,
                    "name": name,
                    "access_mode": cluster.get("data_security_mode"),
                    "owner": cluster.get("creator_user_name"),
                    "single_user_assignee": cluster.get("single_user_name"),
                    "policy_id": cluster.get("policy_id"),
                    "state": cluster.get("state"),
                    "permission_level": permission,
                    "raw": cluster,
                }
            )
        for warehouse in self.ensure_warehouses("compute"):
            warehouse_id = warehouse.get("id") or warehouse.get("warehouse_id")
            name = str(warehouse.get("name") or warehouse_id)
            permission = self.get_permissions(
                "compute", "warehouse", warehouse_id, name
            )
            self.sections["compute"].append(
                {
                    "record_type": "warehouse",
                    "id": warehouse_id,
                    "name": name,
                    "state": warehouse.get("state"),
                    "warehouse_type": warehouse.get("warehouse_type"),
                    "permission_level": permission,
                    "raw": warehouse,
                }
            )
        pools = self.probe_list(
            "compute",
            "list_instance_pools",
            "GET /api/2.0/instance-pools/list",
            self.client.instance_pools.list,
        )
        for pool in pools or []:
            pool_id = pool.get("instance_pool_id")
            name = str(pool.get("instance_pool_name") or pool_id)
            permission = self.get_permissions("compute", "instance_pool", pool_id, name)
            self.sections["compute"].append(
                {
                    "record_type": "instance_pool",
                    "id": pool_id,
                    "name": name,
                    "permission_level": permission,
                    "raw": pool,
                }
            )

    def collect_workspace(self) -> None:
        self._walk_workspace(f"/Users/{self.current_username}", 0)
        self._walk_workspace("/Shared", 0)
        resource_specs: list[tuple[str, str, Callable[[], Any], tuple[str, ...]]] = [
            ("repo", "GET /api/2.0/repos", self.client.repos.list, ("id", "path")),
            (
                "job",
                "GET /api/2.2/jobs/list",
                self.client.jobs.list,
                ("job_id", "settings.name"),
            ),
            (
                "pipeline",
                "GET /api/2.0/pipelines",
                self.client.pipelines.list_pipelines,
                ("pipeline_id", "name"),
            ),
            (
                "query",
                "GET SQL queries list",
                self.client.queries.list,
                ("id", "display_name", "name"),
            ),
            (
                "alert",
                "GET SQL alerts list",
                self.client.alerts.list,
                ("id", "display_name", "name"),
            ),
            (
                "dashboard",
                "GET /api/2.0/lakeview/dashboards",
                self.client.lakeview.list,
                ("dashboard_id", "display_name"),
            ),
            ("app", "GET /api/2.0/apps", self.client.apps.list, ("name", "name")),
            (
                "experiment",
                "GET MLflow experiments list",
                self.client.experiments.list_experiments,
                ("experiment_id", "name"),
            ),
            (
                "registered_model",
                "GET workspace registered models list",
                self.client.model_registry.list_models,
                ("id", "name"),
            ),
            (
                "serving_endpoint",
                "GET /api/2.0/serving-endpoints",
                self.client.serving_endpoints.list,
                ("id", "name"),
            ),
            (
                "vector_search_endpoint",
                "GET /api/2.0/vector-search/endpoints",
                self.client.vector_search_endpoints.list_endpoints,
                ("id", "name"),
            ),
        ]
        for resource_type, endpoint, method, identity_keys in resource_specs:
            rows = self.probe_list(
                "workspace",
                f"list_{resource_type}",
                endpoint,
                method,
            )
            self._record_workspace_objects(resource_type, rows or [], identity_keys)
        spaces = self.probe(
            "workspace",
            "list_genie_space",
            "GET /api/2.0/genie/spaces",
            self._list_genie_spaces,
        )
        self._record_workspace_objects(
            "genie_space", spaces or [], ("space_id", "title", "name")
        )

    def _list_genie_spaces(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        token: str | None = None
        while len(rows) < self.args.max_objects:
            response = self.client.genie.list_spaces(
                page_size=min(100, self.args.max_objects - len(rows)),
                page_token=token,
            )
            data = as_data(response)
            rows.extend(data.get("spaces") or [])
            token = data.get("next_page_token")
            if not token:
                break
        return rows[: self.args.max_objects]

    def _walk_workspace(self, path: str, depth: int) -> None:
        if depth > self.args.max_depth:
            return
        rows = self.probe_list(
            "workspace",
            "list_workspace_path",
            f"GET /api/2.0/workspace/list?path={path}",
            lambda path=path: self.client.workspace.list(path),
        )
        for item in rows or []:
            object_type = enum_text(item.get("object_type")).upper()
            object_id = item.get("object_id")
            item_path = str(item.get("path") or "")
            permission = self.get_permissions(
                "workspace", object_type, object_id, item_path
            )
            self.sections["workspace"].append(
                {
                    "record_type": "workspace_object",
                    "object_type": object_type,
                    "id": object_id,
                    "path": item_path,
                    "permission_level": permission,
                    "raw": item,
                }
            )
            self.effective_access.append(
                {
                    "securable_type": object_type or "WORKSPACE_OBJECT",
                    "securable_name": item_path,
                    "permission": permission or "VISIBLE",
                    "granted_to": self.current_username,
                    "via_group": False,
                    "source": "permissions_api" if permission else "list_visibility",
                }
            )
            if object_type == "DIRECTORY" and depth < self.args.max_depth:
                self._walk_workspace(item_path, depth + 1)

    def _record_workspace_objects(
        self,
        resource_type: str,
        rows: list[dict[str, Any]],
        identity_keys: tuple[str, ...],
    ) -> None:
        id_key = identity_keys[0]
        name_keys = identity_keys[1:]
        for item in rows:
            resource_id = nested_get(item, id_key)
            name = nested_get(item, *name_keys) or resource_id
            permission = self.get_permissions(
                "workspace", resource_type, resource_id, str(name)
            )
            self.sections["workspace"].append(
                {
                    "record_type": resource_type,
                    "id": resource_id,
                    "name": name,
                    "permission_level": permission,
                    "raw": item,
                }
            )
            self.effective_access.append(
                {
                    "securable_type": resource_type.upper(),
                    "securable_name": name,
                    "permission": permission or "VISIBLE",
                    "granted_to": self.current_username,
                    "via_group": False,
                    "source": "permissions_api" if permission else "list_visibility",
                }
            )

    def collect_credentials(self) -> None:
        tokens = self.probe_list(
            "credentials",
            "list_own_tokens",
            "GET /api/2.0/token/list",
            self.client.tokens.list,
        )
        for token in tokens or []:
            self.sections["credentials"].append(
                {
                    "record_type": "token_metadata",
                    "token_id": token.get("token_id"),
                    "creation_time": token.get("creation_time"),
                    "expiry_time": token.get("expiry_time"),
                    "comment": token.get("comment"),
                }
            )
        scopes = self.probe_list(
            "credentials",
            "list_secret_scopes",
            "GET /api/2.0/secrets/scopes/list",
            self.client.secrets.list_scopes,
        )
        for scope in scopes or []:
            scope_name = str(scope.get("name") or "")
            acls = self.probe_list(
                "credentials",
                "list_secret_scope_acls",
                f"GET /api/2.0/secrets/acls/list?scope={scope_name}",
                lambda scope_name=scope_name: self.client.secrets.list_acls(scope_name),
            )
            self.sections["credentials"].append(
                {
                    "record_type": "secret_scope",
                    "scope": scope_name,
                    "backend_type": scope.get("backend_type"),
                    "acls": acls,
                }
            )
        jobs = self.probe_list(
            "credentials",
            "list_jobs_for_run_as",
            "GET /api/2.2/jobs/list",
            lambda: self.client.jobs.list(expand_tasks=True),
        )
        for job in jobs or []:
            run_as = nested_get(job, "settings.run_as.user_name")
            if run_as == self.current_username:
                self.sections["credentials"].append(
                    {
                        "record_type": "job_runs_as_caller",
                        "job_id": job.get("job_id"),
                        "name": nested_get(job, "settings.name"),
                        "run_as": run_as,
                    }
                )
        pipelines = self.probe_list(
            "credentials",
            "list_pipelines_for_run_as",
            "GET /api/2.0/pipelines",
            self.client.pipelines.list_pipelines,
        )
        for pipeline in pipelines or []:
            pipeline_id = pipeline.get("pipeline_id")
            details = self.probe(
                "credentials",
                "get_pipeline_for_run_as",
                f"GET /api/2.0/pipelines/{pipeline_id}",
                lambda pipeline_id=pipeline_id: as_data(
                    self.client.pipelines.get(str(pipeline_id))
                ),
            )
            run_as = nested_get(
                details or {}, "run_as.user_name", "spec.run_as.user_name"
            )
            if run_as == self.current_username:
                self.sections["credentials"].append(
                    {
                        "record_type": "pipeline_runs_as_caller",
                        "pipeline_id": pipeline_id,
                        "name": pipeline.get("name"),
                        "run_as": run_as,
                    }
                )

    def collect_features(self) -> None:
        feature_lists: list[tuple[str, str, Callable[[], Iterable[Any]]]] = [
            ("warehouses", "GET /api/2.0/sql/warehouses", self.client.warehouses.list),
            (
                "serving_endpoints",
                "GET /api/2.0/serving-endpoints",
                self.client.serving_endpoints.list,
            ),
            ("apps", "GET /api/2.0/apps", self.client.apps.list),
        ]
        for feature, endpoint, method in feature_lists:
            rows = self.probe_list(
                "features", f"feature_{feature}", endpoint, method, limit=1
            )
            outcome = self._latest_outcome(f"feature_{feature}")
            self.sections["features"].append(
                {
                    "record_type": "feature_probe",
                    "feature": feature,
                    "outcome": outcome,
                    "sample_count": len(rows or []),
                }
            )
        spaces = self.probe(
            "features",
            "feature_genie_spaces",
            "GET /api/2.0/genie/spaces",
            lambda: as_data(self.client.genie.list_spaces(page_size=1)),
        )
        self.sections["features"].append(
            {
                "record_type": "feature_probe",
                "feature": "genie_spaces",
                "outcome": self._latest_outcome("feature_genie_spaces"),
                "sample_count": len((spaces or {}).get("spaces") or []),
            }
        )
        for feature, statement in (
            ("system.billing.usage", "SELECT * FROM system.billing.usage LIMIT 1"),
            ("system.access.audit", "SELECT * FROM system.access.audit LIMIT 1"),
        ):
            rows = self.run_sql("features", f"feature_{feature}", statement)
            self.sections["features"].append(
                {
                    "record_type": "feature_probe",
                    "feature": feature,
                    "outcome": self._latest_outcome(f"feature_{feature}")
                    if rows is not None
                    else "SKIPPED",
                    "sample_count": len(rows or []),
                }
            )
        config = self.probe(
            "features",
            "feature_workspace_conf",
            "GET /api/2.0/workspace-conf",
            lambda: as_data(
                self.client.workspace_conf.get_status(
                    "enableTokensConfig,enableIpAccessLists"
                )
            ),
        )
        self.sections["features"].append(
            {
                "record_type": "feature_probe",
                "feature": "workspace_conf",
                "outcome": self._latest_outcome("feature_workspace_conf"),
                "metadata": config,
            }
        )

    def _latest_outcome(self, operation: str) -> str:
        for probe in reversed(self.probes):
            if probe["operation"] == operation:
                return str(probe["outcome"])
        return "SKIPPED"

    def run(self) -> tuple[Path, Path]:
        self.bootstrap_identity()
        collectors: dict[str, Callable[[], None]] = {
            "identity": self.collect_identity,
            "entitlements": self.collect_entitlements,
            "uc": self.collect_uc,
            "compute": self.collect_compute,
            "workspace": self.collect_workspace,
            "credentials": self.collect_credentials,
            "features": self.collect_features,
        }
        for section in self.args.sections:
            collectors[section]()
        return write_report(self)


def main() -> int:
    args = parse_args()
    collector = AccessCollector(args)
    report_dir, archive = collector.run()
    print(f"Report: {report_dir}")
    print(f"ZIP: {archive}")
    print("Review the ZIP before sharing it outside your organization.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
