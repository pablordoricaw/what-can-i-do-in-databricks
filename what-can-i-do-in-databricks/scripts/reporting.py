# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# ruff: noqa: I001

from __future__ import annotations

import csv
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ALL_SECTIONS = (
    "identity",
    "entitlements",
    "uc",
    "compute",
    "workspace",
    "credentials",
    "features",
)

WORKSPACE_ACL_TYPES = {
    "ALERT",
    "APP",
    "DASHBOARD",
    "DIRECTORY",
    "EXPERIMENT",
    "FILE",
    "GENIE_SPACE",
    "JOB",
    "NOTEBOOK",
    "PIPELINE",
    "QUERY",
    "REGISTERED_MODEL",
    "REPO",
    "SERVING_ENDPOINT",
    "VECTOR_SEARCH_ENDPOINT",
}

PERMISSION_DESCRIPTIONS = {
    "CAN_ATTACH_TO": "Attach workloads to the object",
    "CAN_BIND": "Bind the object to supported resources",
    "CAN_EDIT": "Modify the object",
    "CAN_MANAGE": "Manage the object and its permissions",
    "CAN_MANAGE_RUN": "Manage runs without changing the definition",
    "CAN_QUERY": "Send queries or inference requests",
    "CAN_READ": "Read the object",
    "CAN_RESTART": "Restart the object",
    "CAN_RUN": "Run the object",
    "CAN_USE": "Use the object",
    "CAN_VIEW": "View the object",
    "CAN_VIEW_METADATA": "View object metadata",
}

ENTITLEMENT_DESCRIPTIONS = {
    "allow-cluster-create": "create all-purpose compute, subject to policy",
    "allow-instance-pool-create": "create instance pools",
    "databricks-sql-access": "use Databricks SQL",
    "workspace-access": "sign in to and use the workspace",
}


def _redact(collector: Any, value: Any, key: str = "") -> Any:
    if not collector.args.redact:
        return value
    if isinstance(value, dict):
        return {
            item_key: _redact(collector, item, str(item_key))
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(collector, item, key) for item in value]
    if not isinstance(value, str):
        return value
    lowered = key.lower()
    if (
        collector.email_pattern.match(value)
        and value.lower() != collector.current_username.lower()
    ):
        return collector.hash_value(value.lower())
    if any(
        marker in lowered
        for marker in ("service_principal", "application_id", "client_id")
    ):
        return collector.hash_value(value)
    if collector.args.redact_objects and lowered in {
        "endpoint_or_query",
        "error_message",
        "notes",
    }:
        # Free text can embed object names in URLs, SQL, or exception messages.
        return collector.hash_value(value) if value else value
    if collector.args.redact_objects and any(
        marker in lowered
        for marker in (
            "name",
            "path",
            "securable",
            "object",
            "catalog",
            "schema",
            "table",
            "volume",
            "routine",
        )
    ):
        return collector.hash_value(value)
    return value


def _csv_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: json.dumps(value, sort_keys=True)
        if isinstance(value, (dict, list))
        else value
        for key, value in row.items()
    }


def _write_csv(collector: Any, path: Path, rows: list[dict[str, Any]]) -> None:
    prepared = [_csv_row(_redact(collector, collector.as_data(row))) for row in rows]
    fieldnames: list[str] = []
    for row in prepared:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    if not fieldnames:
        fieldnames = ["record_type"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(prepared)


def _write_json(collector: Any, path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            _redact(collector, collector.as_data(rows)),
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        handle.write("\n")


def _coverage(collector: Any, section: str) -> str:
    if section not in collector.args.sections:
        return "skipped"
    outcomes = [
        probe["outcome"] for probe in collector.probes if probe["section"] == section
    ]
    if not outcomes:
        return "skipped"
    if (
        all(outcome == "ALLOWED" for outcome in outcomes)
        and not collector.section_notes[section]
    ):
        return "complete"
    if all(outcome == "DENIED" for outcome in outcomes):
        return "denied"
    return "partial"


def _notable_findings(collector: Any) -> list[str]:
    findings: list[str] = []
    admin_groups = sorted(
        group
        for group in collector.groups
        if group.casefold() in {"admins", "account admins"}
    )
    if admin_groups:
        findings.append(
            "The caller belongs to an admin-signaling group: "
            + ", ".join(admin_groups)
            + "."
        )
    all_privileges = [
        row
        for row in collector.effective_access
        if "ALL PRIVILEGES" in str(row.get("permission", "")).upper()
    ]
    if all_privileges:
        findings.append(
            f"ALL PRIVILEGES appeared in {len(all_privileges)} effective-access rows."
        )
    entitlement_values = {
        str(row.get("entitlement", "")).lower()
        for row in collector.sections["entitlements"]
    }
    if "allow-cluster-create" in entitlement_values:
        findings.append("The current-user endpoint reports allow-cluster-create.")
    no_expiry = [
        row
        for row in collector.sections["credentials"]
        if row.get("record_type") == "token_metadata" and not row.get("expiry_time")
    ]
    if no_expiry:
        findings.append(f"{len(no_expiry)} visible token(s) have no expiry time.")
    shared_manage = [
        row
        for row in collector.sections["workspace"]
        if str(row.get("path", "")).startswith("/Shared")
        and "MANAGE" in str(row.get("permission_level", ""))
    ]
    if shared_manage:
        findings.append(
            f"The caller has a manage-level permission on {len(shared_manage)} visible /Shared object(s)."
        )
    if not findings:
        findings.append(
            "No predefined high-impact findings were detected in collected rows."
        )
    return findings


def _rows(
    collector: Any, section: str, record_type: str | None = None
) -> list[dict[str, Any]]:
    rows = collector.sections.get(section, [])
    if record_type is None:
        return rows
    return [row for row in rows if row.get("record_type") == record_type]


def _probe_outcome(collector: Any, operation: str) -> str:
    for probe in reversed(collector.probes):
        if probe.get("operation") == operation:
            return str(probe.get("outcome") or "UNKNOWN")
    return "SKIPPED"


def _format_values(values: list[str], maximum: int = 8) -> str:
    unique = sorted({value for value in values if value}, key=str.casefold)
    shown = unique[:maximum]
    result = ", ".join(f"`{value}`" for value in shown)
    if len(unique) > maximum:
        result += f", and {len(unique) - maximum} more"
    return result or "none discovered"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes"}


def _role_lines(collector: Any) -> list[str]:
    groups = {group.casefold(): group for group in collector.groups}
    principals = {collector.current_username, *collector.groups}
    user_rows = _rows(collector, "identity", "user")
    active = user_rows[0].get("active") if user_rows else None

    if "account admins" in groups:
        account_status = "Yes"
        account_evidence = f"Member of `{groups['account admins']}`."
    else:
        account_status = "Not demonstrated"
        account_evidence = "No visible `account admins` membership; account-console roles are not enumerated."

    if "admins" in groups:
        workspace_status = "Yes"
        workspace_evidence = f"Member of `{groups['admins']}`."
    else:
        workspace_status = "Not demonstrated"
        workspace_evidence = "No visible `admins` membership."

    metastore_rows = _rows(collector, "uc", "metastore_details")
    metastore_outcome = _probe_outcome(collector, "get_current_metastore_details")
    metastore_owner = (
        str(metastore_rows[0].get("owner") or "") if metastore_rows else ""
    )
    if metastore_owner in principals:
        metastore_status = "Yes"
        metastore_evidence = (
            f"The metastore owner is the caller or known group `{metastore_owner}`."
        )
    elif metastore_outcome == "ALLOWED":
        metastore_status = "Admin access demonstrated"
        metastore_evidence = (
            "The admin-restricted metastore detail endpoint was allowed."
        )
    elif metastore_outcome == "DENIED":
        metastore_status = "Not demonstrated"
        metastore_evidence = (
            "The admin-restricted metastore detail endpoint was denied."
        )
    else:
        metastore_status = "Unknown"
        metastore_evidence = f"Metastore detail probe outcome: `{metastore_outcome}`."

    if active is False:
        user_status = "Inactive"
        user_evidence = "The current-user endpoint reports an inactive identity."
    elif user_rows:
        user_status = "Yes"
        user_evidence = "The current-user endpoint returned the caller identity."
    else:
        user_status = "Unknown"
        user_evidence = "The current-user identity was not collected."

    roles = (
        ("Account admin", account_status, account_evidence),
        ("Workspace admin", workspace_status, workspace_evidence),
        ("Metastore admin", metastore_status, metastore_evidence),
        ("Workspace user", user_status, user_evidence),
    )
    lines = [
        "### Roles",
        "",
        "| Role | Status | Evidence |",
        "|---|---|---|",
    ]
    for role, status, evidence in roles:
        escaped_evidence = evidence.replace("|", "\\|")
        lines.append(f"| {role} | {status} | {escaped_evidence} |")
    return lines


def _workspace_acl_lines(collector: Any) -> list[str]:
    explicit = [
        row
        for row in collector.effective_access
        if row.get("source") == "permissions_api"
        and str(row.get("securable_type") or "").upper() in WORKSPACE_ACL_TYPES
    ]
    visible = [
        row
        for row in collector.effective_access
        if row.get("source") == "list_visibility"
        and str(row.get("securable_type") or "").upper() in WORKSPACE_ACL_TYPES
    ]
    by_permission: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in explicit:
        permission = str(row.get("permission") or "UNKNOWN")
        by_permission[permission].add(
            (
                str(row.get("securable_type") or "WORKSPACE_OBJECT").upper(),
                str(row.get("securable_name") or ""),
            )
        )

    lines = ["### Workspace Object ACLs", ""]
    if by_permission:
        lines.extend(
            [
                f"The Permissions API returned effective ACLs for `{len({item for items in by_permission.values() for item in items})}` visible workspace objects.",
                "",
                "| Permission | What it allows | Objects | Object types |",
                "|---|---|---:|---|",
            ]
        )
        for permission, objects in sorted(by_permission.items()):
            object_types = sorted({object_type for object_type, _ in objects})
            description = PERMISSION_DESCRIPTIONS.get(
                permission, "See the object's Databricks permission model"
            )
            lines.append(
                f"| `{permission}` | {description} | {len(objects)} | {', '.join(f'`{value}`' for value in object_types)} |"
            )
    else:
        lines.append(
            "No explicit workspace-object ACL was returned for the caller or known groups."
        )
    if visible:
        lines.extend(
            [
                "",
                f"Additionally, `{len({(row.get('securable_type'), row.get('securable_name')) for row in visible})}` objects were visible through list APIs without a readable ACL. Visibility proves discovery, not run, edit, or manage authority.",
            ]
        )
    return lines


def _group_lines(collector: Any) -> list[str]:
    confirmations = [
        str(row.get("group_name") or "")
        for row in _rows(collector, "identity", "group_confirmation")
        if _truthy(row.get("is_member"))
    ]
    inherited = [row for row in collector.effective_access if row.get("via_group")]
    by_group = Counter(str(row.get("granted_to") or "unknown") for row in inherited)
    lines = [
        "### Group Membership and Inheritance",
        "",
        f"- Visible memberships ({collector.group_method}): {_format_values(list(collector.groups))}.",
    ]
    if confirmations:
        lines.append(
            f"- SQL-confirmed account-group memberships: {_format_values(confirmations)}."
        )
    if by_group:
        inherited_text = ", ".join(
            f"`{group}` ({count})" for group, count in sorted(by_group.items())
        )
        lines.append(
            f"- Effective grants inherited through known groups: {inherited_text}."
        )
    else:
        lines.append(
            "- No collected effective-access row was attributed to a known group."
        )
    lines.append(
        "- Nested or hidden memberships can still be missing; this report does not treat an absent group as proof of non-membership."
    )
    return lines


def _collect_policy_ids(value: Any, found: dict[str, set[str]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).casefold()
            if lowered.endswith("budget_policy_id") and item not in (None, ""):
                found["budget"].add(str(item))
            elif lowered.endswith("usage_policy_id") and item not in (None, ""):
                found["usage"].add(str(item))
            _collect_policy_ids(item, found)
    elif isinstance(value, list):
        for item in value:
            _collect_policy_ids(item, found)


def _other_access_lines(collector: Any) -> list[str]:
    entitlements = [
        str(row.get("entitlement") or "")
        for row in _rows(collector, "entitlements", "current_user_entitlement")
    ]
    entitlement_text = ", ".join(
        f"`{value}` ({ENTITLEMENT_DESCRIPTIONS.get(value.casefold(), 'workspace entitlement')})"
        for value in sorted(set(entitlements), key=str.casefold)
    )

    scopes = _rows(collector, "credentials", "secret_scope")
    principals = {collector.current_username, *collector.groups}
    scope_permissions: Counter[str] = Counter()
    unknown_scope_acls = 0
    for scope in scopes:
        acls = scope.get("acls")
        if acls is None:
            unknown_scope_acls += 1
            continue
        for acl in acls:
            principal = str(acl.get("principal") or "") if isinstance(acl, dict) else ""
            if principal in principals:
                permission = str(acl.get("permission") or "UNKNOWN")
                scope_permissions[permission] += 1

    policy_ids: dict[str, set[str]] = {"budget": set(), "usage": set()}
    _collect_policy_ids(collector.sections, policy_ids)
    budget_text = (
        _format_values(list(policy_ids["budget"]))
        if policy_ids["budget"]
        else "none referenced in collected visible resources"
    )
    usage_text = (
        _format_values(list(policy_ids["usage"]))
        if policy_ids["usage"]
        else "none referenced in collected visible resources"
    )

    feature_outcomes: dict[str, list[str]] = defaultdict(list)
    for row in _rows(collector, "features", "feature_probe"):
        feature_outcomes[str(row.get("outcome") or "UNKNOWN")].append(
            str(row.get("feature") or "")
        )
    feature_text = "; ".join(
        f"{outcome.lower()}: {_format_values(features, maximum=12)}"
        for outcome, features in sorted(feature_outcomes.items())
    )

    lines = ["### Other Access", ""]
    lines.append(
        f"- Entitlements: {entitlement_text or 'none returned by the current-user endpoint'}."
    )
    permission_text = ", ".join(
        f"`{permission}` on {count}"
        for permission, count in sorted(scope_permissions.items())
    )
    scope_detail = permission_text or "no caller/group ACL was readable"
    if unknown_scope_acls:
        scope_detail += f"; ACL unavailable for {unknown_scope_acls}"
    lines.append(f"- Secret scopes: `{len(scopes)}` visible; {scope_detail}.")
    lines.append(
        f"- Serverless budget policies referenced by visible resources: {budget_text}."
    )
    lines.append(
        f"- Serverless usage policies referenced by visible resources: {usage_text}."
    )
    lines.append(
        "- Policy IDs above are assignments exposed on collected workspace resources; account-level policy definitions are not enumerated by this caller-scoped run."
    )
    if feature_text:
        lines.append(f"- Product and system-table probes: {feature_text}.")
    return lines


def _capability_summary(collector: Any) -> list[str]:
    lines = [
        "## What This Run Says You Can Do",
        "",
        "Statuses are evidence-based. `Not demonstrated` means the run found no positive proof; it does not prove the role or access is absent.",
        "",
    ]
    for section in (
        _role_lines(collector),
        _workspace_acl_lines(collector),
        _group_lines(collector),
        _other_access_lines(collector),
    ):
        lines.extend(section)
        lines.append("")
    return lines


def _summary_markdown(collector: Any) -> str:
    finished = collector.now_utc()
    lines = [
        "# My Databricks effective access",
        "",
        "## Run metadata",
        "",
        f"- Started: `{collector.started_at.isoformat()}`",
        f"- Finished: `{finished.isoformat()}`",
        f"- Workspace ID: `{collector.workspace_id}`",
        f"- Current user: `{collector.current_username}`",
        f"- Runtime: `{collector.runtime}`",
        f"- databricks-sdk: `{collector.sdk_version}`",
        f"- Redaction: `{'on' if collector.args.redact else 'off'}`",
        f"- Object-name redaction: `{'on' if collector.args.redact_objects else 'off'}`",
        "",
    ]
    if collector.runtime == "preinstalled SDK":
        lines.extend(
            [
                "> This run used the Databricks runtime's preinstalled SDK without uv and installed nothing.",
                "",
            ]
        )
    lines.extend(_capability_summary(collector))
    lines.extend(
        [
            "## Coverage",
            "",
            "| Section | Coverage | Rows | Notes |",
            "|---|---:|---:|---|",
        ]
    )
    for section in ALL_SECTIONS:
        notes = _redact(
            collector, " ".join(collector.section_notes[section]), "notes"
        ).replace("|", "\\|")
        lines.append(
            f"| {section} | {_coverage(collector, section)} | {len(collector.sections[section])} | {notes} |"
        )
    lines.extend(["", "## Notable findings", ""])
    lines.extend(f"- {finding}" for finding in _notable_findings(collector))
    lines.extend(
        [
            "",
            "## Counts",
            "",
            f"- Probe calls: `{len(collector.probes)}`",
            f"- Effective-access rows: `{len(collector.effective_access)}`",
            f"- Groups discovered: `{len(collector.groups)}`",
            f"- Selected sections: `{','.join(collector.args.sections)}`",
            "",
            "## What this report can't see",
            "",
            "This caller-scoped report reflects the current user's effective access, including any administrative privileges demonstrated by the collected evidence. The report cannot prove that a hidden object, grant, group, product, or account-level setting does not exist. Results can omit nested or inherited groups, objects lacking browse permissions, grants requiring `MANAGE` or `READ METADATA`, other users' credentials, account-console configuration, and permissions that a product does not expose through its list or Permissions APIs. A successful list call proves reachability, not create or manage authority. A denied or unsupported probe is retained as evidence rather than treated as a failed run.",
            "",
            "Review the report and ZIP before sharing them outside your organization.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(collector: Any) -> tuple[Path, Path]:
    if collector.report_dir is None:
        raise RuntimeError("Output directory was not initialized")
    for section in ALL_SECTIONS:
        _write_csv(
            collector,
            collector.report_dir / f"{section}.csv",
            collector.sections[section],
        )
        _write_json(
            collector,
            collector.report_dir / f"{section}.json",
            collector.sections[section],
        )
    _write_csv(
        collector,
        collector.report_dir / "my_effective_access.csv",
        collector.effective_access,
    )
    _write_csv(collector, collector.report_dir / "probe_log.csv", collector.probes)
    (collector.report_dir / "SUMMARY.md").write_text(
        _summary_markdown(collector), encoding="utf-8"
    )
    archive = Path(
        shutil.make_archive(
            str(collector.report_dir), "zip", root_dir=collector.report_dir
        )
    )
    return collector.report_dir, archive
