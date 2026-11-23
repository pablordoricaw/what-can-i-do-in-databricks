# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
# ruff: noqa: I001

from __future__ import annotations

import csv
import json
import shutil
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
    if collector.email_pattern.match(value) and value.lower() != collector.current_username.lower():
        return collector.hash_value(value.lower())
    if any(
        marker in lowered
        for marker in ("service_principal", "application_id", "client_id")
    ):
        return collector.hash_value(value)
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


def _write_csv(
    collector: Any, path: Path, rows: list[dict[str, Any]]
) -> None:
    prepared = [
        _csv_row(_redact(collector, collector.as_data(row))) for row in rows
    ]
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


def _write_json(
    collector: Any, path: Path, rows: list[dict[str, Any]]
) -> None:
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
        probe["outcome"]
        for probe in collector.probes
        if probe["section"] == section
    ]
    if not outcomes:
        return "skipped"
    if all(outcome == "ALLOWED" for outcome in outcomes) and not collector.section_notes[section]:
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
            + ". This run is not a non-admin baseline."
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
        findings.append("No predefined high-impact findings were detected in collected rows.")
    return findings


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
    lines.extend(
        [
            "## Coverage",
            "",
            "| Section | Coverage | Rows | Notes |",
            "|---|---:|---:|---|",
        ]
    )
    for section in ALL_SECTIONS:
        notes = " ".join(collector.section_notes[section]).replace("|", "\\|")
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
            "This is a caller-scoped report designed for non-admin users. If an admin-signaling group appears in the findings, the results reflect that elevated identity and are not a non-admin baseline. The report cannot prove that a hidden object, grant, group, product, or account-level setting does not exist. Results can omit nested or inherited groups, objects lacking browse permissions, grants requiring `MANAGE` or `READ METADATA`, other users' credentials, account-console configuration, and permissions that a product does not expose through its list or Permissions APIs. A successful list call proves reachability, not create or manage authority. A denied or unsupported probe is retained as evidence rather than treated as a failed run.",
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
