---
name: what-can-i-do-in-databricks
description: Create a read-only report of a non-admin Databricks user's own accessible data, privileges, compute, workspace objects, permissions, and product capabilities for review with their Databricks account team.
---

# What Can I Do in Databricks?

Collect evidence about the current user's effective access without changing workspace state. Assume the caller is not an account, workspace, or metastore administrator and has no `MANAGE` or `READ METADATA` unless a probe demonstrates otherwise.

## Run the collector

1. Run `uv --version` before doing anything else.
2. If `uv` is missing outside a Databricks workspace runtime, stop. Show the official installation instructions at <https://docs.astral.sh/uv/getting-started/installation/>. Never use `pip`, `%pip`, or a requirements file.
3. In workspace Genie Code on notebook or serverless compute, try `uv` first. If `uv` cannot resolve the locked dependency, or a shell subprocess cannot inherit the notebook's Databricks authentication, use the already-installed `databricks-sdk` in the notebook process without installing anything. This fallback is allowed even when the `uv` binary exists. Tell the user the report will record `preinstalled SDK`.
4. Do not ask about redaction or the output location. Always run with `--redact`. In a Databricks workspace, the collector automatically writes under `/Users/<username>/what-can-i-do-in-databricks-results/<run-folder>` (the local filesystem path is `/Workspace/Users/<username>/what-can-i-do-in-databricks-results/<run-folder>`). In Genie Code CLI, it writes under `./what-can-i-do-in-databricks-results/<run-folder>`. Use `--output` only when the user explicitly requests another location.
5. Run the provided collector instead of improvising API or SQL calls:

   ```bash
   uv run --script scripts/collect_my_access.py --redact
   ```

   Resolve this path relative to the skill first. If the skill resource mount does not contain the script, do not conclude that the registered Git folder omitted it. Locate the registered workspace folder that contains this skill's `SKILL.md`, then use its `what-can-i-do-in-databricks/scripts/collect_my_access.py` file directly. A typical path is `/Workspace/Users/<email>/what-can-i-do-in-databricks/what-can-i-do-in-databricks/scripts/collect_my_access.py`. If the registered folder cannot be determined safely, ask the user for its path. Never reconstruct or improvise the collector.

   In the workspace-only fallback, execute the resolved `collect_my_access.py` in the notebook's Python process with the same arguments so it inherits notebook authentication and the active Spark session. Do not launch it as a shell subprocess, and do not install dependencies. The collector detects Spark from injected globals, the IPython user namespace, or the active `SparkSession`.
6. Use `--sections` for a narrower run and `--max-objects` or `--max-depth` to bound discovery. Do not add mutating probes.

## Present the result

1. Open the generated `SUMMARY.md`.
2. Show the user its evidence-based capability summary, including roles, workspace object ACLs, group-derived access, and other access such as secret scopes and serverless policy assignments.
3. Show the user its coverage table and notable findings.
4. Explain denied, unsupported, partial, and skipped areas without treating them as failures.
5. Give the user the generated ZIP path.
6. Remind the user to review the ZIP before sharing it outside their organization.

## Invariants

- Use only the script's read-only list/GET probes and `SELECT`, `SHOW`, or `DESCRIBE` statements.
- Never create, update, delete, grant, revoke, start compute, run jobs, or retrieve secret, token, or credential values.
- Authenticate as the caller with Databricks default authentication. Do not introduce service principals or secrets.
- If no already-running SQL warehouse or in-process Spark session is available, allow API-only collection and report SQL coverage as skipped.
- Read [`references/what_non_admins_can_see.md`](references/what_non_admins_can_see.md) when interpreting probe outcomes or extending coverage.
