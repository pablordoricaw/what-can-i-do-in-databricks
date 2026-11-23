---
name: what-can-i-do-in-databricks
description: Create a read-only report of a non-admin Databricks user's own accessible data, privileges, compute, workspace objects, permissions, and product capabilities for review with their Databricks account team.
---

# What Can I Do in Databricks?

Collect evidence about the current user's effective access without changing workspace state. Assume the caller is not an account, workspace, or metastore administrator and has no `MANAGE` or `READ METADATA` unless a probe demonstrates otherwise.

## Run the collector

1. Run `uv --version` before doing anything else.
2. If `uv` is missing outside a Databricks workspace runtime, stop. Show the official installation instructions at <https://docs.astral.sh/uv/getting-started/installation/>. Never use `pip`, `%pip`, or a requirements file.
3. In workspace Genie Code on notebook or serverless compute where `uv` is unavailable, use the already-installed `databricks-sdk` without installing anything. Run the script with that Python runtime and tell the user the report will record `preinstalled SDK`.
4. Confirm the output location and whether default redaction is enabled. Recommend leaving `--redact` on. The default is the current workspace home folder in a Databricks runtime and the current local directory in Genie Code CLI.
5. Run the provided collector instead of improvising API or SQL calls:

   ```bash
   uv run --script scripts/collect_my_access.py --output <path>
   ```

   Resolve this path relative to the skill first. If the skill resource mount does not contain the script, do not conclude that the registered Git folder omitted it. Locate the registered workspace folder that contains this skill's `SKILL.md`, then use its `what-can-i-do-in-databricks/scripts/collect_my_access.py` file directly. A typical path is `/Workspace/Users/<email>/what-can-i-do-in-databricks/what-can-i-do-in-databricks/scripts/collect_my_access.py`. If the registered folder cannot be determined safely, ask the user for its path. Never reconstruct or improvise the collector.

   In the workspace-only fallback, execute the resolved `collect_my_access.py` with the preinstalled Python environment and the same arguments. Do not install dependencies.
6. Use `--sections` for a narrower run and `--max-objects` or `--max-depth` to bound discovery. Do not add mutating probes.

## Present the result

1. Open the generated `SUMMARY.md`.
2. Show the user its coverage table and notable findings.
3. Explain denied, unsupported, partial, and skipped areas without treating them as failures.
4. Give the user the generated ZIP path.
5. Remind the user to review the ZIP before sharing it outside their organization.

## Invariants

- Use only the script's read-only list/GET probes and `SELECT`, `SHOW`, or `DESCRIBE` statements.
- Never create, update, delete, grant, revoke, start compute, run jobs, or retrieve secret, token, or credential values.
- Authenticate as the caller with Databricks default authentication. Do not introduce service principals or secrets.
- If no already-running SQL warehouse or in-process Spark session is available, allow API-only collection and report SQL coverage as skipped.
- Read [`references/what_non_admins_can_see.md`](references/what_non_admins_can_see.md) when interpreting probe outcomes or extending coverage.
