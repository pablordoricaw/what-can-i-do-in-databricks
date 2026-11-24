# What non-admin users can see

The collector treats every surface as a probe. `ALLOWED` means the caller received a result, including an empty result. `DENIED` means the caller lacked permission. `NOT_SUPPORTED` means the API or SQL object is unavailable. `ERROR` means another failure occurred. Empty or denied results are not evidence that an object or feature does not exist for other users.

## Identity

- Uses the Databricks SDK current-user endpoint first to obtain the caller's SCIM identity, groups, and entitlements.
- If group values are absent, lists workspace-visible groups and checks membership values returned to the caller.
- Uses `current_user()` and `is_account_group_member()` when an already-running SQL warehouse or in-process Spark session is available.
- Nested, inherited, `users`, and `account users` membership may not be fully visible to non-admin callers.

## Entitlements

- Reads entitlements returned by the current-user endpoint, such as workspace access, Databricks SQL access, cluster creation, instance-pool creation, and consumer access.
- Adds evidence inferred from successful caller-scoped list probes. List access does not imply create or manage access.

## Unity Catalog

- Reads the current workspace's metastore assignment, then probes the admin-restricted metastore detail endpoint to distinguish demonstrated metastore-admin access from unknown or denied access.
- Queries caller-filtered `system.information_schema` inventory and privilege views.
- Queries `SHOW GRANTS <caller> ON CATALOG` for visible catalogs and samples schemas up to `--max-objects`.
- Derives ownership only from objects returned to the caller and principals discovered for the caller.
- Non-admin results can omit objects, grants, nested group effects, or metadata the caller cannot browse. `READ METADATA` and `MANAGE` are never assumed.

## Compute

- Lists caller-visible cluster policies, clusters, SQL warehouses, and instance pools.
- Reads definitions and Permissions API results only when allowed.
- A caller-scoped policy list can be filtered. Visibility does not prove permission to create, start, attach to, or manage compute.

## Workspace objects

- Lists the caller's home and `/Shared` to bounded depth, plus caller-visible Git folders, jobs, pipelines, queries, alerts, Lakeview dashboards, Genie spaces, Apps, experiments, registered models, serving endpoints, and vector-search endpoints.
- Attempts a read-only Permissions API GET for each returned object type. Some products do not expose a compatible Permissions API to the caller and are recorded as denied or unsupported.
- Summarizes serverless budget-policy and usage-policy IDs exposed on visible resources. It does not enumerate account-level policy definitions.

## Credentials

- Lists only the caller's token metadata: identifier, creation time, expiry time, and comment. Token values are never requested or written.
- Lists visible secret-scope names and attempts to list ACLs. Non-admin ACL reads are commonly denied. Secret values are never requested.
- Lists jobs and pipelines whose visible run-as identity matches the caller. Hidden jobs and pipelines remain unknowable.

## Features

- Repeats a small set of caller-scoped list probes for SQL warehouses, serving endpoints, Apps, and Genie spaces.
- Attempts bounded reads from `system.billing.usage` and `system.access.audit`, plus workspace configuration metadata.
- A successful list or query shows reachability, not full product entitlement or administrative control.
