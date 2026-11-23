# What Can I Do in Databricks?

This agent skill creates a read-only report of the data, compute, workspace objects, permissions, credentials metadata, and Databricks features visible to the current non-admin user. No administrator role is required. Review the report before sharing it with your Databricks account team or outside your organization.

## Requirements

- Genie Code must be enabled in the Databricks workspace.
- The user must have access to Databricks Git folders.
- Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/) and verify it:

```bash
uv --version
```

- When using serverless notebook compute, select environment version 5 or later so `uv` is available.
- No workspace-admin, account-admin, or metastore-admin role is required.

Do not install this skill's Python dependency with `pip` or `%pip`. The collector uses PEP 723 metadata and a committed uv lockfile.

## Workspace Genie Code

Recommended installation follows [Add skills from another folder](https://learn.microsoft.com/en-us/azure/databricks/genie-code/skills#add-skills-from-another-folder):

1. Add this repository as a Databricks Git folder.
2. Open **Genie Code → Customizations → Skills**.
3. Select **New → Add from workspace folder**.
4. Select the repository root, which contains the `what-can-i-do-in-databricks/` skill folder.

Users can register multiple skill folders. Adding this repository does not replace existing folders. As a fallback, run the repository's `install.py` notebook to copy the skill to `/Users/<email>/.assistant/skills/what-can-i-do-in-databricks/`.

The backup installation is the repository's `install.py` notebook. Run it as the intended user on serverless notebook compute with environment version 5 or later. It copies the skill to `/Users/<email>/.assistant/skills/what-can-i-do-in-databricks/`. Run it again after pulling updates to refresh the personal copy.

If a Git-folder-installed skill reports that its collector is missing, pull the latest `main`, verify `scripts/collect_my_access.py` and `scripts/reporting.py` in the workspace browser, and start a new Genie Code chat. The skill is instructed to run the source from the registered Git folder if its packaged resource mount omits the script.

If `uv` cannot resolve dependencies or a shell subprocess cannot inherit notebook authentication, the skill uses the runtime's preinstalled SDK and runs the collector in the notebook Python process. The collector then discovers the notebook's active Spark session for Unity Catalog and other SQL probes.

## Genie Code CLI

Copy or link the skill folder into either supported location:

```text
~/.genie/skills/what-can-i-do-in-databricks/
.agents/skills/what-can-i-do-in-databricks/
```

The collector uses Databricks default authentication for the current user. Configure your normal Databricks CLI authentication before running it; do not provide credentials as arguments.

## Run

From the skill directory:

```bash
uv run --script scripts/collect_my_access.py
```

Common options:

```bash
uv run --script scripts/collect_my_access.py \
  --output ./reports \
  --sections identity,entitlements,uc \
  --max-objects 500 \
  --max-depth 3 \
  --redact
```

Redaction is enabled by default. Use `--redact-objects` to hash object names as well. The collector writes a timestamped report directory and ZIP archive, including `SUMMARY.md`, per-section CSV and JSON files, `my_effective_access.csv`, and `probe_log.csv`.
