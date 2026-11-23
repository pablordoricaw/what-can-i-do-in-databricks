# What Can I Do in Databricks?

A shareable Genie Code skill for non-admin Databricks users to inventory their own effective access.

## Requirements

- Genie Code must be enabled in the Databricks workspace.
- The user must have access to Databricks Git folders.
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/) is required to manage and run the collector's Python dependencies. Do not use `pip` or `%pip`.
- When running from a serverless notebook, select environment version 5 or later so `uv` is available.
- The user must authenticate as themselves. No workspace-admin, account-admin, or metastore-admin role is required.

## Recommended installation: Git folder

Registering the repository as a skill folder keeps the skill connected to version control and makes updates available after pulling the latest changes. See [Add skills from another folder](https://learn.microsoft.com/en-us/azure/databricks/genie-code/skills#add-skills-from-another-folder) in the Databricks documentation.

1. Add this repository to the workspace as a Databricks Git folder.
2. Open **Genie Code → Customizations → Skills**.
3. Select **New → Add from workspace folder**.
4. Select the repository root—the folder containing `what-can-i-do-in-databricks/`.
5. Start a new Genie Code chat and mention `@what-can-i-do-in-databricks` to invoke the skill explicitly.

Users can register multiple skill folders. Adding this repository does not replace or disable existing registered folders or the default `.assistant/skills/` locations.

## Backup installation: notebook

If Git-folder registration is unavailable, use the repository's `install.py` Databricks notebook:

1. Open `install.py` from the Databricks Git folder.
2. Attach the notebook to serverless notebook compute using environment version 5 or later.
3. Run the notebook as the user who will use the skill.
4. Confirm that it reports this personal skill location:

   ```text
   /Users/<email>/.assistant/skills/what-can-i-do-in-databricks/
   ```

5. Start a new Genie Code chat. If the skill still appears stale, hard-refresh the browser tab.

The notebook copies the skill rather than moving it. Run it again after pulling repository updates to refresh the installed copy.

## Troubleshooting Git-folder skills

If Genie Code reports that `scripts/collect_my_access.py` is missing even though the Git folder contains it:

1. Pull the latest `main` branch in the Databricks Git folder.
2. Confirm that `what-can-i-do-in-databricks/scripts/collect_my_access.py` and `reporting.py` are visible in the workspace browser.
3. Start a new Genie Code chat and hard-refresh the browser tab if cached skill metadata remains stale.

The skill can fall back to the collector in the registered Git folder when Genie Code's packaged skill-resource mount omits it. It must use that source file rather than recreating the collector.

## Run the collector

From the skill directory, verify `uv` and run:

```bash
uv --version
uv run --script scripts/collect_my_access.py
```

The collector is read-only and uses the current user's Databricks identity. Review the generated `SUMMARY.md` and ZIP archive before sharing them outside your organization.

See [`what-can-i-do-in-databricks/README.md`](what-can-i-do-in-databricks/README.md) for CLI installation and additional options.
