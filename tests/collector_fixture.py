import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "what-can-i-do-in-databricks" / "scripts"),
)

from collect_my_access import ALL_SECTIONS, EMAIL, AccessCollector, as_data, hash_value


def make_collector(groups=()):
    """Build an offline collector without initializing SDK authentication."""
    collector = AccessCollector.__new__(AccessCollector)
    collector.client = Mock()
    collector.current_username = "alice@example.com"
    collector.current_user = {}
    collector.groups = set(groups)
    collector.sections = {section: [] for section in ALL_SECTIONS}
    collector.section_notes = {section: [] for section in ALL_SECTIONS}
    collector.effective_access = []
    collector.args = SimpleNamespace(
        max_objects=500, max_depth=3, sections=ALL_SECTIONS,
        redact=False, redact_objects=False, output=None,
    )
    collector.probes = []
    collector.group_method = "test fixture"
    collector.started_at = datetime.now(timezone.utc)
    collector.now_utc = lambda: collector.started_at
    collector.workspace_id = "test-workspace"
    collector.runtime = "test fixture"
    collector.sdk_version = "test fixture"
    collector.as_data = as_data
    collector.hash_value = hash_value
    collector.email_pattern = EMAIL
    collector.report_dir = None
    collector.spark = None
    collector.warehouses = None
    collector.sql_warehouse_id = None
    return collector
