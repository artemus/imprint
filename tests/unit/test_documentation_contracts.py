from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from imprint.health.report import HEALTH_SCHEMA_VERSION, HealthInputs, evaluate_health

ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_readme_states_that_log_dates_are_utc_beside_the_example():
    readme = _read("README.md")
    example_line = next(
        line for line in readme.splitlines() if line.startswith("imprint log --date 2026-")
    )
    assert "UTC" in example_line
    # A reader outside UTC needs a runnable way to ask for today.
    assert 'imprint log --date "$(date -u +%F)"' in readme
    assert "[DateTime]::UtcNow.ToString('yyyy-MM-dd')" in readme


def test_cli_default_log_date_is_today_in_utc():
    # The README tells readers to omit --date; that only helps if the default is
    # the UTC day rather than the local one.
    source = _read("src/imprint/cli.py")
    assert "args.date or datetime.now(timezone.utc).date().isoformat()" in source
    assert '--date", help="UTC date in YYYY-MM-DD form (default: today)' in source
    assert datetime.now(timezone.utc).date().isoformat() == datetime.now(timezone.utc).strftime("%Y-%m-%d")


def test_docs_explain_every_compiler_lock_state_and_deny_a_background_service():
    readme = _read("README.md")
    troubleshooting = _read("docs/troubleshooting.md")
    for state, label in (("absent", "idle"), ("held", "compiling"), ("invalid", "invalid")):
        assert state in readme and label in readme
        assert evaluate_health(
            HealthInputs(compiler_count=1, database_state="present",
                         migration_state="not_checked", compiler_state=state),
        ).metrics["compiler_state_label"] == label
    assert "no resident compiler service" in " ".join(readme.lower().split())
    assert "compiler_state: absent" in troubleshooting


def test_docs_explain_the_pending_versus_retained_spool_distinction():
    troubleshooting = _read("docs/troubleshooting.md")
    for metric in (
        "pending_spool_depth",
        "oldest_pending_spool_age_seconds",
        "acknowledged_retained_spool_depth",
    ):
        assert metric in troubleshooting
        assert metric in evaluate_health(HealthInputs(
            compiler_count=1, database_state="present", migration_state="not_checked",
        )).metrics


def test_configuration_documents_the_hook_deadline_and_its_override():
    configuration = _read("docs/configuration.md")
    assert "`hook_timeout_seconds`: 1–300" in configuration
    assert "IMPRINT_HOOK_TIMEOUT_SECONDS" in configuration
    assert "60 on Windows" in configuration


def test_health_schema_version_advertises_the_added_metrics():
    assert HEALTH_SCHEMA_VERSION == "1.2.0"
