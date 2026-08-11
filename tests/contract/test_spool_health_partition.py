from __future__ import annotations

import json
import os
from pathlib import Path

from imprint.compiler import compile_spools, write_envelope
from imprint.health import health_report
from imprint.store import ImprintStore

# Retention refuses to prune below one day, while the stale threshold is one
# hour, so every acknowledged copy spends most of its policy-mandated life in
# the window this test covers.
OLDER_THAN_STALE_THRESHOLD = 3.7 * 3600


def _config(root: Path) -> dict[str, object]:
    hooks = root.parent / "installed-hooks"
    hooks.mkdir(exist_ok=True)
    for name in ("session_start.py", "user_prompt_submit.py", "stop_capture.py", "health_check.py"):
        (hooks / name).write_text("# synthetic hook\n", encoding="utf-8")
    return {"compiler": True, "context_budget_bytes": 32 * 1024, "hooks_dir": str(hooks)}


def _age(path: Path, seconds: float) -> None:
    stamp = path.stat().st_mtime - seconds
    os.utime(path, (stamp, stamp))


def _committed_operator(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    spool = write_envelope(root, capture_envelope)
    store = ImprintStore(root / "imprint.db")
    assert compile_spools(root, store, compiler_authorized=True)["captured"] == 1
    return root, store, spool


def test_acknowledged_retained_spool_is_visible_without_degrading_health(
    tmp_path, capture_envelope,
):
    root, store, spool = _committed_operator(tmp_path, capture_envelope)
    _age(spool, OLDER_THAN_STALE_THRESHOLD)

    report = health_report(root, store, _config(root), deep=True)
    metrics = report["metrics"]

    assert "spool_stale" not in report["degraded_reasons"]
    assert report["status"] == "healthy"
    # The retained copy stays countable; it is simply not pending work.
    assert metrics["spool_depth"] == 1
    assert metrics["acknowledged_retained_spool_depth"] == 1
    assert metrics["pending_spool_depth"] == 0
    assert metrics["oldest_spool_age_seconds"] >= OLDER_THAN_STALE_THRESHOLD - 10
    assert metrics["oldest_pending_spool_age_seconds"] == 0
    assert metrics["spool_evidence"] == "exact_acknowledgement_hash_match"


def test_old_unacknowledged_spool_still_degrades_health(tmp_path, capture_envelope):
    root, store, spool = _committed_operator(tmp_path, capture_envelope)
    _age(spool, OLDER_THAN_STALE_THRESHOLD)
    pending = root / "spool" / capture_envelope["node_id"] / "never-compiled.json"
    pending.write_text("{}\n", encoding="utf-8")
    _age(pending, OLDER_THAN_STALE_THRESHOLD)

    report = health_report(root, store, _config(root), deep=True)
    metrics = report["metrics"]

    assert "spool_stale" in report["degraded_reasons"]
    assert metrics["pending_spool_depth"] == 1
    assert metrics["acknowledged_retained_spool_depth"] == 1
    assert metrics["oldest_pending_spool_age_seconds"] >= OLDER_THAN_STALE_THRESHOLD - 10


def test_acknowledgement_that_does_not_match_its_source_counts_as_pending(
    tmp_path, capture_envelope,
):
    root, store, spool = _committed_operator(tmp_path, capture_envelope)
    _age(spool, OLDER_THAN_STALE_THRESHOLD)
    ack = next((root / "runtime" / "acknowledgements" / capture_envelope["node_id"]).glob("*.json"))
    value = json.loads(ack.read_text())
    value["source_file_sha256"] = "0" * 64
    ack.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")

    report = health_report(root, store, _config(root), deep=True)

    # A present-but-wrong acknowledgement must never suppress the warning.
    assert "spool_stale" in report["degraded_reasons"]
    assert report["metrics"]["pending_spool_depth"] == 1
    assert report["metrics"]["acknowledged_retained_spool_depth"] == 0


def test_recent_pending_spool_is_not_stale_yet(tmp_path, capture_envelope):
    root = tmp_path / "operator"
    spool = write_envelope(root, capture_envelope)
    store = ImprintStore(root / "imprint.db")
    store.initialize()

    report = health_report(root, store, _config(root), deep=True)

    assert "spool_stale" not in report["degraded_reasons"]
    assert report["metrics"]["pending_spool_depth"] == 1
    assert spool.exists()


def test_shallow_health_does_not_claim_a_spool_partition(tmp_path, capture_envelope):
    root, store, _spool = _committed_operator(tmp_path, capture_envelope)

    metrics = health_report(root, store, _config(root), deep=False)["metrics"]

    assert metrics["pending_spool_depth"] == -1
    assert metrics["acknowledged_retained_spool_depth"] == -1
    assert metrics["spool_evidence"] == "spool_file_presence_only"
