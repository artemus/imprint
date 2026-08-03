from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).parents[2]


def _config(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "data"
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "config_version": "3.0.0", "data_root": str(data),
        "operator_slug": "test", "node_id": "primary", "compiler": False,
        "context_budget_bytes": 32768,
    }))
    return config, data / "test"


def _hook(config: Path, action: str, event: dict) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, IMPRINT_CONFIG=str(config))
    return subprocess.run(
        [sys.executable, "-m", "imprint.cli", "hook", action],
        input=json.dumps(event), text=True, capture_output=True,
        cwd=ROOT, env=env, check=False,
    )


def test_missing_transcript_uses_prompt_cache_and_preserves_previous_assistant(tmp_path):
    config, operator_root = _config(tmp_path)
    missing = tmp_path / "streamed-session.jsonl"
    session = "streamed-runtime-session"

    first_submit = _hook(config, "user-prompt-submit", {
        "hook_event_name": "UserPromptSubmit", "session_id": session,
        "transcript_path": str(missing), "prompt": "Please summarize this.",
    })
    assert first_submit.returncode == 0, first_submit.stdout + first_submit.stderr
    first_stop = _hook(config, "stop-capture", {
        "hook_event_name": "Stop", "session_id": session,
        "transcript_path": str(missing),
        "last_assistant_message": "The source says the launch is complete.",
    })
    assert first_stop.returncode == 0, first_stop.stdout + first_stop.stderr
    assert json.loads(first_stop.stdout)["reason"] == "not_explicit_feedback"

    correction = "No, the source says the launch failed, and that changes the decision."
    second_submit = _hook(config, "user-prompt-submit", {
        "hook_event_name": "UserPromptSubmit", "session_id": session,
        "transcript_path": str(missing), "prompt": correction,
    })
    assert second_submit.returncode == 0, second_submit.stdout + second_submit.stderr
    second_stop = _hook(config, "stop-capture", {
        "hook_event_name": "Stop", "session_id": session,
        "transcript_path": str(missing),
        "last_assistant_message": "Corrected.",
    })
    assert second_stop.returncode == 0, second_stop.stdout + second_stop.stderr
    receipt = json.loads(second_stop.stdout)
    assert receipt["status"] == "queued"
    assert receipt["canonical_status"] == "spool_only"
    assert receipt["degradation"]["receipt"] == "missing_transcript_prompt_cache"
    spool = json.loads(next((operator_root / "spool" / "primary").glob("*.json")).read_text())
    assert spool["verdict"]["raw_operator_text"] == correction
    assert any(
        item["content"] == "The source says the launch is complete."
        for item in spool["evidence"]
    )
    assert not list((operator_root / "runtime" / "pending-prompts").glob("*.json"))
    assert len(list((operator_root / "runtime" / "last-assistant").glob("*.json"))) == 1


def test_directory_transcript_uses_exact_bound_prompt_cache(tmp_path):
    config, operator_root = _config(tmp_path)
    transcript_directory = tmp_path / "directory-session"
    transcript_directory.mkdir()
    event = {
        "session_id": "directory-runtime-session",
        "transcript_path": str(transcript_directory),
    }
    submitted = _hook(config, "user-prompt-submit", {
        **event, "hook_event_name": "UserPromptSubmit",
        "prompt": "No, preserve the exact failure because it changes the conclusion.",
    })
    assert submitted.returncode == 0
    stopped = _hook(config, "stop-capture", {
        **event, "hook_event_name": "Stop", "last_assistant_message": "Understood.",
    })
    assert stopped.returncode == 0, stopped.stdout + stopped.stderr
    assert json.loads(stopped.stdout)["status"] == "queued"
    assert len(list((operator_root / "spool" / "primary").glob("*.json"))) == 1


def test_unsafe_transcript_never_falls_back_to_prompt_cache(tmp_path):
    config, operator_root = _config(tmp_path)
    real = tmp_path / "real.jsonl"
    real.write_text('{"type":"user"}\n')
    linked = tmp_path / "linked.jsonl"
    linked.symlink_to(real)
    event = {"session_id": "linked-session", "transcript_path": str(linked)}
    submitted = _hook(config, "user-prompt-submit", {
        **event, "hook_event_name": "UserPromptSubmit",
        "prompt": "No, this must remain pending because the transcript path is unsafe.",
    })
    assert submitted.returncode == 0
    stopped = _hook(config, "stop-capture", {**event, "hook_event_name": "Stop"})
    assert stopped.returncode == 2
    assert "absolute regular non-symlink file" in stopped.stdout
    assert list((operator_root / "runtime" / "pending-prompts").glob("*.json"))
    assert not list((operator_root / "spool").glob("*/*.json"))
