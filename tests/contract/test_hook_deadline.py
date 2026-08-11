from __future__ import annotations

import io
import json
import os
import signal
import threading

import pytest

from hooks import _bridge
from imprint.config import config_path, load_config
from imprint.errors import ValidationError


class _Exited(Exception):
    """Stand-in for os._exit so a test process survives the watchdog."""


@pytest.fixture(autouse=True)
def _isolated_deadline_sources(monkeypatch, tmp_path):
    monkeypatch.delenv(_bridge.HOOK_TIMEOUT_ENV, raising=False)
    monkeypatch.setenv("IMPRINT_CONFIG", str(tmp_path / "absent" / "config.json"))


def _write_config(monkeypatch, tmp_path, value) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"hook_timeout_seconds": value}), encoding="utf-8")
    monkeypatch.setenv("IMPRINT_CONFIG", str(config))


def test_default_deadline_is_wider_on_windows_than_on_posix():
    assert _bridge.DEFAULT_HOOK_TIMEOUT_SECONDS == (60 if os.name == "nt" else 10)
    assert _bridge.hook_timeout_seconds() == _bridge.DEFAULT_HOOK_TIMEOUT_SECONDS


def test_supported_setting_raises_the_deadline_without_touching_package_files(monkeypatch, tmp_path):
    _write_config(monkeypatch, tmp_path, 90)
    assert _bridge.hook_timeout_seconds() == 90
    monkeypatch.setenv(_bridge.HOOK_TIMEOUT_ENV, "45")
    assert _bridge.hook_timeout_seconds() == 45


@pytest.mark.parametrize("value", ["0", "301", "-5", "", "ten", "12.5", "true"])
def test_unsafe_environment_values_fall_through_instead_of_disabling_hooks(monkeypatch, tmp_path, value):
    _write_config(monkeypatch, tmp_path, 75)
    monkeypatch.setenv(_bridge.HOOK_TIMEOUT_ENV, value)
    assert _bridge.hook_timeout_seconds() == 75


@pytest.mark.parametrize("value", [0, 301, -5, True, "30", None, 12.5])
def test_unsafe_config_values_fall_back_to_the_platform_default(monkeypatch, tmp_path, value):
    _write_config(monkeypatch, tmp_path, value)
    assert _bridge.hook_timeout_seconds() == _bridge.DEFAULT_HOOK_TIMEOUT_SECONDS


def test_unreadable_or_corrupt_config_never_leaves_the_hook_unbounded(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    config.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("IMPRINT_CONFIG", str(config))
    assert _bridge.hook_timeout_seconds() == _bridge.DEFAULT_HOOK_TIMEOUT_SECONDS
    monkeypatch.setenv("IMPRINT_CONFIG", str(tmp_path))
    assert _bridge.hook_timeout_seconds() == _bridge.DEFAULT_HOOK_TIMEOUT_SECONDS


@pytest.mark.parametrize("value", [0, 1, 30, 300, 301, -5, True, "30", None, 12.5, [30]])
def test_bridge_and_health_agree_on_which_configured_deadlines_are_valid(monkeypatch, tmp_path, value):
    _write_config(monkeypatch, tmp_path, value)
    config = tmp_path / "config.json"
    accepted_by_bridge = _bridge._bounded_timeout(value) is not None
    try:
        load_config(config)
        accepted_by_health = True
    except ValidationError:
        accepted_by_health = False
    assert accepted_by_bridge is accepted_by_health


def test_bridge_config_lookup_matches_the_package_resolver(monkeypatch, tmp_path):
    monkeypatch.setenv("IMPRINT_CONFIG", str(tmp_path / "explicit.json"))
    assert _bridge._config_file() == config_path()
    monkeypatch.delenv("IMPRINT_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    assert _bridge._config_file() == config_path()


def test_health_rejects_an_out_of_range_configured_deadline(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"hook_timeout_seconds": 0}', encoding="utf-8")
    with pytest.raises(ValidationError, match="hook_timeout_seconds must be 1..300"):
        load_config(config)
    config.write_text('{"hook_timeout_seconds": 90}', encoding="utf-8")
    assert load_config(config)["hook_timeout_seconds"] == 90


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="POSIX interval timer only")
def test_posix_deadline_arms_the_configured_interval(monkeypatch, tmp_path):
    _write_config(monkeypatch, tmp_path, 120)
    armed: list[float] = []
    monkeypatch.setattr(signal, "setitimer", lambda which, seconds: armed.append(seconds))
    with _bridge._deadline("session-start", False):
        pass
    assert armed[0] == 120


def _drive_watchdog(action: str, event: dict, monkeypatch, capfd):
    """Run the bridge off the main thread, which selects the Windows watchdog."""
    recorded: dict[str, int] = {}
    observed = threading.Event()
    released = threading.Event()

    def fake_exit(code: int):
        recorded["code"] = code
        observed.set()
        raise _Exited(code)

    monkeypatch.setattr(_bridge.os, "_exit", fake_exit)
    monkeypatch.setattr(
        _bridge, "_invoke_cli",
        lambda *_args, **_kwargs: (released.wait(30), _bridge._Invocation(0, "", ""))[1],
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(event)))
    prior_excepthook = threading.excepthook
    threading.excepthook = lambda _args: None
    worker = threading.Thread(target=_bridge.run, args=(action,), daemon=True)
    try:
        worker.start()
        assert observed.wait(30), "the watchdog never fired"
    finally:
        released.set()
        worker.join(30)
        threading.excepthook = prior_excepthook
    return recorded["code"], capfd.readouterr()


def test_windows_watchdog_reports_the_configured_deadline_on_session_start(monkeypatch, tmp_path, capfd):
    _write_config(monkeypatch, tmp_path, 1)
    code, captured = _drive_watchdog("session-start", {}, monkeypatch, capfd)
    body = json.loads(captured.out.strip().splitlines()[-1])
    assert code == 0
    assert body["error"] == "hook_action_timeout"
    assert body["hook_action"] == "session-start"
    assert body["timeout_seconds"] == 1
    assert body["failure_policy"] == "fail_open"
    assert body["hookSpecificOutput"]["hookEventName"] == "SessionStart"


def test_windows_watchdog_still_fails_closed_once_for_pre_persist_stop(monkeypatch, tmp_path, capfd):
    _write_config(monkeypatch, tmp_path, 1)
    code, captured = _drive_watchdog(
        "stop-capture", {"stop_hook_active": False}, monkeypatch, capfd,
    )
    body = json.loads(captured.out.strip().splitlines()[-1])
    assert code == 2
    assert body["failure_policy"] == "fail_closed"
    assert body["timeout_seconds"] == 1
    assert "hook_action_timeout" in captured.err


def test_windows_watchdog_does_not_loop_a_repeated_stop(monkeypatch, tmp_path, capfd):
    _write_config(monkeypatch, tmp_path, 1)
    code, _captured = _drive_watchdog(
        "stop-capture", {"stop_hook_active": True}, monkeypatch, capfd,
    )
    assert code == 0


def test_installers_preserve_a_configured_deadline_across_reinstall():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    posix = open(os.path.join(root, "install", "install.sh"), encoding="utf-8").read()
    windows = open(os.path.join(root, "install", "install.ps1"), encoding="utf-8").read()
    # Both installers merge into the existing config object and only set their
    # own required keys, so a configured deadline survives an upgrade.
    assert "value.update({" in posix and "hook_timeout_seconds" not in posix
    assert "$ConfigValue[$Property.Name] = $Property.Value" in windows
    assert "hook_timeout_seconds" not in windows
