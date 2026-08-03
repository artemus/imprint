"""Private cross-hook handoff for Claude sessions without transcript files."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from imprint.durable_io import replace_private
from imprint.errors import ValidationError
from imprint.permissions import assert_private_file, secure_directory


SCHEMA_VERSION = "1.0.0"
MAX_PROMPT_BYTES = 2 * 1024 * 1024
MAX_ASSISTANT_BYTES = 64 * 1024
MAX_CACHE_BYTES = MAX_PROMPT_BYTES + MAX_ASSISTANT_BYTES + 8192


@dataclass(frozen=True)
class PendingPrompt:
    prompt: str
    prior_assistant_output: str | None
    source_locator: str
    degradation: dict[str, object]


def _cache_path(root: Path, session_id: str) -> Path:
    safe_session = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return root / "runtime" / "pending-prompts" / f"{safe_session}.json"


def _assistant_path(root: Path, session_id: str) -> Path:
    safe_session = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return root / "runtime" / "last-assistant" / f"{safe_session}.json"


def _transcript_locator(path_value: str | None) -> str | None:
    if path_value is None:
        return None
    return hashlib.sha256(path_value.encode("utf-8")).hexdigest()


def transcript_source_unavailable(path_value: str) -> bool:
    """Return true only for the observed missing-file or directory modes.

    Links and other special files remain hard failures; the prompt cache must
    never turn an unsafe transcript path into an accepted transcript source.
    """
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        return False
    try:
        info = path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return stat.S_ISDIR(info.st_mode)


def save_pending_prompt(
    root: Path, session_id: str, prompt: str, transcript_path: str | None,
) -> Path | None:
    """Atomically retain the latest submitted prompt for one opaque session."""
    if not prompt.strip():
        return None
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_PROMPT_BYTES:
        raise ValidationError("user prompt is outside the pending-capture bound")
    target = _cache_path(root, session_id)
    secure_directory(target.parent)
    prompt_sha256 = hashlib.sha256(encoded).hexdigest()
    prior_assistant = load_last_assistant(root, session_id)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "transcript_locator_sha256": _transcript_locator(transcript_path),
        "prompt_sha256": prompt_sha256,
        "prompt": prompt,
        "prior_assistant_output": prior_assistant,
    }
    content = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if len(content) > MAX_CACHE_BYTES:
        raise ValidationError("pending prompt cache is outside the supported bound")
    return replace_private(target, content)


def load_pending_prompt(
    root: Path, session_id: str, transcript_path: str | None,
) -> PendingPrompt | None:
    """Read a session- and transcript-bound prompt without following links."""
    target = _cache_path(root, session_id)
    if not target.exists() and not target.is_symlink():
        return None
    try:
        assert_private_file(target)
        if target.stat(follow_symlinks=False).st_size > MAX_CACHE_BYTES:
            raise ValidationError("pending prompt cache is outside the supported bound")
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("pending prompt cache is unsafe or corrupt") from exc
    expected_keys = {
        "schema_version", "session_id", "transcript_locator_sha256",
        "prompt_sha256", "prompt", "prior_assistant_output",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValidationError("pending prompt cache schema is invalid")
    if value["schema_version"] != SCHEMA_VERSION or value["session_id"] != session_id:
        raise ValidationError("pending prompt cache binding is invalid")
    if value["transcript_locator_sha256"] != _transcript_locator(transcript_path):
        raise ValidationError("pending prompt does not match the Stop transcript locator")
    prompt = value["prompt"]
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValidationError("pending prompt cache contains no prompt")
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_PROMPT_BYTES:
        raise ValidationError("pending prompt cache is outside the supported bound")
    prompt_sha256 = hashlib.sha256(encoded).hexdigest()
    if value["prompt_sha256"] != prompt_sha256:
        raise ValidationError("pending prompt cache digest is invalid")
    locator = value["transcript_locator_sha256"]
    prior_assistant = value["prior_assistant_output"]
    if prior_assistant is not None and not isinstance(prior_assistant, str):
        raise ValidationError("pending prompt prior assistant is invalid")
    return PendingPrompt(
        prompt=prompt,
        prior_assistant_output=prior_assistant,
        source_locator=f"prompt-cache:sha256:{prompt_sha256}",
        degradation={
            "receipt": "missing_transcript_prompt_cache",
            "truncated": False,
            "prompt_sha256": prompt_sha256,
            "transcript_locator_sha256": locator,
        },
    )


def save_last_assistant(root: Path, session_id: str, message: str | None) -> Path | None:
    """Retain the latest completed assistant turn for the next operator prompt."""
    if not isinstance(message, str) or not message.strip():
        return None
    encoded = message.encode("utf-8")
    truncated = len(encoded) > MAX_ASSISTANT_BYTES
    if truncated:
        message = encoded[:MAX_ASSISTANT_BYTES].decode("utf-8", errors="ignore")
        encoded = message.encode("utf-8")
    target = _assistant_path(root, session_id)
    secure_directory(target.parent)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "assistant_sha256": hashlib.sha256(encoded).hexdigest(),
        "truncated": truncated,
        "assistant": message,
    }
    return replace_private(
        target,
        (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"),
    )


def load_last_assistant(root: Path, session_id: str) -> str | None:
    target = _assistant_path(root, session_id)
    if not target.exists() and not target.is_symlink():
        return None
    try:
        assert_private_file(target)
        if target.stat(follow_symlinks=False).st_size > MAX_ASSISTANT_BYTES + 4096:
            raise ValidationError("last assistant cache is outside the supported bound")
        value = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("last assistant cache is unsafe or corrupt") from exc
    expected = {"schema_version", "session_id", "assistant_sha256", "truncated", "assistant"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValidationError("last assistant cache schema is invalid")
    if value["schema_version"] != SCHEMA_VERSION or value["session_id"] != session_id:
        raise ValidationError("last assistant cache binding is invalid")
    assistant = value["assistant"]
    if not isinstance(assistant, str) or not isinstance(value["truncated"], bool):
        raise ValidationError("last assistant cache content is invalid")
    if hashlib.sha256(assistant.encode("utf-8")).hexdigest() != value["assistant_sha256"]:
        raise ValidationError("last assistant cache digest is invalid")
    return assistant


def discard_pending_prompt(root: Path, session_id: str) -> None:
    """Remove the exact private cache file after a successful Stop outcome."""
    target = _cache_path(root, session_id)
    if not target.exists() and not target.is_symlink():
        return
    try:
        assert_private_file(target)
        before = target.stat(follow_symlinks=False)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValidationError("pending prompt cache changed before removal")
            current = target.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValidationError("pending prompt cache changed before removal")
            target.unlink()
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ValidationError("pending prompt cache could not be removed safely") from exc
