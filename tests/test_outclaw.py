import asyncio
import pytest
from fastapi import HTTPException


def _default_config():
    return {"mode": "strict"}


def test_tool_guard_blocks_rm_rf():
    """Ensure `rm -rf` is blocked."""
    from drivers.tool_guard import ToolGuard
    guard = ToolGuard(outclaw_config=_default_config())
    with pytest.raises(HTTPException) as exc_info:
        guard._scan_arguments('{"command": "rm -rf /"}')
    assert exc_info.value.status_code == 400
    assert "Outclawed" in str(exc_info.value.detail)
    assert "ToolGuard" in str(exc_info.value.detail)


def test_secret_guard_blocks_openai_key():
    """Ensure leaked OpenAI keys are blocked."""
    from drivers.secret_guard import SecretGuard
    guard = SecretGuard(outclaw_config=_default_config())
    fake_key = "sk-" + "a" * 48
    with pytest.raises(HTTPException):
        guard._scan_text(f"Here is my key: {fake_key}")


def test_pii_guard_redacts_email():
    """Ensure emails are redacted before going upstream."""
    from drivers.pii_guard import PIIGuard
    guard = PIIGuard(outclaw_config=_default_config())
    data = {"messages": [{"role": "user", "content": "Contact me at bob@example.com"}]}
    result = asyncio.run(guard.async_pre_call_hook({}, {}, data, "completion"))
    content = result["messages"][0]["content"]
    assert "bob@example.com" not in content


def test_normal_content_passes():
    """Ensure normal traffic is not flagged by any guard."""
    from drivers.tool_guard import ToolGuard
    from drivers.secret_guard import SecretGuard
    guard = ToolGuard(outclaw_config=_default_config())
    # Should not raise
    guard._scan_arguments('{"command": "ls -la"}')

    sg = SecretGuard(outclaw_config=_default_config())
    # Should not raise
    sg._scan_text("Hello, world!")
