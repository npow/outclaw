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


def test_pii_guard_audit_mode_does_not_mutate_request():
    """Audit mode should detect but not redact request content."""
    from drivers.pii_guard import PIIGuard
    guard = PIIGuard(outclaw_config={"mode": "audit"})
    original = "Contact me at bob@example.com"
    data = {"messages": [{"role": "user", "content": original}]}
    result = asyncio.run(guard.async_pre_call_hook({}, {}, data, "completion"))
    assert result["messages"][0]["content"] == original


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


def test_tool_guard_balanced_profile_allows_common_shell_wrapper():
    """Balanced profile should avoid blocking non-dangerous bash wrappers."""
    from drivers.tool_guard import ToolGuard
    guard = ToolGuard(outclaw_config={"mode": "strict", "tool_guard_profile": "balanced"})
    guard._scan_arguments('{"command": "bash -lc \\"echo hi\\""}')


def test_tool_guard_strict_profile_blocks_shell_wrapper():
    """Strict profile keeps broad AST command blocking for shell wrappers."""
    from drivers.tool_guard import ToolGuard
    guard = ToolGuard(outclaw_config={"mode": "strict", "tool_guard_profile": "strict"})
    with pytest.raises(HTTPException):
        guard._scan_arguments('{"command": "bash -lc \\"echo hi\\""}')


def test_tool_guard_paranoid_profile_blocks_context_commands():
    """Paranoid profile should block wrapper/context commands like find."""
    from drivers.tool_guard import ToolGuard
    guard = ToolGuard(outclaw_config={"mode": "strict", "tool_guard_profile": "paranoid"})
    with pytest.raises(HTTPException):
        guard._scan_arguments('{"command": "find . -name pyproject.toml"}')
