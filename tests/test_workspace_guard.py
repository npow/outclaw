import asyncio
import json
from types import SimpleNamespace
from drivers.workspace_guard import WorkspaceGuard


def _mock_response(choices_data):
    """Build a mock response object with attribute access from a dict."""
    choices = []
    for c in choices_data:
        msg_dict = c.get("message", {})
        tool_calls = []
        for tc_dict in msg_dict.get("tool_calls", []):
            func = tc_dict.get("function", {})
            tc = SimpleNamespace(
                id=tc_dict.get("id", "call_1"),
                type=tc_dict.get("type", "function"),
                function=SimpleNamespace(
                    name=func.get("name", ""),
                    arguments=func.get("arguments", ""),
                ),
            )
            tool_calls.append(tc)
        msg = SimpleNamespace(
            role=msg_dict.get("role", "assistant"),
            content=msg_dict.get("content"),
            tool_calls=tool_calls if tool_calls else None,
        )
        choices.append(SimpleNamespace(message=msg))
    return SimpleNamespace(choices=choices)


def test_scope_enforcement_on_response():
    """
    Scenario: LLM generates a tool call to write to '../hack.txt'.
    Outclaw should catch this in post_call and STRIP it.
    """
    guard = WorkspaceGuard(outclaw_config={"mode": "strict"})

    response = _mock_response([{
        "message": {
            "role": "assistant",
            "content": "Sure, I'll write that file.",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "write_file",
                    "arguments": json.dumps({"path": "../hack.txt", "content": "owned"})
                }
            }]
        }
    }])

    result = asyncio.run(guard.async_post_call_success_hook({}, {}, response))
    message = result.choices[0].message

    # 1. Tool Call should be GONE (stripped by guard)
    assert message.tool_calls is None or len(message.tool_calls) == 0

    # 2. Content should contain the Block Message
    assert "Blocked Action" in message.content
    assert "directory traversal" in message.content


def test_safe_write_allowed():
    """
    Scenario: LLM writes to './safe.txt'.
    Outclaw should allow it.
    """
    guard = WorkspaceGuard(outclaw_config={"mode": "strict"})

    response = _mock_response([{
        "message": {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "function": {
                    "name": "write_file",
                    "arguments": json.dumps({"path": "safe.txt", "content": "ok"})
                }
            }]
        }
    }])

    result = asyncio.run(guard.async_post_call_success_hook({}, {}, response))

    # Should be untouched
    assert len(result.choices[0].message.tool_calls) == 1
    assert "Blocked" not in (result.choices[0].message.content or "")


def test_audit_mode_does_not_strip_tool_calls():
    """
    In audit mode, WorkspaceGuard should log but not mutate tool calls/content.
    """
    guard = WorkspaceGuard(outclaw_config={"mode": "audit"})

    response = _mock_response([{
        "message": {
            "role": "assistant",
            "content": "I'll write this.",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "write_file",
                    "arguments": json.dumps({"path": "../hack.txt", "content": "owned"})
                }
            }]
        }
    }])

    result = asyncio.run(guard.async_post_call_success_hook({}, {}, response))
    message = result.choices[0].message
    assert message.tool_calls is not None
    assert len(message.tool_calls) == 1
    assert message.content == "I'll write this."
