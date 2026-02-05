import json
import re
from typing import Any, Dict, List, Literal, Optional

from drivers.base import OutclawGuardrail, logger
from drivers.deobfuscate import normalize_shell, strip_invisible, normalize_unicode


class ToolGuard(OutclawGuardrail):
    """
    The Bouncer for Tool Calls.
    Blocks dangerous commands in both request history and LLM-generated tool calls.
    """

    DEFAULT_BLOCKLIST = [
        # Destructive
        r'rm\s+-[rRf]+',
        r'mkfs',
        r'dd\b',
        r':\(\)\{\s*:\|:&\s*\};:',
        r'chmod\s+777',
        r'mv\s+.*\s+/dev/null',
        # Remote Access / Reverse Shells
        r'nc\b.*-e\b',
        r'bash\s+-i',
        r'sh\s+-i',
        r'\bsocat\b',
        r'\btelnet\b',
        r'\bssh\b',
        # Privilege escalation
        r'sudo\s+',
        r'su\s+-',
        r'chown\s+root',
        # System manipulation
        r'crontab\s+-[re]',
        r'systemctl\s+(start|enable)',
        # Pipe-to-shell (encoded command execution)
        r'\|\s*(sh|bash|/bin/(ba)?sh)\b',
        # Interpreter abuse with dangerous imports
        r'python[23]?\s+-c\b.*\b(subprocess|os\.system|os\.popen|os\.exec|socket\.socket|pty\.spawn)',
        r'perl\s+-e\b.*\b(system|exec|socket)',
        r'ruby\s+-e\b.*\b(system|exec|socket|IO\.popen)',
        r'node\s+-e\b.*\b(child_process|execSync|spawn)',
        # Eval-based execution
        r'\beval\b.*\b(base64|decode|echo\s+-e)',
        # Process substitution
        r'bash\s+<\(',
    ]

    def __init__(self, outclaw_config=None, **kwargs):
        super().__init__(
            outclaw_config=outclaw_config,
            guardrail_name="outclaw-tools",
            **kwargs,
        )
        custom_blocklist = self.outclaw_config.get(
            "tool_guard_blocklist", self.DEFAULT_BLOCKLIST
        )
        self.blocklist = [re.compile(p) for p in custom_blocklist]

    def _scan_arguments(self, arguments: str):
        """Scan argument string for dangerous patterns.

        Applies full deobfuscation pipeline: strip invisible chars,
        Unicode normalization, and shell normalization, then scans
        all variants for dangerous patterns.
        """
        cleaned = strip_invisible(arguments)
        unicode_norm = normalize_unicode(cleaned)
        shell_norm = normalize_shell(unicode_norm)
        for text in {arguments, cleaned, unicode_norm, shell_norm}:
            for pattern in self.blocklist:
                if pattern.search(text):
                    self._enforce(
                        f"Blocked Dangerous Command: Pattern '{pattern.pattern}' detected.",
                        driver_name="ToolGuard",
                    )

    def _scan_tool_calls(self, tool_calls):
        """Scan a list of tool_call dicts or objects for dangerous arguments."""
        if not tool_calls:
            return
        for tc in tool_calls:
            # Handle both dict (request) and object (response) formats
            if isinstance(tc, dict):
                args = tc.get("function", {}).get("arguments", "")
            else:
                args = getattr(getattr(tc, "function", None), "arguments", "") or ""
            self._scan_arguments(args)

    async def async_pre_call_hook(
        self, user_api_key_dict, cache, data: dict, call_type: str
    ):
        """Scan request messages for dangerous tool calls (from history)."""
        for msg in data.get("messages", []):
            if "tool_calls" in msg:
                self._scan_tool_calls(msg["tool_calls"])
            if "function_call" in msg:
                self._scan_arguments(
                    msg["function_call"].get("arguments", "")
                )
        return data

    async def async_post_call_success_hook(
        self, data, user_api_key_dict, response
    ):
        """Scan LLM-generated tool calls in the response."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if msg and getattr(msg, "tool_calls", None):
                self._scan_tool_calls(msg.tool_calls)
        return response
