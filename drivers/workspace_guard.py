import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

from drivers.base import OutclawGuardrail, logger


class WorkspaceGuard(OutclawGuardrail):
    """
    The Scope Enforcer.
    Strips dangerous tool calls from LLM responses that target paths outside
    the allowed workspace.
    """

    def __init__(self, outclaw_config=None, **kwargs):
        super().__init__(
            outclaw_config=outclaw_config,
            guardrail_name="outclaw-workspace",
            **kwargs,
        )
        ws_config = self.outclaw_config.get("workspace_guard", {})
        self.workspace_root = Path(ws_config.get("workspace_root", ".")).resolve()
        self.enforce_strict_subpath = ws_config.get("enforce_strict_subpath", False)

        if self.enforce_strict_subpath:
            logger.info(
                f"WorkspaceGuard: Strict scoping ENABLED at {self.workspace_root}"
            )

        self.mutation_tools = {
            "write_file", "delete_file", "move_file", "append_file",
            "create_directory", "remove_directory",
            "create_symlink", "soft_link", "hard_link",
            "str_replace_editor", "edit_file", "patch_file",
            "bash", "sh", "shell", "execute_command", "run_command", "process_run",
            "computer", "type", "key", "mouse_move", "left_click",
        }

    def _check_scope(self, tool_name: str, arguments: str) -> tuple[bool, Optional[str]]:
        """Returns (is_safe, error_message)."""
        if tool_name not in self.mutation_tools:
            return True, None

        try:
            args = json.loads(arguments)
        except json.JSONDecodeError:
            return False, "Invalid JSON in arguments"

        path_arg = (
            args.get("path") or args.get("file") or args.get("filename")
            or args.get("target") or args.get("source") or args.get("dest")
        )
        cmd_arg = args.get("command") or args.get("script") or args.get("code")

        if path_arg:
            if ".." in path_arg:
                return False, f"Potential directory traversal detected in path: {path_arg}"
            try:
                target_path = Path(path_arg).resolve()
            except Exception:
                return False, f"Invalid path: {path_arg}"

            if self.enforce_strict_subpath:
                try:
                    if not target_path.is_relative_to(self.workspace_root):
                        return False, f"Path '{path_arg}' is OUTSIDE allowed workspace ({self.workspace_root})."
                except AttributeError:
                    if not str(target_path).startswith(str(self.workspace_root)):
                        return False, f"Path '{path_arg}' is OUTSIDE allowed workspace ({self.workspace_root})."
            else:
                dangerous_roots = [
                    "/etc", "/var", "/root", "/proc", "/sys", "/dev", "/boot",
                    "/usr/bin", "/usr/lib", "/usr/share", "/usr/local/lib", "/usr/sbin",
                    "/bin", "/sbin", "/lib", "/lib64",
                ]
                if any(str(target_path).startswith(dr) for dr in dangerous_roots):
                    if str(target_path) != "/dev/null":
                        return False, f"Access to system path '{path_arg}' is BLOCKED."

        if cmd_arg:
            if "../" in cmd_arg or "..\\" in cmd_arg:
                return False, f"Potential directory traversal detected in command: {cmd_arg}"

            abs_paths = re.findall(r'(/[a-zA-Z0-9._/-]+)', cmd_arg)
            for path in abs_paths:
                if not self.enforce_strict_subpath:
                    dangerous_roots = [
                        "/etc", "/var", "/root", "/proc", "/sys", "/dev",
                        "/usr/bin", "/usr/lib", "/usr/sbin", "/bin", "/sbin",
                    ]
                    if any(path.startswith(dr) for dr in dangerous_roots):
                        if path != "/dev/null":
                            return False, f"Absolute path '{path}' in command is BLOCKED."
                    continue

                try:
                    p = Path(path).resolve()
                    if not p.is_relative_to(self.workspace_root):
                        if not any(path.startswith(safe) for safe in ["/bin", "/usr/bin", "/usr/local/bin", "/dev/null"]):
                            return False, f"Absolute path '{path}' in command is OUTSIDE allowed workspace."
                except Exception:
                    continue

        return True, None

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        """Scan LLM response tool calls and strip any that violate workspace scope."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if not msg or not getattr(msg, "tool_calls", None):
                continue

            safe_calls = []
            blocked_msgs = []

            for tc in msg.tool_calls:
                name = getattr(tc.function, "name", "") if tc.function else ""
                args = getattr(tc.function, "arguments", "") if tc.function else ""

                is_safe, error_msg = self._check_scope(name, args)
                if is_safe:
                    safe_calls.append(tc)
                else:
                    blocked_msgs.append(f"[Outclaw] Blocked Action: {error_msg}")
                    logger.warning(f"🛡️ [SOFT BLOCK] WorkspaceGuard: {error_msg}")

            if blocked_msgs:
                msg.tool_calls = safe_calls or None
                current_content = msg.content or ""
                msg.content = (current_content + "\n" + "\n".join(blocked_msgs)).strip()

        return response
