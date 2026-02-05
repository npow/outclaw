import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import unquote

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

    _PATH_KEYS = ["path", "file", "filename", "target", "source", "dest"]

    _DANGEROUS_ROOTS = [
        "/etc", "/var", "/root", "/proc", "/sys", "/boot",
        "/usr/bin", "/usr/lib", "/usr/share", "/usr/local/lib", "/usr/sbin",
        "/bin", "/sbin", "/lib", "/lib64",
        # macOS symlinks (/etc → /private/etc, /var → /private/var, etc.)
        "/private/etc", "/private/var",
    ]

    # Dangerous /dev paths (allow /dev/null, /dev/stdin, /dev/stdout, /dev/stderr, /dev/tty)
    _DANGEROUS_DEV_PATHS = {
        "/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd",  # Block devices
        "/dev/hda", "/dev/hdb", "/dev/nvme",
        "/dev/mem", "/dev/kmem", "/dev/port",  # Memory access
        "/dev/sd", "/dev/hd",  # Prefixes (will use startswith)
    }
    _SAFE_DEV_PATHS = {"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "/dev/random", "/dev/urandom"}

    # Sensitive home directory paths (relative to ~)
    _SENSITIVE_DOTFILES = {
        ".ssh", ".gnupg", ".gpg", ".aws", ".azure", ".config/gcloud",
        ".kube", ".docker", ".npmrc", ".pypirc", ".netrc", ".git-credentials",
        ".bash_history", ".zsh_history", ".python_history",
        ".bashrc", ".zshrc", ".profile", ".bash_profile",
    }

    def _check_path_arg(self, path_val: str) -> tuple[bool, Optional[str]]:
        """Validate a single path argument. Returns (is_safe, error_message)."""
        # Null byte injection
        if "\x00" in path_val:
            return False, f"Null byte detected in path: {path_val!r}"

        # URL-decode before checking for traversal
        path_decoded = unquote(path_val)

        # Expand tilde to home directory
        if path_decoded.startswith("~"):
            path_decoded = os.path.expanduser(path_decoded)

        if ".." in path_decoded:
            return False, f"Potential directory traversal detected in path: {path_val}"

        try:
            target_path = Path(path_decoded).resolve()
        except Exception:
            return False, f"Invalid path: {path_val}"

        target_str = str(target_path)

        # Check for dangerous /dev paths
        if target_str.startswith("/dev/"):
            if target_str in self._SAFE_DEV_PATHS:
                return True, None  # Allow safe device files
            if target_str in self._DANGEROUS_DEV_PATHS:
                return False, f"Access to dangerous device '{path_val}' is BLOCKED."
            # Block any /dev/sd*, /dev/hd*, /dev/nvme* (disk devices)
            if any(target_str.startswith(p) for p in ["/dev/sd", "/dev/hd", "/dev/nvme", "/dev/loop"]):
                return False, f"Access to block device '{path_val}' is BLOCKED."
            # Block memory/kernel access
            if any(target_str.startswith(p) for p in ["/dev/mem", "/dev/kmem", "/dev/port"]):
                return False, f"Access to kernel memory device '{path_val}' is BLOCKED."

        # Check for sensitive home directory dotfiles
        home = os.path.expanduser("~")
        if target_str.startswith(home):
            rel_path = os.path.relpath(target_str, home)
            for dotfile in self._SENSITIVE_DOTFILES:
                if rel_path == dotfile or rel_path.startswith(dotfile + os.sep):
                    return False, f"Access to sensitive path '{path_val}' is BLOCKED."

        if self.enforce_strict_subpath:
            try:
                if not target_path.is_relative_to(self.workspace_root):
                    return False, f"Path '{path_val}' is OUTSIDE allowed workspace ({self.workspace_root})."
            except AttributeError:
                if not target_str.startswith(str(self.workspace_root)):
                    return False, f"Path '{path_val}' is OUTSIDE allowed workspace ({self.workspace_root})."
        else:
            # Check both the raw decoded path and the resolved path
            # (handles OS-level symlinks like macOS /etc → /private/etc)
            paths_to_check = {path_decoded, target_str}
            for p in paths_to_check:
                if any(p.startswith(dr) for dr in self._DANGEROUS_ROOTS):
                    return False, f"Access to system path '{path_val}' is BLOCKED."

        return True, None

    def _check_scope(self, tool_name: str, arguments: str) -> tuple[bool, Optional[str]]:
        """Returns (is_safe, error_message)."""
        if tool_name not in self.mutation_tools:
            return True, None

        try:
            args = json.loads(arguments)
        except json.JSONDecodeError:
            return False, "Invalid JSON in arguments"

        # Check ALL path-like arguments (not just the first truthy one)
        for key in self._PATH_KEYS:
            path_val = args.get(key)
            if path_val:
                is_safe, error_msg = self._check_path_arg(path_val)
                if not is_safe:
                    return False, error_msg

        cmd_arg = args.get("command") or args.get("script") or args.get("code")

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
