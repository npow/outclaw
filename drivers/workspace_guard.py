import json
import logging
import os
import re
import stat
import base64
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import unquote

from drivers.base import OutclawGuardrail, logger
from drivers.deobfuscate import decode_base64_blobs


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

    _PATH_KEYS = ["path", "file", "filename", "target", "source", "dest", "destination", "output", "dir", "directory"]

    _DANGEROUS_ROOTS = [
        "/etc", "/var", "/root", "/proc", "/sys", "/boot",
        "/usr/bin", "/usr/lib", "/usr/share", "/usr/local/lib", "/usr/sbin",
        "/bin", "/sbin", "/lib", "/lib64",
        # macOS symlinks (/etc → /private/etc, /var → /private/var, etc.)
        "/private/etc", "/private/var",
    ]
    
    # Dangerous proc paths (allow basic reads like /proc/cpuinfo)
    _DANGEROUS_PROC_PATHS = {
        "/proc/self/root",  # Symlink escape
        "/proc/sys/kernel", # Kernel parameters
        "/proc/kcore",      # Kernel memory
        "/proc/kmsg",       # Kernel messages
    }

    # Dangerous /dev paths (allow /dev/null, /dev/stdin, /dev/stdout, /dev/stderr, /dev/tty)
    _DANGEROUS_DEV_PATHS = {
        "/dev/sda", "/dev/sdb", "/dev/sdc", "/dev/sdd",  # Block devices
        "/dev/hda", "/dev/hdb", "/dev/nvme",
        "/dev/mem", "/dev/kmem", "/dev/port",  # Memory access
        "/dev/sd", "/dev/hd",  # Prefixes (will use startswith)
    }
    _SAFE_DEV_PATHS = {"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero", "/dev/random", "/dev/urandom"}

    def _is_sensitive_by_permissions(self, path: Path) -> bool:
        """Detect sensitive files by Unix permissions (600/700)."""
        try:
            mode = path.stat().st_mode
            # Files with 600 (rw-------) or 700 (rwx------) are owner-only
            if (mode & 0o077) == 0:  # No group or other permissions
                return True
        except (OSError, FileNotFoundError):
            pass
        return False

    def _is_sensitive_by_pattern(self, rel_path: str) -> bool:
        """Detect sensitive paths by keyword patterns."""
        path_lower = rel_path.lower()
        
        # Credential/key storage patterns
        if any(keyword in path_lower for keyword in [
            'credential', 'secret', 'password', 'token', 'key',
            'auth', 'private', 'identity', 'id_rsa', 'id_ed25519'
        ]):
            return True
        
        # Config directories that commonly store credentials
        if rel_path.startswith(('.config/', '.local/share/')):
            sensitive_tools = {'gh', 'gcloud', 'azure', 'aws', 'docker', 'kube'}
            parts = rel_path.split('/')
            if len(parts) > 1 and parts[1] in sensitive_tools:
                return True
        
        # SSH/GPG/crypto
        if rel_path.startswith(('.ssh', '.gnupg', '.gpg')):
            return True
        
        # Shell history (contains commands with secrets)
        if any(rel_path.endswith(suffix) for suffix in [
            '_history', '.history', '.bash_history', '.zsh_history',
            '.python_history', '.node_repl_history'
        ]):
            return True
        
        return False

    def _is_sensitive_by_credsweeper(self, path: Path) -> bool:
        """Use CredSweeper to detect if path is a known credential file."""
        try:
            # CredSweeper can scan file paths for credential patterns
            path_str = str(path).lower()
            
            # Common credential file patterns
            credential_indicators = [
                'credential', 'secret', 'password', 'token', 'key',
                'private', 'id_rsa', 'id_ed25519', '.pem', '.key',
                'api_key', 'apikey', 'auth'
            ]
            
            return any(indicator in path_str for indicator in credential_indicators)
                    
        except Exception:
            pass
        return False

    def _is_sensitive_by_xdg(self, target_path: Path) -> bool:
        """Check XDG directories for credential storage locations."""
        home = Path.home()
        
        # Get XDG directories
        xdg_config = Path(os.getenv('XDG_CONFIG_HOME', home / '.config'))
        xdg_data = Path(os.getenv('XDG_DATA_HOME', home / '.local/share'))
        
        # Known credential-storing subdirectories
        credential_dirs = {
            xdg_config / 'gh',           # GitHub CLI
            xdg_config / 'gcloud',       # Google Cloud
            home / '.aws',               # AWS
            home / '.azure',             # Azure
            home / '.ssh',               # SSH keys
            home / '.gnupg',             # GPG keys
            home / '.docker',            # Docker credentials
            home / '.kube',              # Kubernetes
            xdg_data / 'keyrings',       # GNOME keyring
            home / '.config/gh',         # GitHub CLI (fallback)
            home / '.cargo/credentials', # Rust
            home / '.gem/credentials',   # Ruby gems
            home / '.npmrc',             # npm
            home / '.pypirc',            # PyPI
        }
        
        for cred_dir in credential_dirs:
            try:
                if target_path.is_relative_to(cred_dir):
                    return True
            except (ValueError, AttributeError):
                if str(target_path).startswith(str(cred_dir)):
                    return True
        
        return False

    def _check_path_arg(self, path_val: str) -> tuple[bool, Optional[str]]:
        """Validate a single path argument. Returns (is_safe, error_message).
        
        Also checks base64-decoded variants to catch encoded path attacks.
        """
        # Null byte injection
        if "\x00" in path_val:
            return False, f"Null byte detected in path: {path_val!r}"

        # Check both raw and base64-decoded variants
        variants = [path_val]
        
        # Try to decode as base64 (for short strings like L2V0Yy9wYXNzd2Q=)
        if len(path_val) >= 4 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in path_val):
            try:
                decoded = base64.b64decode(path_val).decode('utf-8', errors='strict')
                if decoded and any(c.isprintable() for c in decoded):
                    variants.append(decoded)
            except Exception:
                pass
        
        for variant in variants:
            result = self._check_single_path(variant)
            if not result[0]:  # If any variant is blocked, block the whole thing
                return result
        
        return True, None
    
    def _check_single_path(self, path_val: str) -> tuple[bool, Optional[str]]:
        """Check a single path value (helper for _check_path_arg)."""
        # URL-decode before checking for traversal
        path_decoded = unquote(path_val)
        
        # Windows UNC paths
        if path_decoded.startswith(("\\\\?\\", "\\\\", "//")):
            return False, f"UNC paths are not allowed: {path_val}"

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
        
        # Check for symlinks (TOCTOU mitigation)
        original_path = Path(path_decoded)
        if original_path.exists() and original_path.is_symlink():
            return False, f"Symlinks are not allowed: {path_val}"
        
        # Verify resolved path hasn't escaped via symlink
        if original_path.exists():
            try:
                real_parent = original_path.parent.resolve()
                if not str(real_parent).startswith(str(self.workspace_root)):
                    return False, f"Path escapes workspace via symlink: {path_val}"
            except Exception:
                pass

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
        
        # Check for dangerous /proc paths
        if target_str.startswith("/proc/"):
            if any(target_str.startswith(p) for p in self._DANGEROUS_PROC_PATHS):
                return False, f"Access to dangerous proc path '{path_val}' is BLOCKED."

        # Hybrid sensitive file detection
        home = os.path.expanduser("~")
        if target_str.startswith(home):
            rel_path = os.path.relpath(target_str, home)
            
            # Check by pattern
            if self._is_sensitive_by_pattern(rel_path):
                return False, f"Access to sensitive path '{path_val}' is BLOCKED (pattern match)."
            
            # Check by XDG directories
            if self._is_sensitive_by_xdg(target_path):
                return False, f"Access to credential storage path '{path_val}' is BLOCKED (XDG)."
            
            # Check by CredSweeper
            if self._is_sensitive_by_credsweeper(target_path):
                return False, f"Access to credential file '{path_val}' is BLOCKED (CredSweeper)."
            
            # Check by permissions (if file exists)
            if target_path.exists() and self._is_sensitive_by_permissions(target_path):
                return False, f"Access to restricted file '{path_val}' is BLOCKED (permissions)."

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
            # Also check case-insensitive on Windows
            paths_to_check = {path_decoded, target_str}
            if os.name == 'nt':  # Windows
                paths_to_check.add(path_decoded.lower())
                paths_to_check.add(target_str.lower())
            
            for p in paths_to_check:
                # Case-insensitive check on Windows
                dangerous_roots = self._DANGEROUS_ROOTS
                if os.name == 'nt':
                    dangerous_roots = [dr.lower() for dr in self._DANGEROUS_ROOTS]
                    p = p.lower()
                
                if any(p.startswith(dr) for dr in dangerous_roots):
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
            # Check for directory traversal patterns
            if "../" in cmd_arg or "..\\" in cmd_arg:
                return False, f"Potential directory traversal detected in command: {cmd_arg}"

            # Extract and check absolute paths
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
            
            # Extract and check relative paths (./file, ../file, file.txt)
            # Match word boundaries to avoid false positives in flags
            rel_paths = re.findall(r'\b(\.\./[^\s]+|\.+/[^\s]+|[a-zA-Z0-9_][a-zA-Z0-9._/-]*\.[a-z]{2,4})\b', cmd_arg)
            for rel_path in rel_paths:
                # Skip common flags and options
                if rel_path.startswith('-') or '=' in rel_path:
                    continue
                try:
                    # Resolve relative to workspace root
                    resolved = (self.workspace_root / rel_path).resolve()
                    
                    # Check if resolved path escapes workspace
                    if self.enforce_strict_subpath:
                        if not resolved.is_relative_to(self.workspace_root):
                            return False, f"Relative path '{rel_path}' resolves outside workspace: {resolved}"
                    else:
                        # Check against dangerous roots
                        resolved_str = str(resolved)
                        dangerous_roots = ["/etc", "/var", "/root", "/proc", "/sys"]
                        if any(resolved_str.startswith(dr) for dr in dangerous_roots):
                            return False, f"Relative path '{rel_path}' resolves to dangerous location: {resolved}"
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
                if self.is_audit_mode:
                    logger.warning("🛡️ WorkspaceGuard: blocked action detected (audit mode, passthrough)")
                else:
                    msg.tool_calls = safe_calls or None
                    current_content = msg.content or ""
                    msg.content = (current_content + "\n" + "\n".join(blocked_msgs)).strip()

        return response
