import json
import re
from typing import Any, Dict, List, Literal, Optional, Set

from drivers.base import OutclawGuardrail, logger
from drivers.deobfuscate import normalize_shell, strip_invisible, normalize_unicode

# Graceful import for bashlex (AST-based shell parsing)
try:
    import bashlex
    BASHLEX_AVAILABLE = True
except ImportError:
    BASHLEX_AVAILABLE = False


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
        # File descriptor / network redirection abuse
        r'exec\s+\d*[<>].*(/dev/tcp|/dev/udp)',
        # Environment variable hijacking
        r'export\s+(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_PATH|PATH)\s*=',
        # Indirect execution wrappers
        r'\benv\s+(rm|dd|mkfs|nc|bash|sh)\b',
        r'\bcommand\s+(rm|dd|mkfs|nc|bash|sh)\b',
        r'\$\(which\s+(rm|dd|mkfs|nc)\)',
        r'`which\s+(rm|dd|mkfs|nc)`',
        # Alternative shells
        r'\b(zsh|dash|fish|ksh|csh|tcsh)\s+-c\b',
        # Xargs/parallel with dangerous commands
        r'\bxargs\s+.*(rm|dd|mkfs)\b',
        r'\bparallel\s+.*(rm|dd|mkfs)\b',
        # Find with dangerous actions
        r'\bfind\b.*-delete\b',
        r'\bfind\b.*-exec\s+.*(rm|sh|bash)\b',
        # Here-doc to shell
        r'<<\s*\w*\s*\|?\s*(sh|bash|zsh)\b',
        # Additional interpreter abuse
        r'\bphp\s+-r\b.*\b(system|exec|shell_exec|passthru)',
        r'\blua\s+-e\b.*\bos\.execute\b',
        r'\bawk\b.*\bsystem\s*\(',
        # Timeout/time wrappers with dangerous commands
        r'\b(timeout|time)\s+\d*\s*(rm|dd|mkfs)\b',
        # Source/dot execution of remote content
        r'\b(source|\.)\s+<\(',
    ]

    # Blocked command verbs (used by bashlex AST scanning)
    # This is the "source of truth" - regex patterns above are fallback
    BLOCKED_COMMANDS: Set[str] = {
        # Destructive
        "rm", "rmdir", "unlink", "shred",
        "mkfs", "fdisk", "parted",
        "dd",
        # Remote access / shells
        "nc", "ncat", "netcat",
        "bash", "sh", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
        "socat", "telnet", "ssh", "scp", "sftp", "rsync",
        # Privilege escalation
        "sudo", "su", "doas", "pkexec",
        "chown", "chmod",
        # System manipulation
        "crontab", "at", "systemctl", "service",
        "insmod", "modprobe", "rmmod",
        # Dangerous utilities
        "curl", "wget",  # When combined with pipe-to-shell
        "eval", "exec",
        "nohup", "disown",
        # Interpreters (dangerous when running arbitrary code)
        "python", "python3", "python2",
        "perl", "ruby", "node", "php", "lua",
        "awk", "gawk", "nawk",
    }

    # Commands that are dangerous only in certain contexts
    CONTEXT_DANGEROUS_COMMANDS: Set[str] = {
        "find",  # Dangerous with -exec or -delete
        "xargs",  # Dangerous when piping to rm, etc.
        "parallel",
        "env", "command", "builtin",  # Wrappers
        "timeout", "time", "nice", "ionice",  # Can wrap dangerous commands
    }

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

        # Allow users to extend blocked commands via config
        extra_blocked = self.outclaw_config.get("tool_guard_blocked_commands", [])
        self.blocked_commands = self.BLOCKED_COMMANDS | set(extra_blocked)

        # Allow-list mode: if set, ONLY these commands are permitted
        self.allowed_commands = set(self.outclaw_config.get("tool_guard_allowed_commands", []))
        self.use_allowlist = bool(self.allowed_commands)

        if self.use_allowlist:
            logger.info(f"ToolGuard: Allow-list mode ENABLED with {len(self.allowed_commands)} commands")
        if BASHLEX_AVAILABLE:
            logger.info("ToolGuard: bashlex AST parsing ENABLED")

    def _extract_commands_bashlex(self, cmd: str) -> Set[str]:
        """Extract command names from a shell command using bashlex AST parsing.

        This handles ALL shell obfuscation automatically because bashlex
        understands shell grammar (quotes, escapes, expansions, etc.).
        """
        if not BASHLEX_AVAILABLE:
            return set()

        commands = set()
        try:
            parts = bashlex.parse(cmd)
        except Exception:
            # bashlex can't parse everything (complex scripts, syntax errors)
            return set()

        def visit(node):
            """Recursively visit AST nodes to find commands."""
            if node.kind == "command":
                # Get the command name (first word)
                for part in node.parts:
                    if part.kind == "word":
                        # Extract just the command name (handle paths like /bin/rm)
                        word = part.word
                        if "/" in word:
                            word = word.split("/")[-1]
                        commands.add(word)
                        break  # First word is the command
            # Recurse into child nodes
            for attr in ("parts", "list", "command"):
                child = getattr(node, attr, None)
                if child:
                    if isinstance(child, list):
                        for c in child:
                            visit(c)
                    else:
                        visit(child)

        for part in parts:
            visit(part)

        return commands

    def _scan_with_bashlex(self, cmd: str):
        """Scan a command using bashlex AST parsing.

        This is more robust than regex because it understands shell grammar.
        """
        commands = self._extract_commands_bashlex(cmd)

        if self.use_allowlist:
            # Allow-list mode: block anything not explicitly permitted
            for cmd_name in commands:
                if cmd_name not in self.allowed_commands:
                    self._enforce(
                        f"Blocked Command (not in allow-list): '{cmd_name}'",
                        driver_name="ToolGuard",
                    )
        else:
            # Block-list mode: block known dangerous commands
            for cmd_name in commands:
                if cmd_name in self.blocked_commands:
                    self._enforce(
                        f"Blocked Dangerous Command: '{cmd_name}'",
                        driver_name="ToolGuard",
                    )

    def _scan_arguments(self, arguments: str):
        """Scan argument string for dangerous patterns.

        Uses two complementary approaches:
        1. bashlex AST parsing - handles shell obfuscation automatically
        2. Regex patterns - catches patterns bashlex might miss

        Applies full deobfuscation pipeline: strip invisible chars,
        Unicode normalization, and shell normalization.
        """
        cleaned = strip_invisible(arguments)
        unicode_norm = normalize_unicode(cleaned)
        shell_norm = normalize_shell(unicode_norm)

        # Try to extract the command from JSON arguments
        try:
            args_dict = json.loads(arguments)
            cmd = args_dict.get("command") or args_dict.get("script") or args_dict.get("code") or ""
        except (json.JSONDecodeError, TypeError):
            cmd = arguments  # Treat raw string as command

        # AST-based scanning (primary - handles obfuscation automatically)
        if BASHLEX_AVAILABLE and cmd:
            for variant in {cmd, shell_norm}:
                self._scan_with_bashlex(variant)

        # Regex-based scanning (fallback - catches patterns bashlex misses)
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
