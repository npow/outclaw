import re
import os
import logging
from typing import Any, Dict

from drivers.base import OutclawGuardrail, logger

# Graceful import
try:
    from detect_secrets.core.scan import scan_line
    from detect_secrets.settings import transient_settings
    DETECT_SECRETS_AVAILABLE = True
except ImportError:
    DETECT_SECRETS_AVAILABLE = False


class SecretGuard(OutclawGuardrail):
    """
    The Key Guardian.
    Uses detect-secrets (specific detectors, no entropy) + regex patterns.
    Falls back to regex-only when detect-secrets is not installed.
    """

    REGEX_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key"),
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
        (r"xox[baprs]-([0-9a-zA-Z]{10,48})?", "Slack Token"),
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
        (r"-----BEGIN PRIVATE KEY-----", "RSA Private Key"),
    ]

    # detect-secrets plugins (non-entropy to avoid false positives)
    DETECT_SECRETS_PLUGINS = [
        {"name": "AWSKeyDetector"},
        {"name": "ArtifactoryDetector"},
        {"name": "BasicAuthDetector"},
        {"name": "GitHubTokenDetector"},
        {"name": "PrivateKeyDetector"},
        {"name": "SlackDetector"},
        {"name": "StripeDetector"},
    ]

    def __init__(self, outclaw_config=None, **kwargs):
        super().__init__(
            outclaw_config=outclaw_config,
            guardrail_name="outclaw-secrets",
            **kwargs,
        )
        self.use_detect_secrets = DETECT_SECRETS_AVAILABLE
        self.regexes = [(re.compile(p), name) for p, name in self.REGEX_PATTERNS]

        self.allowlist = set(self.outclaw_config.get("secret_guard_allowlist", []))
        own_key = os.getenv("API_KEY")
        if own_key:
            self.allowlist.add(own_key)

    def _scan_text(self, text: str):
        """Scan text for secrets using regex + detect-secrets detectors."""
        # Normalize for split-secret evasion
        text_normalized = re.sub(r'(\s+|\\n|\\r|\\)', '', text)

        # Always run regex patterns (catches OpenAI, Slack, etc.)
        self._scan_with_regex(text)
        self._scan_with_regex(text_normalized)

        # Additionally run detect-secrets for broader coverage
        if self.use_detect_secrets:
            self._scan_with_detect_secrets(text)
            self._scan_with_detect_secrets(text_normalized)

    def _scan_with_detect_secrets(self, text: str):
        settings = {"plugins_used": self.DETECT_SECRETS_PLUGINS}
        with transient_settings(settings):
            for secret in scan_line(text):
                if any(allowed in text for allowed in self.allowlist):
                    continue
                self._enforce(
                    f"Secret Leak Detected! detect-secrets: {secret.type}",
                    driver_name="SecretGuard",
                )

    def _scan_with_regex(self, text: str):
        for regex, name in self.regexes:
            match = regex.search(text)
            if match:
                if match.group(0) in self.allowlist:
                    continue
                self._enforce(
                    f"Secret Leak Detected! Found suspicious pattern: {name}",
                    driver_name="SecretGuard",
                )

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Scan all message content for secrets."""
        for msg in data.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                self._scan_text(content)
            # Also scan tool call arguments
            for tc in msg.get("tool_calls", []):
                args = tc.get("function", {}).get("arguments", "")
                self._scan_text(args)
        return data
