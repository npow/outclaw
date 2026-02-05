import math
import re
import os
import logging
from collections import Counter
from typing import Any, Dict

from drivers.base import OutclawGuardrail, extract_text_from_content, logger
from drivers.deobfuscate import get_text_variants

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

    Pattern sources:
    - GitHub Secret Scanning: https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns
    - detect-secrets plugins: https://github.com/Yelp/detect-secrets
    - TruffleHog patterns: https://github.com/trufflesecurity/trufflehog
    """

    # Regex patterns for secrets not covered by detect-secrets plugins
    # Patterns sourced from GitHub's secret scanning and TruffleHog
    REGEX_PATTERNS = [
        # ══════════════════════════════════════════════════════════════════════
        # Cloud Provider Keys
        # ══════════════════════════════════════════════════════════════════════
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (r"AIza[0-9A-Za-z_-]{35}", "Google Cloud API Key"),
        (r"AccountKey=[a-zA-Z0-9+/=]{60,}", "Azure Storage Account Key"),
        (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "Azure Client Secret"),
        (r"dop_v1_[a-f0-9]{64}", "DigitalOcean Personal Access Token"),
        (r"doo_v1_[a-f0-9]{64}", "DigitalOcean OAuth Token"),

        # ══════════════════════════════════════════════════════════════════════
        # AI/ML Services
        # ══════════════════════════════════════════════════════════════════════
        (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
        (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API Key"),
        (r"hf_[a-zA-Z0-9]{34}", "HuggingFace Token"),
        (r"r8_[a-zA-Z0-9]{37}", "Replicate API Token"),

        # ══════════════════════════════════════════════════════════════════════
        # Payment/Financial
        # ══════════════════════════════════════════════════════════════════════
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key"),
        (r"rk_live_[0-9a-zA-Z]{24}", "Stripe Restricted Key"),
        (r"sq0csp-[0-9A-Za-z_-]{43}", "Square Access Token"),
        (r"EAACEdEose0cBA[0-9A-Za-z]+", "Facebook Access Token"),

        # ══════════════════════════════════════════════════════════════════════
        # Communication/SaaS
        # ══════════════════════════════════════════════════════════════════════
        (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key"),
        (r"SK[a-f0-9]{32}", "Twilio API Key"),
        (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token"),
        (r"\d{8,10}:[a-zA-Z0-9_-]{35}", "Telegram Bot Token"),
        (r"key-[a-zA-Z0-9]{32}", "Mailgun API Key"),
        (r"[a-f0-9]{32}-us\d+", "Mailchimp API Key"),
        (r"DC[a-zA-Z0-9]{32}", "Discord Webhook Token"),

        # ══════════════════════════════════════════════════════════════════════
        # Source Control/CI
        # ══════════════════════════════════════════════════════════════════════
        (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token"),
        (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token"),
        (r"ghr_[0-9a-zA-Z]{36}", "GitHub Refresh Token"),
        (r"ghs_[0-9a-zA-Z]{36}", "GitHub Server Token"),
        (r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}", "GitHub Fine-grained PAT"),
        (r"glpat-[0-9a-zA-Z_-]{20}", "GitLab Personal Access Token"),
        (r"glrt-[0-9a-zA-Z_-]{20}", "GitLab Runner Token"),
        (r"ATATT3xFfGF0[a-zA-Z0-9_-]{50,}", "Atlassian API Token"),
        (r"npm_[A-Za-z0-9]{36}", "npm Access Token"),
        (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", "PyPI API Token"),

        # ══════════════════════════════════════════════════════════════════════
        # DevOps/Infrastructure
        # ══════════════════════════════════════════════════════════════════════
        (r"pul-[a-f0-9]{40}", "Pulumi Access Token"),
        (r"nf_[a-zA-Z0-9_-]{40}", "Netlify Access Token"),
        (r"vercel_[a-zA-Z0-9]{24}", "Vercel Token"),
        (r"shpat_[a-fA-F0-9]{32}", "Shopify Admin Token"),
        (r"shpca_[a-fA-F0-9]{32}", "Shopify Custom App Token"),
        (r"dp\.pt\.[a-zA-Z0-9]{40,}", "Doppler Token"),
        (r"dapi[a-f0-9]{32}", "Databricks Token"),
        (r"snyk[a-f0-9]{32,}", "Snyk API Token"),
        (r"lin_api_[a-zA-Z0-9]{40}", "Linear API Key"),
        (r"sbp_[a-f0-9]{40}", "Supabase Service Key"),

        # ══════════════════════════════════════════════════════════════════════
        # Observability/Monitoring
        # ══════════════════════════════════════════════════════════════════════
        (r"dd[a-z]_[a-zA-Z0-9]{40}", "Datadog API/App Key"),
        (r"[a-f0-9]{32}@sentry\.io", "Sentry DSN"),
        (r"NR[A-Z]{2}-[a-zA-Z0-9]{27,}", "New Relic API Key"),

        # ══════════════════════════════════════════════════════════════════════
        # Certificates/Keys
        # ══════════════════════════════════════════════════════════════════════
        (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
        (r"-----BEGIN CERTIFICATE-----", "Certificate"),
        (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key"),

        # ══════════════════════════════════════════════════════════════════════
        # Database
        # ══════════════════════════════════════════════════════════════════════
        (r"mongodb(\+srv)?://[^\s]+:[^\s]+@", "MongoDB Connection String"),
        (r"postgres://[^\s]+:[^\s]+@", "PostgreSQL Connection String"),
        (r"mysql://[^\s]+:[^\s]+@", "MySQL Connection String"),
        (r"redis://[^\s]*:[^\s]+@", "Redis Connection String"),
    ]

    # Keywords that indicate a secret value follows
    SECRET_KEYWORDS = {
        "key", "token", "secret", "password", "passwd", "pwd",
        "api_key", "apikey", "api-key", "auth", "credential",
        "access_token", "bearer", "authorization",
    }

    # Entropy thresholds for detecting unknown secrets
    HIGH_ENTROPY_THRESHOLD = 4.0  # bits per character
    MIN_SECRET_LENGTH = 16
    MAX_SECRET_LENGTH = 256

    # Pattern to find keyword=value or keyword: value pairs
    _KEYWORD_VALUE_PATTERN = re.compile(
        r'\b(' + '|'.join(SECRET_KEYWORDS) + r')\b\s*[:=]\s*["\']?([^\s,;"\'\]}>]{16,})',
        re.IGNORECASE
    )

    # detect-secrets plugins — comprehensive list of all available detectors
    # See: https://github.com/Yelp/detect-secrets/blob/master/docs/plugins.md
    DETECT_SECRETS_PLUGINS = [
        # Cloud Provider Keys
        {"name": "AWSKeyDetector"},
        {"name": "AzureStorageKeyDetector"},
        {"name": "CloudantDetector"},
        {"name": "IbmCloudIamDetector"},
        {"name": "IbmCosHmacDetector"},

        # SaaS/API Keys
        {"name": "ArtifactoryDetector"},
        {"name": "MailchimpDetector"},
        {"name": "NpmDetector"},
        {"name": "SendGridDetector"},
        {"name": "SlackDetector"},
        {"name": "SquareOAuthDetector"},
        {"name": "StripeDetector"},
        {"name": "TwilioKeyDetector"},

        # Auth/Tokens
        {"name": "BasicAuthDetector"},
        {"name": "GitHubTokenDetector"},
        {"name": "JwtTokenDetector"},
        {"name": "PrivateKeyDetector"},

        # Keyword-based detection (catches "password=xyz", "secret=abc", etc.)
        {"name": "KeywordDetector"},
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
        """Scan text for secrets using regex + detect-secrets + entropy detection.

        Generates deobfuscated text variants (base64-decoded, hex-decoded,
        Unicode-normalized, etc.) and scans ALL of them.
        """
        # Get all deobfuscated variants
        variants = get_text_variants(text)
        # Also add whitespace-stripped variant for split-secret evasion
        text_normalized = re.sub(r'(\s+|\\n|\\r|\\)', '', text)
        variants.append(text_normalized)

        seen = set()
        for variant in variants:
            if variant in seen:
                continue
            seen.add(variant)
            # Always run regex patterns (catches known key formats)
            self._scan_with_regex(variant)
            # Entropy-based detection (catches unknown key formats)
            self._scan_with_entropy(variant)
            # Additionally run detect-secrets for broader coverage
            if self.use_detect_secrets:
                self._scan_with_detect_secrets(variant)

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

    @staticmethod
    def _entropy(s: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _scan_with_entropy(self, text: str):
        """Detect high-entropy strings near secret keywords.

        This catches unknown/new API key formats that aren't in our regex list.
        """
        for match in self._KEYWORD_VALUE_PATTERN.finditer(text):
            keyword = match.group(1)
            value = match.group(2).rstrip("'\",;")

            # Skip if too short or too long
            if len(value) < self.MIN_SECRET_LENGTH or len(value) > self.MAX_SECRET_LENGTH:
                continue

            # Skip if it's in the allowlist
            if value in self.allowlist:
                continue

            # Calculate entropy
            ent = self._entropy(value)
            if ent >= self.HIGH_ENTROPY_THRESHOLD:
                # High entropy near a secret keyword = suspicious
                self._enforce(
                    f"Potential Secret Detected! High-entropy value near '{keyword}' (entropy={ent:.2f})",
                    driver_name="SecretGuard",
                )

    def _scan_tool_calls(self, tool_calls):
        """Scan tool call arguments for secrets."""
        if not tool_calls:
            return
        for tc in tool_calls:
            if isinstance(tc, dict):
                args = tc.get("function", {}).get("arguments", "")
            else:
                args = getattr(getattr(tc, "function", None), "arguments", "") or ""
            if args:
                self._scan_text(args)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Scan all message content and tool call arguments for secrets."""
        for msg in data.get("messages", []):
            content = extract_text_from_content(msg.get("content", ""))
            if content:
                self._scan_text(content)
            self._scan_tool_calls(msg.get("tool_calls"))
            if "function_call" in msg:
                self._scan_text(msg["function_call"].get("arguments", ""))
        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        """Scan LLM response content and tool call arguments for secrets."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if not msg:
                continue
            content = extract_text_from_content(getattr(msg, "content", None))
            if content:
                self._scan_text(content)
            self._scan_tool_calls(getattr(msg, "tool_calls", None))
        return response
