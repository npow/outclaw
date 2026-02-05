import re
import logging
from typing import Any, Dict

from drivers.base import OutclawGuardrail, logger
from drivers.deobfuscate import normalize_pii

# Graceful import
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


class PIIGuard(OutclawGuardrail):
    """
    The Privacy Visor.
    Uses Presidio NER (30+ entity types) when available, falls back to regex.
    Redacts PII from user messages before they reach the LLM.
    """

    FALLBACK_PATTERNS = [
        (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "[REDACTED_PHONE]"),
        (r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED_CREDIT_CARD]"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[REDACTED_IP]"),
    ]

    CONFIG_TO_PRESIDIO = {
        "email": "EMAIL_ADDRESS",
        "phone_us": "PHONE_NUMBER",
        "ssn": "US_SSN",
    }

    DEFAULT_ENTITIES = [
        "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
        "IP_ADDRESS", "US_PASSPORT", "US_DRIVER_LICENSE", "IBAN_CODE",
        "PERSON", "LOCATION",
    ]

    def __init__(self, outclaw_config=None, **kwargs):
        super().__init__(
            outclaw_config=outclaw_config,
            guardrail_name="outclaw-pii",
            **kwargs,
        )
        self.use_presidio = PRESIDIO_AVAILABLE
        if self.use_presidio:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
            except (Exception, SystemExit):
                logger.warning("Presidio NLP model unavailable, falling back to regex PII patterns")
                self.use_presidio = False

        if self.use_presidio:
            pii_config = self.outclaw_config.get("pii_redact", [])
            if pii_config:
                mapped = [self.CONFIG_TO_PRESIDIO.get(item) for item in pii_config]
                self.entities = list(set([m for m in mapped if m] + self.DEFAULT_ENTITIES))
            else:
                self.entities = self.DEFAULT_ENTITIES
        else:
            logger.warning("Using regex PII patterns")
            self.regexes = [(re.compile(p), repl) for p, repl in self.FALLBACK_PATTERNS]

    def _redact_presidio(self, text: str) -> str:
        results = self.analyzer.analyze(text=text, entities=self.entities, language="en")
        if not results:
            return text
        return self.anonymizer.anonymize(text=text, analyzer_results=results).text

    def _redact_regex(self, text: str) -> str:
        for regex, replacement in self.regexes:
            text = regex.sub(replacement, text)
        return text

    def _redact(self, text: str) -> str:
        """Redact PII from text using the best available engine.

        Applies PII normalization first (e.g., [at] → @, [dot] → .)
        to catch obfuscated PII patterns, then scans the normalized text.
        If normalization produces a different result, we scan both and
        return whichever has more redactions.
        """
        normalized = normalize_pii(text)
        if self.use_presidio:
            redacted_orig = self._redact_presidio(text)
            if normalized != text:
                redacted_norm = self._redact_presidio(normalized)
                # If normalization found more PII, use that result
                if redacted_norm != normalized:
                    return redacted_norm
            return redacted_orig
        redacted_orig = self._redact_regex(text)
        if normalized != text:
            redacted_norm = self._redact_regex(normalized)
            if redacted_norm != normalized:
                return redacted_norm
        return redacted_orig

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Redact PII from user message content."""
        for msg in data.get("messages", []):
            if msg.get("role") != "user":
                continue
            content = msg.get("content", "")
            if not isinstance(content, str) or not content:
                continue

            redacted = self._redact(content)
            if redacted != content:
                msg["content"] = redacted

        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        """Detect PII in LLM response content."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if not msg:
                continue
            content = getattr(msg, "content", None)
            if not isinstance(content, str) or not content:
                continue

            redacted = self._redact(content)
            if redacted != content:
                logger.warning(f"🛡️ PIIGuard: PII detected in LLM response, redacting")
                msg.content = redacted

        return response
