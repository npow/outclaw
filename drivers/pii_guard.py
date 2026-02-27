import re
import logging
from typing import Any, Dict

from drivers.base import OutclawGuardrail, extract_text_from_content, logger
from drivers.deobfuscate import normalize_pii

# Graceful import for Presidio
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

# Graceful import for phonenumbers (Google's libphonenumber)
try:
    import phonenumbers
    from phonenumbers import PhoneNumberMatcher
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False


class PIIGuard(OutclawGuardrail):
    """
    The Privacy Visor.
    Uses Presidio NER (30+ entity types) when available, falls back to regex.
    Redacts PII from user messages before they reach the LLM.
    """

    FALLBACK_PATTERNS = [
        (r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]"),
        (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        (r"\+[1-9]\d{6,14}\b", "[REDACTED_INTL_PHONE]"),
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
        pii_config = self.outclaw_config.get("pii_guard_config", {})
        self.languages = pii_config.get("languages", ["en"])  # Configurable languages
        self.use_presidio = PRESIDIO_AVAILABLE
        self.use_phonenumbers = PHONENUMBERS_AVAILABLE

        if self.use_presidio:
            try:
                self.analyzer = AnalyzerEngine()
                self.anonymizer = AnonymizerEngine()
                logger.info(f"PII Guard initialized for languages: {', '.join(self.languages)}")
            except (Exception, SystemExit):
                logger.warning("Presidio NLP model unavailable, falling back to regex PII patterns")
                self.use_presidio = False

        if self.use_presidio:
            pii_redact_config = self.outclaw_config.get("pii_redact", [])
            if pii_redact_config:
                mapped = [self.CONFIG_TO_PRESIDIO.get(item) for item in pii_redact_config]
                self.entities = list(set([m for m in mapped if m] + self.DEFAULT_ENTITIES))
            else:
                self.entities = self.DEFAULT_ENTITIES
        else:
            logger.warning("Using regex PII patterns")
            self.regexes = [(re.compile(p), repl) for p, repl in self.FALLBACK_PATTERNS]

        if self.use_phonenumbers:
            logger.info("PIIGuard: phonenumbers library loaded for international phone detection")

    def _redact_presidio(self, text: str) -> str:
        results = self.analyzer.analyze(text=text, entities=self.entities, language=self.languages[0])
        if not results:
            return text
        return self.anonymizer.anonymize(text=text, analyzer_results=results).text

    def _redact_regex(self, text: str) -> str:
        for regex, replacement in self.regexes:
            text = regex.sub(replacement, text)
        return text

    def _redact_phone_numbers(self, text: str, region: str = "US") -> str:
        """Redact phone numbers using Google's libphonenumber.

        This handles all international formats correctly, including:
        - +44 20 7946 0958 (UK)
        - +1 (555) 123-4567 (US)
        - +81 3-1234-5678 (Japan)
        - And 200+ other countries

        Falls back gracefully if phonenumbers unavailable.
        """
        if not self.use_phonenumbers:
            return text

        # Find all phone numbers in the text
        # PhoneNumberMatcher is lax by default and finds numbers even without country code
        matches = list(PhoneNumberMatcher(text, region))
        if not matches:
            return text

        # Replace from end to start to preserve indices
        result = text
        for match in reversed(matches):
            # Validate it's a plausible phone number (not just random digits)
            try:
                if phonenumbers.is_possible_number(match.number):
                    start, end = match.start, match.end
                    result = result[:start] + "[REDACTED_PHONE]" + result[end:]
            except Exception:
                continue

        return result

    def _redact(self, text: str) -> str:
        """Redact PII from text using the best available engine.

        Applies PII normalization first (e.g., [at] → @, [dot] → .)
        to catch obfuscated PII patterns, then scans the normalized text.
        If normalization produces a different result, we scan both and
        return whichever has more redactions.

        Also applies libphonenumber for comprehensive international phone detection.
        """
        normalized = normalize_pii(text)
        if self.use_presidio:
            redacted_orig = self._redact_presidio(text)
            if normalized != text:
                redacted_norm = self._redact_presidio(normalized)
                # If normalization found more PII, use that result
                if redacted_norm != normalized:
                    redacted_orig = redacted_norm
        else:
            redacted_orig = self._redact_regex(text)
            if normalized != text:
                redacted_norm = self._redact_regex(normalized)
                if redacted_norm != normalized:
                    redacted_orig = redacted_norm

        # Apply phonenumbers as a second pass to catch international formats
        # that Presidio/regex might miss
        if self.use_phonenumbers:
            redacted_orig = self._redact_phone_numbers(redacted_orig)

        return redacted_orig

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Redact PII from user message content."""
        for msg in data.get("messages", []):
            if msg.get("role") != "user":
                continue
            raw_content = msg.get("content", "")
            if isinstance(raw_content, str):
                if not raw_content:
                    continue
                redacted = self._redact(raw_content)
                if redacted != raw_content:
                    if self.is_audit_mode:
                        logger.warning("🛡️ PIIGuard: PII detected in request (audit mode, passthrough)")
                    else:
                        msg["content"] = redacted
            elif isinstance(raw_content, list):
                for block in raw_content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "")
                        if text:
                            redacted = self._redact(text)
                            if redacted != text:
                                if self.is_audit_mode:
                                    logger.warning("🛡️ PIIGuard: PII detected in request block (audit mode, passthrough)")
                                else:
                                    block["text"] = redacted

        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        """Detect PII in LLM response content."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if not msg:
                continue
            content = extract_text_from_content(getattr(msg, "content", None))
            if not content:
                continue

            redacted = self._redact(content)
            if redacted != content:
                if self.is_audit_mode:
                    logger.warning("🛡️ PIIGuard: PII detected in LLM response (audit mode, passthrough)")
                else:
                    logger.warning("🛡️ PIIGuard: PII detected in LLM response, redacting")
                    msg.content = redacted

        return response
