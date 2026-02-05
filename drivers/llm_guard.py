import json
import logging
from typing import Any, Dict

from drivers.base import OutclawGuardrail, logger
from drivers.deobfuscate import strip_invisible, normalize_unicode

# --- LlamaFirewall (light mode) ---
try:
    from llamafirewall import LlamaFirewall, ScannerType, UserMessage
    LLAMAFIREWALL_AVAILABLE = True
except ImportError:
    LLAMAFIREWALL_AVAILABLE = False

# --- llm-guard (full mode) ---
try:
    from llm_guard.input_scanners import Anonymize, Secrets, PromptInjection, Toxicity, BanCode
    from llm_guard.output_scanners import MaliciousURLs
    from llm_guard.vault import Vault
    LLM_GUARD_AVAILABLE = True
except ImportError:
    LLM_GUARD_AVAILABLE = False


class MLGuard(OutclawGuardrail):
    """
    The Heavy Armor.
    Supports two ML backends via config ml_guard setting:
      - light: LlamaFirewall / PromptGuard 2 (~90MB, default)
      - full:  llm-guard ONNX suite (~500MB+, requires outclaw[heavy])
      - off:   Disabled
    """

    def __init__(self, outclaw_config=None, **kwargs):
        super().__init__(
            outclaw_config=outclaw_config,
            guardrail_name="outclaw-ml",
            **kwargs,
        )
        self.ml_mode = self.outclaw_config.get("ml_guard", "light")
        self.ml_enabled = False

        if self.ml_mode == "off":
            logger.info("ML Guard disabled by config (ml_guard: off)")
            return

        if self.ml_mode == "light":
            self._init_light()
        elif self.ml_mode == "full":
            self._init_full()
        else:
            logger.warning(f"Unknown ml_guard mode '{self.ml_mode}', defaulting to light")
            self.ml_mode = "light"
            self._init_light()

    def _init_light(self):
        if not LLAMAFIREWALL_AVAILABLE:
            logger.warning("LlamaFirewall not available. Install with: pip install llamafirewall")
            return
        logger.info("Initializing LlamaFirewall (PromptGuard 2)...")
        self.firewall = LlamaFirewall(scanners={ScannerType.PROMPT_GUARD: {}})
        self.ml_enabled = True

    def _init_full(self):
        if not LLM_GUARD_AVAILABLE:
            logger.warning("llm-guard not available. Install with: pip install outclaw[heavy]")
            logger.info("Falling back to light mode (LlamaFirewall)...")
            self.ml_mode = "light"
            self._init_light()
            return
        logger.info("Initializing llm-guard full ONNX suite...")
        self.vault = Vault()
        self.sanitizing_scanners = [Anonymize(vault=self.vault), Secrets(redact_mode="REDACT")]
        self.blocking_scanners = [PromptInjection(), Toxicity(), BanCode(use_onnx=True, threshold=0.5)]
        self.output_input_scanners = [Secrets(redact_mode="REDACT"), Anonymize(vault=self.vault)]
        self.output_scanners_list = [MaliciousURLs(threshold=0.75)]
        self.ml_enabled = True

    @staticmethod
    def _clean_for_ml(text: str) -> str:
        """Strip invisible characters and normalize Unicode before ML scanning."""
        return normalize_unicode(strip_invisible(text))

    # --- Light mode ---

    def _scan_light(self, text: str, context: str = "request"):
        cleaned = self._clean_for_ml(text)
        message = UserMessage(content=cleaned)
        result = self.firewall.scan(message)
        if not result.is_safe:
            self._enforce(
                f"LlamaFirewall Blocked ({context}): {result.reason}",
                driver_name="MLGuard",
            )

    # --- Full mode ---

    def _scan_full_request(self, text: str) -> str:
        """Run llm-guard blocking + sanitizing scanners. Returns sanitized text."""
        text = self._clean_for_ml(text)
        for scanner in self.blocking_scanners:
            _, is_valid, risk_score = scanner.scan(text)
            if not is_valid:
                self._enforce(
                    f"LLM Guard Blocked: {scanner.__class__.__name__} (Risk: {risk_score})",
                    driver_name="MLGuard",
                )
        for scanner in self.sanitizing_scanners:
            text, _, _ = scanner.scan(text)
        return text

    def _scan_full_response(self, text: str) -> str:
        """Run llm-guard output scanners. Returns sanitized text."""
        text = self._clean_for_ml(text)
        for scanner in self.output_input_scanners:
            text, is_valid, risk_score = scanner.scan(text)
            if not is_valid:
                logger.warning(f"MLGuard: {scanner.__class__.__name__} (Score: {risk_score}). Redacting.")
        for scanner in self.output_scanners_list:
            text, is_valid, risk_score = scanner.scan("", text)
            if not is_valid:
                logger.warning(f"MLGuard: {scanner.__class__.__name__} (Score: {risk_score}). Redacting.")
        return text

    # --- Hook interface ---

    def _extract_tool_call_text(self, tool_calls):
        """Extract text from tool call arguments for ML scanning."""
        if not tool_calls:
            return ""
        parts = []
        for tc in tool_calls:
            if isinstance(tc, dict):
                args = tc.get("function", {}).get("arguments", "")
            else:
                args = getattr(getattr(tc, "function", None), "arguments", "") or ""
            if args:
                parts.append(args)
        return "\n".join(parts)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        if not self.ml_enabled:
            return data

        for msg in data.get("messages", []):
            # Scan user message content
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str) and content:
                    if self.ml_mode == "light":
                        self._scan_light(content, context="request")
                    else:
                        sanitized = self._scan_full_request(content)
                        if sanitized != content:
                            msg["content"] = sanitized

            # Scan tool call arguments from any message
            tc_text = self._extract_tool_call_text(msg.get("tool_calls"))
            if tc_text:
                if self.ml_mode == "light":
                    self._scan_light(tc_text, context="request tool_call")
                else:
                    self._scan_full_request(tc_text)

        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        if not self.ml_enabled:
            return response

        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if not msg:
                continue

            # Scan response content
            content = getattr(msg, "content", None)
            if isinstance(content, str) and content:
                if self.ml_mode == "light":
                    self._scan_light(content, context="response")
                else:
                    sanitized = self._scan_full_response(content)
                    if sanitized != content:
                        msg.content = sanitized

            # Scan response tool call arguments
            tc_text = self._extract_tool_call_text(getattr(msg, "tool_calls", None))
            if tc_text:
                if self.ml_mode == "light":
                    self._scan_light(tc_text, context="response tool_call")
                else:
                    self._scan_full_request(tc_text)

        return response
