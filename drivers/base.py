"""Base class for all Outclaw security guardrails."""

import logging
from typing import Union

from fastapi import HTTPException
from litellm.integrations.custom_guardrail import CustomGuardrail

logger = logging.getLogger("outclaw")


def extract_text_from_content(content: Union[str, list, None]) -> str:
    """Extract text from string or multimodal content list.

    Multimodal API format sends content as:
        [{"type": "text", "text": "..."}, {"type": "image_url", ...}]
    This helper collapses all text blocks into a single string.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "\n".join(parts)
    return ""


class OutclawGuardrail(CustomGuardrail):
    """
    Base class for Outclaw guards.

    Extends LiteLLM's CustomGuardrail with:
    - Outclaw config loading
    - Strict/audit mode enforcement
    """

    def __init__(self, outclaw_config=None, **kwargs):
        kwargs.setdefault("default_on", True)
        super().__init__(**kwargs)
        self.outclaw_config = outclaw_config or {}
        self.mode = self.outclaw_config.get("mode", "strict")

    def _enforce(self, message: str, driver_name: str):
        """Block in strict mode, log-only in audit mode."""
        logger.warning(f"🛡️ {driver_name}: {message}")
        if self.mode == "strict":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": {
                        "message": f"Outclawed by {driver_name}: {message}",
                        "type": "security_error",
                    }
                },
            )
