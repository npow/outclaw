import re
import json
import logging
from urllib.parse import urlparse
from typing import Any, Dict, Set

from tranco import Tranco

from drivers.base import OutclawGuardrail, logger


class NetworkGuard(OutclawGuardrail):
    """
    The Traffic Cop.
    Controls where your agent can connect. Firewall for the Agent.
    """

    URL_PATTERN = re.compile(r'https?://(?:[-\w.]|(?::\d+)|(?:%[\da-fA-F]{2}))+')

    def __init__(self, outclaw_config=None, **kwargs):
        super().__init__(
            outclaw_config=outclaw_config,
            guardrail_name="outclaw-network",
            **kwargs,
        )
        net_config = self.outclaw_config.get("network_guard", {})
        self.allowed_domains = set(net_config.get("allowed_domains", []))
        self.blocked_domains = set(net_config.get("blocked_domains", []))
        self.allow_unknown = net_config.get("allow_unknown", False)

        self.use_tranco = net_config.get("use_community_list", False)
        self.tranco_list = None
        if self.use_tranco:
            t = Tranco(cache_dir=".tranco_cache")
            self.tranco_list = t.list().top(10000)
            logger.info("NetworkGuard: Loaded Tranco Top 10,000 Safe Sites.")

    def _extract_domain(self, url: str) -> str:
        try:
            netloc = urlparse(url).netloc.lower()
            return netloc.split(":")[0]
        except Exception:
            return ""

    def _is_blocked(self, domain: str) -> bool:
        return any(d == domain or domain.endswith("." + d) for d in self.blocked_domains)

    def _is_allowed(self, domain: str) -> bool:
        if any(d == domain or domain.endswith("." + d) for d in self.allowed_domains):
            return True
        if self.tranco_list and domain in self.tranco_list:
            return True
        return False

    def _scan_text_for_urls(self, text: str):
        """Find URLs in text and enforce domain rules."""
        urls = self.URL_PATTERN.findall(text)
        for url in urls:
            domain = self._extract_domain(url)
            if self._is_blocked(domain):
                self._enforce(
                    f"Blocked Connection to Malicious Domain: {domain}",
                    driver_name="NetworkGuard",
                )
            elif not self.allow_unknown and not self._is_allowed(domain):
                self._enforce(
                    f"Blocked Connection to Unknown Domain: {domain} (Not Whitelisted)",
                    driver_name="NetworkGuard",
                )

    def _scan_tool_calls(self, tool_calls):
        """Scan tool call arguments for URLs."""
        if not tool_calls:
            return
        for tc in tool_calls:
            if isinstance(tc, dict):
                args = tc.get("function", {}).get("arguments", "")
            else:
                args = getattr(getattr(tc, "function", None), "arguments", "") or ""
            self._scan_text_for_urls(args)

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Scan request messages for URLs in tool call arguments."""
        for msg in data.get("messages", []):
            if "tool_calls" in msg:
                self._scan_tool_calls(msg["tool_calls"])
            if "function_call" in msg:
                self._scan_text_for_urls(msg["function_call"].get("arguments", ""))
        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        """Scan LLM-generated tool calls for URLs."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if msg and getattr(msg, "tool_calls", None):
                self._scan_tool_calls(msg.tool_calls)
        return response
