import re
import json
import logging
import struct
import socket
from urllib.parse import urlparse, unquote
from typing import Any, Dict, Set

from tranco import Tranco

from drivers.base import OutclawGuardrail, logger
from drivers.deobfuscate import decode_url_encoding, normalize_unicode


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

    # Regex for numeric IPs: plain decimal (2130706433), 0x-prefixed hex, octal
    _NUMERIC_IP_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")

    def _resolve_numeric_ip(self, host: str) -> str:
        """Convert numeric IP representations to dotted-quad.

        Handles decimal (2130706433 → 127.0.0.1), hex (0x7f000001),
        and returns the original if not numeric.
        """
        try:
            if host.startswith("0x") or host.startswith("0X"):
                ip_int = int(host, 16)
            elif self._NUMERIC_IP_RE.match(host) and host.isdigit():
                ip_int = int(host)
            else:
                return host
            if 0 <= ip_int <= 0xFFFFFFFF:
                return socket.inet_ntoa(struct.pack("!I", ip_int))
        except (ValueError, OverflowError, struct.error):
            pass
        return host

    def _extract_domain(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            # Handle @ in URLs (e.g., http://user@evil.com)
            if "@" in netloc:
                netloc = netloc.split("@", 1)[1]
            host = netloc.split(":")[0]
            # Resolve numeric IPs to dotted-quad
            host = self._resolve_numeric_ip(host)
            # Normalize Unicode (catches IDN/punycode homographs)
            host = normalize_unicode(host)
            return host
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
        """Find URLs in text and enforce domain rules.

        URL-decodes text before extraction to catch percent-encoded domains.
        """
        # URL-decode the text first to catch encoded domains
        decoded_text = decode_url_encoding(text)
        # Scan both original and decoded
        urls = set(self.URL_PATTERN.findall(text) + self.URL_PATTERN.findall(decoded_text))
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
        """Scan request messages for URLs in content and tool call arguments."""
        for msg in data.get("messages", []):
            # Scan message content for URLs
            content = msg.get("content", "")
            if isinstance(content, str) and content:
                self._scan_text_for_urls(content)
            # Scan tool call arguments
            if "tool_calls" in msg:
                self._scan_tool_calls(msg["tool_calls"])
            if "function_call" in msg:
                self._scan_text_for_urls(msg["function_call"].get("arguments", ""))
        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        """Scan LLM response content and tool calls for URLs."""
        for choice in getattr(response, "choices", []):
            msg = getattr(choice, "message", None)
            if not msg:
                continue
            # Scan response content
            content = getattr(msg, "content", None)
            if isinstance(content, str) and content:
                self._scan_text_for_urls(content)
            # Scan tool call arguments
            if getattr(msg, "tool_calls", None):
                self._scan_tool_calls(msg.tool_calls)
        return response
