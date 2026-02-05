import csv
import io
import os
import re
import json
import logging
import struct
import socket
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse, unquote
from urllib.request import urlopen, Request
from typing import Any, Dict, Set

from tranco import Tranco

# Graceful import for publicsuffixlist (proper TLD handling)
try:
    from publicsuffixlist import PublicSuffixList
    PSL_AVAILABLE = True
except ImportError:
    PSL_AVAILABLE = False

from drivers.base import OutclawGuardrail, extract_text_from_content, logger
from drivers.deobfuscate import decode_url_encoding, normalize_unicode

# URLhaus threat feed configuration
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv/"
URLHAUS_CACHE_FILE = ".urlhaus_cache/domains.txt"
URLHAUS_CACHE_TTL = 86400  # 24 hours in seconds

# Safelist: Domains that should never be blocked even if in threat feeds
# These are "too big to block" - legitimate services that malware sometimes abuses
THREAT_FEED_SAFELIST = {
    # Code hosting (frequently abused for malware hosting)
    "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    # Cloud storage (frequently abused)
    "drive.google.com", "docs.google.com", "storage.googleapis.com",
    "dropbox.com", "dl.dropboxusercontent.com",
    "onedrive.live.com", "1drv.ms",
    "s3.amazonaws.com",
    # URL shorteners (frequently abused)
    "bit.ly", "t.co", "goo.gl", "tinyurl.com",
    # Paste sites (frequently abused)
    "pastebin.com", "paste.ee", "hastebin.com",
    # CDNs
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    # Social media
    "twitter.com", "x.com", "facebook.com", "linkedin.com",
    # Other major services
    "discord.com", "discord.gg", "telegram.org", "t.me",
}


class NetworkGuard(OutclawGuardrail):
    """
    The Traffic Cop.
    Controls where your agent can connect. Firewall for the Agent.
    """

    # Match HTTP/HTTPS URLs (primary pattern)
    URL_PATTERN = re.compile(r'https?://(?:[-\w.]|(?::\d+)|(?:%[\da-fA-F]{2})|\[[\da-fA-F:]+\])+')

    # Match dangerous non-HTTP schemes
    DANGEROUS_SCHEME_PATTERN = re.compile(
        r'\b(file|ftp|gopher|data|javascript|vbscript|ldap|dict|sftp|tftp|telnet):'
        r'[^\s<>"\']+',
        re.IGNORECASE
    )

    # IPv6 localhost variants
    _IPV6_LOCALHOST = {
        "::1", "0:0:0:0:0:0:0:1",  # Loopback
        "::ffff:127.0.0.1",  # IPv4-mapped
        "::ffff:7f00:1",  # IPv4-mapped hex
    }

    # Private/internal IPv6 prefixes
    _IPV6_PRIVATE_PREFIXES = [
        "fc", "fd",  # Unique local
        "fe80:",  # Link-local
    ]
    
    # IPv4 private/internal ranges (SSRF protection)
    _IPV4_PRIVATE_RANGES = [
        ("127.0.0.0", "127.255.255.255"),    # Loopback
        ("10.0.0.0", "10.255.255.255"),      # Private Class A
        ("172.16.0.0", "172.31.255.255"),    # Private Class B
        ("192.168.0.0", "192.168.255.255"),  # Private Class C
        ("169.254.0.0", "169.254.255.255"),  # Link-local
        ("0.0.0.0", "0.255.255.255"),        # Current network
        ("224.0.0.0", "239.255.255.255"),    # Multicast
        ("240.0.0.0", "255.255.255.255"),    # Reserved
    ]

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

        # Initialize Public Suffix List for proper TLD handling
        self.psl = PublicSuffixList() if PSL_AVAILABLE else None
        if PSL_AVAILABLE:
            logger.info("NetworkGuard: Public Suffix List loaded for proper TLD parsing")

        self.use_tranco = net_config.get("use_community_list", False)
        self.tranco_list = None
        if self.use_tranco:
            t = Tranco(cache_dir=".tranco_cache")
            self.tranco_list = t.list().top(10000)
            logger.info("NetworkGuard: Loaded Tranco Top 10,000 Safe Sites.")

        # URLhaus threat intelligence feed (enabled by default for secure defaults)
        self.use_urlhaus = net_config.get("use_urlhaus", True)
        self.urlhaus_domains: Set[str] = set()
        if self.use_urlhaus:
            self.urlhaus_domains = self._load_urlhaus_domains()
            if self.urlhaus_domains:
                logger.info(f"NetworkGuard: Loaded {len(self.urlhaus_domains)} malicious domains from URLhaus")

    def _load_urlhaus_domains(self) -> Set[str]:
        """Load malicious domains from URLhaus threat feed.

        Downloads and caches the URLhaus CSV feed, extracting unique domains.
        Cache is refreshed after URLHAUS_CACHE_TTL seconds (default 24h).

        Returns:
            Set of known malicious domains
        """
        cache_path = Path(URLHAUS_CACHE_FILE)
        domains: Set[str] = set()

        # Check if cache exists and is fresh
        if cache_path.exists():
            cache_age = time.time() - cache_path.stat().st_mtime
            if cache_age < URLHAUS_CACHE_TTL:
                try:
                    domains = set(cache_path.read_text().strip().split("\n"))
                    logger.info(f"NetworkGuard: Using cached URLhaus data ({len(domains)} domains)")
                    return domains
                except Exception as e:
                    logger.warning(f"NetworkGuard: Failed to read URLhaus cache: {e}")

        # Download fresh data
        try:
            logger.info("NetworkGuard: Downloading URLhaus threat feed...")
            req = Request(URLHAUS_CSV_URL, headers={"User-Agent": "Outclaw/1.0"})
            with urlopen(req, timeout=30) as response:
                # URLhaus CSV is distributed as a ZIP file
                zip_data = response.read()

            # Extract CSV from ZIP
            with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
                # Find the data file inside the ZIP (csv.txt or *.csv)
                data_files = [n for n in zf.namelist() if n.endswith((".csv", ".txt"))]
                if not data_files:
                    raise ValueError("No data file found in URLhaus ZIP")
                content = zf.read(data_files[0]).decode("utf-8", errors="ignore")

            # Parse CSV and extract domains
            for line in content.split("\n"):
                if line.startswith("#") or not line.strip():
                    continue
                try:
                    # CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
                    parts = next(csv.reader(io.StringIO(line)))
                    if len(parts) >= 3:
                        url = parts[2]
                        parsed = urlparse(url)
                        if parsed.netloc:
                            # Extract domain (without port)
                            domain = parsed.netloc.split(":")[0].lower()
                            # Skip safelisted domains (too big to block)
                            if domain and domain not in THREAT_FEED_SAFELIST:
                                domains.add(domain)
                except Exception:
                    continue

            # Cache the domains
            if domains:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text("\n".join(sorted(domains)))
                logger.info(f"NetworkGuard: Cached {len(domains)} URLhaus domains")

        except Exception as e:
            logger.warning(f"NetworkGuard: Failed to download URLhaus feed: {e}")
            # Try to use stale cache if available
            if cache_path.exists():
                try:
                    domains = set(cache_path.read_text().strip().split("\n"))
                    logger.info(f"NetworkGuard: Using stale URLhaus cache ({len(domains)} domains)")
                except Exception:
                    pass

        return domains

    # Regex for numeric IPs: plain decimal (2130706433), 0x-prefixed hex, octal
    _NUMERIC_IP_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|\d+)$")

    def _resolve_numeric_ip(self, host: str) -> str:
        """Convert numeric IP representations to dotted-quad.

        Handles:
        - Decimal: 2130706433 → 127.0.0.1
        - Hex: 0x7f000001 → 127.0.0.1
        - Octal: 0177.0.0.1 → 127.0.0.1
        - Abbreviated: 127.1 → 127.0.0.1
        """
        try:
            # Hex notation: 0x7f000001
            if host.startswith("0x") or host.startswith("0X"):
                ip_int = int(host, 16)
                if 0 <= ip_int <= 0xFFFFFFFF:
                    return socket.inet_ntoa(struct.pack("!I", ip_int))
            
            # Octal notation: 0177.0.0.1
            if "." in host and any(part.startswith("0") and len(part) > 1 and part.isdigit() for part in host.split(".")):
                parts = host.split(".")
                try:
                    normalized = []
                    for part in parts:
                        if part.startswith("0") and len(part) > 1:
                            normalized.append(str(int(part, 8)))  # Octal
                        else:
                            normalized.append(str(int(part)))
                    return ".".join(normalized)
                except ValueError:
                    pass
            
            # Abbreviated IPs: 127.1 → 127.0.0.1
            if "." in host:
                parts = host.split(".")
                if 1 <= len(parts) <= 4:
                    try:
                        # Convert to 32-bit integer
                        if len(parts) == 1:
                            ip_int = int(parts[0])
                        elif len(parts) == 2:
                            ip_int = (int(parts[0]) << 24) | int(parts[1])
                        elif len(parts) == 3:
                            ip_int = (int(parts[0]) << 24) | (int(parts[1]) << 16) | int(parts[2])
                        else:
                            return host  # Already 4 parts
                        
                        if 0 <= ip_int <= 0xFFFFFFFF:
                            return socket.inet_ntoa(struct.pack("!I", ip_int))
                    except (ValueError, struct.error):
                        pass
            
            # Plain decimal: 2130706433
            if self._NUMERIC_IP_RE.match(host) and host.isdigit():
                ip_int = int(host)
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

            # Handle IPv6 addresses in brackets: [::1]:8080 -> ::1
            if netloc.startswith("["):
                bracket_end = netloc.find("]")
                if bracket_end > 0:
                    host = netloc[1:bracket_end]
                    return host  # Return raw IPv6 for security checking
            else:
                host = netloc.split(":")[0]

            # Resolve numeric IPs to dotted-quad
            host = self._resolve_numeric_ip(host)
            # Normalize Unicode (catches IDN/punycode homographs)
            host = normalize_unicode(host)
            return host
        except Exception:
            return ""

    def _is_ipv6_localhost(self, host: str) -> bool:
        """Check if an IPv6 address is a localhost variant."""
        host_lower = host.lower()
        if host_lower in self._IPV6_LOCALHOST:
            return True
        # Check for IPv4-mapped localhost variants
        if host_lower.startswith("::ffff:") and "127." in host_lower:
            return True
        return False

    def _is_ipv6_private(self, host: str) -> bool:
        """Check if an IPv6 address is in private/internal range."""
        host_lower = host.lower()
        return any(host_lower.startswith(prefix) for prefix in self._IPV6_PRIVATE_PREFIXES)
    
    def _is_ipv4_private(self, host: str) -> bool:
        """Check if an IPv4 address is in private/internal range (SSRF protection)."""
        if not self._is_ip_address(host):
            return False
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(host))[0]
            for start_str, end_str in self._IPV4_PRIVATE_RANGES:
                start_int = struct.unpack("!I", socket.inet_aton(start_str))[0]
                end_int = struct.unpack("!I", socket.inet_aton(end_str))[0]
                if start_int <= ip_int <= end_int:
                    return True
        except (socket.error, struct.error):
            pass
        return False

    # Regex to detect IP addresses (skip PSL processing for these)
    _IP_ADDRESS_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    def _is_ip_address(self, host: str) -> bool:
        """Check if a host is an IPv4 address."""
        return bool(self._IP_ADDRESS_RE.match(host))

    def _get_registrable_domain(self, domain: str) -> str:
        """Extract the registrable domain using Public Suffix List.

        Examples:
            sub.evil.co.uk → evil.co.uk
            www.example.com → example.com
            evil.co.uk → evil.co.uk

        Falls back to simple suffix matching if PSL unavailable.
        Note: IP addresses are returned as-is (PSL doesn't apply to IPs).
        """
        # Skip PSL for IP addresses - they should be matched exactly
        if self._is_ip_address(domain):
            return domain
        if self.psl:
            # publicsuffixlist.privatesuffix returns the registrable domain
            registrable = self.psl.privatesuffix(domain)
            return registrable if registrable else domain
        return domain

    def _domain_matches(self, domain: str, pattern: str) -> bool:
        """Check if domain matches a pattern using proper TLD-aware logic.

        Supports wildcard subdomains: *.ngrok.io matches abc.ngrok.io
        With PSL: Compares registrable domains (evil.co.uk matches evil.co.uk)
        Without PSL: Falls back to suffix matching (domain.endswith pattern)
        """
        # Wildcard subdomain support
        if pattern.startswith("*."):
            base = pattern[2:]  # Remove *.
            return domain == base or domain.endswith("." + base)
        
        if self.psl:
            # Get registrable domains for both
            domain_reg = self._get_registrable_domain(domain)
            pattern_reg = self._get_registrable_domain(pattern)
            # Exact match of registrable domains, or subdomain of pattern
            return domain_reg == pattern_reg or domain == pattern or domain.endswith("." + pattern)
        else:
            # Fallback: simple suffix matching
            return domain == pattern or domain.endswith("." + pattern)

    def _is_blocked(self, domain: str) -> bool:
        # Check user-configured blocklist
        if any(self._domain_matches(domain, d) for d in self.blocked_domains):
            return True
        # Check URLhaus threat feed
        if self.urlhaus_domains and domain in self.urlhaus_domains:
            return True
        return False

    def _is_allowed(self, domain: str) -> bool:
        if any(self._domain_matches(domain, d) for d in self.allowed_domains):
            return True
        # Tranco uses registrable domains, so extract it for comparison
        check_domain = self._get_registrable_domain(domain) if self.psl else domain
        if self.tranco_list and check_domain in self.tranco_list:
            return True
        return False

    def _scan_text_for_urls(self, text: str):
        """Find URLs in text and enforce domain rules.

        URL-decodes text before extraction to catch percent-encoded domains.
        Also blocks dangerous non-HTTP schemes (file://, ftp://, etc.).
        """
        # URL-decode the text first to catch encoded domains
        decoded_text = decode_url_encoding(text)

        # Check for dangerous schemes first (file://, ftp://, etc.)
        for match in self.DANGEROUS_SCHEME_PATTERN.finditer(text):
            scheme = match.group(1).lower()
            self._enforce(
                f"Blocked Dangerous URL Scheme: {scheme}://",
                driver_name="NetworkGuard",
            )
        for match in self.DANGEROUS_SCHEME_PATTERN.finditer(decoded_text):
            scheme = match.group(1).lower()
            self._enforce(
                f"Blocked Dangerous URL Scheme: {scheme}://",
                driver_name="NetworkGuard",
            )

        # Scan both original and decoded for HTTP/HTTPS URLs
        urls = set(self.URL_PATTERN.findall(text) + self.URL_PATTERN.findall(decoded_text))
        for url in urls:
            domain = self._extract_domain(url)

            # Block IPv6 localhost/private addresses (potential internal network access)
            if self._is_ipv6_localhost(domain):
                self._enforce(
                    f"Blocked IPv6 Localhost Access: {domain}",
                    driver_name="NetworkGuard",
                )
            elif self._is_ipv6_private(domain):
                self._enforce(
                    f"Blocked IPv6 Private Network Access: {domain}",
                    driver_name="NetworkGuard",
                )
            
            # Block IPv4 private/internal addresses (SSRF protection)
            elif self._is_ipv4_private(domain):
                self._enforce(
                    f"Blocked IPv4 Private Network Access (SSRF): {domain}",
                    driver_name="NetworkGuard",
                )
                self._enforce(
                    f"Blocked IPv6 Private Network Access: {domain}",
                    driver_name="NetworkGuard",
                )
            elif self._is_blocked(domain):
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
            # Scan message content for URLs (supports multimodal content lists)
            content = extract_text_from_content(msg.get("content", ""))
            if content:
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
            # Scan response content (supports multimodal content lists)
            content = extract_text_from_content(getattr(msg, "content", None))
            if content:
                self._scan_text_for_urls(content)
            # Scan tool call arguments
            if getattr(msg, "tool_calls", None):
                self._scan_tool_calls(msg.tool_calls)
        return response
