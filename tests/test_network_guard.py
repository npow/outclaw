import pytest
from fastapi import HTTPException
from drivers.network_guard import NetworkGuard


def test_network_guard_blocks_malware():
    """Ensure malware.com is blocked (Blacklist)."""
    config = {
        "network_guard": {
            "allow_unknown": True,
            "use_community_list": False,
            "allowed_domains": ["google.com"],
            "blocked_domains": ["malware.com"],
        },
        "mode": "strict",
    }
    guard = NetworkGuard(outclaw_config=config)
    with pytest.raises(HTTPException) as exc_info:
        guard._scan_text_for_urls('{"url": "http://malware.com/evil.sh"}')
    assert exc_info.value.status_code == 400
    detail = str(exc_info.value.detail)
    assert "NetworkGuard" in detail
    assert "Blocked Connection to Malicious Domain" in detail


def test_network_guard_allows_google():
    """Ensure google.com is allowed (Whitelist)."""
    config = {
        "network_guard": {
            "allow_unknown": False,
            "use_community_list": False,
            "allowed_domains": ["google.com"],
            "blocked_domains": ["malware.com"],
        },
        "mode": "strict",
    }
    guard = NetworkGuard(outclaw_config=config)
    # Should not raise
    guard._scan_text_for_urls('{"url": "https://google.com?q=hello"}')


def test_network_guard_strict_mode():
    """Ensure unknown domains are blocked when allow_unknown is false."""
    config = {
        "network_guard": {
            "allow_unknown": False,
            "use_community_list": False,
            "allowed_domains": ["google.com"],
            "blocked_domains": [],
        },
        "mode": "strict",
    }
    guard = NetworkGuard(outclaw_config=config)
    with pytest.raises(HTTPException) as exc_info:
        guard._scan_text_for_urls('{"url": "https://unknown-site.com"}')
    assert "Blocked Connection to Unknown Domain" in str(exc_info.value.detail)
