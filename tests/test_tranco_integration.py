from unittest.mock import patch

# Mock Tranco object
class MockTrancoList:
    def top(self, n):
        return ["github.com", "google.com", "pypi.org"]

class MockTranco:
    def __init__(self, cache_dir=None): pass
    def list(self): return MockTrancoList()

def test_tranco_allow_listed_domain():
    """
    Verify that if 'github.com' is in Top 2000, it is allowed.
    """
    with patch("drivers.network_guard.Tranco", MockTranco):
        from drivers.network_guard import NetworkGuard

        config = {
            "network_guard": {
                "use_community_list": True,
                "allow_unknown": False,
                "allowed_domains": [],
                "blocked_domains": []
            },
            "mode": "strict"
        }

        driver = NetworkGuard(outclaw_config=config)

        assert "github.com" in driver.tranco_list

        assert driver._is_allowed("github.com") == True
        assert driver._is_allowed("random-hacker.com") == False
