from soc_toolkit.whitelist import WhitelistFilter

def test_google_dns_whitelist():
    is_benign, desc, provider = WhitelistFilter.check_ip("8.8.8.8")
    assert is_benign is True
    assert provider == "Google"

def test_cloudflare_dns_whitelist():
    is_benign, desc, provider = WhitelistFilter.check_ip("1.1.1.1")
    assert is_benign is True
    assert provider == "Cloudflare"

def test_malicious_ip_not_whitelisted():
    is_benign, desc, provider = WhitelistFilter.check_ip("185.220.101.45")
    assert is_benign is False

def test_trusted_domain_whitelist():
    is_benign, desc = WhitelistFilter.check_domain("google.com")
    assert is_benign is True
