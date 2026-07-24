from soc_toolkit.sanitizer import IOCSanitizer

def test_ioc_sanitizer_brackets():
    assert IOCSanitizer.sanitize("(185.220.101.45)") == "185.220.101.45"
    assert IOCSanitizer.sanitize("[1.2.3.4]") == "1.2.3.4"

def test_ioc_sanitizer_defanged():
    assert IOCSanitizer.sanitize("hxxps[://]bad[.]com") == "https://bad.com"

def test_ioc_sanitizer_dirty_ip():
    assert IOCSanitizer.sanitize("IP: 185.220.101.45") == "185.220.101.45"
