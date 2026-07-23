import sys
from pathlib import Path
root = str(Path(__file__).parent.parent)
if root not in sys.path:
    sys.path.insert(0, root)

import unittest
from test_whitelist import test_google_dns_whitelist, test_cloudflare_dns_whitelist, test_malicious_ip_not_whitelisted, test_trusted_domain_whitelist
from test_playbook import test_critical_ip_playbook, test_clean_domain_playbook
from test_decoder import test_defang_url, test_refang_url, test_decode_powershell
from test_sdk import test_sdk_defang_refang, test_sdk_decode

class TestSOCToolkit(unittest.TestCase):
    def test_whitelist(self):
        test_google_dns_whitelist()
        test_cloudflare_dns_whitelist()
        test_malicious_ip_not_whitelisted()
        test_trusted_domain_whitelist()

    def test_playbook(self):
        test_critical_ip_playbook()
        test_clean_domain_playbook()

    def test_decoder(self):
        test_defang_url()
        test_refang_url()
        test_decode_powershell()

    def test_sdk(self):
        test_sdk_defang_refang()
        test_sdk_decode()

if __name__ == "__main__":
    unittest.main()
