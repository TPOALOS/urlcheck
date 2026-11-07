import socket
import unittest
from unittest import mock

import urlcheck as uc


def rules(url):
    return {(f[0], f[1]) for f in uc.analyze(url)}


class HelperTests(unittest.TestCase):
    def test_defang(self):
        self.assertEqual(uc.defang("https://example.com/a"), "hxxps://example[.]com/a")

    def test_registered_domain(self):
        self.assertEqual(uc.registered_domain("a.b.example.com"), "example.com")
        self.assertEqual(uc.registered_domain("shop.example.co.uk"), "example.co.uk")

    def test_edit1(self):
        self.assertTrue(uc.edit1("paypall", "paypal"))
        self.assertTrue(uc.edit1("paypsl", "paypal"))
        self.assertFalse(uc.edit1("paypal", "paypal"))
        self.assertFalse(uc.edit1("pay", "paypal"))

    def test_deconfuse(self):
        self.assertEqual(uc.deconfuse("paypa1"), "paypal")
        self.assertEqual(uc.deconfuse("rnicrosoft"), "microsoft")


class CleanTests(unittest.TestCase):
    def test_normal_urls_clean(self):
        for url in ("https://example.com/path?q=1", "https://www.example.org", "example.net/page",
                    "https://paypal.com/signin", "https://accounts.google.com/", "https://shop.example.co.uk/"):
            self.assertEqual(uc.analyze(url), [], url)


class DetectionTests(unittest.TestCase):
    def test_userinfo_trick(self):
        self.assertIn(("HIGH", "userinfo-trick"), rules("https://paypal.com@evil.example.net/login"))

    def test_ip_hosts(self):
        self.assertIn(("MEDIUM", "ip-host"), rules("http://203.0.113.5/login"))
        self.assertIn(("HIGH", "obfuscated-ip"), rules("http://3405803781/"))
        self.assertIn(("HIGH", "obfuscated-ip"), rules("http://0xcb007105/"))
        self.assertIn(("MEDIUM", "ip-host"), rules("http://[2001:db8::1]/"))

    def test_punycode_and_mixed_scripts(self):
        self.assertIn(("MEDIUM", "punycode"), rules("https://xn--exmple-cua.com/"))
        mixed = "https://pаypal.com/"  # Cyrillic a inside Latin
        self.assertIn(("HIGH", "mixed-scripts"), rules(mixed))
        self.assertIn(("MEDIUM", "non-ascii-host"), rules("https://münchen.example/"))

    def test_brand_rules(self):
        self.assertIn(("MEDIUM", "brand-in-wrong-place"), rules("https://paypal.com.secure-login.example.net/"))
        self.assertIn(("MEDIUM", "brand-in-wrong-place"), rules("https://login.apple.example.net/"))
        self.assertIn(("HIGH", "lookalike-brand"), rules("https://paypa1.com/"))
        self.assertIn(("HIGH", "lookalike-brand"), rules("https://rnicrosoft.com/"))
        self.assertIn(("HIGH", "lookalike-brand"), rules("https://paypall.com/"))
        self.assertIn(("MEDIUM", "brand-in-wrong-place"), rules("https://paypal-support.example.org/"))

    def test_shortener_tld_hyphens_subdomains(self):
        self.assertIn(("LOW", "shortener"), rules("https://bit.ly/abc"))
        self.assertIn(("LOW", "abused-tld"), rules("https://free-gift.example.top/"))
        self.assertIn(("LOW", "many-hyphens"), rules("https://a-b-c-d.example.com/"))
        self.assertIn(("LOW", "many-subdomains"), rules("https://a.b.c.d.example.com/"))

    def test_transport_and_ports(self):
        self.assertIn(("LOW", "no-tls"), rules("http://example.com/"))
        self.assertIn(("MEDIUM", "no-tls"), rules("http://example.com/login"))
        self.assertIn(("LOW", "odd-port"), rules("https://example.com:8443/"))
        self.assertNotIn(("LOW", "odd-port"), rules("https://example.com:443/"))

    def test_files_and_redirects(self):
        self.assertIn(("MEDIUM", "risky-file"), rules("https://example.com/invoice.exe"))
        self.assertIn(("LOW", "embedded-url"), rules("https://example.com/r?url=https://other.example.net/"))
        self.assertIn(("LOW", "long-url"), rules("https://example.com/" + "a" * 250))

    def test_schemes(self):
        self.assertIn(("HIGH", "script-scheme"), rules("javascript:alert(1)"))
        self.assertIn(("HIGH", "script-scheme"), rules("data:text/html;base64,AAAA"))
        self.assertIn(("MEDIUM", "file-scheme"), rules("file:///etc/hosts"))

    def test_malformed(self):
        self.assertIn(("MEDIUM", "malformed"), rules("https://example.com:notaport/"))

    def test_percent_encoded_host(self):
        self.assertIn(("MEDIUM", "encoded-host"), rules("https://exam%70le.com/"))


class SafetyAndCliTests(unittest.TestCase):
    def test_never_touches_network(self):
        boom = mock.Mock(side_effect=AssertionError("network used"))
        with mock.patch.object(socket, "create_connection", boom), mock.patch.object(socket, "getaddrinfo", boom), \
                mock.patch.object(socket, "gethostbyname", boom):
            uc.analyze("https://paypa1.com/login")
            uc.analyze("http://3405803781/")
        boom.assert_not_called()

    def test_exit_codes(self):
        self.assertEqual(uc.main(["https://example.com/"]), 0)
        self.assertEqual(uc.main(["https://paypa1.com/"]), 1)
        self.assertEqual(uc.main(["https://bit.ly/abc"]), 0)  # LOW only
        with mock.patch("sys.stdin", iter([])):
            self.assertEqual(uc.main([]), 2)


if __name__ == "__main__":
    unittest.main()
