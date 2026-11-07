import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
import urllib.parse
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


class NewCheckTests(unittest.TestCase):
    def test_hidden_characters(self):
        for ch in ("\u200b", "\u202e", "\u2066", "\ufeff", "\u00ad"):
            self.assertIn(("HIGH", "hidden-characters"), rules("https://exa%smple.com/a" % ch), repr(ch))

    def test_hidden_characters_are_stripped_before_the_other_checks(self):
        r = rules("https://pay\u200bpa1.com")
        self.assertIn(("HIGH", "lookalike-brand"), r)

    def test_double_extension(self):
        for path in ("/invoice.pdf.exe", "/photo.jpg.scr", "/report.docx.js", "/a.xlsx.bat"):
            self.assertIn(("HIGH", "double-extension"), rules("https://files.example.org" + path), path)

    def test_plain_executable_is_only_medium(self):
        r = rules("https://files.example.org/setup.exe")
        self.assertIn(("MEDIUM", "risky-file"), r)
        self.assertNotIn("double-extension", {x for _, x in r})

    def test_document_alone_is_fine(self):
        self.assertEqual(rules("https://files.example.org/report.pdf"), set())

    def test_domain_in_subdomain(self):
        self.assertIn(("MEDIUM", "domain-in-subdomain"), rules("https://mybank.com.secure-check.example.net/login"))
        self.assertIn(("MEDIUM", "domain-in-subdomain"), rules("https://www.example.org.verify.example.net"))

    def test_ordinary_subdomains_are_fine(self):
        for url in ("https://www.example.com", "https://mail.example.co.uk", "https://shop.eu.example.net"):
            self.assertNotIn("domain-in-subdomain", {r for _, r in rules(url)}, url)

    def test_brand_in_path(self):
        self.assertIn(("LOW", "brand-in-path"), rules("https://example.net/paypal/login"))
        self.assertNotIn("brand-in-path", {r for _, r in rules("https://paypal.com/signin")})
        self.assertNotIn("brand-in-path", {r for _, r in rules("https://example.net/about")})

    def test_existing_checks_still_fire(self):
        self.assertIn(("HIGH", "userinfo-trick"), rules("https://paypal.com@evil.example.net/"))
        self.assertIn(("HIGH", "lookalike-brand"), rules("https://paypa1.com"))


class UnwrapTests(unittest.TestCase):
    INNER = "https://paypa1.example.net/login"

    def test_safelinks(self):
        url = "https://eur01.safelinks.protection.outlook.com/?url=%s&data=05" % urllib.parse.quote(self.INNER, safe="")
        self.assertEqual(uc.unwrap_url(url), ("Microsoft SafeLinks", self.INNER))

    def test_google_redirect(self):
        url = "https://www.google.com/url?q=%s&sa=D" % urllib.parse.quote(self.INNER, safe="")
        self.assertEqual(uc.unwrap_url(url), ("Google redirect", self.INNER))

    def test_facebook_redirect(self):
        url = "https://l.facebook.com/l.php?u=%s" % urllib.parse.quote(self.INNER, safe="")
        self.assertEqual(uc.unwrap_url(url)[1], self.INNER)

    def test_proofpoint_v3(self):
        url = "https://urldefense.com/v3/__%s__;!!abc$" % self.INNER
        self.assertEqual(uc.unwrap_url(url), ("Proofpoint URL Defense", self.INNER))

    def test_not_a_wrapper(self):
        for url in ("https://example.com/", "https://www.google.com/search?q=a", "not a url at all", ""):
            self.assertIsNone(uc.unwrap_url(url), url)

    def test_nested_wrappers_limited(self):
        url = self.INNER
        for _ in range(5):
            url = "https://www.google.com/url?q=" + urllib.parse.quote(url, safe="")
        self.assertEqual(len(uc.unwrap_chain(url)), uc.MAX_UNWRAP)

    def test_wrapped_phishing_link_is_analysed_inside(self):
        url = "https://eur01.safelinks.protection.outlook.com/?url=%s" % urllib.parse.quote("https://paypa1.com", safe="")
        entries = uc.check_one(url)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[1]["wrapper"], "Microsoft SafeLinks")
        self.assertIn("lookalike-brand", {f[1] for f in entries[1]["findings"]})
        self.assertTrue(all(f[0] == "LOW" for f in entries[0]["findings"]))  # the gateway link itself is not the problem

    def test_unwrapping_never_touches_the_network(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network used")), \
                mock.patch("socket.getaddrinfo", side_effect=AssertionError("dns used")):
            uc.check_one("https://www.google.com/url?q=https%3A%2F%2Fpaypa1.com")


def run_main(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin)):
        code = uc.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_json_output_is_defanged(self):
        code, out, _ = run_main("--json", "https://paypa1.com/login", "https://example.com")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data[0]["url"], "hxxps://paypa1[.]com/login")
        self.assertEqual((data[0]["severity"], data[1]["severity"]), ("HIGH", None))
        self.assertNotIn("https://", out)
        self.assertEqual(data[0]["checked"][0]["findings"][0]["rule"], "lookalike-brand")

    def test_json_wrapped_entry(self):
        _, out, _ = run_main("--json", "https://www.google.com/url?q=https%3A%2F%2Fpaypa1.com")
        checked = json.loads(out)[0]["checked"]
        self.assertEqual([c["wrapper"] for c in checked], [None, "Google redirect"])
        self.assertEqual(json.loads(out)[0]["severity"], "HIGH")

    def test_text_output_shows_wrapper(self):
        code, out, _ = run_main("https://www.google.com/url?q=https%3A%2F%2Fpaypa1.com")
        self.assertEqual(code, 1)
        self.assertIn("inside Google redirect wrapper: hxxps://paypa1[.]com", out)
        self.assertIn("LIKELY PHISHING", out)

    def test_file_input(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "urls.txt")
            with open(p, "w") as fh:
                fh.write("# from the ticket\nhttps://example.com\n\nhttps://paypa1.com\n")
            code, out, _ = run_main("-f", p, "--json")
        self.assertEqual((code, len(json.loads(out))), (1, 2))

    def test_missing_file_and_no_input(self):
        self.assertEqual(run_main("-f", "/nonexistent/urls.txt")[0], 2)
        self.assertEqual(run_main(stdin="")[0], 2)

    def test_stdin_still_works(self):
        self.assertEqual(run_main(stdin="https://example.com\n")[0], 0)

    def test_clean_url_exit_zero(self):
        self.assertEqual(run_main("https://example.com/about")[0], 0)

    def test_urls_in_text_output_are_defanged(self):
        _, out, _ = run_main("https://paypa1.com")
        self.assertNotIn("https://paypa1.com", out)


if __name__ == "__main__":
    unittest.main()
