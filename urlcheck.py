#!/usr/bin/env python3
"""urlcheck - look for phishing signs in a link WITHOUT opening it.

Analyses the text of a URL offline: credential tricks (https://bank.com@evil.test),
look-alike and mixed-script domains, raw or obfuscated IP hosts, brand names in the
wrong place, link shorteners, risky file types and more. No network access; the
link is never visited. Standard library only.
Exit code 0 = no MEDIUM/HIGH signs, 1 = suspicious, 2 = bad input.
"""
import argparse
import ipaddress
import json
import re
import socket
import sys
import unicodedata
import urllib.parse

__version__ = "1.1.0"
SEV = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
BRANDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "whatsapp",
          "linkedin", "dropbox", "docusign", "adobe", "spotify", "steam", "binance", "coinbase", "metamask",
          "outlook", "office365", "icloud", "dhl", "fedex", "ups", "usps", "github", "twitter"]
LOGIN_WORDS = ("login", "signin", "sign-in", "verify", "account", "secure", "update", "password", "wallet", "billing")
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in"}
ABUSED_TLDS = {"tk", "ml", "ga", "cf", "gq", "zip", "mov", "top", "xyz", "click", "country", "kim", "work",
               "loan", "icu", "cyou", "rest", "monster", "support", "buzz", "cam"}
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".msi", ".apk", ".iso", ".hta", ".lnk", ".jar",
             ".docm", ".xlsm", ".ps1", ".dmg", ".pkg")
SECOND_LEVEL = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "com.br", "com.tr", "co.jp", "co.in",
                "co.za", "com.mx", "com.cn", "co.nz"}
CONFUSABLES = (("rn", "m"), ("vv", "w"), ("1", "l"), ("0", "o"), ("5", "s"), ("3", "e"))


HIDDEN_CHARS = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad]")
DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".ppt", ".pptx", ".rtf", ".csv")
TLD_LABELS = {"com", "net", "org", "co", "gov", "edu", "info", "biz"}
MAX_UNWRAP = 3


def unwrap_url(url):
    """If ``url`` is a security-gateway or redirector wrapper, return (kind, inner_url); else None."""
    try:
        parts = urllib.parse.urlsplit(url.strip() if "://" in url else "//" + url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    query = urllib.parse.parse_qs(parts.query)
    first = lambda *names: next((query[n][0] for n in names if query.get(n)), None)
    if host.endswith("safelinks.protection.outlook.com") and first("url"):
        return "Microsoft SafeLinks", first("url")
    if host in ("www.google.com", "google.com") and parts.path == "/url" and first("q", "url"):
        return "Google redirect", first("q", "url")
    if host in ("l.facebook.com", "lm.facebook.com") and parts.path.startswith("/l.php") and first("u"):
        return "Facebook redirect", first("u")
    if host.endswith("urldefense.com") or host.endswith("urldefense.proofpoint.com"):
        m = re.search(r"/v[23]/(?:url\?u=)?__(.+?)__;", url)
        if m:
            return "Proofpoint URL Defense", m.group(1)
        if first("u"):
            return "Proofpoint URL Defense", urllib.parse.unquote(first("u").replace("-", "%").replace("_", "/"))
    return None


def unwrap_chain(url):
    """[(kind, inner_url), ...] for nested wrappers, at most MAX_UNWRAP deep."""
    chain, cur = [], url
    for _ in range(MAX_UNWRAP):
        hit = unwrap_url(cur)
        if not hit:
            break
        chain.append(hit)
        cur = hit[1]
    return chain


def defang(url):
    return re.sub(r"^http", "hxxp", url, flags=re.I).replace(".", "[.]")


def registered_domain(host):
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def edit1(a, b):
    """True when a and b differ by exactly one insert/delete/substitute."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(l[:i] + l[i + 1:] == s for i in range(len(l)))


def deconfuse(label):
    for src, dst in CONFUSABLES:
        label = label.replace(src, dst)
    return label


def scripts_in(text):
    out = set()
    for ch in text:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def analyze(url):
    """Return list of (severity, rule, message). Never touches the network."""
    out = []
    add = lambda sev, rule, msg: out.append((sev, rule, msg))
    raw = url.strip()
    if HIDDEN_CHARS.search(raw):
        add("HIGH", "hidden-characters", "URL contains invisible or direction-control characters that disguise the real text")
        raw = HIDDEN_CHARS.sub("", raw)
    parts = urllib.parse.urlsplit(raw if "://" in raw or raw.lower().startswith(("javascript:", "data:", "mailto:")) else "//" + raw)
    scheme = parts.scheme.lower()
    if scheme in ("javascript", "data", "vbscript"):
        add("HIGH", "script-scheme", "%s: URLs run code or embed content instead of opening a site" % scheme)
        return out
    if scheme == "file":
        add("MEDIUM", "file-scheme", "file: URL points to a local file")
    if scheme == "http":
        add("MEDIUM" if any(w in raw.lower() for w in LOGIN_WORDS) else "LOW", "no-tls",
            "uses plain http (no encryption)")
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        add("MEDIUM", "malformed", "URL has an invalid host or port")
        return out
    if parts.username is not None or parts.password is not None:
        add("HIGH", "userinfo-trick", "text before '@' (%s) is not the destination; the real host is %s" % (
            urllib.parse.unquote(parts.username or ""), host or "?"))
    if "%" in (parts.netloc.rsplit("@", 1)[-1]):
        add("MEDIUM", "encoded-host", "host contains percent-encoding")
    if port not in (None, 80, 443):
        add("LOW", "odd-port", "non-standard port %s" % port)
    if len(raw) > 200:
        add("LOW", "long-url", "very long URL (%d characters)" % len(raw))
    if not host:
        return out

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
        add("MEDIUM", "ip-host", "host is a raw IP address (%s), not a domain name" % host)
    except ValueError:
        if re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host):
            try:
                socket.inet_aton(host)
                is_ip = True
                add("HIGH", "obfuscated-ip", "host %s is an obfuscated IP address" % host)
            except OSError:
                pass
    if is_ip:
        return out

    labels = host.split(".")
    shown = host
    if any(l.startswith("xn--") for l in labels):
        try:
            shown = host.encode("ascii").decode("idna")
        except (UnicodeError, ValueError):
            shown = host
        add("MEDIUM", "punycode", "host uses punycode and displays as %r (possible look-alike letters)" % shown)
    scripts = scripts_in(shown)
    if len(scripts) > 1:
        add("HIGH", "mixed-scripts", "host mixes alphabets (%s), a classic homograph trick" % ", ".join(sorted(scripts)))
    elif any(ord(c) > 127 for c in shown):
        add("MEDIUM", "non-ascii-host", "host contains non-ASCII letters")
    reg = registered_domain(shown)
    main = reg.split(".")[0]
    rest = shown[:-len(reg)].rstrip(".") if shown.endswith(reg) else shown
    tld = labels[-1]
    if host in SHORTENERS or reg in SHORTENERS:
        add("LOW", "shortener", "link shortener hides the real destination")
    if tld in ABUSED_TLDS:
        add("LOW", "abused-tld", ".%s is a TLD frequently abused for phishing (not proof by itself)" % tld)
    if len(labels) > 4:
        add("LOW", "many-subdomains", "%d labels in the host; the real domain is only %s" % (len(labels), reg))
    if shown.count("-") >= 3:
        add("LOW", "many-hyphens", "many hyphens in the host")
    for brand in BRANDS:
        if main == brand:
            continue
        if deconfuse(main) == brand or (len(brand) >= 5 and edit1(main, brand)):
            add("HIGH", "lookalike-brand", "%r looks like %r (swapped or changed characters)" % (main, brand))
            break
        if brand in rest or brand in main:
            add("MEDIUM", "brand-in-wrong-place", "contains %r but the registered domain is %s" % (brand, reg))
            break
    path = parts.path.lower()
    if path.endswith(RISKY_EXT) and any(d in path[:path.rfind(".")][-6:] for d in DOC_EXT):
        add("HIGH", "double-extension", "file name %r poses as a document but is an executable type" % path.rsplit("/", 1)[-1])
    elif path.endswith(RISKY_EXT):
        add("MEDIUM", "risky-file", "link downloads a %s file" % path[path.rfind("."):])
    sub_labels = rest.split(".") if rest else []
    if any(a in TLD_LABELS for a in sub_labels) and reg.split(".")[0] not in TLD_LABELS:
        add("MEDIUM", "domain-in-subdomain", "host starts like another domain (%s) but the registered domain is %s" % (
            rest, reg))
    if any(b in path for b in BRANDS) and not any(b == main for b in BRANDS) and any(w in path for w in LOGIN_WORDS):
        add("LOW", "brand-in-path", "a brand name and a login word appear in the path of an unrelated domain")
    tail = (parts.path + "?" + parts.query).lower()
    if re.search(r"(https?%3a|https?://|=https?:)", tail):
        add("LOW", "embedded-url", "another URL is embedded (possible open redirect)")
    return out


VERDICTS = {"HIGH": "LIKELY PHISHING / DANGEROUS", "MEDIUM": "SUSPICIOUS", "LOW": "minor oddities",
            None: "no suspicious signs in the text of this URL"}


def check_one(url):
    """Analyse a URL and any URLs hidden inside gateway/redirect wrappers; returns a list of entries."""
    entries = []
    findings = sorted(analyze(url), key=lambda f: SEV[f[0]])
    entries.append({"url": defang(url), "wrapper": None, "findings": findings})
    for kind, inner in unwrap_chain(url):
        entries.append({"url": defang(inner), "wrapper": kind,
                        "findings": sorted(analyze(inner), key=lambda f: SEV[f[0]])})
    return entries


def read_urls(args):
    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            urls += [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
    if not urls and not args.file:
        urls = [l.strip() for l in sys.stdin if l.strip()]
    return urls


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check a URL for phishing signs without visiting it.")
    ap.add_argument("urls", nargs="*", help="URLs to check (default: read one per line from stdin)")
    ap.add_argument("-f", "--file", help="file with one URL per line (# comments ok)")
    ap.add_argument("--json", action="store_true", help="machine-readable output (URLs stay defanged)")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    try:
        urls = read_urls(args)
    except OSError as exc:
        print("urlcheck: %s" % exc, file=sys.stderr)
        return 2
    if not urls:
        print("urlcheck: no URL given", file=sys.stderr)
        return 2
    bad, report = False, []
    for url in urls:
        entries = check_one(url)
        worst_all = min((SEV[f[0]] for e in entries for f in e["findings"]), default=9)
        worst = {0: "HIGH", 1: "MEDIUM", 2: "LOW"}.get(worst_all)
        report.append({"url": entries[0]["url"], "verdict": VERDICTS[worst], "severity": worst,
                       "checked": [{"url": e["url"], "wrapper": e["wrapper"],
                                    "findings": [{"severity": sv, "rule": r, "message": m} for sv, r, m in e["findings"]]}
                                   for e in entries]})
        bad = bad or worst in ("HIGH", "MEDIUM")
        if not args.json:
            print("== %s  ->  %s" % (entries[0]["url"], VERDICTS[worst]))
            for e in entries:
                if e["wrapper"]:
                    print("  inside %s wrapper: %s" % (e["wrapper"], e["url"]))
                for sev, rule, msg in e["findings"]:
                    print("  %-6s %-22s %s" % (sev, rule, msg))
    if args.json:
        print(json.dumps(report, indent=2))
    print("urlcheck: URLs were analysed as text only and never visited.", file=sys.stderr)
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
