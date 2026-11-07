# urlcheck

Look for phishing signs in a link **without opening it**. urlcheck analyses the text of
a URL offline: credential tricks, look-alike and mixed-script domains, raw or obfuscated
IP hosts, brand names in the wrong place, shorteners, risky file types and more.
It makes **no network requests** (the link is never visited, not even a DNS lookup).
One file, standard library only.

## Usage

```bash
python3 urlcheck.py "https://paypal.com@evil.example.net/login"
python3 urlcheck.py http://3405803781/ https://paypa1.com
pbpaste | python3 urlcheck.py              # one URL per line from stdin
```

URLs are shown *defanged* (`hxxps://example[.]com`) so the output is safe to paste into a chat or ticket.

```
== hxxps://paypal[.]com@evil[.]example[.]net/login  ->  LIKELY PHISHING / DANGEROUS
  HIGH   userinfo-trick         text before '@' (paypal.com) is not the destination; the real host is evil.example.net
== hxxps://paypa1[.]com  ->  LIKELY PHISHING / DANGEROUS
  HIGH   lookalike-brand        'paypa1' looks like 'paypal' (swapped or changed characters)
```

## Checks

| Rule | Severity | Meaning |
|------|----------|---------|
| `userinfo-trick`, `obfuscated-ip`, `mixed-scripts`, `lookalike-brand`, `script-scheme` | HIGH | `bank.com@evil.test`, decimal/hex IPs, Latin+Cyrillic mixes, `paypa1`/`rnicrosoft`/one-letter changes of ~25 well-known brands, `javascript:`/`data:` URLs |
| `ip-host`, `punycode`, `non-ascii-host`, `brand-in-wrong-place`, `risky-file`, `encoded-host`, `malformed`, `file-scheme` | MEDIUM | raw IPs, `xn--` hosts, a brand name outside the registered domain, `.exe`/`.js`/`.iso`-style downloads, percent-encoded hosts |
| `no-tls` | LOW, MEDIUM with login words | plain `http` |
| `shortener`, `abused-tld`, `many-subdomains`, `many-hyphens`, `odd-port`, `embedded-url`, `long-url` | LOW | context signals that are common in phishing but also in legitimate links |

Exit codes: `0` no MEDIUM/HIGH signs (LOW only counts as fine), `1` suspicious, `2` no URL given.

## Limits

This is text analysis only: a clean result does not make a site safe, and a flag does not
prove malice. It does not know whether a domain was registered yesterday or is on a
blocklist, and its brand list is small. The registered domain is guessed from the last two
labels (plus a few `co.uk`-style suffixes). When in doubt, do not click: type the address
yourself or use the official app.

## Tests

The tests also verify that no network function is called:

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
