# Changelog

## 1.1.0

- Unwraps Microsoft SafeLinks, Proofpoint URL Defense, Google and Facebook redirect links and analyses the inner URL (text only, never fetched)
- New checks: hidden or direction-control characters, double file extensions, a domain inside the subdomain, brand names in the path
- `--json` (URLs stay defanged) and `--file`
- Installable with pip (`urlcheck` command), CI on Linux and macOS

## 1.0.0

Initial release.
