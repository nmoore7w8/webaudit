# WebAudit

A web application vulnerability scanner that detects XSS, SQL injection, open redirects, sensitive file exposure, and missing security headers.

## Features

- **XSS Detection** — tests query parameters with 7 reflection payloads
- **SQL Injection** — probes parameters for common database error signatures
- **Open Redirect** — identifies redirect parameters pointing to external hosts
- **Sensitive File Exposure** — probes 20+ paths (`.env`, `.git/config`, `wp-config.php`, etc.)
- **Security Header Analysis** — checks for CSP, HSTS, X-Frame-Options, and more
- **TLS Check** — flags sites running on plain HTTP
- Severity ratings: `HIGH`, `MEDIUM`, `LOW`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan (headers + sensitive files)
python webaudit.py http://testphp.vulnweb.com

# Scan with parameter testing
python webaudit.py http://testphp.vulnweb.com --params "id,search,cat"

# HTTPS target
python webaudit.py https://example.com --params "q,redirect"
```

## Options

| Flag | Description |
|------|-------------|
| `--params` | Comma-separated query parameters to test for XSS/SQLi/redirect |

## Example Output

```
  Target  : http://testphp.vulnweb.com

  [*] Checking security headers...
  [i] [LOW]    Missing Header: X-Frame-Options — Clickjacking protection missing
  [i] [LOW]    Missing Header: Content-Security-Policy — CSP not set

  [*] Probing for sensitive files/directories...
  [!] [HIGH]   Sensitive File: 200 /admin

  [*] Testing parameters: ['id', 'search']
  [!] [HIGH]   SQLi: Possible SQL injection in param 'id' (error: sql syntax)
  [!] [HIGH]   XSS: Reflected XSS in param 'search'

  SCAN COMPLETE
  HIGH    : 2
  MEDIUM  : 0
  LOW     : 3
  TOTAL   : 5
```

## Tested Against

- [DVWA](https://github.com/digininja/DVWA)
- [testphp.vulnweb.com](http://testphp.vulnweb.com) (Acunetix demo target)
- [WebGoat](https://github.com/WebGoat/WebGoat)

## Legal

Only scan applications you own or have explicit written authorization to test. Unauthorized scanning is illegal.
