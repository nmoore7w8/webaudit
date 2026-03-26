#!/usr/bin/env python3
"""
WebAudit - Web Vulnerability Scanner
Scans web targets for XSS, SQL injection, open redirects,
directory traversal, and sensitive file exposure.
"""

import argparse
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency: pip install requests")
    sys.exit(1)

# ── Payloads ──────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg onload=alert(1)>',
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "1; DROP TABLE users--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756", "sqlite_", "pg_query",
    "unclosed quotation", "quoted string not properly terminated",
    "syntax error", "mysql error", "division by zero",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "//evil.com/", "https://evil.com",
    "//evil.com%2F", "/%5cevil.com", "/\\evil.com",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/wp-config.php", "/config.php",
    "/admin", "/admin/", "/administrator", "/phpmyadmin",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/backup.zip", "/backup.sql", "/db.sql",
    "/api/v1/users", "/api/users", "/debug",
    "/.DS_Store", "/web.config", "/server-status",
    "/info.php", "/phpinfo.php", "/.well-known/security.txt",
]

HEADERS_TO_CHECK = {
    "X-Frame-Options": "Clickjacking protection missing",
    "X-Content-Type-Options": "MIME sniffing protection missing",
    "Strict-Transport-Security": "HSTS not set",
    "Content-Security-Policy": "CSP not set",
    "X-XSS-Protection": "Legacy XSS filter not set",
    "Referrer-Policy": "Referrer policy not set",
]

findings = []
lock_obj = __import__("threading").Lock()


def log_finding(severity, category, detail, url=""):
    with lock_obj:
        findings.append({"severity": severity, "category": category, "detail": detail, "url": url})
        icons = {"HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[i]", "INFO": "[-]"}
        print(f"  {icons.get(severity, '[?]')} [{severity}] {category}: {detail}")


def make_request(url, params=None, timeout=8, verify=False):
    try:
        resp = requests.get(url, params=params, timeout=timeout, verify=verify,
                            allow_redirects=False,
                            headers={"User-Agent": "WebAudit/1.0 (Security Scanner)"})
        return resp
    except requests.RequestException:
        return None


def check_security_headers(base_url):
    resp = make_request(base_url)
    if not resp:
        return
    for header, message in HEADERS_TO_CHECK.items():
        if header not in resp.headers:
            log_finding("LOW", "Missing Header", message, base_url)


def check_sensitive_files(base_url):
    def probe(path):
        url = base_url.rstrip("/") + path
        resp = make_request(url)
        if resp and resp.status_code in (200, 301, 302, 403):
            severity = "HIGH" if resp.status_code == 200 else "LOW"
            log_finding(severity, "Sensitive File",
                        f"{resp.status_code} {path}", url)

    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(probe, SENSITIVE_PATHS))


def extract_forms(html, base_url):
    """Minimal form extractor — no BeautifulSoup dependency."""
    import re
    forms = []
    for form_match in re.finditer(r'<form[^>]*action=["\']?([^"\'> ]+)', html, re.IGNORECASE):
        action = form_match.group(1)
        if not action.startswith("http"):
            action = base_url.rstrip("/") + "/" + action.lstrip("/")
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html, re.IGNORECASE)
        forms.append({"action": action, "inputs": inputs})
    return forms


def test_xss(base_url, params):
    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = {p: "test" for p in params}
            test_params[param] = payload
            resp = make_request(base_url, params=test_params)
            if resp and payload in resp.text:
                log_finding("HIGH", "XSS",
                            f"Reflected XSS in param '{param}'", base_url)
                break


def test_sqli(base_url, params):
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {p: "1" for p in params}
            test_params[param] = payload
            resp = make_request(base_url, params=test_params)
            if resp:
                body_lower = resp.text.lower()
                for err in SQLI_ERRORS:
                    if err in body_lower:
                        log_finding("HIGH", "SQLi",
                                    f"Possible SQL injection in param '{param}' (error: {err})",
                                    base_url)
                        break


def test_open_redirect(base_url, params):
    redirect_params = ["redirect", "url", "next", "return", "returnUrl",
                       "redirect_uri", "callback", "dest", "destination"]
    matched = [p for p in params if p.lower() in redirect_params]
    for param in matched:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_params = {param: payload}
            resp = make_request(base_url, params=test_params)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("Location", "")
                if "evil.com" in loc:
                    log_finding("MEDIUM", "Open Redirect",
                                f"Param '{param}' redirects to attacker-controlled URL", base_url)
                    break


def check_tls(base_url):
    if base_url.startswith("http://"):
        log_finding("MEDIUM", "TLS", "Site uses plain HTTP — no TLS encryption", base_url)


def print_banner():
    print("""
 __        __   _        _             _ _ _
 \\ \\      / /__| |__    / \\  _   _  __| (_) |_
  \\ \\ /\\ / / _ \\ '_ \\  / _ \\| | | |/ _` | | __|
   \\ V  V /  __/ |_) |/ ___ \\ |_| | (_| | | |_
    \\_/\\_/ \\___|_.__//_/   \\_\\__,_|\\__,_|_|\\__|

  Web Vulnerability Scanner  |  github.com
""")


def run_scan(target, crawl_params):
    print_banner()
    # Normalize URL
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    base_url = target.rstrip("/")

    print(f"  Target  : {base_url}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    # 1. TLS check
    check_tls(base_url)

    # 2. Security headers
    print("\n  [*] Checking security headers...")
    check_security_headers(base_url)

    # 3. Sensitive files
    print("\n  [*] Probing for sensitive files/directories...")
    check_sensitive_files(base_url)

    # 4. Parameter tests
    if crawl_params:
        params = [p.strip() for p in crawl_params.split(",")]
        print(f"\n  [*] Testing parameters: {params}")
        test_xss(base_url, params)
        test_sqli(base_url, params)
        test_open_redirect(base_url, params)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    highs   = [f for f in findings if f["severity"] == "HIGH"]
    mediums = [f for f in findings if f["severity"] == "MEDIUM"]
    lows    = [f for f in findings if f["severity"] == "LOW"]

    print(f"  SCAN COMPLETE — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  HIGH    : {len(highs)}")
    print(f"  MEDIUM  : {len(mediums)}")
    print(f"  LOW     : {len(lows)}")
    print(f"  TOTAL   : {len(findings)}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="WebAudit - Web vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webaudit.py http://testphp.vulnweb.com
  python webaudit.py https://example.com --params "id,search,q"
  python webaudit.py http://192.168.1.10
        """
    )
    parser.add_argument("target", help="Target URL (e.g. http://example.com)")
    parser.add_argument("--params", help="Comma-separated query params to test (e.g. id,search,q)")
    args = parser.parse_args()
    run_scan(args.target, args.params)


if __name__ == "__main__":
    main()
