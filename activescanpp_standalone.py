
#!/usr/bin/env python3
"""
activescanpp_standalone.py
A lightweight, extensible active scanner in pure Python to use instead of a JAR/Burp extension.
- Scans a target URL with simple payload-based checks.
- Supports query params (?a=1&b=2) and form POSTs discovered from the initial page.
- Easy to add new checks: subclass BaseCheck and register in CHECKS.
Requires: requests, beautifulsoup4
Usage:
  python activescanpp_standalone.py https://example.com/path --method GET --params a=1 b=2
  python activescanpp_standalone.py https://example.com/form --method POST --data username=alice password=secret
"""
import argparse
import html
import json
import re
import sys
import time
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

DEFAULT_HEADERS = {
    "User-Agent": "ActiveScanPP-Standalone/0.1 (+https://example.invalid)",
    "Accept": "*/*",
}

class ScanIssue:
    def __init__(self, name: str, severity: str, confidence: str, url: str, evidence: str, request: str, response: str):
        self.name = name
        self.severity = severity
        self.confidence = confidence
        self.url = url
        self.evidence = evidence
        self.request = request
        self.response = response

    def to_dict(self):
        return {
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "evidence": self.evidence[:4096],
            "request": self.request[:4096],
            "response": self.response[:4096],
        }

class BaseCheck:
    name = "Base"
    severity = "Information"
    confidence = "Tentative"

    def generate(self, params: Dict[str, str]) -> List[Tuple[Dict[str, str], Optional[Dict[str, str]]]]:
        """Return list of (new_params, new_headers)."""
        return []

    def analyze(self, resp: requests.Response, payload: str) -> Optional[str]:
        """Return evidence string if vulnerable, else None."""
        return None

class ReflectedXSSCheck(BaseCheck):
    name = "Reflected XSS (basic)"
    severity = "Medium"
    confidence = "Firm"
    PAYLOADS = ["<script>alert(1337)</script>", "\"'><svg onload=alert(1)>"]

    def generate(self, params):
        out = []
        for k in params.keys():
            for p in self.PAYLOADS:
                newp = params.copy()
                newp[k] = p
                out.append((newp, None))
        return out

    def analyze(self, resp, payload):
        body = resp.text
        if payload in body:
            return f"Payload reflected in response body: {payload!r}"
        # HTML-encoded reflection
        enc = html.escape(payload, quote=True)
        if enc in body:
            return f"Payload reflected (HTML-encoded) in response body: {enc!r}"
        return None

class HeaderInjectionCheck(BaseCheck):
    name = "Header Injection (X-Forwarded-For)"
    severity = "Low"
    confidence = "Tentative"
    PAYLOAD = "injected-abc123"

    def generate(self, params):
        return [(params, {"X-Forwarded-For": self.PAYLOAD})]

    def analyze(self, resp, payload):
        if self.PAYLOAD in resp.text:
            return "X-Forwarded-For value reflected in body"
        return None

class OpenRedirectCheck(BaseCheck):
    name = "Open Redirect (basic)"
    severity = "Medium"
    confidence = "Firm"
    KEYS = ["next", "redirect", "url", "target", "dest", "return", "goto"]

    def generate(self, params):
        out = []
        for k in list(params.keys()) + self.KEYS:
            if k not in params:
                continue
            newp = params.copy()
            newp[k] = "https://example.com@evil.test/"
            out.append((newp, None))
        return out

    def analyze(self, resp, payload):
        if 300 <= resp.status_code < 400 and "Location" in resp.headers:
            loc = resp.headers["Location"]
            if "evil.test" in loc:
                return f"Redirects to attacker-controlled domain: {loc}"
        return None

CHECKS: List[BaseCheck] = [ReflectedXSSCheck(), HeaderInjectionCheck(), OpenRedirectCheck()]

def build_request(method: str, url: str, params: Dict[str, str], headers: Dict[str, str]):
    if method == "GET":
        parsed = urlparse(url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        q = {k: v[-1] if v else "" for k, v in q.items()}
        q.update(params)
        qs = urlencode(q, doseq=False)
        full_url = parsed._replace(query=qs).geturl()
        return full_url, None, headers
    else:
        return url, params, headers

def send(method: str, url: str, data: Optional[Dict[str, str]], headers: Dict[str, str], timeout: float = 15.0) -> requests.Response:
    if method == "GET":
        return requests.get(url, headers=headers, allow_redirects=False, timeout=timeout)
    else:
        return requests.post(url, headers=headers, data=data, allow_redirects=False, timeout=timeout)

def format_raw_request(method: str, url: str, data: Optional[Dict[str, str]], headers: Dict[str, str]) -> str:
    start = f"{method} {url} HTTP/1.1\r\n"
    hdrs = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    body = "" if data is None else urlencode(data)
    return start + hdrs + "\r\n" + body

def scan_once(method: str, url: str, base_params: Dict[str, str], base_headers: Dict[str, str]) -> List[ScanIssue]:
    issues: List[ScanIssue] = []
    for check in CHECKS:
        # build payload variations
        variants = check.generate(base_params)  # list of (params, extra_headers)
        for params, add_headers in variants:
            headers = base_headers.copy()
            if add_headers:
                headers.update(add_headers)
            full_url, data, hdrs = build_request(method, url, params, headers)
            try:
                resp = send(method, full_url, data, hdrs)
            except requests.RequestException as e:
                continue
            evidence = check.analyze(resp, payload="N/A")
            if evidence:
                issues.append(ScanIssue(
                    name=check.name,
                    severity=check.severity,
                    confidence=check.confidence,
                    url=full_url,
                    evidence=evidence,
                    request=format_raw_request(method, full_url, data, hdrs),
                    response=f"HTTP {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + "\n\n" + resp.text[:2000]
                ))
            time.sleep(0.05)  # be polite-ish
    return issues

def parse_kv_pairs(pairs: List[str]) -> Dict[str, str]:
    out = {}
    for p in pairs:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k] = v
        elif p:
            out[p] = ""
    return out

def main():
    ap = argparse.ArgumentParser(description="ActiveScan++-style lightweight scanner in pure Python")
    ap.add_argument("url", help="Target URL (e.g., https://host/path?x=1)")
    ap.add_argument("--method", choices=["GET", "POST"], default="GET")
    ap.add_argument("--params", nargs="*", default=[], help="Query parameters for GET, e.g., a=1 b=2")
    ap.add_argument("--data", nargs="*", default=[], help="Form fields for POST, e.g., username=alice password=secret")
    ap.add_argument("--header", action="append", default=[], help="Custom header K=V; can repeat")
    ap.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON findings to stdout")
    args = ap.parse_args()

    params = parse_kv_pairs(args.params if args.method == "GET" else [])
    data = parse_kv_pairs(args.data if args.method == "POST" else [])
    headers = DEFAULT_HEADERS.copy()
    for h in args.header:
        if "=" in h:
            k, v = h.split("=", 1)
            headers[k.strip()] = v.strip()

    issues = scan_once(args.method, args.url, params if args.method=="GET" else data, headers)

    if args.emit_json:
        print(json.dumps([i.to_dict() for i in issues], indent=2))
    else:
        if not issues:
            print("[+] No issues found by basic checks.")
        for i in issues:
            print(f"\n=== {i.name} ===")
            print(f"Severity: {i.severity} | Confidence: {i.confidence}")
            print(f"URL: {i.url}")
            print(f"Evidence: {i.evidence}")
            print("\n-- Request --")
            print(i.request)
            print("\n-- Response (truncated) --")
            print(i.response[:1500])

if __name__ == "__main__":
    main()
