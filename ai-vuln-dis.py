#!/usr/bin/env python3
"""
AI-style URL vulnerability helper (manual testing assistant)

- Static analysis ONLY (no exploitation).
- Optionally does a real GET (--live) to capture actual response snippet.
- Heuristically derives potential vulnerability categories from URLs/params.
- Optional AI backend for more detailed summaries.

Use only on targets you are authorized to test.
"""

import argparse
import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote

# --------- Heuristic Config ----------

SUSPICIOUS_PARAM_NAMES = {
    # Search / content
    "q", "query", "search", "s", "keyword", "message", "comment", "content",
    # Redirects
    "redirect", "url", "next", "return", "returnurl", "target",
    # Auth / identity
    "id", "user", "uid", "userid", "username", "role", "admin",
    "email", "login", "password", "pass", "pwd", "token", "session", "otp", "code",
    # Files / paths
    "file", "path", "page", "include", "template", "view",
    # Sorting / filtering
    "sort", "order", "orderby", "filter",
    # Logic related
    "price", "amount", "qty", "quantity", "discount", "coupon", "promo", "plan",
}

SUSPICIOUS_PATH_KEYWORDS = {
    "admin", "debug", "backup", "bak", "test", "beta", "dev",
    "api", "v1", "v2", "internal", "login", "signin", "reset", "forgot",
    "export", "report",
}

FILE_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".rb", ".py", ".pl",
    ".do", ".action",
}

SQL_KEYWORDS = {
    "select", "union", "insert", "update", "delete", "drop", "sleep", "benchmark",
}

XSS_CHARS = {"<", ">", "\"", "'", "`"}
CMDI_CHARS = {";", "&", "|", "$", "`", ">", "<"}

LFI_PATTERNS = [
    "../", "..\\", "/etc/passwd", "C:\\windows", "C:\\Windows", "/windows/",
]

SSTI_MARKERS = ["{{", "}}", "${", "#{", "%{"]

JWT_REGEX = re.compile(r"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$")

# Master list of vuln categories we care about.
MASTER_VULN_CATEGORIES = [
    "Reflected / Stored XSS",
    "SQL Injection",
    "IDOR / access control",
    "Account Takeover / Auth Issues",
    "Brute Force / Rate Limit",
    "LFI/RFI / path traversal",
    "Directory Traversal",
    "SSRF",
    "Open Redirect",
    "Business Logic / Workflow Abuse",
    "CORS Misconfiguration (needs header inspection)",
    "CSV Injection",
    "Command Injection",
    "Remote Code Execution",
    "Server-Side Template Injection (SSTI)",
    "Interesting Paths",
    "Dynamic Endpoint",
    "Potential CVE Mapping (based on category)",
]

# --------- Small helpers ----------

def looks_like_base64(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]{12,}", value))


# --------- Core analysis ----------

def analyze_parameter(name: str, value: str):
    """Return analysis dict for a single parameter (heuristic only)."""
    issues = []
    score = 0

    lname = name.lower()
    lvalue = value.lower()

    # Suspicious names (just boosts score; ALL params are analyzed anyway)
    if lname in SUSPICIOUS_PARAM_NAMES or any(
        k in lname for k in ["id", "file", "url", "redir", "path", "cmd"]
    ):
        score += 2
        issues.append(f"Parameter name '{name}' looks interesting for manual testing.")

    # Potential open redirect
    if any(k in lname for k in ["redirect", "redir", "url", "next", "return"]):
        score += 2
        issues.append(
            "Potential Open Redirect parameter. Try changing to external domains manually."
        )

    # Possible LFI/RFI / directory traversal
    if any(p in value for p in LFI_PATTERNS):
        score += 3
        issues.append(
            "Value looks like it may be used in file inclusion/path traversal (LFI/RFI)."
        )

    # Possible JWT / token
    if JWT_REGEX.match(value):
        score += 2
        issues.append(
            "Value looks like a JWT or token – check for IDOR, tampering, weak signing."
        )

    # Base64-ish content
    if looks_like_base64(value):
        score += 1
        issues.append("Value looks like base64/encoded data – consider decoding and checking content.")

    # SQL keywords
    if any(k in lvalue for k in SQL_KEYWORDS):
        score += 2
        issues.append("Value contains SQL-related keywords – check for SQL injection.")

    # XSS-like chars
    if any(c in value for c in XSS_CHARS):
        score += 2
        issues.append("Value contains characters interesting for XSS or HTML injection.")

    # Command Injection / RCE chars
    if any(c in value for c in CMDI_CHARS):
        score += 2
        issues.append(
            "Value contains shell-special characters – interesting for Command Injection / RCE."
        )

    # CSV Injection
    if value and value[0] in ("=", "+", "-", "@"):
        issues.append(
            "Value starts with =,+,-,@ – check for CSV Injection if exported to spreadsheets."
        )

    # SSTI markers
    if any(m in value for m in SSTI_MARKERS):
        issues.append(
            "Value contains template markers – possible SSTI if rendered in templates."
        )

    category_suggestions = set()

    # IDOR / Account takeover / brute-force / auth-related
    if any(k in lname for k in ["id", "user", "uid"]) or "token" in lname:
        category_suggestions.add("IDOR / access control")

    if any(
        k in lname
        for k in ["email", "login", "password", "pass", "pwd", "otp", "code", "session"]
    ):
        category_suggestions.add("Account Takeover / Auth Issues")
        category_suggestions.add("Brute Force / Rate Limit")

    # LFI / RFI / Directory traversal
    if "file" in lname or "path" in lname or any(p in value for p in LFI_PATTERNS):
        category_suggestions.add("LFI/RFI / path traversal")
        category_suggestions.add("Directory Traversal")

    # XSS
    if any(k in lname for k in ["q", "query", "search", "msg", "comment", "content"]):
        category_suggestions.add("Reflected / Stored XSS")

    # Open redirect
    if any(k in lname for k in ["redirect", "redir", "url", "next", "return"]):
        category_suggestions.add("Open Redirect")

    # SQLi
    if any(k in lvalue for k in SQL_KEYWORDS):
        category_suggestions.add("SQL Injection")

    # SSRF indicators
    if any(
        k in lname
        for k in ["callback", "endpoint", "fetch", "webhook", "target_url", "dest", "host"]
    ):
        category_suggestions.add("SSRF")

    # Business logic
    if any(
        k in lname
        for k in ["price", "amount", "qty", "quantity", "discount", "coupon", "promo", "plan", "role"]
    ):
        category_suggestions.add("Business Logic / Workflow Abuse")

    # Command Injection / RCE
    if any(k in lname for k in ["cmd", "command", "exec", "shell", "ping", "host"]):
        category_suggestions.add("Command Injection")
        category_suggestions.add("Remote Code Execution")

    if any(c in value for c in CMDI_CHARS):
        category_suggestions.add("Command Injection")

    # CSV Injection
    if value and value[0] in ("=", "+", "-", "@"):
        category_suggestions.add("CSV Injection")

    # SSTI
    if any(m in value for m in SSTI_MARKERS) or any(
        k in lname for k in ["template", "view", "format"]
    ):
        category_suggestions.add("Server-Side Template Injection (SSTI)")

    # CVE mapping is generic – added to help mindset
    if category_suggestions:
        category_suggestions.add("Potential CVE Mapping (based on category)")

    return {
        "name": name,
        "value_sample": value[:80],
        "score": score,
        "issues": issues,
        "suggested_tests": sorted(category_suggestions),
    }


def analyze_url(url: str):
    """Analyze a single URL string and return structured findings."""
    findings = {
        "url": url,
        "parsed": {},
        "parameters": [],
        "overall_score": 0,
        "overall_tags": set(),
        "notes": [],
        "vuln_coverage": {},
        "vuln_to_params": {},  # vuln -> list of parameter names
    }

    try:
        parsed = urlparse(url)
    except Exception as e:
        findings["notes"].append(f"Failed to parse URL: {e}")
        return findings

    findings["parsed"] = {
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }

    # Path analysis
    path = (parsed.path or "").lower()

    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if f"/{kw}" in path or path.endswith(kw):
            findings["overall_score"] += 1
            findings["notes"].append(
                f"Path contains '{kw}' – might be interesting (auth/admin/debug/backup/etc)."
            )
            findings["overall_tags"].add("Interesting Paths")

            if kw in ("login", "signin", "reset", "forgot"):
                findings["overall_tags"].add("Account Takeover / Auth Issues")
                findings["overall_tags"].add("Brute Force / Rate Limit")

            if kw == "api":
                findings["overall_tags"].add(
                    "CORS Misconfiguration (needs header inspection)"
                )

    for ext in FILE_EXTENSIONS:
        if path.endswith(ext):
            findings["overall_score"] += 1
            findings["notes"].append(
                f"Path ends with '{ext}' – dynamic page, good candidate for manual testing."
            )
            findings["overall_tags"].add("Dynamic Endpoint")

    # Query parameter analysis (ALL parameters are inspected)
    param_dict = parse_qs(parsed.query, keep_blank_values=True)

    for name, values in param_dict.items():
        for raw_val in values:
            value = unquote(raw_val)
            param_result = analyze_parameter(name, value)
            findings["parameters"].append(param_result)
            findings["overall_score"] += param_result["score"]
            for t in param_result["suggested_tests"]:
                findings["overall_tags"].add(t)

    # Generic reminder for CORS on APIs / subdomains
    host = (parsed.netloc or "").lower()
    if "api." in host or host.startswith("api-"):
        findings["overall_tags"].add("CORS Misconfiguration (needs header inspection)")

    # Build vuln coverage matrix
    coverage = {}
    for cat in MASTER_VULN_CATEGORIES:
        coverage[cat] = cat in findings["overall_tags"]
    findings["vuln_coverage"] = coverage

    # Build vuln -> parameters mapping
    vuln_to_params = {}
    for p in findings["parameters"]:
        pname = p["name"]
        for cat in p["suggested_tests"]:
            if cat not in vuln_to_params:
                vuln_to_params[cat] = set()
            vuln_to_params[cat].add(pname)

    # Convert sets to sorted lists
    findings["vuln_to_params"] = {
        cat: sorted(list(params)) for cat, params in vuln_to_params.items()
    }

    return findings


# --------- Full detailed report (DEFAULT) ----------

def ai_summarize_local(findings, mode: str = "all") -> str:
    """
    Built-in 'AI-style' summary using heuristics.
    Clean, structured, full detail report.
    """
    mode = (mode or "all").lower()
    if mode == "general":
        mode = "all"

    url = findings["url"]
    parsed = findings.get("parsed", {})
    score = findings["overall_score"]
    tags = sorted(findings["overall_tags"])
    vmap = findings.get("vuln_to_params", {})
    coverage = findings.get("vuln_coverage", {})

    # Rough priority
    if score >= 10:
        risk = "HIGH"
    elif score >= 5:
        risk = "MEDIUM"
    elif score > 0:
        risk = "LOW"
    else:
        risk = "VERY LOW"

    lines = []

    # Header
    lines.append(f"URL: {url}")
    lines.append(f"Risk Level : {risk}  (score = {score})")
    lines.append(f"AI Mode    : {mode.upper()}")
    lines.append("")

    # Parsed URL info
    lines.append("[Parsed URL]")
    lines.append(f"  Scheme  : {parsed.get('scheme', '')}")
    lines.append(f"  Host    : {parsed.get('netloc', '')}")
    lines.append(f"  Path    : {parsed.get('path', '')}")
    lines.append(f"  Query   : {parsed.get('query', '')}")
    lines.append(f"  Fragment: {parsed.get('fragment', '')}")
    lines.append("")

    # Vulnerability coverage
    lines.append("[Detected Vulnerability Categories]")
    for cat in MASTER_VULN_CATEGORIES:
        present = coverage.get(cat, False)
        flag = "✓" if present else "·"
        lines.append(f"  {flag} {cat}")
    lines.append("")

    # Vulnerability → parameters
    if vmap:
        lines.append("[Vulnerability → Parameters]")
        for cat in sorted(vmap.keys()):
            params = ", ".join(sorted(set(vmap[cat])))
            lines.append(f"  - {cat}: {params}")
        lines.append("")
    else:
        lines.append("[Vulnerability → Parameters]")
        lines.append("  (no parameters mapped; URL has no query parameters)")
        lines.append("")

    # Mode hint
    mode_help = {
        "all": "Check all categories above. Start with high-impact (ATO, RCE, SQLi) if tags suggest them.",
        "xss": "Target reflected/stored XSS in parameters reflected into HTML or JS contexts.",
        "sqli": "Test integer/string params with quotes, comments, time-based payloads, UNION SELECT.",
        "idor": "Change user/ID parameters to other users/accounts; observe authorization behavior.",
        "lfi": "Try ../, /etc/passwd, Windows paths, log files, wrappers on file/path parameters.",
        "ssrf": "On URL/host params, try internal IPs (127.0.0.1, metadata endpoints).",
        "ato": "Focus on login/reset/OTP flows; weak tokens, session fixation, missing 2FA.",
        "bruteforce": "Check login/OTP endpoints for missing lockout, CAPTCHA, IP rate limit.",
        "logic": "Tamper with price/quantity/discount/plan and state transitions.",
        "cors": "Inspect Access-Control-Allow-* headers via browser/Burp on API endpoints.",
        "csv": "Look at exported CSV reports; leading =,+,-,@ in cells can trigger formula injection.",
        "cmdi": "Look for cmd/host/file parameters; try harmless command chaining first.",
        "rce": "Combine upload + execution, command injection, deserialization, template issues.",
        "ssti": "Look for template markers {{ }}, ${ }; test simple arithmetic payloads.",
        "cves": "Once a bug is confirmed, map framework/version to known CVEs.",
    }
    lines.append("[Testing Focus Hint]")
    lines.append(f"  {mode_help.get(mode, mode_help['all'])}")
    lines.append("")

    # Tags
    if tags:
        lines.append("[Heuristic Tags]")
        for t in tags:
            lines.append(f"  - {t}")
        lines.append("")

    # General notes
    notes = findings.get("notes", [])
    if notes:
        lines.append("[General Notes]")
        for n in notes:
            lines.append(f"  - {n}")
        lines.append("")

    # Parameter details
    params_list = findings.get("parameters", [])
    if params_list:
        lines.append("[Parameter Details (sorted by score)]")
        params_sorted = sorted(params_list, key=lambda p: p["score"], reverse=True)

        def has_sub(slist, substr):
            return any(substr in s for s in slist)

        for p in params_sorted:
            if p["score"] == 0:
                continue

            sug = p["suggested_tests"]
            pname = p["name"]
            pscore = p["score"]

            mode_mark = ""
            if mode == "xss" and has_sub(sug, "XSS"):
                mode_mark = " [XSS-focus]"
            elif mode == "sqli" and has_sub(sug, "SQL Injection"):
                mode_mark = " [SQLi-focus]"
            elif mode == "idor" and has_sub(sug, "IDOR"):
                mode_mark = " [IDOR-focus]"
            elif mode == "lfi" and (has_sub(sug, "LFI") or has_sub(sug, "Directory Traversal")):
                mode_mark = " [LFI-focus]"
            elif mode == "ssrf" and has_sub(sug, "SSRF"):
                mode_mark = " [SSRF-focus]"
            elif mode == "ato" and has_sub(sug, "Account Takeover"):
                mode_mark = " [ATO-focus]"
            elif mode == "bruteforce" and has_sub(sug, "Brute Force"):
                mode_mark = " [Bruteforce-focus]"
            elif mode == "logic" and has_sub(sug, "Business Logic"):
                mode_mark = " [Logic-focus]"
            elif mode == "csv" and has_sub(sug, "CSV Injection"):
                mode_mark = " [CSV-focus]"
            elif mode == "cmdi" and has_sub(sug, "Command Injection"):
                mode_mark = " [CMDi-focus]"
            elif mode == "rce" and has_sub(sug, "Remote Code Execution"):
                mode_mark = " [RCE-focus]"
            elif mode == "ssti" and has_sub(sug, "Server-Side Template Injection"):
                mode_mark = " [SSTI-focus]"
            elif mode == "cves" and has_sub(sug, "Potential CVE Mapping"):
                mode_mark = " [CVE-relevant]"

            lines.append(f"  Param : {pname}{mode_mark}")
            lines.append(f"    Score          : {pscore}")
            if sug:
                lines.append(f"    Suggested tests: {', '.join(sug)}")
            if p["issues"]:
                lines.append("    Notes:")
                for issue in p["issues"]:
                    lines.append(f"      - {issue}")
            lines.append(f"    Sample value   : {p['value_sample']}")
            lines.append("")
    else:
        lines.append("[Parameter Details]")
        lines.append("  No query parameters to analyze.")
        lines.append("")

    return "\n".join(lines)


# --------- PoC-style output (optional via --poc) ----------

def ai_generate_poc(findings, mode: str = "all") -> str:
    """
    Generate a Proof-of-Concept friendly report format:
    - Per-vulnerability sections (example requests/responses)
    - Final PoC block can include REAL response snippet if --live was used
    """
    mode = (mode or "all").lower()
    url = findings["url"]
    parsed = findings.get("parsed", {})
    tags = sorted(findings["overall_tags"])
    vmap = findings.get("vuln_to_params", {})
    live = findings.get("live_response")
    live_err = findings.get("live_error")

    host = parsed.get("netloc") or "target.com"
    path = parsed.get("path") or "/"
    original_query = parsed.get("query") or ""
    param_dict = parse_qs(original_query, keep_blank_values=True)

    def build_request_template(param_name: str, extra_headers=None):
        """
        Build an HTTP GET request template where param_name is replaced by <PAYLOAD>.
        """
        extra_headers = extra_headers or []
        other_params = [k for k in param_dict.keys() if k != param_name]
        if original_query:
            if other_params:
                others = "&".join(f"{k}={param_dict[k][0]}" for k in other_params)
                query = f"{param_name}=<PAYLOAD>&{others}"
            else:
                query = f"{param_name}=<PAYLOAD>"
        else:
            query = f"{param_name}=<PAYLOAD>"

        req_lines = [
            f"GET {path}?{query} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: <your user agent>",
            "Cookie: session=<redacted>",
        ]
        req_lines.extend(extra_headers)
        return req_lines

    def build_simple_request(extra_headers=None):
        """Request template when there is no obvious parameter."""
        extra_headers = extra_headers or []
        req_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: <your user agent>",
            "Cookie: session=<redacted>",
        ]
        req_lines.extend(extra_headers)
        return req_lines

    # Vulnerability definitions for PoC – with example responses
    VULN_POC_DEFS = [
        {
            "tag": "Reflected / Stored XSS",
            "title": "Cross-Site Scripting (XSS)",
            "impact": "Client-side code execution, session hijacking, account takeover, defacement.",
            "payloads": [
                '<script>alert(1)</script>',
                '"><svg/onload=alert(1)>',
                '\'><img src=x onerror=alert(1)>',
            ],
            "observation": [
                "Injected payload appears in HTML response without encoding.",
                "JavaScript alert or code execution in victim browser.",
                "Payload persists across page loads (stored XSS).",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: text/html; charset=utf-8",
                "",
                "<html>",
                "  <body>",
                "    <div>Welcome back, <script>alert(1)</script></div>",
                "  </body>",
                "</html>",
            ],
        },
        {
            "tag": "SQL Injection",
            "title": "SQL Injection (SQLi)",
            "impact": "Database extraction, modification, or complete compromise.",
            "payloads": [
                "' OR 1=1 --",
                "' OR 'a'='a' --",
                "'; WAITFOR DELAY '0:0:5' --",
            ],
            "observation": [
                "SQL error messages in response.",
                "Time delay when using time-based payloads.",
                "Data from other users or tables being returned.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 500 Internal Server Error",
                "Content-Type: text/html; charset=utf-8",
                "",
                "<html>",
                "  <body>",
                "    <h1>Database Error</h1>",
                "    <p>You have an error in your SQL syntax; check the manual...</p>",
                "  </body>",
                "</html>",
            ],
        },
        {
            "tag": "Command Injection",
            "title": "OS Command Injection",
            "impact": "Execution of arbitrary operating system commands on the server.",
            "payloads": [
                "test;whoami",
                "test|id",
                "127.0.0.1 && ping -c 1 127.0.0.1",
            ],
            "observation": [
                "Command output appears in response.",
                "Timing/delay changes when using ping/sleep commands.",
                "Side effects on system (files created, DNS queries, etc.).",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: text/plain; charset=utf-8",
                "",
                "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            ],
        },
        {
            "tag": "Remote Code Execution",
            "title": "Remote Code Execution (RCE)",
            "impact": "Full compromise of the underlying server or application runtime.",
            "payloads": [
                "test;php -r 'phpinfo();'",
                "test && cat /etc/passwd",
            ],
            "observation": [
                "Arbitrary code output in response.",
                "Access to sensitive system files.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: text/plain; charset=utf-8",
                "",
                "root:x:0:0:root:/root:/bin/bash",
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            ],
        },
        {
            "tag": "Server-Side Template Injection (SSTI)",
            "title": "Server-Side Template Injection (SSTI)",
            "impact": "Server-side template evaluation leading to data exfiltration or RCE.",
            "payloads": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
            ],
            "observation": [
                "Template payload evaluated (e.g., response shows '49').",
                "Ability to access server variables or execute code via templates.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: text/html; charset=utf-8",
                "",
                "<html>",
                "  <body>",
                "    <div>Result: 49</div>",
                "  </body>",
                "</html>",
            ],
        },
        {
            "tag": "SSRF",
            "title": "Server-Side Request Forgery (SSRF)",
            "impact": "Access to internal services, cloud metadata, or other restricted endpoints.",
            "payloads": [
                "http://127.0.0.1:80",
                "http://localhost/admin",
                "http://169.254.169.254/latest/meta-data/",
            ],
            "observation": [
                "Different responses for internal vs external targets.",
                "Metadata or admin pages returned in response.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: application/json",
                "",
                '{"ami-id": "ami-1234567890abcdef0", "instance-id": "i-0123456789abcdef0"}',
            ],
        },
        {
            "tag": "LFI/RFI / path traversal",
            "title": "Local/Remote File Inclusion / Path Traversal",
            "impact": "Read arbitrary files, potentially execute code via included files.",
            "payloads": [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
            ],
            "observation": [
                "Contents of system or application files in response.",
                "Error messages indicating file system access.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: text/plain; charset=utf-8",
                "",
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            ],
        },
        {
            "tag": "Directory Traversal",
            "title": "Directory Traversal",
            "impact": "Read files outside the intended directory.",
            "payloads": [
                "../etc/passwd",
                "../../../../../var/log/auth.log",
            ],
            "observation": [
                "Unexpected file contents returned.",
                "Path traversal indicators in logs or errors.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: text/plain; charset=utf-8",
                "",
                "root:x:0:0:root:/root:/bin/bash",
            ],
        },
        {
            "tag": "CSV Injection",
            "title": "CSV / Formula Injection",
            "impact": "Code execution when exported CSV is opened in spreadsheet software.",
            "payloads": [
                '=2+3',
                '=CMD|\' /C calc\'!A0',
                '@SUM(1+1)',
            ],
            "observation": [
                "Formula executes when CSV is opened in Excel/LibreOffice.",
                "Potential to run arbitrary commands via formula injection.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: text/csv; charset=utf-8",
                "",
                "id,name,comment",
                '1,admin,"=CMD|\' /C calc\'!A0"',
            ],
        },
        {
            "tag": "IDOR / access control",
            "title": "Insecure Direct Object Reference (IDOR)",
            "impact": "Unauthorized access to other users' data or actions.",
            "payloads": [
                "<CHANGE-ID-TO-OTHER-USER>",
            ],
            "observation": [
                "Access to resources belonging to other users/tenants.",
                "No authorization checks on object identifiers.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: application/json",
                "",
                '{"user_id": 2, "email": "victim@example.com", "role": "user"}',
            ],
        },
        {
            "tag": "Account Takeover / Auth Issues",
            "title": "Account Takeover / Authentication Issues",
            "impact": "Unauthorized access to victim accounts.",
            "payloads": [
                "<REUSE-PASSWORD-RESET-LINK>",
                "<BRUTEFORCE-OTP-CODES>",
            ],
            "observation": [
                "Ability to log in as another user.",
                "Missing verification on password reset or email change flows.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 302 Found",
                "Location: /dashboard",
                "",
                "<!-- User logged in as victim@example.com -->",
            ],
        },
        {
            "tag": "Brute Force / Rate Limit",
            "title": "Brute Force / Rate Limiting Issues",
            "impact": "Automated guessing of passwords, OTPs, or tokens.",
            "payloads": [
                "<MULTIPLE-PASSWORD-ATTEMPTS>",
                "<SEQUENTIAL-OTP-ATTEMPTS>",
            ],
            "observation": [
                "No lockout or rate limiting on repeated attempts.",
                "Predictable OTP/token behavior.",
            ],
            "extra_headers": [],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: application/json",
                "",
                '{"message": "Invalid password"}',
                "<!-- No CAPTCHA, no lockout, unlimited attempts allowed -->",
            ],
        },
        {
            "tag": "CORS Misconfiguration (needs header inspection)",
            "title": "CORS Misconfiguration",
            "impact": (
                "An attacker-controlled origin may be able to read responses from this API "
                "in a victim's browser, leading to data theft or account compromise."
            ),
            "payloads": [
                "Origin: https://attacker.com",
                "Origin: https://evil.example",
            ],
            "observation": [
                "Access-Control-Allow-Origin reflects the attacker Origin or uses '*'.",
                "Access-Control-Allow-Credentials: true is present.",
                "Sensitive data is returned to cross-origin JavaScript.",
            ],
            "extra_headers": [
                "Origin: https://attacker.com",
            ],
            "example_response": [
                "HTTP/1.1 200 OK",
                "Content-Type: application/json",
                "Access-Control-Allow-Origin: https://attacker.com",
                "Access-Control-Allow-Credentials: true",
                "",
                '{"email": "victim@example.com", "balance": 1200}',
            ],
        },
    ]

    lines = []
    lines.append("=" * 30)
    lines.append("PROOF OF CONCEPT (PoC) REPORT")
    lines.append("=" * 30)
    lines.append("")
    lines.append("Target URL:")
    lines.append(f"  {url}")
    lines.append("")
    lines.append("Overview:")
    lines.append("  This is a static, heuristic analysis of the URL and its parameters.")
    if live:
        lines.append("  --live was used: response snippet below is REAL data from the target.")
    else:
        lines.append("  Use the payloads and templates below to manually verify vulnerabilities.")
    lines.append("")
    lines.append("Detected Vulnerability Categories (heuristic):")
    if tags:
        for t in tags:
            lines.append(f"  - {t}")
    else:
        lines.append("  - None strongly indicated (further manual testing required).")
    lines.append("")

    # Per-vulnerability sections
    section_idx = 1
    primary_vuln_def = None
    for vuln_def in VULN_POC_DEFS:
        tag = vuln_def["tag"]
        if tag not in tags:
            continue

        if primary_vuln_def is None:
            primary_vuln_def = vuln_def  # first vuln used for final Impact template

        params = vmap.get(tag, [])
        lines.append("-" * 60)
        lines.append(f"{section_idx}. {vuln_def['title']}")
        section_idx += 1
        lines.append("   Impact:")
        lines.append(f"     {vuln_def['impact']}")
        lines.append("")

        if params:
            lines.append(f"   Affected parameter(s): {', '.join(params)}")
        else:
            lines.append("   Affected parameter(s): Not clearly mapped (review manually).")
        lines.append("")

        # Payloads
        if vuln_def["payloads"]:
            lines.append("   Test Payloads / Headers:")
            for pld in vuln_def["payloads"]:
                lines.append(f"     - {pld}")
            lines.append("")

        # Example HTTP request
        extra_headers = vuln_def.get("extra_headers") or []
        example_param = params[0] if params else None
        lines.append("   Example HTTP Request (template):")
        if example_param:
            tmpl = build_request_template(example_param, extra_headers=extra_headers)
        else:
            tmpl = build_simple_request(extra_headers=extra_headers)
        for l in tmpl:
            lines.append(f"     {l}")
        lines.append("")

        # Example vulnerable response (still illustrative)
        lines.append("   Example Vulnerable Response (illustrative):")
        ex_resp = vuln_def.get("example_response")
        if ex_resp:
            for l in ex_resp:
                lines.append(f"     {l}")
        else:
            lines.append("     HTTP/1.1 200 OK")
            lines.append("     <application-specific body / headers here>")
        lines.append("")

        # Observation checklist
        obs = vuln_def.get("observation") or []
        if obs:
            lines.append("   Observation Checklist:")
            for o in obs:
                lines.append(f"     - {o}")
            lines.append("")

        lines.append("   Generic Manual Steps:")
        lines.append("     1. Intercept the request in Burp/ZAP or similar proxy.")
        lines.append("     2. Replace the affected parameter or header with one of the test payloads.")
        lines.append("     3. Send the request and carefully inspect the response.")
        lines.append("     4. Adjust encoding (URL, HTML, double encoding) as needed.")
        lines.append("     5. Capture screenshots / response diffs as PoC evidence.")
        lines.append("")

    if section_idx == 1:
        lines.append("No high-confidence vulnerability categories were mapped.")
        lines.append("You should still manually review:")
        lines.append("  - Authentication and authorization flows (IDOR, ATO).")
        lines.append("  - Input handling for XSS/SQLi/Command Injection.")
        lines.append("  - File/path parameters for LFI/RFI.")
        lines.append("")

    # Final PoC boilerplate – now with real response snippet if available
    lines.append("-" * 60)
    lines.append("PoC Evidence Template")
    lines.append("-" * 60)
    lines.append("")
    lines.append("Request (example to paste and adjust):")
    base_req = build_simple_request()
    for l in base_req:
        lines.append(f"  {l}")
    lines.append("")

    if live:
        lines.append("Response (REAL snippet from --live):")
        lines.append(f"  {live.get('status', 'HTTP/1.1 ? ?')}")
        headers = live.get("headers", {})
        # show first few headers
        for k, v in list(headers.items())[:8]:
            lines.append(f"  {k}: {v}")
        body_snip = (live.get("body_snippet") or "").splitlines()
        if body_snip:
            lines.append("")
            for ln in body_snip[:10]:
                lines.append(f"  {ln}")
        else:
            lines.append("")
            lines.append("  <no body or empty response>")
    elif live_err:
        lines.append("Response:")
        lines.append(f"  (live fetch failed) {live_err}")
    else:
        lines.append("Response (example format):")
        lines.append("  HTTP/1.1 200 OK")
        lines.append("  <body / headers showing the vulnerability, based on the relevant section above>")
    lines.append("")
    lines.append("Impact (to describe in your own words):")
    if primary_vuln_def:
        lines.append(f"  {primary_vuln_def['impact']}")
    else:
        lines.append("  Potential impact depends on confirmed vulnerability (data theft, account takeover, RCE, etc.).")
    lines.append("")
    lines.append("Recommended Remediation:")
    lines.append("  - Validate and sanitize all user inputs.")
    lines.append("  - Use context-aware output encoding (HTML/JS/JSON).")
    lines.append("  - Use parameterized queries for database access where applicable.")
    lines.append("  - Enforce strict authorization checks for sensitive objects and actions.")
    lines.append("  - Apply rate limiting and lockout for authentication endpoints.")
    if any("CORS Misconfiguration" in t for t in tags):
        lines.append("  - Do not use wildcard CORS policies; restrict Access-Control-Allow-Origin to trusted domains.")
        lines.append("  - Avoid Access-Control-Allow-Credentials unless strictly necessary.")
    lines.append("")
    return "\n".join(lines)


# --------- AI summarizers (for non-local backends, still full format) ----------

def ai_summarize_openai(findings, mode: str, model: str = "gpt-4o-mini") -> str:
    """
    Example integration for ChatGPT / OpenAI.
    - Requires: pip install openai
    - Uses environment variable OPENAI_API_KEY
    If anything fails, we fall back to local summarizer.
    """
    try:
        import os
        from openai import OpenAI

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return "[openai] OPENAI_API_KEY not set. Falling back to local heuristic.\n\n" + \
                   ai_summarize_local(findings, mode)

        client = OpenAI(api_key=api_key)

        prompt = (
            "You are an expert web application security assistant.\n"
            "Given the following static URL analysis JSON and a focus mode, "
            "produce a concise, structured manual testing plan.\n\n"
            f"Focus mode: {mode}\n\n"
            "JSON:\n"
            f"{json.dumps(findings, indent=2)}\n\n"
            "Respond with:\n"
            "- Overall risk and priority\n"
            "- Key vulnerability types likely (from the coverage matrix)\n"
            "- Top parameters/paths to test and how\n"
            "- Short checklist of manual tests to perform.\n"
        )

        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful, concise web security testing assistant."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return resp.choices[0].message.content.strip()

    except Exception as e:
        return f"[openai] Error: {e}. Falling back to local heuristic.\n\n" + \
               ai_summarize_local(findings, mode)


def ai_summarize_custom(findings, mode: str, endpoint: str, model: str = None) -> str:
    """
    Generic hook for ANY other AI tool (Ollama, local LLM, Hugging Face, etc.).
    - You implement the HTTP call as per your stack.
    - For now we just explain and fall back to local.
    """
    info = (
        "[custom AI backend]\n"
        f"Endpoint: {endpoint or 'N/A'}\n"
        f"Model: {model or 'N/A'}\n"
        "You can wire this function to your own LLM HTTP API (edit ai_summarize_custom).\n\n"
    )
    return info + ai_summarize_local(findings, mode)


def ai_summarize_router(findings, mode: str, backend: str, model: str, endpoint: str) -> str:
    backend = (backend or "local").lower()
    if backend == "openai":
        return ai_summarize_openai(findings, mode, model or "gpt-4o-mini")
    elif backend == "custom":
        return ai_summarize_custom(findings, mode, endpoint, model)
    else:
        return ai_summarize_local(findings, mode)


# --------- LIVE HTTP FETCH (for real PoC data) ----------

def fetch_real_response(url: str):
    """
    Perform a real GET request to the URL.
    Returns (live_dict, error_string_or_None)
    live_dict has: status, headers, body_snippet
    """
    try:
        import requests
    except ImportError:
        return None, "requests library not installed (pip install requests)"

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True)
    except Exception as e:
        return None, f"HTTP error: {e}"

    status_line = f"HTTP/1.1 {resp.status_code} {resp.reason or ''}".strip()
    headers = dict(resp.headers)
    try:
        text = resp.text
    except Exception:
        text = ""
    body_snippet = text[:800]  # first 800 chars

    return {
        "status": status_line,
        "headers": headers,
        "body_snippet": body_snippet,
    }, None


# --------- CLI main ----------

def main():
    parser = argparse.ArgumentParser(
        prog="ai_url_vuln_assistant",
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "AI-style URL vulnerability helper (manual testing assistant)\n"
            "\n"
            "Static analysis ONLY by default (no exploitation).\n"
            "Optionally, use --live to perform a real GET and include actual\n"
            "response snippet in the PoC evidence block.\n"
            "Default output is full detailed report; use --poc for PoC-style."
        ),
        epilog=(
            "Examples:\n"
            "  Full detailed report on a single URL (default):\n"
            "    ai_url_vuln_assistant.py -u \"https://example.com/?id=1&q=test\"\n"
            "\n"
            "  PoC-style output for bug reports:\n"
            "    ai_url_vuln_assistant.py -u \"https://example.com/?id=1&q=test\" --poc\n"
            "\n"
            "  PoC with REAL response data:\n"
            "    ai_url_vuln_assistant.py -u \"https://api-user.e2ro.com/robots.txt\" --poc --live\n"
            "\n"
            "  File with URLs, XSS mode, 20 threads, 5 URLs/sec:\n"
            "    ai_url_vuln_assistant.py -f urls.txt --ai-mode xss -t 20 -r 5 -o report.txt\n"
        ),
    )

    parser.add_argument(
        "-u", "--url",
        help="Single URL to analyze (e.g. https://example.com/?id=1&q=test)",
    )
    parser.add_argument(
        "-f", "--file",
        help="File with one URL per line",
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output full JSON instead of text",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file to save report (txt for normal, json for -j)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Max concurrent analysis threads (default: 10)",
    )
    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=0.0,
        help=(
            "Max URLs per second (default: 0 = unlimited)\n"
            "Use this if you feed it a LOT of URLs and want to slow it down."
        ),
    )
    parser.add_argument(
        "--ai-mode",
        choices=[
            "all", "general", "xss", "sqli", "idor", "lfi", "ssrf",
            "ato", "bruteforce", "logic", "cors", "csv",
            "cmdi", "rce", "ssti", "cves",
        ],
        default="all",
        help=(
            "AI focus mode / vuln lens (one of):\n"
            "  all         - DEFAULT: consider ALL vulnerability types together\n"
            "  general     - alias of 'all' (balanced view)\n"
            "  xss         - Cross-Site Scripting\n"
            "  sqli        - SQL Injection\n"
            "  idor        - Insecure Direct Object Reference / access control\n"
            "  lfi         - LFI / RFI / Directory Traversal\n"
            "  ssrf        - Server-Side Request Forgery\n"
            "  ato         - Account Takeover (login/reset/OTP flows)\n"
            "  bruteforce  - Brute Force / Rate Limit issues\n"
            "  logic       - Business Logic / workflow abuse\n"
            "  cors        - CORS Misconfiguration (header review)\n"
            "  csv         - CSV/Formula Injection\n"
            "  cmdi        - Command Injection\n"
            "  rce         - Remote Code Execution\n"
            "  ssti        - Server-Side Template Injection\n"
            "  cves        - Mindset for mapping to CVEs\n"
        ),
    )
    parser.add_argument(
        "--all-vulns",
        action="store_true",
        help="Shortcut: force ai-mode to 'all' (scan for ALL vulnerability categories).",
    )
    parser.add_argument(
        "--ai-backend",
        choices=["local", "openai", "custom"],
        default="local",
        help=(
            "Which AI tool to use for the detailed summary (full report):\n"
            "  local  - built-in heuristic summarizer (no network, default)\n"
            "  openai - ChatGPT / OpenAI API (needs OPENAI_API_KEY env var)\n"
            "  custom - your own HTTP endpoint (wire up in ai_summarize_custom)\n"
        ),
    )
    parser.add_argument(
        "--ai-model",
        help=(
            "Model name for openai/custom backends.\n"
            "Examples:\n"
            "  --ai-backend openai --ai-model gpt-4o-mini\n"
            "  --ai-backend custom --ai-model my-llm-name"
        ),
    )
    parser.add_argument(
        "--ai-endpoint",
        help=(
            "Custom AI HTTP endpoint URL (for --ai-backend custom).\n"
            "Example:\n"
            "  --ai-backend custom --ai-endpoint http://localhost:11434/api/chat"
        ),
    )
    parser.add_argument(
        "--poc",
        action="store_true",
        help="Use PoC-style output instead of full detailed report.",
    )
    parser.add_argument(
        "--live", "--live-poc",
        dest="live",
        action="store_true",
        help=(
            "Perform a REAL HTTP GET to each URL and include actual response snippet\n"
            "in the PoC evidence block. Use ONLY on targets you are authorized to test.\n"
            "Requires: pip install requests"
        ),
    )

    args = parser.parse_args()

    # If user explicitly says --all-vulns, force ai-mode to 'all'
    if args.all_vulns:
        args.ai_mode = "all"

    urls = []

    if args.url:
        urls.append(args.url.strip())

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        urls.append(line)
        except OSError as e:
            print(f"[!] Failed to read file: {e}")
            return

    if not urls:
        print("No URL provided. Use -u <url> or -f <file>.\n")
        parser.print_help()
        return

    # Simple rate limiter
    rate_lock = threading.Lock()
    last_time = [0.0]

    def rate_limited():
        if args.rate and args.rate > 0:
            with rate_lock:
                now = time.time()
                min_interval = 1.0 / args.rate
                if last_time[0] == 0.0:
                    last_time[0] = now
                    return
                elapsed = now - last_time[0]
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                    now = time.time()
                last_time[0] = now

    def process_url(u: str):
        rate_limited()
        findings = analyze_url(u)

        # Optional live HTTP fetch for real response snippet
        if args.live:
            live, err = fetch_real_response(u)
            if live:
                findings["live_response"] = live
            if err:
                findings["live_error"] = err

        if args.poc:
            summary = ai_generate_poc(findings, args.ai_mode)
        else:
            summary = ai_summarize_router(
                findings=findings,
                mode=args.ai_mode,
                backend=args.ai_backend,
                model=args.ai_model,
                endpoint=args.ai_endpoint,
            )
        return findings, summary

    results = []
    output_text_chunks = []

    if args.json:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(process_url, u): u for u in urls}
            for fut in as_completed(futures):
                findings, _summary = fut.result()
                results.append(findings)

        json_output = json.dumps(results, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"[+] JSON saved to {args.output}")
        else:
            print(json_output)
        return

    # Human-readable text mode
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_url, u): u for u in urls}
        first = True
        for fut in as_completed(futures):
            findings, summary = fut.result()
            results.append(findings)
            if not first:
                print("=" * 80)
            first = False
            print(summary)
            print()
            output_text_chunks.append("=" * 80 + "\n" + summary + "\n")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.writelines(output_text_chunks)
            print(f"[+] Output saved to '{args.output}'")
        except OSError as e:
            print(f"[!] Failed to write output file: {e}")


if __name__ == "__main__":
    main()

