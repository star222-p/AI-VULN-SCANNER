# AI URL Vulnerability Assistant

AI-style **URL vulnerability helper** for **manual security testing** and **bug bounty research**.

This tool performs **static analysis of URLs and parameters** and suggests possible vulnerability categories such as:

- XSS
- SQL Injection
- IDOR
- SSRF
- LFI / Path Traversal
- Command Injection
- RCE
- Business Logic issues
- CORS Misconfiguration
- CSV Injection
- SSTI

⚠️ This tool **does NOT exploit vulnerabilities**.  
It only helps researchers **identify potential testing areas**.

---

# Features

✔ Static URL vulnerability analysis  
✔ Parameter risk scoring  
✔ Vulnerability category suggestions  
✔ Manual testing hints  
✔ PoC report generator  
✔ Optional **live HTTP response capture**  
✔ Multi-threaded URL processing  
✔ JSON export support  
✔ AI-assisted summaries (OpenAI or custom LLM)  
✔ Works with **single URLs or large URL lists**

---

# Supported Vulnerability Categories

The tool maps parameters and paths to possible security tests.

- Reflected / Stored XSS
- SQL Injection
- IDOR / Access Control
- Account Takeover
- Brute Force / Rate Limit
- LFI / RFI
- Directory Traversal
- SSRF
- Open Redirect
- Business Logic flaws
- Command Injection
- Remote Code Execution
- CSV Injection
- Server Side Template Injection
- CORS Misconfiguration
- Interesting Paths
- Dynamic Endpoints
- CVE Mapping hints

---

# Installation

Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ai-url-vuln-assistant.git
cd ai-url-vuln-assistant
```

Install dependencies

```bash
pip install requests
```

Optional (if using OpenAI backend)

```bash
pip install openai
```

---

# Basic Usage

Analyze a single URL

```bash
python ai_url_vuln_assistant.py -u "https://example.com/?id=1&q=test"
```

---

# Scan URLs from File

```bash
python ai_url_vuln_assistant.py -f urls.txt
```

Example `urls.txt`

```
https://example.com/?id=1
https://test.com/search?q=test
https://api.example.com/user?id=5
```

---

# Generate PoC Style Output

Useful for **bug bounty reports**

```bash
python ai_url_vuln_assistant.py -u "https://example.com/?id=1&q=test" --poc
```

---

# Capture Real Response (Live Mode)

Fetches a real HTTP response snippet and includes it in the report.

```bash
python ai_url_vuln_assistant.py -u "https://example.com/test?id=1" --poc --live
```

⚠ Only use **--live on targets you are authorized to test**

---

# AI Focus Modes

You can focus testing on specific vulnerabilities.

```
--ai-mode xss
--ai-mode sqli
--ai-mode idor
--ai-mode lfi
--ai-mode ssrf
--ai-mode ato
--ai-mode bruteforce
--ai-mode logic
--ai-mode cors
--ai-mode csv
--ai-mode cmdi
--ai-mode rce
--ai-mode ssti
--ai-mode cves
```

Example

```bash
python ai_url_vuln_assistant.py -u "https://example.com/?q=test" --ai-mode xss
```

---

# Scan for All Vulnerabilities

```bash
python ai_url_vuln_assistant.py -u "https://example.com/?id=1&q=test" --all-vulns
```

---

# Multi-threaded Scanning

```bash
python ai_url_vuln_assistant.py -f urls.txt -t 20
```

---

# Rate Limiting

Useful when scanning large URL lists.

```bash
python ai_url_vuln_assistant.py -f urls.txt -r 5
```

Meaning **5 URLs per second**

---

# Save Output

Save report to file

```bash
python ai_url_vuln_assistant.py -f urls.txt -o report.txt
```

---

# JSON Output

```bash
python ai_url_vuln_assistant.py -f urls.txt -j
```

Save JSON output

```bash
python ai_url_vuln_assistant.py -f urls.txt -j -o report.json
```

---

# AI Backend Support

The tool supports multiple AI backends.

## Local (Default)

Uses internal heuristic analysis.

```
--ai-backend local
```

---

## OpenAI

Requires API key.

```bash
export OPENAI_API_KEY=your_api_key
```

Run:

```bash
python ai_url_vuln_assistant.py -u "https://example.com/?id=1" --ai-backend openai
```

---

## Custom AI (Local LLM / Ollama)

```bash
python ai_url_vuln_assistant.py \
--ai-backend custom \
--ai-endpoint http://localhost:11434/api/chat
```

---

# Example Output

```
URL: https://example.com/?id=1&q=test
Risk Level: MEDIUM (score=6)

Detected Vulnerability Categories

✓ SQL Injection
✓ Reflected XSS
✓ IDOR
✓ Open Redirect
```

The report also includes:

- parameter analysis
- vulnerability mapping
- manual testing checklist
- PoC request templates

---

# Use Cases

Bug bounty hunters  
Security researchers  
Penetration testers  
Security analysts  
CTF players  

This tool helps **prioritize manual testing** and identify **high-risk parameters quickly**.

---

# Disclaimer

This tool is intended for **educational and authorized security testing only**.

Do not use it against systems without **explicit permission**.

The author is **not responsible for misuse**.

---

# Author

Security Research Tool  
Built for **Bug Bounty & Manual Testing Workflow**
