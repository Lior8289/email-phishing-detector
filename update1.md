# Update 1 — Gap Analysis & Required Changes

## Summary

Compared your repo against the Part 1 assignment requirements. Your foundation (FastAPI + ML + rules + Gmail add-on) is solid, but several areas explicitly mentioned in the assignment are missing or incomplete. Below is everything you need to fix/add, ordered by priority.

---

## CRITICAL — Must Fix

### 1. Add Email Header Analysis (SPF, DKIM, DMARC)

**Why:** The assignment explicitly says "Analyzing email content, **headers**, metadata." For a phishing detector at a security company, header authentication is the #1 real-world signal. Not having it is a glaring gap.

**What to do:**
- In `Code.gs`, use `msg.getRawContent()` to extract raw email headers
- Parse `Received-SPF`, `Authentication-Results`, and `DKIM-Signature` headers
- Send these headers to the backend as a new field (e.g., `headers: { spf: "pass", dkim: "fail", dmarc: "none" }`)
- In `rules.py`, add rules that trigger on:
  - SPF fail/softfail → severity 6
  - DKIM fail → severity 7
  - DMARC fail/none → severity 5
  - Mismatch between `From:` header and `Return-Path` → severity 8
- Update `ScanRequest` schema to accept optional `raw_headers` or structured header fields

### 2. Add External Reputation Enrichment

**Why:** Assignment explicitly says "Enriching your analysis with external reputation or intelligence data." Currently you have zero external lookups.

**What to do (pick at least 1-2):**
- **Google Safe Browsing API** — Check extracted URLs against Google's threat database. Free tier available. This is the easiest win.
- **VirusTotal API** — Check URLs/domains. Free tier = 4 req/min.
- **DNS-based checks** — Check if sender domain has valid MX records, check domain age via WHOIS (python-whois library)
- Add results to the scan response (e.g., `"external_checks": [{"source": "safe_browsing", "result": "malicious", "url": "..."}]`)
- Even if you just do a basic DNS MX check, that shows you understand enrichment

### 3. Gmail Add-on: Missing "Suspicious" Verdict

**Bug in `Code.gs` line 112-113:**
```javascript
var isPhishing = (String(data.classification || "")).toLowerCase().indexOf("phish") >= 0;
var label = isPhishing ? "⚠️ PHISHING" : "✅ SAFE";
```
This maps both "Safe" AND "Suspicious" to "✅ SAFE". Fix:
```javascript
var cls = String(data.classification || "").toLowerCase();
var label;
if (cls.indexOf("phish") >= 0) label = "⚠️ PHISHING";
else if (cls.indexOf("suspicious") >= 0) label = "⚠️ SUSPICIOUS";
else label = "✅ SAFE";
```

---

## HIGH PRIORITY — Should Add

### 4. Personal Blocklist / Whitelist

**Why:** Assignment explicitly says "Providing users with controls such as personal blocklists or configuration options."

**What to do:**
- Add endpoints: `POST /blocklist` (add domain/email), `GET /blocklist`, `DELETE /blocklist/{id}`
- Store in a simple JSON file or SQLite DB
- In the scan logic, check if sender domain is in the blocklist → auto-flag as Phishing (severity 10)
- In the Gmail add-on, add a "Block Sender" button on the result card
- For the whitelist: if sender domain matches, reduce score or skip rules
- Even a simple in-memory dict with a note about persistence would show the concept

### 5. Scan History

**Why:** Assignment explicitly says "Tracking scan history for context."

**What to do:**
- Add a SQLite database (or even a JSON file) to store scan results with timestamps
- Endpoint: `GET /history` — returns recent scans
- Endpoint: `GET /history/stats` — returns aggregate stats (e.g., "5 phishing emails detected this week")
- Add a "History" section to the web UI or a separate page
- In the Gmail add-on, you could show "This sender was flagged 3 times before" as contextual info
- This also demonstrates you understand the value of threat intelligence over time

### 6. Attachment Analysis

**Why:** Assignment says "Analyzing email content, headers, metadata, and **attachments**."

**What to do:**
- In `Code.gs`, use `msg.getAttachments()` to get attachment metadata
- Send attachment info (filename, MIME type, size) to the backend
- In `rules.py`, add rules for:
  - Executable extensions (.exe, .scr, .bat, .ps1, .vbs, .js) → severity 8
  - Double extensions (e.g., `invoice.pdf.exe`) → severity 9
  - Password-protected archives (.zip with "password" in body) → severity 6
  - Macro-enabled Office files (.docm, .xlsm) → severity 5
- You don't need to actually scan file contents — metadata analysis is enough to demonstrate the concept

---

## MEDIUM PRIORITY — Should Improve

### 7. Unused Dependencies

`requirements.txt` includes `tldextract` and `beautifulsoup4` but neither is imported or used anywhere. Either:
- Remove them (cleaner), or
- Actually use them: `tldextract` is perfect for domain analysis in `rules.py`, and `beautifulsoup4` could parse HTML email bodies

### 8. Tests Are Too Minimal

Only 2 tests (`test_health` and `test_scan`). Add tests for:
- Each major rule category (typosquatting, urgency, scam phrases, etc.)
- Edge cases (empty body, very long body, unicode characters)
- The `combine()` function with various ML/rules score combinations
- Blocklist/whitelist if you add them
- At least 8-10 tests to show you take testing seriously

### 9. README Improvements

The README is decent but should also include:
- **Architecture diagram** — even a simple text-based one showing: `Gmail → Apps Script → FastAPI → [Rules Engine + ML Model] → Response`
- **APIs used** — the assignment deliverables explicitly ask for "APIs used" in the README
- **Security considerations** — mention rate limiting, input validation, API key protection
- **Known limitations** — be more specific and honest (no header analysis, no external lookups, in-memory stash, etc.). The assignment says "documenting decisions and assumptions is appreciated"
- **Design decisions** — explain WHY 70/30 ML/rules weighting, why those specific rules, etc.

### 10. Filename Typo: `appscript.json`

The file is named `appscript.json` but the standard Google Apps Script manifest filename is `appsscript.json` (double 's'). This won't affect anything since it's mirrored for versioning, but it looks like an oversight.

---

## LOW PRIORITY — Nice to Have

### 11. XSS Risk in Web UI

In `index.html` line 564, extracted links are placed in `href` attributes:
```html
html += `<li><a href="${safe}" ...>${safe}</a></li>`;
```
The `safe` variable only escapes `<` and `>`, not `"` or `javascript:` URIs. For a security-focused project, this is a bad look. Fix:
```javascript
const safe = String(link).replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
// Also reject javascript: URIs
if (!/^https?:\/\//i.test(link)) continue;
```

### 12. In-Memory Stash Will Lose Data

The `_stash` dict in `main.py` lives in memory. On Render free tier (which sleeps), all stash tokens are lost on wake. This is fine for a demo but mention it in limitations.

### 13. CORS Configuration

No CORS middleware configured. If anyone tries to call the API from a different origin, it'll fail. Add:
```python
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
```

### 14. Rate Limiting

For a security tool, having no rate limiting means the scan endpoint could be abused. Even a simple IP-based rate limiter (e.g., `slowapi`) would show security awareness.

---

## Checklist (Priority Order)

| # | Task | Priority | Effort |
|---|------|----------|--------|
| 1 | Header analysis (SPF/DKIM/DMARC) | CRITICAL | Medium |
| 2 | External reputation (Safe Browsing or DNS/MX) | CRITICAL | Medium |
| 3 | Fix "Suspicious" verdict bug in Gmail add-on | CRITICAL | 5 min |
| 4 | Blocklist/Whitelist feature | HIGH | Medium |
| 5 | Scan history tracking | HIGH | Medium |
| 6 | Attachment metadata analysis | HIGH | Low |
| 7 | Remove or use unused deps | MEDIUM | 5 min |
| 8 | Add more tests (8-10 minimum) | MEDIUM | Low |
| 9 | Improve README (architecture, APIs, decisions) | MEDIUM | Low |
| 10 | Fix `appscript.json` filename | MEDIUM | 1 min |
| 11 | Fix XSS in extracted links | LOW | 10 min |
| 12 | Document in-memory stash limitation | LOW | 5 min |
| 13 | Add CORS middleware | LOW | 5 min |
| 14 | Add rate limiting | LOW | Low |

---

## Bottom Line

Your current repo covers ~50% of what the assignment asks for. The scoring engine and Gmail add-on work, but you're missing the signals that matter most in real phishing detection (headers, external reputation) and the user-facing features they explicitly listed (blocklist, history). Items 1-6 are what will make the difference between "good attempt" and "strong submission" for a security engineering role.
