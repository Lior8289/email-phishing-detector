# Email Phishing Detector — Gmail Add-on + Backend

A Gmail Add-on that analyzes opened emails for phishing signals and produces a maliciousness score with an explainable verdict. Combines email header authentication, heuristic rules, ML inference, and external DNS enrichment.

## Architecture

```
Gmail Inbox
    |
    v
Gmail Add-on (Apps Script)
    |  Extracts: from, subject, body,
    |  raw headers (SPF/DKIM/DMARC),
    |  attachment metadata
    |
    v  POST /scan
FastAPI Backend (Python)
    |
    +---> Header Auth Rules (SPF, DKIM, DMARC, Return-Path)
    +---> Attachment Rules (exe, macros, double-ext, archives)
    +---> Content Rules (urgency, scam phrases, typosquatting, URLs)
    +---> ML Model (scikit-learn TF-IDF + classifier)
    +---> DNS Enrichment (MX records, domain resolution)
    +---> Blocklist/Whitelist check (SQLite)
    |
    v
Combined Score --> Verdict (Safe / Suspicious / Phishing)
    |
    +---> Response to Gmail card
    +---> Saved to scan history (SQLite)
```

## Features

### Detection Signals

| Signal | Source | What it checks |
|--------|--------|----------------|
| SPF/DKIM/DMARC | Email headers | Whether the sender is authenticated by their domain |
| Return-Path mismatch | Email headers | If the bounce address differs from the From address |
| Typosquatting | Sender + URLs | Homoglyph/edit-distance detection against known brands |
| Shortened URLs | Body links | bit.ly, tinyurl, t.co, etc. |
| Suspicious TLDs | Body links | .tk, .xyz, .top, .loan, etc. |
| IP-based URLs | Body links | URLs using raw IP addresses |
| Punycode domains | Body links | Internationalized domain abuse |
| Urgency language | Subject + body | "urgent", "act now", "verify", "suspended" |
| Scam phrases | Body | "prince", "inheritance", "processing fee", etc. |
| Account threats | Body | "problem with your payment", "update billing" |
| Executable attachments | Attachment metadata | .exe, .scr, .bat, .ps1, .vbs, etc. |
| Double extensions | Attachment metadata | invoice.pdf.exe |
| Macro documents | Attachment metadata | .docm, .xlsm, .pptm |
| Password archives | Attachment + body | .zip with "password" in body |
| No MX records | DNS enrichment | Domain that cannot receive email |
| Unresolvable domain | DNS enrichment | Domain that doesn't exist |
| ML classification | TF-IDF + model | Trained on phishing/ham corpus |

### User Controls

- **Personal blocklist** — Block domains or email addresses; blocked senders are auto-flagged
- **Whitelist** — Mark trusted senders
- **Block from Gmail** — One-click "Block Sender Domain" button in the Gmail add-on card

### Scan History

- Every scan is recorded with timestamp, verdict, confidence, and rule hits
- History page shows recent scans in a table
- Stats endpoint provides aggregate counts (total, phishing, suspicious, safe) and top flagged senders
- Sender history: "This sender was flagged N times before" shown on repeat offenders

## APIs Used

| API | Purpose |
|-----|---------|
| **Gmail API** (via GmailApp in Apps Script) | Read email content, headers, attachments |
| **CardService API** (Apps Script) | Build the Gmail add-on UI cards |
| **UrlFetchApp** (Apps Script) | Call the backend from the add-on |
| **dnspython** (Python) | MX record and SOA lookups for sender domain enrichment |
| **scikit-learn** (Python) | ML model inference for phishing probability |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan` | Analyze an email — returns verdict, confidence, rule hits, enrichment |
| `GET` | `/blocklist` | List all blocked entries |
| `POST` | `/blocklist` | Add a domain/email to blocklist |
| `DELETE` | `/blocklist/{id}` | Remove a blocklist entry |
| `GET` | `/whitelist` | List all whitelisted entries |
| `POST` | `/whitelist` | Add to whitelist |
| `DELETE` | `/whitelist/{id}` | Remove from whitelist |
| `GET` | `/history` | Recent scan results (supports `?limit=N`) |
| `GET` | `/history/stats` | Aggregate scan statistics |
| `GET` | `/health` | Health check |
| `GET` | `/` | Web UI |

### Scan Request Example

```json
POST /scan
{
  "from_addr": "support@paypaI.com",
  "subject": "URGENT: verify your account",
  "body": "Click http://bit.ly/xyz now",
  "headers": {
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail",
    "return_path": "bounce@evil.com",
    "received_count": 12
  },
  "attachments": [
    {"filename": "invoice.pdf.exe", "mime_type": "application/octet-stream", "size": 45000}
  ]
}
```

### Scan Response Example

```json
{
  "classification": "Phishing",
  "confidence": 0.92,
  "ml_probability": 0.78,
  "rules_score": 84,
  "rule_hits": [
    {"id": "spf_fail", "severity": 7, "message": "SPF authentication FAILED"},
    {"id": "dkim_none", "severity": 3, "message": "No DKIM signature present"},
    {"id": "double_extension", "severity": 9, "message": "Double extension detected: invoice.pdf.exe"},
    {"id": "url_shortener", "severity": 3, "message": "Shortened URL used: bit.ly"}
  ],
  "extracted_links": ["http://bit.ly/xyz"],
  "enrichment": {
    "mx": {"has_mx": false, "records": []},
    "resolves": false,
    "soa": null
  },
  "sender_history": {"times_flagged": 2},
  "blocklist_hit": false
}
```

## Scoring System

The final score is a weighted combination:

- **ML model (70%)** — Trained on a phishing/ham email corpus, captures language patterns
- **Rules engine (30%)** — Deterministic checks for known-bad indicators

**Why this weighting?** The ML model generalizes well across unseen emails but can't explain its reasoning. The rules engine is explainable and catches specific technical indicators (SPF failures, typosquatting) that the language model may miss. The 70/30 split gives ML the dominant vote while ensuring hard technical signals always contribute.

**Thresholds:**
- Score >= 0.75 → **Phishing**
- Score >= 0.45 → **Suspicious**
- Score < 0.45 → **Safe**

## Run Locally

```bash
# 1. Create venv + install deps
python -m venv .venv
source .venv/bin/activate    # macOS/Linux
# .\.venv\Scripts\activate   # Windows
pip install -r backend/requirements.txt

# 2. Start the server
python -m uvicorn backend.app.main:app --reload --port 8000

# 3. Open
#    Web UI:  http://127.0.0.1:8000/
#    Swagger: http://127.0.0.1:8000/docs

# 4. Run tests
python -m pytest backend/tests/ -v
```

## Deploy (Render)

1. Push the repo to GitHub
2. Create a new **Web Service** on Render
3. Set:
   - Build Command: `pip install -r backend/requirements.txt`
   - Start Command: `uvicorn backend.app.main:app --host 0.0.0.0 --port 10000`
4. After deploy, verify:
   - `https://<your-render-domain>/health`
   - `https://<your-render-domain>/docs`

## Gmail Add-on Setup

The add-on requires the backend to be reachable via HTTPS.

1. **Create Apps Script project** — Go to [script.google.com](https://script.google.com) → New project
2. **Enable manifest** — Project Settings → Show `appsscript.json` in editor
3. **Copy files** — Paste `gmail-addon/Code.gs` and `gmail-addon/appsscript.json`
4. **Set API_BASE** — In `Code.gs` line 1, set your Render domain
5. **Set urlFetchWhitelist** — In `appsscript.json`, set your Render domain
6. **Test** — Deploy → Test deployments → Google Workspace Add-on → Install
7. Open Gmail → open any email → click "Scan for Phishing"

## Design Decisions

1. **Header-first approach** — SPF/DKIM/DMARC are the most reliable phishing signals in production email security. The add-on extracts raw headers using `getRawContent()` and parses authentication results.

2. **Attachment metadata only** — We analyze filenames, MIME types, and sizes rather than file contents. This avoids the complexity and security risks of handling untrusted file content while still catching common attack vectors (double extensions, executables, password-protected archives).

3. **DNS enrichment with timeouts** — External lookups run in parallel with a 3-second timeout. A slow DNS server won't block the scan response.

4. **SQLite for persistence** — Lightweight, zero-config, file-based storage. Perfect for a single-server deployment. The DB file is created automatically at `backend/data/scanner.db`.

5. **No external threat intelligence API keys required** — The enrichment layer uses DNS (free, no API key). This keeps the project self-contained while still demonstrating the enrichment concept.

## Known Limitations

- **No file content scanning** — Attachment analysis is metadata-only; a production system would sandbox and scan file contents
- **ML model is generic** — Trained on a general phishing corpus; would benefit from fine-tuning on organization-specific data
- **In-memory stash** — The Gmail→WebUI deep-link stash lives in memory and is lost on server restart
- **Single-server SQLite** — Won't scale horizontally; a production deployment would use PostgreSQL
- **No rate limiting** — The scan endpoint has no per-IP throttling (would add `slowapi` for production)
- **DNS enrichment can be slow** — First scan after backend wake-up may take a few seconds due to DNS resolution + Render cold start
- **No URL following** — Shortened URLs are flagged but not resolved to their final destination
