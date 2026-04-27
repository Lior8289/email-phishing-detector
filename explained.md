# Part 1 — Complete Briefing: Everything You Need to Know

This document covers everything about the Gmail Add-on Malicious Email Scorer — what it does, how it works, why each decision was made, and what to say when presenting it.

---

## 1. What Does This Project Do?

It's a **Gmail Add-on** that scans the email you're currently reading and tells you if it's **Safe**, **Suspicious**, or **Phishing** — with a confidence percentage and a clear explanation of *why*.

When a user opens an email in Gmail, they click "Scan for Phishing" in the sidebar. The add-on:
1. Extracts the email content (from, subject, body)
2. Extracts **raw email headers** (SPF, DKIM, DMARC authentication results)
3. Extracts **attachment metadata** (filenames, types, sizes)
4. Sends everything to a Python backend
5. The backend runs **4 detection layers** and returns a scored verdict
6. The result is displayed as a Gmail Card with a breakdown of all signals

There's also a **web UI** for pasting and scanning emails manually, with tabs for **scan history** and a **personal blocklist**.

---

## 2. The 4 Detection Layers — How Scoring Works

### Layer 1: Email Header Authentication (THE most important layer)

**What it does:** Checks SPF, DKIM, and DMARC — the three email authentication protocols that verify whether the sender is who they claim to be.

**How to explain it to the manager:**

> "When you receive an email from `support@paypal.com`, how do you know PayPal actually sent it? That's what SPF, DKIM, and DMARC do. They're like ID checks at the door."
>
> - **SPF** (Sender Policy Framework): The domain owner publishes a list of IP addresses allowed to send email on their behalf. If the sending server's IP isn't on that list → SPF fails → likely spoofed.
>
> - **DKIM** (DomainKeys Identified Mail): The sending server cryptographically signs the email. The recipient can verify the signature using the domain's public key. If the signature is invalid or missing → DKIM fails → the email may have been tampered with or sent from an unauthorized server.
>
> - **DMARC** (Domain-based Message Authentication, Reporting & Conformance): A policy layer on top of SPF and DKIM. The domain owner says "if SPF or DKIM fails, here's what to do (quarantine, reject, or allow)." If DMARC fails → the domain owner's policy is being violated.
>
> - **Return-Path mismatch**: The email's bounce address differs from the From address. In legitimate email, these usually match. A mismatch suggests the visible sender is being spoofed.

**Why it matters:** In real-world phishing, header spoofing is the #1 technique. An email can say "From: ceo@yourcompany.com" but actually be sent from a random server in another country. SPF/DKIM/DMARC are the only way to catch this — no amount of text analysis can detect header spoofing.

**How the add-on gets headers:** The Gmail add-on calls `msg.getRawContent()` to get the full raw email including all headers. It then parses the `Authentication-Results`, `Received-SPF`, and `Return-Path` headers and sends structured results to the backend.

**Severity scores:**
- DKIM fail → severity 8 (highest — means email was tampered or forged)
- SPF fail → severity 7
- Return-Path mismatch → severity 7
- DMARC fail → severity 6
- SPF softfail → severity 4
- No DKIM/SPF/DMARC → severity 2-3 (missing isn't as bad as failing)

### Layer 2: Rule Engine (Heuristic Analysis)

**What it does:** A collection of deterministic pattern-matching rules that check for known phishing indicators.

**Categories of rules:**

**Sender analysis:**
- Typosquatting detection — checks if the sender domain impersonates a known brand using homoglyph substitution (paypa**I**.com with capital I instead of lowercase L, amaz**0**n.com with zero) or edit-distance (1-2 character changes from known brands)
- Suspicious domain patterns — multiple hyphens, mixed alphanumeric, excessively long domains

**Content analysis:**
- Urgency language — "urgent", "act now", "verify immediately", "suspended", "within 24 hours"
- Scam phrases — "prince", "inheritance", "processing fee", "Western Union", "100% risk free"
- Account threats — "problem with your payment", "update your billing"
- Money/personal info requests — dollar amounts, passport copies, bank account numbers
- Excessive capitalization (>30% caps) and punctuation (!!!, ???)
- Generic greetings in financial context ("Dear Friend" + money request)

**URL analysis:**
- Shortened URLs (bit.ly, tinyurl, t.co)
- Raw IP addresses in URLs
- Punycode domains (internationalized domain name abuse)
- Suspicious TLDs (.tk, .xyz, .top, .loan)
- Typosquatting in link domains
- Brand mismatch (claims to be Amazon but links to different domain)

**Attachment analysis:**
- Executable extensions (.exe, .scr, .bat, .ps1, .vbs, .js, etc.)
- Double extensions (invoice.pdf.exe — disguised executables)
- Macro-enabled Office documents (.docm, .xlsm)
- Password-protected archives (.zip with "password" mentioned in body — very common malware delivery technique)
- MIME type mismatches

**How to explain the attachment analysis:**

> "We don't open or scan the actual file contents — that would require a full sandbox environment. Instead, we analyze the *metadata*: the filename, file type, and size. This catches the most common attack vectors. For example, 'invoice.pdf.exe' has a double extension — the user sees 'invoice.pdf' but it's actually an executable. Or a .zip file with the password in the email body — that's a textbook malware delivery pattern because password-protected archives bypass email antivirus scanners."

### Layer 3: ML Model

**What it does:** A scikit-learn classifier trained on a phishing/ham email corpus. It converts email text into TF-IDF features and predicts the probability of the email being phishing.

**How to explain it:**

> "The ML model captures subtle language patterns that are hard to write rules for. It learned from thousands of real phishing and legitimate emails. It's good at generalizing — catching phishing emails that don't match any specific rule but 'feel' like phishing based on word patterns, sentence structure, and vocabulary."

**The model outputs a probability** (0.0 = definitely ham, 1.0 = definitely phishing). This is combined with the rules score.

### Layer 4: DNS Enrichment (External Reputation)

**What it does:** Checks the sender's domain against external DNS infrastructure.

**Checks performed:**
- **MX record lookup** — Does the domain have mail exchange records? A domain without MX records cannot legitimately send or receive email. If `support@totally-legit-bank.com` has no MX records, it's almost certainly fake.
- **Domain resolution** — Does the domain resolve to any IP address at all? An unresolvable domain is clearly fabricated.
- **SOA record** — Retrieves the Start of Authority record for additional context.

**How to explain it:**

> "We go beyond just analyzing the email content — we check if the sender's domain actually exists as a legitimate email-sending domain. If someone emails you from `security@bigbank-verify.com`, we check: does that domain have mail servers configured? Can it even receive a reply? If not, it's almost certainly a throwaway domain set up just for phishing."

**Technical detail:** All DNS lookups run in parallel with a 3-second timeout. A slow or unreachable DNS server won't block the scan.

### How The Scores Combine

```
Final Score = 0.7 × ML_probability + 0.3 × (rules_score / 100)
```

**Why 70/30?**
- ML gets 70% because it generalizes better across unseen emails
- Rules get 30% because they're deterministic and catch specific technical indicators (SPF failures, typosquatting) that the language model may miss
- Rules provide explainability — the user can see exactly which rules triggered and why

**Thresholds:**
- >= 0.75 → **Phishing** (red badge)
- >= 0.45 → **Suspicious** (yellow badge)
- < 0.45 → **Safe** (green badge)

**Override:** If a sender is on the personal blocklist and the score says "Safe", it gets bumped to "Suspicious" automatically.

---

## 3. User Controls — Blocklist & Whitelist

**Blocklist:**
- Users can block domains or email addresses
- Blocked senders are auto-flagged as Suspicious regardless of score
- Can be managed via the Web UI (Blocklist tab) or the "Block Sender Domain" button in the Gmail card
- Stored persistently in SQLite

**Whitelist:**
- Trusted domains/addresses
- Whitelisted senders are still scanned (for safety) but the whitelist status is noted
- Managed via API

**How to explain it:**

> "Users can build their own threat intelligence over time. If they encounter a suspicious domain, they block it with one click — and all future emails from that domain will be auto-flagged. This is important because phishing campaigns often reuse the same infrastructure across multiple emails."

---

## 4. Scan History

**What it stores:** Every scan result — timestamp, sender, subject, verdict, confidence, and all triggered rules.

**Why it matters:**

> "History gives us context. If a sender has been flagged 3 times before, that's more suspicious than a first-time sender. The history also lets users see patterns — 'we're getting a lot of phishing from .xyz domains this week' — and provides evidence for security investigations."

**Endpoints:**
- `GET /history` — list of recent scans
- `GET /history/stats` — aggregate stats (total scans, phishing count, suspicious count, safe count, top flagged senders)

**In the Gmail card:** Shows "This sender was flagged N time(s) before" when a repeat offender is detected.

---

## 5. Technical Architecture

### Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Gmail Add-on | Google Apps Script + CardService | In-Gmail UI, email data extraction |
| Backend API | Python + FastAPI | Detection engine, API endpoints |
| ML Model | scikit-learn (TF-IDF + classifier) | Language-based phishing probability |
| Rule Engine | Python (regex + domain analysis) | Deterministic signal detection |
| Enrichment | dnspython (DNS lookups) | External domain reputation |
| Storage | SQLite | Blocklist, whitelist, scan history |
| Web UI | Vanilla HTML/CSS/JS | Manual scanning, history, blocklist management |

### Data Flow (Gmail Add-on)

```
1. User opens email in Gmail
2. Add-on sidebar appears with "Scan for Phishing" button
3. User clicks scan
4. Apps Script extracts:
   - From address, Subject, Body (via GmailApp)
   - Raw headers (via getRawContent() → parse SPF/DKIM/DMARC)
   - Attachment metadata (via getAttachments() → filename, MIME, size)
5. POST to backend /scan endpoint with all data
6. Backend runs: header rules → attachment rules → content rules → ML → DNS enrichment
7. Combines scores → verdict
8. Saves to history
9. Returns JSON response
10. Apps Script builds a Card with:
    - Verdict badge (Safe/Suspicious/Phishing)
    - Confidence %
    - Score breakdown (ML, Rules)
    - "Why?" section with triggered rules
    - Domain enrichment results
    - "Block Sender Domain" button
    - "Open in Web App" link
```

### Security Considerations

- **XSS prevention**: Web UI uses DOM APIs (createElement/textContent) instead of innerHTML for all user-controlled content. Extracted links are displayed as text only, not clickable (to prevent users from accidentally clicking malicious URLs).
- **Input validation**: Pydantic schemas enforce types and constraints on all API inputs.
- **CORS**: Enabled for development; should be restricted to specific origins in production.
- **No secrets in code**: API keys and URLs are configurable, not hardcoded (except the demo Render URL).
- **Bounded stash**: In-memory stash has a 500-entry cap to prevent memory exhaustion.

---

## 6. What to Say in the Interview

### "Walk me through your architecture"

> "The system has two components: a Gmail Add-on (Apps Script) and a Python backend (FastAPI).
>
> When a user opens an email, the add-on extracts everything — content, raw headers, and attachment metadata. It sends all of this to the backend.
>
> The backend runs four detection layers in order:
> 1. **Header authentication** — SPF, DKIM, DMARC. These are the most reliable signals because they can't be faked from the email content alone.
> 2. **Heuristic rules** — pattern matching for known phishing indicators like typosquatting, urgency language, suspicious attachments.
> 3. **ML inference** — a trained classifier that catches subtle patterns the rules miss.
> 4. **DNS enrichment** — external checks to verify the sender's domain actually exists and can send email.
>
> These are combined into a weighted score (70% ML, 30% rules) and classified as Safe, Suspicious, or Phishing. Everything is stored in a SQLite database so we can track scan history and sender reputation over time."

### "Why didn't you use VirusTotal/Google Safe Browsing?"

> "I prioritized signals that don't require external API keys or paid subscriptions — DNS lookups are free and universally available. In a production environment, I would absolutely integrate VirusTotal for URL/file hash checking and Google Safe Browsing for real-time URL classification. The architecture supports this — the enrichment layer is designed to be extensible with additional data sources."

### "How do you handle false positives?"

> "Three mechanisms: First, the whitelist lets users mark trusted senders that shouldn't be flagged. Second, the three-tier classification (Safe/Suspicious/Phishing) means borderline cases get 'Suspicious' rather than 'Phishing' — it's a soft warning, not a hard block. Third, the rule hit breakdown shows exactly *why* an email was flagged, so users can make informed decisions. If a legitimate email is flagged because the sender's domain has no MX records, the user can see that specific signal and add the sender to their whitelist."

### "What would you do differently in production?"

> "Several things:
> 1. **PostgreSQL** instead of SQLite for horizontal scalability
> 2. **Rate limiting** on the scan endpoint to prevent abuse
> 3. **API authentication** — right now the endpoints are open; in production each user/organization would have an API key
> 4. **VirusTotal integration** for URL and file hash checking
> 5. **URL resolution** — follow shortened URLs to their final destination before checking
> 6. **Attachment sandboxing** — actually open files in a sandbox to detect malicious payloads, not just metadata analysis
> 7. **Feedback loop** — let users mark verdicts as correct/incorrect to retrain the ML model
> 8. **Multi-tenant storage** — scan history per user/organization, not a single shared database"

### "Why did you choose X technology?"

- **FastAPI** — async Python framework with automatic OpenAPI/Swagger docs, Pydantic validation, and excellent performance
- **SQLite** — zero-config persistent storage, perfect for a single-server demo. The schema is simple enough that migrating to Postgres later is trivial
- **scikit-learn** — lightweight ML library that loads fast and serves predictions without a GPU. The TF-IDF + classifier approach is proven for text classification
- **Apps Script** — required by the assignment (Google Workspace APIs). CardService provides a native Gmail sidebar experience
- **dnspython** — standard Python library for DNS queries, used for MX and SOA record lookups

---

## 7. Files Changed / Created

### New files:
- `backend/app/services/storage.py` — SQLite DB for blocklist, whitelist, scan history
- `backend/app/services/enrichment.py` — DNS MX, domain resolution, SOA checks
- `backend/app/api/endpoints/blocklist.py` — Blocklist/whitelist CRUD endpoints
- `backend/app/api/endpoints/history.py` — Scan history + stats endpoints

### Modified files:
- `backend/app/schemas/scan.py` — Added HeaderInfo, AttachmentInfo, enrichment/history models
- `backend/app/services/rules.py` — Added header auth rules, attachment rules
- `backend/app/services/detector.py` — Integrated all 4 detection layers + blocklist + history
- `backend/app/api/endpoints/scan.py` — Updated to pass headers/attachments
- `backend/app/api/router.py` — Added blocklist and history routes
- `backend/app/main.py` — Added CORS, DB init on startup, bounded stash
- `backend/app/templates/index.html` — XSS-safe DOM construction, tabs for history/blocklist
- `gmail-addon/Code.gs` — Header extraction, attachment metadata, Suspicious verdict fix, Block Sender button, enrichment display
- `gmail-addon/appsscript.json` — Fixed filename (was `appscript.json`), added metadata scope
- `backend/requirements.txt` — Added dnspython, removed unused deps
- `backend/tests/test_api.py` — Expanded from 2 to 18 tests
- `README.md` — Full rewrite with architecture, API docs, design decisions

---

## 8. Known Limitations (Be Honest About These)

1. **No file content scanning** — We analyze attachment metadata only. A real system would sandbox and detonate files.
2. **ML model is generic** — Not trained on organization-specific data. Would benefit from fine-tuning.
3. **No URL following** — We flag shortened URLs but don't resolve them to check the final destination.
4. **SQLite is single-server** — Won't scale horizontally. Production would use PostgreSQL.
5. **No rate limiting** — The API is unthrottled. Production needs per-IP rate limiting.
6. **In-memory stash** — The Gmail→WebUI deep-link stash is lost on server restart.
7. **No VirusTotal/Safe Browsing** — DNS enrichment only. Production would add paid threat intelligence APIs.

**How to frame these in the interview:** These are design trade-offs, not oversights. State each limitation and immediately follow with what you'd do in production. This shows you understand the full picture.

---

## 9. Demo Script (For the 60-min Interview)

1. **Open Gmail** → Open a test email → Show the add-on sidebar → Click "Scan for Phishing"
2. **Show the Card** — Walk through the verdict, scores, rule hits, enrichment results
3. **Click "Block Sender Domain"** — Show it adds to blocklist
4. **Open the Web UI** → Swagger docs at `/docs` to show the API
5. **Load a phishing example** → Scan it → Walk through the "Why?" breakdown
6. **Switch to History tab** → Show scan history and stats
7. **Switch to Blocklist tab** → Show the blocked domain from step 3
8. **Load a safe example** → Scan it → Show it correctly identifies as Safe
9. **Show the code** — Walk through the architecture:
   - `rules.py` — explain the header authentication rules
   - `enrichment.py` — explain DNS lookups
   - `detector.py` — explain how the 4 layers combine
   - `Code.gs` — explain header extraction from raw email
