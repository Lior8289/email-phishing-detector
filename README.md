# Email Phishing Detector (Rules + ML) + Gmail Add-on

A lightweight phishing email scanner that combines heuristic rules and a trained ML model to classify emails as Safe / Suspicious / Phishing.
Includes a clean web UI and a Gmail Add-on that scans the currently opened email and shows the result inside Gmail.

## Features

- FastAPI backend with a single /scan endpoint
- ML inference using saved artifacts:
  - backend/model/phishing_model.pkl
  - backend/model/vectorizer.pkl
- Rule engine (links, suspicious patterns, sender hints, etc.) + ML probability → combined confidence
- Web UI: paste an email and scan
- Gmail Add-on: scan the opened email + optional “Open in Web App” deep-link

## API

POST /scan
Request:
{
"from_addr": "support@paypaI.com",
"subject": "URGENT: verify your account",
"body": "Click http://bit.ly/xyz now"
}

Response:
{
"classification": "Phishing",
"confidence": 0.78,
"ml_probability": 0.31,
"rules_score": 0,
"rule_hits": [
{"id": "shortened_link", "severity": 3, "message": "Found a shortened URL"}
],
"extracted_links": ["http://bit.ly/xyz"]
}

## Project Structure (high level)

- backend/app/ FastAPI app, routes, services, schemas, templates
- backend/model/ saved ML artifacts (\*.pkl)
- backend/tests/ API tests
- gmail-addon/ Apps Script files (Code.gs + appsscript.json) mirrored for versioning

## Run Locally

1. Create venv + install deps
   python -m venv .venv

# Windows:

.\.venv\Scripts\activate

# macOS/Linux:

# source .venv/bin/activate

pip install -r requirements.txt

2. Start the server
   python -m uvicorn backend.app.main:app --reload --port 8000

Open:

- Web UI: http://127.0.0.1:8000/
- Swagger: http://127.0.0.1:8000/docs

3. Run tests
   python -m pytest -q

## Deploy (Render)

1. Push the repo to GitHub
2. Create a new Web Service on Render
3. Set:
   - Build Command: pip install -r requirements.txt
   - Start Command: uvicorn backend.app.main:app --host 0.0.0.0 --port 10000
4. After deploy, verify:
   - https://<your-render-domain>/health
   - https://<your-render-domain>/docs

## Gmail Add-on (Apps Script)

The add-on requires the backend to be reachable via HTTPS (Render URL).

1. Create Apps Script project

- Go to script.google.com → New project
- Enable manifest: Project Settings → Show appsscript.json

2. Manifest (appsscript.json)
   Set urlFetchWhitelist to your Render domain and ensure required scopes exist:

{
"timeZone": "Asia/Jerusalem",
"oauthScopes": [
"https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
"https://www.googleapis.com/auth/gmail.addons.execute",
"https://www.googleapis.com/auth/script.external_request",
"https://www.googleapis.com/auth/script.locale"
],
"urlFetchWhitelist": [
"https://YOUR-RENDER-DOMAIN/"
],
"addOns": {
"common": {
"name": "Phishing Scanner",
"logoUrl": "https://www.gstatic.com/images/branding/product/1x/gmail_48dp.png",
"useLocaleFromApp": true
},
"gmail": {
"contextualTriggers": [
{
"unconditional": {},
"onTriggerFunction": "buildContextualCard"
}
]
}
}
}

3. Code (Code.gs)
   Set:
   var API_BASE = "https://YOUR-RENDER-DOMAIN"; // no trailing slash
   var SCAN_PATH = "/scan";

4. Install test deployment

- Deploy → Test deployments → Google Workspace Add-on → Install
- Open Gmail → open an email → click “Scan for Phishing”

Web deep-link:
The add-on can open the web UI with prefilled fields via:
/?from=...&subject=...&body=...
The UI reads these params and can auto-scan on load.

## Notes / Limitations

- Email bodies can be large; for Gmail deep-link the body is intentionally truncated to keep URLs safe.
- Render free instances may “sleep”; the first request may take a few seconds.
