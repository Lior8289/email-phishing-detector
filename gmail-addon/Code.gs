var API_BASE = "https://email-phishing-detector-ws33.onrender.com";
var SCAN_PATH = "/scan";

/* ───────── Trigger: MUST return Card[] ───────── */
function buildContextualCard(e) {
  if (!e || !e.gmail || !e.gmail.messageId) {
    return [createScanCard_("Open an email, then click Scan.")];
  }
  return [createScanCard_("Ready to scan this email.")];
}

/* ───────── Home card builder ───────── */
function createScanCard_(subtitle) {
  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Phishing Scanner")
        .setSubtitle(subtitle)
    );

  var section = CardService.newCardSection()
    .addWidget(
      CardService.newTextParagraph().setText(
        "Analyzes the currently opened email for phishing signals using rules + ML."
      )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("Scan for Phishing")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction().setFunctionName("scanCurrentEmail"))
    );

  card.addSection(section);
  return card.build();
}

/* ───────── Button handler: MUST return ActionResponse ───────── */
function scanCurrentEmail(e) {
  try {
    if (!e || !e.gmail || !e.gmail.messageId) {
      return pushCard_(createErrorCard_("No email is open. Open an email and try again."));
    }

    var card = buildScanResultCard_(e);
    return pushCard_(card);

  } catch (err) {
    return pushCard_(createErrorCard_("Scan failed:\n" + String(err)));
  }
}

/* ───────── Build result card (returns Card, not ActionResponse) ───────── */
function buildScanResultCard_(e) {
  var accessToken = e.gmail.accessToken;
  var messageId = e.gmail.messageId;

  GmailApp.setCurrentMessageAccessToken(accessToken);
  var msg = GmailApp.getMessageById(messageId);

  var fromAddr = msg.getFrom() || "";
  var subject  = msg.getSubject() || "";
  var body     = (msg.getPlainBody() || "").slice(0, 15000);

  var payload = {
    from_addr: fromAddr,
    subject: subject,
    body: body
  };

  // Optional health ping (doesn't block functionality)
  UrlFetchApp.fetch(API_BASE + "/health", { method: "get", muteHttpExceptions: true });

  var res = UrlFetchApp.fetch(API_BASE + SCAN_PATH, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  var code = res.getResponseCode();
  var text = res.getContentText() || "";

  if (code >= 300) {
    return createErrorCard_("Backend returned " + code + ":\n" + text.slice(0, 500));
  }

  var data;
  try {
    data = JSON.parse(text);
  } catch (parseErr) {
    return createErrorCard_("Invalid JSON from backend:\n" + text.slice(0, 500));
  }

  return createResultCard_(data, fromAddr, subject, body);
}

/* ───────── ActionResponse helper ───────── */
function pushCard_(card) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}

/* ───────── Result Card ───────── */
function createResultCard_(data, fromAddr, subject, body) {
  var confPct    = Math.round((data.confidence || 0) * 100);
  var mlPct      = (data.ml_probability == null) ? "N/A" : (Math.round(data.ml_probability * 100) + "%");
  var rulesScore = (data.rules_score == null) ? "N/A" : String(data.rules_score);

  var isPhishing = (String(data.classification || "")).toLowerCase().indexOf("phish") >= 0;
  var label = isPhishing ? "⚠️ PHISHING" : "✅ SAFE";

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Result: " + label)
        .setSubtitle("Confidence " + confPct + "%")
    );

  // --- Scores section ---
  var scores = CardService.newCardSection().setHeader("Scores");
  scores.addWidget(CardService.newDecoratedText().setTopLabel("CONFIDENCE").setText(confPct + "%"));
  scores.addWidget(CardService.newDecoratedText().setTopLabel("ML PROBABILITY").setText(mlPct));
  scores.addWidget(CardService.newDecoratedText().setTopLabel("RULES SCORE").setText(rulesScore));
  card.addSection(scores);

  // --- Rule hits (deduplicated, max 3) ---
  if (data.rule_hits && data.rule_hits.length) {
    var why = CardService.newCardSection().setHeader("Why?");
    var seen = {};
    var count = 0;
    for (var i = 0; i < data.rule_hits.length && count < 3; i++) {
      var msg = String(data.rule_hits[i].message || "");
      if (seen[msg]) continue;
      seen[msg] = true;
      count++;
      why.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(String(data.rule_hits[i].id || "rule") + " (sev " + String(data.rule_hits[i].severity || "?") + ")")
          .setText(msg)
          .setWrapText(true)
      );
    }
    card.addSection(why);
  }

  // --- Extracted links (deduplicated by domain, max 3) ---
  if (data.extracted_links && data.extracted_links.length) {
    var linksSection = CardService.newCardSection().setHeader("Extracted Links");
    var seenLinks = {};
    var linkCount = 0;
    for (var j = 0; j < data.extracted_links.length && linkCount < 3; j++) {
      var domain = extractDomain_(String(data.extracted_links[j]));
      if (seenLinks[domain]) continue;
      seenLinks[domain] = true;
      linkCount++;
      linksSection.addWidget(
        CardService.newTextParagraph().setText(escapeHtml_(truncateUrl_(String(data.extracted_links[j]), 80)))
      );
    }
    card.addSection(linksSection);
  }

  // --- "Go To Website" via stash token (full body, no truncation) ---
  var actions = CardService.newCardSection();

  var stashRes = UrlFetchApp.fetch(API_BASE + "/stash", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify({
      from_addr: fromAddr,
      subject: subject,
      body: body
    }),
    muteHttpExceptions: true
  });

  var safeUrl = API_BASE;
  try {
    var token = JSON.parse(stashRes.getContentText()).token || "";
    if (token) safeUrl = API_BASE + "?token=" + token;
  } catch(e) {}

  actions.addWidget(
    CardService.newTextButton()
      .setText("Go To Website")
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOpenLink(CardService.newOpenLink().setUrl(safeUrl))
  );
  card.addSection(actions);

  return card.build();
}

/* ───────── Error Card ───────── */
function createErrorCard_(text) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Scan Failed"))
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph().setText(
            escapeHtml_(String(text || "").slice(0, 500))
          )
        )
    )
    .build();
}

/* ───────── Utils ───────── */
function escapeHtml_(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function truncateUrl_(url, max) {
  return url.length <= max ? url : url.substring(0, max) + "...";
}

function extractDomain_(url) {
  try {
    var match = url.match(/^https?:\/\/([^\/\?#]+)/);
    return match ? match[1] : url;
  } catch (e) {
    return url;
  }
}