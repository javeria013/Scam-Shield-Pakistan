// script.js – all the browser logic for Scam Shield Pakistan.
// Flow: user clicks Analyze -> rule check (instant) -> AI check (/api/analyze)
//       -> combine both results -> show result card -> save in recent checks.
// SECURITY: there is NO API key in this file. The server function holds it.

/* ============================================================
   1. SETTINGS AND DATA
   ============================================================ */
const LEVELS = ["Likely Safe", "Suspicious", "Likely Scam"];
const LEVEL_CLASS = ["safe", "warn", "scam"]; // CSS class for each level
const HISTORY_KEY = "scamShieldHistory";
const MAX_HISTORY = 8;

// Rule-based check: each rule has a label, a weight (how serious) and words to look for.
// Words can be English, Roman Urdu or Urdu. Add your own words here!
const RULES = [
  { label: "Asks for OTP, PIN or password", weight: 3, words: [
    "otp", "pin", "pin code", "password", "cvv", "verification code", "one time password", "security code",
    "otp batayein", "pin batayein", "code batayein", "code bhejein", "او ٹی پی", "پن", "پاسورڈ", "کوڈ"] },
  { label: "Asks for money or a fee", weight: 2, words: [
    "advance payment", "registration fee", "processing fee", "redelivery fee", "customs fee", "tax fee",
    "send rs", "pay rs", "transfer rs", "send money", "wapas bhejein", "paise bhejein", "raqam bhejein", "رقم", "فیس", "ٹرانسفر"] },
  { label: "Fake prize or reward claim", weight: 2, words: [
    "congratulations", "you have won", "you won", "lucky draw", "prize", "winner", "mubarak", "inaam", "انعام", "مبارک", "جیت"] },
  { label: "Urgent or threatening language", weight: 1, words: [
    "urgent", "immediately", "within 24 hours", "within 12 hours", "last warning", "legal action", "blocked",
    "block ho", "suspended", "arrest", "jaldi", "abhi", "warna", "فوری", "بلاک"] },
  { label: "Possible fake job offer", weight: 1, words: [
    "work from home", "earn rs", "daily income", "part time job", "no experience", "like youtube", "ghar baithe", "hiring"] },
  { label: "Mentions a bank, courier or government name", weight: 1, words: [
    "hbl", "ubl", "meezan", "allied bank", "bank alfalah", "state bank", "sbp", "fbr", "nadra", "pta", "tcs",
    "leopards", "pakistan post", "dhl", "fedex", "k-electric", "sui gas", "easypaisa", "jazzcash", "bisp", "ehsaas", "bank", "بینک"] },
];

// Link detection: normal links, short links, and risky website endings.
const LINK_REGEX = /(https?:\/\/[^\s]+|www\.[^\s]+|\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy)\/[^\s]*|\b[a-z0-9-]+\.(?:xyz|top|click|live|icu|site|online|info|cc|tk)\b[^\s]*)/gi;
const LINK_WEIGHT = 2;

// Example scam messages (all fake: numbers and websites are made up).
const EXAMPLES = [
  { title: "Fake bank", text: "HBL Alert: Your account will be blocked within 24 hours due to incomplete biometric verification. Verify now: http://hbl-verify-pk.xyz and enter your PIN and OTP." },
  { title: "JazzCash mistake transfer", text: "JazzCash: Aap ke account mein Rs 25,000 ghalti se transfer hue hain. Please wapas bhejein is number par 0300-0000000 warna account block ho jayega." },
  { title: "Courier parcel", text: "TCS: Your parcel could not be delivered. Pay Rs 150 redelivery fee within 12 hours: http://tcs-parcel-pk.top/pay or it will be returned." },
  { title: "BISP prize", text: "BISP Ehsaas: Mubarak ho! Aap ka 25,000 ka inaam nikla hai. Registration fee Rs 500 JazzCash par bhejein: 0300-0000000 aur CNIC number reply karein." },
  { title: "Online job", text: "Hiring! Work from home, earn Rs 5,000 daily by liking YouTube videos. No experience needed. Pay Rs 2,000 registration fee to start. WhatsApp 0300-0000000." },
  { title: "OTP request", text: "Assalam o Alaikum, main bank se bol raha hoon. Aap ke account mein masla hai. Abhi apne phone par aaya hua OTP code mujhe batayein." },
  { title: "Urdu message", text: "آپ کا بینک اکاؤنٹ بلاک ہو جائے گا۔ فوری طور پر اپنا پن کوڈ اور او ٹی پی اس لنک پر درج کریں: http://bank-update.top" },
  { title: "Normal bank alert", text: "Meezan Bank: Rs 1,200 was debited from your account ending 4521 at a grocery store on 12-Oct. If this was not you, call the number on the back of your card." },
];

/* ============================================================
   2. SMALL HELPERS
   ============================================================ */
const $ = (id) => document.getElementById(id);
const input = $("messageInput");

function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// Find every place a word/phrase appears in the text. Returns [start, end] pairs.
// English words must match whole words (so "pin" does not match "shopping").
function findRanges(text, term) {
  const ranges = [];
  if (!term || term.length < 2) return ranges;
  const isEnglish = /^[\x00-\x7F]+$/.test(term);
  if (isEnglish) {
    const re = new RegExp("(?<![a-z0-9])" + escapeRegex(term) + "(?![a-z0-9])", "gi");
    for (const m of text.matchAll(re)) ranges.push([m.index, m.index + m[0].length]);
  } else {
    // Urdu has no spaces rule like English, so simple search is fine.
    let i = text.indexOf(term);
    while (i > -1) { ranges.push([i, i + term.length]); i = text.indexOf(term, i + term.length); }
  }
  return ranges;
}

/* ============================================================
   3. RULE-BASED PRE-CHECK (no AI, runs in the browser)
   ============================================================ */
function runRuleCheck(text) {
  let score = 0;
  const labels = [];  // which rules were triggered
  const terms = [];   // words to highlight

  for (const rule of RULES) {
    const found = rule.words.filter((w) => findRanges(text, w).length > 0);
    if (found.length) { score += rule.weight; labels.push(rule.label); terms.push(...found); }
  }
  const links = text.match(LINK_REGEX) || [];
  if (links.length) { score += LINK_WEIGHT; labels.push("Contains a link"); terms.push(...links); }

  // Turn the score into a level: 0 = safe, 1 = suspicious, 2 = scam.
  const levelIndex = score >= 5 ? 2 : score >= 2 ? 1 : 0;
  return { score, levelIndex, labels, terms };
}

/* ============================================================
   4. AI CHECK (calls our serverless function)
   ============================================================ */
async function runAiCheck(text) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000); // give up after 30 seconds
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: text }),
      signal: controller.signal,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "AI check failed.");
    return data;
  } finally {
    clearTimeout(timer);
  }
}

/* ============================================================
   5. COMBINE RULES + AI
   ============================================================ */
// The rules can raise the AI's level by ONE step at most (never lower it).
// This keeps simple keyword rules from overruling the AI completely.
function combine(text, rules, ai) {
  if (!ai) {
    // AI not available: use rules only.
    return {
      levelIndex: rules.levelIndex, confidence: null, aiUsed: false, raised: false,
      explanation: "The AI check was not available, so this result uses only the built-in keyword and link rules.",
      warningSigns: [], advice: defaultAdvice(rules.levelIndex),
      ruleLabels: rules.labels, terms: rules.terms,
    };
  }
  let levelIndex = LEVELS.indexOf(ai.riskLevel);
  let raised = false;
  if (rules.levelIndex > levelIndex) { levelIndex = Math.min(levelIndex + 1, 2); raised = true; }
  return {
    levelIndex, confidence: ai.confidence, aiUsed: true, raised,
    explanation: ai.explanation, warningSigns: ai.warningSigns,
    advice: ai.advice.length ? ai.advice : defaultAdvice(levelIndex),
    ruleLabels: rules.labels, terms: [...rules.terms, ...ai.suspiciousPhrases],
  };
}

function defaultAdvice(levelIndex) {
  if (levelIndex === 0) return ["Stay careful. Do not share OTP, PIN or passwords.", "If unsure, contact the sender through an official number."];
  return ["Do not click any link or reply.", "Never share your OTP, PIN or password.", "Call your bank or company using the official number.", "Block the sender and report the message."];
}

/* ============================================================
   6. SHOW THE RESULT
   (We use textContent, not innerHTML, so pasted text can never run as code.)
   ============================================================ */
function fillList(listEl, items) {
  listEl.replaceChildren();
  items.forEach((t) => { const li = document.createElement("li"); li.textContent = t; listEl.append(li); });
}

// Show the message with risky parts wrapped in <mark>.
function showHighlighted(el, text, terms) {
  let ranges = [];
  [...new Set(terms)].forEach((t) => ranges.push(...findRanges(text, t)));
  ranges.sort((a, b) => a[0] - b[0]);
  const merged = [];
  for (const r of ranges) {                       // join overlapping ranges
    const last = merged[merged.length - 1];
    if (last && r[0] <= last[1]) last[1] = Math.max(last[1], r[1]); else merged.push([...r]);
  }
  el.replaceChildren();
  let pos = 0;
  for (const [s, e] of merged) {
    if (s > pos) el.append(text.slice(pos, s));
    const mark = document.createElement("mark");
    mark.textContent = text.slice(s, e);
    el.append(mark);
    pos = e;
  }
  el.append(text.slice(pos));
}

function renderResult(model, text) {
  const cls = LEVEL_CLASS[model.levelIndex];
  $("result").className = "result " + cls;
  $("riskBadge").className = "badge " + cls;
  $("riskBadge").textContent = LEVELS[model.levelIndex];

  // Confidence meter (only when the AI answered)
  $("meterBox").hidden = !model.aiUsed;
  if (model.aiUsed) {
    $("confValue").textContent = model.confidence + "%";
    $("meterFill").style.width = model.confidence + "%";
  }

  $("explanation").textContent = model.explanation + (model.raised ? " The built-in rules found extra danger signs, so the risk level was raised one step." : "");
  showHighlighted($("highlighted"), text, model.terms);

  // Warning signs: rule-check chips + AI list
  $("ruleChips").replaceChildren();
  model.ruleLabels.forEach((l) => {
    const s = document.createElement("span"); s.className = "chip flag"; s.textContent = l; $("ruleChips").append(s);
  });
  fillList($("signsList"), model.warningSigns);
  if (!model.ruleLabels.length && !model.warningSigns.length) fillList($("signsList"), ["No clear warning signs found. Still stay careful."]);

  fillList($("adviceList"), model.advice);
  $("result").hidden = false;
  $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/* ============================================================
   7. RECENT CHECKS (saved in localStorage on the user's device)
   ============================================================ */
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; }
}
function saveHistory(list) {
  try { localStorage.setItem(HISTORY_KEY, JSON.stringify(list)); } catch { /* storage may be blocked: ignore */ }
}
function addToHistory(text, model) {
  const list = loadHistory();
  list.unshift({ text, model });
  saveHistory(list.slice(0, MAX_HISTORY));
  renderHistory();
}
function renderHistory() {
  const list = loadHistory();
  $("historyBox").hidden = list.length === 0;
  const ul = $("historyList");
  ul.replaceChildren();
  list.forEach((item) => {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    const badge = document.createElement("span");
    badge.className = "badge " + LEVEL_CLASS[item.model.levelIndex];
    badge.textContent = LEVELS[item.model.levelIndex];
    const snippet = document.createElement("span");
    snippet.className = "snippet";
    snippet.dir = "auto";
    snippet.textContent = item.text;
    btn.append(badge, snippet);
    btn.addEventListener("click", () => { input.value = item.text; updateCount(); renderResult(item.model, item.text); });
    li.append(btn);
    ul.append(li);
  });
}

/* ============================================================
   8. BUTTONS AND EVENTS
   ============================================================ */
function showNotice(msg) { $("notice").textContent = msg; $("notice").hidden = !msg; }
function updateCount() { $("charCount").textContent = input.value.length + " / 2000"; }

async function analyze() {
  const text = input.value.trim();
  showNotice("");
  if (text.length < 5) { showNotice("Please paste a message first (at least a few words)."); return; }

  // Loading state
  $("analyzeBtn").disabled = true;
  $("analyzeBtn").textContent = "Analyzing...";
  $("loading").hidden = false;
  $("result").hidden = true;

  const rules = runRuleCheck(text);   // step 1: rules (instant)
  let ai = null;
  try {
    ai = await runAiCheck(text);      // step 2: AI
  } catch (err) {
    showNotice("AI check unavailable (" + err.message + "). Showing the keyword and link check only.");
  }

  const model = combine(text, rules, ai);   // step 3: combine
  renderResult(model, text);
  addToHistory(text, model);

  $("loading").hidden = true;
  $("analyzeBtn").disabled = false;
  $("analyzeBtn").textContent = "Analyze Message";
}

function resetAll() {
  input.value = "";
  updateCount();
  showNotice("");
  $("result").hidden = true;
  input.focus();
}

// Build the "Try an example" buttons
EXAMPLES.forEach((ex) => {
  const b = document.createElement("button");
  b.type = "button"; b.className = "chip"; b.textContent = ex.title;
  b.addEventListener("click", () => { input.value = ex.text; updateCount(); showNotice(""); });
  $("examples").append(b);
});

$("analyzeBtn").addEventListener("click", analyze);
$("resetBtn").addEventListener("click", resetAll);
$("resetBtn2").addEventListener("click", resetAll);
input.addEventListener("input", updateCount);
$("clearHistory").addEventListener("click", () => { saveHistory([]); renderHistory(); });

// Mobile menu
$("menuBtn").addEventListener("click", () => {
  const open = $("nav").classList.toggle("open");
  $("menuBtn").setAttribute("aria-expanded", open);
});
$("nav").addEventListener("click", () => { $("nav").classList.remove("open"); });

renderHistory();
updateCount();
