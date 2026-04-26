const form = document.querySelector("#check-form");
const input = document.querySelector("#url-input");
const result = document.querySelector("#result");
const verdict = document.querySelector("#verdict");
const percentage = document.querySelector("#percentage");
const checkedUrl = document.querySelector("#checked-url");
const reasons = document.querySelector("#reasons");
const ringProgress = document.querySelector("#ring-progress");
const riskBadge = document.querySelector("#risk-badge");
const button = document.querySelector("#check-button");
const formMessage = document.querySelector("#form-message");
const featureGrid = document.querySelector("#feature-grid");
const historyBody = document.querySelector("#history-body");
const historyCount = document.querySelector("#history-count");
const modelStatus = document.querySelector("#model-status");
const copyResult = document.querySelector("#copy-result");
const clearHistory = document.querySelector("#clear-history");
const sampleButtons = document.querySelectorAll(".sample-url");

const historyKey = "phishguard-history";
const ringLength = 327;
let latestResult = null;

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(historyKey)) || [];
  } catch {
    return [];
  }
}

function saveHistory(items) {
  localStorage.setItem(historyKey, JSON.stringify(items.slice(0, 10)));
}

function riskClass(score) {
  if (score >= 75) return "danger";
  if (score >= 45) return "medium";
  return "safe";
}

function appendTextCell(row, text, className) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text;
  row.appendChild(cell);
  return cell;
}

function setResultState(score) {
  result.classList.remove("empty", "safe", "medium", "danger");
  result.classList.add(riskClass(score));
  ringProgress.style.strokeDashoffset = String(ringLength - (ringLength * score) / 100);
}

function renderReasons(items) {
  reasons.innerHTML = "";
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    reasons.appendChild(li);
  }
}

function yesNo(value) {
  return value ? "Yes" : "No";
}

function renderFeatures(features = {}) {
  const items = [
    ["URL length", features.url_length ?? "--"],
    ["HTTPS", features.uses_https === undefined ? "--" : yesNo(features.uses_https)],
    ["Subdomains", features.subdomain_count ?? "--"],
    ["Suspicious words", features.suspicious_word_count ?? "--"],
    ["IP address", features.has_ip_address === undefined ? "--" : yesNo(features.has_ip_address)],
    ["Shortener", features.shortener_domain === undefined ? "--" : yesNo(features.shortener_domain)],
    ["Risky TLD", features.risky_tld === undefined ? "--" : yesNo(features.risky_tld)],
    ["Path depth", features.path_depth ?? "--"]
  ];

  featureGrid.innerHTML = "";
  for (const [label, value] of items) {
    const card = document.createElement("div");
    const labelNode = document.createElement("span");
    const valueNode = document.createElement("strong");
    card.className = "feature-item";
    labelNode.textContent = label;
    valueNode.textContent = value;
    card.append(labelNode, valueNode);
    featureGrid.appendChild(card);
  }
}

function renderHistory() {
  const history = loadHistory();
  historyCount.textContent = `${history.length} saved`;
  historyBody.innerHTML = "";

  if (!history.length) {
    const row = document.createElement("tr");
    const cell = appendTextCell(row, "No scans yet.", "empty-row");
    cell.colSpan = 5;
    historyBody.appendChild(row);
    return;
  }

  for (const item of history) {
    const row = document.createElement("tr");
    appendTextCell(row, item.url, "url-cell");
    appendTextCell(row, item.isPhishing ? "Likely phishing" : "Likely safe");

    const riskCell = document.createElement("td");
    const pill = document.createElement("span");
    pill.className = `pill ${riskClass(item.phishingPercentage)}`;
    pill.textContent = item.riskLevel;
    riskCell.appendChild(pill);
    row.appendChild(riskCell);

    const scoreCell = document.createElement("td");
    const score = document.createElement("strong");
    score.textContent = `${item.phishingPercentage}%`;
    scoreCell.appendChild(score);
    row.appendChild(scoreCell);

    appendTextCell(row, item.time);
    historyBody.appendChild(row);
  }
}

function addToHistory(data) {
  const history = loadHistory();
  const next = [
    {
      url: data.url,
      isPhishing: data.isPhishing,
      phishingPercentage: data.phishingPercentage,
      riskLevel: data.riskLevel,
      time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    },
    ...history.filter((item) => item.url !== data.url)
  ];
  saveHistory(next);
  renderHistory();
}

function setLoading(isLoading) {
  button.disabled = isLoading;
  button.querySelector("span").textContent = isLoading ? "Scanning" : "Scan";
  formMessage.textContent = isLoading ? "Analyzing URL structure and model features..." : "";
}

function renderResult(data) {
  latestResult = data;
  setResultState(data.phishingPercentage);
  verdict.textContent = data.isPhishing ? "Likely phishing" : "Likely safe";
  percentage.textContent = `${data.phishingPercentage}%`;
  riskBadge.textContent = `${data.riskLevel} risk`;
  checkedUrl.textContent = data.url;
  renderReasons(data.reasons);
  renderFeatures(data.featureSnapshot);
  copyResult.disabled = false;
  addToHistory(data);
}

async function scanUrl(url) {
  const cleanUrl = url.trim();
  if (!cleanUrl) {
    formMessage.textContent = "Enter a URL to scan.";
    return;
  }

  setLoading(true);

  try {
    const response = await fetch("/api/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: cleanUrl })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not check this URL.");
    renderResult(data);
  } catch (error) {
    result.classList.remove("empty", "safe", "medium", "danger");
    verdict.textContent = "Scan failed";
    percentage.textContent = "--%";
    riskBadge.textContent = "Unavailable";
    checkedUrl.textContent = error.message;
    ringProgress.style.strokeDashoffset = String(ringLength);
    renderReasons(["The scanner is not reachable right now. Check the deployment status and try again."]);
  } finally {
    setLoading(false);
  }
}

async function checkModelStatus() {
  try {
    const response = await fetch("/api/health");
    if (!response.ok) throw new Error("offline");
    const data = await response.json();
    modelStatus.classList.remove("offline");
    modelStatus.classList.add("ready");
    modelStatus.innerHTML = '<span class="status-dot"></span><span>Model ready</span>';
    modelStatus.title = `Model version: ${data.modelVersion}`;
  } catch {
    modelStatus.classList.remove("ready");
    modelStatus.classList.add("offline");
    modelStatus.innerHTML = '<span class="status-dot"></span><span>Model offline</span>';
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  scanUrl(input.value);
});

sampleButtons.forEach((sample) => {
  sample.addEventListener("click", () => {
    input.value = sample.dataset.url;
    scanUrl(sample.dataset.url);
  });
});

copyResult.addEventListener("click", async () => {
  if (!latestResult) return;
  const report = [
    `URL: ${latestResult.url}`,
    `Verdict: ${latestResult.isPhishing ? "Likely phishing" : "Likely safe"}`,
    `Phishing probability: ${latestResult.phishingPercentage}%`,
    `Risk level: ${latestResult.riskLevel}`,
    `Signals: ${latestResult.reasons.join(" ")}`
  ].join("\n");

  try {
    await navigator.clipboard.writeText(report);
    formMessage.textContent = "Report copied.";
  } catch {
    formMessage.textContent = "Copy is unavailable in this browser.";
  }
});

clearHistory.addEventListener("click", () => {
  saveHistory([]);
  renderHistory();
});

ringProgress.style.strokeDasharray = String(ringLength);
ringProgress.style.strokeDashoffset = String(ringLength);
renderHistory();
renderFeatures();
checkModelStatus();
