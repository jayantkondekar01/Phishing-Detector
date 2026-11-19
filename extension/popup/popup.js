/**
 * PhishGuard — Popup Controller
 *
 * Orchestrates the scan workflow:
 *  1. Gets the active tab URL
 *  2. Requests page content from content script
 *  3. Sends both to the FastAPI backend via the service worker
 *  4. Renders the analysis result in the popup UI
 *
 * Privacy: No URLs or results are persisted. Everything is in-memory only.
 */

// ─── DOM refs ────────────────────────────────────────────────────────────────
const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const ui = {
  serverStatus:        $("#serverStatus"),
  serverOfflineBanner: $("#serverOfflineBanner"),
  currentUrl:          $("#currentUrl"),
  scanBtn:         $("#scanBtn"),
  loadingState:    $("#loadingState"),
  resultCard:      $("#resultCard"),
  errorState:      $("#errorState"),
  errorMessage:    $("#errorMessage"),
  retryBtn:        $("#retryBtn"),
  // Result elements
  shieldIcon:      $("#shieldIcon"),
  shieldCheck:     $("#shieldCheck"),
  shieldX:         $("#shieldX"),
  shieldWarn:      $("#shieldWarn"),
  verdictLabel:    $("#verdictLabel"),
  verdictDesc:     $("#verdictDesc"),
  confidenceValue: $("#confidenceValue"),
  confidenceBar:   $("#confidenceBar"),
  methodBadge:     $("#methodBadge"),
  analysisTime:    $("#analysisTime"),
  breakdownSection:$("#breakdownSection"),
  breakdownList:   $("#breakdownList"),
  nlpSection:      $("#nlpSection"),
  nlpScore:        $("#nlpScore"),
  nlpMethod:       $("#nlpMethod"),
  nlpPhrases:      $("#nlpPhrases"),
  domainSection:   $("#domainSection"),
  domainDetails:   $("#domainDetails"),
};

// ─── Verdict config ──────────────────────────────────────────────────────────
const VERDICTS = {
  safe: {
    label: "Safe",
    desc: "This website appears legitimate",
    color: "#22c55e",
    icon: "check",
  },
  warning: {
    label: "Suspicious",
    desc: "Some risk indicators detected — proceed with caution",
    color: "#f59e0b",
    icon: "warn",
  },
  phishing: {
    label: "Phishing Detected",
    desc: "This website is likely a phishing attempt",
    color: "#ef4444",
    icon: "x",
  },
  high_risk: {
    label: "High Risk — Phishing",
    desc: "Strong phishing indicators — do NOT enter any information",
    color: "#dc2626",
    icon: "x",
  },
};


// ─── Initialization ──────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  loadCurrentUrl();
  checkServerHealth();
  ui.scanBtn.addEventListener("click", runScan);
  ui.retryBtn.addEventListener("click", runScan);
  ui.currentUrl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      runScan();
    }
  });
});


// ─── Server health ───────────────────────────────────────────────────────────

async function checkServerHealth() {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: "checkHealth" }, (resp) => {
      if (resp && resp.status === "healthy") {
        ui.serverStatus.className = "status-dot online";
        ui.serverStatus.title = "Backend online (FastAPI)";
        if (ui.serverOfflineBanner) ui.serverOfflineBanner.classList.add("hidden");
      } else {
        ui.serverStatus.className = "status-dot offline";
        ui.serverStatus.title = "Backend offline — run 'python main.py' in backend directory";
        if (ui.serverOfflineBanner) ui.serverOfflineBanner.classList.remove("hidden");
      }
      resolve(resp);
    });
  });
}


// ─── Load current tab URL ────────────────────────────────────────────────────

function applyTabUrl(tab) {
  if (tab && tab.url) {
    const url = tab.url;
    ui.currentUrl.value = url;
    ui.currentUrl.title = url;
  } else {
    ui.currentUrl.placeholder = "Enter or paste a URL to scan...";
  }
}

async function loadCurrentUrl() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0]) {
        applyTabUrl(tabs[0]);
      } else {
        chrome.tabs.query({ active: true, lastFocusedWindow: true }, (fallbackTabs) => {
          applyTabUrl(fallbackTabs && fallbackTabs[0]);
        });
      }
      resolve();
    });
  });
}


// ─── Scan workflow ───────────────────────────────────────────────────────────

async function runScan() {
  let url = (ui.currentUrl.value || "").trim();

  // If input is empty, try querying the active tab
  if (!url) {
    const tabs = await new Promise((res) => chrome.tabs.query({ active: true, currentWindow: true }, res));
    if (tabs && tabs[0] && tabs[0].url) {
      applyTabUrl(tabs[0]);
      url = tabs[0].url;
    }
  }

  if (!url) {
    showError("Please enter or paste a URL to scan.");
    return;
  }

  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://") || url.startsWith("about:")) {
    showError("Cannot scan internal browser or extension pages. Navigate to a website or paste an external URL.");
    return;
  }

  // Prepend http if bare domain entered
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
    ui.currentUrl.value = url;
  }

  showLoading();

  try {
    // 1. Get page content from content script with quick 800ms timeout
    const pageContent = await getPageContent();

    // 2. Send to backend via service worker
    const result = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        { action: "analyzeUrl", url, pageContent },
        (resp) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else if (resp?.error) {
            reject(new Error(resp.error));
          } else {
            resolve(resp);
          }
        }
      );
    });

    // 3. Render result
    renderResult(result);

  } catch (err) {
    showError(
      err.message.includes("fetch") || err.message.includes("offline") || err.message.includes("timed out")
        ? "Backend server is offline! Start the server in your terminal:\ncd backend\npython main.py"
        : err.message
    );
  }
}


async function getPageContent() {
  return new Promise((resolve) => {
    let finished = false;
    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        resolve(null);
      }
    }, 800);

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0]?.id) {
        if (!finished) { finished = true; clearTimeout(timer); resolve(null); }
        return;
      }
      chrome.tabs.sendMessage(tabs[0].id, { action: "extractContent" }, (resp) => {
        if (!finished) {
          finished = true;
          clearTimeout(timer);
          if (chrome.runtime.lastError || !resp) {
            resolve(null);
          } else {
            resolve(resp.content || null);
          }
        }
      });
    });
  });
}


// ─── Render result ───────────────────────────────────────────────────────────

function renderResult(data) {
  hideAll();
  ui.resultCard.classList.remove("hidden");

  const verdict = VERDICTS[data.risk_level] || VERDICTS.safe;

  // Shield icon
  ui.shieldIcon.className = `shield ${data.risk_level}`;
  ui.shieldCheck.classList.toggle("hidden", verdict.icon !== "check");
  ui.shieldX.classList.toggle("hidden", verdict.icon !== "x");
  ui.shieldWarn.classList.toggle("hidden", verdict.icon !== "warn");

  // Verdict text
  ui.verdictLabel.textContent = verdict.label;
  ui.verdictLabel.style.color = verdict.color;
  ui.verdictDesc.textContent = verdict.desc;

  // Confidence bar
  const pct = Math.round(data.confidence * 100);
  ui.confidenceValue.textContent = `${pct}%`;
  ui.confidenceValue.style.color = verdict.color;
  ui.confidenceBar.style.width = `${pct}%`;
  ui.confidenceBar.className = `confidence-bar ${data.risk_level}`;

  // Method badge
  const methodLabel = data.method === "ml_model" ? "ML Model" : "Heuristic";
  ui.methodBadge.textContent = methodLabel;

  // Analysis time
  ui.analysisTime.textContent = `${data.analysis_time_ms.toFixed(0)} ms`;

  // Breakdown list
  if (data.breakdown && data.breakdown.length > 0) {
    ui.breakdownSection.classList.remove("hidden");
    ui.breakdownList.innerHTML = "";
    data.breakdown.forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      ui.breakdownList.appendChild(li);
    });
  }

  // NLP section
  if (data.nlp_analysis && data.nlp_analysis.nlp_method !== "skipped") {
    ui.nlpSection.classList.remove("hidden");
    const nlpPct = Math.round(data.nlp_analysis.nlp_score * 100);
    ui.nlpScore.textContent = `${nlpPct}%`;
    ui.nlpScore.style.color = nlpPct > 50 ? "#ef4444" : nlpPct > 20 ? "#f59e0b" : "#22c55e";
    ui.nlpMethod.textContent = `Method: ${data.nlp_analysis.nlp_method}`;
    ui.nlpPhrases.innerHTML = "";
    (data.nlp_analysis.phishing_phrases || []).forEach((phrase) => {
      const li = document.createElement("li");
      li.textContent = phrase;
      ui.nlpPhrases.appendChild(li);
    });
  }

  // Domain section
  if (data.domain_info && data.domain_info.ssl) {
    ui.domainSection.classList.remove("hidden");
    ui.domainDetails.innerHTML = "";

    const rows = [
      ["Hostname", data.domain_info.hostname],
      ["SSL", data.domain_info.ssl.has_ssl ? "✅ Yes" : "❌ No"],
    ];
    if (data.domain_info.ssl.issuer) {
      rows.push(["Issuer", data.domain_info.ssl.issuer]);
    }
    if (data.domain_info.ssl.days_remaining !== null && data.domain_info.ssl.days_remaining !== undefined) {
      rows.push(["SSL Expires", `${data.domain_info.ssl.days_remaining} days`]);
    }
    rows.push(["Resolves", data.domain_info.dns.resolves ? "✅ Yes" : "❌ No"]);
    if (data.domain_info.dns.is_ip_based) {
      rows.push(["IP-based URL", "⚠️ Yes"]);
    }

    rows.forEach(([label, value]) => {
      const div = document.createElement("div");
      div.className = "domain-row";
      div.innerHTML = `<span class="domain-label">${label}</span><span class="domain-value">${value}</span>`;
      ui.domainDetails.appendChild(div);
    });
  }
}


// ─── UI state helpers ────────────────────────────────────────────────────────

function showLoading() {
  hideAll();
  ui.loadingState.classList.remove("hidden");
  ui.scanBtn.disabled = true;
}

function showError(msg) {
  hideAll();
  ui.errorState.classList.remove("hidden");
  ui.errorMessage.textContent = msg;
  ui.scanBtn.disabled = false;
}

function hideAll() {
  ui.loadingState.classList.add("hidden");
  ui.resultCard.classList.add("hidden");
  ui.errorState.classList.add("hidden");
  ui.breakdownSection.classList.add("hidden");
  ui.nlpSection.classList.add("hidden");
  ui.domainSection.classList.add("hidden");
  ui.scanBtn.disabled = false;
}
