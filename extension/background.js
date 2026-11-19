/**
 * PhishGuard — Background Service Worker (Manifest V3)
 * 
 * Handles communication between the popup/content scripts and the
 * FastAPI backend. Manages badge updates and analysis state.
 */

const API_BASE = "http://127.0.0.1:8000";

// ─── Message handler ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyzeUrl") {
    analyzeUrl(message.url, message.pageContent)
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true; // keep the message channel open for async response
  }

  if (message.action === "checkHealth") {
    checkHealth()
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.action === "getPageContent") {
    // Forward to content script in the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, { action: "extractContent" }, sendResponse);
      } else {
        sendResponse({ error: "No active tab" });
      }
    });
    return true;
  }
});


// ─── API calls ───────────────────────────────────────────────────────────────

async function analyzeUrl(url, pageContent = null) {
  try {
    const body = {
      url: url,
      page_content: pageContent,
      check_domain: true,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const result = await response.json();

    // Update extension badge based on result
    updateBadge(result.risk_level);

    // Store result briefly for popup (privacy: no URL stored, auto-clears)
    chrome.storage.session.set({
      lastResult: result,
      timestamp: Date.now(),
    });

    return result;
  } catch (err) {
    updateBadge("error");
    if (err.name === "AbortError") {
      throw new Error("Backend connection timed out. Is the FastAPI server running on http://127.0.0.1:8000?");
    }
    throw new Error(`Backend offline or unreachable (${err.message}). Start the server using 'python main.py' in the backend folder.`);
  }
}


async function checkHealth() {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);

    const response = await fetch(`${API_BASE}/api/health`, {
      method: "GET",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
    }).finally(() => clearTimeout(timer));

    if (!response.ok) {
      return { status: "offline", error: `HTTP ${response.status}` };
    }

    return await response.json();
  } catch (err) {
    return { status: "offline", error: err.message };
  }
}


// ─── Badge management ────────────────────────────────────────────────────────

function updateBadge(riskLevel) {
  const badges = {
    safe:      { text: "✓",  color: "#22c55e" },
    warning:   { text: "!",  color: "#f59e0b" },
    phishing:  { text: "✗",  color: "#ef4444" },
    high_risk: { text: "✗✗", color: "#dc2626" },
    error:     { text: "?",  color: "#6b7280" },
  };

  const badge = badges[riskLevel] || badges.error;

  chrome.action.setBadgeText({ text: badge.text });
  chrome.action.setBadgeBackgroundColor({ color: badge.color });
}


// ─── Auto-clear session data on tab change (privacy) ─────────────────────────

chrome.tabs.onActivated.addListener(() => {
  chrome.action.setBadgeText({ text: "" });
  chrome.storage.session.remove(["lastResult", "timestamp"]);
});
