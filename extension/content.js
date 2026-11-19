/**
 * PhishGuard — Content Script
 * 
 * Injected into every webpage to extract visible text content
 * for NLP analysis. Only sends data when explicitly requested
 * by the popup. Never stores or transmits data automatically.
 * 
 * Privacy: No browsing history is stored. Content is processed
 * in-memory and discarded after analysis.
 */

// ─── Message listener ────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "extractContent") {
    try {
      const content = extractPageContent();
      sendResponse({ content: content });
    } catch (err) {
      sendResponse({ error: err.message, content: "" });
    }
    return true;
  }
});


// ─── Content extraction ──────────────────────────────────────────────────────

function extractPageContent() {
  if (!document.body) return "";
  // Get visible text, stripping scripts and styles
  const clone = document.body.cloneNode(true);

  // Remove non-visible elements
  const removeSelectors = [
    "script", "style", "noscript", "iframe", "svg",
    "link", "meta", "head", "[hidden]", "[aria-hidden='true']",
  ];

  removeSelectors.forEach((sel) => {
    clone.querySelectorAll(sel).forEach((el) => el.remove());
  });

  // Extract text
  let text = clone.innerText || clone.textContent || "";

  // Clean up excessive whitespace
  text = text.replace(/\s+/g, " ").trim();

  // Limit to 5000 characters to avoid oversized payloads
  if (text.length > 5000) {
    text = text.substring(0, 5000);
  }

  return text;
}
