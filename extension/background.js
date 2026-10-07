// CyberGuard Sentinel — Chrome Background Service Worker
const BACKEND_ENDPOINT = 'http://localhost:8000/api/v1/monitor/realtime-check';
const REVALIDATION_COOLDOWN_MS = 30 * 60 * 1000; // 30 minutes

// Map of tabId -> { url, lastCheckedAt }
const activeTabs = new Map();
// Map of normalizedUrl -> lastCheckedAt
const urlCheckHistory = new Map();

// Helper to normalize URLs
function normalizeUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    return (u.origin + u.pathname).toLowerCase().replace(/\/+$/, '');
  } catch {
    return (rawUrl || '').toLowerCase().trim().replace(/\/+$/, '');
  }
}

// Evaluate URL against CyberGuard Backend
async function evaluateUrl(url, reasonLabel = "Navigation en direct") {
  if (!url || typeof url !== 'string') return;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  if (url.includes('localhost:3000') || url.includes('127.0.0.1:3000')) return;

  const norm = normalizeUrl(url);
  const now = Date.now();
  const lastChecked = urlCheckHistory.get(norm);

  // If already tested within 30 minutes, skip repeated notification unless re-opened
  if (lastChecked && (now - lastChecked < REVALIDATION_COOLDOWN_MS) && reasonLabel === "periodic") {
    return;
  }

  urlCheckHistory.set(norm, now);

  try {
    const res = await fetch(BACKEND_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    if (res.ok) {
      const data = await res.json();
      displayNotification(data);
      broadcastToCyberguardTab(data);
    }
  } catch (err) {
    console.warn('[CyberGuard Sentinel] Backend unreachable:', err);
  }
}

// Display real desktop notification (Windows Toast / Chrome Notification)
function displayNotification(data) {
  const isSafe = data.is_safe;
  const notifId = 'cyberguard-' + Date.now();

  const title = isSafe 
    ? `🛡️ CyberGuard : Ressource Saine (${data.latency_ms || 18}ms)` 
    : `🚨 CyberGuard : MENACE DÉTECTÉE (${data.verdict})`;

  const message = isSafe
    ? `Site vérifié et conforme : ${data.url}\nRisque: ${Math.round(data.risk_score)}% (Faible)`
    : `ATTENTION : ${data.url}\nRisque: ${Math.round(data.risk_score)}% — Phishing intercepté !`;

  chrome.notifications.create(notifId, {
    type: 'basic',
    iconUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%230ea5e9"><path d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3z"/></svg>',
    title: title,
    message: message,
    priority: isSafe ? 0 : 2
  });

  // Auto clear notification after 8 seconds
  setTimeout(() => {
    chrome.notifications.clear(notifId);
  }, 8000);
}

// Send event to open CyberGuard web dashboard (localhost:3000)
async function broadcastToCyberguardTab(data) {
  try {
    const tabs = await chrome.tabs.query({ url: "*://localhost:3000/*" });
    tabs.forEach(tab => {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (alertData) => {
          window.dispatchEvent(new CustomEvent('cyberguard:inspect-url', {
            detail: {
              url: alertData.url,
              isNewOpen: true,
              context: 'Navigation Chrome Interceptée'
            }
          }));
        },
        args: [data]
      }).catch(() => {});
    });
  } catch (e) {}
}

// 1. Listen for new or updated tabs (user opened a URL in Chrome)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const prevTabInfo = activeTabs.get(tabId);
    const isNewOpening = !prevTabInfo || prevTabInfo.url !== tab.url;

    activeTabs.set(tabId, {
      url: tab.url,
      openedAt: Date.now()
    });

    if (isNewOpening) {
      evaluateUrl(tab.url, "Ouverture d'onglet");
    }
  }
});

// 2. Listen for tab closed (user closed a URL in Chrome)
chrome.tabs.onRemoved.addListener((tabId) => {
  const tabInfo = activeTabs.get(tabId);
  if (tabInfo) {
    // URL was closed. Allow immediate re-testing if opened again.
    const norm = normalizeUrl(tabInfo.url);
    urlCheckHistory.delete(norm);
    activeTabs.delete(tabId);
  }
});

// 3. Periodic re-check every 5 minutes: if a tab has been open for > 30 minutes, re-test it
setInterval(() => {
  const now = Date.now();
  for (const [tabId, info] of activeTabs.entries()) {
    if (now - info.openedAt >= REVALIDATION_COOLDOWN_MS) {
      info.openedAt = now; // reset
      evaluateUrl(info.url, "periodic");
    }
  }
}, 300000); // Check every 5 minutes
