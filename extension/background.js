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
  if (!url || typeof url !== 'string') return null;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return null;
  if (url.includes('localhost:3000') || url.includes('127.0.0.1:3000')) return null;

  const norm = normalizeUrl(url);
  const now = Date.now();
  const lastChecked = urlCheckHistory.get(norm);

  // If already tested within 30 minutes, skip repeated notification unless re-opened
  if (lastChecked && (now - lastChecked < REVALIDATION_COOLDOWN_MS) && reasonLabel === "periodic") {
    return null;
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
      return data;
    }
  } catch (err) {
    console.warn('[CyberGuard Sentinel] Backend unreachable:', err);
  }
  return null;
}

// Display real desktop notification (Windows Toast / Chrome Notification)
function displayNotification(data) {
  if (!data) return;
  const isSafe = data.is_safe;
  const notifId = 'cyberguard-' + Date.now();

  const title = isSafe 
    ? `🛡️ CyberGuard : Ressource Saine (${data.latency_ms || 18}ms)` 
    : `🚨 CyberGuard : MENACE DÉTECTÉE (${data.verdict})`;

  const message = isSafe
    ? `Site vérifié et conforme : ${data.url}\nRisque: ${Math.round(data.risk_score)}% (Faible)`
    : `ATTENTION : ${data.url}\nRisque: ${Math.round(data.risk_score)}% — Phishing intercepté !`;

  try {
    chrome.notifications.create(notifId, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icon.png'),
      title: title,
      message: message,
      priority: isSafe ? 0 : 2
    });

    setTimeout(() => {
      chrome.notifications.clear(notifId);
    }, 8000);
  } catch (e) {
    console.warn('Notification error:', e);
  }
}

// Send event to open CyberGuard web dashboard (localhost:3000)
async function broadcastToCyberguardTab(data) {
  if (!data) return;
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

// Helper to transfer alert directly to Investigator queue
async function transferToInvestigator(alertData) {
  try {
    const res = await fetch('http://localhost:8000/api/v1/incidents/submit-user-report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: `Alerte Sentinelle: ${alertData.url.substring(0, 60)}`,
        target: alertData.url,
        scan_type: "URL",
        verdict: alertData.verdict || (alertData.is_safe ? "CLEAN" : "SUSPICIOUS"),
        risk_score: parseFloat(alertData.risk_score || 0),
        details: {
          intercepted_by: "Extension Chrome Sentinel CyberGuard",
          latency_ms: alertData.latency_ms || 18,
          timestamp: new Date().toISOString()
        },
        reporter_name: "Sentinelle Navigateur (Temps Réel)",
        reporter_email: "sentinel@cyberguard.local"
      })
    });
    if (res.ok) {
      const result = await res.json();
      return { success: true, result };
    }
    return { success: false, status: res.status };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// Handle message from content script injected on web pages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CYBERGUARD_INSPECT_PAGE' && message.url) {
    evaluateUrl(message.url, "Chargement de page").then(data => {
      sendResponse({ success: true, data });
    }).catch(err => {
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep channel open for async response
  }

  if (message.type === 'CYBERGUARD_TRANSFER_INVESTIGATOR' && message.data) {
    transferToInvestigator(message.data).then(res => {
      sendResponse(res);
    }).catch(err => {
      sendResponse({ success: false, error: err.message });
    });
    return true;
  }
});


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
    const norm = normalizeUrl(tabInfo.url);
    urlCheckHistory.delete(norm);
    activeTabs.delete(tabId);
  }
});

// 3. Periodic re-check: if a tab has been open for > 30 minutes, re-test it
setInterval(() => {
  const now = Date.now();
  for (const [tabId, info] of activeTabs.entries()) {
    if (now - info.openedAt >= REVALIDATION_COOLDOWN_MS) {
      info.openedAt = now;
      evaluateUrl(info.url, "periodic");
    }
  }
}, 300000); // 5 min interval
