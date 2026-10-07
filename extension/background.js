// CyberGuard Sentinel — Chrome Background Service Worker
// NOTE: Pure in-memory real-time check. Does NOT modify the database.
const BACKEND_ENDPOINT = 'http://localhost:8000/api/v1/monitor/realtime-check';
const REVALIDATION_COOLDOWN_MS = 15 * 60 * 1000; // 15 minutes

// Map of tabId -> { url, lastCheckedAt, openedAt }
const activeTabs = new Map();
// Map of normalizedUrl -> lastCheckedAt
const urlCheckHistory = new Map();

// Helper to normalize URLs (merges search query updates into single base URL)
function normalizeUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const u = new URL(rawUrl);
    // For search engines (google, bing, duckduckgo, yahoo), normalize to base host to prevent search typing spam
    if (u.hostname.includes('google.') || u.hostname.includes('bing.') || u.hostname.includes('duckduckgo.') || u.hostname.includes('yahoo.')) {
      return u.hostname.toLowerCase();
    }
    // For all websites, use origin + pathname (ignores query params like ?q=... ?ref=...)
    return (u.origin + u.pathname).toLowerCase().replace(/\/+$/, '');
  } catch {
    return rawUrl.toLowerCase().trim().replace(/\/+$/, '');
  }
}

// Evaluate URL against CyberGuard Backend (strictly memory-only, no DB writes)
// Policy: Exactly ONE pop-up per URL. Re-checks only after 15 minutes.
async function evaluateUrl(url, reasonLabel = "Navigation en direct", tabId = null) {
  if (!url || typeof url !== 'string') return null;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return null;
  if (url.includes('localhost:3000') || url.includes('127.0.0.1:3000')) return null;

  const norm = normalizeUrl(url);
  const now = Date.now();
  const lastChecked = urlCheckHistory.get(norm);

  // STRICT RULE: If this URL has already popped up in the last 15 minutes, DO NOT POP UP AGAIN!
  // Only periodic re-check after 15 minutes can trigger another pop-up.
  if (lastChecked && (now - lastChecked < REVALIDATION_COOLDOWN_MS) && reasonLabel !== "periodic") {
    return null; // Suppress duplicate pop-ups for the same URL
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

      // Deliver directly to the specific tab
      if (tabId) {
        chrome.tabs.sendMessage(tabId, { type: 'CYBERGUARD_SHOW_ALERT', data }).catch(() => {});
      }
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
// Identical to how a user sends an analysed URL to the investigator in CyberGuard
async function transferToInvestigator(alertData) {
  try {
    const payload = {
      title: `[Signalement URL] ${alertData.url}`,
      target: alertData.url,
      scan_type: "URL",
      verdict: alertData.verdict || (alertData.is_safe ? "LÉGITIME" : "SUSPECT"),
      risk_score: parseFloat(alertData.risk_score || 0),
      details: {
        report_category: "Signalement URL",
        user_observations: "Rapport généré par l'utilisateur pour étude approfondie par l'enquêteur SOC.",
        features: alertData.features || {},
        reasons: alertData.reasons || [],
        latency_ms: alertData.latency_ms || 18,
        intercepted_by: "Sentinelle Utilisateur CyberGuard",
        timestamp: new Date().toISOString()
      },
      reporter_name: "Utilisateur Standard",
      reporter_email: "alice.martin@example.com"
    };

    const res = await fetch('http://localhost:8000/api/v1/incidents/submit-user-report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
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
    evaluateUrl(message.url, "Chargement de page", sender.tab?.id).then(data => {
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

// ULTRA-FAST INSTANT NAVIGATION DETECTION:
// Fires immediately when a new URL starts navigating
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0 && details.url) { // Main frame only
      const norm = normalizeUrl(details.url);
      const prev = activeTabs.get(details.tabId);
      
      if (!prev || normalizeUrl(prev.url) !== norm) {
        activeTabs.set(details.tabId, {
          url: details.url,
          openedAt: Date.now()
        });
        evaluateUrl(details.url, "Navigation", details.tabId);
      }
    }
  });
}

// Tab closed tracking
chrome.tabs.onRemoved.addListener((tabId) => {
  const tabInfo = activeTabs.get(tabId);
  if (tabInfo) {
    const norm = normalizeUrl(tabInfo.url);
    urlCheckHistory.delete(norm);
    activeTabs.delete(tabId);
  }
});

// Periodic re-check: every minute, check if any tab has been open for > 15 minutes
setInterval(() => {
  const now = Date.now();
  for (const [tabId, info] of activeTabs.entries()) {
    if (now - info.openedAt >= REVALIDATION_COOLDOWN_MS) {
      info.openedAt = now; // reset 15min window
      evaluateUrl(info.url, "periodic", tabId);
    }
  }
}, 60000);
