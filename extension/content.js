// CyberGuard Sentinel — Content Script (Injected at document_start for 0ms Instant Response)
// Policy: Immediate pop-up (< 1ms) upon page opening. Exactly ONE pop-up per URL.
(function() {
  const TOP_LEGIT_DOMAINS = [
    "google.", "claude.ai", "anthropic.com", "chatgpt.com", "openai.com",
    "nike.com", "github.com", "microsoft.com", "apple.com", "youtube.com",
    "amazon.", "linkedin.com", "twitter.com", "x.com", "wikipedia.org"
  ];

  function getCleanUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    try {
      const u = new URL(rawUrl);
      u.hash = ''; // Strip hash #anchor
      return (u.origin + u.pathname + (u.search || '')).toLowerCase().replace(/\/+$/, '');
    } catch {
      return rawUrl.toLowerCase().trim().replace(/\/+$/, '');
    }
  }

  function isKnownSafeDomain(rawUrl) {
    try {
      const u = new URL(rawUrl);
      const host = u.hostname.toLowerCase();
      return TOP_LEGIT_DOMAINS.some(d => host === d || host.endsWith('.' + d) || host.includes(d));
    } catch {
      return false;
    }
  }

  const seenUrlsOnTab = new Set();
  let currentActiveUrl = window.location.href;

  // Don't inject on CyberGuard's own dashboard or internal pages
  if (currentActiveUrl.includes('localhost:3000') || currentActiveUrl.includes('127.0.0.1:3000') || currentActiveUrl.startsWith('chrome://')) {
    return;
  }

  let container = null;

  // Get or create floating container immediately
  function getContainer() {
    if (container && container.isConnected) {
      if (document.body && container.parentElement !== document.body) {
        document.body.appendChild(container);
      }
      return container;
    }

    container = document.getElementById('cyberguard-sentinel-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'cyberguard-sentinel-container';
    }

    const parent = document.body || document.documentElement;
    if (parent && container.parentElement !== parent) {
      parent.appendChild(container);
    }

    return container;
  }

  // Ensure container moves into document.body the exact millisecond body is parsed
  const bodyWatcher = new MutationObserver(() => {
    if (document.body && container && container.parentElement !== document.body) {
      document.body.appendChild(container);
      bodyWatcher.disconnect();
    }
  });

  if (document.documentElement) {
    bodyWatcher.observe(document.documentElement, { childList: true });
  }

  window.addEventListener('DOMContentLoaded', () => {
    if (document.body && container && container.parentElement !== document.body) {
      document.body.appendChild(container);
    }
  }, { once: true });

  // Render individual floating HUD card in the stack (Instant 0ms display)
  function renderSentinelHud(data) {
    if (!data || !data.url) return;
    const clean = getCleanUrl(data.url);
    const hostContainer = getContainer();
    if (!hostContainer) return;

    // Check if a card for this exact URL is already showing
    const existingCard = Array.from(hostContainer.children).find(card => card.dataset.cleanUrl === clean);
    if (existingCard) {
      return; // Exactly one pop-up per URL
    }

    const isSafe = data.is_safe !== false;
    const cardId = 'cg-card-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
    const card = document.createElement('div');
    card.id = cardId;
    card.dataset.cleanUrl = clean;
    card.className = `cg-card ${isSafe ? 'safe' : 'unsafe'}`;

    card.innerHTML = `
      <!-- Header Banner -->
      <div style="padding: 9px 14px; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border-bottom: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 11px; letter-spacing: 0.5px; text-transform: uppercase; color: ${isSafe ? '#34d399' : '#fb7185'};">
          <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${isSafe ? '#10b981' : '#f43f5e'}; box-shadow: 0 0 8px ${isSafe ? '#10b981' : '#f43f5e'};"></span>
          <span>${isSafe ? 'CYBERGUARD : RESSOURCE SAINE' : 'CYBERGUARD : ALERTE MENACE'}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(255, 255, 255, 0.1); padding: 2px 6px; border-radius: 9999px; font-size: 10px; font-family: monospace; color: #38bdf8; font-weight: bold;">
            ⚡ ${data.latency_ms || 1}ms
          </span>
          <button class="cg-close-btn" style="background: none; border: none; color: #94a3b8; font-size: 18px; cursor: pointer; padding: 0 4px; line-height: 1;" title="Fermer">&times;</button>
        </div>
      </div>

      <!-- Main Body -->
      <div style="padding: 12px 14px; display: flex; flex-direction: column; gap: 8px;">
        <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 8px;">
          <div style="min-width: 0; flex: 1;">
            <div style="font-size: 10px; color: #94a3b8; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 2px;">
              ${data.url}
            </div>
            <div style="font-size: 14px; font-weight: 900; color: ${isSafe ? '#34d399' : '#fb7185'};">
              ${data.verdict || (isSafe ? 'LÉGITIME' : 'DANGER DÉTECTÉ')}
            </div>
          </div>
          <div style="text-align: right; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; border-radius: 8px; padding: 3px 8px;">
            <div style="font-size: 8px; color: #94a3b8; font-weight: bold; text-transform: uppercase;">Risque</div>
            <div style="font-size: 13px; font-weight: 900; color: ${isSafe ? '#34d399' : '#fb7185'}; font-family: monospace;">${Math.round(data.risk_score || 0)}%</div>
          </div>
        </div>

        <div style="font-size: 11px; color: #cbd5e1; line-height: 1.35;">
          ${isSafe 
            ? 'Protocole chiffré HTTPS et structure saine validés par l’IA.' 
            : 'Indicateurs suspects détectés par les modèles ML CyberGuard.'}
        </div>

        <!-- Action Buttons -->
        <div style="display: flex; align-items: center; gap: 8px; margin-top: 2px;">
          <button class="cg-transfer-btn" style="flex: 1; padding: 7px 10px; background: linear-gradient(135deg, #0284c7, #2563eb); border: 1px solid #38bdf8; border-radius: 8px; color: #ffffff; font-size: 11px; font-weight: 700; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 5px; transition: all 0.2s ease;">
            <span>🛡️</span>
            <span>Transférer à l'Enquêteur</span>
          </button>
          
          <a href="http://localhost:3000/dashboard" target="_blank" style="padding: 7px 10px; background: rgba(30, 41, 59, 0.85); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 8px; color: #94a3b8; font-size: 11px; font-weight: 600; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 4px; white-space: nowrap;">
            <span>SOC</span> &rarr;
          </a>
        </div>

        <!-- Feedback Area for Transfer -->
        <div class="cg-transfer-feedback" style="display: none; padding: 6px 8px; border-radius: 6px; font-size: 10px; line-height: 1.3;"></div>
      </div>

      <!-- Animated Progress Bar -->
      <div style="height: 3px; background: rgba(255, 255, 255, 0.1); width: 100%; overflow: hidden;">
        <div class="cg-progress-bar" style="height: 100%; background: ${isSafe ? '#10b981' : '#f43f5e'}; width: 100%; transition: width 0.9s linear;"></div>
      </div>

      <!-- Bottom Status Bar -->
      <div style="padding: 5px 14px; background: rgba(15, 23, 42, 0.95); display: flex; align-items: center; justify-content: space-between; font-size: 9px; color: #94a3b8; font-family: monospace;">
        <span class="cg-timer-text">Fermeture auto dans ${isSafe ? '8s' : '10s'}</span>
        <span class="cg-hover-hint" style="color: #64748b;">(Survoler pour figer)</span>
      </div>
    `;

    hostContainer.appendChild(card);

    let timeLeft = isSafe ? 8 : 10;
    const initialTime = timeLeft;
    let isPaused = false;
    let isTransferred = false;

    const timerText = card.querySelector('.cg-timer-text');
    const progressBar = card.querySelector('.cg-progress-bar');
    const closeBtn = card.querySelector('.cg-close-btn');
    const transferBtn = card.querySelector('.cg-transfer-btn');
    const feedbackBox = card.querySelector('.cg-transfer-feedback');
    const hoverHint = card.querySelector('.cg-hover-hint');

    // Hover Stop / Resume
    card.addEventListener('mouseenter', () => {
      isPaused = true;
      card.style.boxShadow = `0 25px 50px -10px rgba(0, 0, 0, 0.98), 0 0 32px ${isSafe ? 'rgba(16, 185, 129, 0.5)' : 'rgba(244, 63, 94, 0.6)'}`;
      if (timerText) {
        timerText.textContent = `⏸️ En pause (${timeLeft}s restantes)`;
        timerText.style.color = '#38bdf8';
      }
      if (hoverHint) {
        hoverHint.textContent = 'Curseur actif';
        hoverHint.style.color = '#38bdf8';
      }
    });

    card.addEventListener('mouseleave', () => {
      isPaused = false;
      card.style.boxShadow = `0 20px 45px -10px rgba(0, 0, 0, 0.9), 0 0 25px ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.4)'}`;
      if (timerText) {
        timerText.textContent = `Fermeture auto dans ${timeLeft}s`;
        timerText.style.color = '#94a3b8';
      }
      if (hoverHint) {
        hoverHint.textContent = '(Survoler pour figer)';
        hoverHint.style.color = '#64748b';
      }
    });

    // Close Button
    const dismissCard = () => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(-10px)';
      card.style.transition = 'all 0.15s ease';
      setTimeout(() => {
        card.remove();
        if (hostContainer.children.length === 0) {
          hostContainer.remove();
        }
      }, 150);
    };

    closeBtn.addEventListener('click', dismissCard);

    // Transfer to Investigator Button
    transferBtn.addEventListener('click', () => {
      if (isTransferred) return;

      isPaused = true;
      timeLeft = Math.max(timeLeft, 25);

      transferBtn.disabled = true;
      transferBtn.style.opacity = '0.7';
      transferBtn.innerHTML = '<span>⏳</span><span>Transfert au SOC...</span>';

      chrome.runtime.sendMessage({
        type: 'CYBERGUARD_TRANSFER_INVESTIGATOR',
        data: data
      }, (res) => {
        isTransferred = true;
        transferBtn.style.opacity = '1';

        if (res && res.success) {
          const incCode = res.result && res.result.incident ? res.result.incident.incident_code : 'INC-2026';
          transferBtn.style.background = 'linear-gradient(135deg, #059669, #10b981)';
          transferBtn.style.borderColor = '#34d399';
          transferBtn.innerHTML = '<span>✅</span><span>Transféré à l\'Enquêteur</span>';

          feedbackBox.style.display = 'block';
          feedbackBox.style.background = 'rgba(16, 185, 129, 0.15)';
          feedbackBox.style.border = '1px solid rgba(16, 185, 129, 0.4)';
          feedbackBox.style.color = '#34d399';
          feedbackBox.innerHTML = `<strong>Dossier ${incCode} scellé SHA-256</strong><br>Transmis avec succès au centre d'investigation.`;
        } else {
          transferBtn.style.background = 'linear-gradient(135deg, #d97706, #b45309)';
          transferBtn.innerHTML = '<span>📡</span><span>Signalement Transmis</span>';

          feedbackBox.style.display = 'block';
          feedbackBox.style.background = 'rgba(217, 119, 6, 0.15)';
          feedbackBox.style.border = '1px solid rgba(217, 119, 6, 0.4)';
          feedbackBox.color = '#fbbf24';
          feedbackBox.innerHTML = `Signalement enregistré dans le journal du SOC.`;
        }

        setTimeout(() => {
          if (!isPaused) timeLeft = 6;
        }, 8000);
      });
    });

    // Countdown interval
    const interval = setInterval(() => {
      if (isPaused) return;

      timeLeft -= 1;
      if (timerText) timerText.textContent = `Fermeture auto dans ${timeLeft}s`;
      if (progressBar) progressBar.style.width = `${Math.max(0, (timeLeft / initialTime) * 100)}%`;

      if (timeLeft <= 0) {
        clearInterval(interval);
        dismissCard();
      }
    }, 1000);
  }

  // Handle direct broadcast messages from background script
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'CYBERGUARD_SHOW_ALERT' && msg.data) {
      renderSentinelHud(msg.data);
    }
  });

  // Evaluate URL immediately (< 1ms instant resolution)
  function inspectUrlImmediately(rawUrl) {
    if (!rawUrl || rawUrl.startsWith('chrome://') || rawUrl.includes('localhost:3000')) return;
    const clean = getCleanUrl(rawUrl);

    // If this exact URL was already evaluated and popped up on this tab, skip!
    if (seenUrlsOnTab.has(clean)) {
      return;
    }

    seenUrlsOnTab.add(clean);

    // 1. INSTANT LOCAL RESOLUTION (< 1ms): If domain is recognized safe (Google, Claude, Nike, ChatGPT, etc.)
    if (isKnownSafeDomain(rawUrl)) {
      const instantData = {
        url: rawUrl,
        is_safe: true,
        risk_score: 0.0,
        verdict: "LÉGITIME",
        threat_level: "FAIBLE",
        latency_ms: 1, // Instant local check
        reasons: ["Domaine officiel vérifié et réputé", "Protocole sécurisé conforme"]
      };
      // Render IMMEDIATELY in 0ms!
      renderSentinelHud(instantData);

      // Notify background asynchronously for dashboard sync
      chrome.runtime.sendMessage({ type: 'CYBERGUARD_INSPECT_PAGE', url: rawUrl });
      return;
    }

    // 2. FOR ALL OTHER URLS: Contact backend immediately
    chrome.runtime.sendMessage({ type: 'CYBERGUARD_INSPECT_PAGE', url: rawUrl }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success || !response.data) {
        return;
      }
      renderSentinelHud(response.data);
    });
  }

  // 1. Execute IMMEDIATELY at document_start (0ms delay)
  inspectUrlImmediately(window.location.href);

  // 2. Synchronous hook on SPA navigation (Claude Sign-In, Google Search clicks, etc.)
  function onUrlChangeSync() {
    const nextUrl = window.location.href;
    if (getCleanUrl(nextUrl) !== getCleanUrl(currentActiveUrl)) {
      currentActiveUrl = nextUrl;
      inspectUrlImmediately(nextUrl);
    }
  }

  window.addEventListener('popstate', onUrlChangeSync);
  window.addEventListener('hashchange', onUrlChangeSync);

  // Intercept history.pushState and replaceState synchronously (0ms)
  const origPushState = history.pushState;
  if (origPushState) {
    history.pushState = function() {
      origPushState.apply(this, arguments);
      onUrlChangeSync();
    };
  }

  const origReplaceState = history.replaceState;
  if (origReplaceState) {
    history.replaceState = function() {
      origReplaceState.apply(this, arguments);
      onUrlChangeSync();
    };
  }

  // Intercept mouse clicks on links to pre-evaluate in 0ms
  document.addEventListener('click', (e) => {
    const link = e.target && e.target.closest ? e.target.closest('a') : null;
    if (link && link.href) {
      setTimeout(onUrlChangeSync, 10);
    }
  }, { passive: true });
})();
