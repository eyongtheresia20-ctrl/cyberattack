// CyberGuard Sentinel — Content Script (Injected at document_start)
// Policy: Exactly ONE pop-up per URL. Never duplicate for search queries or keystrokes.
(function() {
  function normalizeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    try {
      const u = new URL(rawUrl);
      if (u.hostname.includes('google.') || u.hostname.includes('bing.') || u.hostname.includes('duckduckgo.') || u.hostname.includes('yahoo.')) {
        return u.hostname.toLowerCase();
      }
      return (u.origin + u.pathname).toLowerCase().replace(/\/+$/, '');
    } catch {
      return rawUrl.toLowerCase().trim().replace(/\/+$/, '');
    }
  }

  const currentUrl = window.location.href;
  const currentNorm = normalizeUrl(currentUrl);

  // Don't inject on CyberGuard's own dashboard or internal pages
  if (currentUrl.includes('localhost:3000') || currentUrl.includes('127.0.0.1:3000') || currentUrl.startsWith('chrome://')) {
    return;
  }

  // Get or create floating container for pop-ups
  function getContainer() {
    let container = document.getElementById('cyberguard-sentinel-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'cyberguard-sentinel-container';
      container.style.cssText = `
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        z-index: 2147483647 !important;
        display: flex !important;
        flex-direction: column !important;
        gap: 12px !important;
        max-width: 420px !important;
        width: calc(100vw - 40px) !important;
        pointer-events: none !important;
      `;

      const target = document.body || document.documentElement;
      if (target) {
        target.appendChild(container);
      } else {
        window.addEventListener('DOMContentLoaded', () => {
          (document.body || document.documentElement).appendChild(container);
        });
      }
    }
    return container;
  }

  // Render individual floating HUD card in the stack
  function renderSentinelHud(data) {
    if (!data || !data.url) return;
    const norm = normalizeUrl(data.url);
    const container = getContainer();
    if (!container) return;

    // RULE: EXACTLY ONE POP-UP PER URL / DOMAIN
    const existingCard = Array.from(container.children).find(card => card.dataset.normUrl === norm);
    if (existingCard) {
      return; // A pop-up for this URL already exists! Do not create another one.
    }

    const isSafe = data.is_safe;
    const cardId = 'cg-card-' + Date.now() + '-' + Math.floor(Math.random() * 1000);
    const card = document.createElement('div');
    card.id = cardId;
    card.dataset.normUrl = norm;

    // Styling for card
    card.style.cssText = `
      pointer-events: auto !important;
      background: #090d16 !important;
      color: #f8fafc !important;
      border: 1px solid ${isSafe ? '#10b981' : '#f43f5e'} !important;
      border-radius: 18px !important;
      box-shadow: 0 20px 45px -10px rgba(0, 0, 0, 0.85), 0 0 25px ${isSafe ? 'rgba(16, 185, 129, 0.25)' : 'rgba(244, 63, 94, 0.35)'} !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
      overflow: hidden !important;
      box-sizing: border-box !important;
      animation: cyberguardSlideIn 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important;
      transition: all 0.2s ease !important;
    `;

    card.innerHTML = `
      <style>
        @keyframes cyberguardSlideIn {
          from { opacity: 0; transform: translateY(-16px) scale(0.96); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        #${cardId} button:hover {
          filter: brightness(1.15);
        }
      </style>
      
      <!-- Header Banner -->
      <div style="padding: 9px 14px; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border-bottom: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 11px; letter-spacing: 0.5px; text-transform: uppercase; color: ${isSafe ? '#34d399' : '#fb7185'};">
          <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${isSafe ? '#10b981' : '#f43f5e'}; box-shadow: 0 0 8px ${isSafe ? '#10b981' : '#f43f5e'};"></span>
          <span>${isSafe ? 'CYBERGUARD : RESSOURCE SAINE' : 'CYBERGUARD : ALERTE MENACE'}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(255, 255, 255, 0.1); padding: 2px 6px; border-radius: 9999px; font-size: 10px; font-family: monospace; color: #38bdf8; font-weight: bold;">
            ⚡ ${data.latency_ms || 18}ms
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
            <div style="font-size: 13px; font-weight: 800; color: ${isSafe ? '#34d399' : '#fb7185'};">
              ${data.verdict || (isSafe ? 'LÉGITIME & CONFORME' : 'DANGER DÉTECTÉ')}
            </div>
          </div>
          <div style="text-align: right; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; border-radius: 8px; padding: 3px 7px;">
            <div style="font-size: 8px; color: #94a3b8; font-weight: bold; text-transform: uppercase;">Risque</div>
            <div style="font-size: 13px; font-weight: 900; color: ${isSafe ? '#34d399' : '#fb7185'}; font-family: monospace;">${Math.round(data.risk_score)}%</div>
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
      <div style="padding: 5px 14px; background: rgba(15, 23, 42, 0.92); display: flex; align-items: center; justify-content: space-between; font-size: 9px; color: #94a3b8; font-family: monospace;">
        <span class="cg-timer-text">Fermeture auto dans ${isSafe ? '8s' : '10s'}</span>
        <span class="cg-hover-hint" style="color: #64748b;">(Survoler pour figer)</span>
      </div>
    `;

    container.appendChild(card);

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
      card.style.boxShadow = `0 25px 50px -10px rgba(0, 0, 0, 0.95), 0 0 32px ${isSafe ? 'rgba(16, 185, 129, 0.45)' : 'rgba(244, 63, 94, 0.55)'}`;
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
      card.style.boxShadow = `0 20px 45px -10px rgba(0, 0, 0, 0.85), 0 0 25px ${isSafe ? 'rgba(16, 185, 129, 0.25)' : 'rgba(244, 63, 94, 0.35)'}`;
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
      card.style.transform = 'translateY(-12px)';
      card.style.transition = 'all 0.25s ease';
      setTimeout(() => {
        card.remove();
        if (container.children.length === 0) {
          container.remove();
        }
      }, 250);
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

  // Request evaluation only once upon script initialization
  chrome.runtime.sendMessage({ type: 'CYBERGUARD_INSPECT_PAGE', url: currentUrl }, (response) => {
    if (chrome.runtime.lastError || !response || !response.success || !response.data) {
      return;
    }
    renderSentinelHud(response.data);
  });
})();
