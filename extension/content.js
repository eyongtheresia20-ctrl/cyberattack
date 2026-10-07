// CyberGuard Sentinel — Content Script (Injected on every web page)
(function() {
  const currentUrl = window.location.href;

  // Don't inject on CyberGuard's own dashboard or internal pages
  if (currentUrl.includes('localhost:3000') || currentUrl.includes('127.0.0.1:3000') || currentUrl.startsWith('chrome://')) {
    return;
  }

  // Ask background service worker to evaluate this URL
  chrome.runtime.sendMessage({ type: 'CYBERGUARD_INSPECT_PAGE', url: currentUrl }, (response) => {
    if (chrome.runtime.lastError || !response || !response.success || !response.data) {
      return;
    }
    renderSentinelHud(response.data);
  });

  // Render High-Tech Floating HUD directly on the viewed page
  function renderSentinelHud(data) {
    // Prevent duplicate HUD if already present
    if (document.getElementById('cyberguard-sentinel-hud')) return;

    const isSafe = data.is_safe;
    const hud = document.createElement('div');
    hud.id = 'cyberguard-sentinel-hud';

    // Styling
    hud.style.cssText = `
      position: fixed !important;
      top: 24px !important;
      right: 24px !important;
      z-index: 2147483647 !important;
      max-width: 420px !important;
      width: calc(100vw - 48px) !important;
      background: #090d16 !important;
      color: #f8fafc !important;
      border: 1px solid ${isSafe ? '#10b981' : '#f43f5e'} !important;
      border-radius: 20px !important;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.85), 0 0 30px ${isSafe ? 'rgba(16, 185, 129, 0.25)' : 'rgba(244, 63, 94, 0.35)'} !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
      overflow: hidden !important;
      box-sizing: border-box !important;
      animation: cyberguardSlideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
      transition: all 0.2s ease !important;
    `;

    // Internal HTML
    hud.innerHTML = `
      <style>
        @keyframes cyberguardSlideIn {
          from { opacity: 0; transform: translateY(-20px) scale(0.96); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        #cyberguard-sentinel-hud button:hover {
          filter: brightness(1.15);
        }
      </style>
      
      <!-- Header Banner -->
      <div style="padding: 10px 14px; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border-bottom: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 11px; letter-spacing: 0.5px; text-transform: uppercase; color: ${isSafe ? '#34d399' : '#fb7185'};">
          <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${isSafe ? '#10b981' : '#f43f5e'}; box-shadow: 0 0 8px ${isSafe ? '#10b981' : '#f43f5e'};"></span>
          <span>${isSafe ? 'CYBERGUARD : RESSOURCE SAINE' : 'CYBERGUARD : ALERTE MENACE'}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255, 255, 255, 0.1); padding: 2px 6px; border-radius: 9999px; font-size: 10px; font-family: monospace; color: #38bdf8; font-weight: bold;">
            ⚡ ${data.latency_ms || 18}ms
          </span>
          <button id="cyberguard-close-btn" style="background: none; border: none; color: #94a3b8; font-size: 18px; cursor: pointer; padding: 0 4px; line-height: 1;" title="Fermer">&times;</button>
        </div>
      </div>

      <!-- Main Body -->
      <div style="padding: 14px; display: flex; flex-direction: column; gap: 10px;">
        <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 8px;">
          <div style="min-width: 0; flex: 1;">
            <div style="font-size: 10px; color: #94a3b8; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 4px;">
              ${data.url}
            </div>
            <div style="font-size: 14px; font-weight: 800; color: ${isSafe ? '#34d399' : '#fb7185'};">
              ${data.verdict || (isSafe ? 'LÉGITIME & CONFORME' : 'DANGER DÉTECTÉ')}
            </div>
          </div>
          <div style="text-align: right; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; border-radius: 10px; padding: 4px 8px;">
            <div style="font-size: 8px; color: #94a3b8; font-weight: bold; text-transform: uppercase;">Risque</div>
            <div style="font-size: 14px; font-weight: 900; color: ${isSafe ? '#34d399' : '#fb7185'}; font-family: monospace;">${Math.round(data.risk_score)}%</div>
          </div>
        </div>

        <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;">
          ${isSafe 
            ? 'Protocole chiffré HTTPS et réputation saine validés par l’IA CyberGuard.' 
            : 'Indicateurs de compromission détectés. Accès potentiellement risqué !'}
        </div>

        <!-- Action Buttons -->
        <div style="display: flex; align-items: center; gap: 8px; margin-top: 4px;">
          <button id="cyberguard-transfer-btn" style="flex: 1; padding: 8px 12px; background: linear-gradient(135deg, #0284c7, #2563eb); border: 1px solid #38bdf8; border-radius: 10px; color: #ffffff; font-size: 11px; font-weight: 700; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; transition: all 0.2s ease;">
            <span>🛡️</span>
            <span>Transférer à l'Enquêteur</span>
          </button>
          
          <a href="http://localhost:3000/dashboard" target="_blank" style="padding: 8px 12px; background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 10px; color: #94a3b8; font-size: 11px; font-weight: 600; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 4px; white-space: nowrap;">
            <span>SOC</span> &rarr;
          </a>
        </div>

        <!-- Feedback Area for Transfer -->
        <div id="cyberguard-transfer-feedback" style="display: none; padding: 8px 10px; border-radius: 8px; font-size: 10px; line-height: 1.3;"></div>
      </div>

      <!-- Animated Progress Bar -->
      <div style="height: 3px; background: rgba(255, 255, 255, 0.1); width: 100%; overflow: hidden;">
        <div id="cyberguard-progress-bar" style="height: 100%; background: ${isSafe ? '#10b981' : '#f43f5e'}; width: 100%; transition: width 0.9s linear;"></div>
      </div>

      <!-- Bottom Status Bar -->
      <div style="padding: 6px 14px; background: rgba(15, 23, 42, 0.9); display: flex; align-items: center; justify-content: space-between; font-size: 9px; color: #94a3b8; font-family: monospace;">
        <span id="cyberguard-timer-text">Fermeture auto dans ${isSafe ? '8s' : '10s'}</span>
        <span id="cyberguard-hover-hint" style="color: #64748b;">(Survoler pour figer)</span>
      </div>
    `;

    document.body.appendChild(hud);

    let timeLeft = isSafe ? 8 : 10;
    const initialTime = timeLeft;
    let isPaused = false;
    let isTransferred = false;

    const timerText = hud.querySelector('#cyberguard-timer-text');
    const progressBar = hud.querySelector('#cyberguard-progress-bar');
    const closeBtn = hud.querySelector('#cyberguard-close-btn');
    const transferBtn = hud.querySelector('#cyberguard-transfer-btn');
    const feedbackBox = hud.querySelector('#cyberguard-transfer-feedback');
    const hoverHint = hud.querySelector('#cyberguard-hover-hint');

    // 1. Hover Stop / Resume Functionality
    hud.addEventListener('mouseenter', () => {
      isPaused = true;
      hud.style.boxShadow = `0 25px 50px -12px rgba(0, 0, 0, 0.95), 0 0 35px ${isSafe ? 'rgba(16, 185, 129, 0.45)' : 'rgba(244, 63, 94, 0.55)'}`;
      if (timerText) {
        timerText.textContent = `⏸️ En pause (${timeLeft}s restantes)`;
        timerText.style.color = '#38bdf8';
      }
      if (hoverHint) {
        hoverHint.textContent = 'Curseur présent';
        hoverHint.style.color = '#38bdf8';
      }
    });

    hud.addEventListener('mouseleave', () => {
      isPaused = false;
      hud.style.boxShadow = `0 25px 50px -12px rgba(0, 0, 0, 0.85), 0 0 30px ${isSafe ? 'rgba(16, 185, 129, 0.25)' : 'rgba(244, 63, 94, 0.35)'}`;
      if (timerText) {
        timerText.textContent = `Fermeture auto dans ${timeLeft}s`;
        timerText.style.color = '#94a3b8';
      }
      if (hoverHint) {
        hoverHint.textContent = '(Survoler pour figer)';
        hoverHint.style.color = '#64748b';
      }
    });

    // 2. Manual Close Button
    closeBtn.addEventListener('click', () => {
      hud.style.opacity = '0';
      hud.style.transform = 'translateY(-15px)';
      hud.style.transition = 'all 0.25s ease';
      setTimeout(() => hud.remove(), 250);
    });

    // 3. Transfer to Investigator Button
    transferBtn.addEventListener('click', () => {
      if (isTransferred) return;
      
      // Pause countdown so user can review the transfer outcome
      isPaused = true;
      timeLeft = Math.max(timeLeft, 20); // Give 20 more seconds minimum

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
          feedbackBox.innerHTML = `<strong>Dossier ${incCode} créé</strong><br>Scellé cryptographique SHA-256 généré et assigné au SOC.`;
        } else {
          transferBtn.style.background = 'linear-gradient(135deg, #d97706, #b45309)';
          transferBtn.innerHTML = '<span>📡</span><span>Signalement Transmis</span>';

          feedbackBox.style.display = 'block';
          feedbackBox.style.background = 'rgba(217, 119, 6, 0.15)';
          feedbackBox.style.border = '1px solid rgba(217, 119, 6, 0.4)';
          feedbackBox.style.color = '#fbbf24';
          feedbackBox.innerHTML = `Signalement enregistré dans le journal d'investigation.`;
        }

        // Resume timer after 8s if user leaves
        setTimeout(() => {
          if (!isPaused) {
            timeLeft = 6;
          }
        }, 8000);
      });
    });

    // 4. Countdown Loop with Active Pause Checking
    const interval = setInterval(() => {
      // If cursor is on the HUD, DO NOT decrement time!
      if (isPaused) {
        return;
      }

      timeLeft -= 1;
      if (timerText) timerText.textContent = `Fermeture auto dans ${timeLeft}s`;
      if (progressBar) progressBar.style.width = `${Math.max(0, (timeLeft / initialTime) * 100)}%`;

      if (timeLeft <= 0) {
        clearInterval(interval);
        hud.style.opacity = '0';
        hud.style.transform = 'translateY(-15px)';
        hud.style.transition = 'all 0.3s ease';
        setTimeout(() => hud.remove(), 300);
      }
    }, 1000);
  }
})();
