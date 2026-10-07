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
      max-width: 400px !important;
      width: calc(100vw - 48px) !important;
      background: #090d16 !important;
      color: #f8fafc !important;
      border: 1px solid ${isSafe ? '#10b981' : '#f43f5e'} !important;
      border-radius: 20px !important;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.8), 0 0 25px ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.4)'} !important;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
      overflow: hidden !important;
      box-sizing: border-box !important;
      animation: cyberguardSlideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
    `;

    // Internal HTML
    hud.innerHTML = `
      <style>
        @keyframes cyberguardSlideIn {
          from { opacity: 0; transform: translateY(-20px) scale(0.96); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes cyberguardProgress {
          from { width: 100%; }
          to { width: 0%; }
        }
      </style>
      <div style="padding: 10px 14px; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border-bottom: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 11px; letter-spacing: 0.5px; text-transform: uppercase; color: ${isSafe ? '#34d399' : '#fb7185'};">
          <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${isSafe ? '#10b981' : '#f43f5e'}; box-shadow: 0 0 8px ${isSafe ? '#10b981' : '#f43f5e'};"></span>
          <span>${isSafe ? 'CYBERGUARD : RESSOURCE SAINE' : 'CYBERGUARD : ALERTE PHISHING'}</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(255, 255, 255, 0.1); padding: 2px 6px; border-radius: 9999px; font-size: 10px; font-family: monospace; color: #38bdf8;">
            ⚡ ${data.latency_ms || 18}ms
          </span>
          <button id="cyberguard-close-btn" style="background: none; border: none; color: #94a3b8; font-size: 16px; cursor: pointer; padding: 0 4px; line-height: 1;">&times;</button>
        </div>
      </div>
      <div style="padding: 14px; display: flex; flex-direction: column; gap: 8px;">
        <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 8px;">
          <div style="min-width: 0; flex: 1;">
            <div style="font-size: 10px; color: #94a3b8; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 4px;">
              ${data.url}
            </div>
            <div style="font-size: 14px; font-weight: 800; color: ${isSafe ? '#34d399' : '#fb7185'};">
              ${data.verdict || (isSafe ? 'LÉGITIME & CONFORME' : 'DANGER CRITIQUE')}
            </div>
          </div>
          <div style="text-align: right; background: ${isSafe ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.15)'}; border: 1px solid ${isSafe ? 'rgba(16, 185, 129, 0.3)' : 'rgba(244, 63, 94, 0.3)'}; border-radius: 10px; padding: 4px 8px;">
            <div style="font-size: 8px; color: #94a3b8; font-weight: bold; text-transform: uppercase;">Risque</div>
            <div style="font-size: 14px; font-weight: 900; color: ${isSafe ? '#34d399' : '#fb7185'}; font-family: monospace;">${Math.round(data.risk_score)}%</div>
          </div>
        </div>
        <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;">
          ${isSafe ? 'Protocole chiffré HTTPS et structure lexicale saine vérifiés.' : 'Indicateurs de compromission détectés. Soyez très vigilant !'}
        </div>
      </div>
      <div style="height: 3px; background: rgba(255, 255, 255, 0.1); width: 100%; overflow: hidden;">
        <div id="cyberguard-progress-bar" style="height: 100%; background: ${isSafe ? '#10b981' : '#f43f5e'}; width: 100%; transition: width 1s linear;"></div>
      </div>
      <div style="padding: 6px 14px; background: rgba(15, 23, 42, 0.8); display: flex; align-items: center; justify-content: space-between; font-size: 9px; color: #94a3b8; font-family: monospace;">
        <span id="cyberguard-timer-text">Fermeture auto dans ${isSafe ? '8s' : '10s'}</span>
        <a href="http://localhost:3000/dashboard" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: bold;">CyberGuard SOC &rarr;</a>
      </div>
    `;

    document.body.appendChild(hud);

    let timeLeft = isSafe ? 8 : 10;
    const initialTime = timeLeft;
    const timerText = hud.querySelector('#cyberguard-timer-text');
    const progressBar = hud.querySelector('#cyberguard-progress-bar');
    const closeBtn = hud.querySelector('#cyberguard-close-btn');

    closeBtn.addEventListener('click', () => {
      hud.remove();
    });

    const interval = setInterval(() => {
      timeLeft -= 1;
      if (timerText) timerText.textContent = `Fermeture auto dans ${timeLeft}s`;
      if (progressBar) progressBar.style.width = `${(timeLeft / initialTime) * 100}%`;
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
