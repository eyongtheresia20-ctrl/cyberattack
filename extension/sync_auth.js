// CyberGuard — synchronise le token de l'utilisateur connecté (tableau de bord) vers l'extension.
// Permet au backend d'appliquer les sites bloqués spécifiquement pour CET utilisateur.
(function () {
  let lastToken = undefined;
  function push() {
    try {
      const token = localStorage.getItem('phishguard_token') || '';
      let user = null;
      try { user = JSON.parse(localStorage.getItem('phishguard_user') || 'null'); } catch(e){}
      if (token === lastToken) return;
      lastToken = token;
      chrome.runtime.sendMessage({ type: 'CYBERGUARD_AUTH_SYNC', token, user }, () => void chrome.runtime.lastError);
    } catch (e) {}
  }
  push();
  setInterval(push, 1000);
  window.addEventListener('storage', push);
})();
