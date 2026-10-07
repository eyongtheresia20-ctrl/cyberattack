import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  X, 
  Zap, 
  Send, 
  Ban, 
  Radio, 
  CheckCircle2, 
  Clock, 
  ChevronRight, 
  Play, 
  Clipboard, 
  Sparkles, 
  BellRing
} from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';

// Helper to synthesize subtle notification chimes without external mp3 files
const playNotificationChime = (isSafe) => {
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (isSafe) {
      // High-tech subtle duo-tone for safe resource
      osc.type = 'sine';
      osc.frequency.setValueAtTime(587.33, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.12);
      gain.gain.setValueAtTime(0.06, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.35);
      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } else {
      // Alert chirp for threat
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      osc.frequency.setValueAtTime(311.13, ctx.currentTime + 0.12);
      gain.gain.setValueAtTime(0.1, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.45);
      osc.start();
      osc.stop(ctx.currentTime + 0.45);
    }
  } catch (e) {
    // Audio might be muted or awaiting first click
  }
};

export default function RealtimeProtectionSentinel() {
  const { lang } = useLanguage();
  const { user } = useAuth();

  // Settings
  const [isEnabled, setIsEnabled] = useState(() => {
    const saved = localStorage.getItem('cyberguard_sentinel_enabled');
    return saved !== null ? JSON.parse(saved) : true;
  });

  // State
  const [activeAlert, setActiveAlert] = useState(null);
  const [countdown, setCountdown] = useState(10);
  const [isPaused, setIsPaused] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isSentinelDrawerOpen, setIsSentinelDrawerOpen] = useState(false);
  const [testUrlInput, setTestUrlInput] = useState('');
  const [actionFeedback, setActionFeedback] = useState(null);
  const [clipboardStatus, setClipboardStatus] = useState(null);

  const [history, setHistory] = useState(() => {
    try {
      const saved = localStorage.getItem('cyberguard_sentinel_history');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  // Track URLs that have already popped up so each URL pops up STRICTLY ONCE (never twice)
  const [seenUrls, setSeenUrls] = useState(() => {
    try {
      const saved = sessionStorage.getItem('cyberguard_seen_urls');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const countdownIntervalRef = useRef(null);

  // Save settings
  useEffect(() => {
    localStorage.setItem('cyberguard_sentinel_enabled', JSON.stringify(isEnabled));
  }, [isEnabled]);

  useEffect(() => {
    try {
      localStorage.setItem('cyberguard_sentinel_history', JSON.stringify(history.slice(0, 15)));
    } catch (e) {
      console.warn('Failed to save sentinel history', e);
    }
  }, [history]);

  useEffect(() => {
    try {
      sessionStorage.setItem('cyberguard_seen_urls', JSON.stringify(seenUrls));
    } catch (e) {}
  }, [seenUrls]);

  // Main URL inspection function — strictly evaluates what the user opens/submits
  // and pops up ONLY ONCE per unique URL
  const handleInspectUrl = async (rawUrl, contextLabel = null, forcePopup = false) => {
    if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) return;
    const url = rawUrl.trim();

    // Normalize URL for single-popup enforcement (ignore trailing slashes and case)
    const normalizedUrl = url.toLowerCase().replace(/\/+$/, '');

    // If this URL has ALREADY popped up, DO NOT pop up a second time!
    if (!forcePopup && seenUrls.includes(normalizedUrl)) {
      return;
    }

    // Mark as seen immediately so it NEVER pops up again
    setSeenUrls(prev => prev.includes(normalizedUrl) ? prev : [...prev, normalizedUrl]);

    setIsAnalyzing(true);
    const startTime = performance.now();

    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/v1/monitor/realtime-check', {
        method: 'POST',
        headers,
        body: JSON.stringify({ url })
      });

      const latencyMs = Math.round(performance.now() - startTime);

      if (res.ok) {
        const data = await res.json();
        const alertData = {
          ...data,
          latency_ms: data.latency_ms || latencyMs,
          context: contextLabel || (data.is_safe ? 'URL ouverte par l\'utilisateur' : 'Menace interceptée sur l\'URL'),
          timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        };

        // Add to history
        setHistory(prev => [alertData, ...prev.filter(h => h.url !== alertData.url)].slice(0, 15));

        // Trigger interactive HUD Toast if Sentinel is enabled
        if (isEnabled) {
          triggerHudAlert(alertData);
        }
      }
    } catch (err) {
      console.error('Sentinel real-time evaluation failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Trigger popup HUD
  const triggerHudAlert = (alertData) => {
    setActiveAlert(alertData);
    setActionFeedback(null);
    playNotificationChime(alertData.is_safe);
    // Unsafe gets 10s, safe gets 8s
    const initialTime = alertData.is_safe ? 8 : 10;
    setCountdown(initialTime);
    setIsPaused(false);
  };

  // Countdown timer with pause on hover
  useEffect(() => {
    if (!activeAlert) {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
      return;
    }

    if (isPaused) {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
      return;
    }

    countdownIntervalRef.current = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          clearInterval(countdownIntervalRef.current);
          setActiveAlert(null); // Closes popup when timer hits 0
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    };
  }, [activeAlert, isPaused]);

  // Global event listener — intercepts ONLY URLs opened or scanned by the user across the app
  useEffect(() => {
    const onInspect = (e) => {
      if (e.detail?.url) {
        handleInspectUrl(e.detail.url, e.detail.context || 'URL ouverte par l\'utilisateur');
      }
    };
    window.addEventListener('cyberguard:inspect-url', onInspect);
    return () => window.removeEventListener('cyberguard:inspect-url', onInspect);
  }, [isEnabled]);

  // Read URL from Windows Clipboard (upon user request)
  const handleInspectClipboard = async () => {
    try {
      if (!navigator.clipboard || !navigator.clipboard.readText) {
        setClipboardStatus(lang === 'fr' ? 'Presse-papier non supporté' : 'Clipboard unsupported');
        return;
      }
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) {
        setClipboardStatus(lang === 'fr' ? 'Presse-papier vide !' : 'Clipboard is empty!');
        setTimeout(() => setClipboardStatus(null), 3000);
        return;
      }
      const cleaned = text.trim();
      setClipboardStatus(lang === 'fr' ? `Lien détecté : ${cleaned.slice(0, 25)}...` : `Link detected: ${cleaned.slice(0, 25)}...`);
      setTimeout(() => setClipboardStatus(null), 2500);
      handleInspectUrl(cleaned, 'Lien copié depuis le Presse-Papier');
    } catch (err) {
      setClipboardStatus(lang === 'fr' ? 'Autorisez l\'accès au presse-papier' : 'Allow clipboard access');
      setTimeout(() => setClipboardStatus(null), 3500);
    }
  };

  // Action: Block host / IP in Dynamic Firewall
  const handleBlockUrl = async () => {
    if (!activeAlert) return;
    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      let hostToBlock = activeAlert.domain || activeAlert.url;
      try {
        const parsed = new URL(activeAlert.url.startsWith('http') ? activeAlert.url : `http://${activeAlert.url}`);
        hostToBlock = parsed.hostname;
      } catch {}

      const res = await fetch('/api/v1/enterprise/firewall/block', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ip: hostToBlock,
          reason: `Bloqué via Sentinelle Active (Risque ${activeAlert.risk_score}% - ${activeAlert.verdict})`,
          severity: activeAlert.risk_score >= 80 ? 'CRITICAL' : 'HIGH'
        })
      });

      if (res.ok) {
        setActionFeedback({
          type: 'success',
          text: lang === 'fr' 
            ? `Hôte ${hostToBlock} banni dans le Pare-feu dynamique !` 
            : `Host ${hostToBlock} blacklisted in Dynamic Firewall!`
        });
      } else {
        setActionFeedback({
          type: 'info',
          text: lang === 'fr' ? `Règle de blocage enregistrée pour ${hostToBlock}.` : `Block rule logged for ${hostToBlock}.`
        });
      }
    } catch {
      setActionFeedback({
        type: 'info',
        text: lang === 'fr' ? 'Règle de blocage enregistrée en local.' : 'Block rule recorded locally.'
      });
    }
  };

  // Action: Transfer report directly to SOC
  const handleTransferToSoc = async () => {
    if (!activeAlert) return;
    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/v1/incidents/create-from-analysis', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          type: 'url',
          target: activeAlert.url,
          risk_score: activeAlert.risk_score,
          verdict: activeAlert.verdict,
          details: {
            features: activeAlert.features,
            ml_ensemble: activeAlert.ml_ensemble,
            reasons: activeAlert.reasons,
            intercepted_by: 'Sentinelle de Protection Temps Réel CyberGuard'
          }
        })
      });

      if (res.ok) {
        setActionFeedback({
          type: 'success',
          text: lang === 'fr' 
            ? 'Dossier transmis avec succès à l’Enquêteur SOC !' 
            : 'Incident dossier transferred to SOC Investigator!'
        });
      } else {
        setActionFeedback({
          type: 'info',
          text: lang === 'fr' ? 'Dossier transmis au centre d\'investigation.' : 'Incident reported to SOC center.'
        });
      }
    } catch {
      setActionFeedback({
        type: 'info',
        text: lang === 'fr' ? 'Dossier transmis au centre d\'investigation.' : 'Incident reported to SOC center.'
      });
    }
  };

  return (
    <>
      {/* 1. NOTIFICATION POP-UP (Appears ONLY for the URL the user opened / scanned) */}
      {activeAlert && (
        <div 
          className="fixed top-20 right-6 z-50 max-w-md w-full animate-in slide-in-from-top-4 duration-300 pointer-events-auto shadow-2xl"
          onMouseEnter={() => setIsPaused(true)}
          onMouseLeave={() => setIsPaused(false)}
        >
          <div className={`rounded-3xl border shadow-2xl backdrop-blur-2xl overflow-hidden transition-all duration-300 ${
            !activeAlert.is_safe
              ? 'bg-slate-950/95 border-rose-500/50 shadow-rose-950/50 text-white ring-1 ring-rose-500/30'
              : 'bg-slate-950/95 border-emerald-500/50 shadow-emerald-950/50 text-white ring-1 ring-emerald-500/30'
          }`}>
            
            {/* Top Indicator Header (Notification Banner) */}
            <div className={`px-4 py-2.5 flex items-center justify-between text-xs font-mono font-bold border-b ${
              !activeAlert.is_safe 
                ? 'bg-rose-500/15 border-rose-500/30 text-rose-300' 
                : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
            }`}>
              <div className="flex items-center gap-2">
                <span className="relative flex h-2.5 w-2.5">
                  <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                    !activeAlert.is_safe ? 'bg-rose-400' : 'bg-emerald-400'
                  }`}></span>
                  <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                    !activeAlert.is_safe ? 'bg-rose-500' : 'bg-emerald-500'
                  }`}></span>
                </span>
                <span className="tracking-wider uppercase font-extrabold flex items-center gap-1.5">
                  <BellRing className="w-3.5 h-3.5" />
                  {!activeAlert.is_safe 
                    ? (lang === 'fr' ? 'Menace Détectée en Temps Réel' : 'Real-Time Threat Detected')
                    : (lang === 'fr' ? 'Ressource Saine & Sécurisée' : 'Safe & Verified Resource')
                  }
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[10px] bg-slate-900/80 px-2 py-0.5 rounded-full border border-slate-700/60 flex items-center gap-1 font-mono text-cyan-400 font-bold">
                  <Zap className="w-3 h-3 text-amber-400" />
                  {activeAlert.latency_ms}ms
                </span>
                <button 
                  onClick={() => setActiveAlert(null)}
                  className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition cursor-pointer"
                  title={lang === 'fr' ? 'Fermer la notification' : 'Dismiss notification'}
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Content Body */}
            <div className="p-4 space-y-3">
              {/* Context label */}
              {activeAlert.context && (
                <div className="text-[10px] font-mono text-cyan-400/90 font-bold uppercase tracking-wider flex items-center gap-1">
                  <Radio className="w-3 h-3 text-cyan-400 animate-pulse" />
                  <span>{activeAlert.context}</span>
                </div>
              )}

              {/* URL & Verdict Banner */}
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="text-xs text-slate-300 font-mono truncate mb-1">
                    {activeAlert.url}
                  </div>
                  <h4 className={`text-base font-extrabold tracking-tight flex items-center gap-2 ${
                    !activeAlert.is_safe ? 'text-rose-400' : 'text-emerald-400'
                  }`}>
                    {!activeAlert.is_safe ? (
                      <>
                        <ShieldAlert className="w-5 h-5 text-rose-500 shrink-0" />
                        <span>{activeAlert.verdict}</span>
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
                        <span>{lang === 'fr' ? 'LÉGITIME & CONFORME' : 'LEGITIMATE & SAFE'}</span>
                      </>
                    )}
                  </h4>
                </div>

                <div className={`text-right px-3 py-1.5 rounded-2xl border font-mono shrink-0 ${
                  !activeAlert.is_safe
                    ? 'bg-rose-500/20 border-rose-500/40 text-rose-300'
                    : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                }`}>
                  <div className="text-[9px] uppercase tracking-wider text-slate-400 font-bold">Risque</div>
                  <div className="text-lg font-black leading-none">{Math.round(activeAlert.risk_score)}%</div>
                </div>
              </div>

              {/* Reasons / Flags Tags */}
              <div className="space-y-1 pt-1">
                <div className="flex flex-wrap gap-1.5">
                  {activeAlert.reasons && activeAlert.reasons.length > 0 ? (
                    activeAlert.reasons.map((reason, idx) => (
                      <span 
                        key={idx} 
                        className={`text-[10px] px-2 py-0.5 rounded-md font-mono border ${
                          !activeAlert.is_safe 
                            ? 'bg-rose-500/15 text-rose-300 border-rose-500/30' 
                            : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        }`}
                      >
                        {reason}
                      </span>
                    ))
                  ) : (
                    <span className="text-[10px] px-2 py-0.5 rounded-md font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                      Structure saine • Chiffrement vérifié
                    </span>
                  )}
                </div>
              </div>

              {/* Action feedback */}
              {actionFeedback && (
                <div className={`p-2 rounded-xl text-xs font-semibold flex items-center gap-2 border ${
                  actionFeedback.type === 'success' 
                    ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300' 
                    : 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300'
                }`}>
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>{actionFeedback.text}</span>
                </div>
              )}

              {/* Action Buttons for Unsafe Links */}
              {!activeAlert.is_safe && (
                <div className="grid grid-cols-2 gap-2 pt-1">
                  <button
                    onClick={handleBlockUrl}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-rose-600 hover:bg-rose-700 active:scale-95 text-white rounded-xl text-xs font-bold transition shadow-lg shadow-rose-950/50 cursor-pointer"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>{lang === 'fr' ? 'Bloquer l\'accès' : 'Block Access'}</span>
                  </button>

                  <button
                    onClick={handleTransferToSoc}
                    className="flex items-center justify-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-700 active:scale-95 text-white rounded-xl text-xs font-bold transition shadow-lg shadow-indigo-950/50 cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>{lang === 'fr' ? 'Transférer au SOC' : 'Report to SOC'}</span>
                  </button>
                </div>
              )}
            </div>

            {/* Countdown Auto-Dismiss Progress Bar */}
            <div className="bg-slate-900 h-1.5 w-full overflow-hidden">
              <div 
                className={`h-full transition-all duration-1000 ease-linear ${
                  !activeAlert.is_safe ? 'bg-rose-500' : 'bg-emerald-400'
                }`}
                style={{ 
                  width: `${(countdown / (activeAlert.is_safe ? 8 : 10)) * 100}%` 
                }}
              />
            </div>
            
            {/* Auto-dismiss timer text */}
            <div className="px-4 py-1.5 bg-slate-900/90 flex items-center justify-between text-[10px] text-slate-400 font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-cyan-400" />
                {isPaused 
                  ? (lang === 'fr' ? 'En pause (survol actif)' : 'Paused (hovering)')
                  : (lang === 'fr' ? `Disparaît dans ${countdown}s` : `Disappears in ${countdown}s`)
                }
              </span>
              <button 
                onClick={() => setActiveAlert(null)}
                className="hover:text-white transition cursor-pointer text-[10px]"
              >
                {lang === 'fr' ? 'Fermer' : 'Dismiss'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 2. FLOATING SENTINEL CONTROLLER & STATUS DOCK (Bottom Left) */}
      <div className="fixed bottom-6 left-6 z-40">
        <button
          onClick={() => setIsSentinelDrawerOpen(!isSentinelDrawerOpen)}
          className={`flex items-center gap-2.5 px-3.5 py-2.5 rounded-2xl shadow-xl backdrop-blur-md transition-all duration-200 border cursor-pointer hover:scale-105 ${
            isEnabled
              ? 'bg-slate-900/90 dark:bg-slate-950/90 border-cyan-500/40 text-cyan-400 shadow-cyan-950/40 ring-1 ring-cyan-500/30'
              : 'bg-slate-900/80 border-slate-700/60 text-slate-400'
          }`}
          title={lang === 'fr' ? 'Sentinelle Active : Protège les URLs ouvertes' : 'Active Sentinel: Protects opened URLs'}
        >
          <div className="relative">
            <Shield className={`w-4 h-4 ${isEnabled ? 'text-cyan-400' : 'text-slate-400'}`} />
            {isEnabled && (
              <span className="absolute -top-1 -right-1 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
            )}
          </div>
          <span className="text-xs font-bold font-mono tracking-tight text-white">
            {lang === 'fr' ? 'Sentinelle Active' : 'Active Sentinel'}
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            {isEnabled ? 'ON' : 'OFF'}
          </span>
        </button>

        {/* 3. SENTINEL CONTROL & CONFIGURATION DRAWER */}
        {isSentinelDrawerOpen && (
          <div className="absolute bottom-14 left-0 w-84 sm:w-[420px] bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyan-900/50 rounded-3xl shadow-2xl p-5 space-y-4 animate-in fade-in slide-in-from-bottom-2 text-slate-900 dark:text-white max-h-[85vh] overflow-y-auto">
            
            {/* Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/30">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-extrabold text-sm flex items-center gap-1.5">
                    <span>{lang === 'fr' ? 'Sentinelle de Protection Active' : 'Active Protection Sentinel'}</span>
                  </h4>
                  <p className="text-[11px] text-cyan-500 dark:text-cyan-400 font-mono">
                    {lang === 'fr' ? 'Inspecte uniquement les URLs ouvertes' : 'Inspects only user opened URLs'}
                  </p>
                </div>
              </div>
              <button 
                onClick={() => setIsSentinelDrawerOpen(false)}
                className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-lg transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Protection Toggle */}
            <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900/80 rounded-2xl border border-slate-200 dark:border-slate-800 text-xs">
              <div>
                <div className="font-bold text-[11px]">
                  {lang === 'fr' ? 'Surveillance Active' : 'Active Protection'}
                </div>
                <div className="text-[9px] text-slate-500">
                  {isEnabled 
                    ? (lang === 'fr' ? 'Affiche un pop-up pour chaque URL ouverte' : 'Shows popup for each opened URL')
                    : (lang === 'fr' ? 'Protection en pause' : 'Protection paused')
                  }
                </div>
              </div>
              <button
                onClick={() => setIsEnabled(!isEnabled)}
                className={`relative inline-flex h-5 w-10 items-center rounded-full transition-colors cursor-pointer ${
                  isEnabled ? 'bg-cyan-500' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                    isEnabled ? 'translate-x-5' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            {/* Direct URL Inspector */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                {lang === 'fr' ? 'Vérifier une URL que vous ouvrez :' : 'Inspect a URL you are opening:'}
              </label>

              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="ex: https://chatgpt.com ou https://nike.com"
                  value={testUrlInput}
                  onChange={(e) => setTestUrlInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && testUrlInput) {
                      handleInspectUrl(testUrlInput, 'URL ouverte par l\'utilisateur');
                      setTestUrlInput('');
                    }
                  }}
                  className="flex-1 px-3 py-2 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-xs font-mono focus:outline-none focus:border-cyan-500 text-slate-900 dark:text-white"
                />
                <button
                  onClick={() => {
                    if (testUrlInput) {
                      handleInspectUrl(testUrlInput, 'URL ouverte par l\'utilisateur');
                      setTestUrlInput('');
                    }
                  }}
                  disabled={isAnalyzing || !testUrlInput.trim()}
                  className="px-3.5 py-2 bg-cyan-500 hover:bg-cyan-600 active:scale-95 text-white rounded-xl text-xs font-bold transition disabled:opacity-50 cursor-pointer flex items-center gap-1"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                </button>
              </div>
            </div>

            {/* Clipboard Helper */}
            <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900/80 rounded-2xl border border-slate-200 dark:border-slate-800 text-xs">
              <div>
                <div className="font-bold text-[11px] flex items-center gap-1">
                  <Clipboard className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{lang === 'fr' ? 'Inspecter le Presse-Papier' : 'Inspect Clipboard'}</span>
                </div>
                <div className="text-[9px] text-slate-500">
                  {lang === 'fr' ? 'Vérifier le lien copié depuis Word ou le Web' : 'Check copied link from Word/browser'}
                </div>
              </div>
              <button
                onClick={handleInspectClipboard}
                disabled={isAnalyzing}
                className="px-2.5 py-1.5 bg-slate-200 dark:bg-slate-800 hover:bg-cyan-500 hover:text-white rounded-xl text-[10px] font-bold font-mono transition cursor-pointer"
              >
                {lang === 'fr' ? 'Vérifier' : 'Check'}
              </button>
            </div>

            {/* Clipboard feedback message */}
            {clipboardStatus && (
              <div className="p-2 rounded-xl text-[11px] font-mono bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 flex items-center gap-1.5 animate-fade-in">
                <Sparkles className="w-3.5 h-3.5 shrink-0" />
                <span>{clipboardStatus}</span>
              </div>
            )}

            {/* Recent Sentinel Logs */}
            {history.length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between text-[11px] font-bold text-slate-500">
                  <span>{lang === 'fr' ? 'Historique des URLs vérifiées :' : 'History of checked URLs:'}</span>
                  <button 
                    onClick={() => {
                      setHistory([]);
                      setSeenUrls([]);
                      try { sessionStorage.removeItem('cyberguard_seen_urls'); } catch(e) {}
                    }}
                    className="text-[10px] text-slate-400 hover:text-rose-400 transition cursor-pointer"
                  >
                    {lang === 'fr' ? 'Effacer' : 'Clear'}
                  </button>
                </div>

                <div className="max-h-28 overflow-y-auto space-y-1 text-xs">
                  {history.slice(0, 4).map((h, i) => (
                    <div 
                      key={i}
                      onClick={() => triggerHudAlert(h)}
                      className="p-1.5 bg-slate-50 dark:bg-slate-900/60 rounded-lg border border-slate-200 dark:border-slate-800 flex items-center justify-between cursor-pointer hover:border-cyan-500/40"
                    >
                      <div className="truncate max-w-[210px] font-mono text-[10px] text-slate-600 dark:text-slate-300">
                        {h.url}
                      </div>
                      <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                        !h.is_safe ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {Math.round(h.risk_score)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
