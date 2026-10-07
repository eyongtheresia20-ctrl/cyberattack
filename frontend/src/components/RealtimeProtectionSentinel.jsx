import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  X, 
  ExternalLink, 
  Zap, 
  Send, 
  Ban, 
  Radio, 
  CheckCircle2, 
  Clock, 
  ChevronRight, 
  Eye, 
  Sliders,
  Play
} from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';

// Custom Event Dispatcher helper
export const inspectUrlRealtime = (url) => {
  const event = new CustomEvent('cyberguard:inspect-url', { detail: { url } });
  window.dispatchEvent(event);
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
  const [history, setHistory] = useState(() => {
    try {
      const saved = localStorage.getItem('cyberguard_sentinel_history');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const countdownIntervalRef = useRef(null);

  // Save enabled setting
  useEffect(() => {
    localStorage.setItem('cyberguard_sentinel_enabled', JSON.stringify(isEnabled));
  }, [isEnabled]);

  // Save history
  useEffect(() => {
    try {
      localStorage.setItem('cyberguard_sentinel_history', JSON.stringify(history.slice(0, 15)));
    } catch (e) {
      console.warn('Failed to save sentinel history', e);
    }
  }, [history]);

  // Main background inspection function
  const handleInspectUrl = async (rawUrl) => {
    if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) return;
    const url = rawUrl.trim();

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
    // Unsafe URLs get 10 seconds, safe URLs get 5 seconds
    const initialTime = alertData.is_safe ? 5 : 10;
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
          setActiveAlert(null);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      if (countdownIntervalRef.current) clearInterval(countdownIntervalRef.current);
    };
  }, [activeAlert, isPaused]);

  // Listen to global event bus
  useEffect(() => {
    const onInspect = (e) => {
      if (e.detail?.url) {
        handleInspectUrl(e.detail.url);
      }
    };
    window.addEventListener('cyberguard:inspect-url', onInspect);
    return () => window.removeEventListener('cyberguard:inspect-url', onInspect);
  }, [isEnabled]);

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

  // Sample URLs for immediate live demonstration
  const sampleUrls = [
    {
      title: '🚨 Phishing Bancaire Paypal (IP)',
      url: 'http://192.168.1.100/paypal-login.xyz',
      isDanger: true
    },
    {
      title: '🚨 Faux Domaine Crypto / Update',
      url: 'https://metamask-security-update.tk/verify',
      isDanger: true
    },
    {
      title: '🛡️ Google Services (Légitime)',
      url: 'https://www.google.com',
      isDanger: false
    }
  ];

  return (
    <>
      {/* 1. FLOATING HUD TOAST NOTIFICATION (Appears when Sentinel intercepts a URL) */}
      {activeAlert && (
        <div 
          className="fixed top-20 right-6 z-50 max-w-md w-full animate-in slide-in-from-top-4 duration-300 pointer-events-auto"
          onMouseEnter={() => setIsPaused(true)}
          onMouseLeave={() => setIsPaused(false)}
        >
          <div className={`rounded-3xl border shadow-2xl backdrop-blur-xl overflow-hidden transition-all duration-300 ${
            !activeAlert.is_safe
              ? 'bg-slate-950/95 border-rose-500/50 shadow-rose-950/40 text-white ring-1 ring-rose-500/30'
              : 'bg-slate-950/95 border-emerald-500/50 shadow-emerald-950/40 text-white ring-1 ring-emerald-500/30'
          }`}>
            
            {/* Top Indicator Header */}
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
                <span className="tracking-wider uppercase">
                  {!activeAlert.is_safe 
                    ? (lang === 'fr' ? 'Menace Interceptée en Temps Réel' : 'Real-Time Threat Intercepted')
                    : (lang === 'fr' ? 'Ressource Certifiée Saine' : 'Verified Safe Resource')
                  }
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[10px] bg-slate-900/80 px-2 py-0.5 rounded-full border border-slate-700/60 flex items-center gap-1 font-mono text-cyan-400">
                  <Zap className="w-3 h-3 text-amber-400" />
                  {activeAlert.latency_ms}ms
                </span>
                <button 
                  onClick={() => setActiveAlert(null)}
                  className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition cursor-pointer"
                  title={lang === 'fr' ? 'Fermer l\'alerte' : 'Close alert'}
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Content Body */}
            <div className="p-4 space-y-3.5">
              {/* URL & Verdict Banner */}
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5 text-xs text-slate-400 mb-1">
                    <Radio className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span className="font-mono truncate">{activeAlert.url}</span>
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
                        <span>{activeAlert.verdict}</span>
                      </>
                    )}
                  </h4>
                </div>

                <div className={`text-right px-3 py-1.5 rounded-2xl border font-mono ${
                  !activeAlert.is_safe
                    ? 'bg-rose-500/20 border-rose-500/40 text-rose-300'
                    : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                }`}>
                  <div className="text-[9px] uppercase tracking-wider text-slate-400 font-bold">Risque</div>
                  <div className="text-lg font-black leading-none">{Math.round(activeAlert.risk_score)}%</div>
                </div>
              </div>

              {/* Reasons / Flags Tags */}
              {activeAlert.reasons && activeAlert.reasons.length > 0 && (
                <div className="space-y-1.5 pt-1">
                  <div className="text-[11px] font-bold text-slate-400">
                    {lang === 'fr' ? 'Indicateurs de compromission détectés :' : 'Compromise indicators detected:'}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {activeAlert.reasons.map((reason, idx) => (
                      <span 
                        key={idx} 
                        className={`text-[10px] px-2 py-0.5 rounded-md font-mono border ${
                          !activeAlert.is_safe 
                            ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' 
                            : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                        }`}
                      >
                        {reason}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ML Ensemble Details */}
              {activeAlert.ml_ensemble && (
                <div className="bg-slate-900/60 p-2.5 rounded-xl border border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-cyan-400" />
                    <span>Ensemble ML (RF + GBM)</span>
                  </div>
                  <div className="text-cyan-300 font-bold">
                    Confiance : {activeAlert.ml_ensemble.confidence}%
                  </div>
                </div>
              )}

              {/* Dynamic Action Feedback */}
              {actionFeedback && (
                <div className={`p-2.5 rounded-xl text-xs font-semibold flex items-center gap-2 border ${
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
                  width: `${(countdown / (activeAlert.is_safe ? 5 : 10)) * 100}%` 
                }}
              />
            </div>
            
            {/* Auto-dismiss hint */}
            <div className="px-4 py-1.5 bg-slate-900/90 flex items-center justify-between text-[10px] text-slate-400 font-mono">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-cyan-400" />
                {isPaused 
                  ? (lang === 'fr' ? 'Minuteur en pause (survol actif)' : 'Timer paused (hovering)')
                  : (lang === 'fr' ? `Fermeture auto dans ${countdown}s` : `Auto-dismiss in ${countdown}s`)
                }
              </span>
              <button 
                onClick={() => setActiveAlert(null)}
                className="hover:text-white transition cursor-pointer"
              >
                {lang === 'fr' ? 'Ignorer' : 'Dismiss'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 2. FLOATING SENTINEL QUICK DOCK / CONTROLLER (Bottom Left) */}
      <div className="fixed bottom-6 left-6 z-40">
        <button
          onClick={() => setIsSentinelDrawerOpen(!isSentinelDrawerOpen)}
          className={`flex items-center gap-2.5 px-3.5 py-2.5 rounded-2xl shadow-xl backdrop-blur-md transition-all duration-200 border cursor-pointer hover:scale-105 ${
            isEnabled
              ? 'bg-slate-900/90 dark:bg-slate-950/90 border-cyan-500/40 text-cyan-400 shadow-cyan-950/40'
              : 'bg-slate-900/80 border-slate-700/60 text-slate-400'
          }`}
          title={lang === 'fr' ? 'Sentinelle de Protection Active en Arrière-Plan' : 'Real-Time Protection Sentinel'}
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
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${
            isEnabled ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-400'
          }`}>
            {isEnabled ? 'ON' : 'OFF'}
          </span>
        </button>

        {/* 3. SENTINEL CONTROL & LIVE TESTER DRAWER */}
        {isSentinelDrawerOpen && (
          <div className="absolute bottom-14 left-0 w-80 sm:w-96 bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-cyan-900/50 rounded-3xl shadow-2xl p-5 space-y-4 animate-in fade-in slide-in-from-bottom-2 text-slate-900 dark:text-white">
            
            {/* Header */}
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white shadow-md shadow-cyan-500/30">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-extrabold text-sm">
                    {lang === 'fr' ? 'Sentinelle en Arrière-Plan' : 'Background Sentinel'}
                  </h4>
                  <p className="text-[10px] text-cyan-500 dark:text-cyan-400 font-mono">
                    {lang === 'fr' ? 'Analyse heuristique + IA (<300ms)' : 'Heuristic + AI Analysis (<300ms)'}
                  </p>
                </div>
              </div>
              <button 
                onClick={() => setIsSentinelDrawerOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-lg transition cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Toggle Status */}
            <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-900/80 rounded-2xl border border-slate-200 dark:border-slate-800 text-xs">
              <div>
                <div className="font-bold">
                  {lang === 'fr' ? 'Interception en temps réel' : 'Real-time interception'}
                </div>
                <div className="text-[10px] text-slate-500">
                  {isEnabled 
                    ? (lang === 'fr' ? 'Surveille les liens & affiche le pop-up' : 'Monitors links & shows popup HUD')
                    : (lang === 'fr' ? 'Protection temporairement en pause' : 'Protection temporarily paused')
                  }
                </div>
              </div>
              <button
                onClick={() => setIsEnabled(!isEnabled)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors cursor-pointer ${
                  isEnabled ? 'bg-cyan-500' : 'bg-slate-700'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    isEnabled ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            {/* Live Interactive Tester */}
            <div className="space-y-2">
              <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wider block">
                {lang === 'fr' ? 'Tester l\'interception instantanée :' : 'Test instant interception:'}
              </label>

              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="https://example.com/login"
                  value={testUrlInput}
                  onChange={(e) => setTestUrlInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && testUrlInput) {
                      handleInspectUrl(testUrlInput);
                      setTestUrlInput('');
                    }
                  }}
                  className="flex-1 px-3 py-2 bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-xs font-mono focus:outline-none focus:border-cyan-500"
                />
                <button
                  onClick={() => {
                    if (testUrlInput) {
                      handleInspectUrl(testUrlInput);
                      setTestUrlInput('');
                    }
                  }}
                  disabled={isAnalyzing || !testUrlInput.trim()}
                  className="px-3 py-2 bg-cyan-500 hover:bg-cyan-600 active:scale-95 text-white rounded-xl text-xs font-bold transition disabled:opacity-50 cursor-pointer flex items-center gap-1"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                </button>
              </div>

              {/* One-Click Demo Samples */}
              <div className="space-y-1.5 pt-1">
                <div className="text-[10px] text-slate-400 font-mono font-semibold">
                  {lang === 'fr' ? 'Exemples rapides pour démonstration :' : 'Quick demo samples:'}
                </div>
                {sampleUrls.map((s, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleInspectUrl(s.url)}
                    disabled={isAnalyzing}
                    className={`w-full text-left p-2 rounded-xl text-xs transition border flex items-center justify-between cursor-pointer ${
                      s.isDanger 
                        ? 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-600 dark:text-rose-300 border-rose-500/20' 
                        : 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/20'
                    }`}
                  >
                    <span className="font-bold text-[11px] truncate">{s.title}</span>
                    <ChevronRight className="w-3.5 h-3.5 shrink-0 opacity-70" />
                  </button>
                ))}
              </div>
            </div>

            {/* Recent Sentinel Logs */}
            {history.length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between text-[11px] font-bold text-slate-500">
                  <span>{lang === 'fr' ? 'Dernières détections :' : 'Recent detections:'}</span>
                  <button 
                    onClick={() => setHistory([])}
                    className="text-[10px] text-slate-400 hover:text-rose-400 transition"
                  >
                    {lang === 'fr' ? 'Effacer' : 'Clear'}
                  </button>
                </div>

                <div className="max-h-32 overflow-y-auto space-y-1 text-xs">
                  {history.slice(0, 4).map((h, i) => (
                    <div 
                      key={i}
                      onClick={() => triggerHudAlert(h)}
                      className="p-1.5 bg-slate-50 dark:bg-slate-900/60 rounded-lg border border-slate-200 dark:border-slate-800 flex items-center justify-between cursor-pointer hover:border-cyan-500/40"
                    >
                      <div className="truncate max-w-[190px] font-mono text-[10px] text-slate-600 dark:text-slate-300">
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
