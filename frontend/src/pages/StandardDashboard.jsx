import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  Send, History, Bot, CheckCircle2, 
  AlertTriangle, Sparkles, RefreshCw, X, Shield, Clock,
  Cpu, Activity, Zap, Search, FileText, Globe, MapPin,
  Lock, ArrowRight, ShieldCheck, ChevronRight, BarChart2, Eye, ChevronDown
} from 'lucide-react';

export default function StandardDashboard({ isHistoryView = false }) {
  const { user } = useAuth();
  
  // Real-time clock & date
  const [timeString, setTimeString] = useState('');
  const [dateString, setDateString] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeString(now.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
      setDateString(now.toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Universal Scanner State
  const [investigationObjective, setInvestigationObjective] = useState('CONTENT'); // 'CONTENT' or 'SYSTEM'
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
  
  // Persisted scan history state loaded directly from database
  const [scanHistory, setScanHistory] = useState([]);
  
  // Incident Reporting State
  const [isReporting, setIsReporting] = useState(false);
  const [reportSuccess, setReportSuccess] = useState(null);
  
  // Floating AI Assistant State
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    { sender: 'assistant', text: `Bonjour ${user?.prenom || 'Alice'} ! Je suis votre assistant de sécurité PhishGuard AI. Collez un lien, un SMS ou un email pour lancer la détection.` }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isChatting, setIsChatting] = useState(false);

  // Compute metrics strictly from database
  const [dbStats, setDbStats] = useState({
    total_analyses: 0,
    phishing_threats: 0,
    clean_analyses: 0,
    ml_accuracy: 98.4
  });

  const fetchDbMetrics = async () => {
    try {
      const [resStats, resHist] = await Promise.all([
        fetch('/api/v1/analyze/stats'),
        fetch('/api/v1/analyze/history')
      ]);
      if (resStats.ok) {
        const statsData = await resStats.json();
        setDbStats(statsData);
      }
      if (resHist.ok) {
        const histData = await resHist.json();
        setScanHistory(histData.history || []);
      }
    } catch (e) {
      console.log('Error fetching DB metrics:', e);
    }
  };

  useEffect(() => {
    fetchDbMetrics();
  }, []);

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

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!targetContent.trim()) return;
    
    setIsScanning(true);
    setCurrentResult(null);
    setReportSuccess(null);

    const actualType = detectContentType(targetContent);

    try {
      let endpoint = (actualType === 'URL') ? 'analyze/url' : 'analyze/text';
      let payload = (actualType === 'URL') 
        ? { url: targetContent } 
        : { text: targetContent, sender: '', analysis_type: actualType };

      const res = await fetch(`/api/v1/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Erreur serveur (${res.status})`);
      }

      const data = await res.json();
      
      const resObj = {
        id: Date.now(),
        type: actualType,
        target: targetContent,
        verdict: data.verdict || (data.risk_score >= 50 ? 'PHISHING' : 'LÉGITIME'),
        riskScore: data.risk_score !== undefined ? data.risk_score : 20,
        confidence: data.ml_confidence || 0.94,
        details: data,
        timestamp: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
      };

      setCurrentResult(resObj);
      setScanHistory(prev => [resObj, ...prev]);
      fetchDbMetrics();
    } catch (err) {
      alert("Erreur lors de l'analyse : " + (err.message === 'Failed to fetch' ? "Le serveur backend PhishGuard (port 8000) est actuellement hors-ligne ou indisponible." : err.message));
    } finally {
      setIsScanning(false);
    }
  };

  const handleSendReport = async () => {
    if (!currentResult) return;
    setIsReporting(true);

    try {
      const res = await fetch('/api/v1/incidents/submit-user-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: `Signalement ${currentResult.type} par ${user?.prenom || 'Alice'} ${user?.nom || 'Martin'}`,
          target: currentResult.target,
          scan_type: currentResult.type,
          verdict: currentResult.verdict,
          risk_score: currentResult.riskScore,
          details: currentResult.details,
          reporter_name: `${user?.prenom || 'Alice'} ${user?.nom || 'Martin'}`,
          reporter_email: user?.email || 'alice.martin@example.com'
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur de transmission");

      setReportSuccess(`Signalement transmis à l'Enquêteur (${data.report?.report_code || 'REP-OK'}) • Hash SHA-256 : ${data.integrity_hash?.slice(0, 16) || 'SECURE'}...`);
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
      const res = await fetch('/api/v1/assistant/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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

  // Dedicated full history view renderer
  if (isHistoryView) {
    return (
      <div className="space-y-6 max-w-6xl mx-auto pb-20">
        <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-8 shadow-2xl space-y-6">
          <div className="flex items-center justify-between border-b border-sky-100 dark:border-sky-800/30 pb-4">
            <div>
              <h2 className="text-2xl font-black text-slate-900 dark:text-white flex items-center gap-2.5 tracking-tight">
                <History className="w-7 h-7 text-sky-500" /> Historique Général des Analyses
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Registre sécurisé des analyses effectuées pendant votre session active.
              </p>
            </div>
            <span className="px-4 py-1.5 bg-sky-500/10 text-sky-600 dark:text-sky-300 text-xs font-mono font-extrabold rounded-full border border-sky-500/20">
              {scanHistory.length} éléments répertoriés
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-200">
              <thead className="bg-sky-50/50 dark:bg-sky-950/40 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-sky-100 dark:border-sky-800/40">
                <tr>
                  <th className="py-3.5 px-4">Heure</th>
                  <th className="py-3.5 px-4">Canal</th>
                  <th className="py-3.5 px-4">Cible Analysée</th>
                  <th className="py-3.5 px-4">Verdict IA</th>
                  <th className="py-3.5 px-4">Score de Risque</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sky-100 dark:divide-sky-900/30 font-mono">
                {scanHistory.map((item) => (
                  <tr key={item.id} className="hover:bg-sky-500/5 transition duration-150">
                    <td className="py-4 px-4 text-slate-400 font-bold">{item.timestamp}</td>
                    <td className="py-4 px-4 font-bold text-sky-500">{item.type}</td>
                    <td className="py-4 px-4 max-w-md truncate text-slate-900 dark:text-slate-100 font-sans font-medium">{item.target}</td>
                    <td className="py-4 px-4">
                      <span className={`px-3 py-1 rounded-full text-[11px] font-extrabold flex items-center gap-1.5 w-max ${
                        item.riskScore >= 50
                          ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                      }`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${item.riskScore >= 50 ? 'bg-rose-500' : 'bg-emerald-400'}`} />
                        {item.verdict}
                      </span>
                    </td>
                    <td className="py-4 px-4 font-extrabold text-slate-900 dark:text-white text-sm">{item.riskScore}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
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
              <p className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-slate-400">Total Analyses</p>
              <p className="text-3xl font-black text-slate-900 dark:text-white font-mono">{totalScans}</p>
            </div>
            <div className="p-3.5 bg-sky-500/10 text-sky-500 rounded-2xl group-hover:scale-110 transition duration-300">
              <Activity className="w-6 h-6" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">Contenus vérifiés</span>
            <span className="text-sky-500 font-mono font-bold">{cleanScans} Légitimes</span>
          </div>
        </div>

        {/* Card 2: Intercepted Threats */}
        <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-6 shadow-xl relative overflow-hidden group hover:border-rose-400/60 transition duration-300">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-slate-400">Menaces Interceptées</p>
              <p className="text-3xl font-black text-rose-600 dark:text-rose-400 font-mono">{phishingBlocked}</p>
            </div>
            <div className="p-3.5 bg-rose-500/10 text-rose-500 rounded-2xl group-hover:scale-110 transition duration-300">
              <AlertTriangle className="w-6 h-6" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">Attaques bloquées</span>
            <span className="text-rose-500 font-mono font-bold">Haute Sécurité</span>
          </div>
        </div>

        {/* Card 3: Machine Learning Engine */}
        <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-6 shadow-xl relative overflow-hidden group hover:border-emerald-400/60 transition duration-300">
          <div className="flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-[10px] font-mono font-extrabold uppercase tracking-wider text-slate-400">Précision ML Engine</p>
              <p className="text-3xl font-black text-emerald-500 font-mono">{mlAccuracy}%</p>
            </div>
            <div className="p-3.5 bg-emerald-500/10 text-emerald-500 rounded-2xl group-hover:scale-110 transition duration-300">
              <Cpu className="w-6 h-6" />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/60 flex items-center justify-between text-[11px]">
            <span className="text-slate-400 font-medium">Random Forest & NLP</span>
            <span className="text-emerald-500 font-mono font-bold">Opérationnel</span>
          </div>
        </div>

      </div>

      {/* Main Interactive Scanner Container */}
      <div className="bg-white/80 dark:bg-[#111622]/90 backdrop-blur-xl border border-sky-100 dark:border-sky-800/40 rounded-3xl p-8 shadow-2xl space-y-6">
        
        {/* Input Bar & Scan Action */}
        <form onSubmit={handleScan} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3 items-stretch">
            
            <div className="relative flex-1">
              <input
                type="text"
                required
                placeholder={
                  investigationObjective === 'SYSTEM'
                    ? "Entrez l'adresse de votre site web (ex: https://mon-site.com)..."
                    : "Collez l'adresse URL à analyser..."
                }
                value={targetContent}
                onChange={(e) => setTargetContent(e.target.value)}
                className="w-full h-14 px-5 rounded-2xl bg-slate-50 dark:bg-[#1a2333] border-2 border-sky-200 dark:border-sky-800/60 text-slate-900 dark:text-white placeholder-slate-400 text-xs font-mono focus:outline-none focus:border-sky-500 transition shadow-inner pr-10"
              />
              {targetContent && (
                <button
                  type="button"
                  onClick={() => setTargetContent('')}
                  className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              )}
            </div>

            {/* Objective Dropdown Split Action Button */}
            <div ref={dropdownRef} className="relative shrink-0">
              
              <div className="inline-flex rounded-2xl shadow-xl shadow-sky-500/30 overflow-hidden border border-sky-400/20">
                <button
                  type="submit"
                  disabled={isScanning}
                  className="h-14 px-6 bg-gradient-to-r from-sky-500 via-sky-600 to-blue-600 hover:from-sky-600 hover:to-blue-700 disabled:opacity-50 text-white font-extrabold flex items-center gap-2.5 text-xs transition cursor-pointer"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Analyse IA en cours...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 text-sky-200" />
                      <span>Démarrer l'Analyse</span>
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
                      if (targetContent.trim()) handleScan();
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
                      if (targetContent.trim()) handleScan();
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

        {/* Scan Result Card */}
        {currentResult && (
          <div className={`mt-8 rounded-3xl p-7 border-2 transition-all animate-in fade-in slide-in-from-top-6 duration-300 ${
            currentResult.verdict === 'PHISHING' || currentResult.riskScore >= 50
              ? 'bg-rose-950/20 border-rose-500/50 text-rose-900 dark:text-rose-200 shadow-rose-950/20'
              : 'bg-emerald-950/20 border-emerald-500/50 text-emerald-900 dark:text-emerald-200 shadow-emerald-950/20'
          } shadow-2xl space-y-6`}>
            
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-black/10 dark:border-white/10 pb-5">
              
              <div className="flex items-center gap-4">
                {currentResult.verdict === 'PHISHING' || currentResult.riskScore >= 50 ? (
                  <div className="p-4 bg-rose-500 text-white rounded-2xl shadow-lg shadow-rose-500/40 shrink-0">
                    <AlertTriangle className="w-8 h-8" />
                  </div>
                ) : (
                  <div className="p-4 bg-emerald-500 text-white rounded-2xl shadow-lg shadow-emerald-500/40 shrink-0">
                    <CheckCircle2 className="w-8 h-8" />
                  </div>
                )}

                <div>
                  <span className="text-[10px] font-mono font-extrabold uppercase tracking-widest opacity-70">
                    Résultat de Classification IA
                  </span>
                  <h3 className="text-xl sm:text-2xl font-black tracking-tight">
                    {currentResult.verdict === 'PHISHING' || currentResult.riskScore >= 50 
                      ? '⚠️ MENACE DE PHISHING DÉTECTÉE' 
                      : '✅ CONTENU SÉCURISÉ ET LÉGITIME'}
                  </h3>
                </div>
              </div>

              {/* Gauge Score Pill */}
              <div className="px-5 py-2.5 bg-white/90 dark:bg-[#111622] rounded-2xl border border-black/10 dark:border-white/10 font-mono font-black text-base shadow-lg shrink-0 flex items-center gap-2">
                <span>Score de risque :</span>
                <span className={currentResult.riskScore >= 50 ? 'text-rose-500' : 'text-emerald-400'}>
                  {currentResult.riskScore}%
                </span>
              </div>

            </div>

            <div className="space-y-2">
              <p className="text-[11px] font-mono font-extrabold uppercase opacity-75">Contenu soumis à l'analyse :</p>
              <div className="p-4 bg-white/70 dark:bg-[#111622]/80 rounded-2xl border border-black/10 dark:border-white/10 font-mono text-xs break-all shadow-inner">
                {currentResult.target}
              </div>
            </div>

            {reportSuccess ? (
              <div className="p-4 bg-emerald-500/20 border border-emerald-500/40 text-emerald-800 dark:text-emerald-300 text-xs font-bold rounded-2xl flex items-center gap-2.5">
                <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-500" />
                <span>{reportSuccess}</span>
              </div>
            ) : (
              <button
                onClick={handleSendReport}
                disabled={isReporting}
                className="w-full py-4 bg-rose-600 hover:bg-rose-700 disabled:opacity-50 text-white text-xs font-extrabold rounded-2xl shadow-xl shadow-rose-600/30 flex items-center justify-center gap-2 transition cursor-pointer"
              >
                <Send className="w-4 h-4" /> <span>Créer un Signalement (Transmettre à l'Enquêteur)</span>
              </button>
            )}

          </div>
        )}

      </div>

      {/* Floating AI Security Assistant Chat Widget */}
      <div className="fixed bottom-6 right-6 z-50">
        {!isChatOpen ? (
          <button
            onClick={() => setIsChatOpen(true)}
            className="flex items-center gap-2.5 px-5 py-3.5 bg-gradient-to-r from-sky-500 to-blue-600 text-white rounded-full font-bold text-xs shadow-2xl shadow-sky-500/40 hover:scale-105 transition transform active:scale-95 border-2 border-white/20 cursor-pointer"
          >
            <div className="relative">
              <Bot className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full animate-ping" />
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full" />
            </div>
            <span>PhishGuard AI</span>
          </button>
        ) : (
          <div className="bg-white dark:bg-[#111622] border border-sky-100 dark:border-sky-800/60 rounded-3xl shadow-2xl w-80 sm:w-96 flex flex-col h-[480px] overflow-hidden animate-in zoom-in-95 duration-200">
            <div className="p-4 bg-gradient-to-r from-sky-500 to-blue-600 text-white flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-white/20 rounded-xl backdrop-blur-sm">
                  <Bot className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="font-extrabold text-sm">PhishGuard AI</h4>
                  <p className="text-[10px] text-sky-100 font-medium">En ligne • Assistant Cybersécurité</p>
                </div>
              </div>
              <button onClick={() => setIsChatOpen(false)} className="p-1 text-white/80 hover:text-white rounded-lg cursor-pointer">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 p-4 overflow-y-auto space-y-3 bg-slate-50/50 dark:bg-[#090d16]/50 text-xs">
              {chatMessages.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] rounded-2xl p-3 leading-relaxed ${
                    msg.sender === 'user'
                      ? 'bg-sky-500 text-white rounded-br-none shadow-md'
                      : 'bg-white dark:bg-[#1a2333] text-slate-800 dark:text-slate-200 border border-sky-100 dark:border-sky-800/40 rounded-bl-none shadow-sm'
                  }`}>
                    {msg.text}
                  </div>
                </div>
              ))}
              {isChatting && (
                <div className="flex justify-start">
                  <div className="bg-white dark:bg-[#1a2333] text-slate-400 p-2.5 rounded-2xl text-[11px] flex items-center gap-2 border border-sky-100 dark:border-sky-800/40">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin text-sky-500" /> PhishGuard AI réfléchit...
                  </div>
                </div>
              )}
            </div>

            <form onSubmit={handleSendMessage} className="p-3 bg-white dark:bg-[#111622] border-t border-sky-100 dark:border-sky-800/40 flex gap-2">
              <input
                type="text"
                placeholder="Posez une question à PhishGuard AI..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                className="flex-1 px-3 py-2 rounded-xl bg-slate-50 dark:bg-[#1a2333] border border-sky-200 dark:border-sky-800/60 text-slate-900 dark:text-white placeholder-slate-400 text-xs focus:outline-none focus:border-sky-500 font-sans"
              />
              <button
                type="submit"
                disabled={isChatting}
                className="p-2 bg-sky-500 hover:bg-sky-600 text-white rounded-xl shadow-md transition cursor-pointer"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </div>
        )}
      </div>

    </div>
  );
}
