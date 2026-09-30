import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { 
  History, Search, Pin, Eye, Trash2, X, AlertTriangle, 
  CheckCircle2, Cpu, BarChart2, ShieldCheck, MapPin, 
  Lock, Copy, Check, FileText, Send, Sparkles, Filter, RefreshCw, Terminal, ShieldAlert
} from 'lucide-react';

export default function HistoryPage() {
  const { user } = useAuth();
  const { lang, t } = useLanguage();

  const [scanHistory, setScanHistory] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [historySearchQuery, setHistorySearchQuery] = useState('');
  const [historyVerdictFilter, setHistoryVerdictFilter] = useState('ALL'); // 'ALL', 'THREATS', 'CLEAN'
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);
  const [itemToDelete, setItemToDelete] = useState(null);

  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

  // Transfer to Investigator State
  const [transferringId, setTransferringId] = useState(null);
  const [transferredIds, setTransferredIds] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('phishguard_transferred_ids')) || [];
    } catch (e) {
      return [];
    }
  });
  const [transferMessage, setTransferMessage] = useState('');

  // Scroll to top immediately on component mount
  useEffect(() => {
    window.scrollTo(0, 0);
    const mainEl = document.querySelector('main');
    if (mainEl) mainEl.scrollTop = 0;
  }, []);

  // Pinned Items State
  const [pinnedIds, setPinnedIds] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('phishguard_pinned_ids')) || [];
    } catch (e) {
      return [];
    }
  });

  const togglePin = (itemId, e) => {
    if (e) e.stopPropagation();
    setPinnedIds((prev) => {
      const updated = prev.includes(itemId) ? prev.filter((id) => id !== itemId) : [...prev, itemId];
      localStorage.setItem('phishguard_pinned_ids', JSON.stringify(updated));
      return updated;
    });
  };

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
    } catch (e) {}
  };

  const fetchHistory = async () => {
    setIsLoading(true);
    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch('/api/v1/analyze/history', { headers });
      if (res.ok) {
        const data = await res.json();
        const records = data.history || [];
        const formatted = records.map((r) => {
          const det = typeof r.details === 'string' ? JSON.parse(r.details || '{}') : (r.details || {});
          
          const rawScore = r.riskScore ?? r.risk_score ?? det.risk_score ?? det.riskScore ?? 0;
          const score = typeof rawScore === 'number' ? rawScore : parseFloat(rawScore) || 0;
          
          const rawVerdict = (r.verdict || det.verdict || '').toUpperCase();
          const isThreat = score >= 50 || rawVerdict.includes('PHISH') || rawVerdict.includes('MALICIOUS') || rawVerdict.includes('MENACE') || rawVerdict.includes('SUSPICIOUS');
          const verdict = isThreat ? 'PHISHING / MALICIOUS' : 'LEGITIMATE / CLEAN';

          return {
            id: r.id,
            analysis_code: r.analysis_code || det.analysis_code || `ANL-${r.id ? r.id.slice(0, 6).toUpperCase() : 'SCAN'}`,
            type: (r.type || r.scan_type || det.analysis_type || 'URL').toUpperCase(),
            target: r.target || r.target_content || det.target_url || det.text_content || '',
            verdict: verdict,
            riskScore: score,
            riskLevel: r.riskLevel || r.risk_level || det.risk_level || (isThreat ? 'CRITIQUE' : 'FAIBLE'),
            confidence: r.confidence || r.confidence_level || r.ml_confidence || det.ml_confidence || 98.4,
            timestamp: (() => {
              const raw = r.created_at || r.timestamp;
              if (!raw) return new Date().toLocaleTimeString(lang === 'fr' ? 'fr-FR' : 'en-US');
              let s = raw;
              if (typeof s === 'string' && (s.includes('T') || s.includes('-')) && !s.endsWith('Z') && !s.includes('+')) {
                s += 'Z';
              }
              const d = new Date(s);
              return isNaN(d.getTime()) ? raw : d.toLocaleTimeString(lang === 'fr' ? 'fr-FR' : 'en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: lang !== 'fr' });
            })(),
            fullDate: (() => {
              const raw = r.created_at || r.timestamp;
              if (!raw) return '';
              let s = raw;
              if (typeof s === 'string' && (s.includes('T') || s.includes('-')) && !s.endsWith('Z') && !s.includes('+')) {
                s += 'Z';
              }
              const d = new Date(s);
              return isNaN(d.getTime()) ? '' : d.toLocaleDateString(lang === 'fr' ? 'fr-FR' : 'en-US', { day: 'numeric', month: 'short', year: 'numeric' });
            })(),
            details: det,
            integrity_hash: r.integrity_hash || det.integrity_hash
          };
        });

        setScanHistory(formatted);
        const userHistoryKey = user?.id ? `phishguard_cached_history_${user.id}` : 'phishguard_cached_history';
        try {
          localStorage.setItem(userHistoryKey, JSON.stringify(formatted));
        } catch (e) {}
      }
    } catch (err) {
      console.log('Error loading history:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    const userHistoryKey = user?.id ? `phishguard_cached_history_${user.id}` : 'phishguard_cached_history';
    try {
      const saved = localStorage.getItem(userHistoryKey);
      setScanHistory(saved ? JSON.parse(saved) : []);
    } catch(e) {
      setScanHistory([]);
    }
    fetchHistory();
  }, [user?.id]);

  const [isClearingAll, setIsClearingAll] = useState(false);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  const handleClearAllHistory = async () => {
    setIsClearingAll(true);
    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch('/api/v1/analyze/history', { method: 'DELETE', headers });
      if (res.ok) {
        setScanHistory([]);
        const userKey = user?.id ? `_${user.id}` : '';
        localStorage.removeItem('phishguard_cached_history');
        localStorage.removeItem('phishguard_latest_result');
        localStorage.removeItem('phishguard_cached_stats');
        localStorage.removeItem(`phishguard_cached_history${userKey}`);
        localStorage.removeItem(`phishguard_latest_result${userKey}`);
        localStorage.removeItem(`phishguard_cached_stats${userKey}`);
        try {
          Object.keys(localStorage).forEach(k => {
            if (k.startsWith('phishguard_latest_result') || k.startsWith('phishguard_cached_history')) {
              localStorage.removeItem(k);
            }
          });
        } catch (e) {}
      }
    } catch (e) {
      console.error("Error clearing history:", e);
    } finally {
      setIsClearingAll(false);
      setShowClearConfirm(false);
    }
  };

  const handleDeleteItem = async () => {
    if (!itemToDelete) return;
    const id = itemToDelete.id;
    const code = itemToDelete.analysis_code;
    setItemToDelete(null);

    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch(`/api/v1/analyze/history/${id}`, { method: 'DELETE', headers });
      if (res.ok) {
        const userKey = user?.id ? `_${user.id}` : '';
        setScanHistory((prev) => {
          const updated = prev.filter((item) => item.id !== id);
          try {
            localStorage.setItem('phishguard_cached_history', JSON.stringify(updated));
            localStorage.setItem(`phishguard_cached_history${userKey}`, JSON.stringify(updated));
            if (updated.length === 0) {
              localStorage.removeItem('phishguard_latest_result');
              localStorage.removeItem('phishguard_cached_stats');
              localStorage.removeItem(`phishguard_latest_result${userKey}`);
              localStorage.removeItem(`phishguard_cached_stats${userKey}`);
            } else {
              const saved = localStorage.getItem(`phishguard_latest_result${userKey}`) || localStorage.getItem('phishguard_latest_result');
              if (saved) {
                const parsed = JSON.parse(saved);
                if (
                  String(parsed.id) === String(id) || 
                  String(parsed.id) === String(code) || 
                  String(parsed.details?.analysis_code) === String(id) || 
                  String(parsed.details?.analysis_code) === String(code)
                ) {
                  localStorage.removeItem(`phishguard_latest_result${userKey}`);
                  localStorage.removeItem('phishguard_latest_result');
                }
              }
            }
          } catch (e) {}
          return updated;
        });
      }
    } catch (e) {
      console.log('Error deleting record:', e);
    }
  };

  const handleTransferToInvestigator = async (item) => {
    if (!item) return;
    setTransferringId(item.id);
    setTransferMessage('');

    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const reporterName = user?.role === 'ADMINISTRATEUR'
        ? `${user?.prenom || 'Admin'} ${user?.nom || ''}`.trim() + ' (Administrateur)'
        : `${user?.prenom || 'Alice'} ${user?.nom || 'Martin'}`.trim();

      const transferTitle = user?.role === 'ADMINISTRATEUR'
        ? `[Transfert Admin] ${item.target}`
        : `[Demand / Transfer] ${item.target}`;

      const res = await fetch('/api/v1/incidents/submit-user-report', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          title: transferTitle,
          target: item.target,
          scan_type: item.type || 'URL',
          verdict: item.verdict,
          risk_score: item.riskScore,
          details: {
            ...(item.details || {}),
            transferred_from_history: true,
            analysis_code: item.analysis_code,
            transfer_timestamp: new Date().toISOString(),
            transferred_by_role: user?.role || 'UTILISATEUR_STANDARD'
          },
          reporter_name: reporterName,
          reporter_email: user?.email || (user?.role === 'ADMINISTRATEUR' ? 'admin@cyberdefense.local' : 'alice.martin@example.com')
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || (lang === 'fr' ? 'Erreur lors du transfert' : 'Error transferring report'));

      const newTransferred = [...transferredIds, item.id];
      setTransferredIds(newTransferred);
      try {
        localStorage.setItem('phishguard_transferred_ids', JSON.stringify(newTransferred));
      } catch (e) {}

      setTransferMessage(
        lang === 'fr'
          ? `✓ Dossier transféré avec succès à l'enquêteur (${data.report?.report_code || 'DEMANDE-OK'})`
          : `✓ Successfully transferred to the investigator (${data.report?.report_code || 'DEMAND-OK'})`
      );
    } catch (err) {
      alert((lang === 'fr' ? 'Erreur : ' : 'Error: ') + err.message);
    } finally {
      setTransferringId(null);
    }
  };

  // Filter & Search Logic
  const filteredHistory = scanHistory.filter((item) => {
    const query = historySearchQuery.toLowerCase().trim();
    const matchesText =
      !query ||
      (item.target && item.target.toLowerCase().includes(query)) ||
      (item.type && item.type.toLowerCase().includes(query)) ||
      (item.verdict && item.verdict.toLowerCase().includes(query)) ||
      (item.analysis_code && item.analysis_code.toLowerCase().includes(query)) ||
      (item.timestamp && item.timestamp.toLowerCase().includes(query)) ||
      (item.fullDate && item.fullDate.toLowerCase().includes(query));

    const matchesVerdict =
      historyVerdictFilter === 'ALL'
        ? true
        : historyVerdictFilter === 'THREATS'
        ? item.riskScore >= 50 || item.verdict?.includes('PHISHING') || item.verdict?.includes('MALICIOUS')
        : item.riskScore < 50 && !item.verdict?.includes('PHISHING');

    return matchesText && matchesVerdict;
  });

  const sortedScanHistory = [...filteredHistory].sort((a, b) => {
    const aPinned = pinnedIds.includes(a.id);
    const bPinned = pinnedIds.includes(b.id);
    if (aPinned && !bPinned) return -1;
    if (!aPinned && bPinned) return 1;
    return 0;
  });

  const totalThreats = scanHistory.filter((item) => item.riskScore >= 50 || item.verdict?.includes('PHISHING')).length;
  const totalClean = scanHistory.length - totalThreats;

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-20">
      
      {/* Top Banner Card */}
      <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-slate-800/80 rounded-3xl p-6 sm:p-8 shadow-xl space-y-6">
        
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-800/80 pb-5">
          <div className="flex items-center gap-3.5">
            <div className="p-3 bg-sky-500/10 text-sky-500 rounded-2xl">
              <History className="w-7 h-7" />
            </div>
            <div>
              <h2 className="text-2xl font-black text-slate-900 dark:text-white tracking-tight">
                {lang === 'fr' ? 'Historique des Analyses & Renseignement IA' : 'Analysis History & AI Intelligence'}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {lang === 'fr' ? "Registre permanent de l'ensemble de vos analyses enregistrées en base de données." : 'Permanent ledger of all security scans recorded in the database.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-3.5 py-1.5 bg-sky-50 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800/40 rounded-xl text-xs font-mono font-bold">
              {scanHistory.length} {lang === 'fr' ? 'analyses au total' : 'total scans'}
            </span>

            <button
              onClick={fetchHistory}
              disabled={isLoading}
              className="p-1.5 bg-slate-100 dark:bg-slate-800 hover:bg-sky-500/10 text-slate-600 dark:text-slate-300 rounded-xl transition cursor-pointer"
              title={lang === 'fr' ? 'Actualiser' : 'Refresh'}
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-sky-500' : ''}`} />
            </button>

            {scanHistory.length > 0 && (
              <button
                onClick={() => setShowClearConfirm(true)}
                className="px-3 py-1.5 bg-rose-500/10 hover:bg-rose-500 text-rose-500 hover:text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 border border-rose-500/30 cursor-pointer"
                title={lang === 'fr' ? "Vider tout l'historique" : 'Clear all history'}
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>{lang === 'fr' ? "Vider l'historique" : 'Clear History'}</span>
              </button>
            )}
          </div>
        </div>

        {/* Live Search & Segmented Filter Bar */}
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-slate-50 dark:bg-[#111622] p-3 rounded-2xl border border-slate-200 dark:border-slate-800">
          
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder={lang === 'fr' ? "Rechercher par URL, code ANL, canal, statut..." : "Search by URL, ANL code, channel, status..."}
              value={historySearchQuery}
              onChange={(e) => setHistorySearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-slate-700 rounded-xl text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-sky-500 font-sans"
            />
          </div>

          <div className="flex items-center gap-1.5 shrink-0 text-xs font-sans font-bold w-full sm:w-auto">
            <button
              onClick={() => setHistoryVerdictFilter('ALL')}
              className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                historyVerdictFilter === 'ALL'
                  ? 'bg-sky-500 text-white border-sky-500 shadow-sm shadow-sky-500/30'
                  : 'bg-white dark:bg-[#161b27] text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700'
              }`}
            >
              {lang === 'fr' ? 'Tous' : 'All'} ({scanHistory.length})
            </button>

            <button
              onClick={() => setHistoryVerdictFilter('THREATS')}
              className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                historyVerdictFilter === 'THREATS'
                  ? 'bg-rose-600 text-white border-rose-600 shadow-sm shadow-rose-600/30'
                  : 'bg-white dark:bg-[#161b27] text-rose-600 dark:text-rose-400 border-slate-200 dark:border-slate-700'
              }`}
            >
              🚨 {lang === 'fr' ? 'Menaces' : 'Threats'} ({totalThreats})
            </button>

            <button
              onClick={() => setHistoryVerdictFilter('CLEAN')}
              className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                historyVerdictFilter === 'CLEAN'
                  ? 'bg-emerald-600 text-white border-emerald-600 shadow-sm shadow-emerald-600/30'
                  : 'bg-white dark:bg-[#161b27] text-emerald-600 dark:text-emerald-400 border-slate-200 dark:border-slate-700'
              }`}
            >
              ✅ {lang === 'fr' ? 'Légitimes' : 'Legitimate'} ({totalClean})
            </button>
          </div>

        </div>

        {/* History Records Table */}
        {sortedScanHistory.length === 0 ? (
          <div className="py-16 text-center text-slate-400 text-xs font-medium space-y-2">
            <p className="text-sm font-bold text-slate-600 dark:text-slate-300">{lang === 'fr' ? "Aucun résultat trouvé dans l'historique." : 'No results found in history.'}</p>
            <p className="text-slate-500 text-[11px]">{lang === 'fr' ? 'Essayez de modifier votre recherche ou effectuez un nouveau scan sur le tableau de bord.' : 'Try modifying your search query or run a new scan on the dashboard.'}</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-200 font-sans">
              <thead className="bg-slate-50 dark:bg-[#111622] text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="py-3 px-3 w-10 text-center">📌</th>
                  <th className="py-3 px-3">{lang === 'fr' ? 'Date / Heure' : 'Date / Time'}</th>
                  <th className="py-3 px-3">{lang === 'fr' ? 'Canal' : 'Channel'}</th>
                  <th className="py-3 px-3">{lang === 'fr' ? 'Cible Analysée' : 'Analyzed Target'}</th>
                  <th className="py-3 px-3">{lang === 'fr' ? 'Verdict IA' : 'AI Verdict'}</th>
                  <th className="py-3 px-3">{lang === 'fr' ? 'Score' : 'Score'}</th>
                  <th className="py-3 px-3 text-right">{lang === 'fr' ? 'Actions' : 'Actions'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80 font-mono text-xs">
                {sortedScanHistory.map((item) => {
                  const isPinned = pinnedIds.includes(item.id);
                  const isThreat = item.riskScore >= 50 || item.verdict?.includes('PHISHING') || item.verdict?.includes('MALICIOUS');
                  const isTransferred = transferredIds.includes(item.id);

                  return (
                    <tr
                      key={item.id}
                      onClick={() => { setSelectedHistoryItem(item); setTransferMessage(''); }}
                      className={`hover:bg-sky-500/5 dark:hover:bg-sky-500/10 cursor-pointer transition duration-150 ${
                        isPinned ? 'bg-amber-500/5 dark:bg-amber-500/10' : ''
                      }`}
                    >
                      <td className="py-3.5 px-3 text-center" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={(e) => togglePin(item.id, e)}
                          className={`p-1.5 rounded-lg transition cursor-pointer ${
                            isPinned
                              ? 'bg-amber-500/20 text-amber-500 border border-amber-500/40'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                          title={isPinned ? (lang === 'fr' ? 'Désépingler' : 'Unpin') : (lang === 'fr' ? 'Épingler en haut' : 'Pin to top')}
                        >
                          <Pin className="w-3.5 h-3.5" />
                        </button>
                      </td>

                      <td className="py-3.5 px-3 text-slate-400 font-bold">
                        <div>{item.timestamp}</div>
                        {item.fullDate && <div className="text-[10px] text-slate-500 font-normal">{item.fullDate}</div>}
                      </td>

                      <td className="py-3.5 px-3 font-bold text-sky-500">
                        {item.type}
                      </td>

                      <td className="py-3.5 px-3 max-w-xs sm:max-w-md truncate text-slate-900 dark:text-slate-100 font-sans font-medium">
                        <div className="flex items-center gap-1.5">
                          {isPinned && <span className="text-amber-500 font-bold">📌</span>}
                          <span className="truncate">{item.target}</span>
                          {(user?.role === 'UTILISATEUR_STANDARD' || user?.role === 'ADMINISTRATEUR') && isTransferred && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 shrink-0">
                              {lang === 'fr' ? '✓ Transféré' : '✓ Transferred'}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="py-3.5 px-3">
                        <span
                          className={`px-2.5 py-1 rounded-full text-[10px] font-extrabold inline-flex items-center gap-1.5 ${
                            isThreat
                              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30'
                              : 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${isThreat ? 'bg-rose-500 animate-pulse' : 'bg-emerald-400'}`} />
                          {isThreat 
                            ? (lang === 'fr' ? 'PHISHING / MALVEILLANT' : 'PHISHING / MALICIOUS') 
                            : (lang === 'fr' ? 'LÉGITIME / SÛR' : 'LEGITIMATE / CLEAN')}
                        </span>
                      </td>

                      <td className="py-3.5 px-3 font-extrabold text-slate-900 dark:text-white">
                        {item.riskScore}%
                      </td>

                      <td className="py-3.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          {(user?.role === 'UTILISATEUR_STANDARD' || user?.role === 'ADMINISTRATEUR') && (
                            <button
                              onClick={(e) => { e.stopPropagation(); handleTransferToInvestigator(item); }}
                              disabled={transferringId === item.id || isTransferred}
                              className={`px-2 py-1 font-bold rounded-lg text-[10px] border transition cursor-pointer flex items-center gap-1 ${
                                isTransferred
                                  ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 cursor-default'
                                  : 'bg-rose-500/10 hover:bg-rose-500 hover:text-white text-rose-600 dark:text-rose-400 border-rose-500/30'
                              }`}
                              title={isTransferred ? (lang === 'fr' ? "Déjà transféré à l'enquêteur" : "Already transferred") : (lang === 'fr' ? "Transférer à l'enquêteur" : "Transfer to investigator")}
                            >
                              {transferringId === item.id ? (
                                <RefreshCw className="w-3 h-3 animate-spin" />
                              ) : isTransferred ? (
                                <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                              ) : (
                                <Send className="w-3 h-3" />
                              )}
                              <span className="hidden sm:inline">
                                {isTransferred ? (lang === 'fr' ? 'Transféré' : 'Transférer') : (lang === 'fr' ? 'Transférer' : 'Transfer')}
                              </span>
                            </button>
                          )}
                          <button
                            onClick={() => { setSelectedHistoryItem(item); setTransferMessage(''); }}
                            className="px-2.5 py-1 bg-sky-500/10 hover:bg-sky-500/20 text-sky-600 dark:text-sky-400 font-bold rounded-lg text-[11px] border border-sky-500/30 transition cursor-pointer"
                          >
                            {lang === 'fr' ? 'Voir' : 'View'}
                          </button>
                          <button
                            onClick={() => setItemToDelete(item)}
                            className="p-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 rounded-lg border border-rose-500/30 transition cursor-pointer"
                            title={lang === 'fr' ? 'Supprimer définitivement' : 'Delete permanently'}
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
        )}

      </div>

      {/* Delete Confirmation Modal */}
      {itemToDelete && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#161b27] border-2 border-rose-500/50 rounded-3xl p-6 sm:p-8 max-w-md w-full shadow-2xl space-y-5 animate-in zoom-in-95 duration-150 text-center">
            <div className="w-14 h-14 bg-rose-500/10 text-rose-500 rounded-full flex items-center justify-center mx-auto border border-rose-500/30">
              <Trash2 className="w-7 h-7" />
            </div>

            <div className="space-y-2">
              <h3 className="text-xl font-black text-slate-900 dark:text-white font-sans">
                {lang === 'fr' ? 'Confirmer la suppression ?' : 'Confirm deletion?'}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                {lang === 'fr' ? 'Voulez-vous supprimer définitivement cette analyse de votre historique et de la base de données ?' : 'Are you sure you want to permanently delete this scan from your history and database?'}
              </p>
              <div className="p-3 bg-slate-50 dark:bg-[#111622] rounded-xl font-mono text-xs font-bold text-slate-800 dark:text-slate-200 truncate border border-slate-200 dark:border-slate-800">
                {itemToDelete.target}
              </div>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setItemToDelete(null)}
                className="flex-1 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-bold text-xs rounded-2xl transition cursor-pointer"
              >
                {lang === 'fr' ? 'Annuler' : 'Cancel'}
              </button>

              <button
                onClick={handleDeleteItem}
                className="flex-1 py-3 bg-rose-600 hover:bg-rose-700 text-white font-extrabold text-xs rounded-2xl shadow-lg shadow-rose-600/30 transition cursor-pointer"
              >
                {lang === 'fr' ? 'Confirmer' : 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Detailed Modal view for selected history record */}
      {selectedHistoryItem && (() => {
        const itemDetails = selectedHistoryItem.details || selectedHistoryItem;
        const isThreat = selectedHistoryItem.riskScore >= 50 || selectedHistoryItem.verdict?.includes('PHISHING') || selectedHistoryItem.verdict?.includes('MALICIOUS');
        const features = itemDetails?.features || {};
        const models = itemDetails?.model_comparisons || [];
        const geoip = itemDetails?.geoip_info;
        const vt = itemDetails?.virustotal;
        const gsb = itemDetails?.google_safebrowsing;
        const advice = itemDetails?.defensive_advice || [];
        const isTransferred = transferredIds.includes(selectedHistoryItem.id);

        return (
          <div className="fixed inset-0 bg-slate-950/75 backdrop-blur-md z-50 flex items-center justify-center p-4">
            <div className="bg-white dark:bg-[#161b27] border-2 border-sky-200 dark:border-sky-800/80 rounded-3xl p-6 sm:p-8 max-w-4xl w-full shadow-2xl space-y-6 relative max-h-[90vh] overflow-y-auto animate-in zoom-in-95 duration-150">
              
              {/* Modal Header */}
              <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 bg-sky-500/10 text-sky-500 rounded-2xl font-mono text-xs font-bold">
                    {selectedHistoryItem.analysis_code}
                  </div>
                  <div>
                    <h3 className="text-lg font-black text-slate-900 dark:text-white">{lang === 'fr' ? "Fiche Détaillée d'Analyse (Registre Base de Données)" : "Detailed Analysis File (Database Record)"}</h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">{lang === 'fr' ? 'Horodatage :' : 'Timestamp:'} {selectedHistoryItem.timestamp} {selectedHistoryItem.fullDate}</p>
                  </div>
                </div>
                <button
                  onClick={() => { setSelectedHistoryItem(null); setTransferMessage(''); }}
                  className="p-2 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-xl bg-slate-100 dark:bg-slate-800 cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Main Verdict & Risk Score Pill Banner */}
              <div
                className={`p-5 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                  isThreat
                    ? 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/40 text-rose-950 dark:text-rose-100'
                    : 'bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/40 text-emerald-950 dark:text-emerald-100'
                }`}
              >
                <div className="flex items-center gap-3.5">
                  <div
                    className={`p-3 rounded-2xl shadow-md shrink-0 text-white ${
                      isThreat ? 'bg-rose-600' : 'bg-emerald-600'
                    }`}
                  >
                    {isThreat ? <AlertTriangle className="w-6 h-6" /> : <CheckCircle2 className="w-6 h-6" />}
                  </div>
                  <div>
                    <span className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-75">
                      {lang === 'fr' ? 'Classification IA' : 'AI Classification'}
                    </span>
                    <p className="text-xl font-black">
                      {isThreat 
                        ? (lang === 'fr' ? 'PHISHING / MALVEILLANT' : 'PHISHING / MALICIOUS') 
                        : (lang === 'fr' ? 'LÉGITIME / SÛR' : 'LEGITIMATE / CLEAN')}
                    </p>
                  </div>
                </div>

                <div
                  className={`px-5 py-2.5 rounded-xl font-mono font-black text-lg shadow-md shrink-0 text-white ${
                    isThreat ? 'bg-rose-600' : 'bg-emerald-600'
                  }`}
                >
                  Score: {selectedHistoryItem.riskScore}%
                </div>
              </div>

              {/* Submitted Target Content */}
              <div className="space-y-1.5">
                <label className="text-[10px] uppercase font-mono font-bold text-slate-400">
                  {lang === 'fr' ? 'Cible Analysée' : 'Inspected Target'} ({selectedHistoryItem.type})
                </label>
                <div className="p-4 bg-slate-50 dark:bg-[#111622] rounded-2xl border border-slate-200 dark:border-slate-800 text-xs font-mono break-all text-slate-900 dark:text-slate-100 shadow-inner font-bold flex items-center justify-between gap-3">
                  <span>{selectedHistoryItem.target}</span>
                  <button
                    onClick={() => copyToClipboard(selectedHistoryItem.target, 'url')}
                    className="p-1.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-sky-500 text-xs shrink-0 cursor-pointer"
                    title={lang === 'fr' ? 'Copier' : 'Copy'}
                  >
                    {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {/* ── SECTION LABEL ── */}
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-500" />
                  <h4 className="text-xs font-extrabold uppercase font-mono tracking-wider text-slate-700 dark:text-slate-200">
                    {lang === 'fr' ? 'Rapport de Sécurité Complet — Tests Exécutés' : 'Full Security Report — Executed Tests'}
                  </h4>
                </div>
                <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-md bg-indigo-500/10 text-indigo-500 border border-indigo-500/20 shrink-0">
                  {(models.length > 0 ? 1 : 0) + (Object.keys(features).length > 0 ? 1 : 0) + 2 + (geoip ? 1 : 0)} {lang === 'fr' ? 'Blocs' : 'Blocks'}
                </span>
              </div>

              {/* ══ TEST BLOCK 1 — ML ENSEMBLE (3 MODELS) ══ */}
              {models.length > 0 && (
                <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-indigo-50 to-slate-50 dark:from-indigo-950/30 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded-lg bg-indigo-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">1</div>
                      <Cpu className="w-4 h-4 text-indigo-500" />
                      <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">
                        {lang === 'fr' ? 'Moteur IA — Ensemble Machine Learning (3 Modèles)' : 'AI Engine — Machine Learning Ensemble (3 Models)'}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                      {lang === 'fr' ? '✓ 3/3 Actifs' : '✓ 3/3 Active'}
                    </span>
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
                </div>
              )}

              {/* ══ TEST BLOCK 2 — HEURISTIC RULES + 17 FEATURES ══ */}
              {Object.keys(features).length > 0 && (
                <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-amber-50 to-slate-50 dark:from-amber-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded-lg bg-amber-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">2</div>
                      <BarChart2 className="w-4 h-4 text-amber-500" />
                      <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">
                        {lang === 'fr' ? 'Moteur Heuristique — 17 Caractéristiques URL' : 'Heuristic Engine — 17 URL Features'}
                      </span>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${(itemDetails?.rule_triggers?.length || 0) > 0 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                      {(itemDetails?.rule_triggers?.length || 0)} {lang === 'fr' ? 'Règle(s) Déclenchée(s)' : 'Rule(s) Triggered'}
                    </span>
                  </div>
                  <div className="p-4 space-y-4">
                    <div>
                      <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                        {lang === 'fr' ? 'Tests Binaires (Passe / Échec)' : 'Binary Checks (Pass / Fail)'}
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                        {[
                          { label: lang === 'fr' ? 'Chiffrement HTTPS / SSL' : 'HTTPS / SSL Encryption', desc: lang === 'fr' ? 'Protocole de connexion sécurisé' : 'Secure connection protocol', pass: !!features.is_https, value: features.is_https ? (lang === 'fr' ? 'HTTPS Actif' : 'HTTPS Active') : (lang === 'fr' ? 'HTTP Non Chiffré' : 'HTTP Unencrypted') },
                          { label: lang === 'fr' ? 'Hôte IP Direct' : 'Direct IP Host', desc: lang === 'fr' ? "IP brute au lieu d'un domaine" : "Raw IP instead of domain", pass: !features.has_ip, value: features.has_ip ? (lang === 'fr' ? 'IP Détectée — Risque' : 'IP Detected — Risk') : (lang === 'fr' ? 'Domaine Normal' : 'Normal Domain') },
                          { label: lang === 'fr' ? 'TLD Suspect' : 'Suspicious TLD', desc: lang === 'fr' ? 'Extension risquée (.xyz, .top, .tk...)' : 'Risky TLD (.xyz, .top, .tk...)', pass: !features.has_suspicious_tld, value: features.has_suspicious_tld ? (lang === 'fr' ? 'TLD Dangereux' : 'Dangerous TLD') : (lang === 'fr' ? 'TLD Standard' : 'Standard TLD') },
                          { label: lang === 'fr' ? 'Symbole @ Redirection' : '@ Symbol Redirection', desc: lang === 'fr' ? "Trompe le navigateur sur l'hôte réel" : "Tricks browser on actual host", pass: !(features.num_at > 0), value: features.num_at > 0 ? `${features.num_at} Symbol(s) @` : (lang === 'fr' ? 'Aucun' : 'None') },
                          { label: lang === 'fr' ? 'Sous-domaines Excessifs' : 'Excessive Subdomains', desc: 'login.secure.paypal.xyz (2+)', pass: (features.num_subdomains || 0) < 2, value: `${features.num_subdomains || 0} ${lang === 'fr' ? 'Niveau(x)' : 'Level(s)'}` },
                          { label: lang === 'fr' ? 'Mots-clés Suspects' : 'Suspicious Keywords', desc: 'login, verify, paypal, bank...', pass: (features.keyword_count || 0) === 0, value: features.keyword_count > 0 ? `${features.keyword_count} ${lang === 'fr' ? 'Mot(s)' : 'Word(s)'}` : (lang === 'fr' ? 'Aucun' : 'None') },
                        ].map((test, i) => (
                          <div key={i} className={`p-3 rounded-xl border flex items-start gap-3 ${test.pass ? 'bg-emerald-50/60 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-900/30' : 'bg-rose-50/60 dark:bg-rose-950/10 border-rose-200 dark:border-rose-900/30'}`}>
                            <div className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 text-white text-[10px] font-black ${test.pass ? 'bg-emerald-500' : 'bg-rose-500'}`}>{test.pass ? '✓' : '✗'}</div>
                            <div className="min-w-0">
                              <p className="text-xs font-bold text-slate-800 dark:text-white leading-tight">{test.label}</p>
                              <p className="text-[10px] text-slate-400 mt-0.5 leading-tight">{test.desc}</p>
                              <p className={`text-[10px] font-mono font-bold mt-1 ${test.pass ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'}`}>→ {test.value}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div>
                      <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                        {lang === 'fr' ? 'Métriques Numériques Extraites (17 Features ML)' : 'Extracted Numerical Metrics (17 ML Features)'}
                      </p>
                      <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-6 gap-2">
                        {[
                          { label: lang === 'fr' ? 'Long. URL' : 'URL Len.', val: features.url_length || 0, warn: (features.url_length || 0) > 75 },
                          { label: lang === 'fr' ? 'Long. Dom.' : 'Dom. Len.', val: features.domain_length || 0, warn: (features.domain_length || 0) > 30 },
                          { label: lang === 'fr' ? 'Chemin' : 'Path Len.', val: features.path_length || 0, warn: (features.path_length || 0) > 60 },
                          { label: lang === 'fr' ? 'Points (.)' : 'Dots (.)', val: features.num_dots || 0, warn: (features.num_dots || 0) > 4 },
                          { label: lang === 'fr' ? 'Tirets (-)' : 'Hyphens (-)', val: features.num_hyphens || 0, warn: (features.num_hyphens || 0) > 2 },
                          { label: lang === 'fr' ? 'Entropie' : 'Entropy', val: typeof features.entropy === 'number' ? features.entropy.toFixed(2) : '0', warn: (features.entropy || 0) > 4.2 },
                          { label: lang === 'fr' ? 'Params (?)' : 'Params (?)', val: features.num_equals || 0, warn: (features.num_equals || 0) > 3 },
                          { label: lang === 'fr' ? 'Barres (/)' : 'Slashes (/)', val: features.num_slashes || 0, warn: (features.num_slashes || 0) > 7 },
                          { label: lang === 'fr' ? 'Chiffres' : 'Digits', val: features.num_digits || 0, warn: (features.num_digits || 0) > 12 },
                          { label: lang === 'fr' ? 'Spéciaux' : 'Special', val: features.num_special_chars || 0, warn: (features.num_special_chars || 0) > 15 },
                          { label: lang === 'fr' ? 'Sous-dom.' : 'Subdomains', val: features.num_subdomains || 0, warn: (features.num_subdomains || 0) >= 2 },
                          { label: lang === 'fr' ? 'Mots-clés' : 'Keywords', val: features.keyword_count || 0, warn: (features.keyword_count || 0) > 0 },
                        ].map((m, i) => (
                          <div key={i} className={`p-2.5 rounded-xl border text-center ${m.warn ? 'bg-amber-50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-800/40' : 'bg-white dark:bg-slate-900/60 border-slate-100 dark:border-slate-800'}`}>
                            <span className={`text-base font-black font-mono block ${m.warn ? 'text-amber-600 dark:text-amber-400' : 'text-slate-800 dark:text-slate-200'}`}>{m.val}</span>
                            <span className="text-[9px] text-slate-400 font-mono uppercase block leading-tight mt-0.5">{m.label}</span>
                            {m.warn && <span className="text-[8px] text-amber-500 font-bold">↑ {lang === 'fr' ? 'Élevé' : 'High'}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* ══ TEST BLOCK 3 — THREAT INTELLIGENCE ══ */}
              <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-purple-50 to-slate-50 dark:from-purple-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                  <div className="w-6 h-6 rounded-lg bg-purple-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">3</div>
                  <ShieldCheck className="w-4 h-4 text-purple-500" />
                  <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">
                    {lang === 'fr' ? 'Threat Intelligence — Bases de Renseignement Mondiales' : 'Threat Intelligence — Global Intelligence Databases'}
                  </span>
                </div>
                <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className={`p-4 rounded-xl border space-y-3 ${(vt?.positives || 0) > 0 ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xl">🔬</span>
                        <div>
                          <p className="text-xs font-black text-slate-800 dark:text-white">VirusTotal</p>
                          <p className="text-[10px] text-slate-400">{lang === 'fr' ? '90 moteurs antivirus mondiaux' : '90 global antivirus engines'}</p>
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${(vt?.positives || 0) > 0 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                        {(vt?.positives || 0) > 0 ? (lang === 'fr' ? '⚠️ DÉTECTÉ' : '⚠️ DETECTED') : (lang === 'fr' ? '✓ PROPRE' : '✓ CLEAN')}
                      </span>
                    </div>
                    <div className="space-y-1 text-[10px] font-mono">
                      <div className="flex justify-between text-slate-500">
                        <span>{lang === 'fr' ? 'Détections' : 'Detections'}</span>
                        <span className={`font-black ${(vt?.positives || 0) > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{vt?.positives || 0} / {vt?.total_engines || 90}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>{lang === 'fr' ? 'Réputation' : 'Reputation'}</span>
                        <span className="font-bold">{vt?.reputation_score ?? 'N/A'}</span>
                      </div>
                    </div>
                  </div>
                  <div className={`p-4 rounded-xl border space-y-3 ${gsb?.is_flagged ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xl">🛡️</span>
                        <div>
                          <p className="text-xs font-black text-slate-800 dark:text-white">Google Safe Browsing</p>
                          <p className="text-[10px] text-slate-400">{lang === 'fr' ? 'Base mondiale malware & phishing' : 'Global malware & phishing database'}</p>
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${gsb?.is_flagged ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                        {gsb?.is_flagged ? (lang === 'fr' ? '⚠️ SIGNALÉ' : '⚠️ FLAGGED') : (lang === 'fr' ? '✓ LISTE BLANCHE' : '✓ WHITELISTED')}
                      </span>
                    </div>
                    <div className="space-y-1 text-[10px] font-mono">
                      <div className="flex justify-between text-slate-500">
                        <span>{lang === 'fr' ? 'Statut' : 'Status'}</span>
                        <span className={`font-black ${gsb?.is_flagged ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                          {gsb?.is_flagged ? (lang === 'fr' ? 'SIGNALÉ' : 'FLAGGED') : (lang === 'fr' ? 'APPROUVÉ' : 'APPROVED')}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* ══ TEST BLOCK 4 — GeoIP ══ */}
              {geoip && (
                <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-3 bg-gradient-to-r from-sky-50 to-slate-50 dark:from-sky-950/20 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                    <div className="w-6 h-6 rounded-lg bg-sky-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">4</div>
                    <MapPin className="w-4 h-4 text-sky-500" />
                    <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">
                      {lang === 'fr' ? 'GeoIP & ASN — Localisation Réseau' : 'GeoIP & ASN — Network Location'}
                    </span>
                  </div>
                  <div className="p-4">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono text-center">
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800">
                        <span className="text-[9px] text-slate-400 block uppercase">{lang === 'fr' ? 'Adresse IP' : 'IP Address'}</span>
                        <strong className="text-sky-500">{geoip.ip || 'N/A'}</strong>
                      </div>
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800">
                        <span className="text-[9px] text-slate-400 block uppercase">{lang === 'fr' ? 'Pays / Ville' : 'Country / City'}</span>
                        <strong>{geoip.country}, {geoip.city}</strong>
                      </div>
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800">
                        <span className="text-[9px] text-slate-400 block uppercase">ASN</span>
                        <strong>{geoip.asn || 'N/A'}</strong>
                      </div>
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800">
                        <span className="text-[9px] text-slate-400 block uppercase">VPN / Proxy</span>
                        <strong className={geoip.is_vpn_proxy ? 'text-rose-500' : 'text-emerald-500'}>
                          {geoip.is_vpn_proxy ? (lang === 'fr' ? '🔴 OUI' : '🔴 YES') : (lang === 'fr' ? '🟢 NON' : '🟢 NO')}
                        </strong>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* SHA-256 Checksum Signature */}
              {(selectedHistoryItem.integrity_hash || itemDetails?.integrity_hash) && (
                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase font-mono font-bold text-slate-400">
                    {lang === 'fr' ? "Empreinte Cryptographique d'Intégrité SHA-256" : "SHA-256 Integrity Cryptographic Fingerprint"}
                  </label>
                  <div className="p-3 bg-slate-50 dark:bg-[#111622] rounded-2xl font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all font-bold border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
                    <span>{selectedHistoryItem.integrity_hash || itemDetails?.integrity_hash}</span>
                    <button
                      onClick={() => copyToClipboard(selectedHistoryItem.integrity_hash || itemDetails?.integrity_hash, 'hash')}
                      className="text-xs text-sky-500 hover:text-sky-600 font-bold shrink-0 cursor-pointer"
                    >
                      {copiedHash ? (lang === 'fr' ? 'Copié !' : 'Copied!') : (lang === 'fr' ? 'Copier' : 'Copy')}
                    </button>
                  </div>
                </div>
              )}

              {/* Transfer Feedback Notification */}
              {transferMessage && (
                <div className="p-3.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs font-bold rounded-2xl flex items-center gap-2.5 animate-in fade-in">
                  <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-500" />
                  <span>{transferMessage}</span>
                </div>
              )}

              {/* Footer Actions: Transfer to Investigator (for standard users & admin) and Delete & Close */}
              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
                  {(user?.role === 'UTILISATEUR_STANDARD' || user?.role === 'ADMINISTRATEUR') && (
                    <button
                      onClick={() => handleTransferToInvestigator(selectedHistoryItem)}
                      disabled={transferringId === selectedHistoryItem.id || isTransferred}
                      className={`w-full sm:w-auto px-5 py-2.5 font-bold text-xs rounded-xl shadow-md flex items-center justify-center gap-2 transition cursor-pointer ${
                        isTransferred
                          ? 'bg-emerald-600 text-white opacity-90 cursor-default'
                          : 'bg-rose-600 hover:bg-rose-700 text-white'
                      }`}
                    >
                      {transferringId === selectedHistoryItem.id ? (
                        <RefreshCw className="w-4 h-4 animate-spin" />
                      ) : isTransferred ? (
                        <CheckCircle2 className="w-4 h-4" />
                      ) : (
                        <Send className="w-4 h-4" />
                      )}
                      <span>
                        {isTransferred
                          ? (lang === 'fr' ? "✓ Transféré à l'Enquêteur" : "✓ Transferred to Investigator")
                          : (lang === 'fr' ? "Transférer à l'Enquêteur" : "Transfer to Investigator")}
                      </span>
                    </button>
                  )}

                  <button
                    onClick={() => {
                      setItemToDelete(selectedHistoryItem);
                      setSelectedHistoryItem(null);
                    }}
                    className="w-full sm:w-auto px-4 py-2.5 bg-rose-500/10 hover:bg-rose-500 hover:text-white text-rose-500 font-bold text-xs rounded-xl border border-rose-500/30 flex items-center justify-center gap-2 transition cursor-pointer"
                  >
                    <Trash2 className="w-4 h-4" />
                    <span>{lang === 'fr' ? "Supprimer cette analyse" : "Delete this scan"}</span>
                  </button>
                </div>

                <button
                  onClick={() => { setSelectedHistoryItem(null); setTransferMessage(''); }}
                  className="w-full sm:w-auto px-6 py-2.5 bg-sky-500 hover:bg-sky-600 text-white font-bold text-xs rounded-xl shadow-md transition cursor-pointer"
                >
                  {lang === 'fr' ? 'Fermer la Fiche' : 'Close Report'}
                </button>
              </div>

            </div>
          </div>
        );
      })()}

      {/* Clear All History Confirmation Modal */}
      {showClearConfirm && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#161b27] border-2 border-rose-500/50 rounded-3xl p-6 sm:p-8 max-w-md w-full shadow-2xl space-y-5 animate-in zoom-in-95 duration-150 text-center">
            <div className="w-14 h-14 bg-rose-500/10 text-rose-500 rounded-full flex items-center justify-center mx-auto border border-rose-500/30">
              <Trash2 className="w-7 h-7" />
            </div>

            <div className="space-y-2">
              <h3 className="text-xl font-black text-slate-900 dark:text-white font-sans">
                {lang === 'fr' ? "Vider tout l'historique ?" : 'Clear all history?'}
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                {lang === 'fr' 
                  ? "Voulez-vous supprimer définitivement tous les enregistrements de votre historique d'analyse ?" 
                  : "Are you sure you want to permanently delete all scan records from your analysis history?"}
              </p>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="flex-1 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-bold text-xs rounded-2xl transition cursor-pointer"
              >
                {lang === 'fr' ? 'Annuler' : 'Cancel'}
              </button>

              <button
                onClick={handleClearAllHistory}
                disabled={isClearingAll}
                className="flex-1 py-3 bg-rose-600 hover:bg-rose-700 text-white font-extrabold text-xs rounded-2xl shadow-lg shadow-rose-600/30 transition cursor-pointer flex items-center justify-center gap-2"
              >
                {isClearingAll && <RefreshCw className="w-4 h-4 animate-spin" />}
                <span>{lang === 'fr' ? 'Tout Supprimer' : 'Delete All'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
