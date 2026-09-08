import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  History, Search, Pin, Eye, Trash2, X, AlertTriangle, 
  CheckCircle2, Cpu, BarChart2, ShieldCheck, MapPin, 
  Lock, Copy, Check, FileText, Send, Sparkles, Filter, RefreshCw, Terminal
} from 'lucide-react';

export default function HistoryPage() {
  const { user } = useAuth();

  // Hydrate history from cache immediately, then fetch fresh data from database
  const [scanHistory, setScanHistory] = useState(() => {
    try {
      const saved = localStorage.getItem('phishguard_cached_history');
      if (!saved) return [];
      const parsed = JSON.parse(saved);
      return parsed.map(r => {
        const det = typeof r.details === 'string' ? JSON.parse(r.details || '{}') : (r.details || {});
        const rawScore = r.riskScore ?? r.risk_score ?? det.risk_score ?? det.riskScore ?? 0;
        const score = typeof rawScore === 'number' ? rawScore : parseFloat(rawScore) || 0;
        const rawVerdict = (r.verdict || det.verdict || '').toUpperCase();
        const isThreat = score >= 50 || rawVerdict.includes('PHISH') || rawVerdict.includes('MALICIOUS') || rawVerdict.includes('MENACE') || rawVerdict.includes('SUSPICIOUS');
        return {
          ...r,
          id: r.id,
          analysis_code: r.analysis_code || det.analysis_code || `ANL-${r.id ? r.id.slice(0, 6).toUpperCase() : 'SCAN'}`,
          type: (r.type || r.scan_type || det.analysis_type || 'URL').toUpperCase(),
          target: r.target || r.target_content || det.target_url || det.text_content || '',
          riskScore: score,
          verdict: isThreat ? 'PHISHING / MALICIOUS' : 'LEGITIMATE / CLEAN'
        };
      });
    } catch (e) {
      return [];
    }
  });

  const [isLoading, setIsLoading] = useState(false);
  const [historySearchQuery, setHistorySearchQuery] = useState('');
  const [historyVerdictFilter, setHistoryVerdictFilter] = useState('ALL'); // 'ALL', 'THREATS', 'CLEAN'
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);
  const [itemToDelete, setItemToDelete] = useState(null);

  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);

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
          
          // Accurately parse riskScore from camelCase or snake_case or details
          const rawScore = r.riskScore ?? r.risk_score ?? det.risk_score ?? det.riskScore ?? 0;
          const score = typeof rawScore === 'number' ? rawScore : parseFloat(rawScore) || 0;
          
          // Accurately parse verdict from direct verdict or details or score threshold
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
            timestamp: r.timestamp || (r.created_at ? new Date(r.created_at).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })),
            fullDate: r.fullDate || (r.created_at ? new Date(r.created_at).toLocaleDateString('fr-FR', { day: 'numeric', month: 'short', year: 'numeric' }) : ''),
            details: det,
            integrity_hash: r.integrity_hash || det.integrity_hash
          };
        });

        setScanHistory(formatted);
        try {
          localStorage.setItem('phishguard_cached_history', JSON.stringify(formatted));
        } catch (e) {}
      }
    } catch (err) {
      console.log('Error loading history:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [user]);

  const handleDeleteItem = async () => {
    if (!itemToDelete) return;
    const id = itemToDelete.id;
    setItemToDelete(null);

    try {
      const token = localStorage.getItem('phishguard_token');
      const headers = token ? { Authorization: `Bearer ${token}` } : {};
      const res = await fetch(`/api/v1/analyze/history/${id}`, { method: 'DELETE', headers });
      if (res.ok) {
        setScanHistory((prev) => {
          const updated = prev.filter((item) => item.id !== id);
          try {
            localStorage.setItem('phishguard_cached_history', JSON.stringify(updated));
            if (updated.length === 0) {
              localStorage.removeItem('phishguard_latest_result');
              localStorage.removeItem('phishguard_cached_stats');
            }
          } catch (e) {}
          return updated;
        });
      }
    } catch (e) {
      console.log('Error deleting record:', e);
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
                Historique des Analyses & Renseignement IA
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Registre permanent de l'ensemble de vos analyses enregistrées en base de données.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-3.5 py-1.5 bg-sky-50 dark:bg-sky-950/40 text-sky-600 dark:text-sky-400 border border-sky-200 dark:border-sky-800/40 rounded-xl text-xs font-mono font-bold">
              {scanHistory.length} analyses au total
            </span>
          </div>
        </div>

        {/* Live Search & Segmented Filter Bar */}
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-slate-50 dark:bg-[#111622] p-3 rounded-2xl border border-slate-200 dark:border-slate-800">
          
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher par URL, code ANL, canal, statut..."
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
              Tous ({scanHistory.length})
            </button>

            <button
              onClick={() => setHistoryVerdictFilter('THREATS')}
              className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                historyVerdictFilter === 'THREATS'
                  ? 'bg-rose-600 text-white border-rose-600 shadow-sm shadow-rose-600/30'
                  : 'bg-white dark:bg-[#161b27] text-rose-600 dark:text-rose-400 border-slate-200 dark:border-slate-700'
              }`}
            >
              🚨 Menaces ({totalThreats})
            </button>

            <button
              onClick={() => setHistoryVerdictFilter('CLEAN')}
              className={`px-3 py-1.5 rounded-xl border transition cursor-pointer text-[11px] ${
                historyVerdictFilter === 'CLEAN'
                  ? 'bg-emerald-600 text-white border-emerald-600 shadow-sm shadow-emerald-600/30'
                  : 'bg-white dark:bg-[#161b27] text-emerald-600 dark:text-emerald-400 border-slate-200 dark:border-slate-700'
              }`}
            >
              ✅ Légitimes ({totalClean})
            </button>
          </div>

        </div>

        {/* History Records Table */}
        {sortedScanHistory.length === 0 ? (
          <div className="py-16 text-center text-slate-400 text-xs font-medium space-y-2">
            <p className="text-sm font-bold text-slate-600 dark:text-slate-300">Aucun résultat trouvé dans l'historique.</p>
            <p className="text-slate-500 text-[11px]">Essayez de modifier votre recherche ou effectuez un nouveau scan sur le tableau de bord.</p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-2xl border border-slate-200 dark:border-slate-800">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-200 font-sans">
              <thead className="bg-slate-50 dark:bg-[#111622] text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="py-3 px-3 w-10 text-center">📌</th>
                  <th className="py-3 px-3">Date / Heure</th>
                  <th className="py-3 px-3">Canal</th>
                  <th className="py-3 px-3">Cible Analysée</th>
                  <th className="py-3 px-3">Verdict IA</th>
                  <th className="py-3 px-3">Score</th>
                  <th className="py-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80 font-mono text-xs">
                {sortedScanHistory.map((item) => {
                  const isPinned = pinnedIds.includes(item.id);
                  const isThreat = item.riskScore >= 50 || item.verdict?.includes('PHISHING') || item.verdict?.includes('MALICIOUS');

                  return (
                    <tr
                      key={item.id}
                      onClick={() => setSelectedHistoryItem(item)}
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
                          title={isPinned ? 'Désépingler' : 'Épingler en haut'}
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
                        {isPinned && <span className="mr-1.5 text-amber-500 font-bold">📌</span>}
                        {item.target}
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
                          {item.verdict}
                        </span>
                      </td>

                      <td className="py-3.5 px-3 font-extrabold text-slate-900 dark:text-white">
                        {item.riskScore}%
                      </td>

                      <td className="py-3.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setSelectedHistoryItem(item)}
                            className="px-2.5 py-1 bg-sky-500/10 hover:bg-sky-500/20 text-sky-600 dark:text-sky-400 font-bold rounded-lg text-[11px] border border-sky-500/30 transition cursor-pointer"
                          >
                            Voir
                          </button>
                          <button
                            onClick={() => setItemToDelete(item)}
                            className="p-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 rounded-lg border border-rose-500/30 transition cursor-pointer"
                            title="Supprimer définitivement"
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
                Confirmer la suppression ?
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 font-sans leading-relaxed">
                Voulez-vous supprimer définitivement cette analyse de votre historique et de la base de données ?
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
                Annuler
              </button>

              <button
                onClick={handleDeleteItem}
                className="flex-1 py-3 bg-rose-600 hover:bg-rose-700 text-white font-extrabold text-xs rounded-2xl shadow-lg shadow-rose-600/30 transition cursor-pointer"
              >
                Confirmer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Detailed Modal view for selected history record */}
      {selectedHistoryItem && (() => {
        const itemDetails = selectedHistoryItem.details || selectedHistoryItem;
        const isThreat = selectedHistoryItem.riskScore >= 50 || selectedHistoryItem.verdict?.includes('PHISHING');
        const features = itemDetails?.features || {};
        const models = itemDetails?.model_comparisons || [];
        const geoip = itemDetails?.geoip_info;
        const vt = itemDetails?.virustotal;
        const gsb = itemDetails?.google_safebrowsing;
        const advice = itemDetails?.defensive_advice || [];

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
                    <h3 className="text-lg font-black text-slate-900 dark:text-white">Fiche Détaillée d'Analyse (Registre Base de Données)</h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">Horodatage : {selectedHistoryItem.timestamp} {selectedHistoryItem.fullDate}</p>
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
                    <span className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-75">Classification IA</span>
                    <p className="text-xl font-black">{selectedHistoryItem.verdict}</p>
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
                <label className="text-[10px] uppercase font-mono font-bold text-slate-400">Cible Analysée ({selectedHistoryItem.type})</label>
                <div className="p-4 bg-slate-50 dark:bg-[#111622] rounded-2xl border border-slate-200 dark:border-slate-800 text-xs font-mono break-all text-slate-900 dark:text-slate-100 shadow-inner font-bold flex items-center justify-between gap-3">
                  <span>{selectedHistoryItem.target}</span>
                  <button
                    onClick={() => copyToClipboard(selectedHistoryItem.target, 'url')}
                    className="p-1.5 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:text-sky-500 text-xs shrink-0 cursor-pointer"
                    title="Copier"
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
                    Rapport de Sécurité Complet — Tests Exécutés
                  </h4>
                </div>
                <div className="flex-1 h-px bg-slate-200 dark:bg-slate-800" />
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-md bg-indigo-500/10 text-indigo-500 border border-indigo-500/20 shrink-0">
                  {(models.length > 0 ? 1 : 0) + (Object.keys(features).length > 0 ? 1 : 0) + 2 + (geoip ? 1 : 0)} Blocs
                </span>
              </div>

              {/* ══ TEST BLOCK 1 — ML ENSEMBLE (3 MODELS) ══ */}
              {models.length > 0 && (
                <div className="rounded-2xl border border-slate-200 dark:border-slate-800 overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-3 bg-gradient-to-r from-indigo-50 to-slate-50 dark:from-indigo-950/30 dark:to-slate-900/40 border-b border-slate-200 dark:border-slate-800">
                    <div className="flex items-center gap-2">
                      <div className="w-6 h-6 rounded-lg bg-indigo-500 flex items-center justify-center text-white text-[10px] font-black shrink-0">1</div>
                      <Cpu className="w-4 h-4 text-indigo-500" />
                      <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">Moteur IA — Ensemble Machine Learning (3 Modèles)</span>
                    </div>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">✓ 3/3 Actifs</span>
                  </div>

                  <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-3">
                    {models.map((m, idx) => {
                      const mProb = typeof m.phishing_prob === 'number' ? m.phishing_prob : parseFloat(m.phishing_prob) || 0;
                      const isRisky = mProb >= 50;
                      return (
                        <div key={idx} className="bg-slate-50 dark:bg-[#111622] border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 space-y-3">
                          <div className="flex items-start justify-between gap-2">
                            <div>
                              <span className="text-[10px] font-mono text-slate-400 block">Modèle #{idx + 1}</span>
                              <span className="text-xs font-extrabold text-slate-900 dark:text-white leading-tight">{m.name}</span>
                            </div>
                            <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold shrink-0 ${isRisky ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'}`}>
                              {isRisky ? '⚠ MENACE' : '✓ SÛR'}
                            </span>
                          </div>
                          <div className="space-y-1">
                            <div className="flex justify-between text-[10px] font-mono">
                              <span className="text-slate-400">Probabilité de phishing</span>
                              <span className={`font-black ${isRisky ? 'text-rose-500' : 'text-emerald-500'}`}>{mProb}%</span>
                            </div>
                            <div className="h-2 w-full bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                              <div className={`h-full rounded-full transition-all duration-700 ${isRisky ? 'bg-gradient-to-r from-amber-400 to-rose-500' : 'bg-gradient-to-r from-teal-400 to-emerald-500'}`} style={{ width: `${Math.min(100, Math.max(3, mProb))}%` }} />
                            </div>
                          </div>
                          <div className="flex justify-between text-[10px] font-mono text-slate-500">
                            <span>Précision du modèle</span>
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
                      <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">Moteur Heuristique — 17 Caractéristiques URL</span>
                    </div>
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${(itemDetails?.rule_triggers?.length || 0) > 0 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>
                      {(itemDetails?.rule_triggers?.length || 0)} Règle(s) Déclenchée(s)
                    </span>
                  </div>
                  <div className="p-4 space-y-4">
                    <div>
                      <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">Tests Binaires (Passe / Échec)</p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                        {[
                          { label: 'Chiffrement HTTPS / SSL', desc: 'Protocole de connexion sécurisé', pass: !!features.is_https, value: features.is_https ? 'HTTPS Actif' : 'HTTP Non Chiffré' },
                          { label: 'Hôte IP Direct', desc: "IP brute au lieu d'un domaine", pass: !features.has_ip, value: features.has_ip ? 'IP Détectée — Risque' : 'Domaine Normal' },
                          { label: 'TLD Suspect', desc: 'Extension risquée (.xyz, .top, .tk...)', pass: !features.has_suspicious_tld, value: features.has_suspicious_tld ? 'TLD Dangereux' : 'TLD Standard' },
                          { label: 'Symbole @ Redirection', desc: "Trompe le navigateur sur l'hôte réel", pass: !(features.num_at > 0), value: features.num_at > 0 ? `${features.num_at} Symbole(s) @` : 'Aucun' },
                          { label: 'Sous-domaines Excessifs', desc: 'login.secure.paypal.xyz (2+ niveaux)', pass: (features.num_subdomains || 0) < 2, value: `${features.num_subdomains || 0} Niveau(x)` },
                          { label: 'Mots-clés Suspects', desc: 'login, verify, paypal, bank, claim...', pass: (features.keyword_count || 0) === 0, value: features.keyword_count > 0 ? `${features.keyword_count} Mot(s)` : 'Aucun' },
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
                      <p className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">Métriques Numériques Extraites (17 Features ML)</p>
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
                            {m.warn && <span className="text-[8px] text-amber-500 font-bold">↑ Élevé</span>}
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
                  <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">Threat Intelligence — Bases de Renseignement Mondiales</span>
                </div>
                <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className={`p-4 rounded-xl border space-y-3 ${(vt?.positives || 0) > 0 ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xl">🔬</span>
                        <div><p className="text-xs font-black text-slate-800 dark:text-white">VirusTotal</p><p className="text-[10px] text-slate-400">90 moteurs antivirus mondiaux</p></div>
                      </div>
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${(vt?.positives || 0) > 0 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>{(vt?.positives || 0) > 0 ? '⚠ DÉTECTÉ' : '✓ PROPRE'}</span>
                    </div>
                    <div className="space-y-1 text-[10px] font-mono">
                      <div className="flex justify-between text-slate-500"><span>Détections</span><span className={`font-black ${(vt?.positives || 0) > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{vt?.positives || 0} / {vt?.total_engines || 90}</span></div>
                      <div className="flex justify-between text-slate-400"><span>Réputation</span><span className="font-bold">{vt?.reputation_score ?? 'N/A'}</span></div>
                    </div>
                  </div>
                  <div className={`p-4 rounded-xl border space-y-3 ${gsb?.is_flagged ? 'bg-rose-50 dark:bg-rose-950/10 border-rose-200 dark:border-rose-800/40' : 'bg-emerald-50 dark:bg-emerald-950/10 border-emerald-200 dark:border-emerald-800/40'}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xl">🛡️</span>
                        <div><p className="text-xs font-black text-slate-800 dark:text-white">Google Safe Browsing</p><p className="text-[10px] text-slate-400">Base mondiale malware & phishing</p></div>
                      </div>
                      <span className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold border ${gsb?.is_flagged ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'}`}>{gsb?.is_flagged ? '⚠ SIGNALÉ' : '✓ LISTE BLANCHE'}</span>
                    </div>
                    <div className="space-y-1 text-[10px] font-mono">
                      <div className="flex justify-between text-slate-500"><span>Statut</span><span className={`font-black ${gsb?.is_flagged ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>{gsb?.is_flagged ? 'SIGNALÉ' : 'APPROUVÉ'}</span></div>
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
                    <span className="text-xs font-extrabold text-slate-800 dark:text-white font-mono uppercase tracking-wide">GeoIP & ASN — Localisation Réseau</span>
                  </div>
                  <div className="p-4">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono text-center">
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800"><span className="text-[9px] text-slate-400 block uppercase">Adresse IP</span><strong className="text-sky-500">{geoip.ip || 'N/A'}</strong></div>
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800"><span className="text-[9px] text-slate-400 block uppercase">Pays / Ville</span><strong>{geoip.country}, {geoip.city}</strong></div>
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800"><span className="text-[9px] text-slate-400 block uppercase">ASN</span><strong>{geoip.asn || 'N/A'}</strong></div>
                      <div className="p-2 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800"><span className="text-[9px] text-slate-400 block uppercase">VPN / Proxy</span><strong className={geoip.is_vpn_proxy ? 'text-rose-500' : 'text-emerald-500'}>{geoip.is_vpn_proxy ? '🔴 OUI' : '🟢 NON'}</strong></div>
                    </div>
                  </div>
                </div>
              )}

              {/* SHA-256 Checksum Signature */}
              {(selectedHistoryItem.integrity_hash || itemDetails?.integrity_hash) && (
                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase font-mono font-bold text-slate-400">Empreinte Cryptographique d'Intégrité SHA-256</label>
                  <div className="p-3 bg-slate-50 dark:bg-[#111622] rounded-2xl font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all font-bold border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
                    <span>{selectedHistoryItem.integrity_hash || itemDetails?.integrity_hash}</span>
                    <button
                      onClick={() => copyToClipboard(selectedHistoryItem.integrity_hash || itemDetails?.integrity_hash, 'hash')}
                      className="text-xs text-sky-500 hover:text-sky-600 font-bold shrink-0 cursor-pointer"
                    >
                      {copiedHash ? 'Copié !' : 'Copier'}
                    </button>
                  </div>
                </div>
              )}

              {/* Close Button */}
              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 flex justify-end">
                <button
                  onClick={() => setSelectedHistoryItem(null)}
                  className="px-6 py-2.5 bg-sky-500 hover:bg-sky-600 text-white font-bold text-xs rounded-xl shadow-md transition cursor-pointer"
                >
                  Fermer la Fiche
                </button>
              </div>

            </div>
          </div>
        );
      })()}

    </div>
  );
}
