import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { Activity, Clock, Search, Shield, RefreshCw, Filter, User, AlertTriangle, FileSearch, ShieldCheck } from 'lucide-react';

export default function ActivityLogsPage() {
  const { token } = useAuth();
  const { lang } = useLanguage();
  const [activityLogs, setActivityLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');

  const fetchActivityLogs = async () => {
    setLoading(true);
    try {
      const activeToken = token || localStorage.getItem('phishguard_token');
      const headers = activeToken ? { 'Authorization': `Bearer ${activeToken}` } : {};
      const res = await fetch('/api/v1/users/activity-logs', { headers });
      const data = await res.json();
      if (data.activities) {
        setActivityLogs(data.activities);
      }
    } catch (err) {
      console.error('Failed to fetch activity logs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchActivityLogs();
  }, [token]);

  const filteredLogs = activityLogs.filter(log => {
    const actorStr = log.actor ? log.actor.toLowerCase() : '';
    const targetStr = log.target ? log.target.toLowerCase() : '';
    const actionStr = log.action ? log.action.toLowerCase() : '';
    const detailsStr = log.details ? log.details.toLowerCase() : '';
    const query = searchQuery.toLowerCase().trim();

    const matchesSearch = !query ||
      actorStr.includes(query) ||
      targetStr.includes(query) ||
      actionStr.includes(query) ||
      detailsStr.includes(query);

    if (actionFilter === 'SCAN') return matchesSearch && (log.type === 'SCAN_RESEARCH' || log.action?.startsWith('SCAN'));
    if (actionFilter === 'AUDIT') return matchesSearch && (log.action === 'LOGIN' || log.action === 'REGISTER');
    if (actionFilter === 'INCIDENT') return matchesSearch && (log.type === 'INCIDENT_REPORT' || log.action === 'TRANSFERT_RAPPORT');
    if (actionFilter === 'AI') return matchesSearch && log.action === 'CHAT_IA';
    if (actionFilter === 'VERIFY') return matchesSearch && log.action === 'VERIF_INTEGRITE';
    if (actionFilter === 'ERROR') return matchesSearch && (log.type === 'SERVICE_ERROR' || log.action === 'SERVICE_PIPELINE_ERROR');
    return matchesSearch;
  });

  const formatLogDate = (timestamp) => {
    if (!timestamp) return lang === 'fr' ? 'Récemment' : 'Recently';
    let t = timestamp;
    if (typeof t === 'string' && !t.includes('Z') && !t.includes('+')) {
      t += 'Z';
    }
    const d = new Date(t);
    return isNaN(d.getTime()) ? timestamp : d.toLocaleString(lang === 'fr' ? 'fr-FR' : 'en-US');
  };

  const getActionBadge = (type, action) => {
    if (type === 'SERVICE_ERROR' || action === 'SERVICE_PIPELINE_ERROR') {
      return (
        <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30 flex items-center gap-1.5 animate-pulse">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
          {lang === 'fr' ? 'ERREUR SERVICE' : 'SERVICE ERROR'}
        </span>
      );
    }
    if (action === 'CHAT_IA') {
      return (
        <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-purple-500/15 text-purple-600 dark:text-purple-400 border border-purple-500/30 flex items-center gap-1">
          <Shield size={11} className="text-purple-500" />
          {lang === 'fr' ? 'ASSISTANT IA' : 'AI CHAT'}
        </span>
      );
    }
    if (action === 'VERIF_INTEGRITE') {
      return (
        <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-teal-500/15 text-teal-600 dark:text-teal-400 border border-teal-500/30 flex items-center gap-1">
          <ShieldCheck size={11} className="text-teal-500" />
          {lang === 'fr' ? 'INTÉGRITÉ SHA-256' : 'SHA-256 PROOF'}
        </span>
      );
    }
    if (type === 'INCIDENT_REPORT' || action === 'TRANSFERT_RAPPORT') {
      return (
        <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30 flex items-center gap-1">
          <FileSearch size={11} className="text-amber-500" />
          {lang === 'fr' ? 'TRANSFERT RAPPORT' : 'REPORT TRANSFER'}
        </span>
      );
    }
    if (type === 'SCAN_RESEARCH' || action?.startsWith('SCAN')) {
      return (
        <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20">
          {action}
        </span>
      );
    }
    if (action === 'LOGIN') {
      return (
        <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
          {lang === 'fr' ? 'CONNEXION' : 'LOGIN'}
        </span>
      );
    }
    if (action === 'REGISTER') {
      return (
        <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border border-cyan-500/20">
          {lang === 'fr' ? 'INSCRIPTION' : 'REGISTER'}
        </span>
      );
    }
    return (
      <span className="px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
        {action}
      </span>
    );
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-sky-900/40 pb-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-slate-900 dark:text-white tracking-tight flex items-center gap-2.5">
            <Activity className="w-7 h-7 text-sky-500" />
            {lang === 'fr' ? 'Journal des Sessions & Activités' : 'Sessions & Activity Audit Log'}
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-xs sm:text-sm mt-1">
            {lang === 'fr' 
              ? "Suivi en temps réel des actions des utilisateurs et enquêteurs (analyses, consultations IA, transferts de rapports, intégrité SHA-256)." 
              : "Real-time audit of user and investigator actions (threat scans, AI assistance, report transfers, SHA-256 integrity)."}
          </p>
        </div>

        <button
          onClick={fetchActivityLogs}
          className="p-2.5 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-2xl text-slate-600 dark:text-slate-300 hover:border-sky-500 transition cursor-pointer shadow-sm flex items-center gap-2 text-xs font-bold shrink-0"
        >
          <RefreshCw size={14} className={loading ? "animate-spin text-sky-500" : ""} />
          {lang === 'fr' ? 'Actualiser le Journal' : 'Refresh Audit Log'}
        </button>
      </div>

      {/* Search and Filters */}
      <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder={lang === 'fr' ? "Rechercher par utilisateur, action, cible..." : "Search by user, action, target..."}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex items-center gap-2 text-xs">
            <Filter size={14} className="text-sky-500" />
            <span className="text-slate-500 font-medium">{lang === 'fr' ? 'Filtrer par type :' : 'Filter by type:'}</span>
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white rounded-xl px-3 py-1.5 text-xs font-semibold focus:outline-none focus:border-sky-500 cursor-pointer"
            >
              <option value="ALL">{lang === 'fr' ? 'Toutes les activités' : 'All Activities'}</option>
              <option value="AUDIT">{lang === 'fr' ? 'Connexions & Accès' : 'Logins & Access'}</option>
              <option value="SCAN">{lang === 'fr' ? 'Analyses Menaces (URL / SMS)' : 'Threat Scans (URL / SMS)'}</option>
              <option value="INCIDENT">{lang === 'fr' ? 'Transferts de Rapports' : 'Report Transfers'}</option>
              <option value="AI">{lang === 'fr' ? 'Consultations IA' : 'AI Consultations'}</option>
              <option value="VERIFY">{lang === 'fr' ? 'Vérifications Intégrité (SHA-256)' : 'Integrity Checks (SHA-256)'}</option>
              <option value="ERROR">{lang === 'fr' ? '🚨 Erreurs Services & Diagnostics' : '🚨 Service Errors & Diagnostics'}</option>
            </select>
          </div>
        </div>

        {/* Activity Table */}
        {loading ? (
          <div className="py-12 text-center text-slate-500 text-xs flex items-center justify-center gap-2">
            <RefreshCw className="animate-spin text-sky-500" size={16} /> 
            {lang === 'fr' ? 'Chargement du journal des activités...' : 'Loading activity audit logs...'}
          </div>
        ) : filteredLogs.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs">
            {lang === 'fr' ? 'Aucun journal d’activité enregistré pour le moment.' : 'No activity records found matching filters.'}
          </div>
        ) : (
          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800/80 rounded-2xl">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
              <thead className="bg-slate-50 dark:bg-[#0f172a] text-slate-500 dark:text-slate-400 uppercase font-bold border-b border-slate-200 dark:border-slate-800 text-[10px] tracking-wider">
                <tr>
                  <th className="p-3.5">{lang === 'fr' ? 'Horodatage / Heure de Connexion' : 'Timestamp / Session Time'}</th>
                  <th className="p-3.5">{lang === 'fr' ? 'Utilisateur (Acteur)' : 'User (Actor)'}</th>
                  <th className="p-3.5">{lang === 'fr' ? 'Action Effectuée' : 'Action Performed'}</th>
                  <th className="p-3.5">{lang === 'fr' ? 'Cible / Recherche' : 'Target / Identifier'}</th>
                  <th className="p-3.5">{lang === 'fr' ? 'Détails SOC / Diagnostic' : 'SOC Details / Diagnostic'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredLogs.map((log) => {
                  const isError = log.type === 'SERVICE_ERROR' || log.action === 'SERVICE_PIPELINE_ERROR';
                  return (
                    <tr key={log.id} className={isError ? "bg-rose-500/5 hover:bg-rose-500/10 transition border-l-2 border-l-rose-500" : "hover:bg-slate-50/60 dark:hover:bg-slate-800/30 transition"}>
                      <td className="p-3.5 font-mono text-[11px] text-slate-500 dark:text-slate-400 whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <Clock size={12} className={isError ? "text-rose-500 shrink-0" : "text-sky-500 shrink-0"} />
                          {formatLogDate(log.timestamp)}
                        </span>
                      </td>
                      <td className="p-3.5 font-bold text-slate-900 dark:text-white">
                        <span className="flex items-center gap-1.5">
                          <User size={13} className={isError ? "text-rose-400 shrink-0" : "text-sky-400 shrink-0"} />
                          {log.actor}
                        </span>
                      </td>
                      <td className="p-3.5">
                        {getActionBadge(log.type, log.action)}
                      </td>
                      <td className="p-3.5 font-mono text-xs max-w-xs truncate text-slate-800 dark:text-slate-200 font-semibold" title={log.target}>
                        {log.target || '-'}
                      </td>
                      <td className="p-3.5 text-xs">
                        {isError ? (
                          <span className="text-rose-600 dark:text-rose-300 font-medium">
                            {log.details}
                          </span>
                        ) : (
                          <span className="text-slate-500 dark:text-slate-400">
                            {log.details}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
