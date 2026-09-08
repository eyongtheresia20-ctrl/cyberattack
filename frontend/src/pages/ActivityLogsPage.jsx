import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { Activity, Clock, Search, Shield, RefreshCw, Filter, User } from 'lucide-react';

export default function ActivityLogsPage() {
  const { token } = useAuth();
  const [activityLogs, setActivityLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState('ALL');

  const fetchActivityLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/users/activity-logs', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
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
  }, []);

  const filteredLogs = activityLogs.filter(log => {
    const matchesSearch = 
      log.actor.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (log.target && log.target.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (log.action && log.action.toLowerCase().includes(searchQuery.toLowerCase()));

    if (actionFilter === 'SCAN') return matchesSearch && log.type === 'SCAN_RESEARCH';
    if (actionFilter === 'AUDIT') return matchesSearch && log.type === 'AUDIT';
    return matchesSearch;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 dark:border-sky-900/40 pb-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black text-slate-900 dark:text-white tracking-tight flex items-center gap-2.5">
            <Activity className="w-7 h-7 text-sky-500" />
            Journal des Sessions & Activités
          </h1>
          <p className="text-slate-500 dark:text-slate-400 text-xs sm:text-sm mt-1">
            Suivi en temps réel des connexions utilisateurs, des heures d'accès et des actions d'analyse effectuées.
          </p>
        </div>

        <button
          onClick={fetchActivityLogs}
          className="p-2.5 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-2xl text-slate-600 dark:text-slate-300 hover:border-sky-500 transition cursor-pointer shadow-sm flex items-center gap-2 text-xs font-bold shrink-0"
        >
          <RefreshCw size={14} className={loading ? "animate-spin text-sky-500" : ""} />
          Actualiser le Journal
        </button>
      </div>

      {/* Search and Filters */}
      <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Rechercher par utilisateur, action, cible..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex items-center gap-2 text-xs">
            <Filter size={14} className="text-sky-500" />
            <span className="text-slate-500 font-medium">Filtrer par type :</span>
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white rounded-xl px-3 py-1.5 text-xs font-semibold focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">Toutes les activités</option>
              <option value="SCAN">Analyses & Recherches IA</option>
              <option value="AUDIT">Connexions & Audits Système</option>
            </select>
          </div>
        </div>

        {/* Activity Table */}
        {loading ? (
          <div className="py-12 text-center text-slate-500 text-xs flex items-center justify-center gap-2">
            <RefreshCw className="animate-spin text-sky-500" size={16} /> Chargement du journal des activités...
          </div>
        ) : (
          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800/80 rounded-2xl">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
              <thead className="bg-slate-50 dark:bg-[#0f172a] text-slate-500 dark:text-slate-400 uppercase font-bold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="p-3.5">Horodatage / Heure de Connexion</th>
                  <th className="p-3.5">Utilisateur (Acteur)</th>
                  <th className="p-3.5">Action Effectuée</th>
                  <th className="p-3.5">Cible / Recherche</th>
                  <th className="p-3.5">Détails SOC</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/30 transition">
                    <td className="p-3.5 font-mono text-[11px] text-slate-500 dark:text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <Clock size={12} className="text-sky-500 shrink-0" />
                        {log.timestamp ? new Date(log.timestamp).toLocaleString('fr-FR') : 'Connexion récente'}
                      </span>
                    </td>
                    <td className="p-3.5 font-bold text-slate-900 dark:text-white">
                      <span className="flex items-center gap-1.5">
                        <User size={13} className="text-sky-400 shrink-0" />
                        {log.actor}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <span className={`px-2.5 py-0.5 rounded-full font-mono font-bold text-[10px] ${
                        log.type === 'SCAN_RESEARCH' ? 'bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20' : 'bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20'
                      }`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="p-3.5 font-mono text-xs max-w-xs truncate text-slate-800 dark:text-slate-200" title={log.target}>
                      {log.target || 'N/A'}
                    </td>
                    <td className="p-3.5 text-xs text-slate-500 dark:text-slate-400">
                      {log.details}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

    </div>
  );
}
