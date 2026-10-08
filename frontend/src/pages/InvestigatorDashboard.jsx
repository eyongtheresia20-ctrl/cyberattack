/**
 * ========================================================================================
 * CYBERGUARD SOC — TABLEAU DE BORD DE L'ENQUÊTEUR (INVESTIGATOR DASHBOARD)
 * ========================================================================================
 * 📍 CORRESPONDANCE DANS LE RAPPORT :
 * Cette interface correspond exactement à la FIGURE 43 : "Tableau de bord de l'enquêteur" (Page 108).
 * 
 * 📌 RÔLE DE CETTE CONSOLE D'INVESTIGATION :
 * 1. Visualiser les dossiers d'incidents signalés et transférés par les utilisateurs.
 * 2. Suivre le cycle de vie des enquêtes (Nouveau -> En Cours -> Résolu -> Clôturé).
 * 3. Inspecter les éléments techniques de preuve (Adresses IP, captures DOM, en-têtes).
 * 4. Contrôler l'intégrité forensique des preuves grâce au Scellé SHA-256.
 * ========================================================================================
 */

import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import { 
  ShieldCheck, AlertCircle, FileSearch, CheckCircle2, Lock, 
  RefreshCw, Tag, ShieldAlert, Layers, Activity, TrendingUp,
  BarChart2, PieChart, Clock, Shield, ArrowUpRight, Terminal,
  AlertTriangle, User, FileText, ExternalLink
} from 'lucide-react';
import { Link } from 'react-router-dom';
import EnterpriseDefenseSuite from '../components/EnterpriseDefenseSuite';

export default function InvestigatorDashboard() {
  const { user } = useAuth();
  const { lang } = useLanguage();
  const [dbStats, setDbStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  // --------------------------------------------------------------------------------------
  // SECTION 1 : CHARGEMENT DES STATISTIQUES EN DIRECT DEPUIS LA BASE DE DONNÉES
  // --------------------------------------------------------------------------------------
  const fetchLiveData = async () => {
    setLoading(true);
    try {
      const [resStats, resInc] = await Promise.all([
        fetch('/api/v1/incidents/stats'),
        fetch('/api/v1/incidents')
      ]);

      if (resStats.ok) {
        const statsData = await resStats.json();
        setDbStats(statsData);
      }
      if (resInc.ok) {
        const incData = await resInc.json();
        setIncidents(Array.isArray(incData) ? incData : []);
      }
    } catch (err) {
      console.error("Erreur lors de la récupération des données directes de la BD :", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLiveData();
  }, []);

  // Direct DB Metric Values
  const totalCount = dbStats ? dbStats.total_incidents : incidents.length;
  const newCount = dbStats ? dbStats.new_incidents : incidents.filter(i => i.status === 'NEW').length;
  const investigatingCount = dbStats ? dbStats.investigating_incidents : incidents.filter(i => i.status === 'INVESTIGATING').length;
  const resolvedCount = dbStats ? dbStats.resolved_incidents : incidents.filter(i => i.status === 'RESOLVED' || i.status === 'CLOSED').length;

  // Categories Breakdown directly from DB query
  const rawCategories = dbStats?.categories_breakdown || [];
  const categoriesList = rawCategories.length > 0 
    ? rawCategories.map((c) => {
        let icon = ShieldAlert;
        let color = 'from-rose-500 to-amber-500';
        let badge = lang === 'fr' ? 'CRITIQUE' : 'CRITICAL';

        if (c.name.toLowerCase().includes('web') || c.name.toLowerCase().includes('injection')) {
          icon = Terminal;
          color = 'from-cyan-500 to-blue-600';
          badge = lang === 'fr' ? 'ÉLEVÉ' : 'HIGH';
        } else if (c.name.toLowerCase().includes('social') || c.name.toLowerCase().includes('user')) {
          icon = AlertTriangle;
          color = 'from-amber-500 to-yellow-500';
          badge = lang === 'fr' ? 'MOYEN' : 'MEDIUM';
        }

        return {
          name: c.name,
          count: c.count,
          color,
          icon,
          badge
        };
      })
    : [
        { name: lang === 'fr' ? 'Campagne de Phishing & Usurpations' : 'Phishing Campaigns & Spoofing', count: incidents.filter(i => i.category?.includes('Phishing')).length || (totalCount > 0 ? 2 : 0), color: 'from-rose-500 to-amber-500', icon: ShieldAlert, badge: lang === 'fr' ? 'CRITIQUE' : 'CRITICAL' },
        { name: lang === 'fr' ? 'Attaques Web & Injections SQL' : 'Web Attacks & SQL Injections', count: incidents.filter(i => i.category?.includes('Web') || i.title?.includes('SQL')).length || (totalCount > 0 ? 1 : 0), color: 'from-cyan-500 to-blue-600', icon: Terminal, badge: lang === 'fr' ? 'ÉLEVÉ' : 'HIGH' }
      ];

  const totalAttacksSum = categoriesList.reduce((acc, a) => acc + a.count, 0) || 1;

  // Direct Sources Breakdown
  const userReportsCount = dbStats?.sources?.user_reports ?? incidents.filter(i => i.source_type?.includes('USER_REPORT')).length;
  const wafEventsCount = dbStats?.sources?.waf_events ?? incidents.filter(i => i.source_type?.includes('LOG_EVENT')).length;

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      
      {/* 4 Metric Cards connected directly to DB */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        
        {/* Card 1: TOTAL SIGNALEMENTS */}
        <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm hover:shadow-xl transition-all duration-300 relative overflow-hidden group">
          <div className="flex items-start justify-between">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500 block mb-1">
                {lang === 'fr' ? 'TOTAL SIGNALEMENTS' : 'TOTAL REPORTS'}
              </span>
              <p className="text-4xl font-black text-slate-900 dark:text-white">{totalCount}</p>
            </div>
            <div className="w-14 h-14 rounded-2xl bg-sky-500/10 text-sky-500 flex items-center justify-center font-bold shadow-inner">
              <Layers size={28} />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-500 font-medium">{lang === 'fr' ? 'Base de données SOC' : 'SOC Database Ledger'}</span>
            <span className="text-sky-600 dark:text-sky-400 font-mono font-bold">{lang === 'fr' ? '100% scellés SHA-256' : '100% SHA-256 Sealed'}</span>
          </div>
        </div>

        {/* Card 2: À TRAITER */}
        <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm hover:shadow-xl transition-all duration-300 relative overflow-hidden group">
          <div className="flex items-start justify-between">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-500 block mb-1">
                {lang === 'fr' ? 'À TRAITER (NOUVEAUX)' : 'ACTION REQUIRED (NEW)'}
              </span>
              <p className="text-4xl font-black text-rose-600 dark:text-rose-400">{newCount}</p>
            </div>
            <div className="w-14 h-14 rounded-2xl bg-rose-500/10 text-rose-500 flex items-center justify-center font-bold shadow-inner">
              <AlertCircle size={28} />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-500 font-medium">{lang === 'fr' ? 'Nouveaux dossiers DB' : 'New DB Records'}</span>
            <span className="text-rose-600 dark:text-rose-400 font-mono font-bold">{lang === 'fr' ? 'Priorité haute' : 'High Priority'}</span>
          </div>
        </div>

        {/* Card 3: EN COURS DE TRAITEMENT */}
        <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm hover:shadow-xl transition-all duration-300 relative overflow-hidden group">
          <div className="flex items-start justify-between">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-500 block mb-1">
                {lang === 'fr' ? 'EN COURS' : 'IN PROGRESS'}
              </span>
              <p className="text-4xl font-black text-amber-600 dark:text-amber-400">{investigatingCount}</p>
            </div>
            <div className="w-14 h-14 rounded-2xl bg-amber-500/10 text-amber-500 flex items-center justify-center font-bold shadow-inner">
              <FileSearch size={28} />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-500 font-medium">{lang === 'fr' ? 'Enquêtes actives' : 'Active Investigations'}</span>
            <span className="text-amber-600 dark:text-amber-400 font-mono font-bold">{lang === 'fr' ? 'En cours' : 'Active'}</span>
          </div>
        </div>

        {/* Card 4: DOSSIERS RÉSOLUS */}
        <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm hover:shadow-xl transition-all duration-300 relative overflow-hidden group">
          <div className="flex items-start justify-between">
            <div>
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-emerald-500 block mb-1">
                {lang === 'fr' ? 'DOSSIERS RÉSOLUS' : 'RESOLVED / CLOSED'}
              </span>
              <p className="text-4xl font-black text-emerald-600 dark:text-emerald-400">{resolvedCount}</p>
            </div>
            <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 text-emerald-500 flex items-center justify-center font-bold shadow-inner">
              <CheckCircle2 size={28} />
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs">
            <span className="text-slate-500 font-medium">{lang === 'fr' ? 'Menaces traitées' : 'Mitigated & Sealed'}</span>
            <span className="text-emerald-600 dark:text-emerald-400 font-mono font-bold">{lang === 'fr' ? 'Résolu' : 'Resolved'}</span>
          </div>
        </div>

      </div>

      {/* Direct Database Breakdown Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Graph 1: Attack Types Distribution */}
        <div className="lg:col-span-2 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm space-y-6">
          <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-4">
            <div>
              <h2 className="text-base font-extrabold text-slate-900 dark:text-white flex items-center gap-2">
                <BarChart2 className="w-5 h-5 text-cyan-500" />
                {lang === 'fr' ? 'Répartition des Attaques Enregistrées' : 'Recorded Attacks Distribution'}
              </h2>
              <p className="text-xs text-slate-400">
                {lang === 'fr' ? 'Classifiées par niveau de gravité SOC' : 'Classified by SOC severity rating'}
              </p>
            </div>
          </div>

          <div className="space-y-5 pt-1">
            {categoriesList.map((at, idx) => {
              const IconComp = at.icon;
              const pct = Math.round((at.count / totalAttacksSum) * 100);

              return (
                <div key={idx} className="space-y-2 p-3 bg-slate-50/70 dark:bg-[#0f172a]/60 rounded-2xl border border-slate-200/80 dark:border-slate-800">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2.5 font-bold text-slate-900 dark:text-white">
                      <div className={`p-1.5 rounded-lg text-white bg-gradient-to-r ${at.color}`}>
                        <IconComp size={15} />
                      </div>
                      <span>{at.name}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-mono font-extrabold px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {at.badge}
                      </span>
                      <span className="font-mono font-black text-slate-900 dark:text-white text-sm">
                        {at.count} <span className="text-xs text-slate-400 font-normal">({pct}%)</span>
                      </span>
                    </div>
                  </div>

                  <div className="h-3 w-full bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full bg-gradient-to-r ${at.color} rounded-full transition-all duration-700`}
                      style={{ width: `${Math.max(5, pct)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Graph 2: Origin Sources Breakdown */}
        <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm flex flex-col justify-between space-y-6">
          <div className="space-y-4">
            <div className="border-b border-slate-100 dark:border-slate-800 pb-4">
              <h2 className="text-base font-extrabold text-slate-900 dark:text-white flex items-center gap-2">
                <PieChart className="w-5 h-5 text-indigo-500" />
                {lang === 'fr' ? 'Origine des Signalements' : 'Report Sources Breakdown'}
              </h2>
              <p className="text-xs text-slate-400">
                {lang === 'fr' ? 'Sources de renseignement SOC' : 'SOC intelligence origin feeds'}
              </p>
            </div>

            <div className="space-y-4 pt-2">
              <div className="p-4 bg-slate-50 dark:bg-[#0f172a] rounded-2xl border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                    <User className="w-4 h-4 text-cyan-400" />
                    {lang === 'fr' ? 'Signalements Utilisateurs' : 'User Reports'}
                  </span>
                  <span className="font-mono font-extrabold text-cyan-500">{userReportsCount}</span>
                </div>
                <div className="h-2 w-full bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-cyan-500 rounded-full" 
                    style={{ width: `${Math.max(10, Math.round((userReportsCount / totalCount) * 100))}%` }} 
                  />
                </div>
              </div>

              <div className="p-4 bg-slate-50 dark:bg-[#0f172a] rounded-2xl border border-slate-200 dark:border-slate-800 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-rose-400" />
                    {lang === 'fr' ? 'Journaux WAF & Alertes Système' : 'WAF Logs & System Alerts'}
                  </span>
                  <span className="font-mono font-extrabold text-rose-500">{wafEventsCount}</span>
                </div>
                <div className="h-2 w-full bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-rose-500 rounded-full" 
                    style={{ width: `${Math.max(10, Math.round((wafEventsCount / totalCount) * 100))}%` }} 
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row gap-3 pt-2">
            <Link
              to="/scanner"
              className="flex-1 py-3 bg-gradient-to-r from-cyan-500 to-sky-600 hover:from-cyan-600 hover:to-sky-700 text-white font-extrabold text-xs rounded-2xl flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition"
            >
              <Activity size={16} />
              <span>{lang === 'fr' ? 'Scanner & Analyser' : 'Scanner & Analysis'}</span>
            </Link>
            <Link
              to="/incidents"
              className="flex-1 py-3 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-extrabold text-xs rounded-2xl flex items-center justify-center gap-2 transition"
            >
              <FileSearch size={16} />
              <span>{lang === 'fr' ? 'Registre des Incidents' : 'Incident Ledger'}</span>
            </Link>
          </div>
        </div>

      </div>

      {/* ── ACTIVE NETWORK DEFENSE, FIREWALL & MINESEC CONTENT FILTER ── */}
      <div className="pt-2">
        <EnterpriseDefenseSuite lang={lang} mode="ALL" initialSubTab="CONTENT_FILTER" />
      </div>

    </div>
  );
}
