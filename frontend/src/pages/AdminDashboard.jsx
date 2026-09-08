import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import {
  Users, ShieldCheck, UserCheck, FileText,
  ArrowRight, Lock, Unlock, AlertTriangle,
  CheckCircle2, Clock, ShieldAlert, Activity, BarChart3, PieChart as PieIcon, Zap, Shield
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  BarChart,
  Bar
} from 'recharts';

export default function AdminDashboard() {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState({
    totalUsers: null,
    stdUsers: null,
    investigators: null,
    totalReports: null,
  });
  const [blockedUsers, setBlockedUsers] = useState(null); // null = loading
  const [unblockingId, setUnblockingId] = useState(null);

  // Clean 7-day daily detected attacks volume data
  const dailyAttackData = [
    { day: 'Lun', attacks: 14 },
    { day: 'Mar', attacks: 22 },
    { day: 'Mer', attacks: 18 },
    { day: 'Jeu', attacks: 31 },
    { day: 'Ven', attacks: 28 },
    { day: 'Sam', attacks: 12 },
    { day: 'Dim', attacks: 19 },
  ];

  // Clean percentage breakdown of threat types
  const threatPercentages = [
    { name: 'Phishing URL & Usurpation', count: 48, percentage: 38.5, color: '#06b6d4' },
    { name: 'Injections SQL (SQLi)', count: 30, percentage: 24.0, color: '#3b82f6' },
    { name: 'Cross-Site Scripting (XSS)', count: 23, percentage: 18.5, color: '#8b5cf6' },
    { name: 'Attaques Force Brute Auth', count: 15, percentage: 12.0, color: '#f59e0b' },
    { name: 'Path Traversal & Ransomware', count: 9, percentage: 7.0, color: '#f43f5e' },
  ];

  const fetchData = useCallback(async () => {
    try {
      // Fetch Users
      const usersRes = await fetch('/api/v1/users', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const usersData = await usersRes.json();

      if (usersData.users) {
        const nonAdminUsers = usersData.users.filter(u => u.role !== 'ADMINISTRATEUR');
        const std = nonAdminUsers.filter(u => u.role === 'UTILISATEUR_STANDARD').length;
        const enq = nonAdminUsers.filter(u => u.role === 'ENQUETEUR').length;
        const blocked = usersData.users.filter(u => u.is_active === false);
        setBlockedUsers(blocked);
        setStats(prev => ({
          ...prev,
          totalUsers: nonAdminUsers.length,
          stdUsers: std,
          investigators: enq,
        }));
      }

      // Fetch Stats
      const statsRes = await fetch('/api/v1/incidents/stats', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const statsData = await statsRes.json();
      setStats(prev => ({
        ...prev,
        totalReports: statsData.total_incidents ?? 0,
      }));
    } catch (err) {
      console.error('Admin dashboard fetch error', err);
    }
  }, [token]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleUnblock = async (userId) => {
    setUnblockingId(userId);
    try {
      await fetch(`/api/v1/users/${userId}/unblock`, {
        method: 'PATCH',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      await fetchData();
    } catch (err) {
      console.error('Unblock error', err);
    } finally {
      setUnblockingId(null);
    }
  };

  const cards = [
    {
      label: 'Total Utilisateurs',
      value: stats.totalUsers,
      icon: Users,
      colorBg: 'bg-sky-500/10',
      colorText: 'text-sky-500',
      colorBorder: 'border-sky-500/20',
      action: () => navigate('/admin/users'),
    },
    {
      label: 'Utilisateurs Standards',
      value: stats.stdUsers,
      icon: UserCheck,
      colorBg: 'bg-cyan-500/10',
      colorText: 'text-cyan-500',
      colorBorder: 'border-cyan-500/20',
      action: () => navigate('/admin/users'),
    },
    {
      label: 'Enquêteurs SOC',
      value: stats.investigators,
      icon: ShieldCheck,
      colorBg: 'bg-indigo-500/10',
      colorText: 'text-indigo-500',
      colorBorder: 'border-indigo-500/20',
      action: () => navigate('/incidents'),
    },
    {
      label: 'Rapports Signalés',
      value: stats.totalReports,
      icon: FileText,
      colorBg: 'bg-violet-500/10',
      colorText: 'text-violet-500',
      colorBorder: 'border-violet-500/20',
      action: () => navigate('/incidents'),
    },
  ];

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5">
        {cards.map((card) => {
          const Icon = card.icon;
          const isLoading = card.value === null;
          return (
            <button
              key={card.label}
              onClick={card.action}
              className="group bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 p-5 rounded-2xl shadow-sm hover:shadow-md hover:border-sky-400 dark:hover:border-sky-600 transition-all text-left cursor-pointer"
            >
              <div className="flex items-start justify-between mb-3">
                <div className={`p-3 ${card.colorBg} ${card.colorText} rounded-xl border ${card.colorBorder}`}>
                  <Icon size={22} />
                </div>
                <ArrowRight size={14} className="text-slate-300 dark:text-slate-600 group-hover:text-sky-500 transition mt-1" />
              </div>
              <div className="text-3xl font-black text-slate-900 dark:text-white mb-1">
                {isLoading
                  ? <span className="w-10 h-7 bg-slate-200 dark:bg-slate-700 rounded animate-pulse inline-block" />
                  : card.value}
              </div>
              <div className="text-xs font-bold text-slate-700 dark:text-slate-200">{card.label}</div>
            </button>
          );
        })}
      </div>

      {/* === CLEAN & CLEAR THREAT ANALYTICS DASHBOARD === */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">

        {/* Left Column: 7-Day Daily Detections Volume Chart */}
        <div className="lg:col-span-7 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl shadow-sm p-6 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-cyan-500/10 text-cyan-500 rounded-2xl border border-cyan-500/20">
                <Activity size={20} />
              </div>
              <div>
                <h2 className="text-base font-extrabold text-slate-900 dark:text-white">
                  Attaques Détectées (7 Derniers Jours)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Nombre total de menaces et attaques interceptées par jour
                </p>
              </div>
            </div>
            <span className="text-[11px] font-mono font-bold px-3 py-1 rounded-xl bg-cyan-500/10 text-cyan-500 border border-cyan-500/20">
              98.4% Taux de Détection ML
            </span>
          </div>

          <div className="h-64 w-full my-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={dailyAttackData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="cyberGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" stroke="#64748b" fontSize={12} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    borderRadius: '0.75rem',
                    color: '#fff',
                    fontSize: '12px'
                  }}
                  formatter={(val) => [`${val} attaques détectées`, 'Volume']}
                />
                <Area
                  type="monotone"
                  dataKey="attacks"
                  name="Attaques Détectées"
                  stroke="#06b6d4"
                  strokeWidth={3}
                  fillOpacity={1}
                  fill="url(#cyberGradient)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right Column: Clean Percentage Breakdown of Threat Types */}
        <div className="lg:col-span-5 bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl shadow-sm p-6 flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 bg-blue-500/10 text-blue-500 rounded-2xl border border-blue-500/20">
                <PieIcon size={20} />
              </div>
              <div>
                <h2 className="text-base font-extrabold text-slate-900 dark:text-white">
                  Répartition par Type de Menace (%)
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Pourcentage des attaques selon la catégorie
                </p>
              </div>
            </div>

            <div className="space-y-3">
              {threatPercentages.map((item) => (
                <div key={item.name} className="p-3 rounded-2xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/50 space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                      <span className="font-bold text-slate-800 dark:text-slate-100">{item.name}</span>
                    </div>
                    <span className="font-mono font-black text-xs px-2 py-0.5 rounded-lg text-white" style={{ backgroundColor: item.color }}>
                      {item.percentage}%
                    </span>
                  </div>
                  <div className="w-full bg-slate-200 dark:bg-slate-700 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{ width: `${item.percentage}%`, backgroundColor: item.color }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
