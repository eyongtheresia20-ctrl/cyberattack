import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, History, ShieldAlert, FileSearch, CheckCircle2, Users, Globe, Bot, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Sidebar() {
  const { user } = useAuth();

  const stdItems = [
    { path: '/dashboard', label: 'Scanner & Tableau de Bord', icon: LayoutDashboard },
    { path: '/history', label: 'Historique des Analyses', icon: History },
  ];

  const investigatorItems = [
    { path: '/dashboard', label: 'Console d\'Enquête SOC', icon: LayoutDashboard },
    { path: '/scanner', label: 'Scanner de Menaces IA', icon: ShieldAlert },
    { path: '/history', label: 'Historique des Analyses', icon: History },
    { path: '/incidents', label: 'File d\'Incidents', icon: FileSearch },
    { path: '/verification', label: 'Vérification SHA-256', icon: CheckCircle2 },
    { path: '/site-monitoring', label: 'Surveillance Attaques', icon: Globe },
  ];

  const adminItems = [
    { path: '/dashboard', label: 'Gestion & Rôles Admin', icon: Users },
    { path: '/scanner', label: 'Scanner de Menaces IA', icon: ShieldAlert },
    { path: '/history', label: 'Historique des Analyses', icon: History },
    { path: '/site-monitoring', label: 'Moniteur d\'attaques', icon: Globe },
    { path: '/incidents', label: 'Registre des Preuves', icon: FileSearch },
  ];

  let navItems = stdItems;
  if (user?.role === 'ENQUETEUR') navItems = investigatorItems;
  if (user?.role === 'ADMINISTRATEUR') navItems = adminItems;

  return (
    <aside className="w-64 bg-white/80 dark:bg-[#0f172a]/80 backdrop-blur-md border-r border-slate-200 dark:border-sky-900/40 flex flex-col justify-between py-5 px-3 sticky top-16 h-[calc(100vh-4rem)] shadow-sm transition-colors duration-300">
      <div className="space-y-1.5">
        <div className="px-3 mb-4 flex items-center justify-between">
          <p className="text-[10px] uppercase font-mono tracking-widest text-slate-400 dark:text-slate-500 font-bold">
            NAVIGATION SOC
          </p>
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full badge-glass-cyan text-[9px] font-mono font-bold">
            <ShieldCheck className="w-3 h-3 text-cyan-400" />
            {user ? user.role.split('_')[0] : 'GUEST'}
          </span>
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path + item.label}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-3 rounded-2xl text-xs font-semibold transition-all group ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/20 to-blue-600/10 border-l-4 border-cyan-400 text-cyan-500 dark:text-cyan-400 shadow-md font-bold'
                    : 'text-slate-600 dark:text-slate-400 hover:text-cyan-500 dark:hover:text-cyan-300 hover:bg-slate-100 dark:hover:bg-[#1e293b]/60'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0 transition-transform group-hover:scale-110" />
              <span className="truncate">{item.label}</span>
            </NavLink>
          );
        })}
      </div>

      {/* System Status Footer Box */}
      <div className="p-3.5 bg-slate-50 dark:bg-[#1e293b]/70 border border-slate-200 dark:border-slate-800 rounded-2xl space-y-2">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-500 dark:text-slate-400 font-medium">Moteur IA</span>
          <span className="text-emerald-400 font-mono font-bold text-[10px] flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            Ensemble 98.4%
          </span>
        </div>
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-slate-500 dark:text-slate-400 font-medium">Serveur API</span>
          <span className="text-cyan-400 font-mono font-bold text-[10px]">FastAPI 8000</span>
        </div>
      </div>
    </aside>
  );
}
