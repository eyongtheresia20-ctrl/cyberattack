import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, History, ShieldAlert, FileSearch, CheckCircle2, Users } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Sidebar() {
  const { user } = useAuth();

  const stdItems = [
    { path: '/dashboard', label: 'Tableau de Bord', icon: LayoutDashboard },
    { path: '/history', label: 'Historique des Analyses', icon: History },
  ];

  const investigatorItems = [
    { path: '/dashboard', label: 'Tableau de Bord', icon: LayoutDashboard },
    { path: '/incidents', label: 'File d\'Incidents', icon: FileSearch },
    { path: '/verification', label: 'Vérification SHA-256', icon: CheckCircle2 },
    { path: '/site-monitoring', label: 'Surveillance Attaques', icon: ShieldAlert },
  ];

  const adminItems = [
    { path: '/dashboard', label: 'Tableau de Bord', icon: LayoutDashboard },
    { path: '/site-monitoring', label: 'Moniteur d\'attaques', icon: ShieldAlert },
    { path: '/incidents', label: 'Registre des Preuves', icon: FileSearch },
  ];

  let navItems = stdItems;
  if (user?.role === 'ENQUETEUR') navItems = investigatorItems;
  if (user?.role === 'ADMINISTRATEUR') navItems = adminItems;

  return (
    <aside className="w-64 bg-white dark:bg-[#161b27] border-r border-sky-100 dark:border-sky-900/60 flex flex-col justify-between py-4 px-3 sticky top-16 h-[calc(100vh-4rem)] shadow-sm transition-colors duration-300">
      <div className="space-y-1">
        <p className="px-3 text-[10px] uppercase font-mono tracking-widest text-slate-400 dark:text-slate-500 font-bold mb-3">
          {user ? `Rôle: ${user.role}` : 'Menu de Navigation'}
        </p>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path + item.label}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                  isActive
                    ? 'bg-sky-500 text-white shadow-md shadow-sky-500/20'
                    : 'text-slate-600 dark:text-slate-400 hover:text-sky-600 dark:hover:text-sky-400 hover:bg-sky-50 dark:hover:bg-sky-500/10'
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </div>
    </aside>
  );
}
