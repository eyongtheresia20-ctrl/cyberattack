import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, History, FileSearch, Users, ShieldCheck, Activity, Search, Sliders } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';

/**
 * Composant Barre Latérale de Navigation (Sidebar) — CyberGuard SOC
 * =================================================================
 * Affiche dynamiquement les liens de navigation selon le rôle RBAC de l'utilisateur connecté :
 *   - UTILISATEUR : Dashboard & Historique des analyses personnelles.
 *   - ENQUÊTEUR  : Dashboard SOC, Scanner d'investigation, Signalements & Preuves judiciaires.
 *   - ADMINISTRATEUR : Vue complète incluant Gestion des utilisateurs, Journaux d'audit & Paramètres de Sécurité.
 * Supporte le bilinguisme dynamique (Français / Anglais).
 */
export default function Sidebar() {
  const { user } = useAuth();
  const { lang } = useLanguage();

  // Menu pour les utilisateurs standards
  const stdItems = [
    { path: '/dashboard', label: lang === 'fr' ? 'Scanner & Tableau de Bord' : 'Scanner & Dashboard', icon: LayoutDashboard },
    { path: '/history', label: lang === 'fr' ? 'Historique des Analyses' : 'Analysis History', icon: History },
  ];

  const investigatorItems = [
    { path: '/dashboard', label: lang === 'fr' ? 'Tableau de Bord SOC' : 'SOC Dashboard', icon: LayoutDashboard },
    { path: '/scanner', label: lang === 'fr' ? 'Scanner & Analyse' : 'Scanner & Analysis', icon: Activity },
    { path: '/incidents', label: lang === 'fr' ? 'Rapports & Signalements' : 'Reports & Evidence', icon: FileSearch },
    { path: '/settings', label: lang === 'fr' ? 'Paramètres & Politiques' : 'Security Settings', icon: Sliders },
    { path: '/history', label: lang === 'fr' ? 'Historique des Analyses' : 'Analysis History', icon: History },
  ];

  const adminItems = [
    { path: '/dashboard', label: lang === 'fr' ? 'Tableau de Bord' : 'Dashboard', icon: LayoutDashboard },
    { path: '/scanner', label: lang === 'fr' ? 'Recherche & Scanner URL' : 'URL Search & Scanner', icon: Search },
    { path: '/history', label: lang === 'fr' ? 'Historique des Analyses' : 'Analysis History', icon: History },
    { path: '/incidents', label: lang === 'fr' ? 'Signalements & Enquêtes' : 'Incidents & Evidence', icon: FileSearch },
    { path: '/admin/users', label: lang === 'fr' ? 'Gestion d\'utilisateurs' : 'User Management', icon: Users },
    { path: '/activity-logs', label: lang === 'fr' ? 'Journal des Activités' : 'Activity Logs', icon: Activity },
    { path: '/settings', label: lang === 'fr' ? 'Paramètres de Sécurité' : 'Security Settings', icon: Sliders },
  ];

  let navItems = stdItems;
  if (user?.role === 'ENQUETEUR') navItems = investigatorItems;
  if (user?.role === 'ADMINISTRATEUR') navItems = adminItems;

  return (
    <aside className="w-64 bg-white/80 dark:bg-[#0f172a]/80 backdrop-blur-md border-r border-slate-200 dark:border-sky-900/40 flex flex-col justify-between py-5 px-3 sticky top-16 h-[calc(100vh-4rem)] shadow-sm transition-colors duration-300">
      <div className="space-y-1.5">
        <div className="px-3 mb-4 flex items-center justify-between">
          <p className="text-[10px] uppercase font-mono tracking-widest text-slate-400 dark:text-slate-500 font-bold">
            {lang === 'fr' ? 'NAVIGATION SOC' : 'SOC NAVIGATION'}
          </p>
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full badge-glass-cyan text-[9px] font-mono font-bold">
            <ShieldCheck className="w-3 h-3 text-cyan-400" />
            {user?.role === 'ENQUETEUR' ? (lang === 'fr' ? 'ENQUÊTEUR' : 'INVESTIGATOR') : user?.role === 'ADMINISTRATEUR' ? 'ADMIN' : (lang === 'fr' ? 'UTILISATEUR' : 'USER')}
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

    </aside>
  );
}
