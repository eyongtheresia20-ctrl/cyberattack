import React from 'react';
import { NavLink } from 'react-router-dom';
import { Home as HomeIcon, LayoutDashboard, Globe, MessageSquare, ShieldAlert, FileSearch, CheckCircle2, Bot } from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';

export default function Sidebar() {
  const { lang } = useLanguage();

  const navItems = [
    { path: '/', label: lang === 'en' ? 'Home' : 'Accueil', icon: HomeIcon },
    { path: '/dashboard', label: lang === 'en' ? 'SOC Dashboard' : 'Tableau de bord SOC', icon: LayoutDashboard },
    { path: '/url-analysis', label: lang === 'en' ? 'URL Threat Scanner' : 'Scanner d\'URL', icon: Globe },
    { path: '/text-analysis', label: lang === 'en' ? 'SMS & Email Phishing' : 'SMS & Email Phishing', icon: MessageSquare },
    { path: '/site-monitoring', label: lang === 'en' ? 'Web Attack Monitor' : 'Moniteur d\'attaques web', icon: ShieldAlert },
    { path: '/incidents', label: lang === 'en' ? 'Incidents & Evidence' : 'Incidents & Preuves', icon: FileSearch },
    { path: '/verification', label: lang === 'en' ? 'Investigator Portal' : 'Portail Investigateur', icon: CheckCircle2 },
    { path: '/assistant', label: lang === 'en' ? 'AI Security Advisor' : 'Conseiller IA', icon: Bot },
  ];

  return (
    <aside className="w-64 bg-white dark:bg-[#161b27] border-r border-sky-100 dark:border-sky-900/60 flex flex-col justify-between py-4 px-3 sticky top-16 h-[calc(100vh-4rem)] shadow-sm transition-colors duration-300">
      <div className="space-y-1">
        <p className="px-3 text-[10px] uppercase font-mono tracking-widest text-slate-400 dark:text-slate-500 font-bold mb-3">
          {lang === 'en' ? 'Navigation Menu' : 'Menu de navigation'}
        </p>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
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

      <div className="p-4 rounded-2xl bg-sky-50 dark:bg-[#1e2637] border border-sky-200 dark:border-sky-800/60 text-xs space-y-2">
        <p className="font-extrabold text-slate-900 dark:text-white">
          {lang === 'en' ? 'Random Forest + NLP Engine' : 'Moteur Random Forest + NLP'}
        </p>
        <div className="w-full bg-sky-200 dark:bg-sky-900/50 h-2 rounded-full overflow-hidden">
          <div className="bg-sky-500 h-full w-[94%] rounded-full" />
        </div>
        <p className="text-[11px] text-slate-500 dark:text-slate-400">
          {lang === 'en' ? 'Model Accuracy:' : 'Précision:'}{' '}
          <span className="font-mono text-sky-600 dark:text-sky-400 font-extrabold">94.8%</span>
        </p>
      </div>
    </aside>
  );
}
