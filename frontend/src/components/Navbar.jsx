import React from 'react';
import { Shield, Bell, Activity, Sun, Moon, Globe } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';
import { useLanguage } from '../context/LanguageContext';

export default function Navbar() {
  const { isDark, toggle: toggleTheme } = useTheme();
  const { lang, toggle: toggleLang } = useLanguage();

  return (
    <header className="h-16 bg-white dark:bg-[#161b27] border-b border-sky-100 dark:border-sky-900/60 px-6 flex items-center justify-between sticky top-0 z-40 shadow-sm transition-colors duration-300">

      <Link to="/" className="flex items-center gap-3 group">
        <div className="p-2 bg-sky-500 rounded-xl shadow-md shadow-sky-500/20 group-hover:bg-sky-600 transition">
          <Shield className="w-5 h-5 text-white stroke-[2.5]" />
        </div>
        <div>
          <h1 className="font-extrabold tracking-wide text-base text-slate-900 dark:text-white flex items-center gap-2">
            PHISH<span className="text-sky-500">GUARD</span>{' '}
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-sky-100 dark:bg-sky-500/10 text-sky-700 dark:text-sky-400 border border-sky-200 dark:border-sky-700/40 font-bold">v1.0 SOC</span>
          </h1>
          <p className="text-[11px] text-slate-500 dark:text-slate-400 font-medium">Cyber Attack & Phishing Intelligence Platform</p>
        </div>
      </Link>

      <div className="flex items-center gap-3">
        <div className="hidden md:flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-sky-50 dark:bg-sky-500/10 border border-sky-200 dark:border-sky-700/40 text-slate-700 dark:text-slate-300 text-xs font-medium">
          <Activity className="w-3.5 h-3.5 text-sky-500 animate-pulse" />
          <span>Status: <strong className="text-sky-600 dark:text-sky-400 font-mono">OPERATIONAL</strong></span>
        </div>

        {/* Language toggle */}
        <button
          onClick={toggleLang}
          className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-bold border border-sky-200 dark:border-sky-800/60 bg-white dark:bg-[#1e2637] text-sky-700 dark:text-sky-300 hover:border-sky-400 transition"
        >
          <Globe className="w-3.5 h-3.5" />{lang === 'en' ? 'EN' : 'FR'}
        </button>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg border border-sky-200 dark:border-sky-800/60 bg-white dark:bg-[#1e2637] text-slate-600 dark:text-slate-200 hover:border-sky-400 transition"
          title="Toggle theme"
        >
          {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
        </button>

        <button className="p-2 rounded-lg bg-white dark:bg-[#1e2637] border border-sky-200 dark:border-sky-800/60 text-slate-500 dark:text-slate-300 hover:text-sky-600 dark:hover:text-sky-400 hover:border-sky-400 transition shadow-sm">
          <Bell className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2.5 pl-3 border-l border-sky-100 dark:border-sky-900/60">
          <div className="w-8 h-8 rounded-full bg-sky-500 text-white flex items-center justify-center font-bold text-xs shadow-sm">
            SA
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-bold text-slate-900 dark:text-white">Security Analyst</p>
            <p className="text-[10px] text-sky-600 dark:text-sky-400 font-mono font-semibold">SOC Lead</p>
          </div>
        </div>
      </div>
    </header>
  );
}
