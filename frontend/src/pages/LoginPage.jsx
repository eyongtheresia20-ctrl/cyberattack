import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Eye, EyeOff, ArrowRight, Sun, Moon, AlertCircle, RefreshCw, UserCheck, ShieldAlert, Sparkles } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';
import CyberGuardLogo from '../components/CyberGuardLogo';

export default function LoginPage() {
  const { isDark, toggle: toggleTheme } = useTheme();
  const { lang, toggle: toggleLang, t } = useLanguage();
  const { login } = useAuth();
  const navigate = useNavigate();

  const [showPass, setShowPass] = useState(false);
  const [form, setForm] = useState({ email: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(form.email.trim(), form.password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || t('login_invalid'));
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async (email, password) => {
    setForm({ email, password });
    setError(null);
    setLoading(true);
    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || t('login_failed'));
    } finally {
      setLoading(false);
    }
  };

  const demoAccounts = [
    {
      role: 'ENQUETEUR',
      label: t('demo_soc_label'),
      desc: t('demo_soc_desc'),
      email: 'investigator@phishguard.security',
      password: 'phishguard2026',
      badgeColor: 'bg-indigo-500/10 text-indigo-500 border-indigo-500/30 hover:bg-indigo-500/20 hover:border-indigo-500',
      icon: ShieldAlert
    },
    {
      role: 'ADMINISTRATEUR',
      label: t('demo_admin_label'),
      desc: t('demo_admin_desc'),
      email: 'admin@phishguard.security',
      password: 'phishguard2026',
      badgeColor: 'bg-amber-500/10 text-amber-500 border-amber-500/30 hover:bg-amber-500/20 hover:border-amber-500',
      icon: Lock
    },
    {
      role: 'UTILISATEUR_STANDARD',
      label: t('demo_user_label'),
      desc: t('demo_user_desc'),
      email: 'alice.martin@example.com',
      password: 'User123!',
      badgeColor: 'bg-sky-500/10 text-sky-500 border-sky-500/30 hover:bg-sky-500/20 hover:border-sky-500',
      icon: UserCheck
    }
  ];

  return (
    <div className="min-h-screen flex flex-col bg-[#f0f9ff] dark:bg-[#0d1117] text-slate-900 dark:text-slate-100 transition-colors duration-300">

      {/* Minimal Header */}
      <header className="border-b border-sky-200 dark:border-sky-900/60 bg-white/80 dark:bg-[#161b27]/80 backdrop-blur-md px-6 py-4 flex items-center justify-between">
        <Link to="/">
          <CyberGuardLogo size="md" />
        </Link>
        <div className="flex items-center gap-2">
          <button
            onClick={toggleLang}
            className="px-3 py-1.5 rounded-lg text-xs font-bold border border-sky-200 dark:border-sky-800/60 bg-white dark:bg-[#1e2637] text-sky-700 dark:text-sky-300 hover:border-sky-400 transition"
          >
            {lang === 'en' ? 'EN' : 'FR'}
          </button>
          <button onClick={toggleTheme} className="p-2 rounded-lg border border-sky-200 dark:border-sky-800/60 bg-white dark:bg-[#1e2637] text-slate-700 dark:text-slate-200 hover:border-sky-400 transition">
            {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>
      </header>

      {/* Card */}
      <main className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-lg space-y-6">

          {/* Card Header */}
          <div className="text-center space-y-2">
            <div className="flex justify-center">
              <div className="p-4 rounded-2xl bg-sky-500 shadow-xl shadow-sky-500/25">
                <Lock className="w-7 h-7 text-white stroke-[2.5]" />
              </div>
            </div>
            <h1 className="text-2xl font-extrabold text-slate-900 dark:text-white">{t('login_title')}</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {t('login_sub_creds')}
            </p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-300 text-xs font-semibold flex items-center gap-2 animate-fade-in">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-500" />
              <span>{error}</span>
            </div>
          )}

          {/* Standard Form */}
          <form
            onSubmit={handleSubmit}
            className="bg-white dark:bg-[#161b27] border border-sky-100 dark:border-sky-900/50 rounded-2xl shadow-xl shadow-sky-500/5 p-7 space-y-4"
          >
            {/* Email */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">{t('login_email')}</label>
              <input
                type="email"
                required
                value={form.email}
                onChange={e => setForm({ ...form, email: e.target.value })}
                placeholder="investigator@cyberguard.security"
                className="w-full px-4 py-3 rounded-xl bg-sky-50 dark:bg-[#1e2637] border border-sky-200 dark:border-sky-800/60 text-slate-900 dark:text-white text-sm placeholder-slate-400 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition"
              />
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">{t('login_password')}</label>
              <div className="relative">
                <input
                  type={showPass ? 'text' : 'password'}
                  required
                  value={form.password}
                  onChange={e => setForm({ ...form, password: e.target.value })}
                  placeholder="••••••••"
                  className="w-full px-4 py-3 rounded-xl bg-sky-50 dark:bg-[#1e2637] border border-sky-200 dark:border-sky-800/60 text-slate-900 dark:text-white text-sm placeholder-slate-400 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition pr-11"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(s => !s)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-sky-500 transition"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <div className="flex justify-end">
                <a href="#" className="text-xs text-sky-600 dark:text-sky-400 hover:underline font-medium">{t('login_forgot')}</a>
              </div>
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 rounded-xl bg-sky-500 hover:bg-sky-600 disabled:opacity-60 text-white font-extrabold text-sm shadow-lg shadow-sky-500/20 hover:shadow-sky-500/30 transition-all hover:scale-[1.01] flex items-center justify-center gap-2 cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  {t('login_authenticating')}
                </>
              ) : (
                <>
                  {t('login_btn')} <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Create account link */}
          <p className="text-center text-sm text-slate-500 dark:text-slate-400">
            {t('login_no_account')}{' '}
            <Link to="/register" className="text-sky-600 dark:text-sky-400 font-bold hover:underline">{t('login_create')}</Link>
          </p>

          {/* Back to home */}
          <p className="text-center text-xs text-slate-400">
            <Link to="/" className="hover:text-sky-500 transition">{t('login_back_home')}</Link>
          </p>

        </div>
      </main>
    </div>
  );
}
