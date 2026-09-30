import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, UserPlus, Eye, EyeOff, ArrowRight, Sun, Moon, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';
import CyberGuardLogo from '../components/CyberGuardLogo';

export default function RegisterPage() {
  const { isDark, toggle: toggleTheme } = useTheme();
  const { lang, toggle: toggleLang, t } = useLanguage();
  const { register } = useAuth();
  const navigate = useNavigate();

  const [showPass, setShowPass] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({
    name: '', email: '', password: '', confirm: '', terms: false,
  });

  const set = (key) => (e) => setForm({ ...form, [key]: e.target.type === 'checkbox' ? e.target.checked : e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (form.password !== form.confirm) {
      setError(lang === 'en' ? 'Passwords do not match.' : 'Les mots de passe ne correspondent pas.');
      return;
    }

    if (form.password.length < 6) {
      setError(lang === 'en' ? 'Password must be at least 6 characters.' : 'Le mot de passe doit contenir au moins 6 caractères.');
      return;
    }

    const parts = form.name.trim().split(' ');
    const prenom = parts[0] || 'Utilisateur';
    const nom = parts.slice(1).join(' ') || 'CyberGuard';

    setLoading(true);
    try {
      await register(nom, prenom, form.email.trim(), form.password);
      setDone(true);
      setTimeout(() => navigate('/dashboard'), 1500);
    } catch (err) {
      let msg = err.detail || err.message || '';
      if (err.status === 400 || msg.includes('déjà') || msg.includes('already exists')) {
        msg = lang === 'en' ? 'An account already exists with this email address.' : 'Un compte existe déjà avec cette adresse e-mail.';
      } else if (err.status === 0 || msg === 'NETWORK_ERROR') {
        msg = lang === 'en' ? 'Unable to reach the server. Please check your backend service.' : 'Impossible de joindre le serveur. Assurez-vous que le backend est en cours d\'exécution.';
      } else if (err.status >= 500 || msg.includes('token') || msg.includes('JSON')) {
        msg = lang === 'en' ? 'Internal server error (500). Please try again later.' : 'Erreur interne du serveur (500). Veuillez réessayer ultérieurement.';
      } else if (!msg || msg.startsWith('HTTP_')) {
        msg = lang === 'en' ? 'Registration failed. Please check the provided information.' : 'Échec de l\'inscription. Veuillez vérifier les informations saisies.';
      }
      setError(msg);
    } finally {
      setLoading(false);
    }
  };


  const inputClass = "w-full px-4 py-3 rounded-xl bg-sky-50 dark:bg-[#1e2637] border border-sky-200 dark:border-sky-800/60 text-slate-900 dark:text-white text-sm placeholder-slate-400 focus:outline-none focus:border-sky-500 focus:ring-2 focus:ring-sky-500/20 transition";
  const labelClass = "text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider";

  return (
    <div className="min-h-screen flex flex-col bg-[#f0f9ff] dark:bg-[#0d1117] text-slate-900 dark:text-slate-100 transition-colors duration-300">

      {/* Minimal Header */}
      <header className="border-b border-sky-200 dark:border-sky-900/60 bg-white/80 dark:bg-[#161b27]/80 backdrop-blur-md px-6 py-4 flex items-center justify-between">
        <Link to="/">
          <CyberGuardLogo size="md" />
        </Link>
        <div className="flex items-center gap-2">
          <button onClick={toggleLang} className="px-3 py-1.5 rounded-lg text-xs font-bold border border-sky-200 dark:border-sky-800/60 bg-white dark:bg-[#1e2637] text-sky-700 dark:text-sky-300 hover:border-sky-400 transition">
            {lang === 'en' ? 'EN' : 'FR'}
          </button>
          <button onClick={toggleTheme} className="p-2 rounded-lg border border-sky-200 dark:border-sky-800/60 bg-white dark:bg-[#1e2637] text-slate-700 dark:text-slate-200 hover:border-sky-400 transition">
            {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
          </button>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-6 py-16">
        <div className="w-full max-w-md space-y-8">

          {done ? (
            /* Success state */
            <div className="text-center space-y-4 animate-fade-in">
              <div className="flex justify-center">
                <div className="p-4 rounded-2xl bg-emerald-500 shadow-xl shadow-emerald-500/25">
                  <CheckCircle2 className="w-8 h-8 text-white stroke-[2.5]" />
                </div>
              </div>
              <h2 className="text-2xl font-extrabold text-slate-900 dark:text-white">
                {lang === 'en' ? 'Account Created!' : 'Compte créé !'}
              </h2>
              <p className="text-slate-500 dark:text-slate-400 text-sm">
                {lang === 'en' ? 'Redirecting to the platform...' : 'Redirection vers la plateforme...'}
              </p>
              <div className="w-full bg-sky-100 dark:bg-sky-900/30 h-1.5 rounded-full overflow-hidden">
                <div className="bg-sky-500 h-full w-full animate-pulse rounded-full" />
              </div>
            </div>
          ) : (
            <>
              {/* Card Header */}
              <div className="text-center space-y-2">
                <div className="flex justify-center">
                  <div className="p-4 rounded-2xl bg-sky-500 shadow-xl shadow-sky-500/25">
                    <UserPlus className="w-7 h-7 text-white stroke-[2.5]" />
                  </div>
                </div>
                <h1 className="text-2xl font-extrabold text-slate-900 dark:text-white">{t('register_title')}</h1>
                <p className="text-sm text-slate-500 dark:text-slate-400">{t('register_sub')}</p>
              </div>

              {/* Error Banner */}
              {error && (
                <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-300 text-xs font-semibold flex items-center gap-2 animate-fade-in">
                  <AlertCircle className="w-4 h-4 shrink-0 text-rose-500" />
                  <span>{error}</span>
                </div>
              )}

              {/* Form */}
              <form
                onSubmit={handleSubmit}
                className="bg-white dark:bg-[#161b27] border border-sky-100 dark:border-sky-900/50 rounded-2xl shadow-xl shadow-sky-500/5 p-8 space-y-5"
              >
                {/* Full Name */}
                <div className="space-y-1.5">
                  <label className={labelClass}>{t('register_name')}</label>
                  <input type="text" required value={form.name} onChange={set('name')} placeholder="Jane Doe" className={inputClass} />
                </div>

                {/* Email */}
                <div className="space-y-1.5">
                  <label className={labelClass}>{t('register_email')}</label>
                  <input type="email" required value={form.email} onChange={set('email')} placeholder="analyst@cyberguard.io" className={inputClass} />
                </div>

                {/* Password */}
                <div className="space-y-1.5">
                  <label className={labelClass}>{t('register_password')}</label>
                  <div className="relative">
                    <input type={showPass ? 'text' : 'password'} required value={form.password} onChange={set('password')} placeholder="••••••••" className={inputClass + ' pr-11'} />
                    <button type="button" onClick={() => setShowPass(s => !s)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-sky-500 transition">
                      {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Confirm Password */}
                <div className="space-y-1.5">
                  <label className={labelClass}>{t('register_confirm')}</label>
                  <div className="relative">
                    <input type={showConfirm ? 'text' : 'password'} required value={form.confirm} onChange={set('confirm')} placeholder="••••••••" className={inputClass + ' pr-11'} />
                    <button type="button" onClick={() => setShowConfirm(s => !s)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-sky-500 transition">
                      {showConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Terms */}
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    required
                    checked={form.terms}
                    onChange={set('terms')}
                    className="mt-0.5 w-4 h-4 accent-sky-500 rounded"
                  />
                  <span className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">{t('register_terms')}</span>
                </label>

                {/* Submit */}
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-3.5 rounded-xl bg-sky-500 hover:bg-sky-600 disabled:opacity-60 text-white font-extrabold text-sm shadow-lg shadow-sky-500/20 hover:shadow-sky-500/30 transition-all hover:scale-[1.01] flex items-center justify-center gap-2 cursor-pointer"
                >
                  {loading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      {lang === 'en' ? 'Creating account...' : 'Création du compte...'}
                    </>
                  ) : (
                    <>
                      {t('register_btn')} <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              <p className="text-center text-sm text-slate-500 dark:text-slate-400">
                {t('register_have_account')}{' '}
                <Link to="/login" className="text-sky-600 dark:text-sky-400 font-bold hover:underline">{t('register_signin')}</Link>
              </p>
              <p className="text-center text-xs text-slate-400">
                <Link to="/" className="hover:text-sky-500 transition">← {lang === 'en' ? 'Back to Home' : 'Retour à l\'accueil'}</Link>
              </p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
