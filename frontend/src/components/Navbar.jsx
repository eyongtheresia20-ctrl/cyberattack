import React, { useState, useEffect } from 'react';
import { Shield, Globe, LogOut, User, Sun, Moon, History, X, Mail, CheckCircle2, Clock, AlertCircle, Eye, EyeOff, Activity, Lock } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';
import { useLanguage } from '../context/LanguageContext';
import { useAuth } from '../context/AuthContext';

export default function Navbar({ onOpenAuth, onOpenHistory }) {
  const { isDark, toggle: toggleTheme } = useTheme();
  const { lang, toggle: toggleLang } = useLanguage();
  const { user, logout, updateUser, updateProfile } = useAuth();
  const navigate = useNavigate();

  const [showDropdown, setShowDropdown] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [profileMsg, setProfileMsg] = useState(null);
  const [profileError, setProfileError] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Live session timer state
  const [sessionSeconds, setSessionSeconds] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setSessionSeconds(prev => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const formatDuration = (totalSeconds) => {
    const hrs = Math.floor(totalSeconds / 3600);
    const mins = Math.floor((totalSeconds % 3600) / 60);
    const secs = totalSeconds % 60;
    const pad = (n) => String(n).padStart(2, '0');
    return hrs > 0 ? `${pad(hrs)}:${pad(mins)}:${pad(secs)}` : `${pad(mins)}:${pad(secs)}`;
  };

  const activeUser = user || {
    prenom: 'Alice',
    nom: 'Martin',
    email: 'alice.martin@example.com',
    role: 'UTILISATEUR_STANDARD',
    password: 'User123!',
    last_login: new Date().toISOString()
  };

  const getLoginTimeString = () => {
    if (activeUser.last_login) {
      try {
        const d = new Date(activeUser.last_login);
        return d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      } catch (e) {
        return '13:00:00';
      }
    }
    return '13:00:00';
  };

  const [profileForm, setProfileForm] = useState({
    prenom: activeUser.prenom,
    nom: activeUser.nom,
    email: activeUser.email,
    password: activeUser.password || 'User123!'
  });

  const handleOpenProfile = () => {
    setProfileForm({
      prenom: activeUser.prenom,
      nom: activeUser.nom,
      email: activeUser.email,
      password: activeUser.password || 'User123!'
    });
    setShowPassword(false);
    setProfileMsg(null);
    setProfileError(null);
    setShowDropdown(false);
    setShowProfileModal(true);
  };

  const handleProfileSave = async (e) => {
    e.preventDefault();
    setProfileMsg(null);
    setProfileError(null);
    setIsSaving(true);
    try {
      if (updateProfile) {
        await updateProfile({
          prenom: profileForm.prenom,
          nom: profileForm.nom,
          email: profileForm.email,
          password: profileForm.password
        });
      } else if (updateUser) {
        updateUser({
          prenom: profileForm.prenom,
          nom: profileForm.nom,
          email: profileForm.email
        });
      }
      setProfileMsg("Modifications enregistrées avec succès !");
    } catch (err) {
      setProfileError(err.message || "Erreur lors de l'enregistrement");
    } finally {
      setIsSaving(false);
    }
  };

  const handleLogout = () => {
    setShowDropdown(false);
    logout();
    navigate('/');
  };

  return (
    <>
      <header className="h-16 bg-white/90 dark:bg-[#0f172a]/90 backdrop-blur-md border-b border-slate-200 dark:border-sky-900/40 px-6 flex items-center justify-between sticky top-0 z-40 shadow-sm transition-colors duration-300">
        
        {/* Left Brand & Welcome Banner */}
        <div className="flex items-center gap-6">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="p-2 bg-gradient-to-tr from-cyan-500 to-blue-600 rounded-xl shadow-lg shadow-cyan-500/25 group-hover:scale-105 transition-transform duration-200">
              <Shield className="w-5 h-5 text-white stroke-[2.5]" />
            </div>
            <div>
              <h1 className="font-heading font-extrabold tracking-wider text-xl text-slate-900 dark:text-white flex items-center gap-1.5">
                PHISH<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">GUARD</span>
              </h1>
            </div>
          </Link>

          {/* Operational Status Pill & Live Clock */}
          <div className="hidden lg:flex items-center gap-3 pl-5 border-l border-slate-200 dark:border-slate-800">
            <div className="flex items-center gap-2 bg-cyan-500/10 border border-cyan-500/30 px-3 py-1 rounded-full text-xs font-semibold">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
              </span>
              <span className="text-slate-800 dark:text-slate-200 font-sans">
                Bienvenue, <strong className="text-cyan-600 dark:text-cyan-400 font-bold">{activeUser.prenom} {activeUser.nom}</strong>
              </span>
            </div>

            <div className="flex items-center gap-2 bg-slate-100 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 px-3 py-1 rounded-full text-[11px] font-mono text-slate-600 dark:text-slate-300">
              <Clock className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span>Session : <strong className="text-slate-900 dark:text-white">{getLoginTimeString()}</strong></span>
              <span className="text-slate-300 dark:text-slate-700">|</span>
              <span>Actif : <strong className="text-cyan-600 dark:text-cyan-400 font-bold">{formatDuration(sessionSeconds)}</strong></span>
            </div>
          </div>
        </div>

        {/* Right Tools & User Profile */}
        <div className="flex items-center gap-3 relative">
          
          {/* Language toggle */}
          <button
            onClick={toggleLang}
            className="flex items-center gap-1 px-3 py-1.5 rounded-xl text-xs font-bold border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#1e293b] text-slate-700 dark:text-slate-300 hover:border-cyan-500/50 transition cursor-pointer"
          >
            <Globe className="w-3.5 h-3.5 text-cyan-400" />{lang === 'en' ? 'EN' : 'FR'}
          </button>

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="p-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#1e293b] text-slate-600 dark:text-slate-200 hover:border-cyan-500/50 transition cursor-pointer"
            title="Basculer le thème"
          >
            {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-700" />}
          </button>

          {/* History Button */}
          {onOpenHistory && (
            <button
              onClick={onOpenHistory}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl btn-gradient-cyan text-xs font-bold shadow-md transition cursor-pointer"
            >
              <History className="w-3.5 h-3.5" /> Historique
            </button>
          )}

          {/* User Profile Avatar Icon */}
          <div className="pl-3 border-l border-slate-200 dark:border-slate-800">
            <button
              onClick={() => setShowDropdown(!showDropdown)}
              className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-md shadow-cyan-500/20 hover:scale-105 transition cursor-pointer"
              title={`Compte : ${activeUser.prenom} ${activeUser.nom}`}
            >
              <User className="w-5 h-5" />
            </button>

            {/* Sleek Floating Dropdown Menu */}
            {showDropdown && (
              <div className="absolute right-0 top-12 z-50 w-72 bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-2xl shadow-2xl p-3 space-y-2 animate-fade-in">
                <div className="p-3 bg-slate-50 dark:bg-[#1e293b] rounded-xl border border-slate-200 dark:border-slate-800 space-y-1">
                  <p className="font-extrabold text-xs text-slate-900 dark:text-white font-heading">{activeUser.prenom} {activeUser.nom}</p>
                  <p className="text-[10px] text-slate-500 dark:text-slate-400 font-mono truncate">{activeUser.email}</p>
                  
                  <div className="flex items-center justify-between pt-1">
                    <span className="inline-block px-2 py-0.5 rounded-md badge-glass-cyan font-mono font-bold text-[9px]">
                      {activeUser.role}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">⏱️ {formatDuration(sessionSeconds)}</span>
                  </div>
                </div>

                <div className="space-y-1 pt-1">
                  <button
                    onClick={handleOpenProfile}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-bold text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-[#1e293b] hover:text-cyan-500 rounded-xl transition cursor-pointer"
                  >
                    <User className="w-4 h-4 text-cyan-400" /> Mon Profil
                  </button>

                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2.5 px-3 py-2 text-xs font-bold text-rose-500 hover:bg-rose-500/10 rounded-xl transition cursor-pointer"
                  >
                    <LogOut className="w-4 h-4 text-rose-500" /> Déconnexion
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Clean User Profile Modal */}
      {showProfileModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-3xl p-6 max-w-lg w-full shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto animate-fade-in">
            
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-cyan-500 to-blue-600 text-white flex items-center justify-center font-bold text-sm shadow-lg shadow-cyan-500/30">
                  <User className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-heading font-extrabold text-slate-900 dark:text-white text-base">{profileForm.prenom} {profileForm.nom}</h3>
                  <p className="text-xs text-cyan-500 dark:text-cyan-400 font-mono font-bold">{activeUser.role}</p>
                </div>
              </div>
              <button
                onClick={() => setShowProfileModal(false)}
                className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-lg transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Session Stats Header */}
            <div className="p-3 bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 rounded-2xl flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2 text-slate-600 dark:text-slate-300">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span>Connexion : <strong>{getLoginTimeString()}</strong></span>
              </div>
              <div className="text-cyan-500 dark:text-cyan-400 font-bold">
                Temps actif : {formatDuration(sessionSeconds)}
              </div>
            </div>

            {profileMsg && (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold rounded-xl flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" /> {profileMsg}
              </div>
            )}

            {profileError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-semibold rounded-xl flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" /> {profileError}
              </div>
            )}

            {/* Profile Modification Form */}
            <form onSubmit={handleProfileSave} className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                    Prénom
                  </label>
                  <input
                    type="text"
                    required
                    value={profileForm.prenom}
                    onChange={(e) => setProfileForm({ ...profileForm, prenom: e.target.value })}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                    Nom
                  </label>
                  <input
                    type="text"
                    required
                    value={profileForm.nom}
                    onChange={(e) => setProfileForm({ ...profileForm, nom: e.target.value })}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                  Adresse Email
                </label>
                <div className="relative">
                  <input
                    type="email"
                    required
                    value={profileForm.email}
                    onChange={(e) => setProfileForm({ ...profileForm, email: e.target.value })}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-cyan-500 pr-9"
                  />
                  <Mail className="w-4 h-4 text-cyan-400 absolute right-3 top-3" />
                </div>
              </div>

              <div>
                <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                  Mot de passe
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={profileForm.password}
                    onChange={(e) => setProfileForm({ ...profileForm, password: e.target.value })}
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-cyan-500 pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-cyan-400 hover:text-cyan-300 focus:outline-none p-0.5 cursor-pointer"
                    title={showPassword ? "Masquer" : "Afficher"}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={isSaving}
                className="w-full py-2.5 btn-gradient-cyan disabled:opacity-50 font-bold rounded-xl text-xs shadow-lg transition mt-2 flex items-center justify-center gap-2 cursor-pointer"
              >
                {isSaving ? "Enregistrement..." : "Enregistrer les modifications"}
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
