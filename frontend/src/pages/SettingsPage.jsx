import React, { useState, useEffect } from 'react';
import { 
  Settings, Sliders, Shield, Lock, Ban, Zap, Eye, CheckCircle2, 
  AlertTriangle, RefreshCw, Save, Terminal, Radio, BellRing, 
  Volume2, Cpu, HardDrive, KeyRound, ExternalLink, Globe, Plus, Trash2, X
} from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';
import { useNavigate } from 'react-router-dom';

export default function SettingsPage() {
  const { lang } = useLanguage();
  const navigate = useNavigate();

  // Settings State
  const [settings, setSettings] = useState({
    // Content Filter / MINESEC
    block_adult_content: true,
    block_gambling: true,
    enforcement_mode: 'BLOCK', // 'BLOCK' | 'WARN' | 'ALLOW'
    school_shield_active: true,
    redirect_to_block_page: true,
    custom_blacklist: [],
    custom_whitelist: [],

    // Machine Learning & Threat Intel
    ml_auto_block_phishing: true,
    shannon_entropy_detection: true,
    external_threat_intel: true,

    // WAF & Network Defense
    waf_autoban_hostile_ips: true,
    honeypot_active_defense: true,

    // Real-time Sentinel & Extension
    sentinel_realtime_protection: true,
    audio_alert_chimes: true,
    sha256_forensic_sealing: true
  });

  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [newBlacklistDomain, setNewBlacklistDomain] = useState('');

  const addBlacklistDomain = (domainToAdd = null) => {
    const raw = (domainToAdd || newBlacklistDomain || '').trim().toLowerCase();
    const clean = raw.replace(/^https?:\/\//, '').split('/')[0].trim();
    if (!clean || !clean.includes('.')) return;
    const currentList = Array.isArray(settings.custom_blacklist) ? settings.custom_blacklist : [];
    if (!currentList.includes(clean)) {
      const updated = { ...settings, custom_blacklist: [...currentList, clean] };
      setSettings(updated);
      persistSettings(updated);
    }
    setNewBlacklistDomain('');
  };

  const removeBlacklistDomain = (domainToRemove) => {
    const currentList = Array.isArray(settings.custom_blacklist) ? settings.custom_blacklist : [];
    const updated = { ...settings, custom_blacklist: currentList.filter(d => d !== domainToRemove) };
    setSettings(updated);
    persistSettings(updated);
  };

  // Load existing settings
  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const res = await fetch('/api/v1/enterprise/policy-settings');
        if (res.ok) {
          const data = await res.json();
          setSettings(prev => ({
            ...prev,
            ...data,
            // Keep local stored settings if any
            sentinel_realtime_protection: localStorage.getItem('cyberguard_sentinel_enabled') !== 'false',
            audio_alert_chimes: localStorage.getItem('cyberguard_audio_chimes') !== 'false'
          }));
        }
      } catch (e) {
        console.error('Fetch settings error:', e);
      } finally {
        setIsLoading(false);
      }
    };
    fetchSettings();
  }, []);

  const persistSettings = async (updatedSettings) => {
    setIsSaving(true);
    try {
      // 1. Save all settings to backend API
      const res = await fetch('/api/v1/enterprise/policy-settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updatedSettings)
      });

      // 2. Save local Sentinel preferences
      localStorage.setItem('cyberguard_sentinel_enabled', JSON.stringify(updatedSettings.sentinel_realtime_protection));
      localStorage.setItem('cyberguard_audio_chimes', JSON.stringify(updatedSettings.audio_alert_chimes));
      localStorage.setItem('cyberguard_redirect_block_page', JSON.stringify(updatedSettings.redirect_to_block_page));

      // 3. Broadcast to all open tabs and active components
      window.dispatchEvent(new CustomEvent('cyberguard:settings-updated', { detail: updatedSettings }));

      if (res.ok) {
        setSaveSuccess(true);
        setTimeout(() => setSaveSuccess(false), 2500);
      }
    } catch (e) {
      console.error('Error saving settings:', e);
    } finally {
      setIsSaving(false);
    }
  };

  const toggleSetting = (key) => {
    const updated = { ...settings, [key]: !settings[key] };
    setSettings(updated);
    persistSettings(updated);
  };

  const handleSave = () => {
    persistSettings(settings);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      
      {/* Page Title & Save Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-sky-500 via-indigo-600 to-purple-600 flex items-center justify-center text-white shadow-lg shadow-sky-500/20">
            <Sliders className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl sm:text-2xl font-black text-slate-900 dark:text-white tracking-tight">
                {lang === 'fr' ? "Paramètres & Politiques de Sécurité" : "Security Settings & Policies"}
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20">
                ADMIN SOC
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {lang === 'fr'
                ? "Configuration des modules d'interception, du filtrage de contenu scolaire et des règles de pare-feu."
                : "Configuration of threat interception modules, school content filtering, and active firewall rules."}
            </p>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => navigate('/blocked?url=https://pornhub.com/video&category=CONTENU+ADULTE+RESTREINT&reason=Démonstration+de+la+page+de+blocage+personnalisée')}
            className="px-4 py-2.5 text-xs font-bold rounded-xl border border-rose-300 dark:border-rose-900/60 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400 hover:bg-rose-100 transition flex items-center gap-2 cursor-pointer"
          >
            <Eye className="w-4 h-4" />
            <span>{lang === 'fr' ? "Tester la Page de Blocage" : "Preview Block Page"}</span>
          </button>

          <button
            type="button"
            onClick={handleSave}
            disabled={isSaving}
            className={`px-5 py-2.5 text-xs font-bold rounded-xl flex items-center gap-2 transition shadow-lg cursor-pointer ${
              saveSuccess
                ? 'bg-emerald-500 text-white shadow-emerald-500/20'
                : 'bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white shadow-sky-500/20'
            }`}
          >
            {isSaving ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : saveSuccess ? (
              <CheckCircle2 className="w-4 h-4" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            <span>
              {saveSuccess 
                ? (lang === 'fr' ? "Enregistré avec succès !" : "Saved Successfully!") 
                : (lang === 'fr' ? "Enregistrer les modifications" : "Save Changes")}
            </span>
          </button>
        </div>
      </div>

      {/* Grid of Settings Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* ── SECTION 1 : FILTRAGE WEB & CONTRÔLE PARENTAL (MINESEC) ── */}
        <div className="p-6 bg-white dark:bg-[#111726] border border-emerald-500/30 rounded-3xl space-y-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                <Lock className="w-5 h-5" />
              </span>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono">
                  {lang === 'fr' ? "1. Filtrage Web & Contrôle Parental (MINESEC)" : "1. Web Content Filtering (MINESEC Policy)"}
                </h3>
                <p className="text-[11px] text-slate-500">Protection des élèves et établissements scolaires</p>
              </div>
            </div>

            {/* Enforcement Mode Selector */}
            <select
              value={settings.enforcement_mode}
              onChange={(e) => {
                const newMode = e.target.value;
                const updated = { ...settings, enforcement_mode: newMode };
                setSettings(updated);
                persistSettings(updated);
              }}
              className="px-2.5 py-1 text-xs font-mono font-bold rounded-xl bg-slate-50 dark:bg-slate-800 border border-emerald-500/40 text-emerald-600 dark:text-emerald-400 focus:outline-none cursor-pointer"
            >
              <option value="BLOCK">⛔ Blocage Strict</option>
              <option value="WARN">⚠️ Avertissement</option>
              <option value="ALLOW">✅ Autoriser</option>
            </select>
          </div>

          <div className="space-y-4">
            
            {/* Toggle: Adult Content */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Ban className="w-3.5 h-3.5 text-rose-500" />
                  <span>Bloquer le contenu adulte & pornographique</span>
                </div>
                <p className="text-[11px] text-slate-500">Intercepte les sites .xxx, .porn, cam, streaming adulte</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('block_adult_content')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.block_adult_content ? 'bg-emerald-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

            {/* Toggle: Gambling */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-amber-500" />
                  <span>Bloquer les jeux d'argent & paris en ligne</span>
                </div>
                <p className="text-[11px] text-slate-500">Neutralise les casinos en ligne, bookmakers (1xBet, Betway, etc.)</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('block_gambling')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.block_gambling ? 'bg-emerald-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

            {/* Toggle: Custom Block Screen Redirect */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-sky-500" />
                  <span>Redirection physique vers la Page d'Interdiction</span>
                </div>
                <p className="text-[11px] text-slate-500">Affiche la page CyberGuard de blocage au lieu de laisser naviguer</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('redirect_to_block_page')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.redirect_to_block_page ? 'bg-emerald-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

          </div>
        </div>

        {/* ── SECTION 2 : MACHINE LEARNING & DÉTECTION PHISHING ── */}
        <div className="p-6 bg-white dark:bg-[#111726] border border-sky-500/30 rounded-3xl space-y-5 shadow-sm">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100 dark:border-slate-800">
            <span className="p-2 rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400">
              <Cpu className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono">
                {lang === 'fr' ? "2. Moteur IA & Détection Phishing" : "2. AI Engine & Phishing Detection"}
              </h3>
              <p className="text-[11px] text-slate-500">Random Forest (94,8%) et analyse des 27 caractéristiques</p>
            </div>
          </div>

          <div className="space-y-4">
            
            {/* Toggle: ML Auto Block */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-sky-500" />
                  <span>Blocage automatique du Phishing (Score &gt; 70%)</span>
                </div>
                <p className="text-[11px] text-slate-500">Neutralise automatiquement les URLs confirmées malveillantes</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('ml_auto_block_phishing')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.ml_auto_block_phishing ? 'bg-sky-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

            {/* Toggle: Shannon Entropy */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-indigo-500" />
                  <span>Détection d'Entropie de Shannon (Domaines DGA)</span>
                </div>
                <p className="text-[11px] text-slate-500">Repère les domaines aléatoires générés automatiquement par les botnets</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('shannon_entropy_detection')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.shannon_entropy_detection ? 'bg-sky-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

            {/* Toggle: Threat Intel */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-purple-500" />
                  <span>Corrélation Threat Intel (VirusTotal & Safe Browsing)</span>
                </div>
                <p className="text-[11px] text-slate-500">Interroge les bases de réputation mondiales en direct</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('external_threat_intel')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.external_threat_intel ? 'bg-sky-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

          </div>
        </div>

        {/* ── SECTION 3 : PARE-FEU WAF & DÉFENSE RÉSEAU ── */}
        <div className="p-6 bg-white dark:bg-[#111726] border border-rose-500/30 rounded-3xl space-y-5 shadow-sm">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100 dark:border-slate-800">
            <span className="p-2 rounded-xl bg-rose-500/10 text-rose-600 dark:text-rose-400">
              <Shield className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono">
                {lang === 'fr' ? "3. Pare-Feu WAF & Défense Active" : "3. WAF Firewall & Active Defense"}
              </h3>
              <p className="text-[11px] text-slate-500">Protection contre 16 familles d'attaques web (SQLi, XSS, etc.)</p>
            </div>
          </div>

          <div className="space-y-4">
            
            {/* Toggle: Auto-ban IP */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Ban className="w-3.5 h-3.5 text-rose-500" />
                  <span>Bannissement IP automatique sur attaque critique</span>
                </div>
                <p className="text-[11px] text-slate-500">Ajoute immédiatement l'IP assaillante à la liste noire du pare-feu</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('waf_autoban_hostile_ips')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.waf_autoban_hostile_ips ? 'bg-rose-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

            {/* Toggle: Honeypots */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-amber-500" />
                  <span>Leurres Honeypot Actifs (/wp-login.php, /.env)</span>
                </div>
                <p className="text-[11px] text-slate-500">Attire et piège les scanners automatisés pour bloquer leur IP</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('honeypot_active_defense')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.honeypot_active_defense ? 'bg-rose-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

          </div>
        </div>

        {/* ── SECTION 4 : SENTINELLE TEMPS RÉEL & FORENSIQUE ── */}
        <div className="p-6 bg-white dark:bg-[#111726] border border-purple-500/30 rounded-3xl space-y-5 shadow-sm">
          <div className="flex items-center gap-2.5 pb-3 border-b border-slate-100 dark:border-slate-800">
            <span className="p-2 rounded-xl bg-purple-500/10 text-purple-600 dark:text-purple-400">
              <Radio className="w-5 h-5" />
            </span>
            <div>
              <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono">
                {lang === 'fr' ? "4. Sentinelle de Navigation & Forensique" : "4. Real-Time Sentinel & Forensics"}
              </h3>
              <p className="text-[11px] text-slate-500">Inspection en direct et scellement d'intégrité de la preuve</p>
            </div>
          </div>

          <div className="space-y-4">
            
            {/* Toggle: Sentinel */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Radio className="w-3.5 h-3.5 text-purple-500" />
                  <span>Protection Sentinelle en temps réel (Background)</span>
                </div>
                <p className="text-[11px] text-slate-500">Surveille les URLs ouvertes et analyse en mémoire vive (&lt; 15 ms)</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('sentinel_realtime_protection')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.sentinel_realtime_protection ? 'bg-purple-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

            {/* Toggle: Audio Chimes */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <Volume2 className="w-3.5 h-3.5 text-amber-500" />
                  <span>Signaux audio d'alerte lors de la détection</span>
                </div>
                <p className="text-[11px] text-slate-500">Joue un signal sonore haute-fréquence lors d'une interception</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('audio_alert_chimes')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.audio_alert_chimes ? 'bg-purple-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

            {/* Toggle: SHA-256 */}
            <div className="flex items-center justify-between p-3.5 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
              <div className="space-y-0.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Scellement Forensique SHA-256 des rapports</span>
                </div>
                <p className="text-[11px] text-slate-500">Garantit la chaîne de traçabilité immuable pour les enquêtes judiciaires</p>
              </div>
              <button
                type="button"
                onClick={() => toggleSetting('sha256_forensic_sealing')}
                className={`w-12 h-7 rounded-full p-1 transition-colors flex items-center cursor-pointer shrink-0 ${
                  settings.sha256_forensic_sealing ? 'bg-purple-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                }`}
              >
                <div className="w-5 h-5 rounded-full bg-white shadow-md" />
              </button>
            </div>

          </div>
        </div>

         {/* ── SECTION 5 : AGENT SYSTÈME ── */}
        <AgentCard lang={lang} />

        {/* ── SECTION 6 : SITES BLOQUÉS DANS LES PARAMÈTRES (LISTE NOIRE DE L'ORGANISATION) ── */}
        <div className="lg:col-span-2 p-6 bg-white dark:bg-[#111726] border border-rose-500/30 rounded-3xl space-y-5 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800 gap-3">
            <div className="flex items-center gap-2.5">
              <span className="p-2 rounded-xl bg-rose-500/10 text-rose-600 dark:text-rose-400">
                <Ban className="w-5 h-5" />
              </span>
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono">
                  {lang === 'fr' ? "6. Sites Bloqués dans les Paramètres (Liste Noire de l'Organisation)" : "6. Blocked Sites in Settings (Organization Blacklist)"}
                </h3>
                <p className="text-[11px] text-slate-500">
                  {lang === 'fr' 
                    ? "Ces sites sont interdits dans la politique globale et peuvent être assignés individuellement aux utilisateurs."
                    : "These sites are banned in global policy and can be specifically assigned to individual users."}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-rose-500/10 text-rose-500 border border-rose-500/30">
                {(settings.custom_blacklist || []).length} {lang === 'fr' ? 'Site(s) Bloqué(s)' : 'Blocked Site(s)'}
              </span>
            </div>
          </div>

          {/* Quick-add suggestions */}
          <div className="space-y-2">
            <span className="text-[10px] uppercase font-mono font-bold text-slate-400 block">
              {lang === 'fr' ? 'Ajout rapide en 1 clic (Sites les plus fréquents) :' : 'Quick 1-click presets:'}
            </span>
            <div className="flex flex-wrap gap-1.5">
              {[
                { label: 'Facebook', domain: 'facebook.com' },
                { label: 'TikTok', domain: 'tiktok.com' },
                { label: 'Instagram', domain: 'instagram.com' },
                { label: 'Twitter / X', domain: 'x.com' },
                { label: 'YouTube', domain: 'youtube.com' },
                { label: 'Netflix', domain: 'netflix.com' },
                { label: '1xBet', domain: '1xbet.com' },
                { label: 'Betway', domain: 'betway.com' }
              ].map(({ label, domain }) => {
                const isAlready = (settings.custom_blacklist || []).includes(domain);
                return (
                  <button
                    key={domain}
                    type="button"
                    onClick={() => isAlready ? removeBlacklistDomain(domain) : addBlacklistDomain(domain)}
                    className={`px-2.5 py-1 rounded-xl text-xs font-mono font-bold border transition flex items-center gap-1.5 cursor-pointer ${
                      isAlready 
                        ? 'bg-rose-500/15 border-rose-500/40 text-rose-600 dark:text-rose-400' 
                        : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-rose-400'
                    }`}
                  >
                    <span>{isAlready ? '✓' : '+'}</span>
                    <span>{label}</span>
                    <span className="text-[10px] text-slate-400">({domain})</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Custom domain input */}
          <div className="flex gap-2">
            <input
              type="text"
              value={newBlacklistDomain}
              onChange={(e) => setNewBlacklistDomain(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addBlacklistDomain(); } }}
              placeholder={lang === 'fr' ? "Entrez un domaine à interdire (ex: reddit.com, telegram.org)..." : "Enter a domain to block (e.g. reddit.com)..."}
              className="flex-1 px-3.5 py-2.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-white focus:outline-none focus:border-rose-500 font-mono"
            />
            <button
              type="button"
              onClick={() => addBlacklistDomain()}
              className="px-4 py-2.5 bg-rose-500 hover:bg-rose-600 text-white rounded-xl text-xs font-bold transition flex items-center gap-1.5 cursor-pointer shadow-md shadow-rose-500/20"
            >
              <Plus className="w-4 h-4" />
              <span>{lang === 'fr' ? 'Bloquer ce site' : 'Block this site'}</span>
            </button>
          </div>

          {/* Grid of currently blocked domains */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 max-h-60 overflow-y-auto pt-1">
            {(settings.custom_blacklist || []).length === 0 ? (
              <div className="col-span-full py-6 text-center text-xs text-slate-400 font-mono bg-slate-50/50 dark:bg-slate-800/30 rounded-2xl border border-dashed border-slate-200 dark:border-slate-800">
                {lang === 'fr' 
                  ? "Aucun domaine spécifique bloqué dans la liste personnalisée. Cliquez sur les suggestions ci-dessus ou ajoutez un domaine."
                  : "No custom domains blocked yet. Click the presets above or enter a domain."}
              </div>
            ) : (
              (settings.custom_blacklist || []).map((dom) => (
                <div key={dom} className="flex items-center justify-between px-3 py-2 rounded-xl bg-rose-500/5 dark:bg-rose-950/20 border border-rose-500/20 text-xs font-mono">
                  <span className="font-bold text-slate-900 dark:text-white flex items-center gap-2 truncate">
                    <Ban className="w-3 h-3 text-rose-500 shrink-0" />
                    <span className="truncate">{dom}</span>
                  </span>
                  <button
                    type="button"
                    onClick={() => removeBlacklistDomain(dom)}
                    className="p-1 text-slate-400 hover:text-rose-500 transition cursor-pointer"
                    title={lang === 'fr' ? 'Débloquer' : 'Unblock'}
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

      </div>

    </div>
  );
}

function AgentCard({ lang }) {
  const [status, setStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const fr = lang === 'fr';

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [s, e] = await Promise.all([
          fetch('/api/v1/enterprise/agent/status').then(r => r.json()),
          fetch('/api/v1/enterprise/agent/events?limit=8').then(r => r.json()),
        ]);
        if (alive) { setStatus(s); setEvents(e.events || []); }
      } catch (err) { if (alive) setStatus(null); }
    };
    load();
    const t = setInterval(load, 5000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const online = !!status?.online;
  const st = status?.stats || {};
  const counters = [
    [fr ? 'Requêtes DNS' : 'DNS queries', st.dns_queries || 0],
    [fr ? 'DNS bloquées' : 'DNS blocked', st.dns_blocked || 0],
    [fr ? 'Requêtes proxy' : 'Proxy requests', st.proxy_requests || 0],
    [fr ? 'Proxy bloquées' : 'Proxy blocked', st.proxy_blocked || 0],
  ];

  return (
    <div className="lg:col-span-2 p-6 bg-white dark:bg-[#111726] border border-emerald-500/30 rounded-3xl space-y-5 shadow-sm">
      <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800">
        <div className="flex items-center gap-2.5">
          <span className="p-2 rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"><Globe className="w-5 h-5" /></span>
          <div>
            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase font-mono">
              {fr ? "5. Agent Système (DNS + Proxy)" : "5. System Agent (DNS + Proxy)"}
            </h3>
            <p className="text-[11px] text-slate-500">
              {fr ? "Protège toute la machine, même sans l'extension" : "Protects the whole machine, even without the extension"}
            </p>
          </div>
        </div>
        <span className={`px-3 py-1 rounded-full text-[11px] font-mono font-bold border ${online ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30' : 'bg-slate-500/10 text-slate-500 border-slate-500/30'}`}>
          {online ? (fr ? '● EN LIGNE' : '● ONLINE') : (fr ? '○ HORS LIGNE' : '○ OFFLINE')}
        </span>
      </div>

      {!online && (
        <p className="text-xs text-slate-500 font-mono">
          {fr ? 'Lancez en administrateur : ' : 'Run as Administrator: '}<code>agent\run_agent.bat</code>
        </p>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {counters.map(([label, val]) => (
          <div key={label} className="p-3 rounded-2xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800">
            <div className="text-xl font-black text-slate-900 dark:text-white">{val}</div>
            <div className="text-[11px] text-slate-500">{label}</div>
          </div>
        ))}
      </div>

      <div className="space-y-2">
        {events.length === 0 && <p className="text-xs text-slate-500">{fr ? 'Aucun blocage récent.' : 'No recent blocks.'}</p>}
        {events.map((ev, i) => (
          <div key={i} className="flex items-center justify-between gap-3 p-2.5 rounded-xl bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 text-[11px] font-mono">
            <span className="text-rose-500 font-bold shrink-0">{ev.via}</span>
            <span className="truncate flex-1 text-slate-800 dark:text-slate-200">{ev.host}</span>
            <span className="text-slate-500 truncate max-w-[40%]">{ev.category}</span>
            <span className="text-slate-400 shrink-0">{(ev.ts || '').slice(11)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
