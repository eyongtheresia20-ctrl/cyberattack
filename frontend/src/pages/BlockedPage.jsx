import React from 'react';
import { useLocation, Link, useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, Lock, ArrowLeft, AlertTriangle, CheckCircle2, 
  HelpCircle, ExternalLink, RefreshCw, Eye, Shield, Globe, Terminal
} from 'lucide-react';
import { useLanguage } from '../context/LanguageContext';
import CyberGuardLogo from '../components/CyberGuardLogo';

export default function BlockedPage() {
  const { lang } = useLanguage();
  const location = useLocation();
  const navigate = useNavigate();

  // Extract query params: ?url=...&category=...&reason=...
  const queryParams = new URLSearchParams(location.search);
  const blockedUrl = queryParams.get('url') || 'https://site-restreint-detecte.com';
  const category = queryParams.get('category') || (lang === 'fr' ? 'CONTENU ADULTE RESTREINT' : 'ADULT CONTENT RESTRICTED');
  const reason = queryParams.get('reason') || (lang === 'fr' 
    ? "Accès interdit par la politique de sécurité et de contrôle parental du MINESEC."
    : "Access prohibited under MINESEC security and parental filtering policy.");
  const policyId = queryParams.get('policy') || 'SEC-MINESEC-POL-04';

  const isAdult = category.toLowerCase().includes('adulte') || category.toLowerCase().includes('adult');
  const isGambling = category.toLowerCase().includes('argent') || category.toLowerCase().includes('casino') || category.toLowerCase().includes('gambling');
  const isPhishing = category.toLowerCase().includes('phishing') || category.toLowerCase().includes('malveillant');

  return (
    <div className="min-h-screen bg-[#090d16] text-white flex flex-col justify-between selection:bg-rose-500 selection:text-white font-sans relative overflow-hidden">
      
      {/* Background Cyber Tech Grid Effect */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(225,29,72,0.25),rgba(255,255,255,0))] pointer-events-none" />
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1f293d15_1px,transparent_1px),linear-gradient(to_bottom,#1f293d15_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] pointer-events-none" />

      {/* Header */}
      <header className="relative z-10 px-6 py-6 border-b border-rose-500/20 bg-[#0c121f]/80 backdrop-blur-md flex items-center justify-between">
        <div className="flex items-center gap-3">
          <CyberGuardLogo size="md" className="[&_span]:text-white" />
          <span className="hidden sm:inline-block px-2.5 py-1 rounded-full text-[10px] font-mono font-black uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/40">
            {lang === 'fr' ? 'PARE-FEU ACTIF' : 'FIREWALL ACTIVE'}
          </span>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Lock className="w-3.5 h-3.5 text-rose-400" />
          <span>POLITIQUE : {policyId}</span>
        </div>
      </header>

      {/* Main Block Hero Card */}
      <main className="relative z-10 max-w-3xl mx-auto px-6 py-12 flex-1 flex flex-col justify-center items-center text-center space-y-8">
        
        {/* Animated Warning Shield Icon */}
        <div className="relative">
          <div className="w-24 h-24 rounded-3xl bg-gradient-to-tr from-rose-600 via-red-600 to-amber-600 flex items-center justify-center text-white shadow-2xl shadow-rose-600/40 animate-pulse">
            <ShieldAlert className="w-12 h-12" />
          </div>
          <div className="absolute -bottom-2 -right-2 p-2 rounded-xl bg-slate-900 border border-rose-500 text-rose-400">
            <Lock className="w-4 h-4" />
          </div>
        </div>

        {/* Title & Badge */}
        <div className="space-y-3">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-mono font-bold uppercase tracking-widest bg-rose-500/20 text-rose-400 border border-rose-500/40">
            <span>⛔ {lang === 'fr' ? "ACCÈS PHYSIQUEMENT INTERDIT" : "ACCESS STRICTLY BLOCKED"}</span>
          </div>

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight text-white">
            {isAdult 
              ? (lang === 'fr' ? "Contenu Adulte & Explicite Bloqué" : "Adult & Explicit Content Blocked")
              : (isGambling 
                  ? (lang === 'fr' ? "Site de Jeux d'Argent & Paris Bloqué" : "Gambling & Betting Site Blocked")
                  : (lang === 'fr' ? "Site Malveillant Neutralisé" : "Malicious Cyber Threat Neutralized"))}
          </h1>

          <p className="text-slate-400 text-sm sm:text-base max-w-xl mx-auto leading-relaxed">
            {lang === 'fr'
              ? "Cette ressource a été interceptée par le pare-feu CyberGuard SOC. L'accès à ce domaine est formellement restreint conformément aux directives de protection du réseau éducatif."
              : "This target was intercepted by CyberGuard SOC firewall. Access to this domain is strictly restricted in compliance with institutional educational protection directives."}
          </p>
        </div>

        {/* Technical Target Details Box */}
        <div className="w-full bg-[#111726]/90 border border-rose-500/30 rounded-2xl p-5 text-left font-mono space-y-3 shadow-xl backdrop-blur-md">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-xs text-slate-400 uppercase tracking-wider font-bold flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-rose-400" />
              {lang === 'fr' ? "Cible Interceptée" : "Intercepted Target"}
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold uppercase">
              {category}
            </span>
          </div>

          <div className="text-xs text-rose-300 break-all bg-black/40 p-2.5 rounded-xl border border-rose-950/60 font-mono">
            {blockedUrl}
          </div>

          <div className="text-xs text-slate-300 space-y-1 pt-1">
            <div className="text-slate-400 text-[11px] font-bold uppercase">
              {lang === 'fr' ? "Motif de restriction :" : "Restriction Reason:"}
            </div>
            <div className="text-slate-200 text-xs">
              {reason}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-[10px] text-slate-400">
            <span>Règle : MINESEC-POLICY-BLOCK-01</span>
            <span>Statut : Code 403 Forbidden</span>
            <span>Horodatage : {new Date().toLocaleTimeString()}</span>
          </div>
        </div>

        {/* Navigation Action Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
          <button
            type="button"
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-bold text-xs sm:text-sm shadow-lg shadow-sky-500/20 transition cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>{lang === 'fr' ? "Retourner en lieu sûr (Dashboard)" : "Return to Safe Dashboard"}</span>
          </button>

          <Link
            to="/scanner"
            className="flex items-center gap-2 px-6 py-3 rounded-xl border border-slate-700 hover:border-slate-500 bg-[#151c2c] text-slate-200 hover:text-white font-bold text-xs sm:text-sm transition shadow-sm"
          >
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span>{lang === 'fr' ? "Analyser une autre URL" : "Scan Another URL"}</span>
          </Link>
        </div>

      </main>

      {/* Footer */}
      <footer className="relative z-10 px-6 py-4 border-t border-slate-800 text-center text-xs text-slate-500 font-mono">
        © 2026 CyberGuard SOC — Ministère des Enseignements Secondaires (MINESEC). Tous droits réservés.
      </footer>

    </div>
  );
}
