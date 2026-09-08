import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe, MessageSquare, ShieldCheck, FileSearch, MapPin,
  Sun, Moon, Lock, Zap,
  ChevronLeft, ChevronRight
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useLanguage } from '../context/LanguageContext';
import CyberGuardLogo from '../components/CyberGuardLogo';

export default function LandingPage() {
  const { isDark, toggle: toggleTheme } = useTheme();
  const { lang, toggle: toggleLang, t } = useLanguage();
  const [startIndex, setStartIndex] = useState(0);

  const features = [
    {
      icon: Globe,
      title: lang === 'en' ? 'Phishing URL Detection' : 'Détection d\'URL de phishing',
      desc: lang === 'en'
        ? 'Random Forest ML engine analyzes 15+ lexical, structural, and domain-based features with 94.8% accuracy.'
        : 'Moteur ML Random Forest analysant 15+ caractéristiques lexicales, structurelles et de domaine avec 94,8% de précision.',
    },
    {
      icon: MessageSquare,
      title: lang === 'en' ? 'SMS & Email NLP Analysis' : 'Analyse NLP SMS & Email',
      desc: lang === 'en'
        ? 'Natural Language Processing detects urgency manipulation, extortion language, impersonation, and validates SPF/DKIM/DMARC.'
        : 'Le traitement du langage naturel détecte la manipulation d\'urgence, l\'extorsion, l\'usurpation d\'identité, et valide SPF/DKIM/DMARC.',
    },
    {
      icon: ShieldCheck,
      title: lang === 'en' ? 'WAF Attack Log Monitor' : 'Moniteur de logs WAF',
      desc: lang === 'en'
        ? 'Ingests HTTP access logs and classifies 16 attack vectors including SQLi, XSS, Path Traversal, Brute Force, and Log4j RCE.'
        : 'Ingère les logs HTTP et classifie 16 vecteurs d\'attaque : SQLi, XSS, Path Traversal, Force Brute, Log4j RCE.',
    },
    {
      icon: MapPin,
      title: lang === 'en' ? 'GeoIP Threat Tracing' : 'Traçage GeoIP des menaces',
      desc: lang === 'en'
        ? 'Resolves attacker IP to country, city, ASN, ISP, and detects Proxy/VPN anonymization in real time.'
        : 'Résout l\'IP de l\'attaquant en pays, ville, ASN, FAI et détecte l\'anonymisation Proxy/VPN en temps réel.',
    },
    {
      icon: Zap,
      title: lang === 'en' ? 'Ransomware Detection' : 'Détection de ransomware',
      desc: lang === 'en'
        ? 'Identifies ransomware dropper patterns (.crypto, .locked, .enc), extortion language, and malicious payload signatures.'
        : 'Identifie les schémas de droppers ransomware (.crypto, .locked, .enc), le langage d\'extorsion et les signatures malveillantes.',
    },
    {
      icon: FileSearch,
      title: lang === 'en' ? 'SHA-256 Evidence Reports' : 'Rapports d\'evidence SHA-256',
      desc: lang === 'en'
        ? 'Generates cryptographically hashed incident reports for investigator portal verification and chain-of-custody integrity.'
        : 'Génère des rapports d\'incidents signés cryptographiquement pour la vérification et l\'intégrité de la chaîne de traçabilité.',
    },
  ];

  const maxIndex = Math.max(0, features.length - 3);

  const prevSlide = () => {
    setStartIndex(prev => (prev > 0 ? prev - 1 : maxIndex));
  };

  const nextSlide = () => {
    setStartIndex(prev => (prev < maxIndex ? prev + 1 : 0));
  };

  const visibleFeatures = features.slice(startIndex, startIndex + 3);

  const navLinkClass = `text-sm font-semibold transition-colors text-slate-700 dark:text-slate-200 hover:text-sky-600 dark:hover:text-sky-400`;

  return (
    <div className="min-h-screen flex flex-col bg-[#f0f9ff] dark:bg-[#0d1117] text-slate-900 dark:text-slate-100 transition-colors duration-300">

      {/* ===== NAVBAR ===== */}
      <header className="sticky top-0 z-50 border-b border-sky-100 dark:border-sky-900/50 bg-white/90 dark:bg-[#161b27]/90 backdrop-blur-md shadow-xs">
        <div className="max-w-7xl mx-auto px-6 h-18 py-4 flex items-center justify-between gap-6">

          {/* Logo */}
          <Link to="/">
            <CyberGuardLogo size="md" />
          </Link>

          {/* Center Nav */}
          <nav className="hidden md:flex items-center gap-8">
            <Link to="/" className={navLinkClass + ' text-sky-600 dark:text-sky-400 border-b-2 border-sky-500 pb-0.5'}>
              {t('nav_home')}
            </Link>
            <a href="#about" className={navLinkClass}>{t('nav_about')}</a>
          </nav>

          {/* Controls */}
          <div className="flex items-center gap-3">
            <button
              onClick={toggleLang}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold border border-sky-200 dark:border-sky-800 bg-white dark:bg-[#1e2637] text-sky-700 dark:text-sky-300 hover:border-sky-400 transition shadow-xs"
            >
              <Globe className="w-3.5 h-3.5" />
              {lang === 'en' ? 'EN' : 'FR'}
            </button>

            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg border border-sky-200 dark:border-sky-800 bg-white dark:bg-[#1e2637] text-slate-700 dark:text-slate-200 hover:border-sky-400 transition shadow-xs"
              aria-label="Toggle theme"
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-600" />}
            </button>

            <Link
              to="/login"
              className="flex items-center gap-2 px-5 py-2 rounded-xl bg-sky-500 hover:bg-sky-600 text-white font-bold text-sm transition shadow-md shadow-sky-500/20"
            >
              <Lock className="w-4 h-4" />
              {t('nav_login')}
            </Link>
          </div>
        </div>
      </header>

      <main className="flex-1">

        {/* ===== HERO SECTION ===== */}
        <section
          className="relative overflow-hidden py-28 md:py-36 px-6 text-center bg-cover bg-center"
          style={{ backgroundImage: `url('/images/hero-defense.jpg')` }}
        >
          <div className="absolute inset-0 bg-gradient-to-b from-[#f0f9ff]/90 via-[#f0f9ff]/80 to-[#f0f9ff] dark:from-[#0d1117]/90 dark:via-[#0d1117]/85 dark:to-[#0d1117] pointer-events-none" />

          <div className="relative max-w-4xl mx-auto space-y-7">
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight leading-tight text-slate-900 dark:text-white drop-shadow-sm">
              {t('hero_title')}
            </h1>

            <p className="text-base sm:text-lg text-slate-700 dark:text-slate-200 max-w-2xl mx-auto leading-relaxed font-medium">
              {t('hero_subtitle')}
            </p>

            <div className="flex flex-wrap justify-center gap-4 pt-3">
              <a
                href="#about"
                className="flex items-center gap-2 px-7 py-3.5 rounded-xl border border-sky-300 dark:border-sky-700 text-sky-700 dark:text-sky-300 bg-white/90 dark:bg-[#161b27]/90 hover:bg-white dark:hover:bg-sky-500/10 font-bold text-sm sm:text-base transition shadow-sm backdrop-blur-sm"
              >
                {t('hero_cta_learn')}
              </a>
            </div>
          </div>
        </section>

        {/* ===== 3-CARD CAROUSEL SECTION ===== */}
        <section id="features" className="py-20 px-6 bg-white/60 dark:bg-[#0f1520] border-y border-sky-100 dark:border-sky-900/40">
          <div className="max-w-6xl mx-auto space-y-10">
            <div className="text-center space-y-2">
              <h2 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">
                {t('features_title')}
              </h2>
              <p className="text-slate-500 dark:text-slate-400 max-w-lg mx-auto text-xs sm:text-sm leading-relaxed">
                {t('features_sub')}
              </p>
            </div>

            {/* 3 Visible Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 transition-all duration-300">
              {visibleFeatures.map((feat, i) => {
                const Icon = feat.icon;
                return (
                  <div
                    key={startIndex + i}
                    className="p-7 rounded-2xl bg-white dark:bg-[#161b27] border border-sky-100 dark:border-sky-900/50 shadow-sm hover:shadow-md hover:border-sky-300 dark:hover:border-sky-500 transition-all space-y-4 group"
                  >
                    <div className="w-12 h-12 rounded-xl bg-sky-50 dark:bg-sky-500/10 border border-sky-200 dark:border-sky-500/30 flex items-center justify-center text-sky-600 dark:text-sky-400 group-hover:bg-sky-500 group-hover:text-white transition-colors">
                      <Icon className="w-6 h-6" />
                    </div>
                    <h3 className="font-bold text-base text-slate-900 dark:text-white">
                      {feat.title}
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                      {feat.desc}
                    </p>
                  </div>
                );
              })}
            </div>

            {/* Carousel Navigation */}
            <div className="flex items-center justify-center gap-6 pt-2">
              <button
                onClick={prevSlide}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-sky-200 dark:border-sky-800 bg-white dark:bg-[#1e2637] text-slate-700 dark:text-slate-300 hover:text-sky-600 dark:hover:text-sky-400 hover:border-sky-400 font-bold text-xs shadow-xs transition"
              >
                <ChevronLeft className="w-4 h-4" />
                {t('carousel_prev')}
              </button>

              <div className="flex items-center gap-2">
                {Array.from({ length: maxIndex + 1 }).map((_, idx) => (
                  <button
                    key={idx}
                    onClick={() => setStartIndex(idx)}
                    className={`rounded-full transition-all duration-300 ${
                      idx === startIndex
                        ? 'w-6 h-2 bg-sky-500'
                        : 'w-2 h-2 bg-sky-200 dark:bg-slate-700 hover:bg-sky-400'
                    }`}
                    aria-label={`Slide ${idx + 1}`}
                  />
                ))}
              </div>

              <button
                onClick={nextSlide}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl border border-sky-200 dark:border-sky-800 bg-white dark:bg-[#1e2637] text-slate-700 dark:text-slate-300 hover:text-sky-600 dark:hover:text-sky-400 hover:border-sky-400 font-bold text-xs shadow-xs transition"
              >
                {t('carousel_next')}
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </section>

        {/* ===== ABOUT SECTION ===== */}
        <section
          id="about"
          className="relative overflow-hidden py-28 md:py-36 px-6 bg-cover bg-center text-center"
          style={{ backgroundImage: `url('/images/about-clean.jpg')` }}
        >
          <div className="absolute inset-0 bg-gradient-to-b from-[#f0f9ff]/90 via-[#f0f9ff]/80 to-[#f0f9ff] dark:from-[#0d1117]/90 dark:via-[#0d1117]/85 dark:to-[#0d1117] pointer-events-none" />

          <div className="relative max-w-3xl mx-auto space-y-6">
            <div className="space-y-2">
              <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">
                {t('about_title')}
              </h2>
              <div className="w-12 h-1 rounded-full bg-sky-500 mx-auto" />
            </div>

            <p className="text-slate-800 dark:text-slate-100 text-base sm:text-lg leading-relaxed font-medium">
              {t('about_body')}
            </p>
          </div>
        </section>

      </main>

      {/* ===== FOOTER ===== */}
      <footer className="bg-slate-900 dark:bg-[#070b12] text-slate-400 border-t border-slate-800">
        <div className="max-w-7xl mx-auto px-6 py-14 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-10">

          {/* Brand */}
          <div className="space-y-4 lg:col-span-1">
            <CyberGuardLogo size="md" className="[&_span]:text-white" />
            <p className="text-xs leading-relaxed text-slate-400">{t('footer_desc')}</p>
          </div>

          {/* Platform */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-widest">{t('footer_platform')}</h4>
            <ul className="space-y-2 text-xs">
              {[
                { key: 'footer_soc_dash', to: '/dashboard' },
                { key: 'footer_url_scan', to: '/url-analysis' },
                { key: 'footer_sms_email', to: '/text-analysis' },
                { key: 'footer_waf', to: '/site-monitoring' },
              ].map((l) => (
                <li key={l.key}><Link to={l.to} className="hover:text-sky-400 transition">{t(l.key)}</Link></li>
              ))}
            </ul>
          </div>

          {/* Features */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-widest">{t('footer_features')}</h4>
            <ul className="space-y-2 text-xs">
              {[
                { key: 'footer_incidents', to: '/incidents' },
                { key: 'footer_investigator', to: '/verification' },
                { key: 'footer_ai', to: '/assistant' },
                { key: 'footer_geoip', to: '/site-monitoring' },
              ].map((l) => (
                <li key={l.key}><Link to={l.to} className="hover:text-sky-400 transition">{t(l.key)}</Link></li>
              ))}
            </ul>
          </div>

          {/* Legal */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-widest">{t('footer_legal')}</h4>
            <ul className="space-y-2 text-xs">
              {['footer_privacy', 'footer_terms', 'footer_research', 'footer_contact'].map((key) => (
                <li key={key}><a href="#" className="hover:text-sky-400 transition">{t(key)}</a></li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom bar — copyright only */}
        <div className="border-t border-slate-800 py-4 px-6">
          <div className="max-w-7xl mx-auto flex items-center justify-center text-xs">
            <p className="text-slate-500">{t('footer_copy')}</p>
          </div>
        </div>
      </footer>

    </div>
  );
}
