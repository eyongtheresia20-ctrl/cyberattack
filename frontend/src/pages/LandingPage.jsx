/**
 * ========================================================================================
 * CYBERGUARD SOC — PAGE D'ACCUEIL VITRINE (LANDING PAGE - ROUTE: /)
 * ========================================================================================
 * 📍 CORRESPONDANCE DANS LE RAPPORT :
 * Cette interface correspond exactement à la FIGURE 39 : "Page d'accueil" (Page 106).
 * 
 * 📌 RÔLE DE CETTE INTERFACE :
 * 1. Présenter la mission de la plateforme de cybersécurité CyberGuard aux visiteurs.
 * 2. Permettre l'accès rapide aux formulaires d'authentification ("Se Connecter" / "S'inscrire").
 * 3. Permettre le basculement dynamique du thème (Clair / Sombre) et de la langue (FR / EN).
 * 4. Présenter les piliers technologiques : Scanner IA, NLP, WAF, Forensique SHA-256.
 * ========================================================================================
 */

import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe, MessageSquare, ShieldCheck, FileSearch, MapPin,
  Sun, Moon, Lock, Zap,
  ChevronLeft, ChevronRight,
  X, CheckCircle2, LayoutDashboard, Shield, FileText, Bot, Terminal, Mail, Info
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import { useLanguage } from '../context/LanguageContext';
import CyberGuardLogo from '../components/CyberGuardLogo';

export default function LandingPage() {
  // États globaux : Thème (Sombre/Clair) et Langue (Français/Anglais)
  const { isDark, toggle: toggleTheme } = useTheme();
  const { lang, toggle: toggleLang, t } = useLanguage();
  const [startIndex, setStartIndex] = useState(0);
  const [activeModalKey, setActiveModalKey] = useState(null);

  // --------------------------------------------------------------------------------------
  // SECTION 1 : DICTIONNAIRE DES MODALES D'INFORMATION SOC (Contenu bilingue au clic)
  // --------------------------------------------------------------------------------------
  const footerModalData = {
    footer_soc_dash: {
      category: lang === 'fr' ? 'Plateforme' : 'Platform',
      title: lang === 'fr' ? 'Tableau de bord SOC' : 'SOC Dashboard',
      icon: LayoutDashboard,
      desc: lang === 'fr'
        ? "Le centre des opérations de sécurité (SOC) offre une vue globale en direct des cyberattaques web, de la répartition par type d'attaque, des niveaux de sévérité et du flux des incidents récents."
        : "The Security Operations Center (SOC) provides a live bird's-eye overview of web cyberattacks, attack distribution, severity levels, and recent incident streams.",
      highlights: lang === 'fr'
        ? [
            "Surveillance du trafic et des requêtes suspectes en continu",
            "Indicateurs clés de performance de sécurité (KPI SOC)",
            "Visualisation graphique des attaques web en temps réel"
          ]
        : [
            "Continuous monitoring of traffic and suspicious requests",
            "Key security operations performance indicators (SOC KPIs)",
            "Real-time graphical visualization of web cyber threats"
          ]
    },
    footer_url_scan: {
      category: lang === 'fr' ? 'Plateforme' : 'Platform',
      title: lang === 'fr' ? "Scanner d'URL" : "URL Threat Scanner",
      icon: Globe,
      desc: lang === 'fr'
        ? "Moteur d'inspection d'URL combinant un modèle Machine Learning Random Forest entraîné sur plus de 15 caractéristiques lexicales, structurelles et d'entropie, enrichi par des vérifications de réputation externes."
        : "Multi-factor URL inspection engine combining a Random Forest Machine Learning model trained on 15+ lexical, structural, and entropy features with reputation threat intelligence.",
      highlights: lang === 'fr'
        ? [
            "Classification Random Forest à 94,8% de précision",
            "Calcul d'entropie de Shannon et détection d'obfuscation",
            "Interrogation VirusTotal & Google Safe Browsing"
          ]
        : [
            "Random Forest classifier with 94.8% accuracy",
            "Shannon entropy calculation and obfuscation detection",
            "VirusTotal & Google Safe Browsing query feeds"
          ]
    },
    footer_sms_email: {
      category: lang === 'fr' ? 'Plateforme' : 'Platform',
      title: lang === 'fr' ? "Analyse SMS & Email" : "SMS & Email NLP Analysis",
      icon: MessageSquare,
      desc: lang === 'fr'
        ? "Pipeline de Traitement du Langage Naturel (NLP) avec vectorisation TF-IDF, spécialisé dans la détection d'ingénierie sociale, de pression d'urgence, de faux avertissements bancaires et d'usurpation."
        : "Natural Language Processing (NLP) pipeline utilizing TF-IDF vectorization, specialized in detecting social engineering, urgency pressure, fraudulent banking warnings, and identity theft.",
      highlights: lang === 'fr'
        ? [
            "Détection des modèles linguistiques de phishing et smishing",
            "Contrôle de validation des enregistrements SPF, DKIM et DMARC",
            "Calcul du score de risque psychologique et manipulations"
          ]
        : [
            "Phishing and smishing linguistic pattern detection",
            "SPF, DKIM, and DMARC record validation checks",
            "Psychological urgency and manipulation risk scoring"
          ]
    },
    footer_waf: {
      category: lang === 'fr' ? 'Plateforme' : 'Platform',
      title: lang === 'fr' ? "Moniteur d'attaques web" : "Web Attack Monitor",
      icon: ShieldCheck,
      desc: lang === 'fr'
        ? "Système d'ingestion et de classification de logs de Pare-feu Applicatif Web (WAF) analysant les requêtes HTTP suspectes contre 16 familles d'attaques critiques."
        : "Web Application Firewall (WAF) log ingestion and classification system analyzing suspicious HTTP queries across 16 critical cyber attack families.",
      highlights: lang === 'fr'
        ? [
            "Classification automatique SQLi, XSS, Path Traversal, Brute Force",
            "Détection des tentatives de contournement et encodages anormaux",
            "Journalisation enrichie avec horodatage et code réponse HTTP"
          ]
        : [
            "Automated SQLi, XSS, Path Traversal, and Brute Force classification",
            "Bypass attempt identification and anomalous character encodings",
            "Enriched logging with accurate timestamp and HTTP status codes"
          ]
    },
    footer_incidents: {
      category: lang === 'fr' ? 'Fonctionnalité' : 'Feature',
      title: lang === 'fr' ? 'Incidents & Preuves' : 'Incidents & Evidence Ledger',
      icon: FileSearch,
      desc: lang === 'fr'
        ? "Registre forensique numérique garantissant la chaîne de traçabilité des preuves collectées et la génération de rapports d'incident officiels."
        : "Digital forensic ledger ensuring chain-of-custody preservation for gathered digital evidence and official security incident report generation.",
      highlights: lang === 'fr'
        ? [
            "Scellement cryptographique des preuves avec empreinte SHA-256",
            "Gestion des statuts d'enquête et assignation des analystes",
            "Export de procès-verbaux d'incident au format standardisé"
          ]
        : [
            "Cryptographic SHA-256 evidence item sealing",
            "Investigation lifecycle status management and analyst assignment",
            "Standardized formal incident report export"
          ]
    },
    footer_investigator: {
      category: lang === 'fr' ? 'Fonctionnalité' : 'Feature',
      title: lang === 'fr' ? 'Portail investigateur' : 'Investigator Portal',
      icon: Shield,
      desc: lang === 'fr'
        ? "Espace de vérification indépendant permettant aux auditeurs et autorités judiciaires de vérifier qu'un rapport ou une preuve n'a subi aucune falsification."
        : "Independent verification workspace allowing auditors and authorities to certify that a security report or evidence has undergone zero tampering.",
      highlights: lang === 'fr'
        ? [
            "Recalcul automatique du condensat SHA-256 en mémoire",
            "Confrontation instantanée avec le registre de base immuable",
            "Attestation de validité ou alerte immédiate d'altération"
          ]
        : [
            "Automated in-memory SHA-256 digest recalculation",
            "Instant verification against immutable database records",
            "Tamper-proof certification badge or alert upon discrepancy"
          ]
    },
    footer_ai: {
      category: lang === 'fr' ? 'Fonctionnalité' : 'Feature',
      title: lang === 'fr' ? 'Conseiller IA sécurité' : 'AI Security Advisor',
      icon: Bot,
      desc: lang === 'fr'
        ? "Assistant conversationnel spécialisé dans la cyberdéfense, fournissant des directives de remédiation étape par étape et des conseils de durcissement système."
        : "Conversational assistant specialized in cyber defense, providing step-by-step remediation procedures and system hardening guidance.",
      highlights: lang === 'fr'
        ? [
            "Recommandations de correctifs de code (requêtes préparées, encodage)",
            "Guides de configuration WAF, Nginx, Apache et en-têtes HTTP",
            "Sensibilisation interactive aux tactiques d'ingénierie sociale"
          ]
        : [
            "Code patch guidelines (parameterized queries, contextual escaping)",
            "WAF, Nginx, Apache, and HTTP security header hardening configs",
            "Interactive awareness on social engineering threat patterns"
          ]
    },
    footer_geoip: {
      category: lang === 'fr' ? 'Fonctionnalité' : 'Feature',
      title: lang === 'fr' ? 'Traçage GeoIP' : 'GeoIP Threat Tracing',
      icon: MapPin,
      desc: lang === 'fr'
        ? "Module de géolocalisation et de contextualisation des adresses IP assaillantes avec identification de l'ASN, de l'opérateur et détection de mandataires d'anonymisation."
        : "Adversary IP geolocation and contextualization module resolving country, city, ASN, ISP, and identifying anonymizing proxies.",
      highlights: lang === 'fr'
        ? [
            "Localisation géographique instantanée des adresses IP",
            "Détection des réseaux Proxy, VPN et nœuds de sortie anonymes",
            "Corrélation d'attaques par zone géographique"
          ]
        : [
            "Instant geographic localization of suspicious IPs",
            "Detection of Proxy, VPN, and anonymous exit nodes",
            "Geographic threat correlation and origin clustering"
          ]
    },
    footer_privacy: {
      category: lang === 'fr' ? 'Légal' : 'Legal',
      title: lang === 'fr' ? 'Politique de confidentialité' : 'Privacy Policy',
      icon: FileText,
      desc: lang === 'fr'
        ? "CyberGuard respecte scrupuleusement la confidentialité des données traitées. Les analyses soumises ne sont jamais revendues, et les données sensibles ou identifiants personnels sont purgés lors des traitements d'inférence."
        : "CyberGuard strictly respects data privacy. Submitted analyses are never monetized, and sensitive personal identifiers are scrubbed during ML inference.",
      highlights: lang === 'fr'
        ? [
            "Chiffrement de bout en bout des communications et des jetons d'accès",
            "Purge automatique des données de test et politiques de rétention strictes",
            "Conformité avec les principes du RGPD et de minimisation des données"
          ]
        : [
            "End-to-end encryption for API traffic and authentication tokens",
            "Automated test data purging and strict retention policies",
            "Compliance with GDPR principles and data minimization"
          ]
    },
    footer_terms: {
      category: lang === 'fr' ? 'Légal' : 'Legal',
      title: lang === 'fr' ? "Conditions d'utilisation" : "Terms of Service",
      icon: Shield,
      desc: lang === 'fr'
        ? "La plateforme CyberGuard est mise à disposition à des fins d'analyse défensive, de protection des systèmes informatiques et de travaux de recherche académique autorisés."
        : "The CyberGuard platform is provided for defensive analysis, IT system protection, and authorized academic threat research.",
      highlights: lang === 'fr'
        ? [
            "Interdiction formelle d'utilisation à des fins d'attaque ou de nuisance",
            "Obligation d'obtenir l'accord des propriétaires avant tout scan de serveur tiers",
            "Responsabilité limitée aux contextes de supervision déclarés"
          ]
        : [
            "Strict prohibition of offensive exploitation or malicious disruption",
            "Mandatory authorization from target owners prior to server scanning",
            "Liability limited to authorized and defensive supervision scopes"
          ]
    },
    footer_research: {
      category: lang === 'fr' ? 'Légal' : 'Legal',
      title: lang === 'fr' ? 'Recherche en sécurité' : 'Security Research',
      icon: Terminal,
      desc: lang === 'fr'
        ? "Nous soutenons la recherche en cybersécurité et la divulgation responsable des vulnérabilités (Vulnerability Disclosure Program / Safe Harbor)."
        : "We actively support academic cybersecurity research and coordinated vulnerability disclosure (Safe Harbor principles).",
      highlights: lang === 'fr'
        ? [
            "Signalement éthique des anomalies et faux positifs",
            "Partage académique des méthodologies et jeux de données d'apprentissage",
            "Amélioration continue de la résilience des algorithmes d'IA"
          ]
        : [
            "Ethical reporting of security anomalies and false positives",
            "Academic sharing of training methodologies and feature datasets",
            "Continuous resilience enhancement of detection algorithms"
          ]
    },
    footer_contact: {
      category: lang === 'fr' ? 'Légal' : 'Legal',
      title: lang === 'fr' ? 'Nous contacter' : 'Contact Us',
      icon: Mail,
      desc: lang === 'fr'
        ? "Besoin d'informations complémentaires, de signaler un incident de sécurité urgent ou d'obtenir un accompagnement technique ? L'équipe CyberGuard est à votre écoute."
        : "Need additional information, urgent security incident reporting, or technical support? The CyberGuard team is at your service.",
      highlights: lang === 'fr'
        ? [
            "Email du support : support@cyberguard.security",
            "Signalement incident SOC : soc-emergency@cyberguard.security",
            "Recherche & partenariats : research@cyberguard.security"
          ]
        : [
            "Support Email: support@cyberguard.security",
            "SOC Incident Reporting: soc-emergency@cyberguard.security",
            "Research & Partnerships: research@cyberguard.security"
          ]
    }
  };

  const modalData = activeModalKey ? footerModalData[activeModalKey] : null;
  const ModalIcon = modalData ? modalData.icon : Info;


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
                'footer_soc_dash',
                'footer_url_scan',
                'footer_sms_email',
                'footer_waf',
              ].map((key) => (
                <li key={key}>
                  <button
                    type="button"
                    onClick={() => setActiveModalKey(key)}
                    className="hover:text-sky-400 transition text-left cursor-pointer focus:outline-none focus:text-sky-300"
                  >
                    {t(key)}
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* Features */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-widest">{t('footer_features')}</h4>
            <ul className="space-y-2 text-xs">
              {[
                'footer_incidents',
                'footer_investigator',
                'footer_ai',
                'footer_geoip',
              ].map((key) => (
                <li key={key}>
                  <button
                    type="button"
                    onClick={() => setActiveModalKey(key)}
                    className="hover:text-sky-400 transition text-left cursor-pointer focus:outline-none focus:text-sky-300"
                  >
                    {t(key)}
                  </button>
                </li>
              ))}
            </ul>
          </div>

          {/* Legal */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-widest">{t('footer_legal')}</h4>
            <ul className="space-y-2 text-xs">
              {[
                'footer_privacy',
                'footer_terms',
                'footer_research',
                'footer_contact',
              ].map((key) => (
                <li key={key}>
                  <button
                    type="button"
                    onClick={() => setActiveModalKey(key)}
                    className="hover:text-sky-400 transition text-left cursor-pointer focus:outline-none focus:text-sky-300"
                  >
                    {t(key)}
                  </button>
                </li>
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

      {/* ===== FOOTER INFO / LEGAL MODAL ===== */}
      {modalData && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-in fade-in duration-200"
          onClick={() => setActiveModalKey(null)}
          role="dialog"
          aria-modal="true"
        >
          <div
            className="relative w-full max-w-lg bg-white dark:bg-[#161b27] border border-sky-100 dark:border-sky-900/60 rounded-2xl shadow-2xl p-6 sm:p-7 space-y-5 text-slate-900 dark:text-slate-100"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header: Badge & Close Button */}
            <div className="flex items-center justify-between">
              <span className="px-3 py-1 rounded-full text-xs font-bold bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 uppercase tracking-wider">
                {modalData.category}
              </span>
              <button
                type="button"
                onClick={() => setActiveModalKey(null)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                aria-label="Fermer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Title & Icon */}
            <div className="flex items-start gap-3.5">
              <div className="p-2.5 rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 shrink-0">
                <ModalIcon className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white">
                  {modalData.title}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  CyberGuard Platform Overview
                </p>
              </div>
            </div>

            {/* Description */}
            <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-300">
              {modalData.desc}
            </p>

            {/* Highlights List */}
            {modalData.highlights && modalData.highlights.length > 0 && (
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0f1520] border border-slate-100 dark:border-slate-800 space-y-2.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {lang === 'fr' ? 'Points clés & spécifications' : 'Key Specifications'}
                </h4>
                <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
                  {modalData.highlights.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-sky-500 shrink-0 mt-0.5" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end gap-3 pt-2 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setActiveModalKey(null)}
                className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
              >
                {lang === 'fr' ? 'Fermer' : 'Close'}
              </button>
              <Link
                to="/login"
                onClick={() => setActiveModalKey(null)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold bg-sky-500 hover:bg-sky-600 text-white transition shadow-sm"
              >
                <Lock className="w-3.5 h-3.5" />
                {lang === 'fr' ? 'Se connecter' : 'Sign In'}
              </Link>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
