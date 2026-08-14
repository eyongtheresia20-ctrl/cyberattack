import React, { createContext, useContext, useState } from 'react';

const LanguageContext = createContext();

export const translations = {
  en: {
    nav_home: 'Home',
    nav_about: 'About',
    nav_login: 'Login',
    hero_title: 'Cyber Attack Detection Platform',
    hero_subtitle: 'Advanced AI-powered cybersecurity intelligence that detects phishing, malicious URLs, SQL injection, XSS, ransomware, social engineering, and more — in real time.',
    hero_cta: 'Access Platform',
    hero_cta_learn: 'Learn More',
    features_title: 'Platform Capabilities',
    features_sub: 'A complete cyber threat intelligence suite powered by Machine Learning and NLP.',
    about_title: 'About PhishGuard',
    about_body: 'PhishGuard is an advanced cyber attack detection platform built for security analysts and academic research. It combines a Random Forest Machine Learning engine, Natural Language Processing, and web application firewall log analysis to detect a wide spectrum of cyber threats — from URL phishing and SMS social engineering to SQL Injection, Cross-Site Scripting, Ransomware droppers, Brute Force attacks, and Zero-Day RCE exploits. The platform also performs GeoIP threat location tracing, ASN/Proxy detection, and generates SHA-256 cryptographically signed incident reports for forensic investigation.',
    footer_platform: 'Platform',
    footer_features: 'Features',
    footer_resources: 'Resources',
    footer_legal: 'Legal',
    footer_desc: 'Intelligent cyber threat and phishing intelligence platform powered by Machine Learning.',
    footer_copy: '© 2026 PhishGuard. All rights reserved.',
    login_title: 'Sign in to PhishGuard',
    login_sub: 'Enter your credentials to access the SOC platform',
    login_email: 'Email address',
    login_password: 'Password',
    login_btn: 'Sign In',
    login_no_account: "Don't have an account?",
    login_create: 'Create Account',
    login_forgot: 'Forgot password?',
    login_direct: 'Or access platform directly',
    register_title: 'Create your account',
    register_sub: 'Join the PhishGuard cybersecurity platform',
    register_name: 'Full Name',
    register_email: 'Email address',
    register_password: 'Password',
    register_confirm: 'Confirm Password',
    register_role: 'Role',
    register_role_analyst: 'Security Analyst',
    register_role_admin: 'Administrator',
    register_terms: 'I agree to the Terms of Service and Privacy Policy',
    register_btn: 'Create Account',
    register_have_account: 'Already have an account?',
    register_signin: 'Sign In',
  },
  fr: {
    nav_home: 'Accueil',
    nav_about: 'À propos',
    nav_login: 'Connexion',
    hero_title: 'Plateforme de Détection des Cyberattaques',
    hero_subtitle: "Intelligence de cybersécurité avancée alimentée par l'IA qui détecte le phishing, les URL malveillantes, l'injection SQL, les XSS, les ransomwares et bien plus encore — en temps réel.",
    hero_cta: 'Accéder à la plateforme',
    hero_cta_learn: 'En savoir plus',
    features_title: 'Capacités de la Plateforme',
    features_sub: 'Une suite complète de renseignements sur les cybermenaces alimentée par le Machine Learning et le NLP.',
    about_title: 'À propos de PhishGuard',
    about_body: "PhishGuard est une plateforme avancée de détection des cyberattaques conçue pour les analystes en sécurité et la recherche académique. Elle combine un moteur de Machine Learning Random Forest, le traitement du langage naturel et l'analyse des journaux de pare-feu applicatif pour détecter un large spectre de cybermenaces — du phishing d'URL et de l'ingénierie sociale par SMS à l'injection SQL, les XSS, les ransomwares, les attaques par force brute et les exploits RCE zero-day. La plateforme effectue également un traçage de localisation des menaces par GeoIP, une détection ASN/Proxy, et génère des rapports d'incidents signés cryptographiquement par SHA-256 pour les enquêtes forensiques.",
    footer_platform: 'Plateforme',
    footer_features: 'Fonctionnalités',
    footer_resources: 'Ressources',
    footer_legal: 'Légal',
    footer_desc: 'Plateforme intelligente de renseignements sur les menaces cybernétiques et le phishing, alimentée par le Machine Learning.',
    footer_copy: '© 2026 PhishGuard. Tous droits réservés.',
    login_title: 'Connectez-vous à PhishGuard',
    login_sub: 'Entrez vos identifiants pour accéder à la plateforme SOC',
    login_email: 'Adresse e-mail',
    login_password: 'Mot de passe',
    login_btn: 'Se connecter',
    login_no_account: 'Pas encore de compte ?',
    login_create: 'Créer un compte',
    login_forgot: 'Mot de passe oublié ?',
    login_direct: 'Ou accéder directement à la plateforme',
    register_title: 'Créez votre compte',
    register_sub: 'Rejoignez la plateforme de cybersécurité PhishGuard',
    register_name: 'Nom complet',
    register_email: 'Adresse e-mail',
    register_password: 'Mot de passe',
    register_confirm: 'Confirmer le mot de passe',
    register_role: 'Rôle',
    register_role_analyst: 'Analyste en sécurité',
    register_role_admin: 'Administrateur',
    register_terms: "J'accepte les Conditions d'utilisation et la Politique de confidentialité",
    register_btn: 'Créer un compte',
    register_have_account: 'Déjà un compte ?',
    register_signin: 'Se connecter',
  }
};

export function LanguageProvider({ children }) {
  const [lang, setLang] = useState(() => localStorage.getItem('phishguard-lang') || 'en');
  const t = (key) => translations[lang][key] || key;
  const toggle = () => {
    const next = lang === 'en' ? 'fr' : 'en';
    setLang(next);
    localStorage.setItem('phishguard-lang', next);
  };
  return (
    <LanguageContext.Provider value={{ lang, toggle, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  return useContext(LanguageContext);
}
