/**
 * ========================================================================================
 * CYBERGUARD SOC — DISPATCHER CENTRAL DES TABLEAUX DE BORD (ROUTE: /dashboard)
 * ========================================================================================
 * 📍 RÔLE :
 * Ce composant n'affiche pas de données lui-même ; il agit comme un "Aiguilleur de sécurité".
 * Il analyse le rôle RBAC de l'utilisateur connecté (Standard, Enquêteur, Administrateur)
 * et le redirige instantanément vers le bon tableau de bord correspondant.
 * 
 * 📌 CORRESPONDANCES AVEC LE RAPPORT :
 * - Rôle 'UTILISATEUR_STANDARD' -> Charge StandardDashboard (Figure 42 du rapport, page 107)
 * - Rôle 'ENQUETEUR'            -> Charge InvestigatorDashboard (Figure 43 du rapport, page 108)
 * - Rôle 'ADMINISTRATEUR'       -> Charge AdminDashboard (Figure 44 du rapport, page 108)
 * - Non connecté               -> Redirige vers la Landing Page (Figure 39 du rapport, page 106)
 * ========================================================================================
 */

import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import StandardDashboard from './StandardDashboard';
import InvestigatorDashboard from './InvestigatorDashboard';
import AdminDashboard from './AdminDashboard';
import { RefreshCw } from 'lucide-react';

export default function Dashboard() {
  // Récupération de l'état d'authentification (utilisateur connecté et statut de chargement)
  const { user, loading } = useAuth();

  // --------------------------------------------------------------------------------------
  // 1. ÉCRAN D'ATTENTE SÉCURISÉ (Pendant la vérification du jeton JWT)
  // --------------------------------------------------------------------------------------
  if (loading && !user) {
    return (
      <div className="min-h-[50vh] flex flex-col items-center justify-center space-y-4 animate-fade-in">
        <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-500">
          <RefreshCw className="w-8 h-8 animate-spin" />
        </div>
        <p className="text-sm font-semibold text-slate-600 dark:text-slate-300">
          Chargement de votre console sécurisée...
        </p>
      </div>
    );
  }

  // --------------------------------------------------------------------------------------
  // 2. CONTRÔLE D'ACCÈS : Si non connecté, expulsion vers la Landing Page (/)
  // --------------------------------------------------------------------------------------
  if (!user) {
    return <Navigate to="/" replace />;
  }

  // --------------------------------------------------------------------------------------
  // 3. AIGUILLAGE RBAC (Affichage du bon tableau de bord selon les privilèges)
  // --------------------------------------------------------------------------------------

  // CAS A : Enquêteur SOC -> Console de gestion des incidents et preuves forensiques
  if (user?.role === 'ENQUETEUR') {
    return <InvestigatorDashboard />;
  }

  // CAS B : Administrateur Système -> Supervision des attaques globales, WAF et modèles ML
  if (user?.role === 'ADMINISTRATEUR') {
    return <AdminDashboard />;
  }

  // CAS C : Utilisateur Standard -> Scanner d'URL et analyse de messages suspects
  if (user?.role === 'UTILISATEUR_STANDARD') {
    return <StandardDashboard />;
  }

  // Cas par défaut de sécurité : retour à l'accueil
  return <Navigate to="/" replace />;
}
