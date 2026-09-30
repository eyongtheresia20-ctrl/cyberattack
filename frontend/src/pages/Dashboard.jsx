import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import StandardDashboard from './StandardDashboard';
import InvestigatorDashboard from './InvestigatorDashboard';
import AdminDashboard from './AdminDashboard';
import { RefreshCw } from 'lucide-react';

export default function Dashboard() {
  const { user, loading } = useAuth();

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

  // If not logged in, take the user directly to the Landing Page
  if (!user) {
    return <Navigate to="/" replace />;
  }

  if (user?.role === 'ENQUETEUR') {
    return <InvestigatorDashboard />;
  }
  if (user?.role === 'ADMINISTRATEUR') {
    return <AdminDashboard />;
  }
  if (user?.role === 'UTILISATEUR_STANDARD') {
    return <StandardDashboard />;
  }

  return <Navigate to="/" replace />;
}

