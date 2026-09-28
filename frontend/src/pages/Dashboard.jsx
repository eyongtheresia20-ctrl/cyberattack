import React from 'react';
import { useAuth } from '../context/AuthContext';
import StandardDashboard from './StandardDashboard';
import InvestigatorDashboard from './InvestigatorDashboard';
import AdminDashboard from './AdminDashboard';
import { RefreshCw, Shield } from 'lucide-react';

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

  if (user?.role === 'ENQUETEUR') {
    return <InvestigatorDashboard />;
  }
  if (user?.role === 'ADMINISTRATEUR') {
    return <AdminDashboard />;
  }

  // Default for Standard User and logged-in user: show StandardDashboard
  return <StandardDashboard />;
}

