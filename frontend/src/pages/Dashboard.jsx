import React from 'react';
import { useAuth } from '../context/AuthContext';
import StandardDashboard from './StandardDashboard';
import InvestigatorDashboard from './InvestigatorDashboard';
import AdminDashboard from './AdminDashboard';

export default function Dashboard() {
  const { user } = useAuth();

  if (user?.role === 'ENQUETEUR') {
    return <InvestigatorDashboard />;
  }
  if (user?.role === 'ADMINISTRATEUR') {
    return <AdminDashboard />;
  }

  // Default for Standard User and logged-in/guest user: show StandardDashboard
  return <StandardDashboard />;
}
