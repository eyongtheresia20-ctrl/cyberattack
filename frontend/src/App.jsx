import React, { useState, useEffect } from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { LanguageProvider } from './context/LanguageContext';
import { AuthProvider, useAuth } from './context/AuthContext';

import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import AuthModal from './components/AuthModal';

import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import Dashboard from './pages/Dashboard';
import StandardDashboard from './pages/StandardDashboard';
import HistoryPage from './pages/HistoryPage';
import UrlAnalysis from './pages/UrlAnalysis';
import TextAnalysis from './pages/TextAnalysis';
import SiteMonitoring from './pages/SiteMonitoring';
import Incidents from './pages/Incidents';
import Verification from './pages/Verification';
import Assistant from './pages/Assistant';
import AdminUsersPage from './pages/AdminUsersPage';
import ActivityLogsPage from './pages/ActivityLogsPage';

const PUBLIC_ROUTES = ['/', '/login', '/register'];

function AppLayout() {
  const { user } = useAuth();
  const location = useLocation();
  const isPublic = PUBLIC_ROUTES.includes(location.pathname);
  const [authModalOpen, setAuthModalOpen] = useState(false);

  // Automatically scroll main container to top on any route transition
  useEffect(() => {
    window.scrollTo(0, 0);
    const mainEl = document.querySelector('main');
    if (mainEl) mainEl.scrollTop = 0;
  }, [location.pathname]);

  if (isPublic) {
    return (
      <>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Routes>
        <AuthModal isOpen={authModalOpen} onClose={() => setAuthModalOpen(false)} />
      </>
    );
  }

  const isStandardUser = user?.role === 'UTILISATEUR_STANDARD';

  return (
    <div className="min-h-screen bg-[#f0f9ff] dark:bg-[#0d1117] text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors duration-300">
      <Navbar onOpenAuth={() => setAuthModalOpen(true)} />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 p-6 overflow-y-auto max-w-7xl mx-auto w-full">
          <Routes>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scanner" element={<StandardDashboard />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/url-analysis" element={<UrlAnalysis />} />
            <Route path="/text-analysis" element={<TextAnalysis />} />
            <Route path="/site-monitoring" element={<SiteMonitoring />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/verification" element={<Verification />} />
            <Route path="/assistant" element={<Assistant />} />
            <Route path="/admin/users" element={<AdminUsersPage />} />
            <Route path="/activity-logs" element={<ActivityLogsPage />} />
          </Routes>
        </main>
      </div>
      <AuthModal isOpen={authModalOpen} onClose={() => setAuthModalOpen(false)} />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <ThemeProvider>
        <LanguageProvider>
          <AppLayout />
        </LanguageProvider>
      </ThemeProvider>
    </AuthProvider>
  );
}

