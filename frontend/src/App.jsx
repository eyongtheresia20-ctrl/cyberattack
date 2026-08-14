import React from 'react';
import { Routes, Route, useLocation } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import { LanguageProvider } from './context/LanguageContext';

import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';

import LandingPage from './pages/LandingPage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import Dashboard from './pages/Dashboard';
import UrlAnalysis from './pages/UrlAnalysis';
import TextAnalysis from './pages/TextAnalysis';
import SiteMonitoring from './pages/SiteMonitoring';
import Incidents from './pages/Incidents';
import Verification from './pages/Verification';
import Assistant from './pages/Assistant';

const PUBLIC_ROUTES = ['/', '/login', '/register'];

function AppLayout() {
  const location = useLocation();
  const isPublic = PUBLIC_ROUTES.includes(location.pathname);

  if (isPublic) {
    return (
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
      </Routes>
    );
  }

  return (
    <div className="min-h-screen bg-[#f0f9ff] dark:bg-[#0d1117] text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors duration-300">
      <Navbar />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 p-6 overflow-y-auto">
          <Routes>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/url-analysis" element={<UrlAnalysis />} />
            <Route path="/text-analysis" element={<TextAnalysis />} />
            <Route path="/site-monitoring" element={<SiteMonitoring />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/verification" element={<Verification />} />
            <Route path="/assistant" element={<Assistant />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <LanguageProvider>
        <AppLayout />
      </LanguageProvider>
    </ThemeProvider>
  );
}
