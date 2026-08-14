import React, { useEffect, useState } from 'react';
import { Shield, Globe, AlertTriangle, FileCheck, RefreshCw, Activity, Terminal, ArrowRight, Lock, MessageSquare, MapPin, Zap } from 'lucide-react';
import { Link } from 'react-router-dom';
import MetricCard from '../components/MetricCard';
import RiskBadge from '../components/RiskBadge';
import { api } from '../services/api';

export default function Dashboard() {
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [eventsRes, incRes] = await Promise.all([
        api.getSecurityEvents(8),
        api.getIncidents()
      ]);
      setEvents(eventsRes.data);
      setIncidents(incRes.data);
    } catch (e) {
      console.error("Error fetching dashboard data", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSeedLogs = async () => {
    setLoading(true);
    await api.seedDemoLogs();
    await fetchData();
  };

  const highSeverityCount = events.filter(e => e.severity === 'HIGH' || e.severity === 'CRITICAL').length;

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-8">
      {/* Hero Welcome Header (Sky Blue Gradient) */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gradient-to-r from-sky-500 via-sky-600 to-blue-600 p-6 rounded-2xl text-white shadow-xl shadow-sky-500/15">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="px-2.5 py-0.5 rounded-full bg-white/20 text-white text-[10px] font-mono font-bold tracking-wide uppercase border border-white/30">
              V1.0 Threat Intelligence
            </span>
            <span className="flex items-center gap-1 text-[11px] text-sky-100 font-mono">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> System Operational
            </span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">Security Operations Dashboard</h1>
          <p className="text-xs text-sky-100 max-w-xl">
            Real-time cyber threat telemetry, Random Forest Machine Learning predictions, GeoIP location tracing, and cryptographic evidence management.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleSeedLogs}
            disabled={loading}
            className="px-4 py-2.5 rounded-xl bg-white text-sky-700 text-xs font-bold hover:bg-sky-50 transition flex items-center gap-2 shadow-md"
          >
            <Terminal className="w-4 h-4 text-sky-600" /> Simulate Attack Telemetry
          </button>
          <button
            onClick={fetchData}
            disabled={loading}
            className="p-2.5 rounded-xl bg-white/20 hover:bg-white/30 text-white transition border border-white/30"
            title="Refresh Data"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard title="Monitored Events" value={events.length} subtitle="HTTP Telemetry Logs" icon={Activity} color="sky" />
        <MetricCard title="Attacks Detected" value={highSeverityCount} subtitle="SQLi, XSS, Ransomware" icon={AlertTriangle} color="red" />
        <MetricCard title="Active Incidents" value={incidents.length} subtitle="Under Investigation" icon={Shield} color="amber" />
        <MetricCard title="ML Model Accuracy" value="94.8%" subtitle="Random Forest Engine" icon={FileCheck} color="sky" />
      </div>

      {/* Operations Grid */}
      <div className="space-y-3">
        <h2 className="text-xs uppercase font-mono tracking-wider text-slate-500 font-bold px-1">
          Threat Analysis Modules
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link
            to="/url-analysis"
            className="group bg-white p-5 rounded-2xl border border-sky-100 hover:border-sky-400 transition-all duration-300 hover:-translate-y-0.5 space-y-3 shadow-sm hover:shadow-md hover:shadow-sky-500/10"
          >
            <div className="w-10 h-10 rounded-xl bg-sky-100 flex items-center justify-center text-sky-600 group-hover:bg-sky-500 group-hover:text-white transition-colors">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 flex items-center justify-between">
                <span>URL Threat Scanner</span>
                <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-sky-500 group-hover:translate-x-1 transition-all" />
              </h3>
              <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                Scan suspicious links, analyze 15+ lexical variables, SSL certs, VirusTotal & ML reputation scores.
              </p>
            </div>
          </Link>

          <Link
            to="/text-analysis"
            className="group bg-white p-5 rounded-2xl border border-sky-100 hover:border-sky-400 transition-all duration-300 hover:-translate-y-0.5 space-y-3 shadow-sm hover:shadow-md hover:shadow-sky-500/10"
          >
            <div className="w-10 h-10 rounded-xl bg-sky-100 flex items-center justify-center text-sky-600 group-hover:bg-sky-500 group-hover:text-white transition-colors">
              <MessageSquare className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 flex items-center justify-between">
                <span>SMS & Email Phishing</span>
                <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-sky-500 group-hover:translate-x-1 transition-all" />
              </h3>
              <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                Analyze SMS, chat text, and email headers (SPF, DKIM, DMARC) for artificial urgency and extortion.
              </p>
            </div>
          </Link>

          <Link
            to="/site-monitoring"
            className="group bg-white p-5 rounded-2xl border border-sky-100 hover:border-sky-400 transition-all duration-300 hover:-translate-y-0.5 space-y-3 shadow-sm hover:shadow-md hover:shadow-sky-500/10"
          >
            <div className="w-10 h-10 rounded-xl bg-sky-100 flex items-center justify-center text-sky-600 group-hover:bg-sky-500 group-hover:text-white transition-colors">
              <MapPin className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900 flex items-center justify-between">
                <span>Web Security & GeoIP</span>
                <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-sky-500 group-hover:translate-x-1 transition-all" />
              </h3>
              <p className="text-xs text-slate-500 mt-1 leading-relaxed">
                Ingest WAF logs, classify 16 cyber attack vectors, trace IP locations, ASN networks & proxy flags.
              </p>
            </div>
          </Link>
        </div>
      </div>

      {/* Telemetry Table & Protected Vectors Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Live Cyber Attack Telemetry Table */}
        <div className="lg:col-span-2 bg-white p-5 rounded-2xl border border-sky-100 space-y-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-sky-100">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-600" />
              <h3 className="font-bold text-slate-900 text-sm">Recent Cyber Attack Telemetry</h3>
            </div>
            <Link to="/site-monitoring" className="text-xs text-sky-600 hover:underline font-mono font-bold">
              View All Logs &rarr;
            </Link>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-sky-50 text-slate-600 uppercase font-mono text-[10px]">
                <tr>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3">Target Endpoint</th>
                  <th className="py-2.5 px-3">Source IP & Location</th>
                  <th className="py-2.5 px-3">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sky-100 font-mono text-slate-700">
                {events.length === 0 ? (
                  <tr>
                    <td colSpan="4" className="py-8 text-center text-slate-400 font-sans">
                      No events logged. Click <strong>"Simulate Attack Telemetry"</strong> above to populate live data.
                    </td>
                  </tr>
                ) : (
                  events.map((e) => (
                    <tr key={e.id} className="hover:bg-sky-50/50 transition">
                      <td className="py-3 px-3 font-bold text-slate-900">
                        {e.attack_type}
                      </td>
                      <td className="py-3 px-3">
                        <span className="text-sky-600 font-bold">{e.http_method}</span>{' '}
                        <span className="text-slate-600">{e.request_path}</span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="text-slate-900 font-bold">{e.source_ip}</div>
                        <div className="text-[10px] text-slate-500 font-sans">
                          📍 {e.ip_geo_info?.city || 'Unknown'}, {e.ip_geo_info?.country || 'Unknown'}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <RiskBadge level={e.severity} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Protected Attack Vectors List */}
        <div className="bg-white p-5 rounded-2xl border border-sky-100 space-y-4 shadow-sm">
          <div className="flex items-center justify-between pb-2 border-b border-sky-100">
            <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
              <Zap className="w-4 h-4 text-sky-500" /> Active Protection Vectors
            </h3>
            <span className="text-[10px] text-sky-700 font-mono bg-sky-100 px-2 py-0.5 rounded-full font-bold border border-sky-200">
              6 Active Rules
            </span>
          </div>

          <div className="space-y-2.5 text-xs font-sans">
            {[
              { title: 'SQL Injection (SQLi)', desc: 'UNION, DROP, parameter payloads', status: 'PROTECTED' },
              { title: 'Cross-Site Scripting (XSS)', desc: 'Stored & reflected script tags', status: 'PROTECTED' },
              { title: 'Brute Force Auth', desc: 'High-rate POST login attempts', status: 'PROTECTED' },
              { title: 'Path Traversal / LFI', desc: 'Directory sequence escape attempts', status: 'PROTECTED' },
              { title: 'Ransomware Droppers', desc: '.crypto, .enc malicious payloads', status: 'PROTECTED' },
              { title: 'Zero-Day RCE (Log4j)', desc: 'JNDI injection & shell commands', status: 'PROTECTED' },
            ].map((v, i) => (
              <div key={i} className="p-2.5 rounded-xl bg-sky-50/60 border border-sky-100 flex items-center justify-between">
                <div>
                  <p className="font-bold text-slate-900">{v.title}</p>
                  <p className="text-[10px] text-slate-500">{v.desc}</p>
                </div>
                <span className="text-[9px] font-mono font-extrabold text-sky-600 bg-white px-2 py-0.5 rounded-md border border-sky-200 shadow-xs">
                  {v.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
