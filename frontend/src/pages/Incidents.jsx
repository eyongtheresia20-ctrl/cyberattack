import React, { useEffect, useState } from 'react';
import { FileSearch, ShieldAlert, FileText, CheckCircle, RefreshCw, Key, Plus } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import { api } from '../services/api';

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [reportResult, setReportResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // New Incident Form State
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('Phishing Campaign');
  const [severity, setSeverity] = useState('HIGH');
  const [summary, setSummary] = useState('');
  const [showModal, setShowModal] = useState(false);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await api.getIncidents();
      setIncidents(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleSelectIncident = async (incId) => {
    try {
      const res = await api.getIncidentDetails(incId);
      setSelectedIncident(res.data);
      setReportResult(null);
    } catch (e) {
      console.error(e);
    }
  };

  const handleGenerateReport = async (incId) => {
    try {
      const res = await api.generateReport(incId, "Lead Security Investigator");
      setReportResult(res.data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleCreateIncident = async (e) => {
    e.preventDefault();
    if (!title || !summary) return;
    try {
      await api.createIncident({ title, category, severity, summary });
      setShowModal(false);
      setTitle('');
      setSummary('');
      fetchIncidents();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <FileSearch className="w-5 h-5 text-cyan-400" /> Incident Proof Ledger & Evidence Management
          </h2>
          <p className="text-xs text-slate-400">Stores cryptographically bound evidence with SHA-256 integrity checksums</p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowModal(true)}
            className="px-3 py-2 rounded-lg bg-cyan-500 text-black text-xs font-semibold hover:bg-cyan-400 transition flex items-center gap-2 shadow-lg shadow-cyan-500/20"
          >
            <Plus className="w-4 h-4" /> Create Incident Record
          </button>
          <button onClick={fetchIncidents} className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incidents List */}
        <div className="lg:col-span-1 glass-card p-4 rounded-xl border border-slate-800 space-y-3">
          <h3 className="font-semibold text-white text-sm">Security Incidents Ledger</h3>
          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            {incidents.length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-6">No incidents recorded.</p>
            ) : (
              incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => handleSelectIncident(inc.id)}
                  className={`p-3 rounded-lg border text-xs cursor-pointer transition ${
                    selectedIncident?.incident?.id === inc.id
                      ? 'bg-cyan-500/10 border-cyan-500/40 text-white'
                      : 'bg-slate-900/60 border-slate-800/80 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-bold font-mono text-cyan-400">{inc.incident_code}</span>
                    <RiskBadge level={inc.severity} />
                  </div>
                  <p className="font-semibold text-slate-100 truncate">{inc.title}</p>
                  <p className="text-[10px] text-slate-400 mt-1">{inc.category} • {new Date(inc.created_at).toLocaleDateString()}</p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Incident Detail & Report Generator */}
        <div className="lg:col-span-2 glass-card p-5 rounded-xl border border-slate-800 space-y-5">
          {selectedIncident ? (
            <div className="space-y-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <span className="text-xs font-mono text-cyan-400 font-bold">{selectedIncident.incident.incident_code}</span>
                  <h3 className="text-lg font-bold text-white mt-0.5">{selectedIncident.incident.title}</h3>
                  <p className="text-xs text-slate-400">{selectedIncident.incident.category} • Created: {new Date(selectedIncident.incident.created_at).toLocaleString()}</p>
                </div>
                <RiskBadge level={selectedIncident.incident.severity} />
              </div>

              <div className="space-y-2">
                <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400">Incident Executive Summary</h4>
                <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 text-xs text-slate-300">
                  {selectedIncident.incident.summary}
                </div>
              </div>

              {/* Digital Checksum */}
              <div className="p-3 bg-slate-900/80 rounded-lg border border-slate-800 font-mono text-xs space-y-1">
                <span className="text-slate-500 text-[10px] block">IMMUTABLE EVIDENCE SHA-256 CHECKSUM</span>
                <p className="text-cyan-400 break-all text-[11px]">{selectedIncident.incident.evidence_hash}</p>
              </div>

              {/* Generate Report Button */}
              <div className="pt-2 flex items-center justify-between">
                <button
                  onClick={() => handleGenerateReport(selectedIncident.incident.id)}
                  className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold rounded-lg text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20"
                >
                  <FileText className="w-4 h-4" /> Generate Investigator Signed Report
                </button>
              </div>

              {/* Report Export Result */}
              {reportResult && (
                <div className="p-4 bg-slate-900 border border-cyan-500/40 rounded-xl space-y-3 font-mono text-xs">
                  <div className="flex items-center justify-between text-emerald-400 font-bold">
                    <span>REPORT GENERATED: {reportResult.report.report_code}</span>
                    <CheckCircle className="w-4 h-4" />
                  </div>
                  <div className="p-2 bg-slate-950 rounded border border-slate-800 text-[11px] text-slate-300 font-mono">
                    <p className="text-slate-500">Integrity Signature (SHA-256):</p>
                    <p className="text-cyan-400 break-all">{reportResult.integrity_hash}</p>
                  </div>
                  <p className="text-[11px] text-slate-400 font-sans">
                    This report ID can now be submitted to investigators to verify integrity against original database evidence records.
                  </p>
                </div>
              )}
            </div>
          ) : (
            <div className="py-16 text-center text-slate-500 text-xs">
              Select an incident record from the ledger on the left to view evidence details and generate verification reports.
            </div>
          )}
        </div>
      </div>

      {/* Modal for Creating Incident */}
      {showModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="glass-card max-w-md w-full p-5 rounded-xl border border-slate-800 space-y-4">
            <h3 className="font-bold text-white text-base">Create Security Incident</h3>
            <form onSubmit={handleCreateIncident} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">Incident Title</label>
                <input
                  type="text"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  placeholder="e.g. Credential Phishing Target Domain Detected"
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Category</label>
                  <select value={category} onChange={(e) => setCategory(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white">
                    <option>Phishing Campaign</option>
                    <option>Web Cyber Attack</option>
                    <option>Credential Theft</option>
                    <option>Brute Force</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white">
                    <option>LOW</option>
                    <option>MEDIUM</option>
                    <option>HIGH</option>
                    <option>CRITICAL</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Technical Summary</label>
                <textarea
                  rows={3}
                  value={summary}
                  onChange={(e) => setSummary(e.target.value)}
                  placeholder="Describe detected indicators, target endpoints, and evidence..."
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white"
                  required
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button type="button" onClick={() => setShowModal(false)} className="px-3 py-1.5 rounded bg-slate-800 text-slate-300">
                  Cancel
                </button>
                <button type="submit" className="px-4 py-1.5 rounded bg-cyan-500 text-black font-semibold">
                  Save Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
