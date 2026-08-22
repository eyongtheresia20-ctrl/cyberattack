import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  ShieldCheck, AlertCircle, FileSearch, CheckCircle2, Lock, 
  Search, RefreshCw, Eye, MessageSquare, Tag, Hash, ShieldAlert
} from 'lucide-react';

export default function InvestigatorDashboard() {
  const { user } = useAuth();
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [incidentDetails, setIncidentDetails] = useState(null);
  const [newStatus, setNewStatus] = useState('INVESTIGATING');
  const [analystNotes, setAnalystNotes] = useState('');
  const [updating, setUpdating] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/incidents');
      const data = await res.json();
      setIncidents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleOpenIncident = async (inc) => {
    setSelectedIncident(inc);
    setVerificationResult(null);
    setAnalystNotes('');
    setNewStatus(inc.status || 'INVESTIGATING');

    try {
      const res = await fetch(`/api/v1/incidents/${inc.id}`);
      const data = await res.json();
      setIncidentDetails(data);
    } catch (err) {
      alert("Erreur de chargement des détails : " + err.message);
    }
  };

  const handleUpdateStatus = async (e) => {
    e.preventDefault();
    if (!selectedIncident) return;

    setUpdating(true);
    try {
      const res = await fetch(`/api/v1/incidents/${selectedIncident.id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: newStatus,
          notes: analystNotes
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur de mise à jour");

      setSelectedIncident(data);
      fetchIncidents();
      alert(`Statut de l'incident mis à jour vers [${newStatus}]`);
    } catch (err) {
      alert("Erreur : " + err.message);
    } finally {
      setUpdating(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    if (!incidentDetails?.reports?.[0]) return;
    const rpt = incidentDetails.reports[0];

    try {
      const res = await fetch('/api/v1/verify/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          report_code: rpt.report_code,
          provided_hash: rpt.integrity_hash
        })
      });
      const data = await res.json();
      setVerificationResult(data);
    } catch (err) {
      alert("Erreur de vérification SHA-256 : " + err.message);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-800/40 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-indigo-500/10 border border-indigo-400/20 text-indigo-400 text-xs font-semibold rounded-full mb-2">
            <ShieldCheck size={14} /> Portail d'Enquêteur / Analyste SOC
          </div>
          <h1 className="text-2xl font-bold text-white">Console d'Enquête — {user?.prenom} {user?.nom}</h1>
          <p className="text-slate-400 text-sm mt-1">Examinez les rapports soumis par les utilisateurs, vérifiez l'intégrité SHA-256 et gérez le cycle de vie des incidents.</p>
        </div>
        <button
          onClick={fetchIncidents}
          className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 shadow-lg shadow-indigo-600/30 transition-all"
        >
          <RefreshCw size={14} /> Actualiser la File ({incidents.length})
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left List: Incident Queue */}
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col h-[650px]">
          <h2 className="text-md font-bold text-white mb-3 flex items-center justify-between">
            <span>File des Incidents ({incidents.length})</span>
            <Tag size={16} className="text-indigo-400" />
          </h2>

          {loading ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-xs gap-2">
              <RefreshCw className="animate-spin" size={16} /> Chargement de la file...
            </div>
          ) : incidents.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-xs">
              Aucun incident dans la file d'attente.
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto space-y-3 pr-1">
              {incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => handleOpenIncident(inc)}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    selectedIncident?.id === inc.id
                      ? 'bg-indigo-950/40 border-indigo-500 shadow-md shadow-indigo-500/10'
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-indigo-400">{inc.incident_code}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                      inc.status === 'NEW' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      inc.status === 'INVESTIGATING' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      inc.status === 'RESOLVED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                      'bg-slate-700 text-slate-300'
                    }`}>
                      {inc.status}
                    </span>
                  </div>
                  <h4 className="text-xs font-semibold text-white truncate">{inc.title}</h4>
                  <div className="flex items-center justify-between mt-2 text-[10px] text-slate-400">
                    <span>Sévérité : <strong className={inc.severity === 'HIGH' ? 'text-rose-400' : 'text-amber-400'}>{inc.severity}</strong></span>
                    <span>{new Date(inc.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Pane: Detailed Report Inspector */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg flex flex-col h-[650px] overflow-y-auto">
          {!selectedIncident ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-500 space-y-3">
              <FileSearch size={48} className="text-slate-700" />
              <p className="text-sm">Sélectionnez un incident dans la file pour afficher les détails et l'empreinte SHA-256.</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Header Details */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-indigo-400">{selectedIncident.incident_code}</span>
                    <span className="text-xs px-2.5 py-0.5 rounded font-bold bg-slate-800 text-slate-300">
                      {selectedIncident.category}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-white mt-1">{selectedIncident.title}</h2>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Statut :</span>
                  <span className="px-3 py-1 bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 font-bold text-xs rounded-lg">
                    {selectedIncident.status}
                  </span>
                </div>
              </div>

              {/* Raw Payload & Summary */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Résumé et Contenu Brut (Payload)</h3>
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 whitespace-pre-wrap">
                  {selectedIncident.summary}
                </div>
              </div>

              {/* SHA-256 Evidence Signature */}
              <div className="space-y-3">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Sceau Cryptographique (Empreinte SHA-256)</span>
                  <button
                    onClick={handleVerifyIntegrity}
                    className="text-indigo-400 hover:text-indigo-300 text-xs font-bold flex items-center gap-1"
                  >
                    <Lock size={12} /> Tester l'Intégrité en DB
                  </button>
                </h3>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-xs text-emerald-400 break-all flex items-center gap-2">
                  <Hash size={16} className="shrink-0 text-slate-500" />
                  <span>{selectedIncident.evidence_hash}</span>
                </div>

                {verificationResult && (
                  <div className={`p-3 rounded-xl border text-xs font-medium flex items-center gap-2 ${
                    verificationResult.verified ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                  }`}>
                    <CheckCircle2 size={16} />
                    <span>Empreinte SHA-256 recalculée avec succès ! Statut d'intégrité : INTACT & SANS ALTÉRATION.</span>
                  </div>
                )}
              </div>

              {/* Lifecycle Management & Status Update */}
              <form onSubmit={handleUpdateStatus} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-4">
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">Mettre à jour le Statut & Ajouter des Notes d'Analyste</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1 font-medium">Statut de l'Incident :</label>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:border-indigo-500"
                    >
                      <option value="NEW">NOUVEAU (NEW)</option>
                      <option value="INVESTIGATING">EN COURS D'ENQUÊTE (INVESTIGATING)</option>
                      <option value="RESOLVED">RÉSOLU (RESOLVED)</option>
                      <option value="CLOSED">CLOS (CLOSED)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1 font-medium">Notes de l'Enquêteur :</label>
                    <input
                      type="text"
                      placeholder="Ex: Domaine frauduleux bloqué sur le serveur DNS proxy."
                      value={analystNotes}
                      onChange={(e) => setAnalystNotes(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs focus:outline-none focus:border-indigo-500"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={updating}
                  className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-bold py-2.5 rounded-lg shadow-lg shadow-indigo-600/30 flex items-center justify-center gap-2 transition-all"
                >
                  {updating ? <RefreshCw className="animate-spin" size={14} /> : <CheckCircle2 size={14} />}
                  Enregistrer les modifications d'Enquête
                </button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
