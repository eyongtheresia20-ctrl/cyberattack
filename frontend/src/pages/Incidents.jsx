import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { 
  ShieldCheck, AlertCircle, FileSearch, CheckCircle2, Lock, 
  Search, RefreshCw, Eye, Tag, Hash, ShieldAlert, Edit3, Trash2,
  Check, X, FileText, User, AlertTriangle, ChevronRight, Layers,
  ExternalLink, Filter, BarChart2, Shield
} from 'lucide-react';

export default function Incidents() {
  const { user } = useAuth();

  // Incidents data state
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);

  // Search & Filter states
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  // Modals state
  const [selectedIncident, setSelectedIncident] = useState(null); // For Detail Modal
  const [incidentToEdit, setIncidentToEdit] = useState(null); // For Edit Modal
  const [incidentToDelete, setIncidentToDelete] = useState(null); // For Delete Confirmation
  const [verifyingIncidentId, setVerifyingIncidentId] = useState(null);
  const [verificationModalData, setVerificationModalData] = useState(null);

  // Form states for Editing
  const [editStatus, setEditStatus] = useState('NEW');
  const [editSeverity, setEditSeverity] = useState('HIGH');
  const [editVerdict, setEditVerdict] = useState('PHISHING');
  const [editTitle, setEditTitle] = useState('');
  const [editNotes, setEditNotes] = useState('');
  const [isSubmittingEdit, setIsSubmittingEdit] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);

  // Fetch incidents list from backend
  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/incidents');
      if (!res.ok) throw new Error(`Erreur HTTP: ${res.status}`);
      const data = await res.json();
      setIncidents(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Erreur de chargement des incidents :", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  // Filtered incidents
  const filteredIncidents = incidents.filter(inc => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch = !q || 
      (inc.incident_code && inc.incident_code.toLowerCase().includes(q)) ||
      (inc.title && inc.title.toLowerCase().includes(q)) ||
      (inc.target && inc.target.toLowerCase().includes(q)) ||
      (inc.reporter_email && inc.reporter_email.toLowerCase().includes(q)) ||
      (inc.reporter_name && inc.reporter_name.toLowerCase().includes(q)) ||
      (inc.investigator_notes && inc.investigator_notes.toLowerCase().includes(q));

    const matchesStatus = statusFilter === 'ALL' || inc.status === statusFilter;
    const matchesSeverity = severityFilter === 'ALL' || inc.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  // Handler: Open Edit Modal
  const handleOpenEdit = (inc) => {
    setIncidentToEdit(inc);
    setEditStatus(inc.status || 'NEW');
    setEditSeverity(inc.severity || 'HIGH');
    setEditVerdict(inc.verdict || 'PHISHING');
    setEditTitle(inc.title || '');
    setEditNotes(inc.investigator_notes || '');
  };

  // Handler: Save Edit Form (PUT /api/v1/incidents/{id})
  const handleSaveEdit = async (e) => {
    e.preventDefault();
    if (!incidentToEdit) return;
    setIsSubmittingEdit(true);

    try {
      const res = await fetch(`/api/v1/incidents/${incidentToEdit.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: editTitle,
          status: editStatus,
          severity: editSeverity,
          verdict: editVerdict,
          notes: editNotes
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur de mise à jour");

      setIncidentToEdit(null);
      await fetchIncidents();
    } catch (err) {
      alert("Erreur lors de la mise à jour : " + err.message);
    } finally {
      setIsSubmittingEdit(false);
    }
  };

  // Handler: Delete Incident (DELETE /api/v1/incidents/{id})
  const handleConfirmDelete = async () => {
    if (!incidentToDelete) return;
    setIsDeleting(true);
    try {
      const res = await fetch(`/api/v1/incidents/${incidentToDelete.id}`, {
        method: 'DELETE'
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || "Erreur lors de la suppression");
      }

      setIncidentToDelete(null);
      if (selectedIncident?.id === incidentToDelete.id) {
        setSelectedIncident(null);
      }
      await fetchIncidents();
    } catch (err) {
      alert("Erreur de suppression : " + err.message);
    } finally {
      setIsDeleting(false);
    }
  };

  // Handler: SHA-256 Integrity Seal Verification
  const handleVerifySeal = async (inc, e) => {
    if (e) e.stopPropagation();
    setVerifyingIncidentId(inc.id);

    const lookupCode = inc.incident_code || inc.reports?.[0]?.report_code;
    const hash = inc.evidence_hash || inc.reports?.[0]?.integrity_hash;

    try {
      const res = await fetch('/api/v1/verify/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          lookup_code: lookupCode,
          provided_hash: hash
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Erreur de vérification");

      setVerificationModalData({
        incidentCode: lookupCode,
        hash: hash,
        result: data
      });
    } catch (err) {
      alert("Erreur de vérification SHA-256 : " + err.message);
    } finally {
      setVerifyingIncidentId(null);
    }
  };

  // Badge Color Helpers
  const getStatusBadge = (status) => {
    switch (status) {
      case 'NEW':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30">Nouveau</span>;
      case 'INVESTIGATING':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30">En Cours</span>;
      case 'RESOLVED':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">Résolu</span>;
      case 'CLOSED':
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/30">Clos</span>;
      default:
        return <span className="px-2.5 py-1 rounded-full text-[10px] font-mono font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30">{status}</span>;
    }
  };

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-extrabold bg-rose-500/15 text-rose-600 dark:text-rose-400 border border-rose-500/30">Élevée</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-extrabold bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30">Moyenne</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-extrabold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">Faible</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-extrabold bg-slate-500/15 text-slate-400">{sev}</span>;
    }
  };

  const getVerdictBadge = (verdict) => {
    if (verdict === 'PHISHING' || verdict?.includes('MENACE')) {
      return <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-black bg-rose-500/20 text-rose-600 dark:text-rose-400 border border-rose-500/40">🚨 PHISHING</span>;
    }
    if (verdict === 'LEGITIMATE' || verdict?.includes('CONFORME')) {
      return <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-black bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/40">✅ LÉGITIME</span>;
    }
    return <span className="px-2 py-0.5 rounded-md text-[10px] font-mono font-black bg-amber-500/20 text-amber-600 dark:text-amber-400 border border-amber-500/40">⚠️ SUSPECT</span>;
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">
      
      {/* Search & Filter Bar */}
      <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-2xl p-4 shadow-sm flex flex-col md:flex-row items-center justify-between gap-4">
        
        {/* Search Input */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Rechercher par code, URL, email..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-sky-500 font-sans"
          />
        </div>

        {/* Filter Dropdowns */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          
          {/* Status Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <Filter size={14} className="text-sky-500" />
            <span className="text-slate-500 font-medium">Statut :</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white rounded-xl px-3 py-1.5 text-xs font-semibold focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">Tous les statuts</option>
              <option value="NEW">Nouveaux</option>
              <option value="INVESTIGATING">En cours</option>
              <option value="RESOLVED">Résolus</option>
              <option value="CLOSED">Clos</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-500 font-medium">Sévérité :</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white rounded-xl px-3 py-1.5 text-xs font-semibold focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">Toutes les sévérités</option>
              <option value="HIGH">Élevée</option>
              <option value="MEDIUM">Moyenne</option>
              <option value="LOW">Faible</option>
            </select>
          </div>

        </div>
      </div>

      {/* Reports & Incidents Card Grid */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center text-slate-400 gap-3">
          <RefreshCw className="w-8 h-8 animate-spin text-sky-500" />
          <p className="text-xs font-mono font-semibold">Chargement des signalements...</p>
        </div>
      ) : filteredIncidents.length === 0 ? (
        <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-12 text-center space-y-3">
          <FileSearch className="w-12 h-12 text-slate-300 dark:text-slate-600 mx-auto" />
          <h3 className="text-base font-extrabold text-slate-900 dark:text-white">Aucun signalement trouvé</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            Aucun incident ne correspond à vos critères de recherche. Modifiez vos filtres ou attendez qu'un utilisateur transmette un nouveau rapport.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredIncidents.map((inc) => {
            const risk = inc.risk_score !== undefined ? inc.risk_score : 50;

            return (
              <div
                key={inc.id}
                className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 hover:border-sky-500 dark:hover:border-sky-500 rounded-3xl p-5 shadow-sm hover:shadow-xl transition-all duration-300 flex flex-col justify-between space-y-4 group"
              >
                {/* Card Top Header */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs font-extrabold text-sky-600 dark:text-sky-400 bg-sky-500/10 px-2.5 py-1 rounded-lg border border-sky-500/20">
                      {inc.incident_code}
                    </span>
                    <div className="flex items-center gap-1.5">
                      {getSeverityBadge(inc.severity)}
                      {getStatusBadge(inc.status)}
                    </div>
                  </div>

                  <h3 className="font-bold text-sm text-slate-900 dark:text-white line-clamp-2 pt-1 group-hover:text-sky-500 transition-colors">
                    {inc.title}
                  </h3>

                  {/* Target URL/Text Preview */}
                  <div className="bg-slate-50 dark:bg-[#0f172a] p-2.5 rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-mono text-slate-700 dark:text-slate-300 truncate">
                    <span className="text-slate-400 font-bold uppercase text-[9px] mr-2">Cible :</span>
                    {inc.target || "N/A"}
                  </div>
                </div>

                {/* Reporter & Verdict Info */}
                <div className="space-y-2.5 pt-2 border-t border-slate-100 dark:border-slate-800/80">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5 text-slate-600 dark:text-slate-400 font-medium">
                      <User size={13} className="text-sky-400 shrink-0" />
                      <span className="truncate max-w-[140px]" title={inc.reporter_email}>{inc.reporter_name || inc.reporter_email || "Anonyme"}</span>
                    </div>
                    {getVerdictBadge(inc.verdict)}
                  </div>

                  {/* Risk Score Progress Bar */}
                  <div className="space-y-1">
                    <div className="flex items-center justify-between text-[10px] font-mono">
                      <span className="text-slate-400 font-bold">NIVEAU DE RISQUE</span>
                      <span className={`font-black ${risk >= 70 ? 'text-rose-500' : risk >= 40 ? 'text-amber-500' : 'text-emerald-500'}`}>
                        {risk} / 100
                      </span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          risk >= 70 ? 'bg-gradient-to-r from-amber-500 to-rose-500' :
                          risk >= 40 ? 'bg-gradient-to-r from-sky-500 to-amber-500' :
                          'bg-gradient-to-r from-emerald-500 to-sky-500'
                        }`}
                        style={{ width: `${risk}%` }}
                      />
                    </div>
                  </div>

                  {/* Notes Snippet if present */}
                  {inc.investigator_notes && (
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 italic line-clamp-1 bg-sky-50/50 dark:bg-sky-950/20 px-2.5 py-1 rounded-lg border border-sky-100 dark:border-sky-800/30">
                      📝 "{inc.investigator_notes}"
                    </p>
                  )}
                </div>

                {/* Card Action Buttons Bar */}
                <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between gap-1.5">
                  <button
                    onClick={() => setSelectedIncident(inc)}
                    className="flex-1 py-1.5 px-2 bg-slate-100 dark:bg-[#1e293b] hover:bg-sky-500 hover:text-white dark:hover:bg-sky-600 text-slate-700 dark:text-slate-200 rounded-xl text-[11px] font-bold flex items-center justify-center gap-1 transition cursor-pointer"
                    title="Examiner tous les détails"
                  >
                    <Eye size={13} /> Examiner
                  </button>

                  {user?.role !== 'ADMINISTRATEUR' && (
                    <>
                      <button
                        onClick={() => handleOpenEdit(inc)}
                        className="flex-1 py-1.5 px-2 bg-sky-500/10 hover:bg-sky-500 hover:text-white text-sky-600 dark:text-sky-400 rounded-xl text-[11px] font-bold flex items-center justify-center gap-1 transition cursor-pointer"
                        title="Modifier statut et notes"
                      >
                        <Edit3 size={13} /> Modifier
                      </button>

                      <button
                        onClick={(e) => handleVerifySeal(inc, e)}
                        disabled={verifyingIncidentId === inc.id}
                        className="py-1.5 px-2 bg-slate-100 dark:bg-[#1e293b] hover:bg-emerald-500 hover:text-white text-emerald-600 dark:text-emerald-400 rounded-xl text-[11px] font-bold flex items-center justify-center transition cursor-pointer"
                        title="Vérifier l'intégrité SHA-256"
                      >
                        <Lock size={13} />
                      </button>

                      <button
                        onClick={() => setIncidentToDelete(inc)}
                        className="py-1.5 px-2 bg-rose-500/10 hover:bg-rose-500 hover:text-white text-rose-500 rounded-xl text-[11px] font-bold flex items-center justify-center transition cursor-pointer"
                        title="Supprimer ce rapport"
                      >
                        <Trash2 size={13} />
                      </button>
                    </>
                  )}
                </div>

              </div>
            );
          })}
        </div>
      )}

      {/* MODAL 1: EXAMINER / VIEW DETAILS */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-3xl p-6 max-w-2xl w-full shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto animate-fade-in">
            
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-sky-500 to-cyan-500 text-white flex items-center justify-center font-bold text-sm shadow-lg shadow-sky-500/30">
                  <FileSearch className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-extrabold text-sky-500">{selectedIncident.incident_code}</span>
                    {getStatusBadge(selectedIncident.status)}
                    {getSeverityBadge(selectedIncident.severity)}
                  </div>
                  <h3 className="font-heading font-extrabold text-slate-900 dark:text-white text-base mt-0.5">{selectedIncident.title}</h3>
                </div>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-lg transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Reporter & Metadata Grid */}
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-50 dark:bg-[#1e293b] rounded-xl border border-slate-200 dark:border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Signalé Par</span>
                <span className="font-bold text-slate-900 dark:text-white mt-0.5 block">{selectedIncident.reporter_name || "Alice Martin"}</span>
                <span className="text-[11px] text-slate-500 font-mono">{selectedIncident.reporter_email || "alice.martin@example.com"}</span>
              </div>

              <div className="p-3 bg-slate-50 dark:bg-[#1e293b] rounded-xl border border-slate-200 dark:border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase font-mono font-bold block">Date & Heure</span>
                <span className="font-bold text-slate-900 dark:text-white mt-0.5 block">
                  {new Date(selectedIncident.created_at).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' })}
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  {new Date(selectedIncident.created_at).toLocaleTimeString('fr-FR')}
                </span>
              </div>
            </div>

            {/* Target Content & Verdict */}
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold uppercase text-[10px] text-slate-400">Contenu Cible Analysé</span>
                {getVerdictBadge(selectedIncident.verdict)}
              </div>
              <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 font-mono text-cyan-300 break-all">
                {selectedIncident.target || selectedIncident.summary}
              </div>
            </div>

            {/* SHA-256 Integrity Hash */}
            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold uppercase text-[10px] text-slate-400">Sceau Cryptographique (SHA-256)</span>
                <button
                  onClick={(e) => handleVerifySeal(selectedIncident, e)}
                  className="text-emerald-500 hover:text-emerald-400 font-bold flex items-center gap-1 text-[11px]"
                >
                  <Lock size={12} /> Tester l'Intégrité
                </button>
              </div>
              <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono text-emerald-400 break-all text-[11px] flex items-center gap-2">
                <Hash size={14} className="text-slate-500 shrink-0" />
                <span>{selectedIncident.evidence_hash || selectedIncident.reports?.[0]?.integrity_hash}</span>
              </div>
            </div>

            {/* Investigator Notes */}
            <div className="space-y-2 text-xs">
              <span className="font-mono font-bold uppercase text-[10px] text-slate-400">Notes d'Enquête SOC</span>
              <div className="p-3 bg-sky-50 dark:bg-[#1e293b] rounded-xl border border-sky-100 dark:border-slate-800 text-slate-800 dark:text-slate-200 italic">
                {selectedIncident.investigator_notes || "Aucune note d'enquêteur ajoutée pour le moment."}
              </div>
            </div>

            {/* Footer Buttons */}
            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-200 dark:border-slate-800">
              <button
                onClick={() => {
                  const inc = selectedIncident;
                  setSelectedIncident(null);
                  handleOpenEdit(inc);
                }}
                className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-white font-bold rounded-xl text-xs flex items-center gap-1.5 transition cursor-pointer shadow-md shadow-sky-500/20"
              >
                <Edit3 size={14} /> Modifier ce Rapport
              </button>
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 bg-slate-100 dark:bg-[#1e293b] hover:bg-slate-200 text-slate-700 dark:text-slate-300 font-bold rounded-xl text-xs transition cursor-pointer"
              >
                Fermer
              </button>
            </div>

          </div>
        </div>
      )}

      {/* MODAL 2: MODIFIER LE RAPPORT */}
      {incidentToEdit && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-3xl p-6 max-w-lg w-full shadow-2xl space-y-5 animate-fade-in">
            
            <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-2xl bg-sky-500 text-white flex items-center justify-center font-bold text-sm shadow-lg shadow-sky-500/30">
                  <Edit3 className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="font-heading font-extrabold text-slate-900 dark:text-white text-base">Enrichir & Modifier le Rapport</h3>
                  <p className="text-xs text-sky-500 font-mono font-bold">{incidentToEdit.incident_code}</p>
                </div>
              </div>
              <button
                onClick={() => setIncidentToEdit(null)}
                className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-white rounded-lg transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveEdit} className="space-y-4 text-xs">
              
              <div>
                <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                  Titre du Rapport
                </label>
                <input
                  type="text"
                  required
                  value={editTitle}
                  onChange={(e) => setEditTitle(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                    Statut
                  </label>
                  <select
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-sky-500"
                  >
                    <option value="NEW">NOUVEAU</option>
                    <option value="INVESTIGATING">EN COURS</option>
                    <option value="RESOLVED">RÉSOLU</option>
                    <option value="CLOSED">CLOS</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                    Sévérité
                  </label>
                  <select
                    value={editSeverity}
                    onChange={(e) => setEditSeverity(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-sky-500"
                  >
                    <option value="HIGH">ÉLEVÉE</option>
                    <option value="MEDIUM">MOYENNE</option>
                    <option value="LOW">FAIBLE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                    Verdict
                  </label>
                  <select
                    value={editVerdict}
                    onChange={(e) => setEditVerdict(e.target.value)}
                    className="w-full px-3 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-sky-500"
                  >
                    <option value="PHISHING">PHISHING</option>
                    <option value="LEGITIMATE">LÉGITIME</option>
                    <option value="SUSPICIOUS">SUSPECT</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[10px] text-slate-500 dark:text-slate-400 font-mono font-bold uppercase mb-1">
                  Notes de l'Enquêteur SOC
                </label>
                <textarea
                  rows={4}
                  placeholder="Ajoutez vos remarques d'analyse forensique, actions de remédiation, etc."
                  value={editNotes}
                  onChange={(e) => setEditNotes(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-[#1e293b] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white font-semibold text-xs focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIncidentToEdit(null)}
                  className="px-4 py-2.5 bg-slate-100 dark:bg-[#1e293b] hover:bg-slate-200 text-slate-700 dark:text-slate-300 font-bold rounded-xl text-xs transition cursor-pointer"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingEdit}
                  className="px-5 py-2.5 bg-sky-500 hover:bg-sky-400 text-white font-bold rounded-xl text-xs shadow-lg shadow-sky-500/25 flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
                >
                  {isSubmittingEdit ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                  Enregistrer les modifications
                </button>
              </div>

            </form>

          </div>
        </div>
      )}

      {/* MODAL 3: CONFIRMATION DE SUPPRESSION */}
      {incidentToDelete && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-3xl p-6 max-w-md w-full shadow-2xl space-y-4 animate-fade-in">
            <div className="w-12 h-12 rounded-2xl bg-rose-500/10 text-rose-500 flex items-center justify-center mx-auto">
              <Trash2 className="w-6 h-6" />
            </div>

            <div className="text-center space-y-1">
              <h3 className="font-extrabold text-base text-slate-900 dark:text-white">Confirmer la suppression</h3>
              <p className="text-xs text-slate-500">
                Êtes-vous sûr de vouloir supprimer définitivement le rapport <strong className="font-mono text-rose-500">{incidentToDelete.incident_code}</strong> ?
              </p>
            </div>

            <div className="p-3 bg-slate-50 dark:bg-[#1e293b] rounded-xl border border-slate-200 dark:border-slate-800 text-xs font-mono text-slate-700 dark:text-slate-300 truncate">
              {incidentToDelete.title}
            </div>

            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={() => setIncidentToDelete(null)}
                className="w-1/2 py-2.5 bg-slate-100 dark:bg-[#1e293b] hover:bg-slate-200 text-slate-700 dark:text-slate-300 font-bold rounded-xl text-xs transition cursor-pointer"
              >
                Annuler
              </button>
              <button
                onClick={handleConfirmDelete}
                disabled={isDeleting}
                className="w-1/2 py-2.5 bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-xl text-xs shadow-lg shadow-rose-600/25 flex items-center justify-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                {isDeleting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                Supprimer
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 4: RÉSULTAT DE VÉRIFICATION SHA-256 */}
      {verificationModalData && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-3xl p-6 max-w-md w-full shadow-2xl space-y-4 animate-fade-in text-center">
            
            <div className={`w-14 h-14 rounded-3xl flex items-center justify-center mx-auto shadow-lg ${
              verificationModalData.result.valid ? 'bg-emerald-500/10 text-emerald-500 shadow-emerald-500/20' : 'bg-rose-500/10 text-rose-500 shadow-rose-500/20'
            }`}>
              {verificationModalData.result.valid ? <CheckCircle2 className="w-8 h-8" /> : <AlertTriangle className="w-8 h-8" />}
            </div>

            <div>
              <h3 className="font-extrabold text-base text-slate-900 dark:text-white">
                {verificationModalData.result.valid ? "Sceau Cryptographique Valide !" : "Altération Détectée !"}
              </h3>
              <p className="text-xs text-slate-500 mt-1">
                {verificationModalData.result.verification_message || (verificationModalData.result.valid ? "L'empreinte SHA-256 scellée en base correspond parfaitement au contenu." : "Attention, le sceau ne correspond pas.")}
              </p>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] font-mono text-emerald-400 break-all text-left space-y-1">
              <span className="text-[9px] text-slate-500 uppercase font-bold block">Empreinte SHA-256 Vérifiée :</span>
              <span>{verificationModalData.hash}</span>
            </div>

            <button
              onClick={() => setVerificationModalData(null)}
              className="w-full py-2.5 bg-sky-500 hover:bg-sky-400 text-white font-bold rounded-xl text-xs transition cursor-pointer"
            >
              Fermer
            </button>
          </div>
        </div>
      )}

    </div>
  );
}
