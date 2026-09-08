import React, { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { 
  Users, ShieldCheck, ShieldAlert, Lock, Activity, RefreshCw, 
  UserCheck, AlertOctagon, CheckCircle2, FileText, Database, History
} from 'lucide-react';

export default function AdminDashboard() {
  const { user, token } = useAuth();
  const [usersList, setUsersList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [metrics, setMetrics] = useState({ totalUsers: 0, stdUsers: 0, investigators: 0, admins: 0 });
  const [actionMessage, setActionMessage] = useState(null);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/users', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (data.users) {
        setUsersList(data.users);
        const std = data.users.filter(u => u.role === 'UTILISATEUR_STANDARD').length;
        const enq = data.users.filter(u => u.role === 'ENQUETEUR').length;
        const adm = data.users.filter(u => u.role === 'ADMINISTRATEUR').length;
        setMetrics({ totalUsers: data.users.length, stdUsers: std, investigators: enq, admins: adm });
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleChangeRole = async (targetUser, newRole) => {
    setActionMessage(null);
    if (targetUser.role === 'ADMINISTRATEUR') {
      setActionMessage({ type: 'error', text: 'Protection Administrateur : Impossible de modifier un compte Administrateur !' });
      return;
    }

    try {
      const res = await fetch(`/api/v1/users/${targetUser.id}/role`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ new_role: newRole })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Échec de modification de rôle");
      }

      setActionMessage({ type: 'success', text: `Rôle de ${targetUser.prenom} ${targetUser.nom} mis à jour avec succès : ${newRole}` });
      fetchUsers();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-amber-950 to-slate-900 border border-amber-800/40 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-amber-500/10 border border-amber-400/20 text-amber-400 text-xs font-semibold rounded-full mb-2">
            <Lock size={14} /> Console d'Administration PhishGuard
          </div>
          <h1 className="text-2xl font-bold text-white">Gestion Système & Rôles — {user?.prenom} {user?.nom}</h1>
          <p className="text-slate-400 text-sm mt-1">Supervisez les comptes de la plateforme, affectez les rôles Enquêteur et consultez les métriques système.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <NavLink
            to="/scanner"
            className="bg-sky-600 hover:bg-sky-500 text-white px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-sky-600/30 transition-all"
          >
            <ShieldAlert size={14} /> Scanner IA
          </NavLink>
          <NavLink
            to="/history"
            className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all"
          >
            <History size={14} /> Historique
          </NavLink>
          <button
            onClick={fetchUsers}
            className="bg-amber-600 hover:bg-amber-500 text-white px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-amber-600/30 transition-all"
          >
            <RefreshCw size={14} /> Actualiser
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl flex items-center gap-4">
          <div className="p-3 bg-sky-500/10 text-sky-400 rounded-xl border border-sky-500/20">
            <Users size={24} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Total Utilisateurs</div>
            <div className="text-xl font-bold text-white">{metrics.totalUsers}</div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl flex items-center gap-4">
          <div className="p-3 bg-indigo-500/10 text-indigo-400 rounded-xl border border-indigo-500/20">
            <UserCheck size={24} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Utilisateurs Standards</div>
            <div className="text-xl font-bold text-white">{metrics.stdUsers}</div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/20">
            <ShieldCheck size={24} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Enquêteurs SOC</div>
            <div className="text-xl font-bold text-white">{metrics.investigators}</div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-5 rounded-2xl flex items-center gap-4">
          <div className="p-3 bg-amber-500/10 text-amber-400 rounded-xl border border-amber-500/20">
            <Lock size={24} />
          </div>
          <div>
            <div className="text-xs text-slate-400 font-medium">Administrateurs</div>
            <div className="text-xl font-bold text-white">{metrics.admins}</div>
          </div>
        </div>
      </div>

      {actionMessage && (
        <div className={`p-4 rounded-xl border text-xs font-semibold flex items-center gap-2 ${
          actionMessage.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
        }`}>
          {actionMessage.type === 'success' ? <CheckCircle2 size={16} /> : <AlertOctagon size={16} />}
          <span>{actionMessage.text}</span>
        </div>
      )}

      {/* User Directory Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <Users className="text-amber-400" size={20} /> Annuaire et Affectation des Rôles
          </h2>
          <span className="text-xs text-slate-400 bg-slate-950 px-3 py-1 rounded-full border border-slate-800 font-mono">
            Règle de Protection Admin : Active
          </span>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-500 text-xs flex items-center justify-center gap-2">
            <RefreshCw className="animate-spin" size={16} /> Chargement de l'annuaire des utilisateurs...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th className="p-3">Utilisateur</th>
                  <th className="p-3">Email</th>
                  <th className="p-3">Rôle Actuel</th>
                  <th className="p-3">Statut Protection</th>
                  <th className="p-3 text-right">Action de Rôle</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {usersList.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-800/30">
                    <td className="p-3 font-semibold text-white">
                      {u.prenom} {u.nom}
                    </td>
                    <td className="p-3 font-mono text-slate-300">{u.email}</td>
                    <td className="p-3">
                      <span className={`px-2.5 py-1 rounded-md font-bold text-[11px] ${
                        u.role === 'ADMINISTRATEUR' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                        u.role === 'ENQUETEUR' ? 'bg-indigo-500/20 text-indigo-400 border border-indigo-500/30' :
                        'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                      }`}>
                        {u.role}
                      </span>
                    </td>
                    <td className="p-3">
                      {u.role === 'ADMINISTRATEUR' ? (
                        <span className="inline-flex items-center gap-1 text-amber-400 text-[10px] font-bold bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800">
                          <Lock size={10} /> Protégé (Immuable)
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[10px]">Editable par Admin</span>
                      )}
                    </td>
                    <td className="p-3 text-right space-x-2">
                      {u.role === 'ADMINISTRATEUR' ? (
                        <span className="text-slate-600 text-xs italic">Verrouillé</span>
                      ) : (
                        <>
                          {u.role !== 'ENQUETEUR' && (
                            <button
                              onClick={() => handleChangeRole(u, 'ENQUETEUR')}
                              className="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold px-3 py-1 rounded-lg transition-all"
                            >
                              Promouvoir Enquêteur
                            </button>
                          )}
                          {u.role !== 'UTILISATEUR_STANDARD' && (
                            <button
                              onClick={() => handleChangeRole(u, 'UTILISATEUR_STANDARD')}
                              className="bg-slate-700 hover:bg-slate-600 text-white text-xs font-bold px-3 py-1 rounded-lg transition-all"
                            >
                              Rétrograder Standard
                            </button>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
