import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import {
  Users, ShieldCheck, UserCheck,
  AlertOctagon, CheckCircle2, Trash2, Search,
  Filter, RefreshCw, Ban, X
} from 'lucide-react';

export default function AdminUsersPage() {
  const { token } = useAuth();
  const { lang } = useLanguage();
  const [usersList, setUsersList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState('ALL');
  const [actionMessage, setActionMessage] = useState(null);
  const [userToDelete, setUserToDelete] = useState(null);
  const [isDeleting, setIsDeleting] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/users', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (data.users) {
        const nonAdminUsers = data.users.filter(u => u.role !== 'ADMINISTRATEUR');
        setUsersList(nonAdminUsers);
      }
    } catch (err) {
      console.error('Failed to fetch users', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchUsers(); }, []);

  useEffect(() => {
    if (actionMessage) {
      const timer = setTimeout(() => {
        setActionMessage(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [actionMessage]);

  const handleToggleBlockStatus = async (targetUser) => {
    setActionMessage(null);
    if (targetUser.role === 'ADMINISTRATEUR') {
      setActionMessage({ 
        type: 'error', 
        text: lang === 'fr' ? 'Impossible de bloquer un compte Administrateur !' : 'Cannot block Administrator account!' 
      });
      return;
    }
    try {
      const shouldBeActive = !targetUser.is_active;
      const res = await fetch(`/api/v1/users/${targetUser.id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ is_active: shouldBeActive })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Echec du changement de statut");
      setActionMessage({
        type: 'success',
        text: lang === 'fr'
          ? `Compte de ${targetUser.prenom} ${targetUser.nom} ${shouldBeActive ? 'débloqué avec succès' : 'bloqué avec succès'}.`
          : `Account for ${targetUser.prenom} ${targetUser.nom} ${shouldBeActive ? 'unblocked successfully' : 'blocked successfully'}.`
      });
      fetchUsers();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    }
  };

  const handleRoleChange = async (targetUser, newRole) => {
    if (targetUser.role === newRole) return;
    setActionMessage(null);
    try {
      const res = await fetch(`/api/v1/users/${targetUser.id}/role`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ new_role: newRole })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Echec de modification du rôle");
      setActionMessage({
        type: 'success',
        text: lang === 'fr'
          ? `Rôle de ${targetUser.prenom} ${targetUser.nom} mis à jour : ${newRole === 'ENQUETEUR' ? 'Enquêteur SOC' : 'Utilisateur Standard'}.`
          : `Role for ${targetUser.prenom} ${targetUser.nom} updated to ${newRole === 'ENQUETEUR' ? 'SOC Investigator' : 'Standard User'}.`
      });
      fetchUsers();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    }
  };

  const handleDeleteUser = async () => {
    if (!userToDelete) return;
    setActionMessage(null);
    setIsDeleting(true);
    try {
      const res = await fetch(`/api/v1/users/${userToDelete.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Echec de suppression");
      setActionMessage({ 
        type: 'success', 
        text: lang === 'fr' ? `Utilisateur ${userToDelete.email} supprimé avec succès.` : `User ${userToDelete.email} deleted successfully.` 
      });
      setUserToDelete(null);
      fetchUsers();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    } finally {
      setIsDeleting(false);
    }
  };

  const filteredUsers = usersList.filter(u => {
    const matchesSearch =
      `${u.prenom} ${u.nom}`.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.email.toLowerCase().includes(searchQuery.toLowerCase());
    if (roleFilter === 'STANDARD') return matchesSearch && u.role === 'UTILISATEUR_STANDARD';
    if (roleFilter === 'ENQUETEUR') return matchesSearch && u.role === 'ENQUETEUR';
    return matchesSearch;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16">

      {actionMessage && (
        <div className={`p-4 rounded-2xl border text-xs font-semibold flex items-center justify-between shadow-sm transition-all duration-300 animate-in fade-in ${
          actionMessage.type === 'success'
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
            : 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-400'
        }`}>
          <div className="flex items-center gap-2">
            {actionMessage.type === 'success' ? <CheckCircle2 size={16} /> : <AlertOctagon size={16} />}
            <span>{actionMessage.text}</span>
          </div>
          <button
            onClick={() => setActionMessage(null)}
            className="p-1 hover:bg-black/5 dark:hover:bg-white/10 rounded-lg transition cursor-pointer text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            title={lang === 'fr' ? 'Fermer' : 'Close'}
          >
            <X size={15} />
          </button>
        </div>
      )}

      <div className="bg-white dark:bg-[#161b27] border border-slate-200 dark:border-sky-900/40 rounded-3xl p-6 shadow-sm space-y-5">
        {/* Search & Filter Controls */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder={lang === 'fr' ? "Rechercher utilisateur ou email..." : "Search user name or email..."}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:border-sky-500"
            />
          </div>

          <div className="flex items-center gap-2 text-xs">
            <Filter size={14} className="text-sky-500" />
            <span className="text-slate-500 font-medium">{lang === 'fr' ? 'Filtrer par rôle :' : 'Filter by role:'}</span>
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="bg-slate-50 dark:bg-[#0f172a] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white rounded-xl px-3 py-1.5 text-xs font-semibold focus:outline-none focus:border-sky-500 cursor-pointer"
            >
              <option value="ALL">{lang === 'fr' ? 'Tous les comptes' : 'All Accounts'}</option>
              <option value="STANDARD">{lang === 'fr' ? 'Utilisateurs Standards' : 'Standard Users'}</option>
              <option value="ENQUETEUR">{lang === 'fr' ? 'Enquêteurs SOC' : 'SOC Investigators'}</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-500 text-xs flex items-center justify-center gap-2">
            <RefreshCw className="animate-spin text-sky-500" size={16} /> {lang === 'fr' ? 'Chargement des utilisateurs...' : 'Loading user list...'}
          </div>
        ) : (
          <div className="overflow-x-auto border border-slate-200 dark:border-slate-800/80 rounded-2xl">
            <table className="w-full text-left text-xs text-slate-700 dark:text-slate-300">
              <thead className="bg-slate-50 dark:bg-[#0f172a] text-slate-500 dark:text-slate-400 uppercase font-bold border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="p-3.5">{lang === 'fr' ? 'Nom et Prénom' : 'Full Name'}</th>
                  <th className="p-3.5">Email</th>
                  <th className="p-3.5">{lang === 'fr' ? 'Rôle' : 'Role'}</th>
                  <th className="p-3.5">{lang === 'fr' ? 'Statut Compte' : 'Account Status'}</th>
                  <th className="p-3.5 text-right">{lang === 'fr' ? 'Actions Admin' : 'Admin Actions'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredUsers.map((u) => {
                  const isBlocked = u.is_active === false;
                  return (
                    <tr key={u.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/30 transition">
                      <td className="p-3.5 font-bold text-slate-900 dark:text-white">{u.prenom} {u.nom}</td>
                      <td className="p-3.5 font-mono text-slate-600 dark:text-slate-400">{u.email}</td>
                      <td className="p-3.5">
                        <select
                          value={u.role}
                          onChange={(e) => handleRoleChange(u, e.target.value)}
                          className={`px-3 py-1.5 rounded-xl font-bold text-[11px] border cursor-pointer focus:outline-none transition shadow-sm ${
                            u.role === 'ENQUETEUR'
                              ? 'bg-indigo-500/10 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border-indigo-500/30 hover:border-indigo-500'
                              : 'bg-sky-50 dark:bg-sky-950/40 text-sky-600 dark:text-sky-300 border-sky-200 dark:border-sky-800 hover:border-sky-500'
                          }`}
                        >
                          <option value="UTILISATEUR_STANDARD" className="bg-white dark:bg-[#0f172a] text-slate-800 dark:text-slate-200">
                            {lang === 'fr' ? 'UTILISATEUR STANDARD' : 'STANDARD USER'}
                          </option>
                          <option value="ENQUETEUR" className="bg-white dark:bg-[#0f172a] text-indigo-600 dark:text-indigo-400">
                            {lang === 'fr' ? 'SOC ENQUÊTEUR' : 'SOC INVESTIGATOR'}
                          </option>
                        </select>
                      </td>
                      <td className="p-3.5">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[10px] font-bold border ${
                          !isBlocked
                            ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30'
                            : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'
                        }`}>
                          {!isBlocked
                            ? <><CheckCircle2 size={11} /> {lang === 'fr' ? 'Actif' : 'Active'}</>
                            : <><Ban size={11} /> {lang === 'fr' ? 'Bloqué' : 'Blocked'}</>}
                        </span>
                      </td>
                      <td className="p-3.5 text-right space-x-2">
                        <button
                          onClick={() => handleToggleBlockStatus(u)}
                          className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition cursor-pointer inline-flex items-center gap-1.5 ${
                            !isBlocked
                              ? 'bg-amber-500/10 hover:bg-amber-500 hover:text-white text-amber-600 dark:text-amber-400 border border-amber-500/30'
                              : 'bg-emerald-500 hover:bg-emerald-600 text-white shadow-md shadow-emerald-500/20'
                          }`}
                        >
                          {!isBlocked ? <><Ban size={13} /> {lang === 'fr' ? 'Bloquer' : 'Block'}</> : <><CheckCircle2 size={13} /> {lang === 'fr' ? 'Débloquer' : 'Unblock'}</>}
                        </button>
                        <button
                          onClick={() => setUserToDelete(u)}
                          className="bg-rose-500/10 hover:bg-rose-500 text-rose-600 hover:text-white border border-rose-500/20 p-1.5 rounded-xl transition cursor-pointer inline-flex items-center justify-center"
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Confirm Delete Modal */}
      {userToDelete && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-3xl p-6 max-w-md w-full shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-rose-500">
              <div className="p-3 bg-rose-500/10 rounded-2xl border border-rose-500/20"><Trash2 size={24} /></div>
              <div>
                <h3 className="font-extrabold text-slate-900 dark:text-white text-base">
                  {lang === 'fr' ? "Supprimer l'utilisateur ?" : "Delete user account?"}
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">{lang === 'fr' ? 'Cette action est irréversible.' : 'This action cannot be undone.'}</p>
              </div>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              {lang === 'fr' ? 'Êtes-vous sûr de vouloir supprimer le compte de ' : 'Are you sure you want to delete account for '}
              <strong>{userToDelete.prenom} {userToDelete.nom}</strong> ({userToDelete.email}) ?
            </p>
            <div className="flex items-center justify-end gap-3 pt-3">
              <button
                onClick={() => setUserToDelete(null)}
                className="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer"
              >
                {lang === 'fr' ? 'Annuler' : 'Cancel'}
              </button>
              <button
                onClick={handleDeleteUser}
                disabled={isDeleting}
                className="px-4 py-2 bg-rose-500 hover:bg-rose-600 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition shadow-md shadow-rose-500/20 cursor-pointer flex items-center gap-2"
              >
                {isDeleting ? (lang === 'fr' ? "Suppression..." : "Deleting...") : (lang === 'fr' ? "Confirmer la suppression" : "Confirm Delete")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
