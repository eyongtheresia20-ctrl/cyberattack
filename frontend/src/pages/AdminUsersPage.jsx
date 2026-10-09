import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useLanguage } from '../context/LanguageContext';
import {
  Users, ShieldCheck, UserCheck,
  AlertOctagon, CheckCircle2, Trash2, Search,
  Filter, RefreshCw, Ban, X, Globe, Plus
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
  const [siteModalUser, setSiteModalUser] = useState(null);
  const [siteDraft, setSiteDraft] = useState([]);
  const [permsDraft, setPermsDraft] = useState({});
  const [settingsPolicy, setSettingsPolicy] = useState(null);
  const [siteInput, setSiteInput] = useState('');
  const [isSavingSites, setIsSavingSites] = useState(false);
  const [isLoadingPolicy, setIsLoadingPolicy] = useState(false);

  const openSiteModal = async (u) => {
    setSiteModalUser(u);
    setSiteDraft(Array.isArray(u.blocked_sites) ? [...u.blocked_sites] : []);
    setPermsDraft(typeof u.permissions === 'object' && u.permissions ? { ...u.permissions } : {
      can_analyze_url: true,
      can_analyze_message: true,
      can_view_reports: true,
      can_submit_incidents: true,
      can_export_pdf: true,
      block_social_media: false,
      block_streaming: false,
      block_adult_content: true,
      block_gambling: true,
      block_all_settings_sites: false
    });
    setSiteInput('');
    setIsLoadingPolicy(true);
    try {
      const res = await fetch('/api/v1/enterprise/policy-settings');
      if (res.ok) {
        const data = await res.json();
        setSettingsPolicy(data);
      }
    } catch (e) {
      console.error('Fetch policy settings error:', e);
    } finally {
      setIsLoadingPolicy(false);
    }
  };

  const addSiteToDraft = () => {
    const d = siteInput.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (d && d.includes('.') && !siteDraft.includes(d)) setSiteDraft([...siteDraft, d]);
    setSiteInput('');
  };

  const toggleSiteInDraft = (dom) => {
    const clean = dom.trim().toLowerCase();
    if (siteDraft.includes(clean)) {
      setSiteDraft(siteDraft.filter(s => s !== clean));
    } else {
      setSiteDraft([...siteDraft, clean]);
    }
  };

  const toggleCategoryInDraft = (key) => {
    setPermsDraft(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const toggleAllSettingsSites = () => {
    const allSettingsDomains = settingsPolicy?.custom_blacklist || [];
    const allBlocked = allSettingsDomains.length > 0 && allSettingsDomains.every(d => siteDraft.includes(d));
    if (allBlocked) {
      setSiteDraft(siteDraft.filter(d => !allSettingsDomains.includes(d)));
      setPermsDraft(prev => ({ ...prev, block_all_settings_sites: false }));
    } else {
      const combined = Array.from(new Set([...siteDraft, ...allSettingsDomains]));
      setSiteDraft(combined);
      setPermsDraft(prev => ({ ...prev, block_all_settings_sites: true }));
    }
  };

  const saveBlockedSites = async () => {
    if (!siteModalUser) return;
    setIsSavingSites(true);
    try {
      let res = await fetch(`/api/v1/users/${siteModalUser.id}/permissions`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({
          blocked_sites: siteDraft,
          permissions: permsDraft
        })
      });
      if (res.status === 404) {
        res = await fetch(`/api/v1/users/${siteModalUser.id}/status`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
          body: JSON.stringify({
            is_active: siteModalUser.is_active ?? true,
            blocked_sites: siteDraft,
            permissions: permsDraft
          })
        });
      }

      // Synchronisation temps réel avec policy-settings (persistance immédiate)
      try {
        const polRes = await fetch('/api/v1/enterprise/policy-settings');
        if (polRes.ok) {
          const polData = await polRes.json();
          const currentSettings = polData.settings || polData || {};
          const currentRestrictions = currentSettings.user_restrictions || {};
          currentRestrictions[siteModalUser.id] = {
            blocked_sites: siteDraft,
            permissions: permsDraft
          };
          if (siteModalUser.email) {
            currentRestrictions[siteModalUser.email.toLowerCase()] = {
              blocked_sites: siteDraft,
              permissions: permsDraft
            };
          }
          await fetch('/api/v1/enterprise/policy-settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({
              user_restrictions: currentRestrictions
            })
          });
        }
      } catch (pe) {
        console.warn('Sync policy-settings restrictions error:', pe);
      }

      setActionMessage({
        type: 'success',
        text: lang === 'fr'
          ? `Restrictions mises à jour pour ${siteModalUser.prenom} ${siteModalUser.nom} (${siteDraft.length} site(s) bloqué(s)).`
          : `Restrictions updated for ${siteModalUser.prenom} ${siteModalUser.nom} (${siteDraft.length} site(s) blocked).`
      });
      setSiteModalUser(null);
      fetchUsers();
    } catch (err) {
      setActionMessage({ type: 'error', text: err.message });
    } finally {
      setIsSavingSites(false);
    }
  };

  const fetchUsers = async () => {
    setLoading(true);
    try {
      const [res, polRes] = await Promise.all([
        fetch('/api/v1/users', { headers: { 'Authorization': `Bearer ${token}` } }),
        fetch('/api/v1/enterprise/policy-settings').catch(() => null)
      ]);
      const data = await res.json();
      let polMap = {};
      if (polRes && polRes.ok) {
        const pData = await polRes.json();
        polMap = (pData.settings || pData || {}).user_restrictions || {};
      }
      if (data.users) {
        const nonAdminUsers = data.users.filter(u => u.role !== 'ADMINISTRATEUR').map(u => {
          const specific = polMap[u.id] || polMap[u.email?.toLowerCase()] || {};
          const mergedBlockedSites = Array.isArray(u.blocked_sites) && u.blocked_sites.length > 0
            ? u.blocked_sites
            : (specific.blocked_sites || []);
          const mergedPerms = (typeof u.permissions === 'object' && u.permissions && Object.keys(u.permissions).length > 0)
            ? { ...u.permissions, ...(specific.permissions || {}) }
            : (specific.permissions || u.permissions);
          return {
            ...u,
            blocked_sites: mergedBlockedSites,
            permissions: mergedPerms
          };
        });
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
                  <th className="p-3.5">{lang === 'fr' ? 'Sites Interdits (Paramètres)' : 'Blocked Sites (Settings)'}</th>
                  <th className="p-3.5 text-right">{lang === 'fr' ? 'Actions Admin' : 'Admin Actions'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredUsers.map((u) => {
                  const isBlocked = u.is_active === false;
                  const blockedCount = (u.blocked_sites || []).length;
                  const hasAllBlocked = u.permissions?.block_all_settings_sites === true;
                  const isSiteRestricted = blockedCount > 0 || hasAllBlocked;
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
                      <td className="p-3.5">
                        <button
                          onClick={() => openSiteModal(u)}
                          title={lang === 'fr' ? 'Cliquer pour bloquer des sites configurés dans les Paramètres pour cet utilisateur' : 'Click to block sites configured in Settings for this user'}
                          className={`group px-3 py-1.5 rounded-xl text-xs font-bold border flex items-center gap-2.5 transition cursor-pointer shadow-sm select-none ${
                            isSiteRestricted
                              ? 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-600 dark:text-rose-400 border-rose-500/30 hover:border-rose-500'
                              : 'bg-slate-50 dark:bg-slate-800/60 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:border-rose-400'
                          }`}
                        >
                          <span className={`w-8 h-4 rounded-full p-0.5 flex items-center transition-colors shrink-0 ${
                            isSiteRestricted ? 'bg-rose-500 justify-end' : 'bg-slate-300 dark:bg-slate-600 justify-start'
                          }`}>
                            <span className="w-3 h-3 rounded-full bg-white shadow" />
                          </span>
                          <Globe size={13} className={isSiteRestricted ? 'text-rose-500' : 'text-slate-400'} />
                          <span className="font-mono text-[11px]">
                            {blockedCount > 0
                              ? `${blockedCount} ${lang === 'fr' ? 'site(s) bloqué(s)' : 'blocked'}`
                              : hasAllBlocked
                                ? (lang === 'fr' ? 'Tous les sites Paramètres' : 'All settings sites')
                                : (lang === 'fr' ? '0 site bloqué (Libre)' : '0 site (Open)')}
                          </span>
                        </button>
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
                          {!isBlocked ? <><Ban size={13} /> {lang === 'fr' ? 'Bloquer Compte' : 'Block Account'}</> : <><CheckCircle2 size={13} /> {lang === 'fr' ? 'Débloquer' : 'Unblock'}</>}
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

      {/* Per-user blocked sites modal */}
      {siteModalUser && (
        <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white dark:bg-[#0f172a] border border-slate-200 dark:border-sky-900/60 rounded-3xl p-6 max-w-xl w-full shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className="p-3 bg-rose-500/10 rounded-2xl border border-rose-500/20 text-rose-500"><Globe size={22} /></div>
                <div>
                  <h3 className="font-extrabold text-slate-900 dark:text-white text-base">
                    {lang === 'fr' ? 'Restrictions des Sites & Politiques' : 'Site & Policy Restrictions'}
                  </h3>
                  <p className="text-xs text-slate-500">
                    {siteModalUser.prenom} {siteModalUser.nom} — <span className="font-mono text-slate-400">{siteModalUser.email}</span>
                  </p>
                </div>
              </div>
              <button onClick={() => setSiteModalUser(null)} className="p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"><X size={16} /></button>
            </div>

            {/* Quick Master Toggle: Block all settings sites */}
            {(() => {
              const allSettingsDomains = settingsPolicy?.custom_blacklist || [];
              const allBlocked = allSettingsDomains.length > 0 && allSettingsDomains.every(d => siteDraft.includes(d));
              return (
                <div className="p-3.5 rounded-2xl bg-gradient-to-r from-rose-500/10 via-purple-500/5 to-transparent border border-rose-500/30 flex items-center justify-between gap-3">
                  <div>
                    <h4 className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <Ban size={14} className="text-rose-500" />
                      {lang === 'fr' ? 'Bloquer tous les sites assignés dans les Paramètres' : 'Block all sites assigned in Settings'}
                    </h4>
                    <p className="text-[11px] text-slate-500">
                      {lang === 'fr'
                        ? `Applique instantanément les ${allSettingsDomains.length} site(s) configurés dans les Paramètres généraux.`
                        : `Instantly applies the ${allSettingsDomains.length} site(s) configured in general Settings.`}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={toggleAllSettingsSites}
                    className={`w-11 h-6 rounded-full p-0.5 transition-colors flex items-center cursor-pointer shrink-0 ${
                      allBlocked ? 'bg-rose-500 justify-end' : 'bg-slate-300 dark:bg-slate-700 justify-start'
                    }`}
                  >
                    <span className="w-5 h-5 rounded-full bg-white shadow-md" />
                  </button>
                </div>
              );
            })()}

            {/* Section 1: Sites from Settings */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase tracking-wider font-mono text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                  <Globe size={13} className="text-sky-500" />
                  {lang === 'fr' ? '1. Sites configurés dans les Paramètres (À cocher) :' : '1. Sites from Settings (Toggle to block):'}
                </span>
                <span className="text-[10px] font-mono text-slate-400">
                  {settingsPolicy?.custom_blacklist?.length || 0} {lang === 'fr' ? 'disponible(s)' : 'available'}
                </span>
              </div>

              {isLoadingPolicy ? (
                <div className="py-4 text-center text-xs text-slate-400 font-mono flex items-center justify-center gap-2">
                  <RefreshCw size={14} className="animate-spin" /> {lang === 'fr' ? 'Chargement des paramètres...' : 'Loading settings...'}
                </div>
              ) : (!settingsPolicy?.custom_blacklist || settingsPolicy.custom_blacklist.length === 0) ? (
                <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 text-xs text-slate-500 font-mono text-center">
                  {lang === 'fr'
                    ? "Aucun site n'est configuré dans les Paramètres globaux. Ajoutez-en dans la page Paramètres ou saisissez un domaine ci-dessous."
                    : "No sites configured in global Settings yet. Add them in Settings or type below."}
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-40 overflow-y-auto p-1">
                  {settingsPolicy.custom_blacklist.map((dom) => {
                    const isChecked = siteDraft.includes(dom);
                    return (
                      <div
                        key={dom}
                        onClick={() => toggleSiteInDraft(dom)}
                        className={`p-2.5 rounded-xl border flex items-center justify-between gap-2 cursor-pointer transition text-xs font-mono select-none ${
                          isChecked
                            ? 'bg-rose-500/10 border-rose-500/40 text-rose-600 dark:text-rose-400'
                            : 'bg-slate-50 dark:bg-slate-800/60 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-slate-400'
                        }`}
                      >
                        <span className="truncate font-bold flex items-center gap-1.5">
                          <Ban size={12} className={isChecked ? 'text-rose-500' : 'text-slate-400'} />
                          {dom}
                        </span>
                        <span className={`w-8 h-4 rounded-full p-0.5 flex items-center transition-colors shrink-0 ${
                          isChecked ? 'bg-rose-500 justify-end' : 'bg-slate-300 dark:bg-slate-600 justify-start'
                        }`}>
                          <span className="w-3 h-3 rounded-full bg-white shadow" />
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Section 2: Functional & Content Filtering Categories */}
            <div className="space-y-2 pt-1 border-t border-slate-100 dark:border-slate-800">
              <span className="text-[11px] font-bold uppercase tracking-wider font-mono text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                <ShieldCheck size={13} className="text-emerald-500" />
                {lang === 'fr' ? '2. Catégories de Filtrage Web :' : '2. Web Filtering Categories:'}
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                {[
                  { key: 'block_adult_content', label: 'Contenu Adulte', desc: '.xxx, porn, cam...' },
                  { key: 'block_gambling', label: 'Jeux & Paris', desc: '1xBet, Betway, casinos...' },
                  { key: 'block_social_media', label: 'Réseaux Sociaux', desc: 'Facebook, TikTok, X...' },
                  { key: 'block_streaming', label: 'Streaming Vidéo', desc: 'YouTube, Netflix...' }
                ].map(({ key, label, desc }) => {
                  const active = !!permsDraft[key];
                  return (
                    <div
                      key={key}
                      onClick={() => toggleCategoryInDraft(key)}
                      className={`p-2.5 rounded-xl border flex items-center justify-between gap-2 cursor-pointer transition select-none ${
                        active
                          ? 'bg-rose-500/10 border-rose-500/40 text-rose-600 dark:text-rose-400'
                          : 'bg-slate-50 dark:bg-slate-800/60 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-slate-400'
                      }`}
                    >
                      <div>
                        <div className="font-bold">{label}</div>
                        <div className="text-[10px] text-slate-400">{desc}</div>
                      </div>
                      <span className={`w-8 h-4 rounded-full p-0.5 flex items-center transition-colors shrink-0 ${
                        active ? 'bg-rose-500 justify-end' : 'bg-slate-300 dark:bg-slate-600 justify-start'
                      }`}>
                        <span className="w-3 h-3 rounded-full bg-white shadow" />
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Section 3: Add an extra custom domain */}
            <div className="space-y-2 pt-1 border-t border-slate-100 dark:border-slate-800">
              <span className="text-[11px] font-bold uppercase tracking-wider font-mono text-slate-700 dark:text-slate-300">
                {lang === 'fr' ? '3. Ajouter un site spécifique pour cet utilisateur :' : '3. Add a specific site for this user:'}
              </span>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={siteInput}
                  onChange={(e) => setSiteInput(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addSiteToDraft(); } }}
                  placeholder={lang === 'fr' ? 'ex : reddit.com, telegram.org' : 'e.g. reddit.com'}
                  className="flex-1 px-3 py-2 bg-slate-50 dark:bg-[#161b27] border border-slate-200 dark:border-slate-800 rounded-xl text-xs text-slate-900 dark:text-white focus:outline-none focus:border-rose-500 font-mono"
                />
                <button onClick={addSiteToDraft} className="px-3 py-2 bg-slate-900 dark:bg-slate-700 hover:bg-slate-800 text-white rounded-xl text-xs font-bold flex items-center gap-1 cursor-pointer">
                  <Plus size={14} /> {lang === 'fr' ? 'Ajouter' : 'Add'}
                </button>
              </div>

              {/* List of custom added sites not from settings */}
              {(() => {
                const settingsDomains = settingsPolicy?.custom_blacklist || [];
                const extraDomains = siteDraft.filter(d => !settingsDomains.includes(d));
                if (extraDomains.length === 0) return null;
                return (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {extraDomains.map(s => (
                      <span key={s} className="px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-600 dark:text-rose-400 text-xs font-mono font-bold flex items-center gap-1.5">
                        <Ban size={11} /> {s}
                        <button onClick={() => setSiteDraft(siteDraft.filter(x => x !== s))} className="hover:text-rose-700 cursor-pointer"><X size={12} /></button>
                      </span>
                    ))}
                  </div>
                );
              })()}
            </div>

            {/* Total Summary & Actions */}
            <div className="flex items-center justify-between pt-3 border-t border-slate-100 dark:border-slate-800">
              <span className="text-xs font-mono font-bold text-slate-500">
                {siteDraft.length} {lang === 'fr' ? 'site(s) bloqué(s)' : 'site(s) blocked'}
              </span>
              <div className="flex items-center gap-2">
                <button onClick={() => setSiteModalUser(null)} className="px-4 py-2 rounded-xl text-xs font-bold text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition cursor-pointer">
                  {lang === 'fr' ? 'Annuler' : 'Cancel'}
                </button>
                <button onClick={saveBlockedSites} disabled={isSavingSites} className="px-4 py-2 bg-rose-500 hover:bg-rose-600 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition cursor-pointer shadow-md shadow-rose-500/20">
                  {isSavingSites ? (lang === 'fr' ? 'Enregistrement...' : 'Saving...') : (lang === 'fr' ? 'Enregistrer les restrictions' : 'Save Restrictions')}
                </button>
              </div>
            </div>

          </div>
        </div>
      )}

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
