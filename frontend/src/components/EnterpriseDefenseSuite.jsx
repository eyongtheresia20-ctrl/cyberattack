import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, Cpu, Terminal, Radio, Eye, Lock, 
  Ban, Unlock, Zap, RefreshCw, FileText, CheckCircle2, AlertTriangle, 
  Upload, Layers, Activity, ArrowRight, Globe
} from 'lucide-react';

export default function EnterpriseDefenseSuite({ 
  lang = 'fr', 
  mode = 'ALL', 
  initialSubTab = 'SANDBOX',
  initialUrl = '' 
}) {
  const [activeSubTab, setActiveSubTab] = useState(
    mode === 'SYSTEM_DEFENSE' 
      ? (initialSubTab === 'SANDBOX' ? 'PCAP' : initialSubTab) 
      : (mode === 'SANDBOX_ONLY' ? 'SANDBOX' : initialSubTab)
  );

  // ── 1. SANDBOX STATE ──
  const [sandboxUrl, setSandboxUrl] = useState(initialUrl || 'https://portswigger.net');
  const [isDetonating, setIsDetonating] = useState(false);
  const [sandboxResult, setSandboxResult] = useState(null);

  useEffect(() => {
    if (initialUrl && initialUrl.trim()) {
      setSandboxUrl(initialUrl.trim());
    }
  }, [initialUrl]);

  const runSandbox = async (target) => {
    const urlToTest = target || sandboxUrl;
    if (!urlToTest.trim()) return;
    setIsDetonating(true);
    try {
      const res = await fetch('/api/v1/enterprise/sandbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToTest })
      });
      if (res.ok) {
        const data = await res.json();
        setSandboxResult(data);
      }
    } catch (e) {
      console.error('Sandbox error:', e);
    } finally {
      setIsDetonating(false);
    }
  };

  // ── 2. PCAP ANALYZER STATE ──
  const [pcapScenario, setPcapScenario] = useState('SYN_FLOOD');
  const [isAnalyzingPcap, setIsAnalyzingPcap] = useState(false);
  const [pcapResult, setPcapResult] = useState(null);

  const runPcapAnalysis = async (scen) => {
    setIsAnalyzingPcap(true);
    try {
      const res = await fetch('/api/v1/enterprise/pcap/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scen || pcapScenario })
      });
      if (res.ok) {
        const data = await res.json();
        setPcapResult(data);
      }
    } catch (e) {
      console.error('PCAP error:', e);
    } finally {
      setIsAnalyzingPcap(false);
    }
  };

  // ── 3. FIREWALL STATE ──
  const [blockedIps, setBlockedIps] = useState([]);
  const [newIpToBlock, setNewIpToBlock] = useState('');
  const [blockReason, setBlockReason] = useState('');
  const [isFirewallLoading, setIsFirewallLoading] = useState(false);

  const fetchBlockedIps = async () => {
    try {
      const res = await fetch('/api/v1/enterprise/firewall/blocked-ips');
      if (res.ok) {
        const data = await res.json();
        setBlockedIps(data.blocked_ips || []);
      }
    } catch (e) {
      console.error('Firewall fetch error:', e);
    }
  };

  const handleBlockIp = async (e) => {
    if (e) e.preventDefault();
    if (!newIpToBlock.trim()) return;
    try {
      const res = await fetch('/api/v1/enterprise/firewall/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: newIpToBlock.trim(),
          reason: blockReason || "Bannissement manuel par l'administrateur",
          severity: "HIGH"
        })
      });
      if (res.ok) {
        setNewIpToBlock('');
        setBlockReason('');
        fetchBlockedIps();
      }
    } catch (e) {
      console.error('Block IP error:', e);
    }
  };

  const handleUnblockIp = async (ip) => {
    try {
      const res = await fetch('/api/v1/enterprise/firewall/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      if (res.ok) {
        fetchBlockedIps();
      }
    } catch (e) {
      console.error('Unblock IP error:', e);
    }
  };

  // ── 4. HONEYPOT STATE ──
  const [honeypotHits, setHoneypotHits] = useState([]);
  const [isHoneypotLoading, setIsHoneypotLoading] = useState(false);

  const fetchHoneypotHits = async () => {
    try {
      const res = await fetch('/api/v1/enterprise/honeypot/traps');
      if (res.ok) {
        const data = await res.json();
        setHoneypotHits(data.hits || []);
      }
    } catch (e) {
      console.error('Honeypot fetch error:', e);
    }
  };

  const simulateHoneypotProbe = async (trapPath) => {
    setIsHoneypotLoading(true);
    try {
      const res = await fetch('/api/v1/enterprise/honeypot/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trap: trapPath || "/wp-login.php",
          ip: `194.26.29.${Math.floor(Math.random() * 200 + 10)}`,
          payload: "Brute-force automated credential probe"
        })
      });
      if (res.ok) {
        fetchHoneypotHits();
        fetchBlockedIps();
      }
    } catch (e) {
      console.error('Honeypot probe error:', e);
    } finally {
      setIsHoneypotLoading(false);
    }
  };

  useEffect(() => {
    fetchBlockedIps();
    fetchHoneypotHits();
    // Default initial mock runs
    runPcapAnalysis('SYN_FLOOD');
  }, []);

  return (
    <div className="bg-white/90 dark:bg-[#111622]/95 backdrop-blur-xl border border-indigo-100 dark:border-indigo-900/40 rounded-3xl p-6 sm:p-8 shadow-2xl space-y-6">
      
      {/* Header Banner - hidden in SANDBOX_ONLY mode */}
      {mode !== 'SANDBOX_ONLY' && (
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-2xl bg-gradient-to-tr from-indigo-600 via-purple-600 to-pink-500 flex items-center justify-center text-white shadow-lg shadow-indigo-500/30">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-black text-slate-900 dark:text-white uppercase tracking-wider font-mono">
                  {lang === 'fr' ? "Défense Réseau, Pare-feu WAF & Honeypots" : "Network Defense, WAF Firewall & Honeypots"}
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-black bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/30 font-mono">
                  ACTIVE DEFENSE
                </span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {lang === 'fr' 
                  ? "Inspection paquets Layer 3/4 PCAP, pare-feu WAF actif et leurres honeypot pour votre infrastructure." 
                  : "Layer 3/4 PCAP packet inspector, active inline WAF firewall, and honeypot traps for your infrastructure."}
              </p>
            </div>
          </div>

          {/* Sub-Tabs for System Defense */}
          <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-slate-100 dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 text-xs">
            {mode === 'ALL' && (
              <button
                type="button"
                onClick={() => setActiveSubTab('SANDBOX')}
                className={`px-3 py-2 rounded-xl font-bold transition flex items-center gap-1.5 cursor-pointer ${
                  activeSubTab === 'SANDBOX'
                    ? 'bg-gradient-to-r from-sky-500 to-blue-600 text-white shadow-md'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Eye className="w-4 h-4" />
                <span>Sandbox URLScan</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => setActiveSubTab('PCAP')}
              className={`px-3 py-2 rounded-xl font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeSubTab === 'PCAP'
                  ? 'bg-gradient-to-r from-purple-500 to-indigo-600 text-white shadow-md'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <Radio className="w-4 h-4" />
              <span>{lang === 'fr' ? '1. Sniffer PCAP (L3/4)' : '1. PCAP Sniffer (L3/4)'}</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveSubTab('FIREWALL')}
              className={`px-3 py-2 rounded-xl font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeSubTab === 'FIREWALL'
                  ? 'bg-gradient-to-r from-rose-500 to-red-600 text-white shadow-md'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              <span>{lang === 'fr' ? `2. Pare-Feu WAF (${blockedIps.length})` : `2. WAF Firewall (${blockedIps.length})`}</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveSubTab('HONEYPOT')}
              className={`px-3 py-2 rounded-xl font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeSubTab === 'HONEYPOT'
                  ? 'bg-gradient-to-r from-amber-500 to-orange-600 text-white shadow-md'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
              }`}
            >
              <Zap className="w-4 h-4" />
              <span>{lang === 'fr' ? `3. Leurres Honeypot (${honeypotHits.length})` : `3. Honeypot Traps (${honeypotHits.length})`}</span>
            </button>
          </div>
        </div>
      )}

      {/* ── SUB-TAB 1: HEADLESS SANDBOX ── */}
      {activeSubTab === 'SANDBOX' && (
        <div className="space-y-5 animate-in fade-in duration-200">
          <div className="p-4 bg-sky-50 dark:bg-sky-950/20 border border-sky-200 dark:border-sky-800/40 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-xs font-black text-sky-900 dark:text-sky-300 font-mono uppercase">
                🔬 Détonation Sécurisée en Bac à Sable (Dynamic Headless Sandbox)
              </h3>
              <p className="text-[11px] text-slate-600 dark:text-slate-400">
                Charge l'URL dans un conteneur isolé, trace la chaîne de redirections, extrait les formulaires voleurs d'identifiants et détecte les iframes masqués.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={sandboxUrl}
                onChange={(e) => setSandboxUrl(e.target.value)}
                placeholder="https://suspicious-target.com"
                className="px-3 py-2 text-xs font-mono rounded-xl bg-white dark:bg-[#1a2333] border border-sky-300 dark:border-sky-800 text-slate-900 dark:text-white w-64 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => runSandbox()}
                disabled={isDetonating}
                className="px-4 py-2 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-600 hover:to-blue-700 text-white font-bold text-xs rounded-xl flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                {isDetonating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Eye className="w-3.5 h-3.5" />}
                <span>{isDetonating ? "Détonation..." : "Détoner"}</span>
              </button>
            </div>
          </div>

          {sandboxResult && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Left Column: Visual Capture / Summary */}
              <div className="p-4 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-2xl space-y-3">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                  <span className="text-xs font-mono font-bold uppercase text-slate-400">Aperçu Rendu DOM</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-black ${
                    sandboxResult.sandbox_verdict === 'MALICIOUS' ? 'bg-rose-500/20 text-rose-500' :
                    sandboxResult.sandbox_verdict === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-500' : 'bg-emerald-500/20 text-emerald-500'
                  }`}>
                    {sandboxResult.sandbox_verdict}
                  </span>
                </div>

                <div className="p-3 bg-slate-900 rounded-xl text-slate-200 text-xs font-mono space-y-2 border border-slate-800">
                  <div className="flex items-center gap-2 text-sky-400">
                    <Globe className="w-4 h-4" />
                    <span className="truncate font-bold">{sandboxResult.hostname}</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Titre : <strong>{sandboxResult.dom_analysis?.page_title || 'Non spécifié'}</strong>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Éléments DOM : <strong>{sandboxResult.visual_preview?.dom_elements_count || 120} nœuds</strong>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Temps de rendu : <strong>{sandboxResult.duration_ms || 320} ms</strong>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <span className="text-[10px] font-mono uppercase font-bold text-slate-400">Indicateurs Comportementaux :</span>
                  {sandboxResult.behavioral_indicators?.length > 0 ? (
                    sandboxResult.behavioral_indicators.map((ind, i) => (
                      <div key={i} className="p-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-[10px] font-mono text-rose-600 dark:text-rose-300 flex items-start gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-500" />
                        <span>{ind}</span>
                      </div>
                    ))
                  ) : (
                    <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-[10px] font-mono text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                      <span>Aucun comportement trompeur ou iframe malveillant détecté dans le DOM.</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column: Redirect Chain & Form Telemetry */}
              <div className="lg:col-span-2 space-y-3">
                {/* Redirects */}
                <div className="p-4 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-2xl space-y-2">
                  <span className="text-xs font-mono font-bold uppercase text-slate-400">
                    Chaîne de Redirections Détectée ({sandboxResult.redirect_chain?.length || 1} saut)
                  </span>
                  <div className="space-y-1.5">
                    {sandboxResult.redirect_chain?.map((hop, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 bg-white dark:bg-[#111622] rounded-xl text-xs font-mono border border-slate-200 dark:border-slate-800">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-sky-500/10 text-sky-600 border border-sky-500/20 shrink-0">
                          {hop.status_code || 200}
                        </span>
                        <span className="truncate text-slate-700 dark:text-slate-300">{hop.url}</span>
                        {i < (sandboxResult.redirect_chain.length - 1) && (
                          <ArrowRight className="w-3.5 h-3.5 text-slate-400 ml-auto shrink-0" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Form & Scripts */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-2xl text-xs space-y-2">
                    <span className="font-mono font-bold uppercase text-slate-400 text-[10px]">Formulaires & Saisie Identifiants</span>
                    <div className="text-[11px] space-y-1 font-mono">
                      <div>Champs mot de passe : <strong className="text-rose-500">{sandboxResult.dom_analysis?.password_inputs_count || 0}</strong></div>
                      <div>Champs financiers / CB : <strong className="text-rose-500">{sandboxResult.dom_analysis?.credit_card_inputs_count || 0}</strong></div>
                      <div>Iframes intégrés : <strong className="text-slate-700 dark:text-slate-300">{sandboxResult.dom_analysis?.iframes?.length || 0}</strong></div>
                    </div>
                  </div>

                  <div className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-2xl text-xs space-y-2">
                    <span className="font-mono font-bold uppercase text-slate-400 text-[10px]">Scripts Externes ({sandboxResult.dom_analysis?.external_scripts?.length || 0})</span>
                    <div className="space-y-1 max-h-24 overflow-y-auto font-mono text-[10px] text-slate-500">
                      {sandboxResult.dom_analysis?.external_scripts?.slice(0, 4).map((sc, i) => (
                        <div key={i} className="truncate">📜 {sc}</div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── SUB-TAB 2: PCAP PACKET ANALYZER ── */}
      {activeSubTab === 'PCAP' && (
        <div className="space-y-5 animate-in fade-in duration-200">
          <div className="p-4 bg-purple-50 dark:bg-purple-950/20 border border-purple-200 dark:border-purple-800/40 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-xs font-black text-purple-900 dark:text-purple-300 font-mono uppercase">
                📡 Analyseur de Paquets PCAP & Inspection Réseau Layer 3/4
              </h3>
              <p className="text-[11px] text-slate-600 dark:text-slate-400">
                Analyse les flux bruts TCP/UDP/ICMP/DNS pour identifier les attaques volumétriques DDoS, balayages Nmap furtifs et exfiltrations de données par tunnel DNS.
              </p>
            </div>
            
            {/* 1-Click Scenario Buttons */}
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                onClick={() => { setPcapScenario('SYN_FLOOD'); runPcapAnalysis('SYN_FLOOD'); }}
                className="px-2.5 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30 rounded-xl text-xs font-mono font-bold transition cursor-pointer"
              >
                ⚡ SYN Flood DoS
              </button>
              <button
                type="button"
                onClick={() => { setPcapScenario('PORT_SCAN'); runPcapAnalysis('PORT_SCAN'); }}
                className="px-2.5 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30 rounded-xl text-xs font-mono font-bold transition cursor-pointer"
              >
                🔍 Nmap Port Scan
              </button>
              <button
                type="button"
                onClick={() => { setPcapScenario('DNS_TUNNEL'); runPcapAnalysis('DNS_TUNNEL'); }}
                className="px-2.5 py-1.5 bg-purple-500/10 hover:bg-purple-500/20 text-purple-700 dark:text-purple-300 border border-purple-500/30 rounded-xl text-xs font-mono font-bold transition cursor-pointer"
              >
                🕳️ Tunnel DNS Exfil
              </button>
            </div>
          </div>

          {pcapResult && (
            <div className="space-y-4">
              {/* Stats Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-xl font-mono text-xs">
                  <span className="text-[10px] text-slate-400 uppercase block">Total Paquets</span>
                  <span className="text-base font-black text-slate-900 dark:text-white">{pcapResult.total_packets}</span>
                  <span className="text-[10px] text-slate-500 block">({pcapResult.packet_rate_pps} pps)</span>
                </div>
                <div className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-xl font-mono text-xs">
                  <span className="text-[10px] text-slate-400 uppercase block">Flags TCP SYN</span>
                  <span className="text-base font-black text-rose-500">{pcapResult.flags_distribution?.SYN || 0}</span>
                  <span className="text-[10px] text-slate-500 block">Orphelins / Floods</span>
                </div>
                <div className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-xl font-mono text-xs">
                  <span className="text-[10px] text-slate-400 uppercase block">Verdict Réseau</span>
                  <span className={`text-xs font-black block truncate ${pcapResult.risk_level === 'CRITICAL' ? 'text-rose-500' : 'text-amber-500'}`}>
                    {pcapResult.risk_level}
                  </span>
                  <span className="text-[10px] text-slate-500 block truncate">{pcapResult.filename}</span>
                </div>
                <div className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-xl font-mono text-xs">
                  <span className="text-[10px] text-slate-400 uppercase block">Protocole Dominant</span>
                  <span className="text-base font-black text-purple-500">
                    {Object.entries(pcapResult.protocols || {}).sort((a,b) => b[1].percent - a[1].percent)[0]?.[0] || 'TCP'}
                  </span>
                  <span className="text-[10px] text-slate-500 block">Couche 4 Transport</span>
                </div>
              </div>

              {/* Detected Attack Callout */}
              {pcapResult.attacks_detected?.map((atk, i) => (
                <div key={i} className="p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs font-mono space-y-1">
                  <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-bold">
                    <ShieldAlert className="w-4 h-4" />
                    <span>{atk.type} (Confiance : {atk.confidence}%)</span>
                  </div>
                  <p className="text-[11px] text-slate-700 dark:text-slate-300 font-sans leading-relaxed">
                    {atk.detail}
                  </p>
                </div>
              ))}

              {/* Top Talkers & Sample Packet Stream */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="p-4 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-2xl space-y-2">
                  <span className="text-xs font-mono font-bold uppercase text-slate-400">Nœuds Émetteurs Majeurs (Top Talkers)</span>
                  <div className="space-y-1.5">
                    {pcapResult.top_talkers?.map((talker, i) => (
                      <div key={i} className="flex items-center justify-between p-2 bg-white dark:bg-[#111622] rounded-xl text-xs font-mono border border-slate-200 dark:border-slate-800">
                        <span className="font-bold text-sky-600 dark:text-sky-400">{talker.ip}</span>
                        <span className="text-[10px] text-slate-400">{talker.role}</span>
                        <span className="text-slate-700 dark:text-slate-300 font-bold">{talker.packets} paquets</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-4 bg-slate-900 rounded-2xl border border-slate-800 space-y-2 text-xs font-mono">
                  <span className="text-[10px] font-bold uppercase text-slate-400 block">Flux Paquets Bruts Capturés (PCAP Sniffer Stream)</span>
                  <div className="space-y-1.5 text-[10px] text-slate-300">
                    {pcapResult.sample_packets?.map((pkt, i) => (
                      <div key={i} className="p-1.5 bg-slate-950 rounded border border-slate-800 truncate">
                        <span className="text-amber-400 font-bold">[{pkt.proto}]</span> <span className="text-sky-400">{pkt.src}</span> ➔ <span className="text-emerald-400">{pkt.dst}</span>: {pkt.info}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── SUB-TAB 3: ACTIVE INLINE FIREWALL ── */}
      {activeSubTab === 'FIREWALL' && (
        <div className="space-y-5 animate-in fade-in duration-200">
          <div className="p-4 bg-rose-50 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/40 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-xs font-black text-rose-900 dark:text-rose-300 font-mono uppercase">
                🛡️ Pare-Feu WAF Actif & Bannissement Dynamique d'Adresses IP
              </h3>
              <p className="text-[11px] text-slate-600 dark:text-slate-400">
                Bloque activement au niveau du middleware ASGI toute requête provenant d'adresses IP hostiles (Code HTTP 403 Forbidden immédiat).
              </p>
            </div>
            <button
              type="button"
              onClick={fetchBlockedIps}
              className="px-3 py-1.5 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-xl text-xs font-mono font-bold text-slate-700 dark:text-slate-300 flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Actualiser</span>
            </button>
          </div>

          {/* Add IP to Blocklist Form */}
          <form onSubmit={handleBlockIp} className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              required
              placeholder="Adresse IP à bannir (ex: 185.220.101.5)..."
              value={newIpToBlock}
              onChange={(e) => setNewIpToBlock(e.target.value)}
              className="px-3 py-2 text-xs font-mono rounded-xl bg-slate-50 dark:bg-[#1a2333] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white flex-1 focus:outline-none"
            />
            <input
              type="text"
              placeholder="Motif du bannissement (ex: Injection SQL répétée)..."
              value={blockReason}
              onChange={(e) => setBlockReason(e.target.value)}
              className="px-3 py-2 text-xs font-mono rounded-xl bg-slate-50 dark:bg-[#1a2333] border border-slate-200 dark:border-slate-800 text-slate-900 dark:text-white flex-1 focus:outline-none"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs rounded-xl flex items-center gap-1.5 transition cursor-pointer"
            >
              <Ban className="w-3.5 h-3.5" />
              <span>Bannir cette IP</span>
            </button>
          </form>

          {/* Blocked IP Table */}
          <div className="space-y-2">
            <span className="text-xs font-mono font-bold uppercase text-slate-400">
              Liste Noire Active du Pare-Feu ({blockedIps.length} adresses bloquées en temps réel)
            </span>
            <div className="space-y-2">
              {blockedIps.map((entry, i) => (
                <div key={i} className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-600 animate-pulse" />
                      <span className="font-black text-rose-600 dark:text-rose-400 text-sm">{entry.ip}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-600 border border-rose-500/20">
                        {entry.severity || 'CRITICAL'}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-600 dark:text-slate-300 font-sans">
                      {entry.reason}
                    </p>
                    <div className="text-[10px] text-slate-400">
                      Banni par : <strong>{entry.blocked_by}</strong> • {entry.blocked_at}
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleUnblockIp(entry.ip)}
                    className="px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 rounded-xl text-xs font-bold transition flex items-center gap-1.5 self-start sm:self-auto cursor-pointer"
                  >
                    <Unlock className="w-3.5 h-3.5" />
                    <span>Débannir</span>
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── SUB-TAB 4: HONEYPOT DECOY TRAPS ── */}
      {activeSubTab === 'HONEYPOT' && (
        <div className="space-y-5 animate-in fade-in duration-200">
          <div className="p-4 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-800/40 rounded-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-xs font-black text-amber-900 dark:text-amber-300 font-mono uppercase">
                🍯 Réseau de Leurres Honeypot & Pièges à Bots Automatisés
              </h3>
              <p className="text-[11px] text-slate-600 dark:text-slate-400">
                Déploie de faux points d'accès vulnérables (<code className="bg-amber-100 dark:bg-amber-900/40 px-1 py-0.5 rounded">/wp-login.php</code>, <code className="bg-amber-100 dark:bg-amber-900/40 px-1 py-0.5 rounded">/.env</code>, <code className="bg-amber-100 dark:bg-amber-900/40 px-1 py-0.5 rounded">/phpmyadmin</code>) pour piéger et bannir automatiquement les robots pirates.
              </p>
            </div>

            {/* Simulate Honeypot Hit Buttons */}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => simulateHoneypotProbe('/wp-login.php')}
                disabled={isHoneypotLoading}
                className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30 rounded-xl text-xs font-mono font-bold transition cursor-pointer"
              >
                🎣 Piéger Bot WordPress
              </button>
              <button
                type="button"
                onClick={() => simulateHoneypotProbe('/.env')}
                disabled={isHoneypotLoading}
                className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/30 rounded-xl text-xs font-mono font-bold transition cursor-pointer"
              >
                🎣 Piéger Scan /.env
              </button>
            </div>
          </div>

          {/* Trapped Bots List */}
          <div className="space-y-2">
            <span className="text-xs font-mono font-bold uppercase text-slate-400">
              Robots & Scanners Hostiles Piégés ({honeypotHits.length})
            </span>
            <div className="space-y-2">
              {honeypotHits.map((hit, i) => (
                <div key={i} className="p-3.5 bg-slate-50 dark:bg-[#161d2b] border border-slate-200 dark:border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-amber-600 dark:text-amber-400">{hit.trap_endpoint}</span>
                      <span className="text-slate-400">ciblé par</span>
                      <span className="font-black text-rose-500">{hit.attacker_ip}</span>
                    </div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-300">
                      Charge malveillante : <code>{hit.payload}</code>
                    </div>
                    <div className="text-[10px] text-slate-400">
                      Agent : {hit.user_agent} • {hit.timestamp}
                    </div>
                  </div>

                  <span className="px-2 py-1 rounded text-[10px] font-black bg-rose-500/10 text-rose-600 border border-rose-500/30 shrink-0 self-start sm:self-auto">
                    {hit.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
