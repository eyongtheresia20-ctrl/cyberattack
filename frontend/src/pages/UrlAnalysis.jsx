import React, { useState } from 'react';
import { Globe, Search, ShieldCheck, AlertOctagon, CheckCircle2, Copy, ExternalLink, Cpu } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import { api } from '../services/api';
import { useLanguage } from '../context/LanguageContext';

export default function UrlAnalysis() {
  const { lang } = useLanguage();
  const [urlInput, setUrlInput] = useState('http://192.168.1.100/paypal.com/login-verify-account.php?id=99283');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const sampleUrls = [
    "http://192.168.1.100/paypal.com/login-verify-account.php?id=99283",
    "http://secure-update-appleid-billing.xyz/login.html?token=x938",
    "https://github.com/torvalds/linux",
    "https://wikipedia.org/wiki/Machine_learning"
  ];

  const handleAnalyze = async (e) => {
    e?.preventDefault();
    if (!urlInput.trim()) return;
    setLoading(true);
    setResult(null);

    try {
      const res = await api.analyzeUrl(urlInput.trim());
      setResult(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyan-400" /> URL Phishing Threat Scanner
        </h2>
        <p className="text-xs text-slate-400">Lexical structural extraction + Random Forest ML + Threat Intelligence</p>
      </div>

      {/* Input Form */}
      <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
        <form onSubmit={handleAnalyze} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Paste URL to inspect (e.g. http://login-verify-paypal.xyz/...)"
              className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-500 rounded-lg pl-10 pr-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none transition font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-semibold text-xs rounded-lg transition shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
          >
            {loading ? <Cpu className="w-4 h-4 animate-spin text-black" /> : <Search className="w-4 h-4" />}
            <span>Analyze URL</span>
          </button>
        </form>

        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span>Sample Quick Tests:</span>
          <div className="flex flex-wrap gap-2 font-mono">
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                onClick={() => { setUrlInput(s); }}
                className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:text-cyan-400 hover:bg-slate-700 transition"
              >
                Sample {idx + 1}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-6">
          {/* Main Verdict Card */}
          <div className="glass-card p-6 rounded-xl border border-slate-800 grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
            <div className="space-y-2">
              <span className="text-xs uppercase tracking-wider text-slate-400 font-mono">Analysis ID</span>
              <p className="text-lg font-bold text-cyan-400 font-mono">{result.analysis_code}</p>
              <p className="text-xs text-slate-300 font-mono truncate">{result.target_url}</p>
            </div>

            <div className="space-y-2 text-center md:border-x border-slate-800 md:px-4">
              <span className="text-xs uppercase tracking-wider text-slate-400">Threat Verdict</span>
              <div>
                <RiskBadge level={result.risk_level} />
              </div>
              <p className="text-sm font-semibold text-white mt-1">{result.verdict}</p>
            </div>

            <div className="space-y-2 text-right">
              <span className="text-xs uppercase tracking-wider text-slate-400">Hybrid Risk Score</span>
              <p className="text-3xl font-extrabold text-white font-mono">{result.risk_score} <span className="text-sm font-normal text-slate-400">/ 100</span></p>
              <p className="text-xs text-slate-400 font-mono">ML Probability: <strong className="text-cyan-400">{result.ml_confidence}%</strong></p>
            </div>
          </div>

          {/* Detailed Intelligence Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Lexical Features */}
            <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" /> Machine Learning Feature Vectors
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">URL Entropy</span>
                  <strong className="text-cyan-400 text-sm">{result.features.entropy}</strong>
                </div>
                <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Direct IP Host</span>
                  <strong className={result.features.has_ip ? "text-red-400" : "text-emerald-400"}>
                    {result.features.has_ip ? "YES (RISK)" : "NO"}
                  </strong>
                </div>
                <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">HTTPS Enabled</span>
                  <strong className={result.features.is_https ? "text-emerald-400" : "text-amber-400"}>
                    {result.features.is_https ? "YES" : "NO (INSECURE)"}
                  </strong>
                </div>
                <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Subdomain Count</span>
                  <strong className="text-slate-200">{result.features.num_subdomains}</strong>
                </div>
                <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Special Chars</span>
                  <strong className="text-slate-200">{result.features.num_special_chars}</strong>
                </div>
                <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Suspect Keywords</span>
                  <strong className="text-amber-400">{result.features.keyword_count}</strong>
                </div>
              </div>

              {result.rule_triggers?.length > 0 && (
                <div className="mt-3 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs space-y-1">
                  <p className="font-semibold text-red-400">Security Rule Triggers:</p>
                  <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                    {result.rule_triggers.map((rule, idx) => (
                      <li key={idx}>{rule}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* External Threat Intelligence APIs */}
            <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Threat Intelligence Integrations
              </h3>

              <div className="space-y-3 text-xs">
                {/* VirusTotal */}
                <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="font-semibold text-white font-mono">VirusTotal Intelligence</span>
                    <p className="text-[11px] text-slate-400">{result.virustotal.source}</p>
                  </div>
                  <div className="text-right font-mono">
                    <span className={result.virustotal.positives > 0 ? "text-red-400 font-bold" : "text-emerald-400 font-bold"}>
                      {result.virustotal.positives} / {result.virustotal.total_engines} Flagged
                    </span>
                  </div>
                </div>

                {/* Google Safe Browsing */}
                <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="font-semibold text-white font-mono">Google Safe Browsing</span>
                    <p className="text-[11px] text-slate-400">{result.google_safebrowsing.source}</p>
                  </div>
                  <div className="text-right font-mono">
                    {result.google_safebrowsing.is_flagged ? (
                      <span className="text-red-400 font-bold">FLAGGED (MALICIOUS)</span>
                    ) : (
                      <span className="text-emerald-400 font-bold font-sans">SAFE LIST</span>
                    )}
                  </div>
                </div>
              </div>

              {/* GeoIP & Network Location Metadata */}
              {result.geoip_info && (
                <div className="p-4 bg-slate-900/80 rounded-xl border border-slate-800 space-y-2 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white flex items-center gap-1.5">
                      📍 {lang === 'fr' ? 'Localisation Réseau Apparente (GeoIP & ASN)' : 'Apparent Network Location (GeoIP & ASN)'}
                    </span>
                    <span className="font-mono text-cyan-400 font-bold">{result.geoip_info.ip}</span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-slate-300 font-mono">
                    <div>{lang === 'fr' ? 'Pays / Ville :' : 'Country / City:'} <strong className="text-white">{result.geoip_info.country_en && lang === 'en' ? result.geoip_info.country_en : result.geoip_info.country}, {result.geoip_info.city_en && lang === 'en' ? result.geoip_info.city_en : result.geoip_info.city}</strong></div>
                    <div>{lang === 'fr' ? 'Réseau ASN :' : 'ASN Network:'} <strong className="text-white">{result.geoip_info.asn}</strong></div>
                  </div>
                  <p className="text-[10px] text-amber-400/90 italic bg-amber-950/30 p-2 rounded border border-amber-800/40 mt-1">
                    {lang === 'en' 
                      ? (result.geoip_info.disclaimer_en || "⚠️ Warning: The system provides apparent network location. A VPN, Proxy, or Tor network can obscure the real physical perpetrator.")
                      : (result.geoip_info.disclaimer || "⚠️ Le système fournit la localisation réseau apparente. Un VPN, Proxy ou réseau Tor peut masquer l'auteur physique réel.")}
                  </p>
                </div>
              )}

              {/* Defensive Advice */}
              <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-xs space-y-1">
                <p className="font-semibold text-cyan-400">Defensive Remediation Advice:</p>
                <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                  {result.defensive_advice.map((adv, idx) => (
                    <li key={idx}>{adv}</li>
                  ))}
                </ul>
              </div>

              {/* SHA-256 Checksum Signature */}
              <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 font-mono truncate">
                <span>SHA-256 Digest: </span>
                <span className="text-slate-400">{result.integrity_hash}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
