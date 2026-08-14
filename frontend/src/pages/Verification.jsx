import React, { useState } from 'react';
import { CheckCircle2, ShieldAlert, Search, ShieldCheck, FileKey, Copy, AlertOctagon } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import { api } from '../services/api';

export default function Verification() {
  const [lookupCode, setLookupCode] = useState('ANL-');
  const [providedHash, setProvidedHash] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleVerify = async (e) => {
    e?.preventDefault();
    if (!lookupCode.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await api.verifyReport(lookupCode.trim(), providedHash.trim());
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Report verification failed. Code not found.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
          <CheckCircle2 className="w-5 h-5 text-cyan-400" /> Investigator Integrity & Verification Portal
        </h2>
        <p className="text-xs text-slate-400">Verifies digital signatures and SHA-256 evidence hashes directly against original stored analysis records</p>
      </div>

      {/* Form */}
      <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4 max-w-2xl">
        <form onSubmit={handleVerify} className="space-y-3 text-xs">
          <div>
            <label className="block text-slate-400 mb-1 font-semibold">Report Code or Analysis Code</label>
            <input
              type="text"
              value={lookupCode}
              onChange={(e) => setLookupCode(e.target.value.toUpperCase())}
              placeholder="e.g. RPT-2026-10492 or ANL-2026-948201"
              className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2.5 text-white font-mono uppercase text-sm"
              required
            />
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Provided SHA-256 Hash Digest (Optional)</label>
            <input
              type="text"
              value={providedHash}
              onChange={(e) => setProvidedHash(e.target.value)}
              placeholder="Paste SHA-256 hash provided in paper/PDF report..."
              className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-white font-mono text-xs"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-emerald-500 text-black font-bold text-xs rounded-lg shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
          >
            {loading ? <Search className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            <span>Perform Cryptographic Integrity Verification</span>
          </button>
        </form>
      </div>

      {/* Error View */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-xs text-red-400 flex items-center gap-3">
          <AlertOctagon className="w-5 h-5 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Result Card */}
      {result && (
        <div className="glass-card p-6 rounded-xl border border-slate-800 space-y-5 max-w-3xl">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <span className="text-xs font-mono text-slate-400">Lookup Query Code</span>
              <p className="text-lg font-bold text-white font-mono">{result.lookup_code}</p>
            </div>
            <div>
              {result.valid ? (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/40">
                  <ShieldCheck className="w-4 h-4" /> INTEGRITY VERIFIED
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                  <AlertOctagon className="w-4 h-4" /> TAMPERING DETECTED
                </span>
              )}
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 text-xs space-y-3 font-mono">
            <div className="space-y-1">
              <span className="text-slate-500 text-[10px]">DATABASE STORED SHA-256 DIGEST:</span>
              <p className="text-cyan-400 break-all">{result.db_hash}</p>
            </div>
            <div className="space-y-1">
              <span className="text-slate-500 text-[10px]">RECOMPUTED PAYLOAD CHECKSUM:</span>
              <p className="text-emerald-400 break-all">{result.computed_hash}</p>
            </div>
          </div>

          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-xs text-slate-200">
            <p className="font-semibold text-cyan-400 mb-0.5">Verification Summary:</p>
            <p>{result.verification_message}</p>
          </div>

          {/* Original Record Payload Snapshot */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400">Retrieved Original Record Data</h4>
            <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] text-slate-300 font-mono overflow-x-auto max-h-60">
              {JSON.stringify(result.report_details || result.analysis_details, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
