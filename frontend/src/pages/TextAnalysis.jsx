import React, { useState } from 'react';
import { MessageSquare, Mail, AlertTriangle, Cpu, CheckCircle2, ShieldAlert } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import { api } from '../services/api';

export default function TextAnalysis() {
  const [analysisType, setAnalysisType] = useState('MESSAGE');
  const [senderInput, setSenderInput] = useState('+1 (555) 019-2834');
  const [textInput, setTextInput] = useState('URGENT: Your PayPal account has been suspended due to suspicious activity! Verify your identity immediately at http://secure-paypal-verify.xyz within 24 hours to prevent account closure.');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const sampleTexts = {
    MESSAGE: "URGENT: Your PayPal account has been suspended! Click http://secure-paypal-verify.xyz to restore access within 24h.",
    EMAIL: "Dear Customer,\n\nOur automated security system detected multiple failed login attempts on your banking portal from an unrecognized IP address (45.142.120.10).\n\nPlease verify your login credentials immediately to unfreeze your funds:\nhttp://verify-bank-account-security-alert.club/update-pin.asp\n\nFailure to verify within 12 hours will result in permanent account termination.\n\nBest regards,\nSecurity Team"
  };

  const handleAnalyze = async (e) => {
    e?.preventDefault();
    if (!textInput.trim()) return;
    setLoading(true);
    setResult(null);

    try {
      const res = await api.analyzeText(textInput.trim(), senderInput.trim(), analysisType);
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
          <MessageSquare className="w-5 h-5 text-cyan-400" /> SMS & Email Phishing Text Analyzer
        </h2>
        <p className="text-xs text-slate-400">NLP TF-IDF text classification + Urgency & Credential harvesting extraction</p>
      </div>

      {/* Selector & Form */}
      <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
        <div className="flex gap-3">
          <button
            onClick={() => { setAnalysisType('MESSAGE'); setTextInput(sampleTexts.MESSAGE); }}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
              analysisType === 'MESSAGE'
                ? 'bg-cyan-500 text-black shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <MessageSquare className="w-4 h-4" /> SMS Message
          </button>
          <button
            onClick={() => { setAnalysisType('EMAIL'); setTextInput(sampleTexts.EMAIL); }}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition ${
              analysisType === 'EMAIL'
                ? 'bg-cyan-500 text-black shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <Mail className="w-4 h-4" /> Email Body Content
          </button>
        </div>

        <form onSubmit={handleAnalyze} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Sender Address / Phone (Optional)</label>
            <input
              type="text"
              value={senderInput}
              onChange={(e) => setSenderInput(e.target.value)}
              placeholder="e.g. security-alert@paypal-update.com or +1 555-0192"
              className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none transition font-mono"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1">Pasted Message or Email Text</label>
            <textarea
              rows={5}
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              placeholder="Paste suspicious message body here..."
              className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-500 rounded-lg p-3 text-xs text-white placeholder-slate-500 focus:outline-none transition font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full sm:w-auto px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-black font-semibold text-xs rounded-lg transition shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
          >
            {loading ? <Cpu className="w-4 h-4 animate-spin" /> : <MessageSquare className="w-4 h-4" />}
            <span>Run NLP Phishing Inspection</span>
          </button>
        </form>
      </div>

      {/* Result Card */}
      {result && (
        <div className="space-y-6">
          <div className="glass-card p-6 rounded-xl border border-slate-800 grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
            <div className="space-y-1">
              <span className="text-xs uppercase tracking-wider text-slate-400 font-mono">Analysis ID</span>
              <p className="text-lg font-bold text-cyan-400 font-mono">{result.analysis_code}</p>
              <p className="text-xs text-slate-400">Type: <strong className="text-white">{result.analysis_type}</strong></p>
            </div>

            <div className="space-y-2 text-center md:border-x border-slate-800 md:px-4">
              <span className="text-xs uppercase tracking-wider text-slate-400">NLP Classification Verdict</span>
              <div>
                <RiskBadge level={result.risk_level} />
              </div>
              <p className="text-sm font-semibold text-white mt-1">{result.verdict}</p>
            </div>

            <div className="space-y-2 text-right">
              <span className="text-xs uppercase tracking-wider text-slate-400">Threat Probability</span>
              <p className="text-3xl font-extrabold text-white font-mono">{result.risk_score}%</p>
              <p className="text-xs text-slate-400 font-mono">NLP Confidence: <strong className="text-cyan-400">{result.ml_confidence}%</strong></p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Extracted NLP Linguistic Markers */}
            <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" /> Extracted NLP Threat Markers
              </h3>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Urgency Language</span>
                  <strong className={result.indicators.urgency_score > 0 ? "text-red-400 text-sm font-mono" : "text-emerald-400 text-sm font-mono"}>
                    {result.indicators.urgency_score > 0 ? `${result.indicators.urgency_score} Keywords Detected` : 'NONE'}
                  </strong>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Credential Harvesting</span>
                  <strong className={result.indicators.credential_score > 0 ? "text-red-400 text-sm font-mono" : "text-emerald-400 text-sm font-mono"}>
                    {result.indicators.credential_score > 0 ? `${result.indicators.credential_score} Triggers Matched` : 'NONE'}
                  </strong>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Financial Impersonation</span>
                  <strong className={result.indicators.financial_score > 0 ? "text-amber-400 text-sm font-mono" : "text-emerald-400 text-sm font-mono"}>
                    {result.indicators.financial_score > 0 ? `${result.indicators.financial_score} Triggers` : 'NONE'}
                  </strong>
                </div>
                <div className="p-3 bg-slate-900/60 rounded border border-slate-800">
                  <span className="text-slate-400 block text-[10px]">Embedded URL Links</span>
                  <strong className="text-cyan-400 text-sm font-mono">{result.indicators.extracted_urls?.length || 0} Embedded</strong>
                </div>
              </div>

              {result.rule_triggers?.length > 0 && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-xs space-y-1">
                  <p className="font-semibold text-red-400">Triggered Heuristics:</p>
                  <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                    {result.rule_triggers.map((rule, idx) => (
                      <li key={idx}>{rule}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Recommendations */}
            <div className="glass-card p-5 rounded-xl border border-slate-800 space-y-4">
              <h3 className="font-semibold text-white text-sm flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-emerald-400" /> Recommended Action Steps
              </h3>
              <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-xs space-y-1">
                <ul className="list-disc list-inside text-slate-300 space-y-1">
                  {result.defensive_advice.map((adv, idx) => (
                    <li key={idx}>{adv}</li>
                  ))}
                </ul>
              </div>

              <div className="pt-3 border-t border-slate-800 text-[10px] text-slate-500 font-mono truncate">
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
