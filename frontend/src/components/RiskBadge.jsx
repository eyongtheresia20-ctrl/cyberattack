import React from 'react';
import { AlertTriangle, CheckCircle, ShieldAlert, AlertCircle } from 'lucide-react';

export default function RiskBadge({ level }) {
  const norm = (level || 'LOW').toUpperCase();
  
  if (norm === 'CRITICAL') {
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse">
        <ShieldAlert className="w-3.5 h-3.5" /> CRITICAL
      </span>
    );
  }
  if (norm === 'HIGH') {
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/20 text-orange-400 border border-orange-500/30">
        <AlertTriangle className="w-3.5 h-3.5" /> HIGH RISK
      </span>
    );
  }
  if (norm === 'MEDIUM' || norm === 'SUSPICIOUS') {
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
        <AlertCircle className="w-3.5 h-3.5" /> MEDIUM RISK
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
      <CheckCircle className="w-3.5 h-3.5" /> LOW RISK
    </span>
  );
}
