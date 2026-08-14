import React from 'react';

export default function MetricCard({ title, value, subtitle, icon: Icon, color = "sky" }) {
  const colorClasses = {
    sky: "text-sky-600 bg-sky-100 border-sky-200",
    red: "text-rose-600 bg-rose-100 border-rose-200",
    amber: "text-amber-600 bg-amber-100 border-amber-200",
    emerald: "text-emerald-600 bg-emerald-100 border-emerald-200"
  };

  const styleClass = colorClasses[color] || colorClasses.sky;

  return (
    <div className="bg-white p-5 rounded-2xl border border-sky-100 shadow-sm hover:shadow-md hover:border-sky-300 transition-all flex items-center justify-between">
      <div>
        <p className="text-xs uppercase tracking-wider text-slate-500 font-bold mb-1">{title}</p>
        <p className="text-2xl font-extrabold text-slate-900 tracking-tight">{value}</p>
        {subtitle && <p className="text-xs text-slate-500 mt-1 font-medium">{subtitle}</p>}
      </div>
      {Icon && (
        <div className={`p-3 rounded-xl border ${styleClass}`}>
          <Icon className="w-6 h-6" />
        </div>
      )}
    </div>
  );
}
