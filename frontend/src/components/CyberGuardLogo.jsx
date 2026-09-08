import React from 'react';

export default function CyberGuardLogo({ size = 'md', showText = true, className = '' }) {
  const iconSizes = {
    sm: 'w-7 h-7',
    md: 'w-9 h-9',
    lg: 'w-11 h-11',
    xl: 'w-14 h-14'
  };

  const textSizes = {
    sm: 'text-base',
    md: 'text-xl',
    lg: 'text-2xl',
    xl: 'text-3xl'
  };

  return (
    <div className={`flex items-center gap-3 group shrink-0 ${className}`}>
      {/* Unique CyberGuard Shield Core Icon */}
      <div className={`relative ${iconSizes[size]} rounded-xl bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-700 flex items-center justify-center shadow-lg shadow-cyan-500/30 group-hover:shadow-cyan-400/50 group-hover:scale-105 transition-all duration-300 border border-white/20 overflow-hidden`}>
        {/* Futuristic cyber radar / energy backdrop */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_120%,rgba(6,182,212,0.4),transparent)] pointer-events-none" />
        
        {/* Custom Special Vector Emblem: Cyber Shield with Central Lightning/Radar Core & Cyber Nodes */}
        <svg 
          viewBox="0 0 24 24" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg" 
          className="w-3/5 h-3/5 text-white drop-shadow-[0_0_6px_rgba(255,255,255,0.8)] relative z-10 transition-transform duration-300 group-hover:scale-110"
        >
          {/* Cyber Shield Bevel Path */}
          <path 
            d="M12 2L4 5V11C4 16.52 7.41 21.62 12 23C16.59 21.62 20 16.52 20 11V5L12 2Z" 
            stroke="currentColor" 
            strokeWidth="2" 
            strokeLinecap="round" 
            strokeLinejoin="round" 
          />
          {/* Energy Core */}
          <path 
            d="M13 7L8 14H12L11 18L16 11H12L13 7Z" 
            fill="currentColor" 
          />
          {/* Cyber Nodes */}
          <circle cx="12" cy="4" r="1" fill="#38bdf8" />
          <circle cx="6" cy="7" r="1" fill="#38bdf8" />
          <circle cx="18" cy="7" r="1" fill="#38bdf8" />
        </svg>

        {/* Outer Glow Border */}
        <div className="absolute inset-0 rounded-xl ring-2 ring-cyan-400/30 group-hover:ring-cyan-300/60 transition-all duration-300" />
      </div>

      {showText && (
        <span className={`font-heading font-extrabold tracking-wider ${textSizes[size]} text-slate-900 dark:text-white flex items-center leading-none`}>
          CYBER<span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-400 to-blue-500">GUARD</span>
        </span>
      )}
    </div>
  );
}
