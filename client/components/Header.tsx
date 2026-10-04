import React from 'react';
import { ShieldCheck, Cpu, KeyRound, Lock, Unlock, FlaskConical, BookOpen } from 'lucide-react';

interface HeaderProps {
  activeTab: 'encrypt' | 'decrypt' | 'keyring' | 'tamper' | 'architecture';
  setActiveTab: (tab: 'encrypt' | 'decrypt' | 'keyring' | 'tamper' | 'architecture') => void;
  keyCount: number;
  hasActivePackage: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  keyCount,
  hasActivePackage,
}) => {
  return (
    <header className="sticky top-0 z-50 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80 px-4 lg:px-8 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between">
        {/* Zone 1: Single text element wordmark */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <button
            onClick={() => setActiveTab('encrypt')}
            className="text-left group cursor-pointer"
          >
            <span className="text-base font-bold tracking-tight text-white group-hover:text-cyan-400 transition-colors">
              KEM-DEM Cryptosystem
            </span>
          </button>
        </div>

        {/* Zone 2: Navigation Links (Single-line controls) */}
        <nav className="hidden md:flex items-center gap-1 bg-slate-900/60 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('encrypt')}
            className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all whitespace-nowrap ${
              activeTab === 'encrypt'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Encrypt</span>
          </button>

          <button
            onClick={() => setActiveTab('decrypt')}
            className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all whitespace-nowrap ${
              activeTab === 'decrypt'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Unlock className="w-3.5 h-3.5" />
            <span>Decrypt</span>
            {hasActivePackage && (
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            )}
          </button>

          <button
            onClick={() => setActiveTab('keyring')}
            className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all whitespace-nowrap ${
              activeTab === 'keyring'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Keyring</span>
            <span className="font-mono text-[10px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded-md">
              {keyCount}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('tamper')}
            className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all whitespace-nowrap ${
              activeTab === 'tamper'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <FlaskConical className="w-3.5 h-3.5" />
            <span>Tamper Lab</span>
          </button>

          <button
            onClick={() => setActiveTab('architecture')}
            className={`flex items-center gap-2 px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all whitespace-nowrap ${
              activeTab === 'architecture'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-xs'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Architecture</span>
          </button>
        </nav>

        {/* Zone 3: 1-2 Primary Actions */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-[11px] text-slate-400 font-mono">
            <Cpu className="w-3 h-3 text-emerald-400" />
            <span>Node.js Crypto / WebCrypto</span>
          </div>
        </div>
      </div>
    </header>
  );
};
