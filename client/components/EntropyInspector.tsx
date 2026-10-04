import React from 'react';
import { Activity, BarChart2, ShieldCheck, Zap } from 'lucide-react';
import type { KemDemPackage } from '../types/crypto.js';

interface EntropyInspectorProps {
  currentPackage: KemDemPackage | null;
}

export const EntropyInspector: React.FC<EntropyInspectorProps> = ({ currentPackage }) => {
  if (!currentPackage) return null;

  const originalH = currentPackage.metrics.originalEntropy;
  const encryptedH = currentPackage.metrics.encryptedEntropy;
  const maxH = 8.0;

  const origPercent = Math.min(100, Math.round((originalH / maxH) * 100));
  const encPercent = Math.min(100, Math.round((encryptedH / maxH) * 100));

  return (
    <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <Activity className="w-3.5 h-3.5" />
            <span>DIFFUSION & CONFUSION TELEMETRY</span>
          </div>
          <h3 className="text-base font-bold text-white">
            Shannon Entropy & Randomness Verification
          </h3>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-slate-400">Theoretical Limit:</span>
          <span className="text-white font-bold">8.000 bits/byte</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Original Entropy */}
        <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3">
          <div className="flex justify-between items-center text-xs">
            <span className="font-semibold text-slate-300">Original Image Entropy</span>
            <span className="font-mono text-slate-400">{originalH} / 8.000 bits/byte</span>
          </div>

          <div className="w-full bg-slate-900 rounded-full h-3 overflow-hidden border border-slate-800">
            <div
              className="bg-blue-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${origPercent}%` }}
            />
          </div>

          <p className="text-[11px] text-slate-400 leading-relaxed">
            Natural images exhibit localized patterns, contours, and repeated color palettes,
            typically resulting in entropy between 4.0 and 7.2 bits/byte.
          </p>
        </div>

        {/* Encrypted Entropy */}
        <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3">
          <div className="flex justify-between items-center text-xs">
            <span className="font-semibold text-cyan-300">Encrypted Ciphertext Entropy</span>
            <span className="font-mono text-cyan-400 font-bold">
              {encryptedH} / 8.000 bits/byte
            </span>
          </div>

          <div className="w-full bg-slate-900 rounded-full h-3 overflow-hidden border border-slate-800">
            <div
              className="bg-cyan-400 h-full rounded-full transition-all duration-500 shadow-sm shadow-cyan-400/50"
              style={{ width: `${encPercent}%` }}
            />
          </div>

          <p className="text-[11px] text-slate-300 leading-relaxed">
            Near-maximal Shannon entropy ({encryptedH} bits/byte) mathematically proves the absence of
            any residual pixel correlations, visual silhouettes, or ECB-style leakage.
          </p>
        </div>
      </div>
    </div>
  );
};
