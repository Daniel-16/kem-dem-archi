import React, { useState } from 'react';
import {
  FlaskConical,
  ShieldAlert,
  ShieldCheck,
  Zap,
  ArrowRight,
  AlertOctagon,
  Lock,
  FileCode,
  Bug,
} from 'lucide-react';
import type { KemDemPackage, KemKeyPair, TamperTestResult } from '../types/crypto.js';

interface TamperLabProps {
  currentPackage: KemDemPackage | null;
  keyring: KemKeyPair[];
}

export const TamperLab: React.FC<TamperLabProps> = ({ currentPackage, keyring }) => {
  const [selectedTarget, setSelectedTarget] = useState<
    'KEM_HEADER' | 'CIPHERTEXT' | 'IV' | 'TAG' | 'AAD'
  >('CIPHERTEXT');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulationResult, setSimulationResult] = useState<TamperTestResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const attacks = [
    {
      id: 'KEM_HEADER' as const,
      name: 'Tamper KEM Key Header (c_kem)',
      category: 'Stage 1 Asymmetric Attack',
      description:
        'Flips 1 bit in the RSA-OAEP / ECDH encapsulated key ciphertext. Simulates an adversary attempting to inject or splice their own session key.',
      expectedResult:
        'KEM Decapsulation padding check failure or corrupt key, leading to catastrophic DEM tag verification failure.',
    },
    {
      id: 'CIPHERTEXT' as const,
      name: 'Tamper DEM Image Payload (Ciphertext)',
      category: 'Stage 2 Symmetric Attack',
      description:
        'Flips 1 bit in the bulk encrypted image bytes. Simulates in-transit bit corruption or unauthorized pixel tampering.',
      expectedResult:
        'AEAD GCM/Poly1305 tag verification check fails immediately. Zero bytes of plaintext are released to the user.',
    },
    {
      id: 'IV' as const,
      name: 'Tamper Initialization Vector (Nonce)',
      category: 'Stage 2 Protocol Attack',
      description:
        'Modifies 1 bit in the 96-bit initialization vector. Simulates replay manipulation or IV alteration.',
      expectedResult:
        'AEAD authentication tag mismatch. Prevents stream cipher offset attacks.',
    },
    {
      id: 'TAG' as const,
      name: 'Tamper 128-bit Authentication Tag',
      category: 'Stage 2 Integrity Attack',
      description:
        'Flips 1 bit in the GHASH / Poly1305 authentication tag. Simulates forgery attempts.',
      expectedResult:
        'Immediate authentication rejection. Forgery probability is 1 in 2^128 (cryptographically impossible).',
    },
    {
      id: 'AAD' as const,
      name: 'Tamper Additional Authenticated Data (AAD)',
      category: 'Metadata Spoofing Attack',
      description:
        'Alters the unencrypted metadata bound to the package (e.g. changing classification level or timestamp).',
      expectedResult:
        'AEAD tag verification rejects the packet because the metadata hash is integrated into the polynomial authenticator.',
    },
  ];

  const handleExecuteAttack = async () => {
    if (!currentPackage) {
      setErrorMsg('No KEM-DEM package available. Please encrypt an image first in the Encrypt tab.');
      return;
    }

    const keyWithPriv = keyring.find(
      (k) =>
        k.fingerprint === currentPackage.kemHeader.recipientFingerprint && !!k.privateKeyPem
    ) || keyring.find((k) => !!k.privateKeyPem);

    if (!keyWithPriv || !keyWithPriv.privateKeyPem) {
      setErrorMsg('No private key available in keyring to test decapsulation.');
      return;
    }

    setIsSimulating(true);
    setErrorMsg(null);
    setSimulationResult(null);

    try {
      const res = await fetch('/api/kem-dem/tamper-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: currentPackage,
          recipientPrivateKeyPem: keyWithPriv.privateKeyPem,
          tamperTarget: selectedTarget,
        }),
      });

      const data = await res.json();
      if (!data.success) {
        throw new Error(data.error || 'Tamper simulation failed');
      }

      setSimulationResult(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'Simulation error');
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <FlaskConical className="w-3.5 h-3.5" />
            <span>IND-CCA2 SECURITY VERIFICATION LABORATORY</span>
          </div>
          <h3 className="text-lg font-bold text-white mb-2">
            Active Tamper & Ciphertext Malleability Attack Simulator
          </h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            In non-authenticated encryption (e.g. standard CBC mode without HMAC, or naive RSA
            textbook encryption), an adversary can flip bits in the ciphertext and trick the recipient
            into decrypting modified images or executing padding oracle attacks. Test how the
            authenticated <strong className="text-cyan-400">KEM-DEM</strong> architecture neutralizes
            these attacks mathematically.
          </p>
        </div>

        {/* Attack Vector Selector Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 mt-6">
          {attacks.map((atk) => {
            const isSelected = selectedTarget === atk.id;
            return (
              <div
                key={atk.id}
                onClick={() => setSelectedTarget(atk.id)}
                className={`cursor-pointer rounded-xl border p-4 transition-all duration-150 ${
                  isSelected
                    ? 'border-amber-400/80 bg-slate-900/90 shadow-md shadow-amber-500/5'
                    : 'border-slate-800 bg-slate-950/40 hover:border-slate-700 hover:bg-slate-900/30'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono text-amber-400 uppercase font-semibold">
                    {atk.category}
                  </span>
                  <Bug className="w-3.5 h-3.5 text-amber-400/80" />
                </div>
                <h4 className="text-xs font-bold text-white mb-1.5">{atk.name}</h4>
                <p className="text-[11px] text-slate-400 leading-relaxed mb-3">
                  {atk.description}
                </p>
                <div className="text-[10px] text-slate-500 font-mono bg-slate-900/80 p-1.5 rounded border border-slate-800/80">
                  Expected: {atk.expectedResult}
                </div>
              </div>
            );
          })}
        </div>

        {/* Execution Trigger Bar */}
        <div className="mt-6 flex flex-col sm:flex-row items-center justify-between gap-4 p-4 rounded-xl bg-slate-950/80 border border-slate-800">
          <div className="text-xs text-slate-300">
            {currentPackage ? (
              <span>
                Active Target Package:{' '}
                <strong className="text-white font-mono">{currentPackage.sourceImage.name}</strong>{' '}
                ({currentPackage.kemHeader.algorithm} + {currentPackage.demPayload.algorithm})
              </span>
            ) : (
              <span className="text-amber-400">
                Notice: Encrypt an image first so the simulator has an active ciphertext container to
                tamper with.
              </span>
            )}
          </div>

          <button
            onClick={handleExecuteAttack}
            disabled={isSimulating || !currentPackage}
            className="w-full sm:w-auto px-5 py-2 text-xs font-bold text-slate-950 bg-amber-400 hover:bg-amber-300 active:bg-amber-500 rounded-lg transition-colors disabled:opacity-50 cursor-pointer shadow-md shadow-amber-500/20 whitespace-nowrap"
          >
            {isSimulating ? 'Injecting Bit Flip & Executing...' : 'Simulate 1-Bit Attack'}
          </button>
        </div>

        {errorMsg && (
          <div className="mt-4 p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-xs text-rose-300">
            {errorMsg}
          </div>
        )}
      </div>

      {/* Simulation Attack Result */}
      {simulationResult && (
        <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6 space-y-5 animate-fadeIn">
          <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold border-b border-slate-800 pb-3">
            <ShieldCheck className="w-5 h-5" />
            <span>Attack Neutralized: Cryptographic Invariants Upheld</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Attack Details */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
              <span className="text-xs font-mono text-amber-400 uppercase font-semibold">
                Simulated Attack Mechanics
              </span>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-slate-800/80">
                  <span className="text-slate-400">Target Vector:</span>
                  <span className="text-white">{simulationResult.tamperTarget}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/80">
                  <span className="text-slate-400">Action:</span>
                  <span className="text-slate-200">{simulationResult.tamperDescription}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/80">
                  <span className="text-slate-400">Interception Point:</span>
                  <span className="text-amber-300">{simulationResult.failedPhase}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Status:</span>
                  <span className="text-emerald-400 font-bold">ATTACK DEFLECTED</span>
                </div>
              </div>
            </div>

            {/* Cryptographic Proof Card */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
              <span className="text-xs font-mono text-cyan-400 uppercase font-semibold">
                Cryptographic Exception Caught
              </span>
              <div className="p-2.5 rounded bg-slate-900 text-rose-300 font-mono text-[11px] border border-slate-800 break-words">
                {simulationResult.errorMessage || 'Decryption verification check failed'}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {simulationResult.cryptographicGuarantee}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
