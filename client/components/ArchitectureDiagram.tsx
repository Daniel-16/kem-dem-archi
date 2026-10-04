import React, { useState } from 'react';
import {
  KeyRound,
  Shield,
  FileDigit,
  ArrowRight,
  Layers,
  Sparkles,
  Lock,
  Unlock,
  CheckCircle2,
  Info,
} from 'lucide-react';

export const ArchitectureDiagram: React.FC = () => {
  const [activeStep, setActiveStep] = useState<number | null>(null);

  const steps = [
    {
      id: 1,
      phase: 'KEM (Key Encapsulation)',
      title: 'Ephemeral Session Key Generation & Encapsulation',
      formula: '(c_kem, K) ← KEM.Encaps(pk_recipient)',
      description:
        'A high-entropy 256-bit symmetric key K is generated. The sender encapsulates K using the recipient’s public key (RSA-OAEP, ECDH-P256 with HKDF, or Hybrid Post-Quantum), producing the encapsulated key header c_kem.',
      detail:
        'Because asymmetric ciphers are computationally heavy and have strict plaintext size limits (RSA-2048 with OAEP can only encrypt up to 190 bytes), KEM is used strictly to establish the 32-byte session key K.',
      accent: 'border-cyan-500/50 bg-cyan-950/20 text-cyan-300',
    },
    {
      id: 2,
      phase: 'DEM (Data Encapsulation)',
      title: 'Authenticated Symmetric Image Encryption',
      formula: '(C, Tag) ← DEM.Encrypt(K, IV, Plaintext_Image, AAD)',
      description:
        'The derived symmetric key K is fed into an AEAD cipher (AES-256-GCM or ChaCha20-Poly1305) along with a fresh 96-bit IV and optional Additional Authenticated Data (AAD) such as image metadata.',
      detail:
        'The image is encrypted into pseudo-random ciphertext C with maximal Shannon entropy (~7.999 bits/byte), while generating a cryptographic 128-bit authentication tag.',
      accent: 'border-blue-500/50 bg-blue-950/20 text-blue-300',
    },
    {
      id: 3,
      phase: 'Container Serialization',
      title: 'KEM-DEM Unified Artifact Assembly',
      formula: 'Package = { KEM_Header: (c_kem, salt), DEM_Payload: (IV, C, Tag, AAD) }',
      description:
        'The encapsulated key header and encrypted payload are packed into a single standard .kemdem container. The package contains no secrets—the session key K was destroyed from memory immediately after encryption.',
      detail:
        'The resulting file can be transmitted over untrusted channels or stored publicly without revealing any image data or key material.',
      accent: 'border-emerald-500/50 bg-emerald-950/20 text-emerald-300',
    },
    {
      id: 4,
      phase: 'Decapsulation & Decryption',
      title: 'KEM Decapsulation & Authenticated DEM Decryption',
      formula: 'K ← KEM.Decaps(sk, c_kem)  ⟹  Plaintext ← DEM.Decrypt(K, IV, C, Tag, AAD)',
      description:
        'The recipient uses their private key sk to decapsulate c_kem and recover K. Next, DEM verifies the 16-byte authentication tag and AAD. If verification succeeds, the image is decrypted bit-for-bit with 100% fidelity.',
      detail:
        'If even a single bit of c_kem, ciphertext, IV, tag, or AAD was modified in transit, AEAD tag verification fails catastrophically and zero bytes of image data are released (IND-CCA2 security guarantee).',
      accent: 'border-amber-500/50 bg-amber-950/20 text-amber-300',
    },
  ];

  return (
    <div className="space-y-8">
      {/* Title & Overview */}
      <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6 lg:p-8">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2">
            <Layers className="w-3.5 h-3.5" />
            <span>ISO/IEC 18033-2 & NIST SP 800-56B STANDARDS</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white mb-3">
            The KEM-DEM Hybrid Cryptographic Architecture
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            The <strong className="text-white">Key Encapsulation Mechanism (KEM)</strong> and{' '}
            <strong className="text-white">Data Encapsulation Mechanism (DEM)</strong> paradigm is the
            mathematical foundation for modern hybrid public-key encryption. It formally decouples key
            establishment from bulk data encryption, delivering proven{' '}
            <strong className="text-cyan-400">IND-CCA2</strong> (indistinguishability under adaptive
            chosen-ciphertext attack) security.
          </p>
        </div>

        {/* Visual Pipeline Flowchart */}
        <div className="mt-8 grid grid-cols-1 lg:grid-cols-4 gap-4">
          {/* Card 1 */}
          <div
            onClick={() => setActiveStep(1)}
            className={`cursor-pointer rounded-xl border p-4 transition-all duration-200 ${
              activeStep === 1
                ? 'border-cyan-400 bg-slate-900/90 shadow-lg shadow-cyan-500/10'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono text-cyan-400 font-semibold uppercase">
                Stage 1: KEM
              </span>
              <KeyRound className="w-4 h-4 text-cyan-400" />
            </div>
            <h4 className="text-sm font-semibold text-white mb-1">Encapsulation</h4>
            <p className="text-xs text-slate-400 leading-relaxed mb-3">
              Recipient Public Key <code className="text-cyan-300">pk</code> wraps session key{' '}
              <code className="text-cyan-300">K</code> into header{' '}
              <code className="text-cyan-300">c_kem</code>.
            </p>
            <div className="font-mono text-[10px] bg-slate-900 px-2 py-1 rounded text-cyan-300/90 border border-slate-800">
              c_kem = Encaps(pk)
            </div>
          </div>

          {/* Card 2 */}
          <div
            onClick={() => setActiveStep(2)}
            className={`cursor-pointer rounded-xl border p-4 transition-all duration-200 ${
              activeStep === 2
                ? 'border-blue-400 bg-slate-900/90 shadow-lg shadow-blue-500/10'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono text-blue-400 font-semibold uppercase">
                Stage 2: DEM
              </span>
              <Lock className="w-4 h-4 text-blue-400" />
            </div>
            <h4 className="text-sm font-semibold text-white mb-1">Data AEAD</h4>
            <p className="text-xs text-slate-400 leading-relaxed mb-3">
              Session key <code className="text-blue-300">K</code> encrypts bulk image with AES-256-GCM
              plus 128-bit tag.
            </p>
            <div className="font-mono text-[10px] bg-slate-900 px-2 py-1 rounded text-blue-300/90 border border-slate-800">
              C = DEM.Enc(K, M, IV)
            </div>
          </div>

          {/* Card 3 */}
          <div
            onClick={() => setActiveStep(3)}
            className={`cursor-pointer rounded-xl border p-4 transition-all duration-200 ${
              activeStep === 3
                ? 'border-emerald-400 bg-slate-900/90 shadow-lg shadow-emerald-500/10'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono text-emerald-400 font-semibold uppercase">
                Container
              </span>
              <FileDigit className="w-4 h-4 text-emerald-400" />
            </div>
            <h4 className="text-sm font-semibold text-white mb-1">.kemdem Artifact</h4>
            <p className="text-xs text-slate-400 leading-relaxed mb-3">
              Header (<code className="text-emerald-300">c_kem</code>) + Payload (
              <code className="text-emerald-300">C, IV, Tag</code>) combined.
            </p>
            <div className="font-mono text-[10px] bg-slate-900 px-2 py-1 rounded text-emerald-300/90 border border-slate-800">
              Entropy H ≈ 7.999 bits/byte
            </div>
          </div>

          {/* Card 4 */}
          <div
            onClick={() => setActiveStep(4)}
            className={`cursor-pointer rounded-xl border p-4 transition-all duration-200 ${
              activeStep === 4
                ? 'border-amber-400 bg-slate-900/90 shadow-lg shadow-amber-500/10'
                : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono text-amber-400 font-semibold uppercase">
                Decryption
              </span>
              <Unlock className="w-4 h-4 text-amber-400" />
            </div>
            <h4 className="text-sm font-semibold text-white mb-1">Decaps & Decrypt</h4>
            <p className="text-xs text-slate-400 leading-relaxed mb-3">
              Private key <code className="text-amber-300">sk</code> decapsulates{' '}
              <code className="text-amber-300">K</code>; DEM verifies Tag before output.
            </p>
            <div className="font-mono text-[10px] bg-slate-900 px-2 py-1 rounded text-amber-300/90 border border-slate-800">
              M = DEM.Dec(K, C)
            </div>
          </div>
        </div>

        {/* Selected Step Deep Dive */}
        {activeStep !== null && (
          <div className="mt-6 p-5 rounded-xl bg-slate-950/80 border border-slate-800 animate-fadeIn">
            {(() => {
              const item = steps.find((s) => s.id === activeStep)!;
              return (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-semibold text-cyan-400">
                      {item.phase}
                    </span>
                    <button
                      onClick={() => setActiveStep(null)}
                      className="text-xs text-slate-500 hover:text-slate-300"
                    >
                      Close details
                    </button>
                  </div>
                  <h3 className="text-base font-bold text-white">{item.title}</h3>
                  <div className="font-mono text-xs text-emerald-400 bg-slate-900/80 px-3 py-2 rounded-lg border border-slate-800">
                    {item.formula}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{item.description}</p>
                  <p className="text-xs text-slate-400 leading-relaxed italic border-l-2 border-cyan-500/50 pl-3">
                    {item.detail}
                  </p>
                </div>
              );
            })()}
          </div>
        )}
      </div>

      {/* Comparison Grid: KEM-DEM vs Naive RSA vs Naive AES */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="border border-slate-800/80 bg-slate-900/20 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2 text-rose-400">
            <span className="text-xs font-mono font-semibold">TRADITIONAL DRAWBACK</span>
          </div>
          <h4 className="text-sm font-bold text-white mb-2">Naive Direct RSA Encryption</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Directly encrypting an image with RSA is impossible for files larger than ~190 bytes (RSA-2048 with OAEP limit). Splitting an image into hundreds of RSA blocks is computationally catastrophic and leaks structural block patterns.
          </p>
        </div>

        <div className="border border-slate-800/80 bg-slate-900/20 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2 text-amber-400">
            <span className="text-xs font-mono font-semibold">TRADITIONAL DRAWBACK</span>
          </div>
          <h4 className="text-sm font-bold text-white mb-2">Standalone Symmetric (AES)</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Encrypting with pure AES requires both parties to pre-share a 256-bit secret over a secure out-of-band channel before any message can be transmitted. This fails in open or zero-trust networks.
          </p>
        </div>

        <div className="border border-cyan-500/30 bg-cyan-950/10 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2 text-cyan-400">
            <CheckCircle2 className="w-4 h-4" />
            <span className="text-xs font-mono font-semibold">KEM-DEM ADVANTAGE</span>
          </div>
          <h4 className="text-sm font-bold text-white mb-2">Hybrid Composition</h4>
          <p className="text-xs text-slate-300 leading-relaxed">
            KEM transmits only 256 to 512 bytes of encapsulated key material using public keys, while DEM streams gigabytes of image data at full hardware bus speeds (AES-NI / Poly1305) with 100% AEAD tamper detection.
          </p>
        </div>
      </div>
    </div>
  );
};
