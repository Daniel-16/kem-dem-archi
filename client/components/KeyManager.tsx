import React, { useState } from 'react';
import {
  KeyRound,
  Plus,
  Download,
  Copy,
  Check,
  Trash2,
  Upload,
  Shield,
  FileCode,
  Sparkles,
} from 'lucide-react';
import type { KemKeyPair, KemAlgorithm } from '../types/crypto.js';

interface KeyManagerProps {
  keyring: KemKeyPair[];
  activeRecipientKeyId: string;
  setActiveRecipientKeyId: (id: string) => void;
  onAddKey: (key: KemKeyPair) => void;
  onRemoveKey: (id: string) => void;
}

export const KeyManager: React.FC<KeyManagerProps> = ({
  keyring,
  activeRecipientKeyId,
  setActiveRecipientKeyId,
  onAddKey,
  onRemoveKey,
}) => {
  const [isGenerating, setIsGenerating] = useState(false);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState<KemAlgorithm>('RSA-OAEP-2048');
  const [keyLabel, setKeyLabel] = useState('');
  const [copiedKeyId, setCopiedKeyId] = useState<string | null>(null);
  const [showImportModal, setShowImportModal] = useState(false);
  const [importLabel, setImportLabel] = useState('');
  const [importAlgorithm, setImportAlgorithm] = useState<KemAlgorithm>('RSA-OAEP-2048');
  const [importPublicPem, setImportPublicPem] = useState('');
  const [importPrivatePem, setImportPrivatePem] = useState('');
  const [importError, setImportError] = useState<string | null>(null);

  const handleGenerateKey = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch('/api/kem-dem/keygen', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          algorithm: selectedAlgorithm,
          label: keyLabel.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (data.success && data.keyPair) {
        onAddKey(data.keyPair);
        setActiveRecipientKeyId(data.keyPair.id);
        setKeyLabel('');
      } else {
        alert(`Failed to generate key: ${data.error}`);
      }
    } catch (err: any) {
      alert(`Key generation request error: ${err.message}`);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKeyId(id);
    setTimeout(() => setCopiedKeyId(null), 2000);
  };

  const handleDownloadPem = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleImportSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setImportError(null);

    if (!importPublicPem.includes('BEGIN') || !importPublicPem.includes('PUBLIC KEY')) {
      setImportError('Public Key must be a valid PEM formatted string (BEGIN PUBLIC KEY)');
      return;
    }

    const cleanKey = importPublicPem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
    const id = `imported_${Date.now()}`;
    const fingerprint = cleanKey.substring(0, 16).toLowerCase();

    const importedKey: KemKeyPair = {
      id,
      label: importLabel.trim() || `Imported ${importAlgorithm} (${fingerprint.substring(0, 8)})`,
      algorithm: importAlgorithm,
      publicKeyPem: importPublicPem.trim(),
      privateKeyPem: importPrivatePem.trim(),
      fingerprint,
      createdAt: Date.now(),
      keyDetails: {
        description: `Imported ${importAlgorithm} Key Pair`,
      },
    };

    onAddKey(importedKey);
    setActiveRecipientKeyId(id);
    setShowImportModal(false);
    setImportPublicPem('');
    setImportPrivatePem('');
    setImportLabel('');
  };

  return (
    <div className="space-y-6">
      {/* Key Generator Panel */}
      <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
              <KeyRound className="w-3.5 h-3.5" />
              <span>ASYMMETRIC KEY MANAGEMENT</span>
            </div>
            <h3 className="text-lg font-bold text-white">KEM Keyring & Identity Pairs</h3>
            <p className="text-xs text-slate-400">
              Generate or import asymmetric public/private key pairs used by the KEM stage to
              encapsulate symmetric session keys.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowImportModal(true)}
              className="flex items-center gap-2 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded-lg transition-colors border border-slate-700/60"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Import PEM</span>
            </button>
          </div>
        </div>

        {/* Generator Controls */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-xl bg-slate-950/70 border border-slate-800">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              KEM Algorithm & Strength
            </label>
            <select
              value={selectedAlgorithm}
              onChange={(e) => setSelectedAlgorithm(e.target.value as KemAlgorithm)}
              className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="RSA-OAEP-2048">RSA-OAEP 2048-bit (Standard Enterprise)</option>
              <option value="RSA-OAEP-3072">RSA-OAEP 3072-bit (NIST High-Security)</option>
              <option value="RSA-OAEP-4096">RSA-OAEP 4096-bit (Maximum Classical)</option>
              <option value="ECDH-P256">ECDH NIST P-256 + HKDF (Fast & Modern)</option>
              <option value="ECDH-P384">ECDH NIST P-384 + HKDF (Top Secret Tier)</option>
              <option value="ECDH-X25519">ECDH Curve25519 + HKDF (Ultra-High Perf)</option>
              <option value="HYBRID-PQ">HYBRID-PQ: NIST P-256 + Lattice ML-KEM</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Key Pair Label (Optional)
            </label>
            <input
              type="text"
              placeholder="e.g. Hospital Radiologist Key"
              value={keyLabel}
              onChange={(e) => setKeyLabel(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={handleGenerateKey}
              disabled={isGenerating}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 active:bg-cyan-500 rounded-lg transition-colors disabled:opacity-50 cursor-pointer shadow-sm shadow-cyan-500/20"
            >
              <Plus className="w-4 h-4" />
              <span>{isGenerating ? 'Generating Pair...' : 'Generate New Key Pair'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Keyring List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 px-1">
          <span>Active Key Pairs ({keyring.length})</span>
          <span>Click a key to set as the active recipient for encryption</span>
        </div>

        {keyring.length === 0 ? (
          <div className="border border-dashed border-slate-800 rounded-xl p-8 text-center text-slate-500 text-xs">
            No keys currently in keyring. Generate one above or import existing PEM keys.
          </div>
        ) : (
          keyring.map((k) => {
            const isActive = k.id === activeRecipientKeyId;
            return (
              <div
                key={k.id}
                onClick={() => setActiveRecipientKeyId(k.id)}
                className={`cursor-pointer rounded-xl border p-4.5 transition-all duration-150 ${
                  isActive
                    ? 'border-cyan-500/60 bg-slate-900/80 shadow-md shadow-cyan-500/5'
                    : 'border-slate-800/80 bg-slate-950/40 hover:border-slate-700/80 hover:bg-slate-900/30'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-white">{k.label}</span>
                      {isActive && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-md bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                          Active Target
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                      <span className="font-mono text-cyan-400/90">{k.algorithm}</span>
                      <span>·</span>
                      <span className="font-mono text-[11px] text-slate-500">
                        FP: {k.fingerprint}
                      </span>
                      <span>·</span>
                      <span>{k.keyDetails.description}</span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div
                    className="flex items-center gap-2 shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      onClick={() =>
                        handleDownloadPem(
                          k.publicKeyPem,
                          `${k.label.replace(/\s+/g, '_')}_public.pem`
                        )
                      }
                      title="Download Public Key PEM"
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700/60 transition-colors"
                    >
                      <Download className="w-3 h-3 text-cyan-400" />
                      <span>Pub PEM</span>
                    </button>

                    {k.privateKeyPem && (
                      <button
                        onClick={() =>
                          handleDownloadPem(
                            k.privateKeyPem,
                            `${k.label.replace(/\s+/g, '_')}_private.pem`
                          )
                        }
                        title="Download Private Key PEM"
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-amber-300 text-xs border border-slate-700/60 transition-colors"
                      >
                        <Download className="w-3 h-3 text-amber-400" />
                        <span>Priv PEM</span>
                      </button>
                    )}

                    <button
                      onClick={() => handleCopy(k.publicKeyPem, `pub-${k.id}`)}
                      title="Copy Public Key"
                      className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700/60 transition-colors"
                    >
                      {copiedKeyId === `pub-${k.id}` ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>

                    {keyring.length > 1 && (
                      <button
                        onClick={() => onRemoveKey(k.id)}
                        title="Remove Key"
                        className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-rose-950 text-slate-400 hover:text-rose-400 border border-slate-700/60 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Import Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-xl w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white">Import Existing PEM Key Pair</h3>
              <button
                onClick={() => setShowImportModal(false)}
                className="text-slate-400 hover:text-white text-xs"
              >
                ✕ Cancel
              </button>
            </div>

            {importError && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-xs text-rose-300">
                {importError}
              </div>
            )}

            <form onSubmit={handleImportSubmit} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Key Label</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. External Party RSA"
                    value={importLabel}
                    onChange={(e) => setImportLabel(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Algorithm</label>
                  <select
                    value={importAlgorithm}
                    onChange={(e) => setImportAlgorithm(e.target.value as KemAlgorithm)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono"
                  >
                    <option value="RSA-OAEP-2048">RSA-OAEP-2048</option>
                    <option value="RSA-OAEP-3072">RSA-OAEP-3072</option>
                    <option value="RSA-OAEP-4096">RSA-OAEP-4096</option>
                    <option value="ECDH-P256">ECDH-P256</option>
                    <option value="ECDH-X25519">ECDH-X25519</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Public Key PEM (Required)
                </label>
                <textarea
                  rows={4}
                  required
                  placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
                  value={importPublicPem}
                  onChange={(e) => setImportPublicPem(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-[11px] font-mono text-cyan-300"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Private Key PEM (Optional for decryption)
                </label>
                <textarea
                  rows={4}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  value={importPrivatePem}
                  onChange={(e) => setImportPrivatePem(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-[11px] font-mono text-amber-300"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowImportModal(false)}
                  className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg"
                >
                  Save to Keyring
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
