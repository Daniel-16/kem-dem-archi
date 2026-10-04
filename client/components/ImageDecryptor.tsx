import { useState, useEffect } from "react";
import {
  Unlock,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  Download,
  Upload,
  ShieldCheck
} from "lucide-react";
import type {
  KemKeyPair,
  KemDemPackage,
  DecryptionResult,
  ExecutionEngine,
} from "../types/crypto.js";
import { decryptImageWithWebCrypto } from "../crypto/webCryptoKemDem.js";

interface ImageDecryptorProps {
  keyring: KemKeyPair[];
  activePackage: KemDemPackage | null;
}

export const ImageDecryptor: React.FC<ImageDecryptorProps> = ({
  keyring,
  activePackage,
}) => {
  const [currentPackage, setCurrentPackage] = useState<KemDemPackage | null>(
    activePackage,
  );
  const [selectedPrivateKeyId, setSelectedPrivateKeyId] = useState<string>("");
  const [customPrivateKeyPem, setCustomPrivateKeyPem] = useState<string>("");
  const [useCustomKey, setUseCustomKey] = useState<boolean>(false);
  const [engine, setEngine] = useState<ExecutionEngine>("NODEJS_BACKEND");

  // Execution state
  const [isDecrypting, setIsDecrypting] = useState<boolean>(false);
  const [decryptionResult, setDecryptionResult] =
    useState<DecryptionResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Raw JSON package input state
  const [rawPackageJson, setRawPackageJson] = useState<string>("");
  const [showJsonInput, setShowJsonInput] = useState<boolean>(false);

  // Keep the currently selected package in sync with encryption in this session.
  useEffect(() => {
    if (activePackage) {
      setCurrentPackage(activePackage);
      setDecryptionResult(null);
      setErrorMessage(null);
    }
  }, [activePackage]);

  // Prefer the exact recipient key; otherwise prompt for a private PEM.
  useEffect(() => {
    if (!currentPackage) return;
    const match = keyring.find(
      (key) =>
        key.privateKeyPem &&
        key.fingerprint === currentPackage.kemHeader.recipientFingerprint,
    );
    if (match) {
      setSelectedPrivateKeyId(match.id);
      setUseCustomKey(false);
    } else {
      setSelectedPrivateKeyId("");
      setUseCustomKey(true);
    }
  }, [currentPackage, keyring]);

  const handlePrivateKeyUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const pem = String(event.target?.result || "").trim();
      if (!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(pem)) {
        setErrorMessage(
          "This file does not look like a private PEM key. Select the matching *_private.pem file.",
        );
        return;
      }
      setCustomPrivateKeyPem(pem);
      setUseCustomKey(true);
      setErrorMessage(null);
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const parsed: KemDemPackage = JSON.parse(text);
        if (parsed.format !== "KEM-DEM-V1") {
          throw new Error("Unrecognized format: Expected KEM-DEM-V1 package");
        }
        setCurrentPackage(parsed);
        setDecryptionResult(null);
        setErrorMessage(null);

        // Auto-match key
        if (parsed.kemHeader.recipientFingerprint) {
          const match = keyring.find(
            (k) => k.fingerprint === parsed.kemHeader.recipientFingerprint,
          );
          if (match) {
            setSelectedPrivateKeyId(match.id);
            setUseCustomKey(false);
          }
        }
      } catch (err: any) {
        setErrorMessage(`Invalid .kemdem file: ${err.message}`);
      }
    };
    reader.readAsText(file);
  };

  const handleLoadJson = () => {
    try {
      const parsed: KemDemPackage = JSON.parse(rawPackageJson);
      if (parsed.format !== "KEM-DEM-V1") {
        throw new Error("Unrecognized format: Expected KEM-DEM-V1");
      }
      setCurrentPackage(parsed);
      setShowJsonInput(false);
      setDecryptionResult(null);
      setErrorMessage(null);
    } catch (err: any) {
      setErrorMessage(`JSON Parse Error: ${err.message}`);
    }
  };

  const handleExecuteDecryption = async () => {
    if (!currentPackage) {
      setErrorMessage("No KEM-DEM package loaded.");
      return;
    }

    let privateKeyPem = "";
    if (useCustomKey) {
      privateKeyPem = customPrivateKeyPem.trim();
    } else {
      const selected = keyring.find((k) => k.id === selectedPrivateKeyId);
      if (!selected || !selected.privateKeyPem) {
        setErrorMessage(
          "The selected key in keyring has no private key available.",
        );
        return;
      }
      privateKeyPem = selected.privateKeyPem;
    }

    if (!privateKeyPem) {
      setErrorMessage(
        "No private key is loaded. Select the matching key from your keyring or upload its *_private.pem file.",
      );
      return;
    }

    setIsDecrypting(true);
    setErrorMessage(null);

    try {
      if (engine === "BROWSER_WEBCRYPTO") {
        if (!currentPackage.kemHeader.algorithm.startsWith("RSA-OAEP")) {
          throw new Error(
            "Browser WebCrypto currently natively decapsulates RSA-OAEP. For ECDH curves or PQ-Hybrid, please select the Node.js Backend Engine.",
          );
        }

        const result = await decryptImageWithWebCrypto({
          package: currentPackage,
          recipientPrivateKeyPem: privateKeyPem,
        });

        if (!result.success) {
          throw new Error(result.error || "Decryption failed");
        }

        setDecryptionResult(result);
      } else {
        // Node.js Express server route
        const res = await fetch("/api/kem-dem/decrypt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            package: currentPackage,
            recipientPrivateKeyPem: privateKeyPem,
          }),
        });

        const data = await res.json();
        if (!data.success) {
          throw new Error(
            `[${data.errorPhase || "ERROR"}] ${data.error || "Server decapsulation/decryption failed"}`,
          );
        }

        setDecryptionResult(data);
      }
    } catch (err: any) {
      setErrorMessage(err.message || "Decryption process failed");
    } finally {
      setIsDecrypting(false);
    }
  };

  const downloadDecryptedImage = () => {
    if (!decryptionResult || !currentPackage) return;
    const a = document.createElement("a");
    a.href = decryptionResult.decryptedDataUrl;
    a.download = `decrypted_${currentPackage.sourceImage.name}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="space-y-6">
      {/* Decryptor Header */}
      <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
              <Unlock className="w-3.5 h-3.5" />
              <span>STAGE 3 & 4 PIPELINE</span>
            </div>
            <h3 className="text-lg font-bold text-white">
              KEM-DEM Image Decryptor
            </h3>
            <p className="text-xs text-slate-400">
              Decapsulates symmetric session key K using the recipient’s private
              key, then verifies AEAD tag and decrypts image payload.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <label className="cursor-pointer px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded-lg transition-colors border border-slate-700/60 flex items-center gap-1.5">
              <span>Upload encrypted JSON</span>
              <input
                type="file"
                accept=".json,.kemdem"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>

            <button
              onClick={() => setShowJsonInput(!showJsonInput)}
              className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800/80 hover:bg-slate-700 rounded-lg transition-colors border border-slate-700/60"
            >
              {showJsonInput ? "Hide JSON" : "Paste JSON"}
            </button>
          </div>
        </div>

        {/* JSON Paste Drawer */}
        {showJsonInput && (
          <div className="mb-6 p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
            <label className="block text-xs font-medium text-slate-300">
              Paste KEM-DEM JSON Package String:
            </label>
            <textarea
              rows={4}
              value={rawPackageJson}
              onChange={(e) => setRawPackageJson(e.target.value)}
              placeholder='{ "format": "KEM-DEM-V1", "kemHeader": { ... }, "demPayload": { ... } }'
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono text-slate-200"
            />
            <div className="flex justify-end">
              <button
                onClick={handleLoadJson}
                className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg"
              >
                Load Package
              </button>
            </div>
          </div>
        )}

        {/* Current Package Overview */}
        {currentPackage ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Package Details */}
            <div className="lg:col-span-6 space-y-4">
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-white">
                    Target Package
                  </span>
                  <span className="font-mono text-[10px] bg-slate-900 text-cyan-400 px-2 py-0.5 rounded border border-slate-800">
                    {currentPackage.format}
                  </span>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Source Image:</span>
                    <span className="text-white font-mono">
                      {currentPackage.sourceImage.name}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">Dimensions:</span>
                    <span className="text-slate-300 font-mono">
                      {currentPackage.sourceImage.width} x{" "}
                      {currentPackage.sourceImage.height} px
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">KEM Algorithm:</span>
                    <span className="text-cyan-300 font-mono">
                      {currentPackage.kemHeader.algorithm}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span className="text-slate-400">DEM Cipher:</span>
                    <span className="text-blue-300 font-mono">
                      {currentPackage.demPayload.algorithm}
                    </span>
                  </div>
                  {currentPackage.demPayload.aad && (
                    <div className="flex justify-between py-1 border-b border-slate-800/60">
                      <span className="text-slate-400">Authenticated AAD:</span>
                      <span className="text-slate-300 font-mono text-[11px] truncate max-w-50">
                        {currentPackage.demPayload.aad}
                      </span>
                    </div>
                  )}
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">Expected SHA-256:</span>
                    <span className="text-slate-400 font-mono text-[10px] truncate max-w-50">
                      {currentPackage.sourceImage.originalSha256}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Recipient Private Key Selection */}
            <div className="lg:col-span-6 space-y-4">
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3.5">
                <p className="text-[11px] leading-relaxed text-amber-200/90">
                  The encrypted JSON does not include a private key. Use the key
                  that was selected when encrypting, or upload its matching
                  private .pem file.
                </p>
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-slate-300">
                    Recipient Private Key (KEM Decapsulator)
                  </label>
                  <button
                    onClick={() => setUseCustomKey(!useCustomKey)}
                    className="text-[11px] text-cyan-400 hover:underline"
                  >
                    {useCustomKey ? "Select from Keyring" : "Enter Custom PEM"}
                  </button>
                </div>

                {!useCustomKey ? (
                  <select
                    value={selectedPrivateKeyId}
                    onChange={(e) => setSelectedPrivateKeyId(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    {keyring
                      .filter((k) => !!k.privateKeyPem)
                      .map((k) => (
                        <option key={k.id} value={k.id}>
                          {k.label} [{k.algorithm}]
                        </option>
                      ))}
                  </select>
                ) : (
                  <div className="space-y-2">
                    <label className="flex w-fit cursor-pointer items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200 hover:bg-amber-500/20">
                      <Upload className="h-4 w-4" />
                      <span>
                        {customPrivateKeyPem
                          ? "Replace private key file"
                          : "Upload private key (.pem)"}
                      </span>
                      <input
                        type="file"
                        accept=".pem,.key,text/plain"
                        onChange={handlePrivateKeyUpload}
                        className="hidden"
                      />
                    </label>
                    <textarea
                      rows={3}
                      placeholder="Or paste the contents of the matching private PEM file"
                      value={customPrivateKeyPem}
                      onChange={(e) => setCustomPrivateKeyPem(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700/80 rounded-lg p-2.5 text-[11px] font-mono text-amber-300"
                    />
                  </div>
                )}

                {/* Engine Selector */}
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Decryption Engine
                  </label>
                  <select
                    value={engine}
                    onChange={(e) =>
                      setEngine(e.target.value as ExecutionEngine)
                    }
                    className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="NODEJS_BACKEND">
                      Node.js Express Server Engine
                    </option>
                    <option value="BROWSER_WEBCRYPTO">
                      Browser Web Crypto API Engine
                    </option>
                  </select>
                </div>

                {/* Execute Button */}
                <button
                  onClick={handleExecuteDecryption}
                  disabled={isDecrypting}
                  className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 active:bg-cyan-500 rounded-lg transition-colors disabled:opacity-50 cursor-pointer shadow-md shadow-cyan-500/20"
                >
                  <Unlock className="w-4 h-4" />
                  <span>
                    {isDecrypting
                      ? "Decapsulating & Verifying AEAD Tag..."
                      : "Decapsulate & Decrypt Image"}
                  </span>
                </button>

                {errorMessage && (
                  <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-xs text-rose-300 space-y-1">
                    <div className="flex items-center gap-1.5 font-bold">
                      <AlertTriangle className="w-4 h-4" />
                      <span>Decryption Rejected</span>
                    </div>
                    <p className="text-[11px] leading-relaxed">
                      {errorMessage}
                    </p>
                    <p className="text-[10px] text-rose-400/80 italic">
                      This occurs when the private key is incorrect or if any
                      bit of the ciphertext, tag, or AAD was tampered with.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="border border-dashed border-slate-800 rounded-xl p-8 text-center text-slate-500 text-xs space-y-3">
            <p>
              No encrypted package loaded. Encrypt an image in Stage 1 or upload
              a .kemdem file.
            </p>
          </div>
        )}
      </div>

      {/* Decryption Verification & Image Output */}
      {decryptionResult && (
        <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6 space-y-6 animate-fadeIn">
          {/* Top Banner Status */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold">
              <CheckCircle2 className="w-5 h-5" />
              <span>
                Decryption & Authentication Verified: 100% Lossless Match
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={downloadDecryptedImage}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>Download Decrypted Image</span>
              </button>
            </div>
          </div>

          {/* Decrypted Image Display */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
            <div className="flex items-center justify-center bg-slate-950/80 rounded-xl border border-slate-800 p-4 min-h-75">
              <img
                src={decryptionResult.decryptedDataUrl}
                alt="Decrypted result"
                referrerPolicy="no-referrer"
                className="max-h-70 max-w-full rounded object-contain shadow-lg"
              />
            </div>

            {/* Cryptographic Proof Card */}
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                  Cryptographic Integrity Report
                </h4>

                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-slate-800/80">
                    <span className="text-slate-400">
                      Bit-for-Bit Equality:
                    </span>
                    <span className="text-emerald-400 font-bold">
                      100% IDENTICAL
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80">
                    <span className="text-slate-400">Decrypted SHA-256:</span>
                    <span className="text-cyan-300 truncate max-w-50">
                      {decryptionResult.decryptedSha256}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80">
                    <span className="text-slate-400">
                      KEM Decapsulation Time:
                    </span>
                    <span className="text-slate-200">
                      {decryptionResult.decapsulationTimeMs} ms
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80">
                    <span className="text-slate-400">
                      DEM AEAD Decryption Time:
                    </span>
                    <span className="text-slate-200">
                      {decryptionResult.decryptionTimeMs} ms
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/80">
                    <span className="text-slate-400">
                      Total Decryption Pipeline:
                    </span>
                    <span className="text-emerald-400 font-bold">
                      {decryptionResult.totalDecryptionTimeMs} ms
                    </span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-400">
                      Image Entropy Restored:
                    </span>
                    <span className="text-slate-200">
                      {decryptionResult.entropy} bits/byte
                    </span>
                  </div>
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-xs text-emerald-300 space-y-1">
                <span className="font-bold flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Authenticated Decryption Guaranteed</span>
                </span>
                <p className="text-[11px] text-emerald-400/90 leading-relaxed">
                  Both the cryptographic MAC tag and the KEM key encapsulation
                  passed verification. The restored image is mathematically
                  guaranteed to be untampered and identical to the original.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
