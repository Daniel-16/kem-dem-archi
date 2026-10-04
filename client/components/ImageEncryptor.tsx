import React, { useState, useRef, useEffect } from "react";
import {
  Upload,
  Lock,
  Cpu,
  FileDigit,
  Download,
  ArrowRight,
  ShieldCheck,
  Zap,
  Layers,
  Sparkles,
  Info,
  CheckCircle,
} from "lucide-react";
import type {
  KemKeyPair,
  KemAlgorithm,
  DemAlgorithm,
  ExecutionEngine,
  KemDemPackage,
  SampleImage,
} from "../types/crypto.js";
import { encryptImageWithWebCrypto } from "../crypto/webCryptoKemDem.js";

interface ImageEncryptorProps {
  keyring: KemKeyPair[];
  activeRecipientKeyId: string;
  samples: SampleImage[];
  onPackageGenerated: (pkg: KemDemPackage, visualNoiseBase64?: string) => void;
  onNavigateToDecrypt: () => void;
  onNavigateToTamper: () => void;
}

export const ImageEncryptor: React.FC<ImageEncryptorProps> = ({
  keyring,
  activeRecipientKeyId,
  samples,
  onPackageGenerated,
  onNavigateToDecrypt,
  onNavigateToTamper,
}) => {
  // Input image state
  const [selectedImageSrc, setSelectedImageSrc] = useState<string>("");
  const [imageMeta, setImageMeta] = useState<{
    name: string;
    mimeType: string;
    sizeBytes: number;
    width: number;
    height: number;
  }>({
    name: "",
    mimeType: "image/png",
    sizeBytes: 0,
    width: 0,
    height: 0,
  });

  // Crypto parameters
  const [recipientKeyId, setRecipientKeyId] =
    useState<string>(activeRecipientKeyId);
  const [kemAlgorithm, setKemAlgorithm] =
    useState<KemAlgorithm>("RSA-OAEP-2048");
  const [demAlgorithm, setDemAlgorithm] = useState<DemAlgorithm>("AES-256-GCM");
  const [engine, setEngine] = useState<ExecutionEngine>("NODEJS_BACKEND");
  const [aadText, setAadText] = useState<string>(
    `Classification=CONFIDENTIAL; Issued=${new Date().toISOString().split("T")[0]}`,
  );

  // Execution state
  const [isEncrypting, setIsEncrypting] = useState<boolean>(false);
  const [currentPackage, setCurrentPackage] = useState<KemDemPackage | null>(
    null,
  );
  const [visualNoiseSrc, setVisualNoiseSrc] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Sync with active recipient key from parent if updated
  useEffect(() => {
    if (
      activeRecipientKeyId &&
      keyring.some((k) => k.id === activeRecipientKeyId)
    ) {
      setRecipientKeyId(activeRecipientKeyId);
      const activeKey = keyring.find((k) => k.id === activeRecipientKeyId);
      if (activeKey) {
        setKemAlgorithm(activeKey.algorithm);
      }
    }
  }, [activeRecipientKeyId, keyring]);

  // Load first sample as default on mount if nothing selected
  useEffect(() => {
    if (!selectedImageSrc && samples.length > 0) {
      loadSample(samples[0]);
    }
  }, [samples]);

  const loadSample = (sample: SampleImage) => {
    setSelectedImageSrc(sample.dataUrl);
    setImageMeta({
      name: `${sample.id}.png`,
      mimeType: "image/png",
      sizeBytes: Math.round(sample.dataUrl.length * 0.75),
      width: sample.width,
      height: sample.height,
    });
    setCurrentPackage(null);
    setVisualNoiseSrc("");
    setErrorMessage(null);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target?.result as string;
      const img = new Image();
      img.onload = () => {
        setSelectedImageSrc(dataUrl);
        setImageMeta({
          name: file.name,
          mimeType: file.type || "image/png",
          sizeBytes: file.size,
          width: img.width,
          height: img.height,
        });
        setCurrentPackage(null);
        setVisualNoiseSrc("");
        setErrorMessage(null);
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const dataUrl = event.target?.result as string;
        const img = new Image();
        img.onload = () => {
          setSelectedImageSrc(dataUrl);
          setImageMeta({
            name: file.name,
            mimeType: file.type || "image/png",
            sizeBytes: file.size,
            width: img.width,
            height: img.height,
          });
          setCurrentPackage(null);
          setVisualNoiseSrc("");
          setErrorMessage(null);
        };
        img.src = dataUrl;
      };
      reader.readAsDataURL(file);
    }
  };

  // Render noise bytes onto Canvas for high-fidelity visualization
  const renderNoiseToCanvas = (
    rawBase64OrOctet: string,
    width: number,
    height: number,
  ) => {
    if (!canvasRef.current) return;
    const canvas = canvasRef.current;
    canvas.width = Math.min(width, 300);
    canvas.height = Math.min(height, 300);
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    try {
      let b64 = rawBase64OrOctet;
      if (b64.includes("base64,")) {
        b64 = b64.split("base64,")[1];
      }
      const binary = atob(b64);
      const imgData = ctx.createImageData(canvas.width, canvas.height);
      const totalPixels = canvas.width * canvas.height;

      for (let i = 0; i < totalPixels; i++) {
        const byteIdx = (i * 3) % binary.length;
        imgData.data[i * 4] = binary.charCodeAt(byteIdx);
        imgData.data[i * 4 + 1] = binary.charCodeAt(
          (byteIdx + 1) % binary.length,
        );
        imgData.data[i * 4 + 2] = binary.charCodeAt(
          (byteIdx + 2) % binary.length,
        );
        imgData.data[i * 4 + 3] = 255;
      }
      ctx.putImageData(imgData, 0, 0);
    } catch (e) {
      console.error("Failed to render noise canvas", e);
    }
  };

  const handleExecuteEncryption = async () => {
    if (!selectedImageSrc) {
      setErrorMessage("Please select or upload an image to encrypt.");
      return;
    }

    const selectedKey = keyring.find((k) => k.id === recipientKeyId);
    if (!selectedKey) {
      setErrorMessage(
        "Please select a valid recipient public key from the keyring.",
      );
      return;
    }

    setIsEncrypting(true);
    setErrorMessage(null);

    try {
      if (engine === "BROWSER_WEBCRYPTO") {
        // Run Client-Side Web Crypto API
        if (!selectedKey.algorithm.startsWith("RSA-OAEP")) {
          throw new Error(
            "Browser WebCrypto currently natively supports RSA-OAEP for KEM. For ECDH curves or PQ-Hybrid, please select the Node.js Backend Engine.",
          );
        }

        // Convert data URL to Uint8Array
        const b64 = selectedImageSrc.split("base64,")[1];
        const binary = atob(b64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }

        const result = await encryptImageWithWebCrypto({
          imageBytes: bytes,
          imageName: imageMeta.name,
          mimeType: imageMeta.mimeType,
          width: imageMeta.width || 400,
          height: imageMeta.height || 400,
          recipientPublicKeyPem: selectedKey.publicKeyPem,
          kemAlgorithm: selectedKey.algorithm,
          demAlgorithm: "AES-256-GCM",
          aad: aadText.trim() || undefined,
        });

        setCurrentPackage(result.package);
        setVisualNoiseSrc(result.noiseRgbaBase64);
        renderNoiseToCanvas(
          result.noiseRgbaBase64,
          imageMeta.width || 300,
          imageMeta.height || 300,
        );
        onPackageGenerated(result.package, result.noiseRgbaBase64);
      } else {
        // Run Node.js Backend Engine via /api/kem-dem/encrypt
        const res = await fetch("/api/kem-dem/encrypt", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            imageData: selectedImageSrc,
            imageName: imageMeta.name,
            mimeType: imageMeta.mimeType,
            width: imageMeta.width,
            height: imageMeta.height,
            recipientPublicKeyPem: selectedKey.publicKeyPem,
            kemAlgorithm: selectedKey.algorithm,
            demAlgorithm,
            aad: aadText.trim() || undefined,
          }),
        });

        const data = await res.json();
        if (!data.success) {
          throw new Error(data.error || "Server encryption failed");
        }

        setCurrentPackage(data.package);
        setVisualNoiseSrc(data.noiseData);
        renderNoiseToCanvas(
          data.noiseData,
          imageMeta.width || 300,
          imageMeta.height || 300,
        );
        onPackageGenerated(data.package, data.noiseData);
      }
    } catch (err: any) {
      setErrorMessage(err.message || "Encryption failed");
    } finally {
      setIsEncrypting(false);
    }
  };

  const downloadPackageJson = () => {
    if (!currentPackage) return;
    const blob = new Blob([JSON.stringify(currentPackage, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${currentPackage.sourceImage.name.replace(/\.[^/.]+$/, "")}.kemdem.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadRecipientPrivateKey = () => {
    const recipientKey = keyring.find((key) => key.id === recipientKeyId);
    if (!recipientKey?.privateKeyPem) return;

    const blob = new Blob([recipientKey.privateKeyPem], {
      type: "application/x-pem-file",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${recipientKey.label.replace(/[^a-zA-Z0-9_-]/g, "_")}_private.pem`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Preset Selector */}
      <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
              <Lock className="w-3.5 h-3.5" />
              <span>STAGE 1 & 2 PIPELINE</span>
            </div>
            <h3 className="text-lg font-bold text-white">
              KEM-DEM Image Encryptor
            </h3>
            <p className="text-xs text-slate-400">
              Encapsulates an ephemeral session key using asymmetric KEM, then
              encrypts bulk pixel data using authenticated symmetric DEM.
            </p>
          </div>

          {/* Preset Buttons */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 mr-1 hidden sm:inline">
              Presets:
            </span>
            {samples.map((s) => (
              <button
                key={s.id}
                onClick={() => loadSample(s)}
                className="px-2.5 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700/60 transition-colors whitespace-nowrap cursor-pointer"
              >
                {s.name.split(" ")[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Upload Drop Zone & Preview Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 mt-6">
          {/* Left: Input Selection & File Drag/Drop */}
          <div className="lg:col-span-6 space-y-4">
            <div
              onDragOver={handleDragOver}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="group cursor-pointer border border-dashed border-slate-700/80 hover:border-cyan-500/80 bg-slate-950/60 rounded-xl p-5 text-center transition-all duration-150 flex flex-col items-center justify-center min-h-[220px]"
            >
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={handleFileUpload}
                className="hidden"
              />
              <div className="w-10 h-10 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 group-hover:text-cyan-400 transition-colors mb-3">
                <Upload className="w-5 h-5" />
              </div>
              <p className="text-xs font-semibold text-slate-200 mb-1">
                Drop your image here, or{" "}
                <span className="text-cyan-400 underline">browse</span>
              </p>
              <p className="text-[11px] text-slate-500">
                Supports PNG, JPEG, SVG, WebP (up to 50MB)
              </p>
            </div>

            {/* Selected Image Metadata Card */}
            {selectedImageSrc && (
              <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                <img
                  src={selectedImageSrc}
                  alt="Plaintext source"
                  referrerPolicy="no-referrer"
                  className="w-14 h-14 rounded-lg object-cover bg-slate-900 border border-slate-800 shrink-0"
                />
                <div className="min-w-0 flex-1 space-y-0.5">
                  <p className="text-xs font-semibold text-white truncate">
                    {imageMeta.name}
                  </p>
                  <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
                    <span>
                      {imageMeta.width}x{imageMeta.height} px
                    </span>
                    <span>·</span>
                    <span>{Math.round(imageMeta.sizeBytes / 1024)} KB</span>
                    <span>·</span>
                    <span>{imageMeta.mimeType}</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right: Cryptographic Configuration */}
          <div className="lg:col-span-6 space-y-4">
            <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3.5">
              {/* Recipient Public Key */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Recipient Public Key (KEM Target)
                </label>
                <select
                  value={recipientKeyId}
                  onChange={(e) => {
                    setRecipientKeyId(e.target.value);
                    const k = keyring.find((key) => key.id === e.target.value);
                    if (k) setKemAlgorithm(k.algorithm);
                  }}
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                >
                  {keyring.map((k) => (
                    <option key={k.id} value={k.id}>
                      {k.label} [{k.algorithm}]
                    </option>
                  ))}
                </select>
              </div>

              {/* DEM Cipher Selector & Engine */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    DEM Cipher (Bulk AEAD)
                  </label>
                  <select
                    value={demAlgorithm}
                    onChange={(e) =>
                      setDemAlgorithm(e.target.value as DemAlgorithm)
                    }
                    className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="AES-256-GCM">
                      AES-256-GCM (NIST SP 800-38D)
                    </option>
                    <option value="CHACHA20-POLY1305">
                      ChaCha20-Poly1305 (RFC 8439)
                    </option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Execution Engine
                  </label>
                  <select
                    value={engine}
                    onChange={(e) =>
                      setEngine(e.target.value as ExecutionEngine)
                    }
                    className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono"
                  >
                    <option value="NODEJS_BACKEND">
                      Node.js Express Server
                    </option>
                    <option value="BROWSER_WEBCRYPTO">
                      Browser Web Crypto API
                    </option>
                  </select>
                </div>
              </div>

              {/* Additional Authenticated Data (AAD) */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Additional Authenticated Data (AAD)
                </label>
                <input
                  type="text"
                  value={aadText}
                  onChange={(e) => setAadText(e.target.value)}
                  placeholder="Classification, owner, timestamp..."
                  className="w-full bg-slate-900 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono text-[11px]"
                />
                <p className="text-[10px] text-slate-500 mt-1">
                  AAD is authenticated under the DEM tag but transmitted
                  unencrypted.
                </p>
              </div>

              {/* Action Button */}
              <button
                onClick={handleExecuteEncryption}
                disabled={isEncrypting || !selectedImageSrc}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 active:bg-cyan-500 rounded-lg transition-colors disabled:opacity-50 cursor-pointer shadow-md shadow-cyan-500/20"
              >
                <Lock className="w-4 h-4" />
                <span>
                  {isEncrypting
                    ? "Encapsulating & Encrypting..."
                    : "Execute KEM-DEM Encryption"}
                </span>
              </button>

              {errorMessage && (
                <div className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-800 text-xs text-rose-300">
                  {errorMessage}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Output Results & Visual Noise Inspector */}
      {currentPackage && (
        <div className="border border-slate-800 bg-slate-900/40 rounded-2xl p-6 space-y-6 animate-fadeIn">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold">
              <CheckCircle className="w-4 h-4" />
              <span>KEM-DEM Container Package Generated</span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={downloadPackageJson}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                <span>Save .kemdem Package</span>
              </button>

              {keyring.find((key) => key.id === recipientKeyId)
                ?.privateKeyPem && (
                <button
                  onClick={downloadRecipientPrivateKey}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-200 text-xs border border-amber-500/30 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-amber-400" />
                  <span>Save matching private key</span>
                </button>
              )}

              <button
                onClick={onNavigateToDecrypt}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 text-xs border border-cyan-500/40 transition-colors"
              >
                <span>Go to Decryptor</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={onNavigateToTamper}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 text-xs border border-amber-500/40 transition-colors"
              >
                <span>Test in Tamper Lab</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <p className="text-xs text-amber-200/90">
            Keep the .kemdem package and matching private .pem key. The package
            does not contain the private key. Protect the .pem file and never
            share it.
          </p>

          {/* Side-by-Side: Original vs Ciphertext Visual Noise */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Original Card */}
            <div className="border border-slate-800/80 bg-slate-950/60 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-white">
                  Original Plaintext Image
                </span>
                <span className="font-mono text-slate-400">
                  Entropy: {currentPackage.metrics.originalEntropy} bits/byte
                </span>
              </div>
              <div className="flex items-center justify-center bg-slate-900/60 rounded-lg p-2 min-h-[240px]">
                <img
                  src={selectedImageSrc}
                  alt="Original preview"
                  referrerPolicy="no-referrer"
                  className="max-h-[220px] max-w-full rounded object-contain"
                />
              </div>
              <div className="font-mono text-[10px] text-slate-500 truncate">
                SHA-256: {currentPackage.sourceImage.originalSha256}
              </div>
            </div>

            {/* Ciphertext Visual Noise Card */}
            <div className="border border-slate-800/80 bg-slate-950/60 rounded-xl p-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-white">
                  Encrypted Ciphertext Noise
                </span>
                <span className="font-mono text-cyan-400 font-semibold">
                  Entropy: {currentPackage.metrics.encryptedEntropy} bits/byte
                  (Maximal)
                </span>
              </div>
              <div className="flex items-center justify-center bg-slate-900/60 rounded-lg p-2 min-h-[240px]">
                <canvas
                  ref={canvasRef}
                  className="max-h-[220px] max-w-full rounded shadow-inner"
                />
              </div>
              <div className="flex items-center justify-between font-mono text-[10px] text-slate-400">
                <span>
                  Payload:{" "}
                  {Math.round(
                    currentPackage.demPayload.ciphertext.length * 0.75,
                  )}{" "}
                  bytes
                </span>
                <span className="text-emerald-400">
                  Perfect Diffusion Achieved
                </span>
              </div>
            </div>
          </div>

          {/* Package Architecture Inspector */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 font-mono text-[11px] space-y-1">
              <span className="text-slate-500 uppercase block">
                KEM Header (c_kem)
              </span>
              <p className="text-cyan-300 truncate">
                {currentPackage.kemHeader.c_kem}
              </p>
              <span className="text-[10px] text-slate-500 block">
                Algorithm: {currentPackage.kemHeader.algorithm} (
                {currentPackage.metrics.encapsulationTimeMs} ms)
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 font-mono text-[11px] space-y-1">
              <span className="text-slate-500 uppercase block">
                DEM Nonce & 128-bit Tag
              </span>
              <p className="text-blue-300 truncate">
                IV: {currentPackage.demPayload.iv} | Tag:{" "}
                {currentPackage.demPayload.tag}
              </p>
              <span className="text-[10px] text-slate-500 block">
                Algorithm: {currentPackage.demPayload.algorithm} (
                {currentPackage.metrics.encryptionTimeMs} ms)
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 font-mono text-[11px] space-y-1">
              <span className="text-slate-500 uppercase block">
                Total Pipeline Latency
              </span>
              <p className="text-emerald-400 font-bold">
                {currentPackage.metrics.totalPipelineTimeMs} ms
              </p>
              <span className="text-[10px] text-slate-500 block">
                Recipient Fingerprint:{" "}
                {currentPackage.kemHeader.recipientFingerprint?.substring(
                  0,
                  10,
                )}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
