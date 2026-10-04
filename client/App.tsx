import React, { useState, useEffect } from "react";
import { Header } from "./components/Header.js";
import { ImageEncryptor } from "./components/ImageEncryptor.js";
import { ImageDecryptor } from "./components/ImageDecryptor.js";
import { KeyManager } from "./components/KeyManager.js";
import { EntropyInspector } from "./components/EntropyInspector.js";
import type { KemKeyPair, KemDemPackage, SampleImage } from "./types/crypto.js";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"encrypt" | "decrypt" | "keyring">(
    "encrypt",
  );

  const [keyring, setKeyring] = useState<KemKeyPair[]>([]);
  const [activeRecipientKeyId, setActiveRecipientKeyId] = useState<string>("");
  const [samples, setSamples] = useState<SampleImage[]>([]);
  const [currentPackage, setCurrentPackage] = useState<KemDemPackage | null>(
    null,
  );

  // Initialize samples and generate a default key pair on first launch
  useEffect(() => {
    // 1. Fetch pre-packaged sample images from server
    fetch("/api/kem-dem/samples")
      .then((res) => res.json())
      .then((data) => {
        if (data.success && data.samples) {
          setSamples(data.samples);
        }
      })
      .catch((err) => console.error("Failed to load samples", err));

    // 2. Generate a default RSA-OAEP demo key pair so the app is instantly ready
    fetch("/api/kem-dem/keygen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        algorithm: "RSA-OAEP-2048",
        label: "Default Recipient Key (RSA-OAEP-2048)",
      }),
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.success && data.keyPair) {
          setKeyring([data.keyPair]);
          setActiveRecipientKeyId(data.keyPair.id);
        }
      })
      .catch((err) => console.error("Failed to generate initial key", err));
  }, []);

  const handleAddKey = (newKey: KemKeyPair) => {
    setKeyring((prev) => [newKey, ...prev]);
  };

  const handleRemoveKey = (id: string) => {
    setKeyring((prev) => prev.filter((k) => k.id !== id));
    if (activeRecipientKeyId === id && keyring.length > 1) {
      const remaining = keyring.filter((k) => k.id !== id);
      setActiveRecipientKeyId(remaining[0].id);
    }
  };

  const handlePackageGenerated = (pkg: KemDemPackage) => {
    setCurrentPackage(pkg);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Universal Top Bar */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        keyCount={keyring.length}
        hasActivePackage={Boolean(currentPackage)}
      />

      {/* Main Workspace Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 lg:px-8 py-6 space-y-8">
        {activeTab === "encrypt" && (
          <div className="space-y-6">
            <ImageEncryptor
              keyring={keyring}
              activeRecipientKeyId={activeRecipientKeyId}
              samples={samples}
              onPackageGenerated={handlePackageGenerated}
              onNavigateToDecrypt={() => setActiveTab("decrypt")}
            />
            {currentPackage && (
              <EntropyInspector currentPackage={currentPackage} />
            )}
          </div>
        )}

        {activeTab === "decrypt" && (
          <ImageDecryptor keyring={keyring} activePackage={currentPackage} />
        )}

        {activeTab === "keyring" && (
          <KeyManager
            keyring={keyring}
            activeRecipientKeyId={activeRecipientKeyId}
            setActiveRecipientKeyId={setActiveRecipientKeyId}
            onAddKey={handleAddKey}
            onRemoveKey={handleRemoveKey}
          />
        )}
      </main>

      {/* Minimal Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-6 px-4 lg:px-8 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <span>KEM-DEM Image Cryptosystem</span>
          <div className="flex items-center gap-4 text-slate-400">
            <span>ISO/IEC 18033-2</span>
            <span>·</span>
            <span>NIST SP 800-38D (AES-GCM)</span>
            <span>·</span>
            <span>RFC 8439 (ChaCha20-Poly1305)</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
