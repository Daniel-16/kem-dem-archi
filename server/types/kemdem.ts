export type KemAlgorithm =
  | 'RSA-OAEP-2048'
  | 'RSA-OAEP-3072'
  | 'RSA-OAEP-4096'
  | 'ECDH-P256'
  | 'ECDH-P384'
  | 'ECDH-X25519'
  | 'HYBRID-PQ';

export type DemAlgorithm =
  | 'AES-256-GCM'
  | 'CHACHA20-POLY1305';

export interface KemKeyPair {
  id: string;
  label: string;
  algorithm: KemAlgorithm;
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
  createdAt: number;
  keyDetails: {
    modulusLength?: number;
    namedCurve?: string;
    description: string;
  };
}

export interface KemEncapsulationResult {
  symmetricKey: Buffer; // Shared secret 256-bit key
  c_kem: string;        // Base64 encoded encapsulated key
  ephemeralPublicKey?: string; // For ECDH schemes
  salt?: string;        // For HKDF schemes
  algorithm: KemAlgorithm;
  encapsulationTimeMs: number;
}

export interface DemEncryptionResult {
  ciphertext: string;   // Base64 encoded ciphertext
  iv: string;           // Base64 encoded 12-byte IV / Nonce
  tag: string;          // Base64 encoded 16-byte authentication tag
  algorithm: DemAlgorithm;
  aad?: string;         // Additional authenticated data
  encryptionTimeMs: number;
  originalSizeBytes: number;
  cipherSizeBytes: number;
}

export interface KemDemPackage {
  format: 'KEM-DEM-V1';
  id: string;
  timestamp: number;
  sourceImage: {
    name: string;
    mimeType: string;
    width: number;
    height: number;
    originalSha256: string;
    originalSizeBytes: number;
  };
  kemHeader: {
    algorithm: KemAlgorithm;
    c_kem: string;
    ephemeralPublicKey?: string;
    salt?: string;
    recipientFingerprint?: string;
  };
  demPayload: {
    algorithm: DemAlgorithm;
    iv: string;
    tag: string;
    ciphertext: string;
    aad?: string;
  };
  metrics: {
    encapsulationTimeMs: number;
    encryptionTimeMs: number;
    totalPipelineTimeMs: number;
    originalEntropy: number;
    encryptedEntropy: number;
  };
}

export interface DecryptionResult {
  success: boolean;
  decryptedDataUrl: string;
  decryptedSha256: string;
  isLosslessMatch: boolean;
  decapsulationTimeMs: number;
  decryptionTimeMs: number;
  totalDecryptionTimeMs: number;
  entropy: number;
  error?: string;
  errorPhase?: 'KEM_DECAPSULATION' | 'DEM_DECRYPTION' | 'INTEGRITY_VERIFICATION';
}

export interface EntropyAnalysis {
  entropy: number;
  byteCount: number;
  histogram: {
    red: number[];
    green: number[];
    blue: number[];
    overall: number[];
  };
  isTheoreticalNoise: boolean;
}

export interface SampleImage {
  id: string;
  name: string;
  description: string;
  category: string;
  dataUrl: string;
  width: number;
  height: number;
}
