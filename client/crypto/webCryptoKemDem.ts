import type {
  KemAlgorithm,
  DemAlgorithm,
  KemDemPackage,
  DecryptionResult,
} from '../types/crypto.js';

// Convert PEM to binary Uint8Array
function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64Lines = pem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
  const b64 = atob(b64Lines);
  const buf = new Uint8Array(b64.length);
  for (let i = 0; i < b64.length; i++) {
    buf[i] = b64.charCodeAt(i);
  }
  return buf.buffer;
}

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Convert Base64 to Uint8Array
function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Compute SHA-256 hex string via Web Crypto
export async function computeBrowserSha256(buffer: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer as unknown as BufferSource);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Compute Shannon entropy in browser
export function computeBrowserEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    counts[bytes[i]]++;
  }
  let entropy = 0;
  const total = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / total;
      entropy -= p * Math.log2(p);
    }
  }
  return Math.round(entropy * 1000) / 1000;
}

// Client-side KEM-DEM Image Encryptor
export async function encryptImageWithWebCrypto(params: {
  imageBytes: Uint8Array;
  imageName: string;
  mimeType: string;
  width: number;
  height: number;
  recipientPublicKeyPem: string;
  kemAlgorithm: KemAlgorithm;
  demAlgorithm: DemAlgorithm;
  aad?: string;
}): Promise<{ package: KemDemPackage; noiseRgbaBase64: string }> {
  const startPipeline = performance.now();

  const originalSha256 = await computeBrowserSha256(params.imageBytes);
  const originalEntropy = computeBrowserEntropy(params.imageBytes);

  // KEM STAGE
  const startKem = performance.now();
  // 1. Generate random 256-bit symmetric session key K
  const rawSessionKey = crypto.getRandomValues(new Uint8Array(32));

  // 2. Import recipient public key
  const spkiBuffer = pemToArrayBuffer(params.recipientPublicKeyPem);
  const rsaPublicKey = await crypto.subtle.importKey(
    'spki',
    spkiBuffer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt']
  );

  // 3. Encapsulate session key
  const encapsulatedKeyBuffer = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    rsaPublicKey,
    rawSessionKey
  );
  const c_kem = arrayBufferToBase64(encapsulatedKeyBuffer);
  const endKem = performance.now();
  const encapsulationTimeMs = Math.round((endKem - startKem) * 100) / 100;

  // DEM STAGE
  const startDem = performance.now();
  // 1. Import symmetric session key into AES-GCM
  const aesKey = await crypto.subtle.importKey(
    'raw',
    rawSessionKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // 2. Generate 96-bit IV
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // 3. Optional Additional Authenticated Data (AAD)
  const additionalData = params.aad ? new TextEncoder().encode(params.aad) : undefined;

  // 4. Encrypt image buffer with AES-256-GCM
  // Note: Web Crypto AES-GCM appends 16-byte authentication tag to the end of ciphertext
  const encryptedCombinedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
      additionalData,
      tagLength: 128,
    },
    aesKey,
    params.imageBytes as unknown as BufferSource
  );

  const encryptedCombinedBytes = new Uint8Array(encryptedCombinedBuffer);
  // Separate ciphertext and 16-byte tag
  const tagLength = 16;
  const ciphertextBytes = encryptedCombinedBytes.slice(0, encryptedCombinedBytes.length - tagLength);
  const tagBytes = encryptedCombinedBytes.slice(encryptedCombinedBytes.length - tagLength);

  const endDem = performance.now();
  const encryptionTimeMs = Math.round((endDem - startDem) * 100) / 100;

  const totalPipelineTimeMs = Math.round((performance.now() - startPipeline) * 100) / 100;
  const encryptedEntropy = computeBrowserEntropy(ciphertextBytes);

  // Generate visual noise
  const pixelCount = Math.min(params.width * params.height, 160000);
  const noiseRgba = new Uint8Array(pixelCount * 4);
  for (let i = 0; i < pixelCount; i++) {
    const idx = (i * 3) % ciphertextBytes.length;
    noiseRgba[i * 4] = ciphertextBytes[idx];
    noiseRgba[i * 4 + 1] = ciphertextBytes[(idx + 1) % ciphertextBytes.length];
    noiseRgba[i * 4 + 2] = ciphertextBytes[(idx + 2) % ciphertextBytes.length];
    noiseRgba[i * 4 + 3] = 255;
  }

  const pkg: KemDemPackage = {
    format: 'KEM-DEM-V1',
    id: `pkg_web_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    timestamp: Date.now(),
    sourceImage: {
      name: params.imageName,
      mimeType: params.mimeType,
      width: params.width,
      height: params.height,
      originalSha256,
      originalSizeBytes: params.imageBytes.byteLength,
    },
    kemHeader: {
      algorithm: params.kemAlgorithm,
      c_kem,
    },
    demPayload: {
      algorithm: params.demAlgorithm,
      iv: arrayBufferToBase64(iv.buffer),
      tag: arrayBufferToBase64(tagBytes.buffer),
      ciphertext: arrayBufferToBase64(ciphertextBytes.buffer),
      aad: params.aad,
    },
    metrics: {
      encapsulationTimeMs,
      encryptionTimeMs,
      totalPipelineTimeMs,
      originalEntropy,
      encryptedEntropy,
    },
  };

  return {
    package: pkg,
    noiseRgbaBase64: arrayBufferToBase64(noiseRgba.buffer),
  };
}

// Client-side KEM-DEM Image Decryptor
export async function decryptImageWithWebCrypto(params: {
  package: KemDemPackage;
  recipientPrivateKeyPem: string;
}): Promise<DecryptionResult> {
  const startPipeline = performance.now();

  try {
    // 1. KEM Decapsulation
    const startKem = performance.now();
    const pkcs8Buffer = pemToArrayBuffer(params.recipientPrivateKeyPem);
    const rsaPrivateKey = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8Buffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      false,
      ['decrypt']
    );

    const cKemBytes = base64ToUint8Array(params.package.kemHeader.c_kem);
    const rawSessionKeyBuffer = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      rsaPrivateKey,
      cKemBytes as unknown as BufferSource
    );
    const endKem = performance.now();
    const decapsulationTimeMs = Math.round((endKem - startKem) * 100) / 100;

    // 2. DEM Decryption
    const startDem = performance.now();
    const aesKey = await crypto.subtle.importKey(
      'raw',
      rawSessionKeyBuffer,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const iv = base64ToUint8Array(params.package.demPayload.iv);
    const ciphertext = base64ToUint8Array(params.package.demPayload.ciphertext);
    const tag = base64ToUint8Array(params.package.demPayload.tag);

    // Recombine ciphertext + tag for Web Crypto AES-GCM
    const combinedEncrypted = new Uint8Array(ciphertext.length + tag.length);
    combinedEncrypted.set(ciphertext, 0);
    combinedEncrypted.set(tag, ciphertext.length);

    const additionalData = params.package.demPayload.aad
      ? new TextEncoder().encode(params.package.demPayload.aad)
      : undefined;

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv as unknown as BufferSource,
        additionalData,
        tagLength: 128,
      },
      aesKey,
      combinedEncrypted as unknown as BufferSource
    );

    const endDem = performance.now();
    const decryptionTimeMs = Math.round((endDem - startDem) * 100) / 100;

    const decryptedBytes = new Uint8Array(decryptedBuffer);
    const decryptedSha256 = await computeBrowserSha256(decryptedBytes);
    const isLosslessMatch = decryptedSha256 === params.package.sourceImage.originalSha256;
    const entropy = computeBrowserEntropy(decryptedBytes);

    const mime = params.package.sourceImage.mimeType || 'image/png';
    const decryptedDataUrl = `data:${mime};base64,${arrayBufferToBase64(decryptedBuffer)}`;

    return {
      success: true,
      decryptedDataUrl,
      decryptedSha256,
      isLosslessMatch,
      decapsulationTimeMs,
      decryptionTimeMs,
      totalDecryptionTimeMs: Math.round((performance.now() - startPipeline) * 100) / 100,
      entropy,
    };
  } catch (err: any) {
    return {
      success: false,
      decryptedDataUrl: '',
      decryptedSha256: '',
      isLosslessMatch: false,
      decapsulationTimeMs: 0,
      decryptionTimeMs: 0,
      totalDecryptionTimeMs: 0,
      entropy: 0,
      error: `Web Crypto Decryption Failed: ${err.message || 'Tag verification error or corrupted key'}`,
      errorPhase: 'DEM_DECRYPTION',
    };
  }
}
