import {
  Buffer,
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPair,
  generateKeyPairSync,
  hkdfSync,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
} from 'react-native-quick-crypto';
import type {
  DemAlgorithm,
  DecryptionResult,
  EntropyAnalysis,
  KemAlgorithm,
  KemDemPackage,
  KemKeyPair,
  TamperTarget,
  TamperTestResult,
} from '../types';

type ByteHistogram = EntropyAnalysis['histogram'];

function elapsedMilliseconds(start: number): number {
  return Math.round((performance.now() - start) * 100) / 100;
}

function randomHex(bytes: number): string {
  return randomBytes(bytes).toString('hex');
}

export function calculateBufferEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;

  const frequencies = new Array<number>(256).fill(0);
  for (const byte of bytes) frequencies[byte]++;

  let entropy = 0;
  for (const frequency of frequencies) {
    if (frequency > 0) {
      const probability = frequency / bytes.length;
      entropy -= probability * Math.log2(probability);
    }
  }
  return Math.round(entropy * 1000) / 1000;
}

export function generateHistogram(bytes: Uint8Array): ByteHistogram {
  const overall = new Array<number>(256).fill(0);
  const red = new Array<number>(256).fill(0);
  const green = new Array<number>(256).fill(0);
  const blue = new Array<number>(256).fill(0);
  const sampleLimit = Math.min(bytes.length, 200_000);

  for (let i = 0; i < sampleLimit; i++) {
    const value = bytes[i];
    overall[value]++;
    if (i % 3 === 0) red[value]++;
    else if (i % 3 === 1) green[value]++;
    else blue[value]++;
  }
  return { red, green, blue, overall };
}

export function performEntropyAnalysis(bytes: Uint8Array): EntropyAnalysis {
  const entropy = calculateBufferEntropy(bytes);
  return {
    entropy,
    byteCount: bytes.length,
    histogram: generateHistogram(bytes),
    isTheoreticalNoise: entropy >= 7.95,
  };
}

export function fingerprint(publicKeyPem: string): string {
  const body = publicKeyPem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
  return createHash('sha256')
    .update(Buffer.from(body, 'base64'))
    .digest('hex')
    .slice(0, 16);
}

export function validateKemKeyPair(keyPair: KemKeyPair): boolean {
  try {
    const encapsulated = encapsulateKey(keyPair.algorithm, keyPair.publicKeyPem);
    if (!keyPair.privateKeyPem) return true;
    const recovered =
      keyPair.algorithm.startsWith('RSA-OAEP-')
        ? privateDecrypt(
            {
              key: keyPair.privateKeyPem,
              padding: constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: 'sha256',
            },
            Buffer.from(encapsulated.c_kem, 'base64'),
          )
        : deriveSharedKey(
            keyPair.privateKeyPem,
            encapsulated.ephemeralPublicKey ?? '',
            keyPair.algorithm,
            Buffer.from(encapsulated.salt ?? '', 'base64'),
          );
    return recovered.equals(encapsulated.symmetricKey);
  } catch {
    return false;
  }
}

function generatePair(
  type: 'rsa' | 'ec' | 'x25519',
  options: { modulusLength?: number; namedCurve?: string },
): Promise<{ publicKeyPem: string; privateKeyPem: string }> {
  return new Promise((resolve, reject) => {
    generateKeyPair(
      type,
      {
        ...options,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (error, publicKey, privateKey) => {
        if (error) {
          reject(error);
          return;
        }
        if (typeof publicKey !== 'string' || typeof privateKey !== 'string') {
          reject(new Error('The device crypto provider returned an invalid key pair.'));
          return;
        }
        resolve({ publicKeyPem: publicKey, privateKeyPem: privateKey });
      },
    );
  });
}

export async function generateKemKeyPair(
  algorithm: KemAlgorithm,
  label?: string,
): Promise<KemKeyPair> {
  let pair: { publicKeyPem: string; privateKeyPem: string };
  let keyDetails: KemKeyPair['keyDetails'];

  if (algorithm.startsWith('RSA-OAEP-')) {
    const modulusLength = Number(algorithm.slice('RSA-OAEP-'.length));
    pair = await generatePair('rsa', { modulusLength });
    keyDetails = {
      modulusLength,
      description: `RSA ${modulusLength}-bit key with OAEP padding (SHA-256)`,
    };
  } else {
    const namedCurve =
      algorithm === 'ECDH-P256'
        ? 'prime256v1'
        : algorithm === 'ECDH-P384'
          ? 'secp384r1'
          : undefined;
    pair = await generatePair(namedCurve ? 'ec' : 'x25519', { namedCurve });
    keyDetails = {
      ...(namedCurve ? { namedCurve } : { namedCurve: 'Curve25519' }),
      description:
        algorithm === 'ECDH-X25519'
          ? 'X25519 Diffie-Hellman with HKDF-SHA256'
          : `ECDH ${namedCurve === 'prime256v1' ? 'NIST P-256' : 'NIST P-384'} with HKDF-SHA256`,
    };
  }

  const keyFingerprint = fingerprint(pair.publicKeyPem);
  return {
    id: `key_${Date.now()}_${randomHex(4)}`,
    label: label?.trim() || `${algorithm} Key (${keyFingerprint.slice(0, 8)})`,
    algorithm,
    ...pair,
    fingerprint: keyFingerprint,
    createdAt: Date.now(),
    keyDetails,
  };
}

function deriveSharedKey(
  privateKeyPem: string,
  publicKeyPem: string,
  algorithm: KemAlgorithm,
  salt: Buffer,
): Buffer {
  const sharedSecret = diffieHellman({
    privateKey: createPrivateKey(privateKeyPem),
    publicKey: createPublicKey(publicKeyPem),
  });
  if (!sharedSecret) throw new Error('The device crypto provider did not derive a shared secret.');
  return Buffer.from(
    hkdfSync(
      'sha256',
      sharedSecret,
      salt,
      Buffer.from(`KEM-DEM-${algorithm}`, 'utf8'),
      32,
    ),
  );
}

interface EncapsulatedKey {
  symmetricKey: Buffer;
  c_kem: string;
  ephemeralPublicKey?: string;
  salt?: string;
  elapsedMs: number;
}

function encapsulateKey(algorithm: KemAlgorithm, publicKeyPem: string): EncapsulatedKey {
  const start = performance.now();
  if (algorithm.startsWith('RSA-OAEP-')) {
    const symmetricKey = randomBytes(32);
    const encryptedKey = publicEncrypt(
      {
        key: publicKeyPem,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      symmetricKey,
    );
    return {
      symmetricKey,
      c_kem: encryptedKey.toString('base64'),
      elapsedMs: elapsedMilliseconds(start),
    };
  }

  const namedCurve =
    algorithm === 'ECDH-P256'
      ? 'prime256v1'
      : algorithm === 'ECDH-P384'
        ? 'secp384r1'
        : undefined;
  const ephemeral = generateKeyPairSync(
    namedCurve ? 'ec' : 'x25519',
    namedCurve ? { namedCurve } : {},
  );
  const ephemeralPublicKey = ephemeral.publicKey.export({
    type: 'spki',
    format: 'pem',
  }) as string;
  const ephemeralPrivateKey = ephemeral.privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  }) as string;
  const salt = randomBytes(16);

  return {
    symmetricKey: deriveSharedKey(
      ephemeralPrivateKey,
      publicKeyPem,
      algorithm,
      salt,
    ),
    c_kem: Buffer.from(ephemeralPublicKey, 'utf8').toString('base64'),
    ephemeralPublicKey,
    salt: salt.toString('base64'),
    elapsedMs: elapsedMilliseconds(start),
  };
}

function encryptPayload(
  algorithm: DemAlgorithm,
  symmetricKey: Buffer,
  plaintext: Buffer,
  aad?: string,
): { ciphertext: string; iv: string; tag: string; elapsedMs: number } {
  const start = performance.now();
  const iv = randomBytes(12);
  const cipher = createCipheriv(
    algorithm === 'AES-256-GCM' ? 'aes-256-gcm' : 'chacha20-poly1305',
    symmetricKey,
    iv,
    algorithm === 'CHACHA20-POLY1305' ? { authTagLength: 16 } : undefined,
  );
  if (aad) {
    cipher.setAAD(
      Buffer.from(aad, 'utf8'),
      algorithm === 'CHACHA20-POLY1305'
        ? { plaintextLength: plaintext.length }
        : undefined,
    );
  }
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    elapsedMs: elapsedMilliseconds(start),
  };
}

function decryptPayload(
  algorithm: DemAlgorithm,
  symmetricKey: Buffer,
  ciphertextBase64: string,
  ivBase64: string,
  tagBase64: string,
  aad?: string,
): { plaintext: Buffer; elapsedMs: number } {
  const start = performance.now();
  try {
    const ciphertext = Buffer.from(ciphertextBase64, 'base64');
    const decipher = createDecipheriv(
      algorithm === 'AES-256-GCM' ? 'aes-256-gcm' : 'chacha20-poly1305',
      symmetricKey,
      Buffer.from(ivBase64, 'base64'),
      algorithm === 'CHACHA20-POLY1305' ? { authTagLength: 16 } : undefined,
    );
    decipher.setAuthTag(Buffer.from(tagBase64, 'base64'));
    if (aad) {
      decipher.setAAD(
        Buffer.from(aad, 'utf8'),
        algorithm === 'CHACHA20-POLY1305'
          ? { plaintextLength: ciphertext.length }
          : undefined,
      );
    }
    return {
      plaintext: Buffer.concat([decipher.update(ciphertext), decipher.final()]),
      elapsedMs: elapsedMilliseconds(start),
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Authentication tag mismatch.';
    throw new Error(`DEM decryption failed (integrity verification failed): ${message}`);
  }
}

export function encryptImageOffline(params: {
  imageBase64: string;
  imageName: string;
  mimeType: string;
  width: number;
  height: number;
  recipient: KemKeyPair;
  demAlgorithm: DemAlgorithm;
  aad: string;
}): KemDemPackage {
  const startedAt = performance.now();
  const imageBytes = Buffer.from(params.imageBase64, 'base64');
  if (imageBytes.length === 0) throw new Error('The selected image is empty.');

  const originalSha256 = createHash('sha256').update(imageBytes).digest('hex');
  const originalEntropy = calculateBufferEntropy(imageBytes);
  const kem = encapsulateKey(params.recipient.algorithm, params.recipient.publicKeyPem);
  const dem = encryptPayload(params.demAlgorithm, kem.symmetricKey, imageBytes, params.aad);
  const encryptedBytes = Buffer.from(dem.ciphertext, 'base64');

  return {
    format: 'KEM-DEM-V1',
    id: `pkg_${Date.now()}_${randomHex(4)}`,
    timestamp: Date.now(),
    sourceImage: {
      name: params.imageName,
      mimeType: params.mimeType || 'image/jpeg',
      width: params.width,
      height: params.height,
      originalSha256,
      originalSizeBytes: imageBytes.length,
    },
    kemHeader: {
      algorithm: params.recipient.algorithm,
      c_kem: kem.c_kem,
      ephemeralPublicKey: kem.ephemeralPublicKey,
      salt: kem.salt,
      recipientFingerprint: params.recipient.fingerprint,
    },
    demPayload: {
      algorithm: params.demAlgorithm,
      iv: dem.iv,
      tag: dem.tag,
      ciphertext: dem.ciphertext,
      aad: params.aad,
    },
    metrics: {
      encapsulationTimeMs: kem.elapsedMs,
      encryptionTimeMs: dem.elapsedMs,
      totalPipelineTimeMs: elapsedMilliseconds(startedAt),
      originalEntropy,
      encryptedEntropy: calculateBufferEntropy(encryptedBytes),
    },
  };
}

export function decryptImageOffline(
  kemDemPackage: KemDemPackage,
  privateKeyPem: string,
): DecryptionResult {
  const startedAt = performance.now();
  const kemStartedAt = performance.now();
  let symmetricKey: Buffer;
  try {
    if (kemDemPackage.kemHeader.algorithm.startsWith('RSA-OAEP-')) {
      symmetricKey = privateDecrypt(
        {
          key: privateKeyPem,
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        Buffer.from(kemDemPackage.kemHeader.c_kem, 'base64'),
      );
    } else {
      const ephemeralPublicKey =
        kemDemPackage.kemHeader.ephemeralPublicKey ||
        Buffer.from(kemDemPackage.kemHeader.c_kem, 'base64').toString('utf8');
      const salt = kemDemPackage.kemHeader.salt
        ? Buffer.from(kemDemPackage.kemHeader.salt, 'base64')
        : Buffer.alloc(16);
      symmetricKey = deriveSharedKey(
        privateKeyPem,
        ephemeralPublicKey,
        kemDemPackage.kemHeader.algorithm,
        salt,
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Invalid private key or KEM header.';
    throw new Error(`KEM decapsulation failed: ${message}`);
  }
  const decapsulationTimeMs = elapsedMilliseconds(kemStartedAt);

  const dem = decryptPayload(
    kemDemPackage.demPayload.algorithm,
    symmetricKey,
    kemDemPackage.demPayload.ciphertext,
    kemDemPackage.demPayload.iv,
    kemDemPackage.demPayload.tag,
    kemDemPackage.demPayload.aad,
  );
  const decryptedSha256 = createHash('sha256').update(dem.plaintext).digest('hex');
  return {
    success: true,
    decryptedBase64: dem.plaintext.toString('base64'),
    decryptedSha256,
    isLosslessMatch: decryptedSha256 === kemDemPackage.sourceImage.originalSha256,
    decapsulationTimeMs,
    decryptionTimeMs: dem.elapsedMs,
    totalDecryptionTimeMs: elapsedMilliseconds(startedAt),
    entropy: calculateBufferEntropy(dem.plaintext),
  };
}

function flipBase64Bit(value: string, preferredIndex: number): string {
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0) throw new Error('Cannot tamper with an empty package field.');
  bytes[Math.min(preferredIndex, bytes.length - 1)] ^= 1;
  return bytes.toString('base64');
}

export function runTamperTest(
  originalPackage: KemDemPackage,
  recipientPrivateKeyPem: string,
  tamperTarget: TamperTarget,
): TamperTestResult {
  const tampered = JSON.parse(JSON.stringify(originalPackage)) as KemDemPackage;
  const descriptions: Record<TamperTarget, string> = {
    KEM_HEADER: 'Flipped one bit in the encapsulated key header.',
    CIPHERTEXT: 'Flipped one bit in the encrypted image payload.',
    IV: 'Flipped one bit in the initialization vector.',
    TAG: 'Flipped one bit in the authentication tag.',
    AAD: 'Modified authenticated additional data.',
  };

  switch (tamperTarget) {
    case 'KEM_HEADER':
      tampered.kemHeader.c_kem = flipBase64Bit(tampered.kemHeader.c_kem, 10);
      if (tampered.kemHeader.ephemeralPublicKey) {
        tampered.kemHeader.ephemeralPublicKey = Buffer.from(
          tampered.kemHeader.c_kem,
          'base64',
        ).toString('utf8');
      }
      break;
    case 'CIPHERTEXT':
      tampered.demPayload.ciphertext = flipBase64Bit(tampered.demPayload.ciphertext, 12);
      break;
    case 'IV':
      tampered.demPayload.iv = flipBase64Bit(tampered.demPayload.iv, 2);
      break;
    case 'TAG':
      tampered.demPayload.tag = flipBase64Bit(tampered.demPayload.tag, 4);
      break;
    case 'AAD':
      tampered.demPayload.aad = `${tampered.demPayload.aad ?? ''}_TAMPERED`;
      break;
  }

  let failedPhase = '';
  let errorMessage = '';
  try {
    decryptImageOffline(tampered, recipientPrivateKeyPem);
  } catch (error) {
    errorMessage = error instanceof Error ? error.message : 'Tampering was rejected.';
    failedPhase = errorMessage.startsWith('KEM decapsulation')
      ? 'KEM_DECAPSULATION'
      : 'DEM_DECRYPTION_AEAD';
  }

  return {
    success: true,
    tamperTarget,
    tamperDescription: descriptions[tamperTarget],
    failedPhase,
    errorMessage,
    attackNeutralized: Boolean(failedPhase),
    cryptographicGuarantee: failedPhase.startsWith('KEM')
      ? 'KEM decapsulation rejected the modified encapsulated key.'
      : 'AEAD verification rejected the modified ciphertext or metadata before returning plaintext.',
  };
}
