import express, { Router, Request, Response } from 'express';
import crypto from 'node:crypto';
import {
  generateKemKeyPair,
  encapsulateKey,
  decapsulateKey,
  computeSha256Fingerprint,
} from '../crypto/kem.js';
import { encryptPayload, decryptPayload } from '../crypto/dem.js';
import { performEntropyAnalysis, calculateBufferEntropy } from '../crypto/entropy.js';
import { SAMPLE_IMAGES } from '../crypto/samples.js';
import type {
  KemAlgorithm,
  DemAlgorithm,
  KemDemPackage,
  DecryptionResult,
} from '../types/kemdem.js';

const router = Router();

function extractBufferFromDataUrl(dataUrl: string): Buffer {
  if (dataUrl.includes('base64,')) {
    const base64Data = dataUrl.split('base64,')[1];
    return Buffer.from(base64Data, 'base64');
  }
  return Buffer.from(dataUrl, 'utf8');
}

function generateNoiseDataUrlFromCiphertext(cipherBuffer: Buffer, width: number, height: number): string {
  const pixelCount = Math.min(width * height, 160000);
  const rgbaBuffer = Buffer.alloc(pixelCount * 4);

  for (let i = 0; i < pixelCount; i++) {
    const byteIndex = (i * 3) % cipherBuffer.length;
    rgbaBuffer[i * 4] = cipherBuffer[byteIndex];
    rgbaBuffer[i * 4 + 1] = cipherBuffer[(byteIndex + 1) % cipherBuffer.length];
    rgbaBuffer[i * 4 + 2] = cipherBuffer[(byteIndex + 2) % cipherBuffer.length];
    rgbaBuffer[i * 4 + 3] = 255;
  }

  return `data:application/octet-stream;base64,${rgbaBuffer.toString('base64')}`;
}

router.post('/kem-dem/keygen', (req: Request, res: Response) => {
  try {
    const { algorithm = 'RSA-OAEP-2048', label } = req.body as {
      algorithm: KemAlgorithm;
      label?: string;
    };

    const keyPair = generateKemKeyPair(algorithm, label);
    res.json({ success: true, keyPair });
  } catch (error: any) {
    res.status(400).json({ success: false, error: error.message });
  }
});

router.post('/kem-dem/encrypt', (req: Request, res: Response) => {
  const pipelineStart = performance.now();
  try {
    const {
      imageData,
      imageName = 'encrypted_image.png',
      mimeType = 'image/png',
      width = 400,
      height = 400,
      recipientPublicKeyPem,
      kemAlgorithm = 'RSA-OAEP-2048',
      demAlgorithm = 'AES-256-GCM',
      aad = '',
    } = req.body as {
      imageData: string;
      imageName?: string;
      mimeType?: string;
      width?: number;
      height?: number;
      recipientPublicKeyPem: string;
      kemAlgorithm: KemAlgorithm;
      demAlgorithm: DemAlgorithm;
      aad?: string;
    };

    if (!imageData) {
      return res.status(400).json({ success: false, error: 'Missing imageData' });
    }
    if (!recipientPublicKeyPem) {
      return res.status(400).json({ success: false, error: 'Missing recipientPublicKeyPem' });
    }

    const imageBuffer = extractBufferFromDataUrl(imageData);
    const originalSha256 = crypto.createHash('sha256').update(imageBuffer).digest('hex');
    const originalEntropy = calculateBufferEntropy(imageBuffer);

    const kemResult = encapsulateKey(kemAlgorithm, recipientPublicKeyPem);

    const demResult = encryptPayload(demAlgorithm, kemResult.symmetricKey, imageBuffer, aad);

    const ciphertextBuffer = Buffer.from(demResult.ciphertext, 'base64');
    const encryptedEntropy = calculateBufferEntropy(ciphertextBuffer);

    const pipelineEnd = performance.now();
    const totalPipelineTimeMs = Math.round((pipelineEnd - pipelineStart) * 100) / 100;

    const recipientFingerprint = computeSha256Fingerprint(recipientPublicKeyPem);

    const kemDemPackage: KemDemPackage = {
      format: 'KEM-DEM-V1',
      id: `pkg_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
      timestamp: Date.now(),
      sourceImage: {
        name: imageName,
        mimeType,
        width,
        height,
        originalSha256,
        originalSizeBytes: imageBuffer.length,
      },
      kemHeader: {
        algorithm: kemAlgorithm,
        c_kem: kemResult.c_kem,
        ephemeralPublicKey: kemResult.ephemeralPublicKey,
        salt: kemResult.salt,
        recipientFingerprint,
      },
      demPayload: {
        algorithm: demAlgorithm,
        iv: demResult.iv,
        tag: demResult.tag,
        ciphertext: demResult.ciphertext,
        aad: demResult.aad,
      },
      metrics: {
        encapsulationTimeMs: kemResult.encapsulationTimeMs,
        encryptionTimeMs: demResult.encryptionTimeMs,
        totalPipelineTimeMs,
        originalEntropy,
        encryptedEntropy,
      },
    };

    const noiseData = generateNoiseDataUrlFromCiphertext(ciphertextBuffer, width, height);

    res.json({
      success: true,
      package: kemDemPackage,
      noiseData,
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/kem-dem/decrypt', (req: Request, res: Response) => {
  const pipelineStart = performance.now();
  try {
    const { package: kemDemPackage, recipientPrivateKeyPem } = req.body as {
      package: KemDemPackage;
      recipientPrivateKeyPem: string;
    };

    if (!kemDemPackage) {
      return res.status(400).json({ success: false, error: 'Missing KEM-DEM package' });
    }
    if (!recipientPrivateKeyPem) {
      return res.status(400).json({ success: false, error: 'Missing recipientPrivateKeyPem' });
    }

    let symmetricKey: Buffer;
    let decapsulationTimeMs = 0;
    try {
      const kemResult = decapsulateKey(
        kemDemPackage.kemHeader.algorithm,
        recipientPrivateKeyPem,
        kemDemPackage.kemHeader.c_kem,
        {
          salt: kemDemPackage.kemHeader.salt,
          ephemeralPublicKey: kemDemPackage.kemHeader.ephemeralPublicKey,
        }
      );
      symmetricKey = kemResult.symmetricKey;
      decapsulationTimeMs = kemResult.decapsulationTimeMs;
    } catch (kemErr: any) {
      return res.status(400).json({
        success: false,
        errorPhase: 'KEM_DECAPSULATION',
        error: kemErr.message,
      });
    }

    let decryptedBuffer: Buffer;
    let decryptionTimeMs = 0;
    try {
      const demResult = decryptPayload(
        kemDemPackage.demPayload.algorithm,
        symmetricKey,
        kemDemPackage.demPayload.ciphertext,
        kemDemPackage.demPayload.iv,
        kemDemPackage.demPayload.tag,
        kemDemPackage.demPayload.aad
      );
      decryptedBuffer = demResult.plaintext;
      decryptionTimeMs = demResult.decryptionTimeMs;
    } catch (demErr: any) {
      return res.status(400).json({
        success: false,
        errorPhase: 'DEM_DECRYPTION',
        error: demErr.message,
      });
    }

    const decryptedSha256 = crypto.createHash('sha256').update(decryptedBuffer).digest('hex');
    const isLosslessMatch = decryptedSha256 === kemDemPackage.sourceImage.originalSha256;

    const pipelineEnd = performance.now();
    const totalDecryptionTimeMs = Math.round((pipelineEnd - pipelineStart) * 100) / 100;
    const entropy = calculateBufferEntropy(decryptedBuffer);

    const mime = kemDemPackage.sourceImage.mimeType || 'image/png';
    const decryptedDataUrl = `data:${mime};base64,${decryptedBuffer.toString('base64')}`;

    const result: DecryptionResult = {
      success: true,
      decryptedDataUrl,
      decryptedSha256,
      isLosslessMatch,
      decapsulationTimeMs,
      decryptionTimeMs,
      totalDecryptionTimeMs,
      entropy,
    };

    res.json(result);
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/kem-dem/tamper-test', (req: Request, res: Response) => {
  try {
    const {
      package: originalPackage,
      recipientPrivateKeyPem,
      tamperTarget,
    } = req.body as {
      package: KemDemPackage;
      recipientPrivateKeyPem: string;
      tamperTarget: 'KEM_HEADER' | 'CIPHERTEXT' | 'IV' | 'TAG' | 'AAD';
    };

    if (!originalPackage || !recipientPrivateKeyPem || !tamperTarget) {
      return res.status(400).json({ success: false, error: 'Missing parameters' });
    }

    const tamperedPackage: KemDemPackage = JSON.parse(JSON.stringify(originalPackage));

    let tamperDescription = '';

    if (tamperTarget === 'KEM_HEADER') {
      const buf = Buffer.from(tamperedPackage.kemHeader.c_kem, 'base64');
      buf[10] ^= 0x01;
      tamperedPackage.kemHeader.c_kem = buf.toString('base64');
      tamperDescription = 'Flipped 1 bit in KEM Encapsulated Key Header (c_kem)';
    } else if (tamperTarget === 'CIPHERTEXT') {
      const buf = Buffer.from(tamperedPackage.demPayload.ciphertext, 'base64');
      buf[12] ^= 0x01;
      tamperedPackage.demPayload.ciphertext = buf.toString('base64');
      tamperDescription = 'Flipped 1 bit in DEM Encrypted Image Payload (Ciphertext)';
    } else if (tamperTarget === 'IV') {
      const buf = Buffer.from(tamperedPackage.demPayload.iv, 'base64');
      buf[2] ^= 0x01;
      tamperedPackage.demPayload.iv = buf.toString('base64');
      tamperDescription = 'Flipped 1 bit in DEM 96-bit Initialization Vector (IV)';
    } else if (tamperTarget === 'TAG') {
      const buf = Buffer.from(tamperedPackage.demPayload.tag, 'base64');
      buf[4] ^= 0x01;
      tamperedPackage.demPayload.tag = buf.toString('base64');
      tamperDescription = 'Flipped 1 bit in DEM 128-bit Authentication Tag (MAC)';
    } else if (tamperTarget === 'AAD') {
      tamperedPackage.demPayload.aad = (tamperedPackage.demPayload.aad || '') + '_TAMPERED';
      tamperDescription = 'Appended unauthorized metadata to Additional Authenticated Data (AAD)';
    }

    let symmetricKey: Buffer | null = null;
    let failedPhase = '';
    let errorMessage = '';

    try {
      const kemResult = decapsulateKey(
        tamperedPackage.kemHeader.algorithm,
        recipientPrivateKeyPem,
        tamperedPackage.kemHeader.c_kem,
        {
          salt: tamperedPackage.kemHeader.salt,
          ephemeralPublicKey: tamperedPackage.kemHeader.ephemeralPublicKey,
        }
      );
      symmetricKey = kemResult.symmetricKey;
    } catch (e: any) {
      failedPhase = 'KEM_DECAPSULATION';
      errorMessage = e.message;
    }

    if (symmetricKey) {
      try {
        decryptPayload(
          tamperedPackage.demPayload.algorithm,
          symmetricKey,
          tamperedPackage.demPayload.ciphertext,
          tamperedPackage.demPayload.iv,
          tamperedPackage.demPayload.tag,
          tamperedPackage.demPayload.aad
        );
      } catch (e: any) {
        failedPhase = 'DEM_DECRYPTION_AEAD';
        errorMessage = e.message;
      }
    }

    res.json({
      success: true,
      tamperTarget,
      tamperDescription,
      failedPhase,
      errorMessage,
      attackNeutralized: Boolean(failedPhase),
      cryptographicGuarantee:
        failedPhase === 'KEM_DECAPSULATION'
          ? 'IND-CCA2 Public Key Security: Man-in-the-middle key modification intercepted and decapsulation rejected.'
          : 'AEAD Integrity Proof: Symmetric authenticated encryption detected ciphertext/tag tampering; zero bytes released.',
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/kem-dem/entropy-analysis', (req: Request, res: Response) => {
  try {
    const { dataUrl } = req.body as { dataUrl: string };
    if (!dataUrl) {
      return res.status(400).json({ success: false, error: 'Missing dataUrl' });
    }
    const buffer = extractBufferFromDataUrl(dataUrl);
    const analysis = performEntropyAnalysis(buffer);
    res.json({ success: true, analysis });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/kem-dem/samples', (_req: Request, res: Response) => {
  res.json({ success: true, samples: SAMPLE_IMAGES });
});

export default router;
