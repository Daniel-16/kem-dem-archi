import crypto from 'node:crypto';
import type { DemAlgorithm, DemEncryptionResult } from '../types/kemdem.js';

export function encryptPayload(
  algorithm: DemAlgorithm,
  symmetricKey: Buffer,
  plaintext: Buffer,
  aad?: string
): DemEncryptionResult {
  const start = performance.now();

  if (algorithm === 'AES-256-GCM') {
    // 96-bit (12-byte) IV is standard for AES-GCM
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);

    if (aad && aad.length > 0) {
      cipher.setAAD(Buffer.from(aad, 'utf8'));
    }

    const encryptedChunks = [cipher.update(plaintext), cipher.final()];
    const ciphertext = Buffer.concat(encryptedChunks);
    const tag = cipher.getAuthTag(); // 16 bytes

    const end = performance.now();
    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      algorithm,
      aad,
      encryptionTimeMs: Math.round((end - start) * 100) / 100,
      originalSizeBytes: plaintext.length,
      cipherSizeBytes: ciphertext.length,
    };
  }

  if (algorithm === 'CHACHA20-POLY1305') {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('chacha20-poly1305', symmetricKey, iv, {
      authTagLength: 16,
    });

    if (aad && aad.length > 0) {
      cipher.setAAD(Buffer.from(aad, 'utf8'), { plaintextLength: plaintext.length });
    }

    const encryptedChunks = [cipher.update(plaintext), cipher.final()];
    const ciphertext = Buffer.concat(encryptedChunks);
    const tag = cipher.getAuthTag();

    const end = performance.now();
    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      algorithm,
      aad,
      encryptionTimeMs: Math.round((end - start) * 100) / 100,
      originalSizeBytes: plaintext.length,
      cipherSizeBytes: ciphertext.length,
    };
  }

  throw new Error(`Unsupported DEM algorithm: ${algorithm}`);
}

export function decryptPayload(
  algorithm: DemAlgorithm,
  symmetricKey: Buffer,
  ciphertextBase64: string,
  ivBase64: string,
  tagBase64: string,
  aad?: string
): { plaintext: Buffer; decryptionTimeMs: number } {
  const start = performance.now();

  try {
    const ciphertext = Buffer.from(ciphertextBase64, 'base64');
    const iv = Buffer.from(ivBase64, 'base64');
    const tag = Buffer.from(tagBase64, 'base64');

    if (algorithm === 'AES-256-GCM') {
      const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
      decipher.setAuthTag(tag);

      if (aad && aad.length > 0) {
        decipher.setAAD(Buffer.from(aad, 'utf8'));
      }

      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);

      const end = performance.now();
      return {
        plaintext: decrypted,
        decryptionTimeMs: Math.round((end - start) * 100) / 100,
      };
    }

    if (algorithm === 'CHACHA20-POLY1305') {
      const decipher = crypto.createDecipheriv('chacha20-poly1305', symmetricKey, iv, {
        authTagLength: 16,
      });
      decipher.setAuthTag(tag);

      if (aad && aad.length > 0) {
        decipher.setAAD(Buffer.from(aad, 'utf8'), { plaintextLength: ciphertext.length });
      }

      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);

      const end = performance.now();
      return {
        plaintext: decrypted,
        decryptionTimeMs: Math.round((end - start) * 100) / 100,
      };
    }

    throw new Error(`Unsupported DEM algorithm: ${algorithm}`);
  } catch (error: any) {
    throw new Error(
      `DEM Decryption Failed (Integrity Verification Failed): ${
        error.message || 'Authentication tag mismatch or corrupted ciphertext'
      }`
    );
  }
}
