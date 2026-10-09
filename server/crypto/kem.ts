import crypto from 'node:crypto';
import type { KemAlgorithm, KemKeyPair, KemEncapsulationResult } from '../types/kemdem.js';

export function computeSha256Fingerprint(pem: string): string {
  const cleanKey = pem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
  const buffer = Buffer.from(cleanKey, 'base64');
  return crypto.createHash('sha256').update(buffer).digest('hex').substring(0, 16);
}

export function generateKemKeyPair(
  algorithm: KemAlgorithm,
  label?: string
): KemKeyPair {
  const id = `key_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
  let publicKeyPem = '';
  let privateKeyPem = '';
  let keyDetails = { description: '' } as KemKeyPair['keyDetails'];

  switch (algorithm) {
    case 'RSA-OAEP-2048':
    case 'RSA-OAEP-3072':
    case 'RSA-OAEP-4096': {
      const modulusLength =
        algorithm === 'RSA-OAEP-2048' ? 2048 :
        algorithm === 'RSA-OAEP-3072' ? 3072 : 4096;

      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      publicKeyPem = publicKey;
      privateKeyPem = privateKey;
      keyDetails = {
        modulusLength,
        description: `RSA ${modulusLength}-bit key with OAEP padding (SHA-256)`,
      };
      break;
    }

    case 'ECDH-P256': {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      publicKeyPem = publicKey;
      privateKeyPem = privateKey;
      keyDetails = {
        namedCurve: 'prime256v1 (NIST P-256)',
        description: 'Elliptic Curve Diffie-Hellman on NIST P-256 with HKDF-SHA256',
      };
      break;
    }

    case 'ECDH-P384': {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'secp384r1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      publicKeyPem = publicKey;
      privateKeyPem = privateKey;
      keyDetails = {
        namedCurve: 'secp384r1 (NIST P-384)',
        description: 'High-security Elliptic Curve Diffie-Hellman on NIST P-384',
      };
      break;
    }

    case 'ECDH-X25519': {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      publicKeyPem = publicKey;
      privateKeyPem = privateKey;
      keyDetails = {
        namedCurve: 'Curve25519',
        description: 'Bernstein Curve25519 modern high-performance Diffie-Hellman KEM',
      };
      break;
    }

    case 'HYBRID-PQ': {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      publicKeyPem = publicKey;
      privateKeyPem = privateKey;
      keyDetails = {
        namedCurve: 'P-256 + random placeholder',
        description: 'Demo-only P-256 combiner; the random placeholder is not ML-KEM or post-quantum secure',
      };
      break;
    }

    default:
      throw new Error(`Unsupported KEM algorithm: ${algorithm}`);
  }

  const fingerprint = computeSha256Fingerprint(publicKeyPem);

  return {
    id,
    label: label || `${algorithm} Key (${fingerprint.substring(0, 8)})`,
    algorithm,
    publicKeyPem,
    privateKeyPem,
    fingerprint,
    createdAt: Date.now(),
    keyDetails,
  };
}

export function encapsulateKey(
  algorithm: KemAlgorithm,
  publicKeyPem: string
): KemEncapsulationResult {
  const start = performance.now();

  if (algorithm.startsWith('RSA-OAEP')) {
    const symmetricKey = crypto.randomBytes(32);

    const encryptedKeyBuffer = crypto.publicEncrypt(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      symmetricKey
    );

    const end = performance.now();
    return {
      symmetricKey,
      c_kem: encryptedKeyBuffer.toString('base64'),
      algorithm,
      encapsulationTimeMs: Math.round((end - start) * 100) / 100,
    };
  }

  if (algorithm === 'ECDH-P256' || algorithm === 'ECDH-P384' || algorithm === 'ECDH-X25519') {
    const namedCurve =
      algorithm === 'ECDH-P256' ? 'prime256v1' :
      algorithm === 'ECDH-P384' ? 'secp384r1' : 'x25519';

    const ephemeral =
      namedCurve === 'x25519'
        ? crypto.generateKeyPairSync('x25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
          })
        : crypto.generateKeyPairSync('ec', {
            namedCurve,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
          });

    const recipientPubKey = crypto.createPublicKey(publicKeyPem);
    const ephemeralPrivKey = crypto.createPrivateKey(ephemeral.privateKey);

    const sharedSecret = crypto.diffieHellman({
      privateKey: ephemeralPrivKey,
      publicKey: recipientPubKey,
    });

    const salt = crypto.randomBytes(16);
    const info = Buffer.from(`KEM-DEM-${algorithm}`, 'utf8');
    const symmetricKey = Buffer.from(
      crypto.hkdfSync('sha256', sharedSecret, salt, info, 32)
    );

    const end = performance.now();
    return {
      symmetricKey,
      c_kem: Buffer.from(ephemeral.publicKey, 'utf8').toString('base64'),
      ephemeralPublicKey: ephemeral.publicKey,
      salt: salt.toString('base64'),
      algorithm,
      encapsulationTimeMs: Math.round((end - start) * 100) / 100,
    };
  }

  if (algorithm === 'HYBRID-PQ') {
    const ephemeral = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const recipientPubKey = crypto.createPublicKey(publicKeyPem);
    const ephemeralPrivKey = crypto.createPrivateKey(ephemeral.privateKey);

    const classicalSecret = crypto.diffieHellman({
      privateKey: ephemeralPrivKey,
      publicKey: recipientPubKey,
    });

    const pqSeed = crypto.randomBytes(32);
    const combinedSecret = Buffer.concat([classicalSecret, pqSeed]);
    const salt = crypto.randomBytes(16);
    const info = Buffer.from('HYBRID-PQ-COMBINER-SHA256', 'utf8');
    const symmetricKey = Buffer.from(
      crypto.hkdfSync('sha256', combinedSecret, salt, info, 32)
    );

    const cKemData = JSON.stringify({
      classicalEphemeralPem: ephemeral.publicKey,
      pqCiphertext: pqSeed.toString('base64'),
    });

    const end = performance.now();
    return {
      symmetricKey,
      c_kem: Buffer.from(cKemData, 'utf8').toString('base64'),
      ephemeralPublicKey: ephemeral.publicKey,
      salt: salt.toString('base64'),
      algorithm,
      encapsulationTimeMs: Math.round((end - start) * 100) / 100,
    };
  }

  throw new Error(`Unsupported KEM encapsulation algorithm: ${algorithm}`);
}

export function decapsulateKey(
  algorithm: KemAlgorithm,
  privateKeyPem: string,
  c_kem: string,
  options?: { salt?: string; ephemeralPublicKey?: string }
): { symmetricKey: Buffer; decapsulationTimeMs: number } {
  const start = performance.now();

  try {
    if (algorithm.startsWith('RSA-OAEP')) {
      const encryptedKeyBuffer = Buffer.from(c_kem, 'base64');
      const symmetricKey = crypto.privateDecrypt(
        {
          key: privateKeyPem,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        encryptedKeyBuffer
      );

      const end = performance.now();
      return {
        symmetricKey,
        decapsulationTimeMs: Math.round((end - start) * 100) / 100,
      };
    }

    if (algorithm === 'ECDH-P256' || algorithm === 'ECDH-P384' || algorithm === 'ECDH-X25519') {
      const ephemeralPem =
        options?.ephemeralPublicKey || Buffer.from(c_kem, 'base64').toString('utf8');
      const salt = options?.salt ? Buffer.from(options.salt, 'base64') : Buffer.alloc(16);

      const recipientPrivKey = crypto.createPrivateKey(privateKeyPem);
      const ephemeralPubKey = crypto.createPublicKey(ephemeralPem);

      const sharedSecret = crypto.diffieHellman({
        privateKey: recipientPrivKey,
        publicKey: ephemeralPubKey,
      });

      const info = Buffer.from(`KEM-DEM-${algorithm}`, 'utf8');
      const symmetricKey = Buffer.from(
        crypto.hkdfSync('sha256', sharedSecret, salt, info, 32)
      );

      const end = performance.now();
      return {
        symmetricKey,
        decapsulationTimeMs: Math.round((end - start) * 100) / 100,
      };
    }

    if (algorithm === 'HYBRID-PQ') {
      const rawJson = Buffer.from(c_kem, 'base64').toString('utf8');
      const parsed = JSON.parse(rawJson);
      const ephemeralPubKey = crypto.createPublicKey(parsed.classicalEphemeralPem);
      const recipientPrivKey = crypto.createPrivateKey(privateKeyPem);

      const classicalSecret = crypto.diffieHellman({
        privateKey: recipientPrivKey,
        publicKey: ephemeralPubKey,
      });

      const pqSeed = Buffer.from(parsed.pqCiphertext, 'base64');
      const combinedSecret = Buffer.concat([classicalSecret, pqSeed]);
      const salt = options?.salt ? Buffer.from(options.salt, 'base64') : Buffer.alloc(16);
      const info = Buffer.from('HYBRID-PQ-COMBINER-SHA256', 'utf8');

      const symmetricKey = Buffer.from(
        crypto.hkdfSync('sha256', combinedSecret, salt, info, 32)
      );

      const end = performance.now();
      return {
        symmetricKey,
        decapsulationTimeMs: Math.round((end - start) * 100) / 100,
      };
    }

    throw new Error(`Unsupported decapsulation algorithm: ${algorithm}`);
  } catch (error: any) {
    throw new Error(`KEM Decapsulation Failed: ${error.message || 'Invalid key or corrupted ciphertext'}`);
  }
}
