import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import {
  Buffer,
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'react-native-quick-crypto';
import type { KemKeyPair } from './types';

const masterKeyName = 'kem-dem-keyring-master-v1';
const keyringFileName = 'kem-dem-keyring-v1.enc';
const keyringAad = 'KEM-DEM-KEYRING-V1';
const supportedKemAlgorithms = new Set([
  'RSA-OAEP-2048',
  'RSA-OAEP-3072',
  'RSA-OAEP-4096',
  'ECDH-P256',
  'ECDH-P384',
  'ECDH-X25519',
]);

function getKeyringUri(): string {
  if (!FileSystem.documentDirectory) {
    throw new Error('This device did not provide a private app storage directory.');
  }
  return `${FileSystem.documentDirectory}${keyringFileName}`;
}

function isKemKeyPairList(value: unknown): value is KemKeyPair[] {
  if (!Array.isArray(value)) return false;
  return value.every((entry: unknown) => {
    if (typeof entry !== 'object' || entry === null) return false;
    const key = entry as Partial<KemKeyPair>;
    return (
      typeof key.id === 'string' &&
      typeof key.label === 'string' &&
      typeof key.algorithm === 'string' &&
      supportedKemAlgorithms.has(key.algorithm) &&
      typeof key.publicKeyPem === 'string' &&
      typeof key.privateKeyPem === 'string' &&
      typeof key.fingerprint === 'string' &&
      /^[a-f0-9]{16}$/i.test(key.fingerprint) &&
      typeof key.createdAt === 'number' &&
      Number.isFinite(key.createdAt) &&
      typeof key.keyDetails?.description === 'string'
    );
  });
}

async function readMasterKey(fileExists: boolean): Promise<Buffer | null> {
  const encodedKey = await SecureStore.getItemAsync(masterKeyName);
  if (!encodedKey) {
    if (fileExists) {
      throw new Error(
        'The encrypted keyring exists but its device-protected key is missing. The keyring was not overwritten.',
      );
    }
    return null;
  }

  const key = Buffer.from(encodedKey, 'base64');
  if (key.length !== 32) {
    throw new Error('The device-protected keyring key is invalid.');
  }
  return key;
}

export async function loadKeyring(): Promise<KemKeyPair[]> {
  const uri = getKeyringUri();
  const fileInfo = await FileSystem.getInfoAsync(uri);
  const masterKey = await readMasterKey(fileInfo.exists);
  if (!fileInfo.exists) return [];
  if (!masterKey) {
    throw new Error('A keyring file exists without its device-protected encryption key.');
  }

  const encodedRecord = await FileSystem.readAsStringAsync(uri);
  let record: { iv?: string; tag?: string; ciphertext?: string };
  try {
    record = JSON.parse(encodedRecord) as typeof record;
  } catch {
    throw new Error('The encrypted keyring file is not valid JSON.');
  }
  if (
    typeof record.iv !== 'string' ||
    typeof record.tag !== 'string' ||
    typeof record.ciphertext !== 'string'
  ) {
    throw new Error('The encrypted keyring file is missing required fields.');
  }

  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      masterKey,
      Buffer.from(record.iv, 'base64'),
    );
    decipher.setAAD(Buffer.from(keyringAad, 'utf8'));
    decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(record.ciphertext, 'base64')),
      decipher.final(),
    ]);
    const parsed: unknown = JSON.parse(plaintext.toString('utf8'));
    if (!isKemKeyPairList(parsed)) {
      throw new Error('The decrypted keyring has an invalid data structure.');
    }
    return parsed;
  } catch (error) {
    if (error instanceof Error && error.message.includes('invalid data structure')) {
      throw error;
    }
    throw new Error('The keyring could not be decrypted or failed integrity verification.');
  }
}

export async function saveKeyring(keys: KemKeyPair[]): Promise<void> {
  const uri = getKeyringUri();
  if (keys.length === 0) {
    const fileInfo = await FileSystem.getInfoAsync(uri);
    if (fileInfo.exists) await FileSystem.deleteAsync(uri);
    await SecureStore.deleteItemAsync(masterKeyName);
    return;
  }

  const fileInfo = await FileSystem.getInfoAsync(uri);
  let masterKey = await readMasterKey(fileInfo.exists);
  if (!masterKey) {
    masterKey = randomBytes(32);
    await SecureStore.setItemAsync(
      masterKeyName,
      masterKey.toString('base64'),
      { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY },
    );
  }

  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(keyringAad, 'utf8'));
  const plaintext = Buffer.from(JSON.stringify(keys), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const record = {
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
  await FileSystem.writeAsStringAsync(uri, JSON.stringify(record));
}
