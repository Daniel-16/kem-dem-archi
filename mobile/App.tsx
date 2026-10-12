import { StatusBar } from 'expo-status-bar';
import { Asset } from 'expo-asset';
import * as DocumentPicker from 'expo-document-picker';
import * as FileSystem from 'expo-file-system/legacy';
import * as ImagePicker from 'expo-image-picker';
import * as Sharing from 'expo-sharing';
import React, { useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Image,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  StatusBar as NativeStatusBar,
  Text,
  TextInput,
  View,
} from 'react-native';
import { Buffer } from 'react-native-quick-crypto';
import {
  decryptImageOffline,
  encryptImageOffline,
  fingerprint,
  generateKemKeyPair,
  performEntropyAnalysis,
  runTamperTest,
  validateKemKeyPair,
} from './src/crypto/offline';
import { loadKeyring, saveKeyring } from './src/keyring-storage';
import type {
  DemAlgorithm,
  KemAlgorithm,
  KemDemPackage,
  KemKeyPair,
  TamperTarget,
} from './src/types';

type Tab = 'encrypt' | 'decrypt' | 'keys' | 'lab';

interface SelectedImage {
  uri: string;
  base64: string;
  name: string;
  mimeType: string;
  width: number;
  height: number;
  sizeBytes: number;
}

const COLORS = {
  background: '#07131F',
  panel: '#0D1D2B',
  panelRaised: '#122638',
  border: '#20394A',
  text: '#EDF7FA',
  muted: '#90A8B6',
  dim: '#607986',
  teal: '#63E8D4',
  blue: '#6FA9FF',
  amber: '#FFC36E',
  red: '#FF8B87',
  green: '#82E6A9',
};

const kemAlgorithms: { id: KemAlgorithm; label: string }[] = [
  { id: 'RSA-OAEP-2048', label: 'RSA 2048' },
  { id: 'RSA-OAEP-3072', label: 'RSA 3072' },
  { id: 'RSA-OAEP-4096', label: 'RSA 4096' },
  { id: 'ECDH-P256', label: 'P-256' },
  { id: 'ECDH-P384', label: 'P-384' },
  { id: 'ECDH-X25519', label: 'X25519' },
];

const tamperTargets: { id: TamperTarget; label: string }[] = [
  { id: 'KEM_HEADER', label: 'KEM header' },
  { id: 'CIPHERTEXT', label: 'Ciphertext' },
  { id: 'IV', label: 'Nonce / IV' },
  { id: 'TAG', label: 'Auth tag' },
  { id: 'AAD', label: 'AAD' },
];

const bundledSamples = [
  {
    id: 'sample-mri',
    label: 'Medical scan',
    name: 'medical-scan.png',
    module: require('./assets/samples/medical-scan.png'),
  },
  {
    id: 'sample-blueprint',
    label: 'Blueprint',
    name: 'blueprint.png',
    module: require('./assets/samples/blueprint.png'),
  },
  {
    id: 'sample-credential',
    label: 'Credential',
    name: 'credential.png',
    module: require('./assets/samples/credential.png'),
  },
];

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'The operation could not be completed.';
}

function isKemAlgorithm(value: unknown): value is KemAlgorithm {
  return kemAlgorithms.some(({ id }) => id === value);
}

function isDemAlgorithm(value: unknown): value is DemAlgorithm {
  return value === 'AES-256-GCM' || value === 'CHACHA20-POLY1305';
}

function isFiniteNonNegative(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function isKemDemPackage(value: unknown): value is KemDemPackage {
  if (!isRecord(value)) return false;
  const source = value.sourceImage;
  const kem = value.kemHeader;
  const dem = value.demPayload;
  const metrics = value.metrics;
  return (
    value.format === 'KEM-DEM-V1' &&
    typeof value.id === 'string' &&
    isFiniteNonNegative(value.timestamp) &&
    isRecord(source) &&
    typeof source.name === 'string' &&
    typeof source.mimeType === 'string' &&
    /^image\/[a-z0-9.+-]+$/i.test(source.mimeType) &&
    isFiniteNonNegative(source.width) &&
    source.width > 0 &&
    isFiniteNonNegative(source.height) &&
    source.height > 0 &&
    typeof source.originalSha256 === 'string' &&
    isFiniteNonNegative(source.originalSizeBytes) &&
    isRecord(kem) &&
    isKemAlgorithm(kem.algorithm) &&
    typeof kem.c_kem === 'string' &&
    (kem.ephemeralPublicKey === undefined || typeof kem.ephemeralPublicKey === 'string') &&
    (kem.salt === undefined || typeof kem.salt === 'string') &&
    (kem.recipientFingerprint === undefined || typeof kem.recipientFingerprint === 'string') &&
    isRecord(dem) &&
    isDemAlgorithm(dem.algorithm) &&
    typeof dem.iv === 'string' &&
    typeof dem.tag === 'string' &&
    typeof dem.ciphertext === 'string' &&
    (dem.aad === undefined || typeof dem.aad === 'string') &&
    isRecord(metrics) &&
    isFiniteNonNegative(metrics.encapsulationTimeMs) &&
    isFiniteNonNegative(metrics.encryptionTimeMs) &&
    isFiniteNonNegative(metrics.totalPipelineTimeMs) &&
    isFiniteNonNegative(metrics.originalEntropy) &&
    metrics.originalEntropy <= 8 &&
    isFiniteNonNegative(metrics.encryptedEntropy) &&
    metrics.encryptedEntropy <= 8
  );
}

function safeFileName(value: string, fallback: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, '_').replace(/^\.+/, '') || fallback;
}

function parsePackage(value: string): KemDemPackage {
  const parsed: unknown = JSON.parse(value);
  if (
    isRecord(parsed) &&
    isRecord(parsed.kemHeader) &&
    parsed.kemHeader.algorithm === 'HYBRID-PQ'
  ) {
    throw new Error(
      'This package uses the project’s legacy HYBRID-PQ mode, which is not real post-quantum cryptography and is intentionally disabled in the mobile app.',
    );
  }
  if (!isKemDemPackage(parsed)) {
    throw new Error('The file is not a complete supported KEM-DEM-V1 package.');
  }
  return parsed;
}

function Panel({
  children,
  style,
}: {
  children: React.ReactNode;
  style?: object;
}) {
  return <View style={[styles.panel, style]}>{children}</View>;
}

function SectionTitle({
  eyebrow,
  title,
  subtitle,
}: {
  eyebrow: string;
  title: string;
  subtitle?: string;
}) {
  return (
    <View style={styles.sectionHeading}>
      <Text style={styles.eyebrow}>{eyebrow}</Text>
      <Text style={styles.sectionTitle}>{title}</Text>
      {subtitle ? <Text style={styles.bodyMuted}>{subtitle}</Text> : null}
    </View>
  );
}

function ActionButton({
  title,
  onPress,
  secondary = false,
  disabled = false,
  busy = false,
  compact = false,
}: {
  title: string;
  onPress: () => void;
  secondary?: boolean;
  disabled?: boolean;
  busy?: boolean;
  compact?: boolean;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      disabled={disabled || busy}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        secondary && styles.buttonSecondary,
        compact && styles.buttonCompact,
        (disabled || busy) && styles.buttonDisabled,
        pressed && !disabled && styles.buttonPressed,
      ]}
    >
      {busy ? (
        <ActivityIndicator color={secondary ? COLORS.teal : COLORS.background} size="small" />
      ) : (
        <Text style={[styles.buttonText, secondary && styles.buttonTextSecondary]}>
          {title}
        </Text>
      )}
    </Pressable>
  );
}

function ChoiceChip({
  label,
  selected,
  onPress,
}: {
  label: string;
  selected: boolean;
  onPress: () => void;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ selected }}
      onPress={onPress}
      style={[styles.chip, selected && styles.chipSelected]}
    >
      <Text style={[styles.chipText, selected && styles.chipTextSelected]}>{label}</Text>
    </Pressable>
  );
}

function KeyAlgorithmChoices({
  value,
  onChange,
}: {
  value: KemAlgorithm;
  onChange: (algorithm: KemAlgorithm) => void;
}) {
  return (
    <View style={styles.chipWrap}>
      {kemAlgorithms.map(({ id, label }) => (
        <ChoiceChip
          key={id}
          label={label}
          selected={value === id}
          onPress={() => onChange(id)}
        />
      ))}
    </View>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.metric}>
      <Text style={styles.metricValue}>{value}</Text>
      <Text style={styles.metricLabel}>{label}</Text>
    </View>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>('encrypt');
  const [keyring, setKeyring] = useState<KemKeyPair[]>([]);
  const [activeKeyId, setActiveKeyId] = useState('');
  const [keyringReady, setKeyringReady] = useState(false);
  const [keyringError, setKeyringError] = useState<string | null>(null);
  const [selectedImage, setSelectedImage] = useState<SelectedImage | null>(null);
  const [demAlgorithm, setDemAlgorithm] = useState<DemAlgorithm>('AES-256-GCM');
  const [aad, setAad] = useState('');
  const [currentPackage, setCurrentPackage] = useState<KemDemPackage | null>(null);
  const [decryptedImage, setDecryptedImage] = useState<string | null>(null);
  const [decryptedImageMatchesHash, setDecryptedImageMatchesHash] = useState<boolean | null>(
    null,
  );
  const [privatePem, setPrivatePem] = useState('');
  const [isWorking, setIsWorking] = useState(false);
  const [keyAlgorithm, setKeyAlgorithm] = useState<KemAlgorithm>('RSA-OAEP-2048');
  const [keyLabel, setKeyLabel] = useState('');
  const [importAlgorithm, setImportAlgorithm] = useState<KemAlgorithm>('RSA-OAEP-2048');
  const [importLabel, setImportLabel] = useState('');
  const [importPublicPem, setImportPublicPem] = useState('');
  const [importPrivatePem, setImportPrivatePem] = useState('');
  const [selectedTamper, setSelectedTamper] = useState<TamperTarget>('CIPHERTEXT');
  const [tamperResult, setTamperResult] = useState<ReturnType<typeof runTamperTest> | null>(
    null,
  );

  useEffect(() => {
    let mounted = true;
    loadKeyring()
      .then((savedKeys) => {
        if (!mounted) return;
        setKeyring(savedKeys);
        setActiveKeyId(savedKeys[0]?.id ?? '');
      })
      .catch((error: unknown) => {
        if (mounted) {
          setKeyringError(errorMessage(error));
          Alert.alert(
            'Could not unlock the local keyring',
            `${errorMessage(error)}\n\nThe saved keyring has not been replaced.`,
          );
        }
      })
      .finally(() => {
        if (mounted) setKeyringReady(true);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const activeKey = useMemo(
    () => keyring.find((key) => key.id === activeKeyId) ?? null,
    [activeKeyId, keyring],
  );

  const updateKeyring = async (nextKeys: KemKeyPair[]) => {
    if (keyringError) throw new Error(keyringError);
    await saveKeyring(nextKeys);
    setKeyring(nextKeys);
    if (!nextKeys.some((key) => key.id === activeKeyId)) {
      setActiveKeyId(nextKeys[0]?.id ?? '');
    }
  };

  const selectImage = async () => {
    try {
      const result = await ImagePicker.launchImageLibraryAsync({
        mediaTypes: ['images'],
        allowsEditing: false,
        quality: 1,
        base64: true,
      });
      if (result.canceled) return;
      const asset = result.assets[0];
      let base64 = asset.base64;
      if (!base64) {
        base64 = await FileSystem.readAsStringAsync(asset.uri, {
          encoding: FileSystem.EncodingType.Base64,
        });
      }
      if (!base64) throw new Error('The image picker returned an empty image.');
      setSelectedImage({
        uri: asset.uri,
        base64,
        name: asset.fileName || `image-${Date.now()}.jpg`,
        mimeType: asset.mimeType || 'image/jpeg',
        width: asset.width,
        height: asset.height,
        sizeBytes: asset.fileSize ?? Buffer.from(base64, 'base64').length,
      });
      setCurrentPackage(null);
      setDecryptedImage(null);
      setDecryptedImageMatchesHash(null);
      setTamperResult(null);
    } catch (error) {
      Alert.alert('Image could not be selected', errorMessage(error));
    }
  };

  const selectSample = async (sample: (typeof bundledSamples)[number]) => {
    try {
      const asset = Asset.fromModule(sample.module);
      await asset.downloadAsync();
      if (!asset.localUri) {
        throw new Error('The bundled sample image is not available in local app storage.');
      }
      const base64 = await FileSystem.readAsStringAsync(asset.localUri, {
        encoding: FileSystem.EncodingType.Base64,
      });
      setSelectedImage({
        uri: asset.localUri,
        base64,
        name: sample.name,
        mimeType: 'image/png',
        width: asset.width ?? 400,
        height: asset.height ?? 400,
        sizeBytes: Buffer.from(base64, 'base64').length,
      });
      setCurrentPackage(null);
      setDecryptedImage(null);
      setDecryptedImageMatchesHash(null);
      setTamperResult(null);
    } catch (error) {
      Alert.alert('Sample image could not be loaded', errorMessage(error));
    }
  };

  const createKey = async () => {
    if (!keyringReady || keyringError) return;
    setIsWorking(true);
    try {
      const newKey = await generateKemKeyPair(keyAlgorithm, keyLabel);
      const nextKeys = [newKey, ...keyring];
      await saveKeyring(nextKeys);
      setKeyring(nextKeys);
      setActiveKeyId(newKey.id);
      setKeyLabel('');
      Alert.alert('Key created on this device', `${newKey.label}\n\nPrivate key stored encrypted in this app’s private storage.`);
    } catch (error) {
      Alert.alert('Key generation failed', errorMessage(error));
    } finally {
      setIsWorking(false);
    }
  };

  const importKey = async () => {
    if (!keyringReady || keyringError) return;
    const publicKeyPem = importPublicPem.trim();
    const privateKey = importPrivatePem.trim();
    if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) {
      Alert.alert('Public key required', 'Paste a valid SPKI public PEM key.');
      return;
    }
    if (privateKey && !/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(privateKey)) {
      Alert.alert('Private key is not valid PEM', 'Check that the private PEM block is complete.');
      return;
    }

    try {
      const importedFingerprint = fingerprint(publicKeyPem);
      const imported: KemKeyPair = {
        id: `imported_${Date.now()}`,
        label: importLabel.trim() || `${importAlgorithm} (${importedFingerprint.slice(0, 8)})`,
        algorithm: importAlgorithm,
        publicKeyPem,
        privateKeyPem: privateKey,
        fingerprint: importedFingerprint,
        createdAt: Date.now(),
        keyDetails: {
          description: `Imported ${importAlgorithm} key`,
        },
      };
      if (!validateKemKeyPair(imported)) {
        throw new Error(
          privateKey
            ? 'The supplied public and private keys do not match or use the selected algorithm.'
            : 'The public key is invalid or does not use the selected algorithm.',
        );
      }
      const nextKeys = [imported, ...keyring];
      await saveKeyring(nextKeys);
      setKeyring(nextKeys);
      setActiveKeyId(imported.id);
      setImportLabel('');
      setImportPublicPem('');
      setImportPrivatePem('');
      Alert.alert(
        'Key imported',
        privateKey
          ? 'The PEM pair is encrypted before it is saved in this app’s private storage.'
          : 'Public key saved. Import its matching private key before decrypting packages.',
      );
    } catch (error) {
      Alert.alert('Key import failed', errorMessage(error));
    }
  };

  const pickPemForImport = async (target: 'public' | 'private') => {
    try {
      const picked = await DocumentPicker.getDocumentAsync({
        type: '*/*',
        copyToCacheDirectory: true,
      });
      if (picked.canceled) return;
      const pem = (await FileSystem.readAsStringAsync(picked.assets[0].uri)).trim();
      const valid =
        target === 'public'
          ? pem.includes('-----BEGIN PUBLIC KEY-----')
          : /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(pem);
      if (!valid) {
        throw new Error(`The selected file is not a valid ${target} PEM key.`);
      }
      if (target === 'public') setImportPublicPem(pem);
      else setImportPrivatePem(pem);
    } catch (error) {
      Alert.alert('PEM import failed', errorMessage(error));
    }
  };

  const removeKey = (key: KemKeyPair) => {
    Alert.alert('Remove this key?', `${key.label}\n\nIts locally stored private key will be deleted.`, [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Remove',
        style: 'destructive',
        onPress: () => {
          const nextKeys = keyring.filter((entry) => entry.id !== key.id);
          updateKeyring(nextKeys).catch((error: unknown) =>
            Alert.alert('Key could not be removed', errorMessage(error)),
          );
        },
      },
    ]);
  };

  const shareTextFile = async (name: string, content: string, mimeType: string) => {
    if (!FileSystem.cacheDirectory) {
      throw new Error('This device did not provide a temporary file directory.');
    }
    const uri = `${FileSystem.cacheDirectory}${name}`;
    try {
      await FileSystem.writeAsStringAsync(uri, content);
      if (!(await Sharing.isAvailableAsync())) {
        throw new Error('The Android share sheet is not available on this device.');
      }
      await Sharing.shareAsync(uri, { mimeType, dialogTitle: `Share ${name}` });
    } finally {
      await FileSystem.deleteAsync(uri, { idempotent: true });
    }
  };

  const shareBinaryFile = async (
    name: string,
    base64: string,
    mimeType: string,
  ) => {
    if (!FileSystem.cacheDirectory) {
      throw new Error('This device did not provide a temporary file directory.');
    }
    const uri = `${FileSystem.cacheDirectory}${name}`;
    try {
      await FileSystem.writeAsStringAsync(uri, base64, {
        encoding: FileSystem.EncodingType.Base64,
      });
      if (!(await Sharing.isAvailableAsync())) {
        throw new Error('The Android share sheet is not available on this device.');
      }
      await Sharing.shareAsync(uri, { mimeType, dialogTitle: `Share ${name}` });
    } finally {
      await FileSystem.deleteAsync(uri, { idempotent: true });
    }
  };

  const shareKey = async (key: KemKeyPair, kind: 'public' | 'private') => {
    const pem = kind === 'public' ? key.publicKeyPem : key.privateKeyPem;
    if (!pem) {
      Alert.alert('Key is not available', `This keyring entry does not contain its ${kind} key.`);
      return;
    }
    try {
      await shareTextFile(
        `${key.id}_${kind}.pem`,
        pem,
        'application/x-pem-file',
      );
    } catch (error) {
      Alert.alert('Key export failed', errorMessage(error));
    }
  };

  const encryptSelectedImage = async () => {
    if (!selectedImage) {
      Alert.alert('Choose an image first', 'Select a photo stored on this phone.');
      return;
    }
    if (!activeKey) {
      Alert.alert('Create or import a key first', 'The app needs a recipient public key to encrypt.');
      setTab('keys');
      return;
    }

    setIsWorking(true);
    await new Promise<void>((resolve) => setTimeout(resolve, 40));
    try {
      const nextPackage = encryptImageOffline({
        imageBase64: selectedImage.base64,
        imageName: selectedImage.name,
        mimeType: selectedImage.mimeType,
        width: selectedImage.width,
        height: selectedImage.height,
        recipient: activeKey,
        demAlgorithm,
        aad,
      });
      setCurrentPackage(nextPackage);
      setDecryptedImage(null);
      setDecryptedImageMatchesHash(null);
      setTamperResult(null);
      setTab('decrypt');
    } catch (error) {
      Alert.alert('Encryption failed', errorMessage(error));
    } finally {
      setIsWorking(false);
    }
  };

  const sharePackage = async () => {
    if (!currentPackage) return;
    try {
      await shareTextFile(
        `${safeFileName(currentPackage.id, 'encrypted-image')}.kemdem`,
        JSON.stringify(currentPackage, null, 2),
        'application/json',
      );
    } catch (error) {
      Alert.alert('Package export failed', errorMessage(error));
    }
  };

  const importPackage = async () => {
    try {
      const picked = await DocumentPicker.getDocumentAsync({
        type: '*/*',
        copyToCacheDirectory: true,
      });
      if (picked.canceled) return;
      const asset = picked.assets[0];
      const contents = await FileSystem.readAsStringAsync(asset.uri);
      const imported = parsePackage(contents);
      setCurrentPackage(imported);
      setPrivatePem('');
      setDecryptedImage(null);
      setDecryptedImageMatchesHash(null);
      setTamperResult(null);
    } catch (error) {
      Alert.alert('Package import failed', errorMessage(error));
    }
  };

  const decryptCurrentPackage = async () => {
    if (!currentPackage) {
      Alert.alert('No package loaded', 'Import a .kemdem package or encrypt an image first.');
      return;
    }
    const matchingKey = keyring.find(
      (key) => key.fingerprint === currentPackage.kemHeader.recipientFingerprint,
    );
    const keyPem = privatePem.trim() || matchingKey?.privateKeyPem || '';
    if (!keyPem) {
      Alert.alert('Matching private key required', 'Select a key in the keyring or paste its private PEM.');
      setTab('keys');
      return;
    }

    setIsWorking(true);
    setDecryptedImage(null);
    setDecryptedImageMatchesHash(null);
    await new Promise<void>((resolve) => setTimeout(resolve, 40));
    try {
      const result = decryptImageOffline(currentPackage, keyPem);
      setDecryptedImage(result.decryptedBase64);
      setDecryptedImageMatchesHash(result.isLosslessMatch);
      if (!result.isLosslessMatch) {
        Alert.alert(
          'Image decrypted, but hash differs',
          'The image bytes did not match the original hash recorded in the package.',
        );
      }
    } catch (error) {
      Alert.alert('Decryption failed', errorMessage(error));
    } finally {
      setIsWorking(false);
    }
  };

  const pickPrivatePemForDecryption = async () => {
    try {
      const picked = await DocumentPicker.getDocumentAsync({
        type: '*/*',
        copyToCacheDirectory: true,
      });
      if (picked.canceled) return;
      const pem = (await FileSystem.readAsStringAsync(picked.assets[0].uri)).trim();
      if (!/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/.test(pem)) {
        throw new Error('The selected file is not a private PEM key.');
      }
      setPrivatePem(pem);
    } catch (error) {
      Alert.alert('Private key import failed', errorMessage(error));
    }
  };

  const exportDecryptedImage = async () => {
    if (!currentPackage || !decryptedImage) return;
    const extension =
      currentPackage.sourceImage.mimeType.split('/')[1]?.replace(/[^a-z0-9]/gi, '') ||
      'img';
    try {
      await shareBinaryFile(
        `decrypted_${currentPackage.sourceImage.name.replace(/[^\w.-]/g, '_') || `image.${extension}`}`,
        decryptedImage,
        currentPackage.sourceImage.mimeType,
      );
    } catch (error) {
      Alert.alert('Image export failed', errorMessage(error));
    }
  };

  const performTamperTest = () => {
    if (!currentPackage) {
      Alert.alert('No package loaded', 'Encrypt or import a package before running a tamper test.');
      return;
    }
    const matchingKey = keyring.find(
      (key) =>
        key.fingerprint === currentPackage.kemHeader.recipientFingerprint &&
        Boolean(key.privateKeyPem),
    );
    const keyPem = privatePem.trim() || matchingKey?.privateKeyPem || '';
    if (!keyPem) {
      Alert.alert('Matching private key required', 'Load the package recipient’s private key first.');
      return;
    }
    try {
      setTamperResult(runTamperTest(currentPackage, keyPem, selectedTamper));
    } catch (error) {
      Alert.alert('Tamper test failed', errorMessage(error));
    }
  };

  const tabs: { id: Tab; label: string }[] = [
    { id: 'encrypt', label: 'Encrypt' },
    { id: 'decrypt', label: 'Decrypt' },
    { id: 'keys', label: 'Keys' },
    { id: 'lab', label: 'Lab' },
  ];

  return (
    <View style={styles.root}>
      <StatusBar style="light" />
      <View style={styles.header}>
        <View style={styles.brandRow}>
          <Image source={require('./assets/app-icon.png')} style={styles.brandIcon} />
          <View style={styles.brandText}>
            <Text style={styles.brandName}>KEM<Text style={styles.brandDivider}> · </Text>DEM</Text>
            <Text style={styles.brandCaption}>IMAGE CRYPTOSYSTEM</Text>
          </View>
          <View style={styles.deviceBadge}>
            <View style={styles.liveDot} />
            <Text style={styles.deviceBadgeText}>ON DEVICE</Text>
          </View>
        </View>
        <View style={styles.nav}>
          {tabs.map(({ id, label }) => (
            <Pressable
              key={id}
              accessibilityRole="tab"
              accessibilityState={{ selected: tab === id }}
              onPress={() => setTab(id)}
              style={[styles.navItem, tab === id && styles.navItemActive]}
            >
              <Text style={[styles.navText, tab === id && styles.navTextActive]}>{label}</Text>
            </Pressable>
          ))}
        </View>
      </View>

      <KeyboardAvoidingView
        style={styles.content}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      >
        <ScrollView
          contentContainerStyle={styles.scrollContent}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
        >
          <View style={styles.hero}>
            <Text style={styles.heroEyebrow}>PRIVATE BY DESIGN</Text>
            <Text style={styles.heroTitle}>Your images.{'\n'}Your device. Your keys.</Text>
            <Text style={styles.heroCopy}>
              Hybrid encryption, entirely offline. Images and private keys stay on this phone.
            </Text>
          </View>

          <View style={styles.trustStrip}>
            <TrustItem label="No account" />
            <TrustItem label="No server" />
            <TrustItem label="Works offline" />
          </View>

          {!keyringReady ? (
            <Panel>
              <View style={styles.inlineLoading}>
                <ActivityIndicator color={COLORS.teal} />
                <Text style={styles.bodyMuted}>Unlocking encrypted local keyring…</Text>
              </View>
            </Panel>
          ) : null}

          {tab === 'encrypt' ? (
            <>
              <SectionTitle
                eyebrow="STAGE 01 · ENCRYPT"
                title="Seal an image"
                subtitle="Select a photo, choose an AEAD cipher and encrypt on this device."
              />
              <Panel>
                <Text style={styles.fieldLabel}>SOURCE IMAGE</Text>
                {selectedImage ? (
                  <View style={styles.imagePreviewRow}>
                    <Image source={{ uri: selectedImage.uri }} style={styles.imagePreview} />
                    <View style={styles.imageDetails}>
                      <Text style={styles.keyName} numberOfLines={2}>{selectedImage.name}</Text>
                      <Text style={styles.bodyMuted}>
                        {selectedImage.width} × {selectedImage.height} · {formatBytes(selectedImage.sizeBytes)}
                      </Text>
                      <ActionButton title="Choose another" secondary compact onPress={selectImage} />
                    </View>
                  </View>
                ) : (
                  <Pressable onPress={selectImage} style={styles.imagePicker}>
                    <View style={styles.imageGlyph}><Text style={styles.imageGlyphText}>＋</Text></View>
                    <Text style={styles.imagePickerTitle}>Choose an image</Text>
                    <Text style={styles.bodyMuted}>Pick a photo stored on your phone</Text>
                  </Pressable>
                )}
                <Text style={[styles.fieldLabel, styles.fieldSpacing]}>OR USE AN INCLUDED OFFLINE SAMPLE</Text>
                <View style={styles.chipWrap}>
                  {bundledSamples.map((sample) => (
                    <ChoiceChip
                      key={sample.id}
                      label={sample.label}
                      selected={selectedImage?.name === sample.name}
                      onPress={() => selectSample(sample)}
                    />
                  ))}
                </View>

                <Text style={[styles.fieldLabel, styles.fieldSpacing]}>RECIPIENT KEY</Text>
                {keyring.length > 0 ? (
                  <View style={styles.selectList}>
                    {keyring.map((key) => (
                      <Pressable
                        key={key.id}
                        onPress={() => setActiveKeyId(key.id)}
                        style={[styles.keyChoice, key.id === activeKeyId && styles.keyChoiceActive]}
                      >
                        <View style={styles.keyChoiceMain}>
                          <Text style={[styles.keyName, key.id === activeKeyId && styles.tealText]}>
                            {key.label}
                          </Text>
                          <Text style={styles.keyMeta}>
                            {key.algorithm} · {key.privateKeyPem ? 'private key on device' : 'public key only'}
                          </Text>
                        </View>
                        {key.id === activeKeyId ? <Text style={styles.checkmark}>✓</Text> : null}
                      </Pressable>
                    ))}
                  </View>
                ) : (
                  <Text style={styles.emptyHint}>Create or import a recipient key in the Keys tab.</Text>
                )}

                <Text style={[styles.fieldLabel, styles.fieldSpacing]}>DATA ENCRYPTION</Text>
                <View style={styles.chipWrap}>
                  <ChoiceChip
                    label="AES-256-GCM"
                    selected={demAlgorithm === 'AES-256-GCM'}
                    onPress={() => setDemAlgorithm('AES-256-GCM')}
                  />
                  <ChoiceChip
                    label="ChaCha20-Poly1305"
                    selected={demAlgorithm === 'CHACHA20-POLY1305'}
                    onPress={() => setDemAlgorithm('CHACHA20-POLY1305')}
                  />
                </View>
                <Text style={[styles.fieldLabel, styles.fieldSpacing]}>AUTHENTICATED DATA · OPTIONAL</Text>
                <TextInput
                  value={aad}
                  onChangeText={setAad}
                  placeholder="Metadata bound to the encrypted image"
                  placeholderTextColor={COLORS.dim}
                  style={styles.textInput}
                  autoCapitalize="none"
                />
                <View style={styles.noteBox}>
                  <Text style={styles.noteText}>
                    The image is encrypted locally. Its private key is never sent to a server.
                  </Text>
                </View>
                <ActionButton
                  title="Encrypt image on this phone"
                  onPress={encryptSelectedImage}
                  busy={isWorking}
                  disabled={!keyringReady || !selectedImage || !activeKey}
                />
              </Panel>
            </>
          ) : null}

          {tab === 'decrypt' ? (
            <>
              <SectionTitle
                eyebrow="STAGE 02 · DECRYPT"
                title="Open a KEM-DEM package"
                subtitle="Import a .kemdem file or decrypt the package you just created."
              />
              <Panel>
                <View style={styles.rowBetween}>
                  <Text style={styles.fieldLabel}>ENCRYPTED PACKAGE</Text>
                  <ActionButton title="Import file" secondary compact onPress={importPackage} />
                </View>
                {currentPackage ? (
                  <View style={styles.packageCard}>
                    <View style={styles.packageIcon}><Text style={styles.packageIconText}>▧</Text></View>
                    <View style={styles.packageDetails}>
                      <Text style={styles.keyName} numberOfLines={2}>{currentPackage.sourceImage.name}</Text>
                      <Text style={styles.keyMeta}>
                        {currentPackage.kemHeader.algorithm} · {currentPackage.demPayload.algorithm}
                      </Text>
                      <Text style={styles.keyMeta}>
                        {formatBytes(currentPackage.sourceImage.originalSizeBytes)} · {shortId(currentPackage.id)}
                      </Text>
                    </View>
                  </View>
                ) : (
                  <View style={styles.emptyCard}>
                    <Text style={styles.emptyHint}>No package loaded yet.</Text>
                    <ActionButton title="Import encrypted package" secondary onPress={importPackage} />
                  </View>
                )}
                {currentPackage ? (
                  <>
                    <View style={styles.rowGap}>
                      <ActionButton title="Share .kemdem file" secondary onPress={sharePackage} />
                      <ActionButton
                        title="Verify & decrypt locally"
                        onPress={decryptCurrentPackage}
                        busy={isWorking}
                        disabled={!keyringReady}
                      />
                    </View>
                    {decryptedImage ? (
                      <View
                        style={[
                          styles.resultCard,
                          decryptedImageMatchesHash ? styles.resultGood : styles.resultWarning,
                        ]}
                      >
                        <View style={styles.resultHeading}>
                          <View
                            style={
                              decryptedImageMatchesHash ? styles.successDot : styles.warningDot
                            }
                          />
                          <Text
                            style={
                              decryptedImageMatchesHash
                                ? styles.successTitle
                                : styles.warningText
                            }
                          >
                            {decryptedImageMatchesHash
                              ? 'Authenticated; image hash verified'
                              : 'Decrypted, but image hash mismatch'}
                          </Text>
                        </View>
                        <Image
                          source={{
                            uri: `data:${currentPackage.sourceImage.mimeType};base64,${decryptedImage}`,
                          }}
                          style={styles.decryptedPreview}
                          resizeMode="contain"
                        />
                        <Text style={styles.bodyMuted}>
                          {decryptedImageMatchesHash
                            ? 'The image SHA-256 matches the value recorded in the package.'
                            : 'The encrypted payload authenticated, but its SHA-256 does not match the package record. Package metadata may have been altered.'}
                        </Text>
                        <ActionButton
                          title="Share decrypted image"
                          secondary
                          onPress={exportDecryptedImage}
                        />
                      </View>
                    ) : null}
                  </>
                ) : null}
                <Text style={[styles.fieldLabel, styles.fieldSpacing]}>PRIVATE KEY</Text>
                {keyring.some(
                  (key) =>
                    key.fingerprint === currentPackage?.kemHeader.recipientFingerprint &&
                    Boolean(key.privateKeyPem),
                ) ? (
                  <Text style={styles.noteText}>
                    Matching private key found in the encrypted local keyring.
                  </Text>
                ) : (
                  <>
                    <ActionButton
                      title="Choose private PEM file"
                      secondary
                      compact
                      onPress={pickPrivatePemForDecryption}
                    />
                    <TextInput
                      value={privatePem}
                      onChangeText={setPrivatePem}
                      placeholder="Or paste the recipient’s private PEM"
                      placeholderTextColor={COLORS.dim}
                      style={[styles.textInput, styles.pemInput, styles.fieldSpacing]}
                      multiline
                      autoCapitalize="none"
                      autoCorrect={false}
                    />
                  </>
                )}
              </Panel>
            </>
          ) : null}

          {tab === 'keys' ? (
            <>
              <SectionTitle
                eyebrow="LOCAL KEYRING"
                title="Keys stay on this phone"
                subtitle="Key material is encrypted at rest with AES-GCM; the wrapping key is held in the device secure store."
              />
              <Panel>
                <Text style={styles.fieldLabel}>GENERATE A RECIPIENT KEY</Text>
                {keyringError ? (
                  <View style={styles.noteBox}>
                    <Text style={styles.errorTitle}>Keyring locked</Text>
                    <Text style={styles.noteText}>{keyringError}</Text>
                  </View>
                ) : null}
                <KeyAlgorithmChoices value={keyAlgorithm} onChange={setKeyAlgorithm} />
                <TextInput
                  value={keyLabel}
                  onChangeText={setKeyLabel}
                  placeholder="Key label (optional)"
                  placeholderTextColor={COLORS.dim}
                  style={[styles.textInput, styles.fieldSpacing]}
                />
                <ActionButton
                  title="Generate key pair on this phone"
                  onPress={createKey}
                  busy={isWorking}
                  disabled={!keyringReady || Boolean(keyringError)}
                />
                <View style={[styles.noteBox, styles.warningBox]}>
                  <Text style={styles.warningText}>
                    HYBRID-PQ is intentionally omitted: the old project mode did not implement real post-quantum cryptography.
                  </Text>
                </View>
              </Panel>

              <Panel>
                <Text style={styles.fieldLabel}>IMPORT PEM KEY</Text>
                <KeyAlgorithmChoices value={importAlgorithm} onChange={setImportAlgorithm} />
                <TextInput
                  value={importLabel}
                  onChangeText={setImportLabel}
                  placeholder="Key label (optional)"
                  placeholderTextColor={COLORS.dim}
                  style={[styles.textInput, styles.fieldSpacing]}
                />
                <TextInput
                  value={importPublicPem}
                  onChangeText={setImportPublicPem}
                  placeholder="-----BEGIN PUBLIC KEY-----"
                  placeholderTextColor={COLORS.dim}
                  style={[styles.textInput, styles.pemInput, styles.fieldSpacing]}
                  multiline
                  autoCapitalize="none"
                  autoCorrect={false}
                />
                <ActionButton
                  title="Choose public PEM file"
                  secondary
                  compact
                  onPress={() => pickPemForImport('public')}
                />
                <TextInput
                  value={importPrivatePem}
                  onChangeText={setImportPrivatePem}
                  placeholder="Matching private PEM (optional)"
                  placeholderTextColor={COLORS.dim}
                  style={[styles.textInput, styles.pemInput, styles.fieldSpacing]}
                  multiline
                  autoCapitalize="none"
                  autoCorrect={false}
                />
                <ActionButton
                  title="Choose private PEM file (optional)"
                  secondary
                  compact
                  onPress={() => pickPemForImport('private')}
                />
                <ActionButton
                  title="Import and protect key"
                  secondary
                  onPress={importKey}
                  disabled={!keyringReady || Boolean(keyringError)}
                />
              </Panel>

              <View style={styles.rowBetween}>
                <Text style={styles.sectionSmallTitle}>Saved on this device ({keyring.length})</Text>
                <Text style={styles.keyMeta}>Encrypted local storage</Text>
              </View>
              {keyring.length ? (
                keyring.map((key) => (
                  <Panel key={key.id} style={styles.keyPanel}>
                    <View style={styles.rowBetween}>
                      <View style={styles.keyChoiceMain}>
                        <Text style={styles.keyName}>{key.label}</Text>
                        <Text style={styles.keyMeta}>{key.algorithm}</Text>
                        <Text style={styles.keyFingerprint}>SHA-256 · {key.fingerprint}</Text>
                      </View>
                      <Pressable onPress={() => removeKey(key)} style={styles.removeButton}>
                        <Text style={styles.removeText}>Remove</Text>
                      </Pressable>
                    </View>
                    <View style={styles.rowGap}>
                      <ActionButton
                        title="Share public PEM"
                        secondary
                        compact
                        onPress={() => shareKey(key, 'public')}
                      />
                      {key.privateKeyPem ? (
                        <ActionButton
                          title="Share private PEM"
                          secondary
                          compact
                          onPress={() => shareKey(key, 'private')}
                        />
                      ) : null}
                    </View>
                    {key.id === activeKeyId ? <Text style={styles.activeLabel}>ACTIVE FOR ENCRYPTION</Text> : null}
                    {key.id !== activeKeyId ? (
                      <Pressable onPress={() => setActiveKeyId(key.id)}>
                        <Text style={styles.makeActive}>Set active recipient</Text>
                      </Pressable>
                    ) : null}
                  </Panel>
                ))
              ) : (
                <Panel><Text style={styles.emptyHint}>No keys yet. Generate one to encrypt and decrypt images offline.</Text></Panel>
              )}
            </>
          ) : null}

          {tab === 'lab' ? (
            <>
              <SectionTitle
                eyebrow="INTEGRITY & RANDOMNESS"
                title="Inspect the result"
                subtitle="Review byte entropy and demonstrate how AEAD rejects tampering."
              />
              {currentPackage ? (
                <>
                  <Panel>
                    <Text style={styles.fieldLabel}>SHANNON ENTROPY · BITS PER BYTE</Text>
                    <View style={styles.metricRow}>
                      <Metric label="Original" value={`${currentPackage.metrics.originalEntropy.toFixed(3)} / 8`} />
                      <Metric label="Encrypted" value={`${currentPackage.metrics.encryptedEntropy.toFixed(3)} / 8`} />
                    </View>
                    <View style={styles.entropyTrack}>
                      <View
                        style={[
                          styles.entropyFill,
                          { width: `${(currentPackage.metrics.originalEntropy / 8) * 100}%` },
                        ]}
                      />
                    </View>
                    <View style={[styles.entropyTrack, styles.entropyTrackEncrypted]}>
                      <View
                        style={[
                          styles.entropyFillEncrypted,
                          { width: `${(currentPackage.metrics.encryptedEntropy / 8) * 100}%` },
                        ]}
                      />
                    </View>
                    <Histogram ciphertext={currentPackage.demPayload.ciphertext} />
                    <Text style={styles.keyMeta}>
                      This is a byte-frequency visualization, not a proof of cryptographic security.
                    </Text>
                  </Panel>
                  <Panel>
                    <Text style={styles.fieldLabel}>TAMPER LAB</Text>
                    <Text style={styles.bodyMuted}>
                      Flip a bit in the selected field and try local decryption. Authenticated decryption must reject altered data.
                    </Text>
                    <View style={[styles.chipWrap, styles.fieldSpacing]}>
                      {tamperTargets.map(({ id, label }) => (
                        <ChoiceChip
                          key={id}
                          label={label}
                          selected={selectedTamper === id}
                          onPress={() => {
                            setSelectedTamper(id);
                            setTamperResult(null);
                          }}
                        />
                      ))}
                    </View>
                    <ActionButton
                      title="Run offline tamper test"
                      onPress={performTamperTest}
                      disabled={isWorking}
                    />
                    {tamperResult ? (
                      <View style={[styles.resultCard, tamperResult.attackNeutralized ? styles.resultGood : styles.resultBad]}>
                        <Text style={tamperResult.attackNeutralized ? styles.successTitle : styles.errorTitle}>
                          {tamperResult.attackNeutralized ? 'Tampering rejected' : 'Tampering was not detected'}
                        </Text>
                        <Text style={styles.bodyMuted}>{tamperResult.tamperDescription}</Text>
                        {tamperResult.errorMessage ? (
                          <Text style={styles.keyMeta}>{tamperResult.errorMessage}</Text>
                        ) : null}
                      </View>
                    ) : null}
                  </Panel>
                </>
              ) : (
                <Panel>
                  <Text style={styles.emptyHint}>Encrypt an image or import a package to inspect its entropy and run the tamper lab.</Text>
                </Panel>
              )}
            </>
          ) : null}

          <View style={styles.footerNote}>
            <View style={styles.footerRule} />
            <Text style={styles.footerTitle}>OFFLINE CRYPTOGRAPHY</Text>
            <Text style={styles.footerText}>
              RSA-OAEP · ECDH · AES-256-GCM · ChaCha20-Poly1305
            </Text>
            <Text style={styles.footerText}>
              Private-key exports are unencrypted PEM files. Share them only with care.
            </Text>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </View>
  );
}

function TrustItem({ label }: { label: string }) {
  return (
    <View style={styles.trustItem}>
      <Text style={styles.trustCheck}>✓</Text>
      <Text style={styles.trustText}>{label}</Text>
    </View>
  );
}

function Histogram({ ciphertext }: { ciphertext: string }) {
  const bins = useMemo(() => {
    const analysis = performEntropyAnalysis(Buffer.from(ciphertext, 'base64'));
    const overall = analysis.histogram.overall;
    const buckets = Array.from({ length: 32 }, (_, index) => {
      const start = index * 8;
      let sum = 0;
      for (let byte = start; byte < start + 8; byte++) sum += overall[byte];
      return sum;
    });
    const max = Math.max(...buckets, 1);
    return buckets.map((value) => Math.max(3, (value / max) * 100));
  }, [ciphertext]);

  return (
    <View style={styles.histogram}>
      {bins.map((height, index) => (
        <View key={index} style={styles.histogramColumn}>
          <View style={[styles.histogramBar, { height: `${height}%` }]} />
        </View>
      ))}
    </View>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function shortId(value: string): string {
  return value.length > 22 ? `${value.slice(0, 10)}…${value.slice(-7)}` : value;
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: COLORS.background },
  header: {
    paddingTop: Platform.OS === 'android' ? (NativeStatusBar.currentHeight ?? 24) + 6 : 12,
    paddingHorizontal: 18,
    paddingBottom: 12,
    backgroundColor: '#091724',
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  brandRow: { flexDirection: 'row', alignItems: 'center', minHeight: 54 },
  brandIcon: { width: 42, height: 42, marginRight: 10 },
  brandText: { flex: 1 },
  brandName: { color: COLORS.text, fontSize: 19, fontWeight: '800', letterSpacing: 1.1 },
  brandDivider: { color: COLORS.teal },
  brandCaption: { color: COLORS.dim, fontSize: 8, fontWeight: '700', letterSpacing: 2.2, marginTop: 3 },
  deviceBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    borderColor: '#2D6A66',
    borderWidth: 1,
    borderRadius: 20,
    paddingHorizontal: 9,
    paddingVertical: 6,
    backgroundColor: '#0D2A30',
  },
  liveDot: { width: 6, height: 6, borderRadius: 4, backgroundColor: COLORS.teal, marginRight: 6 },
  deviceBadgeText: { color: COLORS.teal, fontSize: 9, fontWeight: '800', letterSpacing: 1 },
  nav: {
    flexDirection: 'row',
    backgroundColor: '#0C1C29',
    borderRadius: 12,
    padding: 4,
    marginTop: 14,
  },
  navItem: { flex: 1, alignItems: 'center', borderRadius: 9, paddingVertical: 10 },
  navItemActive: { backgroundColor: '#193448' },
  navText: { color: COLORS.muted, fontSize: 12, fontWeight: '600' },
  navTextActive: { color: COLORS.teal, fontWeight: '800' },
  content: { flex: 1 },
  scrollContent: { paddingHorizontal: 18, paddingBottom: 38, paddingTop: 20 },
  hero: { marginBottom: 17 },
  heroEyebrow: { color: COLORS.teal, fontSize: 9, fontWeight: '800', letterSpacing: 2.4, marginBottom: 9 },
  heroTitle: { color: COLORS.text, fontSize: 29, fontWeight: '800', lineHeight: 34, letterSpacing: -0.8 },
  heroCopy: { color: COLORS.muted, fontSize: 13, lineHeight: 20, marginTop: 9, maxWidth: 430 },
  trustStrip: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    backgroundColor: '#0B1A27',
    borderColor: COLORS.border,
    borderWidth: 1,
    borderRadius: 12,
    paddingVertical: 12,
    paddingHorizontal: 11,
    marginBottom: 23,
  },
  trustItem: { flexDirection: 'row', alignItems: 'center' },
  trustCheck: { color: COLORS.teal, fontSize: 10, fontWeight: '900', marginRight: 5 },
  trustText: { color: '#B8CAD4', fontSize: 10, fontWeight: '600' },
  sectionHeading: { marginBottom: 13 },
  eyebrow: { color: COLORS.teal, fontSize: 9, fontWeight: '800', letterSpacing: 1.8, marginBottom: 7 },
  sectionTitle: { color: COLORS.text, fontSize: 21, fontWeight: '800', letterSpacing: -0.3 },
  sectionSmallTitle: { color: COLORS.text, fontSize: 13, fontWeight: '700' },
  bodyMuted: { color: COLORS.muted, fontSize: 12, lineHeight: 18, marginTop: 5 },
  panel: {
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 16,
    backgroundColor: COLORS.panel,
    padding: 15,
    marginBottom: 13,
  },
  fieldLabel: { color: '#849DAA', fontSize: 9, fontWeight: '800', letterSpacing: 1.5, marginBottom: 9 },
  fieldSpacing: { marginTop: 17 },
  imagePicker: {
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 154,
    borderWidth: 1,
    borderStyle: 'dashed',
    borderColor: '#36576C',
    borderRadius: 13,
    backgroundColor: '#0A1925',
    padding: 16,
  },
  imageGlyph: {
    width: 36,
    height: 36,
    borderRadius: 12,
    backgroundColor: '#153B44',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 9,
  },
  imageGlyphText: { color: COLORS.teal, fontSize: 24, lineHeight: 28, fontWeight: '400' },
  imagePickerTitle: { color: COLORS.text, fontSize: 13, fontWeight: '700' },
  imagePreviewRow: { flexDirection: 'row', alignItems: 'center', padding: 10, borderRadius: 13, backgroundColor: '#0A1925' },
  imagePreview: { width: 82, height: 82, borderRadius: 10, backgroundColor: '#132A39' },
  imageDetails: { flex: 1, paddingLeft: 12, alignItems: 'flex-start' },
  keyName: { color: COLORS.text, fontSize: 12, fontWeight: '700', lineHeight: 17 },
  keyMeta: { color: COLORS.muted, fontSize: 10, lineHeight: 15, marginTop: 3 },
  chipWrap: { flexDirection: 'row', flexWrap: 'wrap', gap: 7 },
  chip: {
    borderRadius: 9,
    borderWidth: 1,
    borderColor: COLORS.border,
    backgroundColor: '#0A1925',
    paddingHorizontal: 10,
    paddingVertical: 8,
  },
  chipSelected: { borderColor: '#4BAF9F', backgroundColor: '#123A3B' },
  chipText: { color: COLORS.muted, fontSize: 10, fontWeight: '600' },
  chipTextSelected: { color: COLORS.teal, fontWeight: '800' },
  textInput: {
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 10,
    backgroundColor: '#091722',
    color: COLORS.text,
    minHeight: 43,
    paddingHorizontal: 11,
    paddingVertical: 10,
    fontSize: 12,
  },
  pemInput: { minHeight: 100, textAlignVertical: 'top', fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' },
  noteBox: { borderLeftWidth: 2, borderLeftColor: COLORS.teal, backgroundColor: '#102A30', padding: 10, borderRadius: 7, marginTop: 13, marginBottom: 13 },
  noteText: { color: '#A8D8D0', fontSize: 10, lineHeight: 15 },
  warningBox: { borderLeftColor: COLORS.amber, backgroundColor: '#30271D' },
  warningText: { color: '#E7C798', fontSize: 10, lineHeight: 15 },
  button: {
    minHeight: 44,
    paddingHorizontal: 14,
    paddingVertical: 11,
    borderRadius: 10,
    backgroundColor: COLORS.teal,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 12,
  },
  buttonSecondary: { backgroundColor: '#102A38', borderWidth: 1, borderColor: '#325465' },
  buttonCompact: { minHeight: 34, marginTop: 8, paddingVertical: 7, paddingHorizontal: 10 },
  buttonDisabled: { opacity: 0.45 },
  buttonPressed: { opacity: 0.78 },
  buttonText: { color: COLORS.background, fontSize: 12, fontWeight: '800', textAlign: 'center' },
  buttonTextSecondary: { color: '#B8EDE6' },
  selectList: { gap: 7 },
  keyChoice: { flexDirection: 'row', alignItems: 'center', padding: 11, borderWidth: 1, borderColor: COLORS.border, borderRadius: 10, backgroundColor: '#0A1925' },
  keyChoiceActive: { borderColor: '#368C85', backgroundColor: '#102D32' },
  keyChoiceMain: { flex: 1 },
  checkmark: { color: COLORS.teal, fontSize: 17, fontWeight: '800', marginLeft: 10 },
  tealText: { color: COLORS.teal },
  emptyHint: { color: COLORS.muted, fontSize: 11, lineHeight: 17 },
  rowBetween: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', gap: 10 },
  rowGap: { gap: 1 },
  inlineLoading: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  packageCard: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#091722', borderWidth: 1, borderColor: COLORS.border, padding: 11, borderRadius: 12, marginTop: 10 },
  packageIcon: { width: 42, height: 42, borderRadius: 11, backgroundColor: '#163847', alignItems: 'center', justifyContent: 'center' },
  packageIconText: { color: COLORS.teal, fontSize: 23 },
  packageDetails: { flex: 1, paddingLeft: 11 },
  emptyCard: { alignItems: 'center', padding: 13, borderRadius: 12, backgroundColor: '#091722' },
  resultCard: { padding: 12, borderRadius: 12, backgroundColor: '#0D282B', borderWidth: 1, borderColor: '#2B675C', marginTop: 14 },
  resultGood: { backgroundColor: '#0D282B', borderColor: '#2B675C' },
  resultBad: { backgroundColor: '#2C1C22', borderColor: '#72424B' },
  resultWarning: { backgroundColor: '#30271D', borderColor: '#8A683A' },
  resultHeading: { flexDirection: 'row', alignItems: 'center' },
  successDot: { width: 8, height: 8, borderRadius: 5, backgroundColor: COLORS.green, marginRight: 8 },
  warningDot: { width: 8, height: 8, borderRadius: 5, backgroundColor: COLORS.amber, marginRight: 8 },
  successTitle: { color: COLORS.green, fontSize: 12, fontWeight: '800' },
  errorTitle: { color: COLORS.red, fontSize: 12, fontWeight: '800' },
  decryptedPreview: { width: '100%', height: 220, marginVertical: 12, borderRadius: 10, backgroundColor: '#08131D' },
  metricRow: { flexDirection: 'row', gap: 10, marginTop: 9 },
  metric: { flex: 1, padding: 12, borderRadius: 11, backgroundColor: '#091722' },
  metricValue: { color: COLORS.teal, fontSize: 18, fontWeight: '800' },
  metricLabel: { color: COLORS.muted, fontSize: 10, marginTop: 4 },
  entropyTrack: { height: 5, borderRadius: 4, backgroundColor: '#1A2B38', overflow: 'hidden', marginTop: 14 },
  entropyTrackEncrypted: { marginTop: 7 },
  entropyFill: { height: '100%', backgroundColor: COLORS.blue, borderRadius: 4 },
  entropyFillEncrypted: { height: '100%', backgroundColor: COLORS.teal, borderRadius: 4 },
  histogram: { height: 68, flexDirection: 'row', alignItems: 'flex-end', gap: 2, marginTop: 16, marginBottom: 6 },
  histogramColumn: { flex: 1, height: '100%', justifyContent: 'flex-end' },
  histogramBar: { width: '100%', backgroundColor: '#51CDBE', borderTopLeftRadius: 2, borderTopRightRadius: 2, opacity: 0.85 },
  keyPanel: { paddingTop: 13 },
  keyFingerprint: { color: COLORS.dim, fontSize: 9, marginTop: 6, letterSpacing: 0.5 },
  removeButton: { paddingHorizontal: 9, paddingVertical: 7, borderRadius: 8, backgroundColor: '#321F25' },
  removeText: { color: COLORS.red, fontSize: 10, fontWeight: '700' },
  activeLabel: { color: COLORS.teal, fontSize: 9, fontWeight: '800', letterSpacing: 1.1, marginTop: 12 },
  makeActive: { color: COLORS.blue, fontSize: 10, fontWeight: '700', marginTop: 12 },
  footerNote: { alignItems: 'center', paddingTop: 14, paddingBottom: 8 },
  footerRule: { height: 1, backgroundColor: COLORS.border, width: '100%', marginBottom: 18 },
  footerTitle: { color: COLORS.dim, fontSize: 9, letterSpacing: 1.8, fontWeight: '800' },
  footerText: { color: COLORS.dim, fontSize: 9, lineHeight: 16, textAlign: 'center', marginTop: 5 },
});
