# KEM-DEM Image Cryptosystem

This project is a full-stack, browser-based cryptography demo that shows how a Key Encapsulation Mechanism (KEM) and Data Encapsulation Mechanism (DEM) are combined to encrypt and decrypt image data securely.

The app demonstrates the classic hybrid encryption pattern:

- Use an asymmetric public-key algorithm to wrap a random session key
- Use a symmetric AEAD cipher to encrypt the actual image bytes
- Package the encrypted image and key material into a single `KEM-DEM` artifact
- Verify integrity with authenticated encryption tags and demonstrate tamper resistance

This is primarily a learning and visualization project, not a hardened production cryptography library. It is designed to help users understand the difference between key establishment and bulk-data encryption, and to visually prove why AEAD and KEM/DEM patterns are important in modern secure systems.

## What the app does

The UI lets you:

- Generate or import asymmetric key pairs for KEM
- Encrypt a local image or one of the built-in demo samples
- Choose between key encapulation algorithms such as RSA-OAEP and ECDH-based schemes
- Encrypt the image using AES-256-GCM or ChaCha20-Poly1305
- Decrypt the image using the matching private key
- Inspect entropy before and after encryption
- Simulate bit-flip tampering attacks to see that authentication fails immediately

The app is intentionally designed to make the cryptographic pipeline visible rather than hiding it behind opaque implementation details.

## High-level architecture

The codebase is split into a React frontend and an Express backend.

### Frontend (`client/`)

The frontend is a Vite + React application.

Key files:

- `client/App.tsx` – top-level app shell and tab management
- `client/components/ImageEncryptor.tsx` – image upload, key selection, encryption flow, and noise rendering
- `client/components/ImageDecryptor.tsx` – package loading, private key selection, and decryption flow
- `client/components/KeyManager.tsx` – generate/import keys and manage active recipients
- `client/components/EntropyInspector.tsx` – shows Shannon entropy before/after encryption
- `client/components/TamperLab.tsx` – simulates tampering and demonstrates tag verification
- `client/components/ArchitectureDiagram.tsx` – educational pipeline diagram explaining KEM-DEM
- `client/crypto/webCryptoKemDem.ts` – browser-side encryption/decryption logic using Web Crypto API

### Backend (`server/`)

The backend is an Express service that provides API routes used by the frontend and also implements the cryptographic logic in Node.js.

Key files:

- `server.ts` – starts Express, mounts the API router, and serves the Vite app in development
- `server/routes/api.ts` – all `/api/kem-dem/*` endpoints
- `server/crypto/kem.ts` – KEM generation, encapsulation, and decapsulation
- `server/crypto/dem.ts` – DEM encryption/decryption using AEAD modes
- `server/crypto/entropy.ts` – Shannon entropy and histogram analysis
- `server/crypto/samples.ts` – built-in demo image payloads
- `server/types/kemdem.ts` – backend data model for package format and results

### Shared type contracts

The frontend and backend both model the same KEM-DEM artifact structure.

- `client/types/crypto.ts` – frontend types
- `server/types/kemdem.ts` – backend types

The main artifact shape looks like this:

- `sourceImage` – original image metadata and SHA-256 hash
- `kemHeader` – KEM algorithm, encapsulated key material, and optional metadata
- `demPayload` – IV, ciphertext, tag, and AAD
- `metrics` – performance and entropy stats

## How the cryptography works

### 1) KEM stage: establish a symmetric key

A fresh random symmetric session key is generated for the image. That key is then wrapped using the recipient's public key.

Supported KEM algorithms include:

- `RSA-OAEP-2048`
- `RSA-OAEP-3072`
- `RSA-OAEP-4096`
- `ECDH-P256`
- `ECDH-P384`
- `ECDH-X25519`
- `HYBRID-PQ`

In the Node.js backend, this happens in `server/crypto/kem.ts`:

- `generateKemKeyPair()` creates RSA or EC key pairs
- `encapsulateKey()` wraps a random 32-byte session key with the recipient public key or derives a shared secret with ECDH/HKDF
- `decapsulateKey()` unwraps it using the corresponding private key

Why this is useful:

- asymmetric encryption is expensive and limited in size
- the KEM is only used to establish a short, high-entropy session key
- the actual image is encrypted with a fast symmetric cipher

### 2) DEM stage: encrypt the image

Once the session key is established, the image is encrypted using an AEAD scheme.

Supported DEM algorithms include:

- `AES-256-GCM`
- `CHACHA20-POLY1305`

In `server/crypto/dem.ts`:

- a random IV/nonce is generated
- the image bytes are encrypted using the symmetric key
- a 128-bit authentication tag is created
- options such as AAD (Additional Authenticated Data) can be included

This is important because the authentication tag binds the ciphertext and metadata together. If any bit is changed, the decryptor will reject the package.

### 3) Artifact packaging

The app serializes the result as a `KEM-DEM-V1` package that includes:

- `kemHeader.c_kem` – the encapsulated key material
- `demPayload.iv` – nonce/IV
- `demPayload.ciphertext` – encrypted image bytes
- `demPayload.tag` – authentication tag
- `demPayload.aad` – optional metadata bound to the payload

The package is then treated like a portable encrypted artifact. The session key is not stored in the package; it is recovered only by the recipient using the private key.

### 4) Decrypting and verifying

On decrypt:

- the recipient private key is used to decapsulate the session key
- the sender's symmetric key is recovered
- the payload is decrypted with the corresponding AEAD cipher
- the tag is checked before any plaintext is released

If the ciphertext, IV, tag, or AAD has been tampered with, the decryption fails with a cryptographic integrity error instead of returning corrupted data.

## Entropy analysis

The project includes a Shannon entropy view to visualize how random the plaintext and ciphertext look.

File:

- `server/crypto/entropy.ts`

The app computes:

- original image entropy
- ciphertext entropy
- a histogram over byte frequencies

A normal image tends to have structured patterns and lower entropy. Encrypted data tends toward the theoretical maximum (~8 bits/byte), which visually proves that the ciphertext looks random and has no obvious structure.

<!-- ## Tamper laboratory

The project includes a built-in tampering simulator that flips a single bit in:

- the KEM header
- ciphertext
- IV
- tag
- AAD

This demonstrates that authenticated encryption prevents bit-flip attacks and metadata tampering. The failure is immediate and intentional: decryption is rejected, and no plaintext is released.

This is the educational version of the security guarantee behind AEAD primitives and the reason authenticating the ciphertext matters. -->

## API surface

The Express server exposes the following main routes:

### Key generation

- `POST /api/kem-dem/keygen`

Body:

```json
{
  "algorithm": "RSA-OAEP-2048",
  "label": "Default Recipient Key"
}
```

Response:

```json
{
  "success": true,
  "keyPair": {
    "id": "key_...",
    "label": "...",
    "algorithm": "RSA-OAEP-2048",
    "publicKeyPem": "-----BEGIN PUBLIC KEY----- ...",
    "privateKeyPem": "-----BEGIN PRIVATE KEY----- ...",
    "fingerprint": "..."
  }
}
```

### Encryption

- `POST /api/kem-dem/encrypt`

Body includes:

- `imageData` – a data URL or raw image payload
- `imageName`
- `mimeType`
- `width`
- `height`
- `recipientPublicKeyPem`
- `kemAlgorithm`
- `demAlgorithm`
- `aad`

Returns:

- `success`
- `package` – the `KEM-DEM-V1` package
- `noiseData` – a visual noise blob representing the encrypted data

### Decryption

- `POST /api/kem-dem/decrypt`

Body includes:

```json
{
  "package": { "format": "KEM-DEM-V1", "...": "..." },
  "recipientPrivateKeyPem": "-----BEGIN PRIVATE KEY----- ..."
}
```

Returns a `DecryptionResult` with:

- `success`
- `decryptedDataUrl`
- `decryptedSha256`
- `isLosslessMatch`
- `decapsulationTimeMs`
- `decryptionTimeMs`
- `totalDecryptionTimeMs`
- `entropy`

### Tamper tests

- `POST /api/kem-dem/tamper-test`

This flips bits in the encrypted package to emulate an attack and reports whether the decryption path rejects it.

### Entropy analysis

- `POST /api/kem-dem/entropy-analysis`

Returns Shannon entropy and byte histogram data for an image or ciphertext.

### Sample images

- `GET /api/kem-dem/samples`

Returns built-in sample images for demonstration.

## Project structure

```text
.
├── client/
│   ├── App.tsx
│   ├── components/
│   ├── crypto/
│   ├── index.css
│   ├── main.tsx
│   └── types/
├── server/
│   ├── crypto/
│   ├── routes/
│   └── types/
├── .env.example
├── .gitignore
├── index.html
├── package.json
├── server.ts
├── tsconfig.json
├── vite.config.ts
├── README.md
└── dist/
```

## Exactly how to run it

### Prerequisites

Install Node.js 18 or newer. This project uses:

- Vite for frontend bundling
- React 19
- Express for the API server
- Node's built-in crypto library for KEM/DEM logic

### 1) Install dependencies

From the project root:

```bash
npm install
```

### 2) Start the app in development mode

```bash
npm run dev
```

This starts the Express server and serves the frontend through Vite in middleware mode.

By default, the server listens on port `3000`:

```text
http://localhost:3000
```

If port `3000` is already in use, set a different port:

```bash
PORT=3001 npm run dev
```

Then open:

```text
http://localhost:3001
```

### 3) Production build and run

Build the app first:

```bash
npm run build
```

Then run the production server:

```bash
NODE_ENV=production npm run start
```

This serves the static `dist/` output from Express. The server still defaults to port `3000`, unless you set `PORT`:

```bash
PORT=3001 NODE_ENV=production npm run start
```

### 4) Use the app

Once the app is running:

1. Open the app in a browser.
2. The app automatically fetches sample images and creates a default RSA key pair.
3. Go to the Encrypt tab.
4. Select an image or sample.
5. Choose a recipient key and KEM/DEM settings.
6. Click Encrypt.
7. Switch to Decrypt and use the matching private key to recover the image.
8. Explore the entropy telemetry and tamper lab.

## Useful scripts

From `package.json`:

```bash
npm run dev     # start dev server
npm run build   # build frontend bundle
npm run start   # start Express server (development or production workflow)
npm run lint    # TypeScript check via tsc --noEmit
npm run preview # local preview of production build
```

## Troubleshooting

### Port already in use

The Express server binds to port `3000` by default unless `PORT` is set. If another service is already using it, use:

```bash
PORT=3001 npm run dev
```

### Browser cannot decrypt or key not found

Make sure the private key matches the same recipient public key used during encryption. The app also supports uploading a matching private PEM file manually.

### Encryption/decryption fails with tag mismatch

That is the expected security behavior if the ciphertext, IV, tag, or AAD is modified. The app intentionally demonstrates this in the Tamper Lab.

## Security note

This project is a demonstration of cryptographic design and protocol composition. It is a useful teaching tool for understanding modern hybrid encryption, but it should not be treated as a complete, audited production implementation.

Real-world systems should additionally consider:

- secure private key storage
- certificate management and trust chains
- key rotation and revocation
- proper serialization standards for encrypted bundles
- threat modeling and operational security

## Summary

The application turns a classic cryptographic design into an interactive visual demonstration:

- KEM establishes a random session key securely
- DEM encrypts the payload with authenticated encryption
- package serialization keeps the key and ciphertext together in a portable format
- integrity checks guarantee tampering is detected
- entropy analysis confirms the ciphertext is effectively random

If you want to understand modern hybrid encryption in a practical, visual way, this project is designed to make the pipeline recognizable, measurable, and easy to explore.
