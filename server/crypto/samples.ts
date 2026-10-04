import type { SampleImage } from '../types/kemdem.js';

// Clean SVG data URLs that render realistic test images
const sample1Svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400" width="400" height="400">
  <rect width="400" height="400" fill="#090d16"/>
  <circle cx="200" cy="200" r="160" fill="#111827" stroke="#06b6d4" stroke-width="2"/>
  <ellipse cx="200" cy="200" rx="120" ry="140" fill="#1e293b"/>
  <path d="M140 160 Q 200 120 260 160 Q 240 240 200 270 Q 160 240 140 160 Z" fill="#334155" opacity="0.8"/>
  <circle cx="170" cy="180" r="25" fill="#38bdf8" opacity="0.3"/>
  <circle cx="230" cy="180" r="25" fill="#38bdf8" opacity="0.3"/>
  <circle cx="200" cy="220" r="15" fill="#f43f5e" opacity="0.7"/>
  <text x="20" y="380" fill="#94a3b8" font-family="monospace" font-size="12">NEURO-SCAN // PATIENT #4829-X</text>
  <line x1="20" y1="200" x2="380" y2="200" stroke="#06b6d4" stroke-dasharray="4 4" stroke-width="1" opacity="0.5"/>
  <line x1="200" y1="20" x2="200" y2="380" stroke="#06b6d4" stroke-dasharray="4 4" stroke-width="1" opacity="0.5"/>
</svg>`;

const sample2Svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400" width="400" height="400">
  <rect width="400" height="400" fill="#030712"/>
  <defs>
    <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
      <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1e293b" stroke-width="1"/>
    </pattern>
  </defs>
  <rect width="400" height="400" fill="url(#grid)"/>
  <rect x="50" y="50" width="300" height="300" fill="none" stroke="#3b82f6" stroke-width="2"/>
  <rect x="80" y="80" width="100" height="120" fill="#1e3a8a" opacity="0.6"/>
  <rect x="220" y="80" width="100" height="80" fill="#1e3a8a" opacity="0.6"/>
  <rect x="120" y="240" width="160" height="80" fill="#047857" opacity="0.6"/>
  <circle cx="200" cy="160" r="20" fill="#f59e0b"/>
  <text x="60" y="40" fill="#60a5fa" font-family="monospace" font-weight="bold" font-size="12">ARCHITECTURAL BLUEPRINT // SECTOR 7G</text>
  <text x="60" y="375" fill="#94a3b8" font-family="monospace" font-size="10">SCALE: 1:500 | CLASSIFIED ASSET</text>
</svg>`;

const sample3Svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400" width="400" height="400">
  <rect width="400" height="400" fill="#0f172a"/>
  <rect x="40" y="60" width="320" height="280" rx="8" fill="#1e293b" stroke="#475569" stroke-width="2"/>
  <rect x="40" y="60" width="320" height="45" fill="#334155"/>
  <text x="60" y="88" fill="#f8fafc" font-family="sans-serif" font-weight="bold" font-size="14">SECURITY CLEARANCE CREDENTIAL</text>
  <rect x="65" y="130" width="80" height="100" rx="4" fill="#0f172a" stroke="#64748b"/>
  <circle cx="105" cy="165" r="22" fill="#94a3b8"/>
  <path d="M80 220 Q 105 195 130 220 Z" fill="#64748b"/>
  <rect x="165" y="140" width="160" height="14" rx="2" fill="#475569"/>
  <rect x="165" y="165" width="120" height="10" rx="2" fill="#334155"/>
  <rect x="165" y="185" width="140" height="10" rx="2" fill="#334155"/>
  <rect x="165" y="210" width="90" height="16" rx="4" fill="#ef4444"/>
  <text x="175" y="222" fill="#ffffff" font-family="sans-serif" font-weight="bold" font-size="10">LEVEL 5 ACCESS</text>
  <rect x="65" y="260" width="270" height="35" fill="#090d16" stroke="#334155"/>
  <text x="80" y="282" fill="#22c55e" font-family="monospace" font-size="12">UUID: 8F92-B41E-KEM-DEM-KEY</text>
</svg>`;

export const SAMPLE_IMAGES: SampleImage[] = [
  {
    id: 'sample-mri',
    name: 'Medical MRI Neuro-Scan',
    description: 'High-contrast anatomical scan with fine localized structural data',
    category: 'Healthcare & Medical',
    dataUrl: `data:image/svg+xml;utf8,${encodeURIComponent(sample1Svg)}`,
    width: 400,
    height: 400,
  },
  {
    id: 'sample-blueprint',
    name: 'Confidential Sector Blueprint',
    description: 'Technical CAD layout containing geometric vectors and grid features',
    category: 'Engineering & CAD',
    dataUrl: `data:image/svg+xml;utf8,${encodeURIComponent(sample2Svg)}`,
    width: 400,
    height: 400,
  },
  {
    id: 'sample-id',
    name: 'Defense Clearance Credential',
    description: 'Identity document with biometric photo, barcode, and clearance level',
    category: 'Identity & Access',
    dataUrl: `data:image/svg+xml;utf8,${encodeURIComponent(sample3Svg)}`,
    width: 400,
    height: 400,
  },
];
