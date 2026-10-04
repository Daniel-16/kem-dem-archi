import type { EntropyAnalysis } from '../types/kemdem.js';

export function calculateBufferEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;

  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    frequencies[buffer[i]]++;
  }

  let entropy = 0;
  const total = buffer.length;

  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / total;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 1000) / 1000;
}

export function generateHistogram(buffer: Buffer): {
  red: number[];
  green: number[];
  blue: number[];
  overall: number[];
} {
  const overall = new Array(256).fill(0);
  const red = new Array(256).fill(0);
  const green = new Array(256).fill(0);
  const blue = new Array(256).fill(0);

  const sampleLimit = Math.min(buffer.length, 200000);
  for (let i = 0; i < sampleLimit; i++) {
    const val = buffer[i];
    overall[val]++;
    const mod = i % 3;
    if (mod === 0) red[val]++;
    else if (mod === 1) green[val]++;
    else blue[val]++;
  }

  return { red, green, blue, overall };
}

export function performEntropyAnalysis(buffer: Buffer): EntropyAnalysis {
  const entropy = calculateBufferEntropy(buffer);
  const histogram = generateHistogram(buffer);
  const isTheoreticalNoise = entropy >= 7.95;

  return {
    entropy,
    byteCount: buffer.length,
    histogram,
    isTheoreticalNoise,
  };
}
