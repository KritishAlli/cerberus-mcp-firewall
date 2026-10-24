/** Heuristic secret detection for tool arguments. Return only a boolean; never echo a match. */
const KNOWN_SECRET_PATTERNS = [
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/i,
  /\bglpat-[A-Za-z0-9_-]{20,}\b/i,
];

const LONG_TOKEN = /[A-Za-z0-9+/_=-]{32,}/g;

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function looksLikeHighEntropySecret(value: string): boolean {
  return value.length >= 32 && new Set(value).size >= 12 && shannonEntropy(value) >= 4.0;
}

export function containsSecretPattern(value: string): boolean {
  if (KNOWN_SECRET_PATTERNS.some((pattern) => pattern.test(value))) return true;
  LONG_TOKEN.lastIndex = 0;
  for (const match of value.matchAll(LONG_TOKEN)) {
    if (looksLikeHighEntropySecret(match[0])) return true;
  }
  return false;
}
