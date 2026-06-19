// Client-side secret/PII detector — the privacy-routing policy (ADR-0001 consequence #2).
// A hit FORCES the attested private lane. Runs in the agent BEFORE any bytes leave;
// tempRouter is a blind relay and cannot classify a prompt it cannot read.

export type Detection = { sensitive: boolean; matches: string[] }

const PATTERNS: { label: string; re: RegExp }[] = [
  { label: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { label: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { label: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { label: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'private-key-pem', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { label: 'hex-private-key', re: /\b0x[a-fA-F0-9]{64}\b/ },
  { label: 'solana-seed-phrase', re: /\b(?:[a-z]+\s+){11,23}[a-z]+\b/ }, // 12/24-word mnemonic shape
  { label: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { label: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
  { label: 'credit-card', re: /\b(?:\d[ -]?){13,16}\b/ },
]

// Shannon entropy — catches high-entropy secrets that don't match a known shape.
function entropy(s: string): number {
  const freq: Record<string, number> = {}
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1
  return -Object.values(freq).reduce((h, n) => {
    const p = n / s.length
    return h + p * Math.log2(p)
  }, 0)
}

function hasHighEntropyToken(text: string): boolean {
  for (const tok of text.split(/\s+/)) {
    if (tok.length >= 24 && /[A-Za-z]/.test(tok) && /[0-9]/.test(tok) && entropy(tok) > 3.6) return true
  }
  return false
}

/** Returns whether the prompt contains secrets/PII that must use the private lane. */
export function detectSensitive(prompt: string): Detection {
  const matches: string[] = []
  for (const { label, re } of PATTERNS) if (re.test(prompt)) matches.push(label)
  if (hasHighEntropyToken(prompt)) matches.push('high-entropy-token')
  return { sensitive: matches.length > 0, matches }
}
