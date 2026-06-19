// Client-side secret/PII detector — the privacy-routing policy (ADR-0001 consequence #2).
// A hit FORCES the attested private lane. Runs in the agent BEFORE any bytes leave;
// tempRouter is a blind relay and cannot classify a prompt it cannot read.
//
// Design note: this gate fails *safe* (toward privacy), but precision still matters —
// over-firing routes ordinary prose to the slower, paid private lane and erodes the
// "not sensitive → use a cheaper public model" decision. The seed-phrase and
// credit-card checks below are therefore structural (valid BIP-39 word counts; Luhn),
// not the loose "any 12 lowercase words" / "any 13-16 digits" heuristics they replaced.

export type Detection = { sensitive: boolean; matches: string[] }

const PATTERNS: { label: string; re: RegExp }[] = [
  { label: 'openai-key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { label: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/ },
  { label: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { label: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { label: 'private-key-pem', re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { label: 'hex-private-key', re: /\b0x[a-fA-F0-9]{64}\b/ },
  { label: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { label: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/ },
]

// Valid BIP-39 mnemonic word counts (entropy 128..256 bits → 12/15/18/21/24 words).
const MNEMONIC_LENGTHS = new Set([12, 15, 18, 21, 24])

/**
 * Seed-phrase / mnemonic shape — without shipping a 2048-word list.
 *
 * A BIP-39 mnemonic is a run of EXACTLY 12/15/18/21/24 words that are each 3–8 lowercase
 * letters (every wordlist entry is lowercase, length 3–8) separated only by whitespace.
 * Ordinary prose almost never produces such a run: it is full of 1–2 letter words ("a",
 * "I", "to", "of", "is", "me", "my") and punctuation, each of which breaks the run. We look
 * for a maximal whitespace-separated run of 3–8 letter lowercase words whose length is a
 * valid mnemonic count — precise enough to catch a pasted seed phrase without flagging
 * normal sentences (the loose "any 12+ lowercase words" rule flagged everyday prose).
 */
function looksLikeSeedPhrase(text: string): boolean {
  const runs = text.match(/\b[a-z]{3,8}(?:\s+[a-z]{3,8})*\b/g) ?? []
  return runs.some((run) => MNEMONIC_LENGTHS.has(run.split(/\s+/).length))
}

// Luhn check — the checksum every real payment-card number satisfies.
function luhnValid(digits: string): boolean {
  let sum = 0
  let dbl = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (dbl) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
    dbl = !dbl
  }
  return sum % 10 === 0
}

/** Credit-card shape: a 13–19 digit run (optionally space/hyphen separated) that passes Luhn. */
function looksLikeCreditCard(text: string): boolean {
  for (const m of text.matchAll(/\b(?:\d[ -]?){12,18}\d\b/g)) {
    const digits = m[0].replace(/[ -]/g, '')
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) return true
  }
  return false
}

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
  if (looksLikeSeedPhrase(prompt)) matches.push('seed-phrase')
  if (looksLikeCreditCard(prompt)) matches.push('credit-card')
  if (hasHighEntropyToken(prompt)) matches.push('high-entropy-token')
  return { sensitive: matches.length > 0, matches }
}
