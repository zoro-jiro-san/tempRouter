import { describe, it, expect } from 'vitest'
import { detectSensitive } from '@temprouter/sdk'

// These fixtures are secret-SHAPED but synthetic, and are assembled from fragments so no
// literal credential pattern is committed to source (keeps secret scanners quiet). The
// strings still match the detector's regexes at runtime — that's exactly what we test.
const SK = 'sk-' + 'proj-' + 'a1b2c3d4e5f6g7h8i9j0klmnop'
const SK_ANT = 'sk-' + 'ant-' + 'api03-' + 'abcdefghijklmnopqrstuvwx'
const AKIA = 'AKIA' + 'IOSFODNN7EXAMPLE'
const GH = 'gh' + 'p_' + '0123456789abcdefghijklmnopqrstuvwxyz'
const SLACK = 'xox' + 'b-' + '1234567890-abcdefghij'
const PEM = '-----BEGIN ' + 'OPENSSH ' + 'PRIVATE KEY-----\nabc'
const JWT = 'eyJ' + 'hbGciOiJIUzI1NiJ9.' + 'eyJzdWIiOiIxMjM0NTY3.' + 'dBjftJeZ4CVPmB92'
const CARD = '4242 '.repeat(4).trim() // Luhn-valid (canonical test card), no contiguous literal
const HEX_PK = '0x' + 'a'.repeat(64)

describe('detectSensitive — known secret shapes (positives)', () => {
  const cases: [string, string, string][] = [
    ['openai-key', `rotate ${SK} now`, 'openai-key'],
    ['anthropic-key', `key is ${SK_ANT}`, 'anthropic-key'],
    ['aws-access-key', `creds ${AKIA} leaked`, 'aws-access-key'],
    ['github-token', `token ${GH}`, 'github-token'],
    ['slack-token', `${SLACK} in logs`, 'slack-token'],
    ['hex-private-key', `pk ${HEX_PK}`, 'hex-private-key'],
    ['jwt', `auth ${JWT}`, 'jwt'],
    ['email', 'contact jane.doe@example.com please', 'email'],
  ]
  for (const [name, input, label] of cases) {
    it(`flags ${name}`, () => {
      const d = detectSensitive(input)
      expect(d.sensitive).toBe(true)
      expect(d.matches).toContain(label)
    })
  }

  it('flags a PEM private key block', () => {
    expect(detectSensitive(PEM).matches).toContain('private-key-pem')
  })

  it('flags a high-entropy token without a known shape', () => {
    expect(detectSensitive('token Zk9Q2mX7pL4vR8nT1wY6bC3dF5gH0jK2').matches).toContain('high-entropy-token')
  })
})

describe('detectSensitive — seed phrases (the over-firing regression)', () => {
  // Canonical BIP-39 test vector (12 words, all valid wordlist entries).
  const mnemonic12 =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
  const mnemonic24 = (mnemonic12 + ' ' + mnemonic12).split(' ').slice(0, 24).join(' ')

  it('flags a real 12-word mnemonic', () => {
    expect(detectSensitive(mnemonic12).matches).toContain('seed-phrase')
  })

  it('flags a real 24-word mnemonic', () => {
    expect(detectSensitive(mnemonic24).matches).toContain('seed-phrase')
  })

  it('does NOT flag ordinary 12+ word prose (regression)', () => {
    const prose =
      'can you please help me write a short friendly email to my landlord about the broken kitchen sink today'
    const d = detectSensitive(prose)
    expect(d.matches).not.toContain('seed-phrase')
    expect(d.sensitive).toBe(false)
  })

  it('does NOT flag a normal short request', () => {
    expect(detectSensitive('summarize this article for me please').sensitive).toBe(false)
  })

  it('does NOT flag a run of 13 clean words (not a valid mnemonic count)', () => {
    const thirteen = Array.from({ length: 13 }, () => 'travel').join(' ')
    expect(detectSensitive(thirteen).matches).not.toContain('seed-phrase')
  })
})

describe('detectSensitive — credit cards (Luhn, not any 13–16 digits)', () => {
  it('flags a Luhn-valid card number', () => {
    expect(detectSensitive(`card ${CARD} on file`).matches).toContain('credit-card')
  })

  it('does NOT flag a Luhn-invalid 16-digit number', () => {
    expect(detectSensitive('order id 1234567890123456 shipped').matches).not.toContain('credit-card')
  })
})

describe('detectSensitive — clean negatives', () => {
  for (const input of [
    'what is the capital of France',
    'refactor this function to be more readable',
    'explain how photosynthesis works in plants',
  ]) {
    it(`treats as not sensitive: "${input.slice(0, 24)}…"`, () => {
      expect(detectSensitive(input).sensitive).toBe(false)
    })
  }
})
