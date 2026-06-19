import { describe, it, expect } from 'vitest'
import { detectSensitive } from '@temprouter/sdk'

describe('detectSensitive — known secret shapes (positives)', () => {
  const cases: [string, string, string][] = [
    ['openai-key', 'rotate sk-proj-1a2b3c4d5e6f7g8h9i0jklmnopqrstuv now', 'openai-key'],
    ['anthropic-key', 'key is sk-ant-api03-abcdefghijklmnopqrstuvwx', 'anthropic-key'],
    ['aws-access-key', 'creds AKIAIOSFODNN7EXAMPLE leaked', 'aws-access-key'],
    ['github-token', 'token ghp_0123456789abcdefghijklmnopqrstuvwxyz', 'github-token'],
    ['slack-token', 'xoxb-1234567890-abcdefghij in logs', 'slack-token'],
    ['hex-private-key', 'pk 0x' + 'a'.repeat(64), 'hex-private-key'],
    ['jwt', 'auth eyJhbGciOiJIUzI1Ni009.eyJzdWIiOiIxMjM0NTY3.dBjftJeZ4CVPmB92', 'jwt'],
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
    expect(detectSensitive('-----BEGIN OPENSSH PRIVATE KEY-----\nabc').matches).toContain('private-key-pem')
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
    expect(detectSensitive('card 4242 4242 4242 4242 on file').matches).toContain('credit-card')
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
