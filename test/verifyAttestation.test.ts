import { describe, it, expect } from 'vitest'
import { verifyQuote, verifyAttestation, formatReport } from '@temprouter/sdk'

// These cover the load-bearing security property: the verifier FAILS CLOSED on anything
// that isn't a genuine, non-null Intel TDX quote, *before* any DCAP/network work — so a
// stub or a swapped/absent enclave can never produce a passing report (→ zero vouchers).
// The positive DCAP path needs live Intel collateral and is exercised by
// scripts/capture-fixture.ts against the real enclave, not in unit tests.

describe('verifyQuote — pre-pay gate fails closed', () => {
  it('rejects the STUB-NO-TDX attestation (no real enclave)', async () => {
    const r = await verifyQuote({ teeType: 'STUB-NO-TDX', tdxQuote: null })
    expect(r.ok).toBe(false)
  })

  it('rejects INTEL-TDX-PHALA with a null quote', async () => {
    const r = await verifyQuote({ teeType: 'INTEL-TDX-PHALA', tdxQuote: null })
    expect(r.ok).toBe(false)
  })

  it('rejects a missing teeType', async () => {
    const r = await verifyQuote({ tdxQuote: null } as never)
    expect(r.ok).toBe(false)
    expect(r.checks[0].pass).toBe(false)
  })
})

describe('verifyAttestation — post-pay receipt fails closed', () => {
  it('rejects a stub receipt', async () => {
    const r = await verifyAttestation({
      response: { attestation: { teeType: 'STUB-NO-TDX', tdxQuote: null } },
      encryptedPrompt: '{}',
      model: 'nosana:gpt-oss:20b',
    })
    expect(r.ok).toBe(false)
  })

  it('rejects a real-looking attestation that is missing the encryptionProof', async () => {
    const r = await verifyAttestation({
      response: { attestation: { teeType: 'INTEL-TDX-PHALA', tdxQuote: { quote: 'deadbeef' } } },
      encryptedPrompt: '{}',
      model: 'nosana:gpt-oss:20b',
    })
    expect(r.ok).toBe(false)
  })
})

describe('formatReport', () => {
  it('renders a failing report with the refusal line', async () => {
    const r = await verifyQuote({ teeType: 'STUB-NO-TDX', tdxQuote: null })
    const out = formatReport(r)
    expect(out).toContain('❌')
    expect(out).toContain('refusing to pay')
  })
})
