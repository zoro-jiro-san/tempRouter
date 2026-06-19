// Capture a real /tee/process fixture from prod and validate verifyAttestation()
// end-to-end. Permission granted 2026-06-16. Run: npx tsx scripts/capture-fixture.ts
import { encrypt, packageForTEE } from '@solrouter/sdk'
import { writeFileSync, mkdirSync } from 'node:fs'
import { verifyAttestation, formatReport } from '@temprouter/sdk'

const BASE = 'https://solrouter-obb4.onrender.com' // SDK appends /tee/public-key etc.
const MODEL = 'nosana:gpt-oss:20b' // must match enclave signing convention (verify-attestation.mjs)
const PROMPT = 'tempRouter fixture capture — verify the attested private lane.'

const enc = await encrypt(PROMPT, BASE)
const encryptedPrompt = packageForTEE(enc)
console.log('→ POST', BASE + '/tee/process')
const res = await fetch(`${BASE}/tee/process`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ encryptedPrompt, model: MODEL }),
})
const body: any = await res.json()
console.log('status:', res.status, '| has encryptionProof:', !!body.encryptionProof, '| teeType:', body.attestation?.teeType)

mkdirSync('fixtures', { recursive: true })
// Save the response + the encryptedPrompt (needed to re-verify the ed25519 sig over the ciphertext).
writeFileSync('fixtures/process.json', JSON.stringify({ encryptedPrompt, model: MODEL, response: body }, null, 2))
console.log('saved fixtures/process.json')

console.log('\n── verifyAttestation() against the real receipt ──')
const report = await verifyAttestation({
  response: { attestation: body.attestation, encryptionProof: body.encryptionProof },
  encryptedPrompt,
  model: MODEL,
})
console.log(formatReport(report))
process.exit(report.ok ? 0 : 1)
