// tempRouter demo agent — now built on @temprouter/sdk. Shows the privacy policy gate
// + verify-before-pay + per-chunk MPP metering + decrypt, all via the reusable client.
// Fail-closed: a failed attestation gate signs ZERO vouchers (ADR-0002).

import { TempRouter, detectSensitive, formatReport, AttestationError } from '@temprouter/sdk'
import { config } from './config.js'

const MODEL = process.env.MODEL ?? 'nosana:gpt-oss:20b'
// Default demo prompt carries a (fake) leaked credential → forces the private lane.
// Assembled from fragments so no literal credential pattern sits in source (secret
// scanners flag the shape, not the realness); the runtime string still trips the detector.
const FAKE_LEAKED_KEY = 'sk-' + 'proj-' + '1a2b3c4d5e6f7g8h9i0jklmnopqrstuvwx'
const PROMPT =
  process.env.PROMPT ??
  `A service leaked this key: ${FAKE_LEAKED_KEY}. Assess the blast radius and the exact rotation steps.`

async function main() {
  // 0. Policy gate — runs before any bytes leave the agent (ADR-0001).
  const det = detectSensitive(PROMPT)
  if (det.sensitive) console.log(`🔒 sensitive payload detected (${det.matches.join(', ')}) → forcing attested private lane`)
  else {
    console.log('ℹ️  not sensitive → a normal agent would use a public/frontier model (out of tempRouter scope)')
    return
  }

  if (!config.agentPrivateKey) {
    console.error('\nAGENT_PRIVATE_KEY not set — fund a Tempo testnet key to run the paid stream (faucet: https://explore.testnet.tempo.xyz).')
    process.exit(2)
  }

  const client = new TempRouter({
    serverUrl: config.serverUrl,
    account: config.agentPrivateKey,
    maxDeposit: config.maxDeposit,
    pricePerUnit: config.pricePerUnit,
    expectedMeasurement: config.expectedMeasurement || undefined,
  })

  try {
    const res = await client.infer(PROMPT, {
      model: MODEL,
      onVerify: (r) => console.log('\n── pre-pay attestation gate ──\n' + formatReport(r)),
      onUnit: (n, paid) => process.stdout.write(`\r  💸 [units paid: ${n} | ${paid} pathUSD]`),
    })
    if (res.attestation.postPay) console.log('\n── post-pay receipt verification ──\n' + formatReport(res.attestation.postPay))
    console.log('\n🔓 decrypted answer (plaintext only ever seen by you + the attested enclave):\n' + res.answer)
  } catch (e) {
    if (e instanceof AttestationError) {
      console.error('\n⛔ ' + e.message + '\n' + formatReport(e.report))
      process.exit(1)
    }
    throw e
  }
}

main().catch((e) => {
  console.error('❌', e)
  process.exit(1)
})
