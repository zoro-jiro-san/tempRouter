#!/usr/bin/env -S npx tsx
// tempRouter use-case runner — three confidential-compute scenarios that each genuinely
// need a blind, attested lane (a public model host would see the secret/PII). Each runs
// the full dance via @temprouter/sdk: detect → verify (Intel DCAP) → encrypt → pay per
// response-chunk in pathUSD on Tempo → decrypt locally.
//
// Run (needs a funded Tempo testnet key + network egress to the server, enclave, and RPC):
//   AGENT_PRIVATE_KEY=0x… SERVER_URL=https://temprouter.onrender.com npm run usecases
// Dry run (no key/network) prints only the local detector verdict for each case.
//
// Secret-shaped inputs are assembled from fragments so no literal credential is committed.

import process from 'node:process'
import { TempRouter, detectSensitive, formatReport, AttestationError } from '@temprouter/sdk'

const SERVER_URL = (process.env.SERVER_URL ?? 'https://temprouter.onrender.com').replace(/\/$/, '')
const KEY = (process.env.AGENT_PRIVATE_KEY ?? '') as `0x${string}` | ''
const MODEL = process.env.MODEL ?? 'nosana:gpt-oss:20b'

// ── Synthetic-but-realistic inputs (built from fragments; never literal secrets) ──
const FAKE_API_KEY = 'sk-' + 'proj-' + 'Xy7Qa2Lp9Vc4Rb6Nd1Mf3Tg8'
const CUSTOMER_EMAIL = 'jane.doe' + '@' + 'acme-customer.com'
const FAKE_PRIVKEY = '0x' + 'a1b2c3d4'.repeat(8) // 64 hex → hex-private-key shape

type UseCase = { id: string; title: string; whyConfidential: string; prompt: string }

const USE_CASES: UseCase[] = [
  {
    id: 'incident-response',
    title: 'Leaked credential → incident-response runbook',
    whyConfidential:
      'A live API key surfaced in logs. Pasting it into a public model host would re-leak it; the analysis must run somewhere that provably cannot read it.',
    prompt:
      `Our log shipper exposed this production key: ${FAKE_API_KEY}. ` +
      'Give me the blast radius and an ordered rotation runbook (revoke, re-issue, redeploy, audit).',
  },
  {
    id: 'pii-support-triage',
    title: 'Customer-support ticket with PII → triage + safe reply',
    whyConfidential:
      'The ticket carries a real customer email (and could carry more PII). Sending it to a third-party model host is a data-processing/GDPR problem — the private lane keeps it confidential.',
    prompt:
      `Support ticket from ${CUSTOMER_EMAIL} (phone 555-0142): "I was double-charged on order #A-3391 ` +
      'and need a refund today, I am furious." Classify urgency, list every piece of PII present, and ' +
      'draft a calm, GDPR-safe reply that does not echo the PII back in plaintext.',
  },
  {
    id: 'wallet-exposure-review',
    title: 'Self-custody key exposure → security review',
    whyConfidential:
      'A private key/seed must NEVER reach a public model. The attested enclave is the only place it is safe to reason about one at all.',
    prompt:
      `I think this hot-wallet key may be compromised: ${FAKE_PRIVKEY}. ` +
      'Assess the exposure and give me a safe, step-by-step migration to a fresh wallet without losing funds.',
  },
]

function divider(t: string) {
  console.log('\n' + '─'.repeat(72) + '\n' + t + '\n' + '─'.repeat(72))
}

async function main() {
  const dryRun = !KEY
  console.log(`tempRouter use cases · server=${SERVER_URL} · model=${MODEL} · mode=${dryRun ? 'DRY RUN (detect only)' : 'LIVE (will pay)'}`)
  if (dryRun)
    console.log('No AGENT_PRIVATE_KEY set — running the local detector only. Set a funded key + SERVER_URL to execute the paid lane.')

  const client = dryRun ? null : new TempRouter({ serverUrl: SERVER_URL, account: KEY })
  let totalUnits = 0
  let totalPaid = 0
  const receipts: { id: string; ok: boolean; units: number; paid: string }[] = []

  for (const uc of USE_CASES) {
    divider(`▶ ${uc.title}`)
    console.log('why confidential: ' + uc.whyConfidential)
    const det = detectSensitive(uc.prompt)
    console.log(`detector: sensitive=${det.sensitive} matches=[${det.matches.join(', ')}] → ${det.sensitive ? 'FORCE private lane' : 'public model OK'}`)

    if (dryRun || !client) continue

    try {
      const res = await client.infer(uc.prompt, {
        model: MODEL,
        onVerify: (r) => console.log('\n── pre-pay attestation gate ──\n' + formatReport(r)),
        onUnit: (n, paid) => process.stdout.write(`\r  💸 [units paid: ${n} | ${paid} pathUSD]`),
      })
      totalUnits += res.units
      totalPaid += Number(res.paid)
      receipts.push({ id: uc.id, ok: res.attestation.prePay.ok, units: res.units, paid: res.paid })
      console.log(`\n🔓 answer (plaintext seen only by you + the attested enclave):\n${res.answer.slice(0, 480)}${res.answer.length > 480 ? '\n…[truncated]' : ''}`)
      console.log(`\n   receipt: prePay=${res.attestation.prePay.ok ? '✓' : '✗'} postPay=${res.attestation.postPay?.ok ? '✓' : 'n/a'} · ${res.units} unit(s) · ${res.paid} pathUSD`)
    } catch (e) {
      if (e instanceof AttestationError) {
        console.error('\n⛔ attestation failed — refused to pay (zero vouchers):\n' + formatReport(e.report))
      } else {
        console.error('\n❌ ' + (e instanceof Error ? e.message : String(e)))
      }
    }
  }

  if (!dryRun) {
    const { privateKeyToAccount } = await import('viem/accounts')
    const addr = privateKeyToAccount(KEY).address
    divider('SUMMARY (on-chain proof)')
    console.log(`payer address : ${addr}`)
    console.log(`explorer      : https://explore.testnet.tempo.xyz/address/${addr}`)
    console.log(`total         : ${totalUnits} unit(s) · ${totalPaid.toFixed(4)} pathUSD across ${receipts.length} use case(s)`)
    console.log('→ open the explorer address above; each run opens an MPP channel on-chain. Copy the')
    console.log('  channel-open tx hash for each use case into the landing page "Use cases" section.')
    console.log('\nJSON: ' + JSON.stringify({ payer: addr, totalUnits, totalPaid: totalPaid.toFixed(4), receipts }))
  }
}

main().catch((e) => {
  console.error('❌', e)
  process.exit(1)
})
