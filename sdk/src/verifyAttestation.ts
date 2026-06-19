// Independent, end-to-end verifier for a SolRouter v2 encryption-proof attestation.
// Ported verbatim from SolRouter's dev/backend/verify-attestation.mjs (the only
// prod-passing formula) — see ADR-0002. Differences for tempRouter:
//   - pure function: verifies a GIVEN /process response (does not fetch its own)
//   - DROPS the Solana Light Protocol on-chain check (chain-coupled; out of scope)
//   - adds a structural teeType gate (STUB-NO-TDX / null quote fail closed)
//   - adds mrtd/rtmr extraction + optional strict-pin (DESIGN §1, transparency)
//
// Proves, with NO trust in tempRouter or the enclave operator:
//   1. The TDX quote is genuine Intel hardware (DCAP: sig → PCK chain → Intel root + TCB).
//   2. The quote commits to the enclave keys: report_data == sha512("app-data:" || sha256(teePub||enclavePub)).
//   3. The enclave ed25519-signed THIS exact ciphertext (SOLR-ATTEST-v2 envelope).
//   4. sha256(JSON.stringify(tdxQuote)) == encryptionProof.tdxQuoteHash (the enclave committed to its own quote digest — self-consistency, NOT a payment/voucher binding).

import { getCollateralAndVerify } from '@phala/dcap-qvl'
import { createHash, verify as edVerify, createPublicKey } from 'node:crypto'

const sha256 = (b: Buffer) => createHash('sha256').update(b).digest()
const sha512 = (b: Buffer) => createHash('sha512').update(b).digest()
const b64 = (s: string) => Buffer.from(s, 'base64')
// raw 32-byte ed25519 pubkey → SPKI DER for crypto.verify
const rawToEdPub = (r: Buffer) =>
  createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), r]),
    format: 'der',
    type: 'spki',
  })

/** The enclave's per-request signed receipt (verbatim field names from /process). */
export type EncryptionProof = {
  teePubkey: string
  enclavePubkey: string
  nonce: string
  clientPubkey: string
  enclaveSigR: string
  enclaveSigS: string
  tdxQuoteHash: string
}

export type ProcessResponse = {
  attestation: { teeType?: string; tdxQuote: { quote: string } | null }
  encryptionProof?: EncryptionProof
}

export type VerifyInput = {
  /** The full /tee/process response (attestation + encryptionProof). */
  response: ProcessResponse
  /** The exact packageForTEE() JSON string the agent sent (for bundle.ciphertext). */
  encryptedPrompt: string
  /** Model string, e.g. "nosana:gpt-oss:20b" — must match the enclave's signing convention. */
  model: string
  /** Optional strict-pin: reject unless mrtd/rtmr hex equals this. Unset → soft-pin/display only. */
  expectedMeasurement?: string
}

export type Check = { name: string; pass: boolean; detail?: string }
export type VerifyReport = {
  ok: boolean
  checks: Check[]
  /** sha256(JSON.stringify(tdxQuote)) — the enclave's own quote digest (== encryptionProof.tdxQuoteHash). Not bound to any voucher. */
  tdxQuoteDigest: string
  measurement: { mrtd?: string; rtmr?: string }
}

// Find a 64-byte reportData anywhere in the verified TD report object.
function findReportData(obj: any, depth = 0): Buffer | null {
  if (!obj || depth > 6) return null
  if (obj.reportData && obj.reportData.length === 64) return Buffer.from(obj.reportData)
  for (const k of Object.keys(obj)) {
    if (typeof obj[k] === 'object') {
      const f = findReportData(obj[k], depth + 1)
      if (f) return f
    }
  }
  return null
}

// Best-effort extraction of a measurement field (mrtd / rtmr*) as hex.
function findHexField(obj: any, re: RegExp, depth = 0): string | undefined {
  if (!obj || depth > 6) return undefined
  for (const k of Object.keys(obj)) {
    const v = obj[k]
    if (re.test(k)) {
      if (Buffer.isBuffer(v)) return v.toString('hex')
      if (v instanceof Uint8Array) return Buffer.from(v).toString('hex')
      if (typeof v === 'string') return v
    }
    if (v && typeof v === 'object') {
      const f = findHexField(v, re, depth + 1)
      if (f) return f
    }
  }
  return undefined
}

/** The free GET /tee/attestation response (no per-request encryptionProof). */
export type AttestationDoc = {
  teeType?: string
  teePublicKey?: string
  teePublicKeySha256?: string
  reportDataHex?: string
  tdxQuote: { quote: string } | null
}

/**
 * PRE-PAY gate. Verifies the free `/tee/attestation` quote BEFORE the agent pays:
 * proves we're talking to genuine, up-to-date Intel TDX hardware advertising
 * `teePublicKey`, and pins/displays the code measurement. Returns `tdxQuoteDigest`
 * (the enclave's own quote digest) for display/logging — it is NOT bound to a voucher.
 *
 * NOTE: the strong key→quote binding (ed25519 over the exact ciphertext) is only
 * provable from the /process receipt → see verifyAttestation() (post-pay). Pre-pay
 * proves "genuine TDX + this key + UpToDate TCB + measurement", which is the
 * load-bearing gate for whether to pay at all. Fail-closed.
 */
export async function verifyQuote(
  att: AttestationDoc,
  opts: { expectedMeasurement?: string } = {},
): Promise<VerifyReport> {
  const checks: Check[] = []
  const structural = att?.teeType === 'INTEL-TDX-PHALA' && att?.tdxQuote != null
  checks.push({
    name: 'real TDX enclave advertised (INTEL-TDX-PHALA + non-null quote)',
    pass: structural,
    detail: `teeType=${att?.teeType ?? 'none'} quote=${att?.tdxQuote ? 'present' : 'null'}`,
  })
  if (!structural || !att.tdxQuote) return { ok: false, checks, tdxQuoteDigest: '', measurement: {} }

  const rawQuote = Buffer.from(att.tdxQuote.quote, 'hex')
  const tdxQuoteDigest = sha256(Buffer.from(JSON.stringify(att.tdxQuote))).toString('hex')
  const measurement: { mrtd?: string; rtmr?: string } = {}

  let vr: any = null
  try {
    vr = await getCollateralAndVerify(rawQuote)
  } catch (e: any) {
    checks.push({ name: 'DCAP quote authentic (Intel-signed)', pass: false, detail: `DCAP threw: ${e?.message ?? e}` })
    return { ok: false, checks, tdxQuoteDigest, measurement }
  }
  const tcbOk = String(vr?.status ?? '').toUpperCase() === 'UPTODATE'
  checks.push({ name: 'DCAP quote authentic (Intel-signed)', pass: !!vr })
  checks.push({ name: 'TCB up to date', pass: tcbOk, detail: `status=${vr?.status ?? '?'} advisories=${(vr?.advisory_ids || []).join(',') || 'none'}` })

  measurement.mrtd = findHexField(vr.report, /^mr_?td$/i)
  measurement.rtmr = findHexField(vr.report, /^rtmr/i)
  if (opts.expectedMeasurement) {
    const m = (measurement.mrtd ?? '').toLowerCase()
    checks.push({ name: 'mrtd == EXPECTED_MEASUREMENT (strict-pin)', pass: m === opts.expectedMeasurement.toLowerCase(), detail: `mrtd=${m.slice(0, 16)}…` })
  } else {
    checks.push({ name: 'measurement (soft-pin: displayed)', pass: true, detail: `mrtd=${(measurement.mrtd ?? 'n/a').slice(0, 16)}… rtmr=${(measurement.rtmr ?? 'n/a').slice(0, 16)}…` })
  }

  return { ok: checks.every((c) => c.pass), checks, tdxQuoteDigest, measurement }
}

/**
 * POST-PAY verify, fail-closed. Verifies the /process receipt: genuine TDX +
 * report_data binds teePub+enclavePub (sha512 app-data) + enclave ed25519 signed
 * THIS ciphertext + quote-digest match. Returns a transparency report: every check
 * with PASS/FAIL + raw values so the payer can audit each independently.
 */
export async function verifyAttestation(input: VerifyInput): Promise<VerifyReport> {
  const { response, encryptedPrompt, model } = input
  const checks: Check[] = []
  const att = response.attestation
  const ep = response.encryptionProof

  // 0. Structural gate — STUB-NO-TDX / missing quote / missing proof fail here.
  const structural = att?.teeType === 'INTEL-TDX-PHALA' && att?.tdxQuote != null && !!ep
  checks.push({
    name: 'real TDX enclave present (INTEL-TDX-PHALA + non-null quote + proof)',
    pass: structural,
    detail: `teeType=${att?.teeType ?? 'none'} quote=${att?.tdxQuote ? 'present' : 'null'} proof=${ep ? 'present' : 'none'}`,
  })
  if (!structural || !ep || !att.tdxQuote) {
    return { ok: false, checks, tdxQuoteDigest: '', measurement: {} }
  }

  const rawQuote = Buffer.from(att.tdxQuote.quote, 'hex')
  const tdxQuoteDigest = sha256(Buffer.from(JSON.stringify(att.tdxQuote))).toString('hex')
  const measurement: { mrtd?: string; rtmr?: string } = {}

  // 1. DCAP: genuine Intel TDX hardware (sig → PCK chain → Intel root + TCB).
  let vr: any = null
  try {
    vr = await getCollateralAndVerify(rawQuote)
    checks.push({ name: 'DCAP quote authentic (Intel-signed)', pass: !!vr, detail: `TCB status: ${vr?.status ?? '?'}` })
  } catch (e: any) {
    checks.push({ name: 'DCAP quote authentic (Intel-signed)', pass: false, detail: `DCAP threw: ${e?.message ?? e}` })
    return { ok: false, checks, tdxQuoteDigest, measurement }
  }

  // 2. quote report_data binds the enclave keys.
  const dcapReportData = findReportData(vr.report)
  const expected = sha512(
    Buffer.concat([
      Buffer.from('app-data:'),
      sha256(Buffer.concat([b64(ep.teePubkey), b64(ep.enclavePubkey)])),
    ]),
  )
  checks.push({
    name: 'quote report_data binds teePub+enclavePub',
    pass: !!dcapReportData && Buffer.compare(dcapReportData, expected) === 0,
  })

  // 3. enclave ed25519 signed THIS ciphertext (SOLR-ATTEST-v2 envelope).
  const bundle = JSON.parse(encryptedPrompt)
  const [provider, modelName] = model.split(':')
  const msg = Buffer.concat([
    Buffer.from('SOLR-ATTEST-v2'),
    sha256(Buffer.from(bundle.ciphertext)),
    b64(ep.teePubkey),
    b64(ep.nonce),
    b64(ep.clientPubkey),
    Buffer.from([modelName.length]),
    Buffer.from(modelName, 'utf8'),
    Buffer.from([provider.length]),
    Buffer.from(provider, 'utf8'),
  ])
  const sig = Buffer.concat([b64(ep.enclaveSigR), b64(ep.enclaveSigS)])
  let sigOk = false
  try {
    sigOk = edVerify(null, msg, rawToEdPub(b64(ep.enclavePubkey)), sig)
  } catch (e: any) {
    checks.push({ name: 'enclave ed25519 signature valid', pass: false, detail: `${e?.message ?? e}` })
  }
  if (!checks.some((c) => c.name.startsWith('enclave ed25519'))) {
    checks.push({ name: 'enclave ed25519 signature valid', pass: sigOk })
  }

  // 4. quote hash matches the enclave's committed digest.
  checks.push({
    name: 'sha256(tdxQuote) == encryptionProof.tdxQuoteHash',
    pass: tdxQuoteDigest === ep.tdxQuoteHash,
    detail: tdxQuoteDigest.slice(0, 16) + '… vs ' + String(ep.tdxQuoteHash).slice(0, 16) + '…',
  })

  // 5. Measurement (transparency): extract + (strict-pin if configured).
  measurement.mrtd = findHexField(vr.report, /^mr_?td$/i)
  measurement.rtmr = findHexField(vr.report, /^rtmr/i)
  if (input.expectedMeasurement) {
    const m = (measurement.mrtd ?? '').toLowerCase()
    checks.push({
      name: 'mrtd == EXPECTED_MEASUREMENT (strict-pin)',
      pass: m === input.expectedMeasurement.toLowerCase(),
      detail: `mrtd=${m.slice(0, 16)}…`,
    })
  } else {
    checks.push({
      name: 'measurement (soft-pin: displayed, compare-to-advertised in agent)',
      pass: true,
      detail: `mrtd=${(measurement.mrtd ?? 'n/a').slice(0, 16)}… rtmr=${(measurement.rtmr ?? 'n/a').slice(0, 16)}…`,
    })
  }

  const ok = checks.every((c) => c.pass)
  return { ok, checks, tdxQuoteDigest, measurement }
}

/** Render a transparency report to a string (agent prints this). */
export function formatReport(r: VerifyReport): string {
  const lines = r.checks.map((c) => `${c.pass ? '✅' : '❌'} ${c.name}${c.detail ? `  (${c.detail})` : ''}`)
  lines.push(r.ok ? '\n✅✅ INDEPENDENTLY VERIFIED — genuine TDX, bound keys, signed receipt.' : '\n❌ verification incomplete — refusing to pay.')
  return lines.join('\n')
}
