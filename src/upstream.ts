// The private upstream: the REAL Phala Intel TDX enclave (chain-agnostic over HTTP).
// tempRouter forwards opaque ciphertext to it and meters the response — it is a
// blind relay (ADR-0001). In stub/down mode there is no TDX, so the attestation is
// STUB-NO-TDX and the agent's pre-pay verifyQuote() correctly refuses to pay.

import { config, teeAttestationUrl, teePublicKeyUrl } from './config.js'

export type TeeProcessResult = {
  encryptedResponse: string
  attestation: any
  encryptionProof: any
}

const STUB_ATTESTATION = { teeType: 'STUB-NO-TDX', tdxQuote: null }

// Every call to the upstream enclave is bounded — a hung enclave must not pin a request
// (or a paid stream) open indefinitely. Inference is the slow path; the GETs are cheap.
const PROCESS_TIMEOUT_MS = Number(process.env.TEE_PROCESS_TIMEOUT_MS ?? 90_000)
const ATTESTATION_TIMEOUT_MS = Number(process.env.TEE_ATTESTATION_TIMEOUT_MS ?? 8_000)

/** fetch() with an AbortController timeout, so no upstream call can hang forever. */
async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    return await fetch(url, { ...init, signal: ctrl.signal })
  } finally {
    clearTimeout(t)
  }
}

/** POST ciphertext to the enclave; returns the re-encrypted blob + per-request proof. */
export async function teeProcess(encryptedPrompt: string, model: string): Promise<TeeProcessResult> {
  if (!config.teeEndpoint) throw new Error('TEE_ENDPOINT not configured (stub mode cannot run real inference)')
  const res = await fetchWithTimeout(
    `${config.teeEndpoint}/process`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ encryptedPrompt, model }),
    },
    PROCESS_TIMEOUT_MS,
  )
  if (!res.ok) throw new Error(`TEE /process ${res.status}: ${(await res.text()).slice(0, 200)}`)
  const b: any = await res.json()
  return { encryptedResponse: b.encryptedResponse, attestation: b.attestation, encryptionProof: b.encryptionProof }
}

/** GET the enclave attestation (blind passthrough). Returns STUB-NO-TDX when no TEE. */
export async function fetchAttestation(): Promise<any> {
  if (!teeAttestationUrl) return STUB_ATTESTATION
  try {
    const res = await fetchWithTimeout(teeAttestationUrl, {}, ATTESTATION_TIMEOUT_MS)
    if (!res.ok) return STUB_ATTESTATION
    return await res.json()
  } catch {
    return STUB_ATTESTATION
  }
}

/** GET the enclave X25519 public key (blind passthrough). */
export async function fetchTeePublicKeyRaw(): Promise<any> {
  if (!teePublicKeyUrl) return { error: 'no TEE_ENDPOINT' }
  const res = await fetchWithTimeout(teePublicKeyUrl, {}, ATTESTATION_TIMEOUT_MS)
  return res.json()
}

/** Slice a string into n ordered chunks — each chunk = one MPP voucher tick. */
export function chunk(s: string, n: number): string[] {
  if (n <= 1 || s.length <= n) return [s]
  const size = Math.ceil(s.length / n)
  const out: string[] = []
  for (let i = 0; i < s.length; i += size) out.push(s.slice(i, i + size))
  return out
}
