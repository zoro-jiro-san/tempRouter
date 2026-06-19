// Central config + Tempo testnet constants (sourced from mppx defaults).
import process from 'node:process'
// Native .env loader (Node 20.12+), no dependency. Safe if .env is absent.
try {
  ;(process as any).loadEnvFile?.('.env')
} catch {
  /* no .env — use process env / defaults */
}

export const config = {
  port: Number(process.env.PORT ?? 8402),
  secretKey: process.env.MPP_SECRET_KEY ?? 'dev-insecure-secret-change-me',
  recipient: (process.env.TEMPO_RECIPIENT ??
    '0xa726a1CD723409074DF9108A2187cfA19899aCF8') as `0x${string}`,

  // Pricing (decimal token units; TIP-20 stablecoins use 6 decimals).
  pricePerUnit: process.env.PRICE_PER_UNIT ?? '0.0002', // per response-chunk (session/SSE)
  // How many SSE chunks the blind relay slices the enclave's single ciphertext
  // blob into — each chunk = one MPP voucher tick, so the payer's balance visibly
  // ticks per chunk. Multi-unit metering is fixed + verified end-to-end (ADR-0003).
  // Default 1 = one charge per inference; set CHUNK_COUNT>1 to meter a response in N ticks.
  chunkCount: Number(process.env.CHUNK_COUNT ?? 1),

  // Real Phala Intel TDX enclave (the private upstream). When unset → stub mode.
  teeEndpoint: (process.env.TEE_ENDPOINT ?? '').replace(/\/$/, ''),

  // Optional strict-pin: reject the quote unless mrtd/rtmr equals this value.
  // Unset → soft-pin (compare-to-advertised + display only). See DESIGN §1.
  expectedMeasurement: process.env.EXPECTED_MEASUREMENT ?? '',

  // Optional PAYEE key: when set, the server can cooperatively CLOSE (settle) the
  // channel on-chain as the recipient — the settlement tx sender must equal the
  // channel payee. Its address MUST equal TEMPO_RECIPIENT. Unset → close stays
  // best-effort (deposit reclaims on channel timeout). See ADR-0003.
  recipientPrivateKey: (process.env.TEMPO_RECIPIENT_PRIVATE_KEY ?? '') as `0x${string}` | '',

  // Client/agent side.
  agentPrivateKey: (process.env.AGENT_PRIVATE_KEY ?? '') as `0x${string}` | '',
  serverUrl: (process.env.SERVER_URL ?? 'http://localhost:8402').replace(/\/$/, ''),
  maxDeposit: process.env.MAX_DEPOSIT ?? '1', // pathUSD headroom cap (human units)

  // Default model id the blind relay forwards to the enclave when a client omits one.
  upstreamModel: process.env.UPSTREAM_MODEL ?? 'nosana:gpt-oss:20b',
} as const

// Tempo testnet ("Moderato") — verified from mppx/dist/tempo/internal/defaults.
export const tempoTestnet = {
  chainId: 42431,
  rpcUrl: 'https://rpc.moderato.tempo.xyz',
  explorer: 'https://explore.testnet.tempo.xyz',
  pathUsd: '0x20c0000000000000000000000000000000000000' as `0x${string}`,
  decimals: 6,
} as const

// Derived: where to fetch the enclave attestation + public key (blind passthrough).
export const teeAttestationUrl = config.teeEndpoint ? `${config.teeEndpoint}/attestation` : ''
export const teePublicKeyUrl = config.teeEndpoint ? `${config.teeEndpoint}/public-key` : ''

/**
 * Three-valued privacy mode, resolved at boot by an honest healthcheck of the
 * real Phala TDX enclave. The green/private path is reachable ONLY in 'tdx-live'.
 * See ADR-0001 + DESIGN §2 (loud, code-enforced fallback).
 *
 *  - 'stub'     : no TEE_ENDPOINT configured → intentional offline demo (no TDX).
 *  - 'down'     : TEE_ENDPOINT set but unreachable / not a real INTEL-TDX-PHALA enclave.
 *  - 'tdx-live' : reachable enclave returning teeType INTEL-TDX-PHALA + a non-null tdxQuote.
 */
export type PrivacyMode = 'tdx-live' | 'stub' | 'down'

export async function resolveMode(timeoutMs = 6000): Promise<PrivacyMode> {
  if (!config.teeEndpoint) return 'stub'
  try {
    const ctrl = new AbortController()
    const t = setTimeout(() => ctrl.abort(), timeoutMs)
    const res = await fetch(teeAttestationUrl, { signal: ctrl.signal })
    clearTimeout(t)
    if (!res.ok) return 'down'
    const att: any = await res.json()
    const live = att?.teeType === 'INTEL-TDX-PHALA' && att?.tdxQuote != null
    return live ? 'tdx-live' : 'down'
  } catch {
    return 'down'
  }
}
