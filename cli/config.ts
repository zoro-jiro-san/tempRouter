// Client-side env for the CLI. The CLI is a payer: it never holds an enclave key.
// Kept local (not imported from the server package) so @temprouter/cli is standalone.
import process from 'node:process'
try {
  ;(process as any).loadEnvFile?.('.env')
} catch {
  /* no .env — use process env / defaults */
}

export const config = {
  serverUrl: (process.env.SERVER_URL ?? 'http://localhost:8402').replace(/\/$/, ''),
  agentPrivateKey: (process.env.AGENT_PRIVATE_KEY ?? '') as `0x${string}` | '',
  maxDeposit: process.env.MAX_DEPOSIT ?? '1',
  pricePerUnit: process.env.PRICE_PER_UNIT ?? '0.0002',
  expectedMeasurement: process.env.EXPECTED_MEASUREMENT ?? '',
} as const
