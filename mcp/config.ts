// Client-side env for the MCP server. The MCP server is a payer running in the agent's
// own process: encryption + wallet stay local. Kept independent of the server package.
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
