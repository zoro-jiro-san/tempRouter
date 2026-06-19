#!/usr/bin/env -S npx tsx
// tempRouter MCP server — confidential, attestation-gated inference as agent tools.
//
// Run this LOCALLY (the agent spawns it as a stdio MCP server): the encryption and the
// payer wallet stay inside the agent's own process, so the prompt plaintext never leaves
// your trust domain. The remote tempRouter relay only ever sees ciphertext. Backed by
// @temprouter/sdk.
//
// Tools:
//   • detect_sensitive(text)            — should this prompt go to the private lane?
//   • verify_enclave()                  — pre-pay Intel DCAP attestation report (no payment)
//   • private_inference(prompt, model?) — verify → encrypt → pay-per-chunk → decrypt
//
// Wire into an MCP client (e.g. Claude) as a stdio server, with AGENT_PRIVATE_KEY (a
// funded Tempo testnet wallet) in the environment:
//   { "command": "npx", "args": ["tsx", "/abs/path/tempRouter/mcp/server.ts"] }

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { TempRouter, detectSensitive, formatReport, AttestationError } from '@temprouter/sdk'
import { config } from './config.js'

const ok = (t: string) => ({ content: [{ type: 'text' as const, text: t }] })
const err = (t: string) => ({ content: [{ type: 'text' as const, text: t }], isError: true })

/** Build a client bound to the local payer wallet (if any). `verify()` needs no wallet;
 *  `infer()` throws a clear error when unfunded — private_inference guards for that below. */
function makeClient(serverUrl?: string) {
  return new TempRouter({
    serverUrl: serverUrl ?? config.serverUrl,
    account: config.agentPrivateKey || undefined,
    maxDeposit: config.maxDeposit,
    pricePerUnit: config.pricePerUnit,
    expectedMeasurement: config.expectedMeasurement || undefined,
  })
}

const NO_WALLET = 'AGENT_PRIVATE_KEY not set — fund a Tempo testnet wallet and set it in this MCP server\'s environment.'

const server = new McpServer({ name: 'temprouter', version: '0.1.0' })

server.registerTool(
  'detect_sensitive',
  {
    title: 'Detect sensitive payload',
    description:
      'Classify whether a prompt contains secrets, credentials, or PII (API keys, private keys, seed phrases, JWTs, AWS keys, emails, …). Call this BEFORE sending a prompt to a public model — a hit means route it to private_inference instead.',
    inputSchema: { text: z.string().describe('The prompt/text to classify.') },
  },
  async ({ text }) => {
    const d = detectSensitive(text)
    return ok(
      d.sensitive
        ? `SENSITIVE — matched: ${d.matches.join(', ')}. Route this to private_inference; do NOT send it to a public model host.`
        : 'not sensitive — safe to use a normal public model.',
    )
  },
)

server.registerTool(
  'verify_enclave',
  {
    title: 'Verify the TDX enclave (pre-pay, free)',
    description:
      'Fetch tempRouter\'s live enclave attestation and run Intel DCAP verification. Returns a per-check PASS/FAIL transparency report. Never pays. Use to independently confirm the enclave is genuine Intel TDX before relying on private_inference.',
    inputSchema: { server: z.string().optional().describe('Override the tempRouter base URL.') },
  },
  async ({ server }) => {
    const report = await makeClient(server).verify() // free — no wallet required
    return ok(formatReport(report))
  },
)

server.registerTool(
  'private_inference',
  {
    title: 'Confidential inference (verify → encrypt → pay → decrypt)',
    description:
      'Run a prompt through tempRouter\'s confidential lane: verify a real Phala Intel TDX enclave with Intel DCAP, encrypt the prompt to the enclave key, pay per response-chunk in pathUSD on Tempo, and decrypt the answer locally. A failed attestation pays NOTHING. Use for any prompt containing secrets, credentials, or PII. The enclave runs an OSS model (gpt-oss:20b) — use it for confidential payloads, not as a frontier-model replacement.',
    inputSchema: {
      prompt: z.string().describe('The (possibly sensitive) prompt to run privately.'),
      model: z.string().optional().describe('Model id (default nosana:gpt-oss:20b).'),
      server: z.string().optional().describe('Override the tempRouter base URL.'),
    },
  },
  async ({ prompt, model, server }) => {
    if (!config.agentPrivateKey) return err(NO_WALLET)
    try {
      const res = await makeClient(server).infer(prompt, { model })
      const footer = `\n\n— verified TDX enclave · ${res.units} chunk(s) · ${res.paid} pathUSD${res.attestation.postPay?.ok ? ' · receipt ✓' : ''}`
      return ok(res.answer + footer)
    } catch (e) {
      if (e instanceof AttestationError)
        return err('⛔ Refused to pay — the enclave failed attestation (zero vouchers signed).\n\n' + formatReport(e.report))
      return err('private inference failed: ' + (e instanceof Error ? e.message : String(e)))
    }
  },
)

await server.connect(new StdioServerTransport())
// stdout is the MCP protocol channel — logs MUST go to stderr.
console.error('tempRouter MCP server ready (stdio) · tools: detect_sensitive, verify_enclave, private_inference')
