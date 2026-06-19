#!/usr/bin/env -S npx tsx
// temprouter CLI — thin wrapper over @temprouter/sdk. Three commands:
//   infer   verify-before-pay → encrypt → per-chunk MPP pay → decrypt (the full lane)
//   verify  pre-pay attestation gate only, never pays
//   detect  run the sensitive-payload policy check on text
// Fail-closed: a failed pre-pay gate prints the FAIL report + exits 1, zero vouchers signed.

import { parseArgs } from 'node:util'
import process from 'node:process'
import { TempRouter, detectSensitive, formatReport, AttestationError } from '@temprouter/sdk'
import { config } from './config.js'

const USAGE = `temprouter — attestation-gated, MPP-paid confidential inference on Tempo

usage:
  temprouter infer "<prompt>" [--model <m>] [--server <url>] [--max-deposit <n>] [--json]
      verify the enclave, pay per response-chunk in pathUSD, decrypt locally.
  temprouter verify [--server <url>]
      run the pre-pay attestation gate only. Never pays. Exit 0 if it passes.
  temprouter detect "<text>"
      run the sensitive-payload policy check. Prints { sensitive, matches }.

flags:
  --model <m>        model id (default from SDK, e.g. nosana:gpt-oss:20b)
  --server <url>     tempRouter base URL (default: $SERVER_URL or config)
  --max-deposit <n>  pathUSD deposit headroom (default: config.maxDeposit)
  --json             machine-readable output for 'infer' (no decorative lines)
  -h, --help         show this help
`

function printUsage() {
  process.stdout.write(USAGE)
}

async function cmdInfer(prompt: string, flags: Record<string, unknown>) {
  const json = flags.json === true

  // 0. Policy gate. The user explicitly asked, so we proceed regardless — but we
  //    surface the detection so the forced private lane is never silent.
  const det = detectSensitive(prompt)
  if (det.sensitive && !json) {
    console.log(`🔒 sensitive payload detected (${det.matches.join(', ')}) → forcing attested private lane`)
  }

  if (!config.agentPrivateKey) {
    console.error('AGENT_PRIVATE_KEY not set (fund a Tempo testnet wallet)')
    process.exit(2)
  }

  const client = new TempRouter({
    serverUrl: (flags.server as string) || config.serverUrl,
    account: config.agentPrivateKey,
    maxDeposit: (flags['max-deposit'] as string) || config.maxDeposit,
    pricePerUnit: config.pricePerUnit,
    expectedMeasurement: config.expectedMeasurement || undefined,
  })

  try {
    const res = await client.infer(prompt, {
      model: (flags.model as string) || undefined,
      onVerify: (r) => {
        if (!json) console.log('\n── pre-pay attestation gate ──\n' + formatReport(r))
      },
      onUnit: (n, paid) => {
        if (!json) process.stdout.write(`\r  💸 [units paid: ${n} | ${paid} pathUSD]`)
      },
    })

    if (json) {
      console.log(
        JSON.stringify(
          {
            answer: res.answer,
            units: res.units,
            paid: res.paid,
            prePayOk: res.attestation.prePay.ok,
            postPayOk: res.attestation.postPay?.ok ?? null,
          },
          null,
          2,
        ),
      )
      return
    }

    if (res.attestation.postPay) {
      console.log('\n── post-pay receipt verification ──\n' + formatReport(res.attestation.postPay))
    }
    console.log('\n🔓 decrypted answer (plaintext only ever seen by you + the attested enclave):\n' + res.answer)
    console.log(`\n(${res.units} units · ${res.paid} pathUSD)`)
  } catch (e) {
    if (e instanceof AttestationError) {
      console.error('⛔ ' + e.message + '\n' + formatReport(e.report))
      process.exit(1)
    }
    throw e
  }
}

async function cmdVerify(flags: Record<string, unknown>) {
  const client = new TempRouter({
    serverUrl: (flags.server as string) || config.serverUrl,
    account: config.agentPrivateKey || undefined, // verify() never pays — no wallet needed
    expectedMeasurement: config.expectedMeasurement || undefined,
  })
  const report = await client.verify()
  console.log(formatReport(report))
  process.exit(report.ok ? 0 : 1)
}

function cmdDetect(text: string) {
  const det = detectSensitive(text)
  console.log(JSON.stringify({ sensitive: det.sensitive, matches: det.matches }, null, 2))
}

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      model: { type: 'string' },
      server: { type: 'string' },
      'max-deposit': { type: 'string' },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  const cmd = positionals[0]

  if (values.help || !cmd) {
    printUsage()
    process.exit(cmd ? 0 : values.help ? 0 : 1)
  }

  switch (cmd) {
    case 'infer': {
      const prompt = positionals[1]
      if (!prompt) {
        console.error('infer: missing prompt. usage: temprouter infer "<prompt>"')
        process.exit(1)
      }
      await cmdInfer(prompt, values)
      break
    }
    case 'verify':
      await cmdVerify(values)
      break
    case 'detect': {
      const text = positionals[1]
      if (!text) {
        console.error('detect: missing text. usage: temprouter detect "<text>"')
        process.exit(1)
      }
      cmdDetect(text)
      break
    }
    default:
      console.error(`unknown command: ${cmd}\n`)
      printUsage()
      process.exit(1)
  }
}

main().catch((e) => {
  console.error('❌', e)
  process.exit(1)
})
