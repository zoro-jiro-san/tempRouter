// @temprouter/sdk — the Tempo client SDK for tempRouter.
//
// Confidential, attestation-gated, MPP-paid AI inference in ONE call. Wraps three
// pieces so an agent never hand-rolls the dance:
//   • @solrouter/sdk  — client-side encryption (Arcium RescueCipher + X25519)
//   • mppx (Tempo)    — per-response-chunk stablecoin payment over an MPP session
//   • Intel DCAP      — verify the TDX enclave BEFORE any money moves (fail-closed)
//
// The payer verifies the enclave, encrypts to its key, pays per chunk in pathUSD on
// Tempo, then decrypts locally. tempRouter is a blind relay — it only ever sees
// ciphertext. A failed attestation signs ZERO vouchers.
//
// The DCAP verifier + secret detector live here in the SDK (./verifyAttestation,
// ./detectSensitive) so this package is self-contained and publishable; the server
// is a separate package that never imports them (it is blind by construction).

import { encrypt, decrypt, packageForTEE } from '@solrouter/sdk'
import { Session } from 'mppx/tempo'
import { createWalletClient, http, type Account } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { tempoModerato } from 'viem/chains'
import {
  verifyQuote,
  verifyAttestation,
  formatReport,
  type VerifyReport,
} from './verifyAttestation.js'
import { detectSensitive, type Detection } from './detectSensitive.js'

const PROOF_SENTINEL = '__TEMPROUTER_PROOF__' // final SSE frame carrying the post-pay receipt
const DEFAULT_MODEL = 'nosana:gpt-oss:20b'

export type TempRouterOptions = {
  /** tempRouter base URL, e.g. https://temprouter.onrender.com */
  serverUrl: string
  /** Payer wallet: a viem `Account`, or a `0x` private key (Tempo testnet). Only
   *  required to pay — `verify()` works without it. */
  account?: Account | `0x${string}`
  /** pathUSD deposit headroom (human units). Default '1'. */
  maxDeposit?: string
  /** Per-response-chunk price, for the running tally. Default '0.0002'. */
  pricePerUnit?: string
  /** Strict-pin: reject the quote unless mrtd/rtmr equals this. Unset → soft-pin. */
  expectedMeasurement?: string
}

export type InferOptions = {
  /** Model id, e.g. 'nosana:gpt-oss:20b'. */
  model?: string
  /** Fires once after the pre-pay attestation gate (pass OR fail), before any payment. */
  onVerify?: (report: VerifyReport) => void
  /** Fires after each paid chunk with the running unit count + pathUSD tally. */
  onUnit?: (units: number, paidPathUsd: string) => void
}

export type InferResult = {
  /** Decrypted plaintext — only ever seen by the caller and the attested enclave. */
  answer: string
  /** Number of response-chunk units paid for. */
  units: number
  /** Total paid, pathUSD. */
  paid: string
  /** The verification reports: pre-pay gate + (optional) post-pay receipt. */
  attestation: { prePay: VerifyReport; postPay?: VerifyReport }
}

/** Thrown when the pre-pay attestation gate fails. Zero vouchers are signed. */
export class AttestationError extends Error {
  report: VerifyReport
  constructor(report: VerifyReport) {
    super('tempRouter: attestation gate FAILED — refusing to pay (zero vouchers signed).')
    this.name = 'AttestationError'
    this.report = report
  }
}

/**
 * The tempRouter client. Construct once with a payer wallet, then call `infer()`.
 *
 * @example
 * ```ts
 * import { TempRouter, detectSensitive } from '@temprouter/sdk'
 *
 * const client = new TempRouter({ serverUrl: 'https://temprouter.onrender.com', account: '0x…' })
 * if (detectSensitive(prompt).sensitive) {
 *   const { answer } = await client.infer(prompt)   // verify → encrypt → pay → decrypt
 * }
 * ```
 */
export class TempRouter {
  #serverUrl: string
  #accountInput?: Account | `0x${string}`
  #account?: Account
  #maxDeposit: string
  #pricePerUnit: string
  #expectedMeasurement?: string

  constructor(opts: TempRouterOptions) {
    this.#serverUrl = opts.serverUrl.replace(/\/$/, '')
    this.#accountInput = opts.account
    this.#maxDeposit = opts.maxDeposit ?? '1'
    this.#pricePerUnit = opts.pricePerUnit ?? '0.0002'
    this.#expectedMeasurement = opts.expectedMeasurement
  }

  /** Resolve the payer account lazily — only `infer()` needs it, so `verify()` works
   *  with no wallet configured. Throws a clear error when payment is attempted unfunded. */
  #resolveAccount(): Account {
    if (this.#account) return this.#account
    if (!this.#accountInput)
      throw new Error('tempRouter: no payer account configured — pass `account` (a viem Account or 0x private key) to pay for inference.')
    this.#account = typeof this.#accountInput === 'string' ? privateKeyToAccount(this.#accountInput) : this.#accountInput
    return this.#account
  }

  /** PRE-PAY gate only: fetch + Intel-DCAP-verify the enclave quote. Never pays (no wallet needed). */
  async verify(): Promise<VerifyReport> {
    const att = await (await fetch(`${this.#serverUrl}/tee/attestation`)).json()
    return verifyQuote(att, { expectedMeasurement: this.#expectedMeasurement })
  }

  /**
   * Confidential inference in one call: verify-before-pay → encrypt → pay per
   * response-chunk over an MPP session on Tempo → decrypt. Fail-closed: a failed
   * attestation throws {@link AttestationError} and signs ZERO vouchers.
   */
  async infer(prompt: string, opts: InferOptions = {}): Promise<InferResult> {
    const model = opts.model ?? DEFAULT_MODEL

    // 1. PRE-PAY: verify the enclave BEFORE paying. Fail-closed.
    const prePay = await this.verify()
    opts.onVerify?.(prePay)
    if (!prePay.ok) throw new AttestationError(prePay)

    // 2. Encrypt the prompt to the enclave key (via tempRouter's blind passthrough).
    const enc = await encrypt(prompt, this.#serverUrl)
    const encryptedPrompt = packageForTEE(enc)

    // 3. Pay per response-chunk over an MPP session (Tempo Moderato testnet).
    const account = this.#resolveAccount()
    const client = createWalletClient({ account, chain: tempoModerato, transport: http() })
    const manager = Session.Client.sessionManager({ account, client, decimals: 6, maxDeposit: this.#maxDeposit })

    const stream = await manager.sse(`${this.#serverUrl}/v1/chat/completions/stream`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ encryptedPrompt, model }),
    })

    let cipher = ''
    let units = 0
    let proof: unknown = null
    for await (const frame of stream) {
      if (frame.startsWith(PROOF_SENTINEL)) {
        proof = JSON.parse(frame.slice(PROOF_SENTINEL.length))
        continue
      }
      cipher += frame
      units++
      opts.onUnit?.(units, (units * Number(this.#pricePerUnit)).toFixed(4))
    }

    // 4. POST-PAY receipt verify (bonus) + decrypt. Plaintext stays local.
    let postPay: VerifyReport | undefined
    if (proof) postPay = await verifyAttestation({ response: proof as never, encryptedPrompt, model })
    const answer = await decrypt(JSON.parse(cipher), enc.ephemeralPrivateKey)

    // 5. Best-effort cooperative close (reclaims unspent deposit). Non-fatal —
    //    the deposit reclaims on channel timeout if the server can't settle.
    try {
      await manager.close()
    } catch {
      /* non-fatal: data is already paid for + received */
    }

    return {
      answer,
      units,
      paid: (units * Number(this.#pricePerUnit)).toFixed(4),
      attestation: { prePay, postPay },
    }
  }
}

// Re-export the policy + verifier primitives so consumers get everything from the SDK.
export { detectSensitive, formatReport, verifyQuote, verifyAttestation }
export type { VerifyReport, Detection }
