# tempRouter

> **Pay an LLM only after you can prove it never saw your prompt.**
> Confidential, pay-per-use LLM inference for agents — end-to-end encrypted to a real
> Intel TDX enclave your agent verifies (Intel DCAP) *before* it pays, per response-chunk
> in pathUSD on Tempo.

**🟢 Live:** https://temprouter.onrender.com · [`/openapi.json`](https://temprouter.onrender.com/openapi.json) · [`/tee/attestation`](https://temprouter.onrender.com/tee/attestation)

## The problem

When an autonomous agent hits a secret in its own prompt — an API key, a private key, a
seed phrase, a customer's PII — it has two bad options: ship that secret to a third-party
model host (which can log it, retain it, or train on it — and you can't prove it didn't),
or drop the task. There's no clean way to **pay per use** for inference that can *prove* it
never read your data.

**tempRouter is the private lane for exactly those prompts.** Your agent detects the
secret locally, encrypts the prompt to a key that exists only inside a **real Phala Intel
TDX enclave**, verifies that enclave with **Intel DCAP** *before* any money moves, and only
then pays per response-chunk in **pathUSD** on Tempo. tempRouter itself is a **blind
relay** — it forwards ciphertext, holds no key, and never sees plaintext. A failed
attestation signs **zero vouchers**: you never pay a host that can't prove it's blind.

Payment is the easy half — MPP already does per-chunk stablecoin billing. The half
tempRouter adds is **provable confidentiality on a payable endpoint**.

## How it fits together

```
agent (src/agent.ts)
  0. detectSensitive(prompt)         ── secret/PII? → force the private lane
  1. GET /tee/attestation            ── verifyQuote() : Intel DCAP, fail-closed
  2. encrypt(prompt → enclave key)   ── Arcium RescueCipher + X25519 (@solrouter/sdk)
  3. sessionManager.sse(POST …)      ── MPP session, pay per response-chunk (Tempo Moderato)
        │
        ▼
tempRouter (src/server.ts)  ── BLIND RELAY (holds no key)
  · mppx.session({sse:true}) gates payment per response-chunk (402 → pay → SSE stream)
  · forwards ciphertext → real Phala Intel TDX /process → meters reply chunks (withReceipt)
        │
        ▼
Phala Intel TDX enclave (SolRouter prod, chain-agnostic)
  · decrypts INSIDE the enclave · runs gpt-oss:20b · re-encrypts · returns a TDX-attested receipt
        │
        ▼
agent  ── reassemble chunks → decrypt() locally.  Plaintext seen only by agent + enclave.
```

- **Privacy** is real and verifiable live: prod returns `teeType: INTEL-TDX-PHALA` + a
  real Intel TDX quote (DCAP `UpToDate`). Reused as-is from SolRouter; only the Solana
  on-chain attestation is dropped. See [docs/adr/0001](docs/adr/0001-temprouter-is-a-blind-relay.md).
- **Payment** is native Tempo/pathUSD via [`mppx`](https://www.npmjs.com/package/mppx)
  session vouchers (~2 on-chain txs per stream). See [docs/adr/0002](docs/adr/0002-attestation-bound-mpp-settlement.md).

## Integrate

tempRouter is infrastructure, not a destination — the same verify-before-pay lane ships at
four altitudes. Each runs the whole dance (verify the enclave → encrypt → pay per chunk in
pathUSD → decrypt):

| surface | use it |
|---|---|
| **SDK** — [`@temprouter/sdk`](sdk/) | `new TempRouter({ serverUrl, account }).infer(prompt)` → `{ answer, units, paid }`. A failed gate throws `AttestationError` and pays zero. |
| **CLI** — [`cli/`](cli/) | `npm run cli -- infer "<prompt>"` (also `verify`, `detect`). |
| **MCP** — [`mcp/`](mcp/) | local stdio server: tools `private_inference`, `detect_sensitive`, `verify_enclave`. Encryption + wallet stay in your agent's process. |
| **Skill** — [`skills/temprouter`](skills/temprouter/SKILL.md) | agent entrypoint: `npx skills add Router-Labs/tempRouter`, or read it live at [`/SKILL.md`](https://temprouter.onrender.com/SKILL.md). Auto-routes secret/PII prompts to the private lane. |

```ts
import { TempRouter, detectSensitive } from '@temprouter/sdk'

const client = new TempRouter({ serverUrl: 'https://temprouter.onrender.com', account: '0x…' })
if (detectSensitive(prompt).sensitive) {
  const { answer } = await client.infer(prompt) // verify → encrypt → pay → decrypt
}
```

Wire the MCP server into a client (e.g. Claude) with a funded `AGENT_PRIVATE_KEY` in env:

```json
{ "command": "npx", "args": ["tsx", "/abs/path/tempRouter/mcp/server.ts"] }
```

## Run it

```bash
npm install
# tdx-live: point at the real enclave (payment still needs a funded testnet key)
TEE_ENDPOINT=https://solrouter-obb4.onrender.com/tee MPP_SECRET_KEY=$(openssl rand -hex 24) npm start
# in another shell — the paying agent (fund AGENT_PRIVATE_KEY first; see below)
SERVER_URL=http://localhost:8402 AGENT_PRIVATE_KEY=0x… npm run agent
```

- **No `TEE_ENDPOINT`** → `mode=stub`: there's no live TDX, so the agent's attestation
  gate correctly **refuses to pay** (this is the demo's "refusal" run).
- Fund a Tempo testnet key: `curl -X POST https://docs.tempo.xyz/api/faucet -d '{"address":"0x…"}'`
  (or `npx mppx account fund --network testnet`).

### Env (`.env.example`)
| var | meaning |
|---|---|
| `TEE_ENDPOINT` | real Phala TDX base (`…/tee`). Unset → stub mode. |
| `MPP_SECRET_KEY` | HMAC secret for challenge binding (not a chain key). |
| `PRICE_PER_UNIT` | pathUSD per response-chunk (default 0.0002). |
| `AGENT_PRIVATE_KEY` | funded Tempo testnet key (agent side). |
| `EXPECTED_MEASUREMENT` | optional strict-pin of `mrtd` (else soft-pin). |

## Endpoints

| | path | |
|---|---|---|
| `POST` | `/v1/chat/completions/stream` | attested private inference, metered per response-chunk (SSE) |
| `GET` | `/tee/attestation` | enclave attestation — **verify before you pay** |
| `GET` | `/openapi.json` | MPP service discovery (`x-service-info` + `x-payment-info`) |
| `GET` | `/llms.txt` | agent-readable context |
| `GET` | `/` | branded landing page (browser) / service JSON (agent) |

Discoverable on **mpp.dev/services** (GitHub PR) + **MPPScan**.

## Status

**✅ Full loop VERIFIED end-to-end on Tempo testnet (2026-06-16):**
`detect secret → pre-pay DCAP verify (real INTEL-TDX-PHALA, UpToDate) → encrypt →
pay pathUSD on-chain (balance moves) → real Phala TDX inference → SSE stream + charge →
decrypt to plaintext answer.`

- ✅ Verifier validated against live prod hardware (DCAP + key-binding + ed25519 + quote-digest).
- ✅ Server boots `mode=tdx-live`; discovery + landing page serve.
- ✅ Attestation-gated payment, real MPP session on Tempo Moderato, real pathUSD spent.
- ✅ Funded testnet wallet (`mppx account temprouter`).

**✅ ADR-0003 closed (2026-06-17) — see [ADR-0003](docs/adr/0003-per-unit-sse-metering.md):**
- ✅ Multi-unit streaming (`CHUNK_COUNT > 1`) is supported + verified; **prod bills one charge per inference** (`CHUNK_COUNT=1`). (Fixed a request-classification bug where header-only voucher POSTs were misread as billable content.)
- ✅ Cooperative `manager.close()` settles on-chain as the payee (opt-in via `TEMPO_RECIPIENT_PRIVATE_KEY`).
- ✅ SDK · CLI · MCP · agent skill shipped (see **Integrate** above), all verified end-to-end on testnet.

See [`DESIGN.md`](DESIGN.md) for the original design, [`CONTEXT.md`](CONTEXT.md)
for the domain glossary, and `docs/adr/` for the load-bearing decisions.

---

<sub>Origin: built at the Berlin MPP Hackathon @ Futura Camp 2026; now maintained as
standalone confidential-inference infrastructure. Scope is Tempo Moderato **testnet**
(pathUSD) with an OSS model (`gpt-oss:20b`) in the enclave — see the honest-scope notes
above and in `docs/adr/`.</sub>
