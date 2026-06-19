---
name: temprouter
description: Call tempRouter — a payable, end-to-end-encrypted LLM inference endpoint on MPP (Tempo). Pay per inference in pathUSD stablecoin AFTER your agent verifies (Intel DCAP) that the prompt runs inside a real Phala Intel TDX enclave that can't read it. Use when a prompt holds secrets/PII (API keys sk-…, private keys 0x…, seed phrases, JWTs, passwords, customer data) that must never reach a public model host. Verify-before-pay: a failed attestation pays nothing; the relay is blind (ciphertext only).
---

# tempRouter — payable confidential inference (entrypoint)

**Live endpoint:** `https://temprouter.onrender.com`
- `POST /v1/chat/completions/stream` — the payable inference endpoint (MPP 402 → pay → SSE)
- `GET /tee/attestation` — enclave attestation (verify before you pay)
- `GET /openapi.json` · `GET /llms.txt` — MPP service discovery

## What it is
The **private lane** for prompts that hold secrets you must not leak to a third-party
model host. A **payable inference endpoint on MPP**: your agent pays per response-chunk in **pathUSD**
on Tempo for an LLM answer that is **end-to-end encrypted** to a real **Phala Intel TDX
enclave**. Before any money moves, the agent runs **Intel DCAP** on the live enclave quote;
a failed check signs **zero vouchers**. tempRouter is a **blind relay** — it forwards only
ciphertext and never holds a key, so plaintext is seen only by your agent and the enclave.

## When to use
Route a prompt here when it contains anything that must never reach a third-party model host:
- API key (`sk-…`, `sk-proj-…`), provider token
- Private key (`0x…` 64-hex), seed phrase / mnemonic
- JWT, session token, password / credential
- AWS / cloud access key
- Customer or personal PII; confidential business data, private contracts, proprietary source

Not sensitive? Use a normal public/frontier model (cheaper, more capable). The private lane
runs an **OSS model (`gpt-oss:20b`)** in the enclave — it's the *confidential* lane, not a
frontier-model replacement. Decide with `detectSensitive(prompt).sensitive`.

## How to use
Pick a surface; all run the same dance (**verify → encrypt → pay per chunk → decrypt**):

### SDK
```ts
import { TempRouter, detectSensitive } from '@temprouter/sdk'

const client = new TempRouter({
  serverUrl: 'https://temprouter.onrender.com',
  account: process.env.AGENT_PRIVATE_KEY as `0x${string}`, // funded Tempo testnet wallet
})
if (detectSensitive(prompt).sensitive) {
  const { answer, units, paid } = await client.infer(prompt) // throws AttestationError on a failed gate
}
```

### CLI
```bash
temprouter infer "<prompt>" [--model <m>]   # verify → pay → decrypt
temprouter verify                            # pre-pay gate only (free, no payment)
temprouter detect "<text>"                   # is it sensitive?
```

### MCP (local stdio — encryption + wallet stay in your process)
- `private_inference({ prompt, model? })` → decrypted answer + attestation verdict + units paid
- `verify_enclave()` → pre-pay attestation report (free, never pays)
- `detect_sensitive(text)` → classify whether the text needs the private lane

## The guarantee
- The agent runs **Intel DCAP** on the enclave quote **before signing any voucher**.
- A failed gate signs **zero** vouchers — you never pay a host that can't prove it's blind.
- A swapped enclave **can't decrypt** the prompt (it's encrypted to the attested key), so
  plaintext is only ever seen by your agent + the genuine enclave.

## Honest scope
- The payment↔enclave binding ships as an unenforced **label** (`meta.enclaveKey`), not a
  settlement gate — the real guarantee is verify-before-pay + encryption-to-the-attested-key.
- Verification = DCAP cert-chain + key binding + enclave ed25519 signature. **Code-measurement
  pinning is opt-in** (`EXPECTED_MEASUREMENT`); default is soft-pin ("same enclave the service
  advertised"), not "trusted reproducible build."
- Currently **Tempo Moderato testnet** (chain `42431`), currency **pathUSD**; one charge per inference.

## Install this skill
```bash
npx skills add Router-Labs/tempRouter
```
Or read it live at `https://temprouter.onrender.com/SKILL.md`.
