# tempRouter — End-to-End Evidence

> **An AI agent paid for, and received, attested confidential inference — with on-chain proof.**
> A live client ran the full loop against the deployed endpoint:
> **detect → verify (Intel DCAP) → encrypt → pay (MPP session on Tempo) → decrypt.**
> Captured 2026-06-18, Tempo Moderato **testnet** (chain `42431`).

**Result: ✅ PASS** — the attestation gate cleared, an MPP payment channel opened on-chain
(`SUCCESS`), one response-chunk was metered and paid, and the agent decrypted a genuine
`gpt-oss:20b` answer that only the agent and the attested enclave ever saw in plaintext.

| | |
|---|---|
| **Endpoint** | `https://temprouter.onrender.com` → `POST /v1/chat/completions/stream` |
| **Network** | Tempo Moderato **testnet**, chain `42431`, currency **pathUSD** (TIP-20, 6 dp) |
| **Payer (agent)** | `0x9BD2B3C6dc9bDF069333EaeC42596E6d119C9f70` |
| **Payee (service)** | `0xa726a1CD723409074DF9108A2187cfA19899aCF8` (matches `src/config.ts` `TEMPO_RECIPIENT`) |
| **Enclave** | real Phala **Intel TDX** (`teeType: INTEL-TDX-PHALA`), DCAP `UpToDate` |
| **Model** | `nosana:gpt-oss:20b` (OSS model, inside the enclave) |

---

## 1. Attestation gate — verified **before** any payment (fail-closed)

The agent fetched `GET /tee/attestation` and ran Intel DCAP. Every check passed; only then did
it construct the payer and sign a voucher. A failure here signs **zero** vouchers.

```
✅ real TDX enclave advertised (INTEL-TDX-PHALA + non-null quote)   (teeType=INTEL-TDX-PHALA quote=present)
✅ DCAP quote authentic (Intel-signed)
✅ TCB up to date                                                   (status=UpToDate advisories=none)
✅ measurement (soft-pin: displayed)                                (mrtd=f06dfda6dce1cf90… rtmr=68102e7b524af310…)
✅✅ INDEPENDENTLY VERIFIED — genuine TDX, bound keys, signed receipt.

# post-pay receipt (binds the enclave keys to THIS ciphertext)
✅ quote report_data binds teePub+enclavePub
✅ enclave ed25519 signature valid
✅ sha256(tdxQuote) == encryptionProof.tdxQuoteHash                 (d2fdb8b8968ac68a… vs d2fdb8b8968ac68a…)
```

---

## 2. The payment — on-chain channel + off-chain voucher

MPP `session` payments are **two layers**: a channel is opened **on-chain** (a deposit of
headroom), then each unit is metered **off-chain** with a signed voucher. Vouchers never hit
the chain; the deposit reclaims on close/timeout. Both layers are shown below honestly.

### On-chain — MPP channel OPEN ✅ `SUCCESS`

**Tx hash:** `0xaa213739980b114a516ac38588703be1cd72fa4ef96d1e9b98227ce990cb915b`
**Explorer:** https://explore.testnet.tempo.xyz/tx/0xaa213739980b114a516ac38588703be1cd72fa4ef96d1e9b98227ce990cb915b

| field | value |
|---|---|
| block | `22788263` (`0x15bb8a7`), txIndex `0xf` |
| timestamp | `2026-06-18T15:43:25Z` |
| from | `0x9bd2…9f70` (the payer ✓) |
| to | `0x4d50500000000000000000000000000000000000` (MPP precompile — ASCII `"MPP"`) |
| nonce | `20` (the payer's latest tx) |
| status | `0x1` = **SUCCESS**, gasUsed `295037` |

**Decoded logs (this one tx carries the whole channel open):**

1. **pathUSD `Transfer`** — payer → MPP precompile, **`1.000000` pathUSD** — the channel **deposit** (headroom = SDK `maxDeposit: '1'`).
2. **MPP channel-OPEN event** (from the `0x4d5050…` precompile):
   - `channelId` = `0x7c1261fb43253cc772fe045d90e321c7515f85a3b1b74b375c942e0b0ca7cacc`
   - payer = `0x9bd2…9f70`
   - payee = `0xa726a1cd723409074df9108a2187cfa19899acf8` ✓
3. **pathUSD `Transfer`** — payer → fee collector (`0xfeec0000…`), **`0.005902` pathUSD** (channel-open fee).

### Off-chain — metered consumption

| | |
|---|---|
| Units paid | **1** response-chunk (`unitType: response-chunk`) |
| Amount metered | **`0.0002` pathUSD** (the price per response-chunk) |
| Client tally | `💸 [units paid: 1 \| 0.0002 pathUSD]` |
| Settlement | signed MPP voucher (off-chain); the unused `0.9998` of the deposit reclaims on close/timeout |

> **Honest note — do not conflate the two numbers.** What moved **on-chain** is the **1.0 pathUSD
> deposit** (locked headroom) plus the **0.005902 pathUSD** open fee. The **0.0002 pathUSD** is the
> actual metered spend, settled **off-chain** by voucher. This is standard MPP session design, not a
> discrepancy.

---

## 3. The inference — a genuine decrypted answer

The agent decrypted the enclave's ciphertext locally. Plaintext was seen only by the agent and
the attested enclave. First ~300 chars:

```
**Short-Answer**
1. **Blast radius:** Depends on the scope of permissions the key carries.
   * If it's an API key for a third-party service (e.g., Stripe, SendGrid, Slack), the blast
     radius is limited to the operations that key permits…
   * If it's a cloud-provider key (AWS IAM, GCP Service Account, Azure AD App)…
```

**Why this is genuine model output (not a stub):** the full answer is a structured
incident-response runbook (blast-radius analysis, a 10-step rotation order, per-platform
AWS/GCP/Stripe tables) and — decisively — it generated a `grep` snippet echoing the **exact**
leaked key from the prompt (a synthetic `sk-proj-1a2b…` test key, truncated here). A stub cannot reproduce
prompt-specific content inside generated code. Consistent with `nosana:gpt-oss:20b`.

---

## 4. End-to-end encryption — the relay is blind (proven)

The prompt **and** the answer are encrypted end-to-end between the agent and the attested enclave
(Arcium RescueCipher + X25519). tempRouter is **structurally blind**: its code has no decryption
path, holds no key, and only ever moves opaque ciphertext in both directions.

**Code (verified):**
- The SDK encrypts **before** sending — the request body is only `{ encryptedPrompt, model }`; the raw prompt is never in it (`sdk/src/index.ts:136,147`).
- The decryption key never leaves the agent — `packageForTEE()` serializes only `{ciphertext, nonce, publicKey, algorithm, version}` and **drops** the ephemeral private key (`@solrouter/sdk` `encryption.js`); `decrypt()` runs locally (`sdk/src/index.ts:166`).
- The relay never decrypts — `server.ts:129` destructures only `{ encryptedPrompt, model }` (no `messages`/`content`), imports no decrypt code / no `@solrouter/sdk`, forwards ciphertext to the enclave, and logs **byte lengths only** (`server.ts:130,132`).
- The answer is ciphertext on the wire too — the enclave returns `encryptedResponse`; the relay streams the chunks verbatim; the agent reassembles and decrypts locally.

**Live proof (no payment).** Encrypting a unique marker `E2E_MARKER_9f3c__sk-proj-LEAKTEST` to the
live enclave key, the on-wire payload is:

```json
{ "ciphertext": "eyJkYXRhIjpbIjQwI…",  "nonce": "BNyHYA+rXu4BCqGSwjEREA==",
  "publicKey": "oKAFD8TOTnaf…  (agent EPHEMERAL public key — safe to share)",
  "algorithm": "Arcium-RescueCipher",  "version": "2.0-packed31" }
```

```
marker present on wire?        false      ← plaintext never on the wire
private key present on wire?   false      ← only the EPHEMERAL public key is sent
decrypt with agent key         → "E2E_MARKER_9f3c__sk-proj-LEAKTEST"  (round-trips)
decrypt with a wrong key       → garbage  (recovers nothing)
```

**What *is* plaintext** (non-sensitive routing metadata, no content leak): the `model` id, the
`algorithm`/`version` tags, the agent's ephemeral public key + nonce (these *must* be public for
X25519), and approximate byte lengths in server logs. On-chain payment metadata is financial, not
content.

**No plaintext fallback.** If the enclave public key can't be fetched, `@solrouter/sdk` **throws**
("Refusing to encrypt — would risk sending plaintext") — the old guessable-key fallback was removed
— and the attestation gate fail-closes *before* encryption, so a bad enclave means zero bytes sent.

## 5. What is **not** on-chain (and why)

- **No cooperative-close / settlement tx.** Scanning the MPP precompile for `channelId 0x7c1261fb…`
  returns exactly one event — the OPEN — and no close. The production server runs close **best-effort**
  (no payee settlement key set), so the channel deposit reclaims on **timeout** rather than settling
  on-chain. Vouchers are off-chain, so this is the expected MPP shape, not a failure.

## 6. Payer state (read-only, public RPC)

```
chainId               0xa5bf = 42431        ✓
nonce  (latest)       21
native gas balance    seeded sentinel (Tempo testnet ~free gas)
pathUSD balanceOf     1,999,997.624119 pathUSD   (well-funded)
```

## 7. Verify it yourself

The explorer (`explore.testnet.tempo.xyz`) is a custom SPA with **no public REST API** (its
indexer `tidx.tempo.xyz` needs auth), so this evidence was reconstructed from the **public RPC**
`https://rpc.moderato.tempo.xyz` via `eth_getLogs` — anyone can re-run it:

```bash
RPC=https://rpc.moderato.tempo.xyz
TX=0xaa213739980b114a516ac38588703be1cd72fa4ef96d1e9b98227ce990cb915b

# the transaction + receipt (status 0x1, to = MPP precompile 0x4d5050…)
curl -s $RPC -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["'$TX'"]}'

# payer pathUSD balance (TIP-20 balanceOf @ 0x20c0…, 6 decimals)
curl -s $RPC -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x20c0000000000000000000000000000000000000","data":"0x70a082310000000000000000000000009bd2b3c6dc9bdf069333eaec42596e6d119c9f70"},"latest"]}'
```

## 8. Reproduce the full run

```bash
cd tempRouter
# fund a Tempo testnet key (see README), then:
SERVER_URL=https://temprouter.onrender.com AGENT_PRIVATE_KEY=0x… npm run agent
#   → detect → DCAP verify → encrypt → open MPP channel (on-chain) → pay per chunk → decrypt
# free attestation gate only (no payment):
SERVER_URL=https://temprouter.onrender.com npm run cli -- verify
```

---

## 9. Multi-use-case run — three confidential-compute scenarios (2026-06-19)

`npm run usecases` was run against the live deployment with a funded testnet key. All
three scenarios cleared the gate and paid, each via its own MPP session.

| | scenario | detector trigger | pre-pay DCAP | post-pay receipt | paid |
|---|---|---|---|---|---|
| 1 | Leaked credential → incident response | `openai-key`, `high-entropy-token` | ✅ genuine TDX, UpToDate | ✅ ed25519 + quote-hash | 1 unit · 0.0002 pathUSD |
| 2 | Support ticket with PII → safe triage | `email` | ✅ genuine TDX, UpToDate | ✅ ed25519 + quote-hash | 1 unit · 0.0002 pathUSD |
| 3 | Wallet key exposure → security review | `hex-private-key` | ✅ genuine TDX, UpToDate | ✅ ed25519 + quote-hash | 1 unit · 0.0002 pathUSD |

**Total: 3 × 0.0002 = `0.0006` pathUSD.** Each run detected the sensitive payload locally
and forced the private lane; plaintext was decrypted only by the agent (it never touched
the relay).

| | |
|---|---|
| **Payer** | `0xA2056e417bF343328e0890702ed7c1961Eb4dbe0` |
| **Explorer** | https://explore.testnet.tempo.xyz/address/0xA2056e417bF343328e0890702ed7c1961Eb4dbe0 |

The three most recent MPP channel-open transactions at that address are these runs. (The
CLI does not surface per-run tx hashes; they are auditable on the explorer address page
above. Capturing the hash programmatically — via the MPP channel-open log — is a tracked
SDK follow-up.)

---

_Scope: Tempo Moderato **testnet**, pathUSD, OSS model (`gpt-oss:20b`) in the enclave.
Verification covers DCAP cert-chain + key binding + enclave ed25519 signature; code-measurement
pinning is opt-in (soft-pin by default). The enclave key is attached to the MPP session as a
settlement **label**, not an enforced gate — see `docs/adr/0002`. Captured 2026-06-18._
