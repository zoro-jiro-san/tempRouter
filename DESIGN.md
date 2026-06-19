# tempRouter — Attestation-Gated Private Inference on Tempo

> **FINAL LOCKED DESIGN + 4-DAY BUILD PLAN.** Berlin MPP Hackathon @ Futura Camp 2026. Submit **June 20, 9:00 AM**.
> This document already folds in every required change from the adversarial review. Read the **honesty box** in each section — it states exactly what is real vs. stubbed.

> **⚠️ Historical planning doc — read `docs/adr/` for the as-built truth.** A few build-plan
> details evolved during implementation: the offline path is now a single **stub mode**
> (`teeType: STUB-NO-TDX`, null quote → the agent fail-closes) rather than a mock LLM
> streamer with an `x-temprouter-attestation` header (that mock was never built and its
> dead config was removed). The attestation→payment binding ships as an unenforced
> **label**, not a settlement gate (ADR-0002 §4). Where this doc and the ADRs disagree,
> the ADRs win.

---

## 1. Pitch + the precise, defensible privacy claim

**One-liner:** A payable inference endpoint on MPP where the prompt is **end-to-end encrypted to a real Phala Intel TDX enclave**, and the paying agent runs a **real Intel DCAP verification** of the live quote before signing the first voucher — *pay only what you can prove is private*.

**The privacy claim, scoped to EXACTLY what runs live (this is the slide text):**

> Prompts are client-side encrypted (Arcium RescueCipher + X25519 ECDH, via `@solrouter/sdk`) to a key that exists only inside a real Phala Intel TDX enclave. Before any money moves, the payer verifies, against the live enclave:
> 1. **Intel DCAP signature chain** — `getCollateralAndVerify(rawQuote)` from `@phala/dcap-qvl` proves the quote is genuine Intel TDX hardware (PCK chain → Intel root + TCB). *This is the load-bearing silicon proof, not optional.*
> 2. **Key binding** — the quote's `report_data` equals `sha512("app-data:" ‖ sha256(teePub ‖ enclavePub))` — binding the X25519 sealing key + ed25519 signing key to that silicon.
> 3. **Enclave signature** — the in-enclave ed25519 key signed *this exact ciphertext* (`SOLR-ATTEST-v2` envelope).
> 4. **Confidentiality** — the prompt is encrypted to the enclave's X25519 key (the same key the quote's `report_data` attests), so the blind relay forwards only ciphertext and a swapped enclave cannot decrypt what you paid to send.
> 5. **Measurement (transparency)** — the quote's `mrtd`/`rtmr` are displayed and compared to the value `/attestation` advertised at boot (soft-pin); with `EXPECTED_MEASUREMENT` set, mismatch is rejected (strict-pin).
>
> **Full transparency:** the agent prints a per-check PASS/FAIL report with the raw values, so the payer verifies *all of it* independently — nothing is taken on trust.

**What we do NOT claim (stated on the slide, pre-empting the kill-shots):**
- By default we **soft-pin** the code measurement (`mrtd`/`rtmr`): we compare-to-advertised + display, which proves *"the same enclave the service advertised"*, NOT *"a trusted reproducible build"*. Strict-pin to a published constant is opt-in via `EXPECTED_MEASUREMENT`; a fully reproducible-build measurement is the documented next step.
- The verify-before-pay decision lives in **our agent**, enforced as ordinary control flow (not an mppx protocol hook — mppx 0.7.0 has none). A failed verify means the agent never constructs the payer, so **zero vouchers are signed** — the money-not-moving decision is the agent's, by construction. We attach the enclave key to the session `meta` as a settlement *label*, but neither side enforces a voucher↔enclave gate (no mppx settlement hook exists).
- The reused crypto + TEE stack is **chain-agnostic by design** — that is a strength (real, audited-in-prod). The contribution is a **discoverable, payable confidential-inference endpoint on MPP**: provable confidentiality (E2E-encrypted to a DCAP-verified TDX enclave) fronted by a standard MPP `session` 402 flow.
- We do **NOT** claim a billed unit == one LLM token. The real enclave `/process` is `stream:false` (returns one re-encrypted blob) and tempRouter is **blind**, so it cannot count plaintext tokens. We meter **`unitType: 'response-chunk'`** — MPP's server-defined-unit model (the spec's flagship example charges one *word* = one unit; *"the protocol specifies the payment mechanics, not the resource output format"*). Billing-by-ciphertext-chunk is *consistent with* the blindness, not a workaround. True per-model-token billing would require the enclave to emit a cleartext token count → post-hackathon.

---

## 2. Folded-in fixes from the adversarial review (traceability)

| Attack (lens) | Required fix | Where it lands |
|---|---|---|
| **Privacy-is-marketing** | Real DCAP verify; route real ciphertext on the wire | `verifyAttestation.ts` ports `verify-attestation.mjs` **verbatim** (DCAP + correct `sha512("app-data:"‖…)` binding + ed25519 sig). `upstream.ts` `teeProcess()` POSTs `packageForTEE(encrypt())` ciphertext to `TEE_ENDPOINT/process`; private route **never reads `messages` plaintext**. §6 demo proves it on the wire (`tcpdump`/proxy log). |
| **Invented `sha256(teePublicKey)===reportDataHex` check** | DELETE it — false against the genuine enclave | The paid `/process` quote binds `sha256(X25519‖ed25519)` then the verifier wraps `sha512("app-data:"‖…)`. We use the **verifier's** formula (it passes against prod today). |
| **No MPP novelty** | Ship a clean, discoverable payable endpoint; differentiate on confidentiality | tempRouter is a live MPP `session` endpoint (402 → pay-per-response-chunk → SSE) discoverable via `/openapi.json` + `/llms.txt`. The differentiator is **provable confidentiality on a paid endpoint** — E2E-encrypted to a DCAP-verified TDX enclave, blind relay. (An earlier design bound the quote digest into settlement server-side — NOT built; mppx 0.7.0 has no settlement hook.) |
| **4-day infeasibility / no pre-voucher hook** | Stop relying on `sessionManager.sse()` for the gate (it has only `onReceipt`+`signal`; `onChallenge` auto-drives) | Gate is **standalone control flow**: `verifyAttestation()` runs to completion and throws *before* `sessionManager` is ever constructed. Wrong hash → throw → `.sse()` never reached → zero vouchers. Drop all "intercept open→first-voucher" language. |
| **Live-demo robustness / TEE-down** | Fallback must be a LOUD, code-enforced state | `config.ts` resolves `mode: 'tdx-live' | 'stub' | 'down'` via boot healthcheck. Stub `/tee/attestation` returns `teeType:'STUB-NO-TDX'`, `tdxQuote:null`; mock path sets header `x-temprouter-attestation: stub`. Badge green **only** when `teeType==='INTEL-TDX-PHALA' && tdxQuote!==null && DCAP valid`. Pre-recorded primary demo + pre-funded keys. SSE keepalive `:\n\n` every 15s. |
| **Proof↔payment seam / report_data mismatch** | Pin the exact prod-passing byte formula | Verifier pins the **`sha512("app-data:"‖sha256(teePub‖enclavePub))`** bytes from `verify-attestation.mjs:48` — the one that passes live. (No quote-digest-into-`externalId` binding — see the row above.) |

**Honesty box (global):** Until tasks T2+T4 are green against the live Phala CVM, the honest claim is *"private-inference architecture with a real client-side DCAP gate"* — not *"the paid server cannot read your prompt."* The agent's `verifyAttestation()` (fail-closed, prints the verdict + quote digest to stdout) makes that distinction physically un-fakeable on stage: a failed/stubbed quote ⇒ zero vouchers, no transfer, by construction.

---

## 3. Request → payment → inference flow (numbered)

0. **Agent policy gate (client-side, before any bytes leave).** The agent runs `detectSensitive(prompt)` (regex/entropy: API keys, private keys, JWTs, emails, …). **Hit → force the private attested lane** (steps 1–8). No hit → the agent is free to use any public/frontier model (out of tempRouter's scope). The detector must be client-side: tempRouter is blind and cannot classify ciphertext.
1. **Agent POSTs** `/v1/chat/completions/stream` with **no credential**. Server replies **402** (`mppx.session({ amount: pricePerUnit, unitType:'response-chunk', description:'Private inference in a real Phala Intel TDX enclave', meta:{ enclaveKey } })`). `meta.enclaveKey` is the live enclave's stable `teePublicKeySha256` (mppx HMAC-signs it into the challenge `opaque`) — a settlement **label** naming the enclave; it is not an enforced gate (see step 8).
2. **Agent** then calls **`GET /tee/attestation`** on tempRouter (blind passthrough to the real Phala `GET /attestation`) → `{ teeType, teePublicKey, teePublicKeySha256, reportDataHex, tdxQuote }`. For the *paid* path it also triggers a real `/tee/process` attestation envelope (`encryptionProof`) so it has the ed25519 sig + `tdxQuoteHash` to check.
3. **Agent VERIFIES** (`verifyAttestation.ts`, ported verbatim from `verify-attestation.mjs`), fail-closed:
   - (a) **DCAP**: `getCollateralAndVerify(rawQuote)` returns valid (Intel-signed, TCB ok).
   - (b) **Key binding**: `report_data === sha512("app-data:" ‖ sha256(teePub ‖ enclavePub))`.
   - (c) **Enclave sig**: ed25519 over the `SOLR-ATTEST-v2` ciphertext message verifies.
   - (d) **Quote self-consistency**: `sha256(JSON.stringify(tdxQuote)) === ep.tdxQuoteHash` (the enclave committed to its own quote digest). *Not* a voucher binding.
   - (e) **Measurement**: `mrtd`/`rtmr` match the boot-advertised value (soft-pin); if `EXPECTED_MEASUREMENT` set, must equal it (strict-pin).
   - **Transparency:** prints a per-check PASS/FAIL report + raw values so the payer can verify each independently.
   - **Any failure → throw, sign ZERO vouchers, abort.** (`teeType==='STUB-NO-TDX'` or `tdxQuote===null` → structural fail here.)
4. **Only after step 3 passes** does the agent call `@solrouter/sdk` `encrypt(prompt, TEE_ENDPOINT)` + `packageForTEE()` (ciphertext bound to the verified X25519 key), **then** construct `sessionManager({account,client,decimals:6,maxDeposit})` and call `.sse(url, init)`. The gate is plain control flow — verify *then* instantiate payer.
5. **tempRouter is blind**: forwards the ciphertext bundle to the real Phala `POST /tee/process`. The private route **never** JSON-parses or logs `messages` plaintext.
6. **Enclave** decrypts inside hardware isolation, runs Nosana/Ollama inference, re-encrypts, returns ciphertext + fresh attestation envelope.
7. **Per-unit SSE billing (MPP-canonical).** The real `/process` returns ONE re-encrypted blob (`stream:false`) and the relay is blind, so tempRouter slices that ciphertext into N ordered chunks and feeds them to `Sse.serve({store, channelId, challengeId, tickCost, generate})` — each chunk = one `unitType:'response-chunk'` voucher tick (MPP's server-defined-unit model). `payment-need-voucher` → agent auto-top-up; final `payment-receipt`. Agent reassembles the chunks and `decrypt()`s the full blob. Keepalive `:\n\n` every 15s survives NAT idle-timeout.
8. **Settlement.** mppx settles the session vouchers; channel = **open + close ≈ 2 on-chain txs**, vouchers off-chain. NB: there is **no** custom server-side voucher-refusal gate — `meta.enclaveKey` is an HMAC'd *label*, not an enforced check (mppx 0.7.0 exposes no pre-settlement hook). The enforcement that matters is the agent's **verify-before-pay** (step 3): a bad enclave means the agent never signs a voucher, and a swapped enclave can't decrypt the ciphertext it was paid to process.
9. **Discoverable on mpp.dev/services**: tempRouter serves `GET /openapi.json` (OpenAPI 3.1) annotated with root `x-service-info` (`categories:['ai','inference','privacy']`, `docs.homepage`, `docs.llms:'/llms.txt'`) and per-operation `x-payment-info.offers` (`{amount, currency: pathUSD, intent:'session', method:'tempo'}`), with the paid route declaring a `402` response. A `/llms.txt` gives agents full context. Emitted as a hand-built OpenAPI 3.1 document (the same shape mppx `discovery()` produces). The service is then indexed by registering: GitHub PR to the mpp.dev/services repo + one-click submit on MPPScan. Discovery is advisory; the runtime 402 challenge stays authoritative. **No human/browser payer surface — agent-only.**

---

## 4. Reused from SolRouter vs. newly built

**Reused verbatim (do NOT rebuild — this is a strength):**
- `@solrouter/sdk` `encrypt()` / `decrypt()` / `packageForTEE()` / `fetchTeePublicKey()` / `clearSession()` — Arcium RescueCipher + X25519, packed31 format (`packages/sdk/src/encryption.ts`).
- The real Phala Intel TDX CVM **unchanged** (`tee-service/src/index.js`): `GET /attestation` (`reportData=sha256(TEE_PUBLIC_KEY)`, `tdxQuote`), `GET /public-key`, `POST /process` (decrypt+infer+re-encrypt in-enclave; emits `encryptionProof` with `enclavePubkey`, `teePubkey`, `tdxQuoteHash`, ed25519 sig, `reportData=sha256(X25519‖ed25519)`).
- `dev/backend/verify-attestation.mjs` — **ported verbatim** as `verifyAttestation.ts` (the DCAP + `sha512("app-data:"‖…)` binding + ed25519 logic; this is the only correct, prod-passing formula).

**Newly built (tempRouter):**
- `src/verifyAttestation.ts` — TS port of the `.mjs` verifier (DCAP, binding, ed25519, quote-digest match).
- `src/agent.ts` — paying client: `detectSensitive(prompt)` policy gate → 402 → fetch attestation → `verifyAttestation()` (throw-on-fail) → `encrypt()` → `sessionManager().sse()` → reassemble chunks → `decrypt()`.
- `src/detectSensitive.ts` — client-side secret/PII detector (regex + entropy: API keys, private keys, JWTs, emails); returns `{sensitive, matches[]}`. Forces the private lane on a hit.
- `src/upstream.ts` — add `teeProcess(ciphertextBundle)` (POST to `TEE_ENDPOINT/process`); keep mock **only** as the loud, header-flagged honest fallback.
- `src/server.ts` — `GET /tee/attestation` + `GET /tee/public-key` blind passthrough; set session `meta.enclaveKey = teePublicKeySha256` (settlement label); never read private-route plaintext. Serve a hand-built `GET /openapi.json` (MPP discovery shape) + `GET /llms.txt`.
- `src/config.ts` — `teeEndpoint`, `mode` resolver (`tdx-live|stub|down`).
- `public/llms.txt` + a hand-built `/openapi.json` — MPP service-discovery surface so tempRouter is listable on mpp.dev/services + MPPScan.
- `.env.example` — `TEE_ENDPOINT`.

**Dropped from SolRouter:** Solana Light Protocol on-chain attestation (`services/lightAttestation.js`) and the `onchainAttestation` field. We keep the **chain-free** hardware TDX quote only. Payment is 100% Tempo/pathUSD.

**Dropped from scope:** the human/browser payer surface (mppx `charge` + HTML payment page + Tempo Wallet checkout). tempRouter is **agent-only**; the only "directory" presence is the machine-readable discovery doc for agents/registries (mpp.dev/services), not a human UI.

---

## 5. Ordered 4-day task list (mock-first; testnet funds never block)

> **Mock-first principle:** every task has a green acceptance check that runs **offline** (local enclave-stub + local mppx store). Live testnet money is exercised ONLY in T7, last, after the recording is in the can.

| # | What | Files | Acceptance check | Size | Depends |
|---|------|-------|------------------|------|---------|
| **T0** | Pin deps: add `@phala/dcap-qvl`, `@solrouter/sdk`, `viem`; confirm `mppx@0.7.0`. Add `TEE_ENDPOINT` to `.env.example`. | `package.json`, `.env.example` | `npm i` clean; `node -e "require('@phala/dcap-qvl')"` resolves | S | — |
| **T1** | `config.ts` mode resolver: boot healthcheck `GET TEE_ENDPOINT/attestation` → `mode = tdx-live | stub | down`. | `config.ts` | Unit: unset `TEE_ENDPOINT` → `stub`; bad host → `down`; live → `tdx-live` | S | T0 |
| **T2** | `verifyAttestation.ts` — port `verify-attestation.mjs` verbatim to TS (DCAP, `sha512("app-data:"‖sha256(teePub‖enclavePub))` binding, ed25519 sig, `sha256(tdxQuote)` digest). **Delete the invented `sha256(teePublicKey)` check.** Add **transparency report** (per-check PASS/FAIL + raw values) + `mrtd`/`rtmr` soft-pin (compare-to-advertised) with opt-in `EXPECTED_MEASUREMENT` strict-pin. | `verifyAttestation.ts` | Against a **cached real `/process` fixture** (T6) → all checks PASS + report prints every field; tamper 1 quote byte → DCAP throws → returns false; swapped measurement → fails (e) | **L** | T0 |
| **T3** | `upstream.ts` `teeProcess(bundle)` → POST `TEE_ENDPOINT/process`; mock path sets `x-temprouter-attestation: stub`. Private route never parses `messages`. | `upstream.ts` | Stub mode → response carries stub header; live mode → returns enclave ciphertext (no plaintext in logs) | M | T1 |
| **T4** | `server.ts` — `GET /tee/attestation`+`/public-key` passthrough; session `meta.enclaveKey=teePublicKeySha256` (settlement label); never read private-route plaintext. | `server.ts` | Curl `/tee/attestation` mirrors enclave; session carries the enclave-key label; blind relay logs no plaintext | **L** | T1, T3 |
| **T5** | **MPP discovery**: serve a hand-built `GET /openapi.json` with `x-service-info` (`categories`, `docs.homepage`, `docs.llms`) + per-op `x-payment-info.offers` ({amount, pathUSD, intent:'session', method:'tempo'}) + `402` response; serve `GET /llms.txt`. Draft the mpp.dev/services PR + MPPScan submission. | `server.ts`, `public/llms.txt` | `/openapi.json` validates as MPP discovery doc (x-service-info + x-payment-info present, 402 declared); `/llms.txt` 200s; PR drafted (not opened w/o ok) | M | T4 |
| **T6** | Local **enclave-stub** + capture one **real** `/process` + `/attestation` fixture (non-null `tdxQuote`) from live Phala CVM. Stub = real X25519+ed25519 keypair, self-signed "stub quote" so SDK `encrypt()/decrypt()` round-trips offline; `tdxQuote:null` so verifier hard-fails. | `scripts/stub-enclave.mjs`, `fixtures/attestation.json` | SDK encrypt→decrypt round-trips against stub offline; `verifyAttestation(fixture)` green; `verifyAttestation(stub)` red | M | T2 |
| **T7** | `agent.ts` + `detectSensitive.ts` — policy gate `detectSensitive(prompt)` → on hit: 402 → attestation → `verifyAttestation()` (throw-on-fail, **before** `sessionManager`) → `encrypt()` → `sessionManager({decimals:6,maxDeposit:high}).sse()` → `decrypt()`. SSE keepalive `:\n\n`. | `agent.ts` | **Offline (mock+stub):** stub/bad quote → DCAP fails → throws → zero vouchers; genuine → chunks stream. **Online (T9):** on-chain delta == `units*pricePerUnit*1e6` | **L** | T2, T4, T6 |
| **T8** | **Record primary demo** (local network, both runs) as MP4. | — | MP4 plays both runs: refuse→no-pay, verify→pay-with-tick | S | T7 |
| **T9** | **Live testnet pass** (June 19): pre-fund **two** keys via faucet; verify balances on-chain that morning; confirm `decimals:6` charge delta exact. | — | Two runs live; explorer shows transfer only on the verified run | M | T7, T8 |
| **T10** | Slide + this README; 3-min script rehearsal. | `README.md`, slides | Dry-run ≤ 3:00 incl. fallback | S | T8 |

**Critical path:** T0→T2→T6→T7→T8→T9. T2 and T7 are the load-bearing **L**s — start T2 day 1. **Hard stop: T8 (recording) done by June 19 PM** so a dead venue wifi / drained faucet cannot zero the demo.

---

## 6. 3-minute demo script (with wow + no-funds fallback)

**[0:00–0:30] Frame.** "tempRouter: pay an LLM per streamed unit in stablecoin on Tempo — *but only after you cryptographically prove the inference runs in a real Intel TDX enclave that can't read your prompt.* Same endpoint, two runs. The only difference is whether privacy is provable."

**[0:30–0:50] The trigger.** Hand the agent a task whose prompt contains a **secret** (e.g. an `sk-...` API key / a private key). `detectSensitive()` fires on stdout: `sensitive payload detected (api-key) → forcing attested private lane`. "A normal agent would have just shipped that key to a model host. This one won't pay anyone who can't prove they're blind."

**[0:30–1:15] Run 1 — refusal.** Point `TEE_ENDPOINT` at a non-TDX host (or feed the cached fixture with one quote byte flipped). Run the agent. **`getCollateralAndVerify` throws / returns invalid** → agent prints `attestation FAILED: DCAP invalid — refusing to pay`, signs **zero vouchers**. Show Tempo explorer: **no transfer**.

**[1:15–2:30] Run 2 — the wow.** Point at the real Phala CVM. Agent prints `TDX verified: INTEL-TDX-PHALA, DCAP ok, key bound, enclave sig ok`. **Split screen:** left = `tcpdump`/proxy log showing the request body is **ciphertext** (not plaintext `messages`); right = tokens streaming in *while the on-chain pathUSD balance ticks* on the explorer. Close channel → ~2 txs. "Money moved only because privacy was provable, and the bytes on the wire were ciphertext — proven, not promised."

**[2:30–3:00] The MPP point + honest scope.** "What tempRouter is: a **discoverable, payable confidential-inference endpoint on MPP** — pay per response-chunk in pathUSD for inference that's E2E-encrypted to a TDX enclave you DCAP-verify *before* you pay. We verify the Intel cert chain + key binding + enclave signature; we do **not** enforce a voucher↔enclave settlement gate, and we do **not** pin code measurement — both are next."

**No-funds / TEE-down fallback (announced, never silent):**
- **Primary artifact is the pre-recorded MP4 (T8).** Play it first; run live only as a bonus.
- If live TEE is down at showtime: `mode` resolves `down`/`stub` → `/tee/attestation` returns `STUB-NO-TDX`, `tdxQuote:null`, mock sets `x-temprouter-attestation: stub`, and the **agent's `verifyAttestation()` hard-fails** (zero vouchers). Say out loud: *"Running the local enclave-stub — real SDK crypto round-trips, but I am NOT hitting TDX this run, so the badge is correctly red."* The green path is **physically un-reachable** on the stub.
- Pre-funded **two** testnet keys; balances confirmed the morning of.

---

## 7. One-sentence rebuttal per kill-question

1. **"Run the verifier live — DCAP to Intel root — and prove ciphertext on the wire; your `sha256(teePublicKey)` check fails the real enclave and your upstream sends plaintext."**
   → We deleted that invented check and ported `verify-attestation.mjs` verbatim: `getCollateralAndVerify` runs the Intel cert chain, the binding we check is `sha512("app-data:"‖sha256(teePub‖enclavePub))` (the formula that passes prod today), and the proxy log on stage shows the `/tee/process` body is `@solrouter/sdk` ciphertext, never `messages`.

2. **"Show me the one byte of NEW MPP behavior — your gate is just a client if-statement."**
   → Honest scope: the verify-before-pay gate *is* client-side control flow (mppx 0.7.0 has no settlement hook), and we don't claim otherwise. What tempRouter contributes on MPP is a **discoverable, payable confidential-inference endpoint** — a live `session` endpoint metering E2E-encrypted TDX inference per response-chunk in pathUSD, listed via `/openapi.json` + `/llms.txt`. The differentiator is *provable confidentiality on a paid endpoint*, not a new settlement primitive.

3. **"Show the line that BLOCKS the first voucher — mppx 0.7.0 has no pre-voucher hook."**
   → There is no protocol hook and we don't claim one: `verifyAttestation()` runs to completion and throws **before** `sessionManager` is ever constructed, so a failed verify means `.sse()` is never reached and zero vouchers are signed — ordinary fail-closed control flow.

4. **"When the TEE is down your 'honest fallback' silently runs the green path over a mock."**
   → It cannot: `mode` is resolved at boot, the stub `/tee/attestation` returns `STUB-NO-TDX` with `tdxQuote:null`, the mock sets header `x-temprouter-attestation: stub`, and the agent verifier is hard-wired to require `INTEL-TDX-PHALA + non-null quote + DCAP-valid`, so the stub forces verifier failure and zero payment by construction.

5. **"What ties a signed Tempo voucher to the specific attested enclave — your report_data is the wrong value anyway?"**
   → Honestly: nothing *enforces* a voucher↔enclave binding today — we attach the enclave's stable key as a `meta` label, but neither side refuses on a mismatch (mppx 0.7.0 has no settlement hook). The real tie is cryptographic, not on the voucher: the prompt is **encrypted to the enclave's X25519 key**, which (a) the quote's `report_data` attests via `sha512("app-data:"‖sha256(teePub‖enclavePub))`, and (b) the agent DCAP-verifies before paying — so a swapped enclave simply **cannot decrypt** what you paid to send. We pin the prod-passing formula; we do **not** pin the code measurement. A hard voucher-refusal gate is the documented next step.
