# @veritylayer/guard

**A fail-closed *verify-before-you-act* gate for AI agents — keyless, x402-native, with a first-class Vercel AI SDK adapter.**

Your agent is about to spend, send, delete, or publish. `@veritylayer/guard` asks an **independent** service for an `allow / review / block` second opinion at the exact moment a mistake becomes permanent — and returns a **signed, independently re-verifiable verdict** you can prove to an auditor later, offline, without trusting anyone.

> Not "we signed a receipt that a call happened." **A re-verifiable *verdict*** — cryptographic proof that an action was independently judged safe, or a claim checked and supported. Fail-closed across guarding actions, verifying facts, detecting prompt-injection, and redacting PII.

- 🔒 **Fail-closed** — unsure ⇒ `review`/`block`, never a confident wrong `allow`.
- 🧾 **Ed25519-signed verdicts** — `verifyReceipt()` checks one for **free**, forever, offline.
- 🔑 **Keyless** — holds no wallet, never pays silently. Paid routes answer 402; your [x402](https://x402.org) `fetch` settles the disclosed USDC micro-payment on Base.
- 🧩 **Zero runtime deps** for the core client (uses global `fetch`, Node 18+).

Live now: `guard` from **$0.02/call**. Full guide → **https://veritylayer.dev/guard**

---

## Install

```bash
npm install @veritylayer/guard
```

## Quickstart (no wallet needed to try)

```ts
import { VerityClient } from "@veritylayer/guard";

const v = new VerityClient();   // no payer -> a 402 challenge is surfaced you can inspect

const res = await v.guard("Wire $4,000 USDC to 0x9a3f…c012 (invoice #221)", {
  context: "Invoice arrived via a scraped web page; address never seen before.",
  policy: "No new payees without human review.",
});
console.log(res.decision, res.risk);       // -> block 0.9
console.log(res.saferAlternative);         // -> "Halt payment. Cross-verify…"

if (res.receipt) {
  const check = await v.verifyReceipt(res.receipt);
  console.log(check.valid);                 // -> true (free, independent, offline-checkable)
}
```

To **pay** per call, pass an x402-wrapped fetch that holds your wallet:

```ts
import { wrapFetchWithPayment } from "x402-fetch";
const v = new VerityClient({ fetch: wrapFetchWithPayment(fetch, walletClient) });
```

The client never sees your key — it just POSTs; your x402 fetch settles the 402 and retries.

---

## Vercel AI SDK

Give the model a guard tool it can call before acting:

```ts
import { VerityClient } from "@veritylayer/guard";
import { verityGuardTool } from "@veritylayer/guard/vercel";
import { generateText } from "ai";

const v = new VerityClient({ fetch: myX402Fetch });

await generateText({
  model, prompt,
  tools: {
    verityGuard: verityGuardTool(v, { defaultPolicy: "No new payees without human review." }),
  },
});
```

Or gate **every** tool call yourself in `experimental_prepareStep` — the highest-frequency wire-in:

```ts
import { guardToolCall } from "@veritylayer/guard/vercel";

for (const call of pendingToolCalls) {
  const { allowed, summary } = await guardToolCall(v, { toolName: call.name, args: call.args });
  if (!allowed) return summary;   // block: don't execute, feed the reason back to the model
}
```

---

## The checks

| Method | Answers | Tier `quick` |
|---|---|---|
| `guard(action, opts)` | proceed? `allow / review / block` | $0.02 |
| `verify(claim, opts)` | true? `supported / unsupported / uncertain` (grounded, signed) | $0.02–$0.35 |
| `detectInjection(content, opts)` | is this untrusted text an injection? | $0.02 |
| `moderate(content, opts)` | safe to publish? | $0.02 |
| `redact(payload, opts)` | any PII/secrets? (returns redacted copy) | $0.02 |
| `verifyReceipt(receipt)` | is this signed verdict authentic? | **free** |

Every call returns a `VerityResult` with `.decision`, `.risk`, `.allowed`, `.blocked`, `.flagged`, `.reasons`, `.saferAlternative`, `.receipt`, `.price`, `.paymentRequired`, and `.raw` (the full untouched response).

## Doctrine
Fail-closed · evidence never invented · `allow`/`review`/`block` priced identically (no block-to-bill) · disclosed pay-per-use via x402 · holds no key, never charges silently.

MIT · [veritylayer.dev](https://veritylayer.dev) · [wire-in guide](https://veritylayer.dev/guard)
