# @veritylayer/guard

**A fail-closed *verify-before-you-act* gate for AI agents — keyless, x402-native, with a first-class Vercel AI SDK adapter.**

Your agent is about to spend, send, delete, or publish. `@veritylayer/guard` asks an **independent** service for an `allow / review / block` second opinion at the exact moment a mistake becomes permanent — and returns a **signed, independently re-verifiable verdict** you can prove to an auditor later, offline, without trusting anyone.

> Not "we signed a receipt that a call happened." **A re-verifiable *verdict*** — cryptographic proof that an action was independently judged safe, or a claim checked and supported. Fail-closed across guarding actions, verifying facts, detecting prompt-injection, and redacting PII.

- 🔒 **Fail-closed** — unsure ⇒ `review`/`block`, never a confident wrong `allow`.
- 🧾 **Ed25519-signed verdicts** — every receipt verifies **offline** against our published key at [`/.well-known/verity-pubkey.json`](https://api.veritylayer.dev/.well-known/verity-pubkey.json), forever, without us. `verifyReceipt()` is the convenient **free** live check (it POSTs to the issuer — use the key directly if you want an independent one).
- 🔑 **Keyless by default** — the core client holds no wallet and never pays silently. Paid routes answer [x402](https://x402.org); opt in to `x402Payer` to settle them, with a **spend cap and a chain pin** so a hostile 402 can't name its own price.
- 🧩 **Zero runtime deps** for the core client (uses global `fetch`, Node 18+).

Live now: `guard` from **$0.02/call**. Full guide → **https://veritylayer.dev/guard**

---

## Install

```bash
npm install @veritylayer/guard
```

## Quickstart

Verdicts are paid per call ($0.02–$0.35 in USDC on Base). Attach a wallet and you get one:

```ts
import { VerityClient } from "@veritylayer/guard";
import { x402Payer } from "@veritylayer/guard/payer";   // needs: npm i @x402/fetch @x402/evm viem

const v = new VerityClient({ fetch: await x402Payer(process.env.WALLET_KEY!) });

const res = await v.guard("Wire $4,000 USDC to 0x9a3f…c012 (invoice #221)", {
  context: "Invoice arrived via a scraped web page; address never seen before.",
  policy: "No new payees without human review.",
});
console.log(res.decision, res.risk);       // -> block 0.9
console.log(res.saferAlternative);         // -> "Halt payment. Cross-verify…"

if (res.receipt) {
  const check = await v.verifyReceipt(res.receipt);
  console.log(check.valid);                 // -> true (free live check; the receipt itself
                                            //    verifies offline against our published key)
}
```

**Without a wallet**, nothing is verified and we say so rather than pretending:

```ts
const v = new VerityClient();               // keyless: holds no key, pays nothing
const res = await v.guard("Wire $4,000 USDC to 0x9a3f…c012");
res.paymentRequired  // -> true
res.decision         // -> undefined. NO VERDICT EXISTS. Never treat this as an allow.
```

> Earlier releases of this README showed the keyless snippet printing `block 0.9`. It never
> did — it printed `undefined undefined`, because a 402 was never settled. Fixed, and the
> gate helpers now refuse to render a missing verdict as anything but missing.

`verifyReceipt()` is **free and always will be** — checking someone else's verdict costs you nothing.

### The payer holds your key. Here's exactly what it will and won't sign.

`x402Payer(key)` treats the 402 as **untrusted input**, because the endpoint isn't a trust
anchor (`VERITY_ENGINE_URL` is env-overridable, and DNS/TLS interception is real):

- **Spend cap** — default **$1.00** per call (~3× our priciest tier). A 402 naming more is
  refused *before* any signature. Set your own: `x402Payer(key, { maxPriceUsdc: "0.35" })`.
- **Chain pin** — Base (`eip155:8453`) only. Another chain is refused, not signed.

> ### ⚠️ Use `@x402/fetch`, not `x402-fetch`
>
> The unscoped **`x402-fetch`** (latest 1.2.0) is the **v1** protocol client: it reads the
> challenge from the response *body*. VerityLayer speaks **v2**, which carries the
> challenge in the `payment-required` *header* and leaves the body empty — so v1 clients
> don't get a 402 or a verdict, they get
> `TypeError: Cannot read properties of undefined (reading 'map')`.
> We're not exotic here: of nine live x402 sellers probed, **seven serve the v2 header only
> and none serve v1 alone**. The v2 line is the scoped **`@x402/*`** packages (2.x).
> Earlier versions of this README recommended the v1 package. That was wrong, and it meant
> the documented quickstart could not pay us at all.

Two more sharp edges the hand-rolled path has, which `x402Payer` closes for you:

1. v1's `maxValue` defaults to **$0.10** — below our `verify` default tier ($0.25) and pro
   ($0.35). Only the $0.02 tier fit under it, which is why it went unnoticed.
2. pinning a *signer* to a chain does **not** pin the *payment* — v1's selector falls back
   to whatever chain the 402 offers and then signs it, so a Base signer handed a polygon
   challenge emits a real polygon USDC authorization.

Prefer to own the money path yourself? Do — just register v2 and keep the policies:

```ts
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";

const client = new x402Client()
  .register("eip155:8453", new ExactEvmScheme(toClientEvmSigner(privateKeyToAccount(key))))
  .registerPolicy((_v, reqs) => reqs.filter((r) => r.network === "eip155:8453"))   // pin the chain
  .registerPolicy((_v, reqs) => reqs.filter((r) => BigInt(r.amount) <= 1_000_000n)); // cap the spend

const v = new VerityClient({ fetch: wrapFetchWithPayment(fetch, client) });
```

---

## Vercel AI SDK

Give the model a guard tool it can call before acting:

```ts
import { VerityClient } from "@veritylayer/guard";
import { verityGuardTool } from "@veritylayer/guard/vercel";
import { generateText } from "ai";

const v = new VerityClient({ fetch: await x402Payer(process.env.WALLET_KEY!) });

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
| `verify(claim, opts)` | true? `supported / unsupported / uncertain` (signed) | **$0.25 by default** ⚠️ |
| `detectInjection(content, opts)` | is this untrusted text an injection? | $0.02 |
| `moderate(content, opts)` | safe to publish? | $0.02 |
| `redact(payload, opts)` | any PII/secrets? (returns redacted copy) | $0.02 |
| `verifyReceipt(receipt)` | is this signed verdict authentic? | **free** |

> ⚠️ **`verify()` is the one method that does not default to the $0.02 tier.** A bare
> `v.verify(claim)` runs the **`grounded`** tier — live web citations, **$0.25**, 12.5× the
> $0.02 anchored above. That is the right default for "is this claim true" (the cheap tier is
> ungrounded and won't cite), but you should choose it, not discover it on a bill. Pass
> `{ tier: "quick" }` for $0.02 or `{ tier: "pro" }` for $0.35. The same default applies to
> `verityVerifyTool`, which the **model** invokes — so the model controls how many $0.25 calls
> you make. Every price is disclosed in the 402 before anything is signed, and `x402Payer`'s
> $1.00 cap bounds a single call regardless.

Every call returns a `VerityResult` with `.decision`, `.decisionIs()`, `.risk`, `.allowed`, `.blocked`, `.flagged`, `.reasons`, `.saferAlternative`, `.receipt`, `.price`, `.paymentRequired`, and `.raw` (the full untouched response).

Compare decisions with `.decisionIs("review")`, never `=== "review"` — a case variant compares unequal and silently skips your branch.

## Doctrine
Fail-closed · evidence never invented · `allow`/`review`/`block` priced identically (no block-to-bill) · disclosed pay-per-use via x402 · holds no key, never charges silently.

MIT · [veritylayer.dev](https://veritylayer.dev) · [wire-in guide](https://veritylayer.dev/guard)
