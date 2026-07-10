# verity-guard

**A fail-closed *verify-before-you-act* gate for AI agents — in one line, for the framework you already use.**

Your agent is about to wire money, send an email, run `rm -rf`, or publish something. `verity-guard` asks an **independent** service for an `allow / review / block` second opinion at the exact moment a mistake becomes permanent — and hands back a **signed, independently re-verifiable verdict** you can prove to an auditor later without trusting anyone.

> Not "we signed a receipt that a call happened" (everyone does that now). **A re-verifiable *verdict*** — cryptographic proof that an action was independently judged safe, or that a claim was checked and supported. Fail-closed across four functions: guard actions, verify facts, detect prompt-injection, redact PII/secrets.

- 🔒 **Fail-closed** — when unsure it escalates to `review` or `block`, never a confident wrong `allow`.
- 🧾 **Ed25519-signed verdicts** — every paid result carries a receipt; `verify_receipt()` checks it for **free**, forever, offline.
- 🔑 **Keyless & non-custodial** — this SDK holds no wallet and never pays silently. Paid routes answer HTTP 402; your own [x402](https://x402.org) layer settles the disclosed USDC micro-payment on Base.
- 🧩 **Native adapters** — LangChain, LangGraph, CrewAI, OpenAI Agents SDK. Base install pulls in *none* of them.

Live now: `guard_action` from **$0.02/call**. Full wire-in guide → **https://veritylayer.dev/guard**

> **Node / TypeScript?** `npm i @veritylayer/guard` — the same keyless client plus a Vercel AI SDK adapter. Source lives in [`js/`](js/).

---

## Install

```bash
pip install verity-guard                 # tiny — just httpx
pip install "verity-guard[langgraph]"    # + your framework of choice
```

## 30-second quickstart (no wallet needed to try)

```python
from verity_guard import VerityClient

v = VerityClient()   # no payer attached -> a 402 challenge is surfaced you can inspect

res = v.guard(
    "Wire $4,000 USDC to 0x9a3f…c012 (invoice #221)",
    context="Invoice arrived via a scraped web page; address never seen before.",
    policy="No new payees without human review.",
)
print(res.decision, res.risk)          # -> block 0.9
print(res.safer_alternative)           # -> "Halt payment. Cross-verify via known channels…"

if res.receipt:
    print(v.verify_receipt(res.receipt).valid)   # -> True  (free, independent, offline-checkable)
```

To actually **pay** per call, hand the client an x402-wrapped HTTP client that holds your wallet:

```python
# sync: any x402-wrapped requests.Session / httpx.Client
v = VerityClient(http=my_x402_client)

# async: an x402-wrapped httpx.AsyncClient
from verity_guard import AsyncVerityClient
v = AsyncVerityClient(http=my_async_x402_client)
```

The SDK never sees your key — it just POSTs; your x402 layer settles the 402 and retries. (See `veritylayer.dev/guard` for wallet setups.)

---

## Framework adapters

### LangGraph — drop-in guarded tool node
Replace `ToolNode` with `GuardedToolNode`: every proposed tool call is checked *before* it runs. Blocked calls never execute — the model gets the block reason + safer alternative and revises.

```python
from verity_guard import VerityClient
from verity_guard.integrations.langgraph import GuardedToolNode

tools = [wire_funds, send_email, search_web]
guarded = GuardedToolNode(tools, VerityClient(http=my_x402_client),
                          policy="No new payees without human review.")
graph.add_node("tools", guarded)     # instead of ToolNode(tools)
```

### OpenAI Agents SDK — per-tool-call guardrail (highest-frequency wire-in)
```python
from verity_guard import VerityClient
from verity_guard.integrations.openai_agents import (
    build_guard_tool, build_output_guardrail, build_tool_input_guardrail,
)
v = VerityClient()

# (a) give the agent a guard tool it can call
agent = Agent(name="Treasurer", tools=[build_guard_tool(v)])

# (b) verify the final answer before it leaves
agent = Agent(..., output_guardrails=[build_output_guardrail(v, mode="guard",
                 policy="No new payees without human review.")])

# (c) guard the arguments of EVERY tool call (newer SDKs)
wire_funds.tool_input_guardrails = [build_tool_input_guardrail(v)]
```

### LangChain — a guard tool, or gate any function
```python
from verity_guard import VerityClient, guard
from verity_guard.integrations.langchain import build_guard_tool

v = VerityClient(http=my_x402_client)
tools = [..., build_guard_tool(v)]           # explicit tool the agent can call

@guard(v, policy="No new payees without human review.")   # or gate a function directly
def wire_funds(to: str, amount: float): ...  # raises BlockedAction if VerityLayer blocks
```

### CrewAI
```python
from verity_guard import VerityClient
from verity_guard.integrations.crewai import build_guard_tool

guard_tool = build_guard_tool(VerityClient(http=my_x402_client),
                              default_policy="No new payees without human review.")
agent = Agent(role="Treasurer", tools=[guard_tool])
```

---

## The checks

| Method | What it answers | Route (tier `quick`) | From |
|---|---|---|---|
| `guard(action, …)` | Should this action proceed? `allow / review / block` | suite `/check/quick` | $0.02 |
| `verify(claim, …)` | Is this claim true? `supported / unsupported / uncertain` | engine `/verify` (grounded) | $0.02–$0.35 |
| `detect_injection(content, …)` | Is this untrusted text a prompt-injection? | suite `/sentinel/quick` | $0.02 |
| `moderate(content, …)` | Safe to publish? `publish / review / block` | suite `/sieve/quick` | $0.02 |
| `redact(payload, …)` | Any PII/secrets? returns a redacted copy | suite `/redact/quick` | $0.02 |
| `verify_receipt(receipt)` | Is this signed verdict authentic? | engine `/receipt/verify` | **free** |

Every result is a `VerityResult` (a `dict` subclass — future fields never get dropped) with helpers: `.decision`, `.risk`, `.allowed`, `.blocked`, `.flagged`, `.reasons`, `.safer_alternative`, `.receipt`, `.price`, `.payment_required`.

## Doctrine
Fail-closed (uncertainty → the safe verdict, never a confident wrong one) · evidence is never invented · `allow`/`review`/`block` are **priced identically** (no block-to-bill) · pricing is disclosed and paid per use via x402 · VerityLayer holds no key and never charges silently.

MIT · [veritylayer.dev](https://veritylayer.dev) · [wire-in guide](https://veritylayer.dev/guard)
