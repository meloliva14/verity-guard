# @veritylayer/openclaw-plugin

**A gate on the irreversible step — in OpenClaw's tool-call path, where it can't be skipped.**

Your agent is about to run a shell command, overwrite a file, or execute generated code. This
plugin asks an **independent** service for an `allow / review / block` verdict *first*, and
turns that verdict into OpenClaw's own controls: pass through, raise a human approval, or block
with a reason.

```bash
openclaw plugins install clawhub:@veritylayer/openclaw-plugin
```

```jsonc
// openclaw config
{
  "plugins": {
    "entries": {
      "verity-gate": {
        "enabled": true,
        "policy": "No new payees without human review. Never curl|sh.",
        "onUnavailable": "review"   // or "block". There is no "allow".
      }
    }
  }
}
```
Set `VERITY_WALLET_KEY` (a Base wallet holding a little USDC) and each check settles $0.02 via
x402. Without it, checks return `payment_required` — and the plugin says so out loud instead of
pretending it verified anything. Installing requires a Gateway restart.

---

## Why a plugin and not a skill

We also ship a `verity-guard` **skill**. It's honest about its own ceiling, and so are we:

> A skill is markdown. OpenClaw injects its name and description into the prompt, and the model
> decides whether to follow it. That's a fine way to **offer** a capability and a useless way to
> **enforce** a rule — a prompt-injected agent is precisely the agent that skips its safety step.

The plugin sits in the tool-call path. The model doesn't get a vote.

### What we claim, exactly

- ✅ **"Verifies every command your agent tries to run."** True on this path — it sees every
  agent-initiated `exec`, including allowlist hits that never raise an approval.
- ❌ **"Nothing executes without our verdict."** **False, and we won't say it.** A `node.invoke`
  from another authenticated operator bypasses the agent entirely, node hosts carry their own
  local approval policy, and `tools.exec.mode: full` bypasses approvals outright.

We'd rather ship the smaller true claim. That is the whole product.

## What it gates

`exec`, `write`, `edit`, `apply_patch`, `process`, `code_execution`, `terminal` — override with
`gatedTools`.

`read` is deliberately excluded: gating a read spends money to bless something that can't be
undone because it was never done.

> Note: gate **`exec`**, not `bash`. OpenClaw aliases `bash` → `exec` before any hook sees it, so
> a plugin matching on `"bash"` silently never fires on the most dangerous tool there is.

## When VerityLayer can't answer

This is the part most guards get wrong, so here's ours in full.

OpenClaw registers `before_tool_call` **fail-closed**: if a handler throws or times out, the tool
is blocked. Good posture — but taken naively it means our bad afternoon becomes your dead agent.
And the opposite (swallow the error, let it run) is the fail-open that makes a safety product a
liability.

So we take neither. When **no verdict exists** — we're unreachable, the payment wasn't settled,
the response was malformed, the decision was unrecognized — the default is `onUnavailable:
"review"`: the action stops and OpenClaw asks **you**, with the reason printed. Prefer a hard
stop? Set `"block"`.

**There is deliberately no `"allow"` option.** An unverified action must never pass as verified.
That's not a setting; it's the product.

A blocked verdict and a missing verdict never render the same:

```
VerityLayer blocked this (risk 0.92): recipient unseen in 30 days. Safer: hold for confirmation.
VerityLayer did NOT verify this action: guard unreachable: timeout. No verdict exists — this is not an allow.
```

## Config

| key | default | what it does |
|---|---|---|
| `gatedTools` | the 7 above | which tools to verify |
| `policy` | — | your standing rule, passed to every check |
| `tier` | `quick` | `quick` $0.02 · `standard` $0.08 · `pro` $0.20 |
| `timeoutMs` | `8000` | per-check budget |
| `onUnavailable` | `review` | `review` asks you · `block` refuses. No `allow`. |
| `maxPriceUsdc` | `1.00` | hard per-call spend ceiling |

Env: `VERITY_WALLET_KEY` — the only place a key is read. The plugin never logs it, and the
payer it builds is **spend-capped and pinned to Base**, so a hostile 402 can't name its own
price or chain.

## Approvals are one-shot

The approval card offers **allow-once** and **deny** — never *allow-always*. A standing allow is
the gate removing itself, and the next call with that same tool is the one that matters.

## Receipts

Every paid verdict carries an Ed25519-signed receipt you can verify for free, forever, offline —
proof of what was decided for what action. Rip VerityLayer out and you lose the audit trail.

---

MIT · [veritylayer.dev/guard](https://veritylayer.dev/guard) · built on
[`@veritylayer/guard`](https://www.npmjs.com/package/@veritylayer/guard)
