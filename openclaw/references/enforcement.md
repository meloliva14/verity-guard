# If you need enforcement, a skill is the wrong layer

Read this before you rely on `verity-guard` to *stop* anything.

## The honest limitation

A skill is markdown. OpenClaw injects only its `name` and `description` into the system
prompt and the model decides whether to read the body and follow it. That is a fine
mechanism for *offering* a capability — and a bad one for *enforcing* a rule:

- The model can simply not call the check. Nothing fails; the action just happens.
- A prompt-injected agent is precisely the agent that will skip its safety step — which is
  the exact threat `injection` exists to catch.
- Skills sit outside `tools.exec.*` policy. They are not an authorization boundary.

So: **this skill gives your agent a second opinion when it asks for one. It cannot make it
ask.** Anyone claiming a skill-shaped guard means "nothing runs without our verdict" is
selling security theater, and we won't.

Where a skill is genuinely the right tool: verifying a claim before you repeat it,
screening text you were handed, redacting a payload before it goes out, sanity-checking a
number. Those are *decisions the agent wants help with*, not rules imposed on it. Most of
what this skill does is that.

## Where a real gate lives

Enforcement has to sit in the tool-call path, where it cannot be skipped. In OpenClaw that
means a **plugin**, not a skill:

1. **`before_tool_call` hook** — documented async and network-capable, so it can await an
   HTTPS verdict. Its return shape maps onto allow / review / block with no impedance
   mismatch:
   - allow → return nothing (pass through)
   - block → `{block: true, blockReason: "…"}` (the reason surfaces to the user)
   - review → `{requireApproval: {title, description, severity, allowedDecisions, timeoutMs}}`,
     which lands in OpenClaw's normal human-approval surfaces. (The field is
     `allowedDecisions?: Array<"allow-once"|"allow-always"|"deny">` — verified against
     their `docs/plugins/hooks.md` BeforeToolCallResult; a field named `decisions` is
     silently ignored.)
   - ⚠️ never return `{block: false}` to mean allow — that is treated as *no decision*.
2. **`api.registerTrustedToolPolicy()`** — the stronger tier: manifest-gated policies
   (declared in `contracts.trustedToolPolicies`) that run ahead of ordinary hooks and can
   block or rewrite tool params before execution.
3. **Operator client** (no plugin at all) — pair as a device, connect to the Gateway with
   the `operator.approvals` scope, consume `exec.approval.requested`, answer
   `exec.approval.resolve`. This is the same path the shipped Slack/Discord/Telegram
   approval clients use.

Fail-closed matters here too: on timeout, network error, or 5xx, default to block or
`requireApproval` — never a silent allow.

## The claim boundary — say this, not that

Even a plugin is not a total chokepoint, and it matters that we're precise:

- ✅ **"Verifies every command your agent tries to run."** True for the plugin path: it
  sees every agent-initiated exec, including allowlist hits that never raise an approval.
- ❌ **"Nothing executes without our verdict."** False. A `node.invoke` issued directly by
  another authenticated operator client bypasses the agent entirely, node hosts carry their
  own local approval policy, and `tools.exec.mode: full` bypasses approvals outright.

We'd rather ship the smaller true claim. That is the whole product.

## Status

The plugin is not built yet. This skill is the advisory layer, shipped honestly as such.
If you want the enforcing layer, say so — it's a well-defined, sanctioned integration
(maintainers closed the competing generic-interceptor PR in favor of extending plugin
hooks, so this tier is the supported direction), and it is the thing worth building next.

→ https://veritylayer.dev/guard
