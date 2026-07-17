/**
 * @veritylayer/guard — a fail-closed verify-before-you-act gate for AI agents.
 *
 * Keyless & non-custodial: this client holds NO wallet and never pays silently.
 * VerityLayer's paid routes answer HTTP 402 until settled — pass an x402-wrapped `fetch`
 * (`x402Payer` from `@veritylayer/guard/payer`, which caps the spend and pins the chain)
 * and it settles the disclosed USDC micro-payment on Base and retries. Pass nothing and a
 * 402 is surfaced as `payment_required` — with NO decision, which is not an allow.
 *
 * If you wrap your own: VerityLayer speaks x402 **v2** (challenge in the
 * `payment-required` header). The unscoped `x402-fetch` package is the **v1** client and
 * reads the challenge from the response body, so it cannot pay us — use the scoped
 * `@x402/*` 2.x line.
 *
 * Every paid verdict carries an Ed25519-signed, independently re-verifiable receipt;
 * `verifyReceipt()` checks one for free against VerityLayer's published public key.
 */

export const ENGINE_DEFAULT = "https://api.veritylayer.dev";
export const SUITE_DEFAULT = "https://suite.veritylayer.dev";

/**
 * Tiers are PER-METHOD. A single flat union let `verify(x, {tier:"standard"})` and
 * `guard(x, {tier:"grounded"})` typecheck cleanly and then throw at runtime — synchronously,
 * from `call()`, so a `.catch()` never even attaches. The type promised tiers no method
 * accepts. Narrowing this after publish would be breaking, so it is narrowed now.
 */
/** `verify` — the grounding ladder. Note the default is `grounded` ($0.25), not `quick`. */
export type VerifyTier = "quick" | "grounded" | "pro";
/** `guard` / `detectInjection` / `moderate` / `redact` — the suite ladder. Default `quick` ($0.02). */
export type CheckTier = "quick" | "standard" | "pro";
/** The union of both. Prefer `VerifyTier` / `CheckTier`; this cannot tell them apart. */
export type Tier = VerifyTier | CheckTier;
type Host = "engine" | "suite";
type Json = Record<string, unknown>;

const ROUTES: Record<string, { host: Host; tiers: Record<string, [string, string]>; def: string }> = {
  verify: { host: "engine", tiers: { quick: ["/verify/quick", "$0.02"], grounded: ["/verify", "$0.25"], pro: ["/verify/pro", "$0.35"] }, def: "grounded" },
  guard: { host: "suite", tiers: { quick: ["/check/quick", "$0.02"], standard: ["/check", "$0.08"], pro: ["/check/pro", "$0.20"] }, def: "quick" },
  injection: { host: "suite", tiers: { quick: ["/sentinel/quick", "$0.02"], standard: ["/sentinel", "$0.06"], pro: ["/sentinel/pro", "$0.15"] }, def: "quick" },
  moderate: { host: "suite", tiers: { quick: ["/sieve/quick", "$0.02"], standard: ["/sieve", "$0.06"], pro: ["/sieve/pro", "$0.15"] }, def: "quick" },
  redact: { host: "suite", tiers: { quick: ["/redact/quick", "$0.02"], standard: ["/redact", "$0.06"], pro: ["/redact/pro", "$0.15"] }, def: "quick" },
};

/** The raw verdict object plus typed convenience accessors. `.raw` always holds every field. */
export class VerityResult {
  constructor(public readonly raw: Json) {}
  get decision(): string | undefined { return (this.raw.decision as string) ?? (this.raw.verdict as string); }
  get risk(): number | undefined { const r = this.raw.risk; return (r as number) ?? (this.raw.confidence as number); }
  get receipt(): Json | undefined { return this.raw.receipt as Json | undefined; }
  get price(): string | undefined { return this.raw.price as string | undefined; }
  get paymentRequired(): boolean { return Boolean(this.raw.payment_required); }
  get valid(): boolean | undefined { return this.raw.valid as boolean | undefined; }
  get reasons(): unknown[] { return (this.raw.reasons as unknown[]) ?? []; }
  get saferAlternative(): string | undefined { return this.raw.safer_alternative as string | undefined; }
  /** Compare decisions case- and whitespace-insensitively. `blocked` is what every gate
   *  consults, so `"BLOCK"` or `" block"` must never compare unequal to `"block"`, read as
   *  not-blocked, and execute the very action the verdict meant to stop. */
  private get norm(): string { const d = this.decision; return typeof d === "string" ? d.trim().toLowerCase() : ""; }
  /** The decision, case- and whitespace-normalized. `""` when there is no decision. */
  get decisionNorm(): string { return this.norm; }
  /**
   * True if the decision is any of `names`, compared normalized.
   *
   * Use this for EVERY decision comparison. `res.decision === "review"` reopens the exact
   * hole `norm` exists to close — and `verdictProblem` normalizes before its allowlist check,
   * so a case variant is ADMITTED as a genuine verdict and then sails past the comparison
   * that was supposed to catch it. (The Python adapters shipped that bug on four gates,
   * including the prompt-injection tripwire.)
   */
  decisionIs(...names: string[]): boolean {
    return this.norm !== "" && names.some((n) => n.trim().toLowerCase() === this.norm);
  }
  get allowed(): boolean { return ["allow", "publish", "clean", "supported"].includes(this.norm); }
  get blocked(): boolean { return this.norm === "block"; }
  get flagged(): boolean { return !this.allowed; }
}

export interface VerityOptions {
  /** An x402-wrapped fetch (holds your wallet) to auto-settle 402s. Defaults to global fetch (surfaces 402). */
  fetch?: typeof fetch;
  engine?: string;
  suite?: string;
  /** Per-call budget in MILLISECONDS. Default 90_000 (90s — a grounded verify does live web work). */
  timeoutMs?: number;
  /** Routing tag sent as X-Verity-Ref; reserved for a future referral program, never changes price/verdict. */
  affiliateId?: string;
}

export interface CheckOpts {
  context?: string;
  policy?: string;
  /** quick $0.02 (default) · standard $0.08 · pro $0.20. */
  tier?: CheckTier;
}

export interface VerifyOpts {
  context?: string;
  policy?: string;
  /** quick $0.02 (ungrounded) · grounded $0.25 (DEFAULT, live citations) · pro $0.35. */
  tier?: VerifyTier;
}

export class VerityClient {
  private readonly f: typeof fetch;
  private readonly engine: string;
  private readonly suite: string;
  private readonly timeoutMs: number;
  private readonly affiliateId?: string;

  constructor(opts: VerityOptions = {}) {
    if (!opts.fetch && typeof fetch === "undefined") {
      throw new Error("No global fetch found — pass opts.fetch (Node 18+ has fetch built in).");
    }
    this.f = opts.fetch ?? fetch;
    this.engine = (opts.engine ?? ENGINE_DEFAULT).replace(/\/+$/, "");
    this.suite = (opts.suite ?? SUITE_DEFAULT).replace(/\/+$/, "");
    // Milliseconds, as the name says. This used to be `(opts.timeoutMs ?? 90) * 1000` — the
    // option was named `timeoutMs` and interpreted as SECONDS, so every caller was off by
    // 1000x. It hid because the default (90 -> 90s) was sane and nobody passed the option;
    // it surfaced when the OpenClaw plugin passed a considered 8_000ms budget and silently
    // got 8,000,000ms (2h13m) — long enough that its own abort could never fire, which made
    // the plugin's documented `onUnavailable` posture unreachable in every configuration.
    // Only 0.1.0 is on npm, so fixing the meaning now costs nothing later.
    this.timeoutMs = opts.timeoutMs ?? 90_000;
    this.affiliateId = opts.affiliateId;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { "content-type": "application/json" };
    if (this.affiliateId) h["X-Verity-Ref"] = String(this.affiliateId);
    return h;
  }

  private async post(base: string, path: string, body: Json, price: string): Promise<VerityResult> {
    const url = `${base}${path}`;
    const clean = Object.fromEntries(Object.entries(body).filter(([, v]) => v !== undefined && v !== null));
    let r: Response;
    try {
      r = await this.f(url, {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify(clean),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e) {
      return new VerityResult({ error: `verity_unreachable: ${String(e).slice(0, 160)}`, endpoint: url, price });
    }
    const text = await r.text();
    if (r.status === 402) {
      let challenge: unknown;
      try { challenge = JSON.parse(text); } catch { challenge = text.slice(0, 1000); }
      return new VerityResult({
        payment_required: true, price, currency: "USDC", network: "Base mainnet (eip155:8453)",
        detail: `This VerityLayer check is paid per call via x402 (${price} USDC on Base). ` +
          "Settle the disclosed micro-payment with your x402 layer and retry. This client holds no key.",
        challenge,
      });
    }
    let data: unknown;
    try { data = JSON.parse(text); } catch { return new VerityResult({ error: `unexpected_status_${r.status}`, body: text.slice(0, 300), price }); }
    if (data && typeof data === "object" && !Array.isArray(data)) {
      const o = data as Json;
      if (o.price === undefined) o.price = price;
      return new VerityResult(o);
    }
    return new VerityResult({ result: data, price });
  }

  private call(kind: string, tier: Tier | undefined, fields: Json): Promise<VerityResult> {
    const spec = ROUTES[kind];
    const t = tier ?? spec.def;
    const entry = spec.tiers[t];
    if (!entry) throw new Error(`${kind}: unknown tier '${t}' (choose ${Object.keys(spec.tiers).join(", ")})`);
    const [path, price] = entry;
    return this.post(spec.host === "engine" ? this.engine : this.suite, path, fields, price);
  }

  /** THE FLAGSHIP. allow / review / block for a proposed action, with a signed receipt. */
  guard(action: string, o: CheckOpts = {}): Promise<VerityResult> {
    return this.call("guard", o.tier, { action, context: o.context, policy: o.policy });
  }
  verify(claim: string, o: VerifyOpts = {}): Promise<VerityResult> {
    return this.call("verify", o.tier, { claim, context: o.context });
  }
  detectInjection(content: string, o: CheckOpts = {}): Promise<VerityResult> {
    return this.call("injection", o.tier, { content, context: o.context });
  }
  moderate(content: string, o: CheckOpts = {}): Promise<VerityResult> {
    return this.call("moderate", o.tier, { content, policy: o.policy, context: o.context });
  }
  redact(payload: string, o: CheckOpts = {}): Promise<VerityResult> {
    return this.call("redact", o.tier, { payload, context: o.context });
  }
  /** FREE — verify an Ed25519 receipt against VerityLayer's public key. */
  verifyReceipt(receipt: Json | string): Promise<VerityResult> {
    const body: Json = typeof receipt === "string" ? (JSON.parse(receipt) as Json) : receipt;
    return this.post(this.engine, "/receipt/verify", body, "$0.00 (free)");
  }
}

export const GUARD_TOOL_DESCRIPTION =
  "Independent fail-closed safety gate. BEFORE any irreversible action (a payment/spend, an outbound " +
  "message, a destructive command, a data share, a publish), describe the action and call this. Returns " +
  "allow / review / block with an honest risk score, concrete reasons, and a safer alternative when it " +
  "blocks — plus an Ed25519-signed, independently re-verifiable receipt. If it blocks, do NOT take the action.";

const NOT_CHECKED = "No verdict exists — do not treat this as an allow.";

/**
 * Why `res` is not a usable verdict, or `undefined` if it is one.
 *
 * THE FAIL-CLOSED CHOKEPOINT. The obvious check is silently backwards: `blocked` is
 * `decision === "block"`, and `decision` is undefined when the guard is unreachable and
 * when a 402 was never settled — so `!res.blocked` reads TRUE in both cases and waves the
 * unverified action through. Fail-closed means: proceed only on an affirmative verdict.
 * No verdict, no action.
 */
/** Every decision the services are contracted to return. An ALLOWLIST: gates must recognize
 *  a verdict, not merely fail to recognize a block. */
export const KNOWN_DECISIONS: ReadonlySet<string> = new Set([
  "allow", "review", "block",
  "supported", "unsupported", "uncertain",
  "clean", "suspicious", "injection",
  "publish", "contains_pii", "contains_secret",
]);

export function verdictProblem(res: VerityResult): string | undefined {
  // This function IS the chokepoint every gate consults, so it must answer rather than throw.
  // It used to assume a VerityResult and read `res.raw.error`; anything else (a plain object,
  // an un-awaited promise, undefined) crashed it — turning "there is no verdict" into an
  // exception thrown from the very code whose job is to report that there is no verdict.
  // Mirrors the Python `verdict_problem`, which has always had these two guards.
  if (typeof (res as unknown as PromiseLike<unknown> | undefined)?.then === "function")
    return "guard returned an un-awaited promise — you likely forgot to await the check, so nothing was verified";
  if (!(res instanceof VerityResult))
    return `guard returned ${res === null ? "null" : typeof res}, not a VerityResult — nothing was verified`;

  if (res.paymentRequired) return `payment_required (${res.price}) — the check was never performed`;
  if (res.raw?.error) return `guard unreachable: ${String(res.raw.error)}`;
  if (res.decision === undefined) return "guard returned no decision";
  if (!KNOWN_DECISIONS.has(String(res.decision).trim().toLowerCase()))
    return `guard returned an unrecognized decision ${JSON.stringify(res.decision)}`;
  return undefined;
}

/** Compact one-line summary an agent/LLM can read back. Never reads like an allow when no verdict exists. */
export function formatVerdict(res: VerityResult): string {
  // Driven off the same chokepoint the gate uses, so the string can never disagree with it.
  // Hand-listing the cases let a decision-less 200 render as "[verity] decision=undefined |
  // risk=0.1" with no warning — on the advisory tool paths that string is the ONLY signal
  // the model gets.
  const problem = verdictProblem(res);
  if (problem) {
    // `res instanceof` first: verdictProblem now answers for non-VerityResults instead of
    // throwing, so this branch can be reached with a plain object / promise / undefined, and
    // reading `.paymentRequired` off one of those would crash the very reporter of "no verdict".
    if (res instanceof VerityResult && res.paymentRequired)
      return `[verity] NOT CHECKED — payment_required (${res.price}); settle via x402 and retry. ${NOT_CHECKED}`;
    return `[verity] NOT CHECKED — ${problem}. ${NOT_CHECKED}`;
  }
  const parts = [`[verity] decision=${res.decision}`, `risk=${res.risk}`];
  if (res.reasons.length) parts.push("reasons: " + res.reasons.slice(0, 4).map(String).join("; "));
  if (res.blocked && res.saferAlternative) parts.push("safer_alternative: " + res.saferAlternative);
  const rid = res.receipt?.receipt_id;
  if (rid) parts.push(`receipt=${String(rid)}`);
  return parts.join(" | ");
}

export interface GuardToolCallInput {
  toolName: string;
  args: unknown;
  policy?: string;
  tier?: "quick" | "standard" | "pro";
}

export interface GuardToolCallResult {
  /** TRUE only on an affirmative, non-blocking verdict. Never true when no verdict exists. */
  allowed: boolean;
  blocked: boolean;
  /** Set when NO verdict was produced (unreachable / unsettled 402 / no decision). If this is
   *  set, `allowed` is false and the tool must not run — the check did not happen. */
  problem?: string;
  result: VerityResult;
  summary: string;
}

/**
 * Pure per-tool-call gate for `experimental_prepareStep` or a manual pre-execute hook.
 * Guards the ARGUMENTS of a pending tool call — the highest-frequency wire-in.
 *
 * Fail-closed. This used to return `allowed: !res.blocked`, which is the fail-OPEN formula:
 * `blocked` is `decision === "block"`, so it is false when the guard is unreachable and when
 * a 402 was never settled — meaning `allowed` came back TRUE and the caller ran the tool with
 * nothing verified, in the one function documented as "the gate". Now a missing verdict is
 * never permission: `allowed` requires a real verdict that did not block.
 *
 * `review` still proceeds by default (only `block` stops), matching the documented behavior —
 * inspect `result.result.decisionIs("review")` if you want to escalate those to a human.
 * (Use `decisionIs`, never `decision === "review"`: a case variant compares unequal, silently
 * skips your escalation, and reads as a clean pass.)
 */
export async function guardToolCall(client: VerityClient, input: GuardToolCallInput): Promise<GuardToolCallResult> {
  let argStr: string;
  try { argStr = JSON.stringify(input.args); } catch { argStr = String(input.args); }
  const res = await client.guard(`Execute tool \`${input.toolName}\` with arguments ${argStr.slice(0, 800)}`, {
    policy: input.policy,
    tier: input.tier ?? "quick",
  });
  const problem = verdictProblem(res);
  // `!problem &&` guards the property read, not just the logic: verdictProblem answers for
  // non-VerityResults (a plain {error}, an un-awaited promise, undefined) rather than throwing,
  // so `res` here may have no `.blocked` at all. `blocked: res.blocked` was evaluated
  // unconditionally and crashed the gate on exactly the inputs the gate exists to survive.
  // When there's a problem there is no verdict, so nothing was blocked AND nothing is allowed.
  const blocked = !problem && res.blocked;
  return {
    allowed: !problem && !blocked,
    blocked,
    problem,
    result: res,
    summary: formatVerdict(res),
  };
}
