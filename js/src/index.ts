/**
 * @veritylayer/guard — a fail-closed verify-before-you-act gate for AI agents.
 *
 * Keyless & non-custodial: this client holds NO wallet and never pays silently.
 * VerityLayer's paid routes answer HTTP 402 until settled — pass an x402-wrapped
 * `fetch` (e.g. from `x402-fetch`) and it settles the disclosed USDC micro-payment
 * on Base and retries. Pass nothing and a 402 is surfaced as `payment_required`.
 *
 * Every paid verdict carries an Ed25519-signed, independently re-verifiable receipt;
 * `verifyReceipt()` checks one for free against VerityLayer's published public key.
 */

export const ENGINE_DEFAULT = "https://api.veritylayer.dev";
export const SUITE_DEFAULT = "https://suite.veritylayer.dev";

export type Tier = "quick" | "grounded" | "pro" | "standard";
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
  get allowed(): boolean { return ["allow", "publish", "clean", "supported"].includes(this.norm); }
  get blocked(): boolean { return this.norm === "block"; }
  get flagged(): boolean { return !this.allowed; }
}

export interface VerityOptions {
  /** An x402-wrapped fetch (holds your wallet) to auto-settle 402s. Defaults to global fetch (surfaces 402). */
  fetch?: typeof fetch;
  engine?: string;
  suite?: string;
  timeoutMs?: number;
  /** Routing tag sent as X-Verity-Ref; reserved for a future referral program, never changes price/verdict. */
  affiliateId?: string;
}

export interface CheckOpts {
  context?: string;
  policy?: string;
  tier?: Tier;
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
    this.timeoutMs = (opts.timeoutMs ?? 90) * 1000;
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
  verify(claim: string, o: CheckOpts = {}): Promise<VerityResult> {
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
  if (res.paymentRequired) return `payment_required (${res.price}) — the check was never performed`;
  if (res.raw.error) return `guard unreachable: ${String(res.raw.error)}`;
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
    if (res.paymentRequired)
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
