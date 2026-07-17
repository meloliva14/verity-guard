/**
 * VerityLayer Gate — an OpenClaw plugin that verifies irreversible tool calls before they run.
 *
 * WHY THIS EXISTS AND THE SKILL DOESN'T REPLACE IT
 * -----------------------------------------------
 * We also ship a `verity-guard` OpenClaw *skill*. A skill is markdown: OpenClaw injects its
 * name and description into the prompt and the MODEL decides whether to follow it. That is a
 * fine way to *offer* a capability and a useless way to *enforce* a rule — a prompt-injected
 * agent is precisely the agent that skips its safety step. A skill-shaped guard is security
 * theater and we won't sell it as more.
 *
 * A plugin sits in the tool-call path, where it cannot be skipped. That is the difference.
 *
 * THE CLAIM BOUNDARY (we ship the smaller true claim)
 * --------------------------------------------------
 *  ✅ "Verifies every command your agent tries to run."
 *  ❌ "Nothing executes without our verdict." — false, and we won't say it: a `node.invoke`
 *     from another authenticated operator bypasses the agent entirely, node hosts carry their
 *     own local approval policy, and `tools.exec.mode: full` bypasses approvals outright.
 *
 * THREE THINGS ABOUT OpenClaw's HOOK THAT ARE EASY TO GET WRONG (all verified in their source,
 * two of them contradicting their own docs):
 *  1. `before_tool_call` is registered FAIL-CLOSED by the global runner, so a handler that
 *     throws or times out BLOCKS the tool. Good posture — but it means a flaky verifier bricks
 *     the agent, which is why unavailability here routes to `requireApproval` by default rather
 *     than either a hard block or a silent allow. See `onUnavailable`.
 *  2. This hook has NO default timeout. Omit `timeoutMs` and a hung request hangs the agent
 *     forever (not a block). We pass one, and we also carry our own AbortSignal, because a
 *     timed-out handler keeps running — hooks get no cancellation signal.
 *  3. Tool names are normalized before the hook sees them: `bash` is aliased to `exec`. Match
 *     on `exec`, or the gate silently never fires on the single most dangerous tool.
 *
 * And the one that would quietly invert the whole thing: returning `{block: false}` means
 * NO DECISION, not "allow". Allowing is `return undefined`. We never construct `{block:false}`.
 */
import {
  buildJsonPluginConfigSchema,
  definePluginEntry,
  type OpenClawPluginApi,
  type OpenClawPluginConfigSchema,
} from "openclaw/plugin-sdk/plugin-entry";
// Bind to the HOST's real hook types, not hand-written shapes. If OpenClaw renames a field,
// this build breaks — which is the point. A gate that silently stops matching is worse than
// one that fails to compile.
import type {
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
} from "openclaw/plugin-sdk/types";
import { VerityClient, VerityResult, verdictProblem, type CheckTier } from "@veritylayer/guard";
import { x402Payer } from "@veritylayer/guard/payer";

/**
 * Tools that can change the world. `read` is deliberately absent: gating a read spends money
 * to bless something that cannot be undone because it was never done.
 *
 * These are the real ids from OpenClaw's tool catalog. `bash` is NOT here on purpose — the host
 * rewrites it to `exec` before we see it, so listing it would be cargo cult.
 */
const DEFAULT_GATED_TOOLS = ["exec", "write", "edit", "apply_patch", "process", "code_execution", "terminal"];

type Unavailable = "review" | "block";

interface GateConfig {
  gatedTools?: string[];
  policy?: string;
  tier?: CheckTier;   // the suite ladder — `grounded` belongs to verify(), not guard()
  timeoutMs?: number;
  /** What to do when NO verdict exists (down, unpaid, malformed). Never "allow" — that isn't offered. */
  onUnavailable?: Unavailable;
  maxPriceUsdc?: string;
}

const CONFIG_SCHEMA = {
  type: "object",
  additionalProperties: false,
  properties: {
    gatedTools: {
      type: "array",
      items: { type: "string" },
      description: `Tool names to verify. Default: ${DEFAULT_GATED_TOOLS.join(", ")}. Note: "bash" is aliased to "exec" by the host.`,
    },
    policy: { type: "string", description: "Your standing rule, e.g. 'No new payees without human review.'" },
    tier: { type: "string", enum: ["quick", "standard", "pro"], description: "quick $0.02 (default), standard $0.08, pro $0.20." },
    timeoutMs: { type: "number", description: "Per-check budget. Default 8000." },
    onUnavailable: {
      type: "string",
      enum: ["review", "block"],
      description:
        "When no verdict exists (unreachable/unpaid): 'review' asks the human (default), 'block' refuses. " +
        "There is deliberately no 'allow' — an unverified action must never pass as verified.",
    },
    maxPriceUsdc: { type: "string", description: "Hard per-call spend ceiling. Default 1.00." },
  },
} as const;

/** Truncate for a human-readable approval card without smuggling a novel into the UI. */
const clip = (s: string, n = 400) => (s.length > n ? `${s.slice(0, n)}…` : s);

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

/**
 * Describe the tool call in the plain language the verifier expects.
 *
 * We read `params` ourselves rather than trusting `derivedPaths`, whose own docstring warns it
 * "may be incomplete or over-approximate" and tells policy code to parse params directly.
 *
 * The per-tool param SHAPES are not pinned by any contract we've verified, so this prefers a few
 * likely keys and otherwise falls back to serializing the params. It must never throw: a
 * describe() that throws would, under this hook's fail-closed policy, block the tool with an
 * unrelated error message.
 */
export function describeToolCall(toolName: string, params: Record<string, unknown>, toolKind?: string): string {
  try {
    const p = params ?? {};
    const pick = (...keys: string[]) => {
      for (const k of keys) if (typeof p[k] === "string" && p[k]) return p[k] as string;
      return undefined;
    };
    if (toolKind === "code_mode_exec") {
      const code = pick("code", "source", "script", "command");
      return clip(`run ${toolName} code: ${code ?? JSON.stringify(p)}`);
    }
    if (toolName === "exec" || toolName === "terminal" || toolName === "process") {
      const cmd = pick("command", "cmd", "script", "input");
      if (cmd) return clip(`run shell command: ${cmd}`);
    }
    if (toolName === "write" || toolName === "edit" || toolName === "apply_patch") {
      const path = pick("path", "file_path", "filePath", "file");
      const body = pick("content", "patch", "new_string", "text");
      return clip(`${toolName} file ${path ?? "(unknown path)"}${body ? `: ${body}` : ""}`);
    }
    return clip(`${toolName}(${JSON.stringify(p)})`);
  } catch {
    return `${toolName}(<unserializable params>)`;
  }
}

/** The gate's decision, independent of OpenClaw's types so it can be tested directly. */
export type GateOutcome =
  | { kind: "pass" }
  | { kind: "block"; reason: string }
  | { kind: "approve"; title: string; description: string; severity: "warning" | "critical" };

/**
 * Turn a verdict into an outcome. Fail-closed, and honest about WHICH failure occurred:
 * "we judged this and said block" and "we never checked" both stop the action, but they are
 * different facts and must never render identically.
 */
export function decide(res: unknown, onUnavailable: Unavailable, action: string): GateOutcome {
  const problem = verdictProblem(res as never);
  if (problem) {
    const detail = `VerityLayer did NOT verify this action: ${problem}. No verdict exists — this is not an allow.`;
    return onUnavailable === "block"
      ? { kind: "block", reason: detail }
      : { kind: "approve", title: "Unverified action — you decide", description: `${detail}\n\nAction: ${action}`, severity: "critical" };
  }

  const r = res as { decision?: string; risk?: number; reasons?: unknown[]; saferAlternative?: string; blocked: boolean; allowed: boolean };
  if (r.blocked) {
    const why = Array.isArray(r.reasons) && r.reasons.length ? r.reasons.join("; ") : "no reason given";
    const safer = r.saferAlternative ? ` Safer: ${r.saferAlternative}` : "";
    return { kind: "block", reason: `VerityLayer blocked this (risk ${r.risk ?? "?"}): ${why}.${safer}` };
  }
  if (r.allowed) return { kind: "pass" };

  // Anything recognized but not an allow — `review` above all — asks the human. Reached only
  // for KNOWN decisions, because verdictProblem already rejected everything else.
  const why = Array.isArray(r.reasons) && r.reasons.length ? r.reasons.join("; ") : "flagged for human review";
  return {
    kind: "approve",
    title: `VerityLayer: ${r.decision}`,
    description: `${why}${(res as { saferAlternative?: string }).saferAlternative ? `\n\nSafer: ${(res as { saferAlternative?: string }).saferAlternative}` : ""}\n\nAction: ${action}`,
    severity: "warning",
  };
}

/**
 * The shape `definePluginEntry` returns. Declared locally because OpenClaw's
 * `DefinedPluginEntry` isn't exported, and without an annotation TS can't name the inferred
 * type across their bundled chunk boundary (TS2742).
 */
type PluginEntry = {
  id: string;
  name: string;
  description: string;
  configSchema: OpenClawPluginConfigSchema;
  register: (api: OpenClawPluginApi) => void;
};

/** The one call the gate needs. Narrowed so tests can drive the handler without a network. */
export interface Guarder {
  guard(action: string, opts: { policy?: string; tier?: CheckTier }): Promise<unknown>;
}

/**
 * The gate itself, independent of OpenClaw's registry so it can be executed directly in tests.
 * `getGuarder` is lazy: constructing the payer derives an address from a key, and a process
 * that never makes a paid call shouldn't do that at import time.
 */
export function createGateHandler(cfg: GateConfig, getGuarder: () => Promise<Guarder>) {
  const gated = new Set(cfg.gatedTools ?? DEFAULT_GATED_TOOLS);
  const onUnavailable: Unavailable = cfg.onUnavailable === "block" ? "block" : "review";

  // Memoized HERE rather than in register(), so the guarantee lives in the unit that's tested.
  // Rebuilding per tool call would re-derive an address from the wallet key on every command.
  let guarderPromise: Promise<Guarder> | null = null;
  const guarderOnce = () => (guarderPromise ??= getGuarder());

  return async (event: PluginHookBeforeToolCallEvent): Promise<PluginHookBeforeToolCallResult | void> => {
    if (!gated.has(event.toolName)) return; // undefined = no decision = pass through

    const action = describeToolCall(event.toolName, event.params, event.toolKind);

    // Nothing below rethrows. The host's fail-closed policy would turn any throw into a block
    // carrying a generic "hook failed" message — losing both the real reason and the operator's
    // chosen posture. We'd rather say exactly what happened and let onUnavailable decide.
    //
    // Every failure becomes a VerityResult, never a bare {error}: verdictProblem reads `.raw`,
    // and handing it a plain object threw right here — inside the handler whose entire job is
    // to report that nothing was verified.
    let res: unknown;
    let guarder: Guarder | undefined;
    try {
      guarder = await guarderOnce();
    } catch (err) {
      // Only a failed BUILD resets the memo. Caching a rejected promise would replay this same
      // stale error on every later call, long after the cause was fixed.
      guarderPromise = null;
      res = new VerityResult({ error: `guard unavailable: ${message(err)}` });
    }
    if (guarder) {
      try {
        res = await guarder.guard(action, { policy: cfg.policy, tier: cfg.tier ?? "quick" });
      } catch (err) {
        res = new VerityResult({ error: `guard threw: ${message(err)}` });
      }
    }

    const outcome = decide(res, onUnavailable, action);
    switch (outcome.kind) {
      case "pass":
        return; // NOT {block:false} — that means "no decision" to the host, not "allow"
      case "block":
        return { block: true, blockReason: outcome.reason };
      case "approve":
        return {
          requireApproval: {
            title: outcome.title,
            description: outcome.description,
            severity: outcome.severity,
            timeoutMs: 120_000,
            // Deliberately no "allow-always": this gate exists because the NEXT call with the
            // same tool may be the dangerous one. A standing allow is the gate removing itself.
            allowedDecisions: ["allow-once", "deny"],
          },
        };
    }
  };
}

const entry: PluginEntry = definePluginEntry({
  id: "verity-gate",
  name: "VerityLayer Gate",
  description: "Independently verifies irreversible tool calls (allow / review / block) before they run.",
  // buildJsonPluginConfigSchema, NOT the raw JSON Schema object: OpenClawPluginConfigSchema is a
  // validator ({safeParse, parse, validate, jsonSchema}), not a schema literal. Handing it the
  // literal typechecks only if you cast, and then nothing validates.
  configSchema: () => buildJsonPluginConfigSchema(CONFIG_SCHEMA as never),
  register(api: OpenClawPluginApi) {
    // `api.pluginConfig`, NOT `api.config`. `api.config` is OpenClaw's ENTIRE config object;
    // reading it here and casting would leave every field undefined, so every setting the
    // operator wrote — onUnavailable: "block", a custom gatedTools list, their policy — would
    // silently fall back to defaults. A security gate quietly ignoring its own security config
    // is exactly the failure this product exists to catch.
    const cfg: GateConfig = (api.pluginConfig ?? {}) as GateConfig;
    const timeoutMs = cfg.timeoutMs ?? 8_000;

    let clientPromise: Promise<Guarder> | null = null;
    const getGuarder = () => {
      if (!clientPromise) {
        clientPromise = (async () => {
          const key = process.env.VERITY_WALLET_KEY;
          if (!key) {
            // Keyless: paid routes answer 402, verdictProblem catches it, and onUnavailable
            // decides. The agent is never told an unpaid call was an allow.
            return new VerityClient({ timeoutMs });
          }
          return new VerityClient({
            fetch: await x402Payer(key, { maxPriceUsdc: cfg.maxPriceUsdc ?? "1.00" }),
            timeoutMs,
          });
        })();
      }
      return clientPromise;
    };

    api.on(
      "before_tool_call",
      createGateHandler(cfg, getGuarder),
      // timeoutMs is effectively MANDATORY: this hook has no default, so omitting it means an
      // unbounded hang rather than a block. Slightly above our own per-check budget so our
      // error message wins the race against the host's generic one.
      { priority: 100, timeoutMs: timeoutMs + 2_000 },
    );
  },
});

export default entry;
