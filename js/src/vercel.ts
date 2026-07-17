/**
 * Vercel AI SDK adapter for @veritylayer/guard.
 *
 *   import { VerityClient } from "@veritylayer/guard";
 *   import { verityGuardTool } from "@veritylayer/guard/vercel";
 *
 *   const v = new VerityClient({ fetch: myX402Fetch });
 *   const result = await generateText({
 *     model, prompt,
 *     tools: { verityGuard: verityGuardTool(v, { defaultPolicy: "No new payees without review." }) },
 *   });
 *
 * Or gate every tool call yourself via `experimental_prepareStep` with `guardToolCall`.
 * Requires `ai` and `zod` (peer deps you already have in a Vercel AI SDK app).
 */
import { z } from "zod";

import { GUARD_TOOL_DESCRIPTION, VerityClient, VerityResult, formatVerdict, verdictProblem } from "./index.js";

export interface VercelToolOpts {
  tier?: "quick" | "standard" | "pro";
  defaultPolicy?: string;
}

/**
 * A shape compatible with the AI SDK `tool()` across v3–v5 (carries both schema keys).
 *
 * The schema fields are `any`, not `unknown`, and that is deliberate. `unknown` is assignable
 * to NOTHING, so the README's flagship snippet —
 * `tools: { verityGuard: verityGuardTool(v) }` — failed to typecheck against the AI SDK's
 * `Tool<...>` with `TS2322: Type 'unknown' is not assignable to type 'FlexibleSchema<never>'`,
 * on ai@5 and ai@7, strict and non-strict. Runtime was always correct; the documented
 * quickstart was simply a red `next build` for the median (TypeScript/Next) user.
 * The SDK's `Tool` is generic over its schema and the type moves between majors, so this is
 * the compat seam.
 */
export interface VerityVercelTool {
  description: string;
  inputSchema: any;
  parameters: any;
  execute: (args: Record<string, unknown>) => Promise<string>;
}

/** A guard tool the model can call before acting. Returns a compact verdict summary. */
export function verityGuardTool(client: VerityClient, opts: VercelToolOpts = {}): VerityVercelTool {
  const schema = z.object({
    action: z.string().describe("The action the agent is about to take."),
    context: z.string().optional().describe("Situation / background for the action."),
    policy: z.string().optional().describe("Rules that must not be violated."),
  });
  return {
    description: GUARD_TOOL_DESCRIPTION,
    inputSchema: schema,
    parameters: schema,
    execute: async (args) => {
      const a = args as { action: string; context?: string; policy?: string };
      const res = await client.guard(a.action, {
        context: a.context,
        policy: a.policy ?? opts.defaultPolicy,
        tier: opts.tier ?? "quick",
      });
      return formatVerdict(res);
    },
  };
}

/** A fact-check tool (grounded, signed receipt). */
export function verityVerifyTool(client: VerityClient, opts: { tier?: "quick" | "grounded" | "pro" } = {}): VerityVercelTool {
  const schema = z.object({
    claim: z.string().describe("The factual claim to verify."),
    context: z.string().optional().describe("Optional surrounding context."),
  });
  return {
    description:
      "Reality-check a factual claim before acting on or repeating it. Returns supported / unsupported / " +
      "uncertain with a calibrated confidence, live-web reasoning, and a signed, independently re-verifiable " +
      "receipt. Fail-closed: abstains rather than guess.",
    inputSchema: schema,
    parameters: schema,
    execute: async (args) => {
      const a = args as { claim: string; context?: string };
      const res = await client.verify(a.claim, { context: a.context, tier: opts.tier ?? "grounded" });
      return formatVerdict(res);
    },
  };
}

// guardToolCall lives in the main entry now — it is framework-agnostic (it gates a tool call;
// it builds no schema and never touched zod). It stayed here behind this module's top-level
// `import { z } from "zod"`, so importing our own README's "highest-frequency wire-in" threw
// ERR_MODULE_NOT_FOUND for anyone without zod — and zod is only a PEER of `ai`, not a
// dependency, so an AI SDK user is not guaranteed to have it. Re-exported so existing imports
// from `@veritylayer/guard/vercel` keep working.
export { guardToolCall } from "./index.js";
export type { GuardToolCallInput, GuardToolCallResult } from "./index.js";
