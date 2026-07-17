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
