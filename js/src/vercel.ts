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

import { GUARD_TOOL_DESCRIPTION, VerityClient, VerityResult, formatVerdict } from "./index.js";

export interface VercelToolOpts {
  tier?: "quick" | "standard" | "pro";
  defaultPolicy?: string;
}

/** A shape compatible with the AI SDK `tool()` across v3–v5 (carries both schema keys). */
export interface VerityVercelTool {
  description: string;
  inputSchema: unknown;
  parameters: unknown;
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
  allowed: boolean;
  blocked: boolean;
  result: VerityResult;
  summary: string;
}

/**
 * Pure per-tool-call gate for `experimental_prepareStep` or a manual pre-execute hook.
 * Guards the ARGUMENTS of a pending tool call — the highest-frequency wire-in.
 */
export async function guardToolCall(client: VerityClient, input: GuardToolCallInput): Promise<GuardToolCallResult> {
  let argStr: string;
  try { argStr = JSON.stringify(input.args); } catch { argStr = String(input.args); }
  const res = await client.guard(`Execute tool \`${input.toolName}\` with arguments ${argStr.slice(0, 800)}`, {
    policy: input.policy,
    tier: input.tier ?? "quick",
  });
  return { allowed: !res.blocked, blocked: res.blocked, result: res, summary: formatVerdict(res) };
}
