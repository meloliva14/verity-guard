/**
 * Fail-closed tests for @veritylayer/guard. Uses node's built-in test runner — no deps.
 * Run: npm test   (builds first, then tests dist/)
 *
 * These exist because this package shipped with ZERO tests and a fail-OPEN gate:
 * guardToolCall returned `allowed: !res.blocked`, and `blocked` is `decision === "block"`,
 * which is false when the guard is unreachable and when a 402 was never settled. So
 * `allowed` came back TRUE and a caller doing `if (r.allowed) runTool()` ran the tool with
 * nothing verified — in the one function documented as "the gate".
 *
 * The invariant: `allowed` is true ONLY on a real, non-blocking verdict.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { VerityResult, formatVerdict, verdictProblem } from "../dist/index.js";
import { guardToolCall } from "../dist/vercel.js";

const mk = (raw) => new VerityResult(raw);
const client = (raw) => ({ guard: async () => mk(raw) });
const call = (raw) => guardToolCall(client(raw), { toolName: "wire_money", args: { amount: 4000 } });

test("verdictProblem passes real verdicts", () => {
  for (const d of ["allow", "review", "block"]) {
    assert.equal(verdictProblem(mk({ decision: d })), undefined);
  }
});

test("verdictProblem catches every non-verdict", () => {
  assert.match(verdictProblem(mk({ error: "timeout" })), /unreachable/);
  assert.match(verdictProblem(mk({ payment_required: true, price: "$0.02" })), /payment_required/);
  assert.match(verdictProblem(mk({ risk: 0.1 })), /no decision/);
});

test("REGRESSION: an unreachable guard is never 'allowed'", async () => {
  const r = await call({ error: "verity_unreachable: timeout" });
  assert.equal(r.allowed, false, "FAIL-OPEN: tool allowed with the guard down");
  assert.ok(r.problem);
});

test("REGRESSION: an unsettled 402 is never 'allowed'", async () => {
  const r = await call({ payment_required: true, price: "$0.02" });
  assert.equal(r.allowed, false, "FAIL-OPEN: tool allowed without paying for a verdict");
  assert.ok(r.problem);
});

test("a missing decision is never 'allowed'", async () => {
  assert.equal((await call({ risk: 0.1 })).allowed, false);
});

test("block is not allowed; allow is allowed", async () => {
  assert.equal((await call({ decision: "block", risk: 0.99 })).allowed, false);
  const ok = await call({ decision: "allow", risk: 0.05 });
  assert.equal(ok.allowed, true);
  assert.equal(ok.problem, undefined);
});

test("review still proceeds by default (only block stops)", async () => {
  assert.equal((await call({ decision: "review", risk: 0.5 })).allowed, true);
});

test("formatVerdict never reads like an allow when no verdict exists", () => {
  for (const raw of [{ error: "boom" }, { payment_required: true, price: "$0.02" }]) {
    const s = formatVerdict(mk(raw));
    assert.match(s, /NOT CHECKED/);
    assert.match(s, /do not treat this as an allow/i);
  }
});

test("formatVerdict renders a real verdict normally", () => {
  const s = formatVerdict(mk({ decision: "block", risk: 0.9, safer_alternative: "ask a human" }));
  assert.match(s, /decision=block/);
  assert.match(s, /safer_alternative/);
});

/**
 * verdictProblem is the chokepoint every gate consults, so it has to ANSWER, not throw.
 *
 * It read `res.raw.error` on the assumption it was handed a VerityResult. Anything else — a
 * plain `{error}` object, an un-awaited promise, undefined — crashed it, which means the code
 * whose entire job is to report "there is no verdict" was itself throwing instead of saying so.
 * Python's verdict_problem has always had these guards; JS didn't. Found by the OpenClaw
 * plugin's own tests: its error path handed verdictProblem a bare {error} and it threw.
 */
test("verdictProblem answers instead of throwing on a non-VerityResult", () => {
  assert.match(verdictProblem({ error: "timeout" }), /not a VerityResult/);
  assert.match(verdictProblem(undefined), /not a VerityResult/);
  assert.match(verdictProblem(null), /not a VerityResult/);
  assert.match(verdictProblem("allow"), /not a VerityResult/);
  assert.match(verdictProblem(42), /not a VerityResult/);
});

test("verdictProblem names the un-awaited promise instead of crashing on it", () => {
  // The JS shape of the un-awaited-coroutine bug: `client.guard(...)` without await is a
  // Promise, which is truthy and has no decision. Silently "not blocked" is the fail-open.
  const problem = verdictProblem(Promise.resolve(mk({ decision: "block" })));
  assert.match(problem, /un-awaited promise/);
  assert.match(problem, /nothing was verified/);
});

test("guardToolCall never allows — and never crashes — when handed a non-verdict", async () => {
  // A client that answers with something that isn't a VerityResult. `blocked: res.blocked` was
  // read unconditionally here and threw, so the gate died on exactly the inputs it exists to
  // survive. A TypeError out of the gate is not a verdict.
  for (const bad of [{ error: "x" }, undefined, null, "allow"]) {
    const r = await guardToolCall({ guard: async () => bad }, { toolName: "wire_money", args: {} });
    assert.equal(r.allowed, false, `${JSON.stringify(bad)} must never be allowed`);
    assert.equal(r.blocked, false, "no verdict means nothing was blocked either — both are false");
    assert.ok(r.problem, "the caller must be told WHY there is no verdict");
    assert.match(r.summary, /NOT CHECKED/);
  }
});

test("a promise handed BACK from guard() is awaited, so it is a real verdict", async () => {
  // Not the un-awaited bug: guardToolCall awaits client.guard(), so this resolves normally.
  // Recording it so nobody 'fixes' it into reporting a phantom problem.
  const r = await guardToolCall({ guard: () => Promise.resolve(mk({ decision: "block" })) }, { toolName: "wire_money", args: {} });
  assert.equal(r.problem, undefined);
  assert.equal(r.blocked, true);
  assert.equal(r.allowed, false);
});
